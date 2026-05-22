#!/usr/bin/env python3
"""Capture Beta-4 GitHub draft PR review state without authorizing merge.

This packet binds one GitHub PR review-state observation to an already valid
Beta-4 draft PR receipt. It records pending, comment-only, reviewed, approved,
or changes-requested metadata returned by `gh pr view`; it never creates a
review, marks a draft ready, merges, deploys, or promotes H.3 readiness.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from beta4_draft_pr_executor import RECEIPT_SCHEMA as DRAFT_PR_RECEIPT_SCHEMA
from beta4_draft_pr_executor import validate_draft_pr_receipt


PACKET_SCHEMA = "beta4-pr-review-evidence-packet:v1"
PACKET_VALIDATION_SCHEMA = "beta4-pr-review-evidence-packet-validation:v1"
CAPTURE_SCHEMA = "beta4-pr-review-evidence-capture-report:v1"
PR_REVIEW_VIEW_FIELDS = (
    "number,url,isDraft,state,headRefName,headRefOid,baseRefName,title,"
    "reviewDecision,reviews,latestReviews,comments,statusCheckRollup,mergeStateStatus"
)
REVIEW_STATES = {
    "pending_no_review",
    "comment_observed_without_review",
    "review_observed_without_approval",
    "approved_review_observed",
    "changes_requested",
}
NON_CLAIMS = (
    "beta4_pr_review_evidence_is_l1_controlled_pilot_only",
    "beta4_pr_review_evidence_observes_github_review_state_only",
    "beta4_pr_review_evidence_does_not_create_or_approve_a_review",
    "beta4_pr_review_evidence_does_not_authorize_merge_or_deploy",
    "beta4_pr_review_evidence_does_not_claim_h3_production_readiness",
    "beta4_pr_review_evidence_does_not_write_production_receipts",
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    capture = subparsers.add_parser("capture", help="capture one GitHub draft PR review state packet")
    capture.add_argument("--draft-pr-receipt", required=True)
    capture.add_argument("--output", required=True)

    validate = subparsers.add_parser("validate", help="validate a review evidence packet")
    validate.add_argument("--packet", required=True)
    validate.add_argument("--output")

    args = parser.parse_args(argv)
    if args.command == "capture":
        report = capture_review_evidence(
            draft_pr_receipt_path=Path(args.draft_pr_receipt),
            output_path=Path(args.output),
        )
    elif args.command == "validate":
        report = validate_review_evidence_packet(Path(args.packet))
        if args.output:
            _write_json(Path(args.output), report)
    else:
        raise AssertionError(f"unknown command: {args.command}")
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    validation = report.get("validation")
    status = validation if isinstance(validation, dict) else report
    return 0 if status.get("passed") else 1


def capture_review_evidence(*, draft_pr_receipt_path: Path, output_path: Path) -> dict[str, Any]:
    failures: list[str] = []
    receipt = _load_draft_pr_receipt(draft_pr_receipt_path, failures)
    pr = _as_dict(receipt.get("draft_pr"), failures, "draft_pr")
    repo = _required_text(receipt.get("github_repo"), failures, "github_repo")
    number = pr.get("number")
    if not isinstance(number, int) or number <= 0:
        failures.append("draft_pr.number must be a positive integer")

    view_run: dict[str, Any] | None = None
    view = {}
    if not failures:
        view_run = _gh(
            failures,
            "pr",
            "view",
            str(number),
            "--repo",
            repo,
            "--json",
            PR_REVIEW_VIEW_FIELDS,
        )
        if view_run["returncode"] == 0:
            view = _parse_object(view_run.get("stdout"), failures, "gh pr view review JSON")
    if view:
        _validate_pr_binding(view, receipt, failures)
        observation = _review_observation(view, failures)
    else:
        observation = {}

    packet_written = False
    validation = None
    if not failures:
        packet = {
            "schema_version": PACKET_SCHEMA,
            "captured_at": _now(),
            "request_id": receipt["request_id"],
            "review_observation_scope": "github_draft_pr_review_state_only",
            "source_draft_pr_receipt": _artifact_ref(draft_pr_receipt_path),
            "source_git_push_receipt": receipt["source_git_push_receipt"],
            "source_commit_id": receipt["source_commit_id"],
            "source_branch": receipt["source_branch"],
            "github_repo": receipt["github_repo"],
            "base_branch": receipt["base_branch"],
            "draft_pr": receipt["draft_pr"],
            "github_pr_review_state": view,
            "review_observation": observation,
            "gh_view": view_run,
            "github_review_approval_observed": observation["review_state"] == "approved_review_observed",
            "merge_authorization_required": True,
            "git_actions_performed": {"commit": True, "push": True, "merge": False},
            "merge_allowed": False,
            "deploy_allowed": False,
            "production_runtime_execution_allowed": False,
            "production_receipt_write_allowed": False,
            "h3_boundary": _h3_boundary(),
            "non_claims": list(NON_CLAIMS),
        }
        _write_json(output_path, packet)
        packet_written = True
        validation = validate_review_evidence_packet(output_path)
        if validation["passed"] is not True:
            failures.extend(f"review evidence packet invalid: {reason}" for reason in validation["failure_reasons"])

    return {
        "schema_version": CAPTURE_SCHEMA,
        "passed": not failures,
        "packet_written": packet_written,
        "packet_path": str(output_path.resolve()) if packet_written else None,
        "packet_sha256": _sha256(output_path) if packet_written else None,
        "failure_reasons": failures,
        "checked_at": _now(),
        "source_draft_pr_receipt": _artifact_ref_or_path(draft_pr_receipt_path),
        "github_repo": receipt.get("github_repo"),
        "draft_pr_number": number,
        "review_observation": observation,
        "gh_view": view_run,
        "validation": validation,
        "merge_allowed": False,
        "deploy_allowed": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
        "h3_boundary": _h3_boundary(),
        "non_claims": list(NON_CLAIMS),
    }


def validate_review_evidence_packet(packet_path: Path) -> dict[str, Any]:
    failures: list[str] = []
    packet = _safe_read_json(packet_path, failures, "review evidence packet")
    if not isinstance(packet, dict):
        return _validation_report(packet_path, failures or ["review evidence packet must be an object"])
    if packet.get("schema_version") != PACKET_SCHEMA:
        failures.append(f"schema_version must be {PACKET_SCHEMA}")
    if packet.get("review_observation_scope") != "github_draft_pr_review_state_only":
        failures.append("review_observation_scope must be github_draft_pr_review_state_only")

    receipt_ref = _as_ref(packet.get("source_draft_pr_receipt"), failures, "source_draft_pr_receipt")
    receipt_path = _validate_ref_bytes(receipt_ref, failures, "source_draft_pr_receipt")
    receipt = _load_draft_pr_receipt(receipt_path, failures)
    for field in (
        "request_id",
        "source_git_push_receipt",
        "source_commit_id",
        "source_branch",
        "github_repo",
        "base_branch",
        "draft_pr",
    ):
        if packet.get(field) != receipt.get(field):
            failures.append(f"{field} must match draft PR receipt")

    view = _as_dict(packet.get("github_pr_review_state"), failures, "github_pr_review_state")
    _validate_pr_binding(view, receipt, failures)
    observation = _review_observation(view, failures)
    if packet.get("review_observation") != observation:
        failures.append("review_observation must match captured GitHub review state")
    if packet.get("github_review_approval_observed") is not (
        observation.get("review_state") == "approved_review_observed"
    ):
        failures.append("github_review_approval_observed must match review_observation")

    gh_view = _as_dict(packet.get("gh_view"), failures, "gh_view")
    if gh_view.get("returncode") != 0:
        failures.append("gh_view returncode must be zero")
    if packet.get("merge_authorization_required") is not True:
        failures.append("merge_authorization_required must be true")
    _validate_non_authority_boundary(packet, failures)
    _validate_h3_boundary(packet, failures)
    return _validation_report(packet_path, failures)


def _load_draft_pr_receipt(path: Path | None, failures: list[str]) -> dict[str, Any]:
    if path is None:
        return {}
    validation = validate_draft_pr_receipt(path)
    if validation.get("passed") is not True:
        failures.extend(f"draft PR receipt invalid: {reason}" for reason in validation.get("failure_reasons", []))
    receipt = _safe_read_json(path, failures, "draft PR receipt")
    if not isinstance(receipt, dict):
        return {}
    if receipt.get("schema_version") != DRAFT_PR_RECEIPT_SCHEMA:
        failures.append(f"draft PR receipt schema_version must be {DRAFT_PR_RECEIPT_SCHEMA}")
    return receipt


def _validate_pr_binding(view: dict[str, Any], receipt: dict[str, Any], failures: list[str]) -> None:
    draft_pr = _as_dict(receipt.get("draft_pr"), failures, "receipt draft_pr")
    expected = {
        "number": draft_pr.get("number"),
        "url": draft_pr.get("url"),
        "isDraft": True,
        "state": "OPEN",
        "headRefName": receipt.get("source_branch"),
        "headRefOid": receipt.get("source_commit_id"),
        "baseRefName": receipt.get("base_branch"),
        "title": draft_pr.get("title"),
    }
    for field, value in expected.items():
        if view.get(field) != value:
            failures.append(f"github_pr_review_state.{field} must match draft PR receipt")


def _review_observation(view: dict[str, Any], failures: list[str]) -> dict[str, Any]:
    reviews = _as_list(view.get("reviews"), failures, "github_pr_review_state.reviews")
    latest_reviews = _as_list(view.get("latestReviews"), failures, "github_pr_review_state.latestReviews")
    comments = _as_list(view.get("comments"), failures, "github_pr_review_state.comments")
    checks = _as_list(view.get("statusCheckRollup"), failures, "github_pr_review_state.statusCheckRollup")
    review_decision = str(view.get("reviewDecision") or "").strip().upper()
    review_states = sorted(
        {
            state
            for review in [*reviews, *latest_reviews]
            if isinstance(review, dict)
            for state in [str(review.get("state") or "").strip().upper()]
            if state
        }
    )
    if review_decision == "CHANGES_REQUESTED" or "CHANGES_REQUESTED" in review_states:
        state = "changes_requested"
    elif review_decision == "APPROVED" or "APPROVED" in review_states:
        state = "approved_review_observed"
    elif reviews or latest_reviews:
        state = "review_observed_without_approval"
    elif comments:
        state = "comment_observed_without_review"
    else:
        state = "pending_no_review"
    if state not in REVIEW_STATES:
        failures.append("review_state classification is unsupported")
    return {
        "review_state": state,
        "review_decision": review_decision,
        "review_count": len(reviews),
        "latest_review_count": len(latest_reviews),
        "comment_count": len(comments),
        "status_check_count": len(checks),
        "merge_state_status": str(view.get("mergeStateStatus") or "").strip(),
        "review_states": review_states,
    }


def _validate_non_authority_boundary(payload: dict[str, Any], failures: list[str]) -> None:
    if payload.get("git_actions_performed") != {"commit": True, "push": True, "merge": False}:
        failures.append("git_actions_performed must prove pushed branch without merge")
    for field in (
        "merge_allowed",
        "deploy_allowed",
        "production_runtime_execution_allowed",
        "production_receipt_write_allowed",
    ):
        if payload.get(field) is not False:
            failures.append(f"{field} must be false")


def _h3_boundary() -> dict[str, bool]:
    return {
        "h3_remains_blocked": True,
        "h3_production_readiness_claimed": False,
    }


def _validate_h3_boundary(payload: dict[str, Any], failures: list[str]) -> None:
    if payload.get("h3_boundary") != _h3_boundary():
        failures.append("h3_boundary must keep production readiness blocked")


def _validation_report(path: Path, failures: list[str]) -> dict[str, Any]:
    return {
        "schema_version": PACKET_VALIDATION_SCHEMA,
        "passed": not failures,
        "failure_reasons": failures,
        "checked_at": _now(),
        "packet_path": str(path.resolve()),
        "packet_sha256": _sha256(path) if path.is_file() else None,
        "non_claims": list(NON_CLAIMS),
    }


def _gh(failures: list[str], *args: str) -> dict[str, Any]:
    result = subprocess.run(["gh", *args], check=False, text=True, capture_output=True)
    run = {
        "command": " ".join(["gh", *args]),
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }
    if result.returncode != 0:
        failures.append(f"{run['command']} failed")
    return run


def _parse_object(value: Any, failures: list[str], label: str) -> dict[str, Any]:
    try:
        payload = json.loads(value if isinstance(value, str) else "")
    except Exception as exc:  # noqa: BLE001 - GitHub output is evidence input.
        failures.append(f"{label} could not be parsed: {exc}")
        return {}
    if not isinstance(payload, dict):
        failures.append(f"{label} must be an object")
        return {}
    return payload


def _safe_read_json(path: Path | None, failures: list[str], label: str) -> Any:
    if path is None:
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 - validators preserve artifact detail.
        failures.append(f"{label} could not be read: {exc}")
        return None
    if not isinstance(payload, dict):
        failures.append(f"{label} must be a JSON object")
        return None
    return payload


def _artifact_ref(path: Path) -> dict[str, str]:
    if not path.is_file():
        raise FileNotFoundError(f"artifact path is not a file: {path}")
    return {"path": str(path.resolve()), "sha256": _sha256(path)}


def _artifact_ref_or_path(path: Path) -> dict[str, str | None]:
    return {"path": str(path.resolve()), "sha256": _sha256(path) if path.is_file() else None}


def _validate_ref_bytes(ref: dict[str, Any], failures: list[str], label: str) -> Path | None:
    path_text = str(ref.get("path") or "").strip()
    if not path_text:
        failures.append(f"{label}.path must be a non-empty string")
        return None
    path = Path(path_text)
    if not path.is_file():
        failures.append(f"{label}.path is not a file: {path}")
        return None
    if ref.get("sha256") != _sha256(path):
        failures.append(f"{label}.sha256 does not match file bytes")
    return path


def _as_ref(value: Any, failures: list[str], label: str) -> dict[str, Any]:
    return _as_dict(value, failures, label)


def _as_dict(value: Any, failures: list[str], label: str) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    failures.append(f"{label} must be an object")
    return {}


def _as_list(value: Any, failures: list[str], label: str) -> list[Any]:
    if isinstance(value, list):
        return value
    failures.append(f"{label} must be an array")
    return []


def _required_text(value: Any, failures: list[str], label: str) -> str:
    text = value.strip() if isinstance(value, str) else ""
    if not text:
        failures.append(f"{label} must be a non-empty string")
    return text


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


if __name__ == "__main__":
    sys.exit(main())
