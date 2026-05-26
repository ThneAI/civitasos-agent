#!/usr/bin/env python3
"""Capture and validate real GitHub cross-account approval observation.

This helper is intentionally narrower than Beta-5. It proves that a real GitHub
PR approval can be observed from an auxiliary repository. It does not authorize
merge, deploy, runtime execution, or production receipt writes.
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


OBSERVATION_SCHEMA = "beta-approval-sandbox-observation:v1"
VALIDATION_SCHEMA = "beta-approval-sandbox-observation-validation:v1"
CAPTURE_SCHEMA = "beta-approval-sandbox-observation-capture-report:v1"
VIEW_FIELDS = (
    "number,url,isDraft,state,headRefName,headRefOid,baseRefName,title,author,"
    "reviewDecision,reviews,latestReviews,comments,statusCheckRollup,mergeStateStatus"
)
NON_CLAIMS = (
    "approval_sandbox_observation_is_l1_controlled_validation_only",
    "approval_sandbox_observation_does_not_replace_beta4_review_packet",
    "approval_sandbox_observation_does_not_execute_beta5_authorization",
    "approval_sandbox_observation_does_not_merge_or_deploy",
    "approval_sandbox_observation_does_not_claim_h3_production_readiness",
    "approval_sandbox_observation_does_not_write_production_receipts",
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    capture = subparsers.add_parser("capture", help="capture real GitHub approval observation")
    capture.add_argument("--github-repo", required=True)
    capture.add_argument("--pr-number", type=int, required=True)
    capture.add_argument("--expected-author", required=True)
    capture.add_argument("--expected-approver", required=True)
    capture.add_argument("--output", required=True)

    validate = subparsers.add_parser("validate", help="validate approval observation")
    validate.add_argument("--observation", required=True)
    validate.add_argument("--output")

    args = parser.parse_args(argv)
    if args.command == "capture":
        report = capture_approval_observation(
            github_repo=args.github_repo,
            pr_number=args.pr_number,
            expected_author=args.expected_author,
            expected_approver=args.expected_approver,
            output_path=Path(args.output),
        )
    elif args.command == "validate":
        report = validate_approval_observation(Path(args.observation))
        if args.output:
            _write_json(Path(args.output), report)
    else:
        raise AssertionError(f"unknown command: {args.command}")
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report.get("validation", report).get("passed") else 1


def capture_approval_observation(
    *,
    github_repo: str,
    pr_number: int,
    expected_author: str,
    expected_approver: str,
    output_path: Path,
) -> dict[str, Any]:
    failures: list[str] = []
    github_repo = _required_text(github_repo, "github_repo")
    expected_author = _required_text(expected_author, "expected_author")
    expected_approver = _required_text(expected_approver, "expected_approver")
    if pr_number <= 0:
        failures.append("pr_number must be positive")
    view_run = _gh(failures, "pr", "view", str(pr_number), "--repo", github_repo, "--json", VIEW_FIELDS)
    view = _parse_object(view_run.get("stdout"), failures, "gh pr view JSON") if view_run["returncode"] == 0 else {}
    if not failures:
        observation = _build_observation(github_repo, pr_number, view, view_run, expected_author, expected_approver)
        _write_json(output_path, observation)
        validation = validate_approval_observation(output_path)
        if validation["passed"] is not True:
            failures.extend(f"approval observation invalid: {reason}" for reason in validation["failure_reasons"])
    else:
        validation = None
    return {
        "schema_version": CAPTURE_SCHEMA,
        "passed": not failures,
        "observation_written": output_path.is_file() and not failures,
        "observation_path": str(output_path.resolve()) if output_path.is_file() else None,
        "observation_sha256": _sha256(output_path) if output_path.is_file() else None,
        "failure_reasons": failures,
        "checked_at": _now(),
        "github_repo": github_repo,
        "pr_number": pr_number,
        "expected_author": expected_author,
        "expected_approver": expected_approver,
        "validation": validation,
        "non_claims": list(NON_CLAIMS),
    }


def validate_approval_observation(path: Path) -> dict[str, Any]:
    failures: list[str] = []
    observation = _safe_read_json(path, failures, "approval observation")
    if not isinstance(observation, dict):
        return _validation_report(path, failures or ["approval observation must be an object"])
    if observation.get("schema_version") != OBSERVATION_SCHEMA:
        failures.append(f"schema_version must be {OBSERVATION_SCHEMA}")
    if observation.get("observation_scope") != "github_cross_account_approval_observation_only":
        failures.append("observation_scope must be github_cross_account_approval_observation_only")
    for field in ("github_repo", "pr_url", "expected_author", "expected_approver", "pr_author"):
        if not _text(observation.get(field)):
            failures.append(f"{field} must be a non-empty string")
    if not isinstance(observation.get("pr_number"), int) or observation.get("pr_number") <= 0:
        failures.append("pr_number must be a positive integer")
    if observation.get("pr_state") != "OPEN":
        failures.append("pr_state must be OPEN")
    if observation.get("is_draft") is not False:
        failures.append("is_draft must be false because GitHub approval is a ready-for-review PR fact")
    if observation.get("review_decision") != "APPROVED":
        failures.append("review_decision must be APPROVED")
    if observation.get("approval_observed") is not True:
        failures.append("approval_observed must be true")
    if observation.get("pr_author") != observation.get("expected_author"):
        failures.append("pr_author must match expected_author")
    if observation.get("expected_approver") not in observation.get("approvers", []):
        failures.append("expected_approver must appear in approvers")
    if observation.get("expected_approver") == observation.get("pr_author"):
        failures.append("expected_approver must differ from pr_author")
    if observation.get("merge_state_status") not in {"CLEAN", "HAS_HOOKS", "UNKNOWN", "UNSTABLE", "BLOCKED", "BEHIND", "DIRTY"}:
        failures.append("merge_state_status must be a GitHub mergeStateStatus string")
    for field in (
        "beta4_review_packet_replaced",
        "beta5_authorization_executed",
        "merge_performed",
        "deploy_allowed",
        "production_runtime_execution_allowed",
        "production_receipt_write_allowed",
    ):
        if observation.get(field) is not False:
            failures.append(f"{field} must be false")
    if observation.get("h3_boundary") != _h3_boundary():
        failures.append("h3_boundary must keep production readiness blocked")
    return _validation_report(path, failures)


def _build_observation(
    github_repo: str,
    pr_number: int,
    view: dict[str, Any],
    view_run: dict[str, Any],
    expected_author: str,
    expected_approver: str,
) -> dict[str, Any]:
    reviews = view.get("reviews") if isinstance(view.get("reviews"), list) else []
    latest_reviews = view.get("latestReviews") if isinstance(view.get("latestReviews"), list) else []
    approvers = sorted({
        _text(_as_dict(review.get("author")).get("login"))
        for review in [*reviews, *latest_reviews]
        if _text(review.get("state")) == "APPROVED"
    } - {""})
    author = _text(_as_dict(view.get("author")).get("login"))
    return {
        "schema_version": OBSERVATION_SCHEMA,
        "captured_at": _now(),
        "observation_scope": "github_cross_account_approval_observation_only",
        "github_repo": github_repo,
        "pr_number": pr_number,
        "pr_url": _text(view.get("url")),
        "pr_title": _text(view.get("title")),
        "pr_state": _text(view.get("state")),
        "is_draft": view.get("isDraft"),
        "head_ref_name": _text(view.get("headRefName")),
        "head_ref_oid": _text(view.get("headRefOid")),
        "base_ref_name": _text(view.get("baseRefName")),
        "expected_author": expected_author,
        "expected_approver": expected_approver,
        "pr_author": author,
        "review_decision": _text(view.get("reviewDecision")),
        "approval_observed": _text(view.get("reviewDecision")) == "APPROVED" and expected_approver in approvers,
        "approvers": approvers,
        "review_count": len(reviews),
        "latest_review_count": len(latest_reviews),
        "comment_count": len(view.get("comments") if isinstance(view.get("comments"), list) else []),
        "status_check_count": len(view.get("statusCheckRollup") if isinstance(view.get("statusCheckRollup"), list) else []),
        "merge_state_status": _text(view.get("mergeStateStatus")),
        "gh_view": view_run,
        "beta4_review_packet_replaced": False,
        "beta5_authorization_executed": False,
        "merge_performed": False,
        "deploy_allowed": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
        "h3_boundary": _h3_boundary(),
        "non_claims": list(NON_CLAIMS),
    }


def _gh(failures: list[str], *args: str) -> dict[str, Any]:
    command = ["gh", *args]
    run = subprocess.run(command, text=True, capture_output=True)
    result = {
        "command": " ".join(command),
        "returncode": run.returncode,
        "stdout": run.stdout,
        "stderr": run.stderr,
    }
    if run.returncode != 0:
        failures.append(f"gh command failed: {' '.join(command)}: {run.stderr.strip()}")
    return result


def _parse_object(text: Any, failures: list[str], label: str) -> dict[str, Any]:
    try:
        value = json.loads(text or "{}")
    except json.JSONDecodeError as exc:
        failures.append(f"{label} could not be parsed: {exc}")
        return {}
    if not isinstance(value, dict):
        failures.append(f"{label} must be an object")
        return {}
    return value


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _h3_boundary() -> dict[str, bool]:
    return {
        "h3_remains_blocked": True,
        "h3_production_readiness_claimed": False,
    }


def _validation_report(path: Path, failures: list[str]) -> dict[str, Any]:
    return {
        "schema_version": VALIDATION_SCHEMA,
        "passed": not failures,
        "failure_reasons": failures,
        "checked_at": _now(),
        "observation_path": str(path.resolve()),
        "observation_sha256": _sha256(path) if path.is_file() else None,
        "non_claims": list(NON_CLAIMS),
    }


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


def _required_text(value: Any, field: str) -> str:
    text = _text(value)
    if not text:
        raise ValueError(f"{field} must be a non-empty string")
    return text


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


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
