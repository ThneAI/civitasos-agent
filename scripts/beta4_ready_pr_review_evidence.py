#!/usr/bin/env python3
"""Normalize a ready-for-review GitHub approval observation into Beta-4 evidence.

The original Beta-4 review evidence gate is intentionally draft-PR scoped. A
real GitHub approval, however, is only possible after the PR is ready for
review. This adapter consumes one valid cross-account approval observation and
writes a ready-PR review evidence packet that Beta-5 can authorize against.
It does not create reviews, merge, deploy, execute production runtime actions,
or write production receipts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from beta_approval_sandbox_observation import OBSERVATION_SCHEMA as APPROVAL_OBSERVATION_SCHEMA
from beta_approval_sandbox_observation import validate_approval_observation


PACKET_SCHEMA = "beta4-ready-pr-review-evidence-packet:v1"
PACKET_VALIDATION_SCHEMA = "beta4-ready-pr-review-evidence-packet-validation:v1"
WRITE_REPORT_SCHEMA = "beta4-ready-pr-review-evidence-write-report:v1"
APPROVED_REVIEW_STATE = "approved_review_observed"
NON_CLAIMS = (
    "beta4_ready_pr_review_evidence_is_l1_controlled_pilot_only",
    "beta4_ready_pr_review_evidence_observes_ready_pr_github_approval_only",
    "beta4_ready_pr_review_evidence_does_not_create_or_approve_a_review",
    "beta4_ready_pr_review_evidence_does_not_authorize_merge_or_deploy",
    "beta4_ready_pr_review_evidence_does_not_claim_h3_production_readiness",
    "beta4_ready_pr_review_evidence_does_not_write_production_receipts",
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    record = subparsers.add_parser("record", help="record ready PR review evidence from approval observation")
    record.add_argument("--approval-observation", required=True)
    record.add_argument("--output", required=True)

    validate = subparsers.add_parser("validate", help="validate a ready PR review evidence packet")
    validate.add_argument("--packet", required=True)
    validate.add_argument("--output")

    args = parser.parse_args(argv)
    if args.command == "record":
        report = record_ready_pr_review_evidence(
            approval_observation_path=Path(args.approval_observation),
            output_path=Path(args.output),
        )
    elif args.command == "validate":
        report = validate_ready_pr_review_evidence_packet(Path(args.packet))
        if args.output:
            _write_json(Path(args.output), report)
    else:
        raise AssertionError(f"unknown command: {args.command}")
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report.get("validation", report).get("passed") else 1


def record_ready_pr_review_evidence(*, approval_observation_path: Path, output_path: Path) -> dict[str, Any]:
    failures: list[str] = []
    observation = _load_approval_observation(approval_observation_path, failures)
    if failures:
        raise ValueError(f"ready PR review evidence blocked: {failures}")

    packet = _packet_from_observation(observation, approval_observation_path)
    _write_json(output_path, packet)
    validation = validate_ready_pr_review_evidence_packet(output_path)
    if validation["passed"] is not True:
        raise ValueError(f"written ready PR review evidence failed validation: {validation['failure_reasons']}")
    return {
        "schema_version": WRITE_REPORT_SCHEMA,
        "packet_written": True,
        "packet_path": str(output_path.resolve()),
        "packet_sha256": _sha256(output_path),
        "request_id": packet["request_id"],
        "github_repo": packet["github_repo"],
        "pr_number": packet["pr"]["number"],
        "validation": validation,
        "merge_allowed": False,
        "deploy_allowed": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
        "h3_boundary": _h3_boundary(),
        "non_claims": list(NON_CLAIMS),
    }


def validate_ready_pr_review_evidence_packet(packet_path: Path) -> dict[str, Any]:
    failures: list[str] = []
    packet = _safe_read_json(packet_path, failures, "ready PR review evidence packet")
    if not isinstance(packet, dict):
        return _validation_report(packet_path, failures or ["ready PR review evidence packet must be an object"])
    if packet.get("schema_version") != PACKET_SCHEMA:
        failures.append(f"schema_version must be {PACKET_SCHEMA}")
    if packet.get("review_observation_scope") != "github_ready_pr_review_state_only":
        failures.append("review_observation_scope must be github_ready_pr_review_state_only")

    observation_ref = _as_ref(packet.get("source_approval_observation"), failures, "source_approval_observation")
    observation_path = _validate_ref_bytes(observation_ref, failures, "source_approval_observation")
    observation = _load_approval_observation(observation_path, failures)
    expected = _packet_from_observation(observation, observation_path) if observation else {}
    for field in (
        "request_id",
        "source_approval_observation",
        "source_commit_id",
        "source_branch",
        "github_repo",
        "base_branch",
        "pr",
        "draft_pr",
        "github_pr_review_state",
        "review_observation",
        "github_review_approval_observed",
    ):
        if packet.get(field) != expected.get(field):
            failures.append(f"{field} must match approval observation")
    if packet.get("source_draft_pr_receipt") is not None:
        failures.append("source_draft_pr_receipt must be null for ready PR approval observation packets")
    if packet.get("source_git_push_receipt") is not None:
        failures.append("source_git_push_receipt must be null for ready PR approval observation packets")
    if packet.get("merge_authorization_required") is not True:
        failures.append("merge_authorization_required must be true")
    _validate_non_authority_boundary(packet, failures)
    _validate_h3_boundary(packet, failures)
    return _validation_report(packet_path, failures)


def _packet_from_observation(observation: dict[str, Any], observation_path: Path | None) -> dict[str, Any]:
    pr = {
        "number": observation.get("pr_number"),
        "url": observation.get("pr_url"),
        "isDraft": observation.get("is_draft"),
        "state": observation.get("pr_state"),
        "headRefName": observation.get("head_ref_name"),
        "headRefOid": observation.get("head_ref_oid"),
        "baseRefName": observation.get("base_ref_name"),
        "title": observation.get("pr_title"),
        "author": observation.get("pr_author"),
    }
    review_observation = {
        "review_state": APPROVED_REVIEW_STATE,
        "review_decision": observation.get("review_decision"),
        "review_count": observation.get("review_count"),
        "latest_review_count": observation.get("latest_review_count"),
        "comment_count": observation.get("comment_count"),
        "status_check_count": observation.get("status_check_count"),
        "merge_state_status": observation.get("merge_state_status"),
        "approvers": observation.get("approvers"),
        "expected_approver": observation.get("expected_approver"),
    }
    return {
        "schema_version": PACKET_SCHEMA,
        "captured_at": _now(),
        "request_id": _request_id(observation),
        "review_observation_scope": "github_ready_pr_review_state_only",
        "source_approval_observation": _artifact_ref(observation_path) if observation_path else None,
        "source_draft_pr_receipt": None,
        "source_git_push_receipt": None,
        "source_commit_id": observation.get("head_ref_oid"),
        "source_branch": observation.get("head_ref_name"),
        "github_repo": observation.get("github_repo"),
        "base_branch": observation.get("base_ref_name"),
        "pr": pr,
        "draft_pr": pr,
        "github_pr_review_state": observation.get("gh_view"),
        "review_observation": review_observation,
        "github_review_approval_observed": True,
        "merge_authorization_required": True,
        "git_actions_performed": {"commit": True, "push": True, "merge": False},
        "merge_allowed": False,
        "deploy_allowed": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
        "h3_boundary": _h3_boundary(),
        "non_claims": list(NON_CLAIMS),
    }


def _load_approval_observation(path: Path | None, failures: list[str]) -> dict[str, Any]:
    if path is None:
        return {}
    validation = validate_approval_observation(path)
    if validation.get("passed") is not True:
        failures.extend(
            f"approval observation invalid: {reason}" for reason in validation.get("failure_reasons", [])
        )
    observation = _safe_read_json(path, failures, "approval observation")
    if not isinstance(observation, dict):
        return {}
    if observation.get("schema_version") != APPROVAL_OBSERVATION_SCHEMA:
        failures.append(f"approval observation schema_version must be {APPROVAL_OBSERVATION_SCHEMA}")
    if observation.get("approval_observed") is not True:
        failures.append("approval_observed must be true")
    if observation.get("review_decision") != "APPROVED":
        failures.append("review_decision must be APPROVED")
    if observation.get("is_draft") is not False:
        failures.append("is_draft must be false for ready PR approval observation")
    return observation


def _request_id(observation: dict[str, Any]) -> str:
    repo = str(observation.get("github_repo") or "unknown-repo").replace("/", "_")
    number = observation.get("pr_number")
    return f"beta4-ready-review:{repo}:pr-{number}"


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


def _artifact_ref(path: Path | None) -> dict[str, str]:
    if path is None or not path.is_file():
        raise FileNotFoundError(f"artifact path is not a file: {path}")
    return {"path": str(path.resolve()), "sha256": _sha256(path)}


def _validate_ref_bytes(ref: dict[str, Any], failures: list[str], label: str) -> Path | None:
    path_text = _text(ref.get("path"))
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
    if isinstance(value, dict):
        return value
    failures.append(f"{label} must be an object")
    return {}


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
