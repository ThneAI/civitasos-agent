#!/usr/bin/env python3
"""Record Beta-5 merge authorization after observed GitHub PR approval.

This gate consumes one valid Beta-4 PR review-state packet. It accepts the
original draft-PR packet or the ready-for-review approval packet, and only
records a fresh operator authorization when GitHub approval was observed in that
packet. It does not merge a PR, mark a draft ready, deploy, execute production
runtime actions, or write production receipts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from beta4_pr_review_evidence import PACKET_SCHEMA as REVIEW_PACKET_SCHEMA
from beta4_pr_review_evidence import validate_review_evidence_packet
from beta4_ready_pr_review_evidence import PACKET_SCHEMA as READY_REVIEW_PACKET_SCHEMA
from beta4_ready_pr_review_evidence import validate_ready_pr_review_evidence_packet
from beta9_review_reconciliation import RECONCILIATION_SCHEMA as REVIEW_RECONCILIATION_SCHEMA
from beta9_review_reconciliation import validate_reconciliation


AUTHORIZATION_SCHEMA = "beta5-post-review-merge-authorization:v1"
VALIDATION_SCHEMA = "beta5-post-review-merge-authorization-validation:v1"
WRITE_REPORT_SCHEMA = "beta5-post-review-merge-authorization-write-report:v1"
APPROVED_REVIEW_STATE = "approved_review_observed"
SUPPORTED_REVIEW_PACKET_SCHEMAS = (REVIEW_PACKET_SCHEMA, READY_REVIEW_PACKET_SCHEMA)
NON_CLAIMS = (
    "beta5_post_review_merge_authorization_is_l1_controlled_pilot_only",
    "beta5_post_review_merge_authorization_requires_observed_github_approval",
    "beta5_post_review_merge_authorization_does_not_merge_or_deploy",
    "beta5_post_review_merge_authorization_does_not_claim_h3_production_readiness",
    "beta5_post_review_merge_authorization_does_not_write_production_receipts",
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    record = subparsers.add_parser("record", help="record post-review merge authorization")
    record.add_argument("--review-evidence-packet", required=True)
    record.add_argument("--output", required=True)
    record.add_argument("--operator-id", default="l1-controlled-pilot-operator")
    record.add_argument("--reason", required=True)
    record.add_argument("--rollback-evidence-ref", required=True)
    record.add_argument(
        "--review-reconciliation",
        help="optional Beta-9 reconciliation artifact that must be ready for Beta-5 authorization",
    )

    validate = subparsers.add_parser("validate", help="validate post-review merge authorization")
    validate.add_argument("--authorization", required=True)
    validate.add_argument("--output")

    args = parser.parse_args(argv)
    if args.command == "record":
        report = record_post_review_merge_authorization(
            review_evidence_packet_path=Path(args.review_evidence_packet),
            output_path=Path(args.output),
            operator_id=args.operator_id,
            reason=args.reason,
            rollback_evidence_ref=args.rollback_evidence_ref,
            review_reconciliation_path=Path(args.review_reconciliation) if args.review_reconciliation else None,
        )
    elif args.command == "validate":
        report = validate_post_review_merge_authorization(Path(args.authorization))
        if args.output:
            _write_json(Path(args.output), report)
    else:
        raise AssertionError(f"unknown command: {args.command}")
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report.get("validation", report).get("passed") else 1


def record_post_review_merge_authorization(
    *,
    review_evidence_packet_path: Path,
    output_path: Path,
    operator_id: str,
    reason: str,
    rollback_evidence_ref: str,
    review_reconciliation_path: Path | None = None,
) -> dict[str, Any]:
    failures: list[str] = []
    packet = _load_approved_review_packet(review_evidence_packet_path, failures)
    reconciliation = _load_ready_review_reconciliation(
        review_reconciliation_path,
        review_evidence_packet_path,
        failures,
    )
    operator_id = _required_text(operator_id, "operator_id")
    reason = _required_text(reason, "reason")
    rollback_evidence_ref = _required_text(rollback_evidence_ref, "rollback_evidence_ref")
    if failures:
        raise ValueError(f"post-review merge authorization blocked: {failures}")

    authorization = {
        "schema_version": AUTHORIZATION_SCHEMA,
        "recorded_at": _now(),
        "request_id": packet["request_id"],
        "authorization_scope": "github_post_review_merge_only",
        "operator_id": operator_id,
        "reason": reason,
        "rollback_evidence_ref": rollback_evidence_ref,
        "source_review_evidence_packet": _artifact_ref(review_evidence_packet_path),
        "source_review_evidence_packet_schema": packet["schema_version"],
        "source_review_reconciliation": _artifact_ref(review_reconciliation_path) if review_reconciliation_path else None,
        "source_review_reconciliation_schema": reconciliation.get("schema_version") if reconciliation else None,
        "source_draft_pr_receipt": packet.get("source_draft_pr_receipt"),
        "source_git_push_receipt": packet.get("source_git_push_receipt"),
        "source_approval_observation": packet.get("source_approval_observation"),
        "source_commit_id": packet["source_commit_id"],
        "source_branch": packet["source_branch"],
        "github_repo": packet["github_repo"],
        "base_branch": packet["base_branch"],
        "pr": packet.get("pr", packet.get("draft_pr")),
        "draft_pr": packet.get("draft_pr", packet.get("pr")),
        "review_observation": packet["review_observation"],
        "github_review_approval_observed": True,
        "merge_authorized": True,
        "merge_performed": False,
        "git_actions_performed": {"commit": True, "push": True, "merge": False},
        "deploy_allowed": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
        "h3_boundary": _h3_boundary(),
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(output_path, authorization)
    validation = validate_post_review_merge_authorization(output_path)
    if validation["passed"] is not True:
        raise ValueError(f"written post-review merge authorization failed validation: {validation['failure_reasons']}")
    return {
        "schema_version": WRITE_REPORT_SCHEMA,
        "authorization_written": True,
        "authorization_path": str(output_path.resolve()),
        "authorization_sha256": _sha256(output_path),
        "request_id": packet["request_id"],
        "validation": validation,
        "non_claims": list(NON_CLAIMS),
    }


def validate_post_review_merge_authorization(path: Path) -> dict[str, Any]:
    failures: list[str] = []
    authorization = _safe_read_json(path, failures, "post-review merge authorization")
    if not isinstance(authorization, dict):
        return _validation_report(path, failures or ["post-review merge authorization must be an object"])
    if authorization.get("schema_version") != AUTHORIZATION_SCHEMA:
        failures.append(f"schema_version must be {AUTHORIZATION_SCHEMA}")
    if authorization.get("authorization_scope") != "github_post_review_merge_only":
        failures.append("authorization_scope must be github_post_review_merge_only")
    for field in ("operator_id", "reason", "rollback_evidence_ref"):
        if not _text(authorization.get(field)):
            failures.append(f"{field} must be a non-empty string")

    packet_ref = _as_ref(authorization.get("source_review_evidence_packet"), failures, "source_review_evidence_packet")
    packet_path = _validate_ref_bytes(packet_ref, failures, "source_review_evidence_packet")
    packet = _load_approved_review_packet(packet_path, failures)
    reconciliation_ref = authorization.get("source_review_reconciliation")
    if reconciliation_ref is not None:
        reconciliation_path = _validate_ref_bytes(
            _as_ref(reconciliation_ref, failures, "source_review_reconciliation"),
            failures,
            "source_review_reconciliation",
        )
        reconciliation = _load_ready_review_reconciliation(reconciliation_path, packet_path, failures)
        if authorization.get("source_review_reconciliation_schema") != reconciliation.get("schema_version"):
            failures.append("source_review_reconciliation_schema must match review reconciliation artifact")
    for field in (
        "request_id",
        "source_commit_id",
        "source_branch",
        "github_repo",
        "base_branch",
        "review_observation",
    ):
        if authorization.get(field) != packet.get(field):
            failures.append(f"{field} must match approved review evidence packet")
    if authorization.get("source_review_evidence_packet_schema") != packet.get("schema_version"):
        failures.append("source_review_evidence_packet_schema must match approved review evidence packet")
    for field in (
        "source_draft_pr_receipt",
        "source_git_push_receipt",
        "source_approval_observation",
    ):
        if authorization.get(field) != packet.get(field):
            failures.append(f"{field} must match approved review evidence packet")
    expected_pr = packet.get("pr", packet.get("draft_pr"))
    expected_draft_pr = packet.get("draft_pr", packet.get("pr"))
    if authorization.get("pr") != expected_pr:
        failures.append("pr must match approved review evidence packet")
    if authorization.get("draft_pr") != expected_draft_pr:
        failures.append("draft_pr must match approved review evidence packet")
    if authorization.get("github_review_approval_observed") is not True:
        failures.append("github_review_approval_observed must be true")
    if authorization.get("merge_authorized") is not True:
        failures.append("merge_authorized must be true")
    if authorization.get("merge_performed") is not False:
        failures.append("merge_performed must be false")
    if authorization.get("git_actions_performed") != {"commit": True, "push": True, "merge": False}:
        failures.append("git_actions_performed must prove pushed branch without merge")
    _validate_false_boundary_flags(authorization, failures)
    _validate_h3_boundary(authorization, failures)
    return _validation_report(path, failures)


def _load_approved_review_packet(path: Path | None, failures: list[str]) -> dict[str, Any]:
    if path is None:
        return {}
    packet = _safe_read_json(path, failures, "review evidence packet")
    if not isinstance(packet, dict):
        return {}
    schema = packet.get("schema_version")
    if schema == REVIEW_PACKET_SCHEMA:
        validation = validate_review_evidence_packet(path)
    elif schema == READY_REVIEW_PACKET_SCHEMA:
        validation = validate_ready_pr_review_evidence_packet(path)
    else:
        failures.append(f"review evidence packet schema_version must be one of {SUPPORTED_REVIEW_PACKET_SCHEMAS}")
        validation = {"passed": False, "failure_reasons": []}
    if validation.get("passed") is not True:
        failures.extend(f"review evidence packet invalid: {reason}" for reason in validation.get("failure_reasons", []))
    observation = _as_dict(packet.get("review_observation"), failures, "review_observation")
    if observation.get("review_state") != APPROVED_REVIEW_STATE:
        failures.append(f"review_observation.review_state must be {APPROVED_REVIEW_STATE}")
    if packet.get("github_review_approval_observed") is not True:
        failures.append("review evidence packet must observe GitHub review approval")
    return packet


def _load_ready_review_reconciliation(
    path: Path | None,
    review_evidence_packet_path: Path | None,
    failures: list[str],
) -> dict[str, Any]:
    if path is None:
        return {}
    validation = validate_reconciliation(path)
    if validation.get("passed") is not True:
        failures.extend(f"review reconciliation invalid: {reason}" for reason in validation.get("failure_reasons", []))
    reconciliation = _safe_read_json(path, failures, "review reconciliation")
    if not isinstance(reconciliation, dict):
        return {}
    if reconciliation.get("schema_version") != REVIEW_RECONCILIATION_SCHEMA:
        failures.append(f"review reconciliation schema_version must be {REVIEW_RECONCILIATION_SCHEMA}")
    if reconciliation.get("beta5_authorization_input_ready") is not True:
        failures.append("review reconciliation must have beta5_authorization_input_ready=true")
    if reconciliation.get("merge_authorized") is not False:
        failures.append("review reconciliation must not authorize merge")
    if reconciliation.get("deploy_allowed") is not False:
        failures.append("review reconciliation must not allow deploy")
    if reconciliation.get("h3_boundary") != _h3_boundary():
        failures.append("review reconciliation must keep H.3 blocked")
    if review_evidence_packet_path is not None:
        source_pr = _as_ref(
            reconciliation.get("source_pr_review_evidence"),
            failures,
            "review_reconciliation.source_pr_review_evidence",
        )
        if source_pr != _artifact_ref(review_evidence_packet_path):
            failures.append("review reconciliation source_pr_review_evidence must match authorization review evidence packet")
    return reconciliation


def _validate_false_boundary_flags(payload: dict[str, Any], failures: list[str]) -> None:
    for field in (
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
        "schema_version": VALIDATION_SCHEMA,
        "passed": not failures,
        "failure_reasons": failures,
        "checked_at": _now(),
        "authorization_path": str(path.resolve()),
        "authorization_sha256": _sha256(path) if path.is_file() else None,
        "non_claims": list(NON_CLAIMS),
    }


def _artifact_ref(path: Path) -> dict[str, str]:
    if not path.is_file():
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
    return _as_dict(value, failures, label)


def _as_dict(value: Any, failures: list[str], label: str) -> dict[str, Any]:
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
