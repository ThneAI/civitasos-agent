#!/usr/bin/env python3
"""Record Beta-9 post-review reconciliation evidence.

This gate reconciles a Beta-8 external Agent review response with a Beta-4
GitHub PR review-state packet and an explicit operator decision. It may mark a
post-review packet as ready for the next authorization gate only when GitHub
approval evidence is observed. It never performs merge, deploy, runtime
execution, or production receipt writes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from beta4_pr_review_evidence import PACKET_SCHEMA as BETA4_PACKET_SCHEMA
from beta4_pr_review_evidence import validate_review_evidence_packet
from beta4_ready_pr_review_evidence import PACKET_SCHEMA as BETA4_READY_PACKET_SCHEMA
from beta4_ready_pr_review_evidence import validate_ready_pr_review_evidence_packet
from beta8_external_agent_review_response import REVIEW_RESPONSE_SCHEMA
from beta8_external_agent_review_response import validate_review_response


RECONCILIATION_SCHEMA = "beta9-post-review-reconciliation:v1"
RECONCILIATION_VALIDATION_SCHEMA = "beta9-post-review-reconciliation-validation:v1"
RECONCILIATION_WRITE_SCHEMA = "beta9-post-review-reconciliation-write-report:v1"
OPERATOR_DECISIONS = (
    "blocked_pending_github_approval",
    "changes_required_followup",
    "ready_for_beta5_authorization",
    "no_action",
)
FORBIDDEN_TOKENS = ("TODO", "REPLACE", "PLACEHOLDER", "TEMPLATE_ONLY")
SUPPORTED_PR_REVIEW_PACKET_SCHEMAS = (BETA4_PACKET_SCHEMA, BETA4_READY_PACKET_SCHEMA)
NON_CLAIMS = (
    "beta9_reconciliation_is_l1_controlled_pilot_evidence_only",
    "beta9_reconciliation_does_not_replace_github_review_state_packet",
    "beta9_reconciliation_does_not_create_github_review_approval",
    "beta9_reconciliation_does_not_execute_beta5_merge_authorization",
    "beta9_reconciliation_does_not_perform_merge_or_deploy",
    "beta9_reconciliation_does_not_claim_h3_production_readiness",
    "beta9_reconciliation_does_not_write_production_receipts",
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    record = subparsers.add_parser("record", help="record post-review reconciliation evidence")
    record.add_argument("--review-response", required=True)
    record.add_argument("--pr-review-evidence", required=True)
    record.add_argument("--operator-decision", choices=OPERATOR_DECISIONS, required=True)
    record.add_argument("--reason", required=True)
    record.add_argument("--output", required=True)
    record.add_argument("--operator-id", default="post-review-reconciliation-operator-001")

    validate = subparsers.add_parser("validate", help="validate post-review reconciliation evidence")
    validate.add_argument("--reconciliation", required=True)
    validate.add_argument("--output")

    args = parser.parse_args(argv)
    if args.command == "record":
        report = record_reconciliation(
            review_response_path=Path(args.review_response),
            pr_review_evidence_path=Path(args.pr_review_evidence),
            operator_decision=args.operator_decision,
            reason=args.reason,
            output_path=Path(args.output),
            operator_id=args.operator_id,
        )
    elif args.command == "validate":
        report = validate_reconciliation(Path(args.reconciliation))
        if args.output:
            _write_json(Path(args.output), report)
    else:
        raise AssertionError(f"unknown command: {args.command}")
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report.get("validation", report).get("passed") else 1


def record_reconciliation(
    *,
    review_response_path: Path,
    pr_review_evidence_path: Path,
    operator_decision: str,
    reason: str,
    output_path: Path,
    operator_id: str,
) -> dict[str, Any]:
    failures: list[str] = []
    response = _load_valid_review_response(review_response_path, failures)
    pr_packet = _load_valid_pr_review_evidence(pr_review_evidence_path, failures)
    operator_id = _required_text(operator_id, "operator_id")
    reason = _required_text(reason, "reason")
    if operator_decision not in OPERATOR_DECISIONS:
        failures.append(f"operator_decision must be one of {list(OPERATOR_DECISIONS)}")
    _validate_pr_packet_was_task_source(response, pr_review_evidence_path, failures)
    outcome = _derive_outcome(response, pr_packet, operator_decision, failures)
    _reject_forbidden_text([operator_id, reason], failures)
    if failures:
        raise ValueError(f"post-review reconciliation blocked: {failures}")

    reconciliation = {
        "schema_version": RECONCILIATION_SCHEMA,
        "recorded_at": _now(),
        "reconciliation_scope": "post_review_upstream_evidence_reconciliation_only",
        "operator_id": operator_id,
        "operator_decision": operator_decision,
        "reason": reason,
        "source_review_response": _artifact_ref(review_response_path),
        "source_pr_review_evidence": _artifact_ref(pr_review_evidence_path),
        "external_agent_id": response["external_agent_id"],
        "external_review_verdict": response["review_verdict"],
        "external_response_channel": response["response_channel"],
        "github_review_state": pr_packet["review_observation"],
        "github_review_approval_observed": pr_packet["github_review_approval_observed"],
        "external_response_replaces_github_review_state": False,
        "operator_decision_recorded": True,
        "post_review_evidence_complete": True,
        "beta5_authorization_input_ready": outcome["beta5_authorization_input_ready"],
        "blocking_reason": outcome["blocking_reason"],
        "merge_authorized": False,
        "merge_performed": False,
        "deploy_allowed": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
        "h3_boundary": _h3_boundary(),
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(output_path, reconciliation)
    validation = validate_reconciliation(output_path)
    if validation["passed"] is not True:
        raise ValueError(f"written post-review reconciliation failed validation: {validation['failure_reasons']}")
    return {
        "schema_version": RECONCILIATION_WRITE_SCHEMA,
        "reconciliation_written": True,
        "reconciliation_path": str(output_path.resolve()),
        "reconciliation_sha256": _sha256(output_path),
        "operator_decision": operator_decision,
        "beta5_authorization_input_ready": outcome["beta5_authorization_input_ready"],
        "blocking_reason": outcome["blocking_reason"],
        "validation": validation,
        "non_claims": list(NON_CLAIMS),
    }


def validate_reconciliation(path: Path) -> dict[str, Any]:
    failures: list[str] = []
    reconciliation = _safe_read_json(path, failures, "post-review reconciliation")
    if not isinstance(reconciliation, dict):
        return _validation_report(path, failures or ["post-review reconciliation must be an object"])
    if reconciliation.get("schema_version") != RECONCILIATION_SCHEMA:
        failures.append(f"schema_version must be {RECONCILIATION_SCHEMA}")
    if reconciliation.get("reconciliation_scope") != "post_review_upstream_evidence_reconciliation_only":
        failures.append("reconciliation_scope must be post_review_upstream_evidence_reconciliation_only")
    for field in ("operator_id", "operator_decision", "reason", "external_agent_id", "external_review_verdict"):
        if not _text(reconciliation.get(field)):
            failures.append(f"{field} must be a non-empty string")
    if _text(reconciliation.get("operator_decision")) not in OPERATOR_DECISIONS:
        failures.append(f"operator_decision must be one of {list(OPERATOR_DECISIONS)}")
    response_path = _validate_ref_bytes(
        _as_ref(reconciliation.get("source_review_response"), failures, "source_review_response"),
        failures,
        "source_review_response",
    )
    pr_path = _validate_ref_bytes(
        _as_ref(reconciliation.get("source_pr_review_evidence"), failures, "source_pr_review_evidence"),
        failures,
        "source_pr_review_evidence",
    )
    response = _load_valid_review_response(response_path, failures)
    pr_packet = _load_valid_pr_review_evidence(pr_path, failures)
    _validate_pr_packet_was_task_source(response, pr_path, failures)
    expected_outcome = _derive_outcome(response, pr_packet, _text(reconciliation.get("operator_decision")), failures)
    if reconciliation.get("external_agent_id") != response.get("external_agent_id"):
        failures.append("external_agent_id must match review response")
    if reconciliation.get("external_review_verdict") != response.get("review_verdict"):
        failures.append("external_review_verdict must match review response")
    if reconciliation.get("external_response_channel") != response.get("response_channel"):
        failures.append("external_response_channel must match review response")
    if reconciliation.get("github_review_state") != pr_packet.get("review_observation"):
        failures.append("github_review_state must match PR review evidence packet")
    if reconciliation.get("github_review_approval_observed") is not pr_packet.get("github_review_approval_observed"):
        failures.append("github_review_approval_observed must match PR review evidence packet")
    if reconciliation.get("external_response_replaces_github_review_state") is not False:
        failures.append("external_response_replaces_github_review_state must be false")
    if reconciliation.get("operator_decision_recorded") is not True:
        failures.append("operator_decision_recorded must be true")
    if reconciliation.get("post_review_evidence_complete") is not True:
        failures.append("post_review_evidence_complete must be true")
    if reconciliation.get("beta5_authorization_input_ready") is not expected_outcome.get("beta5_authorization_input_ready"):
        failures.append("beta5_authorization_input_ready must match derived outcome")
    if reconciliation.get("blocking_reason") != expected_outcome.get("blocking_reason"):
        failures.append("blocking_reason must match derived outcome")
    for field in (
        "merge_authorized",
        "merge_performed",
        "deploy_allowed",
        "production_runtime_execution_allowed",
        "production_receipt_write_allowed",
    ):
        if reconciliation.get(field) is not False:
            failures.append(f"{field} must be false")
    _validate_h3_boundary(reconciliation, failures)
    return _validation_report(path, failures)


def _load_valid_review_response(path: Path | None, failures: list[str]) -> dict[str, Any]:
    if path is None:
        return {}
    validation = validate_review_response(path)
    if validation.get("passed") is not True:
        failures.extend(f"review response invalid: {reason}" for reason in validation.get("failure_reasons", []))
    response = _safe_read_json(path, failures, "external Agent review response")
    if not isinstance(response, dict):
        return {}
    if response.get("schema_version") != REVIEW_RESPONSE_SCHEMA:
        failures.append(f"review response schema_version must be {REVIEW_RESPONSE_SCHEMA}")
    return response


def _load_valid_pr_review_evidence(path: Path | None, failures: list[str]) -> dict[str, Any]:
    if path is None:
        return {}
    packet = _safe_read_json(path, failures, "PR review evidence packet")
    if not isinstance(packet, dict):
        return {}
    schema = packet.get("schema_version")
    if schema == BETA4_PACKET_SCHEMA:
        validation = validate_review_evidence_packet(path)
    elif schema == BETA4_READY_PACKET_SCHEMA:
        validation = validate_ready_pr_review_evidence_packet(path)
    else:
        failures.append(f"PR review evidence schema_version must be one of {SUPPORTED_PR_REVIEW_PACKET_SCHEMAS}")
        validation = {"passed": False, "failure_reasons": []}
    if validation.get("passed") is not True:
        failures.extend(f"PR review evidence invalid: {reason}" for reason in validation.get("failure_reasons", []))
    return packet


def _validate_pr_packet_was_task_source(response: dict[str, Any], pr_packet_path: Path | None, failures: list[str]) -> None:
    if pr_packet_path is None:
        return
    task_ref = _as_ref(response.get("source_task_invitation"), failures, "response.source_task_invitation")
    task_path = _validate_ref_bytes(task_ref, failures, "response.source_task_invitation")
    task = _safe_read_json(task_path, failures, "source task invitation") if task_path else {}
    refs = task.get("source_artifacts") if isinstance(task, dict) else None
    if not isinstance(refs, list):
        failures.append("source task invitation source_artifacts must be an array")
        return
    expected = _artifact_ref(pr_packet_path)
    if expected not in refs:
        failures.append("PR review evidence packet must be included in the Beta-7 task invitation source_artifacts")


def _derive_outcome(response: dict[str, Any], pr_packet: dict[str, Any], operator_decision: str, failures: list[str]) -> dict[str, Any]:
    external_verdict = _text(response.get("review_verdict"))
    github_approved = pr_packet.get("github_review_approval_observed") is True
    beta5_ready = external_verdict == "approved" and github_approved and operator_decision == "ready_for_beta5_authorization"
    if operator_decision == "ready_for_beta5_authorization" and not beta5_ready:
        failures.append("ready_for_beta5_authorization requires external approved verdict and GitHub approval evidence")
    if github_approved is False:
        blocking_reason = "github_review_approval_missing"
    elif external_verdict in {"changes_requested", "rejected", "inconclusive"}:
        blocking_reason = f"external_verdict_{external_verdict}"
    elif operator_decision != "ready_for_beta5_authorization":
        blocking_reason = f"operator_decision_{operator_decision}"
    else:
        blocking_reason = "none"
    return {
        "beta5_authorization_input_ready": beta5_ready,
        "blocking_reason": blocking_reason,
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
    if isinstance(value, dict):
        return value
    failures.append(f"{label} must be an object")
    return {}


def _reject_forbidden_text(values: list[str], failures: list[str]) -> None:
    upper_values = [value.upper() for value in values if value]
    for token in FORBIDDEN_TOKENS:
        if any(token in value for value in upper_values):
            failures.append(f"forbidden placeholder token found: {token}")
            return


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
        "schema_version": RECONCILIATION_VALIDATION_SCHEMA,
        "passed": not failures,
        "failure_reasons": failures,
        "checked_at": _now(),
        "reconciliation_path": str(path.resolve()),
        "reconciliation_sha256": _sha256(path) if path.is_file() else None,
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
