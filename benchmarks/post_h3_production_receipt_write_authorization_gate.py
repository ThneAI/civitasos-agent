"""Authorize controlled production runtime receipt writing after PostH3-D.

PostH3-E consumes a passed PostH3-D internal runtime execution summary and
authorizes a single controlled production runtime receipt write. This gate only
writes authorization artifacts. It does not write the production runtime receipt,
open public ingress, deploy, contact VMs, access production data, or mutate Git.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from benchmarks.i_gate_evidence import artifact_ref, check, object_value, read_json_object, sha256_file, sha256_json, write_json_object
from benchmarks.post_h3_first_internal_runtime_execution_gate import (
    CHAIN_SCHEMA as POST_H3D_SCHEMA,
    NO_PRODUCTION_SCHEMA as POST_H3D_NO_PRODUCTION_SCHEMA,
    OWNER_AUDIT_REVIEW_SCHEMA as POST_H3D_OWNER_AUDIT_REVIEW_SCHEMA,
    ROLLBACK_DECISION_SCHEMA as POST_H3D_ROLLBACK_DECISION_SCHEMA,
    STATUS_INDEX_SCHEMA as POST_H3D_STATUS_INDEX_SCHEMA,
    TASK_RECEIPT_SCHEMA as POST_H3D_TASK_RECEIPT_SCHEMA,
)

CHAIN_SCHEMA = "post-h3-production-receipt-write-authorization-chain:v1"
CONTEXT_SCHEMA = "post-h3e-post-h3d-context-validation:v1"
REQUEST_SCHEMA = "post-h3e-production-runtime-receipt-write-request:v1"
DECISION_SCHEMA = "post-h3e-production-runtime-receipt-write-decision:v1"
BOUNDARY_REPORT_SCHEMA = "post-h3e-production-runtime-receipt-write-boundary-report:v1"
AUTHORIZATION_SCHEMA = "post-h3e-production-runtime-receipt-write-authorization:v1"

ACCEPTED_OPERATOR_DECISION = "authorize_post_h3_controlled_production_runtime_receipt_write"
ACCEPTED_AUDIT_DECISION = "accept_post_h3d_evidence_for_receipt_write"
NON_CLAIMS = (
    "post_h3e_authorizes_receipt_write_only",
    "post_h3e_does_not_write_production_runtime_receipt",
    "post_h3e_does_not_execute_runtime",
    "post_h3e_does_not_contact_vm_targets",
    "post_h3e_does_not_deploy",
    "post_h3e_does_not_open_public_ingress",
    "post_h3e_does_not_access_production_data",
)


def run_gate(
    *,
    post_h3d_summary_path: Path,
    output_root: Path,
    operator_id: str = "operator-primary",
    operator_decision: str = ACCEPTED_OPERATOR_DECISION,
    audit_decision: str = ACCEPTED_AUDIT_DECISION,
    operator_statement: str = "Authorize one controlled production runtime receipt write for the passed PostH3-D execution.",
    ack_receipt_write_authorization: bool = False,
) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "context_validation": output_root / "post_h3e_post_h3d_context_validation.json",
        "receipt_write_request": output_root / "post_h3e_production_receipt_write_request.json",
        "receipt_write_decision": output_root / "post_h3e_production_receipt_write_decision.json",
        "boundary_report": output_root / "post_h3e_production_receipt_write_boundary_report.json",
        "receipt_write_authorization": output_root / "post_h3e_production_receipt_write_authorization.json",
        "summary": output_root / "post_h3e_production_receipt_write_authorization_summary.json",
    }
    context = validate_post_h3d_context(post_h3d_summary_path, output=artifacts["context_validation"])
    request = _write_request(context=context, post_h3d_summary_path=post_h3d_summary_path, output=artifacts["receipt_write_request"])
    decision = _write_decision(
        request_path=artifacts["receipt_write_request"],
        output=artifacts["receipt_write_decision"],
        operator_id=operator_id,
        operator_decision=operator_decision,
        audit_decision=audit_decision,
        operator_statement=operator_statement,
        ack_receipt_write_authorization=ack_receipt_write_authorization,
    )
    boundary = _write_boundary_report(
        context=context,
        request_path=artifacts["receipt_write_request"],
        decision_path=artifacts["receipt_write_decision"],
        output=artifacts["boundary_report"],
    )
    authorization = _write_authorization(
        context=context,
        request_path=artifacts["receipt_write_request"],
        decision_path=artifacts["receipt_write_decision"],
        boundary_report_path=artifacts["boundary_report"],
        output=artifacts["receipt_write_authorization"],
    )
    reports = [context, request, decision, boundary, authorization]
    passed = all(report.get("passed") is True for report in reports)
    summary = {
        "schema_version": CHAIN_SCHEMA,
        "passed": passed,
        "failure_reasons": _failures(reports),
        "checked_at": _now(),
        "source_artifacts": {"post_h3d_summary": artifact_ref(post_h3d_summary_path)},
        "artifacts": {name: artifact_ref(path) for name, path in artifacts.items() if name != "summary"},
        "task_id": object_value(context.get("post_h3d_summary")).get("task_id"),
        "authorization_id": authorization.get("authorization_id"),
        "readiness": {
            "state": "post_h3e_production_receipt_write_authorized" if passed else "blocked_post_h3e_production_receipt_write_authorization",
            "post_h3e_production_receipt_write_authorized": passed,
            "production_runtime_receipt_write_allowed": passed,
            "production_runtime_receipt_written": False,
            "public_ingress_authorized": False,
            "external_limited_release_ready": False,
        },
        "boundary": _boundary(
            context_validation_written=context.get("passed") is True,
            receipt_write_request_written=request.get("passed") is True,
            receipt_write_decision_written=decision.get("passed") is True,
            boundary_report_written=boundary.get("passed") is True,
            receipt_write_authorization_written=authorization.get("passed") is True,
            production_runtime_receipt_write_allowed=passed,
        ),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(artifacts["summary"], summary)
    return summary


def validate_post_h3d_context(post_h3d_summary_path: Path, *, output: Path | None = None) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    try:
        summary = read_json_object(post_h3d_summary_path)
    except Exception as exc:  # noqa: BLE001
        return _write_optional(_report(CONTEXT_SCHEMA, False, [f"post_h3d_summary_unreadable:{exc}"], checks), output)

    artifacts = object_value(summary.get("artifacts"))
    task_receipt = _read_verified_ref(artifacts.get("task_pool_execution_receipt"), checks, failures, "post_h3d_task_pool_execution_receipt")
    status_index = _read_verified_ref(artifacts.get("status_evidence_index"), checks, failures, "post_h3d_status_evidence_index")
    no_production = _read_verified_ref(artifacts.get("no_production_attestation"), checks, failures, "post_h3d_no_production_attestation")
    rollback = _read_verified_ref(artifacts.get("rollback_or_continue_decision"), checks, failures, "post_h3d_rollback_or_continue_decision")
    owner_review = _read_verified_ref(artifacts.get("owner_audit_review"), checks, failures, "post_h3d_owner_audit_review")

    readiness = object_value(summary.get("readiness"))
    boundary = object_value(summary.get("boundary"))
    task_id = str(summary.get("task_id") or "")
    _check_summary(summary, readiness, boundary, checks, failures)
    _check_artifacts(task_id, task_receipt, status_index, no_production, rollback, owner_review, checks, failures)
    passed = _passed(checks, failures)
    report = {
        "schema_version": CONTEXT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "post_h3d_summary": summary,
        "task_pool_execution_receipt": task_receipt,
        "status_evidence_index": status_index,
        "no_production_attestation": no_production,
        "rollback_or_continue_decision": rollback,
        "owner_audit_review": owner_review,
        "source_artifacts": {"post_h3d_summary": artifact_ref(post_h3d_summary_path)},
        "boundary": _boundary(context_validation_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    return _write_optional(report, output)


def _write_request(*, context: dict[str, Any], post_h3d_summary_path: Path, output: Path) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    summary = object_value(context.get("post_h3d_summary"))
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "task_id_present", bool(summary.get("task_id")))
    check(checks, failures, "receipt_write_not_already_allowed", object_value(summary.get("readiness")).get("production_runtime_receipt_write_allowed") is False)
    passed = _passed(checks, failures)
    request = {
        "schema_version": REQUEST_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "requested_at": _now(),
        "receipt_write_request": {
            "task_id": summary.get("task_id"),
            "source_task_id": summary.get("source_task_id"),
            "receipt_kind": "post_h3_internal_controlled_runtime_receipt",
            "write_mode": "single_controlled_receipt_write",
            "allowed_fields": [
                "task_id",
                "source_task_id",
                "post_h3d_summary_ref",
                "task_pool_execution_receipt_ref",
                "status_evidence_index_ref",
                "no_production_attestation_ref",
                "owner_audit_review_ref",
                "rollback_or_continue_decision_ref",
            ],
            "forbidden_actions": [
                "execute_runtime_again",
                "deploy",
                "open_public_ingress",
                "access_production_data",
                "write_source_or_git",
            ],
        },
        "source_artifacts": {"post_h3d_summary": artifact_ref(post_h3d_summary_path)},
        "boundary": _boundary(receipt_write_request_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, request)
    return request


def _write_decision(
    *,
    request_path: Path,
    output: Path,
    operator_id: str,
    operator_decision: str,
    audit_decision: str,
    operator_statement: str,
    ack_receipt_write_authorization: bool,
) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    request = read_json_object(request_path)
    check(checks, failures, "request_passed", request.get("schema_version") == REQUEST_SCHEMA and request.get("passed") is True)
    check(checks, failures, "operator_id_present", bool(operator_id.strip()))
    check(checks, failures, "operator_decision_accepted", operator_decision == ACCEPTED_OPERATOR_DECISION)
    check(checks, failures, "audit_decision_accepted", audit_decision == ACCEPTED_AUDIT_DECISION)
    check(checks, failures, "operator_statement_present", bool(operator_statement.strip()))
    check(checks, failures, "explicit_operator_ack", ack_receipt_write_authorization is True)
    passed = _passed(checks, failures)
    decision = {
        "schema_version": DECISION_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "decided_at": _now(),
        "operator_id": operator_id,
        "operator_decision": operator_decision,
        "audit_decision": audit_decision,
        "operator_statement": operator_statement,
        "operator_statement_sha256": sha256_json(operator_statement),
        "ack_receipt_write_authorization": ack_receipt_write_authorization,
        "source_artifacts": {"receipt_write_request": artifact_ref(request_path)},
        "boundary": _boundary(receipt_write_decision_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, decision)
    return decision


def _write_boundary_report(*, context: dict[str, Any], request_path: Path, decision_path: Path, output: Path) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    request = read_json_object(request_path)
    decision = read_json_object(decision_path)
    summary = object_value(context.get("post_h3d_summary"))
    boundary = object_value(summary.get("boundary"))
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "request_passed", request.get("passed") is True)
    check(checks, failures, "decision_passed", decision.get("passed") is True)
    check(checks, failures, "post_h3d_runtime_executed", object_value(summary.get("readiness")).get("runtime_execution_performed") is True)
    check(checks, failures, "post_h3d_no_receipt_written", boundary.get("production_runtime_receipt_written") is False)
    check(checks, failures, "post_h3d_no_public_ingress", boundary.get("external_public_ingress_opened") is False)
    check(checks, failures, "post_h3d_no_deploy", boundary.get("deploy_performed") is False)
    check(checks, failures, "post_h3d_no_production_data", boundary.get("production_data_accessed") is False)
    passed = _passed(checks, failures)
    report = {
        "schema_version": BOUNDARY_REPORT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "source_artifacts": {
            "post_h3d_context": object_value(context.get("source_artifacts")).get("post_h3d_summary"),
            "receipt_write_request": artifact_ref(request_path),
            "receipt_write_decision": artifact_ref(decision_path),
        },
        "boundary": _boundary(boundary_report_written=passed, production_runtime_receipt_write_allowed=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def _write_authorization(
    *,
    context: dict[str, Any],
    request_path: Path,
    decision_path: Path,
    boundary_report_path: Path,
    output: Path,
) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    request = read_json_object(request_path)
    decision = read_json_object(decision_path)
    boundary_report = read_json_object(boundary_report_path)
    summary = object_value(context.get("post_h3d_summary"))
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "request_passed", request.get("passed") is True)
    check(checks, failures, "decision_passed", decision.get("passed") is True)
    check(checks, failures, "boundary_report_passed", boundary_report.get("passed") is True)
    passed = _passed(checks, failures)
    auth_id = f"post-h3e-receipt-write-auth:{sha256_json([artifact_ref(request_path), artifact_ref(decision_path), artifact_ref(boundary_report_path)])[:24]}"
    authorization = {
        "schema_version": AUTHORIZATION_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "authorized_at": _now(),
        "authorization_id": auth_id,
        "single_use": True,
        "consumed": False,
        "task_id": summary.get("task_id"),
        "source_task_id": summary.get("source_task_id"),
        "receipt_write_scope": object_value(request.get("receipt_write_request")),
        "source_artifacts": {
            "receipt_write_request": artifact_ref(request_path),
            "receipt_write_decision": artifact_ref(decision_path),
            "boundary_report": artifact_ref(boundary_report_path),
        },
        "readiness": {
            "production_runtime_receipt_write_allowed": passed,
            "production_runtime_receipt_written": False,
        },
        "boundary": _boundary(receipt_write_authorization_written=passed, production_runtime_receipt_write_allowed=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, authorization)
    return authorization


def _check_summary(summary: dict[str, Any], readiness: dict[str, Any], boundary: dict[str, Any], checks: dict[str, bool], failures: list[str]) -> None:
    check(checks, failures, "post_h3d_schema_valid", summary.get("schema_version") == POST_H3D_SCHEMA)
    check(checks, failures, "post_h3d_passed", summary.get("passed") is True)
    check(checks, failures, "post_h3d_complete", readiness.get("post_h3d_first_internal_runtime_execution_complete") is True)
    check(checks, failures, "post_h3e_ready", readiness.get("post_h3e_production_receipt_write_authorization_ready") is True)
    check(checks, failures, "runtime_execution_performed", readiness.get("runtime_execution_performed") is True)
    check(checks, failures, "receipt_write_not_already_allowed", readiness.get("production_runtime_receipt_write_allowed") is False)
    check(checks, failures, "service_token_used", boundary.get("service_token_used") is True)
    check(checks, failures, "demo_login_not_used", boundary.get("demo_login_used") is False)
    check(checks, failures, "task_pool_path_complete", all(boundary.get(key) is True for key in ("task_pool_post_performed", "task_pool_claim_performed", "task_pool_execute_performed")))
    check(checks, failures, "no_vm_contact", boundary.get("vm_contact_performed") is False)
    check(checks, failures, "no_deploy", boundary.get("deploy_performed") is False)
    check(checks, failures, "no_public_ingress", boundary.get("external_public_ingress_opened") is False)
    check(checks, failures, "no_production_data", boundary.get("production_data_accessed") is False)
    check(checks, failures, "no_production_runtime_receipt_written", boundary.get("production_runtime_receipt_written") is False)


def _check_artifacts(
    task_id: str,
    task_receipt: dict[str, Any],
    status_index: dict[str, Any],
    no_production: dict[str, Any],
    rollback: dict[str, Any],
    owner_review: dict[str, Any],
    checks: dict[str, bool],
    failures: list[str],
) -> None:
    check(checks, failures, "task_receipt_passed", task_receipt.get("schema_version") == POST_H3D_TASK_RECEIPT_SCHEMA and task_receipt.get("passed") is True)
    check(checks, failures, "status_index_passed", status_index.get("schema_version") == POST_H3D_STATUS_INDEX_SCHEMA and status_index.get("passed") is True)
    check(checks, failures, "no_production_passed", no_production.get("schema_version") == POST_H3D_NO_PRODUCTION_SCHEMA and no_production.get("passed") is True)
    check(checks, failures, "rollback_decision_passed", rollback.get("schema_version") == POST_H3D_ROLLBACK_DECISION_SCHEMA and rollback.get("passed") is True)
    check(checks, failures, "owner_review_passed", owner_review.get("schema_version") == POST_H3D_OWNER_AUDIT_REVIEW_SCHEMA and owner_review.get("passed") is True)
    check(checks, failures, "artifact_task_ids_match", all(str(report.get("task_id") or "") == task_id for report in (task_receipt, status_index, no_production, rollback, owner_review)))
    check(checks, failures, "owner_review_supports_receipt_write", object_value(owner_review.get("post_h3e_candidate")).get("production_runtime_receipt_write_authorization_ready") is True)


def _read_verified_ref(value: Any, checks: dict[str, bool], failures: list[str], label: str) -> dict[str, Any]:
    ref = object_value(value)
    path = Path(str(ref.get("path") or ""))
    expected_hash = str(ref.get("sha256") or "")
    check(checks, failures, f"{label}_path_present", path.is_file())
    if not path.is_file():
        return {}
    check(checks, failures, f"{label}_hash_valid", bool(expected_hash) and sha256_file(path) == expected_hash)
    return read_json_object(path)


def _boundary(**overrides: bool) -> dict[str, bool]:
    boundary = {
        "context_validation_written": False,
        "receipt_write_request_written": False,
        "receipt_write_decision_written": False,
        "boundary_report_written": False,
        "receipt_write_authorization_written": False,
        "production_runtime_receipt_write_allowed": False,
        "production_runtime_receipt_written": False,
        "runtime_execution_performed": False,
        "vm_contact_performed": False,
        "deploy_performed": False,
        "external_public_ingress_opened": False,
        "production_data_accessed": False,
        "source_tree_write_performed": False,
        "git_write_performed": False,
        "secrets_recorded": False,
    }
    boundary.update(overrides)
    return boundary


def _report(schema: str, passed: bool, failures: list[str], checks: dict[str, bool]) -> dict[str, Any]:
    return {
        "schema_version": schema,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "boundary": _boundary(),
        "non_claims": list(NON_CLAIMS),
    }


def _write_optional(report: dict[str, Any], output: Path | None) -> dict[str, Any]:
    if output is not None:
        write_json_object(output, report)
    return report


def _failures(reports: list[dict[str, Any]]) -> list[str]:
    failures: list[str] = []
    for report in reports:
        failures.extend(str(item) for item in report.get("failure_reasons", []))
    return sorted(set(failures))


def _passed(checks: dict[str, bool], failures: list[str]) -> bool:
    return bool(checks) and all(checks.values()) and not failures


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def main() -> int:
    parser = argparse.ArgumentParser(description="Run PostH3-E production runtime receipt write authorization gate")
    parser.add_argument("--post-h3d-summary", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--operator-id", default="operator-primary")
    parser.add_argument("--operator-decision", default=ACCEPTED_OPERATOR_DECISION)
    parser.add_argument("--audit-decision", default=ACCEPTED_AUDIT_DECISION)
    parser.add_argument("--operator-statement", default="Authorize one controlled production runtime receipt write for the passed PostH3-D execution.")
    parser.add_argument("--ack-receipt-write-authorization", action="store_true")
    args = parser.parse_args()
    summary = run_gate(
        post_h3d_summary_path=args.post_h3d_summary,
        output_root=args.output_root,
        operator_id=args.operator_id,
        operator_decision=args.operator_decision,
        audit_decision=args.audit_decision,
        operator_statement=args.operator_statement,
        ack_receipt_write_authorization=args.ack_receipt_write_authorization,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if summary.get("passed") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
