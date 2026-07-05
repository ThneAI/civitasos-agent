"""PostH3 minimal production task authorization gate.

This gate consumes a passed minimal production task intake summary and writes a
single-use execution authorization receipt. It authorizes only the next execute
gate to attempt the bounded task. It does not post, claim, execute, deploy,
open public ingress, access production data, write production receipts, or
touch source/Git.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from benchmarks.i_gate_evidence import artifact_ref, check, object_value, read_json_object, sha256_file, sha256_json, write_json_object
from benchmarks.post_h3_minimal_production_task_intake_gate import (
    CHAIN_SCHEMA as INTAKE_CHAIN_SCHEMA,
    INTAKE_PACKET_SCHEMA,
    REQUIRED_FORBIDDEN_ACTIONS,
    RISK_BOUNDARY_SCHEMA,
    ROLLBACK_RUNBOOK_SCHEMA,
)

CHAIN_SCHEMA = "post-h3-minimal-production-task-authorization-chain:v1"
CONTEXT_SCHEMA = "post-h3-minimal-production-task-authorization-context-validation:v1"
AUTHORIZATION_REQUEST_SCHEMA = "post-h3-minimal-production-task-authorization-request:v1"
AUTHORIZATION_DECISION_SCHEMA = "post-h3-minimal-production-task-authorization-decision:v1"
AUTHORIZATION_RECEIPT_SCHEMA = "post-h3-minimal-production-task-authorization-receipt:v1"

OPERATOR_DECISION_AUTHORIZE = "authorize_once"
OWNER_DECISION_ACCEPT = "approve_minimal_production_task"
AUDIT_DECISION_ACCEPT = "accept_no_production_boundary"
ROLLBACK_DECISION_ACCEPT = "accept_rollback_abort_runbook"
MONITORING_DECISION_ACCEPT = "accept_monitoring_scope"
REVISION_DECISION = "request_revision"

NON_CLAIMS = (
    "minimal_production_task_authorization_is_single_use",
    "minimal_production_task_authorization_does_not_execute_runtime_task",
    "minimal_production_task_authorization_does_not_open_public_ingress",
    "minimal_production_task_authorization_does_not_deploy",
    "minimal_production_task_authorization_does_not_access_production_data",
    "minimal_production_task_authorization_does_not_write_production_runtime_receipts",
    "minimal_production_task_authorization_does_not_write_source_or_git",
)


def run_gate(
    *,
    intake_summary_path: Path,
    output_root: Path,
    operator_id: str = "operator-primary",
    operator_decision: str = OPERATOR_DECISION_AUTHORIZE,
    owner_decision: str = OWNER_DECISION_ACCEPT,
    audit_decision: str = AUDIT_DECISION_ACCEPT,
    rollback_decision: str = ROLLBACK_DECISION_ACCEPT,
    monitoring_decision: str = MONITORING_DECISION_ACCEPT,
    operator_statement: str = "Authorize one bounded minimal production task execution attempt.",
    ack_single_use_authorization: bool = False,
) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "context_validation": output_root / "post_h3_minimal_task_authorization_context_validation.json",
        "authorization_request": output_root / "post_h3_minimal_task_authorization_request.json",
        "authorization_decision": output_root / "post_h3_minimal_task_authorization_decision.json",
        "authorization_receipt": output_root / "post_h3_minimal_task_authorization_receipt.json",
        "summary": output_root / "post_h3_minimal_task_authorization_summary.json",
    }
    context = validate_intake_context(intake_summary_path, output=artifacts["context_validation"])
    request = _write_authorization_request(context=context, intake_summary_path=intake_summary_path, output=artifacts["authorization_request"])
    decision = _write_authorization_decision(
        request_path=artifacts["authorization_request"],
        output=artifacts["authorization_decision"],
        operator_id=operator_id,
        operator_decision=operator_decision,
        owner_decision=owner_decision,
        audit_decision=audit_decision,
        rollback_decision=rollback_decision,
        monitoring_decision=monitoring_decision,
        operator_statement=operator_statement,
        ack_single_use_authorization=ack_single_use_authorization,
    )
    receipt = _write_authorization_receipt(request_path=artifacts["authorization_request"], decision_path=artifacts["authorization_decision"], output=artifacts["authorization_receipt"])
    reports = [context, request, decision, receipt]
    passed = all(report.get("passed") is True for report in reports)
    task = object_value(context.get("task_request"))
    summary = {
        "schema_version": CHAIN_SCHEMA,
        "passed": passed,
        "failure_reasons": _failures(reports),
        "checked_at": _now(),
        "task_id": task.get("task_id"),
        "operator_id": operator_id,
        "source_artifacts": {"intake_summary": artifact_ref(intake_summary_path)},
        "artifacts": {name: artifact_ref(path) for name, path in artifacts.items() if name != "summary"},
        "authorization": {
            "authorization_id": receipt.get("authorization_id"),
            "decision": decision.get("decision"),
            "single_use": receipt.get("single_use") is True,
            "consumed": receipt.get("consumed") is True,
            "expires_at": receipt.get("expires_at"),
        },
        "readiness": {
            "state": "post_h3_minimal_production_task_authorized" if passed else "blocked_post_h3_minimal_production_task_authorization",
            "minimal_production_task_authorized": passed,
            "execution_gate_input_ready": passed,
            "single_use_execution_authorized": passed,
            "production_task_execution_allowed": passed,
            "runtime_execution_performed": False,
            "production_runtime_receipt_write_allowed": False,
        },
        "boundary": _closed_boundary(
            context_validation_written=context.get("passed") is True,
            authorization_request_written=request.get("passed") is True,
            authorization_decision_written=decision.get("passed") is True,
            authorization_receipt_written=receipt.get("passed") is True,
            single_use_execution_authorized=passed,
        ),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(artifacts["summary"], summary)
    return summary


def validate_intake_context(intake_summary_path: Path, *, output: Path | None = None) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    try:
        summary = read_json_object(intake_summary_path)
    except Exception as exc:  # noqa: BLE001
        return _write_optional(_report(CONTEXT_SCHEMA, False, [f"intake_summary_unreadable:{exc}"], checks), output)
    artifacts = object_value(summary.get("artifacts"))
    intake_packet = _read_verified_ref(artifacts.get("intake_packet"), checks, failures, "intake_packet")
    risk_boundary = _read_verified_ref(artifacts.get("risk_boundary"), checks, failures, "risk_boundary")
    rollback_runbook = _read_verified_ref(artifacts.get("rollback_runbook"), checks, failures, "rollback_runbook")
    readiness = object_value(summary.get("readiness"))
    boundary = object_value(summary.get("boundary"))
    task = object_value(intake_packet.get("task_request"))
    scope = object_value(task.get("scope"))
    check(checks, failures, "intake_summary_schema", summary.get("schema_version") == INTAKE_CHAIN_SCHEMA)
    check(checks, failures, "intake_summary_passed", summary.get("passed") is True)
    check(checks, failures, "intake_ready", readiness.get("minimal_production_task_intake_ready") is True)
    check(checks, failures, "authorization_gate_input_ready", readiness.get("authorization_gate_input_ready") is True)
    check(checks, failures, "intake_no_execution_allowed", readiness.get("production_task_execution_allowed") is False)
    _check_no_side_effect_boundary("intake_summary", boundary, checks, failures)
    check(checks, failures, "intake_packet_schema", intake_packet.get("schema_version") == INTAKE_PACKET_SCHEMA and intake_packet.get("passed") is True)
    check(checks, failures, "risk_boundary_schema", risk_boundary.get("schema_version") == RISK_BOUNDARY_SCHEMA and risk_boundary.get("passed") is True)
    check(checks, failures, "rollback_runbook_schema", rollback_runbook.get("schema_version") == ROLLBACK_RUNBOOK_SCHEMA and rollback_runbook.get("passed") is True)
    check(checks, failures, "task_id_present", bool(str(task.get("task_id") or "").strip()))
    check(checks, failures, "task_risk_low", task.get("risk_class") == "low")
    check(checks, failures, "single_runtime_task", scope.get("max_runtime_tasks") == 1)
    check(checks, failures, "no_external_users", scope.get("max_external_users") == 0)
    check(checks, failures, "forbidden_actions_complete", REQUIRED_FORBIDDEN_ACTIONS <= set(_texts(scope.get("forbidden_actions"))))
    passed = _passed(checks, failures)
    report = {
        "schema_version": CONTEXT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "intake_summary": summary,
        "intake_packet": intake_packet,
        "risk_boundary": risk_boundary,
        "rollback_runbook": rollback_runbook,
        "task_request": task,
        "source_artifacts": {"intake_summary": artifact_ref(intake_summary_path)},
        "boundary": _closed_boundary(context_validation_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    return _write_optional(report, output)


def _write_authorization_request(*, context: dict[str, Any], intake_summary_path: Path, output: Path) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    task = object_value(context.get("task_request"))
    scope = object_value(task.get("scope"))
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "task_id_present", bool(str(task.get("task_id") or "").strip()))
    check(checks, failures, "risk_class_low", task.get("risk_class") == "low")
    check(checks, failures, "single_runtime_task", scope.get("max_runtime_tasks") == 1)
    check(checks, failures, "forbidden_actions_complete", REQUIRED_FORBIDDEN_ACTIONS <= set(_texts(scope.get("forbidden_actions"))))
    passed = _passed(checks, failures)
    request = {
        "schema_version": AUTHORIZATION_REQUEST_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "requested_at": _now(),
        "authorization_kind": "single_use_minimal_production_task_execution",
        "task_request": task,
        "required_next_gate": "post_h3_minimal_production_task_execution_gate",
        "source_artifacts": {"intake_summary": artifact_ref(intake_summary_path)},
        "readiness": {
            "operator_decision_ready": passed,
            "production_task_execution_allowed": False,
        },
        "boundary": _closed_boundary(authorization_request_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, request)
    return request


def _write_authorization_decision(
    *,
    request_path: Path,
    output: Path,
    operator_id: str,
    operator_decision: str,
    owner_decision: str,
    audit_decision: str,
    rollback_decision: str,
    monitoring_decision: str,
    operator_statement: str,
    ack_single_use_authorization: bool,
) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    request = read_json_object(request_path)
    accepted = (
        operator_decision == OPERATOR_DECISION_AUTHORIZE
        and owner_decision == OWNER_DECISION_ACCEPT
        and audit_decision == AUDIT_DECISION_ACCEPT
        and rollback_decision == ROLLBACK_DECISION_ACCEPT
        and monitoring_decision == MONITORING_DECISION_ACCEPT
    )
    check(checks, failures, "authorization_request_passed", request.get("schema_version") == AUTHORIZATION_REQUEST_SCHEMA and request.get("passed") is True)
    check(checks, failures, "operator_id_present", bool(str(operator_id).strip()))
    check(checks, failures, "operator_statement_present", bool(str(operator_statement).strip()))
    check(checks, failures, "explicit_single_use_authorization_ack", ack_single_use_authorization is True)
    check(checks, failures, "all_owner_roles_accept", accepted)
    passed = _passed(checks, failures)
    decision = {
        "schema_version": AUTHORIZATION_DECISION_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "decided_at": _now(),
        "operator_id": operator_id,
        "decision": OPERATOR_DECISION_AUTHORIZE if passed else REVISION_DECISION,
        "operator_decision": operator_decision,
        "owner_decision": owner_decision,
        "audit_decision": audit_decision,
        "rollback_decision": rollback_decision,
        "monitoring_decision": monitoring_decision,
        "operator_statement": operator_statement,
        "operator_statement_sha256": sha256_json(operator_statement),
        "ack_single_use_authorization": ack_single_use_authorization,
        "source_artifacts": {"authorization_request": artifact_ref(request_path)},
        "boundary": _closed_boundary(authorization_decision_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, decision)
    return decision


def _write_authorization_receipt(*, request_path: Path, decision_path: Path, output: Path) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    request = read_json_object(request_path)
    decision = read_json_object(decision_path)
    task = object_value(request.get("task_request"))
    task_id = str(task.get("task_id") or "")
    authorization_id = f"post-h3-minimal-task-auth:{sha256_file(request_path)[:16]}:{sha256_file(decision_path)[:16]}"
    check(checks, failures, "authorization_request_passed", request.get("schema_version") == AUTHORIZATION_REQUEST_SCHEMA and request.get("passed") is True)
    check(checks, failures, "authorization_decision_passed", decision.get("schema_version") == AUTHORIZATION_DECISION_SCHEMA and decision.get("passed") is True)
    check(checks, failures, "task_id_present", bool(task_id))
    passed = _passed(checks, failures)
    receipt = {
        "schema_version": AUTHORIZATION_RECEIPT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "issued_at": _now(),
        "expires_at": "single_use_next_execution_gate_only",
        "authorization_id": authorization_id,
        "task_id": task_id,
        "single_use": True,
        "consumed": False,
        "consumption_required_by": "post_h3_minimal_production_task_execution_gate",
        "source_artifacts": {
            "authorization_request": artifact_ref(request_path),
            "authorization_decision": artifact_ref(decision_path),
        },
        "boundary": _closed_boundary(authorization_receipt_written=passed, single_use_execution_authorized=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, receipt)
    return receipt


def _read_verified_ref(ref: Any, checks: dict[str, bool], failures: list[str], label: str) -> dict[str, Any]:
    ref_obj = object_value(ref)
    path_text = ref_obj.get("path")
    expected_hash = ref_obj.get("sha256")
    check(checks, failures, f"{label}_ref_present", bool(path_text and expected_hash))
    if not path_text or not expected_hash:
        return {}
    path = Path(path_text)
    check(checks, failures, f"{label}_exists", path.is_file())
    if not path.is_file():
        return {}
    check(checks, failures, f"{label}_hash_valid", sha256_file(path) == expected_hash)
    try:
        return read_json_object(path)
    except Exception as exc:  # noqa: BLE001
        failures.append(f"{label}_unreadable:{exc}")
        return {}


def _check_no_side_effect_boundary(label: str, boundary: dict[str, Any], checks: dict[str, bool], failures: list[str]) -> None:
    for key in (
        "production_task_execution_allowed",
        "runtime_execution_performed",
        "runtime_workers_currently_running",
        "external_public_ingress_opened",
        "deploy_performed",
        "vm_contact_performed",
        "production_data_accessed",
        "production_runtime_receipt_write_allowed",
        "source_tree_write_performed",
        "git_write_performed",
        "secrets_recorded",
    ):
        if key in boundary:
            check(checks, failures, f"{label}_{key}_false", boundary.get(key) is False)


def _texts(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    result: list[str] = []
    for item in value:
        text = str(item).strip()
        if text and text not in result:
            result.append(text)
    return result


def _closed_boundary(**overrides: Any) -> dict[str, Any]:
    boundary = {
        "artifact_only": True,
        "context_validation_written": False,
        "authorization_request_written": False,
        "authorization_decision_written": False,
        "authorization_receipt_written": False,
        "single_use_execution_authorized": False,
        "runtime_execution_performed": False,
        "runtime_workers_currently_running": False,
        "external_public_ingress_opened": False,
        "deploy_performed": False,
        "vm_contact_performed": False,
        "production_data_accessed": False,
        "production_runtime_receipt_write_allowed": False,
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
        "boundary": _closed_boundary(),
        "non_claims": list(NON_CLAIMS),
    }


def _write_optional(report: dict[str, Any], output: Path | None) -> dict[str, Any]:
    if output is not None:
        write_json_object(output, report)
    return report


def _passed(checks: dict[str, bool], failures: list[str]) -> bool:
    return bool(checks) and all(checks.values()) and not failures


def _failures(reports: list[dict[str, Any]]) -> list[str]:
    failures: list[str] = []
    for report in reports:
        for failure in report.get("failure_reasons", []):
            if isinstance(failure, str) and failure not in failures:
                failures.append(failure)
    return failures


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--intake-summary", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--operator-id", default="operator-primary")
    parser.add_argument("--operator-decision", default=OPERATOR_DECISION_AUTHORIZE)
    parser.add_argument("--owner-decision", default=OWNER_DECISION_ACCEPT)
    parser.add_argument("--audit-decision", default=AUDIT_DECISION_ACCEPT)
    parser.add_argument("--rollback-decision", default=ROLLBACK_DECISION_ACCEPT)
    parser.add_argument("--monitoring-decision", default=MONITORING_DECISION_ACCEPT)
    parser.add_argument("--operator-statement", default="Authorize one bounded minimal production task execution attempt.")
    parser.add_argument("--ack-single-use-authorization", action="store_true")
    args = parser.parse_args(argv)
    summary = run_gate(
        intake_summary_path=args.intake_summary,
        output_root=args.output_root,
        operator_id=args.operator_id,
        operator_decision=args.operator_decision,
        owner_decision=args.owner_decision,
        audit_decision=args.audit_decision,
        rollback_decision=args.rollback_decision,
        monitoring_decision=args.monitoring_decision,
        operator_statement=args.operator_statement,
        ack_single_use_authorization=args.ack_single_use_authorization,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if summary.get("passed") is True else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
