"""Run P0-O first controlled beta task authorization gate.

P0-O consumes a passed P0-N controlled beta entry package and writes a
single-use authorization package for the first controlled beta task. It does not
post tasks, contact VMs, mutate source/Git, open public ingress, authorize
production transition, or write production receipts.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from benchmarks.i_gate_evidence import (
    artifact_ref,
    check,
    object_value,
    read_json_object,
    sha256_file,
    write_json_object,
)
from benchmarks.p0n_controlled_beta_entry_gate import (
    CHAIN_SCHEMA as P0N_CHAIN_SCHEMA,
    FIRST_TASK_PROPOSAL_SCHEMA as P0N_FIRST_TASK_PROPOSAL_SCHEMA,
    OWNER_HANDOFF_SCHEMA as P0N_OWNER_HANDOFF_SCHEMA,
    SERVICE_TOKEN_SCOPE_SCHEMA as P0N_SERVICE_TOKEN_SCOPE_SCHEMA,
    STOP_CONDITIONS_SCHEMA as P0N_STOP_CONDITIONS_SCHEMA,
)

CHAIN_SCHEMA = "p0o-first-controlled-beta-task-authorization-chain:v1"
CONTEXT_SCHEMA = "p0o-p0n-context-validation:v1"
AUTHORIZATION_REQUEST_SCHEMA = "p0o-first-controlled-beta-task-authorization-request:v1"
AUTHORIZATION_DECISION_SCHEMA = "p0o-first-controlled-beta-task-authorization-decision:v1"
AUTHORIZATION_RECEIPT_SCHEMA = "p0o-first-controlled-beta-task-authorization-receipt:v1"
ACCEPTED_OPERATOR_DECISION = "authorize_once"
ACCEPTED_OWNER_DECISION = "approve_first_controlled_beta_task"
ACCEPTED_AUDIT_DECISION = "approve_no_production_audit_boundary"
ACCEPTED_ROLLBACK_DECISION = "approve_rollback_or_abort_boundary"

NON_CLAIMS = (
    "p0o_authorizes_one_controlled_beta_task_only",
    "p0o_requires_passed_p0n_entry_package",
    "p0o_does_not_post_or_execute_task",
    "p0o_does_not_contact_vms_or_run_preview_commands",
    "p0o_does_not_open_public_ingress",
    "p0o_does_not_touch_production_data",
    "p0o_does_not_modify_source_or_git",
    "p0o_does_not_write_production_receipts",
    "p0o_does_not_authorize_production_transition",
)

PRODUCTION_FORBIDDEN_ACTIONS = {
    "public_ingress",
    "production_data_access",
    "production_transition",
    "production_receipt_write",
}


def run_gate(
    *,
    p0n_summary_path: Path,
    output_root: Path,
    operator_id: str = "operator-cc",
    operator_decision: str = ACCEPTED_OPERATOR_DECISION,
    owner_decision: str = ACCEPTED_OWNER_DECISION,
    audit_decision: str = ACCEPTED_AUDIT_DECISION,
    rollback_decision: str = ACCEPTED_ROLLBACK_DECISION,
    ack_first_task_authorization: bool = False,
) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "authorization_request": output_root / "p0o_first_task_authorization_request.json",
        "authorization_decision": output_root / "p0o_first_task_authorization_decision.json",
        "authorization_receipt": output_root / "p0o_first_task_authorization_receipt.json",
        "summary": output_root / "p0o_first_controlled_beta_task_authorization_summary.json",
    }
    context = validate_p0n_context(p0n_summary_path)
    request = write_authorization_request(
        context=context,
        output=artifacts["authorization_request"],
        p0n_summary_path=p0n_summary_path,
    )
    decision = write_authorization_decision(
        context=context,
        request_path=artifacts["authorization_request"],
        output=artifacts["authorization_decision"],
        operator_id=operator_id,
        operator_decision=operator_decision,
        owner_decision=owner_decision,
        audit_decision=audit_decision,
        rollback_decision=rollback_decision,
        ack_first_task_authorization=ack_first_task_authorization,
    )
    receipt = write_authorization_receipt(
        context=context,
        request_path=artifacts["authorization_request"],
        decision_path=artifacts["authorization_decision"],
        output=artifacts["authorization_receipt"],
    )
    reports = [context, request, decision, receipt]
    passed = all(report.get("passed") is True for report in reports)
    summary = {
        "schema_version": CHAIN_SCHEMA,
        "passed": passed,
        "failure_reasons": _failures(reports),
        "checked_at": _now(),
        "operator_id": operator_id,
        "task_id": context.get("first_task", {}).get("task_id"),
        "owners": context.get("owners", {}),
        "source_artifacts": {"p0n_summary": artifact_ref(p0n_summary_path)},
        "artifacts": {name: artifact_ref(path) for name, path in artifacts.items() if name != "summary"},
        "authorization": {
            "decision": decision.get("decision"),
            "authorization_id": receipt.get("authorization_id"),
            "single_use": receipt.get("single_use") is True,
            "consumed": receipt.get("consumed") is True,
            "service_token_scope_count": len(context.get("service_token_scopes", [])),
        },
        "readiness": {
            "state": "p0o_first_controlled_beta_task_authorized" if passed else "blocked_p0o_first_task_authorization",
            "p0o_first_controlled_beta_task_authorized": passed,
            "p0p_first_controlled_beta_task_execution_ready": passed,
            "production_transition_allowed": False,
        },
        "boundary": _boundary(
            authorization_request_written=request.get("passed") is True,
            authorization_decision_written=decision.get("passed") is True,
            authorization_receipt_written=receipt.get("passed") is True,
        ),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(artifacts["summary"], summary)
    return summary


def validate_p0n_context(p0n_summary_path: Path) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    try:
        p0n = read_json_object(p0n_summary_path)
    except Exception as exc:  # noqa: BLE001
        return _report(CONTEXT_SCHEMA, False, [f"p0n_summary_unreadable:{exc}"], checks)

    artifacts = object_value(p0n.get("artifacts"))
    service_scope = _read_verified_ref(
        artifacts.get("service_token_scope"),
        checks,
        failures,
        "p0n_service_token_scope",
    )
    owner_handoff = _read_verified_ref(artifacts.get("owner_handoff"), checks, failures, "p0n_owner_handoff")
    stop_conditions = _read_verified_ref(artifacts.get("stop_conditions"), checks, failures, "p0n_stop_conditions")
    first_task = _read_verified_ref(artifacts.get("first_task_proposal"), checks, failures, "p0n_first_task_proposal")
    readiness = object_value(p0n.get("readiness"))
    entry = object_value(p0n.get("entry"))
    service_scopes = _texts(service_scope.get("service_token_scopes"))
    controlled_task = object_value(first_task.get("controlled_beta_task"))
    forbidden_actions = set(_texts(controlled_task.get("forbidden_actions")))

    check(
        checks,
        failures,
        "p0n_summary_passed",
        p0n.get("schema_version") == P0N_CHAIN_SCHEMA and p0n.get("passed") is True,
    )
    check(
        checks,
        failures,
        "p0n_entry_ready",
        readiness.get("p0o_first_controlled_beta_task_authorization_ready") is True,
    )
    check(checks, failures, "p0n_production_transition_closed", readiness.get("production_transition_allowed") is False)
    check(checks, failures, "p0n_boundary_closed", _no_production_violation(object_value(p0n.get("boundary"))))
    check(
        checks,
        failures,
        "service_token_scope_passed",
        service_scope.get("schema_version") == P0N_SERVICE_TOKEN_SCOPE_SCHEMA
        and service_scope.get("passed") is True,
    )
    check(
        checks,
        failures,
        "owner_handoff_passed",
        owner_handoff.get("schema_version") == P0N_OWNER_HANDOFF_SCHEMA and owner_handoff.get("passed") is True,
    )
    check(
        checks,
        failures,
        "stop_conditions_passed",
        stop_conditions.get("schema_version") == P0N_STOP_CONDITIONS_SCHEMA
        and stop_conditions.get("passed") is True,
    )
    check(
        checks,
        failures,
        "first_task_proposal_passed",
        first_task.get("schema_version") == P0N_FIRST_TASK_PROPOSAL_SCHEMA
        and first_task.get("passed") is True,
    )
    check(checks, failures, "first_task_matches_entry", controlled_task.get("task_id") == entry.get("first_task_id"))
    check(checks, failures, "first_task_low_risk", controlled_task.get("risk_class") == "low")
    check(checks, failures, "first_task_forbids_production", PRODUCTION_FORBIDDEN_ACTIONS <= forbidden_actions)
    check(checks, failures, "service_token_scopes_present", len(service_scopes) >= 4)
    passed = _passed(checks, failures)
    return {
        "schema_version": CONTEXT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "p0n_summary": p0n,
        "owners": object_value(owner_handoff.get("owners")),
        "first_task": controlled_task,
        "service_token_scopes": service_scopes,
        "stop_conditions": _texts(stop_conditions.get("stop_conditions")),
        "source_artifacts": {"p0n_summary": artifact_ref(p0n_summary_path)},
        "boundary": _boundary(context_validation_written=passed),
        "non_claims": list(NON_CLAIMS),
    }


def write_authorization_request(*, context: dict[str, Any], output: Path, p0n_summary_path: Path) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    task = object_value(context.get("first_task"))
    scopes = _texts(context.get("service_token_scopes"))
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "task_id_present", bool(task.get("task_id")))
    check(checks, failures, "service_token_scopes_present", len(scopes) >= 4)
    check(
        checks,
        failures,
        "task_forbids_production",
        PRODUCTION_FORBIDDEN_ACTIONS <= set(_texts(task.get("forbidden_actions"))),
    )
    passed = _passed(checks, failures)
    report = {
        "schema_version": AUTHORIZATION_REQUEST_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "requested_at": _now(),
        "authorization_kind": "single_use_controlled_beta_task_pool_execution",
        "controlled_beta_task": task,
        "service_token_scopes": scopes,
        "owners": context.get("owners", {}),
        "source_artifacts": {"p0n_summary": artifact_ref(p0n_summary_path)},
        "boundary": _boundary(authorization_request_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def write_authorization_decision(
    *,
    context: dict[str, Any],
    request_path: Path,
    output: Path,
    operator_id: str,
    operator_decision: str,
    owner_decision: str,
    audit_decision: str,
    rollback_decision: str,
    ack_first_task_authorization: bool,
) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    request = read_json_object(request_path)
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(
        checks,
        failures,
        "authorization_request_passed",
        request.get("schema_version") == AUTHORIZATION_REQUEST_SCHEMA and request.get("passed") is True,
    )
    check(checks, failures, "operator_id_present", bool(str(operator_id).strip()))
    check(checks, failures, "explicit_operator_ack", ack_first_task_authorization is True)
    check(checks, failures, "operator_decision_authorize_once", operator_decision == ACCEPTED_OPERATOR_DECISION)
    check(checks, failures, "owner_decision_accepted", owner_decision == ACCEPTED_OWNER_DECISION)
    check(checks, failures, "audit_decision_accepted", audit_decision == ACCEPTED_AUDIT_DECISION)
    check(checks, failures, "rollback_decision_accepted", rollback_decision == ACCEPTED_ROLLBACK_DECISION)
    passed = _passed(checks, failures)
    report = {
        "schema_version": AUTHORIZATION_DECISION_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "decided_at": _now(),
        "operator_id": operator_id,
        "decision": operator_decision if passed else "blocked_first_controlled_beta_task_authorization",
        "owner_decision": owner_decision,
        "audit_decision": audit_decision,
        "rollback_decision": rollback_decision,
        "source_artifacts": {"authorization_request": artifact_ref(request_path)},
        "boundary": _boundary(authorization_decision_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def write_authorization_receipt(
    *,
    context: dict[str, Any],
    request_path: Path,
    decision_path: Path,
    output: Path,
) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    request = read_json_object(request_path)
    decision = read_json_object(decision_path)
    task_id = str(object_value(request.get("controlled_beta_task")).get("task_id") or "")
    authorization_id = f"p0o-auth:{sha256_file(request_path)[:16]}:{sha256_file(decision_path)[:16]}"
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "authorization_request_passed", request.get("passed") is True)
    check(checks, failures, "authorization_decision_passed", decision.get("passed") is True)
    check(checks, failures, "task_id_present", bool(task_id))
    passed = _passed(checks, failures)
    report = {
        "schema_version": AUTHORIZATION_RECEIPT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "issued_at": _now(),
        "authorization_id": authorization_id,
        "task_id": task_id,
        "single_use": True,
        "consumed": False,
        "consumption_required_by": "p0p_first_controlled_beta_task_execution_gate",
        "source_artifacts": {
            "authorization_request": artifact_ref(request_path),
            "authorization_decision": artifact_ref(decision_path),
        },
        "boundary": _boundary(authorization_receipt_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def _read_verified_ref(value: Any, checks: dict[str, bool], failures: list[str], label: str) -> dict[str, Any]:
    ref = object_value(value)
    path = Path(str(ref.get("path") or ""))
    expected_hash = str(ref.get("sha256") or "")
    check(checks, failures, f"{label}_path_present", path.is_file())
    if not path.is_file():
        return {}
    check(checks, failures, f"{label}_hash_valid", bool(expected_hash) and sha256_file(path) == expected_hash)
    return read_json_object(path)


def _texts(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    result: list[str] = []
    for item in value:
        text = str(item).strip()
        if text and text not in result:
            result.append(text)
    return result


def _no_production_violation(boundary: dict[str, Any]) -> bool:
    forbidden_true_keys = (
        "external_public_ingress_opened",
        "production_transition_allowed",
        "production_receipt_write_allowed",
        "production_data_accessed",
        "secrets_recorded",
        "source_tree_write_performed",
        "git_write_performed",
        "preview_command_executed",
        "vm_contact_performed",
    )
    return all(boundary.get(key) is not True for key in forbidden_true_keys)


def _boundary(**overrides: bool) -> dict[str, bool]:
    base = {
        "context_validation_written": False,
        "authorization_request_written": False,
        "authorization_decision_written": False,
        "authorization_receipt_written": False,
        "vm_contact_performed": False,
        "task_pool_post_performed": False,
        "task_pool_claim_performed": False,
        "task_pool_execute_performed": False,
        "preview_command_executed": False,
        "source_tree_write_performed": False,
        "git_write_performed": False,
        "external_public_ingress_opened": False,
        "production_transition_allowed": False,
        "production_receipt_write_allowed": False,
        "production_data_accessed": False,
        "secrets_recorded": False,
    }
    base.update(overrides)
    return base


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


def _failures(reports: list[dict[str, Any]]) -> list[str]:
    values: list[str] = []
    for report in reports:
        values.extend(str(item) for item in report.get("failure_reasons", []))
    return values


def _passed(checks: dict[str, bool], failures: list[str]) -> bool:
    return bool(checks) and all(checks.values()) and not failures


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def main() -> int:
    parser = argparse.ArgumentParser(description="Run P0-O first controlled beta task authorization gate")
    parser.add_argument("--p0n-summary", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--operator-id", default="operator-cc")
    parser.add_argument("--operator-decision", default=ACCEPTED_OPERATOR_DECISION)
    parser.add_argument("--owner-decision", default=ACCEPTED_OWNER_DECISION)
    parser.add_argument("--audit-decision", default=ACCEPTED_AUDIT_DECISION)
    parser.add_argument("--rollback-decision", default=ACCEPTED_ROLLBACK_DECISION)
    parser.add_argument("--ack-first-task-authorization", action="store_true")
    args = parser.parse_args()
    summary = run_gate(
        p0n_summary_path=args.p0n_summary,
        output_root=args.output_root,
        operator_id=args.operator_id,
        operator_decision=args.operator_decision,
        owner_decision=args.owner_decision,
        audit_decision=args.audit_decision,
        rollback_decision=args.rollback_decision,
        ack_first_task_authorization=args.ack_first_task_authorization,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if summary.get("passed") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
