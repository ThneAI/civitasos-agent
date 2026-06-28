"""Run P0-N controlled beta entry / operator handoff gate.

P0-N consumes a passed P0-M controlled beta readiness summary and writes an
operator-facing controlled beta entry package. It is evidence-only: it does not
contact VMs, deploy services, mutate source/Git, open public ingress, authorize
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
from benchmarks.p0m_controlled_beta_readiness_review_gate import (
    BETA_SCOPE_SCHEMA as P0M_BETA_SCOPE_SCHEMA,
    CHAIN_SCHEMA as P0M_CHAIN_SCHEMA,
    CHAIN_VALIDATION_SCHEMA as P0M_CHAIN_VALIDATION_SCHEMA,
    OPERATOR_RECONCILIATION_SCHEMA as P0M_OPERATOR_RECONCILIATION_SCHEMA,
    READINESS_REVIEW_SCHEMA as P0M_READINESS_REVIEW_SCHEMA,
)
from benchmarks.p0l_external_preview_evidence_gate import CHAIN_SCHEMA as P0L_CHAIN_SCHEMA

CHAIN_SCHEMA = "p0n-controlled-beta-entry-chain:v1"
CONTEXT_SCHEMA = "p0n-p0m-context-validation:v1"
SERVICE_TOKEN_SCOPE_SCHEMA = "p0n-controlled-beta-service-token-scope:v1"
OPERATOR_RUNBOOK_SCHEMA = "p0n-controlled-beta-operator-runbook:v1"
OWNER_HANDOFF_SCHEMA = "p0n-controlled-beta-owner-handoff:v1"
STOP_CONDITIONS_SCHEMA = "p0n-controlled-beta-stop-conditions:v1"
FIRST_TASK_PROPOSAL_SCHEMA = "p0n-controlled-beta-first-task-proposal:v1"
ACCEPTED_OPERATOR_DECISION = "approve_controlled_beta_entry_package"

REQUIRED_FORBIDDEN_ACTIONS = {
    "public_ingress",
    "production_data_access",
    "production_transition",
    "production_receipt_write",
    "unscoped_external_deploy",
}
REQUIRED_ALLOWED_ACTIONS = {
    "service_token_task_pool_preview",
    "private_backend_frontend_preview",
    "private_preview_soak",
    "owner_audit_rollback_evidence_packaging",
}
SERVICE_TOKEN_SCOPES = (
    "agents:read",
    "agents:write",
    "a2a:pool:read",
    "a2a:pool:post",
    "a2a:pool:claim",
    "a2a:task:execute",
    "pool:read",
    "pool:post",
    "pool:claim",
    "pool:write",
    "audit:read",
    "operator:read-model",
)
NON_CLAIMS = (
    "p0n_is_controlled_beta_entry_package_only",
    "p0n_requires_passed_p0m_controlled_beta_readiness",
    "p0n_does_not_contact_vms_or_run_preview_commands",
    "p0n_does_not_open_public_ingress",
    "p0n_does_not_touch_production_data",
    "p0n_does_not_modify_source_or_git",
    "p0n_does_not_write_production_receipts",
    "p0n_does_not_authorize_production_transition",
)


def run_gate(
    *,
    p0m_summary_path: Path,
    output_root: Path,
    operator_id: str = "operator-cc",
    operator_decision: str = ACCEPTED_OPERATOR_DECISION,
    ack_controlled_beta_entry: bool = False,
) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    context = validate_p0m_context(p0m_summary_path)
    artifacts = {
        "service_token_scope": output_root / "p0n_service_token_scope.json",
        "operator_runbook": output_root / "p0n_operator_runbook.json",
        "owner_handoff": output_root / "p0n_owner_handoff.json",
        "stop_conditions": output_root / "p0n_stop_conditions.json",
        "first_task_proposal": output_root / "p0n_first_controlled_beta_task_proposal.json",
        "summary": output_root / "p0n_controlled_beta_entry_chain_summary.json",
    }
    service_scope = write_service_token_scope(
        context=context,
        output=artifacts["service_token_scope"],
        p0m_summary_path=p0m_summary_path,
    )
    runbook = write_operator_runbook(
        context=context,
        output=artifacts["operator_runbook"],
        p0m_summary_path=p0m_summary_path,
    )
    handoff = write_owner_handoff(context=context, output=artifacts["owner_handoff"], p0m_summary_path=p0m_summary_path)
    stop_conditions = write_stop_conditions(
        context=context,
        output=artifacts["stop_conditions"],
        p0m_summary_path=p0m_summary_path,
    )
    first_task = write_first_task_proposal(
        context=context,
        output=artifacts["first_task_proposal"],
        p0m_summary_path=p0m_summary_path,
    )
    reports = [context, service_scope, runbook, handoff, stop_conditions, first_task]
    operator_checks: dict[str, bool] = {}
    operator_failures: list[str] = []
    check(operator_checks, operator_failures, "operator_id_present", bool(str(operator_id).strip()))
    check(operator_checks, operator_failures, "explicit_operator_ack", ack_controlled_beta_entry is True)
    check(
        operator_checks,
        operator_failures,
        "operator_decision_accepted",
        operator_decision == ACCEPTED_OPERATOR_DECISION,
    )
    passed = all(report.get("passed") is True for report in reports) and _passed(operator_checks, operator_failures)
    summary = {
        "schema_version": CHAIN_SCHEMA,
        "passed": passed,
        "failure_reasons": _failures(reports) + operator_failures,
        "checks": operator_checks,
        "checked_at": _now(),
        "operator_id": operator_id,
        "operator_decision": operator_decision if passed else "blocked_controlled_beta_entry_package",
        "task_id": context.get("task_id"),
        "vm_target_ids": context.get("vm_target_ids", []),
        "owners": context.get("owners", {}),
        "source_artifacts": {"p0m_summary": artifact_ref(p0m_summary_path)},
        "artifacts": {name: artifact_ref(path) for name, path in artifacts.items() if name != "summary"},
        "entry": {
            "service_token_scope_count": len(service_scope.get("service_token_scopes", [])),
            "allowed_actions": service_scope.get("allowed_actions", []),
            "forbidden_actions": service_scope.get("forbidden_actions", []),
            "first_task_id": first_task.get("controlled_beta_task", {}).get("task_id"),
        },
        "readiness": {
            "state": "p0n_controlled_beta_entry_package_ready" if passed else "blocked_p0n_controlled_beta_entry",
            "controlled_beta_entry_package_ready": passed,
            "p0o_first_controlled_beta_task_authorization_ready": passed,
            "production_transition_allowed": False,
        },
        "boundary": _boundary(
            service_token_scope_written=service_scope.get("passed") is True,
            operator_runbook_written=runbook.get("passed") is True,
            owner_handoff_written=handoff.get("passed") is True,
            stop_conditions_written=stop_conditions.get("passed") is True,
            first_task_proposal_written=first_task.get("passed") is True,
        ),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(artifacts["summary"], summary)
    return summary


def validate_p0m_context(p0m_summary_path: Path) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    try:
        p0m = read_json_object(p0m_summary_path)
    except Exception as exc:  # noqa: BLE001
        return _report(CONTEXT_SCHEMA, False, [f"p0m_summary_unreadable:{exc}"], checks)
    artifacts = object_value(p0m.get("artifacts"))
    chain = _read_verified_ref(artifacts.get("chain_validation"), checks, failures, "p0m_chain_validation")
    review = _read_verified_ref(artifacts.get("readiness_review"), checks, failures, "p0m_readiness_review")
    scope_report = _read_verified_ref(artifacts.get("beta_scope"), checks, failures, "p0m_beta_scope")
    reconciliation = _read_verified_ref(
        artifacts.get("operator_reconciliation"),
        checks,
        failures,
        "p0m_operator_reconciliation",
    )
    p0l = _read_verified_ref(
        object_value(p0m.get("source_artifacts")).get("p0l_summary"),
        checks,
        failures,
        "p0m_source_p0l_summary",
    )
    readiness = object_value(p0m.get("readiness"))
    review_summary = object_value(p0m.get("review"))
    beta_scope = object_value(scope_report.get("controlled_beta_scope"))
    allowed = set(_texts(beta_scope.get("allowed_actions")))
    forbidden = set(_texts(beta_scope.get("forbidden_actions")))

    check(
        checks,
        failures,
        "p0m_summary_passed",
        p0m.get("schema_version") == P0M_CHAIN_SCHEMA and p0m.get("passed") is True,
    )
    check(checks, failures, "p0m_controlled_beta_ready", readiness.get("controlled_beta_candidate_ready") is True)
    check(checks, failures, "p0m_production_transition_closed", readiness.get("production_transition_allowed") is False)
    check(checks, failures, "p0m_no_blocking_gaps", review_summary.get("blocking_gaps") == [])
    check(
        checks,
        failures,
        "p0m_chain_validation_passed",
        chain.get("schema_version") == P0M_CHAIN_VALIDATION_SCHEMA and chain.get("passed") is True,
    )
    check(
        checks,
        failures,
        "p0m_readiness_review_passed",
        review.get("schema_version") == P0M_READINESS_REVIEW_SCHEMA and review.get("passed") is True,
    )
    check(
        checks,
        failures,
        "p0m_beta_scope_passed",
        scope_report.get("schema_version") == P0M_BETA_SCOPE_SCHEMA and scope_report.get("passed") is True,
    )
    check(
        checks,
        failures,
        "p0m_operator_reconciliation_passed",
        reconciliation.get("schema_version") == P0M_OPERATOR_RECONCILIATION_SCHEMA
        and reconciliation.get("passed") is True,
    )
    check(
        checks,
        failures,
        "p0l_source_passed",
        p0l.get("schema_version") == P0L_CHAIN_SCHEMA and p0l.get("passed") is True,
    )
    check(
        checks,
        failures,
        "scope_environment_private",
        beta_scope.get("allowed_environment") == "private_virtualbox_preview_only",
    )
    check(checks, failures, "scope_allowed_actions_complete", REQUIRED_ALLOWED_ACTIONS <= allowed)
    check(checks, failures, "scope_forbidden_actions_complete", REQUIRED_FORBIDDEN_ACTIONS <= forbidden)
    check(checks, failures, "p0m_boundary_closed", _no_production_violation(object_value(p0m.get("boundary"))))
    passed = _passed(checks, failures)
    return {
        "schema_version": CONTEXT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "task_id": p0m.get("task_id"),
        "vm_target_ids": _texts(p0m.get("vm_target_ids")),
        "owners": object_value(p0l.get("owners")),
        "controlled_beta_scope": beta_scope,
        "p0m_summary": p0m,
        "p0l_summary": p0l,
        "source_artifacts": {"p0m_summary": artifact_ref(p0m_summary_path)},
        "boundary": _boundary(context_validation_written=passed),
        "non_claims": list(NON_CLAIMS),
    }


def write_service_token_scope(*, context: dict[str, Any], output: Path, p0m_summary_path: Path) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    scope = object_value(context.get("controlled_beta_scope"))
    allowed_actions = _texts(scope.get("allowed_actions"))
    forbidden_actions = _texts(scope.get("forbidden_actions"))
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "service_scopes_present", len(SERVICE_TOKEN_SCOPES) >= 4)
    check(checks, failures, "no_service_token_secret_recorded", True)
    check(checks, failures, "scope_forbids_production", REQUIRED_FORBIDDEN_ACTIONS <= set(forbidden_actions))
    passed = _passed(checks, failures)
    report = {
        "schema_version": SERVICE_TOKEN_SCOPE_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "recorded_at": _now(),
        "service_id": "p0_controlled_beta_operator",
        "service_token_scopes": list(SERVICE_TOKEN_SCOPES),
        "service_token_secret_recorded": False,
        "allowed_actions": allowed_actions,
        "forbidden_actions": forbidden_actions,
        "source_artifacts": {"p0m_summary": artifact_ref(p0m_summary_path)},
        "boundary": _boundary(service_token_scope_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def write_operator_runbook(*, context: dict[str, Any], output: Path, p0m_summary_path: Path) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    check(checks, failures, "context_passed", context.get("passed") is True)
    runbook_steps = [
        "verify P0-N entry package hash before use",
        "load service token from local secret store only; never write it into receipts",
        "run P0-O authorization preflight before the first controlled beta task",
        "execute only allowed private preview actions within the P0-M scope",
        "monitor audit/read-model receipts after each task",
        "trigger rollback/abort if any stop condition is met",
    ]
    check(checks, failures, "runbook_steps_present", len(runbook_steps) >= 5)
    passed = _passed(checks, failures)
    report = {
        "schema_version": OPERATOR_RUNBOOK_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "recorded_at": _now(),
        "runbook_steps": runbook_steps,
        "source_artifacts": {"p0m_summary": artifact_ref(p0m_summary_path)},
        "boundary": _boundary(operator_runbook_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def write_owner_handoff(*, context: dict[str, Any], output: Path, p0m_summary_path: Path) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    owners = object_value(context.get("owners"))
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "owner_present", bool(owners.get("owner_id")))
    check(checks, failures, "audit_owner_present", bool(owners.get("audit_owner_id")))
    check(checks, failures, "monitoring_owner_present", bool(owners.get("monitoring_owner_id")))
    check(checks, failures, "rollback_owner_present", bool(owners.get("rollback_owner_id")))
    passed = _passed(checks, failures)
    report = {
        "schema_version": OWNER_HANDOFF_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "recorded_at": _now(),
        "owners": owners,
        "handoff_summary": (
            "Controlled beta entry requires owner/audit/monitoring/rollback "
            "review before each task authorization."
        ),
        "source_artifacts": {"p0m_summary": artifact_ref(p0m_summary_path)},
        "boundary": _boundary(owner_handoff_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def write_stop_conditions(*, context: dict[str, Any], output: Path, p0m_summary_path: Path) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    stop_conditions = [
        "any public ingress is opened",
        "any production data access is requested or observed",
        "any production receipt write is attempted",
        "service token scope exceeds P0-N allowed scopes",
        "rollback or audit receipt is missing after a task",
        "owner, audit owner, or rollback owner rejects the task",
    ]
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "stop_conditions_present", len(stop_conditions) >= 5)
    passed = _passed(checks, failures)
    report = {
        "schema_version": STOP_CONDITIONS_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "recorded_at": _now(),
        "stop_conditions": stop_conditions,
        "source_artifacts": {"p0m_summary": artifact_ref(p0m_summary_path)},
        "boundary": _boundary(stop_conditions_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def write_first_task_proposal(*, context: dict[str, Any], output: Path, p0m_summary_path: Path) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    proposal = {
        "task_id": "p0-beta-task:first-controlled-status-evidence-index",
        "title": "Generate a controlled beta status evidence index",
        "risk_class": "low",
        "environment": "private_virtualbox_preview_only",
        "allowed_actions": ["service_token_task_pool_preview", "owner_audit_rollback_evidence_packaging"],
        "forbidden_actions": [
            "public_ingress",
            "production_data_access",
            "production_transition",
            "production_receipt_write",
        ],
        "acceptance_criteria": [
            "task is posted, claimed, executed, and delivered through CivitasOS task pool",
            "result artifact summarizes P0-M/P0-N evidence without secrets",
            "operator/audit/rollback receipts are written",
            "no-production boundary remains closed",
        ],
    }
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "task_id_present", bool(proposal["task_id"]))
    check(checks, failures, "risk_low", proposal["risk_class"] == "low")
    check(checks, failures, "forbids_production", "production_transition" in proposal["forbidden_actions"])
    passed = _passed(checks, failures)
    report = {
        "schema_version": FIRST_TASK_PROPOSAL_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "recorded_at": _now(),
        "controlled_beta_task": proposal,
        "source_artifacts": {"p0m_summary": artifact_ref(p0m_summary_path)},
        "boundary": _boundary(first_task_proposal_written=passed),
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
    )
    return all(boundary.get(key) is not True for key in forbidden_true_keys)


def _boundary(**overrides: bool) -> dict[str, bool]:
    base = {
        "context_validation_written": False,
        "service_token_scope_written": False,
        "operator_runbook_written": False,
        "owner_handoff_written": False,
        "stop_conditions_written": False,
        "first_task_proposal_written": False,
        "vm_contact_performed": False,
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


def _failures(reports: list[dict[str, Any]]) -> list[str]:
    values: list[str] = []
    for report in reports:
        values.extend(str(item) for item in report.get("failure_reasons", []))
    return sorted(set(values))


def _passed(checks: dict[str, bool], failures: list[str]) -> bool:
    return bool(checks) and all(checks.values()) and not failures


def _report(schema: str, passed: bool, failures: list[str], checks: dict[str, bool]) -> dict[str, Any]:
    return {"schema_version": schema, "passed": passed, "failure_reasons": failures, "checks": checks}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def main() -> int:
    parser = argparse.ArgumentParser(description="Run P0-N controlled beta entry gate")
    parser.add_argument("--p0m-summary", required=True)
    parser.add_argument("--output-root", required=True)
    parser.add_argument("--operator-id", default="operator-cc")
    parser.add_argument("--operator-decision", default=ACCEPTED_OPERATOR_DECISION)
    parser.add_argument("--ack-controlled-beta-entry", action="store_true")
    args = parser.parse_args()
    summary = run_gate(
        p0m_summary_path=Path(args.p0m_summary),
        output_root=Path(args.output_root),
        operator_id=args.operator_id,
        operator_decision=args.operator_decision,
        ack_controlled_beta_entry=bool(args.ack_controlled_beta_entry),
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if summary.get("passed") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
