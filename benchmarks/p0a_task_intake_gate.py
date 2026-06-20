"""Run P0-A task intake gate.

P0-A selects and validates one low-risk real owner task for the first
controlled production pilot. The gate is artifact-only: it records owner,
audit, rollback, VM target, service-token scope, risk classification, and the
allowed execution scope. It does not contact VMs, start agents, deploy, mutate
runtime state, or write production receipts.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from benchmarks.i_gate_evidence import artifact_ref, check, object_value, read_json_object, write_json_object

CHAIN_SCHEMA = "p0a-task-intake-chain:v1"
TASK_INTAKE_SCHEMA = "p0a-task-intake:v1"
INTAKE_RECEIPT_SCHEMA = "p0a-task-intake-receipt:v1"
RISK_DECISION_SCHEMA = "p0a-risk-decision:v1"
ALLOWED_SCOPE_SCHEMA = "p0a-allowed-execution-scope:v1"
I2H_SCHEMA = "i2h-post-merge-smoke-chain:v1"

ALLOWED_TASK_CLASSES = {
    "documentation_update",
    "read_only_analysis",
    "internal_status_page_update",
    "frontend_non_critical_copy_layout_adjustment",
    "evidence_index_generation",
}

REQUIRED_VM_ROLES = {
    "vm1": "backend_frontend_preview_entrypoint",
    "vm2": "csp_memory_evidence_cache",
    "vm3": "agent_runner_probe_node",
}

REQUIRED_SERVICE_SCOPES = {
    "agents:read",
    "agents:write",
    "pool:post",
    "pool:read",
    "pool:claim",
    "pool:write",
    "audit:read",
    "webhooks:write",
}

ALLOWED_SERVICE_SCOPES = REQUIRED_SERVICE_SCOPES | {
    "pool:sweep",
    "outcomes:read",
    "webhooks:read",
}

FORBIDDEN_SCOPE_TOKENS = (
    "*",
    "admin",
    "root",
    "production",
    "prod",
    "deploy",
    "secret",
    "secrets",
    "wallet",
    "payment",
    "git",
    "merge",
)

REQUIRED_FORBIDDEN_OPERATIONS = {
    "production_data_mutation",
    "public_ingress_change",
    "secret_or_key_read",
    "payment_or_wallet_operation",
    "uncontrolled_deploy",
    "automatic_merge_or_release",
}

DEFAULT_TASK_INTAKE: dict[str, Any] = {
    "schema_version": TASK_INTAKE_SCHEMA,
    "task_id": "p0-task:pilot-status-evidence-index-preview",
    "title": "Generate controlled P0 pilot status and evidence index preview",
    "task_class": "evidence_index_generation",
    "risk_class": "low",
    "owner": {
        "id": "product_owner",
        "role": "owner",
        "approval_state": "approved_for_p0a_intake",
    },
    "operator": {"id": "operator-cc", "role": "operator"},
    "audit_owner": {"id": "audit_owner", "role": "audit_owner"},
    "rollback_owner": {"id": "rollback_owner", "role": "rollback_owner"},
    "vm_targets": [
        {
            "id": "vm1",
            "ssh_alias": "vm1",
            "address": "192.168.56.4",
            "role": "backend_frontend_preview_entrypoint",
        },
        {
            "id": "vm2",
            "ssh_alias": "vm2",
            "address": "192.168.56.5",
            "role": "csp_memory_evidence_cache",
        },
        {
            "id": "vm3",
            "ssh_alias": "vm3",
            "address": "192.168.56.6",
            "role": "agent_runner_probe_node",
        },
    ],
    "service_token": {
        "mode": "scoped_service_token_required_before_p0c",
        "secret_material_in_artifact": False,
        "production_allowed": False,
        "evidence_allowed": False,
        "demo_login_allowed": False,
        "scopes": sorted(REQUIRED_SERVICE_SCOPES),
    },
    "allowed_systems": [
        "civitasos backend A2A pool",
        "civitasos CSP memory/evidence cache",
        "local/private VM preview endpoint",
        "pilot run-root evidence directory",
    ],
    "allowed_files": [
        "runs/P0*/**",
        "pilot_workspace/P0*/**",
    ],
    "forbidden_operations": sorted(REQUIRED_FORBIDDEN_OPERATIONS),
    "rollback": {
        "procedure_written": True,
        "owner_id": "rollback_owner",
        "command": "stop pilot services, restore previous VM service state, remove P0 run workspace, verify health endpoints",
        "dry_run_required_before_p0c": True,
        "dry_run_verified": False,
    },
    "audit": {
        "owner_id": "audit_owner",
        "required_receipts": [
            "task_intake_receipt",
            "risk_decision",
            "allowed_execution_scope",
            "future_agent_proposal_receipts",
            "future_execution_receipt",
            "future_preview_smoke_receipt",
            "future_rollback_or_abort_receipt",
            "future_owner_acceptance_receipt",
        ],
    },
    "task_brief": {
        "objective": "Prepare a controlled P0 pilot status/evidence index preview for owner review using CivitasOS task pool mediation.",
        "success_criteria": [
            "one owner-readable status/evidence index preview is generated under the pilot run root",
            "all side effects are traceable to P0 receipts",
            "no production data, public ingress, deployment, git merge, or secret access occurs",
        ],
        "stop_conditions": [
            "service token scope is broader than the P0 allowlist",
            "VM target topology is not exactly vm1/vm2/vm3 controlled private preview",
            "rollback owner or audit owner is unavailable",
            "any production/write/deploy/secret scope is requested",
        ],
    },
}


def run_gate(
    *,
    i2h_summary_path: Path,
    output_root: Path,
    task_intake_path: Path | None = None,
) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "task_intake_receipt": output_root / "p0a_task_intake_receipt.json",
        "risk_decision": output_root / "p0a_risk_decision.json",
        "allowed_execution_scope": output_root / "p0a_allowed_execution_scope.json",
        "summary": output_root / "p0a_task_intake_chain_summary.json",
    }
    intake = _load_task_intake(task_intake_path)
    task_receipt = write_task_intake_receipt(
        i2h_summary_path=i2h_summary_path,
        task_intake=intake,
        output=artifacts["task_intake_receipt"],
    )
    risk_decision = write_risk_decision(
        intake_receipt_path=artifacts["task_intake_receipt"],
        output=artifacts["risk_decision"],
    )
    allowed_scope = write_allowed_execution_scope(
        intake_receipt_path=artifacts["task_intake_receipt"],
        risk_decision_path=artifacts["risk_decision"],
        output=artifacts["allowed_execution_scope"],
    )
    reports = [task_receipt, risk_decision, allowed_scope]
    passed = all(report.get("passed") is True for report in reports)
    summary = {
        "schema_version": CHAIN_SCHEMA,
        "passed": passed,
        "failure_reasons": _collect_failures(*reports),
        "source_artifacts": {"i2h_summary": artifact_ref(i2h_summary_path)},
        "artifacts": {name: artifact_ref(path) for name, path in artifacts.items() if name != "summary"},
        "selected_task": {
            "task_id": intake.get("task_id"),
            "title": intake.get("title"),
            "task_class": intake.get("task_class"),
            "risk_class": intake.get("risk_class"),
            "owner_id": object_value(intake.get("owner")).get("id"),
            "audit_owner_id": object_value(intake.get("audit_owner")).get("id"),
            "rollback_owner_id": object_value(intake.get("rollback_owner")).get("id"),
            "vm_target_ids": [item.get("id") for item in _objects(intake.get("vm_targets"))],
            "service_token_scopes": _strings(object_value(intake.get("service_token")).get("scopes")),
        },
        "readiness": {
            "state": "p0a_task_intake_passed" if passed else "blocked_p0a_task_intake",
            "p0b_agent_proposal_gate_ready": passed,
            "p0c_execution_allowed": False,
            "production_transition_allowed": False,
        },
        "boundary": _boundary(
            intake_recording_allowed=True,
            risk_decision_recording_allowed=passed,
            allowed_scope_recording_allowed=passed,
        ),
        "non_claims": [
            "p0a_does_not_contact_vms",
            "p0a_does_not_start_agents",
            "p0a_does_not_deploy",
            "p0a_does_not_mutate_runtime_state",
            "p0a_does_not_authorize_production_transition",
            "p0a_does_not_write_production_receipt",
        ],
    }
    write_json_object(artifacts["summary"], summary)
    return summary


def write_task_intake_receipt(*, i2h_summary_path: Path, task_intake: dict[str, Any], output: Path) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    i2h = read_json_object(i2h_summary_path)
    readiness = object_value(i2h.get("readiness"))
    boundary = object_value(i2h.get("boundary"))
    service_token = object_value(task_intake.get("service_token"))
    owner = object_value(task_intake.get("owner"))
    operator = object_value(task_intake.get("operator"))
    audit_owner = object_value(task_intake.get("audit_owner"))
    rollback_owner = object_value(task_intake.get("rollback_owner"))
    rollback = object_value(task_intake.get("rollback"))
    audit = object_value(task_intake.get("audit"))
    vm_targets = _objects(task_intake.get("vm_targets"))
    scopes = _strings(service_token.get("scopes"))
    forbidden_operations = set(_strings(task_intake.get("forbidden_operations")))

    check(checks, failures, "i2h_summary_passed", i2h.get("schema_version") == I2H_SCHEMA and i2h.get("passed") is True)
    check(checks, failures, "i2h_p0_ready", readiness.get("p0_controlled_pilot_discussion_ready") is True)
    check(checks, failures, "i2h_deploy_closed", boundary.get("deploy_allowed") is False)
    check(checks, failures, "i2h_production_closed", boundary.get("production_transition_allowed") is False and boundary.get("production_receipt_write_allowed") is False)
    check(checks, failures, "task_intake_schema", task_intake.get("schema_version") == TASK_INTAKE_SCHEMA)
    check(checks, failures, "task_id_present", bool(_text(task_intake.get("task_id"))))
    check(checks, failures, "task_title_present", bool(_text(task_intake.get("title"))))
    check(checks, failures, "task_class_allowed", task_intake.get("task_class") in ALLOWED_TASK_CLASSES)
    check(checks, failures, "risk_class_low", task_intake.get("risk_class") == "low")
    check(checks, failures, "owner_present_and_approved", bool(_text(owner.get("id"))) and owner.get("approval_state") == "approved_for_p0a_intake")
    check(checks, failures, "operator_present", bool(_text(operator.get("id"))))
    check(checks, failures, "audit_owner_present", bool(_text(audit_owner.get("id"))))
    check(checks, failures, "rollback_owner_present", bool(_text(rollback_owner.get("id"))))
    check(checks, failures, "audit_owner_distinct_from_owner", _text(audit_owner.get("id")) not in {"", _text(owner.get("id"))})
    check(checks, failures, "rollback_owner_distinct_from_owner", _text(rollback_owner.get("id")) not in {"", _text(owner.get("id"))})
    check(checks, failures, "vm_targets_complete", _vm_targets_complete(vm_targets))
    check(checks, failures, "service_token_secret_not_in_artifact", service_token.get("secret_material_in_artifact") is False)
    check(checks, failures, "service_token_production_false", service_token.get("production_allowed") is False)
    check(checks, failures, "service_token_evidence_false", service_token.get("evidence_allowed") is False)
    check(checks, failures, "demo_login_disabled", service_token.get("demo_login_allowed") is False)
    check(checks, failures, "service_scopes_required_present", REQUIRED_SERVICE_SCOPES.issubset(set(scopes)))
    check(checks, failures, "service_scopes_allowlisted", bool(scopes) and set(scopes).issubset(ALLOWED_SERVICE_SCOPES))
    check(checks, failures, "service_scopes_no_forbidden_tokens", _scopes_have_no_forbidden_tokens(scopes))
    check(checks, failures, "forbidden_operations_complete", REQUIRED_FORBIDDEN_OPERATIONS.issubset(forbidden_operations))
    check(checks, failures, "allowed_systems_present", bool(_strings(task_intake.get("allowed_systems"))))
    check(checks, failures, "allowed_files_present", bool(_strings(task_intake.get("allowed_files"))))
    check(checks, failures, "rollback_procedure_written", rollback.get("procedure_written") is True and bool(_text(rollback.get("command"))))
    check(checks, failures, "rollback_owner_matches", rollback.get("owner_id") == rollback_owner.get("id"))
    check(checks, failures, "rollback_dry_run_required_before_execution", rollback.get("dry_run_required_before_p0c") is True)
    check(checks, failures, "audit_owner_matches", audit.get("owner_id") == audit_owner.get("id"))
    check(checks, failures, "audit_required_receipts_present", bool(_strings(audit.get("required_receipts"))))
    passed = _all_checks(checks, failures)
    report = {
        "schema_version": INTAKE_RECEIPT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "source_artifacts": {"i2h_summary": artifact_ref(i2h_summary_path)},
        "task_intake": task_intake,
        "readiness": {
            "state": "p0a_task_intake_accepted" if passed else "blocked_p0a_task_intake_receipt",
            "risk_review_ready": passed,
            "p0c_execution_allowed": False,
        },
        "boundary": _boundary(intake_recording_allowed=True),
    }
    write_json_object(output, report)
    return report


def write_risk_decision(*, intake_receipt_path: Path, output: Path) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    receipt = read_json_object(intake_receipt_path)
    intake = object_value(receipt.get("task_intake"))
    forbidden_operations = set(_strings(intake.get("forbidden_operations")))
    check(checks, failures, "intake_receipt_passed", receipt.get("schema_version") == INTAKE_RECEIPT_SCHEMA and receipt.get("passed") is True)
    check(checks, failures, "risk_low", intake.get("risk_class") == "low")
    check(checks, failures, "task_class_low_risk_allowed", intake.get("task_class") in ALLOWED_TASK_CLASSES)
    check(checks, failures, "forbidden_operations_cover_high_risk", REQUIRED_FORBIDDEN_OPERATIONS.issubset(forbidden_operations))
    check(checks, failures, "rollback_before_execution_required", object_value(intake.get("rollback")).get("dry_run_required_before_p0c") is True)
    check(checks, failures, "no_production_scope_requested", _scopes_have_no_forbidden_tokens(_strings(object_value(intake.get("service_token")).get("scopes"))))
    passed = _all_checks(checks, failures)
    decision = "accept_low_risk_p0_task_intake" if passed else "blocked_p0a_risk_decision"
    report = {
        "schema_version": RISK_DECISION_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "source_artifacts": {"task_intake_receipt": artifact_ref(intake_receipt_path)},
        "risk_decision": {
            "decision": decision,
            "risk_class": intake.get("risk_class"),
            "task_class": intake.get("task_class"),
            "approved_for_p0b": passed,
            "approved_for_execution": False,
            "reason": "Low-risk P0 task intake may proceed to Agent proposal gate only." if passed else "P0-A risk controls failed.",
        },
        "readiness": {"state": decision, "p0b_agent_proposal_gate_ready": passed, "p0c_execution_allowed": False},
        "boundary": _boundary(risk_decision_recording_allowed=True),
    }
    write_json_object(output, report)
    return report


def write_allowed_execution_scope(*, intake_receipt_path: Path, risk_decision_path: Path, output: Path) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    receipt = read_json_object(intake_receipt_path)
    risk = read_json_object(risk_decision_path)
    intake = object_value(receipt.get("task_intake"))
    service_token = object_value(intake.get("service_token"))
    check(checks, failures, "intake_receipt_passed", receipt.get("schema_version") == INTAKE_RECEIPT_SCHEMA and receipt.get("passed") is True)
    check(checks, failures, "risk_decision_passed", risk.get("schema_version") == RISK_DECISION_SCHEMA and risk.get("passed") is True)
    check(checks, failures, "service_token_scopes_bounded", set(_strings(service_token.get("scopes"))).issubset(ALLOWED_SERVICE_SCOPES))
    check(checks, failures, "execution_still_blocked", True)
    passed = _all_checks(checks, failures)
    report = {
        "schema_version": ALLOWED_SCOPE_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "source_artifacts": {
            "task_intake_receipt": artifact_ref(intake_receipt_path),
            "risk_decision": artifact_ref(risk_decision_path),
        },
        "allowed_execution_scope": {
            "scope_id": "p0a-scope:agent-proposal-only-before-execution",
            "task_id": intake.get("task_id"),
            "allowed_next_gate": "P0-B Agent Proposal Gate",
            "allowed_task_class": intake.get("task_class"),
            "allowed_vm_targets": _objects(intake.get("vm_targets")),
            "allowed_service_token_scopes": _strings(service_token.get("scopes")),
            "allowed_systems": _strings(intake.get("allowed_systems")),
            "allowed_files": _strings(intake.get("allowed_files")),
            "forbidden_operations": _strings(intake.get("forbidden_operations")),
            "rollback_command": object_value(intake.get("rollback")).get("command"),
            "p0b_agent_proposal_allowed": passed,
            "p0c_execution_allowed": False,
            "vm_contact_allowed": False,
            "agent_start_allowed": False,
            "deploy_allowed": False,
            "runtime_state_mutation_allowed": False,
            "production_transition_allowed": False,
            "production_receipt_write_allowed": False,
        },
        "readiness": {
            "state": "p0a_allowed_scope_recorded" if passed else "blocked_p0a_allowed_scope",
            "p0b_agent_proposal_gate_ready": passed,
            "p0c_execution_allowed": False,
        },
        "boundary": _boundary(allowed_scope_recording_allowed=True),
    }
    write_json_object(output, report)
    return report


def _load_task_intake(path: Path | None) -> dict[str, Any]:
    if path is None:
        return json.loads(json.dumps(DEFAULT_TASK_INTAKE, sort_keys=True))
    return read_json_object(path)


def _vm_targets_complete(vm_targets: list[dict[str, Any]]) -> bool:
    by_id = {str(item.get("id") or ""): item for item in vm_targets}
    for vm_id, role in REQUIRED_VM_ROLES.items():
        target = by_id.get(vm_id)
        if not target:
            return False
        if target.get("role") != role:
            return False
        if not _text(target.get("ssh_alias")) or not _text(target.get("address")):
            return False
    return len(by_id) == len(REQUIRED_VM_ROLES)


def _scopes_have_no_forbidden_tokens(scopes: list[str]) -> bool:
    for scope in scopes:
        compact = scope.strip().lower()
        if compact == "*" or compact.endswith(":*"):
            return False
        parts = compact.replace("-", ":").replace("_", ":").split(":")
        if any(token in parts or token in compact for token in FORBIDDEN_SCOPE_TOKENS):
            return False
    return True


def _boundary(**overrides: bool) -> dict[str, bool]:
    base = {
        "intake_recording_allowed": False,
        "risk_decision_recording_allowed": False,
        "allowed_scope_recording_allowed": False,
        "vm_contact_allowed": False,
        "agent_start_allowed": False,
        "task_pool_post_allowed": False,
        "source_tree_write_allowed": False,
        "git_write_allowed": False,
        "deploy_allowed": False,
        "runtime_state_mutation_allowed": False,
        "production_transition_allowed": False,
        "production_receipt_write_allowed": False,
    }
    base.update(overrides)
    return base


def _collect_failures(*reports: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    for report in reports:
        failures.extend(str(item) for item in report.get("failure_reasons", []))
    return failures


def _all_checks(checks: dict[str, bool], failures: list[str]) -> bool:
    return bool(checks) and all(checks.values()) and not failures


def _objects(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    if not isinstance(value, list):
        return []
    return [str(item).strip() for item in value if str(item).strip()]


def _text(value: Any) -> str:
    return str(value or "").strip()


def main() -> int:
    parser = argparse.ArgumentParser(description="Run P0-A task intake gate")
    parser.add_argument("--i2h-summary", required=True)
    parser.add_argument("--output-root", required=True)
    parser.add_argument("--task-intake")
    args = parser.parse_args()
    summary = run_gate(
        i2h_summary_path=Path(args.i2h_summary),
        output_root=Path(args.output_root),
        task_intake_path=Path(args.task_intake) if args.task_intake else None,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if summary.get("passed") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
