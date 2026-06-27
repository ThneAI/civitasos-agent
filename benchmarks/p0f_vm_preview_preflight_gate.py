"""Run P0-F VM preview preflight gate.

P0-F consumes a passed P0-E rollback/abort drill summary and validates the
bounded VM preview prerequisites before any VM contact or deploy is allowed.
It verifies the VM target, service-token scope surface, rollback runbook,
monitoring/audit ownership, no-public-ingress posture, and no-production
boundary. It does not contact VMs, issue tokens, deploy, mutate source/Git, or
write production receipts.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from benchmarks.i_gate_evidence import artifact_ref, check, object_value, read_json_object, sha256_file, write_json_object
from benchmarks.p0c_controlled_task_pool_execution import PREVIEW_SCHEMA
from benchmarks.p0d_preview_smoke_gate import CHAIN_SCHEMA as P0D_CHAIN_SCHEMA
from benchmarks.p0d_preview_smoke_gate import INTEGRITY_SCHEMA as P0D_INTEGRITY_SCHEMA
from benchmarks.p0e_rollback_abort_drill_gate import (
    CHAIN_SCHEMA as P0E_CHAIN_SCHEMA,
    NO_PRODUCTION_BOUNDARY_SCHEMA as P0E_NO_PRODUCTION_BOUNDARY_SCHEMA,
    OWNER_AUDIT_DECISION_SCHEMA as P0E_OWNER_AUDIT_DECISION_SCHEMA,
    ROLLBACK_ABORT_DRILL_SCHEMA as P0E_ROLLBACK_ABORT_DRILL_SCHEMA,
)

CHAIN_SCHEMA = "p0f-vm-preview-preflight-chain:v1"
CONTEXT_SCHEMA = "p0f-p0e-context-validation:v1"
VM_TARGET_SCHEMA = "p0f-vm-target-preflight:v1"
SERVICE_SCOPE_SCHEMA = "p0f-service-token-scope-review:v1"
ROLLBACK_RUNBOOK_SCHEMA = "p0f-rollback-runbook-review:v1"
OWNER_MONITORING_AUDIT_SCHEMA = "p0f-owner-monitoring-audit-review:v1"
NO_PUBLIC_INGRESS_SCHEMA = "p0f-no-public-ingress-no-production-review:v1"

DEFAULT_VM_TARGET_ID = "vm1"
DEFAULT_MONITORING_OWNER_ID = "observability_owner"

REQUIRED_PREVIEW_SCOPES = {
    "agents:read",
    "agents:write",
    "audit:read",
    "pool:claim",
    "pool:post",
    "pool:read",
    "pool:write",
    "webhooks:write",
}
FORBIDDEN_SCOPE_FRAGMENTS = (
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
ROLLBACK_RUNBOOK_TERMS = ("stop", "restore", "remove", "verify")


def run_gate(
    *,
    p0e_summary_path: Path,
    output_root: Path,
    vm_target_id: str = DEFAULT_VM_TARGET_ID,
    monitoring_owner_id: str = DEFAULT_MONITORING_OWNER_ID,
    operator_id: str = "operator-cc",
    service_token_scopes: list[str] | None = None,
) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "vm_target_preflight": output_root / "p0f_vm_target_preflight.json",
        "service_token_scope_review": output_root / "p0f_service_token_scope_review.json",
        "rollback_runbook_review": output_root / "p0f_rollback_runbook_review.json",
        "owner_monitoring_audit_review": output_root / "p0f_owner_monitoring_audit_review.json",
        "no_public_ingress_no_production_review": output_root / "p0f_no_public_ingress_no_production_review.json",
        "summary": output_root / "p0f_vm_preview_preflight_chain_summary.json",
    }
    context = validate_p0e_context(p0e_summary_path)
    vm_target = write_vm_target_preflight(
        context=context,
        p0e_summary_path=p0e_summary_path,
        output=artifacts["vm_target_preflight"],
        vm_target_id=vm_target_id,
    )
    scope = write_service_token_scope_review(
        context=context,
        vm_target_preflight_path=artifacts["vm_target_preflight"],
        output=artifacts["service_token_scope_review"],
        requested_scopes=service_token_scopes,
    )
    rollback = write_rollback_runbook_review(
        context=context,
        service_token_scope_review_path=artifacts["service_token_scope_review"],
        output=artifacts["rollback_runbook_review"],
    )
    owners = write_owner_monitoring_audit_review(
        context=context,
        rollback_runbook_review_path=artifacts["rollback_runbook_review"],
        output=artifacts["owner_monitoring_audit_review"],
        monitoring_owner_id=monitoring_owner_id,
        operator_id=operator_id,
    )
    boundary = write_no_public_ingress_no_production_review(
        context=context,
        owner_monitoring_audit_review_path=artifacts["owner_monitoring_audit_review"],
        output=artifacts["no_public_ingress_no_production_review"],
    )
    reports = [context, vm_target, scope, rollback, owners, boundary]
    passed = all(report.get("passed") is True for report in reports)
    summary = {
        "schema_version": CHAIN_SCHEMA,
        "passed": passed,
        "failure_reasons": _failures(reports),
        "checked_at": _now(),
        "task_id": context.get("task_id"),
        "vm_target_id": vm_target_id,
        "monitoring_owner_id": monitoring_owner_id,
        "operator_id": operator_id,
        "source_artifacts": {"p0e_summary": artifact_ref(p0e_summary_path)},
        "artifacts": {name: artifact_ref(path) for name, path in artifacts.items() if name != "summary"},
        "readiness": {
            "state": "p0f_vm_preview_preflight_passed" if passed else "blocked_p0f_vm_preview_preflight",
            "p0f_vm_preview_preflight_complete": passed,
            "p0g_single_vm_private_preview_ready": passed,
            "production_transition_allowed": False,
        },
        "boundary": _boundary(
            vm_target_validated=vm_target.get("passed") is True,
            service_token_scope_validated=scope.get("passed") is True,
            rollback_runbook_validated=rollback.get("passed") is True,
            owner_monitoring_audit_validated=owners.get("passed") is True,
            no_public_ingress_validated=boundary.get("checks", {}).get("no_public_ingress_closed") is True,
            no_production_boundary_validated=boundary.get("passed") is True,
        ),
        "non_claims": _non_claims(),
    }
    write_json_object(artifacts["summary"], summary)
    return summary


def validate_p0e_context(p0e_summary_path: Path) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    try:
        p0e = read_json_object(p0e_summary_path)
    except Exception as exc:  # noqa: BLE001
        return _report(CONTEXT_SCHEMA, False, [f"p0e_summary_unreadable:{exc}"], checks)

    p0e_refs = object_value(p0e.get("artifacts"))
    owner_decision = _read_verified_ref(p0e_refs.get("owner_audit_decision"), checks, failures, "p0e_owner_audit_decision")
    p0e_boundary_review = _read_verified_ref(
        p0e_refs.get("no_production_boundary_review"), checks, failures, "p0e_no_production_boundary_review"
    )
    rollback_receipt = _read_verified_ref(p0e_refs.get("rollback_abort_drill_receipt"), checks, failures, "p0e_rollback_abort_drill_receipt")
    p0d_summary = _read_verified_ref(
        object_value(p0e.get("source_artifacts")).get("p0d_summary"), checks, failures, "p0d_summary"
    )
    p0d_integrity = _read_verified_ref(
        object_value(p0d_summary.get("artifacts")).get("artifact_integrity"), checks, failures, "p0d_artifact_integrity"
    )
    preview = _read_verified_ref(
        object_value(p0d_integrity.get("verified_artifacts")).get("preview_artifact"), checks, failures, "p0c_preview_artifact"
    )
    p0c_summary = _read_verified_ref(
        object_value(p0d_summary.get("source_artifacts")).get("p0c_execution_summary"), checks, failures, "p0c_execution_summary"
    )

    readiness = object_value(p0e.get("readiness"))
    p0e_boundary = object_value(p0e.get("boundary"))
    p0d_boundary = object_value(p0d_summary.get("boundary"))
    p0c_boundary = object_value(p0c_summary.get("boundary"))
    selected_task = object_value(preview.get("selected_task")) or object_value(p0c_summary.get("selected_task"))
    execution_scope = object_value(preview.get("execution_scope"))
    task_id = str(p0e.get("task_id") or rollback_receipt.get("task_id") or p0d_summary.get("task_id") or "")

    check(checks, failures, "p0e_summary_passed", p0e.get("schema_version") == P0E_CHAIN_SCHEMA and p0e.get("passed") is True)
    check(checks, failures, "p0e_ready_for_p0f", readiness.get("p0f_vm_preview_preflight_ready") is True)
    check(checks, failures, "p0e_production_transition_closed", readiness.get("production_transition_allowed") is False)
    check(checks, failures, "p0e_boundary_closed", _closed_no_production_boundary(p0e_boundary))
    check(
        checks,
        failures,
        "p0e_owner_decision_passed",
        owner_decision.get("schema_version") == P0E_OWNER_AUDIT_DECISION_SCHEMA and owner_decision.get("passed") is True,
    )
    check(
        checks,
        failures,
        "p0e_boundary_review_passed",
        p0e_boundary_review.get("schema_version") == P0E_NO_PRODUCTION_BOUNDARY_SCHEMA and p0e_boundary_review.get("passed") is True,
    )
    check(
        checks,
        failures,
        "p0e_rollback_abort_receipt_passed",
        rollback_receipt.get("schema_version") == P0E_ROLLBACK_ABORT_DRILL_SCHEMA and rollback_receipt.get("passed") is True,
    )
    check(checks, failures, "p0d_summary_passed", p0d_summary.get("schema_version") == P0D_CHAIN_SCHEMA and p0d_summary.get("passed") is True)
    check(checks, failures, "p0d_integrity_passed", p0d_integrity.get("schema_version") == P0D_INTEGRITY_SCHEMA and p0d_integrity.get("passed") is True)
    check(checks, failures, "p0c_preview_passed", preview.get("schema_version") == PREVIEW_SCHEMA and preview.get("passed") is True)
    check(checks, failures, "p0e_task_matches", rollback_receipt.get("task_id") == task_id)
    check(checks, failures, "p0d_boundary_closed", _closed_no_production_boundary(p0d_boundary))
    check(checks, failures, "p0c_boundary_closed", _closed_no_production_boundary(p0c_boundary))
    check(checks, failures, "preview_boundary_closed", _closed_no_production_boundary(object_value(preview.get("boundary"))))
    check(
        checks,
        failures,
        "p0e_boundary_review_closed",
        _closed_no_production_boundary(object_value(p0e_boundary_review.get("boundary_review"))),
    )
    check(checks, failures, "selected_task_present", bool(selected_task.get("task_id")))
    check(checks, failures, "allowed_vm_targets_present", bool(_allowed_vm_targets(execution_scope)))
    check(checks, failures, "allowed_service_scopes_present", bool(_allowed_service_scopes(execution_scope, selected_task)))

    return {
        "schema_version": CONTEXT_SCHEMA,
        "passed": bool(checks) and all(checks.values()) and not failures,
        "failure_reasons": failures,
        "checks": checks,
        "task_id": task_id,
        "source_artifacts": {"p0e_summary": artifact_ref(p0e_summary_path)},
        "p0e_summary": p0e,
        "p0d_summary": p0d_summary,
        "p0c_summary": p0c_summary,
        "owner_decision": owner_decision,
        "p0e_boundary_review": p0e_boundary_review,
        "rollback_receipt": rollback_receipt,
        "p0d_integrity": p0d_integrity,
        "preview_artifact": preview,
        "selected_task": selected_task,
        "allowed_vm_targets": _allowed_vm_targets(execution_scope),
        "allowed_service_token_scopes": _allowed_service_scopes(execution_scope, selected_task),
    }


def write_vm_target_preflight(*, context: dict[str, Any], p0e_summary_path: Path, output: Path, vm_target_id: str) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    targets = _allowed_vm_targets(object_value(object_value(context.get("preview_artifact")).get("execution_scope")))
    selected_task = object_value(context.get("selected_task"))
    selected_vm_ids = _strings(selected_task.get("vm_target_ids"))
    target = next((item for item in targets if item.get("id") == vm_target_id), {})
    check(checks, failures, "p0e_context_passed", context.get("passed") is True)
    check(checks, failures, "vm_target_id_present", bool(str(vm_target_id).strip()))
    check(checks, failures, "vm_target_authorized_by_selected_task", vm_target_id in selected_vm_ids)
    check(checks, failures, "vm_target_descriptor_present", bool(target))
    check(checks, failures, "vm_target_has_private_address", _is_private_vm_address(str(target.get("address") or "")))
    check(checks, failures, "vm_target_has_ssh_alias", bool(target.get("ssh_alias")))
    passed = _passed(checks, failures)
    report = {
        "schema_version": VM_TARGET_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "task_id": context.get("task_id"),
        "vm_target_id": vm_target_id,
        "vm_target": target,
        "authorized_vm_target_ids": selected_vm_ids,
        "source_artifacts": {"p0e_summary": artifact_ref(p0e_summary_path)},
        "boundary": _boundary(vm_target_validated=passed),
    }
    write_json_object(output, report)
    return report


def write_service_token_scope_review(
    *,
    context: dict[str, Any],
    vm_target_preflight_path: Path,
    output: Path,
    requested_scopes: list[str] | None,
) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    vm_target = read_json_object(vm_target_preflight_path)
    allowed = _strings(context.get("allowed_service_token_scopes"))
    scopes = _strings(requested_scopes) if requested_scopes is not None else allowed
    check(checks, failures, "vm_target_preflight_passed", vm_target.get("passed") is True)
    check(checks, failures, "scopes_present", bool(scopes))
    check(checks, failures, "scopes_match_upstream_allowed_set", sorted(scopes) == sorted(allowed))
    check(checks, failures, "required_preview_scopes_present", REQUIRED_PREVIEW_SCOPES.issubset(set(scopes)))
    check(checks, failures, "no_forbidden_scope_fragment", _scopes_have_no_forbidden_tokens(scopes))
    check(checks, failures, "token_not_issued", True)
    check(checks, failures, "secret_not_recorded", True)
    passed = _passed(checks, failures)
    report = {
        "schema_version": SERVICE_SCOPE_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "task_id": context.get("task_id"),
        "service_token_scope_review": {
            "mode": "scope_review_only_no_token_issuance",
            "requested_scopes": scopes,
            "upstream_allowed_scopes": allowed,
            "token_issued": False,
            "secret_recorded": False,
            "production_allowed": False,
        },
        "source_artifacts": {"vm_target_preflight": artifact_ref(vm_target_preflight_path)},
        "boundary": _boundary(service_token_scope_validated=passed),
    }
    write_json_object(output, report)
    return report


def write_rollback_runbook_review(*, context: dict[str, Any], service_token_scope_review_path: Path, output: Path) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    scope = read_json_object(service_token_scope_review_path)
    rollback_receipt = object_value(context.get("rollback_receipt"))
    runbook = str(rollback_receipt.get("rollback_command_from_p0c") or "").strip()
    runbook_lower = runbook.lower()
    check(checks, failures, "service_token_scope_review_passed", scope.get("passed") is True)
    check(checks, failures, "rollback_receipt_passed", rollback_receipt.get("passed") is True)
    check(checks, failures, "rollback_runbook_present", bool(runbook))
    for term in ROLLBACK_RUNBOOK_TERMS:
        check(checks, failures, f"rollback_runbook_contains_{term}", term in runbook_lower)
    check(checks, failures, "rollback_receipt_abort_only", rollback_receipt.get("abort_receipt_written") is True)
    check(checks, failures, "rollback_not_previously_performed", rollback_receipt.get("rollback_performed") is False)
    passed = _passed(checks, failures)
    report = {
        "schema_version": ROLLBACK_RUNBOOK_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "task_id": context.get("task_id"),
        "rollback_runbook": {
            "source": "p0e_rollback_abort_drill_receipt.rollback_command_from_p0c",
            "command": runbook,
            "rollback_performed": False,
            "abort_receipt_written": rollback_receipt.get("abort_receipt_written") is True,
        },
        "source_artifacts": {"service_token_scope_review": artifact_ref(service_token_scope_review_path)},
        "boundary": _boundary(rollback_runbook_validated=passed),
    }
    write_json_object(output, report)
    return report


def write_owner_monitoring_audit_review(
    *,
    context: dict[str, Any],
    rollback_runbook_review_path: Path,
    output: Path,
    monitoring_owner_id: str,
    operator_id: str,
) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    rollback = read_json_object(rollback_runbook_review_path)
    decision = object_value(context.get("owner_decision"))
    check(checks, failures, "rollback_runbook_review_passed", rollback.get("passed") is True)
    check(checks, failures, "owner_id_present", bool(str(decision.get("owner_id") or "").strip()))
    check(checks, failures, "audit_owner_id_present", bool(str(decision.get("audit_owner_id") or "").strip()))
    check(checks, failures, "rollback_owner_id_present", bool(str(decision.get("rollback_owner_id") or "").strip()))
    check(checks, failures, "monitoring_owner_id_present", bool(str(monitoring_owner_id).strip()))
    check(checks, failures, "operator_id_present", bool(str(operator_id).strip()))
    check(checks, failures, "owner_decision_approved", decision.get("owner_decision") == "approve_rollback_abort_drill")
    check(checks, failures, "audit_decision_approved", decision.get("audit_decision") == "approve_no_production_boundary")
    check(checks, failures, "rollback_owner_decision_approved", decision.get("rollback_owner_decision") == "approve_abort_only_receipt")
    passed = _passed(checks, failures)
    report = {
        "schema_version": OWNER_MONITORING_AUDIT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "task_id": context.get("task_id"),
        "operator_id": operator_id,
        "owners": {
            "owner_id": decision.get("owner_id"),
            "audit_owner_id": decision.get("audit_owner_id"),
            "rollback_owner_id": decision.get("rollback_owner_id"),
            "monitoring_owner_id": monitoring_owner_id,
        },
        "source_artifacts": {"rollback_runbook_review": artifact_ref(rollback_runbook_review_path)},
        "boundary": _boundary(owner_monitoring_audit_validated=passed),
    }
    write_json_object(output, report)
    return report


def write_no_public_ingress_no_production_review(
    *,
    context: dict[str, Any],
    owner_monitoring_audit_review_path: Path,
    output: Path,
) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    owners = read_json_object(owner_monitoring_audit_review_path)
    p0e = object_value(context.get("p0e_summary"))
    p0d = object_value(context.get("p0d_summary"))
    p0c = object_value(context.get("p0c_summary"))
    p0e_boundary_review = object_value(object_value(context.get("p0e_boundary_review")).get("boundary_review"))
    preview = object_value(context.get("preview_artifact"))
    check(checks, failures, "owner_monitoring_audit_review_passed", owners.get("passed") is True)
    check(checks, failures, "p0e_boundary_closed", _closed_no_production_boundary(object_value(p0e.get("boundary"))))
    check(checks, failures, "p0e_boundary_review_closed", _closed_no_production_boundary(p0e_boundary_review))
    check(checks, failures, "p0d_boundary_closed", _closed_no_production_boundary(object_value(p0d.get("boundary"))))
    check(checks, failures, "p0c_boundary_closed", _closed_no_production_boundary(object_value(p0c.get("boundary"))))
    check(checks, failures, "preview_boundary_closed", _closed_no_production_boundary(object_value(preview.get("boundary"))))
    check(checks, failures, "no_public_ingress_closed", _all_boundaries_false("external_public_ingress_opened", p0e, p0d, p0c, preview))
    check(checks, failures, "no_vm_contact_yet", _all_boundaries_false("vm_contact_performed", p0e, p0d, p0c, preview))
    check(checks, failures, "no_deploy_yet", _all_boundaries_false("deploy_performed", p0e, p0d, p0c, preview))
    check(checks, failures, "no_source_or_git_write", _all_boundaries_false("source_tree_write_performed", p0e, p0d, p0c, preview) and _all_boundaries_false("git_write_performed", p0e, p0d, p0c, preview))
    check(checks, failures, "no_production_transition", _all_boundaries_false("production_transition_allowed", p0e, p0d, p0c, preview))
    check(checks, failures, "no_production_receipt", _all_boundaries_false("production_receipt_write_allowed", p0e, p0d, p0c, preview))
    passed = _passed(checks, failures)
    report = {
        "schema_version": NO_PUBLIC_INGRESS_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "task_id": context.get("task_id"),
        "boundary_review": {
            "vm_contact_performed": False,
            "deploy_performed": False,
            "source_tree_write_performed": False,
            "git_write_performed": False,
            "external_public_ingress_opened": False,
            "production_transition_allowed": False,
            "production_receipt_write_allowed": False,
            "production_data_accessed": False,
            "secrets_recorded": False,
        },
        "source_artifacts": {"owner_monitoring_audit_review": artifact_ref(owner_monitoring_audit_review_path)},
        "boundary": _boundary(no_public_ingress_validated=passed, no_production_boundary_validated=passed),
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


def _allowed_vm_targets(execution_scope: dict[str, Any]) -> list[dict[str, Any]]:
    value = execution_scope.get("allowed_vm_targets")
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _allowed_service_scopes(execution_scope: dict[str, Any], selected_task: dict[str, Any]) -> list[str]:
    scopes = _strings(execution_scope.get("allowed_service_token_scopes"))
    if scopes:
        return scopes
    return _strings(selected_task.get("service_token_scopes"))


def _closed_no_production_boundary(boundary: dict[str, Any]) -> bool:
    required_false = (
        "vm_contact_performed",
        "deploy_performed",
        "source_tree_write_performed",
        "git_write_performed",
        "external_public_ingress_opened",
        "production_transition_allowed",
        "production_receipt_write_allowed",
    )
    return all(boundary.get(key) is False for key in required_false)


def _all_boundaries_false(key: str, *objects: dict[str, Any]) -> bool:
    return all(object_value(item.get("boundary")).get(key) is False for item in objects)


def _is_private_vm_address(value: str) -> bool:
    return value.startswith(("10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "192.168."))


def _scopes_have_no_forbidden_tokens(scopes: list[str]) -> bool:
    lowered = [item.lower() for item in scopes]
    return all(not any(fragment in scope for fragment in FORBIDDEN_SCOPE_FRAGMENTS) for scope in lowered)


def _strings(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item).strip() for item in value if str(item).strip()]


def _boundary(**overrides: bool) -> dict[str, bool]:
    base = {
        "vm_target_validated": False,
        "service_token_scope_validated": False,
        "rollback_runbook_validated": False,
        "owner_monitoring_audit_validated": False,
        "no_public_ingress_validated": False,
        "no_production_boundary_validated": False,
        "vm_contact_performed": False,
        "deploy_performed": False,
        "source_tree_write_performed": False,
        "git_write_performed": False,
        "external_public_ingress_opened": False,
        "production_transition_allowed": False,
        "production_receipt_write_allowed": False,
    }
    base.update(overrides)
    return base


def _non_claims() -> list[str]:
    return [
        "p0f_is_preflight_only",
        "p0f_does_not_contact_vm_targets",
        "p0f_does_not_issue_service_tokens",
        "p0f_does_not_deploy",
        "p0f_does_not_modify_source_or_git",
        "p0f_does_not_open_public_ingress",
        "p0f_does_not_write_production_receipt",
        "p0f_does_not_authorize_production_transition",
    ]


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
    parser = argparse.ArgumentParser(description="Run P0-F VM preview preflight gate")
    parser.add_argument("--p0e-summary", required=True)
    parser.add_argument("--output-root", required=True)
    parser.add_argument("--vm-target-id", default=DEFAULT_VM_TARGET_ID)
    parser.add_argument("--monitoring-owner-id", default=DEFAULT_MONITORING_OWNER_ID)
    parser.add_argument("--operator-id", default="operator-cc")
    parser.add_argument("--service-token-scope", action="append", dest="service_token_scopes")
    args = parser.parse_args()
    summary = run_gate(
        p0e_summary_path=Path(args.p0e_summary),
        output_root=Path(args.output_root),
        vm_target_id=args.vm_target_id,
        monitoring_owner_id=args.monitoring_owner_id,
        operator_id=args.operator_id,
        service_token_scopes=args.service_token_scopes,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if summary.get("passed") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
