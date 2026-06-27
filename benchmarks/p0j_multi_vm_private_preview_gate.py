"""Run P0-J multi-VM private preview gate.

P0-J consumes a passed P0-I single-VM service preview summary and performs a
bounded backend/frontend private preview across multiple VM targets. It may
contact the configured VMs and run non-production preview/rollback commands.
It never opens public ingress, mutates source/Git, touches production data,
authorizes production transition, or writes production receipts.
"""

from __future__ import annotations

import argparse
import json
import shlex
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from benchmarks.i_gate_evidence import artifact_ref, check, object_value, read_json_object, sha256_file, write_json_object
from benchmarks.p0i_vm_service_private_preview_gate import (
    AUTHORIZATION_SCHEMA as P0I_AUTHORIZATION_SCHEMA,
    CHAIN_SCHEMA as P0I_CHAIN_SCHEMA,
    MONITORING_AUDIT_SCHEMA as P0I_MONITORING_AUDIT_SCHEMA,
    RECONCILIATION_SCHEMA as P0I_RECONCILIATION_SCHEMA,
    ROLLBACK_SCHEMA as P0I_ROLLBACK_SCHEMA,
    SERVICE_PREVIEW_SCHEMA as P0I_SERVICE_PREVIEW_SCHEMA,
)

CHAIN_SCHEMA = "p0j-multi-vm-private-preview-chain:v1"
CONTEXT_SCHEMA = "p0j-p0i-context-validation:v1"
AUTHORIZATION_SCHEMA = "p0j-multi-vm-private-preview-authorization:v1"
MULTI_VM_PREVIEW_SCHEMA = "p0j-multi-vm-private-preview-receipt:v1"
ROLLBACK_SCHEMA = "p0j-multi-vm-private-preview-rollback-receipt:v1"
MONITORING_AUDIT_SCHEMA = "p0j-multi-vm-private-preview-monitoring-audit-receipt:v1"
RECONCILIATION_SCHEMA = "p0j-multi-vm-private-preview-reconciliation:v1"
EXPECTED_SMOKE_SCHEMA = "beta5-real-backend-frontend-multivm-smoke:v1"
DEFAULT_EXPECTED_NODES = ("vm1", "vm2", "vm3")

NON_CLAIMS = (
    "p0j_is_multi_vm_private_service_preview_only",
    "p0j_requires_passed_p0i_single_vm_service_preview",
    "p0j_requires_explicit_operator_preview_authorization",
    "p0j_does_not_open_public_ingress",
    "p0j_does_not_touch_production_data",
    "p0j_does_not_modify_source_or_git",
    "p0j_does_not_write_production_receipts",
    "p0j_does_not_authorize_production_transition",
)


def run_gate(
    *,
    p0i_summary_path: Path,
    output_root: Path,
    deploy_command: str,
    smoke_command: str,
    rollback_command: str,
    rollback_health_command: str,
    expected_nodes: list[str] | None = None,
    operator_id: str = "operator-cc",
    ack_multi_vm_private_preview: bool = False,
    working_directory: Path | None = None,
) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "authorization": output_root / "p0j_multi_vm_private_preview_authorization.json",
        "multi_vm_preview_receipt": output_root / "p0j_multi_vm_private_preview_receipt.json",
        "rollback_receipt": output_root / "p0j_multi_vm_private_preview_rollback_receipt.json",
        "monitoring_audit_receipt": output_root / "p0j_multi_vm_private_preview_monitoring_audit_receipt.json",
        "reconciliation": output_root / "p0j_multi_vm_private_preview_reconciliation.json",
        "summary": output_root / "p0j_multi_vm_private_preview_chain_summary.json",
    }
    authorization = write_authorization(
        p0i_summary_path=p0i_summary_path,
        output=artifacts["authorization"],
        deploy_command=deploy_command,
        smoke_command=smoke_command,
        rollback_command=rollback_command,
        rollback_health_command=rollback_health_command,
        expected_nodes=expected_nodes or list(DEFAULT_EXPECTED_NODES),
        operator_id=operator_id,
        ack_multi_vm_private_preview=ack_multi_vm_private_preview,
        working_directory=working_directory or Path.cwd(),
    )
    preview = write_multi_vm_preview_receipt(
        authorization_path=artifacts["authorization"],
        output=artifacts["multi_vm_preview_receipt"],
    )
    rollback = write_rollback_receipt(
        authorization_path=artifacts["authorization"],
        multi_vm_preview_receipt_path=artifacts["multi_vm_preview_receipt"],
        output=artifacts["rollback_receipt"],
    )
    audit = write_monitoring_audit_receipt(
        authorization_path=artifacts["authorization"],
        multi_vm_preview_receipt_path=artifacts["multi_vm_preview_receipt"],
        rollback_receipt_path=artifacts["rollback_receipt"],
        output=artifacts["monitoring_audit_receipt"],
    )
    reconciliation = write_reconciliation(
        authorization_path=artifacts["authorization"],
        multi_vm_preview_receipt_path=artifacts["multi_vm_preview_receipt"],
        rollback_receipt_path=artifacts["rollback_receipt"],
        monitoring_audit_receipt_path=artifacts["monitoring_audit_receipt"],
        output=artifacts["reconciliation"],
    )
    reports = [authorization, preview, rollback, audit, reconciliation]
    passed = all(report.get("passed") is True for report in reports)
    summary = {
        "schema_version": CHAIN_SCHEMA,
        "passed": passed,
        "failure_reasons": _failures(reports),
        "checked_at": _now(),
        "task_id": authorization.get("task_id"),
        "vm_target_ids": authorization.get("expected_nodes", []),
        "operator_id": operator_id,
        "owners": authorization.get("owners", {}),
        "source_artifacts": {"p0i_summary": artifact_ref(p0i_summary_path)},
        "artifacts": {name: artifact_ref(path) for name, path in artifacts.items() if name != "summary"},
        "readiness": {
            "state": "p0j_multi_vm_private_preview_passed" if passed else "blocked_p0j_multi_vm_private_preview",
            "p0j_multi_vm_private_preview_complete": passed,
            "p0k_private_preview_soak_ready": passed,
            "production_transition_allowed": False,
        },
        "boundary": _boundary(
            private_preview_authorized=authorization.get("passed") is True,
            vm_contact_performed=object_value(preview.get("boundary")).get("vm_contact_performed") is True,
            multi_vm_private_preview_deploy_performed=preview.get("multi_vm_preview_performed") is True,
            multi_vm_smoke_performed=preview.get("multi_vm_smoke_performed") is True,
            rollback_performed=rollback.get("rollback_performed") is True,
            rollback_health_check_performed=rollback.get("rollback_health_check_performed") is True,
            monitoring_audit_receipt_written=audit.get("passed") is True,
            owner_reconciliation_written=reconciliation.get("passed") is True,
        ),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(artifacts["summary"], summary)
    return summary


def write_authorization(
    *,
    p0i_summary_path: Path,
    output: Path,
    deploy_command: str,
    smoke_command: str,
    rollback_command: str,
    rollback_health_command: str,
    expected_nodes: list[str],
    operator_id: str,
    ack_multi_vm_private_preview: bool,
    working_directory: Path,
) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    context = validate_p0i_context(p0i_summary_path)
    workdir = working_directory.resolve()
    normalized_nodes = _unique_texts(expected_nodes)
    commands = {
        "deploy_command": _command_argv_from_raw(deploy_command, failures, "deploy_command"),
        "smoke_command": _command_argv_from_raw(smoke_command, failures, "smoke_command"),
        "rollback_command": _command_argv_from_raw(rollback_command, failures, "rollback_command"),
        "rollback_health_command": _command_argv_from_raw(rollback_health_command, failures, "rollback_health_command"),
    }
    failures.extend(str(item) for item in context.get("failure_reasons", []))
    check(checks, failures, "p0i_context_passed", context.get("passed") is True)
    check(checks, failures, "operator_id_present", bool(str(operator_id).strip()))
    check(checks, failures, "explicit_operator_ack", ack_multi_vm_private_preview is True)
    check(checks, failures, "working_directory_exists", workdir.is_dir())
    check(checks, failures, "expected_nodes_present", len(normalized_nodes) >= 2)
    passed = _passed(checks, failures)
    authorization = {
        "schema_version": AUTHORIZATION_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "authorized_at": _now(),
        "task_id": context.get("task_id"),
        "operator_id": operator_id,
        "owners": context.get("owners", {}),
        "expected_nodes": normalized_nodes,
        "authorization_scope": "multi_vm_backend_frontend_private_preview_only",
        "working_directory": str(workdir),
        "deploy_command": {"raw": deploy_command, "argv": commands["deploy_command"], "shell": False},
        "smoke_command": {"raw": smoke_command, "argv": commands["smoke_command"], "shell": False},
        "rollback_command": {"raw": rollback_command, "argv": commands["rollback_command"], "shell": False},
        "rollback_health_command": {"raw": rollback_health_command, "argv": commands["rollback_health_command"], "shell": False},
        "source_artifacts": {"p0i_summary": artifact_ref(p0i_summary_path)},
        "p0i_artifacts": context.get("p0i_artifacts", {}),
        "boundary": _boundary(private_preview_authorized=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, authorization)
    return authorization


def validate_p0i_context(p0i_summary_path: Path) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    try:
        p0i = read_json_object(p0i_summary_path)
    except Exception as exc:  # noqa: BLE001
        return _report(CONTEXT_SCHEMA, False, [f"p0i_summary_unreadable:{exc}"], checks)
    refs = object_value(p0i.get("artifacts"))
    authorization = _read_verified_ref(refs.get("authorization"), checks, failures, "p0i_authorization")
    preview = _read_verified_ref(refs.get("service_preview_receipt"), checks, failures, "p0i_service_preview_receipt")
    rollback = _read_verified_ref(refs.get("rollback_receipt"), checks, failures, "p0i_rollback_receipt")
    audit = _read_verified_ref(refs.get("monitoring_audit_receipt"), checks, failures, "p0i_monitoring_audit_receipt")
    reconciliation = _read_verified_ref(refs.get("reconciliation"), checks, failures, "p0i_reconciliation")
    readiness = object_value(p0i.get("readiness"))
    boundary = object_value(p0i.get("boundary"))
    task_id = str(p0i.get("task_id") or authorization.get("task_id") or "")

    check(checks, failures, "p0i_summary_passed", p0i.get("schema_version") == P0I_CHAIN_SCHEMA and p0i.get("passed") is True)
    check(checks, failures, "p0i_ready_for_p0j", readiness.get("p0j_multi_vm_private_preview_ready") is True)
    check(checks, failures, "p0i_production_transition_closed", readiness.get("production_transition_allowed") is False)
    check(checks, failures, "p0i_authorization_passed", authorization.get("schema_version") == P0I_AUTHORIZATION_SCHEMA and authorization.get("passed") is True)
    check(checks, failures, "p0i_service_preview_passed", preview.get("schema_version") == P0I_SERVICE_PREVIEW_SCHEMA and preview.get("passed") is True)
    check(checks, failures, "p0i_rollback_passed", rollback.get("schema_version") == P0I_ROLLBACK_SCHEMA and rollback.get("passed") is True)
    check(checks, failures, "p0i_audit_passed", audit.get("schema_version") == P0I_MONITORING_AUDIT_SCHEMA and audit.get("passed") is True)
    check(checks, failures, "p0i_reconciliation_passed", reconciliation.get("schema_version") == P0I_RECONCILIATION_SCHEMA and reconciliation.get("passed") is True)
    check(checks, failures, "task_id_consistent", all(item.get("task_id") == task_id for item in (authorization, preview, rollback, audit, reconciliation)))
    check(checks, failures, "p0i_boundary_private_preview_observed", _single_vm_preview_observed(boundary))
    check(checks, failures, "p0i_boundary_closed", _closed_no_production_boundary(boundary))
    return {
        "schema_version": CONTEXT_SCHEMA,
        "passed": _passed(checks, failures),
        "failure_reasons": failures,
        "checks": checks,
        "task_id": task_id,
        "owners": object_value(p0i.get("owners")),
        "p0i_artifacts": refs,
        "p0i_summary": p0i,
    }


def write_multi_vm_preview_receipt(*, authorization_path: Path, output: Path) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    authorization = read_json_object(authorization_path)
    expected_nodes = _unique_texts(authorization.get("expected_nodes"))
    check(checks, failures, "authorization_passed", authorization.get("schema_version") == AUTHORIZATION_SCHEMA and authorization.get("passed") is True)
    workdir = Path(str(authorization.get("working_directory") or "")).resolve()
    deploy = _run_authorized_command(authorization, "deploy_command", workdir, failures) if authorization.get("passed") is True else None
    if deploy and deploy.get("returncode") != 0:
        failures.append("deploy_command_failed")
    deploy_succeeded = bool(deploy) and deploy.get("returncode") == 0
    smoke = _run_authorized_command(authorization, "smoke_command", workdir, failures) if deploy_succeeded else None
    if smoke and smoke.get("returncode") != 0:
        failures.append("smoke_command_failed")
    smoke_summary = _parse_json_from_stdout(str(object_value(smoke).get("stdout") or ""), failures, "smoke_summary") if smoke else {}
    smoke_nodes = _unique_texts(smoke_summary.get("nodes"))
    check(checks, failures, "deploy_command_success", deploy_succeeded)
    if deploy_succeeded:
        check(checks, failures, "smoke_command_success", bool(smoke) and smoke.get("returncode") == 0)
        check(checks, failures, "smoke_summary_schema", smoke_summary.get("schema_version") == EXPECTED_SMOKE_SCHEMA)
        check(checks, failures, "smoke_summary_passed", smoke_summary.get("passed") is True)
        check(checks, failures, "smoke_nodes_match_expected", set(smoke_nodes) == set(expected_nodes))
        check(checks, failures, "smoke_total_checks_cover_expected_nodes", int(smoke_summary.get("total_checks") or 0) >= len(expected_nodes))
        check(checks, failures, "smoke_production_deploy_closed", smoke_summary.get("production_deploy_allowed") is False)
        check(checks, failures, "smoke_production_runtime_closed", smoke_summary.get("production_runtime_execution_allowed") is False)
        check(checks, failures, "smoke_production_receipt_closed", smoke_summary.get("production_receipt_write_allowed") is False)
    else:
        checks["smoke_skipped_after_deploy_failure"] = True
    passed = _passed(checks, failures)
    receipt = {
        "schema_version": MULTI_VM_PREVIEW_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "completed_at": _now(),
        "task_id": authorization.get("task_id"),
        "expected_nodes": expected_nodes,
        "observed_nodes": smoke_nodes,
        "source_artifacts": {"authorization": artifact_ref(authorization_path)},
        "deploy": deploy,
        "smoke": smoke,
        "smoke_summary": smoke_summary,
        "multi_vm_preview_performed": deploy_succeeded,
        "multi_vm_smoke_performed": bool(smoke and smoke.get("returncode") == 0 and smoke_summary.get("passed") is True),
        "boundary": _boundary(
            vm_contact_performed=bool(deploy),
            multi_vm_private_preview_deploy_performed=deploy_succeeded,
            multi_vm_smoke_performed=bool(smoke and smoke.get("returncode") == 0 and smoke_summary.get("passed") is True),
        ),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, receipt)
    return receipt


def write_rollback_receipt(*, authorization_path: Path, multi_vm_preview_receipt_path: Path, output: Path) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    authorization = read_json_object(authorization_path)
    preview = read_json_object(multi_vm_preview_receipt_path)
    workdir = Path(str(authorization.get("working_directory") or "")).resolve()
    should_rollback = authorization.get("passed") is True and preview.get("multi_vm_preview_performed") is True
    rollback = _run_authorized_command(authorization, "rollback_command", workdir, failures) if should_rollback else None
    if rollback and rollback.get("returncode") != 0:
        failures.append("rollback_command_failed")
    rollback_health = _run_authorized_command(authorization, "rollback_health_command", workdir, failures) if rollback and rollback.get("returncode") == 0 else None
    if rollback_health and rollback_health.get("returncode") != 0:
        failures.append("rollback_health_command_failed")
    check(checks, failures, "authorization_passed", authorization.get("passed") is True)
    check(checks, failures, "multi_vm_preview_attempt_recorded", preview.get("schema_version") == MULTI_VM_PREVIEW_SCHEMA)
    if should_rollback:
        check(checks, failures, "rollback_command_success", bool(rollback) and rollback.get("returncode") == 0)
        check(checks, failures, "rollback_health_command_success", bool(rollback_health) and rollback_health.get("returncode") == 0)
    else:
        checks["rollback_not_required_no_deploy"] = True
    passed = _passed(checks, failures)
    receipt = {
        "schema_version": ROLLBACK_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "completed_at": _now(),
        "task_id": authorization.get("task_id"),
        "expected_nodes": authorization.get("expected_nodes", []),
        "source_artifacts": {
            "authorization": artifact_ref(authorization_path),
            "multi_vm_preview_receipt": artifact_ref(multi_vm_preview_receipt_path),
        },
        "rollback_needed": should_rollback,
        "rollback": rollback,
        "rollback_health": rollback_health,
        "rollback_performed": bool(rollback and rollback.get("returncode") == 0),
        "rollback_health_check_performed": bool(rollback_health and rollback_health.get("returncode") == 0),
        "boundary": _boundary(
            vm_contact_performed=bool(rollback),
            rollback_performed=bool(rollback and rollback.get("returncode") == 0),
            rollback_health_check_performed=bool(rollback_health and rollback_health.get("returncode") == 0),
        ),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, receipt)
    return receipt


def write_monitoring_audit_receipt(
    *,
    authorization_path: Path,
    multi_vm_preview_receipt_path: Path,
    rollback_receipt_path: Path,
    output: Path,
) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    authorization = read_json_object(authorization_path)
    preview = read_json_object(multi_vm_preview_receipt_path)
    rollback = read_json_object(rollback_receipt_path)
    check(checks, failures, "authorization_passed", authorization.get("passed") is True)
    check(checks, failures, "multi_vm_preview_passed", preview.get("passed") is True)
    check(checks, failures, "rollback_passed", rollback.get("passed") is True)
    check(checks, failures, "owners_present", bool(object_value(authorization.get("owners"))))
    check(checks, failures, "preview_boundary_closed", _closed_no_production_boundary(object_value(preview.get("boundary"))))
    check(checks, failures, "rollback_boundary_closed", _closed_no_production_boundary(object_value(rollback.get("boundary"))))
    passed = _passed(checks, failures)
    report = {
        "schema_version": MONITORING_AUDIT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "task_id": authorization.get("task_id"),
        "expected_nodes": authorization.get("expected_nodes", []),
        "owners": authorization.get("owners", {}),
        "source_artifacts": {
            "authorization": artifact_ref(authorization_path),
            "multi_vm_preview_receipt": artifact_ref(multi_vm_preview_receipt_path),
            "rollback_receipt": artifact_ref(rollback_receipt_path),
        },
        "boundary": _boundary(monitoring_audit_receipt_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def write_reconciliation(
    *,
    authorization_path: Path,
    multi_vm_preview_receipt_path: Path,
    rollback_receipt_path: Path,
    monitoring_audit_receipt_path: Path,
    output: Path,
) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    authorization = read_json_object(authorization_path)
    preview = read_json_object(multi_vm_preview_receipt_path)
    rollback = read_json_object(rollback_receipt_path)
    audit = read_json_object(monitoring_audit_receipt_path)
    check(checks, failures, "authorization_passed", authorization.get("passed") is True)
    check(checks, failures, "multi_vm_preview_passed", preview.get("passed") is True)
    check(checks, failures, "rollback_passed", rollback.get("passed") is True)
    check(checks, failures, "audit_passed", audit.get("passed") is True)
    check(checks, failures, "expected_nodes_consistent", authorization.get("expected_nodes") == preview.get("expected_nodes") == rollback.get("expected_nodes") == audit.get("expected_nodes"))
    passed = _passed(checks, failures)
    report = {
        "schema_version": RECONCILIATION_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "decided_at": _now(),
        "task_id": authorization.get("task_id"),
        "expected_nodes": authorization.get("expected_nodes", []),
        "decision": "p0j_multi_vm_private_preview_passed" if passed else "blocked_p0j_multi_vm_private_preview",
        "source_artifacts": {
            "authorization": artifact_ref(authorization_path),
            "multi_vm_preview_receipt": artifact_ref(multi_vm_preview_receipt_path),
            "rollback_receipt": artifact_ref(rollback_receipt_path),
            "monitoring_audit_receipt": artifact_ref(monitoring_audit_receipt_path),
        },
        "boundary": _boundary(owner_reconciliation_written=passed),
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


def _run_authorized_command(authorization: dict[str, Any], field: str, workdir: Path, failures: list[str]) -> dict[str, Any] | None:
    command = object_value(authorization.get(field))
    argv = command.get("argv")
    if not isinstance(argv, list) or not argv or not all(isinstance(item, str) and item for item in argv):
        failures.append(f"{field}_argv_invalid")
        return None
    try:
        completed = subprocess.run(argv, cwd=workdir, text=True, capture_output=True, timeout=900, check=False)
    except Exception as exc:  # noqa: BLE001
        failures.append(f"{field}_execution_error:{exc}")
        return {"argv": argv, "returncode": None, "stdout": "", "stderr": str(exc)}
    return {
        "argv": argv,
        "returncode": completed.returncode,
        "stdout": completed.stdout[-12000:],
        "stderr": completed.stderr[-12000:],
    }


def _parse_json_from_stdout(stdout: str, failures: list[str], label: str) -> dict[str, Any]:
    for line in reversed([item.strip() for item in stdout.splitlines() if item.strip()]):
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            return value
    failures.append(f"{label}_json_missing")
    return {}


def _command_argv_from_raw(raw: str, failures: list[str], label: str) -> list[str]:
    try:
        argv = shlex.split(raw)
    except ValueError as exc:
        failures.append(f"{label}_parse_failed:{exc}")
        return []
    if not argv:
        failures.append(f"{label}_empty")
    return argv


def _single_vm_preview_observed(boundary: dict[str, Any]) -> bool:
    return (
        boundary.get("vm_contact_performed") is True
        and boundary.get("private_preview_deploy_performed") is True
        and boundary.get("backend_health_check_performed") is True
        and boundary.get("frontend_health_check_performed") is True
        and boundary.get("rollback_performed") is True
        and boundary.get("rollback_health_check_performed") is True
    )


def _closed_no_production_boundary(boundary: dict[str, Any]) -> bool:
    return (
        boundary.get("external_public_ingress_opened") is False
        and boundary.get("production_transition_allowed") is False
        and boundary.get("production_receipt_write_allowed") is False
        and boundary.get("source_tree_write_performed") is False
        and boundary.get("git_write_performed") is False
        and boundary.get("production_data_accessed") is False
        and boundary.get("secrets_recorded") is False
    )


def _boundary(**overrides: bool) -> dict[str, bool]:
    base = {
        "private_preview_authorized": False,
        "vm_contact_performed": False,
        "multi_vm_private_preview_deploy_performed": False,
        "multi_vm_smoke_performed": False,
        "rollback_performed": False,
        "rollback_health_check_performed": False,
        "monitoring_audit_receipt_written": False,
        "owner_reconciliation_written": False,
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


def _unique_texts(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    result = []
    for item in value:
        text = str(item).strip()
        if text and text not in result:
            result.append(text)
    return result


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
    parser = argparse.ArgumentParser(description="Run P0-J multi-VM private preview gate")
    parser.add_argument("--p0i-summary", required=True)
    parser.add_argument("--output-root", required=True)
    parser.add_argument("--deploy-command", required=True)
    parser.add_argument("--smoke-command", required=True)
    parser.add_argument("--rollback-command", required=True)
    parser.add_argument("--rollback-health-command", required=True)
    parser.add_argument("--expected-node", action="append", default=[])
    parser.add_argument("--operator-id", default="operator-cc")
    parser.add_argument("--working-directory", default=".")
    parser.add_argument("--ack-multi-vm-private-preview", action="store_true")
    args = parser.parse_args()
    summary = run_gate(
        p0i_summary_path=Path(args.p0i_summary),
        output_root=Path(args.output_root),
        deploy_command=args.deploy_command,
        smoke_command=args.smoke_command,
        rollback_command=args.rollback_command,
        rollback_health_command=args.rollback_health_command,
        expected_nodes=args.expected_node or list(DEFAULT_EXPECTED_NODES),
        operator_id=args.operator_id,
        ack_multi_vm_private_preview=bool(args.ack_multi_vm_private_preview),
        working_directory=Path(args.working_directory),
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if summary.get("passed") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
