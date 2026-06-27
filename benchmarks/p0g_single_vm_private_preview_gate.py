"""Run P0-G single-VM private preview gate.

P0-G consumes a passed P0-F VM preview preflight summary and performs one
bounded private preview on a single VM target. Unlike P0-F, this gate may touch
the VM and run a non-production preview command. It still forbids public
ingress, production data, production transition, production receipts, source
tree writes, and Git writes.
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
from benchmarks.p0f_vm_preview_preflight_gate import CHAIN_SCHEMA as P0F_CHAIN_SCHEMA
from benchmarks.p0f_vm_preview_preflight_gate import (
    NO_PUBLIC_INGRESS_SCHEMA as P0F_NO_PUBLIC_INGRESS_SCHEMA,
    OWNER_MONITORING_AUDIT_SCHEMA as P0F_OWNER_MONITORING_AUDIT_SCHEMA,
    ROLLBACK_RUNBOOK_SCHEMA as P0F_ROLLBACK_RUNBOOK_SCHEMA,
    SERVICE_SCOPE_SCHEMA as P0F_SERVICE_SCOPE_SCHEMA,
    VM_TARGET_SCHEMA as P0F_VM_TARGET_SCHEMA,
)

CHAIN_SCHEMA = "p0g-single-vm-private-preview-chain:v1"
AUTHORIZATION_SCHEMA = "p0g-single-vm-private-preview-authorization:v1"
PREVIEW_RECEIPT_SCHEMA = "p0g-single-vm-private-preview-receipt:v1"
ROLLBACK_RECEIPT_SCHEMA = "p0g-single-vm-private-preview-rollback-receipt:v1"
MONITORING_AUDIT_SCHEMA = "p0g-single-vm-private-preview-monitoring-audit-receipt:v1"
RECONCILIATION_SCHEMA = "p0g-single-vm-private-preview-reconciliation:v1"

NON_CLAIMS = (
    "p0g_is_single_vm_private_preview_only",
    "p0g_requires_passed_p0f_preflight",
    "p0g_requires_explicit_operator_preview_authorization",
    "p0g_does_not_open_public_ingress",
    "p0g_does_not_touch_production_data",
    "p0g_does_not_modify_source_or_git",
    "p0g_does_not_write_production_receipts",
    "p0g_does_not_authorize_production_transition",
)


def run_gate(
    *,
    p0f_summary_path: Path,
    output_root: Path,
    preview_command: str,
    health_command: str,
    rollback_command: str,
    rollback_health_command: str,
    operator_id: str = "operator-cc",
    ack_single_vm_private_preview: bool = False,
    working_directory: Path | None = None,
) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "authorization": output_root / "p0g_single_vm_private_preview_authorization.json",
        "preview_receipt": output_root / "p0g_single_vm_private_preview_receipt.json",
        "rollback_receipt": output_root / "p0g_single_vm_private_preview_rollback_receipt.json",
        "monitoring_audit_receipt": output_root / "p0g_single_vm_private_preview_monitoring_audit_receipt.json",
        "reconciliation": output_root / "p0g_single_vm_private_preview_reconciliation.json",
        "summary": output_root / "p0g_single_vm_private_preview_chain_summary.json",
    }
    authorization = write_authorization(
        p0f_summary_path=p0f_summary_path,
        output=artifacts["authorization"],
        preview_command=preview_command,
        health_command=health_command,
        rollback_command=rollback_command,
        rollback_health_command=rollback_health_command,
        operator_id=operator_id,
        ack_single_vm_private_preview=ack_single_vm_private_preview,
        working_directory=working_directory or Path.cwd(),
    )
    preview = write_preview_receipt(
        authorization_path=artifacts["authorization"],
        output=artifacts["preview_receipt"],
    )
    rollback = write_rollback_receipt(
        authorization_path=artifacts["authorization"],
        preview_receipt_path=artifacts["preview_receipt"],
        output=artifacts["rollback_receipt"],
    )
    audit = write_monitoring_audit_receipt(
        authorization_path=artifacts["authorization"],
        preview_receipt_path=artifacts["preview_receipt"],
        rollback_receipt_path=artifacts["rollback_receipt"],
        output=artifacts["monitoring_audit_receipt"],
    )
    reconciliation = write_reconciliation(
        authorization_path=artifacts["authorization"],
        preview_receipt_path=artifacts["preview_receipt"],
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
        "vm_target_id": authorization.get("vm_target_id"),
        "operator_id": operator_id,
        "source_artifacts": {"p0f_summary": artifact_ref(p0f_summary_path)},
        "artifacts": {name: artifact_ref(path) for name, path in artifacts.items() if name != "summary"},
        "readiness": {
            "state": "p0g_single_vm_private_preview_passed" if passed else "blocked_p0g_single_vm_private_preview",
            "p0g_single_vm_private_preview_complete": passed,
            "p0h_private_preview_owner_review_ready": passed,
            "production_transition_allowed": False,
        },
        "boundary": _boundary(
            private_preview_authorized=authorization.get("passed") is True,
            vm_contact_performed=object_value(preview.get("boundary")).get("vm_contact_performed") is True,
            private_preview_deploy_performed=preview.get("private_preview_performed") is True,
            private_preview_health_check_performed=preview.get("private_preview_health_check_performed") is True,
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
    p0f_summary_path: Path,
    output: Path,
    preview_command: str,
    health_command: str,
    rollback_command: str,
    rollback_health_command: str,
    operator_id: str,
    ack_single_vm_private_preview: bool,
    working_directory: Path,
) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    context = validate_p0f_context(p0f_summary_path)
    workdir = working_directory.resolve()
    preview_argv = _command_argv_from_raw(preview_command, failures, "preview_command")
    health_argv = _command_argv_from_raw(health_command, failures, "health_command")
    rollback_argv = _command_argv_from_raw(rollback_command, failures, "rollback_command")
    rollback_health_argv = _command_argv_from_raw(rollback_health_command, failures, "rollback_health_command")
    failures.extend(str(item) for item in context.get("failure_reasons", []))
    check(checks, failures, "p0f_context_passed", context.get("passed") is True)
    check(checks, failures, "operator_id_present", bool(str(operator_id).strip()))
    check(checks, failures, "explicit_operator_ack", ack_single_vm_private_preview is True)
    check(checks, failures, "working_directory_exists", workdir.is_dir())
    passed = _passed(checks, failures)
    vm_target = object_value(context.get("vm_target"))
    authorization = {
        "schema_version": AUTHORIZATION_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "authorized_at": _now(),
        "task_id": context.get("task_id"),
        "operator_id": operator_id,
        "authorization_scope": "single_vm_private_preview_only",
        "vm_target_id": vm_target.get("id"),
        "vm_target": vm_target,
        "working_directory": str(workdir),
        "preview_command": {"raw": preview_command, "argv": preview_argv, "shell": False},
        "health_command": {"raw": health_command, "argv": health_argv, "shell": False},
        "rollback_command": {"raw": rollback_command, "argv": rollback_argv, "shell": False},
        "rollback_health_command": {"raw": rollback_health_command, "argv": rollback_health_argv, "shell": False},
        "source_artifacts": {"p0f_summary": artifact_ref(p0f_summary_path)},
        "p0f_artifacts": context.get("p0f_artifacts", {}),
        "owners": context.get("owners", {}),
        "boundary": _boundary(private_preview_authorized=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, authorization)
    return authorization


def write_preview_receipt(*, authorization_path: Path, output: Path) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    authorization = read_json_object(authorization_path)
    check(checks, failures, "authorization_passed", authorization.get("schema_version") == AUTHORIZATION_SCHEMA and authorization.get("passed") is True)
    workdir = Path(str(authorization.get("working_directory") or "")).resolve()
    preview = _run_authorized_command(authorization, "preview_command", workdir, failures) if authorization.get("passed") is True else None
    if preview and preview.get("returncode") != 0:
        failures.append("preview_command_failed")
    preview_succeeded = bool(preview) and preview.get("returncode") == 0
    health = _run_authorized_command(authorization, "health_command", workdir, failures) if preview_succeeded else None
    if health and health.get("returncode") != 0:
        failures.append("health_command_failed")
    check(checks, failures, "preview_command_success", preview_succeeded)
    if preview_succeeded:
        check(checks, failures, "health_command_success", bool(health) and health.get("returncode") == 0)
    else:
        checks["health_skipped_after_preview_failure"] = True
    passed = _passed(checks, failures)
    receipt = {
        "schema_version": PREVIEW_RECEIPT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "completed_at": _now(),
        "task_id": authorization.get("task_id"),
        "vm_target_id": authorization.get("vm_target_id"),
        "source_artifacts": {"authorization": artifact_ref(authorization_path)},
        "preview": preview,
        "health": health,
        "private_preview_performed": bool(preview and preview.get("returncode") == 0),
        "private_preview_health_check_performed": bool(health and health.get("returncode") == 0),
        "boundary": _boundary(
            vm_contact_performed=bool(preview),
            private_preview_deploy_performed=bool(preview and preview.get("returncode") == 0),
            private_preview_health_check_performed=bool(health and health.get("returncode") == 0),
        ),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, receipt)
    return receipt


def write_rollback_receipt(*, authorization_path: Path, preview_receipt_path: Path, output: Path) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    authorization = read_json_object(authorization_path)
    preview_receipt = read_json_object(preview_receipt_path)
    workdir = Path(str(authorization.get("working_directory") or "")).resolve()
    should_rollback = authorization.get("passed") is True and preview_receipt.get("private_preview_performed") is True
    rollback = _run_authorized_command(authorization, "rollback_command", workdir, failures) if should_rollback else None
    if rollback and rollback.get("returncode") != 0:
        failures.append("rollback_command_failed")
    rollback_health = _run_authorized_command(authorization, "rollback_health_command", workdir, failures) if rollback and rollback.get("returncode") == 0 else None
    if rollback_health and rollback_health.get("returncode") != 0:
        failures.append("rollback_health_command_failed")
    check(checks, failures, "authorization_passed", authorization.get("passed") is True)
    check(checks, failures, "preview_attempt_recorded", preview_receipt.get("schema_version") == PREVIEW_RECEIPT_SCHEMA)
    if should_rollback:
        check(checks, failures, "rollback_command_success", bool(rollback) and rollback.get("returncode") == 0)
        check(checks, failures, "rollback_health_command_success", bool(rollback_health) and rollback_health.get("returncode") == 0)
    else:
        checks["rollback_not_required_no_deploy"] = True
    passed = _passed(checks, failures)
    receipt = {
        "schema_version": ROLLBACK_RECEIPT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "completed_at": _now(),
        "task_id": authorization.get("task_id"),
        "vm_target_id": authorization.get("vm_target_id"),
        "source_artifacts": {
            "authorization": artifact_ref(authorization_path),
            "preview_receipt": artifact_ref(preview_receipt_path),
        },
        "rollback": rollback,
        "rollback_health": rollback_health,
        "rollback_needed": should_rollback,
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
    preview_receipt_path: Path,
    rollback_receipt_path: Path,
    output: Path,
) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    authorization = read_json_object(authorization_path)
    preview = read_json_object(preview_receipt_path)
    rollback = read_json_object(rollback_receipt_path)
    check(checks, failures, "authorization_passed", authorization.get("passed") is True)
    check(checks, failures, "preview_passed", preview.get("passed") is True)
    check(checks, failures, "rollback_passed", rollback.get("passed") is True)
    check(checks, failures, "owners_present", bool(object_value(authorization.get("owners"))))
    check(checks, failures, "no_public_ingress", _boundary_false(preview, "external_public_ingress_opened") and _boundary_false(rollback, "external_public_ingress_opened"))
    check(checks, failures, "no_production_transition", _boundary_false(preview, "production_transition_allowed") and _boundary_false(rollback, "production_transition_allowed"))
    check(checks, failures, "no_production_receipt", _boundary_false(preview, "production_receipt_write_allowed") and _boundary_false(rollback, "production_receipt_write_allowed"))
    passed = _passed(checks, failures)
    receipt = {
        "schema_version": MONITORING_AUDIT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "task_id": authorization.get("task_id"),
        "vm_target_id": authorization.get("vm_target_id"),
        "owners": authorization.get("owners", {}),
        "source_artifacts": {
            "authorization": artifact_ref(authorization_path),
            "preview_receipt": artifact_ref(preview_receipt_path),
            "rollback_receipt": artifact_ref(rollback_receipt_path),
        },
        "boundary": _boundary(monitoring_audit_receipt_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, receipt)
    return receipt


def write_reconciliation(
    *,
    authorization_path: Path,
    preview_receipt_path: Path,
    rollback_receipt_path: Path,
    monitoring_audit_receipt_path: Path,
    output: Path,
) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    authorization = read_json_object(authorization_path)
    preview = read_json_object(preview_receipt_path)
    rollback = read_json_object(rollback_receipt_path)
    audit = read_json_object(monitoring_audit_receipt_path)
    check(checks, failures, "authorization_passed", authorization.get("passed") is True)
    check(checks, failures, "preview_passed", preview.get("passed") is True)
    check(checks, failures, "rollback_passed", rollback.get("passed") is True)
    check(checks, failures, "audit_passed", audit.get("passed") is True)
    check(checks, failures, "preview_and_rollback_same_vm", preview.get("vm_target_id") == rollback.get("vm_target_id") == authorization.get("vm_target_id"))
    passed = _passed(checks, failures)
    reconciliation = {
        "schema_version": RECONCILIATION_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "decided_at": _now(),
        "task_id": authorization.get("task_id"),
        "vm_target_id": authorization.get("vm_target_id"),
        "decision": "p0g_private_preview_passed_ready_for_owner_review" if passed else "blocked_p0g_private_preview",
        "source_artifacts": {
            "authorization": artifact_ref(authorization_path),
            "preview_receipt": artifact_ref(preview_receipt_path),
            "rollback_receipt": artifact_ref(rollback_receipt_path),
            "monitoring_audit_receipt": artifact_ref(monitoring_audit_receipt_path),
        },
        "boundary": _boundary(owner_reconciliation_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, reconciliation)
    return reconciliation


def validate_p0f_context(p0f_summary_path: Path) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    try:
        p0f = read_json_object(p0f_summary_path)
    except Exception as exc:  # noqa: BLE001
        return _report("p0g-p0f-context-validation:v1", False, [f"p0f_summary_unreadable:{exc}"], checks)
    refs = object_value(p0f.get("artifacts"))
    vm_target = _read_verified_ref(refs.get("vm_target_preflight"), checks, failures, "p0f_vm_target_preflight")
    scope = _read_verified_ref(refs.get("service_token_scope_review"), checks, failures, "p0f_service_token_scope_review")
    rollback = _read_verified_ref(refs.get("rollback_runbook_review"), checks, failures, "p0f_rollback_runbook_review")
    owners = _read_verified_ref(refs.get("owner_monitoring_audit_review"), checks, failures, "p0f_owner_monitoring_audit_review")
    boundary = _read_verified_ref(refs.get("no_public_ingress_no_production_review"), checks, failures, "p0f_no_public_ingress_no_production_review")
    readiness = object_value(p0f.get("readiness"))
    check(checks, failures, "p0f_summary_passed", p0f.get("schema_version") == P0F_CHAIN_SCHEMA and p0f.get("passed") is True)
    check(checks, failures, "p0f_ready_for_p0g", readiness.get("p0g_single_vm_private_preview_ready") is True)
    check(checks, failures, "p0f_production_transition_closed", readiness.get("production_transition_allowed") is False)
    check(checks, failures, "p0f_vm_target_passed", vm_target.get("schema_version") == P0F_VM_TARGET_SCHEMA and vm_target.get("passed") is True)
    check(checks, failures, "p0f_scope_passed", scope.get("schema_version") == P0F_SERVICE_SCOPE_SCHEMA and scope.get("passed") is True)
    check(checks, failures, "p0f_rollback_passed", rollback.get("schema_version") == P0F_ROLLBACK_RUNBOOK_SCHEMA and rollback.get("passed") is True)
    check(checks, failures, "p0f_owners_passed", owners.get("schema_version") == P0F_OWNER_MONITORING_AUDIT_SCHEMA and owners.get("passed") is True)
    check(checks, failures, "p0f_boundary_passed", boundary.get("schema_version") == P0F_NO_PUBLIC_INGRESS_SCHEMA and boundary.get("passed") is True)
    check(checks, failures, "p0f_boundary_allows_no_production", _p0f_boundary_closed(object_value(p0f.get("boundary"))))
    return {
        "schema_version": "p0g-p0f-context-validation:v1",
        "passed": _passed(checks, failures),
        "failure_reasons": failures,
        "checks": checks,
        "task_id": p0f.get("task_id"),
        "vm_target": object_value(vm_target.get("vm_target")),
        "owners": owners.get("owners", {}),
        "p0f_artifacts": refs,
        "p0f_summary": p0f,
    }


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
        completed = subprocess.run(argv, cwd=workdir, text=True, capture_output=True, timeout=120, check=False)
    except Exception as exc:  # noqa: BLE001
        failures.append(f"{field}_execution_error:{exc}")
        return {"argv": argv, "returncode": None, "stdout": "", "stderr": str(exc)}
    return {
        "argv": argv,
        "returncode": completed.returncode,
        "stdout": completed.stdout[-4000:],
        "stderr": completed.stderr[-4000:],
    }


def _command_argv_from_raw(raw: str, failures: list[str], label: str) -> list[str]:
    try:
        argv = shlex.split(raw)
    except ValueError as exc:
        failures.append(f"{label}_parse_failed:{exc}")
        return []
    if not argv:
        failures.append(f"{label}_empty")
    return argv


def _p0f_boundary_closed(boundary: dict[str, Any]) -> bool:
    return (
        boundary.get("external_public_ingress_opened") is False
        and boundary.get("production_transition_allowed") is False
        and boundary.get("production_receipt_write_allowed") is False
        and boundary.get("source_tree_write_performed") is False
        and boundary.get("git_write_performed") is False
    )


def _boundary_false(report: dict[str, Any], key: str) -> bool:
    return object_value(report.get("boundary")).get(key) is False


def _boundary(**overrides: bool) -> dict[str, bool]:
    base = {
        "private_preview_authorized": False,
        "vm_contact_performed": False,
        "private_preview_deploy_performed": False,
        "private_preview_health_check_performed": False,
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
    parser = argparse.ArgumentParser(description="Run P0-G single VM private preview gate")
    parser.add_argument("--p0f-summary", required=True)
    parser.add_argument("--output-root", required=True)
    parser.add_argument("--preview-command", required=True)
    parser.add_argument("--health-command", required=True)
    parser.add_argument("--rollback-command", required=True)
    parser.add_argument("--rollback-health-command", required=True)
    parser.add_argument("--operator-id", default="operator-cc")
    parser.add_argument("--working-directory", default=".")
    parser.add_argument("--ack-single-vm-private-preview", action="store_true")
    args = parser.parse_args()
    summary = run_gate(
        p0f_summary_path=Path(args.p0f_summary),
        output_root=Path(args.output_root),
        preview_command=args.preview_command,
        health_command=args.health_command,
        rollback_command=args.rollback_command,
        rollback_health_command=args.rollback_health_command,
        operator_id=args.operator_id,
        ack_single_vm_private_preview=bool(args.ack_single_vm_private_preview),
        working_directory=Path(args.working_directory),
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if summary.get("passed") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
