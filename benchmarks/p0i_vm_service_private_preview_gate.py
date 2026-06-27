"""Run P0-I VM service private preview gate.

P0-I consumes a passed P0-H owner review summary and performs a bounded
single-VM backend/frontend private service preview. It may contact the VM and
run non-production preview/rollback commands. It never opens public ingress,
mutates source/Git, touches production data, authorizes production transition,
or writes production receipts.
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
from benchmarks.p0h_private_preview_owner_review_gate import (
    AUDIT_BOUNDARY_SCHEMA as P0H_AUDIT_BOUNDARY_SCHEMA,
    CHAIN_SCHEMA as P0H_CHAIN_SCHEMA,
    OWNER_ACCEPTANCE_SCHEMA as P0H_OWNER_ACCEPTANCE_SCHEMA,
    RECONCILIATION_SCHEMA as P0H_RECONCILIATION_SCHEMA,
    ROLLBACK_OWNER_SCHEMA as P0H_ROLLBACK_OWNER_SCHEMA,
)

CHAIN_SCHEMA = "p0i-vm-service-private-preview-chain:v1"
CONTEXT_SCHEMA = "p0i-p0h-context-validation:v1"
AUTHORIZATION_SCHEMA = "p0i-vm-service-private-preview-authorization:v1"
SERVICE_PREVIEW_SCHEMA = "p0i-vm-service-private-preview-receipt:v1"
ROLLBACK_SCHEMA = "p0i-vm-service-private-preview-rollback-receipt:v1"
MONITORING_AUDIT_SCHEMA = "p0i-vm-service-private-preview-monitoring-audit-receipt:v1"
RECONCILIATION_SCHEMA = "p0i-vm-service-private-preview-reconciliation:v1"

NON_CLAIMS = (
    "p0i_is_single_vm_private_service_preview_only",
    "p0i_requires_passed_p0h_owner_review",
    "p0i_requires_explicit_operator_preview_authorization",
    "p0i_does_not_open_public_ingress",
    "p0i_does_not_touch_production_data",
    "p0i_does_not_modify_source_or_git",
    "p0i_does_not_write_production_receipts",
    "p0i_does_not_authorize_production_transition",
)


def run_gate(
    *,
    p0h_summary_path: Path,
    output_root: Path,
    deploy_command: str,
    backend_health_command: str,
    frontend_health_command: str,
    rollback_command: str,
    rollback_health_command: str,
    operator_id: str = "operator-cc",
    ack_vm_service_private_preview: bool = False,
    working_directory: Path | None = None,
) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "authorization": output_root / "p0i_vm_service_private_preview_authorization.json",
        "service_preview_receipt": output_root / "p0i_vm_service_private_preview_receipt.json",
        "rollback_receipt": output_root / "p0i_vm_service_private_preview_rollback_receipt.json",
        "monitoring_audit_receipt": output_root / "p0i_vm_service_private_preview_monitoring_audit_receipt.json",
        "reconciliation": output_root / "p0i_vm_service_private_preview_reconciliation.json",
        "summary": output_root / "p0i_vm_service_private_preview_chain_summary.json",
    }
    authorization = write_authorization(
        p0h_summary_path=p0h_summary_path,
        output=artifacts["authorization"],
        deploy_command=deploy_command,
        backend_health_command=backend_health_command,
        frontend_health_command=frontend_health_command,
        rollback_command=rollback_command,
        rollback_health_command=rollback_health_command,
        operator_id=operator_id,
        ack_vm_service_private_preview=ack_vm_service_private_preview,
        working_directory=working_directory or Path.cwd(),
    )
    preview = write_service_preview_receipt(
        authorization_path=artifacts["authorization"],
        output=artifacts["service_preview_receipt"],
    )
    rollback = write_rollback_receipt(
        authorization_path=artifacts["authorization"],
        service_preview_receipt_path=artifacts["service_preview_receipt"],
        output=artifacts["rollback_receipt"],
    )
    audit = write_monitoring_audit_receipt(
        authorization_path=artifacts["authorization"],
        service_preview_receipt_path=artifacts["service_preview_receipt"],
        rollback_receipt_path=artifacts["rollback_receipt"],
        output=artifacts["monitoring_audit_receipt"],
    )
    reconciliation = write_reconciliation(
        authorization_path=artifacts["authorization"],
        service_preview_receipt_path=artifacts["service_preview_receipt"],
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
        "owners": authorization.get("owners", {}),
        "source_artifacts": {"p0h_summary": artifact_ref(p0h_summary_path)},
        "artifacts": {name: artifact_ref(path) for name, path in artifacts.items() if name != "summary"},
        "readiness": {
            "state": "p0i_vm_service_private_preview_passed" if passed else "blocked_p0i_vm_service_private_preview",
            "p0i_vm_service_private_preview_complete": passed,
            "p0j_multi_vm_private_preview_ready": passed,
            "production_transition_allowed": False,
        },
        "boundary": _boundary(
            private_preview_authorized=authorization.get("passed") is True,
            vm_contact_performed=object_value(preview.get("boundary")).get("vm_contact_performed") is True,
            private_preview_deploy_performed=preview.get("service_preview_performed") is True,
            backend_health_check_performed=preview.get("backend_health_check_performed") is True,
            frontend_health_check_performed=preview.get("frontend_health_check_performed") is True,
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
    p0h_summary_path: Path,
    output: Path,
    deploy_command: str,
    backend_health_command: str,
    frontend_health_command: str,
    rollback_command: str,
    rollback_health_command: str,
    operator_id: str,
    ack_vm_service_private_preview: bool,
    working_directory: Path,
) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    context = validate_p0h_context(p0h_summary_path)
    workdir = working_directory.resolve()
    commands = {
        "deploy_command": _command_argv_from_raw(deploy_command, failures, "deploy_command"),
        "backend_health_command": _command_argv_from_raw(backend_health_command, failures, "backend_health_command"),
        "frontend_health_command": _command_argv_from_raw(frontend_health_command, failures, "frontend_health_command"),
        "rollback_command": _command_argv_from_raw(rollback_command, failures, "rollback_command"),
        "rollback_health_command": _command_argv_from_raw(rollback_health_command, failures, "rollback_health_command"),
    }
    failures.extend(str(item) for item in context.get("failure_reasons", []))
    check(checks, failures, "p0h_context_passed", context.get("passed") is True)
    check(checks, failures, "operator_id_present", bool(str(operator_id).strip()))
    check(checks, failures, "explicit_operator_ack", ack_vm_service_private_preview is True)
    check(checks, failures, "working_directory_exists", workdir.is_dir())
    passed = _passed(checks, failures)
    authorization = {
        "schema_version": AUTHORIZATION_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "authorized_at": _now(),
        "task_id": context.get("task_id"),
        "vm_target_id": context.get("vm_target_id"),
        "operator_id": operator_id,
        "owners": context.get("owners", {}),
        "authorization_scope": "single_vm_backend_frontend_private_preview_only",
        "working_directory": str(workdir),
        "deploy_command": {"raw": deploy_command, "argv": commands["deploy_command"], "shell": False},
        "backend_health_command": {"raw": backend_health_command, "argv": commands["backend_health_command"], "shell": False},
        "frontend_health_command": {"raw": frontend_health_command, "argv": commands["frontend_health_command"], "shell": False},
        "rollback_command": {"raw": rollback_command, "argv": commands["rollback_command"], "shell": False},
        "rollback_health_command": {"raw": rollback_health_command, "argv": commands["rollback_health_command"], "shell": False},
        "source_artifacts": {"p0h_summary": artifact_ref(p0h_summary_path)},
        "p0h_artifacts": context.get("p0h_artifacts", {}),
        "boundary": _boundary(private_preview_authorized=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, authorization)
    return authorization


def validate_p0h_context(p0h_summary_path: Path) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    try:
        p0h = read_json_object(p0h_summary_path)
    except Exception as exc:  # noqa: BLE001
        return _report(CONTEXT_SCHEMA, False, [f"p0h_summary_unreadable:{exc}"], checks)
    refs = object_value(p0h.get("artifacts"))
    owner = _read_verified_ref(refs.get("owner_acceptance"), checks, failures, "p0h_owner_acceptance")
    audit = _read_verified_ref(refs.get("audit_boundary_review"), checks, failures, "p0h_audit_boundary_review")
    rollback_owner = _read_verified_ref(refs.get("rollback_owner_review"), checks, failures, "p0h_rollback_owner_review")
    reconciliation = _read_verified_ref(refs.get("reconciliation"), checks, failures, "p0h_reconciliation")
    readiness = object_value(p0h.get("readiness"))
    boundary = object_value(p0h.get("boundary"))
    task_id = str(p0h.get("task_id") or owner.get("task_id") or "")
    vm_target_id = str(p0h.get("vm_target_id") or owner.get("vm_target_id") or "")

    check(checks, failures, "p0h_summary_passed", p0h.get("schema_version") == P0H_CHAIN_SCHEMA and p0h.get("passed") is True)
    check(checks, failures, "p0h_ready_for_p0i", readiness.get("p0i_vm_service_private_preview_ready") is True)
    check(checks, failures, "p0h_production_transition_closed", readiness.get("production_transition_allowed") is False)
    check(checks, failures, "p0h_boundary_review_only", _review_only_boundary(boundary))
    check(checks, failures, "p0h_owner_acceptance_passed", owner.get("schema_version") == P0H_OWNER_ACCEPTANCE_SCHEMA and owner.get("passed") is True)
    check(checks, failures, "p0h_audit_boundary_passed", audit.get("schema_version") == P0H_AUDIT_BOUNDARY_SCHEMA and audit.get("passed") is True)
    check(checks, failures, "p0h_rollback_owner_passed", rollback_owner.get("schema_version") == P0H_ROLLBACK_OWNER_SCHEMA and rollback_owner.get("passed") is True)
    check(checks, failures, "p0h_reconciliation_passed", reconciliation.get("schema_version") == P0H_RECONCILIATION_SCHEMA and reconciliation.get("passed") is True)
    check(checks, failures, "task_id_consistent", all(item.get("task_id") == task_id for item in (owner, audit, rollback_owner, reconciliation)))
    check(checks, failures, "vm_target_consistent", all(item.get("vm_target_id") == vm_target_id for item in (owner, audit, rollback_owner, reconciliation)))
    return {
        "schema_version": CONTEXT_SCHEMA,
        "passed": _passed(checks, failures),
        "failure_reasons": failures,
        "checks": checks,
        "task_id": task_id,
        "vm_target_id": vm_target_id,
        "owners": object_value(p0h.get("owners")),
        "p0h_artifacts": refs,
        "p0h_summary": p0h,
    }


def write_service_preview_receipt(*, authorization_path: Path, output: Path) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    authorization = read_json_object(authorization_path)
    check(checks, failures, "authorization_passed", authorization.get("schema_version") == AUTHORIZATION_SCHEMA and authorization.get("passed") is True)
    workdir = Path(str(authorization.get("working_directory") or "")).resolve()
    deploy = _run_authorized_command(authorization, "deploy_command", workdir, failures) if authorization.get("passed") is True else None
    if deploy and deploy.get("returncode") != 0:
        failures.append("deploy_command_failed")
    deploy_succeeded = bool(deploy) and deploy.get("returncode") == 0
    backend = _run_authorized_command(authorization, "backend_health_command", workdir, failures) if deploy_succeeded else None
    if backend and backend.get("returncode") != 0:
        failures.append("backend_health_command_failed")
    frontend = _run_authorized_command(authorization, "frontend_health_command", workdir, failures) if deploy_succeeded else None
    if frontend and frontend.get("returncode") != 0:
        failures.append("frontend_health_command_failed")
    check(checks, failures, "deploy_command_success", deploy_succeeded)
    if deploy_succeeded:
        check(checks, failures, "backend_health_command_success", bool(backend) and backend.get("returncode") == 0)
        check(checks, failures, "frontend_health_command_success", bool(frontend) and frontend.get("returncode") == 0)
    else:
        checks["health_skipped_after_deploy_failure"] = True
    passed = _passed(checks, failures)
    receipt = {
        "schema_version": SERVICE_PREVIEW_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "completed_at": _now(),
        "task_id": authorization.get("task_id"),
        "vm_target_id": authorization.get("vm_target_id"),
        "source_artifacts": {"authorization": artifact_ref(authorization_path)},
        "deploy": deploy,
        "backend_health": backend,
        "frontend_health": frontend,
        "service_preview_performed": deploy_succeeded,
        "backend_health_check_performed": bool(backend and backend.get("returncode") == 0),
        "frontend_health_check_performed": bool(frontend and frontend.get("returncode") == 0),
        "boundary": _boundary(
            vm_contact_performed=bool(deploy),
            private_preview_deploy_performed=deploy_succeeded,
            backend_health_check_performed=bool(backend and backend.get("returncode") == 0),
            frontend_health_check_performed=bool(frontend and frontend.get("returncode") == 0),
        ),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, receipt)
    return receipt


def write_rollback_receipt(*, authorization_path: Path, service_preview_receipt_path: Path, output: Path) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    authorization = read_json_object(authorization_path)
    preview = read_json_object(service_preview_receipt_path)
    workdir = Path(str(authorization.get("working_directory") or "")).resolve()
    should_rollback = authorization.get("passed") is True and preview.get("service_preview_performed") is True
    rollback = _run_authorized_command(authorization, "rollback_command", workdir, failures) if should_rollback else None
    if rollback and rollback.get("returncode") != 0:
        failures.append("rollback_command_failed")
    rollback_health = _run_authorized_command(authorization, "rollback_health_command", workdir, failures) if rollback and rollback.get("returncode") == 0 else None
    if rollback_health and rollback_health.get("returncode") != 0:
        failures.append("rollback_health_command_failed")
    check(checks, failures, "authorization_passed", authorization.get("passed") is True)
    check(checks, failures, "service_preview_attempt_recorded", preview.get("schema_version") == SERVICE_PREVIEW_SCHEMA)
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
        "vm_target_id": authorization.get("vm_target_id"),
        "source_artifacts": {
            "authorization": artifact_ref(authorization_path),
            "service_preview_receipt": artifact_ref(service_preview_receipt_path),
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
    service_preview_receipt_path: Path,
    rollback_receipt_path: Path,
    output: Path,
) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    authorization = read_json_object(authorization_path)
    preview = read_json_object(service_preview_receipt_path)
    rollback = read_json_object(rollback_receipt_path)
    check(checks, failures, "authorization_passed", authorization.get("passed") is True)
    check(checks, failures, "service_preview_passed", preview.get("passed") is True)
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
        "vm_target_id": authorization.get("vm_target_id"),
        "owners": authorization.get("owners", {}),
        "source_artifacts": {
            "authorization": artifact_ref(authorization_path),
            "service_preview_receipt": artifact_ref(service_preview_receipt_path),
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
    service_preview_receipt_path: Path,
    rollback_receipt_path: Path,
    monitoring_audit_receipt_path: Path,
    output: Path,
) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    authorization = read_json_object(authorization_path)
    preview = read_json_object(service_preview_receipt_path)
    rollback = read_json_object(rollback_receipt_path)
    audit = read_json_object(monitoring_audit_receipt_path)
    check(checks, failures, "authorization_passed", authorization.get("passed") is True)
    check(checks, failures, "service_preview_passed", preview.get("passed") is True)
    check(checks, failures, "rollback_passed", rollback.get("passed") is True)
    check(checks, failures, "audit_passed", audit.get("passed") is True)
    check(checks, failures, "task_id_consistent", authorization.get("task_id") == preview.get("task_id") == rollback.get("task_id") == audit.get("task_id"))
    check(checks, failures, "vm_target_consistent", authorization.get("vm_target_id") == preview.get("vm_target_id") == rollback.get("vm_target_id") == audit.get("vm_target_id"))
    passed = _passed(checks, failures)
    report = {
        "schema_version": RECONCILIATION_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "decided_at": _now(),
        "task_id": authorization.get("task_id"),
        "vm_target_id": authorization.get("vm_target_id"),
        "decision": "p0i_vm_service_private_preview_passed" if passed else "blocked_p0i_vm_service_private_preview",
        "source_artifacts": {
            "authorization": artifact_ref(authorization_path),
            "service_preview_receipt": artifact_ref(service_preview_receipt_path),
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
        completed = subprocess.run(argv, cwd=workdir, text=True, capture_output=True, timeout=600, check=False)
    except Exception as exc:  # noqa: BLE001
        failures.append(f"{field}_execution_error:{exc}")
        return {"argv": argv, "returncode": None, "stdout": "", "stderr": str(exc)}
    return {
        "argv": argv,
        "returncode": completed.returncode,
        "stdout": completed.stdout[-8000:],
        "stderr": completed.stderr[-8000:],
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


def _review_only_boundary(boundary: dict[str, Any]) -> bool:
    return (
        boundary.get("vm_contact_performed") is False
        and boundary.get("private_preview_deploy_performed") is False
        and _closed_no_production_boundary(boundary)
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
        "private_preview_deploy_performed": False,
        "backend_health_check_performed": False,
        "frontend_health_check_performed": False,
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
    parser = argparse.ArgumentParser(description="Run P0-I VM service private preview gate")
    parser.add_argument("--p0h-summary", required=True)
    parser.add_argument("--output-root", required=True)
    parser.add_argument("--deploy-command", required=True)
    parser.add_argument("--backend-health-command", required=True)
    parser.add_argument("--frontend-health-command", required=True)
    parser.add_argument("--rollback-command", required=True)
    parser.add_argument("--rollback-health-command", required=True)
    parser.add_argument("--operator-id", default="operator-cc")
    parser.add_argument("--working-directory", default=".")
    parser.add_argument("--ack-vm-service-private-preview", action="store_true")
    args = parser.parse_args()
    summary = run_gate(
        p0h_summary_path=Path(args.p0h_summary),
        output_root=Path(args.output_root),
        deploy_command=args.deploy_command,
        backend_health_command=args.backend_health_command,
        frontend_health_command=args.frontend_health_command,
        rollback_command=args.rollback_command,
        rollback_health_command=args.rollback_health_command,
        operator_id=args.operator_id,
        ack_vm_service_private_preview=bool(args.ack_vm_service_private_preview),
        working_directory=Path(args.working_directory),
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if summary.get("passed") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
