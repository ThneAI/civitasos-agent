"""Run P0-K private preview soak gate.

P0-K consumes a passed P0-J multi-VM private preview summary and performs a
bounded multi-cycle backend/frontend private preview soak. It may contact the
configured VMs and run non-production preview/rollback commands. It never opens
public ingress, mutates source/Git, touches production data, authorizes
production transition, or writes production receipts.
"""

from __future__ import annotations

import argparse
import json
import statistics
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from benchmarks.i_gate_evidence import artifact_ref, check, object_value, read_json_object, sha256_file, write_json_object
from benchmarks.p0j_multi_vm_private_preview_gate import (
    AUTHORIZATION_SCHEMA as P0J_AUTHORIZATION_SCHEMA,
    CHAIN_SCHEMA as P0J_CHAIN_SCHEMA,
    EXPECTED_SMOKE_SCHEMA,
    MONITORING_AUDIT_SCHEMA as P0J_MONITORING_AUDIT_SCHEMA,
    MULTI_VM_PREVIEW_SCHEMA as P0J_MULTI_VM_PREVIEW_SCHEMA,
    RECONCILIATION_SCHEMA as P0J_RECONCILIATION_SCHEMA,
    ROLLBACK_SCHEMA as P0J_ROLLBACK_SCHEMA,
    _command_argv_from_raw,
    _closed_no_production_boundary,
    _parse_json_from_stdout,
    _read_verified_ref,
    _run_authorized_command,
    _unique_texts,
)

CHAIN_SCHEMA = "p0k-private-preview-soak-chain:v1"
CONTEXT_SCHEMA = "p0k-p0j-context-validation:v1"
AUTHORIZATION_SCHEMA = "p0k-private-preview-soak-authorization:v1"
SOAK_RECEIPT_SCHEMA = "p0k-private-preview-soak-receipt:v1"
ROLLBACK_SCHEMA = "p0k-private-preview-soak-rollback-receipt:v1"
MONITORING_AUDIT_SCHEMA = "p0k-private-preview-soak-monitoring-audit-receipt:v1"
RECONCILIATION_SCHEMA = "p0k-private-preview-soak-reconciliation:v1"
DEFAULT_EXPECTED_NODES = ("vm1", "vm2", "vm3")
DEFAULT_CYCLES = 3
DEFAULT_INTERVAL_SECONDS = 0.0
DEFAULT_MAX_LATENCY_MS = 5000.0

NON_CLAIMS = (
    "p0k_is_private_preview_soak_only",
    "p0k_requires_passed_p0j_multi_vm_private_preview",
    "p0k_requires_explicit_operator_soak_authorization",
    "p0k_does_not_open_public_ingress",
    "p0k_does_not_touch_production_data",
    "p0k_does_not_modify_source_or_git",
    "p0k_does_not_write_production_receipts",
    "p0k_does_not_authorize_production_transition",
)


def run_gate(
    *,
    p0j_summary_path: Path,
    output_root: Path,
    deploy_command: str,
    smoke_command: str,
    rollback_command: str,
    rollback_health_command: str,
    expected_nodes: list[str] | None = None,
    cycles: int = DEFAULT_CYCLES,
    interval_seconds: float = DEFAULT_INTERVAL_SECONDS,
    max_latency_ms: float = DEFAULT_MAX_LATENCY_MS,
    operator_id: str = "operator-cc",
    ack_private_preview_soak: bool = False,
    working_directory: Path | None = None,
) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "authorization": output_root / "p0k_private_preview_soak_authorization.json",
        "soak_receipt": output_root / "p0k_private_preview_soak_receipt.json",
        "rollback_receipt": output_root / "p0k_private_preview_soak_rollback_receipt.json",
        "monitoring_audit_receipt": output_root / "p0k_private_preview_soak_monitoring_audit_receipt.json",
        "reconciliation": output_root / "p0k_private_preview_soak_reconciliation.json",
        "summary": output_root / "p0k_private_preview_soak_chain_summary.json",
    }
    authorization = write_authorization(
        p0j_summary_path=p0j_summary_path,
        output=artifacts["authorization"],
        deploy_command=deploy_command,
        smoke_command=smoke_command,
        rollback_command=rollback_command,
        rollback_health_command=rollback_health_command,
        expected_nodes=expected_nodes or list(DEFAULT_EXPECTED_NODES),
        cycles=cycles,
        interval_seconds=interval_seconds,
        max_latency_ms=max_latency_ms,
        operator_id=operator_id,
        ack_private_preview_soak=ack_private_preview_soak,
        working_directory=working_directory or Path.cwd(),
    )
    soak = write_soak_receipt(
        authorization_path=artifacts["authorization"],
        output=artifacts["soak_receipt"],
    )
    rollback = write_rollback_receipt(
        authorization_path=artifacts["authorization"],
        soak_receipt_path=artifacts["soak_receipt"],
        output=artifacts["rollback_receipt"],
    )
    audit = write_monitoring_audit_receipt(
        authorization_path=artifacts["authorization"],
        soak_receipt_path=artifacts["soak_receipt"],
        rollback_receipt_path=artifacts["rollback_receipt"],
        output=artifacts["monitoring_audit_receipt"],
    )
    reconciliation = write_reconciliation(
        authorization_path=artifacts["authorization"],
        soak_receipt_path=artifacts["soak_receipt"],
        rollback_receipt_path=artifacts["rollback_receipt"],
        monitoring_audit_receipt_path=artifacts["monitoring_audit_receipt"],
        output=artifacts["reconciliation"],
    )
    reports = [authorization, soak, rollback, audit, reconciliation]
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
        "source_artifacts": {"p0j_summary": artifact_ref(p0j_summary_path)},
        "artifacts": {name: artifact_ref(path) for name, path in artifacts.items() if name != "summary"},
        "soak": {
            "requested_cycles": authorization.get("cycles"),
            "completed_cycles": soak.get("completed_cycles", 0),
            "latency_summary": soak.get("latency_summary", {}),
        },
        "readiness": {
            "state": "p0k_private_preview_soak_passed" if passed else "blocked_p0k_private_preview_soak",
            "p0k_private_preview_soak_complete": passed,
            "p0l_external_preview_evidence_ready": passed,
            "production_transition_allowed": False,
        },
        "boundary": _boundary(
            private_preview_soak_authorized=authorization.get("passed") is True,
            vm_contact_performed=object_value(soak.get("boundary")).get("vm_contact_performed") is True,
            private_preview_soak_deploy_performed=soak.get("deploy_performed") is True,
            multi_cycle_smoke_performed=soak.get("multi_cycle_smoke_performed") is True,
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
    p0j_summary_path: Path,
    output: Path,
    deploy_command: str,
    smoke_command: str,
    rollback_command: str,
    rollback_health_command: str,
    expected_nodes: list[str],
    cycles: int,
    interval_seconds: float,
    max_latency_ms: float,
    operator_id: str,
    ack_private_preview_soak: bool,
    working_directory: Path,
) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    context = validate_p0j_context(p0j_summary_path)
    workdir = working_directory.resolve()
    normalized_nodes = _unique_texts(expected_nodes)
    commands = {
        "deploy_command": _command_argv_from_raw(deploy_command, failures, "deploy_command"),
        "smoke_command": _command_argv_from_raw(smoke_command, failures, "smoke_command"),
        "rollback_command": _command_argv_from_raw(rollback_command, failures, "rollback_command"),
        "rollback_health_command": _command_argv_from_raw(rollback_health_command, failures, "rollback_health_command"),
    }
    failures.extend(str(item) for item in context.get("failure_reasons", []))
    check(checks, failures, "p0j_context_passed", context.get("passed") is True)
    check(checks, failures, "operator_id_present", bool(str(operator_id).strip()))
    check(checks, failures, "explicit_operator_ack", ack_private_preview_soak is True)
    check(checks, failures, "working_directory_exists", workdir.is_dir())
    check(checks, failures, "expected_nodes_present", len(normalized_nodes) >= 2)
    check(checks, failures, "cycles_at_least_two", cycles >= 2)
    check(checks, failures, "interval_seconds_non_negative", interval_seconds >= 0)
    check(checks, failures, "max_latency_ms_positive", max_latency_ms > 0)
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
        "cycles": cycles,
        "interval_seconds": interval_seconds,
        "max_latency_ms": max_latency_ms,
        "authorization_scope": "multi_vm_backend_frontend_private_preview_soak_only",
        "working_directory": str(workdir),
        "deploy_command": {"raw": deploy_command, "argv": commands["deploy_command"], "shell": False},
        "smoke_command": {"raw": smoke_command, "argv": commands["smoke_command"], "shell": False},
        "rollback_command": {"raw": rollback_command, "argv": commands["rollback_command"], "shell": False},
        "rollback_health_command": {"raw": rollback_health_command, "argv": commands["rollback_health_command"], "shell": False},
        "source_artifacts": {"p0j_summary": artifact_ref(p0j_summary_path)},
        "p0j_artifacts": context.get("p0j_artifacts", {}),
        "boundary": _boundary(private_preview_soak_authorized=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, authorization)
    return authorization


def validate_p0j_context(p0j_summary_path: Path) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    try:
        p0j = read_json_object(p0j_summary_path)
    except Exception as exc:  # noqa: BLE001
        return _report(CONTEXT_SCHEMA, False, [f"p0j_summary_unreadable:{exc}"], checks)
    refs = object_value(p0j.get("artifacts"))
    authorization = _read_verified_ref(refs.get("authorization"), checks, failures, "p0j_authorization")
    preview = _read_verified_ref(refs.get("multi_vm_preview_receipt"), checks, failures, "p0j_multi_vm_preview_receipt")
    rollback = _read_verified_ref(refs.get("rollback_receipt"), checks, failures, "p0j_rollback_receipt")
    audit = _read_verified_ref(refs.get("monitoring_audit_receipt"), checks, failures, "p0j_monitoring_audit_receipt")
    reconciliation = _read_verified_ref(refs.get("reconciliation"), checks, failures, "p0j_reconciliation")
    readiness = object_value(p0j.get("readiness"))
    boundary = object_value(p0j.get("boundary"))
    task_id = str(p0j.get("task_id") or authorization.get("task_id") or "")

    check(checks, failures, "p0j_summary_passed", p0j.get("schema_version") == P0J_CHAIN_SCHEMA and p0j.get("passed") is True)
    check(checks, failures, "p0j_ready_for_p0k", readiness.get("p0k_private_preview_soak_ready") is True)
    check(checks, failures, "p0j_production_transition_closed", readiness.get("production_transition_allowed") is False)
    check(checks, failures, "p0j_authorization_passed", authorization.get("schema_version") == P0J_AUTHORIZATION_SCHEMA and authorization.get("passed") is True)
    check(checks, failures, "p0j_multi_vm_preview_passed", preview.get("schema_version") == P0J_MULTI_VM_PREVIEW_SCHEMA and preview.get("passed") is True)
    check(checks, failures, "p0j_rollback_passed", rollback.get("schema_version") == P0J_ROLLBACK_SCHEMA and rollback.get("passed") is True)
    check(checks, failures, "p0j_audit_passed", audit.get("schema_version") == P0J_MONITORING_AUDIT_SCHEMA and audit.get("passed") is True)
    check(checks, failures, "p0j_reconciliation_passed", reconciliation.get("schema_version") == P0J_RECONCILIATION_SCHEMA and reconciliation.get("passed") is True)
    check(checks, failures, "task_id_consistent", all(item.get("task_id") == task_id for item in (authorization, preview, rollback, audit, reconciliation)))
    check(checks, failures, "p0j_boundary_multi_vm_preview_observed", _p0j_preview_observed(boundary))
    check(checks, failures, "p0j_boundary_closed", _closed_no_production_boundary(boundary))
    return {
        "schema_version": CONTEXT_SCHEMA,
        "passed": _passed(checks, failures),
        "failure_reasons": failures,
        "checks": checks,
        "task_id": task_id,
        "owners": object_value(p0j.get("owners")),
        "p0j_artifacts": refs,
        "p0j_summary": p0j,
    }


def write_soak_receipt(*, authorization_path: Path, output: Path) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    authorization = read_json_object(authorization_path)
    expected_nodes = _unique_texts(authorization.get("expected_nodes"))
    cycles = int(authorization.get("cycles") or 0)
    interval_seconds = float(authorization.get("interval_seconds") or 0.0)
    max_latency_ms = float(authorization.get("max_latency_ms") or 0.0)
    workdir = Path(str(authorization.get("working_directory") or "")).resolve()
    check(checks, failures, "authorization_passed", authorization.get("schema_version") == AUTHORIZATION_SCHEMA and authorization.get("passed") is True)
    deploy = _run_authorized_command(authorization, "deploy_command", workdir, failures) if authorization.get("passed") is True else None
    if deploy and deploy.get("returncode") != 0:
        failures.append("deploy_command_failed")
    deploy_succeeded = bool(deploy) and deploy.get("returncode") == 0
    cycle_reports: list[dict[str, Any]] = []
    observed_nodes: list[str] = []
    latency_samples: list[float] = []
    started = time.monotonic()
    if deploy_succeeded:
        for cycle in range(1, cycles + 1):
            smoke_started = time.monotonic()
            smoke = _run_authorized_command(authorization, "smoke_command", workdir, failures)
            smoke_duration_ms = round((time.monotonic() - smoke_started) * 1000, 3)
            smoke_summary = _parse_json_from_stdout(str(object_value(smoke).get("stdout") or ""), failures, f"smoke_cycle_{cycle}") if smoke else {}
            smoke_nodes = _unique_texts(smoke_summary.get("nodes"))
            observed_nodes.extend(node for node in smoke_nodes if node not in observed_nodes)
            _collect_latencies(smoke_summary, latency_samples)
            cycle_passed = _smoke_summary_passed(smoke, smoke_summary, expected_nodes, max_latency_ms)
            if not cycle_passed:
                failures.append(f"smoke_cycle_{cycle}_failed")
            cycle_reports.append(
                {
                    "cycle": cycle,
                    "passed": cycle_passed,
                    "duration_ms": smoke_duration_ms,
                    "command": smoke,
                    "smoke_summary": smoke_summary,
                    "observed_nodes": smoke_nodes,
                }
            )
            if not cycle_passed:
                break
            if cycle < cycles and interval_seconds > 0:
                time.sleep(interval_seconds)
    else:
        checks["smoke_skipped_after_deploy_failure"] = True
    latency_summary = _latency_summary(latency_samples)
    check(checks, failures, "deploy_command_success", deploy_succeeded)
    if deploy_succeeded:
        check(checks, failures, "requested_cycles_completed", len(cycle_reports) == cycles)
        check(checks, failures, "all_cycles_passed", bool(cycle_reports) and all(item.get("passed") is True for item in cycle_reports))
        check(checks, failures, "observed_nodes_match_expected", set(observed_nodes) == set(expected_nodes))
        check(checks, failures, "latency_samples_present", bool(latency_samples))
        check(checks, failures, "latency_under_threshold", bool(latency_samples) and max(latency_samples) <= max_latency_ms)
    passed = _passed(checks, failures)
    receipt = {
        "schema_version": SOAK_RECEIPT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "completed_at": _now(),
        "duration_seconds": round(time.monotonic() - started, 3),
        "task_id": authorization.get("task_id"),
        "expected_nodes": expected_nodes,
        "observed_nodes": observed_nodes,
        "requested_cycles": cycles,
        "completed_cycles": len(cycle_reports),
        "source_artifacts": {"authorization": artifact_ref(authorization_path)},
        "deploy": deploy,
        "cycle_reports": cycle_reports,
        "latency_summary": latency_summary,
        "deploy_performed": deploy_succeeded,
        "multi_cycle_smoke_performed": len(cycle_reports) == cycles and all(item.get("passed") is True for item in cycle_reports),
        "boundary": _boundary(
            vm_contact_performed=bool(deploy),
            private_preview_soak_deploy_performed=deploy_succeeded,
            multi_cycle_smoke_performed=len(cycle_reports) == cycles and all(item.get("passed") is True for item in cycle_reports),
        ),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, receipt)
    return receipt


def write_rollback_receipt(*, authorization_path: Path, soak_receipt_path: Path, output: Path) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    authorization = read_json_object(authorization_path)
    soak = read_json_object(soak_receipt_path)
    workdir = Path(str(authorization.get("working_directory") or "")).resolve()
    should_rollback = authorization.get("passed") is True and soak.get("deploy_performed") is True
    rollback = _run_authorized_command(authorization, "rollback_command", workdir, failures) if should_rollback else None
    if rollback and rollback.get("returncode") != 0:
        failures.append("rollback_command_failed")
    rollback_health = _run_authorized_command(authorization, "rollback_health_command", workdir, failures) if rollback and rollback.get("returncode") == 0 else None
    if rollback_health and rollback_health.get("returncode") != 0:
        failures.append("rollback_health_command_failed")
    check(checks, failures, "authorization_passed", authorization.get("passed") is True)
    check(checks, failures, "soak_attempt_recorded", soak.get("schema_version") == SOAK_RECEIPT_SCHEMA)
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
            "soak_receipt": artifact_ref(soak_receipt_path),
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
    soak_receipt_path: Path,
    rollback_receipt_path: Path,
    output: Path,
) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    authorization = read_json_object(authorization_path)
    soak = read_json_object(soak_receipt_path)
    rollback = read_json_object(rollback_receipt_path)
    check(checks, failures, "authorization_passed", authorization.get("passed") is True)
    check(checks, failures, "soak_passed", soak.get("passed") is True)
    check(checks, failures, "rollback_passed", rollback.get("passed") is True)
    check(checks, failures, "owners_present", bool(object_value(authorization.get("owners"))))
    check(checks, failures, "soak_boundary_closed", _closed_no_production_boundary(object_value(soak.get("boundary"))))
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
            "soak_receipt": artifact_ref(soak_receipt_path),
            "rollback_receipt": artifact_ref(rollback_receipt_path),
        },
        "latency_summary": soak.get("latency_summary", {}),
        "boundary": _boundary(monitoring_audit_receipt_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def write_reconciliation(
    *,
    authorization_path: Path,
    soak_receipt_path: Path,
    rollback_receipt_path: Path,
    monitoring_audit_receipt_path: Path,
    output: Path,
) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    authorization = read_json_object(authorization_path)
    soak = read_json_object(soak_receipt_path)
    rollback = read_json_object(rollback_receipt_path)
    audit = read_json_object(monitoring_audit_receipt_path)
    check(checks, failures, "authorization_passed", authorization.get("passed") is True)
    check(checks, failures, "soak_passed", soak.get("passed") is True)
    check(checks, failures, "rollback_passed", rollback.get("passed") is True)
    check(checks, failures, "audit_passed", audit.get("passed") is True)
    check(checks, failures, "expected_nodes_consistent", authorization.get("expected_nodes") == soak.get("expected_nodes") == rollback.get("expected_nodes") == audit.get("expected_nodes"))
    check(checks, failures, "cycle_count_consistent", authorization.get("cycles") == soak.get("requested_cycles") == soak.get("completed_cycles"))
    passed = _passed(checks, failures)
    report = {
        "schema_version": RECONCILIATION_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "decided_at": _now(),
        "task_id": authorization.get("task_id"),
        "expected_nodes": authorization.get("expected_nodes", []),
        "decision": "p0k_private_preview_soak_passed" if passed else "blocked_p0k_private_preview_soak",
        "source_artifacts": {
            "authorization": artifact_ref(authorization_path),
            "soak_receipt": artifact_ref(soak_receipt_path),
            "rollback_receipt": artifact_ref(rollback_receipt_path),
            "monitoring_audit_receipt": artifact_ref(monitoring_audit_receipt_path),
        },
        "boundary": _boundary(owner_reconciliation_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def _smoke_summary_passed(smoke: dict[str, Any] | None, summary: dict[str, Any], expected_nodes: list[str], max_latency_ms: float) -> bool:
    if not smoke or smoke.get("returncode") != 0:
        return False
    smoke_nodes = _unique_texts(summary.get("nodes"))
    latency_values: list[float] = []
    _collect_latencies(summary, latency_values)
    return (
        summary.get("schema_version") == EXPECTED_SMOKE_SCHEMA
        and summary.get("passed") is True
        and set(smoke_nodes) == set(expected_nodes)
        and int(summary.get("total_checks") or 0) >= len(expected_nodes)
        and summary.get("production_deploy_allowed") is False
        and summary.get("production_runtime_execution_allowed") is False
        and summary.get("production_receipt_write_allowed") is False
        and bool(latency_values)
        and max(latency_values) <= max_latency_ms
    )


def _collect_latencies(summary: dict[str, Any], samples: list[float]) -> None:
    observations = summary.get("observations")
    if isinstance(observations, list):
        for item in observations:
            value = _float_or_none(object_value(item).get("elapsed_ms"))
            if value is not None:
                samples.append(value)
    for field in ("latency_ms_min", "latency_ms_median", "latency_ms_max"):
        value = _float_or_none(summary.get(field))
        if value is not None:
            samples.append(value)


def _latency_summary(samples: list[float]) -> dict[str, Any]:
    if not samples:
        return {"sample_count": 0}
    return {
        "sample_count": len(samples),
        "latency_ms_min": min(samples),
        "latency_ms_median": round(statistics.median(samples), 3),
        "latency_ms_max": max(samples),
    }


def _float_or_none(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _p0j_preview_observed(boundary: dict[str, Any]) -> bool:
    return (
        boundary.get("vm_contact_performed") is True
        and boundary.get("multi_vm_private_preview_deploy_performed") is True
        and boundary.get("multi_vm_smoke_performed") is True
        and boundary.get("rollback_performed") is True
        and boundary.get("rollback_health_check_performed") is True
    )


def _boundary(**overrides: bool) -> dict[str, bool]:
    base = {
        "private_preview_soak_authorized": False,
        "vm_contact_performed": False,
        "private_preview_soak_deploy_performed": False,
        "multi_cycle_smoke_performed": False,
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
    parser = argparse.ArgumentParser(description="Run P0-K private preview soak gate")
    parser.add_argument("--p0j-summary", required=True)
    parser.add_argument("--output-root", required=True)
    parser.add_argument("--deploy-command", required=True)
    parser.add_argument("--smoke-command", required=True)
    parser.add_argument("--rollback-command", required=True)
    parser.add_argument("--rollback-health-command", required=True)
    parser.add_argument("--expected-node", action="append", default=[])
    parser.add_argument("--cycles", type=int, default=DEFAULT_CYCLES)
    parser.add_argument("--interval-seconds", type=float, default=DEFAULT_INTERVAL_SECONDS)
    parser.add_argument("--max-latency-ms", type=float, default=DEFAULT_MAX_LATENCY_MS)
    parser.add_argument("--operator-id", default="operator-cc")
    parser.add_argument("--working-directory", default=".")
    parser.add_argument("--ack-private-preview-soak", action="store_true")
    args = parser.parse_args()
    summary = run_gate(
        p0j_summary_path=Path(args.p0j_summary),
        output_root=Path(args.output_root),
        deploy_command=args.deploy_command,
        smoke_command=args.smoke_command,
        rollback_command=args.rollback_command,
        rollback_health_command=args.rollback_health_command,
        expected_nodes=args.expected_node or list(DEFAULT_EXPECTED_NODES),
        cycles=args.cycles,
        interval_seconds=args.interval_seconds,
        max_latency_ms=args.max_latency_ms,
        operator_id=args.operator_id,
        ack_private_preview_soak=bool(args.ack_private_preview_soak),
        working_directory=Path(args.working_directory),
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if summary.get("passed") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
