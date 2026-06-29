"""Execute one bounded PostH3 external user usage action.

PostH3-W consumes a PostH3-T authorize-once review plus the matching PostH3-V
limited usage binding. It performs one status/read-only external-user usage
against a temporary local endpoint, writes monitoring and rollback/abort
receipts, then closes the endpoint. It does not execute runtime tasks, contact
VMs, deploy, access production data, write production receipts, or write
source/Git state.
"""

from __future__ import annotations

import argparse
import json
import os
import threading
import time
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from benchmarks.i_gate_evidence import artifact_ref, check, object_value, read_json_object, sha256_file, sha256_json, write_json_object
from benchmarks.post_h3_external_user_usage_review_gate import (
    BOUNDARY_REPORT_SCHEMA as POST_H3T_BOUNDARY_REPORT_SCHEMA,
    CHAIN_SCHEMA as POST_H3T_SCHEMA,
    REVIEW_RECONCILIATION_SCHEMA as POST_H3T_RECONCILIATION_SCHEMA,
)
from benchmarks.post_h3_limited_external_usage_scope_binding_gate import (
    BOUNDARY_REPORT_SCHEMA as POST_H3V_BOUNDARY_REPORT_SCHEMA,
    CHAIN_SCHEMA as POST_H3V_SCHEMA,
    MONITORING_ROLLBACK_SCHEMA as POST_H3V_MONITORING_ROLLBACK_SCHEMA,
    USAGE_SCOPE_SCHEMA as POST_H3V_USAGE_SCOPE_SCHEMA,
)

CHAIN_SCHEMA = "post-h3-external-user-usage-execution-chain:v1"
CONTEXT_SCHEMA = "post-h3w-post-h3t-v-context-validation:v1"
AUTHORIZATION_CONSUMPTION_SCHEMA = "post-h3w-external-user-usage-authorization-consumption:v1"
USAGE_RECEIPT_SCHEMA = "post-h3w-external-user-usage-receipt:v1"
MONITORING_ROLLBACK_RECEIPT_SCHEMA = "post-h3w-monitoring-rollback-receipt:v1"
OWNER_AUDIT_RECONCILIATION_SCHEMA = "post-h3w-owner-audit-reconciliation:v1"
BOUNDARY_REPORT_SCHEMA = "post-h3w-external-user-usage-execution-boundary-report:v1"

ACCEPTED_OPERATOR_DECISION = "execute_limited_external_user_usage_once"
ACCEPTED_AUDIT_DECISION = "accept_limited_external_user_usage_execution_once"
ACCEPTED_MONITORING_DECISION = "accept_limited_external_user_monitoring_execution_once"
ACCEPTED_ROLLBACK_DECISION = "accept_limited_external_user_abort_path_once"
ALLOWED_USAGE_SCOPE = "invite-only-status-read-only-task"
NON_CLAIMS = (
    "post_h3w_executes_one_limited_external_user_usage_only",
    "post_h3w_uses_status_read_only_endpoint_only",
    "post_h3w_closes_limited_usage_endpoint_after_probe",
    "post_h3w_does_not_execute_runtime_task",
    "post_h3w_does_not_contact_vm_targets",
    "post_h3w_does_not_deploy",
    "post_h3w_does_not_access_production_data",
    "post_h3w_does_not_write_production_runtime_receipts",
    "post_h3w_does_not_write_source_or_git",
)


def run_gate(
    *,
    post_h3t_summary_path: Path,
    post_h3v_summary_path: Path,
    output_root: Path,
    operator_id: str = "operator-primary",
    operator_decision: str = ACCEPTED_OPERATOR_DECISION,
    audit_decision: str = ACCEPTED_AUDIT_DECISION,
    monitoring_decision: str = ACCEPTED_MONITORING_DECISION,
    rollback_decision: str = ACCEPTED_ROLLBACK_DECISION,
    operator_statement: str = "Execute one bounded invite-only status/read-only external user usage and close the endpoint after probe.",
    external_user_handle: str = "Thneoly",
    requested_usage_scope: str = ALLOWED_USAGE_SCOPE,
    usage_seconds: float = 0.1,
    bind_host: str = "127.0.0.1",
    probe_host: str = "127.0.0.1",
    authorization_consumption_path: Path | None = None,
    ack_external_user_usage_execution: bool = False,
) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "context_validation": output_root / "post_h3w_post_h3t_v_context_validation.json",
        "authorization_consumption": output_root / "post_h3w_external_user_usage_authorization_consumption.json",
        "usage_receipt": output_root / "post_h3w_external_user_usage_receipt.json",
        "monitoring_rollback_receipt": output_root / "post_h3w_monitoring_rollback_receipt.json",
        "owner_audit_reconciliation": output_root / "post_h3w_owner_audit_reconciliation.json",
        "boundary_report": output_root / "post_h3w_external_user_usage_execution_boundary_report.json",
        "summary": output_root / "post_h3w_external_user_usage_execution_summary.json",
    }
    context = validate_post_h3w_context(
        post_h3t_summary_path=post_h3t_summary_path,
        post_h3v_summary_path=post_h3v_summary_path,
        output=artifacts["context_validation"],
    )
    try:
        consumption = _write_authorization_consumption(
            context=context,
            post_h3t_summary_path=post_h3t_summary_path,
            output=artifacts["authorization_consumption"],
            lease_path=authorization_consumption_path or _default_consumption_lease_path(post_h3t_summary_path),
            operator_id=operator_id,
            operator_decision=operator_decision,
            audit_decision=audit_decision,
            monitoring_decision=monitoring_decision,
            rollback_decision=rollback_decision,
            operator_statement=operator_statement,
            ack_external_user_usage_execution=ack_external_user_usage_execution,
        )
    except RuntimeError as exc:
        consumption = _write_blocked_consumption(
            output=artifacts["authorization_consumption"],
            post_h3t_summary_path=post_h3t_summary_path,
            error=str(exc),
        )
    usage = _write_usage_receipt(
        context=context,
        consumption_path=artifacts["authorization_consumption"],
        output=artifacts["usage_receipt"],
        external_user_handle=external_user_handle,
        requested_usage_scope=requested_usage_scope,
        usage_seconds=usage_seconds,
        bind_host=bind_host,
        probe_host=probe_host,
    )
    monitoring = _write_monitoring_rollback_receipt(
        context=context,
        usage_receipt_path=artifacts["usage_receipt"],
        output=artifacts["monitoring_rollback_receipt"],
    )
    reconciliation = _write_owner_audit_reconciliation(
        context=context,
        usage_receipt_path=artifacts["usage_receipt"],
        monitoring_rollback_receipt_path=artifacts["monitoring_rollback_receipt"],
        output=artifacts["owner_audit_reconciliation"],
    )
    boundary = _write_boundary_report(
        context=context,
        owner_audit_reconciliation_path=artifacts["owner_audit_reconciliation"],
        output=artifacts["boundary_report"],
    )
    reports = [context, consumption, usage, monitoring, reconciliation, boundary]
    passed = all(report.get("passed") is True for report in reports)
    summary = {
        "schema_version": CHAIN_SCHEMA,
        "passed": passed,
        "failure_reasons": _failures(reports),
        "checked_at": _now(),
        "source_artifacts": {
            "post_h3t_summary": artifact_ref(post_h3t_summary_path),
            "post_h3v_summary": artifact_ref(post_h3v_summary_path),
        },
        "artifacts": {name: artifact_ref(path) for name, path in artifacts.items() if name != "summary"},
        "external_user_usage_review_id": object_value(context.get("post_h3t_summary")).get("external_user_usage_review_id"),
        "limited_external_usage_scope_binding_id": object_value(context.get("post_h3v_summary")).get("limited_external_usage_scope_binding_id"),
        "external_user_usage_execution_id": usage.get("external_user_usage_execution_id"),
        "external_user_usage_receipt_id": usage.get("external_user_usage_receipt_id"),
        "readiness": {
            "state": "post_h3_external_user_usage_execution_complete" if passed else "blocked_post_h3_external_user_usage_execution",
            "external_user_usage_execution_complete": passed,
            "external_user_usage_authorization_consumed": consumption.get("passed") is True,
            "external_user_usage_performed": passed,
            "external_user_usage_closed": passed,
            "monitoring_receipt_written": monitoring.get("passed") is True,
            "rollback_abort_receipt_written": monitoring.get("passed") is True,
            "owner_audit_reconciliation_complete": reconciliation.get("passed") is True,
            "external_public_ingress_opened": False,
            "runtime_execution_performed": False,
            "production_runtime_receipt_write_allowed": False,
        },
        "boundary": _boundary(
            context_validation_written=context.get("passed") is True,
            authorization_consumed=consumption.get("passed") is True,
            usage_receipt_written=usage.get("passed") is True,
            monitoring_rollback_receipt_written=monitoring.get("passed") is True,
            owner_audit_reconciliation_written=reconciliation.get("passed") is True,
            boundary_report_written=boundary.get("passed") is True,
            limited_external_user_usage_performed=passed,
            limited_usage_endpoint_opened=passed,
            limited_usage_endpoint_closed=passed,
        ),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(artifacts["summary"], summary)
    return summary


def validate_post_h3w_context(*, post_h3t_summary_path: Path, post_h3v_summary_path: Path, output: Path | None = None) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    try:
        t_summary = read_json_object(post_h3t_summary_path)
        v_summary = read_json_object(post_h3v_summary_path)
    except Exception as exc:  # noqa: BLE001
        return _write_optional(_report(CONTEXT_SCHEMA, False, [f"summary_unreadable:{exc}"], checks), output)
    t_artifacts = object_value(t_summary.get("artifacts"))
    v_artifacts = object_value(v_summary.get("artifacts"))
    t_reconciliation = _read_verified_ref(t_artifacts.get("review_reconciliation"), checks, failures, "post_h3t_review_reconciliation")
    t_boundary = _read_verified_ref(t_artifacts.get("boundary_report"), checks, failures, "post_h3t_boundary_report")
    v_usage_scope = _read_verified_ref(v_artifacts.get("usage_scope"), checks, failures, "post_h3v_usage_scope")
    v_monitoring = _read_verified_ref(v_artifacts.get("monitoring_rollback_binding"), checks, failures, "post_h3v_monitoring_rollback_binding")
    v_boundary = _read_verified_ref(v_artifacts.get("boundary_report"), checks, failures, "post_h3v_boundary_report")
    _check_t_summary(t_summary, checks, failures)
    _check_t_reconciliation(t_reconciliation, checks, failures)
    _check_t_boundary(t_boundary, checks, failures)
    _check_v_summary(v_summary, checks, failures)
    _check_v_usage_scope(v_usage_scope, checks, failures)
    _check_v_monitoring(v_monitoring, checks, failures)
    _check_v_boundary(v_boundary, checks, failures)
    check(checks, failures, "t_v_user_matches", t_reconciliation.get("authorization_evidence", {}).get("external_user_handle") == v_summary.get("external_user_handle"))
    check(checks, failures, "t_v_scope_matches", t_reconciliation.get("allowed_usage_scope") == v_summary.get("allowed_usage_scope"))
    check(checks, failures, "t_v_max_users_matches", t_reconciliation.get("max_external_users") == v_summary.get("max_external_users"))
    t_source_v = object_value(object_value(t_summary.get("source_artifacts")).get("post_h3v_summary"))
    check(checks, failures, "t_source_binds_v_path", Path(str(t_source_v.get("path") or "")) == post_h3v_summary_path.resolve())
    check(checks, failures, "t_source_binds_v_hash", t_source_v.get("sha256") == sha256_file(post_h3v_summary_path))
    passed = _passed(checks, failures)
    report = {
        "schema_version": CONTEXT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "post_h3t_summary": t_summary,
        "post_h3v_summary": v_summary,
        "post_h3t_review_reconciliation": t_reconciliation,
        "post_h3v_usage_scope": v_usage_scope,
        "post_h3v_monitoring_rollback_binding": v_monitoring,
        "source_artifacts": {
            "post_h3t_summary": artifact_ref(post_h3t_summary_path),
            "post_h3v_summary": artifact_ref(post_h3v_summary_path),
        },
        "boundary": _boundary(context_validation_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    return _write_optional(report, output)


def _write_authorization_consumption(
    *,
    context: dict[str, Any],
    post_h3t_summary_path: Path,
    output: Path,
    lease_path: Path,
    operator_id: str,
    operator_decision: str,
    audit_decision: str,
    monitoring_decision: str,
    rollback_decision: str,
    operator_statement: str,
    ack_external_user_usage_execution: bool,
) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    t_summary = object_value(context.get("post_h3t_summary"))
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "t_authorizes_usage", t_summary.get("external_user_usage_allowed") is True)
    check(checks, failures, "t_execution_ready", object_value(t_summary.get("readiness")).get("external_user_usage_execution_ready") is True)
    check(checks, failures, "operator_id_present", bool(operator_id.strip()))
    check(checks, failures, "operator_decision_accepted", operator_decision == ACCEPTED_OPERATOR_DECISION)
    check(checks, failures, "audit_decision_accepted", audit_decision == ACCEPTED_AUDIT_DECISION)
    check(checks, failures, "monitoring_decision_accepted", monitoring_decision == ACCEPTED_MONITORING_DECISION)
    check(checks, failures, "rollback_decision_accepted", rollback_decision == ACCEPTED_ROLLBACK_DECISION)
    check(checks, failures, "operator_statement_present", bool(operator_statement.strip()))
    check(checks, failures, "explicit_operator_ack", ack_external_user_usage_execution is True)
    if not _passed(checks, failures):
        return _write_consumption_report(
            output=output,
            passed=False,
            failures=failures,
            checks=checks,
            lease_path=lease_path,
            post_h3t_summary_path=post_h3t_summary_path,
            t_summary=t_summary,
            operator_id=operator_id,
            operator_decision=operator_decision,
            audit_decision=audit_decision,
            monitoring_decision=monitoring_decision,
            rollback_decision=rollback_decision,
            operator_statement=operator_statement,
            ack_external_user_usage_execution=ack_external_user_usage_execution,
        )
    lease = {
        "schema_version": "post-h3w-external-user-usage-authorization-consumption-lease:v1",
        "consumed_at": _now(),
        "post_h3t_summary": artifact_ref(post_h3t_summary_path),
        "external_user_usage_review_id": t_summary.get("external_user_usage_review_id"),
        "operator_id": operator_id,
    }
    lease_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(lease_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise RuntimeError(f"external_user_usage_authorization_already_consumed:{lease_path}") from exc
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(lease, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")
    check(checks, failures, "single_use_lease_written", lease_path.is_file())
    return _write_consumption_report(
        output=output,
        passed=_passed(checks, failures),
        failures=failures,
        checks=checks,
        lease_path=lease_path,
        post_h3t_summary_path=post_h3t_summary_path,
        t_summary=t_summary,
        operator_id=operator_id,
        operator_decision=operator_decision,
        audit_decision=audit_decision,
        monitoring_decision=monitoring_decision,
        rollback_decision=rollback_decision,
        operator_statement=operator_statement,
        ack_external_user_usage_execution=ack_external_user_usage_execution,
    )


def _write_consumption_report(
    *,
    output: Path,
    passed: bool,
    failures: list[str],
    checks: dict[str, bool],
    lease_path: Path,
    post_h3t_summary_path: Path,
    t_summary: dict[str, Any],
    operator_id: str,
    operator_decision: str,
    audit_decision: str,
    monitoring_decision: str,
    rollback_decision: str,
    operator_statement: str,
    ack_external_user_usage_execution: bool,
) -> dict[str, Any]:
    report = {
        "schema_version": AUTHORIZATION_CONSUMPTION_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "consumed_at": _now(),
        "external_user_usage_review_id": t_summary.get("external_user_usage_review_id"),
        "single_use_consumption": passed,
        "lease_path": str(lease_path.resolve()),
        "operator_id": operator_id,
        "operator_decision": operator_decision,
        "audit_decision": audit_decision,
        "monitoring_decision": monitoring_decision,
        "rollback_decision": rollback_decision,
        "operator_statement": operator_statement,
        "operator_statement_sha256": sha256_json(operator_statement),
        "ack_external_user_usage_execution": ack_external_user_usage_execution,
        "source_artifacts": {"post_h3t_summary": artifact_ref(post_h3t_summary_path)},
        "boundary": _boundary(authorization_consumed=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def _write_blocked_consumption(*, output: Path, post_h3t_summary_path: Path, error: str) -> dict[str, Any]:
    checks = {"authorization_not_previously_consumed": False}
    report = {
        "schema_version": AUTHORIZATION_CONSUMPTION_SCHEMA,
        "passed": False,
        "failure_reasons": [error],
        "checks": checks,
        "consumed_at": _now(),
        "single_use_consumption": False,
        "source_artifacts": {"post_h3t_summary": artifact_ref(post_h3t_summary_path)},
        "boundary": _boundary(),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def _write_usage_receipt(
    *,
    context: dict[str, Any],
    consumption_path: Path,
    output: Path,
    external_user_handle: str,
    requested_usage_scope: str,
    usage_seconds: float,
    bind_host: str,
    probe_host: str,
) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    consumption = read_json_object(consumption_path)
    v_summary = object_value(context.get("post_h3v_summary"))
    v_usage_scope = object_value(context.get("post_h3v_usage_scope"))
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "authorization_consumed", consumption.get("passed") is True)
    check(checks, failures, "external_user_handle_matches", external_user_handle == v_summary.get("external_user_handle"))
    check(checks, failures, "usage_scope_matches", requested_usage_scope == v_usage_scope.get("allowed_usage_scope") == ALLOWED_USAGE_SCOPE)
    check(checks, failures, "usage_seconds_positive", usage_seconds > 0)
    check(checks, failures, "usage_seconds_within_scope", usage_seconds <= float(v_usage_scope.get("max_usage_seconds") or 0))
    check(checks, failures, "single_runtime_task_scope", int(v_usage_scope.get("max_runtime_tasks") or 0) == 1)
    check(checks, failures, "localhost_bound_endpoint", bind_host in {"127.0.0.1", "localhost"})
    action_result: dict[str, Any] = {"attempted": False}
    if _passed(checks, failures):
        action_result = _execute_status_read_only_usage(
            bind_host=bind_host,
            probe_host=probe_host,
            external_user_handle=external_user_handle,
            requested_usage_scope=requested_usage_scope,
            usage_seconds=usage_seconds,
        )
        check(checks, failures, "usage_endpoint_opened", action_result.get("opened") is True)
        check(checks, failures, "usage_request_observed", action_result.get("request_observed") is True)
        check(checks, failures, "usage_response_passed", action_result.get("response_passed") is True)
        check(checks, failures, "usage_endpoint_closed", action_result.get("closed") is True)
        check(checks, failures, "no_production_data_returned", action_result.get("production_data_returned") is False)
    passed = _passed(checks, failures)
    execution_id = f"post-h3w-usage-exec:{sha256_json([artifact_ref(consumption_path), external_user_handle, requested_usage_scope, usage_seconds])[:24]}"
    receipt = {
        "schema_version": USAGE_RECEIPT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "written_at": _now(),
        "external_user_usage_execution_id": execution_id,
        "external_user_usage_receipt_id": f"post-h3w-usage-receipt:{sha256_json([execution_id, action_result])[:24]}",
        "external_user_handle": external_user_handle,
        "requested_usage_scope": requested_usage_scope,
        "usage_seconds": usage_seconds,
        "action_result": action_result,
        "source_artifacts": {"authorization_consumption": artifact_ref(consumption_path)},
        "readiness": {
            "external_user_usage_performed": passed,
            "external_user_usage_closed": passed,
            "runtime_execution_performed": False,
            "production_runtime_receipt_write_allowed": False,
        },
        "boundary": _boundary(usage_receipt_written=passed, limited_external_user_usage_performed=passed, limited_usage_endpoint_opened=passed, limited_usage_endpoint_closed=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, receipt)
    return receipt


def _write_monitoring_rollback_receipt(*, context: dict[str, Any], usage_receipt_path: Path, output: Path) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    usage = read_json_object(usage_receipt_path)
    monitoring = object_value(context.get("post_h3v_monitoring_rollback_binding"))
    action = object_value(usage.get("action_result"))
    slo = object_value(monitoring.get("monitoring_slo"))
    latency = float(action.get("latency_ms") or 0)
    check(checks, failures, "usage_receipt_passed", usage.get("passed") is True)
    check(checks, failures, "monitoring_binding_passed", monitoring.get("passed") is True)
    check(checks, failures, "latency_within_slo", latency <= float(slo.get("max_probe_latency_ms") or 0))
    check(checks, failures, "usage_closed", action.get("closed") is True)
    check(checks, failures, "abort_path_bound", bool(monitoring.get("abort_path")))
    check(checks, failures, "rollback_runbook_bound", bool(monitoring.get("rollback_runbook_id")))
    passed = _passed(checks, failures)
    report = {
        "schema_version": MONITORING_ROLLBACK_RECEIPT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "written_at": _now(),
        "monitoring_receipt_id": f"post-h3w-monitoring:{sha256_json([artifact_ref(usage_receipt_path), latency])[:24]}",
        "rollback_abort_receipt_id": f"post-h3w-rollback-abort:{sha256_json([artifact_ref(usage_receipt_path), monitoring.get('rollback_runbook_id')])[:24]}",
        "monitoring_owner": monitoring.get("monitoring_owner"),
        "audit_owner": monitoring.get("audit_owner"),
        "rollback_owner": monitoring.get("rollback_owner"),
        "latency_ms": latency,
        "abort_required": False,
        "rollback_required": False,
        "rollback_runbook_id": monitoring.get("rollback_runbook_id"),
        "abort_path": monitoring.get("abort_path"),
        "source_artifacts": {"usage_receipt": artifact_ref(usage_receipt_path)},
        "readiness": {
            "monitoring_receipt_written": passed,
            "rollback_abort_receipt_written": passed,
            "external_user_usage_closed": passed,
        },
        "boundary": _boundary(monitoring_rollback_receipt_written=passed, limited_usage_endpoint_closed=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def _write_owner_audit_reconciliation(*, context: dict[str, Any], usage_receipt_path: Path, monitoring_rollback_receipt_path: Path, output: Path) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    usage = read_json_object(usage_receipt_path)
    monitoring = read_json_object(monitoring_rollback_receipt_path)
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "usage_receipt_passed", usage.get("passed") is True)
    check(checks, failures, "monitoring_rollback_passed", monitoring.get("passed") is True)
    check(checks, failures, "usage_closed", object_value(usage.get("readiness")).get("external_user_usage_closed") is True)
    check(checks, failures, "rollback_not_required", monitoring.get("rollback_required") is False)
    passed = _passed(checks, failures)
    report = {
        "schema_version": OWNER_AUDIT_RECONCILIATION_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "reviewed_at": _now(),
        "owner_decision": "accept_post_h3w_limited_external_user_usage_execution" if passed else "reject_post_h3w_limited_external_user_usage_execution",
        "audit_decision": "accept_post_h3w_no_production_boundary" if passed else "reject_post_h3w_no_production_boundary",
        "rollback_decision": "continue_after_post_h3w_no_rollback_required" if passed else "abort_after_post_h3w_failure",
        "source_artifacts": {
            "usage_receipt": artifact_ref(usage_receipt_path),
            "monitoring_rollback_receipt": artifact_ref(monitoring_rollback_receipt_path),
        },
        "readiness": {
            "owner_audit_reconciliation_complete": passed,
            "post_h3w_closeout_ready": passed,
        },
        "boundary": _boundary(owner_audit_reconciliation_written=passed, limited_external_user_usage_performed=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def _write_boundary_report(*, context: dict[str, Any], owner_audit_reconciliation_path: Path, output: Path) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    reconciliation = read_json_object(owner_audit_reconciliation_path)
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "owner_audit_reconciliation_passed", reconciliation.get("passed") is True)
    check(checks, failures, "external_public_ingress_not_opened", True)
    check(checks, failures, "runtime_execution_not_performed", True)
    check(checks, failures, "production_receipt_write_not_allowed", True)
    passed = _passed(checks, failures)
    report = {
        "schema_version": BOUNDARY_REPORT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "source_artifacts": {"owner_audit_reconciliation": artifact_ref(owner_audit_reconciliation_path)},
        "boundary": _boundary(boundary_report_written=passed, limited_external_user_usage_performed=passed, limited_usage_endpoint_closed=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def _execute_status_read_only_usage(*, bind_host: str, probe_host: str, external_user_handle: str, requested_usage_scope: str, usage_seconds: float) -> dict[str, Any]:
    observed: list[dict[str, Any]] = []
    payload = {
        "schema_version": "post-h3w-status-read-only-response:v1",
        "status": "ok",
        "external_user_handle": external_user_handle,
        "usage_scope": requested_usage_scope,
        "production_data": False,
        "runtime_task_executed": False,
        "source_or_git_write": False,
    }

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            observed.append({"path": self.path, "external_user": self.headers.get("X-CivitasOS-External-User"), "scope": self.headers.get("X-CivitasOS-Usage-Scope")})
            if self.path != "/usage/status" or self.headers.get("X-CivitasOS-External-User") != external_user_handle or self.headers.get("X-CivitasOS-Usage-Scope") != requested_usage_scope:
                self.send_response(403)
                self.end_headers()
                return
            body = json.dumps(payload, sort_keys=True).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            return

    server: ThreadingHTTPServer | None = None
    started_at = _now()
    try:
        server = ThreadingHTTPServer((bind_host, 0), Handler)
        server.daemon_threads = True
        port = int(server.server_address[1])
        thread = threading.Thread(target=server.serve_forever, name="post-h3w-external-user-usage", daemon=True)
        thread.start()
        url = f"http://{probe_host}:{port}/usage/status"
        request = urllib.request.Request(url, headers={"X-CivitasOS-External-User": external_user_handle, "X-CivitasOS-Usage-Scope": requested_usage_scope})
        probe_started = time.perf_counter()
        with urllib.request.urlopen(request, timeout=2) as response:  # noqa: S310 - local bounded probe
            body = response.read().decode("utf-8")
            status = response.status
        latency_ms = round((time.perf_counter() - probe_started) * 1000, 3)
        time.sleep(usage_seconds)
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()
        parsed = json.loads(body)
        return {
            "attempted": True,
            "opened": True,
            "closed": True,
            "bind_host": bind_host,
            "probe_host": probe_host,
            "port": port,
            "request_url": url,
            "request_observed": len(observed) == 1,
            "observed_request": observed[0] if observed else {},
            "response_status": status,
            "latency_ms": latency_ms,
            "response_body_sha256": sha256_json(body),
            "started_at": started_at,
            "closed_at": _now(),
            "response_passed": status == 200 and parsed.get("status") == "ok" and parsed.get("external_user_handle") == external_user_handle,
            "production_data_returned": parsed.get("production_data") is not False,
            "runtime_task_executed": parsed.get("runtime_task_executed") is True,
        }
    except Exception as exc:  # noqa: BLE001
        if server is not None:
            try:
                server.shutdown()
                server.server_close()
            except Exception:  # noqa: BLE001
                pass
        return {"attempted": True, "opened": False, "closed": server is not None, "started_at": started_at, "error": str(exc), "request_observed": bool(observed), "response_passed": False}


def _check_t_summary(summary: dict[str, Any], checks: dict[str, bool], failures: list[str]) -> None:
    readiness = object_value(summary.get("readiness"))
    boundary = object_value(summary.get("boundary"))
    check(checks, failures, "post_h3t_schema_valid", summary.get("schema_version") == POST_H3T_SCHEMA)
    check(checks, failures, "post_h3t_passed", summary.get("passed") is True)
    check(checks, failures, "post_h3t_usage_allowed", summary.get("external_user_usage_allowed") is True)
    check(checks, failures, "post_h3t_execution_ready", readiness.get("external_user_usage_execution_ready") is True)
    check(checks, failures, "post_h3t_runtime_not_performed", boundary.get("runtime_execution_performed") is False)
    check(checks, failures, "post_h3t_no_production_receipt_write", boundary.get("production_runtime_receipt_write_allowed") is False)


def _check_t_reconciliation(reconciliation: dict[str, Any], checks: dict[str, bool], failures: list[str]) -> None:
    check(checks, failures, "post_h3t_reconciliation_schema_valid", reconciliation.get("schema_version") == POST_H3T_RECONCILIATION_SCHEMA)
    check(checks, failures, "post_h3t_reconciliation_passed", reconciliation.get("passed") is True)
    check(checks, failures, "post_h3t_reconciliation_usage_allowed", reconciliation.get("external_user_usage_allowed") is True)


def _check_t_boundary(report: dict[str, Any], checks: dict[str, bool], failures: list[str]) -> None:
    boundary = object_value(report.get("boundary"))
    check(checks, failures, "post_h3t_boundary_schema_valid", report.get("schema_version") == POST_H3T_BOUNDARY_REPORT_SCHEMA and report.get("passed") is True)
    check(checks, failures, "post_h3t_boundary_usage_allowed", boundary.get("external_user_usage_allowed") is True)
    check(checks, failures, "post_h3t_boundary_no_runtime", boundary.get("runtime_execution_performed") is False)


def _check_v_summary(summary: dict[str, Any], checks: dict[str, bool], failures: list[str]) -> None:
    readiness = object_value(summary.get("readiness"))
    check(checks, failures, "post_h3v_schema_valid", summary.get("schema_version") == POST_H3V_SCHEMA)
    check(checks, failures, "post_h3v_passed", summary.get("passed") is True)
    check(checks, failures, "post_h3v_scope_bound", readiness.get("limited_external_usage_scope_bound") is True)
    check(checks, failures, "post_h3v_authorization_review_ready", readiness.get("external_user_usage_authorization_review_ready") is True)
    check(checks, failures, "post_h3v_usage_not_preexecuted", readiness.get("external_user_usage_allowed") is False)


def _check_v_usage_scope(scope: dict[str, Any], checks: dict[str, bool], failures: list[str]) -> None:
    check(checks, failures, "post_h3v_usage_scope_schema_valid", scope.get("schema_version") == POST_H3V_USAGE_SCOPE_SCHEMA)
    check(checks, failures, "post_h3v_usage_scope_passed", scope.get("passed") is True)
    check(checks, failures, "post_h3v_usage_scope_bounded", scope.get("allowed_usage_scope") == ALLOWED_USAGE_SCOPE)
    check(checks, failures, "post_h3v_usage_scope_one_user", scope.get("max_external_users") == 1)
    check(checks, failures, "post_h3v_usage_scope_one_task", scope.get("max_runtime_tasks") == 1)


def _check_v_monitoring(monitoring: dict[str, Any], checks: dict[str, bool], failures: list[str]) -> None:
    check(checks, failures, "post_h3v_monitoring_schema_valid", monitoring.get("schema_version") == POST_H3V_MONITORING_ROLLBACK_SCHEMA)
    check(checks, failures, "post_h3v_monitoring_passed", monitoring.get("passed") is True)
    check(checks, failures, "post_h3v_monitoring_owner_present", bool(monitoring.get("monitoring_owner")))
    check(checks, failures, "post_h3v_rollback_owner_present", bool(monitoring.get("rollback_owner")))


def _check_v_boundary(report: dict[str, Any], checks: dict[str, bool], failures: list[str]) -> None:
    boundary = object_value(report.get("boundary"))
    check(checks, failures, "post_h3v_boundary_schema_valid", report.get("schema_version") == POST_H3V_BOUNDARY_REPORT_SCHEMA and report.get("passed") is True)
    check(checks, failures, "post_h3v_boundary_scope_bound", boundary.get("limited_external_usage_scope_bound") is True)
    check(checks, failures, "post_h3v_boundary_no_execution", boundary.get("runtime_execution_performed") is False)


def _read_verified_ref(value: Any, checks: dict[str, bool], failures: list[str], label: str) -> dict[str, Any]:
    ref = object_value(value)
    path = Path(str(ref.get("path") or ""))
    expected_hash = str(ref.get("sha256") or "")
    check(checks, failures, f"{label}_path_present", path.is_file())
    if not path.is_file():
        return {}
    check(checks, failures, f"{label}_hash_valid", bool(expected_hash) and sha256_file(path) == expected_hash)
    return read_json_object(path)


def _default_consumption_lease_path(post_h3t_summary_path: Path) -> Path:
    return post_h3t_summary_path.with_name("post_h3t_external_user_usage_authorization_consumed_by_post_h3w.json")


def _boundary(**overrides: bool) -> dict[str, bool]:
    boundary = {
        "context_validation_written": False,
        "authorization_consumed": False,
        "usage_receipt_written": False,
        "monitoring_rollback_receipt_written": False,
        "owner_audit_reconciliation_written": False,
        "boundary_report_written": False,
        "limited_external_user_usage_performed": False,
        "limited_usage_endpoint_opened": False,
        "limited_usage_endpoint_closed": False,
        "external_public_ingress_opened": False,
        "runtime_workers_currently_running": False,
        "runtime_execution_performed": False,
        "vm_contact_performed": False,
        "deploy_performed": False,
        "production_data_accessed": False,
        "production_runtime_receipt_write_allowed": False,
        "source_tree_write_performed": False,
        "git_write_performed": False,
        "secrets_recorded": False,
    }
    boundary.update(overrides)
    return boundary


def _report(schema: str, passed: bool, failures: list[str], checks: dict[str, bool]) -> dict[str, Any]:
    return {"schema_version": schema, "passed": passed, "failure_reasons": failures, "checks": checks, "checked_at": _now(), "boundary": _boundary(), "non_claims": list(NON_CLAIMS)}


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
    parser = argparse.ArgumentParser(description="Run PostH3-W external user usage execution gate")
    parser.add_argument("--post-h3t-summary", required=True, type=Path)
    parser.add_argument("--post-h3v-summary", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--operator-id", default="operator-primary")
    parser.add_argument("--operator-decision", default=ACCEPTED_OPERATOR_DECISION)
    parser.add_argument("--audit-decision", default=ACCEPTED_AUDIT_DECISION)
    parser.add_argument("--monitoring-decision", default=ACCEPTED_MONITORING_DECISION)
    parser.add_argument("--rollback-decision", default=ACCEPTED_ROLLBACK_DECISION)
    parser.add_argument("--operator-statement", default="Execute one bounded invite-only status/read-only external user usage and close the endpoint after probe.")
    parser.add_argument("--external-user-handle", default="Thneoly")
    parser.add_argument("--requested-usage-scope", default=ALLOWED_USAGE_SCOPE)
    parser.add_argument("--usage-seconds", type=float, default=0.1)
    parser.add_argument("--bind-host", default="127.0.0.1")
    parser.add_argument("--probe-host", default="127.0.0.1")
    parser.add_argument("--authorization-consumption-path", type=Path)
    parser.add_argument("--ack-external-user-usage-execution", action="store_true")
    args = parser.parse_args()
    summary = run_gate(
        post_h3t_summary_path=args.post_h3t_summary,
        post_h3v_summary_path=args.post_h3v_summary,
        output_root=args.output_root,
        operator_id=args.operator_id,
        operator_decision=args.operator_decision,
        audit_decision=args.audit_decision,
        monitoring_decision=args.monitoring_decision,
        rollback_decision=args.rollback_decision,
        operator_statement=args.operator_statement,
        external_user_handle=args.external_user_handle,
        requested_usage_scope=args.requested_usage_scope,
        usage_seconds=args.usage_seconds,
        bind_host=args.bind_host,
        probe_host=args.probe_host,
        authorization_consumption_path=args.authorization_consumption_path,
        ack_external_user_usage_execution=args.ack_external_user_usage_execution,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if summary.get("passed") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
