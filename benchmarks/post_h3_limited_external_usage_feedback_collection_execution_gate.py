"""Execute one PostH3 limited external-usage feedback collection.

This gate consumes a single-use authorization receipt produced by
``post_h3_limited_external_usage_feedback_authorization_decision_gate`` and
records one operator-supplied feedback-only payload. It writes authorization
consumption, feedback, monitoring, rollback/abort, owner/audit reconciliation,
and boundary receipts. It does not execute external usage, runtime work, public
ingress, deploy, production data access, production runtime receipt writes, or
source/Git writes.
"""

from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from benchmarks.i_gate_evidence import artifact_ref, check, object_value, read_json_object, sha256_file, sha256_json, write_json_object
from benchmarks.post_h3_limited_external_usage_feedback_authorization_decision_gate import (
    AUTHORIZATION_RECEIPT_SCHEMA,
    CHAIN_SCHEMA as DECISION_CHAIN_SCHEMA,
)
from benchmarks.post_h3_limited_external_usage_feedback_authorization_request_gate import (
    AUTHORIZATION_DOMAIN,
    DEFAULT_FEEDBACK_SCOPE,
    EXECUTION_GATE_AFTER_AUTHORIZATION,
)

CHAIN_SCHEMA = "post-h3-limited-external-usage-feedback-collection-execution-gate:v1"
CONTEXT_SCHEMA = "post-h3-limited-feedback-collection-execution-context:v1"
AUTHORIZATION_CONSUMPTION_SCHEMA = "post-h3-limited-feedback-authorization-consumption:v1"
FEEDBACK_RECEIPT_SCHEMA = "post-h3-limited-feedback-execution-receipt:v1"
MONITORING_ROLLBACK_RECEIPT_SCHEMA = "post-h3-limited-feedback-monitoring-rollback-receipt:v1"
OWNER_AUDIT_RECONCILIATION_SCHEMA = "post-h3-limited-feedback-owner-audit-reconciliation:v1"
BOUNDARY_REPORT_SCHEMA = "post-h3-limited-feedback-collection-execution-boundary:v1"

ACCEPTED_OPERATOR_DECISION = "collect_limited_external_usage_feedback_once"
ACCEPTED_AUDIT_DECISION = "accept_limited_feedback_execution_no_production_boundary"
ACCEPTED_MONITORING_DECISION = "accept_limited_feedback_execution_monitoring_receipt"
ACCEPTED_ROLLBACK_DECISION = "accept_limited_feedback_execution_no_rollback_required"
DEFAULT_OPERATOR_STATEMENT = "Consume one limited-feedback authorization receipt and collect one feedback-only record; no external usage execution."
DEFAULT_FEEDBACK_TEXT = "External user feedback: continue with bounded feedback-only collection before any further external usage expansion."
FORBIDDEN_FEEDBACK_TOKENS = ("sk-", "BEGIN PRIVATE KEY", "password=", "api_key", "secret=")
NON_CLAIMS = (
    "limited_feedback_execution_collects_one_feedback_record_only",
    "limited_feedback_execution_consumes_single_use_authorization",
    "limited_feedback_execution_does_not_execute_external_usage",
    "limited_feedback_execution_does_not_open_public_ingress",
    "limited_feedback_execution_does_not_start_runtime_workers",
    "limited_feedback_execution_does_not_execute_runtime_task",
    "limited_feedback_execution_does_not_contact_vm_targets",
    "limited_feedback_execution_does_not_deploy",
    "limited_feedback_execution_does_not_access_production_data",
    "limited_feedback_execution_does_not_write_production_runtime_receipts",
    "limited_feedback_execution_does_not_write_source_or_git",
)


def run_gate(
    *,
    limited_feedback_authorization_decision_summary_path: Path,
    output_root: Path,
    operator_id: str = "operator-primary",
    operator_decision: str = ACCEPTED_OPERATOR_DECISION,
    audit_decision: str = ACCEPTED_AUDIT_DECISION,
    monitoring_decision: str = ACCEPTED_MONITORING_DECISION,
    rollback_decision: str = ACCEPTED_ROLLBACK_DECISION,
    operator_statement: str = DEFAULT_OPERATOR_STATEMENT,
    external_user_handle: str = "Thneoly",
    feedback_scope: str = DEFAULT_FEEDBACK_SCOPE,
    feedback_text: str = DEFAULT_FEEDBACK_TEXT,
    feedback_source: str = "operator_supplied_external_user_feedback",
    authorization_consumption_path: Path | None = None,
    ack_feedback_collection: bool = False,
) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "context_validation": output_root / "post_h3_limited_feedback_execution_context.json",
        "authorization_consumption": output_root / "post_h3_limited_feedback_authorization_consumption.json",
        "feedback_receipt": output_root / "post_h3_limited_feedback_execution_receipt.json",
        "monitoring_rollback_receipt": output_root / "post_h3_limited_feedback_monitoring_rollback_receipt.json",
        "owner_audit_reconciliation": output_root / "post_h3_limited_feedback_owner_audit_reconciliation.json",
        "boundary_report": output_root / "post_h3_limited_feedback_execution_boundary_report.json",
        "summary": output_root / "post_h3_limited_feedback_collection_execution_summary.json",
    }
    context = _validate_context(decision_summary_path=limited_feedback_authorization_decision_summary_path, output=artifacts["context_validation"])
    try:
        consumption = _write_authorization_consumption(
            context=context,
            decision_summary_path=limited_feedback_authorization_decision_summary_path,
            output=artifacts["authorization_consumption"],
            lease_path=authorization_consumption_path or _default_consumption_lease_path(context, limited_feedback_authorization_decision_summary_path),
            operator_id=operator_id,
            operator_decision=operator_decision,
            audit_decision=audit_decision,
            monitoring_decision=monitoring_decision,
            rollback_decision=rollback_decision,
            operator_statement=operator_statement,
            ack_feedback_collection=ack_feedback_collection,
        )
    except RuntimeError as exc:
        consumption = _write_blocked_consumption(output=artifacts["authorization_consumption"], context=context, error=str(exc))
    feedback = _write_feedback_receipt(
        context=context,
        consumption_path=artifacts["authorization_consumption"],
        output=artifacts["feedback_receipt"],
        external_user_handle=external_user_handle,
        feedback_scope=feedback_scope,
        feedback_text=feedback_text,
        feedback_source=feedback_source,
    )
    monitoring = _write_monitoring_rollback_receipt(feedback_receipt_path=artifacts["feedback_receipt"], output=artifacts["monitoring_rollback_receipt"])
    reconciliation = _write_owner_audit_reconciliation(
        feedback_receipt_path=artifacts["feedback_receipt"],
        monitoring_rollback_receipt_path=artifacts["monitoring_rollback_receipt"],
        output=artifacts["owner_audit_reconciliation"],
    )
    boundary = _write_boundary_report(context=context, reconciliation_path=artifacts["owner_audit_reconciliation"], output=artifacts["boundary_report"])
    reports = [context, consumption, feedback, monitoring, reconciliation, boundary]
    passed = all(report.get("passed") is True for report in reports)
    summary = {
        "schema_version": CHAIN_SCHEMA,
        "passed": passed,
        "failure_reasons": _failures(reports),
        "checked_at": _now(),
        "source_artifacts": {"limited_feedback_authorization_decision_summary": artifact_ref(limited_feedback_authorization_decision_summary_path)},
        "artifacts": {name: artifact_ref(path) for name, path in artifacts.items() if name != "summary"},
        "authorization_id": object_value(context.get("authorization_receipt")).get("authorization_id"),
        "authorization_request_id": object_value(context.get("authorization_receipt")).get("authorization_request_id"),
        "external_user_feedback_collection_id": feedback.get("external_user_feedback_collection_id"),
        "external_user_feedback_receipt_id": feedback.get("external_user_feedback_receipt_id"),
        "monitoring_receipt_id": monitoring.get("monitoring_receipt_id"),
        "rollback_abort_receipt_id": monitoring.get("rollback_abort_receipt_id"),
        "readiness": {
            "state": "limited_external_usage_feedback_collection_complete" if passed else "blocked_limited_external_usage_feedback_collection_execution",
            "limited_external_usage_feedback_collection_complete": passed,
            "feedback_authorization_consumed": consumption.get("passed") is True,
            "feedback_receipt_written": feedback.get("passed") is True,
            "monitoring_receipt_written": monitoring.get("passed") is True,
            "rollback_abort_receipt_written": monitoring.get("passed") is True,
            "owner_audit_reconciliation_complete": reconciliation.get("passed") is True,
            "external_user_feedback_collection_allowed": False,
            "feedback_collection_execution_ready": False,
            "external_user_usage_allowed": False,
            "external_public_ingress_opened": False,
            "runtime_execution_performed": False,
            "production_runtime_receipt_write_allowed": False,
        },
        "boundary": _boundary(
            context_validation_written=context.get("passed") is True,
            authorization_consumed=consumption.get("passed") is True,
            feedback_receipt_written=feedback.get("passed") is True,
            monitoring_rollback_receipt_written=monitoring.get("passed") is True,
            owner_audit_reconciliation_written=reconciliation.get("passed") is True,
            boundary_report_written=boundary.get("passed") is True,
            external_user_feedback_collected=passed,
        ),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(artifacts["summary"], summary)
    return summary


def _validate_context(*, decision_summary_path: Path, output: Path) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    decision_summary = _read_json_or_empty(decision_summary_path, failures, "limited_feedback_authorization_decision_summary")
    artifacts = object_value(decision_summary.get("artifacts"))
    receipt = _read_verified_ref(artifacts.get("authorization_receipt"), checks, failures, "authorization_receipt")
    boundary_report = _read_verified_ref(artifacts.get("boundary_report"), checks, failures, "decision_boundary_report")
    readiness = object_value(decision_summary.get("readiness"))
    receipt_readiness = object_value(receipt.get("readiness"))
    scope = object_value(receipt.get("authorization_scope"))
    boundary = object_value(decision_summary.get("boundary"))
    expires_at = _parse_datetime(receipt.get("expires_at"))
    now = datetime.now(timezone.utc)

    check(checks, failures, "decision_summary_schema", decision_summary.get("schema_version") == DECISION_CHAIN_SCHEMA)
    check(checks, failures, "decision_summary_passed", decision_summary.get("passed") is True)
    check(checks, failures, "receipt_schema", receipt.get("schema_version") == AUTHORIZATION_RECEIPT_SCHEMA and receipt.get("passed") is True)
    check(checks, failures, "authorization_domain", decision_summary.get("authorization_domain") == AUTHORIZATION_DOMAIN and receipt.get("authorization_domain") == AUTHORIZATION_DOMAIN)
    check(checks, failures, "authorization_granted", decision_summary.get("authorization_granted") is True and receipt.get("authorization_granted") is True)
    check(checks, failures, "receipt_single_use", receipt.get("single_use") is True)
    check(checks, failures, "receipt_not_consumed", receipt.get("consumed") is False)
    check(checks, failures, "receipt_consumption_target", receipt.get("consumption_required_by") == EXECUTION_GATE_AFTER_AUTHORIZATION)
    check(checks, failures, "receipt_currently_valid", expires_at is not None and expires_at > now)
    check(checks, failures, "feedback_allowed_by_authorization", readiness.get("external_user_feedback_collection_allowed") is True and receipt_readiness.get("external_user_feedback_collection_allowed") is True)
    check(checks, failures, "feedback_execution_ready", readiness.get("feedback_collection_execution_ready") is True and receipt_readiness.get("feedback_collection_execution_ready") is True)
    check(checks, failures, "feedback_not_already_performed", readiness.get("feedback_collection_performed") is False)
    check(checks, failures, "scope_collects_one_feedback", scope.get("collect_one_external_user_feedback_record") is True)
    check(checks, failures, "scope_feedback_only", scope.get("requested_feedback_scope") == DEFAULT_FEEDBACK_SCOPE)
    check(checks, failures, "scope_max_one_external_user", scope.get("max_external_users") == 1)
    check(checks, failures, "scope_no_external_usage", scope.get("external_user_usage_allowed") is False)
    check(checks, failures, "scope_no_public_ingress", scope.get("public_ingress_authorized") is False)
    check(checks, failures, "scope_no_runtime_expansion", scope.get("runtime_expansion_authorized") is False)
    check(checks, failures, "scope_no_production_receipt_write", scope.get("production_runtime_receipt_write_allowed") is False)
    check(checks, failures, "boundary_no_side_effects", _no_side_effect_boundary(boundary))
    check(checks, failures, "decision_boundary_report_passed", boundary_report.get("passed") is True)
    passed = _passed(checks, failures)
    report = {
        "schema_version": CONTEXT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "decision_summary": decision_summary,
        "authorization_receipt": receipt,
        "decision_boundary_report": boundary_report,
        "source_artifacts": {"limited_feedback_authorization_decision_summary": artifact_ref(decision_summary_path)},
        "boundary": _boundary(context_validation_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def _write_authorization_consumption(
    *,
    context: dict[str, Any],
    decision_summary_path: Path,
    output: Path,
    lease_path: Path,
    operator_id: str,
    operator_decision: str,
    audit_decision: str,
    monitoring_decision: str,
    rollback_decision: str,
    operator_statement: str,
    ack_feedback_collection: bool,
) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    receipt = object_value(context.get("authorization_receipt"))
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "operator_id_present", bool(operator_id.strip()))
    check(checks, failures, "operator_decision_accepted", operator_decision == ACCEPTED_OPERATOR_DECISION)
    check(checks, failures, "audit_decision_accepted", audit_decision == ACCEPTED_AUDIT_DECISION)
    check(checks, failures, "monitoring_decision_accepted", monitoring_decision == ACCEPTED_MONITORING_DECISION)
    check(checks, failures, "rollback_decision_accepted", rollback_decision == ACCEPTED_ROLLBACK_DECISION)
    check(checks, failures, "operator_statement_present", bool(operator_statement.strip()))
    check(checks, failures, "explicit_operator_ack", ack_feedback_collection is True)
    if not _passed(checks, failures):
        return _write_consumption_report(
            output=output,
            passed=False,
            failures=failures,
            checks=checks,
            lease_path=lease_path,
            decision_summary_path=decision_summary_path,
            receipt=receipt,
            operator_id=operator_id,
            operator_decision=operator_decision,
            audit_decision=audit_decision,
            monitoring_decision=monitoring_decision,
            rollback_decision=rollback_decision,
            operator_statement=operator_statement,
            ack_feedback_collection=ack_feedback_collection,
        )

    lease = {
        "schema_version": "post-h3-limited-feedback-authorization-consumption-lease:v1",
        "consumed_at": _now(),
        "authorization_id": receipt.get("authorization_id"),
        "authorization_request_id": receipt.get("authorization_request_id"),
        "decision_summary": artifact_ref(decision_summary_path),
        "operator_id": operator_id,
    }
    lease_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(lease_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise RuntimeError(f"limited_feedback_authorization_already_consumed:{lease_path}") from exc
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
        decision_summary_path=decision_summary_path,
        receipt=receipt,
        operator_id=operator_id,
        operator_decision=operator_decision,
        audit_decision=audit_decision,
        monitoring_decision=monitoring_decision,
        rollback_decision=rollback_decision,
        operator_statement=operator_statement,
        ack_feedback_collection=ack_feedback_collection,
    )


def _write_consumption_report(
    *,
    output: Path,
    passed: bool,
    failures: list[str],
    checks: dict[str, bool],
    lease_path: Path,
    decision_summary_path: Path,
    receipt: dict[str, Any],
    operator_id: str,
    operator_decision: str,
    audit_decision: str,
    monitoring_decision: str,
    rollback_decision: str,
    operator_statement: str,
    ack_feedback_collection: bool,
) -> dict[str, Any]:
    report = {
        "schema_version": AUTHORIZATION_CONSUMPTION_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "consumed_at": _now(),
        "authorization_id": receipt.get("authorization_id"),
        "authorization_request_id": receipt.get("authorization_request_id"),
        "single_use_consumption": passed,
        "lease_path": str(lease_path.resolve()),
        "operator_id": operator_id,
        "operator_decision": operator_decision,
        "audit_decision": audit_decision,
        "monitoring_decision": monitoring_decision,
        "rollback_decision": rollback_decision,
        "operator_statement": operator_statement,
        "operator_statement_sha256": sha256_json(operator_statement),
        "ack_feedback_collection": ack_feedback_collection,
        "source_artifacts": {"limited_feedback_authorization_decision_summary": artifact_ref(decision_summary_path)},
        "boundary": _boundary(authorization_consumed=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def _write_blocked_consumption(*, output: Path, context: dict[str, Any], error: str) -> dict[str, Any]:
    report = {
        "schema_version": AUTHORIZATION_CONSUMPTION_SCHEMA,
        "passed": False,
        "failure_reasons": [error],
        "checks": {"authorization_not_previously_consumed": False},
        "consumed_at": _now(),
        "authorization_id": object_value(context.get("authorization_receipt")).get("authorization_id"),
        "single_use_consumption": False,
        "source_artifacts": object_value(context.get("source_artifacts")),
        "boundary": _boundary(),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def _write_feedback_receipt(
    *,
    context: dict[str, Any],
    consumption_path: Path,
    output: Path,
    external_user_handle: str,
    feedback_scope: str,
    feedback_text: str,
    feedback_source: str,
) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    consumption = read_json_object(consumption_path)
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "authorization_consumed", consumption.get("passed") is True)
    check(checks, failures, "external_user_handle_present", bool(external_user_handle.strip()))
    check(checks, failures, "feedback_scope_bounded", feedback_scope == DEFAULT_FEEDBACK_SCOPE)
    check(checks, failures, "feedback_text_present", bool(feedback_text.strip()) and len(feedback_text.strip()) >= 12)
    check(checks, failures, "feedback_source_present", bool(feedback_source.strip()))
    check(checks, failures, "feedback_has_no_forbidden_tokens", not _contains_forbidden_token(feedback_text))
    passed = _passed(checks, failures)
    receipt = {
        "schema_version": FEEDBACK_RECEIPT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "written_at": _now(),
        "external_user_feedback_collection_id": f"post-h3-limited-feedback-collection:{sha256_json([artifact_ref(consumption_path), external_user_handle, feedback_scope, feedback_text])[:24]}",
        "external_user_feedback_receipt_id": f"post-h3-limited-feedback-receipt:{sha256_json([artifact_ref(consumption_path), feedback_source, feedback_text])[:24]}",
        "external_user_handle": external_user_handle,
        "feedback_scope": feedback_scope,
        "feedback_source": feedback_source,
        "feedback_text": feedback_text,
        "feedback_text_sha256": sha256_json(feedback_text),
        "source_artifacts": {"authorization_consumption": artifact_ref(consumption_path)},
        "readiness": {
            "external_user_feedback_collected": passed,
            "external_user_feedback_collection_closed": passed,
            "external_user_usage_allowed": False,
            "runtime_execution_performed": False,
            "production_runtime_receipt_write_allowed": False,
        },
        "boundary": _boundary(
            authorization_consumed=consumption.get("passed") is True,
            feedback_receipt_written=passed,
            external_user_feedback_collected=passed,
        ),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, receipt)
    return receipt


def _write_monitoring_rollback_receipt(*, feedback_receipt_path: Path, output: Path) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    feedback = read_json_object(feedback_receipt_path)
    check(checks, failures, "feedback_receipt_passed", feedback.get("passed") is True)
    check(checks, failures, "feedback_collected", object_value(feedback.get("readiness")).get("external_user_feedback_collected") is True)
    passed = _passed(checks, failures)
    report = {
        "schema_version": MONITORING_ROLLBACK_RECEIPT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "written_at": _now(),
        "monitoring_receipt_id": f"post-h3-limited-feedback-monitoring:{sha256_json([artifact_ref(feedback_receipt_path), 'feedback-only'])[:24]}",
        "rollback_abort_receipt_id": f"post-h3-limited-feedback-rollback-abort:{sha256_json([artifact_ref(feedback_receipt_path), 'no-rollback-required'])[:24]}",
        "monitoring_owner": "monitoring_owner",
        "audit_owner": "audit_owner",
        "rollback_owner": "rollback_owner",
        "abort_required": False,
        "rollback_required": False,
        "source_artifacts": {"feedback_receipt": artifact_ref(feedback_receipt_path)},
        "readiness": {
            "monitoring_receipt_written": passed,
            "rollback_abort_receipt_written": passed,
            "external_user_feedback_collection_closed": passed,
        },
        "boundary": _boundary(monitoring_rollback_receipt_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def _write_owner_audit_reconciliation(*, feedback_receipt_path: Path, monitoring_rollback_receipt_path: Path, output: Path) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    feedback = read_json_object(feedback_receipt_path)
    monitoring = read_json_object(monitoring_rollback_receipt_path)
    check(checks, failures, "feedback_receipt_passed", feedback.get("passed") is True)
    check(checks, failures, "monitoring_rollback_passed", monitoring.get("passed") is True)
    check(checks, failures, "rollback_not_required", monitoring.get("rollback_required") is False)
    passed = _passed(checks, failures)
    report = {
        "schema_version": OWNER_AUDIT_RECONCILIATION_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "reviewed_at": _now(),
        "owner_decision": "accept_limited_feedback_collection" if passed else "reject_limited_feedback_collection",
        "audit_decision": "accept_limited_feedback_no_production_boundary" if passed else "reject_limited_feedback_no_production_boundary",
        "rollback_decision": "continue_after_limited_feedback_no_rollback_required" if passed else "abort_after_limited_feedback_failure",
        "source_artifacts": {
            "feedback_receipt": artifact_ref(feedback_receipt_path),
            "monitoring_rollback_receipt": artifact_ref(monitoring_rollback_receipt_path),
        },
        "readiness": {
            "owner_audit_reconciliation_complete": passed,
            "external_user_feedback_collection_closed": passed,
        },
        "boundary": _boundary(owner_audit_reconciliation_written=passed, external_user_feedback_collected=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def _write_boundary_report(*, context: dict[str, Any], reconciliation_path: Path, output: Path) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    reconciliation = read_json_object(reconciliation_path)
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "owner_audit_reconciliation_passed", reconciliation.get("passed") is True)
    check(checks, failures, "external_user_usage_not_executed", True)
    check(checks, failures, "public_ingress_not_opened", True)
    check(checks, failures, "runtime_execution_not_performed", True)
    check(checks, failures, "production_receipt_write_not_allowed", True)
    passed = _passed(checks, failures)
    report = {
        "schema_version": BOUNDARY_REPORT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "source_artifacts": {"owner_audit_reconciliation": artifact_ref(reconciliation_path)},
        "boundary": _boundary(boundary_report_written=passed, external_user_feedback_collected=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def _no_side_effect_boundary(boundary: dict[str, Any]) -> bool:
    for key in (
        "feedback_collection_performed",
        "external_user_usage_allowed",
        "public_ingress_authorized",
        "runtime_expansion_authorized",
        "external_public_ingress_opened",
        "runtime_execution_performed",
        "runtime_workers_currently_running",
        "backend_task_pool_mutation_performed",
        "vm_contact_performed",
        "deploy_performed",
        "production_data_accessed",
        "production_runtime_receipt_write_allowed",
        "production_runtime_receipt_written",
        "source_tree_write_performed",
        "git_write_performed",
        "secrets_recorded",
    ):
        if boundary.get(key) is not False:
            return False
    return True


def _default_consumption_lease_path(context: dict[str, Any], decision_summary_path: Path) -> Path:
    authorization_id = str(object_value(context.get("authorization_receipt")).get("authorization_id") or "unknown").replace(":", "_")
    return decision_summary_path.with_name(f"{authorization_id}_consumed_by_limited_feedback_execution.json")


def _contains_forbidden_token(value: str) -> bool:
    lowered = value.lower()
    return any(token.lower() in lowered for token in FORBIDDEN_FEEDBACK_TOKENS)


def _parse_datetime(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _boundary(**overrides: bool) -> dict[str, bool]:
    boundary = {
        "context_validation_written": False,
        "authorization_consumed": False,
        "feedback_receipt_written": False,
        "monitoring_rollback_receipt_written": False,
        "owner_audit_reconciliation_written": False,
        "boundary_report_written": False,
        "external_user_feedback_collected": False,
        "external_user_usage_performed": False,
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


def _read_json_or_empty(path: Path, failures: list[str], label: str) -> dict[str, Any]:
    try:
        return read_json_object(path)
    except Exception as exc:  # noqa: BLE001
        failures.append(f"{label}_unreadable:{exc}")
        return {}


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
    parser.add_argument("--limited-feedback-authorization-decision-summary", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--operator-id", default="operator-primary")
    parser.add_argument("--operator-decision", default=ACCEPTED_OPERATOR_DECISION)
    parser.add_argument("--audit-decision", default=ACCEPTED_AUDIT_DECISION)
    parser.add_argument("--monitoring-decision", default=ACCEPTED_MONITORING_DECISION)
    parser.add_argument("--rollback-decision", default=ACCEPTED_ROLLBACK_DECISION)
    parser.add_argument("--operator-statement", default=DEFAULT_OPERATOR_STATEMENT)
    parser.add_argument("--external-user-handle", default="Thneoly")
    parser.add_argument("--feedback-scope", default=DEFAULT_FEEDBACK_SCOPE)
    parser.add_argument("--feedback-text", default=DEFAULT_FEEDBACK_TEXT)
    parser.add_argument("--feedback-source", default="operator_supplied_external_user_feedback")
    parser.add_argument("--authorization-consumption-path", type=Path)
    parser.add_argument("--ack-feedback-collection", action="store_true")
    args = parser.parse_args(argv)
    summary = run_gate(
        limited_feedback_authorization_decision_summary_path=args.limited_feedback_authorization_decision_summary,
        output_root=args.output_root,
        operator_id=args.operator_id,
        operator_decision=args.operator_decision,
        audit_decision=args.audit_decision,
        monitoring_decision=args.monitoring_decision,
        rollback_decision=args.rollback_decision,
        operator_statement=args.operator_statement,
        external_user_handle=args.external_user_handle,
        feedback_scope=args.feedback_scope,
        feedback_text=args.feedback_text,
        feedback_source=args.feedback_source,
        authorization_consumption_path=args.authorization_consumption_path,
        ack_feedback_collection=args.ack_feedback_collection,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if summary.get("passed") is True else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
