"""Collect one bounded PostH3 external-user feedback record.

PostH3-Z consumes a PostH3-Y feedback-only authorization. It records one
operator-supplied external-user feedback payload and writes monitoring,
rollback/abort, owner/audit reconciliation, and boundary receipts. It does not
perform another usage action, open public ingress, start runtime workers,
execute runtime tasks, contact VMs, deploy, access production data, write
production runtime receipts, or write source/Git state.
"""

from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from benchmarks.i_gate_evidence import artifact_ref, check, object_value, read_json_object, sha256_file, sha256_json, write_json_object
from benchmarks.post_h3_next_external_usage_review_gate import (
    BOUNDARY_REPORT_SCHEMA as POST_H3Y_BOUNDARY_REPORT_SCHEMA,
    CHAIN_SCHEMA as POST_H3Y_SCHEMA,
    FEEDBACK_ONLY_SCOPE,
    REVIEW_RECONCILIATION_SCHEMA as POST_H3Y_REVIEW_RECONCILIATION_SCHEMA,
)

CHAIN_SCHEMA = "post-h3-external-user-feedback-collection-chain:v1"
CONTEXT_SCHEMA = "post-h3z-post-h3y-context-validation:v1"
AUTHORIZATION_CONSUMPTION_SCHEMA = "post-h3z-feedback-collection-authorization-consumption:v1"
FEEDBACK_RECEIPT_SCHEMA = "post-h3z-external-user-feedback-receipt:v1"
MONITORING_ROLLBACK_RECEIPT_SCHEMA = "post-h3z-feedback-monitoring-rollback-receipt:v1"
OWNER_AUDIT_RECONCILIATION_SCHEMA = "post-h3z-feedback-owner-audit-reconciliation:v1"
BOUNDARY_REPORT_SCHEMA = "post-h3z-feedback-collection-boundary-report:v1"

ACCEPTED_OPERATOR_DECISION = "collect_external_user_feedback_once"
ACCEPTED_AUDIT_DECISION = "accept_external_user_feedback_no_production_boundary"
ACCEPTED_MONITORING_DECISION = "accept_external_user_feedback_monitoring_receipt"
ACCEPTED_ROLLBACK_DECISION = "accept_external_user_feedback_no_rollback_required"
FORBIDDEN_FEEDBACK_TOKENS = ("sk-", "BEGIN PRIVATE KEY", "password=", "api_key", "secret=")
NON_CLAIMS = (
    "post_h3z_collects_one_feedback_record_only",
    "post_h3z_does_not_execute_external_user_usage",
    "post_h3z_does_not_open_public_ingress",
    "post_h3z_does_not_start_runtime_workers",
    "post_h3z_does_not_execute_runtime_task",
    "post_h3z_does_not_contact_vm_targets",
    "post_h3z_does_not_deploy",
    "post_h3z_does_not_access_production_data",
    "post_h3z_does_not_write_production_runtime_receipts",
    "post_h3z_does_not_write_source_or_git",
)


def run_gate(
    *,
    post_h3y_summary_path: Path,
    output_root: Path,
    operator_id: str = "operator-primary",
    operator_decision: str = ACCEPTED_OPERATOR_DECISION,
    audit_decision: str = ACCEPTED_AUDIT_DECISION,
    monitoring_decision: str = ACCEPTED_MONITORING_DECISION,
    rollback_decision: str = ACCEPTED_ROLLBACK_DECISION,
    operator_statement: str = "Collect one feedback-only record after PostH3-Y authorization; no second usage execution.",
    external_user_handle: str = "Thneoly",
    feedback_scope: str = FEEDBACK_ONLY_SCOPE,
    feedback_text: str = "External user prefers feedback-only collection before any second limited usage.",
    feedback_source: str = "operator_supplied_external_user_feedback",
    authorization_consumption_path: Path | None = None,
    ack_feedback_collection: bool = False,
) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "context_validation": output_root / "post_h3z_post_h3y_context_validation.json",
        "authorization_consumption": output_root / "post_h3z_feedback_collection_authorization_consumption.json",
        "feedback_receipt": output_root / "post_h3z_external_user_feedback_receipt.json",
        "monitoring_rollback_receipt": output_root / "post_h3z_feedback_monitoring_rollback_receipt.json",
        "owner_audit_reconciliation": output_root / "post_h3z_feedback_owner_audit_reconciliation.json",
        "boundary_report": output_root / "post_h3z_feedback_collection_boundary_report.json",
        "summary": output_root / "post_h3z_external_user_feedback_collection_summary.json",
    }
    context = validate_post_h3y_context(post_h3y_summary_path, output=artifacts["context_validation"])
    try:
        consumption = _write_authorization_consumption(
            context=context,
            post_h3y_summary_path=post_h3y_summary_path,
            output=artifacts["authorization_consumption"],
            lease_path=authorization_consumption_path or _default_consumption_lease_path(post_h3y_summary_path),
            operator_id=operator_id,
            operator_decision=operator_decision,
            audit_decision=audit_decision,
            monitoring_decision=monitoring_decision,
            rollback_decision=rollback_decision,
            operator_statement=operator_statement,
            ack_feedback_collection=ack_feedback_collection,
        )
    except RuntimeError as exc:
        consumption = _write_blocked_consumption(output=artifacts["authorization_consumption"], post_h3y_summary_path=post_h3y_summary_path, error=str(exc))
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
        "source_artifacts": {"post_h3y_summary": artifact_ref(post_h3y_summary_path)},
        "artifacts": {name: artifact_ref(path) for name, path in artifacts.items() if name != "summary"},
        "next_external_usage_review_id": object_value(context.get("post_h3y_summary")).get("next_external_usage_review_id"),
        "external_user_feedback_collection_id": feedback.get("external_user_feedback_collection_id"),
        "external_user_feedback_receipt_id": feedback.get("external_user_feedback_receipt_id"),
        "monitoring_receipt_id": monitoring.get("monitoring_receipt_id"),
        "rollback_abort_receipt_id": monitoring.get("rollback_abort_receipt_id"),
        "readiness": {
            "state": "post_h3_external_user_feedback_collected" if passed else "blocked_post_h3_external_user_feedback_collection",
            "external_user_feedback_collection_complete": passed,
            "feedback_authorization_consumed": consumption.get("passed") is True,
            "feedback_receipt_written": feedback.get("passed") is True,
            "monitoring_receipt_written": monitoring.get("passed") is True,
            "rollback_abort_receipt_written": monitoring.get("passed") is True,
            "owner_audit_reconciliation_complete": reconciliation.get("passed") is True,
            "second_external_user_usage_execution_ready": False,
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


def validate_post_h3y_context(post_h3y_summary_path: Path, *, output: Path | None = None) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    try:
        summary = read_json_object(post_h3y_summary_path)
    except Exception as exc:  # noqa: BLE001
        return _write_optional(_report(CONTEXT_SCHEMA, False, [f"post_h3y_summary_unreadable:{exc}"], checks), output)
    artifacts = object_value(summary.get("artifacts"))
    reconciliation = _read_verified_ref(artifacts.get("review_reconciliation"), checks, failures, "post_h3y_review_reconciliation")
    boundary_report = _read_verified_ref(artifacts.get("boundary_report"), checks, failures, "post_h3y_boundary_report")
    _check_y_summary(summary, checks, failures)
    _check_y_reconciliation(reconciliation, checks, failures)
    _check_y_boundary(boundary_report, checks, failures)
    passed = _passed(checks, failures)
    report = {
        "schema_version": CONTEXT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "post_h3y_summary": summary,
        "post_h3y_review_reconciliation": reconciliation,
        "post_h3y_boundary_report": boundary_report,
        "source_artifacts": {"post_h3y_summary": artifact_ref(post_h3y_summary_path)},
        "boundary": _boundary(context_validation_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    return _write_optional(report, output)


def _write_authorization_consumption(
    *,
    context: dict[str, Any],
    post_h3y_summary_path: Path,
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
    y_summary = object_value(context.get("post_h3y_summary"))
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "y_authorizes_feedback", y_summary.get("external_user_feedback_collection_allowed") is True)
    check(checks, failures, "y_feedback_ready", object_value(y_summary.get("readiness")).get("external_user_feedback_collection_ready") is True)
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
            post_h3y_summary_path=post_h3y_summary_path,
            y_summary=y_summary,
            operator_id=operator_id,
            operator_decision=operator_decision,
            audit_decision=audit_decision,
            monitoring_decision=monitoring_decision,
            rollback_decision=rollback_decision,
            operator_statement=operator_statement,
            ack_feedback_collection=ack_feedback_collection,
        )
    lease = {
        "schema_version": "post-h3z-feedback-collection-authorization-consumption-lease:v1",
        "consumed_at": _now(),
        "post_h3y_summary": artifact_ref(post_h3y_summary_path),
        "next_external_usage_review_id": y_summary.get("next_external_usage_review_id"),
        "operator_id": operator_id,
    }
    lease_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(lease_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise RuntimeError(f"external_user_feedback_authorization_already_consumed:{lease_path}") from exc
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
        post_h3y_summary_path=post_h3y_summary_path,
        y_summary=y_summary,
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
    post_h3y_summary_path: Path,
    y_summary: dict[str, Any],
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
        "next_external_usage_review_id": y_summary.get("next_external_usage_review_id"),
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
        "source_artifacts": {"post_h3y_summary": artifact_ref(post_h3y_summary_path)},
        "boundary": _boundary(authorization_consumed=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def _write_blocked_consumption(*, output: Path, post_h3y_summary_path: Path, error: str) -> dict[str, Any]:
    report = {
        "schema_version": AUTHORIZATION_CONSUMPTION_SCHEMA,
        "passed": False,
        "failure_reasons": [error],
        "checks": {"authorization_not_previously_consumed": False},
        "consumed_at": _now(),
        "single_use_consumption": False,
        "source_artifacts": {"post_h3y_summary": artifact_ref(post_h3y_summary_path)},
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
    check(checks, failures, "feedback_scope_bounded", feedback_scope == FEEDBACK_ONLY_SCOPE)
    check(checks, failures, "feedback_text_present", bool(feedback_text.strip()) and len(feedback_text.strip()) >= 12)
    check(checks, failures, "feedback_source_present", bool(feedback_source.strip()))
    check(checks, failures, "feedback_has_no_forbidden_tokens", not _contains_forbidden_token(feedback_text))
    passed = _passed(checks, failures)
    collection_id = f"post-h3z-feedback-collection:{sha256_json([artifact_ref(consumption_path), external_user_handle, feedback_scope, feedback_text])[:24]}"
    receipt = {
        "schema_version": FEEDBACK_RECEIPT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "written_at": _now(),
        "external_user_feedback_collection_id": collection_id,
        "external_user_feedback_receipt_id": f"post-h3z-feedback-receipt:{sha256_json([collection_id, feedback_source])[:24]}",
        "external_user_handle": external_user_handle,
        "feedback_scope": feedback_scope,
        "feedback_source": feedback_source,
        "feedback_text": feedback_text,
        "feedback_text_sha256": sha256_json(feedback_text),
        "source_artifacts": {"authorization_consumption": artifact_ref(consumption_path)},
        "readiness": {
            "external_user_feedback_collected": passed,
            "external_user_feedback_collection_closed": passed,
            "second_external_user_usage_execution_ready": False,
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
        "monitoring_receipt_id": f"post-h3z-monitoring:{sha256_json([artifact_ref(feedback_receipt_path), 'feedback-only'])[:24]}",
        "rollback_abort_receipt_id": f"post-h3z-rollback-abort:{sha256_json([artifact_ref(feedback_receipt_path), 'no-rollback-required'])[:24]}",
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
        "owner_decision": "accept_post_h3z_external_user_feedback_collection" if passed else "reject_post_h3z_external_user_feedback_collection",
        "audit_decision": "accept_post_h3z_no_production_boundary" if passed else "reject_post_h3z_no_production_boundary",
        "rollback_decision": "continue_after_post_h3z_no_rollback_required" if passed else "abort_after_post_h3z_failure",
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


def _check_y_summary(summary: dict[str, Any], checks: dict[str, bool], failures: list[str]) -> None:
    readiness = object_value(summary.get("readiness"))
    boundary = object_value(summary.get("boundary"))
    check(checks, failures, "post_h3y_schema_valid", summary.get("schema_version") == POST_H3Y_SCHEMA)
    check(checks, failures, "post_h3y_passed", summary.get("passed") is True)
    check(checks, failures, "post_h3y_review_complete", readiness.get("next_external_usage_review_complete") is True)
    check(checks, failures, "post_h3y_feedback_ready", readiness.get("external_user_feedback_collection_ready") is True)
    check(checks, failures, "post_h3y_second_usage_not_ready", readiness.get("second_external_user_usage_execution_ready") is False)
    check(checks, failures, "post_h3y_usage_not_allowed", readiness.get("external_user_usage_allowed") is False)
    check(checks, failures, "post_h3y_no_public_ingress", readiness.get("external_public_ingress_opened") is False)
    check(checks, failures, "post_h3y_runtime_not_executed", readiness.get("runtime_execution_performed") is False)
    check(checks, failures, "post_h3y_no_production_receipt_write", readiness.get("production_runtime_receipt_write_allowed") is False)
    _check_no_side_effect_boundary("post_h3y", boundary, checks, failures)


def _check_y_reconciliation(reconciliation: dict[str, Any], checks: dict[str, bool], failures: list[str]) -> None:
    ready = object_value(reconciliation.get("readiness"))
    check(checks, failures, "y_reconciliation_schema_valid", reconciliation.get("schema_version") == POST_H3Y_REVIEW_RECONCILIATION_SCHEMA)
    check(checks, failures, "y_reconciliation_passed", reconciliation.get("passed") is True)
    check(checks, failures, "y_feedback_allowed", reconciliation.get("external_user_feedback_collection_allowed") is True)
    check(checks, failures, "y_second_usage_not_allowed", reconciliation.get("second_external_user_usage_allowed") is False)
    check(checks, failures, "y_ready_feedback", ready.get("external_user_feedback_collection_ready") is True)


def _check_y_boundary(report: dict[str, Any], checks: dict[str, bool], failures: list[str]) -> None:
    boundary = object_value(report.get("boundary"))
    check(checks, failures, "y_boundary_schema_valid", report.get("schema_version") == POST_H3Y_BOUNDARY_REPORT_SCHEMA and report.get("passed") is True)
    check(checks, failures, "y_boundary_feedback_ready", boundary.get("external_user_feedback_collection_ready") is True)
    _check_no_side_effect_boundary("y_boundary", boundary, checks, failures)


def _check_no_side_effect_boundary(prefix: str, boundary: dict[str, Any], checks: dict[str, bool], failures: list[str]) -> None:
    for key in (
        "external_public_ingress_opened",
        "runtime_execution_performed",
        "vm_contact_performed",
        "deploy_performed",
        "production_data_accessed",
        "production_runtime_receipt_write_allowed",
        "source_tree_write_performed",
        "git_write_performed",
    ):
        check(checks, failures, f"{prefix}_no_{key}", boundary.get(key) is False)


def _read_verified_ref(value: Any, checks: dict[str, bool], failures: list[str], label: str) -> dict[str, Any]:
    ref = object_value(value)
    path = Path(str(ref.get("path") or ""))
    expected_hash = str(ref.get("sha256") or "")
    check(checks, failures, f"{label}_path_present", path.is_file())
    if not path.is_file():
        return {}
    check(checks, failures, f"{label}_hash_valid", bool(expected_hash) and sha256_file(path) == expected_hash)
    return read_json_object(path)


def _default_consumption_lease_path(post_h3y_summary_path: Path) -> Path:
    return post_h3y_summary_path.with_name("post_h3y_feedback_collection_authorization_consumed_by_post_h3z.json")


def _contains_forbidden_token(value: str) -> bool:
    lowered = value.lower()
    return any(token.lower() in lowered for token in FORBIDDEN_FEEDBACK_TOKENS)


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
    parser = argparse.ArgumentParser(description="Run PostH3-Z external user feedback collection gate")
    parser.add_argument("--post-h3y-summary", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--operator-id", default="operator-primary")
    parser.add_argument("--operator-decision", default=ACCEPTED_OPERATOR_DECISION)
    parser.add_argument("--audit-decision", default=ACCEPTED_AUDIT_DECISION)
    parser.add_argument("--monitoring-decision", default=ACCEPTED_MONITORING_DECISION)
    parser.add_argument("--rollback-decision", default=ACCEPTED_ROLLBACK_DECISION)
    parser.add_argument("--operator-statement", default="Collect one feedback-only record after PostH3-Y authorization; no second usage execution.")
    parser.add_argument("--external-user-handle", default="Thneoly")
    parser.add_argument("--feedback-scope", default=FEEDBACK_ONLY_SCOPE)
    parser.add_argument("--feedback-text", default="External user prefers feedback-only collection before any second limited usage.")
    parser.add_argument("--feedback-source", default="operator_supplied_external_user_feedback")
    parser.add_argument("--authorization-consumption-path", type=Path)
    parser.add_argument("--ack-feedback-collection", action="store_true")
    args = parser.parse_args()
    summary = run_gate(
        post_h3y_summary_path=args.post_h3y_summary,
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


if __name__ == "__main__":
    raise SystemExit(main())
