"""Close out limited-feedback collection and review the next strategy.

This gate consumes a passed
``post_h3_limited_external_usage_feedback_collection_execution_gate`` summary.
It hash-verifies the feedback, monitoring/rollback, owner/audit, and boundary
artifacts, writes a limited-feedback evidence index, and records a strategy
review decision. The default decision is to continue observer mode. A higher
permission path can only be prepared as a review input; this gate never grants
execution authorization and never performs external usage, public ingress,
runtime expansion, deploy, production receipt writes, or source/Git writes.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from benchmarks.i_gate_evidence import artifact_ref, check, object_value, read_json_object, sha256_file, sha256_json, write_json_object
from benchmarks.post_h3_limited_external_usage_feedback_collection_execution_gate import (
    AUTHORIZATION_CONSUMPTION_SCHEMA as EXEC_AUTHORIZATION_CONSUMPTION_SCHEMA,
    BOUNDARY_REPORT_SCHEMA as EXEC_BOUNDARY_REPORT_SCHEMA,
    CHAIN_SCHEMA as EXEC_CHAIN_SCHEMA,
    CONTEXT_SCHEMA as EXEC_CONTEXT_SCHEMA,
    FEEDBACK_RECEIPT_SCHEMA as EXEC_FEEDBACK_RECEIPT_SCHEMA,
    MONITORING_ROLLBACK_RECEIPT_SCHEMA as EXEC_MONITORING_ROLLBACK_RECEIPT_SCHEMA,
    OWNER_AUDIT_RECONCILIATION_SCHEMA as EXEC_OWNER_AUDIT_RECONCILIATION_SCHEMA,
)

CHAIN_SCHEMA = "post-h3-limited-feedback-closeout-strategy-gate:v1"
CONTEXT_SCHEMA = "post-h3-limited-feedback-closeout-context:v1"
EVIDENCE_INDEX_SCHEMA = "post-h3-limited-feedback-closeout-evidence-index:v1"
STRATEGY_PACKET_SCHEMA = "post-h3-limited-feedback-strategy-packet:v1"
STRATEGY_RECONCILIATION_SCHEMA = "post-h3-limited-feedback-strategy-reconciliation:v1"
BOUNDARY_REPORT_SCHEMA = "post-h3-limited-feedback-closeout-strategy-boundary:v1"

CONTINUE_OBSERVER_DECISION = "continue_observer_mode_after_limited_feedback"
REQUEST_HIGHER_PERMISSION_DECISION = "request_higher_permission_review_after_limited_feedback"
REQUEST_REVISION_DECISION = "request_revision_before_limited_feedback_strategy"
ALLOWED_OPERATOR_DECISIONS = (
    CONTINUE_OBSERVER_DECISION,
    REQUEST_HIGHER_PERMISSION_DECISION,
    REQUEST_REVISION_DECISION,
)
OBSERVER_AUDIT_DECISION = "accept_limited_feedback_closeout_continue_observer"
OBSERVER_MONITORING_DECISION = "accept_limited_feedback_monitoring_continue_observer"
OBSERVER_ROLLBACK_DECISION = "accept_limited_feedback_no_rollback_required_continue_observer"
HIGHER_PERMISSION_AUDIT_DECISION = "accept_limited_feedback_boundary_for_higher_permission_review"
HIGHER_PERMISSION_MONITORING_DECISION = "accept_limited_feedback_monitoring_for_higher_permission_review"
HIGHER_PERMISSION_ROLLBACK_DECISION = "accept_limited_feedback_abort_before_higher_permission_review"
REVISION_DECISION = REQUEST_REVISION_DECISION
ACCEPTED_AUDIT_DECISIONS = (OBSERVER_AUDIT_DECISION, HIGHER_PERMISSION_AUDIT_DECISION, REVISION_DECISION)
ACCEPTED_MONITORING_DECISIONS = (OBSERVER_MONITORING_DECISION, HIGHER_PERMISSION_MONITORING_DECISION, REVISION_DECISION)
ACCEPTED_ROLLBACK_DECISIONS = (OBSERVER_ROLLBACK_DECISION, HIGHER_PERMISSION_ROLLBACK_DECISION, REVISION_DECISION)
DEFAULT_OPERATOR_STATEMENT = "Close limited-feedback collection and continue observer mode; require a separate review before any higher permission action."
NON_CLAIMS = (
    "limited_feedback_closeout_strategy_only",
    "limited_feedback_closeout_does_not_collect_additional_feedback",
    "limited_feedback_closeout_does_not_execute_external_user_usage",
    "limited_feedback_closeout_does_not_open_public_ingress",
    "limited_feedback_closeout_does_not_start_runtime_workers",
    "limited_feedback_closeout_does_not_execute_runtime_task",
    "limited_feedback_closeout_does_not_contact_vm_targets",
    "limited_feedback_closeout_does_not_deploy",
    "limited_feedback_closeout_does_not_access_production_data",
    "limited_feedback_closeout_does_not_write_production_runtime_receipts",
    "limited_feedback_closeout_does_not_write_source_or_git",
)


def run_gate(
    *,
    limited_feedback_collection_execution_summary_path: Path,
    output_root: Path,
    operator_id: str = "operator-primary",
    operator_decision: str = CONTINUE_OBSERVER_DECISION,
    audit_decision: str = OBSERVER_AUDIT_DECISION,
    monitoring_decision: str = OBSERVER_MONITORING_DECISION,
    rollback_decision: str = OBSERVER_ROLLBACK_DECISION,
    operator_statement: str = DEFAULT_OPERATOR_STATEMENT,
    ack_strategy_review: bool = False,
) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "context_validation": output_root / "post_h3_limited_feedback_closeout_context.json",
        "evidence_index": output_root / "post_h3_limited_feedback_evidence_index.json",
        "strategy_packet": output_root / "post_h3_limited_feedback_strategy_packet.json",
        "strategy_reconciliation": output_root / "post_h3_limited_feedback_strategy_reconciliation.json",
        "boundary_report": output_root / "post_h3_limited_feedback_closeout_strategy_boundary_report.json",
        "summary": output_root / "post_h3_limited_feedback_closeout_strategy_summary.json",
    }
    context = validate_execution_context(
        limited_feedback_collection_execution_summary_path,
        output=artifacts["context_validation"],
    )
    evidence_index = _write_evidence_index(
        context=context,
        execution_summary_path=limited_feedback_collection_execution_summary_path,
        output=artifacts["evidence_index"],
    )
    packet = _write_strategy_packet(
        evidence_index_path=artifacts["evidence_index"],
        output=artifacts["strategy_packet"],
    )
    reconciliation = _write_strategy_reconciliation(
        packet_path=artifacts["strategy_packet"],
        output=artifacts["strategy_reconciliation"],
        operator_id=operator_id,
        operator_decision=operator_decision,
        audit_decision=audit_decision,
        monitoring_decision=monitoring_decision,
        rollback_decision=rollback_decision,
        operator_statement=operator_statement,
        ack_strategy_review=ack_strategy_review,
    )
    boundary = _write_boundary_report(
        context=context,
        reconciliation_path=artifacts["strategy_reconciliation"],
        output=artifacts["boundary_report"],
    )
    reports = [context, evidence_index, packet, reconciliation, boundary]
    passed = all(report.get("passed") is True for report in reports)
    observer_mode = passed and reconciliation.get("observer_mode_continues") is True
    higher_ready = passed and reconciliation.get("higher_permission_review_request_ready") is True
    revision_required = passed and reconciliation.get("revision_required") is True
    execution_summary = object_value(context.get("execution_summary"))
    summary = {
        "schema_version": CHAIN_SCHEMA,
        "passed": passed,
        "failure_reasons": _failures(reports),
        "checked_at": _now(),
        "source_artifacts": {
            "limited_feedback_collection_execution_summary": artifact_ref(limited_feedback_collection_execution_summary_path),
        },
        "artifacts": {name: artifact_ref(path) for name, path in artifacts.items() if name != "summary"},
        "limited_feedback_closeout_strategy_id": reconciliation.get("limited_feedback_closeout_strategy_id"),
        "authorization_id": execution_summary.get("authorization_id"),
        "external_user_feedback_collection_id": execution_summary.get("external_user_feedback_collection_id"),
        "external_user_feedback_receipt_id": execution_summary.get("external_user_feedback_receipt_id"),
        "operator_decision": operator_decision,
        "observer_mode_continues": observer_mode,
        "higher_permission_review_request_ready": higher_ready,
        "revision_required": revision_required,
        "readiness": {
            "state": _state(passed, observer_mode, higher_ready, revision_required),
            "limited_feedback_closeout_strategy_complete": passed,
            "limited_feedback_execution_closed": passed,
            "limited_feedback_evidence_index_complete": evidence_index.get("passed") is True,
            "strategy_review_complete": reconciliation.get("passed") is True,
            "observer_mode_continues": observer_mode,
            "higher_permission_review_request_ready": higher_ready,
            "revision_required": revision_required,
            "next_single_use_gate_input_ready": False,
            "additional_feedback_collection_ready": False,
            "external_user_usage_allowed": False,
            "external_user_usage_execution_ready": False,
            "external_public_ingress_opened": False,
            "runtime_execution_performed": False,
            "production_runtime_receipt_write_allowed": False,
        },
        "boundary": _boundary(
            context_validation_written=context.get("passed") is True,
            evidence_index_written=evidence_index.get("passed") is True,
            strategy_packet_written=packet.get("passed") is True,
            strategy_reconciliation_written=reconciliation.get("passed") is True,
            boundary_report_written=boundary.get("passed") is True,
            limited_feedback_execution_closed=passed,
            limited_feedback_closeout_strategy_complete=passed,
            observer_mode_continues=observer_mode,
            higher_permission_review_request_ready=higher_ready,
        ),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(artifacts["summary"], summary)
    return summary


def validate_execution_context(execution_summary_path: Path, *, output: Path | None = None) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    try:
        summary = read_json_object(execution_summary_path)
    except Exception as exc:  # noqa: BLE001
        return _write_optional(_report(CONTEXT_SCHEMA, False, [f"execution_summary_unreadable:{exc}"], checks), output)
    artifacts = object_value(summary.get("artifacts"))
    context_validation = _read_verified_ref(artifacts.get("context_validation"), checks, failures, "execution_context_validation")
    authorization_consumption = _read_verified_ref(artifacts.get("authorization_consumption"), checks, failures, "authorization_consumption")
    feedback_receipt = _read_verified_ref(artifacts.get("feedback_receipt"), checks, failures, "feedback_receipt")
    monitoring_rollback = _read_verified_ref(artifacts.get("monitoring_rollback_receipt"), checks, failures, "monitoring_rollback_receipt")
    owner_audit = _read_verified_ref(artifacts.get("owner_audit_reconciliation"), checks, failures, "owner_audit_reconciliation")
    boundary_report = _read_verified_ref(artifacts.get("boundary_report"), checks, failures, "execution_boundary_report")
    _check_execution_summary(summary, checks, failures)
    _check_context_validation(context_validation, checks, failures)
    _check_authorization_consumption(authorization_consumption, checks, failures)
    _check_feedback_receipt(summary, feedback_receipt, checks, failures)
    _check_monitoring_rollback(monitoring_rollback, checks, failures)
    _check_owner_audit(owner_audit, checks, failures)
    _check_boundary_report(boundary_report, checks, failures)
    passed = _passed(checks, failures)
    report = {
        "schema_version": CONTEXT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "execution_summary": summary,
        "execution_context_validation": context_validation,
        "authorization_consumption": authorization_consumption,
        "feedback_receipt": feedback_receipt,
        "monitoring_rollback_receipt": monitoring_rollback,
        "owner_audit_reconciliation": owner_audit,
        "execution_boundary_report": boundary_report,
        "source_artifacts": {"limited_feedback_collection_execution_summary": artifact_ref(execution_summary_path)},
        "boundary": _boundary(context_validation_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    return _write_optional(report, output)


def _write_evidence_index(*, context: dict[str, Any], execution_summary_path: Path, output: Path) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    execution_summary = object_value(context.get("execution_summary"))
    feedback = object_value(context.get("feedback_receipt"))
    monitoring = object_value(context.get("monitoring_rollback_receipt"))
    owner_audit = object_value(context.get("owner_audit_reconciliation"))
    boundary_report = object_value(context.get("execution_boundary_report"))
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "feedback_receipt_present", bool(feedback.get("external_user_feedback_receipt_id")))
    check(checks, failures, "feedback_text_hash_present", bool(feedback.get("feedback_text_sha256")))
    check(checks, failures, "monitoring_receipt_present", bool(monitoring.get("monitoring_receipt_id")))
    check(checks, failures, "rollback_abort_receipt_present", bool(monitoring.get("rollback_abort_receipt_id")))
    check(checks, failures, "owner_audit_passed", owner_audit.get("passed") is True)
    check(checks, failures, "boundary_report_passed", boundary_report.get("passed") is True)
    passed = _passed(checks, failures)
    index = {
        "schema_version": EVIDENCE_INDEX_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "written_at": _now(),
        "limited_feedback_evidence_index_id": f"post-h3-limited-feedback-evidence-index:{sha256_json([artifact_ref(execution_summary_path), feedback.get('external_user_feedback_receipt_id')])[:24]}",
        "authorization_id": execution_summary.get("authorization_id"),
        "external_user_feedback_collection_id": execution_summary.get("external_user_feedback_collection_id"),
        "external_user_feedback_receipt_id": feedback.get("external_user_feedback_receipt_id"),
        "feedback_text_sha256": feedback.get("feedback_text_sha256"),
        "monitoring_receipt_id": monitoring.get("monitoring_receipt_id"),
        "rollback_abort_receipt_id": monitoring.get("rollback_abort_receipt_id"),
        "owner_decision": owner_audit.get("owner_decision"),
        "audit_decision": owner_audit.get("audit_decision"),
        "rollback_decision": owner_audit.get("rollback_decision"),
        "source_artifacts": {"limited_feedback_collection_execution_summary": artifact_ref(execution_summary_path)},
        "evidence_refs": _artifact_refs_from_summary(execution_summary),
        "readiness": {
            "limited_feedback_evidence_index_complete": passed,
            "limited_feedback_execution_closed": passed,
            "strategy_review_input_ready": passed,
            "external_user_usage_allowed": False,
            "additional_feedback_collection_ready": False,
            "production_runtime_receipt_write_allowed": False,
        },
        "boundary": _boundary(evidence_index_written=passed, limited_feedback_execution_closed=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, index)
    return index


def _write_strategy_packet(*, evidence_index_path: Path, output: Path) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    evidence_index = read_json_object(evidence_index_path)
    readiness = object_value(evidence_index.get("readiness"))
    check(checks, failures, "evidence_index_schema", evidence_index.get("schema_version") == EVIDENCE_INDEX_SCHEMA)
    check(checks, failures, "evidence_index_passed", evidence_index.get("passed") is True)
    check(checks, failures, "strategy_input_ready", readiness.get("strategy_review_input_ready") is True)
    check(checks, failures, "external_usage_not_pre_authorized", readiness.get("external_user_usage_allowed") is False)
    check(checks, failures, "additional_feedback_not_pre_authorized", readiness.get("additional_feedback_collection_ready") is False)
    passed = _passed(checks, failures)
    packet = {
        "schema_version": STRATEGY_PACKET_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "written_at": _now(),
        "strategy_packet_id": f"post-h3-limited-feedback-strategy-packet:{sha256_json([artifact_ref(evidence_index_path), evidence_index.get('external_user_feedback_receipt_id')])[:24]}",
        "available_decisions": list(ALLOWED_OPERATOR_DECISIONS),
        "default_decision": CONTINUE_OBSERVER_DECISION,
        "review_scope": {
            "review_observer_mode": True,
            "review_higher_permission_request": True,
            "review_revision": True,
            "grant_authorization": False,
            "execute_external_user_usage": False,
            "collect_additional_feedback": False,
            "open_public_ingress": False,
            "start_runtime_workers": False,
            "write_production_runtime_receipt": False,
        },
        "requirements_for_higher_permission_request": [
            "explicit operator decision request_higher_permission_review_after_limited_feedback",
            "audit, monitoring, and rollback decisions must match higher-permission review path",
            "separate authorization request gate required before any execution",
        ],
        "source_artifacts": {"limited_feedback_evidence_index": artifact_ref(evidence_index_path)},
        "readiness": {
            "limited_feedback_strategy_packet_ready": passed,
            "observer_mode_recommendation_available": passed,
            "higher_permission_review_request_available": passed,
            "external_user_usage_allowed": False,
            "additional_feedback_collection_ready": False,
        },
        "boundary": _boundary(strategy_packet_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, packet)
    return packet


def _write_strategy_reconciliation(
    *,
    packet_path: Path,
    output: Path,
    operator_id: str,
    operator_decision: str,
    audit_decision: str,
    monitoring_decision: str,
    rollback_decision: str,
    operator_statement: str,
    ack_strategy_review: bool,
) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    packet = read_json_object(packet_path)
    wants_observer = operator_decision == CONTINUE_OBSERVER_DECISION
    wants_higher = operator_decision == REQUEST_HIGHER_PERMISSION_DECISION
    wants_revision = operator_decision == REQUEST_REVISION_DECISION
    check(checks, failures, "packet_passed", packet.get("schema_version") == STRATEGY_PACKET_SCHEMA and packet.get("passed") is True)
    check(checks, failures, "operator_id_present", bool(operator_id.strip()))
    check(checks, failures, "operator_decision_known", operator_decision in ALLOWED_OPERATOR_DECISIONS)
    check(checks, failures, "audit_decision_known", audit_decision in ACCEPTED_AUDIT_DECISIONS)
    check(checks, failures, "monitoring_decision_known", monitoring_decision in ACCEPTED_MONITORING_DECISIONS)
    check(checks, failures, "rollback_decision_known", rollback_decision in ACCEPTED_ROLLBACK_DECISIONS)
    check(checks, failures, "operator_statement_present", bool(operator_statement.strip()))
    check(checks, failures, "explicit_operator_ack", ack_strategy_review is True)
    if wants_observer:
        check(checks, failures, "audit_accepts_observer", audit_decision == OBSERVER_AUDIT_DECISION)
        check(checks, failures, "monitoring_accepts_observer", monitoring_decision == OBSERVER_MONITORING_DECISION)
        check(checks, failures, "rollback_accepts_observer", rollback_decision == OBSERVER_ROLLBACK_DECISION)
    if wants_higher:
        check(checks, failures, "audit_accepts_higher_permission_review", audit_decision == HIGHER_PERMISSION_AUDIT_DECISION)
        check(checks, failures, "monitoring_accepts_higher_permission_review", monitoring_decision == HIGHER_PERMISSION_MONITORING_DECISION)
        check(checks, failures, "rollback_accepts_higher_permission_review", rollback_decision == HIGHER_PERMISSION_ROLLBACK_DECISION)
    if wants_revision:
        check(checks, failures, "audit_requests_revision", audit_decision == REVISION_DECISION)
        check(checks, failures, "monitoring_requests_revision", monitoring_decision == REVISION_DECISION)
        check(checks, failures, "rollback_requests_revision", rollback_decision == REVISION_DECISION)
    passed = _passed(checks, failures)
    reconciliation = {
        "schema_version": STRATEGY_RECONCILIATION_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "reviewed_at": _now(),
        "limited_feedback_closeout_strategy_id": f"post-h3-limited-feedback-strategy:{sha256_json([artifact_ref(packet_path), operator_id, operator_decision, audit_decision, monitoring_decision, rollback_decision])[:24]}",
        "operator_id": operator_id,
        "operator_decision": operator_decision,
        "audit_decision": audit_decision,
        "monitoring_decision": monitoring_decision,
        "rollback_decision": rollback_decision,
        "operator_statement": operator_statement,
        "operator_statement_sha256": sha256_json(operator_statement),
        "ack_strategy_review": ack_strategy_review,
        "observer_mode_continues": passed and wants_observer,
        "higher_permission_review_request_ready": passed and wants_higher,
        "revision_required": passed and wants_revision,
        "source_artifacts": {"strategy_packet": artifact_ref(packet_path)},
        "readiness": {
            "strategy_review_complete": passed,
            "observer_mode_continues": passed and wants_observer,
            "higher_permission_review_request_ready": passed and wants_higher,
            "revision_required": passed and wants_revision,
            "next_single_use_gate_input_ready": False,
            "external_user_usage_allowed": False,
            "external_user_usage_execution_ready": False,
            "additional_feedback_collection_ready": False,
        },
        "boundary": _boundary(
            strategy_reconciliation_written=passed,
            observer_mode_continues=passed and wants_observer,
            higher_permission_review_request_ready=passed and wants_higher,
        ),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, reconciliation)
    return reconciliation


def _write_boundary_report(*, context: dict[str, Any], reconciliation_path: Path, output: Path) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    reconciliation = read_json_object(reconciliation_path)
    readiness = object_value(reconciliation.get("readiness"))
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "reconciliation_passed", reconciliation.get("passed") is True)
    check(checks, failures, "strategy_review_complete", readiness.get("strategy_review_complete") is True)
    check(checks, failures, "no_next_single_use_authorization", readiness.get("next_single_use_gate_input_ready") is False)
    check(checks, failures, "external_usage_not_allowed", readiness.get("external_user_usage_allowed") is False)
    check(checks, failures, "additional_feedback_not_ready", readiness.get("additional_feedback_collection_ready") is False)
    passed = _passed(checks, failures)
    report = {
        "schema_version": BOUNDARY_REPORT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "source_artifacts": {"strategy_reconciliation": artifact_ref(reconciliation_path)},
        "boundary": _boundary(
            boundary_report_written=passed,
            limited_feedback_closeout_strategy_complete=passed,
            observer_mode_continues=readiness.get("observer_mode_continues") is True,
            higher_permission_review_request_ready=readiness.get("higher_permission_review_request_ready") is True,
        ),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def _check_execution_summary(summary: dict[str, Any], checks: dict[str, bool], failures: list[str]) -> None:
    readiness = object_value(summary.get("readiness"))
    boundary = object_value(summary.get("boundary"))
    check(checks, failures, "execution_summary_schema", summary.get("schema_version") == EXEC_CHAIN_SCHEMA)
    check(checks, failures, "execution_summary_passed", summary.get("passed") is True)
    check(checks, failures, "execution_complete", readiness.get("limited_external_usage_feedback_collection_complete") is True)
    check(checks, failures, "authorization_consumed", readiness.get("feedback_authorization_consumed") is True)
    check(checks, failures, "feedback_receipt_written", readiness.get("feedback_receipt_written") is True)
    check(checks, failures, "monitoring_receipt_written", readiness.get("monitoring_receipt_written") is True)
    check(checks, failures, "rollback_abort_receipt_written", readiness.get("rollback_abort_receipt_written") is True)
    check(checks, failures, "owner_audit_reconciliation_complete", readiness.get("owner_audit_reconciliation_complete") is True)
    check(checks, failures, "execution_boundary_feedback_collected", boundary.get("external_user_feedback_collected") is True)
    _check_no_side_effect_boundary("execution_summary", boundary, checks, failures)


def _check_context_validation(report: dict[str, Any], checks: dict[str, bool], failures: list[str]) -> None:
    check(checks, failures, "execution_context_schema", report.get("schema_version") == EXEC_CONTEXT_SCHEMA)
    check(checks, failures, "execution_context_passed", report.get("passed") is True)


def _check_authorization_consumption(consumption: dict[str, Any], checks: dict[str, bool], failures: list[str]) -> None:
    check(checks, failures, "authorization_consumption_schema", consumption.get("schema_version") == EXEC_AUTHORIZATION_CONSUMPTION_SCHEMA)
    check(checks, failures, "authorization_consumption_passed", consumption.get("passed") is True)
    check(checks, failures, "authorization_single_use_consumption", consumption.get("single_use_consumption") is True)
    check(checks, failures, "authorization_ack_present", consumption.get("ack_feedback_collection") is True)


def _check_feedback_receipt(summary: dict[str, Any], receipt: dict[str, Any], checks: dict[str, bool], failures: list[str]) -> None:
    readiness = object_value(receipt.get("readiness"))
    receipt_checks = object_value(receipt.get("checks"))
    check(checks, failures, "feedback_receipt_schema", receipt.get("schema_version") == EXEC_FEEDBACK_RECEIPT_SCHEMA)
    check(checks, failures, "feedback_receipt_passed", receipt.get("passed") is True)
    check(checks, failures, "feedback_collection_id_matches", receipt.get("external_user_feedback_collection_id") == summary.get("external_user_feedback_collection_id"))
    check(checks, failures, "feedback_receipt_id_matches", receipt.get("external_user_feedback_receipt_id") == summary.get("external_user_feedback_receipt_id"))
    check(checks, failures, "feedback_text_hash_present", bool(receipt.get("feedback_text_sha256")))
    check(checks, failures, "feedback_no_forbidden_tokens", receipt_checks.get("feedback_has_no_forbidden_tokens") is True)
    check(checks, failures, "feedback_collected", readiness.get("external_user_feedback_collected") is True)
    check(checks, failures, "feedback_closed", readiness.get("external_user_feedback_collection_closed") is True)
    check(checks, failures, "feedback_runtime_not_executed", readiness.get("runtime_execution_performed") is False)
    check(checks, failures, "feedback_no_production_receipt_write", readiness.get("production_runtime_receipt_write_allowed") is False)


def _check_monitoring_rollback(report: dict[str, Any], checks: dict[str, bool], failures: list[str]) -> None:
    readiness = object_value(report.get("readiness"))
    check(checks, failures, "monitoring_rollback_schema", report.get("schema_version") == EXEC_MONITORING_ROLLBACK_RECEIPT_SCHEMA)
    check(checks, failures, "monitoring_rollback_passed", report.get("passed") is True)
    check(checks, failures, "monitoring_receipt_present", bool(report.get("monitoring_receipt_id")))
    check(checks, failures, "rollback_abort_receipt_present", bool(report.get("rollback_abort_receipt_id")))
    check(checks, failures, "rollback_not_required", report.get("rollback_required") is False)
    check(checks, failures, "abort_not_required", report.get("abort_required") is False)
    check(checks, failures, "monitoring_receipt_written", readiness.get("monitoring_receipt_written") is True)
    check(checks, failures, "rollback_abort_receipt_written", readiness.get("rollback_abort_receipt_written") is True)


def _check_owner_audit(report: dict[str, Any], checks: dict[str, bool], failures: list[str]) -> None:
    readiness = object_value(report.get("readiness"))
    check(checks, failures, "owner_audit_schema", report.get("schema_version") == EXEC_OWNER_AUDIT_RECONCILIATION_SCHEMA)
    check(checks, failures, "owner_audit_passed", report.get("passed") is True)
    check(checks, failures, "owner_decision_accepts_limited_feedback", report.get("owner_decision") == "accept_limited_feedback_collection")
    check(checks, failures, "audit_decision_accepts_boundary", report.get("audit_decision") == "accept_limited_feedback_no_production_boundary")
    check(checks, failures, "rollback_decision_continue", report.get("rollback_decision") == "continue_after_limited_feedback_no_rollback_required")
    check(checks, failures, "owner_audit_reconciliation_complete", readiness.get("owner_audit_reconciliation_complete") is True)


def _check_boundary_report(report: dict[str, Any], checks: dict[str, bool], failures: list[str]) -> None:
    boundary = object_value(report.get("boundary"))
    check(checks, failures, "execution_boundary_report_schema", report.get("schema_version") == EXEC_BOUNDARY_REPORT_SCHEMA)
    check(checks, failures, "execution_boundary_report_passed", report.get("passed") is True)
    check(checks, failures, "boundary_feedback_collected", boundary.get("external_user_feedback_collected") is True)
    _check_no_side_effect_boundary("execution_boundary", boundary, checks, failures)


def _check_no_side_effect_boundary(prefix: str, boundary: dict[str, Any], checks: dict[str, bool], failures: list[str]) -> None:
    for key in (
        "external_user_usage_performed",
        "external_public_ingress_opened",
        "runtime_execution_performed",
        "vm_contact_performed",
        "deploy_performed",
        "production_data_accessed",
        "production_runtime_receipt_write_allowed",
        "source_tree_write_performed",
        "git_write_performed",
        "secrets_recorded",
    ):
        check(checks, failures, f"{prefix}_no_{key}", boundary.get(key) is False)


def _artifact_refs_from_summary(summary: dict[str, Any]) -> dict[str, dict[str, str]]:
    refs: dict[str, dict[str, str]] = {}
    for name, value in object_value(summary.get("artifacts")).items():
        path_text = object_value(value).get("path")
        if isinstance(path_text, str):
            path = Path(path_text)
            if path.is_file():
                refs[name] = artifact_ref(path)
    return refs


def _read_verified_ref(value: Any, checks: dict[str, bool], failures: list[str], label: str) -> dict[str, Any]:
    ref = object_value(value)
    path_text = ref.get("path")
    expected_hash = ref.get("sha256")
    check(checks, failures, f"{label}_ref_present", bool(path_text and expected_hash))
    if not path_text or not expected_hash:
        return {}
    path = Path(path_text)
    check(checks, failures, f"{label}_exists", path.is_file())
    if not path.is_file():
        return {}
    check(checks, failures, f"{label}_hash_valid", sha256_file(path) == expected_hash)
    return read_json_object(path)


def _boundary(**overrides: bool) -> dict[str, bool]:
    boundary = {
        "context_validation_written": False,
        "evidence_index_written": False,
        "strategy_packet_written": False,
        "strategy_reconciliation_written": False,
        "boundary_report_written": False,
        "limited_feedback_execution_closed": False,
        "limited_feedback_closeout_strategy_complete": False,
        "observer_mode_continues": False,
        "higher_permission_review_request_ready": False,
        "next_single_use_gate_input_ready": False,
        "additional_feedback_collection_ready": False,
        "external_user_usage_allowed": False,
        "external_user_usage_execution_ready": False,
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


def _state(passed: bool, observer_mode: bool, higher_ready: bool, revision_required: bool) -> str:
    if not passed:
        return "blocked_limited_feedback_closeout_strategy"
    if higher_ready:
        return "limited_feedback_higher_permission_review_request_ready"
    if revision_required:
        return "limited_feedback_strategy_revision_required"
    if observer_mode:
        return "limited_feedback_observer_mode_continues"
    return "limited_feedback_strategy_reviewed"


def _report(schema: str, passed: bool, failures: list[str], checks: dict[str, bool]) -> dict[str, Any]:
    return {
        "schema_version": schema,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "boundary": _boundary(),
        "non_claims": list(NON_CLAIMS),
    }


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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--limited-feedback-collection-execution-summary", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--operator-id", default="operator-primary")
    parser.add_argument("--operator-decision", default=CONTINUE_OBSERVER_DECISION)
    parser.add_argument("--audit-decision", default=OBSERVER_AUDIT_DECISION)
    parser.add_argument("--monitoring-decision", default=OBSERVER_MONITORING_DECISION)
    parser.add_argument("--rollback-decision", default=OBSERVER_ROLLBACK_DECISION)
    parser.add_argument("--operator-statement", default=DEFAULT_OPERATOR_STATEMENT)
    parser.add_argument("--ack-strategy-review", action="store_true")
    args = parser.parse_args(argv)
    summary = run_gate(
        limited_feedback_collection_execution_summary_path=args.limited_feedback_collection_execution_summary,
        output_root=args.output_root,
        operator_id=args.operator_id,
        operator_decision=args.operator_decision,
        audit_decision=args.audit_decision,
        monitoring_decision=args.monitoring_decision,
        rollback_decision=args.rollback_decision,
        operator_statement=args.operator_statement,
        ack_strategy_review=args.ack_strategy_review,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if summary.get("passed") is True else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
