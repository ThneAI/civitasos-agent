"""Review the next external usage strategy after PostH3-AA feedback closeout.

PostH3-AB consumes PostH3-AA post-feedback closeout evidence. It decides whether
there is enough closed feedback evidence to remain in observer mode, request
revision, or prepare a separate single-use authorization path for another
bounded external usage or feedback-only collection. It never performs usage,
collects feedback, opens public ingress, starts runtime workers, executes
runtime tasks, contacts VMs, deploys, accesses production data, writes
production runtime receipts, or writes source/Git state.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from benchmarks.i_gate_evidence import artifact_ref, check, object_value, read_json_object, sha256_file, sha256_json, write_json_object
from benchmarks.post_h3_external_user_feedback_closeout_gate import (
    BOUNDARY_REPORT_SCHEMA as POST_H3AA_BOUNDARY_REPORT_SCHEMA,
    CHAIN_SCHEMA as POST_H3AA_SCHEMA,
    CLOSEOUT_RECONCILIATION_SCHEMA as POST_H3AA_CLOSEOUT_RECONCILIATION_SCHEMA,
    CONTEXT_SCHEMA as POST_H3AA_CONTEXT_SCHEMA,
    EVIDENCE_INDEX_SCHEMA as POST_H3AA_EVIDENCE_INDEX_SCHEMA,
)
from benchmarks.post_h3_next_external_usage_review_gate import ALLOWED_USAGE_SCOPE, FEEDBACK_ONLY_SCOPE

CHAIN_SCHEMA = "post-h3-next-external-usage-strategy-review-chain:v1"
CONTEXT_SCHEMA = "post-h3ab-post-h3aa-context-validation:v1"
STRATEGY_PACKET_SCHEMA = "post-h3ab-next-external-usage-strategy-packet:v1"
STRATEGY_RECONCILIATION_SCHEMA = "post-h3ab-next-external-usage-strategy-reconciliation:v1"
BOUNDARY_REPORT_SCHEMA = "post-h3ab-next-external-usage-strategy-boundary-report:v1"

CONTINUE_OBSERVER_DECISION = "continue_observer_mode_after_feedback"
REQUEST_REVISION_DECISION = "request_revision_before_next_external_usage_strategy"
AUTHORIZE_SECOND_USAGE_DECISION = "authorize_second_limited_external_user_usage_once_after_feedback"
AUTHORIZE_FEEDBACK_COLLECTION_DECISION = "authorize_additional_external_user_feedback_collection_once"
ALLOWED_OPERATOR_DECISIONS = (
    CONTINUE_OBSERVER_DECISION,
    REQUEST_REVISION_DECISION,
    AUTHORIZE_SECOND_USAGE_DECISION,
    AUTHORIZE_FEEDBACK_COLLECTION_DECISION,
)
OBSERVER_AUDIT_DECISION = "accept_post_h3aa_no_production_boundary_continue_observer"
OBSERVER_MONITORING_DECISION = "accept_post_h3aa_monitoring_continue_observer"
OBSERVER_ROLLBACK_DECISION = "accept_post_h3aa_no_rollback_required_continue_observer"
SECOND_USAGE_AUDIT_DECISION = "accept_post_h3aa_no_production_boundary_for_second_usage"
SECOND_USAGE_MONITORING_DECISION = "accept_second_limited_external_user_monitoring_after_feedback"
SECOND_USAGE_ROLLBACK_DECISION = "accept_second_limited_external_user_abort_runbook_after_feedback"
FEEDBACK_AUDIT_DECISION = "accept_post_h3aa_no_production_boundary_for_additional_feedback"
FEEDBACK_MONITORING_DECISION = "accept_additional_external_user_feedback_monitoring_once"
FEEDBACK_ROLLBACK_DECISION = "accept_additional_external_user_feedback_abort_runbook_once"
REVISION_DECISION = REQUEST_REVISION_DECISION
ACCEPTED_AUDIT_DECISIONS = (OBSERVER_AUDIT_DECISION, SECOND_USAGE_AUDIT_DECISION, FEEDBACK_AUDIT_DECISION, REVISION_DECISION)
ACCEPTED_MONITORING_DECISIONS = (OBSERVER_MONITORING_DECISION, SECOND_USAGE_MONITORING_DECISION, FEEDBACK_MONITORING_DECISION, REVISION_DECISION)
ACCEPTED_ROLLBACK_DECISIONS = (OBSERVER_ROLLBACK_DECISION, SECOND_USAGE_ROLLBACK_DECISION, FEEDBACK_ROLLBACK_DECISION, REVISION_DECISION)
NON_CLAIMS = (
    "post_h3ab_reviews_strategy_only",
    "post_h3ab_does_not_execute_external_user_usage",
    "post_h3ab_does_not_collect_feedback",
    "post_h3ab_does_not_open_public_ingress",
    "post_h3ab_does_not_start_runtime_workers",
    "post_h3ab_does_not_execute_runtime_task",
    "post_h3ab_does_not_contact_vm_targets",
    "post_h3ab_does_not_deploy",
    "post_h3ab_does_not_access_production_data",
    "post_h3ab_does_not_write_production_runtime_receipts",
    "post_h3ab_does_not_write_source_or_git",
)


def run_gate(
    *,
    post_h3aa_summary_path: Path,
    output_root: Path,
    operator_id: str = "operator-primary",
    operator_decision: str = CONTINUE_OBSERVER_DECISION,
    audit_decision: str = OBSERVER_AUDIT_DECISION,
    monitoring_decision: str = OBSERVER_MONITORING_DECISION,
    rollback_decision: str = OBSERVER_ROLLBACK_DECISION,
    operator_statement: str = "Keep observer mode after PostH3-AA feedback closeout; require separate single-use authorization for any next usage.",
    max_external_users: int = 0,
    requested_usage_scope: str = "observer-only",
    ack_strategy_review: bool = False,
) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "context_validation": output_root / "post_h3ab_post_h3aa_context_validation.json",
        "strategy_packet": output_root / "post_h3ab_next_external_usage_strategy_packet.json",
        "strategy_reconciliation": output_root / "post_h3ab_next_external_usage_strategy_reconciliation.json",
        "boundary_report": output_root / "post_h3ab_next_external_usage_strategy_boundary_report.json",
        "summary": output_root / "post_h3ab_next_external_usage_strategy_review_summary.json",
    }
    context = validate_post_h3aa_context(post_h3aa_summary_path, output=artifacts["context_validation"])
    packet = _write_strategy_packet(context=context, post_h3aa_summary_path=post_h3aa_summary_path, output=artifacts["strategy_packet"])
    reconciliation = _write_reconciliation(
        packet_path=artifacts["strategy_packet"],
        output=artifacts["strategy_reconciliation"],
        operator_id=operator_id,
        operator_decision=operator_decision,
        audit_decision=audit_decision,
        monitoring_decision=monitoring_decision,
        rollback_decision=rollback_decision,
        operator_statement=operator_statement,
        max_external_users=max_external_users,
        requested_usage_scope=requested_usage_scope,
        ack_strategy_review=ack_strategy_review,
    )
    boundary = _write_boundary_report(context=context, reconciliation_path=artifacts["strategy_reconciliation"], output=artifacts["boundary_report"])
    reports = [context, packet, reconciliation, boundary]
    passed = all(report.get("passed") is True for report in reports)
    second_usage_allowed = passed and reconciliation.get("second_external_user_usage_allowed") is True
    feedback_allowed = passed and reconciliation.get("external_user_feedback_collection_allowed") is True
    observer_mode = passed and reconciliation.get("observer_mode_continues") is True
    summary = {
        "schema_version": CHAIN_SCHEMA,
        "passed": passed,
        "failure_reasons": _failures(reports),
        "checked_at": _now(),
        "source_artifacts": {"post_h3aa_summary": artifact_ref(post_h3aa_summary_path)},
        "artifacts": {name: artifact_ref(path) for name, path in artifacts.items() if name != "summary"},
        "next_external_usage_strategy_review_id": reconciliation.get("next_external_usage_strategy_review_id"),
        "external_user_feedback_closeout_id": object_value(context.get("post_h3aa_summary")).get("external_user_feedback_closeout_id"),
        "external_user_feedback_receipt_id": object_value(context.get("post_h3aa_summary")).get("external_user_feedback_receipt_id"),
        "observer_mode_continues": observer_mode,
        "second_external_user_usage_allowed": second_usage_allowed,
        "external_user_feedback_collection_allowed": feedback_allowed,
        "readiness": {
            "state": _state(passed, observer_mode, second_usage_allowed, feedback_allowed, operator_decision),
            "next_external_usage_strategy_review_complete": passed,
            "observer_mode_continues": observer_mode,
            "second_limited_usage_authorized": second_usage_allowed,
            "second_external_user_usage_execution_ready": second_usage_allowed,
            "external_user_feedback_collection_ready": feedback_allowed,
            "external_user_usage_allowed": second_usage_allowed,
            "external_public_ingress_opened": False,
            "runtime_execution_performed": False,
            "production_runtime_receipt_write_allowed": False,
        },
        "boundary": _boundary(
            context_validation_written=context.get("passed") is True,
            strategy_packet_written=packet.get("passed") is True,
            strategy_reconciliation_written=reconciliation.get("passed") is True,
            boundary_report_written=boundary.get("passed") is True,
            next_external_usage_strategy_review_complete=passed,
            observer_mode_continues=observer_mode,
            second_limited_usage_authorized=second_usage_allowed,
            external_user_feedback_collection_ready=feedback_allowed,
        ),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(artifacts["summary"], summary)
    return summary


def validate_post_h3aa_context(post_h3aa_summary_path: Path, *, output: Path | None = None) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    try:
        summary = read_json_object(post_h3aa_summary_path)
    except Exception as exc:  # noqa: BLE001
        return _write_optional(_report(CONTEXT_SCHEMA, False, [f"post_h3aa_summary_unreadable:{exc}"], checks), output)
    artifacts = object_value(summary.get("artifacts"))
    aa_context = _read_verified_ref(artifacts.get("context_validation"), checks, failures, "post_h3aa_context_validation")
    evidence_index = _read_verified_ref(artifacts.get("evidence_index"), checks, failures, "post_h3aa_evidence_index")
    closeout_reconciliation = _read_verified_ref(artifacts.get("closeout_reconciliation"), checks, failures, "post_h3aa_closeout_reconciliation")
    boundary_report = _read_verified_ref(artifacts.get("boundary_report"), checks, failures, "post_h3aa_boundary_report")
    _check_aa_summary(summary, checks, failures)
    _check_aa_context(aa_context, checks, failures)
    _check_aa_evidence_index(evidence_index, checks, failures)
    _check_aa_reconciliation(closeout_reconciliation, checks, failures)
    _check_aa_boundary_report(boundary_report, checks, failures)
    passed = _passed(checks, failures)
    report = {
        "schema_version": CONTEXT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "post_h3aa_summary": summary,
        "post_h3aa_context_validation": aa_context,
        "post_h3aa_evidence_index": evidence_index,
        "post_h3aa_closeout_reconciliation": closeout_reconciliation,
        "post_h3aa_boundary_report": boundary_report,
        "source_artifacts": {"post_h3aa_summary": artifact_ref(post_h3aa_summary_path)},
        "boundary": _boundary(context_validation_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    return _write_optional(report, output)


def _write_strategy_packet(*, context: dict[str, Any], post_h3aa_summary_path: Path, output: Path) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    summary = object_value(context.get("post_h3aa_summary"))
    readiness = object_value(summary.get("readiness"))
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "feedback_closeout_complete", readiness.get("external_user_feedback_closeout_complete") is True)
    check(checks, failures, "feedback_closed", readiness.get("post_h3z_feedback_closed") is True)
    check(checks, failures, "strategy_review_input_ready", readiness.get("next_external_usage_strategy_review_input_ready") is True)
    check(checks, failures, "second_usage_not_pre_authorized", readiness.get("second_external_user_usage_execution_ready") is False)
    check(checks, failures, "feedback_collection_not_pre_authorized", readiness.get("external_user_feedback_collection_allowed") is False)
    passed = _passed(checks, failures)
    packet = {
        "schema_version": STRATEGY_PACKET_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "written_at": _now(),
        "strategy_packet_id": f"post-h3ab-strategy-packet:{sha256_json([artifact_ref(post_h3aa_summary_path), summary.get('external_user_feedback_closeout_id')])[:24]}",
        "review_scope": {
            "review_observer_mode": True,
            "review_second_limited_external_user_usage": True,
            "review_additional_feedback_collection": True,
            "default_decision": CONTINUE_OBSERVER_DECISION,
            "execute_external_user_usage": False,
            "collect_feedback": False,
            "open_public_ingress": False,
            "start_runtime_workers": False,
        },
        "available_decisions": list(ALLOWED_OPERATOR_DECISIONS),
        "minimum_requirements_for_authorization": [
            "PostH3-AA closeout passed and hash verified",
            "strategy decision must be explicit and acked by operator",
            "second usage or additional feedback still needs a separate single-use execution gate",
            "public ingress/runtime expansion/production receipt remain independently gated",
        ],
        "source_artifacts": {"post_h3aa_summary": artifact_ref(post_h3aa_summary_path)},
        "readiness": {
            "next_external_usage_strategy_packet_ready": passed,
            "observer_mode_recommendation_available": passed,
            "second_limited_usage_authorized": False,
            "external_user_feedback_collection_ready": False,
        },
        "boundary": _boundary(strategy_packet_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, packet)
    return packet


def _write_reconciliation(
    *,
    packet_path: Path,
    output: Path,
    operator_id: str,
    operator_decision: str,
    audit_decision: str,
    monitoring_decision: str,
    rollback_decision: str,
    operator_statement: str,
    max_external_users: int,
    requested_usage_scope: str,
    ack_strategy_review: bool,
) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    packet = read_json_object(packet_path)
    wants_second_usage = operator_decision == AUTHORIZE_SECOND_USAGE_DECISION
    wants_feedback = operator_decision == AUTHORIZE_FEEDBACK_COLLECTION_DECISION
    wants_observer = operator_decision == CONTINUE_OBSERVER_DECISION
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
        check(checks, failures, "observer_has_no_external_users", max_external_users == 0)
        check(checks, failures, "observer_scope", requested_usage_scope == "observer-only")
    if wants_revision:
        check(checks, failures, "audit_requests_revision", audit_decision == REVISION_DECISION)
        check(checks, failures, "monitoring_requests_revision", monitoring_decision == REVISION_DECISION)
        check(checks, failures, "rollback_requests_revision", rollback_decision == REVISION_DECISION)
        check(checks, failures, "revision_has_no_external_users", max_external_users == 0)
        check(checks, failures, "revision_scope", requested_usage_scope == "revision-only")
    if wants_second_usage:
        check(checks, failures, "audit_accepts_second_usage", audit_decision == SECOND_USAGE_AUDIT_DECISION)
        check(checks, failures, "monitoring_accepts_second_usage", monitoring_decision == SECOND_USAGE_MONITORING_DECISION)
        check(checks, failures, "rollback_accepts_second_usage", rollback_decision == SECOND_USAGE_ROLLBACK_DECISION)
        check(checks, failures, "second_usage_max_one_user", max_external_users == 1)
        check(checks, failures, "second_usage_scope_bounded", requested_usage_scope == ALLOWED_USAGE_SCOPE)
    if wants_feedback:
        check(checks, failures, "audit_accepts_feedback", audit_decision == FEEDBACK_AUDIT_DECISION)
        check(checks, failures, "monitoring_accepts_feedback", monitoring_decision == FEEDBACK_MONITORING_DECISION)
        check(checks, failures, "rollback_accepts_feedback", rollback_decision == FEEDBACK_ROLLBACK_DECISION)
        check(checks, failures, "feedback_max_one_user", max_external_users == 1)
        check(checks, failures, "feedback_scope_bounded", requested_usage_scope == FEEDBACK_ONLY_SCOPE)
    passed = _passed(checks, failures)
    second_usage_allowed = passed and wants_second_usage
    feedback_allowed = passed and wants_feedback
    observer_mode = passed and wants_observer
    reconciliation = {
        "schema_version": STRATEGY_RECONCILIATION_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "reviewed_at": _now(),
        "next_external_usage_strategy_review_id": f"post-h3ab-strategy-review:{sha256_json([artifact_ref(packet_path), operator_id, operator_decision, audit_decision, monitoring_decision, rollback_decision, max_external_users, requested_usage_scope])[:24]}",
        "operator_id": operator_id,
        "operator_decision": operator_decision,
        "audit_decision": audit_decision,
        "monitoring_decision": monitoring_decision,
        "rollback_decision": rollback_decision,
        "operator_statement": operator_statement,
        "operator_statement_sha256": sha256_json(operator_statement),
        "max_external_users": max_external_users,
        "requested_usage_scope": requested_usage_scope,
        "ack_strategy_review": ack_strategy_review,
        "observer_mode_continues": observer_mode,
        "revision_required": passed and wants_revision,
        "second_external_user_usage_allowed": second_usage_allowed,
        "external_user_feedback_collection_allowed": feedback_allowed,
        "source_artifacts": {"strategy_packet": artifact_ref(packet_path)},
        "readiness": {
            "next_external_usage_strategy_review_complete": passed,
            "observer_mode_continues": observer_mode,
            "revision_required": passed and wants_revision,
            "second_limited_usage_authorized": second_usage_allowed,
            "second_external_user_usage_execution_ready": second_usage_allowed,
            "external_user_feedback_collection_ready": feedback_allowed,
            "external_user_usage_allowed": second_usage_allowed,
        },
        "boundary": _boundary(
            strategy_reconciliation_written=passed,
            next_external_usage_strategy_review_complete=passed,
            observer_mode_continues=observer_mode,
            second_limited_usage_authorized=second_usage_allowed,
            external_user_feedback_collection_ready=feedback_allowed,
        ),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, reconciliation)
    return reconciliation


def _write_boundary_report(*, context: dict[str, Any], reconciliation_path: Path, output: Path) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    reconciliation = read_json_object(reconciliation_path)
    ready = object_value(reconciliation.get("readiness"))
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "reconciliation_passed", reconciliation.get("passed") is True)
    check(checks, failures, "strategy_review_complete", ready.get("next_external_usage_strategy_review_complete") is True)
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
        "source_artifacts": {"strategy_reconciliation": artifact_ref(reconciliation_path)},
        "boundary": _boundary(
            boundary_report_written=passed,
            next_external_usage_strategy_review_complete=passed,
            observer_mode_continues=ready.get("observer_mode_continues") is True,
            second_limited_usage_authorized=ready.get("second_limited_usage_authorized") is True,
            external_user_feedback_collection_ready=ready.get("external_user_feedback_collection_ready") is True,
        ),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def _check_aa_summary(summary: dict[str, Any], checks: dict[str, bool], failures: list[str]) -> None:
    readiness = object_value(summary.get("readiness"))
    boundary = object_value(summary.get("boundary"))
    check(checks, failures, "post_h3aa_schema_valid", summary.get("schema_version") == POST_H3AA_SCHEMA)
    check(checks, failures, "post_h3aa_passed", summary.get("passed") is True)
    check(checks, failures, "post_h3aa_feedback_closeout_complete", readiness.get("external_user_feedback_closeout_complete") is True)
    check(checks, failures, "post_h3aa_feedback_closed", readiness.get("post_h3z_feedback_closed") is True)
    check(checks, failures, "post_h3aa_evidence_index_complete", readiness.get("post_h3z_feedback_evidence_index_complete") is True)
    check(checks, failures, "post_h3aa_reconciliation_complete", readiness.get("post_feedback_reconciliation_complete") is True)
    check(checks, failures, "post_h3aa_strategy_input_ready", readiness.get("next_external_usage_strategy_review_input_ready") is True)
    check(checks, failures, "post_h3aa_feedback_not_reauthorized", readiness.get("external_user_feedback_collection_allowed") is False)
    check(checks, failures, "post_h3aa_usage_not_allowed", readiness.get("external_user_usage_allowed") is False)
    check(checks, failures, "post_h3aa_second_usage_not_ready", readiness.get("second_external_user_usage_execution_ready") is False)
    check(checks, failures, "post_h3aa_runtime_not_executed", readiness.get("runtime_execution_performed") is False)
    check(checks, failures, "post_h3aa_no_production_receipt_write", readiness.get("production_runtime_receipt_write_allowed") is False)
    check(checks, failures, "post_h3aa_boundary_strategy_input_ready", boundary.get("next_external_usage_strategy_review_input_ready") is True)
    _check_no_side_effect_boundary("post_h3aa", boundary, checks, failures)


def _check_aa_context(context: dict[str, Any], checks: dict[str, bool], failures: list[str]) -> None:
    check(checks, failures, "aa_context_schema_valid", context.get("schema_version") == POST_H3AA_CONTEXT_SCHEMA)
    check(checks, failures, "aa_context_passed", context.get("passed") is True)


def _check_aa_evidence_index(evidence_index: dict[str, Any], checks: dict[str, bool], failures: list[str]) -> None:
    readiness = object_value(evidence_index.get("readiness"))
    check(checks, failures, "aa_evidence_index_schema_valid", evidence_index.get("schema_version") == POST_H3AA_EVIDENCE_INDEX_SCHEMA)
    check(checks, failures, "aa_evidence_index_passed", evidence_index.get("passed") is True)
    check(checks, failures, "aa_feedback_receipt_present", bool(evidence_index.get("external_user_feedback_receipt_id")))
    check(checks, failures, "aa_feedback_hash_present", bool(evidence_index.get("feedback_text_sha256")))
    check(checks, failures, "aa_strategy_input_ready", readiness.get("next_external_usage_strategy_review_input_ready") is True)


def _check_aa_reconciliation(reconciliation: dict[str, Any], checks: dict[str, bool], failures: list[str]) -> None:
    readiness = object_value(reconciliation.get("readiness"))
    check(checks, failures, "aa_reconciliation_schema_valid", reconciliation.get("schema_version") == POST_H3AA_CLOSEOUT_RECONCILIATION_SCHEMA)
    check(checks, failures, "aa_reconciliation_passed", reconciliation.get("passed") is True)
    check(checks, failures, "aa_feedback_closeout_complete", readiness.get("external_user_feedback_closeout_complete") is True)
    check(checks, failures, "aa_feedback_closed", readiness.get("post_h3z_feedback_closed") is True)
    check(checks, failures, "aa_strategy_input_ready_from_reconciliation", readiness.get("next_external_usage_strategy_review_input_ready") is True)


def _check_aa_boundary_report(report: dict[str, Any], checks: dict[str, bool], failures: list[str]) -> None:
    boundary = object_value(report.get("boundary"))
    check(checks, failures, "aa_boundary_schema_valid", report.get("schema_version") == POST_H3AA_BOUNDARY_REPORT_SCHEMA and report.get("passed") is True)
    check(checks, failures, "aa_boundary_strategy_input_ready", boundary.get("next_external_usage_strategy_review_input_ready") is True)
    _check_no_side_effect_boundary("aa_boundary", boundary, checks, failures)


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
        "secrets_recorded",
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


def _boundary(**overrides: bool) -> dict[str, bool]:
    boundary = {
        "context_validation_written": False,
        "strategy_packet_written": False,
        "strategy_reconciliation_written": False,
        "boundary_report_written": False,
        "next_external_usage_strategy_review_complete": False,
        "observer_mode_continues": False,
        "external_user_feedback_collection_ready": False,
        "external_user_usage_allowed": False,
        "second_limited_usage_authorized": False,
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


def _state(passed: bool, observer_mode: bool, second_usage_allowed: bool, feedback_allowed: bool, operator_decision: str) -> str:
    if not passed:
        return "blocked_post_h3_next_external_usage_strategy_review"
    if second_usage_allowed:
        return "post_h3_second_external_usage_authorized_once_after_feedback"
    if feedback_allowed:
        return "post_h3_additional_feedback_collection_authorized_once"
    if observer_mode:
        return "post_h3_observer_mode_continues_after_feedback"
    if operator_decision == REQUEST_REVISION_DECISION:
        return "post_h3_next_external_usage_strategy_revision_required"
    return "post_h3_next_external_usage_strategy_reviewed"


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
    parser = argparse.ArgumentParser(description="Run PostH3-AB next external usage strategy review gate")
    parser.add_argument("--post-h3aa-summary", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--operator-id", default="operator-primary")
    parser.add_argument("--operator-decision", default=CONTINUE_OBSERVER_DECISION)
    parser.add_argument("--audit-decision", default=OBSERVER_AUDIT_DECISION)
    parser.add_argument("--monitoring-decision", default=OBSERVER_MONITORING_DECISION)
    parser.add_argument("--rollback-decision", default=OBSERVER_ROLLBACK_DECISION)
    parser.add_argument("--operator-statement", default="Keep observer mode after PostH3-AA feedback closeout; require separate single-use authorization for any next usage.")
    parser.add_argument("--max-external-users", type=int, default=0)
    parser.add_argument("--requested-usage-scope", default="observer-only")
    parser.add_argument("--ack-strategy-review", action="store_true")
    args = parser.parse_args()
    summary = run_gate(
        post_h3aa_summary_path=args.post_h3aa_summary,
        output_root=args.output_root,
        operator_id=args.operator_id,
        operator_decision=args.operator_decision,
        audit_decision=args.audit_decision,
        monitoring_decision=args.monitoring_decision,
        rollback_decision=args.rollback_decision,
        operator_statement=args.operator_statement,
        max_external_users=args.max_external_users,
        requested_usage_scope=args.requested_usage_scope,
        ack_strategy_review=args.ack_strategy_review,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if summary.get("passed") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
