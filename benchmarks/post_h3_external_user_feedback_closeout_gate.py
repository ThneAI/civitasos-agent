"""Close out the PostH3 external-user feedback-only collection.

PostH3-AA consumes PostH3-Z feedback collection evidence. It writes a
hash-bound feedback closeout packet and prepares a separate strategy review
input. It does not authorize another external user usage, collect another
feedback record, open public ingress, start runtime workers, execute runtime
tasks, contact VMs, deploy, access production data, write production runtime
receipts, or write source/Git state.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from benchmarks.i_gate_evidence import artifact_ref, check, object_value, read_json_object, sha256_file, sha256_json, write_json_object
from benchmarks.post_h3_external_user_feedback_collection_gate import (
    AUTHORIZATION_CONSUMPTION_SCHEMA as POST_H3Z_AUTHORIZATION_CONSUMPTION_SCHEMA,
    BOUNDARY_REPORT_SCHEMA as POST_H3Z_BOUNDARY_REPORT_SCHEMA,
    CHAIN_SCHEMA as POST_H3Z_SCHEMA,
    FEEDBACK_RECEIPT_SCHEMA as POST_H3Z_FEEDBACK_RECEIPT_SCHEMA,
    MONITORING_ROLLBACK_RECEIPT_SCHEMA as POST_H3Z_MONITORING_ROLLBACK_RECEIPT_SCHEMA,
    OWNER_AUDIT_RECONCILIATION_SCHEMA as POST_H3Z_OWNER_AUDIT_RECONCILIATION_SCHEMA,
)

CHAIN_SCHEMA = "post-h3-external-user-feedback-closeout-chain:v1"
CONTEXT_SCHEMA = "post-h3aa-post-h3z-context-validation:v1"
EVIDENCE_INDEX_SCHEMA = "post-h3aa-external-user-feedback-evidence-index:v1"
CLOSEOUT_RECONCILIATION_SCHEMA = "post-h3aa-external-user-feedback-closeout-reconciliation:v1"
BOUNDARY_REPORT_SCHEMA = "post-h3aa-external-user-feedback-closeout-boundary-report:v1"

ACCEPTED_OPERATOR_DECISION = "close_post_h3z_external_user_feedback_collection"
ACCEPTED_AUDIT_DECISION = "accept_post_h3z_feedback_no_production_boundary"
ACCEPTED_MONITORING_DECISION = "accept_post_h3z_feedback_monitoring_receipt"
ACCEPTED_ROLLBACK_DECISION = "accept_post_h3z_feedback_no_rollback_required"
NON_CLAIMS = (
    "post_h3aa_closes_feedback_only_collection_only",
    "post_h3aa_does_not_authorize_second_external_user_usage",
    "post_h3aa_does_not_collect_additional_feedback",
    "post_h3aa_does_not_open_public_ingress",
    "post_h3aa_does_not_start_runtime_workers",
    "post_h3aa_does_not_execute_runtime_task",
    "post_h3aa_does_not_contact_vm_targets",
    "post_h3aa_does_not_deploy",
    "post_h3aa_does_not_access_production_data",
    "post_h3aa_does_not_write_production_runtime_receipts",
    "post_h3aa_does_not_write_source_or_git",
)


def run_gate(
    *,
    post_h3z_summary_path: Path,
    output_root: Path,
    operator_id: str = "operator-primary",
    operator_decision: str = ACCEPTED_OPERATOR_DECISION,
    audit_decision: str = ACCEPTED_AUDIT_DECISION,
    monitoring_decision: str = ACCEPTED_MONITORING_DECISION,
    rollback_decision: str = ACCEPTED_ROLLBACK_DECISION,
    operator_statement: str = "Close PostH3-Z feedback-only collection and require a separate strategy review before any next usage.",
    ack_feedback_closeout: bool = False,
) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "context_validation": output_root / "post_h3aa_post_h3z_context_validation.json",
        "evidence_index": output_root / "post_h3aa_external_user_feedback_evidence_index.json",
        "closeout_reconciliation": output_root / "post_h3aa_external_user_feedback_closeout_reconciliation.json",
        "boundary_report": output_root / "post_h3aa_external_user_feedback_closeout_boundary_report.json",
        "summary": output_root / "post_h3aa_external_user_feedback_closeout_summary.json",
    }
    context = validate_post_h3z_context(post_h3z_summary_path, output=artifacts["context_validation"])
    evidence_index = _write_evidence_index(context=context, post_h3z_summary_path=post_h3z_summary_path, output=artifacts["evidence_index"])
    reconciliation = _write_reconciliation(
        evidence_index_path=artifacts["evidence_index"],
        output=artifacts["closeout_reconciliation"],
        operator_id=operator_id,
        operator_decision=operator_decision,
        audit_decision=audit_decision,
        monitoring_decision=monitoring_decision,
        rollback_decision=rollback_decision,
        operator_statement=operator_statement,
        ack_feedback_closeout=ack_feedback_closeout,
    )
    boundary = _write_boundary_report(context=context, reconciliation_path=artifacts["closeout_reconciliation"], output=artifacts["boundary_report"])
    reports = [context, evidence_index, reconciliation, boundary]
    passed = all(report.get("passed") is True for report in reports)
    feedback = object_value(context.get("feedback_receipt"))
    monitoring = object_value(context.get("monitoring_rollback_receipt"))
    summary = {
        "schema_version": CHAIN_SCHEMA,
        "passed": passed,
        "failure_reasons": _failures(reports),
        "checked_at": _now(),
        "source_artifacts": {"post_h3z_summary": artifact_ref(post_h3z_summary_path)},
        "artifacts": {name: artifact_ref(path) for name, path in artifacts.items() if name != "summary"},
        "external_user_feedback_closeout_id": reconciliation.get("external_user_feedback_closeout_id"),
        "external_user_feedback_collection_id": feedback.get("external_user_feedback_collection_id"),
        "external_user_feedback_receipt_id": feedback.get("external_user_feedback_receipt_id"),
        "monitoring_receipt_id": monitoring.get("monitoring_receipt_id"),
        "rollback_abort_receipt_id": monitoring.get("rollback_abort_receipt_id"),
        "readiness": {
            "state": "post_h3_external_user_feedback_closed" if passed else "blocked_post_h3_external_user_feedback_closeout",
            "external_user_feedback_closeout_complete": passed,
            "post_h3z_feedback_closed": passed,
            "post_h3z_feedback_evidence_index_complete": evidence_index.get("passed") is True,
            "post_feedback_reconciliation_complete": reconciliation.get("passed") is True,
            "next_external_usage_strategy_review_input_ready": passed,
            "external_user_feedback_collection_allowed": False,
            "external_user_usage_allowed": False,
            "second_external_user_usage_execution_ready": False,
            "external_public_ingress_opened": False,
            "runtime_execution_performed": False,
            "production_runtime_receipt_write_allowed": False,
        },
        "boundary": _boundary(
            context_validation_written=context.get("passed") is True,
            evidence_index_written=evidence_index.get("passed") is True,
            closeout_reconciliation_written=reconciliation.get("passed") is True,
            boundary_report_written=boundary.get("passed") is True,
            external_user_feedback_closeout_complete=passed,
            post_h3z_feedback_previously_collected=passed,
            next_external_usage_strategy_review_input_ready=passed,
        ),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(artifacts["summary"], summary)
    return summary


def validate_post_h3z_context(post_h3z_summary_path: Path, *, output: Path | None = None) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    try:
        summary = read_json_object(post_h3z_summary_path)
    except Exception as exc:  # noqa: BLE001
        return _write_optional(_report(CONTEXT_SCHEMA, False, [f"post_h3z_summary_unreadable:{exc}"], checks), output)
    artifacts = object_value(summary.get("artifacts"))
    authorization_consumption = _read_verified_ref(artifacts.get("authorization_consumption"), checks, failures, "post_h3z_authorization_consumption")
    feedback_receipt = _read_verified_ref(artifacts.get("feedback_receipt"), checks, failures, "post_h3z_feedback_receipt")
    monitoring_rollback_receipt = _read_verified_ref(artifacts.get("monitoring_rollback_receipt"), checks, failures, "post_h3z_monitoring_rollback_receipt")
    owner_audit_reconciliation = _read_verified_ref(artifacts.get("owner_audit_reconciliation"), checks, failures, "post_h3z_owner_audit_reconciliation")
    boundary_report = _read_verified_ref(artifacts.get("boundary_report"), checks, failures, "post_h3z_boundary_report")
    _check_z_summary(summary, checks, failures)
    _check_authorization_consumption(authorization_consumption, checks, failures)
    _check_feedback_receipt(summary, feedback_receipt, checks, failures)
    _check_monitoring_rollback_receipt(monitoring_rollback_receipt, checks, failures)
    _check_owner_audit_reconciliation(owner_audit_reconciliation, checks, failures)
    _check_boundary_report(boundary_report, checks, failures)
    passed = _passed(checks, failures)
    report = {
        "schema_version": CONTEXT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "post_h3z_summary": summary,
        "authorization_consumption": authorization_consumption,
        "feedback_receipt": feedback_receipt,
        "monitoring_rollback_receipt": monitoring_rollback_receipt,
        "owner_audit_reconciliation": owner_audit_reconciliation,
        "boundary_report": boundary_report,
        "source_artifacts": {"post_h3z_summary": artifact_ref(post_h3z_summary_path)},
        "boundary": _boundary(context_validation_written=passed, post_h3z_feedback_previously_collected=passed),
        "non_claims": list(NON_CLAIMS),
    }
    return _write_optional(report, output)


def _write_evidence_index(*, context: dict[str, Any], post_h3z_summary_path: Path, output: Path) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    summary = object_value(context.get("post_h3z_summary"))
    feedback = object_value(context.get("feedback_receipt"))
    monitoring = object_value(context.get("monitoring_rollback_receipt"))
    reconciliation = object_value(context.get("owner_audit_reconciliation"))
    boundary = object_value(context.get("boundary_report"))
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "feedback_receipt_present", bool(feedback.get("external_user_feedback_receipt_id")))
    check(checks, failures, "feedback_collection_id_present", bool(feedback.get("external_user_feedback_collection_id")))
    check(checks, failures, "feedback_text_hash_present", bool(feedback.get("feedback_text_sha256")))
    check(checks, failures, "monitoring_receipt_present", bool(monitoring.get("monitoring_receipt_id")))
    check(checks, failures, "rollback_abort_receipt_present", bool(monitoring.get("rollback_abort_receipt_id")))
    check(checks, failures, "owner_audit_reconciliation_present", reconciliation.get("passed") is True)
    check(checks, failures, "boundary_report_present", boundary.get("passed") is True)
    passed = _passed(checks, failures)
    artifact_paths = _paths_from_z_artifacts(summary)
    evidence_index = {
        "schema_version": EVIDENCE_INDEX_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "written_at": _now(),
        "evidence_index_id": f"post-h3aa-feedback-evidence-index:{sha256_json([artifact_ref(post_h3z_summary_path), feedback.get('external_user_feedback_receipt_id')])[:24]}",
        "external_user_feedback_collection_id": feedback.get("external_user_feedback_collection_id"),
        "external_user_feedback_receipt_id": feedback.get("external_user_feedback_receipt_id"),
        "feedback_text_sha256": feedback.get("feedback_text_sha256"),
        "monitoring_receipt_id": monitoring.get("monitoring_receipt_id"),
        "rollback_abort_receipt_id": monitoring.get("rollback_abort_receipt_id"),
        "owner_decision": reconciliation.get("owner_decision"),
        "audit_decision": reconciliation.get("audit_decision"),
        "rollback_decision": reconciliation.get("rollback_decision"),
        "evidence_refs": {name: artifact_ref(path) for name, path in artifact_paths.items() if path.is_file()},
        "source_artifacts": {"post_h3z_summary": artifact_ref(post_h3z_summary_path)},
        "readiness": {
            "post_h3z_feedback_evidence_index_complete": passed,
            "post_feedback_reconciliation_input_ready": passed,
            "next_external_usage_strategy_review_input_ready": passed,
            "external_user_feedback_collection_allowed": False,
            "external_user_usage_allowed": False,
            "second_limited_usage_authorized": False,
        },
        "boundary": _boundary(evidence_index_written=passed, post_h3z_feedback_previously_collected=passed, next_external_usage_strategy_review_input_ready=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, evidence_index)
    return evidence_index


def _write_reconciliation(
    *,
    evidence_index_path: Path,
    output: Path,
    operator_id: str,
    operator_decision: str,
    audit_decision: str,
    monitoring_decision: str,
    rollback_decision: str,
    operator_statement: str,
    ack_feedback_closeout: bool,
) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    evidence_index = read_json_object(evidence_index_path)
    check(checks, failures, "evidence_index_passed", evidence_index.get("schema_version") == EVIDENCE_INDEX_SCHEMA and evidence_index.get("passed") is True)
    check(checks, failures, "operator_id_present", bool(operator_id.strip()))
    check(checks, failures, "operator_decision_accepted", operator_decision == ACCEPTED_OPERATOR_DECISION)
    check(checks, failures, "audit_decision_accepted", audit_decision == ACCEPTED_AUDIT_DECISION)
    check(checks, failures, "monitoring_decision_accepted", monitoring_decision == ACCEPTED_MONITORING_DECISION)
    check(checks, failures, "rollback_decision_accepted", rollback_decision == ACCEPTED_ROLLBACK_DECISION)
    check(checks, failures, "operator_statement_present", bool(operator_statement.strip()))
    check(checks, failures, "explicit_operator_ack", ack_feedback_closeout is True)
    passed = _passed(checks, failures)
    reconciliation = {
        "schema_version": CLOSEOUT_RECONCILIATION_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "closed_at": _now(),
        "external_user_feedback_closeout_id": f"post-h3aa-feedback-closeout:{sha256_json([artifact_ref(evidence_index_path), operator_id, operator_decision, audit_decision, monitoring_decision, rollback_decision])[:24]}",
        "operator_id": operator_id,
        "operator_decision": operator_decision,
        "audit_decision": audit_decision,
        "monitoring_decision": monitoring_decision,
        "rollback_decision": rollback_decision,
        "operator_statement": operator_statement,
        "operator_statement_sha256": sha256_json(operator_statement),
        "ack_feedback_closeout": ack_feedback_closeout,
        "source_artifacts": {"evidence_index": artifact_ref(evidence_index_path)},
        "readiness": {
            "external_user_feedback_closeout_complete": passed,
            "post_h3z_feedback_closed": passed,
            "next_external_usage_strategy_review_input_ready": passed,
            "external_user_feedback_collection_allowed": False,
            "external_user_usage_allowed": False,
            "second_limited_usage_authorized": False,
        },
        "boundary": _boundary(closeout_reconciliation_written=passed, external_user_feedback_closeout_complete=passed, next_external_usage_strategy_review_input_ready=passed),
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
    check(checks, failures, "feedback_closed", ready.get("post_h3z_feedback_closed") is True)
    check(checks, failures, "next_strategy_review_ready", ready.get("next_external_usage_strategy_review_input_ready") is True)
    check(checks, failures, "external_user_usage_not_allowed", ready.get("external_user_usage_allowed") is False)
    check(checks, failures, "second_usage_not_authorized", ready.get("second_limited_usage_authorized") is False)
    check(checks, failures, "feedback_collection_not_reauthorized", ready.get("external_user_feedback_collection_allowed") is False)
    passed = _passed(checks, failures)
    report = {
        "schema_version": BOUNDARY_REPORT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "source_artifacts": {"closeout_reconciliation": artifact_ref(reconciliation_path)},
        "boundary": _boundary(
            boundary_report_written=passed,
            external_user_feedback_closeout_complete=passed,
            post_h3z_feedback_previously_collected=passed,
            feedback_collection_endpoint_currently_open=False,
            next_external_usage_strategy_review_input_ready=passed,
        ),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def _check_z_summary(summary: dict[str, Any], checks: dict[str, bool], failures: list[str]) -> None:
    readiness = object_value(summary.get("readiness"))
    boundary = object_value(summary.get("boundary"))
    check(checks, failures, "post_h3z_schema_valid", summary.get("schema_version") == POST_H3Z_SCHEMA)
    check(checks, failures, "post_h3z_passed", summary.get("passed") is True)
    check(checks, failures, "post_h3z_feedback_complete", readiness.get("external_user_feedback_collection_complete") is True)
    check(checks, failures, "post_h3z_authorization_consumed", readiness.get("feedback_authorization_consumed") is True)
    check(checks, failures, "post_h3z_feedback_receipt_written", readiness.get("feedback_receipt_written") is True)
    check(checks, failures, "post_h3z_monitoring_written", readiness.get("monitoring_receipt_written") is True)
    check(checks, failures, "post_h3z_rollback_written", readiness.get("rollback_abort_receipt_written") is True)
    check(checks, failures, "post_h3z_owner_audit_reconciled", readiness.get("owner_audit_reconciliation_complete") is True)
    check(checks, failures, "post_h3z_usage_not_allowed", readiness.get("external_user_usage_allowed") is False)
    check(checks, failures, "post_h3z_second_usage_not_ready", readiness.get("second_external_user_usage_execution_ready") is False)
    check(checks, failures, "post_h3z_runtime_not_executed", readiness.get("runtime_execution_performed") is False)
    check(checks, failures, "post_h3z_no_production_receipt_write", readiness.get("production_runtime_receipt_write_allowed") is False)
    check(checks, failures, "post_h3z_boundary_feedback_collected", boundary.get("external_user_feedback_collected") is True)
    check(checks, failures, "post_h3z_boundary_feedback_receipt_written", boundary.get("feedback_receipt_written") is True)
    _check_no_side_effect_boundary("post_h3z", boundary, checks, failures)


def _check_authorization_consumption(consumption: dict[str, Any], checks: dict[str, bool], failures: list[str]) -> None:
    check(checks, failures, "authorization_consumption_schema_valid", consumption.get("schema_version") == POST_H3Z_AUTHORIZATION_CONSUMPTION_SCHEMA)
    check(checks, failures, "authorization_consumption_passed", consumption.get("passed") is True)
    check(checks, failures, "authorization_single_use", consumption.get("single_use_consumption") is True)
    check(checks, failures, "authorization_ack_present", consumption.get("ack_feedback_collection") is True)


def _check_feedback_receipt(summary: dict[str, Any], receipt: dict[str, Any], checks: dict[str, bool], failures: list[str]) -> None:
    readiness = object_value(receipt.get("readiness"))
    receipt_checks = object_value(receipt.get("checks"))
    check(checks, failures, "feedback_receipt_schema_valid", receipt.get("schema_version") == POST_H3Z_FEEDBACK_RECEIPT_SCHEMA)
    check(checks, failures, "feedback_receipt_passed", receipt.get("passed") is True)
    check(checks, failures, "feedback_collection_id_matches", receipt.get("external_user_feedback_collection_id") == summary.get("external_user_feedback_collection_id"))
    check(checks, failures, "feedback_receipt_id_matches", receipt.get("external_user_feedback_receipt_id") == summary.get("external_user_feedback_receipt_id"))
    check(checks, failures, "feedback_handle_present", bool(receipt.get("external_user_handle")))
    check(checks, failures, "feedback_scope_present", bool(receipt.get("feedback_scope")))
    check(checks, failures, "feedback_source_present", bool(receipt.get("feedback_source")))
    check(checks, failures, "feedback_text_hash_present", bool(receipt.get("feedback_text_sha256")))
    check(checks, failures, "feedback_no_forbidden_tokens", receipt_checks.get("feedback_has_no_forbidden_tokens") is True)
    check(checks, failures, "feedback_collected", readiness.get("external_user_feedback_collected") is True)
    check(checks, failures, "feedback_collection_closed", readiness.get("external_user_feedback_collection_closed") is True)
    check(checks, failures, "feedback_runtime_not_executed", readiness.get("runtime_execution_performed") is False)
    check(checks, failures, "feedback_no_production_receipt_write", readiness.get("production_runtime_receipt_write_allowed") is False)


def _check_monitoring_rollback_receipt(receipt: dict[str, Any], checks: dict[str, bool], failures: list[str]) -> None:
    readiness = object_value(receipt.get("readiness"))
    check(checks, failures, "monitoring_rollback_schema_valid", receipt.get("schema_version") == POST_H3Z_MONITORING_ROLLBACK_RECEIPT_SCHEMA)
    check(checks, failures, "monitoring_rollback_passed", receipt.get("passed") is True)
    check(checks, failures, "monitoring_receipt_present", bool(receipt.get("monitoring_receipt_id")))
    check(checks, failures, "rollback_abort_receipt_present", bool(receipt.get("rollback_abort_receipt_id")))
    check(checks, failures, "monitoring_owner_present", bool(receipt.get("monitoring_owner")))
    check(checks, failures, "audit_owner_present", bool(receipt.get("audit_owner")))
    check(checks, failures, "rollback_owner_present", bool(receipt.get("rollback_owner")))
    check(checks, failures, "abort_not_required", receipt.get("abort_required") is False)
    check(checks, failures, "rollback_not_required", receipt.get("rollback_required") is False)
    check(checks, failures, "monitoring_receipt_written", readiness.get("monitoring_receipt_written") is True)
    check(checks, failures, "rollback_abort_receipt_written", readiness.get("rollback_abort_receipt_written") is True)


def _check_owner_audit_reconciliation(reconciliation: dict[str, Any], checks: dict[str, bool], failures: list[str]) -> None:
    readiness = object_value(reconciliation.get("readiness"))
    check(checks, failures, "owner_audit_schema_valid", reconciliation.get("schema_version") == POST_H3Z_OWNER_AUDIT_RECONCILIATION_SCHEMA)
    check(checks, failures, "owner_audit_passed", reconciliation.get("passed") is True)
    check(checks, failures, "owner_decision_accepts_z", reconciliation.get("owner_decision") == "accept_post_h3z_external_user_feedback_collection")
    check(checks, failures, "audit_decision_accepts_boundary", reconciliation.get("audit_decision") == "accept_post_h3z_no_production_boundary")
    check(checks, failures, "rollback_decision_continue", reconciliation.get("rollback_decision") == "continue_after_post_h3z_no_rollback_required")
    check(checks, failures, "owner_audit_reconciliation_complete", readiness.get("owner_audit_reconciliation_complete") is True)
    check(checks, failures, "feedback_collection_closed", readiness.get("external_user_feedback_collection_closed") is True)


def _check_boundary_report(report: dict[str, Any], checks: dict[str, bool], failures: list[str]) -> None:
    boundary = object_value(report.get("boundary"))
    check(checks, failures, "boundary_report_schema_valid", report.get("schema_version") == POST_H3Z_BOUNDARY_REPORT_SCHEMA and report.get("passed") is True)
    check(checks, failures, "boundary_feedback_collected", boundary.get("external_user_feedback_collected") is True)
    _check_no_side_effect_boundary("boundary_report", boundary, checks, failures)


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


def _read_verified_ref(value: Any, checks: dict[str, bool], failures: list[str], label: str) -> dict[str, Any]:
    ref = object_value(value)
    path = Path(str(ref.get("path") or ""))
    expected_hash = str(ref.get("sha256") or "")
    check(checks, failures, f"{label}_path_present", path.is_file())
    if not path.is_file():
        return {}
    check(checks, failures, f"{label}_hash_valid", bool(expected_hash) and sha256_file(path) == expected_hash)
    return read_json_object(path)


def _paths_from_z_artifacts(summary: dict[str, Any]) -> dict[str, Path]:
    artifacts = object_value(summary.get("artifacts"))
    paths: dict[str, Path] = {}
    for name in ("authorization_consumption", "feedback_receipt", "monitoring_rollback_receipt", "owner_audit_reconciliation", "boundary_report"):
        ref = object_value(artifacts.get(name))
        paths[name] = Path(str(ref.get("path") or ""))
    return paths


def _boundary(**overrides: bool) -> dict[str, bool]:
    boundary = {
        "context_validation_written": False,
        "evidence_index_written": False,
        "closeout_reconciliation_written": False,
        "boundary_report_written": False,
        "external_user_feedback_closeout_complete": False,
        "post_h3z_feedback_previously_collected": False,
        "feedback_collection_endpoint_currently_open": False,
        "next_external_usage_strategy_review_input_ready": False,
        "external_user_feedback_collection_allowed": False,
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
    parser = argparse.ArgumentParser(description="Run PostH3-AA external user feedback closeout gate")
    parser.add_argument("--post-h3z-summary", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--operator-id", default="operator-primary")
    parser.add_argument("--operator-decision", default=ACCEPTED_OPERATOR_DECISION)
    parser.add_argument("--audit-decision", default=ACCEPTED_AUDIT_DECISION)
    parser.add_argument("--monitoring-decision", default=ACCEPTED_MONITORING_DECISION)
    parser.add_argument("--rollback-decision", default=ACCEPTED_ROLLBACK_DECISION)
    parser.add_argument("--operator-statement", default="Close PostH3-Z feedback-only collection and require a separate strategy review before any next usage.")
    parser.add_argument("--ack-feedback-closeout", action="store_true")
    args = parser.parse_args()
    summary = run_gate(
        post_h3z_summary_path=args.post_h3z_summary,
        output_root=args.output_root,
        operator_id=args.operator_id,
        operator_decision=args.operator_decision,
        audit_decision=args.audit_decision,
        monitoring_decision=args.monitoring_decision,
        rollback_decision=args.rollback_decision,
        operator_statement=args.operator_statement,
        ack_feedback_closeout=args.ack_feedback_closeout,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if summary.get("passed") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
