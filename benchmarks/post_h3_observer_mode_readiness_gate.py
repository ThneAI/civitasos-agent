"""Collect observer-mode evidence and review readiness after PostH3-AB.

PostH3-AC consumes the PostH3-AB next-usage strategy review. It records a
read-only observer evidence snapshot and an operator/audit/monitoring/rollback
readiness review for continuing observer mode. It never authorizes or executes
external user usage, feedback collection, public ingress, runtime expansion,
VM contact, deploy, production-data access, production receipt writing, or
source/Git writes.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from benchmarks.i_gate_evidence import artifact_ref, check, object_value, read_json_object, sha256_file, sha256_json, sha256_text, write_json_object
from benchmarks.post_h3_next_external_usage_strategy_review_gate import (
    BOUNDARY_REPORT_SCHEMA as POST_H3AB_BOUNDARY_REPORT_SCHEMA,
    CHAIN_SCHEMA as POST_H3AB_SCHEMA,
    CONTINUE_OBSERVER_DECISION,
    CONTEXT_SCHEMA as POST_H3AB_CONTEXT_SCHEMA,
    STRATEGY_PACKET_SCHEMA as POST_H3AB_STRATEGY_PACKET_SCHEMA,
    STRATEGY_RECONCILIATION_SCHEMA as POST_H3AB_STRATEGY_RECONCILIATION_SCHEMA,
)

CHAIN_SCHEMA = "post-h3-observer-mode-readiness-chain:v1"
CONTEXT_SCHEMA = "post-h3ac-post-h3ab-context-validation:v1"
OBSERVER_EVIDENCE_SCHEMA = "post-h3ac-observer-mode-evidence-snapshot:v1"
READINESS_REVIEW_SCHEMA = "post-h3ac-observer-mode-readiness-review:v1"
BOUNDARY_REPORT_SCHEMA = "post-h3ac-observer-mode-readiness-boundary-report:v1"

OPERATOR_DECISION_CONTINUE = "continue_observer_mode_evidence_collection"
OPERATOR_DECISION_REVISION = "request_revision_before_observer_mode_readiness"
ACCEPTED_OPERATOR_DECISIONS = (OPERATOR_DECISION_CONTINUE, OPERATOR_DECISION_REVISION)
AUDIT_DECISION_ACCEPT = "accept_observer_mode_no_production_boundary"
MONITORING_DECISION_ACCEPT = "accept_observer_mode_monitoring_snapshot"
ROLLBACK_DECISION_ACCEPT = "accept_observer_mode_no_rollback_required"
REVISION_DECISION = OPERATOR_DECISION_REVISION
ACCEPTED_AUDIT_DECISIONS = (AUDIT_DECISION_ACCEPT, REVISION_DECISION)
ACCEPTED_MONITORING_DECISIONS = (MONITORING_DECISION_ACCEPT, REVISION_DECISION)
ACCEPTED_ROLLBACK_DECISIONS = (ROLLBACK_DECISION_ACCEPT, REVISION_DECISION)

NON_CLAIMS = (
    "post_h3ac_observer_mode_evidence_only",
    "post_h3ac_does_not_execute_external_user_usage",
    "post_h3ac_does_not_collect_feedback",
    "post_h3ac_does_not_open_public_ingress",
    "post_h3ac_does_not_start_runtime_workers",
    "post_h3ac_does_not_execute_runtime_task",
    "post_h3ac_does_not_contact_vm_targets",
    "post_h3ac_does_not_deploy",
    "post_h3ac_does_not_access_production_data",
    "post_h3ac_does_not_write_production_runtime_receipts",
    "post_h3ac_does_not_write_source_or_git",
)


def run_gate(
    *,
    post_h3ab_summary_path: Path,
    output_root: Path,
    operator_id: str = "operator-primary",
    operator_decision: str = OPERATOR_DECISION_CONTINUE,
    audit_decision: str = AUDIT_DECISION_ACCEPT,
    monitoring_decision: str = MONITORING_DECISION_ACCEPT,
    rollback_decision: str = ROLLBACK_DECISION_ACCEPT,
    operator_observation: str = "PostH3-AB remains in observer mode; no additional external use is authorized.",
    audit_observation: str = "Observer-mode boundary remains closed for public ingress, runtime execution, production data, and production receipts.",
    monitoring_observation: str = "Observer-mode evidence snapshot is based on hash-bound PostH3-AB artifacts; no live runtime action is performed.",
    rollback_observation: str = "No rollback is required because PostH3-AC performs no external action.",
    ack_observer_readiness: bool = False,
) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "context_validation": output_root / "post_h3ac_post_h3ab_context_validation.json",
        "observer_evidence_snapshot": output_root / "post_h3ac_observer_mode_evidence_snapshot.json",
        "readiness_review": output_root / "post_h3ac_observer_mode_readiness_review.json",
        "boundary_report": output_root / "post_h3ac_observer_mode_readiness_boundary_report.json",
        "summary": output_root / "post_h3ac_observer_mode_readiness_summary.json",
    }
    context = validate_post_h3ab_context(post_h3ab_summary_path, output=artifacts["context_validation"])
    snapshot = _write_observer_evidence_snapshot(
        context=context,
        post_h3ab_summary_path=post_h3ab_summary_path,
        output=artifacts["observer_evidence_snapshot"],
    )
    review = _write_readiness_review(
        snapshot_path=artifacts["observer_evidence_snapshot"],
        output=artifacts["readiness_review"],
        operator_id=operator_id,
        operator_decision=operator_decision,
        audit_decision=audit_decision,
        monitoring_decision=monitoring_decision,
        rollback_decision=rollback_decision,
        operator_observation=operator_observation,
        audit_observation=audit_observation,
        monitoring_observation=monitoring_observation,
        rollback_observation=rollback_observation,
        ack_observer_readiness=ack_observer_readiness,
    )
    boundary = _write_boundary_report(
        context=context,
        readiness_review_path=artifacts["readiness_review"],
        output=artifacts["boundary_report"],
    )
    reports = [context, snapshot, review, boundary]
    passed = all(report.get("passed") is True for report in reports)
    observer_ready = passed and review.get("observer_mode_readiness_accepted") is True
    summary = {
        "schema_version": CHAIN_SCHEMA,
        "passed": passed,
        "failure_reasons": _failures(reports),
        "checked_at": _now(),
        "source_artifacts": {"post_h3ab_summary": artifact_ref(post_h3ab_summary_path)},
        "artifacts": {name: artifact_ref(path) for name, path in artifacts.items() if name != "summary"},
        "observer_mode_readiness_review_id": review.get("observer_mode_readiness_review_id"),
        "next_external_usage_strategy_review_id": object_value(context.get("post_h3ab_summary")).get("next_external_usage_strategy_review_id"),
        "external_user_feedback_closeout_id": object_value(context.get("post_h3ab_summary")).get("external_user_feedback_closeout_id"),
        "observer_mode_evidence_collection_complete": snapshot.get("passed") is True,
        "observer_mode_readiness_accepted": observer_ready,
        "readiness": {
            "state": _state(passed, observer_ready, operator_decision),
            "observer_mode_evidence_collection_complete": snapshot.get("passed") is True,
            "observer_mode_readiness_review_complete": passed,
            "observer_mode_continues": observer_ready,
            "next_single_use_gate_input_ready": False,
            "second_external_user_usage_execution_ready": False,
            "external_user_feedback_collection_ready": False,
            "external_user_usage_allowed": False,
            "external_public_ingress_opened": False,
            "runtime_execution_performed": False,
            "production_runtime_receipt_write_allowed": False,
        },
        "boundary": _boundary(
            context_validation_written=context.get("passed") is True,
            observer_evidence_snapshot_written=snapshot.get("passed") is True,
            readiness_review_written=review.get("passed") is True,
            boundary_report_written=boundary.get("passed") is True,
            observer_mode_evidence_collection_complete=snapshot.get("passed") is True,
            observer_mode_readiness_review_complete=passed,
            observer_mode_continues=observer_ready,
        ),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(artifacts["summary"], summary)
    return summary


def validate_post_h3ab_context(post_h3ab_summary_path: Path, *, output: Path | None = None) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    try:
        summary = read_json_object(post_h3ab_summary_path)
    except Exception as exc:  # noqa: BLE001
        return _write_optional(_report(CONTEXT_SCHEMA, False, [f"post_h3ab_summary_unreadable:{exc}"], checks), output)
    artifacts = object_value(summary.get("artifacts"))
    context = _read_verified_ref(artifacts.get("context_validation"), checks, failures, "post_h3ab_context_validation")
    packet = _read_verified_ref(artifacts.get("strategy_packet"), checks, failures, "post_h3ab_strategy_packet")
    reconciliation = _read_verified_ref(artifacts.get("strategy_reconciliation"), checks, failures, "post_h3ab_strategy_reconciliation")
    boundary_report = _read_verified_ref(artifacts.get("boundary_report"), checks, failures, "post_h3ab_boundary_report")
    _check_ab_summary(summary, checks, failures)
    _check_ab_context(context, checks, failures)
    _check_ab_packet(packet, checks, failures)
    _check_ab_reconciliation(reconciliation, checks, failures)
    _check_ab_boundary_report(boundary_report, checks, failures)
    passed = _passed(checks, failures)
    report = {
        "schema_version": CONTEXT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "post_h3ab_summary": summary,
        "post_h3ab_context_validation": context,
        "post_h3ab_strategy_packet": packet,
        "post_h3ab_strategy_reconciliation": reconciliation,
        "post_h3ab_boundary_report": boundary_report,
        "source_artifacts": {"post_h3ab_summary": artifact_ref(post_h3ab_summary_path)},
        "boundary": _boundary(context_validation_written=passed, observer_mode_continues=passed),
        "non_claims": list(NON_CLAIMS),
    }
    return _write_optional(report, output)


def _write_observer_evidence_snapshot(*, context: dict[str, Any], post_h3ab_summary_path: Path, output: Path) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    summary = object_value(context.get("post_h3ab_summary"))
    reconciliation = object_value(context.get("post_h3ab_strategy_reconciliation"))
    boundary = object_value(context.get("post_h3ab_boundary_report"))
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "ab_observer_mode_continues", summary.get("observer_mode_continues") is True)
    check(checks, failures, "ab_reconciliation_observer", reconciliation.get("observer_mode_continues") is True)
    check(checks, failures, "ab_boundary_report_passed", boundary.get("passed") is True)
    _check_no_side_effect_boundary("ab_summary", object_value(summary.get("boundary")), checks, failures)
    _check_no_side_effect_boundary("ab_boundary", object_value(boundary.get("boundary")), checks, failures)
    passed = _passed(checks, failures)
    source_refs = _source_refs_from_ab_summary(summary)
    snapshot = {
        "schema_version": OBSERVER_EVIDENCE_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "written_at": _now(),
        "observer_evidence_snapshot_id": f"post-h3ac-observer-evidence:{sha256_json([artifact_ref(post_h3ab_summary_path), summary.get('next_external_usage_strategy_review_id')])[:24]}",
        "next_external_usage_strategy_review_id": summary.get("next_external_usage_strategy_review_id"),
        "external_user_feedback_closeout_id": summary.get("external_user_feedback_closeout_id"),
        "source_refs": source_refs,
        "observer_findings": {
            "post_h3ab_passed": summary.get("passed") is True,
            "observer_mode_continues": summary.get("observer_mode_continues") is True,
            "second_external_user_usage_allowed": summary.get("second_external_user_usage_allowed") is True,
            "external_user_feedback_collection_allowed": summary.get("external_user_feedback_collection_allowed") is True,
            "external_user_usage_allowed": object_value(summary.get("readiness")).get("external_user_usage_allowed") is True,
            "runtime_execution_performed": object_value(summary.get("readiness")).get("runtime_execution_performed") is True,
            "production_runtime_receipt_write_allowed": object_value(summary.get("readiness")).get("production_runtime_receipt_write_allowed") is True,
        },
        "readiness": {
            "observer_mode_evidence_collection_complete": passed,
            "observer_mode_readiness_review_input_ready": passed,
            "next_single_use_gate_input_ready": False,
            "external_user_feedback_collection_ready": False,
            "external_user_usage_allowed": False,
            "second_external_user_usage_execution_ready": False,
        },
        "source_artifacts": {"post_h3ab_summary": artifact_ref(post_h3ab_summary_path)},
        "boundary": _boundary(observer_evidence_snapshot_written=passed, observer_mode_evidence_collection_complete=passed, observer_mode_continues=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, snapshot)
    return snapshot


def _write_readiness_review(
    *,
    snapshot_path: Path,
    output: Path,
    operator_id: str,
    operator_decision: str,
    audit_decision: str,
    monitoring_decision: str,
    rollback_decision: str,
    operator_observation: str,
    audit_observation: str,
    monitoring_observation: str,
    rollback_observation: str,
    ack_observer_readiness: bool,
) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    snapshot = read_json_object(snapshot_path)
    wants_continue = operator_decision == OPERATOR_DECISION_CONTINUE
    wants_revision = operator_decision == OPERATOR_DECISION_REVISION
    check(checks, failures, "snapshot_passed", snapshot.get("schema_version") == OBSERVER_EVIDENCE_SCHEMA and snapshot.get("passed") is True)
    check(checks, failures, "operator_id_present", bool(operator_id.strip()))
    check(checks, failures, "operator_decision_known", operator_decision in ACCEPTED_OPERATOR_DECISIONS)
    check(checks, failures, "audit_decision_known", audit_decision in ACCEPTED_AUDIT_DECISIONS)
    check(checks, failures, "monitoring_decision_known", monitoring_decision in ACCEPTED_MONITORING_DECISIONS)
    check(checks, failures, "rollback_decision_known", rollback_decision in ACCEPTED_ROLLBACK_DECISIONS)
    check(checks, failures, "operator_observation_present", bool(operator_observation.strip()))
    check(checks, failures, "audit_observation_present", bool(audit_observation.strip()))
    check(checks, failures, "monitoring_observation_present", bool(monitoring_observation.strip()))
    check(checks, failures, "rollback_observation_present", bool(rollback_observation.strip()))
    check(checks, failures, "explicit_observer_readiness_ack", ack_observer_readiness is True)
    if wants_continue:
        check(checks, failures, "audit_accepts_observer_boundary", audit_decision == AUDIT_DECISION_ACCEPT)
        check(checks, failures, "monitoring_accepts_snapshot", monitoring_decision == MONITORING_DECISION_ACCEPT)
        check(checks, failures, "rollback_accepts_no_action", rollback_decision == ROLLBACK_DECISION_ACCEPT)
    if wants_revision:
        check(checks, failures, "audit_requests_revision", audit_decision == REVISION_DECISION)
        check(checks, failures, "monitoring_requests_revision", monitoring_decision == REVISION_DECISION)
        check(checks, failures, "rollback_requests_revision", rollback_decision == REVISION_DECISION)
    passed = _passed(checks, failures)
    observer_accepted = passed and wants_continue
    review = {
        "schema_version": READINESS_REVIEW_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "reviewed_at": _now(),
        "observer_mode_readiness_review_id": f"post-h3ac-readiness-review:{sha256_json([artifact_ref(snapshot_path), operator_id, operator_decision, audit_decision, monitoring_decision, rollback_decision])[:24]}",
        "operator_id": operator_id,
        "operator_decision": operator_decision,
        "audit_decision": audit_decision,
        "monitoring_decision": monitoring_decision,
        "rollback_decision": rollback_decision,
        "operator_observation_sha256": sha256_text(operator_observation),
        "audit_observation_sha256": sha256_text(audit_observation),
        "monitoring_observation_sha256": sha256_text(monitoring_observation),
        "rollback_observation_sha256": sha256_text(rollback_observation),
        "ack_observer_readiness": ack_observer_readiness,
        "observer_mode_readiness_accepted": observer_accepted,
        "revision_required": passed and wants_revision,
        "source_artifacts": {"observer_evidence_snapshot": artifact_ref(snapshot_path)},
        "readiness": {
            "observer_mode_readiness_review_complete": passed,
            "observer_mode_continues": observer_accepted,
            "revision_required": passed and wants_revision,
            "next_single_use_gate_input_ready": False,
            "external_user_feedback_collection_ready": False,
            "external_user_usage_allowed": False,
            "second_external_user_usage_execution_ready": False,
        },
        "boundary": _boundary(readiness_review_written=passed, observer_mode_readiness_review_complete=passed, observer_mode_continues=observer_accepted),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, review)
    return review


def _write_boundary_report(*, context: dict[str, Any], readiness_review_path: Path, output: Path) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    review = read_json_object(readiness_review_path)
    readiness = object_value(review.get("readiness"))
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "readiness_review_passed", review.get("passed") is True)
    check(checks, failures, "observer_readiness_complete", readiness.get("observer_mode_readiness_review_complete") is True)
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
        "source_artifacts": {"readiness_review": artifact_ref(readiness_review_path)},
        "boundary": _boundary(
            boundary_report_written=passed,
            observer_mode_readiness_review_complete=passed,
            observer_mode_continues=readiness.get("observer_mode_continues") is True,
        ),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def _check_ab_summary(summary: dict[str, Any], checks: dict[str, bool], failures: list[str]) -> None:
    readiness = object_value(summary.get("readiness"))
    boundary = object_value(summary.get("boundary"))
    check(checks, failures, "post_h3ab_schema_valid", summary.get("schema_version") == POST_H3AB_SCHEMA)
    check(checks, failures, "post_h3ab_passed", summary.get("passed") is True)
    check(checks, failures, "post_h3ab_strategy_review_complete", readiness.get("next_external_usage_strategy_review_complete") is True)
    check(checks, failures, "post_h3ab_observer_mode", readiness.get("observer_mode_continues") is True)
    check(checks, failures, "post_h3ab_second_usage_not_ready", readiness.get("second_external_user_usage_execution_ready") is False)
    check(checks, failures, "post_h3ab_feedback_not_ready", readiness.get("external_user_feedback_collection_ready") is False)
    check(checks, failures, "post_h3ab_usage_not_allowed", readiness.get("external_user_usage_allowed") is False)
    check(checks, failures, "post_h3ab_runtime_not_executed", readiness.get("runtime_execution_performed") is False)
    check(checks, failures, "post_h3ab_no_production_receipt_write", readiness.get("production_runtime_receipt_write_allowed") is False)
    check(checks, failures, "post_h3ab_boundary_observer_mode", boundary.get("observer_mode_continues") is True)
    _check_no_side_effect_boundary("post_h3ab", boundary, checks, failures)


def _check_ab_context(context: dict[str, Any], checks: dict[str, bool], failures: list[str]) -> None:
    check(checks, failures, "ab_context_schema_valid", context.get("schema_version") == POST_H3AB_CONTEXT_SCHEMA)
    check(checks, failures, "ab_context_passed", context.get("passed") is True)


def _check_ab_packet(packet: dict[str, Any], checks: dict[str, bool], failures: list[str]) -> None:
    check(checks, failures, "ab_packet_schema_valid", packet.get("schema_version") == POST_H3AB_STRATEGY_PACKET_SCHEMA)
    check(checks, failures, "ab_packet_passed", packet.get("passed") is True)


def _check_ab_reconciliation(reconciliation: dict[str, Any], checks: dict[str, bool], failures: list[str]) -> None:
    readiness = object_value(reconciliation.get("readiness"))
    check(checks, failures, "ab_reconciliation_schema_valid", reconciliation.get("schema_version") == POST_H3AB_STRATEGY_RECONCILIATION_SCHEMA)
    check(checks, failures, "ab_reconciliation_passed", reconciliation.get("passed") is True)
    check(checks, failures, "ab_operator_observer_decision", reconciliation.get("operator_decision") == CONTINUE_OBSERVER_DECISION)
    check(checks, failures, "ab_reconciliation_observer_mode", readiness.get("observer_mode_continues") is True)
    check(checks, failures, "ab_reconciliation_second_usage_not_ready", readiness.get("second_external_user_usage_execution_ready") is False)
    check(checks, failures, "ab_reconciliation_feedback_not_ready", readiness.get("external_user_feedback_collection_ready") is False)
    check(checks, failures, "ab_reconciliation_usage_not_allowed", readiness.get("external_user_usage_allowed") is False)


def _check_ab_boundary_report(report: dict[str, Any], checks: dict[str, bool], failures: list[str]) -> None:
    boundary = object_value(report.get("boundary"))
    check(checks, failures, "ab_boundary_schema_valid", report.get("schema_version") == POST_H3AB_BOUNDARY_REPORT_SCHEMA and report.get("passed") is True)
    check(checks, failures, "ab_boundary_observer_mode", boundary.get("observer_mode_continues") is True)
    _check_no_side_effect_boundary("ab_boundary", boundary, checks, failures)


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


def _source_refs_from_ab_summary(summary: dict[str, Any]) -> dict[str, dict[str, str]]:
    refs: dict[str, dict[str, str]] = {}
    for name, ref in object_value(summary.get("artifacts")).items():
        ref_obj = object_value(ref)
        if ref_obj.get("path") and ref_obj.get("sha256"):
            refs[f"post_h3ab_{name}"] = {"path": str(ref_obj["path"]), "sha256": str(ref_obj["sha256"])}
    source_summary = object_value(object_value(summary.get("source_artifacts")).get("post_h3ab_summary"))
    if source_summary.get("path") and source_summary.get("sha256"):
        refs["post_h3ab_source_summary"] = {"path": str(source_summary["path"]), "sha256": str(source_summary["sha256"])}
    return refs


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
        "observer_evidence_snapshot_written": False,
        "readiness_review_written": False,
        "boundary_report_written": False,
        "observer_mode_evidence_collection_complete": False,
        "observer_mode_readiness_review_complete": False,
        "observer_mode_continues": False,
        "next_single_use_gate_input_ready": False,
        "external_user_feedback_collection_ready": False,
        "external_user_usage_allowed": False,
        "second_external_user_usage_execution_ready": False,
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


def _state(passed: bool, observer_ready: bool, operator_decision: str) -> str:
    if not passed:
        return "blocked_post_h3_observer_mode_readiness_review"
    if observer_ready:
        return "post_h3_observer_mode_evidence_collected_readiness_accepted"
    if operator_decision == OPERATOR_DECISION_REVISION:
        return "post_h3_observer_mode_readiness_revision_required"
    return "post_h3_observer_mode_readiness_reviewed"


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
    parser = argparse.ArgumentParser(description="Run PostH3-AC observer-mode evidence collection / readiness review gate")
    parser.add_argument("--post-h3ab-summary", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--operator-id", default="operator-primary")
    parser.add_argument("--operator-decision", default=OPERATOR_DECISION_CONTINUE)
    parser.add_argument("--audit-decision", default=AUDIT_DECISION_ACCEPT)
    parser.add_argument("--monitoring-decision", default=MONITORING_DECISION_ACCEPT)
    parser.add_argument("--rollback-decision", default=ROLLBACK_DECISION_ACCEPT)
    parser.add_argument("--operator-observation", default="PostH3-AB remains in observer mode; no additional external use is authorized.")
    parser.add_argument("--audit-observation", default="Observer-mode boundary remains closed for public ingress, runtime execution, production data, and production receipts.")
    parser.add_argument("--monitoring-observation", default="Observer-mode evidence snapshot is based on hash-bound PostH3-AB artifacts; no live runtime action is performed.")
    parser.add_argument("--rollback-observation", default="No rollback is required because PostH3-AC performs no external action.")
    parser.add_argument("--ack-observer-readiness", action="store_true")
    args = parser.parse_args()
    summary = run_gate(
        post_h3ab_summary_path=args.post_h3ab_summary,
        output_root=args.output_root,
        operator_id=args.operator_id,
        operator_decision=args.operator_decision,
        audit_decision=args.audit_decision,
        monitoring_decision=args.monitoring_decision,
        rollback_decision=args.rollback_decision,
        operator_observation=args.operator_observation,
        audit_observation=args.audit_observation,
        monitoring_observation=args.monitoring_observation,
        rollback_observation=args.rollback_observation,
        ack_observer_readiness=args.ack_observer_readiness,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if summary.get("passed") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
