"""Review whether real external user usage can start after PostH3-S closeout.

PostH3-T consumes the PostH3-S Q/R closeout. The default review outcome is a
revision request because Q/R only proved status-only ingress open/close and local
worker heartbeat expansion. The gate can record an explicit one-time allowance,
but it still does not execute usage, open ingress, start workers, deploy, contact
VMs, access production data, or write source/Git.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from benchmarks.i_gate_evidence import artifact_ref, check, object_value, read_json_object, sha256_file, sha256_json, write_json_object
from benchmarks.post_h3_qr_execution_closeout_gate import (
    BOUNDARY_REPORT_SCHEMA as POST_H3S_BOUNDARY_REPORT_SCHEMA,
    CHAIN_SCHEMA as POST_H3S_SCHEMA,
    CLOSEOUT_RECONCILIATION_SCHEMA as POST_H3S_RECONCILIATION_SCHEMA,
)

CHAIN_SCHEMA = "post-h3-external-user-usage-review-chain:v1"
CONTEXT_SCHEMA = "post-h3t-post-h3s-context-validation:v1"
REVIEW_PACKET_SCHEMA = "post-h3t-external-user-usage-review-packet:v1"
REVIEW_RECONCILIATION_SCHEMA = "post-h3t-external-user-usage-review-reconciliation:v1"
BOUNDARY_REPORT_SCHEMA = "post-h3t-external-user-usage-review-boundary-report:v1"

REQUEST_REVISION_DECISION = "request_revision_before_external_user_usage"
AUTHORIZE_ONCE_DECISION = "authorize_limited_external_user_usage_once"
ACCEPTED_AUDIT_DECISIONS = ("request_revision_before_external_user_usage", "accept_limited_external_user_usage_once")
ACCEPTED_MONITORING_DECISIONS = ("request_revision_before_external_user_usage", "accept_limited_external_user_monitoring_once")
ACCEPTED_ROLLBACK_DECISIONS = ("request_revision_before_external_user_usage", "accept_limited_external_user_abort_runbook_once")
DEFAULT_MISSING_REQUIREMENTS = (
    "real_external_user_identity_and_consent_not_bound",
    "production_grade_public_ingress_not_authorized",
    "sustained_runtime_expansion_not_authorized",
    "external_user_task_scope_not_bound",
    "external_user_monitoring_slo_not_bound",
    "external_user_rollback_abort_owner_not_bound",
)
POST_H3U_SCHEMA = "post-h3-external-user-identity-consent-chain:v1"
POST_H3V_SCHEMA = "post-h3-limited-external-usage-scope-binding-chain:v1"
NON_CLAIMS = (
    "post_h3t_reviews_external_user_usage_only",
    "post_h3t_does_not_execute_external_user_usage",
    "post_h3t_does_not_open_public_ingress",
    "post_h3t_does_not_start_runtime_workers",
    "post_h3t_does_not_execute_runtime_task",
    "post_h3t_does_not_contact_vm_targets",
    "post_h3t_does_not_deploy",
    "post_h3t_does_not_access_production_data",
    "post_h3t_does_not_write_source_or_git",
)


def run_gate(
    *,
    post_h3s_summary_path: Path,
    post_h3u_summary_path: Path | None = None,
    post_h3v_summary_path: Path | None = None,
    output_root: Path,
    operator_id: str = "operator-primary",
    operator_decision: str = REQUEST_REVISION_DECISION,
    audit_decision: str = REQUEST_REVISION_DECISION,
    monitoring_decision: str = REQUEST_REVISION_DECISION,
    rollback_decision: str = REQUEST_REVISION_DECISION,
    operator_statement: str = "Request revision before real external user usage; Q/R proved bounded mechanics only.",
    max_external_users: int = 0,
    allowed_usage_scope: str = "none",
    ack_external_user_usage_review: bool = False,
) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "context_validation": output_root / "post_h3t_post_h3s_context_validation.json",
        "review_packet": output_root / "post_h3t_external_user_usage_review_packet.json",
        "review_reconciliation": output_root / "post_h3t_external_user_usage_review_reconciliation.json",
        "boundary_report": output_root / "post_h3t_external_user_usage_review_boundary_report.json",
        "summary": output_root / "post_h3t_external_user_usage_review_summary.json",
    }
    context = validate_post_h3s_context(post_h3s_summary_path, output=artifacts["context_validation"])
    packet = _write_review_packet(context=context, post_h3s_summary_path=post_h3s_summary_path, output=artifacts["review_packet"])
    reconciliation = _write_reconciliation(
        packet_path=artifacts["review_packet"],
        output=artifacts["review_reconciliation"],
        operator_id=operator_id,
        operator_decision=operator_decision,
        audit_decision=audit_decision,
        monitoring_decision=monitoring_decision,
        rollback_decision=rollback_decision,
        operator_statement=operator_statement,
        max_external_users=max_external_users,
        allowed_usage_scope=allowed_usage_scope,
        post_h3u_summary_path=post_h3u_summary_path,
        post_h3v_summary_path=post_h3v_summary_path,
        ack_external_user_usage_review=ack_external_user_usage_review,
    )
    boundary = _write_boundary_report(context=context, reconciliation_path=artifacts["review_reconciliation"], output=artifacts["boundary_report"])
    reports = [context, packet, reconciliation, boundary]
    passed = all(report.get("passed") is True for report in reports)
    usage_allowed = reconciliation.get("external_user_usage_allowed") is True and passed
    summary = {
        "schema_version": CHAIN_SCHEMA,
        "passed": passed,
        "failure_reasons": _failures(reports),
        "checked_at": _now(),
        "source_artifacts": _source_artifacts(
            post_h3s_summary_path=post_h3s_summary_path,
            post_h3u_summary_path=post_h3u_summary_path,
            post_h3v_summary_path=post_h3v_summary_path,
        ),
        "artifacts": {name: artifact_ref(path) for name, path in artifacts.items() if name != "summary"},
        "external_user_usage_review_id": reconciliation.get("external_user_usage_review_id"),
        "external_user_usage_allowed": usage_allowed,
        "readiness": {
            "state": "post_h3_external_user_usage_allowed_once" if usage_allowed else "post_h3_external_user_usage_revision_required" if passed else "blocked_post_h3_external_user_usage_review",
            "external_user_usage_review_complete": passed,
            "external_user_usage_allowed": usage_allowed,
            "external_user_usage_execution_ready": usage_allowed,
            "external_user_usage_revision_required": passed and not usage_allowed,
            "external_public_ingress_opened": False,
            "runtime_workers_currently_running": False,
            "runtime_execution_performed": False,
            "production_runtime_receipt_write_allowed": False,
        },
        "boundary": _boundary(
            context_validation_written=context.get("passed") is True,
            review_packet_written=packet.get("passed") is True,
            review_reconciliation_written=reconciliation.get("passed") is True,
            boundary_report_written=boundary.get("passed") is True,
            external_user_usage_review_complete=passed,
            external_user_usage_allowed=usage_allowed,
        ),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(artifacts["summary"], summary)
    return summary


def validate_post_h3s_context(post_h3s_summary_path: Path, *, output: Path | None = None) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    try:
        summary = read_json_object(post_h3s_summary_path)
    except Exception as exc:  # noqa: BLE001
        return _write_optional(_report(CONTEXT_SCHEMA, False, [f"post_h3s_summary_unreadable:{exc}"], checks), output)
    artifacts = object_value(summary.get("artifacts"))
    reconciliation = _read_verified_ref(artifacts.get("closeout_reconciliation"), checks, failures, "post_h3s_closeout_reconciliation")
    boundary_report = _read_verified_ref(artifacts.get("boundary_report"), checks, failures, "post_h3s_boundary_report")
    _check_summary(summary, checks, failures)
    _check_reconciliation(reconciliation, checks, failures)
    _check_boundary_report(boundary_report, checks, failures)
    passed = _passed(checks, failures)
    report = {
        "schema_version": CONTEXT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "post_h3s_summary": summary,
        "closeout_reconciliation": reconciliation,
        "boundary_report": boundary_report,
        "source_artifacts": {"post_h3s_summary": artifact_ref(post_h3s_summary_path)},
        "boundary": _boundary(context_validation_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    return _write_optional(report, output)


def _write_review_packet(*, context: dict[str, Any], post_h3s_summary_path: Path, output: Path) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    summary = object_value(context.get("post_h3s_summary"))
    readiness = object_value(summary.get("readiness"))
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "qr_closeout_complete", readiness.get("post_h3_qr_execution_closeout_complete") is True)
    check(checks, failures, "external_user_usage_review_ready", readiness.get("external_user_usage_review_ready") is True)
    check(checks, failures, "external_user_usage_not_preallowed", readiness.get("external_user_usage_allowed") is False)
    check(checks, failures, "public_ingress_currently_closed", readiness.get("external_public_ingress_currently_open") is False)
    check(checks, failures, "runtime_workers_currently_stopped", readiness.get("runtime_workers_currently_running") is False)
    passed = _passed(checks, failures)
    packet = {
        "schema_version": REVIEW_PACKET_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "written_at": _now(),
        "review_packet_id": f"post-h3t-usage-review-packet:{sha256_json([artifact_ref(post_h3s_summary_path), summary.get('qr_closeout_id')])[:24]}",
        "review_scope": {
            "review_external_user_usage": True,
            "default_decision": REQUEST_REVISION_DECISION,
            "allow_external_user_usage_without_new_authorization": False,
            "execute_external_user_usage": False,
            "open_public_ingress": False,
            "start_runtime_workers": False,
        },
        "missing_requirements": list(DEFAULT_MISSING_REQUIREMENTS),
        "source_artifacts": {"post_h3s_summary": artifact_ref(post_h3s_summary_path)},
        "readiness": {
            "external_user_usage_review_packet_ready": passed,
            "external_user_usage_allowed": False,
            "external_user_usage_revision_required": passed,
        },
        "boundary": _boundary(review_packet_written=passed),
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
    allowed_usage_scope: str,
    post_h3u_summary_path: Path | None,
    post_h3v_summary_path: Path | None,
    ack_external_user_usage_review: bool,
) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    packet = read_json_object(packet_path)
    wants_allow = operator_decision == AUTHORIZE_ONCE_DECISION
    authorization_evidence = _authorization_evidence_report(
        post_h3u_summary_path=post_h3u_summary_path,
        post_h3v_summary_path=post_h3v_summary_path,
        max_external_users=max_external_users,
        allowed_usage_scope=allowed_usage_scope,
    )
    check(checks, failures, "packet_passed", packet.get("schema_version") == REVIEW_PACKET_SCHEMA and packet.get("passed") is True)
    check(checks, failures, "operator_id_present", bool(operator_id.strip()))
    check(checks, failures, "operator_decision_known", operator_decision in (REQUEST_REVISION_DECISION, AUTHORIZE_ONCE_DECISION))
    check(checks, failures, "audit_decision_known", audit_decision in ACCEPTED_AUDIT_DECISIONS)
    check(checks, failures, "monitoring_decision_known", monitoring_decision in ACCEPTED_MONITORING_DECISIONS)
    check(checks, failures, "rollback_decision_known", rollback_decision in ACCEPTED_ROLLBACK_DECISIONS)
    check(checks, failures, "operator_statement_present", bool(operator_statement.strip()))
    check(checks, failures, "explicit_operator_ack", ack_external_user_usage_review is True)
    if wants_allow:
        check(checks, failures, "audit_allows_usage", audit_decision == "accept_limited_external_user_usage_once")
        check(checks, failures, "monitoring_allows_usage", monitoring_decision == "accept_limited_external_user_monitoring_once")
        check(checks, failures, "rollback_allows_usage", rollback_decision == "accept_limited_external_user_abort_runbook_once")
        check(checks, failures, "max_external_users_positive", max_external_users > 0)
        check(checks, failures, "allowed_usage_scope_present", bool(allowed_usage_scope.strip()) and allowed_usage_scope != "none")
        check(checks, failures, "identity_consent_evidence_valid", authorization_evidence["checks"].get("identity_consent_evidence_valid") is True)
        check(checks, failures, "usage_scope_evidence_valid", authorization_evidence["checks"].get("usage_scope_evidence_valid") is True)
        check(checks, failures, "authorization_evidence_scope_matches", authorization_evidence["checks"].get("authorization_evidence_scope_matches") is True)
    else:
        check(checks, failures, "revision_path_has_no_external_users", max_external_users == 0)
        check(checks, failures, "revision_path_scope_none", allowed_usage_scope == "none")
    passed = _passed(checks, failures)
    usage_allowed = passed and wants_allow
    reconciliation = {
        "schema_version": REVIEW_RECONCILIATION_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "reviewed_at": _now(),
        "external_user_usage_review_id": f"post-h3t-usage-review:{sha256_json([artifact_ref(packet_path), operator_id, operator_decision, audit_decision, monitoring_decision, rollback_decision, max_external_users, allowed_usage_scope])[:24]}",
        "operator_id": operator_id,
        "operator_decision": operator_decision,
        "audit_decision": audit_decision,
        "monitoring_decision": monitoring_decision,
        "rollback_decision": rollback_decision,
        "operator_statement": operator_statement,
        "operator_statement_sha256": sha256_json(operator_statement),
        "ack_external_user_usage_review": ack_external_user_usage_review,
        "external_user_usage_allowed": usage_allowed,
        "max_external_users": max_external_users,
        "allowed_usage_scope": allowed_usage_scope,
        "authorization_evidence": authorization_evidence,
        "missing_requirements": [] if usage_allowed else list(DEFAULT_MISSING_REQUIREMENTS),
        "source_artifacts": _source_artifacts(
            review_packet_path=packet_path,
            post_h3u_summary_path=post_h3u_summary_path,
            post_h3v_summary_path=post_h3v_summary_path,
        ),
        "readiness": {
            "external_user_usage_review_complete": passed,
            "external_user_usage_allowed": usage_allowed,
            "external_user_usage_execution_ready": usage_allowed,
            "external_user_usage_revision_required": passed and not usage_allowed,
        },
        "boundary": _boundary(review_reconciliation_written=passed, external_user_usage_review_complete=passed, external_user_usage_allowed=usage_allowed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, reconciliation)
    return reconciliation


def _write_boundary_report(*, context: dict[str, Any], reconciliation_path: Path, output: Path) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    reconciliation = read_json_object(reconciliation_path)
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "reconciliation_passed", reconciliation.get("passed") is True)
    check(checks, failures, "public_ingress_not_opened", True)
    check(checks, failures, "runtime_workers_not_started", True)
    check(checks, failures, "runtime_task_not_executed", True)
    passed = _passed(checks, failures)
    usage_allowed = passed and reconciliation.get("external_user_usage_allowed") is True
    report = {
        "schema_version": BOUNDARY_REPORT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "source_artifacts": {"review_reconciliation": artifact_ref(reconciliation_path)},
        "boundary": _boundary(boundary_report_written=passed, external_user_usage_review_complete=passed, external_user_usage_allowed=usage_allowed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def _check_summary(summary: dict[str, Any], checks: dict[str, bool], failures: list[str]) -> None:
    readiness = object_value(summary.get("readiness"))
    boundary = object_value(summary.get("boundary"))
    check(checks, failures, "post_h3s_schema_valid", summary.get("schema_version") == POST_H3S_SCHEMA)
    check(checks, failures, "post_h3s_passed", summary.get("passed") is True)
    check(checks, failures, "qr_closeout_complete", readiness.get("post_h3_qr_execution_closeout_complete") is True)
    check(checks, failures, "external_user_usage_review_ready", readiness.get("external_user_usage_review_ready") is True)
    check(checks, failures, "external_user_usage_not_allowed", readiness.get("external_user_usage_allowed") is False)
    check(checks, failures, "public_ingress_currently_closed", readiness.get("external_public_ingress_currently_open") is False)
    check(checks, failures, "runtime_workers_currently_stopped", readiness.get("runtime_workers_currently_running") is False)
    for key in ("runtime_execution_performed", "vm_contact_performed", "deploy_performed", "production_data_accessed", "source_tree_write_performed", "git_write_performed"):
        check(checks, failures, f"s_no_{key}", boundary.get(key) is False)


def _check_reconciliation(reconciliation: dict[str, Any], checks: dict[str, bool], failures: list[str]) -> None:
    ready = object_value(reconciliation.get("readiness"))
    check(checks, failures, "s_reconciliation_schema_valid", reconciliation.get("schema_version") == POST_H3S_RECONCILIATION_SCHEMA)
    check(checks, failures, "s_reconciliation_passed", reconciliation.get("passed") is True)
    check(checks, failures, "s_reconciliation_closeout_complete", ready.get("post_h3_qr_execution_closeout_complete") is True)
    check(checks, failures, "s_reconciliation_review_ready", ready.get("external_user_usage_review_ready") is True)
    check(checks, failures, "s_reconciliation_usage_not_allowed", ready.get("external_user_usage_allowed") is False)


def _check_boundary_report(report: dict[str, Any], checks: dict[str, bool], failures: list[str]) -> None:
    boundary = object_value(report.get("boundary"))
    check(checks, failures, "s_boundary_schema_valid", report.get("schema_version") == POST_H3S_BOUNDARY_REPORT_SCHEMA and report.get("passed") is True)
    check(checks, failures, "s_boundary_closeout_complete", boundary.get("post_h3_qr_execution_closeout_complete") is True)
    check(checks, failures, "s_boundary_public_ingress_closed", boundary.get("external_public_ingress_currently_open") is False)
    check(checks, failures, "s_boundary_runtime_workers_stopped", boundary.get("runtime_workers_currently_running") is False)


def _authorization_evidence_report(
    *,
    post_h3u_summary_path: Path | None,
    post_h3v_summary_path: Path | None,
    max_external_users: int,
    allowed_usage_scope: str,
) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    u_summary = _read_optional_summary(post_h3u_summary_path, checks, failures, "post_h3u_summary")
    v_summary = _read_optional_summary(post_h3v_summary_path, checks, failures, "post_h3v_summary")
    _check_u_authorization_evidence(u_summary, checks, failures)
    _check_v_authorization_evidence(v_summary, checks, failures)
    u_handle = u_summary.get("external_user_handle")
    check(checks, failures, "authorization_evidence_user_matches", bool(u_handle) and u_handle == v_summary.get("external_user_handle"))
    check(checks, failures, "authorization_evidence_scope_matches", v_summary.get("allowed_usage_scope") == allowed_usage_scope and v_summary.get("max_external_users") == max_external_users)
    return {
        "passed": _passed(checks, failures),
        "failure_reasons": failures,
        "checks": checks,
        "external_user_handle": u_handle,
        "post_h3u_summary": artifact_ref(post_h3u_summary_path) if post_h3u_summary_path and post_h3u_summary_path.is_file() else {},
        "post_h3v_summary": artifact_ref(post_h3v_summary_path) if post_h3v_summary_path and post_h3v_summary_path.is_file() else {},
    }


def _read_optional_summary(path: Path | None, checks: dict[str, bool], failures: list[str], label: str) -> dict[str, Any]:
    check(checks, failures, f"{label}_present", path is not None and path.is_file())
    if path is None or not path.is_file():
        return {}
    return read_json_object(path)


def _check_u_authorization_evidence(summary: dict[str, Any], checks: dict[str, bool], failures: list[str]) -> None:
    readiness = object_value(summary.get("readiness"))
    check(checks, failures, "post_h3u_schema_valid", summary.get("schema_version") == POST_H3U_SCHEMA)
    check(checks, failures, "post_h3u_passed", summary.get("passed") is True)
    check(checks, failures, "post_h3u_identity_consent_bound", readiness.get("external_user_identity_and_consent_bound") is True)
    check(checks, failures, "post_h3u_review_rerun_ready", readiness.get("external_user_usage_review_rerun_ready") is True)
    check(checks, failures, "identity_consent_evidence_valid", summary.get("passed") is True and readiness.get("external_user_identity_and_consent_bound") is True)


def _check_v_authorization_evidence(summary: dict[str, Any], checks: dict[str, bool], failures: list[str]) -> None:
    readiness = object_value(summary.get("readiness"))
    bounded = object_value(summary.get("bounded_requirement_resolution"))
    check(checks, failures, "post_h3v_schema_valid", summary.get("schema_version") == POST_H3V_SCHEMA)
    check(checks, failures, "post_h3v_passed", summary.get("passed") is True)
    check(checks, failures, "post_h3v_task_scope_bound", readiness.get("external_user_task_scope_bound") is True)
    check(checks, failures, "post_h3v_monitoring_bound", readiness.get("external_user_monitoring_slo_bound") is True)
    check(checks, failures, "post_h3v_rollback_bound", readiness.get("external_user_rollback_abort_owner_bound") is True)
    check(checks, failures, "post_h3v_public_ingress_not_required", bounded.get("production_grade_public_ingress_required") is False)
    check(checks, failures, "post_h3v_sustained_runtime_not_required", bounded.get("sustained_runtime_expansion_required") is False)
    check(checks, failures, "usage_scope_evidence_valid", summary.get("passed") is True and readiness.get("external_user_usage_authorization_review_ready") is True)


def _source_artifacts(
    *,
    post_h3s_summary_path: Path | None = None,
    review_packet_path: Path | None = None,
    post_h3u_summary_path: Path | None = None,
    post_h3v_summary_path: Path | None = None,
) -> dict[str, dict[str, str]]:
    artifacts: dict[str, dict[str, str]] = {}
    if post_h3s_summary_path is not None:
        artifacts["post_h3s_summary"] = artifact_ref(post_h3s_summary_path)
    if review_packet_path is not None:
        artifacts["review_packet"] = artifact_ref(review_packet_path)
    if post_h3u_summary_path is not None and post_h3u_summary_path.is_file():
        artifacts["post_h3u_summary"] = artifact_ref(post_h3u_summary_path)
    if post_h3v_summary_path is not None and post_h3v_summary_path.is_file():
        artifacts["post_h3v_summary"] = artifact_ref(post_h3v_summary_path)
    return artifacts


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
        "review_packet_written": False,
        "review_reconciliation_written": False,
        "boundary_report_written": False,
        "external_user_usage_review_complete": False,
        "external_user_usage_allowed": False,
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
    parser = argparse.ArgumentParser(description="Run PostH3-T external user usage review gate")
    parser.add_argument("--post-h3s-summary", required=True, type=Path)
    parser.add_argument("--post-h3u-summary", type=Path)
    parser.add_argument("--post-h3v-summary", type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--operator-id", default="operator-primary")
    parser.add_argument("--operator-decision", default=REQUEST_REVISION_DECISION)
    parser.add_argument("--audit-decision", default=REQUEST_REVISION_DECISION)
    parser.add_argument("--monitoring-decision", default=REQUEST_REVISION_DECISION)
    parser.add_argument("--rollback-decision", default=REQUEST_REVISION_DECISION)
    parser.add_argument("--operator-statement", default="Request revision before real external user usage; Q/R proved bounded mechanics only.")
    parser.add_argument("--max-external-users", default=0, type=int)
    parser.add_argument("--allowed-usage-scope", default="none")
    parser.add_argument("--ack-external-user-usage-review", action="store_true")
    args = parser.parse_args()
    summary = run_gate(
        post_h3s_summary_path=args.post_h3s_summary,
        post_h3u_summary_path=args.post_h3u_summary,
        post_h3v_summary_path=args.post_h3v_summary,
        output_root=args.output_root,
        operator_id=args.operator_id,
        operator_decision=args.operator_decision,
        audit_decision=args.audit_decision,
        monitoring_decision=args.monitoring_decision,
        rollback_decision=args.rollback_decision,
        operator_statement=args.operator_statement,
        max_external_users=args.max_external_users,
        allowed_usage_scope=args.allowed_usage_scope,
        ack_external_user_usage_review=args.ack_external_user_usage_review,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if summary.get("passed") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
