"""Reconcile limited-feedback higher-permission review decisions.

This gate consumes a limited-feedback higher-permission review request and
records explicit operator, audit, security, rollback, and monitoring decisions.
A passing result means the path is ready for a separate single-use authorization
request. It does not grant authorization, execute external usage, open public
ingress, start runtime workers, deploy, access production data, write production
runtime receipts, or write source/Git state.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from benchmarks.i_gate_evidence import artifact_ref, check, object_value, read_json_object, sha256_file, sha256_json, write_json_object
from benchmarks.post_h3_limited_feedback_higher_permission_review_request_gate import (
    BOUNDARY_REPORT_SCHEMA as REQUEST_BOUNDARY_REPORT_SCHEMA,
    CHAIN_SCHEMA as REQUEST_CHAIN_SCHEMA,
    CONTEXT_SCHEMA as REQUEST_CONTEXT_SCHEMA,
    REVIEW_REQUEST_SCHEMA,
)

CHAIN_SCHEMA = "post-h3-limited-feedback-higher-permission-review-reconciliation-gate:v1"
CONTEXT_SCHEMA = "post-h3-limited-feedback-higher-permission-review-reconciliation-context:v1"
DECISION_PACKET_SCHEMA = "post-h3-limited-feedback-higher-permission-review-decision-packet:v1"
ROLE_DECISION_SCHEMA = "post-h3-limited-feedback-higher-permission-review-role-decision:v1"
RECONCILIATION_SCHEMA = "post-h3-limited-feedback-higher-permission-review-reconciliation:v1"
BOUNDARY_REPORT_SCHEMA = "post-h3-limited-feedback-higher-permission-review-reconciliation-boundary:v1"

ACCEPTED_OPERATOR_DECISION = "approve_limited_feedback_higher_permission_review_only"
ACCEPTED_AUDIT_DECISION = "accept_limited_feedback_higher_permission_boundary_no_execution_or_authorization"
ACCEPTED_SECURITY_DECISION = "accept_bounded_external_or_runtime_scope_no_public_wildcard"
ACCEPTED_ROLLBACK_DECISION = "accept_abort_before_side_effects_and_single_use_rollback_required"
ACCEPTED_MONITORING_DECISION = "accept_monitoring_required_before_any_higher_permission_execution"
DEFAULT_OPERATOR_STATEMENT = (
    "Reconcile limited-feedback higher-permission review for future single-use authorization requests only; "
    "do not grant or execute higher-permission action in this gate."
)
DEFAULT_APPROVED_REVIEW_DOMAINS = (
    "limited_external_usage_feedback_collection_once",
    "status_only_public_ingress_short_window",
    "bounded_runtime_worker_heartbeat_once",
)
NON_CLAIMS = (
    "limited_feedback_higher_permission_reconciliation_records_review_decisions_only",
    "limited_feedback_higher_permission_reconciliation_does_not_grant_authorization",
    "limited_feedback_higher_permission_reconciliation_does_not_execute_external_user_usage",
    "limited_feedback_higher_permission_reconciliation_does_not_open_public_ingress",
    "limited_feedback_higher_permission_reconciliation_does_not_start_runtime_workers",
    "limited_feedback_higher_permission_reconciliation_does_not_deploy",
    "limited_feedback_higher_permission_reconciliation_does_not_access_production_data",
    "limited_feedback_higher_permission_reconciliation_does_not_write_production_runtime_receipts",
    "limited_feedback_higher_permission_reconciliation_does_not_write_source_or_git",
)


def run_gate(
    *,
    higher_permission_review_request_summary_path: Path,
    output_root: Path,
    operator_id: str = "operator-primary",
    operator_decision: str = ACCEPTED_OPERATOR_DECISION,
    audit_decision: str = ACCEPTED_AUDIT_DECISION,
    security_decision: str = ACCEPTED_SECURITY_DECISION,
    rollback_decision: str = ACCEPTED_ROLLBACK_DECISION,
    monitoring_decision: str = ACCEPTED_MONITORING_DECISION,
    operator_statement: str = DEFAULT_OPERATOR_STATEMENT,
    approved_review_domains: tuple[str, ...] | list[str] = DEFAULT_APPROVED_REVIEW_DOMAINS,
    ack_reconciliation: bool = False,
) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "context_validation": output_root / "post_h3_limited_feedback_higher_permission_review_reconciliation_context.json",
        "decision_packet": output_root / "post_h3_limited_feedback_higher_permission_review_decision_packet.json",
        "operator_decision": output_root / "post_h3_limited_feedback_higher_permission_review_operator_decision.json",
        "audit_decision": output_root / "post_h3_limited_feedback_higher_permission_review_audit_decision.json",
        "security_decision": output_root / "post_h3_limited_feedback_higher_permission_review_security_decision.json",
        "rollback_decision": output_root / "post_h3_limited_feedback_higher_permission_review_rollback_decision.json",
        "monitoring_decision": output_root / "post_h3_limited_feedback_higher_permission_review_monitoring_decision.json",
        "reconciliation": output_root / "post_h3_limited_feedback_higher_permission_review_reconciliation.json",
        "boundary_report": output_root / "post_h3_limited_feedback_higher_permission_review_reconciliation_boundary_report.json",
        "summary": output_root / "post_h3_limited_feedback_higher_permission_review_reconciliation_summary.json",
    }
    if not ack_reconciliation:
        return _write_blocked_summary(
            output=artifacts["summary"],
            higher_permission_review_request_summary_path=higher_permission_review_request_summary_path,
            failure="explicit_limited_feedback_higher_permission_reconciliation_ack",
        )

    context = _validate_context(
        higher_permission_review_request_summary_path=higher_permission_review_request_summary_path,
        output=artifacts["context_validation"],
    )
    packet = _write_decision_packet(context=context, output=artifacts["decision_packet"])
    role_decisions = {
        "operator": _write_role_decision(
            packet_path=artifacts["decision_packet"],
            output=artifacts["operator_decision"],
            role="operator",
            actor_id=operator_id,
            decision=operator_decision,
            accepted_decision=ACCEPTED_OPERATOR_DECISION,
            statement=operator_statement,
        ),
        "audit": _write_role_decision(
            packet_path=artifacts["decision_packet"],
            output=artifacts["audit_decision"],
            role="audit",
            actor_id="audit_owner",
            decision=audit_decision,
            accepted_decision=ACCEPTED_AUDIT_DECISION,
            statement="Accept higher-permission review boundary only if no execution or authorization is granted here.",
        ),
        "security": _write_role_decision(
            packet_path=artifacts["decision_packet"],
            output=artifacts["security_decision"],
            role="security",
            actor_id="security_owner",
            decision=security_decision,
            accepted_decision=ACCEPTED_SECURITY_DECISION,
            statement="Accept bounded external or runtime scopes only; no wildcard public ingress or unbounded runtime expansion.",
        ),
        "rollback": _write_role_decision(
            packet_path=artifacts["decision_packet"],
            output=artifacts["rollback_decision"],
            role="rollback",
            actor_id="rollback_owner",
            decision=rollback_decision,
            accepted_decision=ACCEPTED_ROLLBACK_DECISION,
            statement="Require abort before side effects and fresh rollback or abort receipt before execution authorization.",
        ),
        "monitoring": _write_role_decision(
            packet_path=artifacts["decision_packet"],
            output=artifacts["monitoring_decision"],
            role="monitoring",
            actor_id="observability_owner",
            decision=monitoring_decision,
            accepted_decision=ACCEPTED_MONITORING_DECISION,
            statement="Require monitoring owner binding before any higher-permission execution authorization.",
        ),
    }
    reconciliation = _write_reconciliation(
        context=context,
        packet_path=artifacts["decision_packet"],
        role_decision_paths={
            "operator": artifacts["operator_decision"],
            "audit": artifacts["audit_decision"],
            "security": artifacts["security_decision"],
            "rollback": artifacts["rollback_decision"],
            "monitoring": artifacts["monitoring_decision"],
        },
        output=artifacts["reconciliation"],
        approved_review_domains=tuple(approved_review_domains),
    )
    boundary = _write_boundary_report(reconciliation_path=artifacts["reconciliation"], output=artifacts["boundary_report"])
    reports = [context, packet, *role_decisions.values(), reconciliation, boundary]
    passed = all(report.get("passed") is True for report in reports)
    summary = {
        "schema_version": CHAIN_SCHEMA,
        "passed": passed,
        "failure_reasons": _failures(reports),
        "checked_at": _now(),
        "source_artifacts": {"higher_permission_review_request_summary": artifact_ref(higher_permission_review_request_summary_path)},
        "artifacts": {name: artifact_ref(path) for name, path in artifacts.items() if name != "summary"},
        "reconciliation_id": reconciliation.get("reconciliation_id"),
        "higher_permission_review_request_id": object_value(context.get("request_summary")).get("higher_permission_review_request_id"),
        "approved_review_domains": list(approved_review_domains),
        "readiness": {
            "state": "limited_feedback_higher_permission_review_reconciliation_complete" if passed else "blocked_limited_feedback_higher_permission_review_reconciliation",
            "higher_permission_review_reconciliation_complete": passed,
            "single_use_authorization_request_ready": passed,
            "limited_feedback_authorization_request_ready": passed and "limited_external_usage_feedback_collection_once" in approved_review_domains,
            "status_only_public_ingress_authorization_request_ready": passed and "status_only_public_ingress_short_window" in approved_review_domains,
            "bounded_runtime_heartbeat_authorization_request_ready": passed and "bounded_runtime_worker_heartbeat_once" in approved_review_domains,
            "authorization_granted": False,
            "execution_authorization_ready": False,
            "external_user_usage_allowed": False,
            "public_ingress_authorized": False,
            "runtime_expansion_authorized": False,
            "production_task_execution_allowed": False,
            "runtime_execution_performed": False,
            "production_runtime_receipt_write_allowed": False,
        },
        "boundary": _boundary(
            context_validation_written=context.get("passed") is True,
            decision_packet_written=packet.get("passed") is True,
            role_decisions_written=all(report.get("passed") is True for report in role_decisions.values()),
            reconciliation_written=reconciliation.get("passed") is True,
            boundary_report_written=boundary.get("passed") is True,
            higher_permission_review_reconciliation_complete=passed,
            single_use_authorization_request_ready=passed,
        ),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(artifacts["summary"], summary)
    return summary


def _validate_context(*, higher_permission_review_request_summary_path: Path, output: Path) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    summary = _read_json_or_empty(higher_permission_review_request_summary_path, failures, "higher_permission_review_request_summary")
    artifacts = object_value(summary.get("artifacts"))
    request_context = _read_verified_ref(artifacts.get("context_validation"), checks, failures, "request_context")
    review_request = _read_verified_ref(artifacts.get("review_request"), checks, failures, "review_request")
    request_boundary = _read_verified_ref(artifacts.get("boundary_report"), checks, failures, "request_boundary_report")
    readiness = object_value(summary.get("readiness"))
    boundary = object_value(summary.get("boundary"))
    requested_permission = object_value(review_request.get("requested_permission_review"))
    constraints = object_value(review_request.get("constraints"))

    check(checks, failures, "summary_schema", summary.get("schema_version") == REQUEST_CHAIN_SCHEMA)
    check(checks, failures, "summary_passed", summary.get("passed") is True)
    check(checks, failures, "request_context_schema", request_context.get("schema_version") == REQUEST_CONTEXT_SCHEMA and request_context.get("passed") is True)
    check(checks, failures, "review_request_schema", review_request.get("schema_version") == REVIEW_REQUEST_SCHEMA and review_request.get("passed") is True)
    check(checks, failures, "request_boundary_schema", request_boundary.get("schema_version") == REQUEST_BOUNDARY_REPORT_SCHEMA and request_boundary.get("passed") is True)
    check(checks, failures, "higher_permission_review_ready", readiness.get("higher_permission_review_ready") is True)
    check(checks, failures, "authorization_not_granted", readiness.get("authorization_granted") is False)
    check(checks, failures, "execution_not_ready", readiness.get("execution_authorization_ready") is False)
    check(checks, failures, "future_separate_authorization_required", readiness.get("future_execution_requires_separate_single_use_authorization") is True)
    check(checks, failures, "requested_permission_reviews_higher_action", requested_permission.get("review_higher_permission_action") is True)
    check(checks, failures, "requested_permission_requires_reconciliation", requested_permission.get("requires_owner_audit_monitoring_rollback_reconciliation") is True)
    check(checks, failures, "requested_permission_requires_single_use_authorization", requested_permission.get("requires_separate_single_use_authorization_before_execution") is True)
    check(checks, failures, "max_external_users_bounded", requested_permission.get("max_external_users") == 1)
    check(checks, failures, "max_runtime_workers_bounded", requested_permission.get("max_runtime_workers") == 1)
    check(checks, failures, "request_does_not_grant_authorization", constraints.get("authorization_granted_here") is False)
    check(checks, failures, "request_does_not_prepare_execution", constraints.get("execution_authorization_ready_here") is False)
    check(checks, failures, "summary_boundary_closed", _closed_boundary(boundary))
    check(checks, failures, "request_boundary_closed", _closed_boundary(object_value(review_request.get("boundary"))))
    check(checks, failures, "boundary_report_closed", _closed_boundary(object_value(request_boundary.get("boundary"))))
    passed = _passed(checks, failures)
    report = {
        "schema_version": CONTEXT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "request_summary": summary,
        "request_context": request_context,
        "review_request": review_request,
        "request_boundary_report": request_boundary,
        "source_artifacts": {"higher_permission_review_request_summary": artifact_ref(higher_permission_review_request_summary_path)},
        "boundary": _boundary(context_validation_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def _write_decision_packet(*, context: dict[str, Any], output: Path) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    request = object_value(context.get("review_request"))
    requested_permission = object_value(request.get("requested_permission_review"))
    requested_domain = str(request.get("requested_action_domain") or requested_permission.get("allowed_scope") or "")
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "requested_action_domain_present", bool(requested_domain.strip()))
    check(checks, failures, "no_execution_authorization_in_request", object_value(request.get("readiness")).get("authorization_granted") is False)
    passed = _passed(checks, failures)
    packet = {
        "schema_version": DECISION_PACKET_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "written_at": _now(),
        "decision_packet_id": f"post-h3-limited-feedback-higher-permission-decision-packet:{sha256_json([request.get('higher_permission_review_request_id'), requested_domain])[:24]}",
        "higher_permission_review_request_id": request.get("higher_permission_review_request_id"),
        "requested_action_domain": requested_domain,
        "candidate_review_domains": list(DEFAULT_APPROVED_REVIEW_DOMAINS),
        "required_roles": ["operator", "audit", "security", "rollback", "monitoring"],
        "decision_scope": {
            "may_prepare_single_use_authorization_request": True,
            "may_grant_authorization": False,
            "may_execute": False,
            "may_open_public_ingress": False,
            "may_start_runtime_workers": False,
            "may_deploy": False,
            "may_access_production_data": False,
            "may_write_source_or_git": False,
        },
        "readiness": {
            "higher_permission_review_decision_packet_ready": passed,
            "authorization_granted": False,
            "execution_allowed": False,
        },
        "boundary": _boundary(decision_packet_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, packet)
    return packet


def _write_role_decision(
    *,
    packet_path: Path,
    output: Path,
    role: str,
    actor_id: str,
    decision: str,
    accepted_decision: str,
    statement: str,
) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    packet = read_json_object(packet_path)
    check(checks, failures, "packet_passed", packet.get("schema_version") == DECISION_PACKET_SCHEMA and packet.get("passed") is True)
    check(checks, failures, "role_present", role in {"operator", "audit", "security", "rollback", "monitoring"})
    check(checks, failures, "actor_id_present", bool(actor_id.strip()))
    check(checks, failures, "decision_accepted", decision == accepted_decision)
    check(checks, failures, "statement_present", bool(statement.strip()))
    passed = _passed(checks, failures)
    report = {
        "schema_version": ROLE_DECISION_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "decided_at": _now(),
        "role": role,
        "actor_id": actor_id,
        "decision": decision,
        "accepted_decision": accepted_decision,
        "statement": statement,
        "statement_sha256": sha256_json(statement),
        "higher_permission_review_request_id": packet.get("higher_permission_review_request_id"),
        "source_artifacts": {"decision_packet": artifact_ref(packet_path)},
        "readiness": {
            "role_decision_complete": passed,
            "authorization_granted": False,
            "execution_allowed": False,
        },
        "boundary": _boundary(role_decisions_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def _write_reconciliation(
    *,
    context: dict[str, Any],
    packet_path: Path,
    role_decision_paths: dict[str, Path],
    output: Path,
    approved_review_domains: tuple[str, ...],
) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    packet = read_json_object(packet_path)
    request = object_value(context.get("review_request"))
    requested_permission = object_value(request.get("requested_permission_review"))
    approved_set = set(approved_review_domains)
    role_decisions = {role: _read_json_or_empty(path, failures, f"{role}_decision") for role, path in role_decision_paths.items()}
    allowed_set = set(DEFAULT_APPROVED_REVIEW_DOMAINS)
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "packet_passed", packet.get("passed") is True)
    check(checks, failures, "all_roles_present", set(role_decisions) == {"operator", "audit", "security", "rollback", "monitoring"})
    for role, report in role_decisions.items():
        check(checks, failures, f"{role}_decision_passed", report.get("passed") is True)
    check(checks, failures, "approved_domains_nonempty", bool(approved_set))
    check(checks, failures, "approved_domains_allowed", approved_set.issubset(allowed_set))
    check(checks, failures, "max_external_users_still_bounded", requested_permission.get("max_external_users") == 1)
    check(checks, failures, "max_runtime_workers_still_bounded", requested_permission.get("max_runtime_workers") == 1)
    check(checks, failures, "no_deploy_or_source_domain", not {"deploy", "source_tree_write", "git_write", "production_data_access"}.intersection(approved_set))
    passed = _passed(checks, failures)
    report = {
        "schema_version": RECONCILIATION_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "reconciled_at": _now(),
        "reconciliation_id": f"post-h3-limited-feedback-higher-permission-reconciliation:{sha256_json([artifact_ref(packet_path), {role: artifact_ref(path) for role, path in sorted(role_decision_paths.items())}, sorted(approved_set)])[:24]}",
        "higher_permission_review_request_id": request.get("higher_permission_review_request_id"),
        "approved_review_domains": sorted(approved_set),
        "role_decisions": role_decisions,
        "source_artifacts": {"decision_packet": artifact_ref(packet_path)} | {f"{role}_decision": artifact_ref(path) for role, path in role_decision_paths.items()},
        "readiness": {
            "higher_permission_review_reconciliation_complete": passed,
            "single_use_authorization_request_ready": passed,
            "limited_feedback_authorization_request_ready": passed and "limited_external_usage_feedback_collection_once" in approved_set,
            "status_only_public_ingress_authorization_request_ready": passed and "status_only_public_ingress_short_window" in approved_set,
            "bounded_runtime_heartbeat_authorization_request_ready": passed and "bounded_runtime_worker_heartbeat_once" in approved_set,
            "authorization_granted": False,
            "execution_authorization_ready": False,
            "external_user_usage_allowed": False,
            "public_ingress_authorized": False,
            "runtime_expansion_authorized": False,
            "future_execution_requires_separate_single_use_authorization": True,
        },
        "boundary": _boundary(reconciliation_written=passed, single_use_authorization_request_ready=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def _write_boundary_report(*, reconciliation_path: Path, output: Path) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    reconciliation = read_json_object(reconciliation_path)
    readiness = object_value(reconciliation.get("readiness"))
    boundary = object_value(reconciliation.get("boundary"))
    check(checks, failures, "reconciliation_passed", reconciliation.get("schema_version") == RECONCILIATION_SCHEMA and reconciliation.get("passed") is True)
    check(checks, failures, "single_use_request_ready", readiness.get("single_use_authorization_request_ready") is True)
    check(checks, failures, "authorization_not_granted", readiness.get("authorization_granted") is False)
    check(checks, failures, "execution_not_ready", readiness.get("execution_authorization_ready") is False)
    check(checks, failures, "closed_boundary", _closed_boundary(boundary))
    passed = _passed(checks, failures)
    report = {
        "schema_version": BOUNDARY_REPORT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "source_artifacts": {"reconciliation": artifact_ref(reconciliation_path)},
        "boundary": _boundary(
            boundary_report_written=passed,
            reconciliation_written=reconciliation.get("passed") is True,
            higher_permission_review_reconciliation_complete=passed,
            single_use_authorization_request_ready=passed,
        ),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def _closed_boundary(boundary: dict[str, Any]) -> bool:
    required_false = (
        "authorization_granted",
        "execution_authorization_ready",
        "external_user_usage_allowed",
        "external_user_usage_performed",
        "external_public_ingress_opened",
        "public_ingress_authorized",
        "runtime_expansion_authorized",
        "runtime_workers_currently_running",
        "runtime_execution_performed",
        "vm_contact_performed",
        "deploy_performed",
        "production_data_accessed",
        "production_runtime_receipt_write_allowed",
        "production_runtime_receipt_written",
        "source_tree_write_performed",
        "git_write_performed",
        "secrets_recorded",
    )
    return all(boundary.get(key) is False for key in required_false if key in boundary)


def _boundary(**overrides: Any) -> dict[str, Any]:
    boundary = {
        "context_validation_written": False,
        "decision_packet_written": False,
        "role_decisions_written": False,
        "reconciliation_written": False,
        "boundary_report_written": False,
        "higher_permission_review_reconciliation_complete": False,
        "single_use_authorization_request_ready": False,
        "authorization_granted": False,
        "execution_authorization_ready": False,
        "external_user_usage_allowed": False,
        "external_user_usage_performed": False,
        "external_public_ingress_opened": False,
        "public_ingress_authorized": False,
        "runtime_expansion_authorized": False,
        "runtime_workers_currently_running": False,
        "runtime_execution_performed": False,
        "vm_contact_performed": False,
        "deploy_performed": False,
        "production_data_accessed": False,
        "production_runtime_receipt_write_allowed": False,
        "production_runtime_receipt_written": False,
        "source_tree_write_performed": False,
        "git_write_performed": False,
        "secrets_recorded": False,
    }
    boundary.update(overrides)
    return boundary


def _write_blocked_summary(*, output: Path, higher_permission_review_request_summary_path: Path, failure: str) -> dict[str, Any]:
    summary = {
        "schema_version": CHAIN_SCHEMA,
        "passed": False,
        "failure_reasons": [failure],
        "checks": {failure: False},
        "checked_at": _now(),
        "source_artifacts": {
            "higher_permission_review_request_summary": artifact_ref(higher_permission_review_request_summary_path)
            if higher_permission_review_request_summary_path.exists()
            else {"path": str(higher_permission_review_request_summary_path.resolve()), "sha256": ""}
        },
        "readiness": {
            "state": "blocked_limited_feedback_higher_permission_review_reconciliation",
            "higher_permission_review_reconciliation_complete": False,
            "single_use_authorization_request_ready": False,
            "authorization_granted": False,
            "execution_authorization_ready": False,
            "external_user_usage_allowed": False,
            "public_ingress_authorized": False,
            "runtime_expansion_authorized": False,
            "production_task_execution_allowed": False,
            "runtime_execution_performed": False,
            "production_runtime_receipt_write_allowed": False,
        },
        "boundary": _boundary(),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, summary)
    return summary


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
    parser.add_argument("--higher-permission-review-request-summary", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--operator-id", default="operator-primary")
    parser.add_argument("--operator-decision", default=ACCEPTED_OPERATOR_DECISION)
    parser.add_argument("--audit-decision", default=ACCEPTED_AUDIT_DECISION)
    parser.add_argument("--security-decision", default=ACCEPTED_SECURITY_DECISION)
    parser.add_argument("--rollback-decision", default=ACCEPTED_ROLLBACK_DECISION)
    parser.add_argument("--monitoring-decision", default=ACCEPTED_MONITORING_DECISION)
    parser.add_argument("--operator-statement", default=DEFAULT_OPERATOR_STATEMENT)
    parser.add_argument("--approved-review-domain", action="append", default=[])
    parser.add_argument("--ack-reconciliation", action="store_true")
    args = parser.parse_args(argv)
    approved_domains = tuple(args.approved_review_domain) if args.approved_review_domain else DEFAULT_APPROVED_REVIEW_DOMAINS
    summary = run_gate(
        higher_permission_review_request_summary_path=args.higher_permission_review_request_summary,
        output_root=args.output_root,
        operator_id=args.operator_id,
        operator_decision=args.operator_decision,
        audit_decision=args.audit_decision,
        security_decision=args.security_decision,
        rollback_decision=args.rollback_decision,
        monitoring_decision=args.monitoring_decision,
        operator_statement=args.operator_statement,
        approved_review_domains=approved_domains,
        ack_reconciliation=args.ack_reconciliation,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if summary.get("passed") is True else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
