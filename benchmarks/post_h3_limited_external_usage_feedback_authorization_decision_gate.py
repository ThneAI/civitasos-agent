"""Authorize or reject one PostH3 limited external-usage feedback request.

This gate consumes the request-only artifact from
``post_h3_limited_external_usage_feedback_authorization_request_gate`` and
records operator, audit, monitoring, and rollback decisions. If every role
accepts, it writes one single-use authorization receipt for the later feedback
collection execution gate. It does not collect feedback, execute runtime work,
open public ingress, deploy, access production data, write production runtime
receipts, or write source/Git state.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from benchmarks.i_gate_evidence import artifact_ref, check, object_value, read_json_object, sha256_file, sha256_json, write_json_object
from benchmarks.post_h3_limited_external_usage_feedback_authorization_request_gate import (
    AUTHORIZATION_DOMAIN,
    AUTHORIZATION_REQUEST_SCHEMA,
    BOUNDARY_REPORT_SCHEMA as REQUEST_BOUNDARY_REPORT_SCHEMA,
    CHAIN_SCHEMA as REQUEST_CHAIN_SCHEMA,
    DEFAULT_FEEDBACK_SCOPE,
    EXECUTION_GATE_AFTER_AUTHORIZATION,
    REQUIRED_NEXT_GATE,
)

CHAIN_SCHEMA = "post-h3-limited-external-usage-feedback-authorization-decision-gate:v1"
CONTEXT_SCHEMA = "post-h3-limited-feedback-authorization-decision-context:v1"
ROLE_DECISION_SCHEMA = "post-h3-limited-feedback-authorization-role-decision:v1"
AUTHORIZATION_RECEIPT_SCHEMA = "post-h3-limited-feedback-single-use-authorization-receipt:v1"
BOUNDARY_REPORT_SCHEMA = "post-h3-limited-feedback-authorization-decision-boundary:v1"

OPERATOR_AUTHORIZE = "authorize_limited_external_usage_feedback_collection_once"
OPERATOR_REJECT = "reject_limited_external_usage_feedback_collection"
AUDIT_ACCEPT = "accept_limited_feedback_request_boundary_no_execution"
AUDIT_REJECT = "reject_limited_feedback_request_boundary"
MONITORING_ACCEPT = "accept_limited_feedback_monitoring_required_once"
MONITORING_REJECT = "reject_limited_feedback_monitoring_plan"
ROLLBACK_ACCEPT = "accept_limited_feedback_abort_before_side_effects"
ROLLBACK_REJECT = "reject_limited_feedback_abort_plan"
DEFAULT_OPERATOR_STATEMENT = (
    "Authorize exactly one limited external usage feedback collection after the request-only gate; "
    "do not execute feedback collection in this authorization decision gate."
)
NON_CLAIMS = (
    "limited_feedback_authorization_decision_only",
    "limited_feedback_decision_does_not_collect_feedback",
    "limited_feedback_decision_does_not_execute_runtime_task",
    "limited_feedback_decision_does_not_open_public_ingress",
    "limited_feedback_decision_does_not_start_runtime_workers",
    "limited_feedback_decision_does_not_deploy",
    "limited_feedback_decision_does_not_access_production_data",
    "limited_feedback_decision_does_not_write_production_runtime_receipts",
    "limited_feedback_decision_does_not_write_source_or_git",
)


def run_gate(
    *,
    limited_feedback_authorization_request_summary_path: Path,
    output_root: Path,
    operator_id: str = "operator-primary",
    operator_decision: str = OPERATOR_AUTHORIZE,
    audit_decision: str = AUDIT_ACCEPT,
    monitoring_decision: str = MONITORING_ACCEPT,
    rollback_decision: str = ROLLBACK_ACCEPT,
    operator_statement: str = DEFAULT_OPERATOR_STATEMENT,
    expires_in_seconds: int = 3600,
    ack_authorization_decision: bool = False,
) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "context_validation": output_root / "post_h3_limited_feedback_authorization_decision_context.json",
        "operator_decision": output_root / "post_h3_limited_feedback_operator_decision.json",
        "audit_decision": output_root / "post_h3_limited_feedback_audit_decision.json",
        "monitoring_decision": output_root / "post_h3_limited_feedback_monitoring_decision.json",
        "rollback_decision": output_root / "post_h3_limited_feedback_rollback_decision.json",
        "authorization_receipt": output_root / "post_h3_limited_feedback_authorization_receipt.json",
        "boundary_report": output_root / "post_h3_limited_feedback_authorization_decision_boundary_report.json",
        "summary": output_root / "post_h3_limited_feedback_authorization_decision_summary.json",
    }
    if not ack_authorization_decision:
        return _write_blocked_summary(
            output=artifacts["summary"],
            request_summary_path=limited_feedback_authorization_request_summary_path,
            failure="explicit_limited_feedback_authorization_decision_ack",
        )

    context = _validate_context(request_summary_path=limited_feedback_authorization_request_summary_path, output=artifacts["context_validation"])
    role_decisions = {
        "operator": _write_role_decision(
            context=context,
            output=artifacts["operator_decision"],
            role="operator",
            actor_id=operator_id,
            decision=operator_decision,
            accepted_decision=OPERATOR_AUTHORIZE,
            rejected_decision=OPERATOR_REJECT,
            statement=operator_statement,
        ),
        "audit": _write_role_decision(
            context=context,
            output=artifacts["audit_decision"],
            role="audit",
            actor_id="audit_owner",
            decision=audit_decision,
            accepted_decision=AUDIT_ACCEPT,
            rejected_decision=AUDIT_REJECT,
            statement="Accept request boundary only if authorization remains single-use and no feedback is collected in this gate.",
        ),
        "monitoring": _write_role_decision(
            context=context,
            output=artifacts["monitoring_decision"],
            role="monitoring",
            actor_id="observability_owner",
            decision=monitoring_decision,
            accepted_decision=MONITORING_ACCEPT,
            rejected_decision=MONITORING_REJECT,
            statement="Require a monitoring receipt from the later feedback execution gate.",
        ),
        "rollback": _write_role_decision(
            context=context,
            output=artifacts["rollback_decision"],
            role="rollback",
            actor_id="rollback_owner",
            decision=rollback_decision,
            accepted_decision=ROLLBACK_ACCEPT,
            rejected_decision=ROLLBACK_REJECT,
            statement="Accept abort-before-side-effects boundary for a feedback-only collection.",
        ),
    }
    receipt = _write_authorization_receipt(
        context=context,
        role_decision_paths={role: artifacts[f"{role}_decision"] for role in role_decisions},
        output=artifacts["authorization_receipt"],
        expires_in_seconds=expires_in_seconds,
    )
    boundary = _write_boundary_report(context=context, receipt_path=artifacts["authorization_receipt"], output=artifacts["boundary_report"])
    reports = [context, *role_decisions.values(), receipt, boundary]
    passed = all(report.get("passed") is True for report in reports)
    authorized = passed and receipt.get("authorization_granted") is True
    summary = {
        "schema_version": CHAIN_SCHEMA,
        "passed": passed,
        "failure_reasons": _failures(reports),
        "checked_at": _now(),
        "source_artifacts": {"limited_feedback_authorization_request_summary": artifact_ref(limited_feedback_authorization_request_summary_path)},
        "artifacts": {name: artifact_ref(path) for name, path in artifacts.items() if name != "summary"},
        "authorization_request_id": object_value(context.get("request_summary")).get("authorization_request_id"),
        "authorization_id": receipt.get("authorization_id"),
        "rejection_id": receipt.get("rejection_id"),
        "authorization_domain": AUTHORIZATION_DOMAIN,
        "authorization_granted": authorized,
        "required_next_gate": EXECUTION_GATE_AFTER_AUTHORIZATION,
        "readiness": {
            "state": "limited_external_usage_feedback_collection_authorized_once" if authorized else ("limited_external_usage_feedback_collection_rejected" if passed else "blocked_limited_external_usage_feedback_authorization_decision"),
            "limited_external_usage_feedback_authorization_decision_complete": passed,
            "authorization_granted": authorized,
            "external_user_feedback_collection_allowed": authorized,
            "feedback_collection_execution_ready": authorized,
            "feedback_collection_performed": False,
            "external_user_usage_allowed": False,
            "public_ingress_authorized": False,
            "runtime_expansion_authorized": False,
            "production_task_execution_allowed": False,
            "runtime_execution_performed": False,
            "production_runtime_receipt_write_allowed": False,
        },
        "boundary": _boundary(
            context_validation_written=context.get("passed") is True,
            role_decisions_written=all(report.get("passed") is True for report in role_decisions.values()),
            authorization_receipt_written=receipt.get("passed") is True,
            boundary_report_written=boundary.get("passed") is True,
            authorization_granted=authorized,
            external_user_feedback_collection_allowed=authorized,
            feedback_collection_execution_ready=authorized,
        ),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(artifacts["summary"], summary)
    return summary


def _validate_context(*, request_summary_path: Path, output: Path) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    request_summary = _read_json_or_empty(request_summary_path, failures, "limited_feedback_authorization_request_summary")
    artifacts = object_value(request_summary.get("artifacts"))
    request = _read_verified_ref(artifacts.get("authorization_request"), checks, failures, "authorization_request")
    boundary_report = _read_verified_ref(artifacts.get("boundary_report"), checks, failures, "request_boundary_report")
    readiness = object_value(request_summary.get("readiness"))
    boundary = object_value(request_summary.get("boundary"))
    request_readiness = object_value(request.get("readiness"))
    requested_permission = object_value(request.get("requested_permission"))

    check(checks, failures, "summary_schema", request_summary.get("schema_version") == REQUEST_CHAIN_SCHEMA)
    check(checks, failures, "summary_passed", request_summary.get("passed") is True)
    check(checks, failures, "request_schema", request.get("schema_version") == AUTHORIZATION_REQUEST_SCHEMA and request.get("passed") is True)
    check(checks, failures, "boundary_report_schema", boundary_report.get("schema_version") == REQUEST_BOUNDARY_REPORT_SCHEMA and boundary_report.get("passed") is True)
    check(checks, failures, "domain_matches", request_summary.get("authorization_domain") == AUTHORIZATION_DOMAIN and request.get("authorization_domain") == AUTHORIZATION_DOMAIN)
    check(checks, failures, "required_next_gate_matches", request.get("required_next_gate") == REQUIRED_NEXT_GATE)
    check(checks, failures, "execution_gate_matches", request.get("execution_gate_after_authorization") == EXECUTION_GATE_AFTER_AUTHORIZATION)
    check(checks, failures, "request_ready", readiness.get("limited_external_usage_feedback_authorization_request_ready") is True)
    check(checks, failures, "single_use_ready", readiness.get("single_use_authorization_request_ready") is True and request.get("single_use") is True)
    check(checks, failures, "decision_required", readiness.get("authorization_decision_required") is True)
    check(checks, failures, "request_not_pre_authorized", readiness.get("authorization_granted") is False and request_readiness.get("authorization_granted") is False)
    check(checks, failures, "feedback_not_already_allowed", readiness.get("external_user_feedback_collection_allowed") is False)
    check(checks, failures, "feedback_scope_matches", requested_permission.get("requested_feedback_scope") == DEFAULT_FEEDBACK_SCOPE)
    check(checks, failures, "max_external_users_is_one", requested_permission.get("max_external_users") == 1)
    check(checks, failures, "summary_boundary_closed", _request_boundary_closed(boundary))
    check(checks, failures, "request_boundary_closed", _request_boundary_closed(object_value(request.get("boundary"))))
    check(checks, failures, "boundary_report_closed", _request_boundary_closed(object_value(boundary_report.get("boundary"))))
    passed = _passed(checks, failures)
    report = {
        "schema_version": CONTEXT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "request_summary": request_summary,
        "authorization_request": request,
        "request_boundary_report": boundary_report,
        "source_artifacts": {"limited_feedback_authorization_request_summary": artifact_ref(request_summary_path)},
        "boundary": _boundary(context_validation_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def _write_role_decision(
    *,
    context: dict[str, Any],
    output: Path,
    role: str,
    actor_id: str,
    decision: str,
    accepted_decision: str,
    rejected_decision: str,
    statement: str,
) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "role_present", role in {"operator", "audit", "monitoring", "rollback"})
    check(checks, failures, "actor_id_present", bool(actor_id.strip()))
    check(checks, failures, "decision_valid", decision in {accepted_decision, rejected_decision})
    check(checks, failures, "statement_present", bool(statement.strip()))
    passed = _passed(checks, failures)
    accepted = passed and decision == accepted_decision
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
        "rejected_decision": rejected_decision,
        "decision_accepted": accepted,
        "statement": statement,
        "statement_sha256": sha256_json(statement),
        "authorization_request_id": object_value(context.get("request_summary")).get("authorization_request_id"),
        "source_artifacts": object_value(context.get("source_artifacts")),
        "readiness": {
            "role_decision_complete": passed,
            "role_decision_accepted": accepted,
            "authorization_granted": False,
            "feedback_collection_execution_ready": False,
        },
        "boundary": _boundary(role_decisions_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def _write_authorization_receipt(
    *,
    context: dict[str, Any],
    role_decision_paths: dict[str, Path],
    output: Path,
    expires_in_seconds: int,
) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    role_decisions = {role: _read_json_or_empty(path, failures, f"{role}_decision") for role, path in role_decision_paths.items()}
    request_summary = object_value(context.get("request_summary"))
    request_id = request_summary.get("authorization_request_id")
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "all_roles_present", set(role_decisions) == {"operator", "audit", "monitoring", "rollback"})
    for role, decision in role_decisions.items():
        check(checks, failures, f"{role}_decision_passed", decision.get("passed") is True)
    check(checks, failures, "expires_positive", expires_in_seconds > 0)
    passed = _passed(checks, failures)
    authorization_granted = passed and all(decision.get("decision_accepted") is True for decision in role_decisions.values())
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(seconds=expires_in_seconds)
    role_refs = {role: artifact_ref(path) for role, path in sorted(role_decision_paths.items())}
    receipt = {
        "schema_version": AUTHORIZATION_RECEIPT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "written_at": now.isoformat(),
        "expires_at": expires_at.isoformat() if authorization_granted else None,
        "authorization_request_id": request_id,
        "authorization_domain": AUTHORIZATION_DOMAIN,
        "authorization_granted": authorization_granted,
        "authorization_id": f"post-h3-limited-feedback-auth:{sha256_json([request_id, role_refs, expires_in_seconds])[:24]}" if authorization_granted else None,
        "rejection_id": None if authorization_granted else f"post-h3-limited-feedback-reject:{sha256_json([request_id, role_refs])[:24]}",
        "single_use": authorization_granted,
        "consumed": False,
        "consumption_required_by": EXECUTION_GATE_AFTER_AUTHORIZATION,
        "authorization_scope": {
            "authorization_domain": AUTHORIZATION_DOMAIN,
            "external_user_feedback_collection_allowed": authorization_granted,
            "feedback_collection_execution_ready": authorization_granted,
            "collect_one_external_user_feedback_record": authorization_granted,
            "max_external_users": 1 if authorization_granted else 0,
            "requested_feedback_scope": DEFAULT_FEEDBACK_SCOPE if authorization_granted else "none",
            "external_user_usage_allowed": False,
            "public_ingress_authorized": False,
            "runtime_expansion_authorized": False,
            "deploy_authorized": False,
            "production_data_access_authorized": False,
            "production_runtime_receipt_write_allowed": False,
            "source_or_git_write_allowed": False,
        },
        "source_artifacts": {"limited_feedback_authorization_request_summary": object_value(context.get("source_artifacts")).get("limited_feedback_authorization_request_summary")} | role_refs,
        "readiness": {
            "authorization_granted": authorization_granted,
            "external_user_feedback_collection_allowed": authorization_granted,
            "feedback_collection_execution_ready": authorization_granted,
            "feedback_collection_performed": False,
            "external_user_usage_allowed": False,
            "public_ingress_authorized": False,
            "runtime_expansion_authorized": False,
            "production_runtime_receipt_write_allowed": False,
        },
        "boundary": _boundary(
            authorization_receipt_written=passed,
            authorization_granted=authorization_granted,
            external_user_feedback_collection_allowed=authorization_granted,
            feedback_collection_execution_ready=authorization_granted,
        ),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, receipt)
    return receipt


def _write_boundary_report(*, context: dict[str, Any], receipt_path: Path, output: Path) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    receipt = _read_json_or_empty(receipt_path, failures, "authorization_receipt")
    scope = object_value(receipt.get("authorization_scope"))
    readiness = object_value(receipt.get("readiness"))
    authorization_granted = receipt.get("authorization_granted") is True
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "receipt_schema", receipt.get("schema_version") == AUTHORIZATION_RECEIPT_SCHEMA and receipt.get("passed") is True)
    check(checks, failures, "feedback_allowed_matches_authorization", scope.get("external_user_feedback_collection_allowed") is authorization_granted)
    check(checks, failures, "feedback_not_performed", readiness.get("feedback_collection_performed") is False)
    check(checks, failures, "no_external_usage", scope.get("external_user_usage_allowed") is False)
    check(checks, failures, "no_public_ingress", scope.get("public_ingress_authorized") is False)
    check(checks, failures, "no_runtime_expansion", scope.get("runtime_expansion_authorized") is False)
    check(checks, failures, "no_production_receipt_write", scope.get("production_runtime_receipt_write_allowed") is False)
    check(checks, failures, "no_source_or_git", scope.get("source_or_git_write_allowed") is False)
    passed = _passed(checks, failures)
    authorized = passed and authorization_granted
    report = {
        "schema_version": BOUNDARY_REPORT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "source_artifacts": {"authorization_receipt": artifact_ref(receipt_path)},
        "boundary": _boundary(
            boundary_report_written=passed,
            authorization_receipt_written=receipt.get("passed") is True,
            authorization_granted=authorized,
            external_user_feedback_collection_allowed=authorized,
            feedback_collection_execution_ready=authorized,
        ),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def _request_boundary_closed(boundary: dict[str, Any]) -> bool:
    required_false = (
        "authorization_granted",
        "external_user_feedback_collection_allowed",
        "feedback_collection_execution_ready",
        "feedback_collection_performed",
        "public_ingress_authorized",
        "runtime_expansion_authorized",
        "deploy_authorized",
        "source_write_authorized",
        "production_data_access_authorized",
        "production_task_execution_allowed",
        "runtime_execution_performed",
        "runtime_workers_currently_running",
        "backend_task_pool_mutation_performed",
        "external_public_ingress_opened",
        "deploy_performed",
        "vm_contact_performed",
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
        "role_decisions_written": False,
        "authorization_receipt_written": False,
        "boundary_report_written": False,
        "authorization_granted": False,
        "external_user_feedback_collection_allowed": False,
        "feedback_collection_execution_ready": False,
        "feedback_collection_performed": False,
        "external_user_usage_allowed": False,
        "public_ingress_authorized": False,
        "runtime_expansion_authorized": False,
        "deploy_authorized": False,
        "source_write_authorized": False,
        "production_data_access_authorized": False,
        "production_task_execution_allowed": False,
        "runtime_execution_performed": False,
        "runtime_workers_currently_running": False,
        "backend_task_pool_mutation_performed": False,
        "external_public_ingress_opened": False,
        "deploy_performed": False,
        "vm_contact_performed": False,
        "production_data_accessed": False,
        "production_runtime_receipt_write_allowed": False,
        "production_runtime_receipt_written": False,
        "source_tree_write_performed": False,
        "git_write_performed": False,
        "secrets_recorded": False,
    }
    boundary.update(overrides)
    return boundary


def _write_blocked_summary(*, output: Path, request_summary_path: Path, failure: str) -> dict[str, Any]:
    summary = {
        "schema_version": CHAIN_SCHEMA,
        "passed": False,
        "failure_reasons": [failure],
        "checks": {failure: False},
        "checked_at": _now(),
        "source_artifacts": {
            "limited_feedback_authorization_request_summary": artifact_ref(request_summary_path)
            if request_summary_path.exists()
            else {"path": str(request_summary_path.resolve()), "sha256": ""}
        },
        "authorization_domain": AUTHORIZATION_DOMAIN,
        "authorization_granted": False,
        "required_next_gate": EXECUTION_GATE_AFTER_AUTHORIZATION,
        "readiness": {
            "state": "blocked_limited_external_usage_feedback_authorization_decision",
            "limited_external_usage_feedback_authorization_decision_complete": False,
            "authorization_granted": False,
            "external_user_feedback_collection_allowed": False,
            "feedback_collection_execution_ready": False,
            "feedback_collection_performed": False,
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
    parser.add_argument("--limited-feedback-authorization-request-summary", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--operator-id", default="operator-primary")
    parser.add_argument("--operator-decision", default=OPERATOR_AUTHORIZE)
    parser.add_argument("--audit-decision", default=AUDIT_ACCEPT)
    parser.add_argument("--monitoring-decision", default=MONITORING_ACCEPT)
    parser.add_argument("--rollback-decision", default=ROLLBACK_ACCEPT)
    parser.add_argument("--operator-statement", default=DEFAULT_OPERATOR_STATEMENT)
    parser.add_argument("--expires-in-seconds", type=int, default=3600)
    parser.add_argument("--ack-authorization-decision", action="store_true")
    args = parser.parse_args(argv)
    summary = run_gate(
        limited_feedback_authorization_request_summary_path=args.limited_feedback_authorization_request_summary,
        output_root=args.output_root,
        operator_id=args.operator_id,
        operator_decision=args.operator_decision,
        audit_decision=args.audit_decision,
        monitoring_decision=args.monitoring_decision,
        rollback_decision=args.rollback_decision,
        operator_statement=args.operator_statement,
        expires_in_seconds=args.expires_in_seconds,
        ack_authorization_decision=args.ack_authorization_decision,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if summary.get("passed") is True else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
