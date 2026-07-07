"""Request one PostH3 limited external-usage feedback authorization.

This gate consumes the higher-permission authorization reconciliation and writes
one single-use authorization request for
``limited_external_usage_feedback_collection_once``. It does not grant
authorization, collect feedback, execute runtime work, open public ingress,
deploy, access production data, write production runtime receipts, or write
source/Git state.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from benchmarks.i_gate_evidence import artifact_ref, check, object_value, read_json_object, sha256_file, sha256_json, write_json_object
from benchmarks.post_h3_higher_permission_authorization_reconciliation_gate import (
    BOUNDARY_REPORT_SCHEMA as RECONCILIATION_BOUNDARY_REPORT_SCHEMA,
    CHAIN_SCHEMA as RECONCILIATION_CHAIN_SCHEMA,
    RECONCILIATION_SCHEMA,
)
CHAIN_SCHEMA = "post-h3-limited-external-usage-feedback-authorization-request-gate:v1"
CONTEXT_SCHEMA = "post-h3-limited-feedback-authorization-request-context:v1"
AUTHORIZATION_REQUEST_SCHEMA = "post-h3-limited-feedback-single-use-authorization-request:v1"
BOUNDARY_REPORT_SCHEMA = "post-h3-limited-feedback-authorization-request-boundary:v1"
LIMITED_FEEDBACK_RECONCILIATION_CHAIN_SCHEMA = "post-h3-limited-feedback-higher-permission-review-reconciliation-gate:v1"
LIMITED_FEEDBACK_RECONCILIATION_SCHEMA = "post-h3-limited-feedback-higher-permission-review-reconciliation:v1"
LIMITED_FEEDBACK_RECONCILIATION_BOUNDARY_REPORT_SCHEMA = "post-h3-limited-feedback-higher-permission-review-reconciliation-boundary:v1"

AUTHORIZATION_DOMAIN = "limited_external_usage_feedback_collection_once"
REQUIRED_NEXT_GATE = "post_h3_limited_external_usage_feedback_authorization_decision_gate"
EXECUTION_GATE_AFTER_AUTHORIZATION = "post_h3_external_user_feedback_collection_gate"
DEFAULT_OPERATOR_STATEMENT = (
    "Request one single-use authorization for limited external usage feedback collection only; "
    "do not grant or execute in this request gate."
)
DEFAULT_FEEDBACK_SCOPE = "invite-only-post-usage-feedback-only"
NON_CLAIMS = (
    "limited_feedback_authorization_request_only",
    "limited_feedback_request_does_not_grant_authorization",
    "limited_feedback_request_does_not_collect_feedback",
    "limited_feedback_request_does_not_execute_runtime_task",
    "limited_feedback_request_does_not_open_public_ingress",
    "limited_feedback_request_does_not_start_runtime_workers",
    "limited_feedback_request_does_not_deploy",
    "limited_feedback_request_does_not_access_production_data",
    "limited_feedback_request_does_not_write_production_runtime_receipts",
    "limited_feedback_request_does_not_write_source_or_git",
)


def run_gate(
    *,
    higher_permission_reconciliation_summary_path: Path,
    output_root: Path,
    operator_id: str = "operator-primary",
    operator_statement: str = DEFAULT_OPERATOR_STATEMENT,
    max_external_users: int = 1,
    requested_feedback_scope: str = DEFAULT_FEEDBACK_SCOPE,
    ack_authorization_request: bool = False,
) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "context_validation": output_root / "post_h3_limited_feedback_authorization_request_context.json",
        "authorization_request": output_root / "post_h3_limited_feedback_single_use_authorization_request.json",
        "boundary_report": output_root / "post_h3_limited_feedback_authorization_request_boundary_report.json",
        "summary": output_root / "post_h3_limited_feedback_authorization_request_summary.json",
    }
    if not ack_authorization_request:
        return _write_blocked_summary(
            output=artifacts["summary"],
            higher_permission_reconciliation_summary_path=higher_permission_reconciliation_summary_path,
            failure="explicit_limited_feedback_authorization_request_ack",
        )

    context = _validate_context(
        higher_permission_reconciliation_summary_path=higher_permission_reconciliation_summary_path,
        output=artifacts["context_validation"],
    )
    request = _write_authorization_request(
        context=context,
        higher_permission_reconciliation_summary_path=higher_permission_reconciliation_summary_path,
        output=artifacts["authorization_request"],
        operator_id=operator_id,
        operator_statement=operator_statement,
        max_external_users=max_external_users,
        requested_feedback_scope=requested_feedback_scope,
    )
    boundary = _write_boundary_report(
        context=context,
        request_path=artifacts["authorization_request"],
        output=artifacts["boundary_report"],
    )
    reports = [context, request, boundary]
    passed = all(report.get("passed") is True for report in reports)
    summary = {
        "schema_version": CHAIN_SCHEMA,
        "passed": passed,
        "failure_reasons": _failures(reports),
        "checked_at": _now(),
        "source_artifacts": {"higher_permission_reconciliation_summary": artifact_ref(higher_permission_reconciliation_summary_path)},
        "artifacts": {name: artifact_ref(path) for name, path in artifacts.items() if name != "summary"},
        "authorization_request_id": request.get("authorization_request_id"),
        "authorization_domain": AUTHORIZATION_DOMAIN,
        "reconciliation_id": object_value(context.get("reconciliation_summary")).get("reconciliation_id"),
        "required_next_gate": REQUIRED_NEXT_GATE,
        "execution_gate_after_authorization": EXECUTION_GATE_AFTER_AUTHORIZATION,
        "readiness": {
            "state": "limited_external_usage_feedback_authorization_request_ready" if passed else "blocked_limited_external_usage_feedback_authorization_request",
            "limited_external_usage_feedback_authorization_request_ready": passed,
            "single_use_authorization_request_ready": passed,
            "authorization_decision_required": passed,
            "authorization_granted": False,
            "feedback_collection_execution_ready": False,
            "external_user_feedback_collection_allowed": False,
            "production_task_execution_allowed": False,
            "runtime_execution_performed": False,
            "production_runtime_receipt_write_allowed": False,
        },
        "boundary": _boundary(
            context_validation_written=context.get("passed") is True,
            authorization_request_written=request.get("passed") is True,
            boundary_report_written=boundary.get("passed") is True,
            limited_external_usage_feedback_authorization_request_ready=passed,
            single_use_authorization_request_ready=passed,
        ),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(artifacts["summary"], summary)
    return summary


def _validate_context(*, higher_permission_reconciliation_summary_path: Path, output: Path) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    reconciliation_summary = _read_json_or_empty(higher_permission_reconciliation_summary_path, failures, "higher_permission_reconciliation_summary")
    artifacts = object_value(reconciliation_summary.get("artifacts"))
    reconciliation = _read_verified_ref(artifacts.get("reconciliation"), checks, failures, "higher_permission_reconciliation")
    boundary_report = _read_verified_ref(artifacts.get("boundary_report"), checks, failures, "higher_permission_reconciliation_boundary_report")
    readiness = object_value(reconciliation_summary.get("readiness"))
    boundary = object_value(reconciliation_summary.get("boundary"))
    approved_domains = set(reconciliation_summary.get("approved_review_domains") if isinstance(reconciliation_summary.get("approved_review_domains"), list) else [])
    reconciliation_domains = set(reconciliation.get("approved_review_domains") if isinstance(reconciliation.get("approved_review_domains"), list) else [])

    summary_schema = reconciliation_summary.get("schema_version")
    is_standard_reconciliation = summary_schema == RECONCILIATION_CHAIN_SCHEMA
    is_limited_feedback_reconciliation = summary_schema == LIMITED_FEEDBACK_RECONCILIATION_CHAIN_SCHEMA
    expected_reconciliation_schema = (
        LIMITED_FEEDBACK_RECONCILIATION_SCHEMA if is_limited_feedback_reconciliation else RECONCILIATION_SCHEMA
    )
    expected_boundary_schema = (
        LIMITED_FEEDBACK_RECONCILIATION_BOUNDARY_REPORT_SCHEMA
        if is_limited_feedback_reconciliation
        else RECONCILIATION_BOUNDARY_REPORT_SCHEMA
    )
    limited_feedback_ready = (
        readiness.get("limited_external_usage_authorization_request_ready") is True
        or readiness.get("limited_feedback_authorization_request_ready") is True
    )
    execution_not_allowed = (
        readiness.get("production_task_execution_allowed") is False
        and readiness.get("execution_authorization_ready", False) is False
    )

    check(checks, failures, "summary_schema", is_standard_reconciliation or is_limited_feedback_reconciliation)
    check(checks, failures, "summary_passed", reconciliation_summary.get("passed") is True)
    check(checks, failures, "reconciliation_schema", reconciliation.get("schema_version") == expected_reconciliation_schema and reconciliation.get("passed") is True)
    check(checks, failures, "boundary_report_schema", boundary_report.get("schema_version") == expected_boundary_schema and boundary_report.get("passed") is True)
    check(checks, failures, "single_use_request_ready", readiness.get("single_use_authorization_request_ready") is True)
    check(checks, failures, "limited_feedback_request_ready", limited_feedback_ready)
    check(checks, failures, "limited_feedback_domain_approved", AUTHORIZATION_DOMAIN in approved_domains and AUTHORIZATION_DOMAIN in reconciliation_domains)
    check(checks, failures, "summary_authorization_not_granted", readiness.get("authorization_granted") is False)
    check(checks, failures, "summary_execution_not_allowed", execution_not_allowed)
    check(checks, failures, "summary_receipts_not_allowed", readiness.get("production_runtime_receipt_write_allowed") is False)
    check(checks, failures, "summary_boundary_closed", _closed_boundary(boundary))
    check(checks, failures, "reconciliation_boundary_closed", _closed_boundary(object_value(reconciliation.get("boundary"))))
    check(checks, failures, "boundary_report_closed", _closed_boundary(object_value(boundary_report.get("boundary"))))
    passed = _passed(checks, failures)
    report = {
        "schema_version": CONTEXT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "reconciliation_summary": reconciliation_summary,
        "reconciliation": reconciliation,
        "reconciliation_boundary_report": boundary_report,
        "source_artifacts": {"higher_permission_reconciliation_summary": artifact_ref(higher_permission_reconciliation_summary_path)},
        "boundary": _boundary(context_validation_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def _write_authorization_request(
    *,
    context: dict[str, Any],
    higher_permission_reconciliation_summary_path: Path,
    output: Path,
    operator_id: str,
    operator_statement: str,
    max_external_users: int,
    requested_feedback_scope: str,
) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    reconciliation_summary = object_value(context.get("reconciliation_summary"))
    reconciliation_id = reconciliation_summary.get("reconciliation_id")
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "operator_id_present", bool(operator_id.strip()))
    check(checks, failures, "operator_statement_present", bool(operator_statement.strip()))
    check(checks, failures, "max_external_users_is_one", max_external_users == 1)
    check(checks, failures, "feedback_scope_is_feedback_only", requested_feedback_scope == DEFAULT_FEEDBACK_SCOPE)
    passed = _passed(checks, failures)
    request = {
        "schema_version": AUTHORIZATION_REQUEST_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "requested_at": _now(),
        "authorization_request_id": f"post-h3-limited-feedback-auth-request:{sha256_json([artifact_ref(higher_permission_reconciliation_summary_path), operator_id, operator_statement, max_external_users, requested_feedback_scope])[:24]}",
        "authorization_domain": AUTHORIZATION_DOMAIN,
        "single_use": True,
        "operator_id": operator_id,
        "operator_statement": operator_statement,
        "operator_statement_sha256": sha256_json(operator_statement),
        "reconciliation_id": reconciliation_id,
        "required_next_gate": REQUIRED_NEXT_GATE,
        "execution_gate_after_authorization": EXECUTION_GATE_AFTER_AUTHORIZATION,
        "requested_permission": {
            "collect_one_external_user_feedback_record": True,
            "max_external_users": max_external_users,
            "requested_feedback_scope": requested_feedback_scope,
            "allowed_feedback_source": "operator_supplied_external_user_feedback",
            "requires_no_secret_payload": True,
        },
        "constraints": {
            "authorization_granted_here": False,
            "feedback_collection_performed_here": False,
            "execution_allowed_here": False,
            "public_ingress_allowed": False,
            "runtime_expansion_allowed": False,
            "deploy_allowed": False,
            "production_data_access_allowed": False,
            "production_runtime_receipt_write_allowed": False,
            "source_or_git_write_allowed": False,
            "fresh_authorization_decision_required": True,
            "single_use_consumption_required_before_execution_gate": True,
            "rollback_or_abort_receipt_required_after_execution_gate": True,
            "owner_audit_reconciliation_required_after_execution_gate": True,
        },
        "source_artifacts": {"higher_permission_reconciliation_summary": artifact_ref(higher_permission_reconciliation_summary_path)},
        "readiness": {
            "authorization_request_ready": passed,
            "single_use_authorization_request_ready": passed,
            "authorization_decision_required": passed,
            "authorization_granted": False,
            "feedback_collection_execution_ready": False,
            "external_user_feedback_collection_allowed": False,
            "production_task_execution_allowed": False,
        },
        "boundary": _boundary(authorization_request_written=passed, single_use_authorization_request_ready=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, request)
    return request


def _write_boundary_report(*, context: dict[str, Any], request_path: Path, output: Path) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    request = _read_json_or_empty(request_path, failures, "authorization_request")
    readiness = object_value(request.get("readiness"))
    constraints = object_value(request.get("constraints"))
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "request_schema", request.get("schema_version") == AUTHORIZATION_REQUEST_SCHEMA and request.get("passed") is True)
    check(checks, failures, "request_domain", request.get("authorization_domain") == AUTHORIZATION_DOMAIN)
    check(checks, failures, "request_single_use", request.get("single_use") is True)
    check(checks, failures, "request_ready", readiness.get("authorization_request_ready") is True)
    check(checks, failures, "request_does_not_grant", readiness.get("authorization_granted") is False and constraints.get("authorization_granted_here") is False)
    check(checks, failures, "feedback_not_allowed_yet", readiness.get("external_user_feedback_collection_allowed") is False)
    check(checks, failures, "execution_not_ready", readiness.get("feedback_collection_execution_ready") is False)
    check(checks, failures, "closed_boundary", _closed_boundary(object_value(request.get("boundary"))))
    passed = _passed(checks, failures)
    report = {
        "schema_version": BOUNDARY_REPORT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "source_artifacts": {"authorization_request": artifact_ref(request_path)},
        "boundary": _boundary(
            boundary_report_written=passed,
            authorization_request_written=request.get("passed") is True,
            limited_external_usage_feedback_authorization_request_ready=passed,
            single_use_authorization_request_ready=passed,
        ),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def _closed_boundary(boundary: dict[str, Any]) -> bool:
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
        "authorization_request_written": False,
        "boundary_report_written": False,
        "limited_external_usage_feedback_authorization_request_ready": False,
        "single_use_authorization_request_ready": False,
        "authorization_granted": False,
        "authorization_decision_written": False,
        "external_user_feedback_collection_allowed": False,
        "feedback_collection_execution_ready": False,
        "feedback_collection_performed": False,
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


def _write_blocked_summary(*, output: Path, higher_permission_reconciliation_summary_path: Path, failure: str) -> dict[str, Any]:
    summary = {
        "schema_version": CHAIN_SCHEMA,
        "passed": False,
        "failure_reasons": [failure],
        "checks": {failure: False},
        "checked_at": _now(),
        "source_artifacts": {
            "higher_permission_reconciliation_summary": artifact_ref(higher_permission_reconciliation_summary_path)
            if higher_permission_reconciliation_summary_path.exists()
            else {"path": str(higher_permission_reconciliation_summary_path.resolve()), "sha256": ""}
        },
        "authorization_domain": AUTHORIZATION_DOMAIN,
        "required_next_gate": REQUIRED_NEXT_GATE,
        "execution_gate_after_authorization": EXECUTION_GATE_AFTER_AUTHORIZATION,
        "readiness": {
            "state": "blocked_limited_external_usage_feedback_authorization_request",
            "limited_external_usage_feedback_authorization_request_ready": False,
            "single_use_authorization_request_ready": False,
            "authorization_decision_required": False,
            "authorization_granted": False,
            "feedback_collection_execution_ready": False,
            "external_user_feedback_collection_allowed": False,
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
    parser.add_argument("--higher-permission-reconciliation-summary", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--operator-id", default="operator-primary")
    parser.add_argument("--operator-statement", default=DEFAULT_OPERATOR_STATEMENT)
    parser.add_argument("--max-external-users", type=int, default=1)
    parser.add_argument("--requested-feedback-scope", default=DEFAULT_FEEDBACK_SCOPE)
    parser.add_argument("--ack-authorization-request", action="store_true")
    args = parser.parse_args(argv)
    summary = run_gate(
        higher_permission_reconciliation_summary_path=args.higher_permission_reconciliation_summary,
        output_root=args.output_root,
        operator_id=args.operator_id,
        operator_statement=args.operator_statement,
        max_external_users=args.max_external_users,
        requested_feedback_scope=args.requested_feedback_scope,
        ack_authorization_request=args.ack_authorization_request,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if summary.get("passed") is True else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
