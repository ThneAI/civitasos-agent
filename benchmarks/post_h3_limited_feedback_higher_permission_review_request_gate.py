"""Request higher-permission review after limited-feedback closeout.

This gate consumes a passed limited-feedback closeout/strategy summary whose
operator decision is ``request_higher_permission_review_after_limited_feedback``.
It writes a review request only. It never grants authorization, executes
external usage, opens public ingress, starts runtime workers, deploys, accesses
production data, writes production runtime receipts, or writes source/Git state.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from benchmarks.i_gate_evidence import artifact_ref, check, object_value, read_json_object, sha256_file, sha256_json, write_json_object
from benchmarks.post_h3_limited_external_usage_feedback_closeout_strategy_gate import (
    BOUNDARY_REPORT_SCHEMA as CLOSEOUT_BOUNDARY_REPORT_SCHEMA,
    CHAIN_SCHEMA as CLOSEOUT_CHAIN_SCHEMA,
    CONTEXT_SCHEMA as CLOSEOUT_CONTEXT_SCHEMA,
    EVIDENCE_INDEX_SCHEMA as CLOSEOUT_EVIDENCE_INDEX_SCHEMA,
    HIGHER_PERMISSION_AUDIT_DECISION,
    HIGHER_PERMISSION_MONITORING_DECISION,
    HIGHER_PERMISSION_ROLLBACK_DECISION,
    REQUEST_HIGHER_PERMISSION_DECISION,
    STRATEGY_PACKET_SCHEMA as CLOSEOUT_STRATEGY_PACKET_SCHEMA,
    STRATEGY_RECONCILIATION_SCHEMA as CLOSEOUT_STRATEGY_RECONCILIATION_SCHEMA,
)

CHAIN_SCHEMA = "post-h3-limited-feedback-higher-permission-review-request-gate:v1"
CONTEXT_SCHEMA = "post-h3-limited-feedback-higher-permission-review-context:v1"
REVIEW_REQUEST_SCHEMA = "post-h3-limited-feedback-higher-permission-review-request:v1"
BOUNDARY_REPORT_SCHEMA = "post-h3-limited-feedback-higher-permission-review-boundary:v1"

DEFAULT_REQUESTED_ACTION_DOMAIN = "bounded_external_usage_or_runtime_expansion_review_only"
REQUIRED_NEXT_GATE = "post_h3_limited_feedback_higher_permission_review_reconciliation_gate"
DEFAULT_OPERATOR_STATEMENT = (
    "Request higher-permission review after limited-feedback closeout; "
    "execution remains separately gated and is not authorized here."
)
NON_CLAIMS = (
    "higher_permission_review_request_only",
    "higher_permission_review_request_does_not_grant_authorization",
    "higher_permission_review_request_does_not_execute_external_user_usage",
    "higher_permission_review_request_does_not_open_public_ingress",
    "higher_permission_review_request_does_not_start_runtime_workers",
    "higher_permission_review_request_does_not_deploy",
    "higher_permission_review_request_does_not_access_production_data",
    "higher_permission_review_request_does_not_write_production_runtime_receipts",
    "higher_permission_review_request_does_not_write_source_or_git",
)


def run_gate(
    *,
    limited_feedback_closeout_strategy_summary_path: Path,
    output_root: Path,
    operator_id: str = "operator-primary",
    operator_statement: str = DEFAULT_OPERATOR_STATEMENT,
    requested_action_domain: str = DEFAULT_REQUESTED_ACTION_DOMAIN,
    max_external_users: int = 1,
    max_runtime_workers: int = 1,
    ack_review_request: bool = False,
) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "context_validation": output_root / "post_h3_limited_feedback_higher_permission_review_context.json",
        "review_request": output_root / "post_h3_limited_feedback_higher_permission_review_request.json",
        "boundary_report": output_root / "post_h3_limited_feedback_higher_permission_review_boundary_report.json",
        "summary": output_root / "post_h3_limited_feedback_higher_permission_review_request_summary.json",
    }
    if not ack_review_request:
        return _write_blocked_summary(
            output=artifacts["summary"],
            limited_feedback_closeout_strategy_summary_path=limited_feedback_closeout_strategy_summary_path,
            failure="explicit_higher_permission_review_request_ack",
        )

    context = _validate_context(
        limited_feedback_closeout_strategy_summary_path=limited_feedback_closeout_strategy_summary_path,
        output=artifacts["context_validation"],
    )
    request = _write_review_request(
        context=context,
        closeout_strategy_summary_path=limited_feedback_closeout_strategy_summary_path,
        output=artifacts["review_request"],
        operator_id=operator_id,
        operator_statement=operator_statement,
        requested_action_domain=requested_action_domain,
        max_external_users=max_external_users,
        max_runtime_workers=max_runtime_workers,
    )
    boundary = _write_boundary_report(
        context=context,
        review_request_path=artifacts["review_request"],
        output=artifacts["boundary_report"],
    )
    reports = [context, request, boundary]
    passed = all(report.get("passed") is True for report in reports)
    summary = {
        "schema_version": CHAIN_SCHEMA,
        "passed": passed,
        "failure_reasons": _failures(reports),
        "checked_at": _now(),
        "source_artifacts": {"limited_feedback_closeout_strategy_summary": artifact_ref(limited_feedback_closeout_strategy_summary_path)},
        "artifacts": {name: artifact_ref(path) for name, path in artifacts.items() if name != "summary"},
        "higher_permission_review_request_id": request.get("higher_permission_review_request_id"),
        "limited_feedback_closeout_strategy_id": object_value(context.get("closeout_summary")).get("limited_feedback_closeout_strategy_id"),
        "requested_action_domain": requested_action_domain,
        "required_next_gate": REQUIRED_NEXT_GATE,
        "readiness": {
            "state": "limited_feedback_higher_permission_review_requested" if passed else "blocked_limited_feedback_higher_permission_review_request",
            "higher_permission_review_request_complete": passed,
            "higher_permission_review_ready": passed,
            "authorization_granted": False,
            "execution_authorization_ready": False,
            "future_execution_requires_separate_single_use_authorization": True,
            "external_user_usage_allowed": False,
            "public_ingress_authorized": False,
            "runtime_expansion_authorized": False,
            "production_task_execution_allowed": False,
            "runtime_execution_performed": False,
            "production_runtime_receipt_write_allowed": False,
        },
        "boundary": _boundary(
            context_validation_written=context.get("passed") is True,
            higher_permission_review_request_written=request.get("passed") is True,
            boundary_report_written=boundary.get("passed") is True,
            higher_permission_review_ready=passed,
        ),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(artifacts["summary"], summary)
    return summary


def _validate_context(*, limited_feedback_closeout_strategy_summary_path: Path, output: Path) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    summary = _read_json_or_empty(limited_feedback_closeout_strategy_summary_path, failures, "closeout_strategy_summary")
    artifacts = object_value(summary.get("artifacts"))
    context = _read_verified_ref(artifacts.get("context_validation"), checks, failures, "closeout_context")
    evidence_index = _read_verified_ref(artifacts.get("evidence_index"), checks, failures, "closeout_evidence_index")
    strategy_packet = _read_verified_ref(artifacts.get("strategy_packet"), checks, failures, "closeout_strategy_packet")
    reconciliation = _read_verified_ref(artifacts.get("strategy_reconciliation"), checks, failures, "closeout_strategy_reconciliation")
    boundary_report = _read_verified_ref(artifacts.get("boundary_report"), checks, failures, "closeout_boundary_report")
    readiness = object_value(summary.get("readiness"))
    boundary = object_value(summary.get("boundary"))

    check(checks, failures, "summary_schema", summary.get("schema_version") == CLOSEOUT_CHAIN_SCHEMA)
    check(checks, failures, "summary_passed", summary.get("passed") is True)
    check(checks, failures, "summary_requests_higher_permission", summary.get("operator_decision") == REQUEST_HIGHER_PERMISSION_DECISION)
    check(checks, failures, "summary_higher_permission_ready", readiness.get("higher_permission_review_request_ready") is True)
    check(checks, failures, "summary_observer_not_continued", readiness.get("observer_mode_continues") is False)
    check(checks, failures, "summary_revision_not_required", readiness.get("revision_required") is False)
    check(checks, failures, "summary_no_single_use_ready", readiness.get("next_single_use_gate_input_ready") is False)
    check(checks, failures, "summary_external_usage_not_allowed", readiness.get("external_user_usage_allowed") is False)
    check(checks, failures, "summary_boundary_closed", _closed_boundary(boundary))

    check(checks, failures, "context_schema", context.get("schema_version") == CLOSEOUT_CONTEXT_SCHEMA and context.get("passed") is True)
    check(checks, failures, "evidence_index_schema", evidence_index.get("schema_version") == CLOSEOUT_EVIDENCE_INDEX_SCHEMA and evidence_index.get("passed") is True)
    check(checks, failures, "strategy_packet_schema", strategy_packet.get("schema_version") == CLOSEOUT_STRATEGY_PACKET_SCHEMA and strategy_packet.get("passed") is True)
    check(checks, failures, "reconciliation_schema", reconciliation.get("schema_version") == CLOSEOUT_STRATEGY_RECONCILIATION_SCHEMA and reconciliation.get("passed") is True)
    check(checks, failures, "boundary_report_schema", boundary_report.get("schema_version") == CLOSEOUT_BOUNDARY_REPORT_SCHEMA and boundary_report.get("passed") is True)
    check(checks, failures, "reconciliation_operator_requests_higher_permission", reconciliation.get("operator_decision") == REQUEST_HIGHER_PERMISSION_DECISION)
    check(checks, failures, "reconciliation_audit_accepts_higher_permission", reconciliation.get("audit_decision") == HIGHER_PERMISSION_AUDIT_DECISION)
    check(checks, failures, "reconciliation_monitoring_accepts_higher_permission", reconciliation.get("monitoring_decision") == HIGHER_PERMISSION_MONITORING_DECISION)
    check(checks, failures, "reconciliation_rollback_accepts_higher_permission", reconciliation.get("rollback_decision") == HIGHER_PERMISSION_ROLLBACK_DECISION)
    check(checks, failures, "reconciliation_higher_permission_ready", reconciliation.get("higher_permission_review_request_ready") is True)
    check(checks, failures, "reconciliation_boundary_closed", _closed_boundary(object_value(reconciliation.get("boundary"))))
    check(checks, failures, "boundary_report_closed", _closed_boundary(object_value(boundary_report.get("boundary"))))
    passed = _passed(checks, failures)
    report = {
        "schema_version": CONTEXT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "closeout_summary": summary,
        "closeout_context": context,
        "closeout_evidence_index": evidence_index,
        "closeout_strategy_packet": strategy_packet,
        "closeout_strategy_reconciliation": reconciliation,
        "closeout_boundary_report": boundary_report,
        "source_artifacts": {"limited_feedback_closeout_strategy_summary": artifact_ref(limited_feedback_closeout_strategy_summary_path)},
        "boundary": _boundary(context_validation_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def _write_review_request(
    *,
    context: dict[str, Any],
    closeout_strategy_summary_path: Path,
    output: Path,
    operator_id: str,
    operator_statement: str,
    requested_action_domain: str,
    max_external_users: int,
    max_runtime_workers: int,
) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    closeout_summary = object_value(context.get("closeout_summary"))
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "operator_id_present", bool(operator_id.strip()))
    check(checks, failures, "operator_statement_present", bool(operator_statement.strip()))
    check(checks, failures, "requested_action_domain_present", bool(requested_action_domain.strip()))
    check(checks, failures, "max_external_users_bounded", max_external_users == 1)
    check(checks, failures, "max_runtime_workers_bounded", max_runtime_workers == 1)
    passed = _passed(checks, failures)
    request = {
        "schema_version": REVIEW_REQUEST_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "requested_at": _now(),
        "higher_permission_review_request_id": f"post-h3-limited-feedback-higher-permission-review-request:{sha256_json([artifact_ref(closeout_strategy_summary_path), operator_id, operator_statement, requested_action_domain])[:24]}",
        "operator_id": operator_id,
        "operator_statement": operator_statement,
        "operator_statement_sha256": sha256_json(operator_statement),
        "requested_action_domain": requested_action_domain,
        "limited_feedback_closeout_strategy_id": closeout_summary.get("limited_feedback_closeout_strategy_id"),
        "required_next_gate": REQUIRED_NEXT_GATE,
        "requested_permission_review": {
            "review_higher_permission_action": True,
            "max_external_users": max_external_users,
            "max_runtime_workers": max_runtime_workers,
            "allowed_scope": requested_action_domain,
            "requires_owner_audit_monitoring_rollback_reconciliation": True,
            "requires_separate_single_use_authorization_before_execution": True,
        },
        "constraints": {
            "authorization_granted_here": False,
            "execution_authorization_ready_here": False,
            "external_user_usage_allowed_here": False,
            "public_ingress_authorized_here": False,
            "runtime_expansion_authorized_here": False,
            "production_runtime_receipt_write_allowed_here": False,
            "source_or_git_write_allowed_here": False,
        },
        "required_next_steps": [
            "operator_review",
            "audit_review",
            "monitoring_owner_review",
            "rollback_owner_review",
            "security_review_if_public_ingress_or_runtime_expansion_requested",
            "separate_single_use_authorization_before_any_execution",
        ],
        "source_artifacts": {"limited_feedback_closeout_strategy_summary": artifact_ref(closeout_strategy_summary_path)},
        "readiness": {
            "higher_permission_review_request_ready": passed,
            "authorization_granted": False,
            "execution_authorization_ready": False,
            "external_user_usage_allowed": False,
            "public_ingress_authorized": False,
            "runtime_expansion_authorized": False,
            "production_task_execution_allowed": False,
            "production_runtime_receipt_write_allowed": False,
        },
        "boundary": _boundary(higher_permission_review_request_written=passed, higher_permission_review_ready=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, request)
    return request


def _write_boundary_report(*, context: dict[str, Any], review_request_path: Path, output: Path) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    request = _read_json_or_empty(review_request_path, failures, "higher_permission_review_request")
    readiness = object_value(request.get("readiness"))
    constraints = object_value(request.get("constraints"))
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "request_schema", request.get("schema_version") == REVIEW_REQUEST_SCHEMA and request.get("passed") is True)
    check(checks, failures, "request_ready", readiness.get("higher_permission_review_request_ready") is True)
    check(checks, failures, "authorization_not_granted", readiness.get("authorization_granted") is False and constraints.get("authorization_granted_here") is False)
    check(checks, failures, "execution_not_ready", readiness.get("execution_authorization_ready") is False)
    check(checks, failures, "external_usage_not_allowed", readiness.get("external_user_usage_allowed") is False)
    check(checks, failures, "public_ingress_not_authorized", readiness.get("public_ingress_authorized") is False)
    check(checks, failures, "runtime_expansion_not_authorized", readiness.get("runtime_expansion_authorized") is False)
    check(checks, failures, "closed_boundary", _closed_boundary(object_value(request.get("boundary"))))
    passed = _passed(checks, failures)
    report = {
        "schema_version": BOUNDARY_REPORT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "source_artifacts": {"higher_permission_review_request": artifact_ref(review_request_path)},
        "boundary": _boundary(
            boundary_report_written=passed,
            higher_permission_review_request_written=request.get("passed") is True,
            higher_permission_review_ready=passed,
        ),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def _write_blocked_summary(*, output: Path, limited_feedback_closeout_strategy_summary_path: Path, failure: str) -> dict[str, Any]:
    summary = {
        "schema_version": CHAIN_SCHEMA,
        "passed": False,
        "failure_reasons": [failure],
        "checks": {failure: False},
        "checked_at": _now(),
        "source_artifacts": {
            "limited_feedback_closeout_strategy_summary": artifact_ref(limited_feedback_closeout_strategy_summary_path)
            if limited_feedback_closeout_strategy_summary_path.exists()
            else {"path": str(limited_feedback_closeout_strategy_summary_path.resolve()), "sha256": ""}
        },
        "required_next_gate": REQUIRED_NEXT_GATE,
        "readiness": {
            "state": "blocked_limited_feedback_higher_permission_review_request",
            "higher_permission_review_request_complete": False,
            "higher_permission_review_ready": False,
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


def _closed_boundary(boundary: dict[str, Any]) -> bool:
    required_false = (
        "next_single_use_gate_input_ready",
        "additional_feedback_collection_ready",
        "external_user_usage_allowed",
        "external_user_usage_execution_ready",
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


def _boundary(**overrides: bool) -> dict[str, bool]:
    boundary = {
        "context_validation_written": False,
        "higher_permission_review_request_written": False,
        "boundary_report_written": False,
        "higher_permission_review_ready": False,
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
    parser.add_argument("--limited-feedback-closeout-strategy-summary", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--operator-id", default="operator-primary")
    parser.add_argument("--operator-statement", default=DEFAULT_OPERATOR_STATEMENT)
    parser.add_argument("--requested-action-domain", default=DEFAULT_REQUESTED_ACTION_DOMAIN)
    parser.add_argument("--max-external-users", type=int, default=1)
    parser.add_argument("--max-runtime-workers", type=int, default=1)
    parser.add_argument("--ack-review-request", action="store_true")
    args = parser.parse_args(argv)
    summary = run_gate(
        limited_feedback_closeout_strategy_summary_path=args.limited_feedback_closeout_strategy_summary,
        output_root=args.output_root,
        operator_id=args.operator_id,
        operator_statement=args.operator_statement,
        requested_action_domain=args.requested_action_domain,
        max_external_users=args.max_external_users,
        max_runtime_workers=args.max_runtime_workers,
        ack_review_request=args.ack_review_request,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if summary.get("passed") is True else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
