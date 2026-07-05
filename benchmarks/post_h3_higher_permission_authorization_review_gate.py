"""Create a PostH3 higher-permission authorization review request.

This gate consumes the bounded owner briefing repeated-validation summary and
only opens a review surface for higher-permission paths. It does not grant any
permission, execute runtime work, open public ingress, deploy, access production
data, write production runtime receipts, or write source/Git state.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from benchmarks.i_gate_evidence import artifact_ref, check, object_value, read_json_object, sha256_json, write_json_object
from benchmarks.post_h3_bounded_owner_briefing_repeated_validation import SUMMARY_SCHEMA as BOUNDED_BRIEFING_REPEATED_SCHEMA

SUMMARY_SCHEMA = "post-h3-higher-permission-authorization-review-gate:v1"
REVIEW_REQUEST_SCHEMA = "post-h3-higher-permission-authorization-review-request:v1"
BOUNDARY_REPORT_SCHEMA = "post-h3-higher-permission-authorization-review-boundary:v1"

DEFAULT_REVIEW_SCOPE = "limited_external_usage_feedback_or_status_only_runtime_review"
DEFAULT_OPERATOR_STATEMENT = (
    "Enter higher-permission authorization review from stable bounded owner briefing evidence; "
    "do not grant or execute any higher-permission action in this gate."
)

NON_CLAIMS = (
    "higher_permission_authorization_review_gate_creates_review_request_only",
    "higher_permission_authorization_review_gate_does_not_authorize_public_ingress",
    "higher_permission_authorization_review_gate_does_not_authorize_runtime_expansion",
    "higher_permission_authorization_review_gate_does_not_authorize_deploy",
    "higher_permission_authorization_review_gate_does_not_authorize_source_or_git_write",
    "higher_permission_authorization_review_gate_does_not_authorize_production_data_access",
    "higher_permission_authorization_review_gate_does_not_write_production_runtime_receipts",
)


def run_gate(
    *,
    bounded_owner_briefing_repeated_validation_summary_path: Path,
    output_root: Path,
    operator_id: str = "operator-primary",
    operator_statement: str = DEFAULT_OPERATOR_STATEMENT,
    review_scope: str = DEFAULT_REVIEW_SCOPE,
    min_rounds: int = 3,
    ack_review_request: bool = False,
) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "review_request": output_root / "post_h3_higher_permission_authorization_review_request.json",
        "boundary_report": output_root / "post_h3_higher_permission_authorization_review_boundary_report.json",
        "summary": output_root / "post_h3_higher_permission_authorization_review_summary.json",
    }
    if not ack_review_request:
        return _write_blocked_summary(
            output=artifacts["summary"],
            bounded_owner_briefing_repeated_validation_summary_path=bounded_owner_briefing_repeated_validation_summary_path,
            failure="explicit_higher_permission_review_request_ack",
        )

    context = _validate_context(
        bounded_owner_briefing_repeated_validation_summary_path=bounded_owner_briefing_repeated_validation_summary_path,
        min_rounds=min_rounds,
    )
    review_request = _write_review_request(
        context=context,
        bounded_owner_briefing_repeated_validation_summary_path=bounded_owner_briefing_repeated_validation_summary_path,
        output=artifacts["review_request"],
        operator_id=operator_id,
        operator_statement=operator_statement,
        review_scope=review_scope,
        min_rounds=min_rounds,
    )
    boundary_report = _write_boundary_report(
        request_path=artifacts["review_request"],
        output=artifacts["boundary_report"],
    )
    reports = [context, review_request, boundary_report]
    passed = all(report.get("passed") is True for report in reports)
    summary = {
        "schema_version": SUMMARY_SCHEMA,
        "passed": passed,
        "failure_reasons": _failures(reports),
        "checked_at": _now(),
        "operator_id": operator_id,
        "operator_statement": operator_statement,
        "operator_statement_sha256": sha256_json(operator_statement),
        "review_scope": review_scope,
        "review_request_id": review_request.get("review_request_id"),
        "source_artifacts": {
            "bounded_owner_briefing_repeated_validation_summary": artifact_ref(
                bounded_owner_briefing_repeated_validation_summary_path
            ),
        },
        "artifacts": {name: artifact_ref(path) for name, path in artifacts.items() if name != "summary"},
        "readiness": {
            "state": "post_h3_higher_permission_authorization_review_ready" if passed else "blocked_post_h3_higher_permission_authorization_review",
            "higher_permission_authorization_review_ready": passed,
            "authorization_granted": False,
            "external_limited_usage_review_ready": passed,
            "public_ingress_review_ready": passed,
            "runtime_expansion_review_ready": passed,
            "deploy_review_ready": False,
            "source_write_review_ready": False,
            "production_data_access_review_ready": False,
            "future_execution_requires_separate_single_use_authorization": True,
            "production_task_execution_allowed": False,
            "runtime_execution_performed": False,
            "production_runtime_receipt_write_allowed": False,
        },
        "boundary": _boundary(review_request_written=review_request.get("passed") is True, boundary_report_written=boundary_report.get("passed") is True),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(artifacts["summary"], summary)
    return summary


def _validate_context(
    *,
    bounded_owner_briefing_repeated_validation_summary_path: Path,
    min_rounds: int,
) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    repeated = _read_json_or_empty(bounded_owner_briefing_repeated_validation_summary_path, failures, "bounded_owner_briefing_repeated_validation_summary")
    readiness = object_value(repeated.get("readiness"))
    boundary = object_value(repeated.get("boundary"))
    check(checks, failures, "schema_matches", repeated.get("schema_version") == BOUNDED_BRIEFING_REPEATED_SCHEMA)
    check(checks, failures, "summary_passed", repeated.get("passed") is True)
    check(checks, failures, "round_count_sufficient", int(repeated.get("round_count") or 0) >= min_rounds)
    check(checks, failures, "fresh_authorization_verified", readiness.get("fresh_authorization_per_round_verified") is True)
    check(checks, failures, "authorization_consumed_verified", readiness.get("authorization_consumed_per_round_verified") is True)
    check(checks, failures, "owner_briefing_verified", readiness.get("owner_briefing_per_round_verified") is True)
    check(checks, failures, "closeout_verified", readiness.get("closeout_per_round_verified") is True)
    check(checks, failures, "strategy_review_verified", readiness.get("strategy_review_per_round_verified") is True)
    check(checks, failures, "review_input_ready", readiness.get("higher_permission_authorization_review_input_ready") is True)
    check(checks, failures, "production_boundary_closed", _boundary_closed(boundary))
    passed = bool(checks) and all(checks.values()) and not failures
    return {
        "schema_version": "post-h3-higher-permission-authorization-review-context:v1",
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "bounded_owner_briefing_repeated_validation_summary": repeated,
        "boundary": _boundary(context_validation_written=passed),
    }


def _write_review_request(
    *,
    context: dict[str, Any],
    bounded_owner_briefing_repeated_validation_summary_path: Path,
    output: Path,
    operator_id: str,
    operator_statement: str,
    review_scope: str,
    min_rounds: int,
) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    repeated = object_value(context.get("bounded_owner_briefing_repeated_validation_summary"))
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "operator_id_present", bool(operator_id.strip()))
    check(checks, failures, "operator_statement_present", bool(operator_statement.strip()))
    check(checks, failures, "review_scope_present", bool(review_scope.strip()))
    passed = bool(checks) and all(checks.values()) and not failures
    request = {
        "schema_version": REVIEW_REQUEST_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "created_at": _now(),
        "review_request_id": f"post-h3-higher-permission-review:{sha256_json([artifact_ref(bounded_owner_briefing_repeated_validation_summary_path), review_scope, operator_statement])[:24]}",
        "operator_id": operator_id,
        "operator_statement": operator_statement,
        "review_scope": review_scope,
        "minimum_evidence_requirements": {
            "bounded_owner_briefing_repeated_validation_passed": True,
            "min_rounds": min_rounds,
            "fresh_authorization_per_round": True,
            "closeout_per_round": True,
            "strategy_review_per_round": True,
            "closed_production_boundary": True,
        },
        "observed_evidence": {
            "round_count": repeated.get("round_count"),
            "unique_task_id_count": repeated.get("unique_task_id_count"),
            "unique_authorization_id_count": repeated.get("unique_authorization_id_count"),
            "unique_operator_statement_count": repeated.get("unique_operator_statement_count"),
        },
        "requested_review_domains": [
            "limited_external_usage_feedback_collection_once",
            "status_only_public_ingress_short_window",
            "bounded_runtime_worker_heartbeat_once",
        ],
        "explicit_non_authorizations": [
            "do_not_open_public_ingress_in_this_gate",
            "do_not_start_runtime_workers_in_this_gate",
            "do_not_deploy_in_this_gate",
            "do_not_write_source_or_git_in_this_gate",
            "do_not_access_production_data_in_this_gate",
            "do_not_write_production_runtime_receipt_in_this_gate",
        ],
        "required_next_steps": [
            "operator_review",
            "audit_review",
            "security_review_for_public_ingress_if_requested",
            "rollback_owner_review",
            "monitoring_owner_review",
            "separate_single_use_authorization_before_any_execution",
        ],
        "source_artifacts": {
            "bounded_owner_briefing_repeated_validation_summary": artifact_ref(
                bounded_owner_briefing_repeated_validation_summary_path
            ),
        },
        "readiness": {
            "higher_permission_authorization_review_request_ready": passed,
            "authorization_granted": False,
            "future_execution_requires_separate_single_use_authorization": True,
        },
        "boundary": _boundary(review_request_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, request)
    return request


def _write_boundary_report(*, request_path: Path, output: Path) -> dict[str, Any]:
    request = read_json_object(request_path)
    readiness = object_value(request.get("readiness"))
    passed = request.get("passed") is True and readiness.get("authorization_granted") is False
    report = {
        "schema_version": BOUNDARY_REPORT_SCHEMA,
        "passed": passed,
        "failure_reasons": [] if passed else ["higher_permission_review_boundary_failed"],
        "checks": {
            "review_request_passed": request.get("passed") is True,
            "authorization_not_granted": readiness.get("authorization_granted") is False,
        },
        "checked_at": _now(),
        "source_artifacts": {"review_request": artifact_ref(request_path)},
        "boundary": _boundary(boundary_report_written=passed, review_request_written=request.get("passed") is True),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def _boundary_closed(boundary: dict[str, Any]) -> bool:
    required_false = (
        "production_task_execution_allowed",
        "next_single_use_gate_input_ready",
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
    return all(boundary.get(key) is False for key in required_false)


def _boundary(**overrides: Any) -> dict[str, Any]:
    boundary = {
        "context_validation_written": False,
        "review_request_written": False,
        "boundary_report_written": False,
        "higher_permission_authorization_review_ready": False,
        "authorization_granted": False,
        "public_ingress_authorized": False,
        "runtime_expansion_authorized": False,
        "deploy_authorized": False,
        "source_write_authorized": False,
        "production_data_access_authorized": False,
        "production_task_execution_allowed": False,
        "next_single_use_gate_input_ready": False,
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
    if boundary.get("review_request_written") is True and boundary.get("boundary_report_written") is True:
        boundary["higher_permission_authorization_review_ready"] = True
    return boundary


def _write_blocked_summary(
    *,
    output: Path,
    bounded_owner_briefing_repeated_validation_summary_path: Path,
    failure: str,
) -> dict[str, Any]:
    summary = {
        "schema_version": SUMMARY_SCHEMA,
        "passed": False,
        "failure_reasons": [failure],
        "checks": {failure: False},
        "checked_at": _now(),
        "source_artifacts": {
            "bounded_owner_briefing_repeated_validation_summary": artifact_ref(bounded_owner_briefing_repeated_validation_summary_path)
            if bounded_owner_briefing_repeated_validation_summary_path.exists()
            else {"path": str(bounded_owner_briefing_repeated_validation_summary_path.resolve()), "sha256": ""},
        },
        "readiness": {
            "state": "blocked_post_h3_higher_permission_authorization_review",
            "higher_permission_authorization_review_ready": False,
            "authorization_granted": False,
            "production_task_execution_allowed": False,
            "runtime_execution_performed": False,
            "production_runtime_receipt_write_allowed": False,
        },
        "boundary": _boundary(),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, summary)
    return summary


def _read_json_or_empty(path: Path, failures: list[str], label: str) -> dict[str, Any]:
    try:
        return read_json_object(path)
    except Exception as exc:  # noqa: BLE001
        failures.append(f"{label}_unreadable:{exc}")
        return {}


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
    parser.add_argument("--bounded-owner-briefing-repeated-validation-summary", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--operator-id", default="operator-primary")
    parser.add_argument("--operator-statement", default=DEFAULT_OPERATOR_STATEMENT)
    parser.add_argument("--review-scope", default=DEFAULT_REVIEW_SCOPE)
    parser.add_argument("--min-rounds", type=int, default=3)
    parser.add_argument("--ack-review-request", action="store_true")
    args = parser.parse_args(argv)
    summary = run_gate(
        bounded_owner_briefing_repeated_validation_summary_path=args.bounded_owner_briefing_repeated_validation_summary,
        output_root=args.output_root,
        operator_id=args.operator_id,
        operator_statement=args.operator_statement,
        review_scope=args.review_scope,
        min_rounds=args.min_rounds,
        ack_review_request=args.ack_review_request,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if summary.get("passed") is True else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
