"""Prepare the PostH3 external limited release execution authorization request.

PostH3-K consumes a passed PostH3-J preflight and prepares an execution
authorization request for operator review. It does not authorize or perform the
external limited release, open public ingress, expand runtime execution, deploy,
contact VMs, or write Git.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from benchmarks.i_gate_evidence import artifact_ref, check, object_value, read_json_object, sha256_file, sha256_json, write_json_object
from benchmarks.post_h3_external_limited_release_preflight_gate import (
    BOUNDARY_REPORT_SCHEMA as POST_H3J_BOUNDARY_REPORT_SCHEMA,
    CHAIN_SCHEMA as POST_H3J_SCHEMA,
    PREFLIGHT_REPORT_SCHEMA as POST_H3J_PREFLIGHT_REPORT_SCHEMA,
)

CHAIN_SCHEMA = "post-h3-external-limited-release-execution-authorization-request-chain:v1"
CONTEXT_SCHEMA = "post-h3k-post-h3j-context-validation:v1"
REQUEST_SCHEMA = "post-h3k-external-limited-release-execution-authorization-request:v1"
BOUNDARY_REPORT_SCHEMA = "post-h3k-external-limited-release-execution-request-boundary-report:v1"

NON_CLAIMS = (
    "post_h3k_prepares_execution_authorization_request_only",
    "post_h3k_does_not_authorize_external_limited_release_execution",
    "post_h3k_does_not_perform_external_limited_release",
    "post_h3k_does_not_authorize_public_ingress",
    "post_h3k_does_not_expand_runtime_execution",
    "post_h3k_does_not_execute_runtime",
    "post_h3k_does_not_contact_vm_targets",
    "post_h3k_does_not_deploy",
    "post_h3k_does_not_access_production_data",
    "post_h3k_does_not_write_source_or_git",
)

REQUIRED_FUTURE_REVIEWS = (
    "operator_execution_authorization_decision",
    "audit_owner_boundary_acceptance",
    "rollback_owner_abort_readiness_acceptance",
    "monitoring_owner_live_watch_acceptance",
    "service_token_scope_final_review",
)


def run_gate(
    *,
    post_h3j_summary_path: Path,
    output_root: Path,
    operator_id: str = "operator-primary",
    operator_statement: str = "Prepare external limited release execution authorization request for review only.",
    ack_execution_authorization_request: bool = False,
) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "context_validation": output_root / "post_h3k_post_h3j_context_validation.json",
        "execution_authorization_request": output_root / "post_h3k_external_limited_release_execution_authorization_request.json",
        "boundary_report": output_root / "post_h3k_external_limited_release_execution_request_boundary_report.json",
        "summary": output_root / "post_h3k_external_limited_release_execution_authorization_request_summary.json",
    }
    context = validate_post_h3j_context(post_h3j_summary_path, output=artifacts["context_validation"])
    request = _write_execution_authorization_request(
        context=context,
        post_h3j_summary_path=post_h3j_summary_path,
        output=artifacts["execution_authorization_request"],
        operator_id=operator_id,
        operator_statement=operator_statement,
        ack_execution_authorization_request=ack_execution_authorization_request,
    )
    boundary = _write_boundary_report(context=context, request_path=artifacts["execution_authorization_request"], output=artifacts["boundary_report"])
    reports = [context, request, boundary]
    passed = all(report.get("passed") is True for report in reports)
    summary = {
        "schema_version": CHAIN_SCHEMA,
        "passed": passed,
        "failure_reasons": _failures(reports),
        "checked_at": _now(),
        "source_artifacts": {"post_h3j_summary": artifact_ref(post_h3j_summary_path)},
        "artifacts": {name: artifact_ref(path) for name, path in artifacts.items() if name != "summary"},
        "preflight_id": object_value(context.get("post_h3j_summary")).get("preflight_id"),
        "execution_authorization_request_id": request.get("execution_authorization_request_id"),
        "readiness": {
            "state": "post_h3_external_limited_release_execution_authorization_request_ready" if passed else "blocked_post_h3_external_limited_release_execution_authorization_request",
            "external_limited_release_execution_authorization_request_ready": passed,
            "operator_execution_authorization_review_ready": passed,
            "external_limited_release_execution_authorized": False,
            "external_limited_release_ready": False,
            "public_ingress_authorized": False,
            "runtime_expansion_authorized": False,
            "production_runtime_receipt_write_allowed": False,
        },
        "boundary": _boundary(
            context_validation_written=context.get("passed") is True,
            execution_authorization_request_written=request.get("passed") is True,
            boundary_report_written=boundary.get("passed") is True,
        ),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(artifacts["summary"], summary)
    return summary


def validate_post_h3j_context(post_h3j_summary_path: Path, *, output: Path | None = None) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    try:
        summary = read_json_object(post_h3j_summary_path)
    except Exception as exc:  # noqa: BLE001
        return _write_optional(_report(CONTEXT_SCHEMA, False, [f"post_h3j_summary_unreadable:{exc}"], checks), output)

    artifacts = object_value(summary.get("artifacts"))
    preflight_report = _read_verified_ref(artifacts.get("preflight_report"), checks, failures, "post_h3j_preflight_report")
    boundary_report = _read_verified_ref(artifacts.get("boundary_report"), checks, failures, "post_h3j_boundary_report")
    _check_summary(summary, checks, failures)
    _check_artifacts(preflight_report, boundary_report, checks, failures)
    passed = _passed(checks, failures)
    report = {
        "schema_version": CONTEXT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "post_h3j_summary": summary,
        "preflight_report": preflight_report,
        "boundary_report": boundary_report,
        "source_artifacts": {"post_h3j_summary": artifact_ref(post_h3j_summary_path)},
        "boundary": _boundary(context_validation_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    return _write_optional(report, output)


def _write_execution_authorization_request(
    *,
    context: dict[str, Any],
    post_h3j_summary_path: Path,
    output: Path,
    operator_id: str,
    operator_statement: str,
    ack_execution_authorization_request: bool,
) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    summary = object_value(context.get("post_h3j_summary"))
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "operator_id_present", bool(operator_id.strip()))
    check(checks, failures, "operator_statement_present", bool(operator_statement.strip()))
    check(checks, failures, "explicit_operator_ack", ack_execution_authorization_request is True)
    check(checks, failures, "preflight_ready_for_request", object_value(summary.get("readiness")).get("external_limited_release_execution_authorization_request_ready") is True)
    passed = _passed(checks, failures)
    request_id = f"post-h3k-execution-auth-request:{sha256_json([artifact_ref(post_h3j_summary_path), summary.get('preflight_id')])[:24]}"
    request = {
        "schema_version": REQUEST_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "requested_at": _now(),
        "execution_authorization_request_id": request_id,
        "operator_id": operator_id,
        "operator_statement": operator_statement,
        "operator_statement_sha256": sha256_json(operator_statement),
        "ack_execution_authorization_request": ack_execution_authorization_request,
        "requested_scope": {
            "request_kind": "external_limited_release_execution_authorization_review",
            "authorize_external_limited_release_execution": False,
            "authorize_public_ingress": False,
            "authorize_runtime_expansion": False,
            "max_external_participants": 0,
            "max_public_ingress_seconds": 0,
            "rollback_required_before_any_expansion": True,
        },
        "required_future_reviews": list(REQUIRED_FUTURE_REVIEWS),
        "forbidden_without_future_authorization": [
            "perform_external_limited_release",
            "open_public_ingress",
            "invite_external_users",
            "expand_runtime_execution",
            "deploy_to_public_environment",
            "write_additional_production_runtime_receipts",
        ],
        "source_artifacts": {"post_h3j_summary": artifact_ref(post_h3j_summary_path)},
        "readiness": {
            "execution_authorization_request_ready": passed,
            "operator_execution_authorization_review_ready": passed,
            "external_limited_release_execution_authorized": False,
            "external_limited_release_ready": False,
            "public_ingress_authorized": False,
        },
        "boundary": _boundary(execution_authorization_request_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, request)
    return request


def _write_boundary_report(*, context: dict[str, Any], request_path: Path, output: Path) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    request = read_json_object(request_path)
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "request_passed", request.get("passed") is True)
    check(checks, failures, "execution_not_authorized", object_value(request.get("readiness")).get("external_limited_release_execution_authorized") is False)
    check(checks, failures, "release_not_ready", object_value(request.get("readiness")).get("external_limited_release_ready") is False)
    check(checks, failures, "public_ingress_not_authorized", object_value(request.get("readiness")).get("public_ingress_authorized") is False)
    passed = _passed(checks, failures)
    report = {
        "schema_version": BOUNDARY_REPORT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "source_artifacts": {"execution_authorization_request": artifact_ref(request_path)},
        "boundary": _boundary(boundary_report_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def _check_summary(summary: dict[str, Any], checks: dict[str, bool], failures: list[str]) -> None:
    readiness = object_value(summary.get("readiness"))
    boundary = object_value(summary.get("boundary"))
    check(checks, failures, "post_h3j_schema_valid", summary.get("schema_version") == POST_H3J_SCHEMA)
    check(checks, failures, "post_h3j_passed", summary.get("passed") is True)
    check(checks, failures, "preflight_complete", readiness.get("external_limited_release_preflight_complete") is True)
    check(checks, failures, "execution_request_ready", readiness.get("external_limited_release_execution_authorization_request_ready") is True)
    check(checks, failures, "release_not_ready", readiness.get("external_limited_release_ready") is False)
    check(checks, failures, "public_ingress_not_authorized", readiness.get("public_ingress_authorized") is False)
    check(checks, failures, "runtime_expansion_not_authorized", readiness.get("runtime_expansion_authorized") is False)
    for key in ("runtime_execution_performed", "vm_contact_performed", "deploy_performed", "external_public_ingress_opened", "production_data_accessed", "source_tree_write_performed", "git_write_performed"):
        check(checks, failures, f"no_{key}", boundary.get(key) is False)


def _check_artifacts(preflight_report: dict[str, Any], boundary_report: dict[str, Any], checks: dict[str, bool], failures: list[str]) -> None:
    check(checks, failures, "preflight_report_schema_valid", preflight_report.get("schema_version") == POST_H3J_PREFLIGHT_REPORT_SCHEMA and preflight_report.get("passed") is True)
    check(checks, failures, "boundary_report_schema_valid", boundary_report.get("schema_version") == POST_H3J_BOUNDARY_REPORT_SCHEMA and boundary_report.get("passed") is True)
    check(checks, failures, "preflight_report_complete", object_value(preflight_report.get("readiness")).get("external_limited_release_preflight_complete") is True)
    check(checks, failures, "preflight_execution_request_ready", object_value(preflight_report.get("readiness")).get("external_limited_release_execution_authorization_request_ready") is True)
    check(checks, failures, "preflight_no_release_ready", object_value(preflight_report.get("readiness")).get("external_limited_release_ready") is False)
    check(checks, failures, "preflight_no_public_ingress", object_value(preflight_report.get("readiness")).get("public_ingress_authorized") is False)


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
        "execution_authorization_request_written": False,
        "boundary_report_written": False,
        "external_limited_release_execution_authorized": False,
        "external_limited_release_performed": False,
        "external_limited_release_ready": False,
        "public_ingress_authorized": False,
        "runtime_expansion_authorized": False,
        "runtime_execution_performed": False,
        "vm_contact_performed": False,
        "deploy_performed": False,
        "external_public_ingress_opened": False,
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
    parser = argparse.ArgumentParser(description="Run PostH3-K external limited release execution authorization request gate")
    parser.add_argument("--post-h3j-summary", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--operator-id", default="operator-primary")
    parser.add_argument("--operator-statement", default="Prepare external limited release execution authorization request for review only.")
    parser.add_argument("--ack-execution-authorization-request", action="store_true")
    args = parser.parse_args()
    summary = run_gate(
        post_h3j_summary_path=args.post_h3j_summary,
        output_root=args.output_root,
        operator_id=args.operator_id,
        operator_statement=args.operator_statement,
        ack_execution_authorization_request=args.ack_execution_authorization_request,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if summary.get("passed") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
