"""Authorize the PostH3 external limited release preflight.

PostH3-I consumes a passed PostH3-H release boundary request and authorizes only
the next preflight step for an external limited release. It does not perform the
release, open public ingress, expand runtime execution, deploy, or write Git.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from benchmarks.i_gate_evidence import artifact_ref, check, object_value, read_json_object, sha256_file, sha256_json, write_json_object
from benchmarks.post_h3_release_boundary_request_gate import (
    BOUNDARY_REPORT_SCHEMA as POST_H3H_BOUNDARY_REPORT_SCHEMA,
    CHAIN_SCHEMA as POST_H3H_SCHEMA,
    DECISION_SCHEMA as POST_H3H_DECISION_SCHEMA,
    REQUEST_SCHEMA as POST_H3H_REQUEST_SCHEMA,
)

CHAIN_SCHEMA = "post-h3-external-limited-release-authorization-chain:v1"
CONTEXT_SCHEMA = "post-h3i-post-h3h-context-validation:v1"
AUTHORIZATION_REQUEST_SCHEMA = "post-h3i-external-limited-release-preflight-authorization-request:v1"
AUTHORIZATION_DECISION_SCHEMA = "post-h3i-external-limited-release-preflight-authorization-decision:v1"
AUTHORIZATION_RECEIPT_SCHEMA = "post-h3i-external-limited-release-preflight-authorization-receipt:v1"
BOUNDARY_REPORT_SCHEMA = "post-h3i-external-limited-release-authorization-boundary-report:v1"

ACCEPTED_OPERATOR_DECISION = "authorize_post_h3_external_limited_release_preflight_once"
ACCEPTED_AUDIT_DECISION = "accept_post_h3h_boundary_for_external_limited_release_preflight"
NON_CLAIMS = (
    "post_h3i_authorizes_preflight_only",
    "post_h3i_does_not_perform_external_limited_release",
    "post_h3i_does_not_authorize_public_ingress",
    "post_h3i_does_not_expand_runtime_execution",
    "post_h3i_does_not_execute_runtime",
    "post_h3i_does_not_contact_vm_targets",
    "post_h3i_does_not_deploy",
    "post_h3i_does_not_access_production_data",
    "post_h3i_does_not_write_source_or_git",
)


def run_gate(
    *,
    post_h3h_summary_path: Path,
    output_root: Path,
    operator_id: str = "operator-primary",
    operator_decision: str = ACCEPTED_OPERATOR_DECISION,
    audit_decision: str = ACCEPTED_AUDIT_DECISION,
    operator_statement: str = "Authorize one external limited release preflight only; do not release or open public ingress.",
    ack_external_limited_release_preflight: bool = False,
) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "context_validation": output_root / "post_h3i_post_h3h_context_validation.json",
        "authorization_request": output_root / "post_h3i_external_limited_release_preflight_authorization_request.json",
        "authorization_decision": output_root / "post_h3i_external_limited_release_preflight_authorization_decision.json",
        "authorization_receipt": output_root / "post_h3i_external_limited_release_preflight_authorization_receipt.json",
        "boundary_report": output_root / "post_h3i_external_limited_release_authorization_boundary_report.json",
        "summary": output_root / "post_h3i_external_limited_release_authorization_summary.json",
    }
    context = validate_post_h3h_context(post_h3h_summary_path, output=artifacts["context_validation"])
    request = _write_authorization_request(context=context, post_h3h_summary_path=post_h3h_summary_path, output=artifacts["authorization_request"])
    decision = _write_decision(
        request_path=artifacts["authorization_request"],
        output=artifacts["authorization_decision"],
        operator_id=operator_id,
        operator_decision=operator_decision,
        audit_decision=audit_decision,
        operator_statement=operator_statement,
        ack_external_limited_release_preflight=ack_external_limited_release_preflight,
    )
    receipt = _write_authorization_receipt(
        context=context,
        request_path=artifacts["authorization_request"],
        decision_path=artifacts["authorization_decision"],
        output=artifacts["authorization_receipt"],
    )
    boundary = _write_boundary_report(
        context=context,
        receipt_path=artifacts["authorization_receipt"],
        output=artifacts["boundary_report"],
    )
    reports = [context, request, decision, receipt, boundary]
    passed = all(report.get("passed") is True for report in reports)
    summary = {
        "schema_version": CHAIN_SCHEMA,
        "passed": passed,
        "failure_reasons": _failures(reports),
        "checked_at": _now(),
        "source_artifacts": {"post_h3h_summary": artifact_ref(post_h3h_summary_path)},
        "artifacts": {name: artifact_ref(path) for name, path in artifacts.items() if name != "summary"},
        "release_boundary_request_id": object_value(context.get("post_h3h_summary")).get("release_boundary_request_id"),
        "authorization_id": receipt.get("authorization_id"),
        "readiness": {
            "state": "post_h3_external_limited_release_preflight_authorized" if passed else "blocked_post_h3_external_limited_release_preflight_authorization",
            "external_limited_release_preflight_authorized": passed,
            "external_limited_release_preflight_ready": passed,
            "external_limited_release_ready": False,
            "public_ingress_authorized": False,
            "runtime_expansion_authorized": False,
            "production_runtime_receipt_write_allowed": False,
        },
        "boundary": _boundary(
            context_validation_written=context.get("passed") is True,
            authorization_request_written=request.get("passed") is True,
            authorization_decision_written=decision.get("passed") is True,
            authorization_receipt_written=receipt.get("passed") is True,
            boundary_report_written=boundary.get("passed") is True,
            external_limited_release_preflight_authorized=passed,
        ),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(artifacts["summary"], summary)
    return summary


def validate_post_h3h_context(post_h3h_summary_path: Path, *, output: Path | None = None) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    try:
        summary = read_json_object(post_h3h_summary_path)
    except Exception as exc:  # noqa: BLE001
        return _write_optional(_report(CONTEXT_SCHEMA, False, [f"post_h3h_summary_unreadable:{exc}"], checks), output)
    artifacts = object_value(summary.get("artifacts"))
    request = _read_verified_ref(artifacts.get("release_boundary_request"), checks, failures, "post_h3h_release_boundary_request")
    decision = _read_verified_ref(artifacts.get("release_boundary_decision"), checks, failures, "post_h3h_release_boundary_decision")
    boundary_report = _read_verified_ref(artifacts.get("boundary_report"), checks, failures, "post_h3h_boundary_report")
    _check_summary(summary, checks, failures)
    _check_artifacts(request, decision, boundary_report, checks, failures)
    passed = _passed(checks, failures)
    report = {
        "schema_version": CONTEXT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "post_h3h_summary": summary,
        "release_boundary_request": request,
        "release_boundary_decision": decision,
        "boundary_report": boundary_report,
        "source_artifacts": {"post_h3h_summary": artifact_ref(post_h3h_summary_path)},
        "boundary": _boundary(context_validation_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    return _write_optional(report, output)


def _write_authorization_request(*, context: dict[str, Any], post_h3h_summary_path: Path, output: Path) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    summary = object_value(context.get("post_h3h_summary"))
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "release_boundary_request_ready", object_value(summary.get("readiness")).get("post_h3_release_boundary_request_ready") is True)
    check(checks, failures, "external_release_request_ready", object_value(summary.get("readiness")).get("external_limited_release_authorization_request_ready") is True)
    passed = _passed(checks, failures)
    request = {
        "schema_version": AUTHORIZATION_REQUEST_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "requested_at": _now(),
        "authorization_request_id": f"post-h3i-preflight-request:{sha256_json([artifact_ref(post_h3h_summary_path), summary.get('release_boundary_request_id')])[:24]}",
        "requested_scope": {
            "authorize_external_limited_release_preflight_once": True,
            "authorize_external_limited_release_execution": False,
            "authorize_public_ingress": False,
            "authorize_runtime_expansion": False,
            "max_external_participants": 0,
            "max_public_ingress_seconds": 0,
        },
        "required_preflight_inputs": [
            "service_token_scope_review",
            "rollback_abort_readiness",
            "monitoring_audit_owner_assignment",
            "public_ingress_scope_review",
            "runtime_expansion_limit_review",
        ],
        "source_artifacts": {"post_h3h_summary": artifact_ref(post_h3h_summary_path)},
        "readiness": {
            "authorization_request_ready": passed,
            "external_limited_release_ready": False,
            "public_ingress_authorized": False,
        },
        "boundary": _boundary(authorization_request_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, request)
    return request


def _write_decision(
    *,
    request_path: Path,
    output: Path,
    operator_id: str,
    operator_decision: str,
    audit_decision: str,
    operator_statement: str,
    ack_external_limited_release_preflight: bool,
) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    request = read_json_object(request_path)
    check(checks, failures, "request_passed", request.get("schema_version") == AUTHORIZATION_REQUEST_SCHEMA and request.get("passed") is True)
    check(checks, failures, "operator_id_present", bool(operator_id.strip()))
    check(checks, failures, "operator_decision_accepted", operator_decision == ACCEPTED_OPERATOR_DECISION)
    check(checks, failures, "audit_decision_accepted", audit_decision == ACCEPTED_AUDIT_DECISION)
    check(checks, failures, "operator_statement_present", bool(operator_statement.strip()))
    check(checks, failures, "explicit_operator_ack", ack_external_limited_release_preflight is True)
    passed = _passed(checks, failures)
    decision = {
        "schema_version": AUTHORIZATION_DECISION_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "decided_at": _now(),
        "operator_id": operator_id,
        "operator_decision": operator_decision,
        "audit_decision": audit_decision,
        "operator_statement": operator_statement,
        "operator_statement_sha256": sha256_json(operator_statement),
        "ack_external_limited_release_preflight": ack_external_limited_release_preflight,
        "source_artifacts": {"authorization_request": artifact_ref(request_path)},
        "boundary": _boundary(authorization_decision_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, decision)
    return decision


def _write_authorization_receipt(*, context: dict[str, Any], request_path: Path, decision_path: Path, output: Path) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    request = read_json_object(request_path)
    decision = read_json_object(decision_path)
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "request_passed", request.get("passed") is True)
    check(checks, failures, "decision_passed", decision.get("passed") is True)
    passed = _passed(checks, failures)
    auth_id = f"post-h3i-preflight-auth:{sha256_json([artifact_ref(request_path), artifact_ref(decision_path)])[:24]}"
    receipt = {
        "schema_version": AUTHORIZATION_RECEIPT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "authorized_at": _now(),
        "authorization_id": auth_id,
        "single_use": True,
        "consumed": False,
        "authorization_scope": object_value(request.get("requested_scope")),
        "source_artifacts": {
            "authorization_request": artifact_ref(request_path),
            "authorization_decision": artifact_ref(decision_path),
            "post_h3h_summary": object_value(context.get("source_artifacts")).get("post_h3h_summary"),
        },
        "readiness": {
            "external_limited_release_preflight_authorized": passed,
            "external_limited_release_ready": False,
            "public_ingress_authorized": False,
            "runtime_expansion_authorized": False,
        },
        "boundary": _boundary(authorization_receipt_written=passed, external_limited_release_preflight_authorized=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, receipt)
    return receipt


def _write_boundary_report(*, context: dict[str, Any], receipt_path: Path, output: Path) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    receipt = read_json_object(receipt_path)
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "receipt_passed", receipt.get("passed") is True)
    check(checks, failures, "preflight_authorized", object_value(receipt.get("readiness")).get("external_limited_release_preflight_authorized") is True)
    check(checks, failures, "release_not_ready", object_value(receipt.get("readiness")).get("external_limited_release_ready") is False)
    check(checks, failures, "public_ingress_not_authorized", object_value(receipt.get("readiness")).get("public_ingress_authorized") is False)
    passed = _passed(checks, failures)
    report = {
        "schema_version": BOUNDARY_REPORT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "source_artifacts": {"authorization_receipt": artifact_ref(receipt_path)},
        "boundary": _boundary(boundary_report_written=passed, external_limited_release_preflight_authorized=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def _check_summary(summary: dict[str, Any], checks: dict[str, bool], failures: list[str]) -> None:
    readiness = object_value(summary.get("readiness"))
    boundary = object_value(summary.get("boundary"))
    check(checks, failures, "post_h3h_schema_valid", summary.get("schema_version") == POST_H3H_SCHEMA)
    check(checks, failures, "post_h3h_passed", summary.get("passed") is True)
    check(checks, failures, "release_boundary_ready", readiness.get("post_h3_release_boundary_request_ready") is True)
    check(checks, failures, "external_release_request_ready", readiness.get("external_limited_release_authorization_request_ready") is True)
    check(checks, failures, "public_ingress_request_ready", readiness.get("public_ingress_authorization_request_ready") is True)
    check(checks, failures, "external_release_not_ready", readiness.get("external_limited_release_ready") is False)
    check(checks, failures, "public_ingress_not_authorized", readiness.get("public_ingress_authorized") is False)
    check(checks, failures, "runtime_expansion_not_authorized", readiness.get("runtime_expansion_authorized") is False)
    for key in ("runtime_execution_performed", "vm_contact_performed", "deploy_performed", "external_public_ingress_opened", "production_data_accessed", "source_tree_write_performed", "git_write_performed"):
        check(checks, failures, f"no_{key}", boundary.get(key) is False)


def _check_artifacts(request: dict[str, Any], decision: dict[str, Any], boundary_report: dict[str, Any], checks: dict[str, bool], failures: list[str]) -> None:
    check(checks, failures, "request_schema_valid", request.get("schema_version") == POST_H3H_REQUEST_SCHEMA and request.get("passed") is True)
    check(checks, failures, "decision_schema_valid", decision.get("schema_version") == POST_H3H_DECISION_SCHEMA and decision.get("passed") is True)
    check(checks, failures, "boundary_report_schema_valid", boundary_report.get("schema_version") == POST_H3H_BOUNDARY_REPORT_SCHEMA and boundary_report.get("passed") is True)
    check(checks, failures, "request_no_release_ready", object_value(request.get("readiness")).get("external_limited_release_ready") is False)
    check(checks, failures, "request_no_public_ingress", object_value(request.get("readiness")).get("public_ingress_authorized") is False)


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
        "authorization_request_written": False,
        "authorization_decision_written": False,
        "authorization_receipt_written": False,
        "boundary_report_written": False,
        "external_limited_release_preflight_authorized": False,
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
    parser = argparse.ArgumentParser(description="Run PostH3-I external limited release preflight authorization gate")
    parser.add_argument("--post-h3h-summary", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--operator-id", default="operator-primary")
    parser.add_argument("--operator-decision", default=ACCEPTED_OPERATOR_DECISION)
    parser.add_argument("--audit-decision", default=ACCEPTED_AUDIT_DECISION)
    parser.add_argument("--operator-statement", default="Authorize one external limited release preflight only; do not release or open public ingress.")
    parser.add_argument("--ack-external-limited-release-preflight", action="store_true")
    args = parser.parse_args()
    summary = run_gate(
        post_h3h_summary_path=args.post_h3h_summary,
        output_root=args.output_root,
        operator_id=args.operator_id,
        operator_decision=args.operator_decision,
        audit_decision=args.audit_decision,
        operator_statement=args.operator_statement,
        ack_external_limited_release_preflight=args.ack_external_limited_release_preflight,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if summary.get("passed") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
