"""Review the PostH3 external limited release execution authorization request.

PostH3-L consumes PostH3-K's execution authorization request and records an
operator/audit/rollback/monitoring decision. A complete review may authorize or
reject the execution. It never performs the external limited release, opens
public ingress, expands runtime execution, deploys, contacts VMs, or writes Git.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from benchmarks.i_gate_evidence import artifact_ref, check, object_value, read_json_object, sha256_file, sha256_json, write_json_object
from benchmarks.post_h3_external_limited_release_execution_authorization_request_gate import (
    BOUNDARY_REPORT_SCHEMA as POST_H3K_BOUNDARY_REPORT_SCHEMA,
    CHAIN_SCHEMA as POST_H3K_SCHEMA,
    REQUEST_SCHEMA as POST_H3K_REQUEST_SCHEMA,
)

CHAIN_SCHEMA = "post-h3-external-limited-release-execution-authorization-review-chain:v1"
CONTEXT_SCHEMA = "post-h3l-post-h3k-context-validation:v1"
REVIEW_PACKET_SCHEMA = "post-h3l-external-limited-release-execution-authorization-review-packet:v1"
AUTHORIZATION_RECEIPT_SCHEMA = "post-h3l-external-limited-release-execution-authorization-receipt:v1"
BOUNDARY_REPORT_SCHEMA = "post-h3l-external-limited-release-execution-authorization-boundary-report:v1"

OPERATOR_AUTHORIZE = "authorize_external_limited_release_execution_once"
OPERATOR_REJECT = "reject_external_limited_release_execution"
AUDIT_ACCEPT = "accept_post_h3k_boundary_for_execution_authorization"
AUDIT_REJECT = "reject_post_h3k_boundary_for_execution_authorization"
ROLLBACK_ACCEPT = "accept_rollback_abort_ready_for_execution_authorization"
ROLLBACK_REJECT = "reject_rollback_abort_ready_for_execution_authorization"
MONITORING_ACCEPT = "accept_monitoring_audit_ready_for_execution_authorization"
MONITORING_REJECT = "reject_monitoring_audit_ready_for_execution_authorization"

NON_CLAIMS = (
    "post_h3l_reviews_execution_authorization_only",
    "post_h3l_does_not_perform_external_limited_release",
    "post_h3l_does_not_authorize_public_ingress",
    "post_h3l_does_not_expand_runtime_execution",
    "post_h3l_does_not_execute_runtime",
    "post_h3l_does_not_contact_vm_targets",
    "post_h3l_does_not_deploy",
    "post_h3l_does_not_access_production_data",
    "post_h3l_does_not_write_source_or_git",
)


def run_gate(
    *,
    post_h3k_summary_path: Path,
    output_root: Path,
    operator_id: str = "operator-primary",
    operator_decision: str = OPERATOR_AUTHORIZE,
    audit_decision: str = AUDIT_ACCEPT,
    rollback_owner_decision: str = ROLLBACK_ACCEPT,
    monitoring_owner_decision: str = MONITORING_ACCEPT,
    operator_statement: str = "Authorize one external limited release execution; do not authorize public ingress or runtime expansion.",
    ack_execution_authorization_review: bool = False,
) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "context_validation": output_root / "post_h3l_post_h3k_context_validation.json",
        "review_packet": output_root / "post_h3l_execution_authorization_review_packet.json",
        "authorization_receipt": output_root / "post_h3l_execution_authorization_receipt.json",
        "boundary_report": output_root / "post_h3l_execution_authorization_boundary_report.json",
        "summary": output_root / "post_h3l_execution_authorization_review_summary.json",
    }
    context = validate_post_h3k_context(post_h3k_summary_path, output=artifacts["context_validation"])
    review = _write_review_packet(
        context=context,
        post_h3k_summary_path=post_h3k_summary_path,
        output=artifacts["review_packet"],
        operator_id=operator_id,
        operator_decision=operator_decision,
        audit_decision=audit_decision,
        rollback_owner_decision=rollback_owner_decision,
        monitoring_owner_decision=monitoring_owner_decision,
        operator_statement=operator_statement,
        ack_execution_authorization_review=ack_execution_authorization_review,
    )
    receipt = _write_authorization_receipt(context=context, review_packet_path=artifacts["review_packet"], output=artifacts["authorization_receipt"])
    boundary = _write_boundary_report(context=context, receipt_path=artifacts["authorization_receipt"], output=artifacts["boundary_report"])
    reports = [context, review, receipt, boundary]
    passed = all(report.get("passed") is True for report in reports)
    authorized = passed and receipt.get("authorization_granted") is True
    summary = {
        "schema_version": CHAIN_SCHEMA,
        "passed": passed,
        "failure_reasons": _failures(reports),
        "checked_at": _now(),
        "source_artifacts": {"post_h3k_summary": artifact_ref(post_h3k_summary_path)},
        "artifacts": {name: artifact_ref(path) for name, path in artifacts.items() if name != "summary"},
        "execution_authorization_request_id": object_value(context.get("post_h3k_summary")).get("execution_authorization_request_id"),
        "authorization_id": receipt.get("authorization_id"),
        "authorization_granted": authorized,
        "readiness": {
            "state": "post_h3_external_limited_release_execution_authorized" if authorized else ("post_h3_external_limited_release_execution_rejected" if passed else "blocked_post_h3_external_limited_release_execution_authorization_review"),
            "operator_execution_authorization_review_complete": passed,
            "external_limited_release_execution_authorized": authorized,
            "external_limited_release_execution_ready": authorized,
            "external_limited_release_ready": False,
            "public_ingress_authorized": False,
            "runtime_expansion_authorized": False,
            "production_runtime_receipt_write_allowed": False,
        },
        "boundary": _boundary(
            context_validation_written=context.get("passed") is True,
            review_packet_written=review.get("passed") is True,
            authorization_receipt_written=receipt.get("passed") is True,
            boundary_report_written=boundary.get("passed") is True,
            external_limited_release_execution_authorized=authorized,
        ),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(artifacts["summary"], summary)
    return summary


def validate_post_h3k_context(post_h3k_summary_path: Path, *, output: Path | None = None) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    try:
        summary = read_json_object(post_h3k_summary_path)
    except Exception as exc:  # noqa: BLE001
        return _write_optional(_report(CONTEXT_SCHEMA, False, [f"post_h3k_summary_unreadable:{exc}"], checks), output)

    artifacts = object_value(summary.get("artifacts"))
    request = _read_verified_ref(artifacts.get("execution_authorization_request"), checks, failures, "post_h3k_execution_authorization_request")
    boundary_report = _read_verified_ref(artifacts.get("boundary_report"), checks, failures, "post_h3k_boundary_report")
    _check_summary(summary, checks, failures)
    _check_artifacts(request, boundary_report, checks, failures)
    passed = _passed(checks, failures)
    report = {
        "schema_version": CONTEXT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "post_h3k_summary": summary,
        "execution_authorization_request": request,
        "boundary_report": boundary_report,
        "source_artifacts": {"post_h3k_summary": artifact_ref(post_h3k_summary_path)},
        "boundary": _boundary(context_validation_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    return _write_optional(report, output)


def _write_review_packet(
    *,
    context: dict[str, Any],
    post_h3k_summary_path: Path,
    output: Path,
    operator_id: str,
    operator_decision: str,
    audit_decision: str,
    rollback_owner_decision: str,
    monitoring_owner_decision: str,
    operator_statement: str,
    ack_execution_authorization_review: bool,
) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "operator_id_present", bool(operator_id.strip()))
    check(checks, failures, "operator_decision_valid", operator_decision in {OPERATOR_AUTHORIZE, OPERATOR_REJECT})
    check(checks, failures, "audit_decision_valid", audit_decision in {AUDIT_ACCEPT, AUDIT_REJECT})
    check(checks, failures, "rollback_owner_decision_valid", rollback_owner_decision in {ROLLBACK_ACCEPT, ROLLBACK_REJECT})
    check(checks, failures, "monitoring_owner_decision_valid", monitoring_owner_decision in {MONITORING_ACCEPT, MONITORING_REJECT})
    check(checks, failures, "operator_statement_present", bool(operator_statement.strip()))
    check(checks, failures, "explicit_operator_ack", ack_execution_authorization_review is True)
    authorization_granted = (
        operator_decision == OPERATOR_AUTHORIZE
        and audit_decision == AUDIT_ACCEPT
        and rollback_owner_decision == ROLLBACK_ACCEPT
        and monitoring_owner_decision == MONITORING_ACCEPT
    )
    passed = _passed(checks, failures)
    review = {
        "schema_version": REVIEW_PACKET_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "reviewed_at": _now(),
        "operator_id": operator_id,
        "operator_decision": operator_decision,
        "audit_decision": audit_decision,
        "rollback_owner_decision": rollback_owner_decision,
        "monitoring_owner_decision": monitoring_owner_decision,
        "operator_statement": operator_statement,
        "operator_statement_sha256": sha256_json(operator_statement),
        "ack_execution_authorization_review": ack_execution_authorization_review,
        "authorization_granted": passed and authorization_granted,
        "source_artifacts": {"post_h3k_summary": artifact_ref(post_h3k_summary_path)},
        "boundary": _boundary(review_packet_written=passed, external_limited_release_execution_authorized=passed and authorization_granted),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, review)
    return review


def _write_authorization_receipt(*, context: dict[str, Any], review_packet_path: Path, output: Path) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    review = read_json_object(review_packet_path)
    summary = object_value(context.get("post_h3k_summary"))
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "review_packet_passed", review.get("passed") is True)
    passed = _passed(checks, failures)
    authorization_granted = passed and review.get("authorization_granted") is True
    receipt = {
        "schema_version": AUTHORIZATION_RECEIPT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "written_at": _now(),
        "authorization_granted": authorization_granted,
        "authorization_id": f"post-h3l-execution-auth:{sha256_json([artifact_ref(review_packet_path), summary.get('execution_authorization_request_id')])[:24]}" if authorization_granted else None,
        "rejection_id": None if authorization_granted else f"post-h3l-execution-reject:{sha256_json([artifact_ref(review_packet_path), summary.get('execution_authorization_request_id')])[:24]}",
        "single_use": authorization_granted,
        "consumed": False,
        "authorization_scope": {
            "external_limited_release_execution_authorized": authorization_granted,
            "public_ingress_authorized": False,
            "runtime_expansion_authorized": False,
            "max_external_participants": 0,
            "max_public_ingress_seconds": 0,
        },
        "source_artifacts": {
            "review_packet": artifact_ref(review_packet_path),
            "post_h3k_summary": object_value(context.get("source_artifacts")).get("post_h3k_summary"),
        },
        "readiness": {
            "external_limited_release_execution_authorized": authorization_granted,
            "external_limited_release_execution_ready": authorization_granted,
            "external_limited_release_ready": False,
            "public_ingress_authorized": False,
            "runtime_expansion_authorized": False,
        },
        "boundary": _boundary(authorization_receipt_written=passed, external_limited_release_execution_authorized=authorization_granted),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, receipt)
    return receipt


def _write_boundary_report(*, context: dict[str, Any], receipt_path: Path, output: Path) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    receipt = read_json_object(receipt_path)
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "authorization_receipt_passed", receipt.get("passed") is True)
    check(checks, failures, "release_not_performed", object_value(receipt.get("readiness")).get("external_limited_release_ready") is False)
    check(checks, failures, "public_ingress_not_authorized", object_value(receipt.get("readiness")).get("public_ingress_authorized") is False)
    check(checks, failures, "runtime_expansion_not_authorized", object_value(receipt.get("readiness")).get("runtime_expansion_authorized") is False)
    passed = _passed(checks, failures)
    authorized = passed and receipt.get("authorization_granted") is True
    report = {
        "schema_version": BOUNDARY_REPORT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "source_artifacts": {"authorization_receipt": artifact_ref(receipt_path)},
        "boundary": _boundary(boundary_report_written=passed, external_limited_release_execution_authorized=authorized),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def _check_summary(summary: dict[str, Any], checks: dict[str, bool], failures: list[str]) -> None:
    readiness = object_value(summary.get("readiness"))
    boundary = object_value(summary.get("boundary"))
    check(checks, failures, "post_h3k_schema_valid", summary.get("schema_version") == POST_H3K_SCHEMA)
    check(checks, failures, "post_h3k_passed", summary.get("passed") is True)
    check(checks, failures, "execution_request_ready", readiness.get("external_limited_release_execution_authorization_request_ready") is True)
    check(checks, failures, "operator_review_ready", readiness.get("operator_execution_authorization_review_ready") is True)
    check(checks, failures, "execution_not_authorized", readiness.get("external_limited_release_execution_authorized") is False)
    check(checks, failures, "release_not_ready", readiness.get("external_limited_release_ready") is False)
    check(checks, failures, "public_ingress_not_authorized", readiness.get("public_ingress_authorized") is False)
    check(checks, failures, "runtime_expansion_not_authorized", readiness.get("runtime_expansion_authorized") is False)
    for key in ("runtime_execution_performed", "vm_contact_performed", "deploy_performed", "external_public_ingress_opened", "production_data_accessed", "source_tree_write_performed", "git_write_performed"):
        check(checks, failures, f"no_{key}", boundary.get(key) is False)


def _check_artifacts(request: dict[str, Any], boundary_report: dict[str, Any], checks: dict[str, bool], failures: list[str]) -> None:
    check(checks, failures, "request_schema_valid", request.get("schema_version") == POST_H3K_REQUEST_SCHEMA and request.get("passed") is True)
    check(checks, failures, "boundary_report_schema_valid", boundary_report.get("schema_version") == POST_H3K_BOUNDARY_REPORT_SCHEMA and boundary_report.get("passed") is True)
    readiness = object_value(request.get("readiness"))
    check(checks, failures, "request_review_ready", readiness.get("operator_execution_authorization_review_ready") is True)
    check(checks, failures, "request_execution_not_authorized", readiness.get("external_limited_release_execution_authorized") is False)
    check(checks, failures, "request_no_public_ingress", readiness.get("public_ingress_authorized") is False)


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
        "authorization_receipt_written": False,
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
    parser = argparse.ArgumentParser(description="Run PostH3-L external limited release execution authorization review gate")
    parser.add_argument("--post-h3k-summary", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--operator-id", default="operator-primary")
    parser.add_argument("--operator-decision", default=OPERATOR_AUTHORIZE, choices=[OPERATOR_AUTHORIZE, OPERATOR_REJECT])
    parser.add_argument("--audit-decision", default=AUDIT_ACCEPT, choices=[AUDIT_ACCEPT, AUDIT_REJECT])
    parser.add_argument("--rollback-owner-decision", default=ROLLBACK_ACCEPT, choices=[ROLLBACK_ACCEPT, ROLLBACK_REJECT])
    parser.add_argument("--monitoring-owner-decision", default=MONITORING_ACCEPT, choices=[MONITORING_ACCEPT, MONITORING_REJECT])
    parser.add_argument("--operator-statement", default="Authorize one external limited release execution; do not authorize public ingress or runtime expansion.")
    parser.add_argument("--ack-execution-authorization-review", action="store_true")
    args = parser.parse_args()
    summary = run_gate(
        post_h3k_summary_path=args.post_h3k_summary,
        output_root=args.output_root,
        operator_id=args.operator_id,
        operator_decision=args.operator_decision,
        audit_decision=args.audit_decision,
        rollback_owner_decision=args.rollback_owner_decision,
        monitoring_owner_decision=args.monitoring_owner_decision,
        operator_statement=args.operator_statement,
        ack_execution_authorization_review=args.ack_execution_authorization_review,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if summary.get("passed") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
