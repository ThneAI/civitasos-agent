"""Authorize a future PostH3 public ingress gate without opening ingress.

PostH3-O consumes PostH3-N closeout and writes a one-time public-ingress
authorization receipt. It authorizes a later, separately gated public-ingress
execution path only; it does not open public ingress, deploy, contact VMs,
expand runtime execution, access production data, or write source/Git.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from benchmarks.i_gate_evidence import artifact_ref, check, object_value, read_json_object, sha256_file, sha256_json, write_json_object
from benchmarks.post_h3_external_release_closeout_gate import (
    BOUNDARY_REPORT_SCHEMA as POST_H3N_BOUNDARY_REPORT_SCHEMA,
    CHAIN_SCHEMA as POST_H3N_SCHEMA,
    CLOSEOUT_RECONCILIATION_SCHEMA as POST_H3N_RECONCILIATION_SCHEMA,
)

CHAIN_SCHEMA = "post-h3-public-ingress-authorization-chain:v1"
CONTEXT_SCHEMA = "post-h3o-post-h3n-context-validation:v1"
AUTHORIZATION_REQUEST_SCHEMA = "post-h3o-public-ingress-authorization-request:v1"
AUTHORIZATION_DECISION_SCHEMA = "post-h3o-public-ingress-authorization-decision:v1"
AUTHORIZATION_RECEIPT_SCHEMA = "post-h3o-public-ingress-authorization-receipt:v1"
BOUNDARY_REPORT_SCHEMA = "post-h3o-public-ingress-authorization-boundary-report:v1"

ACCEPTED_OPERATOR_DECISION = "authorize_post_h3_public_ingress_once"
ACCEPTED_AUDIT_DECISION = "accept_post_h3n_boundary_for_public_ingress_authorization"
ACCEPTED_SECURITY_DECISION = "accept_public_ingress_low_risk_scope"
ACCEPTED_ROLLBACK_DECISION = "accept_public_ingress_rollback_path"
ACCEPTED_MONITORING_DECISION = "accept_public_ingress_monitoring_path"
NON_CLAIMS = (
    "post_h3o_authorizes_public_ingress_only",
    "post_h3o_does_not_open_public_ingress",
    "post_h3o_does_not_expand_runtime_execution",
    "post_h3o_does_not_execute_runtime",
    "post_h3o_does_not_contact_vm_targets",
    "post_h3o_does_not_deploy",
    "post_h3o_does_not_access_production_data",
    "post_h3o_does_not_write_source_or_git",
)


def run_gate(
    *,
    post_h3n_summary_path: Path,
    output_root: Path,
    operator_id: str = "operator-primary",
    operator_decision: str = ACCEPTED_OPERATOR_DECISION,
    audit_decision: str = ACCEPTED_AUDIT_DECISION,
    security_decision: str = ACCEPTED_SECURITY_DECISION,
    rollback_decision: str = ACCEPTED_ROLLBACK_DECISION,
    monitoring_decision: str = ACCEPTED_MONITORING_DECISION,
    operator_statement: str = "Authorize one bounded public ingress execution gate; do not open ingress in this authorization step.",
    max_public_ingress_seconds: int = 300,
    max_external_participants: int = 1,
    allowed_ingress_scope: str = "invite_only_status_endpoint_preview",
    ack_public_ingress_authorization: bool = False,
) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "context_validation": output_root / "post_h3o_post_h3n_context_validation.json",
        "authorization_request": output_root / "post_h3o_public_ingress_authorization_request.json",
        "authorization_decision": output_root / "post_h3o_public_ingress_authorization_decision.json",
        "authorization_receipt": output_root / "post_h3o_public_ingress_authorization_receipt.json",
        "boundary_report": output_root / "post_h3o_public_ingress_authorization_boundary_report.json",
        "summary": output_root / "post_h3o_public_ingress_authorization_summary.json",
    }
    context = validate_post_h3n_context(post_h3n_summary_path, output=artifacts["context_validation"])
    request = _write_authorization_request(
        context=context,
        post_h3n_summary_path=post_h3n_summary_path,
        output=artifacts["authorization_request"],
        max_public_ingress_seconds=max_public_ingress_seconds,
        max_external_participants=max_external_participants,
        allowed_ingress_scope=allowed_ingress_scope,
    )
    decision = _write_decision(
        request_path=artifacts["authorization_request"],
        output=artifacts["authorization_decision"],
        operator_id=operator_id,
        operator_decision=operator_decision,
        audit_decision=audit_decision,
        security_decision=security_decision,
        rollback_decision=rollback_decision,
        monitoring_decision=monitoring_decision,
        operator_statement=operator_statement,
        ack_public_ingress_authorization=ack_public_ingress_authorization,
    )
    receipt = _write_authorization_receipt(request_path=artifacts["authorization_request"], decision_path=artifacts["authorization_decision"], output=artifacts["authorization_receipt"])
    boundary = _write_boundary_report(context=context, receipt_path=artifacts["authorization_receipt"], output=artifacts["boundary_report"])
    reports = [context, request, decision, receipt, boundary]
    passed = all(report.get("passed") is True for report in reports)
    summary = {
        "schema_version": CHAIN_SCHEMA,
        "passed": passed,
        "failure_reasons": _failures(reports),
        "checked_at": _now(),
        "source_artifacts": {"post_h3n_summary": artifact_ref(post_h3n_summary_path)},
        "artifacts": {name: artifact_ref(path) for name, path in artifacts.items() if name != "summary"},
        "public_ingress_authorization_id": receipt.get("authorization_id"),
        "readiness": {
            "state": "post_h3_public_ingress_authorized" if passed else "blocked_post_h3_public_ingress_authorization",
            "public_ingress_authorization_complete": passed,
            "public_ingress_authorized": passed,
            "public_ingress_execution_ready": passed,
            "runtime_expansion_authorized": False,
            "external_public_ingress_opened": False,
            "production_runtime_receipt_write_allowed": False,
        },
        "boundary": _boundary(
            context_validation_written=context.get("passed") is True,
            authorization_request_written=request.get("passed") is True,
            authorization_decision_written=decision.get("passed") is True,
            authorization_receipt_written=receipt.get("passed") is True,
            boundary_report_written=boundary.get("passed") is True,
            public_ingress_authorized=passed,
        ),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(artifacts["summary"], summary)
    return summary


def validate_post_h3n_context(post_h3n_summary_path: Path, *, output: Path | None = None) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    try:
        summary = read_json_object(post_h3n_summary_path)
    except Exception as exc:  # noqa: BLE001
        return _write_optional(_report(CONTEXT_SCHEMA, False, [f"post_h3n_summary_unreadable:{exc}"], checks), output)
    artifacts = object_value(summary.get("artifacts"))
    reconciliation = _read_verified_ref(artifacts.get("closeout_reconciliation"), checks, failures, "post_h3n_closeout_reconciliation")
    boundary_report = _read_verified_ref(artifacts.get("boundary_report"), checks, failures, "post_h3n_boundary_report")
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
        "post_h3n_summary": summary,
        "closeout_reconciliation": reconciliation,
        "boundary_report": boundary_report,
        "source_artifacts": {"post_h3n_summary": artifact_ref(post_h3n_summary_path)},
        "boundary": _boundary(context_validation_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    return _write_optional(report, output)


def _write_authorization_request(
    *,
    context: dict[str, Any],
    post_h3n_summary_path: Path,
    output: Path,
    max_public_ingress_seconds: int,
    max_external_participants: int,
    allowed_ingress_scope: str,
) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "max_public_ingress_seconds_positive", 0 < max_public_ingress_seconds <= 900)
    check(checks, failures, "max_external_participants_bounded", 0 <= max_external_participants <= 5)
    check(checks, failures, "allowed_ingress_scope_present", bool(allowed_ingress_scope.strip()))
    check(checks, failures, "allowed_ingress_scope_not_public_wildcard", allowed_ingress_scope not in {"*", "public_all", "unbounded"})
    passed = _passed(checks, failures)
    request = {
        "schema_version": AUTHORIZATION_REQUEST_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "requested_at": _now(),
        "authorization_request_id": f"post-h3o-public-ingress-request:{sha256_json([artifact_ref(post_h3n_summary_path), max_public_ingress_seconds, max_external_participants, allowed_ingress_scope])[:24]}",
        "requested_scope": {
            "authorize_public_ingress_execution_once": True,
            "max_public_ingress_seconds": max_public_ingress_seconds,
            "max_external_participants": max_external_participants,
            "allowed_ingress_scope": allowed_ingress_scope,
            "authorize_runtime_expansion": False,
            "allow_production_data_access": False,
            "allow_unbounded_public_ingress": False,
        },
        "source_artifacts": {"post_h3n_summary": artifact_ref(post_h3n_summary_path)},
        "readiness": {
            "authorization_request_ready": passed,
            "public_ingress_authorized": False,
            "external_public_ingress_opened": False,
            "runtime_expansion_authorized": False,
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
    security_decision: str,
    rollback_decision: str,
    monitoring_decision: str,
    operator_statement: str,
    ack_public_ingress_authorization: bool,
) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    request = read_json_object(request_path)
    check(checks, failures, "request_passed", request.get("schema_version") == AUTHORIZATION_REQUEST_SCHEMA and request.get("passed") is True)
    check(checks, failures, "operator_id_present", bool(operator_id.strip()))
    check(checks, failures, "operator_decision_accepted", operator_decision == ACCEPTED_OPERATOR_DECISION)
    check(checks, failures, "audit_decision_accepted", audit_decision == ACCEPTED_AUDIT_DECISION)
    check(checks, failures, "security_decision_accepted", security_decision == ACCEPTED_SECURITY_DECISION)
    check(checks, failures, "rollback_decision_accepted", rollback_decision == ACCEPTED_ROLLBACK_DECISION)
    check(checks, failures, "monitoring_decision_accepted", monitoring_decision == ACCEPTED_MONITORING_DECISION)
    check(checks, failures, "operator_statement_present", bool(operator_statement.strip()))
    check(checks, failures, "explicit_operator_ack", ack_public_ingress_authorization is True)
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
        "security_decision": security_decision,
        "rollback_decision": rollback_decision,
        "monitoring_decision": monitoring_decision,
        "operator_statement": operator_statement,
        "operator_statement_sha256": sha256_json(operator_statement),
        "ack_public_ingress_authorization": ack_public_ingress_authorization,
        "source_artifacts": {"authorization_request": artifact_ref(request_path)},
        "readiness": {"authorization_decision_complete": passed, "public_ingress_authorized": passed},
        "boundary": _boundary(authorization_decision_written=passed, public_ingress_authorized=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, decision)
    return decision


def _write_authorization_receipt(*, request_path: Path, decision_path: Path, output: Path) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    request = read_json_object(request_path)
    decision = read_json_object(decision_path)
    check(checks, failures, "request_passed", request.get("passed") is True)
    check(checks, failures, "decision_passed", decision.get("passed") is True)
    scope = object_value(request.get("requested_scope"))
    check(checks, failures, "scope_authorizes_public_ingress_once", scope.get("authorize_public_ingress_execution_once") is True)
    check(checks, failures, "scope_no_runtime_expansion", scope.get("authorize_runtime_expansion") is False)
    passed = _passed(checks, failures)
    receipt = {
        "schema_version": AUTHORIZATION_RECEIPT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "written_at": _now(),
        "authorization_id": f"post-h3o-public-ingress-auth:{sha256_json([artifact_ref(request_path), artifact_ref(decision_path)])[:24]}",
        "authorization_granted": passed,
        "single_use": True,
        "consumed": False,
        "authorization_scope": scope,
        "source_artifacts": {"authorization_request": artifact_ref(request_path), "authorization_decision": artifact_ref(decision_path)},
        "readiness": {"public_ingress_authorized": passed, "public_ingress_execution_ready": passed, "runtime_expansion_authorized": False},
        "boundary": _boundary(authorization_receipt_written=passed, public_ingress_authorized=passed),
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
    check(checks, failures, "public_ingress_authorized", object_value(receipt.get("readiness")).get("public_ingress_authorized") is True)
    check(checks, failures, "runtime_expansion_not_authorized", object_value(receipt.get("readiness")).get("runtime_expansion_authorized") is False)
    passed = _passed(checks, failures)
    report = {
        "schema_version": BOUNDARY_REPORT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "source_artifacts": {"authorization_receipt": artifact_ref(receipt_path)},
        "boundary": _boundary(boundary_report_written=passed, public_ingress_authorized=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def _check_summary(summary: dict[str, Any], checks: dict[str, bool], failures: list[str]) -> None:
    readiness = object_value(summary.get("readiness"))
    boundary = object_value(summary.get("boundary"))
    check(checks, failures, "post_h3n_schema_valid", summary.get("schema_version") == POST_H3N_SCHEMA)
    check(checks, failures, "post_h3n_passed", summary.get("passed") is True)
    check(checks, failures, "closeout_complete", readiness.get("external_release_closeout_complete") is True)
    check(checks, failures, "public_ingress_authorization_ready", readiness.get("public_ingress_authorization_ready") is True)
    check(checks, failures, "runtime_expansion_authorization_ready", readiness.get("runtime_expansion_authorization_ready") is True)
    check(checks, failures, "public_ingress_not_authorized_before_o", readiness.get("public_ingress_authorized") is False)
    check(checks, failures, "runtime_expansion_not_authorized_before_o", readiness.get("runtime_expansion_authorized") is False)
    check(checks, failures, "boundary_closeout_complete", boundary.get("external_release_closeout_complete") is True)
    for key in ("external_public_ingress_opened", "runtime_execution_performed", "vm_contact_performed", "deploy_performed", "production_data_accessed", "source_tree_write_performed", "git_write_performed"):
        check(checks, failures, f"no_{key}", boundary.get(key) is False)


def _check_reconciliation(reconciliation: dict[str, Any], checks: dict[str, bool], failures: list[str]) -> None:
    check(checks, failures, "reconciliation_schema_valid", reconciliation.get("schema_version") == POST_H3N_RECONCILIATION_SCHEMA)
    check(checks, failures, "reconciliation_passed", reconciliation.get("passed") is True)
    readiness = object_value(reconciliation.get("readiness"))
    check(checks, failures, "reconciliation_public_ready", readiness.get("public_ingress_authorization_ready") is True)
    check(checks, failures, "reconciliation_runtime_ready", readiness.get("runtime_expansion_authorization_ready") is True)


def _check_boundary_report(report: dict[str, Any], checks: dict[str, bool], failures: list[str]) -> None:
    check(checks, failures, "boundary_report_schema_valid", report.get("schema_version") == POST_H3N_BOUNDARY_REPORT_SCHEMA and report.get("passed") is True)
    boundary = object_value(report.get("boundary"))
    check(checks, failures, "boundary_no_public_ingress_opened", boundary.get("external_public_ingress_opened") is False)
    check(checks, failures, "boundary_no_runtime_execution", boundary.get("runtime_execution_performed") is False)


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
        "public_ingress_authorized": False,
        "runtime_expansion_authorized": False,
        "external_public_ingress_opened": False,
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
    parser = argparse.ArgumentParser(description="Run PostH3-O public ingress authorization gate")
    parser.add_argument("--post-h3n-summary", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--operator-id", default="operator-primary")
    parser.add_argument("--operator-decision", default=ACCEPTED_OPERATOR_DECISION)
    parser.add_argument("--audit-decision", default=ACCEPTED_AUDIT_DECISION)
    parser.add_argument("--security-decision", default=ACCEPTED_SECURITY_DECISION)
    parser.add_argument("--rollback-decision", default=ACCEPTED_ROLLBACK_DECISION)
    parser.add_argument("--monitoring-decision", default=ACCEPTED_MONITORING_DECISION)
    parser.add_argument("--operator-statement", default="Authorize one bounded public ingress execution gate; do not open ingress in this authorization step.")
    parser.add_argument("--max-public-ingress-seconds", type=int, default=300)
    parser.add_argument("--max-external-participants", type=int, default=1)
    parser.add_argument("--allowed-ingress-scope", default="invite_only_status_endpoint_preview")
    parser.add_argument("--ack-public-ingress-authorization", action="store_true")
    args = parser.parse_args()
    summary = run_gate(
        post_h3n_summary_path=args.post_h3n_summary,
        output_root=args.output_root,
        operator_id=args.operator_id,
        operator_decision=args.operator_decision,
        audit_decision=args.audit_decision,
        security_decision=args.security_decision,
        rollback_decision=args.rollback_decision,
        monitoring_decision=args.monitoring_decision,
        operator_statement=args.operator_statement,
        max_public_ingress_seconds=args.max_public_ingress_seconds,
        max_external_participants=args.max_external_participants,
        allowed_ingress_scope=args.allowed_ingress_scope,
        ack_public_ingress_authorization=args.ack_public_ingress_authorization,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if summary.get("passed") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
