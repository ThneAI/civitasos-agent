"""Prepare a PostH3 release boundary request from internal pilot closeout.

PostH3-H consumes PostH3-G closeout evidence and prepares a request packet for
future external-limited-release / public-ingress review. It does not authorize or
perform external release, public ingress, runtime expansion, VM deploy, or Git
changes.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from benchmarks.i_gate_evidence import artifact_ref, check, object_value, read_json_object, sha256_file, sha256_json, write_json_object
from benchmarks.post_h3_internal_pilot_closeout_gate import (
    BOUNDARY_RECONCILIATION_SCHEMA as POST_H3G_BOUNDARY_RECONCILIATION_SCHEMA,
    CHAIN_SCHEMA as POST_H3G_SCHEMA,
    CLOSEOUT_SCHEMA as POST_H3G_CLOSEOUT_SCHEMA,
    NEXT_REQUEST_SCHEMA as POST_H3G_NEXT_REQUEST_SCHEMA,
    RECEIPT_INDEX_SCHEMA as POST_H3G_RECEIPT_INDEX_SCHEMA,
)

CHAIN_SCHEMA = "post-h3-release-boundary-request-chain:v1"
CONTEXT_SCHEMA = "post-h3h-post-h3g-context-validation:v1"
REQUEST_SCHEMA = "post-h3h-release-boundary-request:v1"
DECISION_SCHEMA = "post-h3h-release-boundary-request-decision:v1"
BOUNDARY_REPORT_SCHEMA = "post-h3h-release-boundary-boundary-report:v1"

ACCEPTED_OPERATOR_DECISION = "prepare_post_h3_release_boundary_request"
ACCEPTED_AUDIT_DECISION = "accept_post_h3g_closeout_for_release_boundary_review"
NON_CLAIMS = (
    "post_h3h_prepares_request_only",
    "post_h3h_does_not_authorize_external_limited_release",
    "post_h3h_does_not_authorize_public_ingress",
    "post_h3h_does_not_execute_runtime",
    "post_h3h_does_not_contact_vm_targets",
    "post_h3h_does_not_deploy",
    "post_h3h_does_not_access_production_data",
    "post_h3h_does_not_write_source_or_git",
)


def run_gate(
    *,
    post_h3g_summary_path: Path,
    output_root: Path,
    operator_id: str = "operator-primary",
    operator_decision: str = ACCEPTED_OPERATOR_DECISION,
    audit_decision: str = ACCEPTED_AUDIT_DECISION,
    operator_statement: str = "Prepare a release boundary request for independent future review; do not authorize release.",
    ack_release_boundary_request: bool = False,
) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "context_validation": output_root / "post_h3h_post_h3g_context_validation.json",
        "release_boundary_request": output_root / "post_h3h_release_boundary_request.json",
        "release_boundary_decision": output_root / "post_h3h_release_boundary_request_decision.json",
        "boundary_report": output_root / "post_h3h_release_boundary_boundary_report.json",
        "summary": output_root / "post_h3h_release_boundary_request_summary.json",
    }
    context = validate_post_h3g_context(post_h3g_summary_path, output=artifacts["context_validation"])
    request = _write_release_boundary_request(
        context=context,
        post_h3g_summary_path=post_h3g_summary_path,
        output=artifacts["release_boundary_request"],
    )
    decision = _write_decision(
        request_path=artifacts["release_boundary_request"],
        output=artifacts["release_boundary_decision"],
        operator_id=operator_id,
        operator_decision=operator_decision,
        audit_decision=audit_decision,
        operator_statement=operator_statement,
        ack_release_boundary_request=ack_release_boundary_request,
    )
    boundary = _write_boundary_report(
        context=context,
        request_path=artifacts["release_boundary_request"],
        decision_path=artifacts["release_boundary_decision"],
        output=artifacts["boundary_report"],
    )
    reports = [context, request, decision, boundary]
    passed = all(report.get("passed") is True for report in reports)
    summary = {
        "schema_version": CHAIN_SCHEMA,
        "passed": passed,
        "failure_reasons": _failures(reports),
        "checked_at": _now(),
        "source_artifacts": {"post_h3g_summary": artifact_ref(post_h3g_summary_path)},
        "artifacts": {name: artifact_ref(path) for name, path in artifacts.items() if name != "summary"},
        "task_id": object_value(context.get("post_h3g_summary")).get("task_id"),
        "production_runtime_receipt_id": object_value(context.get("post_h3g_summary")).get("production_runtime_receipt_id"),
        "release_boundary_request_id": request.get("release_boundary_request_id"),
        "readiness": {
            "state": "post_h3_release_boundary_request_ready" if passed else "blocked_post_h3_release_boundary_request",
            "post_h3_release_boundary_request_ready": passed,
            "external_limited_release_authorization_request_ready": passed,
            "public_ingress_authorization_request_ready": passed,
            "external_limited_release_ready": False,
            "public_ingress_authorized": False,
            "runtime_expansion_authorized": False,
            "production_runtime_receipt_write_allowed": False,
        },
        "boundary": _boundary(
            context_validation_written=context.get("passed") is True,
            release_boundary_request_written=request.get("passed") is True,
            release_boundary_decision_written=decision.get("passed") is True,
            boundary_report_written=boundary.get("passed") is True,
        ),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(artifacts["summary"], summary)
    return summary


def validate_post_h3g_context(post_h3g_summary_path: Path, *, output: Path | None = None) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    try:
        summary = read_json_object(post_h3g_summary_path)
    except Exception as exc:  # noqa: BLE001
        return _write_optional(_report(CONTEXT_SCHEMA, False, [f"post_h3g_summary_unreadable:{exc}"], checks), output)

    artifacts = object_value(summary.get("artifacts"))
    receipt_index = _read_verified_ref(artifacts.get("receipt_index"), checks, failures, "post_h3g_receipt_index")
    boundary_reconciliation = _read_verified_ref(artifacts.get("boundary_reconciliation"), checks, failures, "post_h3g_boundary_reconciliation")
    owner_audit_closeout = _read_verified_ref(artifacts.get("owner_audit_closeout"), checks, failures, "post_h3g_owner_audit_closeout")
    next_stage_request = _read_verified_ref(artifacts.get("next_stage_request"), checks, failures, "post_h3g_next_stage_request")
    _check_summary(summary, checks, failures)
    _check_artifacts(receipt_index, boundary_reconciliation, owner_audit_closeout, next_stage_request, checks, failures)
    passed = _passed(checks, failures)
    report = {
        "schema_version": CONTEXT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "post_h3g_summary": summary,
        "receipt_index": receipt_index,
        "boundary_reconciliation": boundary_reconciliation,
        "owner_audit_closeout": owner_audit_closeout,
        "next_stage_request": next_stage_request,
        "source_artifacts": {"post_h3g_summary": artifact_ref(post_h3g_summary_path)},
        "boundary": _boundary(context_validation_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    return _write_optional(report, output)


def _write_release_boundary_request(*, context: dict[str, Any], post_h3g_summary_path: Path, output: Path) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    summary = object_value(context.get("post_h3g_summary"))
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "closeout_ready", object_value(summary.get("readiness")).get("next_stage_request_ready") is True)
    check(checks, failures, "public_ingress_not_authorized", object_value(summary.get("readiness")).get("public_ingress_authorized") is False)
    check(checks, failures, "external_release_not_ready", object_value(summary.get("readiness")).get("external_limited_release_ready") is False)
    passed = _passed(checks, failures)
    request_id = f"post-h3h-release-boundary-request:{sha256_json([artifact_ref(post_h3g_summary_path), summary.get('production_runtime_receipt_id')])[:24]}"
    request = {
        "schema_version": REQUEST_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "requested_at": _now(),
        "release_boundary_request_id": request_id,
        "requested_scope": {
            "request_kind": "prepare_release_boundary_authorization_inputs",
            "external_limited_release_review": True,
            "public_ingress_review": True,
            "runtime_expansion_review": True,
            "authorization_granted": False,
        },
        "required_future_gates": [
            "external_limited_release_authorization_gate",
            "public_ingress_authorization_gate",
            "rollback_and_monitoring_readiness_gate",
            "operator_final_release_decision_gate",
        ],
        "forbidden_without_future_gate": [
            "open_public_ingress",
            "invite_external_users",
            "expand_runtime_execution",
            "deploy_to_public_environment",
            "write_additional_production_runtime_receipts",
        ],
        "source_artifacts": {"post_h3g_summary": artifact_ref(post_h3g_summary_path)},
        "readiness": {
            "release_boundary_request_ready": passed,
            "external_limited_release_ready": False,
            "public_ingress_authorized": False,
        },
        "boundary": _boundary(release_boundary_request_written=passed),
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
    ack_release_boundary_request: bool,
) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    request = read_json_object(request_path)
    check(checks, failures, "request_passed", request.get("schema_version") == REQUEST_SCHEMA and request.get("passed") is True)
    check(checks, failures, "operator_id_present", bool(operator_id.strip()))
    check(checks, failures, "operator_decision_accepted", operator_decision == ACCEPTED_OPERATOR_DECISION)
    check(checks, failures, "audit_decision_accepted", audit_decision == ACCEPTED_AUDIT_DECISION)
    check(checks, failures, "operator_statement_present", bool(operator_statement.strip()))
    check(checks, failures, "explicit_operator_ack", ack_release_boundary_request is True)
    passed = _passed(checks, failures)
    decision = {
        "schema_version": DECISION_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "decided_at": _now(),
        "operator_id": operator_id,
        "operator_decision": operator_decision,
        "audit_decision": audit_decision,
        "operator_statement": operator_statement,
        "operator_statement_sha256": sha256_json(operator_statement),
        "ack_release_boundary_request": ack_release_boundary_request,
        "source_artifacts": {"release_boundary_request": artifact_ref(request_path)},
        "boundary": _boundary(release_boundary_decision_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, decision)
    return decision


def _write_boundary_report(*, context: dict[str, Any], request_path: Path, decision_path: Path, output: Path) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    request = read_json_object(request_path)
    decision = read_json_object(decision_path)
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "request_passed", request.get("passed") is True)
    check(checks, failures, "decision_passed", decision.get("passed") is True)
    check(checks, failures, "request_does_not_authorize_release", object_value(request.get("readiness")).get("external_limited_release_ready") is False)
    check(checks, failures, "request_does_not_authorize_public_ingress", object_value(request.get("readiness")).get("public_ingress_authorized") is False)
    passed = _passed(checks, failures)
    report = {
        "schema_version": BOUNDARY_REPORT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "source_artifacts": {
            "release_boundary_request": artifact_ref(request_path),
            "release_boundary_decision": artifact_ref(decision_path),
        },
        "boundary": _boundary(boundary_report_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def _check_summary(summary: dict[str, Any], checks: dict[str, bool], failures: list[str]) -> None:
    readiness = object_value(summary.get("readiness"))
    boundary = object_value(summary.get("boundary"))
    check(checks, failures, "post_h3g_schema_valid", summary.get("schema_version") == POST_H3G_SCHEMA)
    check(checks, failures, "post_h3g_passed", summary.get("passed") is True)
    check(checks, failures, "internal_pilot_closed", readiness.get("post_h3_internal_pilot_closed") is True)
    check(checks, failures, "evidence_index_complete", readiness.get("post_h3_a_f_evidence_index_complete") is True)
    check(checks, failures, "next_stage_request_ready", readiness.get("next_stage_request_ready") is True)
    check(checks, failures, "public_ingress_not_authorized", readiness.get("public_ingress_authorized") is False)
    check(checks, failures, "external_release_not_ready", readiness.get("external_limited_release_ready") is False)
    check(checks, failures, "receipt_write_closed", readiness.get("production_runtime_receipt_write_allowed") is False)
    for key in ("runtime_execution_performed", "vm_contact_performed", "deploy_performed", "external_public_ingress_opened", "production_data_accessed", "source_tree_write_performed", "git_write_performed"):
        check(checks, failures, f"no_{key}", boundary.get(key) is False)
    check(checks, failures, "receipt_index_written", boundary.get("receipt_index_written") is True)
    check(checks, failures, "boundary_reconciliation_written", boundary.get("boundary_reconciliation_written") is True)
    check(checks, failures, "owner_audit_closeout_written", boundary.get("owner_audit_closeout_written") is True)
    check(checks, failures, "next_stage_request_written", boundary.get("next_stage_request_written") is True)


def _check_artifacts(receipt_index: dict[str, Any], boundary: dict[str, Any], closeout: dict[str, Any], next_stage: dict[str, Any], checks: dict[str, bool], failures: list[str]) -> None:
    check(checks, failures, "receipt_index_schema_valid", receipt_index.get("schema_version") == POST_H3G_RECEIPT_INDEX_SCHEMA and receipt_index.get("passed") is True)
    check(checks, failures, "boundary_reconciliation_schema_valid", boundary.get("schema_version") == POST_H3G_BOUNDARY_RECONCILIATION_SCHEMA and boundary.get("passed") is True)
    check(checks, failures, "closeout_schema_valid", closeout.get("schema_version") == POST_H3G_CLOSEOUT_SCHEMA and closeout.get("passed") is True)
    check(checks, failures, "next_stage_schema_valid", next_stage.get("schema_version") == POST_H3G_NEXT_REQUEST_SCHEMA and next_stage.get("passed") is True)
    check(checks, failures, "next_stage_request_ready_artifact", object_value(next_stage.get("readiness")).get("next_stage_request_ready") is True)
    check(checks, failures, "next_stage_no_external_release", object_value(next_stage.get("readiness")).get("external_limited_release_ready") is False)
    check(checks, failures, "next_stage_no_public_ingress", object_value(next_stage.get("readiness")).get("public_ingress_authorized") is False)
    receipts = object_value(receipt_index.get("receipts"))
    check(checks, failures, "production_runtime_receipt_indexed", bool(receipts.get("post_h3f_production_runtime_receipt")))


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
        "release_boundary_request_written": False,
        "release_boundary_decision_written": False,
        "boundary_report_written": False,
        "external_limited_release_authorized": False,
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
    return {
        "schema_version": schema,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "boundary": _boundary(),
        "non_claims": list(NON_CLAIMS),
    }


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
    parser = argparse.ArgumentParser(description="Run PostH3-H release boundary request gate")
    parser.add_argument("--post-h3g-summary", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--operator-id", default="operator-primary")
    parser.add_argument("--operator-decision", default=ACCEPTED_OPERATOR_DECISION)
    parser.add_argument("--audit-decision", default=ACCEPTED_AUDIT_DECISION)
    parser.add_argument("--operator-statement", default="Prepare a release boundary request for independent future review; do not authorize release.")
    parser.add_argument("--ack-release-boundary-request", action="store_true")
    args = parser.parse_args()
    summary = run_gate(
        post_h3g_summary_path=args.post_h3g_summary,
        output_root=args.output_root,
        operator_id=args.operator_id,
        operator_decision=args.operator_decision,
        audit_decision=args.audit_decision,
        operator_statement=args.operator_statement,
        ack_release_boundary_request=args.ack_release_boundary_request,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if summary.get("passed") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
