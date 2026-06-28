"""Close out the PostH3 internal controlled production pilot slice.

PostH3-G consumes PostH3-A..F summaries, builds a receipt index and boundary
reconciliation, and prepares the next-stage request surface. It does not execute
runtime work, deploy, open public ingress, or authorize external release.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from benchmarks.i_gate_evidence import artifact_ref, check, object_value, read_json_object, sha256_json, write_json_object
from benchmarks.post_h3_deployment_boundary_gate import CHAIN_SCHEMA as POST_H3B_SCHEMA
from benchmarks.post_h3_first_internal_runtime_execution_gate import CHAIN_SCHEMA as POST_H3D_SCHEMA
from benchmarks.post_h3_internal_runtime_authorization_gate import CHAIN_SCHEMA as POST_H3A_SCHEMA
from benchmarks.post_h3_production_receipt_write_authorization_gate import CHAIN_SCHEMA as POST_H3E_SCHEMA
from benchmarks.post_h3_production_runtime_receipt_write_gate import CHAIN_SCHEMA as POST_H3F_SCHEMA
from benchmarks.post_h3_rollback_abort_drill_gate import CHAIN_SCHEMA as POST_H3C_SCHEMA

CHAIN_SCHEMA = "post-h3-internal-pilot-closeout-chain:v1"
CONTEXT_SCHEMA = "post-h3g-a-f-context-validation:v1"
RECEIPT_INDEX_SCHEMA = "post-h3g-receipt-index:v1"
BOUNDARY_RECONCILIATION_SCHEMA = "post-h3g-boundary-reconciliation:v1"
CLOSEOUT_SCHEMA = "post-h3g-owner-audit-closeout:v1"
NEXT_REQUEST_SCHEMA = "post-h3g-next-stage-request:v1"

ACCEPTED_OPERATOR_DECISION = "close_post_h3_internal_pilot_and_prepare_next_request"
ACCEPTED_AUDIT_DECISION = "accept_post_h3_a_f_boundary_and_receipt_index"
NON_CLAIMS = (
    "post_h3g_closeout_only",
    "post_h3g_does_not_execute_runtime",
    "post_h3g_does_not_contact_vm_targets",
    "post_h3g_does_not_deploy",
    "post_h3g_does_not_open_public_ingress",
    "post_h3g_does_not_access_production_data",
    "post_h3g_does_not_write_source_or_git",
    "post_h3g_does_not_authorize_external_limited_release",
)

EXPECTED_SCHEMAS = {
    "post_h3a": POST_H3A_SCHEMA,
    "post_h3b": POST_H3B_SCHEMA,
    "post_h3c": POST_H3C_SCHEMA,
    "post_h3d": POST_H3D_SCHEMA,
    "post_h3e": POST_H3E_SCHEMA,
    "post_h3f": POST_H3F_SCHEMA,
}


def run_gate(
    *,
    post_h3a_summary_path: Path,
    post_h3b_summary_path: Path,
    post_h3c_summary_path: Path,
    post_h3d_summary_path: Path,
    post_h3e_summary_path: Path,
    post_h3f_summary_path: Path,
    output_root: Path,
    operator_id: str = "operator-primary",
    operator_decision: str = ACCEPTED_OPERATOR_DECISION,
    audit_decision: str = ACCEPTED_AUDIT_DECISION,
    operator_statement: str = "Close out PostH3 A-F internal controlled pilot slice and prepare next-stage request.",
    ack_internal_pilot_closeout: bool = False,
) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    paths = {
        "post_h3a": post_h3a_summary_path,
        "post_h3b": post_h3b_summary_path,
        "post_h3c": post_h3c_summary_path,
        "post_h3d": post_h3d_summary_path,
        "post_h3e": post_h3e_summary_path,
        "post_h3f": post_h3f_summary_path,
    }
    artifacts = {
        "context_validation": output_root / "post_h3g_a_f_context_validation.json",
        "receipt_index": output_root / "post_h3g_receipt_index.json",
        "boundary_reconciliation": output_root / "post_h3g_boundary_reconciliation.json",
        "owner_audit_closeout": output_root / "post_h3g_owner_audit_closeout.json",
        "next_stage_request": output_root / "post_h3g_next_stage_request.json",
        "summary": output_root / "post_h3g_internal_pilot_closeout_summary.json",
    }
    context = validate_context(paths, output=artifacts["context_validation"])
    receipt_index = _write_receipt_index(context=context, output=artifacts["receipt_index"])
    boundary = _write_boundary_reconciliation(context=context, receipt_index_path=artifacts["receipt_index"], output=artifacts["boundary_reconciliation"])
    closeout = _write_closeout(
        context=context,
        receipt_index_path=artifacts["receipt_index"],
        boundary_reconciliation_path=artifacts["boundary_reconciliation"],
        output=artifacts["owner_audit_closeout"],
        operator_id=operator_id,
        operator_decision=operator_decision,
        audit_decision=audit_decision,
        operator_statement=operator_statement,
        ack_internal_pilot_closeout=ack_internal_pilot_closeout,
    )
    next_request = _write_next_stage_request(
        context=context,
        closeout_path=artifacts["owner_audit_closeout"],
        boundary_reconciliation_path=artifacts["boundary_reconciliation"],
        output=artifacts["next_stage_request"],
    )
    reports = [context, receipt_index, boundary, closeout, next_request]
    passed = all(report.get("passed") is True for report in reports)
    summaries = object_value(context.get("summaries"))
    summary = {
        "schema_version": CHAIN_SCHEMA,
        "passed": passed,
        "failure_reasons": _failures(reports),
        "checked_at": _now(),
        "source_artifacts": {name: artifact_ref(path) for name, path in paths.items()},
        "artifacts": {name: artifact_ref(path) for name, path in artifacts.items() if name != "summary"},
        "task_id": object_value(summaries.get("post_h3f")).get("task_id"),
        "production_runtime_receipt_id": object_value(summaries.get("post_h3f")).get("production_runtime_receipt_id"),
        "readiness": {
            "state": "post_h3_internal_pilot_closed" if passed else "blocked_post_h3_internal_pilot_closeout",
            "post_h3_internal_pilot_closed": passed,
            "post_h3_a_f_evidence_index_complete": passed,
            "next_stage_request_ready": passed,
            "external_limited_release_ready": False,
            "public_ingress_authorized": False,
            "production_runtime_receipt_write_allowed": False,
        },
        "boundary": _boundary(
            context_validation_written=context.get("passed") is True,
            receipt_index_written=receipt_index.get("passed") is True,
            boundary_reconciliation_written=boundary.get("passed") is True,
            owner_audit_closeout_written=closeout.get("passed") is True,
            next_stage_request_written=next_request.get("passed") is True,
        ),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(artifacts["summary"], summary)
    return summary


def validate_context(paths: dict[str, Path], *, output: Path | None = None) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    summaries: dict[str, dict[str, Any]] = {}
    for name, path in paths.items():
        try:
            summaries[name] = read_json_object(path)
        except Exception as exc:  # noqa: BLE001
            failures.append(f"{name}_unreadable:{exc}")
            summaries[name] = {}
    _check_summaries(summaries, checks, failures)
    passed = _passed(checks, failures)
    report = {
        "schema_version": CONTEXT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "summaries": summaries,
        "source_artifacts": {name: artifact_ref(path) for name, path in paths.items() if path.is_file()},
        "boundary": _boundary(context_validation_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    return _write_optional(report, output)


def _write_receipt_index(*, context: dict[str, Any], output: Path) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    summaries = object_value(context.get("summaries"))
    h3f = object_value(summaries.get("post_h3f"))
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "production_runtime_receipt_present", bool(h3f.get("production_runtime_receipt_id")))
    passed = _passed(checks, failures)
    index = {
        "schema_version": RECEIPT_INDEX_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "written_at": _now(),
        "receipt_index_id": f"post-h3g-receipt-index:{sha256_json(object_value(context.get('source_artifacts')))[:24]}",
        "receipts": {
            "post_h3a_authorization": object_value(summaries.get("post_h3a")).get("authorization_id"),
            "post_h3e_receipt_write_authorization": object_value(summaries.get("post_h3e")).get("authorization_id"),
            "post_h3f_production_runtime_receipt": h3f.get("production_runtime_receipt_id"),
        },
        "source_artifacts": object_value(context.get("source_artifacts")),
        "boundary": _boundary(receipt_index_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, index)
    return index


def _write_boundary_reconciliation(*, context: dict[str, Any], receipt_index_path: Path, output: Path) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    receipt_index = read_json_object(receipt_index_path)
    summaries = object_value(context.get("summaries"))
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "receipt_index_passed", receipt_index.get("passed") is True)
    check(checks, failures, "all_no_public_ingress", _all_boundaries_false(summaries, "external_public_ingress_opened"))
    check(checks, failures, "all_no_deploy", _all_boundaries_false(summaries, "deploy_performed"))
    check(checks, failures, "all_no_production_data", _all_boundaries_false(summaries, "production_data_accessed"))
    check(checks, failures, "all_no_source_tree_write", _all_boundaries_false(summaries, "source_tree_write_performed"))
    check(checks, failures, "all_no_git_write", _all_boundaries_false(summaries, "git_write_performed"))
    check(checks, failures, "post_h3f_receipt_written", object_value(object_value(summaries.get("post_h3f")).get("readiness")).get("production_runtime_receipt_written") is True)
    check(checks, failures, "receipt_write_closed", object_value(object_value(summaries.get("post_h3f")).get("readiness")).get("production_runtime_receipt_write_allowed") is False)
    passed = _passed(checks, failures)
    report = {
        "schema_version": BOUNDARY_RECONCILIATION_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "source_artifacts": {
            "context_validation": object_value(context.get("source_artifacts")),
            "receipt_index": artifact_ref(receipt_index_path),
        },
        "boundary": _boundary(receipt_index_written=True, boundary_reconciliation_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def _write_closeout(
    *,
    context: dict[str, Any],
    receipt_index_path: Path,
    boundary_reconciliation_path: Path,
    output: Path,
    operator_id: str,
    operator_decision: str,
    audit_decision: str,
    operator_statement: str,
    ack_internal_pilot_closeout: bool,
) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    receipt_index = read_json_object(receipt_index_path)
    boundary = read_json_object(boundary_reconciliation_path)
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "receipt_index_passed", receipt_index.get("passed") is True)
    check(checks, failures, "boundary_reconciliation_passed", boundary.get("passed") is True)
    check(checks, failures, "operator_id_present", bool(operator_id.strip()))
    check(checks, failures, "operator_decision_accepted", operator_decision == ACCEPTED_OPERATOR_DECISION)
    check(checks, failures, "audit_decision_accepted", audit_decision == ACCEPTED_AUDIT_DECISION)
    check(checks, failures, "operator_statement_present", bool(operator_statement.strip()))
    check(checks, failures, "explicit_operator_ack", ack_internal_pilot_closeout is True)
    passed = _passed(checks, failures)
    closeout = {
        "schema_version": CLOSEOUT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "closed_at": _now(),
        "operator_id": operator_id,
        "operator_decision": operator_decision,
        "audit_decision": audit_decision,
        "operator_statement": operator_statement,
        "operator_statement_sha256": sha256_json(operator_statement),
        "ack_internal_pilot_closeout": ack_internal_pilot_closeout,
        "source_artifacts": {
            "receipt_index": artifact_ref(receipt_index_path),
            "boundary_reconciliation": artifact_ref(boundary_reconciliation_path),
        },
        "boundary": _boundary(owner_audit_closeout_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, closeout)
    return closeout


def _write_next_stage_request(*, context: dict[str, Any], closeout_path: Path, boundary_reconciliation_path: Path, output: Path) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    closeout = read_json_object(closeout_path)
    boundary = read_json_object(boundary_reconciliation_path)
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "closeout_passed", closeout.get("passed") is True)
    check(checks, failures, "boundary_reconciliation_passed", boundary.get("passed") is True)
    passed = _passed(checks, failures)
    request = {
        "schema_version": NEXT_REQUEST_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "requested_at": _now(),
        "next_stage_request_id": f"post-h3g-next-stage-request:{sha256_json([artifact_ref(closeout_path), artifact_ref(boundary_reconciliation_path)])[:24]}",
        "requested_next_stage": "post_h3_internal_pilot_closeout_review",
        "allowed_next_actions": [
            "operator_review_next_stage_request",
            "prepare_external_limited_release_gate_inputs",
            "prepare_public_ingress_gate_inputs",
        ],
        "forbidden_without_future_gate": [
            "open_public_ingress",
            "external_limited_release",
            "expand_runtime_execution",
            "deploy_to_public_environment",
        ],
        "source_artifacts": {
            "owner_audit_closeout": artifact_ref(closeout_path),
            "boundary_reconciliation": artifact_ref(boundary_reconciliation_path),
        },
        "readiness": {
            "next_stage_request_ready": passed,
            "external_limited_release_ready": False,
            "public_ingress_authorized": False,
        },
        "boundary": _boundary(next_stage_request_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, request)
    return request


def _check_summaries(summaries: dict[str, dict[str, Any]], checks: dict[str, bool], failures: list[str]) -> None:
    for name, expected_schema in EXPECTED_SCHEMAS.items():
        summary = object_value(summaries.get(name))
        check(checks, failures, f"{name}_schema_valid", summary.get("schema_version") == expected_schema)
        check(checks, failures, f"{name}_passed", summary.get("passed") is True)
        boundary = object_value(summary.get("boundary"))
        if name not in {"post_h3d"}:
            check(checks, failures, f"{name}_no_runtime_execution", boundary.get("runtime_execution_performed") is False)
        check(checks, failures, f"{name}_no_public_ingress", boundary.get("external_public_ingress_opened") is False)
        check(checks, failures, f"{name}_no_deploy", boundary.get("deploy_performed") is False)
    h3d = object_value(summaries.get("post_h3d"))
    h3e = object_value(summaries.get("post_h3e"))
    h3f = object_value(summaries.get("post_h3f"))
    check(checks, failures, "post_h3d_runtime_performed", object_value(h3d.get("readiness")).get("runtime_execution_performed") is True)
    check(checks, failures, "post_h3e_write_authorized", object_value(h3e.get("readiness")).get("production_runtime_receipt_write_allowed") is True)
    check(checks, failures, "post_h3f_receipt_written", object_value(h3f.get("readiness")).get("production_runtime_receipt_written") is True)
    check(checks, failures, "post_h3f_write_closed", object_value(h3f.get("readiness")).get("production_runtime_receipt_write_allowed") is False)
    check(checks, failures, "task_binding_d_e_f", bool(h3d.get("task_id")) and h3d.get("task_id") == h3e.get("task_id") == h3f.get("task_id"))
    check(checks, failures, "authorization_binding_e_f", bool(h3e.get("authorization_id")) and h3e.get("authorization_id") == h3f.get("authorization_id"))


def _all_boundaries_false(summaries: dict[str, Any], key: str) -> bool:
    return all(object_value(object_value(summary).get("boundary")).get(key) is not True for summary in summaries.values())


def _boundary(**overrides: bool) -> dict[str, bool]:
    boundary = {
        "context_validation_written": False,
        "receipt_index_written": False,
        "boundary_reconciliation_written": False,
        "owner_audit_closeout_written": False,
        "next_stage_request_written": False,
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
    parser = argparse.ArgumentParser(description="Run PostH3-G internal pilot closeout gate")
    parser.add_argument("--post-h3a-summary", required=True, type=Path)
    parser.add_argument("--post-h3b-summary", required=True, type=Path)
    parser.add_argument("--post-h3c-summary", required=True, type=Path)
    parser.add_argument("--post-h3d-summary", required=True, type=Path)
    parser.add_argument("--post-h3e-summary", required=True, type=Path)
    parser.add_argument("--post-h3f-summary", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--operator-id", default="operator-primary")
    parser.add_argument("--operator-decision", default=ACCEPTED_OPERATOR_DECISION)
    parser.add_argument("--audit-decision", default=ACCEPTED_AUDIT_DECISION)
    parser.add_argument("--operator-statement", default="Close out PostH3 A-F internal controlled pilot slice and prepare next-stage request.")
    parser.add_argument("--ack-internal-pilot-closeout", action="store_true")
    args = parser.parse_args()
    summary = run_gate(
        post_h3a_summary_path=args.post_h3a_summary,
        post_h3b_summary_path=args.post_h3b_summary,
        post_h3c_summary_path=args.post_h3c_summary,
        post_h3d_summary_path=args.post_h3d_summary,
        post_h3e_summary_path=args.post_h3e_summary,
        post_h3f_summary_path=args.post_h3f_summary,
        output_root=args.output_root,
        operator_id=args.operator_id,
        operator_decision=args.operator_decision,
        audit_decision=args.audit_decision,
        operator_statement=args.operator_statement,
        ack_internal_pilot_closeout=args.ack_internal_pilot_closeout,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if summary.get("passed") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
