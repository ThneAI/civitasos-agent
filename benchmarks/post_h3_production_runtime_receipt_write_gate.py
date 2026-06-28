"""Write the first controlled PostH3 production runtime receipt.

PostH3-F consumes a passed PostH3-E receipt-write authorization and writes one
controlled production runtime receipt. It does not execute runtime work again,
contact VMs, deploy, open public ingress, access production data, or mutate Git.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from benchmarks.i_gate_evidence import artifact_ref, check, object_value, read_json_object, sha256_file, sha256_json, write_json_object
from benchmarks.post_h3_production_receipt_write_authorization_gate import (
    AUTHORIZATION_SCHEMA as POST_H3E_AUTHORIZATION_SCHEMA,
    CHAIN_SCHEMA as POST_H3E_SCHEMA,
)

CHAIN_SCHEMA = "post-h3-production-runtime-receipt-write-execution-chain:v1"
CONTEXT_SCHEMA = "post-h3f-post-h3e-context-validation:v1"
CONSUMPTION_SCHEMA = "post-h3f-production-runtime-receipt-write-consumption:v1"
RECEIPT_SCHEMA = "post-h3f-production-runtime-receipt:v1"
BOUNDARY_REPORT_SCHEMA = "post-h3f-production-runtime-receipt-write-boundary-report:v1"

ACCEPTED_OPERATOR_DECISION = "write_post_h3_controlled_production_runtime_receipt"
ACCEPTED_AUDIT_DECISION = "accept_post_h3e_authorization_for_receipt_write"
NON_CLAIMS = (
    "post_h3f_writes_one_controlled_production_runtime_receipt_only",
    "post_h3f_does_not_execute_runtime_again",
    "post_h3f_does_not_contact_vm_targets",
    "post_h3f_does_not_deploy",
    "post_h3f_does_not_open_public_ingress",
    "post_h3f_does_not_access_production_data",
    "post_h3f_does_not_write_source_or_git",
    "post_h3f_does_not_authorize_external_limited_release",
)


def run_gate(
    *,
    post_h3e_summary_path: Path,
    output_root: Path,
    operator_id: str = "operator-primary",
    operator_decision: str = ACCEPTED_OPERATOR_DECISION,
    audit_decision: str = ACCEPTED_AUDIT_DECISION,
    operator_statement: str = "Write the single controlled production runtime receipt authorized by PostH3-E.",
    ack_production_runtime_receipt_write: bool = False,
) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "context_validation": output_root / "post_h3f_post_h3e_context_validation.json",
        "authorization_consumption": output_root / "post_h3f_authorization_consumption.json",
        "production_runtime_receipt": output_root / "post_h3f_production_runtime_receipt.json",
        "boundary_report": output_root / "post_h3f_production_runtime_receipt_write_boundary_report.json",
        "summary": output_root / "post_h3f_production_runtime_receipt_write_summary.json",
    }
    context = validate_post_h3e_context(post_h3e_summary_path, output=artifacts["context_validation"])
    consumption = _write_consumption(
        context=context,
        post_h3e_summary_path=post_h3e_summary_path,
        output=artifacts["authorization_consumption"],
        operator_id=operator_id,
        operator_decision=operator_decision,
        audit_decision=audit_decision,
        operator_statement=operator_statement,
        ack_production_runtime_receipt_write=ack_production_runtime_receipt_write,
    )
    receipt = _write_production_runtime_receipt(
        context=context,
        consumption_path=artifacts["authorization_consumption"],
        output=artifacts["production_runtime_receipt"],
    )
    boundary = _write_boundary_report(
        context=context,
        consumption_path=artifacts["authorization_consumption"],
        receipt_path=artifacts["production_runtime_receipt"],
        output=artifacts["boundary_report"],
    )
    reports = [context, consumption, receipt, boundary]
    passed = all(report.get("passed") is True for report in reports)
    summary = {
        "schema_version": CHAIN_SCHEMA,
        "passed": passed,
        "failure_reasons": _failures(reports),
        "checked_at": _now(),
        "source_artifacts": {"post_h3e_summary": artifact_ref(post_h3e_summary_path)},
        "artifacts": {name: artifact_ref(path) for name, path in artifacts.items() if name != "summary"},
        "task_id": object_value(context.get("post_h3e_summary")).get("task_id"),
        "authorization_id": object_value(context.get("authorization")).get("authorization_id"),
        "production_runtime_receipt_id": receipt.get("production_runtime_receipt_id"),
        "readiness": {
            "state": "post_h3f_production_runtime_receipt_written" if passed else "blocked_post_h3f_production_runtime_receipt_write",
            "post_h3f_production_runtime_receipt_written": passed,
            "production_runtime_receipt_write_allowed": False,
            "production_runtime_receipt_written": passed,
            "public_ingress_authorized": False,
            "external_limited_release_ready": False,
            "post_h3_internal_pilot_closeout_ready": passed,
        },
        "boundary": _boundary(
            context_validation_written=context.get("passed") is True,
            authorization_consumed=consumption.get("passed") is True,
            production_runtime_receipt_written=receipt.get("passed") is True,
            boundary_report_written=boundary.get("passed") is True,
        ),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(artifacts["summary"], summary)
    return summary


def validate_post_h3e_context(post_h3e_summary_path: Path, *, output: Path | None = None) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    try:
        summary = read_json_object(post_h3e_summary_path)
    except Exception as exc:  # noqa: BLE001
        return _write_optional(_report(CONTEXT_SCHEMA, False, [f"post_h3e_summary_unreadable:{exc}"], checks), output)

    artifacts = object_value(summary.get("artifacts"))
    authorization = _read_verified_ref(artifacts.get("receipt_write_authorization"), checks, failures, "post_h3e_authorization")
    readiness = object_value(summary.get("readiness"))
    boundary = object_value(summary.get("boundary"))
    _check_post_h3e_summary(summary, readiness, boundary, checks, failures)
    _check_authorization(summary, authorization, checks, failures)
    passed = _passed(checks, failures)
    report = {
        "schema_version": CONTEXT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "post_h3e_summary": summary,
        "authorization": authorization,
        "source_artifacts": {"post_h3e_summary": artifact_ref(post_h3e_summary_path)},
        "boundary": _boundary(context_validation_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    return _write_optional(report, output)


def _write_consumption(
    *,
    context: dict[str, Any],
    post_h3e_summary_path: Path,
    output: Path,
    operator_id: str,
    operator_decision: str,
    audit_decision: str,
    operator_statement: str,
    ack_production_runtime_receipt_write: bool,
) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    authorization = object_value(context.get("authorization"))
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "authorization_passed", authorization.get("passed") is True)
    check(checks, failures, "authorization_single_use", authorization.get("single_use") is True)
    check(checks, failures, "authorization_unconsumed", authorization.get("consumed") is False)
    check(checks, failures, "operator_id_present", bool(operator_id.strip()))
    check(checks, failures, "operator_decision_accepted", operator_decision == ACCEPTED_OPERATOR_DECISION)
    check(checks, failures, "audit_decision_accepted", audit_decision == ACCEPTED_AUDIT_DECISION)
    check(checks, failures, "operator_statement_present", bool(operator_statement.strip()))
    check(checks, failures, "explicit_operator_ack", ack_production_runtime_receipt_write is True)
    passed = _passed(checks, failures)
    consumption = {
        "schema_version": CONSUMPTION_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "consumed_at": _now(),
        "authorization_id": authorization.get("authorization_id"),
        "single_use_consumption": passed,
        "operator_id": operator_id,
        "operator_decision": operator_decision,
        "audit_decision": audit_decision,
        "operator_statement": operator_statement,
        "operator_statement_sha256": sha256_json(operator_statement),
        "ack_production_runtime_receipt_write": ack_production_runtime_receipt_write,
        "source_artifacts": {
            "post_h3e_summary": artifact_ref(post_h3e_summary_path),
            "post_h3e_authorization": object_value(context.get("post_h3e_summary")).get("artifacts", {}).get("receipt_write_authorization"),
        },
        "boundary": _boundary(authorization_consumed=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, consumption)
    return consumption


def _write_production_runtime_receipt(*, context: dict[str, Any], consumption_path: Path, output: Path) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    consumption = read_json_object(consumption_path)
    summary = object_value(context.get("post_h3e_summary"))
    authorization = object_value(context.get("authorization"))
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "consumption_passed", consumption.get("passed") is True)
    check(checks, failures, "authorization_id_bound", consumption.get("authorization_id") == authorization.get("authorization_id"))
    check(checks, failures, "task_id_present", bool(authorization.get("task_id")))
    passed = _passed(checks, failures)
    receipt_id = f"post-h3f-production-runtime-receipt:{sha256_json([artifact_ref(consumption_path), authorization.get('authorization_id'), authorization.get('task_id')])[:24]}"
    receipt = {
        "schema_version": RECEIPT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "written_at": _now(),
        "production_runtime_receipt_id": receipt_id,
        "receipt_kind": "post_h3_internal_controlled_runtime_receipt",
        "authorization_id": authorization.get("authorization_id"),
        "task_id": authorization.get("task_id"),
        "source_task_id": authorization.get("source_task_id"),
        "post_h3e_readiness_state": object_value(summary.get("readiness")).get("state"),
        "receipt_statement": "PostH3-D internal controlled runtime execution has one production runtime receipt recorded under PostH3-E authorization.",
        "source_artifacts": {
            "authorization_consumption": artifact_ref(consumption_path),
            "post_h3e_summary": object_value(context.get("source_artifacts")).get("post_h3e_summary"),
            "post_h3e_authorization": object_value(summary.get("artifacts")).get("receipt_write_authorization"),
            "post_h3d_summary": object_value(summary.get("source_artifacts")).get("post_h3d_summary"),
        },
        "readiness": {
            "production_runtime_receipt_written": passed,
            "production_runtime_receipt_write_allowed": False,
            "external_limited_release_ready": False,
        },
        "boundary": _boundary(production_runtime_receipt_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, receipt)
    return receipt


def _write_boundary_report(*, context: dict[str, Any], consumption_path: Path, receipt_path: Path, output: Path) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    consumption = read_json_object(consumption_path)
    receipt = read_json_object(receipt_path)
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "consumption_passed", consumption.get("passed") is True)
    check(checks, failures, "receipt_passed", receipt.get("passed") is True)
    check(checks, failures, "receipt_written", object_value(receipt.get("readiness")).get("production_runtime_receipt_written") is True)
    check(checks, failures, "receipt_write_not_left_open", object_value(receipt.get("readiness")).get("production_runtime_receipt_write_allowed") is False)
    passed = _passed(checks, failures)
    report = {
        "schema_version": BOUNDARY_REPORT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "source_artifacts": {
            "authorization_consumption": artifact_ref(consumption_path),
            "production_runtime_receipt": artifact_ref(receipt_path),
        },
        "boundary": _boundary(authorization_consumed=passed, production_runtime_receipt_written=passed, boundary_report_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def _check_post_h3e_summary(summary: dict[str, Any], readiness: dict[str, Any], boundary: dict[str, Any], checks: dict[str, bool], failures: list[str]) -> None:
    check(checks, failures, "post_h3e_schema_valid", summary.get("schema_version") == POST_H3E_SCHEMA)
    check(checks, failures, "post_h3e_passed", summary.get("passed") is True)
    check(checks, failures, "post_h3e_authorized", readiness.get("post_h3e_production_receipt_write_authorized") is True)
    check(checks, failures, "receipt_write_allowed", readiness.get("production_runtime_receipt_write_allowed") is True)
    check(checks, failures, "receipt_not_yet_written", readiness.get("production_runtime_receipt_written") is False)
    check(checks, failures, "public_ingress_not_authorized", readiness.get("public_ingress_authorized") is False)
    check(checks, failures, "external_release_not_ready", readiness.get("external_limited_release_ready") is False)
    check(checks, failures, "authorization_written", boundary.get("receipt_write_authorization_written") is True)
    check(checks, failures, "boundary_receipt_write_allowed", boundary.get("production_runtime_receipt_write_allowed") is True)
    check(checks, failures, "boundary_receipt_not_written", boundary.get("production_runtime_receipt_written") is False)
    check(checks, failures, "no_runtime_execution_in_h3e", boundary.get("runtime_execution_performed") is False)
    check(checks, failures, "no_vm_contact", boundary.get("vm_contact_performed") is False)
    check(checks, failures, "no_deploy", boundary.get("deploy_performed") is False)
    check(checks, failures, "no_public_ingress", boundary.get("external_public_ingress_opened") is False)
    check(checks, failures, "no_production_data", boundary.get("production_data_accessed") is False)
    check(checks, failures, "no_source_tree_write", boundary.get("source_tree_write_performed") is False)
    check(checks, failures, "no_git_write", boundary.get("git_write_performed") is False)


def _check_authorization(summary: dict[str, Any], authorization: dict[str, Any], checks: dict[str, bool], failures: list[str]) -> None:
    check(checks, failures, "authorization_schema_valid", authorization.get("schema_version") == POST_H3E_AUTHORIZATION_SCHEMA)
    check(checks, failures, "authorization_passed", authorization.get("passed") is True)
    check(checks, failures, "authorization_id_matches", authorization.get("authorization_id") == summary.get("authorization_id"))
    check(checks, failures, "authorization_task_id_matches", authorization.get("task_id") == summary.get("task_id"))
    check(checks, failures, "authorization_single_use", authorization.get("single_use") is True)
    check(checks, failures, "authorization_unconsumed", authorization.get("consumed") is False)
    check(checks, failures, "authorization_allows_receipt_write", object_value(authorization.get("readiness")).get("production_runtime_receipt_write_allowed") is True)
    check(checks, failures, "authorization_receipt_not_written", object_value(authorization.get("readiness")).get("production_runtime_receipt_written") is False)
    auth_boundary = object_value(authorization.get("boundary"))
    check(checks, failures, "authorization_boundary_written", auth_boundary.get("receipt_write_authorization_written") is True)
    check(checks, failures, "authorization_boundary_allows_write", auth_boundary.get("production_runtime_receipt_write_allowed") is True)
    check(checks, failures, "authorization_no_runtime_execution", auth_boundary.get("runtime_execution_performed") is False)
    check(checks, failures, "authorization_no_public_ingress", auth_boundary.get("external_public_ingress_opened") is False)


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
        "authorization_consumed": False,
        "production_runtime_receipt_written": False,
        "boundary_report_written": False,
        "production_runtime_receipt_write_allowed": False,
        "runtime_execution_performed": False,
        "vm_contact_performed": False,
        "deploy_performed": False,
        "external_public_ingress_opened": False,
        "production_data_accessed": False,
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
    parser = argparse.ArgumentParser(description="Run PostH3-F production runtime receipt write gate")
    parser.add_argument("--post-h3e-summary", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--operator-id", default="operator-primary")
    parser.add_argument("--operator-decision", default=ACCEPTED_OPERATOR_DECISION)
    parser.add_argument("--audit-decision", default=ACCEPTED_AUDIT_DECISION)
    parser.add_argument("--operator-statement", default="Write the single controlled production runtime receipt authorized by PostH3-E.")
    parser.add_argument("--ack-production-runtime-receipt-write", action="store_true")
    args = parser.parse_args()
    summary = run_gate(
        post_h3e_summary_path=args.post_h3e_summary,
        output_root=args.output_root,
        operator_id=args.operator_id,
        operator_decision=args.operator_decision,
        audit_decision=args.audit_decision,
        operator_statement=args.operator_statement,
        ack_production_runtime_receipt_write=args.ack_production_runtime_receipt_write,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if summary.get("passed") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
