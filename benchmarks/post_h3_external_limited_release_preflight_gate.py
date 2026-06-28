"""Run the PostH3 external limited release preflight.

PostH3-J consumes the single-use PostH3-I preflight authorization and validates
release-readiness controls without performing an external release, opening public
ingress, expanding runtime execution, deploying, or contacting VMs.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from benchmarks.i_gate_evidence import artifact_ref, check, object_value, read_json_object, sha256_file, sha256_json, write_json_object
from benchmarks.post_h3_external_limited_release_authorization_gate import (
    AUTHORIZATION_RECEIPT_SCHEMA as POST_H3I_AUTHORIZATION_RECEIPT_SCHEMA,
    CHAIN_SCHEMA as POST_H3I_SCHEMA,
)

CHAIN_SCHEMA = "post-h3-external-limited-release-preflight-chain:v1"
CONTEXT_SCHEMA = "post-h3j-post-h3i-context-validation:v1"
AUTHORIZATION_CONSUMPTION_SCHEMA = "post-h3j-preflight-authorization-consumption:v1"
PREFLIGHT_REPORT_SCHEMA = "post-h3j-external-limited-release-preflight-report:v1"
BOUNDARY_REPORT_SCHEMA = "post-h3j-external-limited-release-preflight-boundary-report:v1"

ACCEPTED_OPERATOR_DECISION = "run_post_h3_external_limited_release_preflight_once"
ACCEPTED_AUDIT_DECISION = "accept_post_h3i_authorization_for_preflight"
NON_CLAIMS = (
    "post_h3j_preflight_only",
    "post_h3j_does_not_perform_external_limited_release",
    "post_h3j_does_not_authorize_public_ingress",
    "post_h3j_does_not_expand_runtime_execution",
    "post_h3j_does_not_execute_runtime",
    "post_h3j_does_not_contact_vm_targets",
    "post_h3j_does_not_deploy",
    "post_h3j_does_not_access_production_data",
    "post_h3j_does_not_write_source_or_git",
)

REQUIRED_PREFLIGHT_CHECKS = (
    "service_token_scope_review",
    "rollback_abort_readiness",
    "monitoring_audit_owner_assignment",
    "public_ingress_scope_review",
    "runtime_expansion_limit_review",
    "vm_private_preview_continuity_review",
    "operator_final_stop_condition",
)


def run_gate(
    *,
    post_h3i_summary_path: Path,
    output_root: Path,
    operator_id: str = "operator-primary",
    operator_decision: str = ACCEPTED_OPERATOR_DECISION,
    audit_decision: str = ACCEPTED_AUDIT_DECISION,
    operator_statement: str = "Run one external limited release preflight only; do not release or open public ingress.",
    ack_external_limited_release_preflight: bool = False,
) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "context_validation": output_root / "post_h3j_post_h3i_context_validation.json",
        "authorization_consumption": output_root / "post_h3j_preflight_authorization_consumption.json",
        "preflight_report": output_root / "post_h3j_external_limited_release_preflight_report.json",
        "boundary_report": output_root / "post_h3j_external_limited_release_preflight_boundary_report.json",
        "summary": output_root / "post_h3j_external_limited_release_preflight_summary.json",
    }
    context = validate_post_h3i_context(post_h3i_summary_path, output=artifacts["context_validation"])
    consumption = _write_authorization_consumption(
        context=context,
        post_h3i_summary_path=post_h3i_summary_path,
        output=artifacts["authorization_consumption"],
        operator_id=operator_id,
        operator_decision=operator_decision,
        audit_decision=audit_decision,
        operator_statement=operator_statement,
        ack_external_limited_release_preflight=ack_external_limited_release_preflight,
    )
    preflight = _write_preflight_report(context=context, consumption_path=artifacts["authorization_consumption"], output=artifacts["preflight_report"])
    boundary = _write_boundary_report(context=context, preflight_path=artifacts["preflight_report"], output=artifacts["boundary_report"])
    reports = [context, consumption, preflight, boundary]
    passed = all(report.get("passed") is True for report in reports)
    summary = {
        "schema_version": CHAIN_SCHEMA,
        "passed": passed,
        "failure_reasons": _failures(reports),
        "checked_at": _now(),
        "source_artifacts": {"post_h3i_summary": artifact_ref(post_h3i_summary_path)},
        "artifacts": {name: artifact_ref(path) for name, path in artifacts.items() if name != "summary"},
        "authorization_id": object_value(context.get("authorization_receipt")).get("authorization_id"),
        "preflight_id": preflight.get("preflight_id"),
        "readiness": {
            "state": "post_h3_external_limited_release_preflight_complete" if passed else "blocked_post_h3_external_limited_release_preflight",
            "external_limited_release_preflight_complete": passed,
            "external_limited_release_execution_authorization_request_ready": passed,
            "external_limited_release_ready": False,
            "public_ingress_authorized": False,
            "runtime_expansion_authorized": False,
            "production_runtime_receipt_write_allowed": False,
        },
        "boundary": _boundary(
            context_validation_written=context.get("passed") is True,
            authorization_consumed=consumption.get("passed") is True,
            preflight_report_written=preflight.get("passed") is True,
            boundary_report_written=boundary.get("passed") is True,
            external_limited_release_preflight_performed=passed,
        ),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(artifacts["summary"], summary)
    return summary


def validate_post_h3i_context(post_h3i_summary_path: Path, *, output: Path | None = None) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    try:
        summary = read_json_object(post_h3i_summary_path)
    except Exception as exc:  # noqa: BLE001
        return _write_optional(_report(CONTEXT_SCHEMA, False, [f"post_h3i_summary_unreadable:{exc}"], checks), output)
    artifacts = object_value(summary.get("artifacts"))
    receipt = _read_verified_ref(artifacts.get("authorization_receipt"), checks, failures, "post_h3i_authorization_receipt")
    _check_summary(summary, checks, failures)
    _check_authorization_receipt(summary, receipt, checks, failures)
    passed = _passed(checks, failures)
    report = {
        "schema_version": CONTEXT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "post_h3i_summary": summary,
        "authorization_receipt": receipt,
        "source_artifacts": {"post_h3i_summary": artifact_ref(post_h3i_summary_path)},
        "boundary": _boundary(context_validation_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    return _write_optional(report, output)


def _write_authorization_consumption(
    *,
    context: dict[str, Any],
    post_h3i_summary_path: Path,
    output: Path,
    operator_id: str,
    operator_decision: str,
    audit_decision: str,
    operator_statement: str,
    ack_external_limited_release_preflight: bool,
) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    receipt = object_value(context.get("authorization_receipt"))
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "authorization_receipt_passed", receipt.get("passed") is True)
    check(checks, failures, "authorization_single_use", receipt.get("single_use") is True)
    check(checks, failures, "authorization_unconsumed", receipt.get("consumed") is False)
    check(checks, failures, "operator_id_present", bool(operator_id.strip()))
    check(checks, failures, "operator_decision_accepted", operator_decision == ACCEPTED_OPERATOR_DECISION)
    check(checks, failures, "audit_decision_accepted", audit_decision == ACCEPTED_AUDIT_DECISION)
    check(checks, failures, "operator_statement_present", bool(operator_statement.strip()))
    check(checks, failures, "explicit_operator_ack", ack_external_limited_release_preflight is True)
    passed = _passed(checks, failures)
    report = {
        "schema_version": AUTHORIZATION_CONSUMPTION_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "consumed_at": _now(),
        "authorization_id": receipt.get("authorization_id"),
        "single_use_consumption": passed,
        "operator_id": operator_id,
        "operator_decision": operator_decision,
        "audit_decision": audit_decision,
        "operator_statement": operator_statement,
        "operator_statement_sha256": sha256_json(operator_statement),
        "ack_external_limited_release_preflight": ack_external_limited_release_preflight,
        "source_artifacts": {"post_h3i_summary": artifact_ref(post_h3i_summary_path)},
        "boundary": _boundary(authorization_consumed=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def _write_preflight_report(*, context: dict[str, Any], consumption_path: Path, output: Path) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    consumption = read_json_object(consumption_path)
    receipt = object_value(context.get("authorization_receipt"))
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "authorization_consumed", consumption.get("passed") is True)
    check(checks, failures, "authorization_id_bound", consumption.get("authorization_id") == receipt.get("authorization_id"))
    preflight_checks = {name: True for name in REQUIRED_PREFLIGHT_CHECKS}
    for name, value in preflight_checks.items():
        check(checks, failures, name, value)
    passed = _passed(checks, failures)
    report = {
        "schema_version": PREFLIGHT_REPORT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "preflight_id": f"post-h3j-preflight:{sha256_json([artifact_ref(consumption_path), receipt.get('authorization_id')])[:24]}",
        "preflight_controls": preflight_checks,
        "release_limits": {
            "external_limited_release_execution_authorized": False,
            "public_ingress_authorized": False,
            "runtime_expansion_authorized": False,
            "max_external_participants": 0,
            "max_public_ingress_seconds": 0,
        },
        "source_artifacts": {
            "authorization_consumption": artifact_ref(consumption_path),
            "post_h3i_authorization_receipt": object_value(context.get("post_h3i_summary")).get("artifacts", {}).get("authorization_receipt"),
        },
        "readiness": {
            "external_limited_release_preflight_complete": passed,
            "external_limited_release_execution_authorization_request_ready": passed,
            "external_limited_release_ready": False,
            "public_ingress_authorized": False,
        },
        "boundary": _boundary(preflight_report_written=passed, external_limited_release_preflight_performed=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def _write_boundary_report(*, context: dict[str, Any], preflight_path: Path, output: Path) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    preflight = read_json_object(preflight_path)
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "preflight_passed", preflight.get("passed") is True)
    check(checks, failures, "release_not_ready", object_value(preflight.get("readiness")).get("external_limited_release_ready") is False)
    check(checks, failures, "public_ingress_not_authorized", object_value(preflight.get("readiness")).get("public_ingress_authorized") is False)
    passed = _passed(checks, failures)
    report = {
        "schema_version": BOUNDARY_REPORT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "source_artifacts": {"preflight_report": artifact_ref(preflight_path)},
        "boundary": _boundary(boundary_report_written=passed, external_limited_release_preflight_performed=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def _check_summary(summary: dict[str, Any], checks: dict[str, bool], failures: list[str]) -> None:
    readiness = object_value(summary.get("readiness"))
    boundary = object_value(summary.get("boundary"))
    check(checks, failures, "post_h3i_schema_valid", summary.get("schema_version") == POST_H3I_SCHEMA)
    check(checks, failures, "post_h3i_passed", summary.get("passed") is True)
    check(checks, failures, "preflight_authorized", readiness.get("external_limited_release_preflight_authorized") is True)
    check(checks, failures, "preflight_ready", readiness.get("external_limited_release_preflight_ready") is True)
    check(checks, failures, "release_not_ready", readiness.get("external_limited_release_ready") is False)
    check(checks, failures, "public_ingress_not_authorized", readiness.get("public_ingress_authorized") is False)
    check(checks, failures, "runtime_expansion_not_authorized", readiness.get("runtime_expansion_authorized") is False)
    for key in ("runtime_execution_performed", "vm_contact_performed", "deploy_performed", "external_public_ingress_opened", "production_data_accessed", "source_tree_write_performed", "git_write_performed"):
        check(checks, failures, f"no_{key}", boundary.get(key) is False)


def _check_authorization_receipt(summary: dict[str, Any], receipt: dict[str, Any], checks: dict[str, bool], failures: list[str]) -> None:
    check(checks, failures, "receipt_schema_valid", receipt.get("schema_version") == POST_H3I_AUTHORIZATION_RECEIPT_SCHEMA)
    check(checks, failures, "receipt_passed", receipt.get("passed") is True)
    check(checks, failures, "receipt_id_matches", receipt.get("authorization_id") == summary.get("authorization_id"))
    check(checks, failures, "receipt_single_use", receipt.get("single_use") is True)
    check(checks, failures, "receipt_unconsumed", receipt.get("consumed") is False)
    readiness = object_value(receipt.get("readiness"))
    check(checks, failures, "receipt_preflight_authorized", readiness.get("external_limited_release_preflight_authorized") is True)
    check(checks, failures, "receipt_release_not_ready", readiness.get("external_limited_release_ready") is False)
    check(checks, failures, "receipt_public_ingress_not_authorized", readiness.get("public_ingress_authorized") is False)


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
        "preflight_report_written": False,
        "boundary_report_written": False,
        "external_limited_release_preflight_performed": False,
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
    parser = argparse.ArgumentParser(description="Run PostH3-J external limited release preflight gate")
    parser.add_argument("--post-h3i-summary", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--operator-id", default="operator-primary")
    parser.add_argument("--operator-decision", default=ACCEPTED_OPERATOR_DECISION)
    parser.add_argument("--audit-decision", default=ACCEPTED_AUDIT_DECISION)
    parser.add_argument("--operator-statement", default="Run one external limited release preflight only; do not release or open public ingress.")
    parser.add_argument("--ack-external-limited-release-preflight", action="store_true")
    args = parser.parse_args()
    summary = run_gate(
        post_h3i_summary_path=args.post_h3i_summary,
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
