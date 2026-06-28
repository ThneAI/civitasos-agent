"""Execute the PostH3 controlled external limited release action.

PostH3-M consumes PostH3-L's one-time execution authorization and writes a
controlled external limited release action packet plus execution receipt. The
current authorization scope still allows zero external participants and no public
ingress, so this gate records the controlled release boundary execution without
inviting external users, opening public ingress, expanding runtime execution,
deploying, contacting VMs, accessing production data, or writing Git.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from benchmarks.i_gate_evidence import artifact_ref, check, object_value, read_json_object, sha256_file, sha256_json, write_json_object
from benchmarks.post_h3_external_limited_release_execution_authorization_review_gate import (
    AUTHORIZATION_RECEIPT_SCHEMA as POST_H3L_AUTHORIZATION_RECEIPT_SCHEMA,
    BOUNDARY_REPORT_SCHEMA as POST_H3L_BOUNDARY_REPORT_SCHEMA,
    CHAIN_SCHEMA as POST_H3L_SCHEMA,
)

CHAIN_SCHEMA = "post-h3-external-limited-release-execution-chain:v1"
CONTEXT_SCHEMA = "post-h3m-post-h3l-context-validation:v1"
AUTHORIZATION_CONSUMPTION_SCHEMA = "post-h3m-execution-authorization-consumption:v1"
RELEASE_ACTION_SCHEMA = "post-h3m-external-limited-release-action:v1"
EXECUTION_RECEIPT_SCHEMA = "post-h3m-external-limited-release-execution-receipt:v1"
BOUNDARY_REPORT_SCHEMA = "post-h3m-external-limited-release-execution-boundary-report:v1"

ACCEPTED_OPERATOR_DECISION = "execute_post_h3_external_limited_release_once"
ACCEPTED_AUDIT_DECISION = "accept_post_h3l_authorization_for_execution"
NON_CLAIMS = (
    "post_h3m_executes_controlled_release_boundary_only",
    "post_h3m_does_not_invite_external_users",
    "post_h3m_does_not_authorize_public_ingress",
    "post_h3m_does_not_expand_runtime_execution",
    "post_h3m_does_not_execute_runtime",
    "post_h3m_does_not_contact_vm_targets",
    "post_h3m_does_not_deploy",
    "post_h3m_does_not_access_production_data",
    "post_h3m_does_not_write_source_or_git",
)


def run_gate(
    *,
    post_h3l_summary_path: Path,
    output_root: Path,
    operator_id: str = "operator-primary",
    operator_decision: str = ACCEPTED_OPERATOR_DECISION,
    audit_decision: str = ACCEPTED_AUDIT_DECISION,
    operator_statement: str = "Execute the one-time controlled external limited release boundary action without public ingress or external users.",
    release_action_kind: str = "controlled_release_boundary_record",
    external_participant_count: int = 0,
    ack_external_limited_release_execution: bool = False,
) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "context_validation": output_root / "post_h3m_post_h3l_context_validation.json",
        "authorization_consumption": output_root / "post_h3m_execution_authorization_consumption.json",
        "release_action": output_root / "post_h3m_external_limited_release_action.json",
        "execution_receipt": output_root / "post_h3m_external_limited_release_execution_receipt.json",
        "boundary_report": output_root / "post_h3m_external_limited_release_execution_boundary_report.json",
        "summary": output_root / "post_h3m_external_limited_release_execution_summary.json",
    }
    context = validate_post_h3l_context(post_h3l_summary_path, output=artifacts["context_validation"])
    consumption = _write_authorization_consumption(
        context=context,
        post_h3l_summary_path=post_h3l_summary_path,
        output=artifacts["authorization_consumption"],
        operator_id=operator_id,
        operator_decision=operator_decision,
        audit_decision=audit_decision,
        operator_statement=operator_statement,
        ack_external_limited_release_execution=ack_external_limited_release_execution,
    )
    action = _write_release_action(
        context=context,
        consumption_path=artifacts["authorization_consumption"],
        output=artifacts["release_action"],
        release_action_kind=release_action_kind,
        external_participant_count=external_participant_count,
    )
    receipt = _write_execution_receipt(
        context=context,
        release_action_path=artifacts["release_action"],
        output=artifacts["execution_receipt"],
    )
    boundary = _write_boundary_report(
        context=context,
        execution_receipt_path=artifacts["execution_receipt"],
        output=artifacts["boundary_report"],
    )
    reports = [context, consumption, action, receipt, boundary]
    passed = all(report.get("passed") is True for report in reports)
    summary = {
        "schema_version": CHAIN_SCHEMA,
        "passed": passed,
        "failure_reasons": _failures(reports),
        "checked_at": _now(),
        "source_artifacts": {"post_h3l_summary": artifact_ref(post_h3l_summary_path)},
        "artifacts": {name: artifact_ref(path) for name, path in artifacts.items() if name != "summary"},
        "authorization_id": object_value(context.get("authorization_receipt")).get("authorization_id"),
        "release_action_id": action.get("release_action_id"),
        "execution_receipt_id": receipt.get("execution_receipt_id"),
        "readiness": {
            "state": "post_h3_external_limited_release_execution_complete" if passed else "blocked_post_h3_external_limited_release_execution",
            "external_limited_release_execution_complete": passed,
            "external_limited_release_performed": passed,
            "external_limited_release_ready": passed,
            "external_participant_count": external_participant_count if passed else 0,
            "public_ingress_authorized": False,
            "runtime_expansion_authorized": False,
            "production_runtime_receipt_write_allowed": False,
            "post_h3_external_release_closeout_ready": passed,
        },
        "boundary": _boundary(
            context_validation_written=context.get("passed") is True,
            authorization_consumed=consumption.get("passed") is True,
            external_limited_release_execution_authorized=consumption.get("passed") is True,
            release_action_written=action.get("passed") is True,
            execution_receipt_written=receipt.get("passed") is True,
            boundary_report_written=boundary.get("passed") is True,
            external_limited_release_performed=passed,
            external_limited_release_ready=passed,
        ),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(artifacts["summary"], summary)
    return summary


def validate_post_h3l_context(post_h3l_summary_path: Path, *, output: Path | None = None) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    try:
        summary = read_json_object(post_h3l_summary_path)
    except Exception as exc:  # noqa: BLE001
        return _write_optional(_report(CONTEXT_SCHEMA, False, [f"post_h3l_summary_unreadable:{exc}"], checks), output)

    artifacts = object_value(summary.get("artifacts"))
    receipt = _read_verified_ref(artifacts.get("authorization_receipt"), checks, failures, "post_h3l_authorization_receipt")
    boundary_report = _read_verified_ref(artifacts.get("boundary_report"), checks, failures, "post_h3l_boundary_report")
    _check_summary(summary, checks, failures)
    _check_authorization_receipt(summary, receipt, checks, failures)
    _check_boundary_report(boundary_report, checks, failures)
    passed = _passed(checks, failures)
    report = {
        "schema_version": CONTEXT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "post_h3l_summary": summary,
        "authorization_receipt": receipt,
        "boundary_report": boundary_report,
        "source_artifacts": {"post_h3l_summary": artifact_ref(post_h3l_summary_path)},
        "boundary": _boundary(context_validation_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    return _write_optional(report, output)


def _write_authorization_consumption(
    *,
    context: dict[str, Any],
    post_h3l_summary_path: Path,
    output: Path,
    operator_id: str,
    operator_decision: str,
    audit_decision: str,
    operator_statement: str,
    ack_external_limited_release_execution: bool,
) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    receipt = object_value(context.get("authorization_receipt"))
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "authorization_receipt_passed", receipt.get("passed") is True)
    check(checks, failures, "authorization_granted", receipt.get("authorization_granted") is True)
    check(checks, failures, "authorization_single_use", receipt.get("single_use") is True)
    check(checks, failures, "authorization_unconsumed", receipt.get("consumed") is False)
    check(checks, failures, "operator_id_present", bool(operator_id.strip()))
    check(checks, failures, "operator_decision_accepted", operator_decision == ACCEPTED_OPERATOR_DECISION)
    check(checks, failures, "audit_decision_accepted", audit_decision == ACCEPTED_AUDIT_DECISION)
    check(checks, failures, "operator_statement_present", bool(operator_statement.strip()))
    check(checks, failures, "explicit_operator_ack", ack_external_limited_release_execution is True)
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
        "ack_external_limited_release_execution": ack_external_limited_release_execution,
        "source_artifacts": {"post_h3l_summary": artifact_ref(post_h3l_summary_path)},
        "boundary": _boundary(
            authorization_consumed=passed,
            external_limited_release_execution_authorized=passed,
        ),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def _write_release_action(
    *,
    context: dict[str, Any],
    consumption_path: Path,
    output: Path,
    release_action_kind: str,
    external_participant_count: int,
) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    consumption = read_json_object(consumption_path)
    receipt = object_value(context.get("authorization_receipt"))
    scope = object_value(receipt.get("authorization_scope"))
    max_external_participants = int(scope.get("max_external_participants") or 0)
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "authorization_consumed", consumption.get("passed") is True)
    check(checks, failures, "authorization_id_bound", consumption.get("authorization_id") == receipt.get("authorization_id"))
    check(checks, failures, "release_action_kind_present", bool(release_action_kind.strip()))
    check(checks, failures, "external_participant_count_non_negative", external_participant_count >= 0)
    check(checks, failures, "external_participant_count_within_scope", external_participant_count <= max_external_participants)
    check(checks, failures, "public_ingress_not_authorized", scope.get("public_ingress_authorized") is False)
    check(checks, failures, "runtime_expansion_not_authorized", scope.get("runtime_expansion_authorized") is False)
    passed = _passed(checks, failures)
    action = {
        "schema_version": RELEASE_ACTION_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "executed_at": _now(),
        "release_action_id": f"post-h3m-release-action:{sha256_json([artifact_ref(consumption_path), release_action_kind, external_participant_count])[:24]}",
        "release_action_kind": release_action_kind,
        "external_participant_count": external_participant_count,
        "public_ingress_opened": False,
        "runtime_expansion_performed": False,
        "deployment_performed": False,
        "source_artifacts": {
            "authorization_consumption": artifact_ref(consumption_path),
            "post_h3l_authorization_receipt": object_value(context.get("post_h3l_summary")).get("artifacts", {}).get("authorization_receipt"),
        },
        "readiness": {
            "external_limited_release_action_complete": passed,
            "external_limited_release_performed": passed,
            "external_limited_release_ready": passed,
            "public_ingress_authorized": False,
            "runtime_expansion_authorized": False,
        },
        "boundary": _boundary(
            external_limited_release_execution_authorized=passed,
            release_action_written=passed,
            external_limited_release_performed=passed,
            external_limited_release_ready=passed,
        ),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, action)
    return action


def _write_execution_receipt(*, context: dict[str, Any], release_action_path: Path, output: Path) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    action = read_json_object(release_action_path)
    receipt = object_value(context.get("authorization_receipt"))
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "release_action_passed", action.get("passed") is True)
    check(checks, failures, "release_action_no_public_ingress", action.get("public_ingress_opened") is False)
    check(checks, failures, "release_action_no_runtime_expansion", action.get("runtime_expansion_performed") is False)
    passed = _passed(checks, failures)
    execution_receipt = {
        "schema_version": EXECUTION_RECEIPT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "written_at": _now(),
        "execution_receipt_id": f"post-h3m-execution-receipt:{sha256_json([artifact_ref(release_action_path), receipt.get('authorization_id')])[:24]}",
        "authorization_id": receipt.get("authorization_id"),
        "release_action_id": action.get("release_action_id"),
        "source_artifacts": {
            "release_action": artifact_ref(release_action_path),
            "post_h3l_authorization_receipt": object_value(context.get("post_h3l_summary")).get("artifacts", {}).get("authorization_receipt"),
        },
        "readiness": {
            "external_limited_release_execution_complete": passed,
            "external_limited_release_performed": passed,
            "external_limited_release_ready": passed,
            "public_ingress_authorized": False,
            "runtime_expansion_authorized": False,
        },
        "boundary": _boundary(
            external_limited_release_execution_authorized=passed,
            execution_receipt_written=passed,
            external_limited_release_performed=passed,
            external_limited_release_ready=passed,
        ),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, execution_receipt)
    return execution_receipt


def _write_boundary_report(*, context: dict[str, Any], execution_receipt_path: Path, output: Path) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    receipt = read_json_object(execution_receipt_path)
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "execution_receipt_passed", receipt.get("passed") is True)
    check(checks, failures, "execution_complete", object_value(receipt.get("readiness")).get("external_limited_release_execution_complete") is True)
    check(checks, failures, "public_ingress_not_authorized", object_value(receipt.get("readiness")).get("public_ingress_authorized") is False)
    check(checks, failures, "runtime_expansion_not_authorized", object_value(receipt.get("readiness")).get("runtime_expansion_authorized") is False)
    passed = _passed(checks, failures)
    report = {
        "schema_version": BOUNDARY_REPORT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "source_artifacts": {"execution_receipt": artifact_ref(execution_receipt_path)},
        "boundary": _boundary(
            external_limited_release_execution_authorized=passed,
            boundary_report_written=passed,
            external_limited_release_performed=passed,
            external_limited_release_ready=passed,
        ),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def _check_summary(summary: dict[str, Any], checks: dict[str, bool], failures: list[str]) -> None:
    readiness = object_value(summary.get("readiness"))
    boundary = object_value(summary.get("boundary"))
    check(checks, failures, "post_h3l_schema_valid", summary.get("schema_version") == POST_H3L_SCHEMA)
    check(checks, failures, "post_h3l_passed", summary.get("passed") is True)
    check(checks, failures, "authorization_granted", summary.get("authorization_granted") is True)
    check(checks, failures, "execution_authorized", readiness.get("external_limited_release_execution_authorized") is True)
    check(checks, failures, "execution_ready", readiness.get("external_limited_release_execution_ready") is True)
    check(checks, failures, "release_not_previously_ready", readiness.get("external_limited_release_ready") is False)
    check(checks, failures, "public_ingress_not_authorized", readiness.get("public_ingress_authorized") is False)
    check(checks, failures, "runtime_expansion_not_authorized", readiness.get("runtime_expansion_authorized") is False)
    check(checks, failures, "authorized_but_not_performed", boundary.get("external_limited_release_execution_authorized") is True and boundary.get("external_limited_release_performed") is False)
    for key in ("runtime_execution_performed", "vm_contact_performed", "deploy_performed", "external_public_ingress_opened", "production_data_accessed", "source_tree_write_performed", "git_write_performed"):
        check(checks, failures, f"no_{key}", boundary.get(key) is False)


def _check_authorization_receipt(summary: dict[str, Any], receipt: dict[str, Any], checks: dict[str, bool], failures: list[str]) -> None:
    check(checks, failures, "receipt_schema_valid", receipt.get("schema_version") == POST_H3L_AUTHORIZATION_RECEIPT_SCHEMA)
    check(checks, failures, "receipt_passed", receipt.get("passed") is True)
    check(checks, failures, "receipt_authorization_granted", receipt.get("authorization_granted") is True)
    check(checks, failures, "receipt_id_matches", receipt.get("authorization_id") == summary.get("authorization_id"))
    check(checks, failures, "receipt_single_use", receipt.get("single_use") is True)
    check(checks, failures, "receipt_unconsumed", receipt.get("consumed") is False)
    readiness = object_value(receipt.get("readiness"))
    check(checks, failures, "receipt_execution_authorized", readiness.get("external_limited_release_execution_authorized") is True)
    check(checks, failures, "receipt_release_not_ready", readiness.get("external_limited_release_ready") is False)
    check(checks, failures, "receipt_public_ingress_not_authorized", readiness.get("public_ingress_authorized") is False)


def _check_boundary_report(report: dict[str, Any], checks: dict[str, bool], failures: list[str]) -> None:
    check(checks, failures, "boundary_report_schema_valid", report.get("schema_version") == POST_H3L_BOUNDARY_REPORT_SCHEMA and report.get("passed") is True)
    boundary = object_value(report.get("boundary"))
    check(checks, failures, "boundary_no_performed_release", boundary.get("external_limited_release_performed") is False)
    check(checks, failures, "boundary_no_public_ingress", boundary.get("external_public_ingress_opened") is False)


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
        "release_action_written": False,
        "execution_receipt_written": False,
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
    parser = argparse.ArgumentParser(description="Run PostH3-M external limited release execution gate")
    parser.add_argument("--post-h3l-summary", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--operator-id", default="operator-primary")
    parser.add_argument("--operator-decision", default=ACCEPTED_OPERATOR_DECISION)
    parser.add_argument("--audit-decision", default=ACCEPTED_AUDIT_DECISION)
    parser.add_argument("--operator-statement", default="Execute the one-time controlled external limited release boundary action without public ingress or external users.")
    parser.add_argument("--release-action-kind", default="controlled_release_boundary_record")
    parser.add_argument("--external-participant-count", type=int, default=0)
    parser.add_argument("--ack-external-limited-release-execution", action="store_true")
    args = parser.parse_args()
    summary = run_gate(
        post_h3l_summary_path=args.post_h3l_summary,
        output_root=args.output_root,
        operator_id=args.operator_id,
        operator_decision=args.operator_decision,
        audit_decision=args.audit_decision,
        operator_statement=args.operator_statement,
        release_action_kind=args.release_action_kind,
        external_participant_count=args.external_participant_count,
        ack_external_limited_release_execution=args.ack_external_limited_release_execution,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if summary.get("passed") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
