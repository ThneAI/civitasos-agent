"""Close out the PostH3 controlled external limited release boundary action.

PostH3-N consumes PostH3-M's execution receipt and records release closeout. It
prepares independent public-ingress and runtime-expansion authorization gates, but
it does not open public ingress, expand runtime execution, deploy, contact VMs,
access production data, or write source/Git.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from benchmarks.i_gate_evidence import artifact_ref, check, object_value, read_json_object, sha256_file, sha256_json, write_json_object
from benchmarks.post_h3_external_limited_release_execution_gate import (
    BOUNDARY_REPORT_SCHEMA as POST_H3M_BOUNDARY_REPORT_SCHEMA,
    CHAIN_SCHEMA as POST_H3M_SCHEMA,
    EXECUTION_RECEIPT_SCHEMA as POST_H3M_EXECUTION_RECEIPT_SCHEMA,
)

CHAIN_SCHEMA = "post-h3-external-release-closeout-chain:v1"
CONTEXT_SCHEMA = "post-h3n-post-h3m-context-validation:v1"
CLOSEOUT_PACKET_SCHEMA = "post-h3n-external-release-closeout-packet:v1"
CLOSEOUT_RECONCILIATION_SCHEMA = "post-h3n-external-release-closeout-reconciliation:v1"
BOUNDARY_REPORT_SCHEMA = "post-h3n-external-release-closeout-boundary-report:v1"

ACCEPTED_OPERATOR_DECISION = "close_post_h3_external_limited_release"
ACCEPTED_AUDIT_DECISION = "accept_post_h3m_execution_boundary"
ACCEPTED_MONITORING_DECISION = "accept_post_h3m_monitoring_evidence"
ACCEPTED_ROLLBACK_DECISION = "accept_no_rollback_needed_for_boundary_action"
NON_CLAIMS = (
    "post_h3n_closes_release_boundary_action_only",
    "post_h3n_does_not_open_public_ingress",
    "post_h3n_does_not_expand_runtime_execution",
    "post_h3n_does_not_execute_runtime",
    "post_h3n_does_not_contact_vm_targets",
    "post_h3n_does_not_deploy",
    "post_h3n_does_not_access_production_data",
    "post_h3n_does_not_write_source_or_git",
)


def run_gate(
    *,
    post_h3m_summary_path: Path,
    output_root: Path,
    operator_id: str = "operator-primary",
    operator_decision: str = ACCEPTED_OPERATOR_DECISION,
    audit_decision: str = ACCEPTED_AUDIT_DECISION,
    monitoring_decision: str = ACCEPTED_MONITORING_DECISION,
    rollback_decision: str = ACCEPTED_ROLLBACK_DECISION,
    operator_statement: str = "Close the controlled external limited release boundary action and prepare independent public ingress and runtime expansion authorization gates.",
    ack_external_release_closeout: bool = False,
) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "context_validation": output_root / "post_h3n_post_h3m_context_validation.json",
        "closeout_packet": output_root / "post_h3n_external_release_closeout_packet.json",
        "closeout_reconciliation": output_root / "post_h3n_external_release_closeout_reconciliation.json",
        "boundary_report": output_root / "post_h3n_external_release_closeout_boundary_report.json",
        "summary": output_root / "post_h3n_external_release_closeout_summary.json",
    }
    context = validate_post_h3m_context(post_h3m_summary_path, output=artifacts["context_validation"])
    packet = _write_closeout_packet(context=context, post_h3m_summary_path=post_h3m_summary_path, output=artifacts["closeout_packet"])
    reconciliation = _write_reconciliation(
        packet_path=artifacts["closeout_packet"],
        output=artifacts["closeout_reconciliation"],
        operator_id=operator_id,
        operator_decision=operator_decision,
        audit_decision=audit_decision,
        monitoring_decision=monitoring_decision,
        rollback_decision=rollback_decision,
        operator_statement=operator_statement,
        ack_external_release_closeout=ack_external_release_closeout,
    )
    boundary = _write_boundary_report(context=context, reconciliation_path=artifacts["closeout_reconciliation"], output=artifacts["boundary_report"])
    reports = [context, packet, reconciliation, boundary]
    passed = all(report.get("passed") is True for report in reports)
    summary = {
        "schema_version": CHAIN_SCHEMA,
        "passed": passed,
        "failure_reasons": _failures(reports),
        "checked_at": _now(),
        "source_artifacts": {"post_h3m_summary": artifact_ref(post_h3m_summary_path)},
        "artifacts": {name: artifact_ref(path) for name, path in artifacts.items() if name != "summary"},
        "release_closeout_id": reconciliation.get("release_closeout_id"),
        "post_h3m_execution_receipt_id": object_value(context.get("execution_receipt")).get("execution_receipt_id"),
        "readiness": {
            "state": "post_h3_external_release_closed" if passed else "blocked_post_h3_external_release_closeout",
            "external_release_closeout_complete": passed,
            "external_limited_release_closed": passed,
            "public_ingress_authorization_ready": passed,
            "runtime_expansion_authorization_ready": passed,
            "public_ingress_authorized": False,
            "runtime_expansion_authorized": False,
            "production_runtime_receipt_write_allowed": False,
        },
        "boundary": _boundary(
            context_validation_written=context.get("passed") is True,
            closeout_packet_written=packet.get("passed") is True,
            closeout_reconciliation_written=reconciliation.get("passed") is True,
            boundary_report_written=boundary.get("passed") is True,
            external_release_closeout_complete=passed,
            public_ingress_authorization_ready=passed,
            runtime_expansion_authorization_ready=passed,
        ),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(artifacts["summary"], summary)
    return summary


def validate_post_h3m_context(post_h3m_summary_path: Path, *, output: Path | None = None) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    try:
        summary = read_json_object(post_h3m_summary_path)
    except Exception as exc:  # noqa: BLE001
        return _write_optional(_report(CONTEXT_SCHEMA, False, [f"post_h3m_summary_unreadable:{exc}"], checks), output)
    artifacts = object_value(summary.get("artifacts"))
    execution_receipt = _read_verified_ref(artifacts.get("execution_receipt"), checks, failures, "post_h3m_execution_receipt")
    boundary_report = _read_verified_ref(artifacts.get("boundary_report"), checks, failures, "post_h3m_boundary_report")
    _check_summary(summary, checks, failures)
    _check_execution_receipt(summary, execution_receipt, checks, failures)
    _check_boundary_report(boundary_report, checks, failures)
    passed = _passed(checks, failures)
    report = {
        "schema_version": CONTEXT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "post_h3m_summary": summary,
        "execution_receipt": execution_receipt,
        "boundary_report": boundary_report,
        "source_artifacts": {"post_h3m_summary": artifact_ref(post_h3m_summary_path)},
        "boundary": _boundary(context_validation_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    return _write_optional(report, output)


def _write_closeout_packet(*, context: dict[str, Any], post_h3m_summary_path: Path, output: Path) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    summary = object_value(context.get("post_h3m_summary"))
    readiness = object_value(summary.get("readiness"))
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "m_execution_complete", readiness.get("external_limited_release_execution_complete") is True)
    check(checks, failures, "m_release_performed", readiness.get("external_limited_release_performed") is True)
    check(checks, failures, "m_closeout_ready", readiness.get("post_h3_external_release_closeout_ready") is True)
    passed = _passed(checks, failures)
    packet = {
        "schema_version": CLOSEOUT_PACKET_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "written_at": _now(),
        "closeout_packet_id": f"post-h3n-closeout-packet:{sha256_json([artifact_ref(post_h3m_summary_path), summary.get('execution_receipt_id')])[:24]}",
        "post_h3m_execution_receipt_id": summary.get("execution_receipt_id"),
        "closeout_scope": {
            "close_external_limited_release_boundary_action": True,
            "prepare_public_ingress_authorization": True,
            "prepare_runtime_expansion_authorization": True,
            "authorize_public_ingress": False,
            "authorize_runtime_expansion": False,
        },
        "source_artifacts": {"post_h3m_summary": artifact_ref(post_h3m_summary_path)},
        "readiness": {
            "closeout_packet_ready": passed,
            "public_ingress_authorization_ready": passed,
            "runtime_expansion_authorization_ready": passed,
            "public_ingress_authorized": False,
            "runtime_expansion_authorized": False,
        },
        "boundary": _boundary(closeout_packet_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, packet)
    return packet


def _write_reconciliation(
    *,
    packet_path: Path,
    output: Path,
    operator_id: str,
    operator_decision: str,
    audit_decision: str,
    monitoring_decision: str,
    rollback_decision: str,
    operator_statement: str,
    ack_external_release_closeout: bool,
) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    packet = read_json_object(packet_path)
    check(checks, failures, "packet_passed", packet.get("schema_version") == CLOSEOUT_PACKET_SCHEMA and packet.get("passed") is True)
    check(checks, failures, "operator_id_present", bool(operator_id.strip()))
    check(checks, failures, "operator_decision_accepted", operator_decision == ACCEPTED_OPERATOR_DECISION)
    check(checks, failures, "audit_decision_accepted", audit_decision == ACCEPTED_AUDIT_DECISION)
    check(checks, failures, "monitoring_decision_accepted", monitoring_decision == ACCEPTED_MONITORING_DECISION)
    check(checks, failures, "rollback_decision_accepted", rollback_decision == ACCEPTED_ROLLBACK_DECISION)
    check(checks, failures, "operator_statement_present", bool(operator_statement.strip()))
    check(checks, failures, "explicit_operator_ack", ack_external_release_closeout is True)
    passed = _passed(checks, failures)
    reconciliation = {
        "schema_version": CLOSEOUT_RECONCILIATION_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "closed_at": _now(),
        "release_closeout_id": f"post-h3n-closeout:{sha256_json([artifact_ref(packet_path), operator_id, operator_decision, audit_decision, monitoring_decision, rollback_decision])[:24]}",
        "operator_id": operator_id,
        "operator_decision": operator_decision,
        "audit_decision": audit_decision,
        "monitoring_decision": monitoring_decision,
        "rollback_decision": rollback_decision,
        "operator_statement": operator_statement,
        "operator_statement_sha256": sha256_json(operator_statement),
        "ack_external_release_closeout": ack_external_release_closeout,
        "source_artifacts": {"closeout_packet": artifact_ref(packet_path)},
        "readiness": {
            "external_release_closeout_complete": passed,
            "public_ingress_authorization_ready": passed,
            "runtime_expansion_authorization_ready": passed,
            "public_ingress_authorized": False,
            "runtime_expansion_authorized": False,
        },
        "boundary": _boundary(closeout_reconciliation_written=passed, external_release_closeout_complete=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, reconciliation)
    return reconciliation


def _write_boundary_report(*, context: dict[str, Any], reconciliation_path: Path, output: Path) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    reconciliation = read_json_object(reconciliation_path)
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "reconciliation_passed", reconciliation.get("passed") is True)
    check(checks, failures, "public_ingress_not_authorized", object_value(reconciliation.get("readiness")).get("public_ingress_authorized") is False)
    check(checks, failures, "runtime_expansion_not_authorized", object_value(reconciliation.get("readiness")).get("runtime_expansion_authorized") is False)
    passed = _passed(checks, failures)
    report = {
        "schema_version": BOUNDARY_REPORT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "source_artifacts": {"closeout_reconciliation": artifact_ref(reconciliation_path)},
        "boundary": _boundary(boundary_report_written=passed, external_release_closeout_complete=passed, public_ingress_authorization_ready=passed, runtime_expansion_authorization_ready=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def _check_summary(summary: dict[str, Any], checks: dict[str, bool], failures: list[str]) -> None:
    readiness = object_value(summary.get("readiness"))
    boundary = object_value(summary.get("boundary"))
    check(checks, failures, "post_h3m_schema_valid", summary.get("schema_version") == POST_H3M_SCHEMA)
    check(checks, failures, "post_h3m_passed", summary.get("passed") is True)
    check(checks, failures, "m_execution_complete", readiness.get("external_limited_release_execution_complete") is True)
    check(checks, failures, "m_release_performed", readiness.get("external_limited_release_performed") is True)
    check(checks, failures, "m_release_ready", readiness.get("external_limited_release_ready") is True)
    check(checks, failures, "m_external_participant_count_zero", readiness.get("external_participant_count") == 0)
    check(checks, failures, "m_public_ingress_not_authorized", readiness.get("public_ingress_authorized") is False)
    check(checks, failures, "m_runtime_expansion_not_authorized", readiness.get("runtime_expansion_authorized") is False)
    check(checks, failures, "m_boundary_release_performed", boundary.get("external_limited_release_performed") is True)
    for key in ("external_public_ingress_opened", "runtime_execution_performed", "vm_contact_performed", "deploy_performed", "production_data_accessed", "source_tree_write_performed", "git_write_performed"):
        check(checks, failures, f"no_{key}", boundary.get(key) is False)


def _check_execution_receipt(summary: dict[str, Any], receipt: dict[str, Any], checks: dict[str, bool], failures: list[str]) -> None:
    readiness = object_value(receipt.get("readiness"))
    check(checks, failures, "receipt_schema_valid", receipt.get("schema_version") == POST_H3M_EXECUTION_RECEIPT_SCHEMA)
    check(checks, failures, "receipt_passed", receipt.get("passed") is True)
    check(checks, failures, "receipt_id_matches", receipt.get("execution_receipt_id") == summary.get("execution_receipt_id"))
    check(checks, failures, "receipt_execution_complete", readiness.get("external_limited_release_execution_complete") is True)
    check(checks, failures, "receipt_public_ingress_not_authorized", readiness.get("public_ingress_authorized") is False)
    check(checks, failures, "receipt_runtime_expansion_not_authorized", readiness.get("runtime_expansion_authorized") is False)


def _check_boundary_report(report: dict[str, Any], checks: dict[str, bool], failures: list[str]) -> None:
    check(checks, failures, "boundary_report_schema_valid", report.get("schema_version") == POST_H3M_BOUNDARY_REPORT_SCHEMA and report.get("passed") is True)
    boundary = object_value(report.get("boundary"))
    check(checks, failures, "boundary_release_performed", boundary.get("external_limited_release_performed") is True)
    check(checks, failures, "boundary_no_public_ingress", boundary.get("external_public_ingress_opened") is False)
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
        "closeout_packet_written": False,
        "closeout_reconciliation_written": False,
        "boundary_report_written": False,
        "external_release_closeout_complete": False,
        "public_ingress_authorization_ready": False,
        "runtime_expansion_authorization_ready": False,
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
    parser = argparse.ArgumentParser(description="Run PostH3-N external release closeout gate")
    parser.add_argument("--post-h3m-summary", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--operator-id", default="operator-primary")
    parser.add_argument("--operator-decision", default=ACCEPTED_OPERATOR_DECISION)
    parser.add_argument("--audit-decision", default=ACCEPTED_AUDIT_DECISION)
    parser.add_argument("--monitoring-decision", default=ACCEPTED_MONITORING_DECISION)
    parser.add_argument("--rollback-decision", default=ACCEPTED_ROLLBACK_DECISION)
    parser.add_argument("--operator-statement", default="Close the controlled external limited release boundary action and prepare independent public ingress and runtime expansion authorization gates.")
    parser.add_argument("--ack-external-release-closeout", action="store_true")
    args = parser.parse_args()
    summary = run_gate(
        post_h3m_summary_path=args.post_h3m_summary,
        output_root=args.output_root,
        operator_id=args.operator_id,
        operator_decision=args.operator_decision,
        audit_decision=args.audit_decision,
        monitoring_decision=args.monitoring_decision,
        rollback_decision=args.rollback_decision,
        operator_statement=args.operator_statement,
        ack_external_release_closeout=args.ack_external_release_closeout,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if summary.get("passed") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
