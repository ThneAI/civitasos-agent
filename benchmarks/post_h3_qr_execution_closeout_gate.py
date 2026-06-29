"""Close out PostH3-Q/R separated execution receipts.

PostH3-S consumes the PostH3-Q public-ingress execution receipt and the
PostH3-R runtime-expansion execution receipt. It writes an auditable closeout
packet and boundary report for the separated execution gates. It does not allow
external users, reopen public ingress, restart runtime workers, execute tasks,
deploy, contact VMs, access production data, or write source/Git state.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from benchmarks.i_gate_evidence import artifact_ref, check, object_value, read_json_object, sha256_file, sha256_json, write_json_object
from benchmarks.post_h3_public_ingress_execution_gate import (
    BOUNDARY_REPORT_SCHEMA as POST_H3Q_BOUNDARY_REPORT_SCHEMA,
    CHAIN_SCHEMA as POST_H3Q_SCHEMA,
    EXECUTION_RECEIPT_SCHEMA as POST_H3Q_EXECUTION_RECEIPT_SCHEMA,
)
from benchmarks.post_h3_runtime_expansion_execution_gate import (
    BOUNDARY_REPORT_SCHEMA as POST_H3R_BOUNDARY_REPORT_SCHEMA,
    CHAIN_SCHEMA as POST_H3R_SCHEMA,
    EXECUTION_RECEIPT_SCHEMA as POST_H3R_EXECUTION_RECEIPT_SCHEMA,
)

CHAIN_SCHEMA = "post-h3-qr-execution-closeout-chain:v1"
CONTEXT_SCHEMA = "post-h3s-post-h3q-r-context-validation:v1"
CLOSEOUT_PACKET_SCHEMA = "post-h3s-qr-execution-closeout-packet:v1"
CLOSEOUT_RECONCILIATION_SCHEMA = "post-h3s-qr-execution-closeout-reconciliation:v1"
BOUNDARY_REPORT_SCHEMA = "post-h3s-qr-execution-closeout-boundary-report:v1"

ACCEPTED_OPERATOR_DECISION = "close_post_h3_qr_execution"
ACCEPTED_AUDIT_DECISION = "accept_post_h3_qr_execution_receipts"
ACCEPTED_MONITORING_DECISION = "accept_post_h3_qr_monitoring_evidence"
ACCEPTED_ROLLBACK_DECISION = "accept_no_rollback_needed_after_qr_shutdown"
NON_CLAIMS = (
    "post_h3s_closes_qr_execution_receipts_only",
    "post_h3s_does_not_allow_external_user_usage",
    "post_h3s_does_not_reopen_public_ingress",
    "post_h3s_does_not_restart_runtime_workers",
    "post_h3s_does_not_execute_runtime_task",
    "post_h3s_does_not_contact_vm_targets",
    "post_h3s_does_not_deploy",
    "post_h3s_does_not_access_production_data",
    "post_h3s_does_not_write_source_or_git",
)


def run_gate(
    *,
    post_h3q_summary_path: Path,
    post_h3r_summary_path: Path,
    output_root: Path,
    operator_id: str = "operator-primary",
    operator_decision: str = ACCEPTED_OPERATOR_DECISION,
    audit_decision: str = ACCEPTED_AUDIT_DECISION,
    monitoring_decision: str = ACCEPTED_MONITORING_DECISION,
    rollback_decision: str = ACCEPTED_ROLLBACK_DECISION,
    operator_statement: str = "Close PostH3-Q/R separated executions and prepare a separate external user usage review.",
    ack_qr_execution_closeout: bool = False,
) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "context_validation": output_root / "post_h3s_post_h3q_r_context_validation.json",
        "closeout_packet": output_root / "post_h3s_qr_execution_closeout_packet.json",
        "closeout_reconciliation": output_root / "post_h3s_qr_execution_closeout_reconciliation.json",
        "boundary_report": output_root / "post_h3s_qr_execution_closeout_boundary_report.json",
        "summary": output_root / "post_h3s_qr_execution_closeout_summary.json",
    }
    context = validate_post_h3q_r_context(post_h3q_summary_path, post_h3r_summary_path, output=artifacts["context_validation"])
    packet = _write_closeout_packet(
        context=context,
        post_h3q_summary_path=post_h3q_summary_path,
        post_h3r_summary_path=post_h3r_summary_path,
        output=artifacts["closeout_packet"],
    )
    reconciliation = _write_reconciliation(
        packet_path=artifacts["closeout_packet"],
        output=artifacts["closeout_reconciliation"],
        operator_id=operator_id,
        operator_decision=operator_decision,
        audit_decision=audit_decision,
        monitoring_decision=monitoring_decision,
        rollback_decision=rollback_decision,
        operator_statement=operator_statement,
        ack_qr_execution_closeout=ack_qr_execution_closeout,
    )
    boundary = _write_boundary_report(context=context, reconciliation_path=artifacts["closeout_reconciliation"], output=artifacts["boundary_report"])
    reports = [context, packet, reconciliation, boundary]
    passed = all(report.get("passed") is True for report in reports)
    summary = {
        "schema_version": CHAIN_SCHEMA,
        "passed": passed,
        "failure_reasons": _failures(reports),
        "checked_at": _now(),
        "source_artifacts": {
            "post_h3q_summary": artifact_ref(post_h3q_summary_path),
            "post_h3r_summary": artifact_ref(post_h3r_summary_path),
        },
        "artifacts": {name: artifact_ref(path) for name, path in artifacts.items() if name != "summary"},
        "qr_closeout_id": reconciliation.get("qr_closeout_id"),
        "post_h3q_execution_receipt_id": object_value(context.get("post_h3q_execution_receipt")).get("execution_receipt_id"),
        "post_h3r_execution_receipt_id": object_value(context.get("post_h3r_execution_receipt")).get("execution_receipt_id"),
        "readiness": {
            "state": "post_h3_qr_execution_closed" if passed else "blocked_post_h3_qr_execution_closeout",
            "post_h3_qr_execution_closeout_complete": passed,
            "public_ingress_execution_closed": passed,
            "runtime_expansion_execution_closed": passed,
            "external_user_usage_review_ready": passed,
            "external_user_usage_allowed": False,
            "external_public_ingress_currently_open": False,
            "runtime_workers_currently_running": False,
            "runtime_execution_performed": False,
            "production_runtime_receipt_write_allowed": False,
        },
        "boundary": _boundary(
            context_validation_written=context.get("passed") is True,
            closeout_packet_written=packet.get("passed") is True,
            closeout_reconciliation_written=reconciliation.get("passed") is True,
            boundary_report_written=boundary.get("passed") is True,
            post_h3_qr_execution_closeout_complete=passed,
            external_user_usage_review_ready=passed,
            external_public_ingress_previously_opened=passed,
            external_public_ingress_currently_open=False,
            runtime_expansion_previously_performed=passed,
            runtime_workers_currently_running=False,
        ),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(artifacts["summary"], summary)
    return summary


def validate_post_h3q_r_context(post_h3q_summary_path: Path, post_h3r_summary_path: Path, *, output: Path | None = None) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    try:
        q_summary = read_json_object(post_h3q_summary_path)
        r_summary = read_json_object(post_h3r_summary_path)
    except Exception as exc:  # noqa: BLE001
        return _write_optional(_report(CONTEXT_SCHEMA, False, [f"post_h3q_r_summary_unreadable:{exc}"], checks), output)
    q_artifacts = object_value(q_summary.get("artifacts"))
    r_artifacts = object_value(r_summary.get("artifacts"))
    q_receipt = _read_verified_ref(q_artifacts.get("execution_receipt"), checks, failures, "post_h3q_execution_receipt")
    q_boundary = _read_verified_ref(q_artifacts.get("boundary_report"), checks, failures, "post_h3q_boundary_report")
    r_receipt = _read_verified_ref(r_artifacts.get("execution_receipt"), checks, failures, "post_h3r_execution_receipt")
    r_boundary = _read_verified_ref(r_artifacts.get("boundary_report"), checks, failures, "post_h3r_boundary_report")
    _check_q_summary(q_summary, checks, failures)
    _check_q_receipt(q_summary, q_receipt, checks, failures)
    _check_q_boundary(q_boundary, checks, failures)
    _check_r_summary(r_summary, checks, failures)
    _check_r_receipt(r_summary, r_receipt, checks, failures)
    _check_r_boundary(r_boundary, checks, failures)
    passed = _passed(checks, failures)
    report = {
        "schema_version": CONTEXT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "post_h3q_summary": q_summary,
        "post_h3q_execution_receipt": q_receipt,
        "post_h3q_boundary_report": q_boundary,
        "post_h3r_summary": r_summary,
        "post_h3r_execution_receipt": r_receipt,
        "post_h3r_boundary_report": r_boundary,
        "source_artifacts": {
            "post_h3q_summary": artifact_ref(post_h3q_summary_path),
            "post_h3r_summary": artifact_ref(post_h3r_summary_path),
        },
        "boundary": _boundary(context_validation_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    return _write_optional(report, output)


def _write_closeout_packet(*, context: dict[str, Any], post_h3q_summary_path: Path, post_h3r_summary_path: Path, output: Path) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    check(checks, failures, "context_passed", context.get("passed") is True)
    q_summary = object_value(context.get("post_h3q_summary"))
    r_summary = object_value(context.get("post_h3r_summary"))
    q_ready = object_value(q_summary.get("readiness"))
    r_ready = object_value(r_summary.get("readiness"))
    check(checks, failures, "q_ingress_closed", q_ready.get("external_public_ingress_closed") is True)
    check(checks, failures, "r_workers_stopped", r_ready.get("runtime_workers_stopped") is True)
    check(checks, failures, "q_runtime_not_executed", q_ready.get("runtime_execution_performed") is False)
    check(checks, failures, "r_runtime_not_executed", r_ready.get("runtime_execution_performed") is False)
    passed = _passed(checks, failures)
    packet = {
        "schema_version": CLOSEOUT_PACKET_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "written_at": _now(),
        "closeout_packet_id": f"post-h3s-closeout-packet:{sha256_json([artifact_ref(post_h3q_summary_path), artifact_ref(post_h3r_summary_path)])[:24]}",
        "execution_receipts": {
            "post_h3q_execution_receipt_id": object_value(context.get("post_h3q_execution_receipt")).get("execution_receipt_id"),
            "post_h3r_execution_receipt_id": object_value(context.get("post_h3r_execution_receipt")).get("execution_receipt_id"),
        },
        "closeout_scope": {
            "close_qr_execution_receipts": True,
            "prepare_external_user_usage_review": True,
            "allow_external_user_usage": False,
            "reopen_public_ingress": False,
            "restart_runtime_workers": False,
            "execute_runtime_task": False,
        },
        "source_artifacts": {
            "post_h3q_summary": artifact_ref(post_h3q_summary_path),
            "post_h3r_summary": artifact_ref(post_h3r_summary_path),
        },
        "readiness": {
            "closeout_packet_ready": passed,
            "external_user_usage_review_ready": passed,
            "external_user_usage_allowed": False,
            "external_public_ingress_currently_open": False,
            "runtime_workers_currently_running": False,
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
    ack_qr_execution_closeout: bool,
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
    check(checks, failures, "explicit_operator_ack", ack_qr_execution_closeout is True)
    passed = _passed(checks, failures)
    reconciliation = {
        "schema_version": CLOSEOUT_RECONCILIATION_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "closed_at": _now(),
        "qr_closeout_id": f"post-h3s-qr-closeout:{sha256_json([artifact_ref(packet_path), operator_id, operator_decision, audit_decision, monitoring_decision, rollback_decision])[:24]}",
        "operator_id": operator_id,
        "operator_decision": operator_decision,
        "audit_decision": audit_decision,
        "monitoring_decision": monitoring_decision,
        "rollback_decision": rollback_decision,
        "operator_statement": operator_statement,
        "operator_statement_sha256": sha256_json(operator_statement),
        "ack_qr_execution_closeout": ack_qr_execution_closeout,
        "source_artifacts": {"closeout_packet": artifact_ref(packet_path)},
        "readiness": {
            "post_h3_qr_execution_closeout_complete": passed,
            "external_user_usage_review_ready": passed,
            "external_user_usage_allowed": False,
            "external_public_ingress_currently_open": False,
            "runtime_workers_currently_running": False,
        },
        "boundary": _boundary(closeout_reconciliation_written=passed, post_h3_qr_execution_closeout_complete=passed, external_user_usage_review_ready=passed),
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
    ready = object_value(reconciliation.get("readiness"))
    check(checks, failures, "external_user_usage_not_allowed", ready.get("external_user_usage_allowed") is False)
    check(checks, failures, "public_ingress_currently_closed", ready.get("external_public_ingress_currently_open") is False)
    check(checks, failures, "runtime_workers_currently_stopped", ready.get("runtime_workers_currently_running") is False)
    passed = _passed(checks, failures)
    report = {
        "schema_version": BOUNDARY_REPORT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "source_artifacts": {"closeout_reconciliation": artifact_ref(reconciliation_path)},
        "boundary": _boundary(
            boundary_report_written=passed,
            post_h3_qr_execution_closeout_complete=passed,
            external_user_usage_review_ready=passed,
            external_public_ingress_previously_opened=passed,
            external_public_ingress_currently_open=False,
            runtime_expansion_previously_performed=passed,
            runtime_workers_currently_running=False,
        ),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def _check_q_summary(summary: dict[str, Any], checks: dict[str, bool], failures: list[str]) -> None:
    readiness = object_value(summary.get("readiness"))
    boundary = object_value(summary.get("boundary"))
    check(checks, failures, "q_schema_valid", summary.get("schema_version") == POST_H3Q_SCHEMA)
    check(checks, failures, "q_passed", summary.get("passed") is True)
    check(checks, failures, "q_ingress_execution_complete", readiness.get("public_ingress_execution_complete") is True)
    check(checks, failures, "q_authorization_consumed", readiness.get("public_ingress_authorization_consumed") is True)
    check(checks, failures, "q_ingress_opened", readiness.get("external_public_ingress_opened") is True)
    check(checks, failures, "q_ingress_closed", readiness.get("external_public_ingress_closed") is True)
    check(checks, failures, "q_runtime_not_executed", readiness.get("runtime_execution_performed") is False)
    check(checks, failures, "q_runtime_expansion_not_authorized", readiness.get("runtime_expansion_authorized") is False)
    check(checks, failures, "q_boundary_ingress_closed", boundary.get("external_public_ingress_closed") is True)
    _check_no_side_effect_boundary("q", boundary, checks, failures)


def _check_q_receipt(summary: dict[str, Any], receipt: dict[str, Any], checks: dict[str, bool], failures: list[str]) -> None:
    readiness = object_value(receipt.get("readiness"))
    check(checks, failures, "q_receipt_schema_valid", receipt.get("schema_version") == POST_H3Q_EXECUTION_RECEIPT_SCHEMA)
    check(checks, failures, "q_receipt_passed", receipt.get("passed") is True)
    check(checks, failures, "q_receipt_id_matches", receipt.get("execution_receipt_id") == summary.get("execution_receipt_id"))
    check(checks, failures, "q_receipt_ingress_closed", readiness.get("external_public_ingress_closed") is True)
    check(checks, failures, "q_receipt_runtime_not_executed", readiness.get("runtime_execution_performed") is False)


def _check_q_boundary(report: dict[str, Any], checks: dict[str, bool], failures: list[str]) -> None:
    check(checks, failures, "q_boundary_schema_valid", report.get("schema_version") == POST_H3Q_BOUNDARY_REPORT_SCHEMA and report.get("passed") is True)
    boundary = object_value(report.get("boundary"))
    check(checks, failures, "q_boundary_report_ingress_closed", boundary.get("external_public_ingress_closed") is True)
    _check_no_side_effect_boundary("q_boundary", boundary, checks, failures)


def _check_r_summary(summary: dict[str, Any], checks: dict[str, bool], failures: list[str]) -> None:
    readiness = object_value(summary.get("readiness"))
    boundary = object_value(summary.get("boundary"))
    check(checks, failures, "r_schema_valid", summary.get("schema_version") == POST_H3R_SCHEMA)
    check(checks, failures, "r_passed", summary.get("passed") is True)
    check(checks, failures, "r_expansion_execution_complete", readiness.get("runtime_expansion_execution_complete") is True)
    check(checks, failures, "r_authorization_consumed", readiness.get("runtime_expansion_authorization_consumed") is True)
    check(checks, failures, "r_expansion_performed", readiness.get("runtime_expansion_performed") is True)
    check(checks, failures, "r_workers_started", readiness.get("runtime_workers_started") is True)
    check(checks, failures, "r_workers_stopped", readiness.get("runtime_workers_stopped") is True)
    check(checks, failures, "r_runtime_not_executed", readiness.get("runtime_execution_performed") is False)
    check(checks, failures, "r_public_ingress_not_opened", readiness.get("external_public_ingress_opened") is False)
    check(checks, failures, "r_boundary_workers_stopped", boundary.get("runtime_workers_stopped") is True)
    _check_no_side_effect_boundary("r", boundary, checks, failures)


def _check_r_receipt(summary: dict[str, Any], receipt: dict[str, Any], checks: dict[str, bool], failures: list[str]) -> None:
    readiness = object_value(receipt.get("readiness"))
    check(checks, failures, "r_receipt_schema_valid", receipt.get("schema_version") == POST_H3R_EXECUTION_RECEIPT_SCHEMA)
    check(checks, failures, "r_receipt_passed", receipt.get("passed") is True)
    check(checks, failures, "r_receipt_id_matches", receipt.get("execution_receipt_id") == summary.get("execution_receipt_id"))
    check(checks, failures, "r_receipt_workers_stopped", readiness.get("runtime_workers_stopped") is True)
    check(checks, failures, "r_receipt_runtime_not_executed", readiness.get("runtime_execution_performed") is False)


def _check_r_boundary(report: dict[str, Any], checks: dict[str, bool], failures: list[str]) -> None:
    check(checks, failures, "r_boundary_schema_valid", report.get("schema_version") == POST_H3R_BOUNDARY_REPORT_SCHEMA and report.get("passed") is True)
    boundary = object_value(report.get("boundary"))
    check(checks, failures, "r_boundary_report_workers_stopped", boundary.get("runtime_workers_stopped") is True)
    _check_no_side_effect_boundary("r_boundary", boundary, checks, failures)


def _check_no_side_effect_boundary(prefix: str, boundary: dict[str, Any], checks: dict[str, bool], failures: list[str]) -> None:
    for key in ("runtime_execution_performed", "vm_contact_performed", "deploy_performed", "production_data_accessed", "source_tree_write_performed", "git_write_performed"):
        check(checks, failures, f"{prefix}_no_{key}", boundary.get(key) is False)


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
        "post_h3_qr_execution_closeout_complete": False,
        "external_user_usage_review_ready": False,
        "external_user_usage_allowed": False,
        "external_public_ingress_previously_opened": False,
        "external_public_ingress_currently_open": False,
        "runtime_expansion_previously_performed": False,
        "runtime_workers_currently_running": False,
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
    parser = argparse.ArgumentParser(description="Run PostH3-S Q/R execution closeout gate")
    parser.add_argument("--post-h3q-summary", required=True, type=Path)
    parser.add_argument("--post-h3r-summary", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--operator-id", default="operator-primary")
    parser.add_argument("--operator-decision", default=ACCEPTED_OPERATOR_DECISION)
    parser.add_argument("--audit-decision", default=ACCEPTED_AUDIT_DECISION)
    parser.add_argument("--monitoring-decision", default=ACCEPTED_MONITORING_DECISION)
    parser.add_argument("--rollback-decision", default=ACCEPTED_ROLLBACK_DECISION)
    parser.add_argument("--operator-statement", default="Close PostH3-Q/R separated executions and prepare a separate external user usage review.")
    parser.add_argument("--ack-qr-execution-closeout", action="store_true")
    args = parser.parse_args()
    summary = run_gate(
        post_h3q_summary_path=args.post_h3q_summary,
        post_h3r_summary_path=args.post_h3r_summary,
        output_root=args.output_root,
        operator_id=args.operator_id,
        operator_decision=args.operator_decision,
        audit_decision=args.audit_decision,
        monitoring_decision=args.monitoring_decision,
        rollback_decision=args.rollback_decision,
        operator_statement=args.operator_statement,
        ack_qr_execution_closeout=args.ack_qr_execution_closeout,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if summary.get("passed") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
