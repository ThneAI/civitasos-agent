"""Review the minimal PostH3 production task path for reuse.

This gate consumes a passed minimal production task execution summary and decides
whether the read-only status/evidence-index task chain is stable enough to be a
reusable minimal production path. It does not authorize another execution, open
public ingress, expand runtime, write production runtime receipts, deploy, or
touch source/Git.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from benchmarks.i_gate_evidence import artifact_ref, check, object_value, read_json_object, sha256_file, sha256_json, write_json_object
from benchmarks.post_h3_minimal_production_task_execution_gate import (
    CHAIN_SCHEMA as EXECUTION_CHAIN_SCHEMA,
    CLOSEOUT_RECEIPT_SCHEMA,
    EXECUTION_RECEIPT_SCHEMA,
    MONITORING_RECEIPT_SCHEMA,
    ROLLBACK_ABORT_RECEIPT_SCHEMA,
    STATUS_EVIDENCE_INDEX_SCHEMA,
)

CHAIN_SCHEMA = "post-h3-minimal-production-task-strategy-review-chain:v1"
CONTEXT_SCHEMA = "post-h3-minimal-production-task-strategy-context-validation:v1"
STRATEGY_PACKET_SCHEMA = "post-h3-minimal-production-task-strategy-packet:v1"
STRATEGY_RECONCILIATION_SCHEMA = "post-h3-minimal-production-task-strategy-reconciliation:v1"
BOUNDARY_REPORT_SCHEMA = "post-h3-minimal-production-task-strategy-boundary-report:v1"

ACCEPT_REUSABLE_PATH_DECISION = "accept_reusable_minimal_production_task_path"
REQUEST_MORE_EVIDENCE_DECISION = "request_more_minimal_production_task_evidence"
REJECT_REUSABLE_PATH_DECISION = "reject_reusable_path_due_to_boundary_or_integrity_failure"
ALLOWED_OPERATOR_DECISIONS = {
    ACCEPT_REUSABLE_PATH_DECISION,
    REQUEST_MORE_EVIDENCE_DECISION,
    REJECT_REUSABLE_PATH_DECISION,
}
ACCEPTED_AUDIT_DECISION = "accept_minimal_task_strategy_no_production_boundary"
ACCEPTED_MONITORING_DECISION = "accept_minimal_task_strategy_monitoring_sufficient"
ACCEPTED_ROLLBACK_DECISION = "accept_minimal_task_strategy_rollback_abort_sufficient"

NON_CLAIMS = (
    "minimal_production_task_strategy_review_is_artifact_review_only",
    "minimal_production_task_strategy_review_does_not_authorize_next_execution",
    "minimal_production_task_strategy_review_does_not_start_runtime_workers",
    "minimal_production_task_strategy_review_does_not_mutate_backend_task_pool",
    "minimal_production_task_strategy_review_does_not_open_public_ingress",
    "minimal_production_task_strategy_review_does_not_deploy",
    "minimal_production_task_strategy_review_does_not_access_production_data",
    "minimal_production_task_strategy_review_does_not_write_production_runtime_receipts",
    "minimal_production_task_strategy_review_does_not_write_source_or_git",
)


def run_gate(
    *,
    execution_summary_path: Path,
    output_root: Path,
    operator_id: str = "operator-primary",
    operator_decision: str = ACCEPT_REUSABLE_PATH_DECISION,
    audit_decision: str = ACCEPTED_AUDIT_DECISION,
    monitoring_decision: str = ACCEPTED_MONITORING_DECISION,
    rollback_decision: str = ACCEPTED_ROLLBACK_DECISION,
    operator_statement: str = "Accept the read-only minimal production task path as reusable; every future execution still requires a fresh single-use authorization.",
    min_evidence_refs: int = 9,
    ack_strategy_review: bool = False,
) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "context_validation": output_root / "post_h3_minimal_task_strategy_context_validation.json",
        "strategy_packet": output_root / "post_h3_minimal_task_strategy_packet.json",
        "strategy_reconciliation": output_root / "post_h3_minimal_task_strategy_reconciliation.json",
        "boundary_report": output_root / "post_h3_minimal_task_strategy_boundary_report.json",
        "summary": output_root / "post_h3_minimal_task_strategy_review_summary.json",
    }
    context = validate_execution_context(execution_summary_path, output=artifacts["context_validation"])
    packet = _write_strategy_packet(context=context, execution_summary_path=execution_summary_path, output=artifacts["strategy_packet"], min_evidence_refs=min_evidence_refs)
    reconciliation = _write_reconciliation(
        packet_path=artifacts["strategy_packet"],
        output=artifacts["strategy_reconciliation"],
        operator_id=operator_id,
        operator_decision=operator_decision,
        audit_decision=audit_decision,
        monitoring_decision=monitoring_decision,
        rollback_decision=rollback_decision,
        operator_statement=operator_statement,
        ack_strategy_review=ack_strategy_review,
    )
    boundary = _write_boundary_report(context=context, reconciliation_path=artifacts["strategy_reconciliation"], output=artifacts["boundary_report"])
    reports = [context, packet, reconciliation, boundary]
    passed = all(report.get("passed") is True for report in reports)
    reusable_ready = passed and reconciliation.get("reusable_minimal_production_path_ready") is True
    summary = {
        "schema_version": CHAIN_SCHEMA,
        "passed": passed,
        "failure_reasons": _failures(reports),
        "checked_at": _now(),
        "task_id": object_value(context.get("execution_summary")).get("task_id"),
        "authorization_id": object_value(context.get("execution_summary")).get("authorization_id"),
        "minimal_production_task_strategy_review_id": reconciliation.get("minimal_production_task_strategy_review_id"),
        "source_artifacts": {"execution_summary": artifact_ref(execution_summary_path)},
        "artifacts": {name: artifact_ref(path) for name, path in artifacts.items() if name != "summary"},
        "readiness": {
            "state": "post_h3_minimal_production_task_reusable_path_ready" if reusable_ready else "post_h3_minimal_production_task_strategy_review_needs_revision",
            "minimal_production_task_strategy_review_complete": passed,
            "reusable_minimal_production_path_ready": reusable_ready,
            "future_execution_requires_fresh_authorization": True,
            "next_intake_authorization_chain_ready": reusable_ready,
            "next_single_use_gate_input_ready": False,
            "production_task_execution_allowed": False,
            "runtime_execution_performed": False,
            "production_runtime_receipt_write_allowed": False,
        },
        "boundary": _boundary(
            context_validation_written=context.get("passed") is True,
            strategy_packet_written=packet.get("passed") is True,
            strategy_reconciliation_written=reconciliation.get("passed") is True,
            boundary_report_written=boundary.get("passed") is True,
            minimal_production_task_strategy_review_complete=passed,
            reusable_minimal_production_path_ready=reusable_ready,
        ),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(artifacts["summary"], summary)
    return summary


def validate_execution_context(execution_summary_path: Path, *, output: Path | None = None) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    try:
        summary = read_json_object(execution_summary_path)
    except Exception as exc:  # noqa: BLE001
        return _write_optional(_report(CONTEXT_SCHEMA, False, [f"execution_summary_unreadable:{exc}"], checks), output)
    artifacts = object_value(summary.get("artifacts"))
    status_index = _read_verified_ref(artifacts.get("status_evidence_index"), checks, failures, "status_evidence_index")
    execution_receipt = _read_verified_ref(artifacts.get("execution_receipt"), checks, failures, "execution_receipt")
    monitoring_receipt = _read_verified_ref(artifacts.get("monitoring_receipt"), checks, failures, "monitoring_receipt")
    rollback_abort_receipt = _read_verified_ref(artifacts.get("rollback_abort_receipt"), checks, failures, "rollback_abort_receipt")
    closeout_receipt = _read_verified_ref(artifacts.get("closeout_receipt"), checks, failures, "closeout_receipt")
    readiness = object_value(summary.get("readiness"))
    boundary = object_value(summary.get("boundary"))
    observations = object_value(monitoring_receipt.get("observations"))

    check(checks, failures, "execution_summary_schema", summary.get("schema_version") == EXECUTION_CHAIN_SCHEMA)
    check(checks, failures, "execution_summary_passed", summary.get("passed") is True)
    check(checks, failures, "execution_closeout_ready", readiness.get("next_strategy_review_input_ready") is True)
    check(checks, failures, "authorization_consumed", readiness.get("authorization_consumed") is True)
    check(checks, failures, "status_index_written", readiness.get("status_evidence_index_written") is True)
    check(checks, failures, "execution_receipt_written", readiness.get("execution_receipt_written") is True)
    check(checks, failures, "monitoring_receipt_written", readiness.get("monitoring_receipt_written") is True)
    check(checks, failures, "rollback_abort_receipt_written", readiness.get("rollback_abort_receipt_written") is True)
    check(checks, failures, "closeout_receipt_written", readiness.get("closeout_receipt_written") is True)
    check(checks, failures, "execution_no_runtime_execution", readiness.get("runtime_execution_performed") is False)
    check(checks, failures, "execution_no_production_runtime_receipts", readiness.get("production_runtime_receipt_write_allowed") is False)
    check(checks, failures, "status_index_schema", status_index.get("schema_version") == STATUS_EVIDENCE_INDEX_SCHEMA and status_index.get("passed") is True)
    check(checks, failures, "execution_receipt_schema", execution_receipt.get("schema_version") == EXECUTION_RECEIPT_SCHEMA and execution_receipt.get("passed") is True)
    check(checks, failures, "monitoring_receipt_schema", monitoring_receipt.get("schema_version") == MONITORING_RECEIPT_SCHEMA and monitoring_receipt.get("passed") is True)
    check(checks, failures, "rollback_abort_receipt_schema", rollback_abort_receipt.get("schema_version") == ROLLBACK_ABORT_RECEIPT_SCHEMA and rollback_abort_receipt.get("passed") is True)
    check(checks, failures, "closeout_receipt_schema", closeout_receipt.get("schema_version") == CLOSEOUT_RECEIPT_SCHEMA and closeout_receipt.get("passed") is True)
    check(checks, failures, "evidence_ref_count_sufficient", int(status_index.get("evidence_ref_count") or 0) >= 9)
    check(checks, failures, "monitoring_no_anomalies", observations.get("anomaly_count") == 0)
    check(checks, failures, "rollback_not_required", monitoring_receipt.get("rollback_required") is False)
    check(checks, failures, "rollback_decision_noop", rollback_abort_receipt.get("decision") == "no_rollback_or_abort_required")
    check(checks, failures, "closeout_outcome_closed", closeout_receipt.get("outcome") == "minimal_production_task_read_only_execution_closed")
    _check_closed_review_boundary("execution_summary", boundary, checks, failures)
    _check_closed_review_boundary("execution_receipt", object_value(execution_receipt.get("boundary")), checks, failures)
    passed = _passed(checks, failures)
    report = {
        "schema_version": CONTEXT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "execution_summary": summary,
        "status_evidence_index": status_index,
        "execution_receipt": execution_receipt,
        "monitoring_receipt": monitoring_receipt,
        "rollback_abort_receipt": rollback_abort_receipt,
        "closeout_receipt": closeout_receipt,
        "source_artifacts": {"execution_summary": artifact_ref(execution_summary_path)},
        "boundary": _boundary(context_validation_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    return _write_optional(report, output)


def _write_strategy_packet(*, context: dict[str, Any], execution_summary_path: Path, output: Path, min_evidence_refs: int) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    summary = object_value(context.get("execution_summary"))
    status_index = object_value(context.get("status_evidence_index"))
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "task_class_read_only", summary.get("task_class") == "read_only_status_evidence_index")
    check(checks, failures, "evidence_refs_meet_threshold", int(status_index.get("evidence_ref_count") or 0) >= min_evidence_refs)
    check(checks, failures, "no_external_side_effects", object_value(status_index.get("status")).get("external_side_effects_observed") is False)
    passed = _passed(checks, failures)
    packet = {
        "schema_version": STRATEGY_PACKET_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "written_at": _now(),
        "strategy_packet_id": f"post-h3-minimal-task-strategy-packet:{sha256_json([artifact_ref(execution_summary_path), min_evidence_refs])[:24]}",
        "task_id": summary.get("task_id"),
        "authorization_id": summary.get("authorization_id"),
        "evaluation": {
            "execution_closed": summary.get("passed") is True,
            "status_evidence_index_written": status_index.get("passed") is True,
            "evidence_ref_count": status_index.get("evidence_ref_count"),
            "min_evidence_refs": min_evidence_refs,
            "future_execution_requires_fresh_authorization": True,
            "reusable_path_candidate": passed,
        },
        "allowed_operator_decisions": sorted(ALLOWED_OPERATOR_DECISIONS),
        "source_artifacts": {"execution_summary": artifact_ref(execution_summary_path)},
        "readiness": {
            "strategy_reconciliation_input_ready": passed,
            "production_task_execution_allowed": False,
            "next_single_use_gate_input_ready": False,
        },
        "boundary": _boundary(strategy_packet_written=passed),
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
    ack_strategy_review: bool,
) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    packet = read_json_object(packet_path)
    accept_reusable = operator_decision == ACCEPT_REUSABLE_PATH_DECISION
    check(checks, failures, "strategy_packet_passed", packet.get("schema_version") == STRATEGY_PACKET_SCHEMA and packet.get("passed") is True)
    check(checks, failures, "operator_id_present", bool(operator_id.strip()))
    check(checks, failures, "operator_statement_present", bool(operator_statement.strip()))
    check(checks, failures, "operator_decision_allowed", operator_decision in ALLOWED_OPERATOR_DECISIONS)
    check(checks, failures, "audit_decision_accepted", audit_decision == ACCEPTED_AUDIT_DECISION)
    check(checks, failures, "monitoring_decision_accepted", monitoring_decision == ACCEPTED_MONITORING_DECISION)
    check(checks, failures, "rollback_decision_accepted", rollback_decision == ACCEPTED_ROLLBACK_DECISION)
    check(checks, failures, "explicit_strategy_review_ack", ack_strategy_review is True)
    passed = _passed(checks, failures)
    reconciliation = {
        "schema_version": STRATEGY_RECONCILIATION_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "decided_at": _now(),
        "minimal_production_task_strategy_review_id": f"post-h3-minimal-task-strategy-review:{sha256_json([artifact_ref(packet_path), operator_id, operator_decision])[:24]}",
        "operator_id": operator_id,
        "operator_decision": operator_decision if passed else REQUEST_MORE_EVIDENCE_DECISION,
        "audit_decision": audit_decision,
        "monitoring_decision": monitoring_decision,
        "rollback_decision": rollback_decision,
        "operator_statement": operator_statement,
        "operator_statement_sha256": sha256_json(operator_statement),
        "reusable_minimal_production_path_ready": passed and accept_reusable,
        "future_execution_requires_fresh_authorization": True,
        "source_artifacts": {"strategy_packet": artifact_ref(packet_path)},
        "readiness": {
            "strategy_review_complete": passed,
            "next_intake_authorization_chain_ready": passed and accept_reusable,
            "next_single_use_gate_input_ready": False,
            "production_task_execution_allowed": False,
        },
        "boundary": _boundary(strategy_reconciliation_written=passed, reusable_minimal_production_path_ready=passed and accept_reusable),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, reconciliation)
    return reconciliation


def _write_boundary_report(*, context: dict[str, Any], reconciliation_path: Path, output: Path) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    reconciliation = _read_json_or_empty(reconciliation_path, failures, "strategy_reconciliation")
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "reconciliation_passed", reconciliation.get("schema_version") == STRATEGY_RECONCILIATION_SCHEMA and reconciliation.get("passed") is True)
    _check_closed_review_boundary("reconciliation", object_value(reconciliation.get("boundary")), checks, failures)
    passed = _passed(checks, failures)
    report = {
        "schema_version": BOUNDARY_REPORT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "minimal_production_task_strategy_review_id": reconciliation.get("minimal_production_task_strategy_review_id"),
        "boundary": _boundary(boundary_report_written=passed),
        "readiness": {
            "boundary_review_complete": passed,
            "production_task_execution_allowed": False,
            "runtime_execution_performed": False,
            "production_runtime_receipt_write_allowed": False,
        },
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def _read_verified_ref(ref: Any, checks: dict[str, bool], failures: list[str], label: str) -> dict[str, Any]:
    ref_obj = object_value(ref)
    path_text = ref_obj.get("path")
    expected_hash = ref_obj.get("sha256")
    check(checks, failures, f"{label}_ref_present", bool(path_text and expected_hash))
    if not path_text or not expected_hash:
        return {}
    path = Path(path_text)
    check(checks, failures, f"{label}_exists", path.is_file())
    if not path.is_file():
        return {}
    check(checks, failures, f"{label}_hash_valid", sha256_file(path) == expected_hash)
    try:
        return read_json_object(path)
    except Exception as exc:  # noqa: BLE001
        failures.append(f"{label}_unreadable:{exc}")
        return {}


def _read_json_or_empty(path: Path, failures: list[str], label: str) -> dict[str, Any]:
    try:
        return read_json_object(path)
    except Exception as exc:  # noqa: BLE001
        failures.append(f"{label}_unreadable:{exc}")
        return {}


def _check_closed_review_boundary(label: str, boundary: dict[str, Any], checks: dict[str, bool], failures: list[str]) -> None:
    for key in (
        "backend_task_pool_mutation_performed",
        "runtime_execution_performed",
        "runtime_workers_currently_running",
        "external_public_ingress_opened",
        "deploy_performed",
        "vm_contact_performed",
        "production_data_accessed",
        "production_runtime_receipt_write_allowed",
        "production_runtime_receipt_written",
        "source_tree_write_performed",
        "git_write_performed",
        "secrets_recorded",
    ):
        if key in boundary:
            check(checks, failures, f"{label}_{key}_false", boundary.get(key) is False)


def _boundary(**overrides: Any) -> dict[str, Any]:
    boundary = {
        "context_validation_written": False,
        "strategy_packet_written": False,
        "strategy_reconciliation_written": False,
        "boundary_report_written": False,
        "minimal_production_task_strategy_review_complete": False,
        "reusable_minimal_production_path_ready": False,
        "production_task_execution_allowed": False,
        "next_single_use_gate_input_ready": False,
        "runtime_execution_performed": False,
        "runtime_workers_currently_running": False,
        "backend_task_pool_mutation_performed": False,
        "external_public_ingress_opened": False,
        "deploy_performed": False,
        "vm_contact_performed": False,
        "production_data_accessed": False,
        "production_runtime_receipt_write_allowed": False,
        "production_runtime_receipt_written": False,
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


def _passed(checks: dict[str, bool], failures: list[str]) -> bool:
    return bool(checks) and all(checks.values()) and not failures


def _failures(reports: list[dict[str, Any]]) -> list[str]:
    failures: list[str] = []
    for report in reports:
        for failure in report.get("failure_reasons", []):
            if isinstance(failure, str) and failure not in failures:
                failures.append(failure)
    return failures


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execution-summary", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--operator-id", default="operator-primary")
    parser.add_argument("--operator-decision", default=ACCEPT_REUSABLE_PATH_DECISION)
    parser.add_argument("--audit-decision", default=ACCEPTED_AUDIT_DECISION)
    parser.add_argument("--monitoring-decision", default=ACCEPTED_MONITORING_DECISION)
    parser.add_argument("--rollback-decision", default=ACCEPTED_ROLLBACK_DECISION)
    parser.add_argument("--operator-statement", default="Accept the read-only minimal production task path as reusable; every future execution still requires a fresh single-use authorization.")
    parser.add_argument("--min-evidence-refs", type=int, default=9)
    parser.add_argument("--ack-strategy-review", action="store_true")
    args = parser.parse_args(argv)
    summary = run_gate(
        execution_summary_path=args.execution_summary,
        output_root=args.output_root,
        operator_id=args.operator_id,
        operator_decision=args.operator_decision,
        audit_decision=args.audit_decision,
        monitoring_decision=args.monitoring_decision,
        rollback_decision=args.rollback_decision,
        operator_statement=args.operator_statement,
        min_evidence_refs=args.min_evidence_refs,
        ack_strategy_review=args.ack_strategy_review,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if summary.get("passed") is True else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
