"""Execute one bounded PostH3 minimal production task.

This gate consumes the single-use authorization receipt produced by
``post_h3_minimal_production_task_authorization_gate`` and executes exactly one
low-risk read-only production task: generate an owner-readable status/evidence
index from already hash-bound PostH3 artifacts.

It writes execution, monitoring, rollback/abort, and closeout receipts. It does
not start runtime workers, mutate backend state, deploy, open public ingress,
access production data, write production runtime receipts, or touch source/Git.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from benchmarks.i_gate_evidence import artifact_ref, check, object_value, read_json_object, sha256_file, sha256_json, write_json_object
from benchmarks.post_h3_minimal_production_task_authorization_gate import (
    AUTHORIZATION_DECISION_SCHEMA,
    AUTHORIZATION_RECEIPT_SCHEMA,
    AUTHORIZATION_REQUEST_SCHEMA,
    CHAIN_SCHEMA as AUTHORIZATION_CHAIN_SCHEMA,
    OPERATOR_DECISION_AUTHORIZE,
)
from benchmarks.post_h3_minimal_production_task_intake_gate import (
    CHAIN_SCHEMA as INTAKE_CHAIN_SCHEMA,
    INTAKE_PACKET_SCHEMA,
    REQUIRED_FORBIDDEN_ACTIONS,
    RISK_BOUNDARY_SCHEMA,
    ROLLBACK_RUNBOOK_SCHEMA,
)

CHAIN_SCHEMA = "post-h3-minimal-production-task-execution-chain:v1"
CONTEXT_SCHEMA = "post-h3-minimal-production-task-execution-context-validation:v1"
AUTHORIZATION_CONSUMPTION_SCHEMA = "post-h3-minimal-production-task-authorization-consumption:v1"
STATUS_EVIDENCE_INDEX_SCHEMA = "post-h3-minimal-production-task-status-evidence-index:v1"
EXECUTION_RECEIPT_SCHEMA = "post-h3-minimal-production-task-execution-receipt:v1"
MONITORING_RECEIPT_SCHEMA = "post-h3-minimal-production-task-monitoring-receipt:v1"
ROLLBACK_ABORT_RECEIPT_SCHEMA = "post-h3-minimal-production-task-rollback-abort-receipt:v1"
CLOSEOUT_RECEIPT_SCHEMA = "post-h3-minimal-production-task-closeout-receipt:v1"

ACCEPTED_OPERATOR_DECISION = "execute_minimal_production_task_once"
ACCEPTED_OWNER_DECISION = "accept_minimal_production_task_execution"
ACCEPTED_AUDIT_DECISION = "accept_minimal_production_task_no_production_boundary"
ACCEPTED_MONITORING_DECISION = "accept_minimal_production_task_monitoring_receipt"
ACCEPTED_ROLLBACK_DECISION = "accept_minimal_production_task_no_rollback_required"
ALLOWED_TASK_CLASS = "read_only_status_evidence_index"

NON_CLAIMS = (
    "minimal_production_task_execution_consumes_one_authorization_only",
    "minimal_production_task_execution_generates_read_only_status_evidence_index_only",
    "minimal_production_task_execution_does_not_start_runtime_workers",
    "minimal_production_task_execution_does_not_mutate_backend_task_pool",
    "minimal_production_task_execution_does_not_open_public_ingress",
    "minimal_production_task_execution_does_not_deploy",
    "minimal_production_task_execution_does_not_access_production_data",
    "minimal_production_task_execution_does_not_write_production_runtime_receipts",
    "minimal_production_task_execution_does_not_write_source_or_git",
)


def run_gate(
    *,
    authorization_summary_path: Path,
    output_root: Path,
    operator_id: str = "operator-primary",
    operator_decision: str = ACCEPTED_OPERATOR_DECISION,
    owner_decision: str = ACCEPTED_OWNER_DECISION,
    audit_decision: str = ACCEPTED_AUDIT_DECISION,
    monitoring_decision: str = ACCEPTED_MONITORING_DECISION,
    rollback_decision: str = ACCEPTED_ROLLBACK_DECISION,
    operator_statement: str = "Execute one read-only minimal production status/evidence index task.",
    authorization_consumption_path: Path | None = None,
    ack_minimal_task_execution: bool = False,
) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "context_validation": output_root / "post_h3_minimal_task_execution_context_validation.json",
        "authorization_consumption": output_root / "post_h3_minimal_task_authorization_consumption.json",
        "status_evidence_index": output_root / "post_h3_minimal_task_status_evidence_index.json",
        "execution_receipt": output_root / "post_h3_minimal_task_execution_receipt.json",
        "monitoring_receipt": output_root / "post_h3_minimal_task_monitoring_receipt.json",
        "rollback_abort_receipt": output_root / "post_h3_minimal_task_rollback_abort_receipt.json",
        "closeout_receipt": output_root / "post_h3_minimal_task_closeout_receipt.json",
        "summary": output_root / "post_h3_minimal_task_execution_summary.json",
    }
    context = validate_authorization_context(authorization_summary_path, output=artifacts["context_validation"])
    try:
        consumption = _write_authorization_consumption(
            context=context,
            authorization_summary_path=authorization_summary_path,
            output=artifacts["authorization_consumption"],
            lease_path=authorization_consumption_path or _default_consumption_lease_path(context),
            operator_id=operator_id,
            operator_decision=operator_decision,
            owner_decision=owner_decision,
            audit_decision=audit_decision,
            monitoring_decision=monitoring_decision,
            rollback_decision=rollback_decision,
            operator_statement=operator_statement,
            ack_minimal_task_execution=ack_minimal_task_execution,
        )
    except RuntimeError as exc:
        consumption = _write_blocked_consumption(
            output=artifacts["authorization_consumption"],
            authorization_summary_path=authorization_summary_path,
            error=str(exc),
        )
    status_index = _write_status_evidence_index(
        context=context,
        consumption_path=artifacts["authorization_consumption"],
        output=artifacts["status_evidence_index"],
    )
    execution = _write_execution_receipt(
        context=context,
        status_evidence_index_path=artifacts["status_evidence_index"],
        output=artifacts["execution_receipt"],
    )
    monitoring = _write_monitoring_receipt(
        context=context,
        execution_receipt_path=artifacts["execution_receipt"],
        status_evidence_index_path=artifacts["status_evidence_index"],
        output=artifacts["monitoring_receipt"],
    )
    rollback_abort = _write_rollback_abort_receipt(
        context=context,
        monitoring_receipt_path=artifacts["monitoring_receipt"],
        output=artifacts["rollback_abort_receipt"],
    )
    closeout = _write_closeout_receipt(
        context=context,
        execution_receipt_path=artifacts["execution_receipt"],
        monitoring_receipt_path=artifacts["monitoring_receipt"],
        rollback_abort_receipt_path=artifacts["rollback_abort_receipt"],
        output=artifacts["closeout_receipt"],
        owner_decision=owner_decision,
        audit_decision=audit_decision,
        monitoring_decision=monitoring_decision,
        rollback_decision=rollback_decision,
    )
    reports = [context, consumption, status_index, execution, monitoring, rollback_abort, closeout]
    passed = all(report.get("passed") is True for report in reports)
    task = object_value(context.get("task_request"))
    summary = {
        "schema_version": CHAIN_SCHEMA,
        "passed": passed,
        "failure_reasons": _failures(reports),
        "checked_at": _now(),
        "task_id": task.get("task_id"),
        "task_class": task.get("task_class"),
        "authorization_id": object_value(context.get("authorization_receipt")).get("authorization_id"),
        "source_artifacts": {"authorization_summary": artifact_ref(authorization_summary_path)},
        "artifacts": {name: artifact_ref(path) for name, path in artifacts.items() if name != "summary"},
        "readiness": {
            "state": "post_h3_minimal_production_task_execution_closed" if passed else "blocked_post_h3_minimal_production_task_execution",
            "minimal_production_task_execution_complete": passed,
            "authorization_consumed": consumption.get("passed") is True,
            "status_evidence_index_written": status_index.get("passed") is True,
            "execution_receipt_written": execution.get("passed") is True,
            "monitoring_receipt_written": monitoring.get("passed") is True,
            "rollback_abort_receipt_written": rollback_abort.get("passed") is True,
            "closeout_receipt_written": closeout.get("passed") is True,
            "next_strategy_review_input_ready": passed,
            "production_task_execution_allowed": False,
            "runtime_execution_performed": False,
            "production_runtime_receipt_write_allowed": False,
        },
        "boundary": _boundary(
            context_validation_written=context.get("passed") is True,
            authorization_consumed=consumption.get("passed") is True,
            status_evidence_index_written=status_index.get("passed") is True,
            execution_receipt_written=execution.get("passed") is True,
            monitoring_receipt_written=monitoring.get("passed") is True,
            rollback_abort_receipt_written=rollback_abort.get("passed") is True,
            closeout_receipt_written=closeout.get("passed") is True,
            production_task_execution_performed=passed,
        ),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(artifacts["summary"], summary)
    return summary


def validate_authorization_context(authorization_summary_path: Path, *, output: Path | None = None) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    try:
        summary = read_json_object(authorization_summary_path)
    except Exception as exc:  # noqa: BLE001
        return _write_optional(_report(CONTEXT_SCHEMA, False, [f"authorization_summary_unreadable:{exc}"], checks), output)
    artifacts = object_value(summary.get("artifacts"))
    auth_context = _read_verified_ref(artifacts.get("context_validation"), checks, failures, "authorization_context_validation")
    auth_request = _read_verified_ref(artifacts.get("authorization_request"), checks, failures, "authorization_request")
    auth_decision = _read_verified_ref(artifacts.get("authorization_decision"), checks, failures, "authorization_decision")
    auth_receipt = _read_verified_ref(artifacts.get("authorization_receipt"), checks, failures, "authorization_receipt")
    intake_summary = _read_verified_ref(object_value(auth_request.get("source_artifacts")).get("intake_summary"), checks, failures, "intake_summary")
    intake_artifacts = object_value(intake_summary.get("artifacts"))
    intake_packet = _read_verified_ref(intake_artifacts.get("intake_packet"), checks, failures, "intake_packet")
    risk_boundary = _read_verified_ref(intake_artifacts.get("risk_boundary"), checks, failures, "risk_boundary")
    rollback_runbook = _read_verified_ref(intake_artifacts.get("rollback_runbook"), checks, failures, "rollback_runbook")
    task = object_value(auth_request.get("task_request"))
    scope = object_value(task.get("scope"))
    readiness = object_value(summary.get("readiness"))
    auth_summary_boundary = object_value(summary.get("boundary"))
    receipt_boundary = object_value(auth_receipt.get("boundary"))

    check(checks, failures, "authorization_summary_schema", summary.get("schema_version") == AUTHORIZATION_CHAIN_SCHEMA)
    check(checks, failures, "authorization_summary_passed", summary.get("passed") is True)
    check(checks, failures, "authorization_context_passed", auth_context.get("passed") is True)
    check(checks, failures, "authorization_request_schema", auth_request.get("schema_version") == AUTHORIZATION_REQUEST_SCHEMA and auth_request.get("passed") is True)
    check(checks, failures, "authorization_decision_schema", auth_decision.get("schema_version") == AUTHORIZATION_DECISION_SCHEMA and auth_decision.get("passed") is True)
    check(checks, failures, "authorization_receipt_schema", auth_receipt.get("schema_version") == AUTHORIZATION_RECEIPT_SCHEMA and auth_receipt.get("passed") is True)
    check(checks, failures, "intake_summary_schema", intake_summary.get("schema_version") == INTAKE_CHAIN_SCHEMA and intake_summary.get("passed") is True)
    check(checks, failures, "intake_packet_schema", intake_packet.get("schema_version") == INTAKE_PACKET_SCHEMA and intake_packet.get("passed") is True)
    check(checks, failures, "risk_boundary_schema", risk_boundary.get("schema_version") == RISK_BOUNDARY_SCHEMA and risk_boundary.get("passed") is True)
    check(checks, failures, "rollback_runbook_schema", rollback_runbook.get("schema_version") == ROLLBACK_RUNBOOK_SCHEMA and rollback_runbook.get("passed") is True)
    check(checks, failures, "execution_gate_input_ready", readiness.get("execution_gate_input_ready") is True)
    check(checks, failures, "single_use_execution_authorized", readiness.get("single_use_execution_authorized") is True)
    check(checks, failures, "summary_authorizes_execution", readiness.get("production_task_execution_allowed") is True)
    check(checks, failures, "summary_no_runtime_execution", readiness.get("runtime_execution_performed") is False)
    check(checks, failures, "summary_no_production_runtime_receipts", readiness.get("production_runtime_receipt_write_allowed") is False)
    check(checks, failures, "receipt_single_use", auth_receipt.get("single_use") is True)
    check(checks, failures, "receipt_unconsumed", auth_receipt.get("consumed") is False)
    check(checks, failures, "receipt_required_by_execution_gate", auth_receipt.get("consumption_required_by") == "post_h3_minimal_production_task_execution_gate")
    check(checks, failures, "request_required_next_gate", auth_request.get("required_next_gate") == "post_h3_minimal_production_task_execution_gate")
    check(checks, failures, "decision_authorize_once", auth_decision.get("decision") == OPERATOR_DECISION_AUTHORIZE)
    check(checks, failures, "task_id_matches_receipt", auth_receipt.get("task_id") == task.get("task_id") == summary.get("task_id"))
    check(checks, failures, "task_class_read_only", task.get("task_class") == ALLOWED_TASK_CLASS)
    check(checks, failures, "task_risk_low", task.get("risk_class") == "low")
    check(checks, failures, "single_runtime_task", scope.get("max_runtime_tasks") == 1)
    check(checks, failures, "no_external_users", scope.get("max_external_users") == 0)
    check(checks, failures, "forbidden_actions_complete", REQUIRED_FORBIDDEN_ACTIONS <= set(_texts(scope.get("forbidden_actions"))))
    _check_no_runtime_side_effect_boundary("authorization_summary", auth_summary_boundary, checks, failures)
    _check_no_runtime_side_effect_boundary("authorization_receipt", receipt_boundary, checks, failures)
    passed = _passed(checks, failures)
    verified_refs = _verified_refs(
        authorization_summary=authorization_summary_path,
        authorization_context_validation=Path(str(object_value(artifacts.get("context_validation")).get("path") or "")),
        authorization_request=Path(str(object_value(artifacts.get("authorization_request")).get("path") or "")),
        authorization_decision=Path(str(object_value(artifacts.get("authorization_decision")).get("path") or "")),
        authorization_receipt=Path(str(object_value(artifacts.get("authorization_receipt")).get("path") or "")),
        intake_summary=Path(str(object_value(object_value(auth_request.get("source_artifacts")).get("intake_summary")).get("path") or "")),
        intake_packet=Path(str(object_value(intake_artifacts.get("intake_packet")).get("path") or "")),
        risk_boundary=Path(str(object_value(intake_artifacts.get("risk_boundary")).get("path") or "")),
        rollback_runbook=Path(str(object_value(intake_artifacts.get("rollback_runbook")).get("path") or "")),
    )
    report = {
        "schema_version": CONTEXT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "authorization_summary": summary,
        "authorization_context_validation": auth_context,
        "authorization_request": auth_request,
        "authorization_decision": auth_decision,
        "authorization_receipt": auth_receipt,
        "intake_summary": intake_summary,
        "intake_packet": intake_packet,
        "risk_boundary": risk_boundary,
        "rollback_runbook": rollback_runbook,
        "task_request": task,
        "verified_artifact_refs": verified_refs,
        "source_artifacts": {"authorization_summary": artifact_ref(authorization_summary_path)},
        "boundary": _boundary(context_validation_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    return _write_optional(report, output)


def _write_authorization_consumption(
    *,
    context: dict[str, Any],
    authorization_summary_path: Path,
    output: Path,
    lease_path: Path,
    operator_id: str,
    operator_decision: str,
    owner_decision: str,
    audit_decision: str,
    monitoring_decision: str,
    rollback_decision: str,
    operator_statement: str,
    ack_minimal_task_execution: bool,
) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    receipt = object_value(context.get("authorization_receipt"))
    task = object_value(context.get("task_request"))
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "authorization_receipt_unconsumed", receipt.get("consumed") is False)
    check(checks, failures, "lease_not_already_present", not lease_path.exists())
    check(checks, failures, "operator_id_present", bool(str(operator_id).strip()))
    check(checks, failures, "operator_statement_present", bool(str(operator_statement).strip()))
    check(checks, failures, "operator_decision_accepted", operator_decision == ACCEPTED_OPERATOR_DECISION)
    check(checks, failures, "owner_decision_accepted", owner_decision == ACCEPTED_OWNER_DECISION)
    check(checks, failures, "audit_decision_accepted", audit_decision == ACCEPTED_AUDIT_DECISION)
    check(checks, failures, "monitoring_decision_accepted", monitoring_decision == ACCEPTED_MONITORING_DECISION)
    check(checks, failures, "rollback_decision_accepted", rollback_decision == ACCEPTED_ROLLBACK_DECISION)
    check(checks, failures, "explicit_execution_ack", ack_minimal_task_execution is True)
    passed = _passed(checks, failures)
    consumption = {
        "schema_version": AUTHORIZATION_CONSUMPTION_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "consumed_at": _now(),
        "authorization_id": receipt.get("authorization_id"),
        "task_id": task.get("task_id"),
        "operator_id": operator_id,
        "operator_decision": operator_decision,
        "owner_decision": owner_decision,
        "audit_decision": audit_decision,
        "monitoring_decision": monitoring_decision,
        "rollback_decision": rollback_decision,
        "operator_statement": operator_statement,
        "operator_statement_sha256": sha256_json(operator_statement),
        "single_use_authorization_consumed": passed,
        "lease_path": str(lease_path.resolve()),
        "source_artifacts": {"authorization_summary": artifact_ref(authorization_summary_path)},
        "boundary": _boundary(authorization_consumed=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, consumption)
    if passed:
        if lease_path.exists():
            raise RuntimeError(f"authorization_already_consumed:{lease_path}")
        write_json_object(lease_path, consumption)
    return consumption


def _write_blocked_consumption(*, output: Path, authorization_summary_path: Path, error: str) -> dict[str, Any]:
    report = {
        "schema_version": AUTHORIZATION_CONSUMPTION_SCHEMA,
        "passed": False,
        "failure_reasons": [error],
        "checks": {"authorization_consumption_available": False},
        "checked_at": _now(),
        "single_use_authorization_consumed": False,
        "source_artifacts": {"authorization_summary": artifact_ref(authorization_summary_path)},
        "boundary": _boundary(),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def _write_status_evidence_index(*, context: dict[str, Any], consumption_path: Path, output: Path) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    consumption = _read_json_or_empty(consumption_path, failures, "authorization_consumption")
    task = object_value(context.get("task_request"))
    refs = object_value(context.get("verified_artifact_refs"))
    evidence_refs = [value for value in refs.values() if isinstance(value, dict) and value.get("path") and value.get("sha256")]
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "authorization_consumption_passed", consumption.get("schema_version") == AUTHORIZATION_CONSUMPTION_SCHEMA and consumption.get("passed") is True)
    check(checks, failures, "task_class_read_only", task.get("task_class") == ALLOWED_TASK_CLASS)
    check(checks, failures, "evidence_refs_complete", len(evidence_refs) >= 9)
    passed = _passed(checks, failures)
    index = {
        "schema_version": STATUS_EVIDENCE_INDEX_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "written_at": _now(),
        "status_evidence_index_id": f"post-h3-minimal-task-status-index:{sha256_json([task.get('task_id'), evidence_refs])[:24]}",
        "task_id": task.get("task_id"),
        "task_class": task.get("task_class"),
        "execution_action": "read_hash_bound_post_h3_artifacts_and_write_owner_readable_status_evidence_index",
        "evidence_ref_count": len(evidence_refs),
        "evidence_refs": evidence_refs,
        "status": {
            "authorization_consumed": consumption.get("passed") is True,
            "production_task_scope": "read_only_status_evidence_index",
            "owner_readable_packet_generated": passed,
            "external_side_effects_observed": False,
        },
        "source_artifacts": {"authorization_consumption": artifact_ref(consumption_path)},
        "boundary": _boundary(status_evidence_index_written=passed, production_task_execution_performed=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, index)
    return index


def _write_execution_receipt(*, context: dict[str, Any], status_evidence_index_path: Path, output: Path) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    index = _read_json_or_empty(status_evidence_index_path, failures, "status_evidence_index")
    task = object_value(context.get("task_request"))
    receipt = object_value(context.get("authorization_receipt"))
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "status_evidence_index_passed", index.get("schema_version") == STATUS_EVIDENCE_INDEX_SCHEMA and index.get("passed") is True)
    check(checks, failures, "task_id_matches", index.get("task_id") == task.get("task_id") == receipt.get("task_id"))
    check(checks, failures, "task_class_read_only", task.get("task_class") == ALLOWED_TASK_CLASS)
    passed = _passed(checks, failures)
    execution = {
        "schema_version": EXECUTION_RECEIPT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "started_at": _now(),
        "completed_at": _now(),
        "execution_id": f"post-h3-minimal-task-exec:{sha256_json([receipt.get('authorization_id'), artifact_ref(status_evidence_index_path)])[:24]}",
        "authorization_id": receipt.get("authorization_id"),
        "task_id": task.get("task_id"),
        "task_class": task.get("task_class"),
        "execution_kind": "read_only_artifact_status_evidence_index",
        "runtime_worker_started": False,
        "backend_task_pool_mutation_performed": False,
        "output_artifacts": {"status_evidence_index": artifact_ref(status_evidence_index_path)},
        "boundary": _boundary(execution_receipt_written=passed, status_evidence_index_written=index.get("passed") is True, production_task_execution_performed=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, execution)
    return execution


def _write_monitoring_receipt(*, context: dict[str, Any], execution_receipt_path: Path, status_evidence_index_path: Path, output: Path) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    execution = _read_json_or_empty(execution_receipt_path, failures, "execution_receipt")
    index = _read_json_or_empty(status_evidence_index_path, failures, "status_evidence_index")
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "execution_receipt_passed", execution.get("schema_version") == EXECUTION_RECEIPT_SCHEMA and execution.get("passed") is True)
    check(checks, failures, "status_evidence_index_passed", index.get("schema_version") == STATUS_EVIDENCE_INDEX_SCHEMA and index.get("passed") is True)
    check(checks, failures, "no_runtime_worker_started", execution.get("runtime_worker_started") is False)
    check(checks, failures, "no_backend_task_pool_mutation", execution.get("backend_task_pool_mutation_performed") is False)
    passed = _passed(checks, failures)
    monitoring = {
        "schema_version": MONITORING_RECEIPT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "monitoring_id": f"post-h3-minimal-task-monitor:{sha256_json([execution.get('execution_id'), artifact_ref(status_evidence_index_path)])[:24]}",
        "task_id": execution.get("task_id"),
        "observations": {
            "status_evidence_index_written": index.get("passed") is True,
            "evidence_ref_count": index.get("evidence_ref_count"),
            "runtime_worker_started": False,
            "backend_task_pool_mutation_performed": False,
            "external_side_effects_observed": False,
            "anomaly_count": 0 if passed else 1,
        },
        "rollback_required": False if passed else True,
        "source_artifacts": {
            "execution_receipt": artifact_ref(execution_receipt_path),
            "status_evidence_index": artifact_ref(status_evidence_index_path),
        },
        "boundary": _boundary(monitoring_receipt_written=passed, production_task_execution_performed=execution.get("passed") is True),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, monitoring)
    return monitoring


def _write_rollback_abort_receipt(*, context: dict[str, Any], monitoring_receipt_path: Path, output: Path) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    monitoring = _read_json_or_empty(monitoring_receipt_path, failures, "monitoring_receipt")
    observations = object_value(monitoring.get("observations"))
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "monitoring_receipt_passed", monitoring.get("schema_version") == MONITORING_RECEIPT_SCHEMA and monitoring.get("passed") is True)
    check(checks, failures, "no_anomalies", observations.get("anomaly_count") == 0)
    check(checks, failures, "rollback_not_required", monitoring.get("rollback_required") is False)
    passed = _passed(checks, failures)
    rollback_abort = {
        "schema_version": ROLLBACK_ABORT_RECEIPT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "task_id": monitoring.get("task_id"),
        "rollback_abort_id": f"post-h3-minimal-task-rollback-abort:{sha256_json([monitoring.get('monitoring_id'), passed])[:24]}",
        "decision": "no_rollback_or_abort_required" if passed else "abort_required_due_to_monitoring_failure",
        "rollback_performed": False,
        "abort_performed": False,
        "rollback_available": True,
        "reason": "No external side effects were performed; no rollback action is required." if passed else "Monitoring did not pass; do not proceed without operator review.",
        "source_artifacts": {"monitoring_receipt": artifact_ref(monitoring_receipt_path)},
        "boundary": _boundary(rollback_abort_receipt_written=passed, production_task_execution_performed=monitoring.get("passed") is True),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, rollback_abort)
    return rollback_abort


def _write_closeout_receipt(
    *,
    context: dict[str, Any],
    execution_receipt_path: Path,
    monitoring_receipt_path: Path,
    rollback_abort_receipt_path: Path,
    output: Path,
    owner_decision: str,
    audit_decision: str,
    monitoring_decision: str,
    rollback_decision: str,
) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    execution = _read_json_or_empty(execution_receipt_path, failures, "execution_receipt")
    monitoring = _read_json_or_empty(monitoring_receipt_path, failures, "monitoring_receipt")
    rollback_abort = _read_json_or_empty(rollback_abort_receipt_path, failures, "rollback_abort_receipt")
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "execution_receipt_passed", execution.get("schema_version") == EXECUTION_RECEIPT_SCHEMA and execution.get("passed") is True)
    check(checks, failures, "monitoring_receipt_passed", monitoring.get("schema_version") == MONITORING_RECEIPT_SCHEMA and monitoring.get("passed") is True)
    check(checks, failures, "rollback_abort_receipt_passed", rollback_abort.get("schema_version") == ROLLBACK_ABORT_RECEIPT_SCHEMA and rollback_abort.get("passed") is True)
    check(checks, failures, "owner_decision_accepted", owner_decision == ACCEPTED_OWNER_DECISION)
    check(checks, failures, "audit_decision_accepted", audit_decision == ACCEPTED_AUDIT_DECISION)
    check(checks, failures, "monitoring_decision_accepted", monitoring_decision == ACCEPTED_MONITORING_DECISION)
    check(checks, failures, "rollback_decision_accepted", rollback_decision == ACCEPTED_ROLLBACK_DECISION)
    passed = _passed(checks, failures)
    closeout = {
        "schema_version": CLOSEOUT_RECEIPT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "closed_at": _now(),
        "closeout_id": f"post-h3-minimal-task-closeout:{sha256_json([execution.get('execution_id'), monitoring.get('monitoring_id'), rollback_abort.get('rollback_abort_id')])[:24]}",
        "task_id": execution.get("task_id"),
        "decisions": {
            "owner_decision": owner_decision,
            "audit_decision": audit_decision,
            "monitoring_decision": monitoring_decision,
            "rollback_decision": rollback_decision,
        },
        "outcome": "minimal_production_task_read_only_execution_closed" if passed else "minimal_production_task_closeout_blocked",
        "next_gate": "post_h3_minimal_production_task_strategy_review_gate" if passed else "operator_reconciliation_required",
        "source_artifacts": {
            "execution_receipt": artifact_ref(execution_receipt_path),
            "monitoring_receipt": artifact_ref(monitoring_receipt_path),
            "rollback_abort_receipt": artifact_ref(rollback_abort_receipt_path),
        },
        "boundary": _boundary(closeout_receipt_written=passed, production_task_execution_performed=execution.get("passed") is True),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, closeout)
    return closeout


def _default_consumption_lease_path(context: dict[str, Any]) -> Path:
    receipt_ref = object_value(object_value(context.get("verified_artifact_refs")).get("authorization_receipt"))
    receipt_path = Path(str(receipt_ref.get("path") or "authorization_receipt.json"))
    return receipt_path.with_suffix(receipt_path.suffix + ".post_h3_minimal_task_execution_consumed.json")


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


def _verified_refs(**paths: Path) -> dict[str, dict[str, str]]:
    refs: dict[str, dict[str, str]] = {}
    for name, path in paths.items():
        if path.is_file():
            refs[name] = artifact_ref(path)
    return refs


def _read_json_or_empty(path: Path, failures: list[str], label: str) -> dict[str, Any]:
    try:
        return read_json_object(path)
    except Exception as exc:  # noqa: BLE001
        failures.append(f"{label}_unreadable:{exc}")
        return {}


def _check_no_runtime_side_effect_boundary(label: str, boundary: dict[str, Any], checks: dict[str, bool], failures: list[str]) -> None:
    for key in (
        "runtime_execution_performed",
        "runtime_workers_currently_running",
        "external_public_ingress_opened",
        "deploy_performed",
        "vm_contact_performed",
        "production_data_accessed",
        "production_runtime_receipt_write_allowed",
        "source_tree_write_performed",
        "git_write_performed",
        "secrets_recorded",
    ):
        if key in boundary:
            check(checks, failures, f"{label}_{key}_false", boundary.get(key) is False)


def _texts(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    result: list[str] = []
    for item in value:
        text = str(item).strip()
        if text and text not in result:
            result.append(text)
    return result


def _boundary(**overrides: Any) -> dict[str, Any]:
    boundary = {
        "context_validation_written": False,
        "authorization_consumed": False,
        "status_evidence_index_written": False,
        "execution_receipt_written": False,
        "monitoring_receipt_written": False,
        "rollback_abort_receipt_written": False,
        "closeout_receipt_written": False,
        "production_task_execution_performed": False,
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
    parser.add_argument("--authorization-summary", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--operator-id", default="operator-primary")
    parser.add_argument("--operator-decision", default=ACCEPTED_OPERATOR_DECISION)
    parser.add_argument("--owner-decision", default=ACCEPTED_OWNER_DECISION)
    parser.add_argument("--audit-decision", default=ACCEPTED_AUDIT_DECISION)
    parser.add_argument("--monitoring-decision", default=ACCEPTED_MONITORING_DECISION)
    parser.add_argument("--rollback-decision", default=ACCEPTED_ROLLBACK_DECISION)
    parser.add_argument("--operator-statement", default="Execute one read-only minimal production status/evidence index task.")
    parser.add_argument("--authorization-consumption", type=Path)
    parser.add_argument("--ack-minimal-task-execution", action="store_true")
    args = parser.parse_args(argv)
    summary = run_gate(
        authorization_summary_path=args.authorization_summary,
        output_root=args.output_root,
        operator_id=args.operator_id,
        operator_decision=args.operator_decision,
        owner_decision=args.owner_decision,
        audit_decision=args.audit_decision,
        monitoring_decision=args.monitoring_decision,
        rollback_decision=args.rollback_decision,
        operator_statement=args.operator_statement,
        authorization_consumption_path=args.authorization_consumption,
        ack_minimal_task_execution=args.ack_minimal_task_execution,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if summary.get("passed") is True else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
