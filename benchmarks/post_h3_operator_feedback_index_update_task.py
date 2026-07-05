"""Run the PostH3 operator feedback index update bounded task.

This is the second bounded PostH3 task class after the minimal read-only
status/evidence index. It consumes the proven repeated-validation artifact and
writes a scoped operator feedback index update artifact. The update is
rollbackable by discarding the produced artifact; it does not touch backend
state, source/Git, public ingress, deploy, production data, or production
runtime receipts.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from benchmarks.i_gate_evidence import artifact_ref, check, object_value, read_json_object, sha256_file, sha256_json, write_json_object
from benchmarks.post_h3_minimal_production_task_authorization_gate import run_gate as run_authorization_gate
from benchmarks.post_h3_minimal_production_task_intake_gate import (
    REQUIRED_FORBIDDEN_ACTIONS,
    REQUIRED_SERVICE_TOKEN_SCOPES,
    run_gate as run_intake_gate,
)
from benchmarks.post_h3_minimal_production_task_repeated_validation import SUMMARY_SCHEMA as REPEATED_VALIDATION_SCHEMA

CHAIN_SCHEMA = "post-h3-operator-feedback-index-update-chain:v1"
TASK_REQUEST_SCHEMA = "post-h3-operator-feedback-index-update-task-request:v1"
EXECUTION_CONTEXT_SCHEMA = "post-h3-operator-feedback-index-update-execution-context:v1"
AUTHORIZATION_CONSUMPTION_SCHEMA = "post-h3-operator-feedback-index-update-authorization-consumption:v1"
FEEDBACK_INDEX_UPDATE_SCHEMA = "post-h3-operator-feedback-index-update:v1"
EXECUTION_RECEIPT_SCHEMA = "post-h3-operator-feedback-index-update-execution-receipt:v1"
MONITORING_RECEIPT_SCHEMA = "post-h3-operator-feedback-index-update-monitoring-receipt:v1"
ROLLBACK_ABORT_RECEIPT_SCHEMA = "post-h3-operator-feedback-index-update-rollback-abort-receipt:v1"
CLOSEOUT_RECEIPT_SCHEMA = "post-h3-operator-feedback-index-update-closeout-receipt:v1"
STRATEGY_REVIEW_SCHEMA = "post-h3-operator-feedback-index-update-strategy-review:v1"

TASK_CLASS = "operator_feedback_index_update"
EXECUTION_GATE_NAME = "post_h3_operator_feedback_index_update_execution_gate"
DEFAULT_TASK_ID = "post-h3-task:operator-feedback-index-update-001"

NON_CLAIMS = (
    "operator_feedback_index_update_writes_artifact_only",
    "operator_feedback_index_update_does_not_start_runtime_workers",
    "operator_feedback_index_update_does_not_mutate_backend_task_pool",
    "operator_feedback_index_update_does_not_open_public_ingress",
    "operator_feedback_index_update_does_not_deploy",
    "operator_feedback_index_update_does_not_access_production_data",
    "operator_feedback_index_update_does_not_write_production_runtime_receipts",
    "operator_feedback_index_update_does_not_write_source_or_git",
)


def run_chain(
    *,
    readiness_index_path: Path,
    repeated_validation_summary_path: Path,
    output_root: Path,
    task_id: str = DEFAULT_TASK_ID,
    operator_id: str = "operator-primary",
    ack_bounded_task: bool = False,
) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "task_request": output_root / "post_h3_operator_feedback_index_update_task_request.json",
        "execution_context": output_root / "post_h3_operator_feedback_index_update_execution_context.json",
        "authorization_consumption": output_root / "post_h3_operator_feedback_index_update_authorization_consumption.json",
        "feedback_index_update": output_root / "post_h3_operator_feedback_index_update.json",
        "execution_receipt": output_root / "post_h3_operator_feedback_index_update_execution_receipt.json",
        "monitoring_receipt": output_root / "post_h3_operator_feedback_index_update_monitoring_receipt.json",
        "rollback_abort_receipt": output_root / "post_h3_operator_feedback_index_update_rollback_abort_receipt.json",
        "closeout_receipt": output_root / "post_h3_operator_feedback_index_update_closeout_receipt.json",
        "strategy_review": output_root / "post_h3_operator_feedback_index_update_strategy_review.json",
        "summary": output_root / "post_h3_operator_feedback_index_update_summary.json",
    }
    if not ack_bounded_task:
        return _write_blocked_summary(
            output=artifacts["summary"],
            readiness_index_path=readiness_index_path,
            repeated_validation_summary_path=repeated_validation_summary_path,
            failure="explicit_bounded_task_ack",
        )

    task_request_path = _write_task_request(artifacts["task_request"], task_id=task_id)
    intake_summary = run_intake_gate(
        readiness_index_path=readiness_index_path,
        output_root=output_root / "intake",
        task_request_path=task_request_path,
    )
    authorization_summary = run_authorization_gate(
        intake_summary_path=output_root / "intake" / "post_h3_minimal_task_intake_summary.json",
        output_root=output_root / "authorization",
        operator_id=operator_id,
        operator_statement="Authorize one bounded operator feedback index update from repeated-validation evidence.",
        required_next_gate=EXECUTION_GATE_NAME,
        ack_single_use_authorization=True,
    )
    context = _write_execution_context(
        authorization_summary_path=output_root / "authorization" / "post_h3_minimal_task_authorization_summary.json",
        repeated_validation_summary_path=repeated_validation_summary_path,
        output=artifacts["execution_context"],
    )
    consumption = _write_authorization_consumption(
        context=context,
        authorization_summary_path=output_root / "authorization" / "post_h3_minimal_task_authorization_summary.json",
        output=artifacts["authorization_consumption"],
        lease_path=_default_consumption_lease_path(context),
        operator_id=operator_id,
    )
    update = _write_feedback_index_update(
        context=context,
        consumption_path=artifacts["authorization_consumption"],
        output=artifacts["feedback_index_update"],
    )
    execution = _write_execution_receipt(
        context=context,
        update_path=artifacts["feedback_index_update"],
        output=artifacts["execution_receipt"],
    )
    monitoring = _write_monitoring_receipt(
        execution_path=artifacts["execution_receipt"],
        update_path=artifacts["feedback_index_update"],
        output=artifacts["monitoring_receipt"],
    )
    rollback_abort = _write_rollback_abort_receipt(
        monitoring_path=artifacts["monitoring_receipt"],
        output=artifacts["rollback_abort_receipt"],
    )
    closeout = _write_closeout_receipt(
        execution_path=artifacts["execution_receipt"],
        monitoring_path=artifacts["monitoring_receipt"],
        rollback_abort_path=artifacts["rollback_abort_receipt"],
        output=artifacts["closeout_receipt"],
    )
    strategy = _write_strategy_review(
        closeout_path=artifacts["closeout_receipt"],
        output=artifacts["strategy_review"],
        operator_id=operator_id,
    )
    reports = [intake_summary, authorization_summary, context, consumption, update, execution, monitoring, rollback_abort, closeout, strategy]
    passed = all(report.get("passed") is True for report in reports)
    summary = {
        "schema_version": CHAIN_SCHEMA,
        "passed": passed,
        "failure_reasons": _failures(reports),
        "checked_at": _now(),
        "task_id": task_id,
        "task_class": TASK_CLASS,
        "authorization_id": object_value(context.get("authorization_receipt")).get("authorization_id"),
        "source_artifacts": {
            "readiness_index": artifact_ref(readiness_index_path),
            "repeated_validation_summary": artifact_ref(repeated_validation_summary_path),
        },
        "artifacts": {name: artifact_ref(path) for name, path in artifacts.items() if name != "summary"},
        "stage_summaries": {
            "intake": artifact_ref(output_root / "intake" / "post_h3_minimal_task_intake_summary.json"),
            "authorization": artifact_ref(output_root / "authorization" / "post_h3_minimal_task_authorization_summary.json"),
        },
        "readiness": {
            "state": "post_h3_operator_feedback_index_update_closed" if passed else "blocked_post_h3_operator_feedback_index_update",
            "operator_feedback_index_update_complete": passed,
            "authorization_consumed": consumption.get("passed") is True,
            "feedback_index_update_written": update.get("passed") is True,
            "monitoring_receipt_written": monitoring.get("passed") is True,
            "rollback_abort_receipt_written": rollback_abort.get("passed") is True,
            "closeout_receipt_written": closeout.get("passed") is True,
            "strategy_review_complete": strategy.get("passed") is True,
            "future_execution_requires_fresh_authorization": True,
            "production_task_execution_allowed": False,
            "next_single_use_gate_input_ready": False,
            "runtime_execution_performed": False,
            "production_runtime_receipt_write_allowed": False,
        },
        "boundary": _boundary(
            context_validation_written=context.get("passed") is True,
            authorization_consumed=consumption.get("passed") is True,
            feedback_index_update_written=update.get("passed") is True,
            execution_receipt_written=execution.get("passed") is True,
            monitoring_receipt_written=monitoring.get("passed") is True,
            rollback_abort_receipt_written=rollback_abort.get("passed") is True,
            closeout_receipt_written=closeout.get("passed") is True,
            strategy_review_written=strategy.get("passed") is True,
            bounded_task_execution_performed=passed,
        ),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(artifacts["summary"], summary)
    return summary


def _write_task_request(path: Path, *, task_id: str) -> Path:
    request = {
        "schema_version": TASK_REQUEST_SCHEMA,
        "task_id": task_id,
        "title": "Update operator feedback index from PostH3 repeated-validation evidence",
        "task_class": TASK_CLASS,
        "risk_class": "low",
        "owner_id": "product_owner",
        "operator_id": "operator-primary",
        "audit_owner_id": "audit_owner",
        "rollback_owner_id": "rollback_owner",
        "monitoring_owner_id": "observability_owner",
        "scope": {
            "max_runtime_tasks": 1,
            "max_external_users": 0,
            "allowed_systems": ["posth3 evidence run-root"],
            "allowed_outputs": ["operator feedback index update artifact", "monitoring snapshot"],
            "service_token_scopes": sorted(REQUIRED_SERVICE_TOKEN_SCOPES | {"outcomes:read"}),
            "forbidden_actions": sorted(REQUIRED_FORBIDDEN_ACTIONS),
        },
        "rollback": {
            "owner_id": "rollback_owner",
            "strategy": "abort_or_noop_before_any_external_side_effect",
            "runbook": "Discard the feedback index update artifact and keep previous feedback index unchanged.",
        },
        "success_criteria": [
            "one operator feedback index update artifact is written",
            "update is hash-bound to repeated-validation evidence",
            "rollback is possible by discarding the update artifact",
            "no backend, public ingress, deploy, production data, production receipt, source tree, or Git mutation occurs",
        ],
    }
    write_json_object(path, request)
    return path


def _write_execution_context(*, authorization_summary_path: Path, repeated_validation_summary_path: Path, output: Path) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    authorization_summary = _read_json_or_empty(authorization_summary_path, failures, "authorization_summary")
    artifacts = object_value(authorization_summary.get("artifacts"))
    authorization_request = _read_verified_ref(artifacts.get("authorization_request"), checks, failures, "authorization_request")
    authorization_decision = _read_verified_ref(artifacts.get("authorization_decision"), checks, failures, "authorization_decision")
    authorization_receipt = _read_verified_ref(artifacts.get("authorization_receipt"), checks, failures, "authorization_receipt")
    repeated = _read_json_or_empty(repeated_validation_summary_path, failures, "repeated_validation_summary")
    task = object_value(authorization_request.get("task_request"))
    readiness = object_value(repeated.get("readiness"))
    check(checks, failures, "authorization_summary_passed", authorization_summary.get("passed") is True)
    check(checks, failures, "authorization_request_passed", authorization_request.get("passed") is True)
    check(checks, failures, "authorization_decision_passed", authorization_decision.get("passed") is True)
    check(checks, failures, "authorization_receipt_passed", authorization_receipt.get("passed") is True)
    check(checks, failures, "task_class_operator_feedback_index_update", task.get("task_class") == TASK_CLASS)
    check(checks, failures, "required_next_gate_matches", authorization_request.get("required_next_gate") == EXECUTION_GATE_NAME)
    check(checks, failures, "receipt_consumption_required_by_matches", authorization_receipt.get("consumption_required_by") == EXECUTION_GATE_NAME)
    check(checks, failures, "receipt_unconsumed", authorization_receipt.get("consumed") is False)
    check(checks, failures, "repeated_validation_schema", repeated.get("schema_version") == REPEATED_VALIDATION_SCHEMA)
    check(checks, failures, "repeated_validation_passed", repeated.get("passed") is True)
    check(checks, failures, "repeated_validation_complete", readiness.get("repeated_validation_complete") is True)
    check(checks, failures, "repeated_validation_rounds_sufficient", int(repeated.get("round_count") or 0) >= 3)
    passed = _passed(checks, failures)
    report = {
        "schema_version": EXECUTION_CONTEXT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "authorization_summary": authorization_summary,
        "authorization_request": authorization_request,
        "authorization_decision": authorization_decision,
        "authorization_receipt": authorization_receipt,
        "repeated_validation_summary": repeated,
        "task_request": task,
        "source_artifacts": {
            "authorization_summary": artifact_ref(authorization_summary_path),
            "repeated_validation_summary": artifact_ref(repeated_validation_summary_path),
        },
        "boundary": _boundary(context_validation_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def _write_authorization_consumption(*, context: dict[str, Any], authorization_summary_path: Path, output: Path, lease_path: Path, operator_id: str) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    receipt = object_value(context.get("authorization_receipt"))
    task = object_value(context.get("task_request"))
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "receipt_unconsumed", receipt.get("consumed") is False)
    check(checks, failures, "lease_not_already_present", not lease_path.exists())
    check(checks, failures, "operator_id_present", bool(operator_id.strip()))
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
        "single_use_authorization_consumed": passed,
        "lease_path": str(lease_path.resolve()),
        "source_artifacts": {"authorization_summary": artifact_ref(authorization_summary_path)},
        "boundary": _boundary(authorization_consumed=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, consumption)
    if passed:
        write_json_object(lease_path, consumption)
    return consumption


def _write_feedback_index_update(*, context: dict[str, Any], consumption_path: Path, output: Path) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    consumption = _read_json_or_empty(consumption_path, failures, "authorization_consumption")
    repeated = object_value(context.get("repeated_validation_summary"))
    task = object_value(context.get("task_request"))
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "authorization_consumption_passed", consumption.get("passed") is True)
    check(checks, failures, "repeated_validation_passed", repeated.get("passed") is True)
    passed = _passed(checks, failures)
    update = {
        "schema_version": FEEDBACK_INDEX_UPDATE_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "written_at": _now(),
        "feedback_index_update_id": f"post-h3-feedback-index-update:{sha256_json([task.get('task_id'), repeated.get('authorization_ids')])[:24]}",
        "task_id": task.get("task_id"),
        "task_class": task.get("task_class"),
        "update_kind": "operator_feedback_index_update_from_repeated_validation",
        "previous_index_ref": None,
        "rollback_mode": "discard_update_artifact_keep_previous_index",
        "indexed_facts": {
            "repeated_validation_summary_passed": repeated.get("passed") is True,
            "round_count": repeated.get("round_count"),
            "unique_task_id_count": repeated.get("unique_task_id_count"),
            "unique_authorization_id_count": repeated.get("unique_authorization_id_count"),
            "unique_operator_statement_count": repeated.get("unique_operator_statement_count"),
            "fresh_authorization_per_round_verified": object_value(repeated.get("readiness")).get("fresh_authorization_per_round_verified") is True,
            "fresh_authorization_consumed_per_round_verified": object_value(repeated.get("readiness")).get("fresh_authorization_consumed_per_round_verified") is True,
        },
        "source_artifacts": {"authorization_consumption": artifact_ref(consumption_path)},
        "boundary": _boundary(feedback_index_update_written=passed, bounded_task_execution_performed=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, update)
    return update


def _write_execution_receipt(*, context: dict[str, Any], update_path: Path, output: Path) -> dict[str, Any]:
    update = read_json_object(update_path)
    receipt = object_value(context.get("authorization_receipt"))
    passed = update.get("passed") is True
    report = {
        "schema_version": EXECUTION_RECEIPT_SCHEMA,
        "passed": passed,
        "failure_reasons": [] if passed else ["feedback_index_update_not_passed"],
        "checks": {"feedback_index_update_passed": passed},
        "started_at": _now(),
        "completed_at": _now(),
        "execution_id": f"post-h3-feedback-index-update-exec:{sha256_json([receipt.get('authorization_id'), artifact_ref(update_path)])[:24]}",
        "authorization_id": receipt.get("authorization_id"),
        "task_id": update.get("task_id"),
        "execution_kind": "artifact_only_operator_feedback_index_update",
        "output_artifacts": {"feedback_index_update": artifact_ref(update_path)},
        "boundary": _boundary(execution_receipt_written=passed, feedback_index_update_written=passed, bounded_task_execution_performed=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def _write_monitoring_receipt(*, execution_path: Path, update_path: Path, output: Path) -> dict[str, Any]:
    execution = read_json_object(execution_path)
    update = read_json_object(update_path)
    passed = execution.get("passed") is True and update.get("passed") is True
    report = {
        "schema_version": MONITORING_RECEIPT_SCHEMA,
        "passed": passed,
        "failure_reasons": [] if passed else ["operator_feedback_index_update_monitoring_failed"],
        "checks": {"execution_passed": execution.get("passed") is True, "update_passed": update.get("passed") is True},
        "checked_at": _now(),
        "monitoring_id": f"post-h3-feedback-index-update-monitor:{sha256_json([execution.get('execution_id'), artifact_ref(update_path)])[:24]}",
        "task_id": execution.get("task_id"),
        "observations": {
            "feedback_index_update_written": update.get("passed") is True,
            "runtime_worker_started": False,
            "backend_task_pool_mutation_performed": False,
            "external_side_effects_observed": False,
            "anomaly_count": 0 if passed else 1,
        },
        "rollback_required": False if passed else True,
        "source_artifacts": {"execution_receipt": artifact_ref(execution_path), "feedback_index_update": artifact_ref(update_path)},
        "boundary": _boundary(monitoring_receipt_written=passed, bounded_task_execution_performed=execution.get("passed") is True),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def _write_rollback_abort_receipt(*, monitoring_path: Path, output: Path) -> dict[str, Any]:
    monitoring = read_json_object(monitoring_path)
    passed = monitoring.get("passed") is True and object_value(monitoring.get("observations")).get("anomaly_count") == 0
    report = {
        "schema_version": ROLLBACK_ABORT_RECEIPT_SCHEMA,
        "passed": passed,
        "failure_reasons": [] if passed else ["rollback_or_abort_required"],
        "checks": {"monitoring_passed": monitoring.get("passed") is True, "no_anomaly": object_value(monitoring.get("observations")).get("anomaly_count") == 0},
        "checked_at": _now(),
        "rollback_abort_id": f"post-h3-feedback-index-update-rollback-abort:{sha256_json([monitoring.get('monitoring_id'), passed])[:24]}",
        "task_id": monitoring.get("task_id"),
        "decision": "no_rollback_or_abort_required" if passed else "discard_update_artifact_before_strategy_review",
        "rollback_available": True,
        "rollback_performed": False,
        "abort_performed": False,
        "source_artifacts": {"monitoring_receipt": artifact_ref(monitoring_path)},
        "boundary": _boundary(rollback_abort_receipt_written=passed, bounded_task_execution_performed=monitoring.get("passed") is True),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def _write_closeout_receipt(*, execution_path: Path, monitoring_path: Path, rollback_abort_path: Path, output: Path) -> dict[str, Any]:
    execution = read_json_object(execution_path)
    monitoring = read_json_object(monitoring_path)
    rollback_abort = read_json_object(rollback_abort_path)
    passed = execution.get("passed") is True and monitoring.get("passed") is True and rollback_abort.get("passed") is True
    report = {
        "schema_version": CLOSEOUT_RECEIPT_SCHEMA,
        "passed": passed,
        "failure_reasons": [] if passed else ["operator_feedback_index_update_closeout_failed"],
        "checks": {"execution_passed": execution.get("passed") is True, "monitoring_passed": monitoring.get("passed") is True, "rollback_abort_passed": rollback_abort.get("passed") is True},
        "closed_at": _now(),
        "closeout_id": f"post-h3-feedback-index-update-closeout:{sha256_json([execution.get('execution_id'), monitoring.get('monitoring_id'), rollback_abort.get('rollback_abort_id')])[:24]}",
        "task_id": execution.get("task_id"),
        "outcome": "operator_feedback_index_update_closed" if passed else "operator_feedback_index_update_blocked",
        "next_gate": "post_h3_operator_feedback_index_update_strategy_review" if passed else "operator_reconciliation_required",
        "source_artifacts": {"execution_receipt": artifact_ref(execution_path), "monitoring_receipt": artifact_ref(monitoring_path), "rollback_abort_receipt": artifact_ref(rollback_abort_path)},
        "boundary": _boundary(closeout_receipt_written=passed, bounded_task_execution_performed=execution.get("passed") is True),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def _write_strategy_review(*, closeout_path: Path, output: Path, operator_id: str) -> dict[str, Any]:
    closeout = read_json_object(closeout_path)
    passed = closeout.get("passed") is True
    report = {
        "schema_version": STRATEGY_REVIEW_SCHEMA,
        "passed": passed,
        "failure_reasons": [] if passed else ["operator_feedback_index_update_strategy_review_failed"],
        "checks": {"closeout_passed": closeout.get("passed") is True, "operator_id_present": bool(operator_id.strip())},
        "decided_at": _now(),
        "strategy_review_id": f"post-h3-feedback-index-update-strategy:{sha256_json([artifact_ref(closeout_path), operator_id])[:24]}",
        "operator_id": operator_id,
        "decision": "accept_bounded_operator_feedback_index_update_path" if passed else "request_revision",
        "future_execution_requires_fresh_authorization": True,
        "source_artifacts": {"closeout_receipt": artifact_ref(closeout_path)},
        "readiness": {"next_single_use_gate_input_ready": False, "production_task_execution_allowed": False},
        "boundary": _boundary(strategy_review_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def _default_consumption_lease_path(context: dict[str, Any]) -> Path:
    receipt_ref = object_value(object_value(context.get("authorization_summary")).get("artifacts")).get("authorization_receipt")
    receipt_path = Path(str(object_value(receipt_ref).get("path") or "authorization_receipt.json"))
    return receipt_path.with_suffix(receipt_path.suffix + ".post_h3_feedback_index_update_consumed.json")


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


def _write_blocked_summary(*, output: Path, readiness_index_path: Path, repeated_validation_summary_path: Path, failure: str) -> dict[str, Any]:
    summary = {
        "schema_version": CHAIN_SCHEMA,
        "passed": False,
        "failure_reasons": [failure],
        "checks": {failure: False},
        "checked_at": _now(),
        "source_artifacts": {
            "readiness_index": artifact_ref(readiness_index_path) if readiness_index_path.is_file() else {"path": str(readiness_index_path.resolve()), "sha256": ""},
            "repeated_validation_summary": artifact_ref(repeated_validation_summary_path) if repeated_validation_summary_path.is_file() else {"path": str(repeated_validation_summary_path.resolve()), "sha256": ""},
        },
        "readiness": {"operator_feedback_index_update_complete": False, "production_task_execution_allowed": False},
        "boundary": _boundary(),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, summary)
    return summary


def _boundary(**overrides: Any) -> dict[str, Any]:
    boundary = {
        "artifact_only": True,
        "context_validation_written": False,
        "authorization_consumed": False,
        "feedback_index_update_written": False,
        "execution_receipt_written": False,
        "monitoring_receipt_written": False,
        "rollback_abort_receipt_written": False,
        "closeout_receipt_written": False,
        "strategy_review_written": False,
        "bounded_task_execution_performed": False,
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
    parser.add_argument("--readiness-index", type=Path, required=True)
    parser.add_argument("--repeated-validation-summary", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--task-id", default=DEFAULT_TASK_ID)
    parser.add_argument("--operator-id", default="operator-primary")
    parser.add_argument("--ack-bounded-task", action="store_true")
    args = parser.parse_args(argv)
    summary = run_chain(
        readiness_index_path=args.readiness_index,
        repeated_validation_summary_path=args.repeated_validation_summary,
        output_root=args.output_root,
        task_id=args.task_id,
        operator_id=args.operator_id,
        ack_bounded_task=args.ack_bounded_task,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if summary.get("passed") is True else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
