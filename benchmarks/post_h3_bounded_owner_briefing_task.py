"""Run the PostH3 bounded owner briefing task.

This is the third bounded PostH3 task class. It reads already-produced
readiness and operator-feedback repeated-validation evidence, writes an
owner-readable briefing artifact, and then closes monitoring, rollback/abort,
closeout, and strategy review. It is artifact-only: it does not touch backend
state, source/Git, public ingress, deploy, production data, VM targets, or
production runtime receipts.
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
from benchmarks.post_h3_operator_feedback_index_update_repeated_validation import SUMMARY_SCHEMA as FEEDBACK_REPEATED_SCHEMA

CHAIN_SCHEMA = "post-h3-bounded-owner-briefing-chain:v1"
TASK_REQUEST_SCHEMA = "post-h3-bounded-owner-briefing-task-request:v1"
EXECUTION_CONTEXT_SCHEMA = "post-h3-bounded-owner-briefing-execution-context:v1"
AUTHORIZATION_CONSUMPTION_SCHEMA = "post-h3-bounded-owner-briefing-authorization-consumption:v1"
OWNER_BRIEFING_SCHEMA = "post-h3-bounded-owner-briefing:v1"
EXECUTION_RECEIPT_SCHEMA = "post-h3-bounded-owner-briefing-execution-receipt:v1"
MONITORING_RECEIPT_SCHEMA = "post-h3-bounded-owner-briefing-monitoring-receipt:v1"
ROLLBACK_ABORT_RECEIPT_SCHEMA = "post-h3-bounded-owner-briefing-rollback-abort-receipt:v1"
CLOSEOUT_RECEIPT_SCHEMA = "post-h3-bounded-owner-briefing-closeout-receipt:v1"
STRATEGY_REVIEW_SCHEMA = "post-h3-bounded-owner-briefing-strategy-review:v1"

TASK_CLASS = "bounded_owner_briefing"
EXECUTION_GATE_NAME = "post_h3_bounded_owner_briefing_execution_gate"
DEFAULT_TASK_ID = "post-h3-task:bounded-owner-briefing-001"
DEFAULT_OPERATOR_STATEMENT = "Authorize one bounded owner briefing from stable PostH3 evidence only."

NON_CLAIMS = (
    "bounded_owner_briefing_reads_existing_evidence_only",
    "bounded_owner_briefing_writes_artifact_only",
    "bounded_owner_briefing_does_not_start_runtime_workers",
    "bounded_owner_briefing_does_not_mutate_backend_task_pool",
    "bounded_owner_briefing_does_not_open_public_ingress",
    "bounded_owner_briefing_does_not_deploy",
    "bounded_owner_briefing_does_not_contact_vms",
    "bounded_owner_briefing_does_not_access_production_data",
    "bounded_owner_briefing_does_not_write_production_runtime_receipts",
    "bounded_owner_briefing_does_not_write_source_or_git",
)


def run_chain(
    *,
    readiness_index_path: Path,
    feedback_repeated_validation_summary_path: Path,
    output_root: Path,
    task_id: str = DEFAULT_TASK_ID,
    operator_id: str = "operator-primary",
    operator_statement: str = DEFAULT_OPERATOR_STATEMENT,
    ack_bounded_task: bool = False,
) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "task_request": output_root / "post_h3_bounded_owner_briefing_task_request.json",
        "execution_context": output_root / "post_h3_bounded_owner_briefing_execution_context.json",
        "authorization_consumption": output_root / "post_h3_bounded_owner_briefing_authorization_consumption.json",
        "owner_briefing": output_root / "post_h3_bounded_owner_briefing.json",
        "execution_receipt": output_root / "post_h3_bounded_owner_briefing_execution_receipt.json",
        "monitoring_receipt": output_root / "post_h3_bounded_owner_briefing_monitoring_receipt.json",
        "rollback_abort_receipt": output_root / "post_h3_bounded_owner_briefing_rollback_abort_receipt.json",
        "closeout_receipt": output_root / "post_h3_bounded_owner_briefing_closeout_receipt.json",
        "strategy_review": output_root / "post_h3_bounded_owner_briefing_strategy_review.json",
        "summary": output_root / "post_h3_bounded_owner_briefing_summary.json",
    }
    if not ack_bounded_task:
        return _write_blocked_summary(
            output=artifacts["summary"],
            readiness_index_path=readiness_index_path,
            feedback_repeated_validation_summary_path=feedback_repeated_validation_summary_path,
            failure="explicit_bounded_owner_briefing_ack",
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
        operator_statement=operator_statement,
        required_next_gate=EXECUTION_GATE_NAME,
        ack_single_use_authorization=True,
    )
    context = _write_execution_context(
        authorization_summary_path=output_root / "authorization" / "post_h3_minimal_task_authorization_summary.json",
        feedback_repeated_validation_summary_path=feedback_repeated_validation_summary_path,
        output=artifacts["execution_context"],
    )
    consumption = _write_authorization_consumption(
        context=context,
        authorization_summary_path=output_root / "authorization" / "post_h3_minimal_task_authorization_summary.json",
        output=artifacts["authorization_consumption"],
        lease_path=_default_consumption_lease_path(context),
        operator_id=operator_id,
    )
    briefing = _write_owner_briefing(
        context=context,
        consumption_path=artifacts["authorization_consumption"],
        output=artifacts["owner_briefing"],
    )
    execution = _write_execution_receipt(
        context=context,
        briefing_path=artifacts["owner_briefing"],
        output=artifacts["execution_receipt"],
    )
    monitoring = _write_monitoring_receipt(
        execution_path=artifacts["execution_receipt"],
        briefing_path=artifacts["owner_briefing"],
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
    reports = [intake_summary, authorization_summary, context, consumption, briefing, execution, monitoring, rollback_abort, closeout, strategy]
    passed = all(report.get("passed") is True for report in reports)
    summary = {
        "schema_version": CHAIN_SCHEMA,
        "passed": passed,
        "failure_reasons": _failures(reports),
        "checked_at": _now(),
        "task_id": task_id,
        "task_class": TASK_CLASS,
        "operator_statement": operator_statement,
        "operator_statement_sha256": sha256_json(operator_statement),
        "authorization_id": object_value(context.get("authorization_receipt")).get("authorization_id"),
        "source_artifacts": {
            "readiness_index": artifact_ref(readiness_index_path),
            "feedback_repeated_validation_summary": artifact_ref(feedback_repeated_validation_summary_path),
        },
        "artifacts": {name: artifact_ref(path) for name, path in artifacts.items() if name != "summary"},
        "stage_summaries": {
            "intake": artifact_ref(output_root / "intake" / "post_h3_minimal_task_intake_summary.json"),
            "authorization": artifact_ref(output_root / "authorization" / "post_h3_minimal_task_authorization_summary.json"),
        },
        "readiness": {
            "state": "post_h3_bounded_owner_briefing_closed" if passed else "blocked_post_h3_bounded_owner_briefing",
            "bounded_owner_briefing_complete": passed,
            "authorization_consumed": consumption.get("passed") is True,
            "owner_briefing_written": briefing.get("passed") is True,
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
            owner_briefing_written=briefing.get("passed") is True,
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
        "title": "Generate bounded owner briefing from stable PostH3 evidence",
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
            "allowed_outputs": ["owner briefing artifact", "monitoring snapshot"],
            "service_token_scopes": sorted(REQUIRED_SERVICE_TOKEN_SCOPES | {"outcomes:read"}),
            "forbidden_actions": sorted(REQUIRED_FORBIDDEN_ACTIONS),
        },
        "rollback": {
            "owner_id": "rollback_owner",
            "strategy": "abort_or_noop_before_any_external_side_effect",
            "runbook": "If briefing content is out of scope, discard the briefing artifact and keep all prior strategy state unchanged.",
        },
        "success_criteria": [
            "one owner briefing artifact is written",
            "briefing is hash-bound to stable PostH3 evidence",
            "rollback is possible by discarding the briefing artifact",
            "no backend, public ingress, deploy, production data, production receipt, source tree, or Git mutation occurs",
        ],
    }
    write_json_object(path, request)
    return path


def _write_execution_context(*, authorization_summary_path: Path, feedback_repeated_validation_summary_path: Path, output: Path) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    authorization_summary = _read_json_or_empty(authorization_summary_path, failures, "authorization_summary")
    artifacts = object_value(authorization_summary.get("artifacts"))
    authorization_request = _read_verified_ref(artifacts.get("authorization_request"), checks, failures, "authorization_request")
    authorization_decision = _read_verified_ref(artifacts.get("authorization_decision"), checks, failures, "authorization_decision")
    authorization_receipt = _read_verified_ref(artifacts.get("authorization_receipt"), checks, failures, "authorization_receipt")
    feedback_repeated = _read_json_or_empty(feedback_repeated_validation_summary_path, failures, "feedback_repeated_validation_summary")
    task = object_value(authorization_request.get("task_request"))
    readiness = object_value(feedback_repeated.get("readiness"))
    check(checks, failures, "authorization_summary_passed", authorization_summary.get("passed") is True)
    check(checks, failures, "authorization_request_passed", authorization_request.get("passed") is True)
    check(checks, failures, "authorization_decision_passed", authorization_decision.get("passed") is True)
    check(checks, failures, "authorization_receipt_passed", authorization_receipt.get("passed") is True)
    check(checks, failures, "task_class_bounded_owner_briefing", task.get("task_class") == TASK_CLASS)
    check(checks, failures, "required_next_gate_matches", authorization_request.get("required_next_gate") == EXECUTION_GATE_NAME)
    check(checks, failures, "receipt_consumption_required_by_matches", authorization_receipt.get("consumption_required_by") == EXECUTION_GATE_NAME)
    check(checks, failures, "receipt_unconsumed", authorization_receipt.get("consumed") is False)
    check(checks, failures, "feedback_repeated_schema", feedback_repeated.get("schema_version") == FEEDBACK_REPEATED_SCHEMA)
    check(checks, failures, "feedback_repeated_passed", feedback_repeated.get("passed") is True)
    check(checks, failures, "feedback_repeated_complete", readiness.get("operator_feedback_index_update_repeated_validation_complete") is True)
    check(checks, failures, "feedback_repeated_rounds_sufficient", int(feedback_repeated.get("round_count") or 0) >= 3)
    check(checks, failures, "feedback_repeated_closeout_verified", readiness.get("closeout_per_round_verified") is True)
    check(checks, failures, "feedback_repeated_strategy_verified", readiness.get("strategy_review_per_round_verified") is True)
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
        "feedback_repeated_validation_summary": feedback_repeated,
        "task_request": task,
        "source_artifacts": {
            "authorization_summary": artifact_ref(authorization_summary_path),
            "feedback_repeated_validation_summary": artifact_ref(feedback_repeated_validation_summary_path),
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


def _write_owner_briefing(*, context: dict[str, Any], consumption_path: Path, output: Path) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    consumption = _read_json_or_empty(consumption_path, failures, "authorization_consumption")
    feedback_repeated = object_value(context.get("feedback_repeated_validation_summary"))
    task = object_value(context.get("task_request"))
    readiness = object_value(feedback_repeated.get("readiness"))
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "authorization_consumption_passed", consumption.get("passed") is True)
    check(checks, failures, "feedback_repeated_validation_passed", feedback_repeated.get("passed") is True)
    passed = _passed(checks, failures)
    briefing = {
        "schema_version": OWNER_BRIEFING_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "written_at": _now(),
        "owner_briefing_id": f"post-h3-owner-briefing:{sha256_json([task.get('task_id'), feedback_repeated.get('authorization_ids')])[:24]}",
        "task_id": task.get("task_id"),
        "task_class": task.get("task_class"),
        "briefing_kind": "bounded_owner_briefing_from_stable_post_h3_evidence",
        "decision_context": {
            "operator_feedback_update_repeated_validation_passed": feedback_repeated.get("passed") is True,
            "round_count": feedback_repeated.get("round_count"),
            "unique_task_id_count": feedback_repeated.get("unique_task_id_count"),
            "unique_authorization_id_count": feedback_repeated.get("unique_authorization_id_count"),
            "fresh_authorization_per_round_verified": readiness.get("fresh_authorization_per_round_verified") is True,
            "authorization_consumed_per_round_verified": readiness.get("authorization_consumed_per_round_verified") is True,
            "closeout_per_round_verified": readiness.get("closeout_per_round_verified") is True,
            "strategy_review_per_round_verified": readiness.get("strategy_review_per_round_verified") is True,
        },
        "owner_recommendation": {
            "decision": "keep_bounded_artifact_only_path_and_prepare_next_reversible_task" if passed else "request_revision",
            "rationale": [
                "read_only_minimal_path_is_stable",
                "operator_feedback_index_update_is_stable_across_three_rounds",
                "fresh_authorization_and_closeout_are_stable",
                "production_expansion_boundaries_remain_closed",
            ] if passed else [],
            "blocked_expansions": [
                "public_ingress",
                "runtime_expansion_persistence",
                "production_runtime_receipt_write",
                "deploy",
                "source_tree_write",
                "git_write",
                "production_data_access",
            ],
        },
        "rollback_mode": "discard_owner_briefing_artifact_keep_prior_strategy_state",
        "source_artifacts": {"authorization_consumption": artifact_ref(consumption_path)},
        "boundary": _boundary(owner_briefing_written=passed, bounded_task_execution_performed=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, briefing)
    return briefing


def _write_execution_receipt(*, context: dict[str, Any], briefing_path: Path, output: Path) -> dict[str, Any]:
    briefing = read_json_object(briefing_path)
    receipt = object_value(context.get("authorization_receipt"))
    passed = briefing.get("passed") is True
    report = {
        "schema_version": EXECUTION_RECEIPT_SCHEMA,
        "passed": passed,
        "failure_reasons": [] if passed else ["owner_briefing_not_passed"],
        "checks": {"owner_briefing_passed": passed},
        "started_at": _now(),
        "completed_at": _now(),
        "execution_id": f"post-h3-owner-briefing-exec:{sha256_json([receipt.get('authorization_id'), artifact_ref(briefing_path)])[:24]}",
        "authorization_id": receipt.get("authorization_id"),
        "task_id": briefing.get("task_id"),
        "execution_kind": "artifact_only_bounded_owner_briefing",
        "output_artifacts": {"owner_briefing": artifact_ref(briefing_path)},
        "boundary": _boundary(execution_receipt_written=passed, owner_briefing_written=passed, bounded_task_execution_performed=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def _write_monitoring_receipt(*, execution_path: Path, briefing_path: Path, output: Path) -> dict[str, Any]:
    execution = read_json_object(execution_path)
    briefing = read_json_object(briefing_path)
    passed = execution.get("passed") is True and briefing.get("passed") is True
    report = {
        "schema_version": MONITORING_RECEIPT_SCHEMA,
        "passed": passed,
        "failure_reasons": [] if passed else ["bounded_owner_briefing_monitoring_failed"],
        "checks": {"execution_passed": execution.get("passed") is True, "briefing_passed": briefing.get("passed") is True},
        "checked_at": _now(),
        "monitoring_id": f"post-h3-owner-briefing-monitor:{sha256_json([execution.get('execution_id'), artifact_ref(briefing_path)])[:24]}",
        "task_id": execution.get("task_id"),
        "observations": {
            "owner_briefing_written": briefing.get("passed") is True,
            "runtime_worker_started": False,
            "backend_task_pool_mutation_performed": False,
            "external_side_effects_observed": False,
            "anomaly_count": 0 if passed else 1,
        },
        "rollback_required": False if passed else True,
        "source_artifacts": {"execution_receipt": artifact_ref(execution_path), "owner_briefing": artifact_ref(briefing_path)},
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
        "rollback_abort_id": f"post-h3-owner-briefing-rollback-abort:{sha256_json([monitoring.get('monitoring_id'), passed])[:24]}",
        "task_id": monitoring.get("task_id"),
        "decision": "no_rollback_or_abort_required" if passed else "discard_owner_briefing_artifact_before_strategy_review",
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
        "failure_reasons": [] if passed else ["bounded_owner_briefing_closeout_failed"],
        "checks": {"execution_passed": execution.get("passed") is True, "monitoring_passed": monitoring.get("passed") is True, "rollback_abort_passed": rollback_abort.get("passed") is True},
        "closed_at": _now(),
        "closeout_id": f"post-h3-owner-briefing-closeout:{sha256_json([execution.get('execution_id'), monitoring.get('monitoring_id'), rollback_abort.get('rollback_abort_id')])[:24]}",
        "task_id": execution.get("task_id"),
        "outcome": "bounded_owner_briefing_closed" if passed else "bounded_owner_briefing_blocked",
        "next_gate": "post_h3_bounded_owner_briefing_strategy_review" if passed else "operator_reconciliation_required",
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
        "failure_reasons": [] if passed else ["bounded_owner_briefing_strategy_review_failed"],
        "checks": {"closeout_passed": closeout.get("passed") is True, "operator_id_present": bool(operator_id.strip())},
        "decided_at": _now(),
        "strategy_review_id": f"post-h3-owner-briefing-strategy:{sha256_json([artifact_ref(closeout_path), operator_id])[:24]}",
        "operator_id": operator_id,
        "decision": "accept_bounded_owner_briefing_path" if passed else "request_revision",
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
    return receipt_path.with_suffix(receipt_path.suffix + ".post_h3_owner_briefing_consumed.json")


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


def _write_blocked_summary(*, output: Path, readiness_index_path: Path, feedback_repeated_validation_summary_path: Path, failure: str) -> dict[str, Any]:
    summary = {
        "schema_version": CHAIN_SCHEMA,
        "passed": False,
        "failure_reasons": [failure],
        "checks": {failure: False},
        "checked_at": _now(),
        "source_artifacts": {
            "readiness_index": artifact_ref(readiness_index_path) if readiness_index_path.is_file() else {"path": str(readiness_index_path.resolve()), "sha256": ""},
            "feedback_repeated_validation_summary": artifact_ref(feedback_repeated_validation_summary_path) if feedback_repeated_validation_summary_path.is_file() else {"path": str(feedback_repeated_validation_summary_path.resolve()), "sha256": ""},
        },
        "readiness": {"bounded_owner_briefing_complete": False, "production_task_execution_allowed": False},
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
        "owner_briefing_written": False,
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
    parser.add_argument("--feedback-repeated-validation-summary", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--task-id", default=DEFAULT_TASK_ID)
    parser.add_argument("--operator-id", default="operator-primary")
    parser.add_argument("--operator-statement", default=DEFAULT_OPERATOR_STATEMENT)
    parser.add_argument("--ack-bounded-task", action="store_true")
    args = parser.parse_args(argv)
    summary = run_chain(
        readiness_index_path=args.readiness_index,
        feedback_repeated_validation_summary_path=args.feedback_repeated_validation_summary,
        output_root=args.output_root,
        task_id=args.task_id,
        operator_id=args.operator_id,
        operator_statement=args.operator_statement,
        ack_bounded_task=args.ack_bounded_task,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if summary.get("passed") is True else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
