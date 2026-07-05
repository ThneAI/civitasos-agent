"""Run repeated validation for the PostH3 bounded owner briefing task.

This runner executes multiple independent bounded owner briefing requests. Each
round uses a distinct task id and operator statement, consumes a fresh
single-use authorization, and must close execution, monitoring, rollback/abort,
closeout, and strategy review while keeping all production expansion boundaries
closed.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from benchmarks.i_gate_evidence import artifact_ref, check, object_value, sha256_json, write_json_object
from benchmarks.post_h3_bounded_owner_briefing_task import run_chain as run_owner_briefing

SUMMARY_SCHEMA = "post-h3-bounded-owner-briefing-repeated-validation:v1"
ROUND_SCHEMA = "post-h3-bounded-owner-briefing-repeated-validation-round:v1"

DEFAULT_TASK_ID_PREFIX = "post-h3-task:bounded-owner-briefing"
DEFAULT_OPERATOR_STATEMENT_TEMPLATE = (
    "Round {round}: authorize one bounded owner briefing for {task_id}; "
    "require fresh authorization, single-use consumption, owner briefing artifact, "
    "monitoring, rollback/abort, closeout, strategy review, and no external side effects."
)

NON_CLAIMS = (
    "bounded_owner_briefing_repeated_validation_runs_artifact_only_briefings",
    "bounded_owner_briefing_repeated_validation_requires_fresh_authorization_per_round",
    "bounded_owner_briefing_repeated_validation_does_not_start_runtime_workers",
    "bounded_owner_briefing_repeated_validation_does_not_mutate_backend_task_pool",
    "bounded_owner_briefing_repeated_validation_does_not_open_public_ingress",
    "bounded_owner_briefing_repeated_validation_does_not_deploy",
    "bounded_owner_briefing_repeated_validation_does_not_contact_vms",
    "bounded_owner_briefing_repeated_validation_does_not_access_production_data",
    "bounded_owner_briefing_repeated_validation_does_not_write_production_runtime_receipts",
    "bounded_owner_briefing_repeated_validation_does_not_write_source_or_git",
)


def run_repeated_validation(
    *,
    readiness_index_path: Path,
    feedback_repeated_validation_summary_path: Path,
    output_root: Path,
    rounds: int = 3,
    start_index: int = 2,
    task_id_prefix: str = DEFAULT_TASK_ID_PREFIX,
    operator_id: str = "operator-primary",
    operator_statement_template: str = DEFAULT_OPERATOR_STATEMENT_TEMPLATE,
    ack_repeated_validation: bool = False,
) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    summary_path = output_root / "post_h3_bounded_owner_briefing_repeated_validation_summary.json"
    if not ack_repeated_validation:
        return _write_blocked_summary(
            output=summary_path,
            readiness_index_path=readiness_index_path,
            feedback_repeated_validation_summary_path=feedback_repeated_validation_summary_path,
            failure="explicit_bounded_owner_briefing_repeated_validation_ack",
            rounds=rounds,
        )
    if rounds < 1:
        return _write_blocked_summary(
            output=summary_path,
            readiness_index_path=readiness_index_path,
            feedback_repeated_validation_summary_path=feedback_repeated_validation_summary_path,
            failure="positive_round_count_required",
            rounds=rounds,
        )
    if start_index < 0:
        return _write_blocked_summary(
            output=summary_path,
            readiness_index_path=readiness_index_path,
            feedback_repeated_validation_summary_path=feedback_repeated_validation_summary_path,
            failure="non_negative_start_index_required",
            rounds=rounds,
        )

    round_reports: list[dict[str, Any]] = []
    previous_authorization_ids: set[str] = set()
    for offset in range(rounds):
        round_number = offset + 1
        task_index = start_index + offset
        task_id = f"{task_id_prefix}-{task_index:03d}"
        operator_statement = _render_operator_statement_template(
            operator_statement_template,
            round_number=round_number,
            task_id=task_id,
            task_index=task_index,
        )
        round_root = output_root / f"round_{round_number:03d}"
        chain_summary = run_owner_briefing(
            readiness_index_path=readiness_index_path,
            feedback_repeated_validation_summary_path=feedback_repeated_validation_summary_path,
            output_root=round_root,
            task_id=task_id,
            operator_id=operator_id,
            operator_statement=operator_statement,
            ack_bounded_task=True,
        )
        round_report = _round_report(
            round_number=round_number,
            task_id=task_id,
            chain_summary=chain_summary,
            chain_summary_path=round_root / "post_h3_bounded_owner_briefing_summary.json",
            operator_statement=operator_statement,
            previous_authorization_ids=previous_authorization_ids,
        )
        write_json_object(round_root / "post_h3_bounded_owner_briefing_repeated_validation_round.json", round_report)
        round_reports.append(round_report)
        authorization_id = str(chain_summary.get("authorization_id") or "")
        if authorization_id:
            previous_authorization_ids.add(authorization_id)
        if chain_summary.get("passed") is not True:
            break

    checks: dict[str, bool] = {}
    failures: list[str] = []
    task_ids = [str(report.get("task_id") or "") for report in round_reports]
    authorization_ids = [str(report.get("authorization_id") or "") for report in round_reports if report.get("authorization_id")]
    statement_hashes = [str(report.get("operator_statement_sha256") or "") for report in round_reports]
    boundaries = [object_value(report.get("boundary")) for report in round_reports]
    readiness_values = [object_value(report.get("readiness")) for report in round_reports]
    check(checks, failures, "all_requested_rounds_completed", len(round_reports) == rounds)
    check(checks, failures, "all_rounds_passed", len(round_reports) == rounds and all(report.get("passed") is True for report in round_reports))
    check(checks, failures, "task_ids_unique", len(task_ids) == rounds and len(set(task_ids)) == rounds)
    check(checks, failures, "operator_statements_unique", len(statement_hashes) == rounds and len(set(statement_hashes)) == rounds)
    check(checks, failures, "authorization_ids_unique", len(authorization_ids) == rounds and len(set(authorization_ids)) == rounds)
    check(checks, failures, "fresh_authorization_observed_all_rounds", len(round_reports) == rounds and all(report.get("fresh_authorization_observed") is True for report in round_reports))
    check(checks, failures, "authorization_consumed_all_rounds", len(readiness_values) == rounds and all(readiness.get("authorization_consumed") is True for readiness in readiness_values))
    check(checks, failures, "owner_briefing_written_all_rounds", len(readiness_values) == rounds and all(readiness.get("owner_briefing_written") is True for readiness in readiness_values))
    check(checks, failures, "closeout_written_all_rounds", len(readiness_values) == rounds and all(readiness.get("closeout_receipt_written") is True for readiness in readiness_values))
    check(checks, failures, "strategy_review_complete_all_rounds", len(readiness_values) == rounds and all(readiness.get("strategy_review_complete") is True for readiness in readiness_values))
    check(checks, failures, "production_boundary_closed_all_rounds", len(boundaries) == rounds and all(_boundary_closed(boundary) for boundary in boundaries))
    passed = bool(checks) and all(checks.values()) and not failures
    summary = {
        "schema_version": SUMMARY_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "round_count": len(round_reports),
        "requested_round_count": rounds,
        "start_index": start_index,
        "task_id_prefix": task_id_prefix,
        "task_ids": task_ids,
        "authorization_ids": authorization_ids,
        "unique_task_id_count": len(set(task_ids)),
        "unique_authorization_id_count": len(set(authorization_ids)),
        "unique_operator_statement_count": len(set(statement_hashes)),
        "rounds": round_reports,
        "source_artifacts": {
            "readiness_index": artifact_ref(readiness_index_path),
            "feedback_repeated_validation_summary": artifact_ref(feedback_repeated_validation_summary_path),
        },
        "readiness": {
            "state": "post_h3_bounded_owner_briefing_repeated_validation_passed" if passed else "blocked_post_h3_bounded_owner_briefing_repeated_validation",
            "bounded_owner_briefing_repeated_validation_complete": passed,
            "fresh_authorization_per_round_verified": checks.get("fresh_authorization_observed_all_rounds") is True,
            "authorization_consumed_per_round_verified": checks.get("authorization_consumed_all_rounds") is True,
            "owner_briefing_per_round_verified": checks.get("owner_briefing_written_all_rounds") is True,
            "closeout_per_round_verified": checks.get("closeout_written_all_rounds") is True,
            "strategy_review_per_round_verified": checks.get("strategy_review_complete_all_rounds") is True,
            "higher_permission_authorization_review_input_ready": passed,
            "future_execution_requires_fresh_authorization": True,
            "production_task_execution_allowed": False,
            "runtime_execution_performed": False,
            "production_runtime_receipt_write_allowed": False,
        },
        "boundary": _summary_boundary(passed=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(summary_path, summary)
    return summary


def _round_report(
    *,
    round_number: int,
    task_id: str,
    chain_summary: dict[str, Any],
    chain_summary_path: Path,
    operator_statement: str,
    previous_authorization_ids: set[str],
) -> dict[str, Any]:
    readiness = object_value(chain_summary.get("readiness"))
    boundary = object_value(chain_summary.get("boundary"))
    authorization_id = str(chain_summary.get("authorization_id") or "")
    fresh_authorization_observed = bool(authorization_id) and authorization_id not in previous_authorization_ids
    passed = (
        chain_summary.get("passed") is True
        and fresh_authorization_observed
        and readiness.get("authorization_consumed") is True
        and readiness.get("owner_briefing_written") is True
        and readiness.get("closeout_receipt_written") is True
        and readiness.get("strategy_review_complete") is True
        and _boundary_closed(boundary)
    )
    return {
        "schema_version": ROUND_SCHEMA,
        "passed": passed,
        "failure_reasons": [] if passed else _round_failures(chain_summary, authorization_id, fresh_authorization_observed, readiness, boundary),
        "round": round_number,
        "task_id": task_id,
        "authorization_id": authorization_id,
        "fresh_authorization_observed": fresh_authorization_observed,
        "operator_statement": operator_statement,
        "operator_statement_sha256": sha256_json(operator_statement),
        "readiness": readiness,
        "boundary": boundary,
        "source_artifacts": {"chain_summary": artifact_ref(chain_summary_path)},
    }


def _render_operator_statement_template(
    template: str,
    *,
    round_number: int,
    task_id: str,
    task_index: int,
) -> str:
    token_rendered = (
        template.replace("__ROUND__", str(round_number))
        .replace("__TASK_ID__", task_id)
        .replace("__TASK_INDEX__", str(task_index))
    )
    try:
        return token_rendered.format(round=round_number, task_id=task_id, task_index=task_index)
    except (KeyError, ValueError):
        return token_rendered


def _round_failures(
    chain_summary: dict[str, Any],
    authorization_id: str,
    fresh_authorization_observed: bool,
    readiness: dict[str, Any],
    boundary: dict[str, Any],
) -> list[str]:
    failures: list[str] = []
    if chain_summary.get("passed") is not True:
        failures.extend(str(item) for item in chain_summary.get("failure_reasons", []) if isinstance(item, str))
        failures.append("bounded_owner_briefing_chain_failed")
    if not authorization_id:
        failures.append("authorization_id_missing")
    if not fresh_authorization_observed:
        failures.append("authorization_id_reused")
    if readiness.get("authorization_consumed") is not True:
        failures.append("authorization_not_consumed")
    if readiness.get("owner_briefing_written") is not True:
        failures.append("owner_briefing_not_written")
    if readiness.get("closeout_receipt_written") is not True:
        failures.append("closeout_not_written")
    if readiness.get("strategy_review_complete") is not True:
        failures.append("strategy_review_not_complete")
    if not _boundary_closed(boundary):
        failures.append("production_boundary_not_closed")
    return sorted(set(failures))


def _boundary_closed(boundary: dict[str, Any]) -> bool:
    required_true = (
        "artifact_only",
        "context_validation_written",
        "authorization_consumed",
        "owner_briefing_written",
        "execution_receipt_written",
        "monitoring_receipt_written",
        "rollback_abort_receipt_written",
        "closeout_receipt_written",
        "strategy_review_written",
        "bounded_task_execution_performed",
    )
    required_false = (
        "production_task_execution_allowed",
        "next_single_use_gate_input_ready",
        "runtime_execution_performed",
        "runtime_workers_currently_running",
        "backend_task_pool_mutation_performed",
        "external_public_ingress_opened",
        "deploy_performed",
        "vm_contact_performed",
        "production_data_accessed",
        "production_runtime_receipt_write_allowed",
        "production_runtime_receipt_written",
        "source_tree_write_performed",
        "git_write_performed",
        "secrets_recorded",
    )
    return all(boundary.get(key) is True for key in required_true) and all(boundary.get(key) is False for key in required_false)


def _summary_boundary(*, passed: bool = False) -> dict[str, Any]:
    return {
        "bounded_owner_briefing_repeated_validation_complete": passed,
        "higher_permission_authorization_review_input_ready": passed,
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


def _write_blocked_summary(
    *,
    output: Path,
    readiness_index_path: Path,
    feedback_repeated_validation_summary_path: Path,
    failure: str,
    rounds: int,
) -> dict[str, Any]:
    summary = {
        "schema_version": SUMMARY_SCHEMA,
        "passed": False,
        "failure_reasons": [failure],
        "checks": {failure: False},
        "checked_at": _now(),
        "requested_round_count": rounds,
        "round_count": 0,
        "source_artifacts": {
            "readiness_index": artifact_ref(readiness_index_path) if readiness_index_path.exists() else {"path": str(readiness_index_path.resolve()), "sha256": ""},
            "feedback_repeated_validation_summary": artifact_ref(feedback_repeated_validation_summary_path) if feedback_repeated_validation_summary_path.exists() else {"path": str(feedback_repeated_validation_summary_path.resolve()), "sha256": ""},
        },
        "readiness": {
            "state": "blocked_post_h3_bounded_owner_briefing_repeated_validation",
            "bounded_owner_briefing_repeated_validation_complete": False,
            "higher_permission_authorization_review_input_ready": False,
            "production_task_execution_allowed": False,
            "runtime_execution_performed": False,
            "production_runtime_receipt_write_allowed": False,
        },
        "boundary": _summary_boundary(),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, summary)
    return summary


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--readiness-index", type=Path, required=True)
    parser.add_argument("--feedback-repeated-validation-summary", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--start-index", type=int, default=2)
    parser.add_argument("--task-id-prefix", default=DEFAULT_TASK_ID_PREFIX)
    parser.add_argument("--operator-id", default="operator-primary")
    parser.add_argument("--operator-statement-template", default=DEFAULT_OPERATOR_STATEMENT_TEMPLATE)
    parser.add_argument("--ack-repeated-validation", action="store_true")
    args = parser.parse_args(argv)
    summary = run_repeated_validation(
        readiness_index_path=args.readiness_index,
        feedback_repeated_validation_summary_path=args.feedback_repeated_validation_summary,
        output_root=args.output_root,
        rounds=args.rounds,
        start_index=args.start_index,
        task_id_prefix=args.task_id_prefix,
        operator_id=args.operator_id,
        operator_statement_template=args.operator_statement_template,
        ack_repeated_validation=args.ack_repeated_validation,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if summary.get("passed") is True else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
