"""Run the reusable minimal PostH3 production task chain.

This runner composes the already-reviewed gates:

intake -> authorization -> execution -> strategy_review

It is intentionally a thin orchestrator. Each stage keeps its own validation,
receipts, and fail-closed boundary. The runner requires an explicit ack and
never reuses a previous single-use authorization receipt.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from benchmarks.i_gate_evidence import artifact_ref, check, object_value, read_json_object, sha256_json, write_json_object
from benchmarks.post_h3_minimal_production_task_authorization_gate import run_gate as run_authorization_gate
from benchmarks.post_h3_minimal_production_task_execution_gate import run_gate as run_execution_gate
from benchmarks.post_h3_minimal_production_task_intake_gate import DEFAULT_TASK_REQUEST, run_gate as run_intake_gate
from benchmarks.post_h3_minimal_production_task_strategy_review_gate import run_gate as run_strategy_review_gate

CHAIN_SCHEMA = "post-h3-minimal-production-task-reusable-chain-run:v1"
TASK_REQUEST_SCHEMA = "post-h3-minimal-production-task-reusable-chain-task-request:v1"

DEFAULT_TASK_ID = "post-h3-task:minimal-production-status-evidence-index-002"
DEFAULT_TITLE = "Generate second minimal production status/evidence index packet"
PREVIOUS_AUTHORIZATION_ID = "post-h3-minimal-task-auth:0edeffe2630a8863:496ccd77fee55a42"

NON_CLAIMS = (
    "minimal_production_task_reusable_chain_runs_one_fresh_task_request_only",
    "minimal_production_task_reusable_chain_does_not_reuse_prior_authorization",
    "minimal_production_task_reusable_chain_does_not_start_runtime_workers",
    "minimal_production_task_reusable_chain_does_not_mutate_backend_task_pool",
    "minimal_production_task_reusable_chain_does_not_open_public_ingress",
    "minimal_production_task_reusable_chain_does_not_deploy",
    "minimal_production_task_reusable_chain_does_not_access_production_data",
    "minimal_production_task_reusable_chain_does_not_write_production_runtime_receipts",
    "minimal_production_task_reusable_chain_does_not_write_source_or_git",
)


def run_chain(
    *,
    readiness_index_path: Path,
    output_root: Path,
    task_request_path: Path | None = None,
    task_id: str = DEFAULT_TASK_ID,
    title: str = DEFAULT_TITLE,
    operator_id: str = "operator-primary",
    previous_authorization_id: str = PREVIOUS_AUTHORIZATION_ID,
    ack_reusable_chain: bool = False,
) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "task_request": output_root / "post_h3_minimal_task_reusable_chain_task_request.json",
        "summary": output_root / "post_h3_minimal_task_reusable_chain_summary.json",
    }
    if not ack_reusable_chain:
        return _write_blocked_summary(
            output=artifacts["summary"],
            readiness_index_path=readiness_index_path,
            failure="explicit_reusable_chain_ack",
        )
    request_path = task_request_path or _write_task_request(artifacts["task_request"], task_id=task_id, title=title)

    intake_summary = run_intake_gate(
        readiness_index_path=readiness_index_path,
        output_root=output_root / "intake",
        task_request_path=request_path,
    )
    if intake_summary.get("passed") is not True:
        return _write_stage_blocked_summary(output=artifacts["summary"], readiness_index_path=readiness_index_path, task_request_path=request_path, stage="intake", stage_summary=intake_summary)

    authorization_summary = run_authorization_gate(
        intake_summary_path=output_root / "intake" / "post_h3_minimal_task_intake_summary.json",
        output_root=output_root / "authorization",
        operator_id=operator_id,
        ack_single_use_authorization=True,
    )
    if authorization_summary.get("passed") is not True:
        return _write_stage_blocked_summary(output=artifacts["summary"], readiness_index_path=readiness_index_path, task_request_path=request_path, stage="authorization", stage_summary=authorization_summary, intake=intake_summary)

    authorization_id = str(authorization_summary.get("authorization", {}).get("authorization_id") or "")
    if previous_authorization_id and authorization_id == previous_authorization_id:
        return _write_stage_blocked_summary(
            output=artifacts["summary"],
            readiness_index_path=readiness_index_path,
            task_request_path=request_path,
            stage="fresh_authorization_check",
            stage_summary=authorization_summary,
            intake=intake_summary,
            extra_failures=["fresh_authorization_id_required"],
        )

    execution_summary = run_execution_gate(
        authorization_summary_path=output_root / "authorization" / "post_h3_minimal_task_authorization_summary.json",
        output_root=output_root / "execution",
        operator_id=operator_id,
        ack_minimal_task_execution=True,
    )
    if execution_summary.get("passed") is not True:
        return _write_stage_blocked_summary(
            output=artifacts["summary"],
            readiness_index_path=readiness_index_path,
            task_request_path=request_path,
            stage="execution",
            stage_summary=execution_summary,
            intake=intake_summary,
            authorization=authorization_summary,
        )

    strategy_summary = run_strategy_review_gate(
        execution_summary_path=output_root / "execution" / "post_h3_minimal_task_execution_summary.json",
        output_root=output_root / "strategy_review",
        operator_id=operator_id,
        ack_strategy_review=True,
    )
    if strategy_summary.get("passed") is not True:
        return _write_stage_blocked_summary(
            output=artifacts["summary"],
            readiness_index_path=readiness_index_path,
            task_request_path=request_path,
            stage="strategy_review",
            stage_summary=strategy_summary,
            intake=intake_summary,
            authorization=authorization_summary,
            execution=execution_summary,
        )

    task = read_json_object(request_path)
    checks: dict[str, bool] = {}
    failures: list[str] = []
    check(checks, failures, "intake_passed", intake_summary.get("passed") is True)
    check(checks, failures, "authorization_passed", authorization_summary.get("passed") is True)
    check(checks, failures, "fresh_authorization_id", bool(authorization_id) and authorization_id != previous_authorization_id)
    check(checks, failures, "execution_passed", execution_summary.get("passed") is True)
    check(checks, failures, "strategy_passed", strategy_summary.get("passed") is True)
    check(checks, failures, "strategy_reusable_ready", object_value(strategy_summary.get("readiness")).get("reusable_minimal_production_path_ready") is True)
    passed = _passed(checks, failures)
    summary = {
        "schema_version": CHAIN_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "task_id": task.get("task_id"),
        "previous_authorization_id": previous_authorization_id,
        "authorization_id": authorization_id,
        "fresh_authorization_observed": authorization_id != previous_authorization_id,
        "stage_summaries": {
            "intake": artifact_ref(output_root / "intake" / "post_h3_minimal_task_intake_summary.json"),
            "authorization": artifact_ref(output_root / "authorization" / "post_h3_minimal_task_authorization_summary.json"),
            "execution": artifact_ref(output_root / "execution" / "post_h3_minimal_task_execution_summary.json"),
            "strategy_review": artifact_ref(output_root / "strategy_review" / "post_h3_minimal_task_strategy_review_summary.json"),
        },
        "source_artifacts": {
            "readiness_index": artifact_ref(readiness_index_path),
            "task_request": artifact_ref(request_path),
        },
        "readiness": {
            "state": "post_h3_minimal_production_task_reusable_chain_passed" if passed else "blocked_post_h3_minimal_production_task_reusable_chain",
            "reusable_chain_complete": passed,
            "fresh_authorization_consumed": object_value(execution_summary.get("readiness")).get("authorization_consumed") is True,
            "reusable_minimal_production_path_ready": object_value(strategy_summary.get("readiness")).get("reusable_minimal_production_path_ready") is True,
            "future_execution_requires_fresh_authorization": True,
            "next_single_use_gate_input_ready": False,
            "production_task_execution_allowed": False,
            "runtime_execution_performed": False,
            "production_runtime_receipt_write_allowed": False,
        },
        "boundary": _boundary(reusable_chain_complete=passed, fresh_authorization_consumed=object_value(execution_summary.get("readiness")).get("authorization_consumed") is True),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(artifacts["summary"], summary)
    return summary


def _write_task_request(path: Path, *, task_id: str, title: str) -> Path:
    request = json.loads(json.dumps(DEFAULT_TASK_REQUEST))
    request["schema_version"] = TASK_REQUEST_SCHEMA
    request["task_id"] = task_id
    request["title"] = title
    request["success_criteria"] = [
        "a fresh single-use authorization is issued for this task request",
        "one bounded status/evidence index packet is generated",
        "execution, monitoring, rollback/abort, closeout, and strategy review all pass",
        "no previous authorization receipt is reused",
        "no production data, public ingress, deploy, Git, source write, or production runtime receipt write occurs",
    ]
    write_json_object(path, request)
    return path


def _write_blocked_summary(*, output: Path, readiness_index_path: Path, failure: str) -> dict[str, Any]:
    summary = {
        "schema_version": CHAIN_SCHEMA,
        "passed": False,
        "failure_reasons": [failure],
        "checks": {failure: False},
        "checked_at": _now(),
        "source_artifacts": {"readiness_index": artifact_ref(readiness_index_path)},
        "readiness": {
            "state": "blocked_post_h3_minimal_production_task_reusable_chain",
            "reusable_chain_complete": False,
            "production_task_execution_allowed": False,
        },
        "boundary": _boundary(),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, summary)
    return summary


def _write_stage_blocked_summary(
    *,
    output: Path,
    readiness_index_path: Path,
    task_request_path: Path,
    stage: str,
    stage_summary: dict[str, Any],
    intake: dict[str, Any] | None = None,
    authorization: dict[str, Any] | None = None,
    execution: dict[str, Any] | None = None,
    extra_failures: list[str] | None = None,
) -> dict[str, Any]:
    failures = _failures([stage_summary]) + list(extra_failures or [])
    summary = {
        "schema_version": CHAIN_SCHEMA,
        "passed": False,
        "failure_reasons": failures,
        "checked_at": _now(),
        "blocked_stage": stage,
        "task_id": _safe_task_id(task_request_path),
        "stage_status": {
            "intake_passed": intake.get("passed") is True if intake else stage_summary.get("passed") is True and stage == "intake",
            "authorization_passed": authorization.get("passed") is True if authorization else False,
            "execution_passed": execution.get("passed") is True if execution else False,
            "current_stage_passed": stage_summary.get("passed") is True,
        },
        "source_artifacts": {
            "readiness_index": artifact_ref(readiness_index_path),
            "task_request": artifact_ref(task_request_path),
        },
        "readiness": {
            "state": "blocked_post_h3_minimal_production_task_reusable_chain",
            "reusable_chain_complete": False,
            "production_task_execution_allowed": False,
            "runtime_execution_performed": False,
            "production_runtime_receipt_write_allowed": False,
        },
        "boundary": _boundary(),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, summary)
    return summary


def _safe_task_id(path: Path) -> str | None:
    try:
        return str(read_json_object(path).get("task_id") or "")
    except Exception:  # noqa: BLE001
        return None


def _boundary(**overrides: Any) -> dict[str, Any]:
    boundary = {
        "reusable_chain_complete": False,
        "fresh_authorization_consumed": False,
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
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--task-request", type=Path)
    parser.add_argument("--task-id", default=DEFAULT_TASK_ID)
    parser.add_argument("--title", default=DEFAULT_TITLE)
    parser.add_argument("--operator-id", default="operator-primary")
    parser.add_argument("--previous-authorization-id", default=PREVIOUS_AUTHORIZATION_ID)
    parser.add_argument("--ack-reusable-chain", action="store_true")
    args = parser.parse_args(argv)
    summary = run_chain(
        readiness_index_path=args.readiness_index,
        output_root=args.output_root,
        task_request_path=args.task_request,
        task_id=args.task_id,
        title=args.title,
        operator_id=args.operator_id,
        previous_authorization_id=args.previous_authorization_id,
        ack_reusable_chain=args.ack_reusable_chain,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if summary.get("passed") is True else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
