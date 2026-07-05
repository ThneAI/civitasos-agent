"""Build a stability index for the minimal PostH3 production task path.

The index consumes one or more repeated-validation summaries and checks that
the read-only path remains stable across task ids, operator statements, fresh
single-use authorizations, consumption leases, monitoring, rollback/abort,
closeout, and strategy review. It is artifact-only and never authorizes a new
execution.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from benchmarks.i_gate_evidence import artifact_ref, check, object_value, read_json_object, write_json_object
from benchmarks.post_h3_minimal_production_task_repeated_validation import SUMMARY_SCHEMA as REPEATED_VALIDATION_SCHEMA

SCHEMA_VERSION = "post-h3-minimal-production-task-path-stability-index:v1"

NON_CLAIMS = (
    "minimal_production_task_path_stability_index_is_artifact_only",
    "minimal_production_task_path_stability_index_does_not_authorize_execution",
    "minimal_production_task_path_stability_index_does_not_start_runtime_workers",
    "minimal_production_task_path_stability_index_does_not_mutate_backend_task_pool",
    "minimal_production_task_path_stability_index_does_not_open_public_ingress",
    "minimal_production_task_path_stability_index_does_not_deploy",
    "minimal_production_task_path_stability_index_does_not_access_production_data",
    "minimal_production_task_path_stability_index_does_not_write_production_runtime_receipts",
    "minimal_production_task_path_stability_index_does_not_write_source_or_git",
)


def build_index(
    *,
    repeated_validation_summary_paths: list[Path],
    output: Path,
    min_summary_count: int = 1,
    min_total_rounds: int = 3,
) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    reports = [_read_report(path, checks, failures, f"repeated_validation_{index}") for index, path in enumerate(repeated_validation_summary_paths, start=1)]
    reports = [report for report in reports if report]
    authorization_ids = _collect_unique(reports, "authorization_ids")
    task_ids = _collect_unique(reports, "task_ids")
    total_rounds = sum(int(report.get("round_count") or 0) for report in reports)
    check(checks, failures, "summary_count_meets_threshold", len(reports) >= min_summary_count)
    check(checks, failures, "total_rounds_meet_threshold", total_rounds >= min_total_rounds)
    check(checks, failures, "all_summaries_passed", bool(reports) and all(report.get("passed") is True for report in reports))
    check(checks, failures, "all_summaries_schema_valid", bool(reports) and all(report.get("schema_version") == REPEATED_VALIDATION_SCHEMA for report in reports))
    check(checks, failures, "all_rounds_passed", bool(reports) and all(object_value(report.get("checks")).get("all_rounds_passed") is True for report in reports))
    check(checks, failures, "fresh_authorization_observed", bool(reports) and all(object_value(report.get("checks")).get("fresh_authorization_observed_all_rounds") is True for report in reports))
    check(checks, failures, "fresh_authorization_consumed", bool(reports) and all(object_value(report.get("checks")).get("fresh_authorization_consumed_all_rounds") is True for report in reports))
    check(checks, failures, "strategy_review_ready", bool(reports) and all(object_value(report.get("checks")).get("strategy_review_ready_all_rounds") is True for report in reports))
    check(checks, failures, "production_boundary_closed", bool(reports) and all(object_value(report.get("checks")).get("production_boundary_closed_all_rounds") is True for report in reports))
    check(checks, failures, "authorization_ids_unique_across_summaries", len(authorization_ids) == sum(len(_texts(report.get("authorization_ids"))) for report in reports))
    check(checks, failures, "task_ids_unique_across_summaries", len(task_ids) == sum(len(_texts(report.get("task_ids"))) for report in reports))
    passed = bool(checks) and all(checks.values()) and not failures
    report = {
        "schema_version": SCHEMA_VERSION,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "summary_count": len(reports),
        "total_rounds": total_rounds,
        "unique_task_id_count": len(task_ids),
        "unique_authorization_id_count": len(authorization_ids),
        "repeated_validation_summaries": [artifact_ref(path) for path in repeated_validation_summary_paths if path.is_file()],
        "readiness": {
            "state": "post_h3_minimal_production_task_path_stable" if passed else "blocked_post_h3_minimal_production_task_path_stability",
            "minimal_production_task_path_stable": passed,
            "fresh_authorization_per_round_verified": checks.get("fresh_authorization_observed") is True,
            "fresh_authorization_consumed_per_round_verified": checks.get("fresh_authorization_consumed") is True,
            "monitoring_rollback_closeout_strategy_verified": checks.get("strategy_review_ready") is True,
            "production_task_execution_allowed": False,
            "next_single_use_gate_input_ready": False,
            "runtime_execution_performed": False,
            "production_runtime_receipt_write_allowed": False,
        },
        "boundary": _boundary(stability_index_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def _read_report(path: Path, checks: dict[str, bool], failures: list[str], label: str) -> dict[str, Any] | None:
    check(checks, failures, f"{label}_present", path.is_file())
    if not path.is_file():
        return None
    try:
        return read_json_object(path)
    except Exception as exc:  # noqa: BLE001
        failures.append(f"{label}_unreadable:{exc}")
        return None


def _collect_unique(reports: list[dict[str, Any]], key: str) -> list[str]:
    values: list[str] = []
    for report in reports:
        for value in _texts(report.get(key)):
            if value not in values:
                values.append(value)
    return values


def _texts(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    result: list[str] = []
    for item in value:
        text = str(item).strip()
        if text:
            result.append(text)
    return result


def _boundary(**overrides: Any) -> dict[str, Any]:
    boundary = {
        "artifact_only": True,
        "stability_index_written": False,
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


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repeated-validation-summary", type=Path, action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--min-summary-count", type=int, default=1)
    parser.add_argument("--min-total-rounds", type=int, default=3)
    args = parser.parse_args(argv)
    report = build_index(
        repeated_validation_summary_paths=args.repeated_validation_summary,
        output=args.output,
        min_summary_count=args.min_summary_count,
        min_total_rounds=args.min_total_rounds,
    )
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report.get("passed") is True else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
