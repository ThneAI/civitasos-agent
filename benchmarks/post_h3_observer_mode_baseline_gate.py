"""Freeze the current PostH3 observer-mode closeout as a reusable baseline.

This gate consumes the limited-feedback closeout/strategy summary and verifies
that the only accepted state is continued observer mode with every execution,
deployment, public ingress, production receipt, source, and Git boundary closed.
It is artifact-only and never prepares the next authorization input.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from benchmarks.i_gate_evidence import artifact_ref, check, object_value, read_json_object, sha256_json, write_json_object
from benchmarks.post_h3_limited_external_usage_feedback_closeout_strategy_gate import (
    CHAIN_SCHEMA as LIMITED_FEEDBACK_CLOSEOUT_SCHEMA,
    CONTINUE_OBSERVER_DECISION,
)

SCHEMA_VERSION = "post-h3-observer-mode-baseline-gate:v1"

NON_CLAIMS = (
    "observer_mode_baseline_is_artifact_only",
    "observer_mode_baseline_does_not_authorize_next_execution",
    "observer_mode_baseline_does_not_prepare_higher_permission_review",
    "observer_mode_baseline_does_not_collect_feedback",
    "observer_mode_baseline_does_not_execute_external_user_usage",
    "observer_mode_baseline_does_not_open_public_ingress",
    "observer_mode_baseline_does_not_start_runtime_workers",
    "observer_mode_baseline_does_not_contact_vm_targets",
    "observer_mode_baseline_does_not_deploy",
    "observer_mode_baseline_does_not_access_production_data",
    "observer_mode_baseline_does_not_write_production_runtime_receipts",
    "observer_mode_baseline_does_not_write_source_or_git",
)


def run_gate(*, closeout_strategy_summary_path: Path, output_root: Path, ack_baseline: bool = False) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    output = output_root / "post_h3_observer_mode_baseline_summary.json"
    checks: dict[str, bool] = {}
    failures: list[str] = []
    summary = _read_closeout(closeout_strategy_summary_path, checks, failures)
    readiness = object_value(summary.get("readiness"))
    boundary = object_value(summary.get("boundary"))

    check(checks, failures, "explicit_baseline_ack", ack_baseline is True)
    check(checks, failures, "closeout_schema", summary.get("schema_version") == LIMITED_FEEDBACK_CLOSEOUT_SCHEMA)
    check(checks, failures, "closeout_passed", summary.get("passed") is True)
    check(checks, failures, "operator_decision_continues_observer", summary.get("operator_decision") == CONTINUE_OBSERVER_DECISION)
    check(checks, failures, "summary_observer_mode_continues", summary.get("observer_mode_continues") is True)
    check(checks, failures, "summary_higher_permission_not_ready", summary.get("higher_permission_review_request_ready") is False)
    check(checks, failures, "summary_revision_not_required", summary.get("revision_required") is False)
    _check_readiness(readiness, checks, failures)
    _check_boundary(boundary, checks, failures)

    passed = bool(checks) and all(checks.values()) and not failures
    report = {
        "schema_version": SCHEMA_VERSION,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "baseline_id": f"post-h3-observer-baseline:{sha256_json([artifact_ref(closeout_strategy_summary_path), summary.get('limited_feedback_closeout_strategy_id')])[:24]}"
        if closeout_strategy_summary_path.is_file()
        else "",
        "source_artifacts": {
            "limited_feedback_closeout_strategy_summary": artifact_ref(closeout_strategy_summary_path)
            if closeout_strategy_summary_path.is_file()
            else {"path": str(closeout_strategy_summary_path.resolve()), "sha256": ""},
        },
        "readiness": {
            "state": "post_h3_observer_mode_baseline_ready" if passed else "blocked_post_h3_observer_mode_baseline",
            "post_h3_observer_mode_baseline_ready": passed,
            "observer_mode_continues": passed,
            "higher_permission_review_request_ready": False,
            "next_single_use_gate_input_ready": False,
            "external_user_usage_allowed": False,
            "external_user_usage_execution_ready": False,
            "additional_feedback_collection_ready": False,
            "public_ingress_authorized": False,
            "runtime_expansion_authorized": False,
            "runtime_execution_performed": False,
            "production_runtime_receipt_write_allowed": False,
        },
        "boundary": _boundary(baseline_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def _read_closeout(path: Path, checks: dict[str, bool], failures: list[str]) -> dict[str, Any]:
    check(checks, failures, "closeout_summary_present", path.is_file())
    if not path.is_file():
        return {}
    try:
        return read_json_object(path)
    except Exception as exc:  # noqa: BLE001
        failures.append(f"closeout_summary_unreadable:{exc}")
        return {}


def _check_readiness(readiness: dict[str, Any], checks: dict[str, bool], failures: list[str]) -> None:
    expected_true = (
        "limited_feedback_closeout_strategy_complete",
        "limited_feedback_execution_closed",
        "limited_feedback_evidence_index_complete",
        "strategy_review_complete",
        "observer_mode_continues",
    )
    expected_false = (
        "higher_permission_review_request_ready",
        "revision_required",
        "next_single_use_gate_input_ready",
        "additional_feedback_collection_ready",
        "external_user_usage_allowed",
        "external_user_usage_execution_ready",
        "external_public_ingress_opened",
        "runtime_execution_performed",
        "production_runtime_receipt_write_allowed",
    )
    check(checks, failures, "readiness_state_observer_mode", readiness.get("state") == "limited_feedback_observer_mode_continues")
    for key in expected_true:
        check(checks, failures, f"readiness_{key}_true", readiness.get(key) is True)
    for key in expected_false:
        check(checks, failures, f"readiness_{key}_false", readiness.get(key) is False)


def _check_boundary(boundary: dict[str, Any], checks: dict[str, bool], failures: list[str]) -> None:
    expected_true = (
        "context_validation_written",
        "evidence_index_written",
        "strategy_packet_written",
        "strategy_reconciliation_written",
        "boundary_report_written",
        "limited_feedback_execution_closed",
        "limited_feedback_closeout_strategy_complete",
        "observer_mode_continues",
    )
    expected_false = (
        "higher_permission_review_request_ready",
        "next_single_use_gate_input_ready",
        "additional_feedback_collection_ready",
        "external_user_usage_allowed",
        "external_user_usage_execution_ready",
        "external_user_usage_performed",
        "external_public_ingress_opened",
        "runtime_workers_currently_running",
        "runtime_execution_performed",
        "vm_contact_performed",
        "deploy_performed",
        "production_data_accessed",
        "production_runtime_receipt_write_allowed",
        "source_tree_write_performed",
        "git_write_performed",
        "secrets_recorded",
    )
    for key in expected_true:
        check(checks, failures, f"boundary_{key}_true", boundary.get(key) is True)
    for key in expected_false:
        check(checks, failures, f"boundary_{key}_false", boundary.get(key) is False)


def _boundary(*, baseline_written: bool) -> dict[str, Any]:
    return {
        "artifact_only": True,
        "baseline_written": baseline_written,
        "higher_permission_review_request_ready": False,
        "next_single_use_gate_input_ready": False,
        "external_user_usage_allowed": False,
        "external_user_usage_execution_ready": False,
        "external_user_usage_performed": False,
        "external_public_ingress_opened": False,
        "runtime_workers_currently_running": False,
        "runtime_execution_performed": False,
        "vm_contact_performed": False,
        "deploy_performed": False,
        "production_data_accessed": False,
        "production_runtime_receipt_write_allowed": False,
        "production_runtime_receipt_written": False,
        "source_tree_write_performed": False,
        "git_write_performed": False,
        "secrets_recorded": False,
    }


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--closeout-strategy-summary", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--ack-baseline", action="store_true")
    args = parser.parse_args(argv)
    report = run_gate(
        closeout_strategy_summary_path=args.closeout_strategy_summary,
        output_root=args.output_root,
        ack_baseline=args.ack_baseline,
    )
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report.get("passed") is True else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
