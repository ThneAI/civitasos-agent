#!/usr/bin/env python3
"""Inspect and index Beta-3 source-apply execution outcomes.

This observability script consumes source-apply execution reports after the
Beta-3 executor runs. It validates report boundaries and any hash-bound
post-source-apply receipt, then writes summary/index artifacts. It never
applies patches or performs Git publication actions.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from beta3_source_apply_executor import EXECUTION_SCHEMA
from beta3_source_apply_executor import validate_post_source_apply_receipt


OUTCOME_SCHEMA = "beta3-source-apply-outcome:v1"
SUMMARY_SCHEMA = "beta3-source-apply-outcome-summary:v1"
INDEX_SCHEMA = "beta3-source-apply-outcome-index-entry:v1"
SOURCE_APPLY_OUTCOMES = (
    "authorization_refused",
    "applied_tests_passed",
    "applied_without_tests",
    "applied_tests_failed",
    "apply_check_refused",
    "apply_failed",
    "blocked_before_verified_apply",
)
NON_CLAIMS = (
    "beta3_source_apply_outcome_is_l1_observability_only",
    "beta3_source_apply_outcome_does_not_apply_patch",
    "beta3_source_apply_outcome_does_not_authorize_commit_push_merge_or_deploy",
    "beta3_source_apply_outcome_does_not_claim_h3_production_readiness",
    "beta3_source_apply_outcome_does_not_write_production_receipts",
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    inspect = subparsers.add_parser("inspect", help="inspect one source-apply execution report")
    inspect.add_argument("--execution-report", required=True)
    inspect.add_argument("--output")

    summarize = subparsers.add_parser("summarize", help="summarize execution reports")
    summarize.add_argument("--execution-report", action="append", required=True)
    summarize.add_argument("--output")

    index = subparsers.add_parser("index", help="write summary plus compact JSONL/latest entry")
    index.add_argument("--execution-report", action="append", required=True)
    index.add_argument("--summary-output", required=True)
    index.add_argument("--index-output", required=True)
    index.add_argument("--latest-output", required=True)

    args = parser.parse_args(argv)
    if args.command == "inspect":
        report = inspect_source_apply_outcome(Path(args.execution_report))
    elif args.command == "summarize":
        report = summarize_source_apply_outcomes([Path(path) for path in args.execution_report])
    elif args.command == "index":
        report = index_source_apply_outcomes(
            [Path(path) for path in args.execution_report],
            summary_output=Path(args.summary_output),
            index_output=Path(args.index_output),
            latest_output=Path(args.latest_output),
        )
    else:
        raise AssertionError(f"unknown command: {args.command}")
    output = getattr(args, "output", None)
    if output:
        _write_json(Path(output), report)
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report["passed"] else 1


def inspect_source_apply_outcome(execution_report_path: Path) -> dict[str, Any]:
    failures: list[str] = []
    execution = _read_json_object(execution_report_path, failures, "source apply execution report")
    if execution.get("schema_version") != EXECUTION_SCHEMA:
        failures.append(f"execution report schema_version must be {EXECUTION_SCHEMA}")
    outcome = execution.get("source_apply_outcome")
    if outcome not in SOURCE_APPLY_OUTCOMES:
        failures.append(f"source_apply_outcome must be one of {list(SOURCE_APPLY_OUTCOMES)}")
    _validate_false_boundary_flags(execution, failures)
    _validate_h3_boundary(execution, failures)
    _validate_outcome_shape(execution, failures)
    receipt_path = _receipt_path(execution.get("post_apply_receipt_path"), failures)
    receipt_validation = validate_post_source_apply_receipt(receipt_path) if receipt_path else None
    if receipt_validation and receipt_validation["passed"] is not True:
        failures.extend(f"post-source-apply receipt invalid: {reason}" for reason in receipt_validation["failure_reasons"])
    _validate_receipt_presence(execution, receipt_path, failures)
    operator_followup = execution.get("operator_followup")
    if not isinstance(operator_followup, dict):
        failures.append("operator_followup must be an object")
        operator_followup = {}
    rollback_required = operator_followup.get("rollback_decision_required") is True
    return {
        "schema_version": OUTCOME_SCHEMA,
        "passed": not failures,
        "failure_reasons": failures,
        "checked_at": _now(),
        "execution_report": _artifact_ref_if_file(execution_report_path),
        "source_apply_passed": execution.get("passed") is True,
        "source_apply_outcome": outcome,
        "source_repo_apply_performed": execution.get("source_repo_apply_performed") is True,
        "test_evidence_status": execution.get("test_evidence_status"),
        "failure_codes": _string_list(execution.get("failure_codes")),
        "rollback_decision_required": rollback_required,
        "operator_followup_required": operator_followup.get("required") is True,
        "post_apply_receipt_path": str(receipt_path.resolve()) if receipt_path else None,
        "post_apply_receipt_validation": receipt_validation,
        "commit_allowed": False,
        "push_allowed": False,
        "merge_allowed": False,
        "deploy_allowed": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
        "non_claims": list(NON_CLAIMS),
    }


def summarize_source_apply_outcomes(execution_reports: list[Path]) -> dict[str, Any]:
    reports = [inspect_source_apply_outcome(path) for path in execution_reports]
    failures = [
        f"{report['execution_report']['path']}: {reason}"
        for report in reports
        for reason in report["failure_reasons"]
    ]
    counts = Counter(report["source_apply_outcome"] for report in reports)
    applied = [report for report in reports if report["source_repo_apply_performed"]]
    tested_passed = [report for report in applied if report["test_evidence_status"] == "passed"]
    rollback_required = [report for report in reports if report["rollback_decision_required"]]
    return {
        "schema_version": SUMMARY_SCHEMA,
        "passed": not failures,
        "failure_reasons": failures,
        "checked_at": _now(),
        "sample_count": len(reports),
        "outcome_counts": {outcome: counts.get(outcome, 0) for outcome in SOURCE_APPLY_OUTCOMES},
        "metrics": {
            "source_apply_pass_ratio": _ratio(
                len([report for report in reports if report["source_apply_passed"]]),
                len(reports),
            ),
            "source_repo_apply_performed_ratio": _ratio(len(applied), len(reports)),
            "tested_passed_apply_ratio": _ratio(len(tested_passed), len(applied)),
            "post_apply_test_failure_ratio": _ratio(counts.get("applied_tests_failed", 0), len(reports)),
            "authorization_refused_ratio": _ratio(counts.get("authorization_refused", 0), len(reports)),
            "rollback_decision_required_ratio": _ratio(len(rollback_required), len(reports)),
        },
        "samples": [
            {
                "execution_report": report["execution_report"]["path"],
                "source_apply_outcome": report["source_apply_outcome"],
                "source_apply_passed": report["source_apply_passed"],
                "source_repo_apply_performed": report["source_repo_apply_performed"],
                "test_evidence_status": report["test_evidence_status"],
                "failure_codes": report["failure_codes"],
                "rollback_decision_required": report["rollback_decision_required"],
            }
            for report in reports
        ],
        "non_claims": list(NON_CLAIMS),
    }


def index_source_apply_outcomes(
    execution_reports: list[Path],
    *,
    summary_output: Path,
    index_output: Path,
    latest_output: Path,
) -> dict[str, Any]:
    summary = summarize_source_apply_outcomes(execution_reports)
    if summary["passed"] is not True:
        return summary
    _write_json(summary_output, summary)
    entry = {
        "schema_version": INDEX_SCHEMA,
        "indexed_at": _now(),
        "summary_path": str(summary_output.resolve()),
        "sample_count": summary["sample_count"],
        "outcome_counts": summary["outcome_counts"],
        "metrics": summary["metrics"],
        "execution_reports": [sample["execution_report"] for sample in summary["samples"]],
        "non_claims": list(NON_CLAIMS),
    }
    _append_jsonl(index_output, entry)
    _write_json(latest_output, entry)
    return {
        **summary,
        "summary_path": str(summary_output.resolve()),
        "index_path": str(index_output.resolve()),
        "latest_path": str(latest_output.resolve()),
        "index_entry": entry,
    }


def _validate_outcome_shape(execution: dict[str, Any], failures: list[str]) -> None:
    outcome = execution.get("source_apply_outcome")
    performed = execution.get("source_repo_apply_performed") is True
    status = execution.get("test_evidence_status")
    if performed and outcome not in {"applied_tests_passed", "applied_without_tests", "applied_tests_failed"}:
        failures.append("source_repo_apply_performed requires applied source_apply_outcome")
    if not performed and outcome in {"applied_tests_passed", "applied_without_tests", "applied_tests_failed"}:
        failures.append("applied source_apply_outcome requires source_repo_apply_performed")
    if outcome == "applied_tests_passed" and status != "passed":
        failures.append("applied_tests_passed requires passed test evidence")
    if outcome == "applied_tests_failed" and status != "failed":
        failures.append("applied_tests_failed requires failed test evidence")
    if outcome == "applied_without_tests" and status != "not_run":
        failures.append("applied_without_tests requires not_run test evidence")
    if execution.get("passed") is True and outcome not in {"applied_tests_passed", "applied_without_tests"}:
        failures.append("passed execution requires successful applied source_apply_outcome")


def _validate_receipt_presence(execution: dict[str, Any], receipt_path: Path | None, failures: list[str]) -> None:
    if execution.get("source_repo_apply_performed") is True and receipt_path is None:
        failures.append("performed source repo apply requires post_apply_receipt_path")
    if execution.get("source_repo_apply_performed") is not True and receipt_path is not None:
        failures.append("non-performed source repo apply must not expose post_apply_receipt_path")


def _receipt_path(value: Any, failures: list[str]) -> Path | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        failures.append("post_apply_receipt_path must be a non-empty string or null")
        return None
    path = Path(value)
    if not path.is_file():
        failures.append(f"post_apply_receipt_path is not a file: {path}")
        return None
    return path


def _validate_false_boundary_flags(payload: dict[str, Any], failures: list[str]) -> None:
    for flag in (
        "commit_allowed",
        "push_allowed",
        "merge_allowed",
        "deploy_allowed",
        "production_runtime_execution_allowed",
        "production_receipt_write_allowed",
    ):
        if payload.get(flag) is not False:
            failures.append(f"{flag} must be false")


def _validate_h3_boundary(payload: dict[str, Any], failures: list[str]) -> None:
    boundary = payload.get("h3_boundary")
    if not isinstance(boundary, dict):
        failures.append("h3_boundary must be an object")
        return
    if boundary.get("h3_remains_blocked") is not True:
        failures.append("h3_boundary.h3_remains_blocked must be true")
    if boundary.get("h3_production_readiness_claimed") is not False:
        failures.append("h3_boundary.h3_production_readiness_claimed must be false")


def _artifact_ref_if_file(path: Path) -> dict[str, str | None]:
    return {
        "path": str(path.resolve()),
        "sha256": _sha256(path) if path.is_file() else None,
    }


def _read_json_object(path: Path, failures: list[str], label: str) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 - outcome report needs artifact detail.
        failures.append(f"{label} could not be read: {exc}")
        return {}
    if not isinstance(payload, dict):
        failures.append(f"{label} must be a JSON object")
        return {}
    return payload


def _string_list(value: Any) -> list[str]:
    return [item for item in value if isinstance(item, str) and item] if isinstance(value, list) else []


def _ratio(part: int, total: int) -> float | None:
    return part / total if total else None


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _append_jsonl(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


if __name__ == "__main__":
    sys.exit(main())
