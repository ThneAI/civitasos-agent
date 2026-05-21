#!/usr/bin/env python3
"""Inspect and summarize Beta-2 patch review outcomes.

This inspector reads Beta-2 proposal validation and operator receipt artifacts.
It does not call an LLM, apply patches, commit, push, merge, deploy, execute
production runtime actions, or write production receipts.
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

from beta1_repo_review_proposal import DANGEROUS_FLAGS, validate_receipt
from beta2_operator_apply_receipt import validate_operator_apply_receipt
from beta2_patch_proposal import VALIDATION_SCHEMA as PATCH_VALIDATION_SCHEMA


OUTCOME_SCHEMA = "beta2-patch-review-outcome:v1"
SUMMARY_SCHEMA = "beta2-patch-review-outcome-summary:v1"
OUTCOMES = (
    "deferred",
    "rejected",
    "approved_pending_apply",
    "applied_as_proposed",
    "corrected_applied",
    "invalid",
)
NON_CLAIMS = (
    "beta2_patch_review_outcome_is_l1_observability_only",
    "beta2_patch_review_outcome_does_not_apply_patch",
    "beta2_patch_review_outcome_does_not_authorize_commit_push_merge_or_deploy",
    "beta2_patch_review_outcome_does_not_claim_h3_production_readiness",
    "beta2_patch_review_outcome_does_not_write_production_receipts",
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    inspect = subparsers.add_parser("inspect", help="inspect one Beta-2 run root")
    inspect.add_argument("--run-root", required=True)
    inspect.add_argument("--output")

    summarize = subparsers.add_parser("summarize", help="summarize multiple Beta-2 run roots")
    summarize.add_argument("--run-root", action="append", required=True)
    summarize.add_argument("--output")

    args = parser.parse_args(argv)
    if args.command == "inspect":
        report = inspect_review_outcome(Path(args.run_root))
    elif args.command == "summarize":
        report = summarize_review_outcomes([Path(path) for path in args.run_root])
    else:
        raise AssertionError(f"unknown command: {args.command}")
    if args.output:
        _write_json(Path(args.output), report)
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report["passed"] else 1


def inspect_review_outcome(run_root: Path) -> dict[str, Any]:
    root = run_root.resolve()
    failures: list[str] = []
    patch_validation_path = root / "beta2_patch_proposal_validation.json"
    proposal_receipt_path = root / "operator_decision_receipt.json"
    apply_receipt_path = root / "beta2_operator_apply_receipt.json"

    patch_validation = _read_json_object(patch_validation_path, failures, "patch validation")
    proposal_receipt = _read_json_object(proposal_receipt_path, failures, "proposal receipt")
    _validate_patch_validation(patch_validation, failures)
    proposal_receipt_validation = _validate_proposal_receipt(proposal_receipt_path, failures)
    _cross_check_proposal_artifacts(patch_validation, proposal_receipt, failures)

    apply_receipt = None
    apply_receipt_validation = None
    if apply_receipt_path.is_file():
        apply_receipt = _read_json_object(apply_receipt_path, failures, "operator apply receipt")
        apply_receipt_validation = validate_operator_apply_receipt(apply_receipt_path)
        if apply_receipt_validation["passed"] is not True:
            failures.extend(f"operator apply receipt invalid: {reason}" for reason in apply_receipt_validation["failure_reasons"])
        _cross_check_apply_receipt(proposal_receipt, apply_receipt, failures)

    decision = proposal_receipt.get("decision") if isinstance(proposal_receipt, dict) else None
    outcome, exact_patch_match = _classify_outcome(decision, patch_validation, apply_receipt)
    if outcome == "invalid":
        failures.append("review outcome could not be classified")
    if apply_receipt is not None and decision != "approved":
        failures.append("operator apply receipt requires approved proposal decision")

    proposal_paths = _string_list(patch_validation.get("target_paths")) if isinstance(patch_validation, dict) else []
    applied_paths = _applied_paths(apply_receipt)
    return {
        "schema_version": OUTCOME_SCHEMA,
        "passed": not failures,
        "failure_reasons": failures,
        "checked_at": _now(),
        "run_root": str(root),
        "request_id": proposal_receipt.get("request_id") if isinstance(proposal_receipt, dict) else None,
        "operator_decision": decision,
        "operator_reason": proposal_receipt.get("reason") if isinstance(proposal_receipt, dict) else None,
        "review_outcome": outcome,
        "proposal": {
            "validation_path": str(patch_validation_path),
            "validation_passed": patch_validation.get("passed") if isinstance(patch_validation, dict) else False,
            "patch_path": patch_validation.get("patch_path") if isinstance(patch_validation, dict) else None,
            "patch_sha256": patch_validation.get("patch_sha256") if isinstance(patch_validation, dict) else None,
            "target_paths": proposal_paths,
        },
        "proposal_receipt_validation": proposal_receipt_validation,
        "operator_apply": {
            "present": apply_receipt is not None,
            "receipt_path": str(apply_receipt_path) if apply_receipt is not None else None,
            "validation": apply_receipt_validation,
            "applied_diff_sha256": _applied_sha(apply_receipt),
            "applied_target_paths": applied_paths,
            "applied_target_paths_match_proposal": sorted(applied_paths) == sorted(proposal_paths) if applied_paths else None,
            "applied_diff_exact_patch_match": exact_patch_match,
            "tests": apply_receipt.get("tests") if isinstance(apply_receipt, dict) else None,
        },
        "dangerous_actions_allowed": {
            "auto_apply": False,
            "commit": False,
            "push": False,
            "merge": False,
            "deploy": False,
            "production_runtime_execution": False,
            "production_receipt_write": False,
        },
        "non_claims": list(NON_CLAIMS),
    }


def summarize_review_outcomes(run_roots: list[Path]) -> dict[str, Any]:
    reports = [inspect_review_outcome(path) for path in run_roots]
    failures = [
        f"{report['run_root']}: {reason}"
        for report in reports
        for reason in report["failure_reasons"]
    ]
    counts = Counter(report["review_outcome"] for report in reports)
    applied_reports = [report for report in reports if report["operator_apply"]["present"]]
    tested_applies = [
        report for report in applied_reports
        if report["operator_apply"].get("tests", {}).get("status") == "passed"
    ]
    return {
        "schema_version": SUMMARY_SCHEMA,
        "passed": not failures,
        "failure_reasons": failures,
        "checked_at": _now(),
        "sample_count": len(reports),
        "outcome_counts": {outcome: counts.get(outcome, 0) for outcome in OUTCOMES},
        "metrics": {
            "rejected_ratio": _ratio(counts.get("rejected", 0), len(reports)),
            "deferred_ratio": _ratio(counts.get("deferred", 0), len(reports)),
            "approved_pending_apply_ratio": _ratio(counts.get("approved_pending_apply", 0), len(reports)),
            "applied_ratio": _ratio(len(applied_reports), len(reports)),
            "corrected_applied_ratio": _ratio(counts.get("corrected_applied", 0), len(reports)),
            "applied_as_proposed_ratio": _ratio(counts.get("applied_as_proposed", 0), len(reports)),
            "tested_apply_ratio": _ratio(len(tested_applies), len(applied_reports)),
        },
        "samples": [
            {
                "run_root": report["run_root"],
                "request_id": report["request_id"],
                "operator_decision": report["operator_decision"],
                "review_outcome": report["review_outcome"],
                "operator_apply_present": report["operator_apply"]["present"],
                "applied_diff_exact_patch_match": report["operator_apply"]["applied_diff_exact_patch_match"],
                "tests": report["operator_apply"]["tests"],
            }
            for report in reports
        ],
        "non_claims": list(NON_CLAIMS),
    }


def _validate_patch_validation(data: dict[str, Any], failures: list[str]) -> None:
    if data.get("schema_version") != PATCH_VALIDATION_SCHEMA:
        failures.append(f"patch validation schema_version must be {PATCH_VALIDATION_SCHEMA}")
    if data.get("passed") is not True:
        failures.append("patch validation must be passed")
    patch_path = data.get("patch_path")
    if not isinstance(patch_path, str) or not Path(patch_path).is_file():
        failures.append("patch validation patch_path must exist")
    elif data.get("patch_sha256") != _sha256(Path(patch_path)):
        failures.append("patch validation patch_sha256 must match patch bytes")
    if not _string_list(data.get("target_paths")):
        failures.append("patch validation target_paths must be non-empty")


def _validate_proposal_receipt(path: Path, failures: list[str]) -> dict[str, Any]:
    report = validate_receipt(receipt_path=path)
    if report["passed"] is not True:
        failures.extend(f"proposal receipt invalid: {reason}" for reason in report["failure_reasons"])
    return report


def _cross_check_proposal_artifacts(
    patch_validation: dict[str, Any],
    proposal_receipt: dict[str, Any],
    failures: list[str],
) -> None:
    artifact = proposal_receipt.get("proposal_artifact")
    if not isinstance(artifact, dict):
        failures.append("proposal receipt proposal_artifact must be an object")
        return
    if artifact.get("path") != patch_validation.get("patch_path"):
        failures.append("proposal artifact path must match patch validation")
    if artifact.get("sha256") != patch_validation.get("patch_sha256"):
        failures.append("proposal artifact sha256 must match patch validation")
    for flag in DANGEROUS_FLAGS:
        if proposal_receipt.get(flag) is not False:
            failures.append(f"proposal receipt {flag} must be false")


def _cross_check_apply_receipt(
    proposal_receipt: dict[str, Any],
    apply_receipt: dict[str, Any],
    failures: list[str],
) -> None:
    if apply_receipt.get("request_id") != proposal_receipt.get("request_id"):
        failures.append("operator apply receipt request_id must match proposal receipt")


def _classify_outcome(
    decision: Any,
    patch_validation: dict[str, Any],
    apply_receipt: dict[str, Any] | None,
) -> tuple[str, bool | None]:
    if isinstance(apply_receipt, dict):
        exact = _applied_sha(apply_receipt) == patch_validation.get("patch_sha256")
        return ("applied_as_proposed" if exact else "corrected_applied"), exact
    if decision == "deferred":
        return "deferred", None
    if decision == "rejected":
        return "rejected", None
    if decision == "approved":
        return "approved_pending_apply", None
    return "invalid", None


def _applied_paths(apply_receipt: dict[str, Any] | None) -> list[str]:
    if not isinstance(apply_receipt, dict):
        return []
    applied_diff = apply_receipt.get("applied_diff")
    return _string_list(applied_diff.get("target_paths")) if isinstance(applied_diff, dict) else []


def _applied_sha(apply_receipt: dict[str, Any] | None) -> str | None:
    if not isinstance(apply_receipt, dict):
        return None
    applied_diff = apply_receipt.get("applied_diff")
    value = applied_diff.get("sha256") if isinstance(applied_diff, dict) else None
    return value if isinstance(value, str) and value else None


def _read_json_object(path: Path, failures: list[str], label: str) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 - report needs failure detail.
        failures.append(f"{label} could not be read: {exc}")
        return {}
    if not isinstance(data, dict):
        failures.append(f"{label} must be a JSON object")
        return {}
    return data


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str) and item]


def _ratio(part: int, total: int) -> float | None:
    return part / total if total else None


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


if __name__ == "__main__":
    sys.exit(main())
