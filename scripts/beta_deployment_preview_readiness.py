#!/usr/bin/env python3
"""Inspect bounded Beta deployment preview readiness.

This gate consumes existing L1/Beta controlled-pilot artifacts and decides
whether a non-production Beta preview deployment flow is ready to be repeated.
It never runs merge, deploy, production runtime execution, or production receipt
writes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPORT_SCHEMA = "beta-deployment-preview-readiness-report:v1"
BETA6_9_SUMMARY_SCHEMA = "beta6-9-real-api-review-run-summary:v1"
PREVIEW_SUMMARY_SCHEMA = "beta5-repeatable-preview-nightly-artifact:v1"
OWNER_INDEX_SCHEMA = "beta5-owner-feedback-evidence-index:v1"
MULTI_EXTERNAL_REVIEW_SCHEMA = "beta-multi-external-review-reconciliation:v1"
NON_CLAIMS = (
    "beta_deployment_preview_readiness_is_l1_controlled_preview_only",
    "beta_deployment_preview_readiness_does_not_execute_merge",
    "beta_deployment_preview_readiness_does_not_execute_deploy",
    "beta_deployment_preview_readiness_does_not_authorize_production_runtime_execution",
    "beta_deployment_preview_readiness_does_not_write_production_receipts",
    "beta_deployment_preview_readiness_does_not_claim_h3_production_readiness",
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--beta6-9-summary", required=True)
    parser.add_argument("--preview-summary", required=True)
    parser.add_argument("--owner-feedback-index", required=True)
    parser.add_argument("--multi-external-review")
    parser.add_argument("--output", required=True)
    parser.add_argument("--min-owner-feedback-packets", type=int, default=3)
    parser.add_argument("--min-owner-feedback-accepted-ratio", type=float, default=0.66)
    parser.add_argument("--min-smoke-checks", type=int, default=15)
    args = parser.parse_args(argv)

    report = inspect_beta_deployment_preview_readiness(
        beta6_9_summary_path=Path(args.beta6_9_summary),
        preview_summary_path=Path(args.preview_summary),
        owner_feedback_index_path=Path(args.owner_feedback_index),
        multi_external_review_path=Path(args.multi_external_review) if args.multi_external_review else None,
        output_path=Path(args.output),
        min_owner_feedback_packets=args.min_owner_feedback_packets,
        min_owner_feedback_accepted_ratio=args.min_owner_feedback_accepted_ratio,
        min_smoke_checks=args.min_smoke_checks,
    )
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report["passed"] else 1


def inspect_beta_deployment_preview_readiness(
    *,
    beta6_9_summary_path: Path,
    preview_summary_path: Path,
    owner_feedback_index_path: Path,
    multi_external_review_path: Path | None = None,
    output_path: Path,
    min_owner_feedback_packets: int = 3,
    min_owner_feedback_accepted_ratio: float = 0.66,
    min_smoke_checks: int = 15,
) -> dict[str, Any]:
    failures: list[str] = []
    beta6_9 = _read_json(beta6_9_summary_path, failures, "beta6_9_summary")
    preview = _read_json(preview_summary_path, failures, "preview_summary")
    owner_index = _read_json(owner_feedback_index_path, failures, "owner_feedback_index")
    multi_review = _read_json(multi_external_review_path, failures, "multi_external_review") if multi_external_review_path else None

    if min_owner_feedback_packets < 1:
        failures.append("min_owner_feedback_packets must be >= 1")
    if not (0 <= min_owner_feedback_accepted_ratio <= 1):
        failures.append("min_owner_feedback_accepted_ratio must be between 0 and 1")
    if min_smoke_checks < 1:
        failures.append("min_smoke_checks must be >= 1")

    if beta6_9:
        _expect(beta6_9, "schema_version", BETA6_9_SUMMARY_SCHEMA, failures, "beta6_9_summary")
        _expect_true(beta6_9, "passed", failures, "beta6_9_summary")
        _expect(beta6_9, "external_review_verdict", "approved", failures, "beta6_9_summary")
        _expect_true(beta6_9, "beta5_authorization_input_ready", failures, "beta6_9_summary")
        _expect_true(beta6_9, "merge_authorized", failures, "beta6_9_summary")
        _expect_false(beta6_9, "merge_performed", failures, "beta6_9_summary")
        _expect_false(beta6_9, "deploy_allowed", failures, "beta6_9_summary")
        _expect_false(beta6_9, "production_runtime_execution_allowed", failures, "beta6_9_summary")
        _expect_false(beta6_9, "production_receipt_write_allowed", failures, "beta6_9_summary")
        _expect_h3_blocked(beta6_9, failures, "beta6_9_summary")

    if preview:
        _expect(preview, "schema_version", PREVIEW_SUMMARY_SCHEMA, failures, "preview_summary")
        _expect_true(preview, "passed", failures, "preview_summary")
        _expect(preview, "external_environment_provider", "virtualbox", failures, "preview_summary")
        _expect(preview, "external_environment_classification", "external_preview", failures, "preview_summary")
        if int(preview.get("smoke_total_checks") or 0) < min_smoke_checks:
            failures.append(f"preview_summary.smoke_total_checks must be >= {min_smoke_checks}")
        _expect_false(preview, "production_deploy_allowed", failures, "preview_summary")
        _expect_false(preview, "production_runtime_execution_allowed", failures, "preview_summary")
        _expect_false(preview, "production_receipt_write_allowed", failures, "preview_summary")
        _expect_false(preview, "h3_production_readiness_claimed", failures, "preview_summary")

    if owner_index:
        _expect(owner_index, "schema_version", OWNER_INDEX_SCHEMA, failures, "owner_feedback_index")
        _expect_true(owner_index, "passed", failures, "owner_feedback_index")
        packet_count = int(owner_index.get("packet_count") or 0)
        if packet_count < min_owner_feedback_packets:
            failures.append(f"owner_feedback_index.packet_count must be >= {min_owner_feedback_packets}")
        accepted_ratio = float(owner_index.get("accepted_ratio") or 0.0)
        if accepted_ratio < min_owner_feedback_accepted_ratio:
            failures.append(
                "owner_feedback_index.accepted_ratio must be >= "
                f"{min_owner_feedback_accepted_ratio}"
            )
        verdict_counts = owner_index.get("verdict_counts") if isinstance(owner_index.get("verdict_counts"), dict) else {}
        if int(verdict_counts.get("rejected") or 0) != 0:
            failures.append("owner_feedback_index.verdict_counts.rejected must be 0")
        _expect_false(owner_index, "production_deploy_allowed", failures, "owner_feedback_index")
        _expect_false(owner_index, "production_runtime_execution_allowed", failures, "owner_feedback_index")
        _expect_false(owner_index, "production_receipt_write_allowed", failures, "owner_feedback_index")
        _expect_false(owner_index, "h3_production_readiness_claimed", failures, "owner_feedback_index")
        _expect_h3_blocked(owner_index, failures, "owner_feedback_index")

    if multi_review:
        _expect(multi_review, "schema_version", MULTI_EXTERNAL_REVIEW_SCHEMA, failures, "multi_external_review")
        _expect_true(multi_review, "passed", failures, "multi_external_review")
        _expect(multi_review, "decision", "multi_external_review_ready", failures, "multi_external_review")
        _expect_true(multi_review, "all_external_verdicts_approved", failures, "multi_external_review")
        if int(multi_review.get("unique_external_agent_count") or 0) < 2:
            failures.append("multi_external_review.unique_external_agent_count must be >= 2")
        readiness = multi_review.get("readiness") if isinstance(multi_review.get("readiness"), dict) else {}
        for key in ("production_deploy_allowed", "production_runtime_execution_allowed", "production_receipt_write_allowed", "h3_production_readiness_claimed"):
            if readiness.get(key) is not False:
                failures.append(f"multi_external_review.readiness.{key} must be false")
        _expect_h3_blocked(multi_review, failures, "multi_external_review")

    passed = not failures
    report = {
        "schema_version": REPORT_SCHEMA,
        "checked_at": _now(),
        "passed": passed,
        "decision": "beta_preview_ready" if passed else "blocked",
        "failure_reasons": failures,
        "inputs": {
            "beta6_9_summary": _artifact_ref(beta6_9_summary_path),
            "preview_summary": _artifact_ref(preview_summary_path),
            "owner_feedback_index": _artifact_ref(owner_feedback_index_path),
            "multi_external_review": _artifact_ref(multi_external_review_path) if multi_external_review_path else None,
        },
        "thresholds": {
            "min_owner_feedback_packets": min_owner_feedback_packets,
            "min_owner_feedback_accepted_ratio": min_owner_feedback_accepted_ratio,
            "min_smoke_checks": min_smoke_checks,
        },
        "readiness": {
            "beta_preview_repeat_ready": passed,
            "multi_external_review_observed": bool(multi_review),
            "production_deploy_allowed": False,
            "production_runtime_execution_allowed": False,
            "production_receipt_write_allowed": False,
            "h3_production_readiness_claimed": False,
        },
        "h3_boundary": {
            "h3_remains_blocked": True,
            "h3_production_readiness_claimed": False,
        },
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(output_path, report)
    return report


def _read_json(path: Path, failures: list[str], label: str) -> dict[str, Any]:
    if not path.is_file():
        failures.append(f"missing {label}: {path}")
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        failures.append(f"invalid {label} JSON: {exc}")
        return {}
    if not isinstance(value, dict):
        failures.append(f"{label} must be a JSON object")
        return {}
    return value


def _expect(payload: dict[str, Any], key: str, expected: Any, failures: list[str], label: str) -> None:
    if payload.get(key) != expected:
        failures.append(f"{label}.{key} must be {expected!r}")


def _expect_true(payload: dict[str, Any], key: str, failures: list[str], label: str) -> None:
    if payload.get(key) is not True:
        failures.append(f"{label}.{key} must be true")


def _expect_false(payload: dict[str, Any], key: str, failures: list[str], label: str) -> None:
    if payload.get(key) is not False:
        failures.append(f"{label}.{key} must be false")


def _expect_h3_blocked(payload: dict[str, Any], failures: list[str], label: str) -> None:
    boundary = payload.get("h3_boundary") if isinstance(payload.get("h3_boundary"), dict) else {}
    if boundary.get("h3_remains_blocked") is not True:
        failures.append(f"{label}.h3_boundary.h3_remains_blocked must be true")
    if boundary.get("h3_production_readiness_claimed") is not False:
        failures.append(f"{label}.h3_boundary.h3_production_readiness_claimed must be false")


def _artifact_ref(path: Path) -> dict[str, str | None]:
    if not path.is_file():
        return {"path": str(path), "sha256": None}
    return {"path": str(path.resolve()), "sha256": _sha256(path)}


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


if __name__ == "__main__":
    raise SystemExit(main())
