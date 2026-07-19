"""Boundary and outcome rules for Beta-3 source apply.

The executor performs git operations. This module owns source-apply outcome
classification and receipt boundary validation. Rollback follow-up policy lives
in beta3_source_apply_rollback and is re-exported here for compatibility.
"""

from __future__ import annotations

from typing import Any

try:
    from beta3_source_apply_rollback import (
        source_apply_operator_followup as source_apply_operator_followup,
    )
except ModuleNotFoundError:
    from scripts.beta3_source_apply_rollback import (
        source_apply_operator_followup as source_apply_operator_followup,
    )


NON_CLAIMS = (
    "beta3_source_apply_executor_is_l1_controlled_pilot_only",
    "beta3_source_apply_executor_does_not_commit_push_merge_or_deploy",
    "beta3_source_apply_executor_does_not_claim_h3_production_readiness",
    "beta3_source_apply_executor_does_not_write_production_receipts",
)

FALSE_RECEIPT_FLAGS = (
    "commit_allowed",
    "push_allowed",
    "merge_allowed",
    "deploy_allowed",
    "production_runtime_execution_allowed",
    "production_receipt_write_allowed",
)


def source_apply_outcome(
    *,
    source_apply_performed: bool,
    failure_codes: list[str],
    test_runs: list[dict[str, Any]],
) -> str:
    if "post_apply_test_failed" in failure_codes:
        return "applied_tests_failed"
    if source_apply_performed and test_runs:
        return "applied_tests_passed"
    if source_apply_performed:
        return "applied_without_tests"
    if "source_apply_check_refused" in failure_codes:
        return "apply_check_refused"
    if "source_apply_failed" in failure_codes:
        return "apply_failed"
    return "blocked_before_verified_apply"


def test_evidence_status(test_runs: list[dict[str, Any]]) -> str:
    if not test_runs:
        return "not_run"
    if any(run["returncode"] != 0 for run in test_runs):
        return "failed"
    return "passed"


def validate_false_boundary_flags(payload: dict[str, Any], failures: list[str]) -> None:
    for flag in FALSE_RECEIPT_FLAGS:
        if payload.get(flag) is not False:
            failures.append(f"{flag} must be false")


def validate_h3_boundary(payload: dict[str, Any], failures: list[str]) -> None:
    boundary = payload.get("h3_boundary") if isinstance(payload.get("h3_boundary"), dict) else {}
    if boundary.get("h3_remains_blocked") is not True:
        failures.append("h3_boundary.h3_remains_blocked must be true")
    if boundary.get("h3_production_readiness_claimed") is not False:
        failures.append("h3_boundary.h3_production_readiness_claimed must be false")


def h3_boundary() -> dict[str, bool]:
    return {"h3_remains_blocked": True, "h3_production_readiness_claimed": False}
