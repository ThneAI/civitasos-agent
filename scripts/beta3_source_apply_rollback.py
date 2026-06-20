"""Rollback follow-up policy for Beta-3 source apply."""

from __future__ import annotations

from typing import Any


def source_apply_operator_followup(failure_codes: list[str]) -> dict[str, Any]:
    test_failure = "post_apply_test_failed" in failure_codes
    return {
        "required": bool(failure_codes),
        "reason_codes": failure_codes,
        "rollback_decision_required": test_failure,
        "automatic_rollback_performed": False,
    }
