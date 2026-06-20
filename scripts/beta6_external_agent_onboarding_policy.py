"""Policy primitives for Beta-6 external Agent onboarding.

The onboarding script owns operator I/O, env intake, and provider probes. This
module owns the stable schema vocabulary, non-claims, and fail-closed boundary
checks shared by invitation, registration, and readiness artifacts.
"""

from __future__ import annotations

from typing import Any

AGENT_KINDS = ("ai_agent", "human_operator", "service_agent")
ALLOWED_SCOPES = ("proposal_only", "review_only", "audit_observation", "l1_controlled_message")
FORBIDDEN_TOKENS = ("TODO", "REPLACE", "PLACEHOLDER", "TEMPLATE_ONLY")
NON_CLAIMS = (
    "beta6_external_agent_onboarding_is_l1_controlled_pilot_only",
    "beta6_external_agent_onboarding_does_not_assign_tasks",
    "beta6_external_agent_onboarding_does_not_grant_merge_or_deploy_authority",
    "beta6_external_agent_onboarding_does_not_start_runtime_or_llm",
    "beta6_external_agent_onboarding_does_not_claim_h3_production_readiness",
    "beta6_external_agent_onboarding_does_not_write_production_receipts",
)


def h3_boundary() -> dict[str, bool]:
    return {
        "h3_remains_blocked": True,
        "h3_production_readiness_claimed": False,
    }


def validate_h3_boundary(payload: dict[str, Any], failures: list[str]) -> None:
    if payload.get("h3_boundary") != h3_boundary():
        failures.append("h3_boundary must keep production readiness blocked")


def validate_no_merge_deploy_production(payload: dict[str, Any], failures: list[str]) -> None:
    for field in (
        "merge_allowed",
        "deploy_allowed",
        "production_runtime_execution_allowed",
        "production_receipt_write_allowed",
    ):
        if payload.get(field) is not False:
            failures.append(f"{field} must be false")
