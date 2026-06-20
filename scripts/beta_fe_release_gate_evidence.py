"""Evidence and boundary primitives for Beta-FE release gates.

This module is intentionally side-effect free. Git, GitHub, provider calls, and
file writes remain in the gate runner; this module only owns stable schemas,
non-claims, release evidence builders, and boundary validation helpers.
"""

from __future__ import annotations

from typing import Any

try:
    from civitasos_contracts.artifacts import build_artifact_envelope
    from civitasos_contracts.provenance import (
        build_git_release_provenance,
        build_governance_evidence,
    )
except ModuleNotFoundError:
    from scripts.civitasos_contracts.artifacts import build_artifact_envelope
    from scripts.civitasos_contracts.provenance import (
        build_git_release_provenance,
        build_governance_evidence,
    )

FE4_RECEIPT_SCHEMA = "beta-fe4-frontend-commit-receipt:v1"
FE5_RECEIPT_SCHEMA = "beta-fe5-frontend-push-receipt:v1"
FE6_RECEIPT_SCHEMA = "beta-fe6-frontend-draft-pr-receipt:v1"
FE7_RECEIPT_SCHEMA = "beta-fe7-frontend-review-reconciliation:v1"
FE8_RECEIPT_SCHEMA = "beta-fe8-frontend-merge-receipt:v1"

NON_CLAIMS = (
    "beta_fe_release_gates_are_l1_controlled_pilot_only",
    "beta_fe_release_gates_do_not_deploy_frontend",
    "beta_fe_release_gates_do_not_claim_h3_production_readiness",
    "beta_fe_release_gates_do_not_write_production_receipts",
)


def release_boundary(
    *,
    push_allowed: bool = False,
    pr_allowed: bool = False,
    review_allowed: bool = False,
    merge_allowed: bool = False,
) -> dict[str, bool]:
    return {
        "frontend_code_modified": True,
        "apply_allowed": True,
        "commit_allowed": True,
        "push_allowed": push_allowed,
        "pr_allowed": pr_allowed,
        "review_allowed": review_allowed,
        "merge_allowed": merge_allowed,
        "deploy_allowed": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
    }


def h3_boundary() -> dict[str, bool]:
    return {"h3_remains_blocked": True, "h3_production_readiness_claimed": False}


def validate_h3_boundary(value: dict[str, Any], label: str, failures: list[str]) -> None:
    h3 = value.get("h3_boundary") if isinstance(value.get("h3_boundary"), dict) else {}
    if h3 != h3_boundary():
        failures.append(f"{label} must keep H.3 blocked")
