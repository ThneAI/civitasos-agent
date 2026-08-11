"""Signed promotion contracts for the prospective confirmatory stack."""

from __future__ import annotations

import copy
from typing import Any

from .controlled_comparison import canonical_sha256
from .qualification_outcome_sensitive_confirmatory_execution_review import (
    REVIEW_CHECKLIST,
)
from .qualification_outcome_sensitive_execution_promotion import (
    FROZEN_BOUNDARY as BASE_FROZEN_BOUNDARY,
    RECEIPT_BOUNDARY as BASE_RECEIPT_BOUNDARY,
    ReviewSigner,
    build_frozen_stack,
    build_signed_review_receipt,
    validate_frozen_stack,
    validate_signed_review_receipt,
)


RECEIPT_SCHEMA = (
    "j1-qualification-outcome-sensitive-confirmatory-signed-review-receipt:v1"
)
FROZEN_SCHEMA = (
    "j1-qualification-outcome-sensitive-confirmatory-frozen-execution-stack:v1"
)
DECISION = "approve_outcome_sensitive_prospective_confirmatory_execution_stack"
RECEIPT_BOUNDARY = {
    **BASE_RECEIPT_BOUNDARY,
    "prospective_confirmatory_execution_review_approved": True,
    "prior_run_reanalysis_performed": False,
    "advice_adherence_inferred": False,
}
FROZEN_BOUNDARY = {
    **BASE_FROZEN_BOUNDARY,
    "prospective_confirmatory_execution_stack_frozen": True,
    "prior_run_reanalysis_performed": False,
    "advice_adherence_inferred": False,
}
READINESS = {
    "outcome_sensitive_execution_contract_frozen": True,
    "prospective_confirmatory_method_frozen": True,
    "confirmatory_consent_assignment_and_advice_frozen": True,
    "offline_480_task_recovery_evidence_frozen": True,
    "fault_matrix_evidence_frozen": True,
    "strict_decision_and_observation_contract_frozen": True,
    "live_provider_admission_refreshed": True,
    "runtime_inventory_40_created_0_running": True,
    "execution_preflight_allowed": True,
    "execution_authorization_issued": False,
    "controlled_experiment_execution_ready": False,
}
NEXT_BLOCKER = "new_confirmatory_single_use_execution_preflight_required"


def build_signed_confirmatory_review_receipt(
    *,
    review_id: str,
    reviewed_at: str,
    request_ref: dict[str, str],
    bundle_ref: dict[str, str],
    contract_sha256: str,
    approval_statement_sha256: str,
    reviewer: dict[str, Any],
    reviewer_profile_sha256: str,
    implementation: dict[str, str],
    signer: ReviewSigner,
) -> dict[str, Any]:
    return build_signed_review_receipt(
        review_id=review_id,
        reviewed_at=reviewed_at,
        request_ref=request_ref,
        bundle_ref=bundle_ref,
        contract_sha256=contract_sha256,
        approval_statement_sha256=approval_statement_sha256,
        reviewer=reviewer,
        reviewer_profile_sha256=reviewer_profile_sha256,
        implementation=implementation,
        signer=signer,
        receipt_schema=RECEIPT_SCHEMA,
        decision=DECISION,
        review_checklist=REVIEW_CHECKLIST,
        receipt_boundary=RECEIPT_BOUNDARY,
    )


def validate_signed_confirmatory_review_receipt(
    value: Any,
    *,
    expected_request_ref: dict[str, str],
    expected_bundle_ref: dict[str, str],
    expected_contract_sha256: str,
    expected_approval_statement_sha256: str,
    expected_reviewer: dict[str, Any],
    expected_reviewer_profile_sha256: str,
    expected_implementation: dict[str, str],
) -> list[str]:
    return validate_signed_review_receipt(
        value,
        expected_request_ref=expected_request_ref,
        expected_bundle_ref=expected_bundle_ref,
        expected_contract_sha256=expected_contract_sha256,
        expected_approval_statement_sha256=expected_approval_statement_sha256,
        expected_reviewer=expected_reviewer,
        expected_reviewer_profile_sha256=expected_reviewer_profile_sha256,
        expected_implementation=expected_implementation,
        receipt_schema=RECEIPT_SCHEMA,
        expected_decision=DECISION,
        review_checklist=REVIEW_CHECKLIST,
        expected_receipt_boundary=RECEIPT_BOUNDARY,
    )


def build_confirmatory_frozen_stack(
    *,
    frozen_id: str,
    promoted_at: str,
    candidate_bundle_sha256: str,
    review_receipt_ref: dict[str, str],
    frozen_artifacts: dict[str, dict[str, str]],
    provider_admission: dict[str, Any],
    runtime_inventory: dict[str, int],
    confirmatory_method_binding: dict[str, Any],
    implementation: dict[str, str],
) -> dict[str, Any]:
    stack = build_frozen_stack(
        frozen_id=frozen_id,
        promoted_at=promoted_at,
        candidate_bundle_sha256=candidate_bundle_sha256,
        review_receipt_ref=review_receipt_ref,
        frozen_artifacts=frozen_artifacts,
        provider_admission=provider_admission,
        runtime_inventory=runtime_inventory,
        implementation=implementation,
        frozen_schema=FROZEN_SCHEMA,
        readiness=READINESS,
        next_blocker=NEXT_BLOCKER,
        frozen_boundary=FROZEN_BOUNDARY,
    )
    stack["confirmatory_method_binding"] = copy.deepcopy(confirmatory_method_binding)
    stack["frozen_stack_sha256"] = canonical_sha256(
        {key: value for key, value in stack.items() if key != "frozen_stack_sha256"}
    )
    failures = validate_confirmatory_frozen_stack(stack)
    if failures:
        raise ValueError(f"confirmatory frozen stack invalid: {failures}")
    return stack


def validate_confirmatory_frozen_stack(value: Any) -> list[str]:
    stack = value if isinstance(value, dict) else {}
    failures = validate_frozen_stack(
        stack,
        frozen_schema=FROZEN_SCHEMA,
        expected_readiness=READINESS,
        expected_next_blocker=NEXT_BLOCKER,
        expected_frozen_boundary=FROZEN_BOUNDARY,
    )
    method = stack.get("confirmatory_method_binding", {})
    if not (
        _sha256(method.get("method_sha256"))
        and _sha256(method.get("promotion_gate_sha256"))
        and _sha256(method.get("consent_gate_sha256"))
        and method.get("test", {}).get("assignment_count") == 1_048_576
        and method.get("multiplicity", {}).get("method") == "holm_step_down"
        and method.get("prior_run_reanalysis_allowed") is False
        and method.get("advice_adherence_inference_allowed") is False
    ):
        failures.append("confirmatory_frozen_method_binding_invalid")
    body = {key: item for key, item in stack.items() if key != "frozen_stack_sha256"}
    if stack.get("frozen_stack_sha256") != canonical_sha256(body):
        failures.append("confirmatory_frozen_stack_hash_invalid")
    return list(dict.fromkeys(failures))


def _sha256(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True
