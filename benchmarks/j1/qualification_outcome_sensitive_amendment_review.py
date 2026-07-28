"""Independent-review request contracts for outcome-sensitive amendments."""

from __future__ import annotations

import copy
import hashlib
from typing import Any

from .controlled_comparison import canonical_sha256
from .qualification_outcome_sensitive_amendment import (
    BOUNDARY,
    PREFLIGHT_SCHEMA,
    validate_bundle,
)


REVIEW_REQUEST_SCHEMA = "j1-qualification-outcome-sensitive-amendment-review-request:v1"
REVIEW_HANDOFF_SCHEMA = "j1-qualification-outcome-sensitive-amendment-review-handoff:v1"
ALLOWED_DECISION = "approve_outcome_sensitive_amendment_materials"
CHECKLIST = {
    "all_six_copy_on_write_materials_read_and_hash_verified",
    "r11_evidence_and_signed_closeout_remain_immutable",
    "baseline_tasks_are_treatment_free_for_both_cohorts",
    "mentor_treatment_and_empty_control_advice_begin_at_ordinal_four",
    "private_fixture_ground_truth_and_deterministic_verifier_reviewed",
    "participant_decision_semantics_are_directly_observed_and_signed",
    "statistical_estimand_censoring_multiplicity_and_missingness_reviewed",
    "no_prospective_power_claim_invented_from_unobserved_r11_endpoints",
    "prior_consent_not_inherited_and_40_new_extensions_required",
    "participant_pair_substitution_and_outcome_exclusion_forbidden",
    "provider_model_identity_unchanged_but_fresh_admission_required",
    "execution_effectiveness_claim_and_si13_upgrade_remain_blocked",
}


def build_review_request(
    *,
    request_id: str,
    created_at: str,
    bundle_ref: dict[str, str],
    bundle: dict[str, Any],
    preflight_ref: dict[str, str],
    preflight: dict[str, Any],
    owner_statement_sha256: str,
    implementation: dict[str, str],
) -> dict[str, Any]:
    failures = validate_review_sources(
        bundle_ref=bundle_ref,
        bundle=bundle,
        preflight_ref=preflight_ref,
        preflight=preflight,
        owner_statement_sha256=owner_statement_sha256,
    )
    if failures:
        raise ValueError(f"amendment review sources invalid: {failures}")
    value = {
        "schema_version": REVIEW_REQUEST_SCHEMA,
        "request_id": request_id,
        "created_at": created_at,
        "status": "independent_reviewer_decision_required",
        "reviewed_bundle": copy.deepcopy(bundle_ref),
        "owner_approval_preflight": copy.deepcopy(preflight_ref),
        "reviewed_materials": copy.deepcopy(bundle["materials"]),
        "scope_summary": copy.deepcopy(bundle["inventory"]),
        "required_checklist": sorted(CHECKLIST),
        "allowed_decision": ALLOWED_DECISION,
        "decision_template": _empty_decision(),
        "implementation": copy.deepcopy(implementation),
        "execution_boundary": copy.deepcopy(BOUNDARY),
    }
    value["request_sha256"] = canonical_sha256(value)
    return value


def validate_review_sources(
    *,
    bundle_ref: dict[str, str],
    bundle: dict[str, Any],
    preflight_ref: dict[str, str],
    preflight: dict[str, Any],
    owner_statement_sha256: str,
) -> list[str]:
    failures = validate_bundle(bundle)
    _require(
        _valid_ref(bundle_ref, bundle.get("bundle_sha256")),
        "review_bundle_ref_invalid",
        failures,
    )
    _require(
        preflight.get("schema_version") == PREFLIGHT_SCHEMA
        and preflight.get("passed") is True
        and preflight.get("failure_reasons") == []
        and preflight.get("state")
        == "outcome_sensitive_amendment_materials_owner_review_only_approval_required"
        and _self_hash(preflight, "report_sha256"),
        "review_preflight_invalid",
        failures,
    )
    _require(
        _valid_ref(preflight_ref, preflight.get("report_sha256")),
        "review_preflight_ref_invalid",
        failures,
    )
    statement = preflight.get("required_owner_statement")
    _require(
        isinstance(statement, str)
        and hashlib.sha256(statement.encode()).hexdigest()
        == owner_statement_sha256
        == preflight.get("required_owner_statement_sha256"),
        "review_owner_statement_invalid",
        failures,
    )
    _require(
        preflight.get("bundle") == bundle_ref
        and preflight.get("execution_boundary") == BOUNDARY,
        "review_preflight_binding_or_boundary_invalid",
        failures,
    )
    return list(dict.fromkeys(failures))


def validate_review_request(
    value: Any,
    *,
    expected_bundle_ref: dict[str, str],
    expected_preflight_ref: dict[str, str],
    expected_materials: dict[str, dict[str, str]],
    expected_implementation: dict[str, str],
) -> list[str]:
    request = value if isinstance(value, dict) else {}
    failures: list[str] = []
    _require(
        request.get("schema_version") == REVIEW_REQUEST_SCHEMA
        and request.get("status") == "independent_reviewer_decision_required"
        and _self_hash(request, "request_sha256"),
        "amendment_review_request_identity_invalid",
        failures,
    )
    _require(
        request.get("reviewed_bundle") == expected_bundle_ref
        and request.get("owner_approval_preflight") == expected_preflight_ref
        and request.get("reviewed_materials") == expected_materials,
        "amendment_review_request_binding_invalid",
        failures,
    )
    _require(
        request.get("required_checklist") == sorted(CHECKLIST)
        and request.get("allowed_decision") == ALLOWED_DECISION
        and request.get("decision_template") == _empty_decision(),
        "amendment_review_decision_contract_invalid",
        failures,
    )
    _require(
        request.get("implementation") == expected_implementation
        and request.get("execution_boundary") == BOUNDARY,
        "amendment_review_implementation_or_boundary_invalid",
        failures,
    )
    return list(dict.fromkeys(failures))


def reviewer_approval_statement(
    *,
    request: dict[str, Any],
    request_raw_sha256: str,
) -> str:
    return (
        "I have independently reviewed J1-D outcome-sensitive amendment review "
        f"request raw SHA-256 {request_raw_sha256}, canonical SHA-256 "
        f"{request['request_sha256']} and choose {ALLOWED_DECISION}. I confirm all "
        f"{len(CHECKLIST)} required checklist items, disclose all conflicts, affirm "
        "that I am independent from candidate authoring and have completed human "
        "review. I approve only copy-on-write promotion of the six amendment "
        "materials bound by the request. I acknowledge that prior participant "
        "consent is not inherited and 40 of 40 new consent extensions remain "
        "required. This approval does not start or create a container, read a "
        "provider credential, call a provider or model, execute an Agent or task, "
        "append Backend Facts, append the Ledger, issue or consume an execution "
        "authorization, authorize an effectiveness claim, or upgrade SI-13 maturity."
    )


def build_review_handoff(
    *,
    request_ref: dict[str, str],
    request: dict[str, Any],
    request_raw_sha256: str,
) -> dict[str, Any]:
    statement = reviewer_approval_statement(
        request=request,
        request_raw_sha256=request_raw_sha256,
    )
    value = {
        "schema_version": REVIEW_HANDOFF_SCHEMA,
        "status": "independent_reviewer_action_required",
        "review_request": copy.deepcopy(request_ref),
        "allowed_decision": ALLOWED_DECISION,
        "required_checklist": sorted(CHECKLIST),
        "decision_template": copy.deepcopy(request["decision_template"]),
        "required_exact_approval_statement": statement,
        "required_exact_approval_statement_sha256": hashlib.sha256(
            statement.encode()
        ).hexdigest(),
        "execution_boundary": copy.deepcopy(BOUNDARY),
    }
    value["handoff_sha256"] = canonical_sha256(value)
    return value


def _empty_decision() -> dict[str, Any]:
    return {
        "decision": None,
        "reviewer_did": None,
        "reviewed_at": None,
        "independent_from_candidate_authoring": None,
        "conflicts_disclosed": None,
        "human_review_completed": None,
        "checklist": {name: None for name in sorted(CHECKLIST)},
    }


def _self_hash(value: Any, field: str) -> bool:
    if not isinstance(value, dict):
        return False
    body = {key: item for key, item in value.items() if key != field}
    return value.get(field) == canonical_sha256(body)


def _valid_ref(value: Any, canonical: Any) -> bool:
    ref = value if isinstance(value, dict) else {}
    return (
        isinstance(ref.get("path"), str)
        and _sha256(ref.get("sha256"))
        and _sha256(ref.get("canonical_sha256"))
        and ref.get("canonical_sha256") == canonical
    )


def _sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _require(condition: bool, failure: str, failures: list[str]) -> None:
    if not condition:
        failures.append(failure)
