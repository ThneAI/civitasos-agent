"""Copy-on-write confirmatory-method amendment materials for J1-D."""

from __future__ import annotations

import copy
import hashlib
from fractions import Fraction
from typing import Any

from .controlled_comparison import canonical_sha256
from .qualification_outcome_sensitive_confirmatory import (
    ENDPOINT_ORDER,
    FAMILYWISE_ALPHA,
    METHOD_VERSION,
    evaluate_confirmatory_effects,
)


PLAN_SCHEMA = "j1-outcome-sensitive-confirmatory-amendment-plan:v1"
METHOD_SCHEMA = "j1-outcome-sensitive-confirmatory-method:v1"
PROTOCOL_SCHEMA = "j1-outcome-sensitive-confirmatory-protocol-addendum:v1"
EVALUATOR_SCHEMA = "j1-outcome-sensitive-confirmatory-evaluator-addendum:v1"
CONSENT_SCHEMA = "j1-outcome-sensitive-confirmatory-consent-impact:v1"
VERIFICATION_SCHEMA = "j1-outcome-sensitive-confirmatory-verification:v1"
BUNDLE_SCHEMA = "j1-outcome-sensitive-confirmatory-amendment-bundle:v1"
PREFLIGHT_SCHEMA = "j1-outcome-sensitive-confirmatory-amendment-preflight:v1"
MATERIAL_STATUS = "review_required"
PARENT_PROTOCOL_SHA256 = (
    "c2172b0ac5e51040d5348dc332aedfca6ef5a42a6023c2de3b65a7eaa53f8fda"
)
PARENT_EVALUATOR_SHA256 = (
    "d68d035f4762bc7cea2402c207dcfe5616800a3988b16433fbafff3bd5f80b78"
)
PARENT_STATISTICAL_SHA256 = (
    "f96b86027a16c0675354f395de1a6a13a6befdbf0230edd30ab27d60382f84e1"
)
FIXTURE_SHA256 = "bc2dbd0f13ec84127d5568bcd1880b7f5c4e1db95400af5ff5a49e03229dda14"
ASSIGNMENT_SHA256 = "2fcb9bca06504dd855930f912b7dffa7e13d67db775bd1d5689de0db8d6df81f"
POSTMORTEM_GATE_SHA256 = (
    "461238d1a36c6967fd750f137b47ec7c02e1aa0700ea96378ef03e3e4ac0900e"
)
FROZEN_POSTMORTEM_SHA256 = (
    "aa8eb70ff44abb7c8f57e84b340750b6d54bf3b5c9d12fbe6108d03ef88a6b12"
)
BOUNDARY = {
    "offline_material_generation_only": True,
    "prior_run_reanalysis_for_claim_performed": False,
    "protocol_or_evaluator_promoted": False,
    "participant_consent_migrated": False,
    "participant_signature_performed": False,
    "participant_container_created_or_started": False,
    "provider_credential_read": False,
    "provider_api_call_performed": False,
    "model_invocation_performed": False,
    "agent_or_task_execution_performed": False,
    "backend_fact_append_performed": False,
    "ledger_append_performed": False,
    "execution_authorization_issued_or_consumed": False,
    "effectiveness_or_causal_claim_authorized": False,
    "si13_maturity_upgrade_authorized": False,
}


def build_plan(
    *,
    amendment_id: str,
    created_at: str,
    sources: dict[str, dict[str, str]],
    implementation: dict[str, str],
) -> dict[str, Any]:
    _require_source_set(sources)
    value = {
        "schema_version": PLAN_SCHEMA,
        "amendment_id": amendment_id,
        "created_at": created_at,
        "status": MATERIAL_STATUS,
        "sources": copy.deepcopy(sources),
        "scope": {
            "analysis_method_change_only": True,
            "participant_count": 40,
            "matched_pair_count": 20,
            "task_count": 480,
            "fixture_changed": False,
            "decision_schema_changed": False,
            "treatment_changed": False,
            "assignment_changed": False,
            "provider_or_model_changed": False,
            "advice_adherence_observation_added": False,
        },
        "copy_on_write_invariants": {
            "r4_run_and_postmortem_immutable": True,
            "r4_not_reanalyzed_for_confirmatory_claim": True,
            "parent_protocol_evaluator_and_plan_immutable": True,
            "future_execution_must_bind_promoted_method": True,
            "post_execution_method_selection_allowed": False,
        },
        "required_sequence": [
            "method_and_reference_implementation_verification",
            "owner_review_only_approval",
            "independent_human_review",
            "signed_copy_on_write_promotion",
            "participant_consent_extension_40_of_40",
            "fresh_execution_stack_review",
            "fresh_infrastructure_and_provider_admission",
            "fresh_single_use_execution_authorization",
        ],
        "implementation": copy.deepcopy(implementation),
        "execution_boundary": copy.deepcopy(BOUNDARY),
    }
    return _seal(value, "plan_sha256")


def build_method(
    *,
    method_id: str,
    created_at: str,
    plan_ref: dict[str, str],
    parent_statistical_ref: dict[str, str],
) -> dict[str, Any]:
    value = {
        "schema_version": METHOD_SCHEMA,
        "method_id": method_id,
        "method_version": METHOD_VERSION,
        "created_at": created_at,
        "status": MATERIAL_STATUS,
        "plan": copy.deepcopy(plan_ref),
        "parent_statistical_plan": {
            **copy.deepcopy(parent_statistical_ref),
            "immutable": True,
        },
        "population": {
            "unit": "matched_pair",
            "pair_count": 20,
            "all_pairs_required": True,
            "outcome_based_exclusion_allowed": False,
        },
        "endpoints": [
            {
                "endpoint_id": ENDPOINT_ORDER[0],
                "pair_effect": "control_maturity_ordinal_minus_mentor_maturity_ordinal",
                "positive_direction": "favors_mentorship",
                "maturity_censoring_ordinal": 13,
            },
            {
                "endpoint_id": ENDPOINT_ORDER[1],
                "pair_effect": (
                    "control_repeated_error_rate_minus_mentor_repeated_error_rate"
                ),
                "positive_direction": "favors_mentorship",
                "zero_opportunity_rule": (
                    "structural_failure_endpoint_not_estimable_no_claim"
                ),
            },
        ],
        "test": {
            "name": "exact_matched_pair_sign_flip_randomization_test",
            "null": "no_positive_treatment_effect",
            "alternative": "control_minus_mentor_greater_than_zero",
            "statistic": "sum_of_20_pair_effects",
            "enumeration": "all_2_power_20_with_exact_integer_frequency_dp",
            "assignment_count": 1 << 20,
            "tail": "greater_than_or_equal_to_observed_statistic",
            "p_value": "extreme_assignment_count_divided_by_1048576",
            "plus_one_correction": False,
            "zero_pair_effects": "retained_and_sign_invariant",
            "tail_ties": "included",
            "numeric_representation": "exact_rational_no_binary_float",
        },
        "multiplicity": {
            "method": "holm_step_down",
            "family": list(ENDPOINT_ORDER),
            "familywise_alpha": _fraction(FAMILYWISE_ALPHA),
            "sort": "ascending_raw_p_value",
            "equal_p_value_tie_order": list(ENDPOINT_ORDER),
            "first_threshold": _fraction(Fraction(1, 40)),
            "second_threshold": _fraction(Fraction(1, 20)),
            "stop_after_first_non_rejection": True,
            "both_endpoints_must_reject_for_effectiveness": True,
        },
        "missingness_and_censoring": {
            "all_480_terminal_task_evidence_required": True,
            "all_40_participant_outcomes_required": True,
            "all_20_complete_pairs_required": True,
            "missing_or_invalid_evidence": (
                "structural_failure_no_confirmatory_inference_no_effectiveness_claim"
            ),
            "outcome_imputation_for_claim_allowed": False,
            "maturity_not_reached": "censor_at_ordinal_13_before_pair_effect",
        },
        "descriptive_analysis": {
            "paired_bootstrap_retained": True,
            "confirmatory_test_selection_from_bootstrap_allowed": False,
            "descriptive_thresholds_remain_additional_gate_conditions": True,
        },
        "claim_gate": {
            "structural_gate_must_pass": True,
            "both_holm_adjusted_endpoints_must_reject": True,
            "all_existing_descriptive_and_safeguard_thresholds_must_pass": True,
            "signed_evaluation_and_closeout_required": True,
            "single_run_proves_long_term_sustainability": False,
        },
        "measurement_boundary": {
            "advice_exposure_observed": True,
            "advice_provenance_observed": True,
            "advice_adherence_observed": False,
            "advice_adherence_change_deferred_to_separate_protocol_schema_review": True,
        },
        "execution_boundary": copy.deepcopy(BOUNDARY),
    }
    return _seal(value, "method_sha256")


def build_protocol_addendum(
    *,
    addendum_id: str,
    created_at: str,
    plan_ref: dict[str, str],
    parent_protocol_ref: dict[str, str],
    method_ref: dict[str, str],
) -> dict[str, Any]:
    value = {
        "schema_version": PROTOCOL_SCHEMA,
        "addendum_id": addendum_id,
        "created_at": created_at,
        "status": MATERIAL_STATUS,
        "plan": copy.deepcopy(plan_ref),
        "parent_protocol": {
            **copy.deepcopy(parent_protocol_ref),
            "immutable": True,
        },
        "confirmatory_method": copy.deepcopy(method_ref),
        "unchanged_contracts": {
            "participant_count": 40,
            "matched_pair_count": 20,
            "tasks_per_participant": 12,
            "task_fixture_canonical_sha256": FIXTURE_SHA256,
            "decision_fields": ["selected_action_id", "predicted_pattern_ids"],
            "treatment_ordinals": list(range(4, 13)),
            "control_advice_projection": [],
            "advice_adherence_field_added": False,
        },
        "fresh_bindings_required": {
            "participant_consent_extensions": 40,
            "execution_stack_review": True,
            "infrastructure_and_provider_admission": True,
            "single_use_execution_authorization": True,
        },
        "execution_boundary": copy.deepcopy(BOUNDARY),
    }
    return _seal(value, "addendum_sha256")


def build_evaluator_addendum(
    *,
    evaluator_id: str,
    created_at: str,
    plan_ref: dict[str, str],
    parent_evaluator_ref: dict[str, str],
    method_ref: dict[str, str],
    protocol_addendum_ref: dict[str, str],
    implementation: dict[str, str],
) -> dict[str, Any]:
    value = {
        "schema_version": EVALUATOR_SCHEMA,
        "evaluator_id": evaluator_id,
        "created_at": created_at,
        "status": MATERIAL_STATUS,
        "plan": copy.deepcopy(plan_ref),
        "parent_evaluator": {
            **copy.deepcopy(parent_evaluator_ref),
            "immutable": True,
        },
        "confirmatory_method": copy.deepcopy(method_ref),
        "protocol_addendum": copy.deepcopy(protocol_addendum_ref),
        "reference_implementation": copy.deepcopy(implementation),
        "input_contract": {
            "complete_pair_count": 20,
            "maturity_effects": "20_exact_integer_values",
            "repeated_error_effects": "20_exact_rational_values",
            "binary_float_p_value_allowed": False,
        },
        "output_contract": {
            "raw_and_adjusted_p_values_as_exact_rationals": True,
            "structural_result_separate_from_confirmatory_result": True,
            "effectiveness_claim_before_signed_closeout_allowed": False,
        },
        "execution_boundary": copy.deepcopy(BOUNDARY),
    }
    return _seal(value, "evaluator_sha256")


def build_consent_impact(
    *,
    assessment_id: str,
    created_at: str,
    plan_ref: dict[str, str],
    prior_consent_ref: dict[str, str],
    method_ref: dict[str, str],
    protocol_addendum_ref: dict[str, str],
    evaluator_ref: dict[str, str],
) -> dict[str, Any]:
    value = {
        "schema_version": CONSENT_SCHEMA,
        "assessment_id": assessment_id,
        "created_at": created_at,
        "status": MATERIAL_STATUS,
        "plan": copy.deepcopy(plan_ref),
        "prior_consent_manifest": {
            **copy.deepcopy(prior_consent_ref),
            "immutable": True,
        },
        "amended_materials": {
            "confirmatory_method": copy.deepcopy(method_ref),
            "protocol_addendum": copy.deepcopy(protocol_addendum_ref),
            "evaluator_addendum": copy.deepcopy(evaluator_ref),
        },
        "impact": {
            "task_or_treatment_scope_changed": False,
            "participant_data_fields_changed": False,
            "advice_adherence_observation_added": False,
            "confirmatory_use_and_claim_semantics_changed": True,
            "prior_signed_statistical_plan_hash_changed": True,
        },
        "decision": {
            "prior_consent_inherited": False,
            "new_consent_extension_required": True,
            "required_participant_count": 40,
            "each_signature_must_bind_promoted_bundle": True,
            "decline_without_penalty_required": True,
        },
        "execution_boundary": copy.deepcopy(BOUNDARY),
    }
    return _seal(value, "assessment_sha256")


def build_verification(
    *,
    verification_id: str,
    created_at: str,
    plan_ref: dict[str, str],
    method_ref: dict[str, str],
) -> dict[str, Any]:
    scenarios = [
        _scenario("all_positive", [1] * 20, [Fraction(1, 2)] * 20, True),
        _scenario("all_zero", [0] * 20, [0] * 20, True),
        _scenario("all_negative", [-1] * 20, [Fraction(-1, 2)] * 20, True),
        _scenario("mixed_symmetric", [1, -1] * 10, [1, -1] * 10, True),
        _scenario("primary_only", [1] * 20, [0] * 20, True),
        _scenario("secondary_only", [0] * 20, [Fraction(1, 3)] * 20, True),
        _scenario("structural_failure", [], [], False),
        _scenario("rational_denominators", [1] * 20, [Fraction(1, 3)] * 20, True),
    ]
    value = {
        "schema_version": VERIFICATION_SCHEMA,
        "verification_id": verification_id,
        "created_at": created_at,
        "status": MATERIAL_STATUS,
        "plan": copy.deepcopy(plan_ref),
        "confirmatory_method": copy.deepcopy(method_ref),
        "scenario_count": len(scenarios),
        "scenarios": scenarios,
        "passed": all(item["passed"] for item in scenarios),
        "execution_boundary": copy.deepcopy(BOUNDARY),
    }
    return _seal(value, "verification_sha256")


def build_bundle(
    *,
    bundle_id: str,
    created_at: str,
    plan_ref: dict[str, str],
    method_ref: dict[str, str],
    protocol_addendum_ref: dict[str, str],
    evaluator_ref: dict[str, str],
    consent_ref: dict[str, str],
    verification_ref: dict[str, str],
    implementation: dict[str, str],
) -> dict[str, Any]:
    materials = {
        "confirmatory_method": copy.deepcopy(method_ref),
        "protocol_addendum": copy.deepcopy(protocol_addendum_ref),
        "evaluator_addendum": copy.deepcopy(evaluator_ref),
        "consent_impact": copy.deepcopy(consent_ref),
        "verification": copy.deepcopy(verification_ref),
    }
    value = {
        "schema_version": BUNDLE_SCHEMA,
        "bundle_id": bundle_id,
        "created_at": created_at,
        "status": MATERIAL_STATUS,
        "plan": copy.deepcopy(plan_ref),
        "materials": materials,
        "inventory": {
            "material_count": len(materials),
            "verification_scenario_count": 8,
            "participant_count": 40,
            "matched_pair_count": 20,
            "new_consent_signature_count_required": 40,
        },
        "implementation": copy.deepcopy(implementation),
        "readiness": {
            "independent_review_required": True,
            "promotion_allowed": False,
            "execution_preflight_allowed": False,
            "effectiveness_claim_allowed": False,
        },
        "execution_boundary": copy.deepcopy(BOUNDARY),
    }
    return _seal(value, "bundle_sha256")


def build_preflight(
    *,
    bundle_ref: dict[str, str],
    bundle: dict[str, Any],
    postmortem_gate_ref: dict[str, str],
) -> dict[str, Any]:
    failures = validate_bundle(bundle)
    if postmortem_gate_ref.get("canonical_sha256") != POSTMORTEM_GATE_SHA256:
        failures.append("postmortem_promotion_gate_binding_invalid")
    statement = owner_review_statement(bundle_ref=bundle_ref, bundle=bundle)
    value = {
        "schema_version": PREFLIGHT_SCHEMA,
        "bundle": copy.deepcopy(bundle_ref),
        "postmortem_promotion_gate": copy.deepcopy(postmortem_gate_ref),
        "passed": not failures,
        "failure_reasons": list(dict.fromkeys(failures)),
        "required_owner_statement": statement,
        "required_owner_statement_sha256": hashlib.sha256(
            statement.encode()
        ).hexdigest(),
        "execution_boundary": copy.deepcopy(BOUNDARY),
        "state": (
            "confirmatory_method_amendment_owner_review_only_approval_required"
            if not failures
            else "confirmatory_method_amendment_preflight_failed"
        ),
    }
    return _seal(value, "report_sha256")


def owner_review_statement(
    *,
    bundle_ref: dict[str, str],
    bundle: dict[str, Any],
) -> str:
    materials = bundle["materials"]
    return (
        "I approve for independent review only the J1-D outcome-sensitive "
        f"confirmatory-method amendment bundle raw SHA-256 {bundle_ref['sha256']}, "
        f"canonical SHA-256 {bundle['bundle_sha256']}, containing exact paired "
        f"method {materials['confirmatory_method']['canonical_sha256']}, protocol "
        f"addendum {materials['protocol_addendum']['canonical_sha256']}, evaluator "
        f"addendum {materials['evaluator_addendum']['canonical_sha256']}, consent "
        f"impact {materials['consent_impact']['canonical_sha256']}, and verification "
        f"{materials['verification']['canonical_sha256']}. I acknowledge that the "
        "method prospectively freezes a one-sided exact 20-pair sign-flip test, "
        "zero-effect and tail-tie retention, exact rational p-values, and a "
        "primary-before-secondary Holm tie order at familywise alpha 0.05. The r4 "
        "run remains immutable and may not be reanalyzed for a confirmatory claim. "
        "No task, treatment, fixture, assignment, decision field, provider, or model "
        "changes; advice adherence remains unobserved and deferred to a separate "
        "protocol-schema review. I acknowledge that prior consent is not inherited "
        "and 40 of 40 new consent extensions remain required after independent "
        "promotion. This approval permits independent human review only. It does "
        "not promote any material, migrate consent, create or start a container, "
        "read a provider credential, call a provider or model, execute an Agent or "
        "task, append Backend Facts or the Ledger, issue or consume an execution "
        "authorization, authorize an effectiveness or causal claim, or upgrade "
        "SI-13 maturity."
    )


def validate_material(
    value: Any,
    *,
    schema: str,
    hash_field: str,
) -> list[str]:
    material = value if isinstance(value, dict) else {}
    failures: list[str] = []
    if not (
        material.get("schema_version") == schema
        and material.get("status") == MATERIAL_STATUS
        and material.get("execution_boundary") == BOUNDARY
        and _self_hash(material, hash_field)
    ):
        failures.append("confirmatory_material_contract_invalid")
    return failures


def validate_bundle(value: Any) -> list[str]:
    bundle = value if isinstance(value, dict) else {}
    failures: list[str] = []
    materials = bundle.get("materials", {})
    readiness = bundle.get("readiness", {})
    if not (
        bundle.get("schema_version") == BUNDLE_SCHEMA
        and bundle.get("status") == MATERIAL_STATUS
        and isinstance(materials, dict)
        and set(materials)
        == {
            "confirmatory_method",
            "protocol_addendum",
            "evaluator_addendum",
            "consent_impact",
            "verification",
        }
        and all(_valid_ref(item) for item in materials.values())
        and readiness.get("independent_review_required") is True
        and readiness.get("promotion_allowed") is False
        and readiness.get("execution_preflight_allowed") is False
        and readiness.get("effectiveness_claim_allowed") is False
        and bundle.get("execution_boundary") == BOUNDARY
        and _self_hash(bundle, "bundle_sha256")
    ):
        failures.append("confirmatory_bundle_contract_invalid")
    return failures


def validate_preflight(value: Any) -> list[str]:
    report = value if isinstance(value, dict) else {}
    failures: list[str] = []
    statement = report.get("required_owner_statement")
    if not (
        report.get("schema_version") == PREFLIGHT_SCHEMA
        and report.get("passed") is True
        and report.get("failure_reasons") == []
        and report.get("state")
        == "confirmatory_method_amendment_owner_review_only_approval_required"
        and isinstance(statement, str)
        and hashlib.sha256(statement.encode()).hexdigest()
        == report.get("required_owner_statement_sha256")
        and report.get("execution_boundary") == BOUNDARY
        and _self_hash(report, "report_sha256")
    ):
        failures.append("confirmatory_preflight_contract_invalid")
    return failures


def _scenario(
    scenario_id: str,
    maturity: list[Fraction | int],
    repeated: list[Fraction | int],
    structural_passed: bool,
) -> dict[str, Any]:
    result = evaluate_confirmatory_effects(
        maturity_effects=maturity,
        repeated_error_effects=repeated,
        structural_passed=structural_passed,
    )
    return {
        "scenario_id": scenario_id,
        "result": result,
        "passed": (
            result.get("valid") is structural_passed
            and result.get("effectiveness_claim_authorized") is not True
        ),
    }


def _require_source_set(sources: dict[str, dict[str, str]]) -> None:
    expected = {
        "postmortem_promotion_gate": POSTMORTEM_GATE_SHA256,
        "frozen_postmortem": FROZEN_POSTMORTEM_SHA256,
        "parent_protocol": PARENT_PROTOCOL_SHA256,
        "parent_evaluator": PARENT_EVALUATOR_SHA256,
        "parent_statistical_plan": PARENT_STATISTICAL_SHA256,
        "task_fixture": FIXTURE_SHA256,
        "reviewed_assignment": ASSIGNMENT_SHA256,
        "prior_consent_manifest": None,
    }
    if set(sources) != set(expected):
        raise ValueError("confirmatory amendment source inventory invalid")
    for name, canonical in expected.items():
        if not _valid_ref(sources[name]):
            raise ValueError(f"confirmatory amendment source ref invalid: {name}")
        if canonical is not None and sources[name]["canonical_sha256"] != canonical:
            raise ValueError(f"confirmatory amendment source binding invalid: {name}")


def _seal(value: dict[str, Any], field: str) -> dict[str, Any]:
    value[field] = canonical_sha256(value)
    return value


def _self_hash(value: dict[str, Any], field: str) -> bool:
    body = {key: item for key, item in value.items() if key != field}
    return value.get(field) == canonical_sha256(body)


def _valid_ref(value: Any) -> bool:
    return (
        isinstance(value, dict)
        and isinstance(value.get("path"), str)
        and _sha256(value.get("sha256"))
        and _sha256(value.get("canonical_sha256"))
    )


def _sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _fraction(value: Fraction) -> dict[str, int]:
    return {"numerator": value.numerator, "denominator": value.denominator}
