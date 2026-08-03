from __future__ import annotations

import copy
from fractions import Fraction

import pytest

from benchmarks.j1.controlled_comparison import canonical_sha256
from benchmarks.j1.qualification_outcome_sensitive_confirmatory import (
    evaluate_confirmatory_effects,
    exact_paired_sign_flip_test,
    holm_step_down,
)
from benchmarks.j1.qualification_outcome_sensitive_confirmatory_amendment import (
    ASSIGNMENT_SHA256,
    BOUNDARY,
    FIXTURE_SHA256,
    FROZEN_POSTMORTEM_SHA256,
    PARENT_EVALUATOR_SHA256,
    PARENT_PROTOCOL_SHA256,
    PARENT_STATISTICAL_SHA256,
    POSTMORTEM_GATE_SHA256,
    build_bundle,
    build_consent_impact,
    build_evaluator_addendum,
    build_method,
    build_plan,
    build_preflight,
    build_protocol_addendum,
    build_verification,
    validate_bundle,
    validate_preflight,
)


CREATED_AT = "2026-08-03T14:00:00+00:00"


def _ref(name: str, canonical: str = "a" * 64) -> dict[str, str]:
    return {
        "path": f"/private/{name}.json",
        "sha256": "b" * 64,
        "canonical_sha256": canonical,
    }


def _sources() -> dict[str, dict[str, str]]:
    return {
        "postmortem_promotion_gate": _ref("gate", POSTMORTEM_GATE_SHA256),
        "frozen_postmortem": _ref("postmortem", FROZEN_POSTMORTEM_SHA256),
        "parent_protocol": _ref("protocol", PARENT_PROTOCOL_SHA256),
        "parent_evaluator": _ref("evaluator", PARENT_EVALUATOR_SHA256),
        "parent_statistical_plan": _ref(
            "statistical",
            PARENT_STATISTICAL_SHA256,
        ),
        "task_fixture": _ref("fixture", FIXTURE_SHA256),
        "reviewed_assignment": _ref("assignment", ASSIGNMENT_SHA256),
        "prior_consent_manifest": _ref("consent"),
    }


def _chain() -> dict[str, object]:
    implementation = {
        "source_revision": "1" * 40,
        "confirmatory_source_sha256": "2" * 64,
        "amendment_source_sha256": "3" * 64,
        "operation_source_sha256": "4" * 64,
    }
    plan = build_plan(
        amendment_id="confirmatory-r1",
        created_at=CREATED_AT,
        sources=_sources(),
        implementation=implementation,
    )
    plan_ref = _ref("plan", plan["plan_sha256"])
    method = build_method(
        method_id="method-r1",
        created_at=CREATED_AT,
        plan_ref=plan_ref,
        parent_statistical_ref=_sources()["parent_statistical_plan"],
    )
    method_ref = _ref("method", method["method_sha256"])
    protocol = build_protocol_addendum(
        addendum_id="protocol-r1",
        created_at=CREATED_AT,
        plan_ref=plan_ref,
        parent_protocol_ref=_sources()["parent_protocol"],
        method_ref=method_ref,
    )
    protocol_ref = _ref("protocol-addendum", protocol["addendum_sha256"])
    evaluator = build_evaluator_addendum(
        evaluator_id="evaluator-r1",
        created_at=CREATED_AT,
        plan_ref=plan_ref,
        parent_evaluator_ref=_sources()["parent_evaluator"],
        method_ref=method_ref,
        protocol_addendum_ref=protocol_ref,
        implementation=implementation,
    )
    evaluator_ref = _ref("evaluator-addendum", evaluator["evaluator_sha256"])
    consent = build_consent_impact(
        assessment_id="consent-r1",
        created_at=CREATED_AT,
        plan_ref=plan_ref,
        prior_consent_ref=_sources()["prior_consent_manifest"],
        method_ref=method_ref,
        protocol_addendum_ref=protocol_ref,
        evaluator_ref=evaluator_ref,
    )
    consent_ref = _ref("consent-impact", consent["assessment_sha256"])
    verification = build_verification(
        verification_id="verification-r1",
        created_at=CREATED_AT,
        plan_ref=plan_ref,
        method_ref=method_ref,
    )
    verification_ref = _ref(
        "verification",
        verification["verification_sha256"],
    )
    bundle = build_bundle(
        bundle_id="bundle-r1",
        created_at=CREATED_AT,
        plan_ref=plan_ref,
        method_ref=method_ref,
        protocol_addendum_ref=protocol_ref,
        evaluator_ref=evaluator_ref,
        consent_ref=consent_ref,
        verification_ref=verification_ref,
        implementation=implementation,
    )
    return {
        "plan": plan,
        "method": method,
        "protocol": protocol,
        "evaluator": evaluator,
        "consent": consent,
        "verification": verification,
        "bundle": bundle,
    }


def test_exact_sign_flip_all_positive_is_one_in_two_power_n() -> None:
    result = exact_paired_sign_flip_test([1] * 20)
    assert result["assignment_count"] == 1_048_576
    assert result["extreme_assignment_count"] == 1
    assert result["p_value"] == {"numerator": 1, "denominator": 1_048_576}


def test_exact_sign_flip_retains_zero_effects_and_tail_ties() -> None:
    result = exact_paired_sign_flip_test([1, 0, 0])
    assert result["zero_pair_effect_count"] == 2
    assert result["assignment_count"] == 8
    assert result["extreme_assignment_count"] == 4
    assert result["p_value"] == {"numerator": 1, "denominator": 2}


def test_exact_sign_flip_uses_exact_rational_arithmetic() -> None:
    result = exact_paired_sign_flip_test([Fraction(1, 3)] * 4)
    assert result["observed_mean"] == {"numerator": 1, "denominator": 3}
    assert result["p_value"] == {"numerator": 1, "denominator": 16}


def test_holm_freezes_primary_before_secondary_for_equal_p_values() -> None:
    result = holm_step_down(
        {
            "strategy_maturity_time": Fraction(1, 100),
            "repeated_error_rate": Fraction(1, 100),
        }
    )
    assert result["endpoint_order_after_sort"] == [
        "strategy_maturity_time",
        "repeated_error_rate",
    ]
    assert result["all_confirmatory_endpoints_rejected"] is True


def test_holm_stops_after_first_non_rejection() -> None:
    result = holm_step_down(
        {
            "strategy_maturity_time": Fraction(3, 100),
            "repeated_error_rate": Fraction(4, 100),
        }
    )
    assert result["rejected"] == {
        "strategy_maturity_time": False,
        "repeated_error_rate": False,
    }


def test_confirmatory_evaluation_fails_closed_on_structural_failure() -> None:
    result = evaluate_confirmatory_effects(
        maturity_effects=[],
        repeated_error_effects=[],
        structural_passed=False,
    )
    assert result["valid"] is False
    assert result["confirmatory_endpoints_rejected"] is False
    assert result["effectiveness_thresholds_met"] is False


def test_confirmatory_rejection_does_not_bypass_other_effectiveness_gates() -> None:
    result = evaluate_confirmatory_effects(
        maturity_effects=[1] * 20,
        repeated_error_effects=[Fraction(1, 2)] * 20,
        structural_passed=True,
    )
    assert result["confirmatory_endpoints_rejected"] is True
    assert result["effectiveness_thresholds_met"] is False
    assert result["effectiveness_claim_authorized"] is False


def test_method_amendment_preserves_measurement_boundary() -> None:
    chain = _chain()
    method = chain["method"]
    plan = chain["plan"]
    assert plan["scope"]["analysis_method_change_only"] is True
    assert plan["scope"]["advice_adherence_observation_added"] is False
    assert method["measurement_boundary"]["advice_adherence_observed"] is False
    assert method["test"]["assignment_count"] == 1_048_576
    assert method["multiplicity"]["equal_p_value_tie_order"] == [
        "strategy_maturity_time",
        "repeated_error_rate",
    ]


def test_consent_does_not_inherit_old_statistical_hash() -> None:
    consent = _chain()["consent"]
    assert consent["impact"]["participant_data_fields_changed"] is False
    assert consent["impact"]["confirmatory_use_and_claim_semantics_changed"] is True
    assert consent["decision"]["prior_consent_inherited"] is False
    assert consent["decision"]["required_participant_count"] == 40


def test_verification_covers_eight_fail_closed_scenarios() -> None:
    verification = _chain()["verification"]
    assert verification["scenario_count"] == 8
    assert verification["passed"] is True
    assert all(item["passed"] for item in verification["scenarios"])


def test_bundle_and_preflight_remain_review_only() -> None:
    bundle = _chain()["bundle"]
    bundle_ref = _ref("bundle", bundle["bundle_sha256"])
    preflight = build_preflight(
        bundle_ref=bundle_ref,
        bundle=bundle,
        postmortem_gate_ref=_sources()["postmortem_promotion_gate"],
    )
    assert validate_bundle(bundle) == []
    assert validate_preflight(preflight) == []
    assert bundle["execution_boundary"] == BOUNDARY
    assert "40 of 40 new consent extensions" in preflight["required_owner_statement"]
    assert (
        "advice adherence remains unobserved" in preflight["required_owner_statement"]
    )


def test_bundle_rejects_material_ref_drift() -> None:
    bundle = copy.deepcopy(_chain()["bundle"])
    bundle["materials"]["confirmatory_method"]["canonical_sha256"] = "invalid"
    bundle["bundle_sha256"] = canonical_sha256(
        {key: value for key, value in bundle.items() if key != "bundle_sha256"}
    )
    assert validate_bundle(bundle) == ["confirmatory_bundle_contract_invalid"]


def test_plan_rejects_parent_statistical_drift() -> None:
    sources = _sources()
    sources["parent_statistical_plan"]["canonical_sha256"] = "f" * 64
    with pytest.raises(ValueError, match="source binding invalid"):
        build_plan(
            amendment_id="confirmatory-r1",
            created_at=CREATED_AT,
            sources=sources,
            implementation={"source_revision": "1" * 40},
        )
