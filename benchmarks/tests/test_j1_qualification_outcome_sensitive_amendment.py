from __future__ import annotations

import copy

from benchmarks.j1.controlled_comparison import canonical_sha256
from benchmarks.j1.qualification_outcome_sensitive_amendment import (
    BOUNDARY,
    CONSENT_SCHEMA,
    FIXTURE_SCHEMA,
    build_bundle,
    build_consent_impact,
    build_evaluator_amendment,
    build_preflight,
    build_protocol_amendment,
    build_statistical_plan,
    build_task_fixture_manifest,
    validate_bundle,
    validate_material,
    validate_preflight,
)


CREATED_AT = "2026-07-28T13:00:00+00:00"


def _ref(label: str, canonical: str | None = None) -> dict[str, str]:
    return {
        "path": f"/private/{label}.json",
        "sha256": canonical_sha256([label, "raw"]),
        "canonical_sha256": canonical or canonical_sha256([label, "canonical"]),
    }


def _chain() -> dict[str, object]:
    plan_ref = _ref("plan")
    candidate_ref = _ref("reviewed-candidate")
    fixture = build_task_fixture_manifest(
        fixture_id="fixture-r1",
        created_at=CREATED_AT,
        plan_ref=plan_ref,
        reviewed_candidate_ref=candidate_ref,
    )
    fixture_ref = _ref("fixture", fixture["fixture_sha256"])
    statistical = build_statistical_plan(
        statistical_plan_id="stats-r1",
        created_at=CREATED_AT,
        plan_ref=plan_ref,
        fixture_ref=fixture_ref,
    )
    statistical_ref = _ref("stats", statistical["statistical_plan_sha256"])
    protocol = build_protocol_amendment(
        protocol_id="protocol-r1",
        created_at=CREATED_AT,
        plan_ref=plan_ref,
        current_protocol_ref=_ref("current-protocol"),
        fixture_ref=fixture_ref,
        statistical_plan_ref=statistical_ref,
        current_protocol={
            "amended_frozen_stack": {
                "provider_id": "openai_compatible",
                "model_id": "deepseek-v4-pro",
                "temperature": 0,
            }
        },
    )
    protocol_ref = _ref("protocol", protocol["protocol_sha256"])
    evaluator = build_evaluator_amendment(
        evaluator_id="evaluator-r1",
        created_at=CREATED_AT,
        plan_ref=plan_ref,
        current_evaluator_ref=_ref("current-evaluator"),
        protocol_ref=protocol_ref,
        fixture_ref=fixture_ref,
        statistical_plan_ref=statistical_ref,
    )
    evaluator_ref = _ref("evaluator", evaluator["evaluator_sha256"])
    consent = build_consent_impact(
        assessment_id="consent-r1",
        created_at=CREATED_AT,
        plan_ref=plan_ref,
        current_consent_ref=_ref("current-consent"),
        protocol_ref=protocol_ref,
        evaluator_ref=evaluator_ref,
        fixture_ref=fixture_ref,
        statistical_plan_ref=statistical_ref,
    )
    consent_ref = _ref("consent", consent["assessment_sha256"])
    bundle = build_bundle(
        bundle_id="bundle-r1",
        created_at=CREATED_AT,
        plan_ref=plan_ref,
        fixture_ref=fixture_ref,
        statistical_plan_ref=statistical_ref,
        protocol_ref=protocol_ref,
        evaluator_ref=evaluator_ref,
        consent_impact_ref=consent_ref,
        implementation={
            "source_revision": "a" * 40,
            "domain_source_sha256": "b" * 64,
            "operation_source_sha256": "c" * 64,
        },
    )
    return {
        "fixture": fixture,
        "statistical": statistical,
        "protocol": protocol,
        "evaluator": evaluator,
        "consent": consent,
        "bundle": bundle,
    }


def test_builds_twelve_task_content_addressed_fixture() -> None:
    fixture = _chain()["fixture"]
    assert len(fixture["fixtures"]) == 12
    assert [item["task_ordinal"] for item in fixture["fixtures"]] == list(range(1, 13))
    assert all(
        item["ground_truth_commitment_sha256"]
        == canonical_sha256(item["ground_truth"])
        for item in fixture["fixtures"]
    )
    assert (
        validate_material(
            fixture,
            schema=FIXTURE_SCHEMA,
            hash_field="fixture_sha256",
        )
        == []
    )


def test_baseline_is_treatment_free_and_control_advice_empty() -> None:
    protocol = _chain()["protocol"]
    treatment = protocol["treatment_contract"]
    assert treatment["baseline_ordinals"] == [1, 2, 3]
    assert treatment["baseline_mentor_advice_allowed"] is False
    assert treatment["treatment_ordinals"] == list(range(4, 13))
    assert treatment["control_advice_projection"] == []


def test_statistical_plan_refuses_invented_power_claim() -> None:
    statistical = _chain()["statistical"]
    assert statistical["power_disclosure"]["prospective_power_claim_made"] is False
    assert statistical["analysis"]["all_20_pairs_required"] is True
    assert statistical["analysis"]["outcome_based_exclusion_allowed"] is False


def test_consent_impact_requires_forty_new_signatures() -> None:
    consent = _chain()["consent"]
    assert consent["impact"]["scope_materially_changed"] is True
    assert consent["decision"]["prior_consent_inherited"] is False
    assert consent["decision"]["required_participant_count"] == 40
    assert (
        validate_material(
            consent,
            schema=CONSENT_SCHEMA,
            hash_field="assessment_sha256",
        )
        == []
    )


def test_bundle_remains_fail_closed() -> None:
    bundle = _chain()["bundle"]
    assert validate_bundle(bundle) == []
    assert bundle["execution_boundary"] == BOUNDARY
    assert bundle["readiness"]["execution_preflight_allowed"] is False
    assert bundle["readiness"]["si13_maturity_upgrade_allowed"] is False


def test_bundle_rejects_material_ref_drift() -> None:
    bundle = copy.deepcopy(_chain()["bundle"])
    bundle["materials"]["protocol"]["canonical_sha256"] = "not-a-hash"
    bundle["bundle_sha256"] = canonical_sha256(
        {key: item for key, item in bundle.items() if key != "bundle_sha256"}
    )
    assert "bundle_material_inventory_invalid" in validate_bundle(bundle)


def test_owner_preflight_is_review_only() -> None:
    bundle = _chain()["bundle"]
    bundle_ref = _ref("bundle", bundle["bundle_sha256"])
    gate_ref = _ref("promotion-gate")
    preflight = build_preflight(
        bundle_ref=bundle_ref,
        promotion_gate_ref=gate_ref,
    )
    statement = preflight["required_owner_statement"]
    assert preflight["passed"] is True
    assert "480 participant decisions" in statement
    assert "40 of 40 new consent extensions" in statement
    assert "independent human review only" in statement
    assert preflight["execution_boundary"] == BOUNDARY
    assert validate_preflight(preflight) == []
