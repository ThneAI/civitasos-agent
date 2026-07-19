"""Stable, non-executable contracts for the J.1 mentorship path."""

from __future__ import annotations

import hashlib
import json
from typing import Any


BUNDLE_SCHEMA = "j1-mentorship-contract-bundle:v1"
RELATION_SCHEMA = "j1-mentorship-relation:v1"
OBSERVATION_SCHEMA = "j1-mentor-observation:v1"
ADVICE_SCHEMA = "j1-mentor-advice:v1"
DECISION_SCHEMA = "j1-advice-decision:v1"
OUTCOME_SCHEMA = "j1-advice-outcome:v1"

ALLOWED_MEMORY_RECORD_KINDS = {
    "episodic_error_pattern",
    "lesson_reference",
    "task_outcome",
}
ALLOWED_DECISIONS = {"accepted", "rejected", "deferred"}
REQUIRED_NON_CLAIMS = {
    "contract_validation_does_not_activate_mentorship",
    "mentor_advice_does_not_execute_apprentice_actions",
    "advice_outcome_does_not_prove_causality",
    "j1_contracts_do_not_claim_group_intelligence",
    "j1_contracts_do_not_authorize_production",
}
FALSE_EXECUTION_BOUNDARIES = {
    "mentorship_activation_allowed",
    "automatic_matching_allowed",
    "fact_append_allowed",
    "runtime_advice_injection_allowed",
    "agent_or_model_execution_allowed",
    "external_side_effect_allowed",
    "production_transition_allowed",
    "production_receipt_write_allowed",
}


def canonical_sha256(value: Any) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def validate_bundle(value: Any) -> list[str]:
    failures: list[str] = []
    bundle = _object(value, "bundle", failures)
    if not bundle:
        if "bundle_must_be_object" not in failures:
            failures.append("bundle_must_not_be_empty")
        return failures
    _require(bundle.get("schema_version") == BUNDLE_SCHEMA, "bundle_schema_invalid", failures)

    relation = _object(bundle.get("relation"), "relation", failures)
    observation = _object(bundle.get("observation"), "observation", failures)
    advice = _object(bundle.get("advice"), "advice", failures)
    decision = _object(bundle.get("decision"), "decision", failures)
    outcome = _object(bundle.get("outcome"), "outcome", failures)

    _validate_relation(relation, failures)
    _validate_observation(observation, relation, failures)
    _validate_advice(advice, relation, observation, failures)
    _validate_decision(decision, relation, advice, failures)
    _validate_outcome(outcome, advice, decision, failures)
    _validate_execution_boundary(bundle.get("execution_boundary"), failures)

    non_claims = _strings(bundle.get("non_claims"))
    _require(
        REQUIRED_NON_CLAIMS.issubset(non_claims),
        "required_non_claims_missing",
        failures,
    )
    return failures


def contract_hashes(bundle: dict[str, Any]) -> dict[str, str]:
    return {
        name: canonical_sha256(bundle.get(name))
        for name in ("relation", "observation", "advice", "decision", "outcome")
    }


def _validate_relation(value: dict[str, Any], failures: list[str]) -> None:
    _require(value.get("schema_version") == RELATION_SCHEMA, "relation_schema_invalid", failures)
    _require(_text(value.get("relation_id")), "relation_id_missing", failures)
    mentor = _text(value.get("mentor_did"))
    apprentice = _text(value.get("apprentice_did"))
    _require(mentor.startswith("did:"), "mentor_did_invalid", failures)
    _require(apprentice.startswith("did:"), "apprentice_did_invalid", failures)
    _require(mentor != apprentice, "mentor_and_apprentice_must_differ", failures)
    scope = _strings(value.get("capability_scope"))
    _require(bool(scope) and len(scope) == len(set(scope)), "capability_scope_invalid", failures)

    lifecycle = _object(value.get("lifecycle"), "relation_lifecycle", failures)
    _require(lifecycle.get("state") == "proposed", "relation_state_must_be_proposed", failures)
    activation = set(_strings(lifecycle.get("activation_requires")))
    _require(
        {"mentor_consent", "apprentice_consent", "valid_credentials"}.issubset(activation),
        "relation_activation_requirements_incomplete",
        failures,
    )
    _require(
        lifecycle.get("unilateral_activation_allowed") is False,
        "unilateral_activation_must_be_false",
        failures,
    )
    _require(
        lifecycle.get("automatic_matching_allowed") is False,
        "automatic_matching_must_be_false",
        failures,
    )

    projection = _object(value.get("memory_projection"), "memory_projection", failures)
    kinds = set(_strings(projection.get("allowed_record_kinds")))
    _require(
        projection.get("mode") == "scoped_projection_only",
        "memory_projection_mode_invalid",
        failures,
    )
    _require(
        bool(kinds) and kinds.issubset(ALLOWED_MEMORY_RECORD_KINDS),
        "memory_projection_scope_invalid",
        failures,
    )
    _require(
        projection.get("raw_memory_access_allowed") is False,
        "raw_memory_access_must_be_false",
        failures,
    )
    _require(
        projection.get("hidden_chain_of_thought_access_allowed") is False,
        "hidden_chain_of_thought_access_must_be_false",
        failures,
    )
    _require(
        projection.get("apprentice_consent_required") is True,
        "memory_projection_requires_apprentice_consent",
        failures,
    )
    _require(
        projection.get("revocation_enforced") is True,
        "memory_projection_requires_revocation",
        failures,
    )


def _validate_observation(
    value: dict[str, Any], relation: dict[str, Any], failures: list[str]
) -> None:
    _require(value.get("schema_version") == OBSERVATION_SCHEMA, "observation_schema_invalid", failures)
    _require(_text(value.get("observation_id")), "observation_id_missing", failures)
    _require(value.get("relation_id") == relation.get("relation_id"), "observation_relation_mismatch", failures)
    _require(
        value.get("apprentice_did") == relation.get("apprentice_did"),
        "observation_apprentice_mismatch",
        failures,
    )
    _require(_text(value.get("pattern_id")), "observation_pattern_id_missing", failures)
    refs = value.get("occurrence_refs")
    _require(
        isinstance(refs, list) and len(refs) >= 2,
        "observation_requires_repeated_occurrences",
        failures,
    )
    for index, ref in enumerate(refs if isinstance(refs, list) else []):
        _validate_ref(ref, f"observation_occurrence_ref_{index}_invalid", failures)
    _require(
        value.get("raw_memory_included") is False,
        "observation_raw_memory_must_be_false",
        failures,
    )


def _validate_advice(
    value: dict[str, Any],
    relation: dict[str, Any],
    observation: dict[str, Any],
    failures: list[str],
) -> None:
    _require(value.get("schema_version") == ADVICE_SCHEMA, "advice_schema_invalid", failures)
    _require(_text(value.get("advice_id")), "advice_id_missing", failures)
    _require(value.get("relation_id") == relation.get("relation_id"), "advice_relation_mismatch", failures)
    _require(value.get("observation_id") == observation.get("observation_id"), "advice_observation_mismatch", failures)
    _require(value.get("mentor_did") == relation.get("mentor_did"), "advice_mentor_mismatch", failures)
    _require(value.get("apprentice_did") == relation.get("apprentice_did"), "advice_apprentice_mismatch", failures)
    _require(_text(value.get("recommendation")), "advice_recommendation_missing", failures)
    _require(_text(value.get("nonce")), "advice_nonce_missing", failures)
    _require(_text(value.get("expires_at")), "advice_expiry_missing", failures)

    boundary = _object(value.get("boundary"), "advice_boundary", failures)
    _require(boundary.get("advisory_only") is True, "advice_must_be_advisory_only", failures)
    for field in (
        "direct_execution_allowed",
        "constitution_override_allowed",
        "normative_mutation_allowed",
        "identity_mutation_allowed",
        "memory_mutation_allowed",
    ):
        _require(boundary.get(field) is False, f"advice_{field}_must_be_false", failures)


def _validate_decision(
    value: dict[str, Any],
    relation: dict[str, Any],
    advice: dict[str, Any],
    failures: list[str],
) -> None:
    _require(value.get("schema_version") == DECISION_SCHEMA, "decision_schema_invalid", failures)
    _require(_text(value.get("decision_id")), "decision_id_missing", failures)
    _require(value.get("advice_id") == advice.get("advice_id"), "decision_advice_mismatch", failures)
    _require(
        value.get("decided_by") == relation.get("apprentice_did"),
        "decision_actor_must_be_apprentice",
        failures,
    )
    _require(value.get("decision") in ALLOWED_DECISIONS, "decision_value_invalid", failures)
    _require(_text(value.get("rationale")), "decision_rationale_missing", failures)
    _require(
        value.get("mentor_decision_allowed") is False,
        "mentor_decision_must_be_false",
        failures,
    )


def _validate_outcome(
    value: dict[str, Any],
    advice: dict[str, Any],
    decision: dict[str, Any],
    failures: list[str],
) -> None:
    _require(value.get("schema_version") == OUTCOME_SCHEMA, "outcome_schema_invalid", failures)
    _require(_text(value.get("outcome_id")), "outcome_id_missing", failures)
    _require(value.get("advice_id") == advice.get("advice_id"), "outcome_advice_mismatch", failures)
    _require(value.get("decision_id") == decision.get("decision_id"), "outcome_decision_mismatch", failures)
    refs = value.get("task_outcome_refs")
    _require(isinstance(refs, list) and bool(refs), "outcome_refs_missing", failures)
    for index, ref in enumerate(refs if isinstance(refs, list) else []):
        _validate_ref(ref, f"outcome_ref_{index}_invalid", failures)
    _require(isinstance(value.get("error_recurred"), bool), "outcome_error_recurred_invalid", failures)
    attribution = _object(value.get("attribution"), "outcome_attribution", failures)
    _require(
        attribution.get("causal_claim_allowed") is False,
        "outcome_causal_claim_must_be_false",
        failures,
    )
    _require(
        attribution.get("mode") == "correlation_only",
        "outcome_attribution_mode_invalid",
        failures,
    )


def _validate_execution_boundary(value: Any, failures: list[str]) -> None:
    boundary = _object(value, "execution_boundary", failures)
    _require(boundary.get("contract_fixture_only") is True, "contract_fixture_only_required", failures)
    for field in FALSE_EXECUTION_BOUNDARIES:
        _require(boundary.get(field) is False, f"{field}_must_be_false", failures)


def _validate_ref(value: Any, code: str, failures: list[str]) -> None:
    ref = value if isinstance(value, dict) else {}
    digest = _text(ref.get("sha256"))
    valid = bool(_text(ref.get("id"))) and len(digest) == 64
    valid = valid and all(char in "0123456789abcdef" for char in digest)
    _require(valid, code, failures)


def _object(value: Any, label: str, failures: list[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        failures.append(f"{label}_must_be_object")
        return {}
    return value


def _strings(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [text for item in value if (text := _text(item))]


def _text(value: Any) -> str:
    return str(value or "").strip()


def _require(condition: bool, code: str, failures: list[str]) -> None:
    if not condition and code not in failures:
        failures.append(code)
