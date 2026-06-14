"""Validate I.1 verifier preparation source assets."""

from __future__ import annotations

from typing import Any

from benchmarks.i1.data import as_object, check, objects, strings

ROSTER_SCHEMA = "i1-verifier-identity-roster:v1"
CORPUS_SCHEMA = "i1-verifier-fixed-corpus:v1"
CONTROL_SCHEMA = "i1-verifier-negative-controls:v1"
REQUIRED_CONTROL_TYPES = {
    "schema_error",
    "semantic_error",
    "hash_mismatch",
    "side_effect_request",
    "identity_conflict",
    "response_replay",
    "provider_homogeneity",
}

def validate_roster(
    roster: dict[str, Any],
    checks: dict[str, bool],
    failures: list[str],
) -> list[dict[str, Any]]:
    check(
        checks,
        failures,
        "identity_roster_schema_valid",
        roster.get("schema_version") == ROSTER_SCHEMA,
    )
    identities = objects(roster.get("identities"))
    aliases = [str(item.get("identity_alias") or "") for item in identities]
    verifier_aliases = {
        str(item.get("identity_alias"))
        for item in identities
        if "verifier" in strings(item.get("roles"))
    }
    allowlist = strings(roster.get("default_verifier_allowlist"))
    proposer = str(roster.get("proposer_identity_alias") or "")
    family_pairs = {
        (
            str(item.get("provider_family") or ""),
            str(item.get("runtime_family") or ""),
        )
        for item in identities
    }
    check(
        checks,
        failures,
        "stable_identity_count_sufficient",
        len(identities) >= int(roster.get("minimum_stable_identities", 5)),
    )
    check(
        checks,
        failures,
        "identity_aliases_unique",
        bool(aliases) and all(aliases) and len(aliases) == len(set(aliases)),
    )
    check(
        checks,
        failures,
        "verifier_count_sufficient",
        len(verifier_aliases) >= int(roster.get("minimum_verifiers", 3)),
    )
    check(
        checks,
        failures,
        "provider_runtime_independence_sufficient",
        len(family_pairs)
        >= int(roster.get("minimum_provider_runtime_families", 2))
        and all(provider and runtime for provider, runtime in family_pairs),
    )
    check(
        checks,
        failures,
        "proposer_excluded_from_default_quorum",
        bool(proposer)
        and proposer in aliases
        and proposer not in allowlist
        and set(allowlist).issubset(verifier_aliases)
        and len(set(allowlist)) >= int(roster.get("minimum_verifiers", 3)),
    )
    boundary = as_object(roster.get("boundary"))
    check(
        checks,
        failures,
        "identity_roster_boundary_safe",
        boundary.get("local_test_identities_only") is True
        and boundary.get("registration_required_before_i1") is True
        and boundary.get("signature_control_proof_required_before_i1") is True
        and boundary.get("model_credentials_in_roster") is False
        and boundary.get("i1_execution_allowed") is False
        and boundary.get("external_side_effect_allowed") is False,
    )
    return identities


def validate_corpus(
    corpus: dict[str, Any],
    checks: dict[str, bool],
    failures: list[str],
) -> list[dict[str, Any]]:
    check(
        checks,
        failures,
        "fixed_corpus_schema_valid",
        corpus.get("schema_version") == CORPUS_SCHEMA,
    )
    cases = objects(corpus.get("cases"))
    case_ids = [str(item.get("case_id") or "") for item in cases]
    valid = all(
        item.get("expected_verdict") == "accept"
        and bool(strings(item.get("acceptance_criteria")))
        and bool(as_object(item.get("artifact")))
        for item in cases
    )
    check(
        checks,
        failures,
        "positive_corpus_complete",
        len(cases) >= 4
        and all(case_ids)
        and len(case_ids) == len(set(case_ids))
        and valid,
    )
    boundary = as_object(corpus.get("boundary"))
    check(
        checks,
        failures,
        "fixed_corpus_boundary_safe",
        boundary.get("fixture_only") is True
        and boundary.get("contains_production_evidence") is False
        and boundary.get("i1_execution_allowed") is False
        and boundary.get("state_mutation_allowed") is False,
    )
    return cases


def validate_controls(
    controls: dict[str, Any],
    cases: list[dict[str, Any]],
    checks: dict[str, bool],
    failures: list[str],
) -> list[dict[str, Any]]:
    check(
        checks,
        failures,
        "negative_control_schema_valid",
        controls.get("schema_version") == CONTROL_SCHEMA,
    )
    records = objects(controls.get("controls"))
    case_ids = {str(item.get("case_id")) for item in cases}
    control_ids = [str(item.get("control_id") or "") for item in records]
    control_types = {str(item.get("control_type") or "") for item in records}
    valid = all(
        item.get("expected_verdict") == "reject"
        and bool(str(item.get("expected_failure_reason") or ""))
        and str(item.get("base_case_id") or "") in case_ids
        and bool(as_object(item.get("mutation")))
        for item in records
    )
    check(
        checks,
        failures,
        "negative_control_coverage_complete",
        REQUIRED_CONTROL_TYPES.issubset(control_types)
        and all(control_ids)
        and len(control_ids) == len(set(control_ids))
        and valid,
    )
    boundary = as_object(controls.get("boundary"))
    check(
        checks,
        failures,
        "negative_control_boundary_safe",
        boundary.get("fixture_only") is True
        and boundary.get("negative_controls_must_fail_closed") is True
        and boundary.get("i1_execution_allowed") is False
        and boundary.get("external_side_effect_allowed") is False,
    )
    return records
