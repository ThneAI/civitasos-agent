from __future__ import annotations

import copy

import pytest

from benchmarks.j1.controlled_comparison import canonical_sha256
from benchmarks.j1.qualification_real_evaluator import SOURCE_FIELDS
from benchmarks.j1_qualification_evaluation_closeout_candidate import (
    _source_binding,
    _validate_bundle,
    _validate_sources,
    approval_statement,
)


def _self_hash(value: dict, field: str) -> dict:
    result = copy.deepcopy(value)
    result[field] = canonical_sha256(result)
    return result


def _artifacts() -> dict[str, dict]:
    common_source = {"reviewed_verifier_v2_artifact_sha256": "1" * 64}
    verifier = _self_hash(
        {
            "schema_version": "j1-qualification-verifier-manifest:v2",
            "status": "operator_reviewed",
        },
        "manifest_sha256",
    )
    protocol = _self_hash(
        {
            "schema_version": "j1-qualification-protocol-amendment:v1",
            "status": "reviewed_plan_derived_consent_extension_required",
            "amendment_id": "amendment-r1",
            "source_binding": common_source,
            "amended_frozen_stack": {
                "verifier_manifest_sha256": verifier["manifest_sha256"]
            },
        },
        "amended_protocol_sha256",
    )
    design = _self_hash(
        {
            "schema_version": "j1-qualification-execution-design-amendment:v1",
            "status": "reviewed_plan_derived_consent_extension_required",
            "amendment_id": "amendment-r1",
            "source_binding": common_source,
        },
        "amended_design_sha256",
    )
    roster = _self_hash(
        {
            "schema_version": ("j1-qualification-roster-rebound:operator-reviewed:v1"),
            "status": "operator_reviewed",
            "participants": [{"participant_id": f"p-{index}"} for index in range(40)],
        },
        "reviewed_rebound_roster_sha256",
    )
    assignment = _self_hash(
        {
            "schema_version": (
                "j1-qualification-cohort-assignment-rebound:operator-reviewed:v1"
            ),
            "status": "operator_reviewed",
            "operator_reviewed_roster_sha256": roster["reviewed_rebound_roster_sha256"],
            "assignments": [{"pair_id": f"pair-{index}"} for index in range(20)],
        },
        "reviewed_rebound_assignment_sha256",
    )
    receipt = _self_hash(
        {
            "schema_version": ("j1-qualification-provider-admission-probe-receipt:v1"),
            "status": "admitted",
            "inventory": {"unchanged": True, "after": {"running_count": 0}},
        },
        "receipt_sha256",
    )
    receipt_raw_sha256 = "2" * 64
    gate = _self_hash(
        {
            "passed": True,
            "state": "live_provider_admission_refreshed_execution_still_blocked",
            "readiness": {"live_provider_admission_refreshed": True},
            "receipt": {
                "sha256": receipt_raw_sha256,
                "canonical_sha256": receipt["receipt_sha256"],
            },
        },
        "report_sha256",
    )
    values = {
        "amended_protocol": protocol,
        "amended_design": design,
        "reviewed_verifier": verifier,
        "rebound_roster": roster,
        "rebound_assignment": assignment,
        "provider_admission_gate": gate,
        "provider_admission_receipt": receipt,
    }
    return {
        name: {
            "value": value,
            "ref": {
                "path": f"/private/{name}.json",
                "sha256": (
                    receipt_raw_sha256
                    if name == "provider_admission_receipt"
                    else canonical_sha256(["raw", name])
                ),
            },
        }
        for name, value in values.items()
    }


def test_candidate_source_validation_and_binding_pass() -> None:
    artifacts = _artifacts()
    _validate_sources(artifacts)

    binding = _source_binding(artifacts)
    assert set(binding) == SOURCE_FIELDS
    assert (
        binding["provider_admission_receipt_sha256"]
        == artifacts["provider_admission_receipt"]["value"]["receipt_sha256"]
    )


def test_candidate_source_validation_rejects_admission_or_assignment_drift() -> None:
    artifacts = _artifacts()
    artifacts["provider_admission_gate"]["value"]["passed"] = False
    artifacts["rebound_assignment"]["value"]["operator_reviewed_roster_sha256"] = (
        "3" * 64
    )

    with pytest.raises(ValueError, match="source validation failed"):
        _validate_sources(artifacts)


def test_owner_approval_statement_binds_all_candidate_hashes() -> None:
    bundle = {
        "bundle_sha256": "a" * 64,
        "candidate_artifacts": {
            "real_evaluator": {"canonical_sha256": "b" * 64},
            "post_run_contract": {"canonical_sha256": "c" * 64},
            "operator_closeout_contract": {"canonical_sha256": "d" * 64},
        },
    }
    statement = approval_statement(
        bundle_artifact_sha256="e" * 64,
        bundle=bundle,
    )

    for digest in ("a" * 64, "b" * 64, "c" * 64, "d" * 64, "e" * 64):
        assert digest in statement
    assert "does not freeze or promote" in statement


def test_candidate_bundle_validator_rejects_boundary_tamper() -> None:
    bundle = {
        "schema_version": "j1-qualification-evaluation-closeout-candidate-bundle:v1",
        "candidate_id": "candidate-r1",
        "status": "review_required",
        "created_at": "2026-07-23T00:00:00+00:00",
        "source_binding": _source_binding(_artifacts()),
        "candidate_artifacts": {
            "real_evaluator": {
                "path": "/private/evaluator.json",
                "sha256": "1" * 64,
                "canonical_sha256": "2" * 64,
            },
            "post_run_contract": {
                "path": "/private/post-run.json",
                "sha256": "3" * 64,
                "canonical_sha256": "4" * 64,
            },
            "operator_closeout_contract": {
                "path": "/private/closeout.json",
                "sha256": "5" * 64,
                "canonical_sha256": "6" * 64,
            },
        },
        "review_scope": {},
        "readiness": {},
        "execution_boundary": {
            "candidate_generation_only": True,
            "provider_api_call_performed": False,
            "model_invocation_performed": False,
            "agent_execution_performed": False,
            "participant_container_started": False,
            "backend_fact_append_performed": False,
            "ledger_append_performed": False,
            "execution_authorization_issued_or_consumed": False,
            "effectiveness_claim_authorized": False,
        },
        "implementation": {},
    }
    bundle["bundle_sha256"] = canonical_sha256(bundle)
    assert _validate_bundle(bundle) == []

    bundle["execution_boundary"]["effectiveness_claim_authorized"] = True
    failures = _validate_bundle(bundle)
    assert "candidate_bundle_boundary_invalid" in failures
    assert "candidate_bundle_hash_invalid" in failures
