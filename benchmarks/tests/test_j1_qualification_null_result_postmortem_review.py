from __future__ import annotations

import copy
import hashlib

import pytest

from benchmarks.j1.controlled_comparison import canonical_sha256
from benchmarks.j1.qualification_null_result_postmortem import (
    AMENDMENT_SCHEMA,
    POSTMORTEM_SCHEMA,
    ROOT_CAUSES,
    build_postmortem_gate,
)
from benchmarks.j1.qualification_null_result_postmortem_review import (
    ALLOWED_DECISION,
    BOUNDARY,
    CHECKLIST,
    build_review_handoff,
    build_review_request,
    reviewer_approval_statement,
    validate_review_request,
)


OWNER_STATEMENT = "owner approved exact review scope"
OWNER_STATEMENT_SHA256 = hashlib.sha256(OWNER_STATEMENT.encode()).hexdigest()
IMPLEMENTATION = {
    "source_revision": "a" * 40,
    "domain_source_sha256": "b" * 64,
    "operation_source_sha256": "c" * 64,
}


def _self_hashed(
    value: dict[str, object],
    field: str,
) -> dict[str, object]:
    value[field] = canonical_sha256(value)
    return value


def _source_boundary() -> dict[str, bool]:
    return {
        "offline_evidence_analysis_only": True,
        "provider_credential_read": False,
        "provider_api_call_performed": False,
        "model_invocation_performed": False,
        "agent_execution_performed": False,
        "participant_container_started": False,
        "participant_signature_performed": False,
        "backend_fact_append_performed": False,
        "ledger_append_performed": False,
        "execution_authorization_issued_or_consumed": False,
        "effectiveness_claim_authorized": False,
        "maturity_upgrade_authorized": False,
    }


def _postmortem() -> dict[str, object]:
    return _self_hashed(
        {
            "schema_version": POSTMORTEM_SCHEMA,
            "status": "complete_null_result_root_cause_candidate",
            "replay_summary": {
                "task_count": 320,
                "participant_count": 40,
                "matched_pair_count": 20,
                "behaviorally_decoupled_acceptance_count": 320,
                "participant_decision_semantic_assertion_count": 0,
                "direct_pattern_prediction_observation_count": 0,
                "provider_response_content_copied_to_postmortem": False,
            },
            "root_causes": list(ROOT_CAUSES),
            "interpretation": {
                "registered_effectiveness_estimand_observable": False,
                "mentor_effectiveness_disproven": False,
                "mentor_effectiveness_proven": False,
                "same_protocol_mechanical_rerun_justified": False,
                "si13_maturity_upgrade_allowed": False,
            },
            "implementation": {"source_revision": "d" * 40},
            "execution_boundary": _source_boundary(),
        },
        "report_sha256",
    )


def _candidate(postmortem_ref: dict[str, str]) -> dict[str, object]:
    return _self_hashed(
        {
            "schema_version": AMENDMENT_SCHEMA,
            "status": "review_required",
            "parent_postmortem": postmortem_ref,
            "direct_observation_contract": {
                "raw_provider_response_persisted": False,
                "free_text_decision_copied_to_observation": False,
                "model_judge_allowed": False,
                "operator_override_allowed": False,
                "participant_signature_required": True,
                "host_verifier_signature_required": True,
            },
            "outcome_sensitive_task_contract": {
                "task_count_per_participant": 12,
                "matched_pair_count": 20,
                "bounded_action_space_required": True,
                "deterministic_hidden_fixture_verifier_required": True,
            },
            "endpoint_contract": {
                "pattern_prediction": {"unobserved_zero_fill_allowed": False},
                "strategy_maturity_time": {"script_supplied_value_allowed": False},
                "repeated_error_rate": {"script_supplied_value_allowed": False},
            },
            "readiness": {
                "candidate_complete": True,
                "operator_reviewed": False,
                "protocol_amended": False,
                "participant_consent_migrated": False,
                "execution_preflight_allowed": False,
                "provider_or_model_execution_allowed": False,
                "si13_maturity_upgrade_allowed": False,
            },
            "execution_boundary": _source_boundary(),
        },
        "candidate_sha256",
    )


def _sources() -> tuple[
    dict[str, object],
    dict[str, str],
    dict[str, object],
    dict[str, str],
    dict[str, object],
    dict[str, str],
]:
    postmortem = _postmortem()
    postmortem_ref = {
        "path": "/private/postmortem.json",
        "sha256": "1" * 64,
        "canonical_sha256": postmortem["report_sha256"],
    }
    candidate = _candidate(postmortem_ref)
    candidate_ref = {
        "path": "/private/candidate.json",
        "sha256": "2" * 64,
        "canonical_sha256": candidate["candidate_sha256"],
    }
    gate = build_postmortem_gate(
        postmortem_ref=postmortem_ref,
        postmortem=postmortem,
        candidate_ref=candidate_ref,
        candidate=candidate,
        owner_statement=OWNER_STATEMENT,
    )
    gate_ref = {
        "path": "/private/gate.json",
        "sha256": "3" * 64,
        "canonical_sha256": gate["report_sha256"],
    }
    return (
        postmortem,
        postmortem_ref,
        candidate,
        candidate_ref,
        gate,
        gate_ref,
    )


def _request() -> tuple[dict[str, object], tuple[object, ...]]:
    sources = _sources()
    postmortem, postmortem_ref, candidate, candidate_ref, gate, gate_ref = sources
    request = build_review_request(
        request_id="r11-review-request-r1",
        created_at="2026-07-28T00:00:00+00:00",
        postmortem_ref=postmortem_ref,
        postmortem=postmortem,
        candidate_ref=candidate_ref,
        candidate=candidate,
        gate_ref=gate_ref,
        gate=gate,
        owner_statement_sha256=OWNER_STATEMENT_SHA256,
        implementation=IMPLEMENTATION,
    )
    return request, sources


def test_builds_unsigned_fail_closed_review_request() -> None:
    request, sources = _request()
    _, postmortem_ref, _, candidate_ref, _, gate_ref = sources
    assert request["allowed_decision"] == ALLOWED_DECISION
    assert request["required_checklist"] == sorted(CHECKLIST)
    assert request["decision_template"]["decision"] is None
    assert all(
        value is None for value in request["decision_template"]["checklist"].values()
    )
    assert (
        validate_review_request(
            request,
            expected_postmortem_ref=postmortem_ref,
            expected_candidate_ref=candidate_ref,
            expected_gate_ref=gate_ref,
            expected_owner_statement_sha256=OWNER_STATEMENT_SHA256,
            expected_implementation=IMPLEMENTATION,
        )
        == []
    )


def test_rejects_owner_statement_drift() -> None:
    postmortem, postmortem_ref, candidate, candidate_ref, gate, gate_ref = _sources()
    with pytest.raises(ValueError, match="review_owner_statement_binding_invalid"):
        build_review_request(
            request_id="r11-review-request-r1",
            created_at="2026-07-28T00:00:00+00:00",
            postmortem_ref=postmortem_ref,
            postmortem=postmortem,
            candidate_ref=candidate_ref,
            candidate=candidate,
            gate_ref=gate_ref,
            gate=gate,
            owner_statement_sha256="f" * 64,
            implementation=IMPLEMENTATION,
        )


def test_rejects_request_self_hash_and_decision_drift() -> None:
    request, sources = _request()
    _, postmortem_ref, _, candidate_ref, _, gate_ref = sources
    changed = copy.deepcopy(request)
    changed["decision_template"]["decision"] = ALLOWED_DECISION
    failures = validate_review_request(
        changed,
        expected_postmortem_ref=postmortem_ref,
        expected_candidate_ref=candidate_ref,
        expected_gate_ref=gate_ref,
        expected_owner_statement_sha256=OWNER_STATEMENT_SHA256,
        expected_implementation=IMPLEMENTATION,
    )
    assert "null_result_review_request_identity_invalid" in failures
    assert "null_result_review_decision_contract_invalid" in failures


def test_handoff_preserves_empty_decision_and_exact_statement() -> None:
    request, _ = _request()
    statement = reviewer_approval_statement(
        request=request,
        request_raw_sha256="4" * 64,
    )
    handoff = build_review_handoff(
        request_ref={
            "path": "/private/request.json",
            "sha256": "4" * 64,
            "canonical_sha256": request["request_sha256"],
        },
        request=request,
        request_raw_sha256="4" * 64,
    )
    assert handoff["decision_template"]["decision"] is None
    assert handoff["required_exact_approval_statement"] == statement
    assert f"all {len(CHECKLIST)} required checklist items" in statement
    assert ALLOWED_DECISION in statement
    assert handoff["execution_boundary"] == BOUNDARY
