from __future__ import annotations

import copy
import hashlib

from nacl.signing import SigningKey

from benchmarks.j1.controlled_comparison import canonical_sha256
from benchmarks.j1.qualification_outcome_sensitive_confirmatory_treatment_advice import (
    CANDIDATE_BOUNDARY,
    authorization_statement,
    build_advice_candidate,
    build_signed_advice,
    validate_advice_candidate,
    validate_signed_advice,
)


NOW = "2026-08-04T12:00:00+08:00"
SIGNING_KEY = SigningKey(b"\x01" * 32)


class _Signer:
    public_key_hex = SIGNING_KEY.verify_key.encode().hex()

    def sign(self, payload: bytes) -> bytes:
        return SIGNING_KEY.sign(payload).signature


def _inputs() -> tuple[dict, ...]:
    protocol = {"protocol_sha256": "1" * 64}
    fixture = {"fixture_sha256": "2" * 64}
    method = {"method_sha256": "3" * 64}
    reviewed_assignment = {"reviewed_rebound_assignment_sha256": "4" * 64}
    assignment_gate = {"report_sha256": "5" * 64}
    mentor = {
        "profile_sha256": "6" * 64,
        "mentor": {
            "mentor_id": "mentor-1",
            "did": "did:civ:mentor:test",
            "credential_version": 1,
            "public_key_sha256": "7" * 64,
            "public_key_hex": SIGNING_KEY.verify_key.encode().hex(),
        },
    }
    assignment = {
        "pair_id": "pair-1",
        "rebind_commitment_sha256": "8" * 64,
        "mentor": {
            "participant_id": "participant-1",
            "execution_did": "did:civ:participant:test",
            "confirmatory_consent_sha256": "9" * 64,
        },
    }
    task = {
        "task_id": "task-4",
        "task_ordinal": 4,
        "phase": "near_transfer",
        "prompt_sha256": "a" * 64,
        "allowed_action_ids": ["pause_and_request_scope"],
        "allowed_pattern_ids": ["authorization_scope_gap"],
    }
    return (
        protocol,
        fixture,
        method,
        reviewed_assignment,
        assignment_gate,
        mentor,
        assignment,
        task,
    )


def _candidate() -> tuple[dict, tuple[dict, ...]]:
    inputs = _inputs()
    candidate = build_advice_candidate(
        created_at=NOW,
        protocol=inputs[0],
        task_fixture=inputs[1],
        confirmatory_method=inputs[2],
        reviewed_assignment=inputs[3],
        assignment_gate=inputs[4],
        mentor_identity=inputs[5],
        assignment=inputs[6],
        task=inputs[7],
    )
    return candidate, inputs


def _validate(candidate: dict, inputs: tuple[dict, ...]) -> list[str]:
    return validate_advice_candidate(
        candidate,
        protocol=inputs[0],
        task_fixture=inputs[1],
        confirmatory_method=inputs[2],
        reviewed_assignment=inputs[3],
        assignment_gate=inputs[4],
        mentor_identity=inputs[5],
        assignment=inputs[6],
        task=inputs[7],
    )


def test_candidate_binds_confirmatory_method_consent_and_assignment() -> None:
    candidate, inputs = _candidate()

    assert _validate(candidate, inputs) == []
    binding = candidate["source_binding"]
    assert binding["confirmatory_method_sha256"] == "3" * 64
    assert binding["reviewed_confirmatory_assignment_sha256"] == "4" * 64
    assert binding["assignment_promotion_gate_sha256"] == "5" * 64
    assert binding["confirmatory_consent_sha256"] == "9" * 64
    assert candidate["execution_boundary"] == CANDIDATE_BOUNDARY


def test_candidate_rejects_method_and_consent_tamper() -> None:
    candidate, inputs = _candidate()
    changed = copy.deepcopy(candidate)
    changed["source_binding"]["confirmatory_method_sha256"] = "b" * 64
    changed["recipient"]["confirmatory_consent_sha256"] = "c" * 64
    changed["candidate_sha256"] = canonical_sha256(
        {key: item for key, item in changed.items() if key != "candidate_sha256"}
    )

    failures = _validate(changed, inputs)

    assert "confirmatory_advice_source_binding_invalid" in failures
    assert "confirmatory_advice_recipient_invalid" in failures


def test_candidate_rejects_answer_identifier_leakage() -> None:
    candidate, inputs = _candidate()
    changed = copy.deepcopy(candidate)
    changed["advice"]["text"] = "Choose pause_and_request_scope."
    changed["candidate_sha256"] = canonical_sha256(
        {key: item for key, item in changed.items() if key != "candidate_sha256"}
    )

    failures = _validate(changed, inputs)

    assert "confirmatory_advice_advice_invalid" in failures
    assert "confirmatory_advice_ground_truth_identifier_leak" in failures


def test_candidate_records_exposure_but_not_adherence() -> None:
    candidate, _ = _candidate()

    assert candidate["measurement_boundary"] == {
        "advice_exposure_observable": True,
        "advice_adherence_observed": False,
        "advice_adherence_inference_allowed": False,
    }


def test_authorization_is_exact_new_non_executable_scope() -> None:
    manifest = {
        "manifest_sha256": "d" * 64,
        "source_binding": {
            "reviewed_assignment": {"canonical_sha256": "1" * 64},
            "assignment_gate": {"canonical_sha256": "2" * 64},
            "confirmatory_method": {"canonical_sha256": "3" * 64},
            "protocol": {"canonical_sha256": "4" * 64},
            "task_fixture": {"canonical_sha256": "5" * 64},
            "mentor_identity": {"canonical_sha256": "6" * 64},
        },
        "mentor": {"mentor_did": "did:civ:mentor:test"},
    }

    statement = authorization_statement(manifest, "e" * 64)

    assert "exactly 180 prospective confirmatory" in statement
    assert "prior advice and signatures are not reused" in statement
    assert "advice adherence remains unobserved" in statement
    assert "one PKCS#11 session on token dev-token" in statement
    assert "does not authorize infrastructure changes" in statement
    assert "r4 reanalysis" in statement
    assert hashlib.sha256(statement.encode()).hexdigest()


def test_signed_advice_preserves_measurement_boundary_and_verifies() -> None:
    candidate, inputs = _candidate()
    signed = build_signed_advice(
        candidate=candidate,
        candidate_artifact_sha256="b" * 64,
        source_manifest_artifact_sha256="c" * 64,
        source_manifest_sha256="d" * 64,
        authorization_id="authorization-1",
        authorization_statement_sha256="e" * 64,
        signed_at=NOW,
        mentor_identity=inputs[5],
        signer=_Signer(),
    )

    assert (
        validate_signed_advice(
            signed,
            candidate=candidate,
            candidate_artifact_sha256="b" * 64,
            source_manifest_artifact_sha256="c" * 64,
            source_manifest_sha256="d" * 64,
            authorization_id="authorization-1",
            authorization_statement_sha256="e" * 64,
            mentor_identity=inputs[5],
        )
        == []
    )
    assert signed["measurement_boundary"] == candidate["measurement_boundary"]
    assert signed["execution_boundary"]["r4_reanalysis_allowed"] is False


def test_signed_advice_rejects_measurement_boundary_tamper() -> None:
    candidate, inputs = _candidate()
    signed = build_signed_advice(
        candidate=candidate,
        candidate_artifact_sha256="b" * 64,
        source_manifest_artifact_sha256="c" * 64,
        source_manifest_sha256="d" * 64,
        authorization_id="authorization-1",
        authorization_statement_sha256="e" * 64,
        signed_at=NOW,
        mentor_identity=inputs[5],
        signer=_Signer(),
    )
    changed = copy.deepcopy(signed)
    changed["measurement_boundary"]["advice_adherence_observed"] = True
    changed["signed_advice_sha256"] = canonical_sha256(
        {key: item for key, item in changed.items() if key != "signed_advice_sha256"}
    )

    failures = validate_signed_advice(
        changed,
        candidate=candidate,
        candidate_artifact_sha256="b" * 64,
        source_manifest_artifact_sha256="c" * 64,
        source_manifest_sha256="d" * 64,
        authorization_id="authorization-1",
        authorization_statement_sha256="e" * 64,
        mentor_identity=inputs[5],
    )

    assert "signed_confirmatory_advice_measurement_boundary_invalid" in failures
    assert "signed_confirmatory_advice_signature_unverified" in failures
