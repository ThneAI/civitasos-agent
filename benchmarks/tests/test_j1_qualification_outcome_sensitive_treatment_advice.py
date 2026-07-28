from __future__ import annotations

import copy
import hashlib

from nacl.signing import SigningKey

from benchmarks.j1.controlled_comparison import canonical_sha256
from benchmarks.j1.qualification_outcome_sensitive_treatment_advice import (
    ADVICE_TEMPLATES,
    TREATMENT_ORDINALS,
    authorization_statement,
    build_advice_candidate,
    build_signed_advice,
    validate_advice_candidate,
    validate_signed_advice,
)


NOW = "2026-07-29T10:00:00+08:00"
SIGNING_KEY = SigningKey(b"\x01" * 32)


class _Signer:
    public_key_hex = SIGNING_KEY.verify_key.encode().hex()

    def sign(self, payload: bytes) -> bytes:
        return SIGNING_KEY.sign(payload).signature


def _inputs() -> tuple[dict, dict, dict, dict, dict, dict]:
    protocol = {"protocol_sha256": "1" * 64}
    fixture = {"fixture_sha256": "2" * 64}
    reviewed_assignment = {"reviewed_rebound_assignment_sha256": "3" * 64}
    mentor = {
        "profile_sha256": "4" * 64,
        "mentor": {
            "mentor_id": "mentor-1",
            "did": "did:civ:mentor:test",
            "credential_version": 1,
            "public_key_hex": SIGNING_KEY.verify_key.encode().hex(),
            "public_key_sha256": "5" * 64,
        },
    }
    assignment = {
        "pair_id": "pair-1",
        "rebind_commitment_sha256": "6" * 64,
        "mentor": {
            "participant_id": "participant-1",
            "execution_did": "did:civ:participant:test",
        },
    }
    task = {
        "task_id": "task-4",
        "task_ordinal": 4,
        "phase": "near_transfer",
        "prompt_sha256": "7" * 64,
        "allowed_action_ids": ["pause_and_request_scope"],
        "allowed_pattern_ids": ["authorization_scope_gap"],
    }
    return protocol, fixture, reviewed_assignment, mentor, assignment, task


def _candidate() -> tuple[dict, tuple[dict, ...]]:
    inputs = _inputs()
    candidate = build_advice_candidate(
        created_at=NOW,
        protocol=inputs[0],
        task_fixture=inputs[1],
        reviewed_assignment=inputs[2],
        mentor_identity=inputs[3],
        assignment=inputs[4],
        task=inputs[5],
    )
    return candidate, inputs


def test_candidate_is_participant_task_scoped_and_answer_free() -> None:
    candidate, inputs = _candidate()

    assert (
        validate_advice_candidate(
            candidate,
            protocol=inputs[0],
            task_fixture=inputs[1],
            reviewed_assignment=inputs[2],
            mentor_identity=inputs[3],
            assignment=inputs[4],
            task=inputs[5],
        )
        == []
    )
    assert candidate["recipient"]["participant_id"] == "participant-1"
    assert candidate["task"]["task_ordinal"] in TREATMENT_ORDINALS
    assert candidate["leakage_guard"]["ground_truth_copied"] is False
    advice = candidate["advice"]["text"]
    assert "pause_and_request_scope" not in advice
    assert "authorization_scope_gap" not in advice


def test_candidate_rejects_template_and_hash_tamper() -> None:
    candidate, inputs = _candidate()
    changed = copy.deepcopy(candidate)
    changed["advice"]["text"] = "Choose pause_and_request_scope."
    changed["candidate_sha256"] = canonical_sha256(
        {key: item for key, item in changed.items() if key != "candidate_sha256"}
    )

    failures = validate_advice_candidate(
        changed,
        protocol=inputs[0],
        task_fixture=inputs[1],
        reviewed_assignment=inputs[2],
        mentor_identity=inputs[3],
        assignment=inputs[4],
        task=inputs[5],
    )

    assert "outcome_advice_advice_invalid" in failures
    assert "outcome_advice_ground_truth_identifier_leak" in failures


def test_authorization_is_exact_scope_and_non_executable() -> None:
    manifest = {
        "manifest_sha256": "8" * 64,
        "source_binding": {
            "reviewed_assignment": {"canonical_sha256": "9" * 64},
            "protocol": {"canonical_sha256": "a" * 64},
            "task_fixture": {"canonical_sha256": "b" * 64},
            "mentor_identity": {"canonical_sha256": "c" * 64},
        },
        "mentor": {"mentor_did": "did:civ:mentor:test"},
    }
    statement = authorization_statement(manifest, "d" * 64)

    assert "exactly 180" in statement
    assert "treatment ordinals 4 through 12" in statement
    assert "baseline ordinals 1 through 3 have no advice" in statement
    assert "control advice remains empty" in statement
    assert "one PKCS#11 session" in statement
    assert "does not authorize infrastructure changes" in statement
    assert hashlib.sha256(statement.encode()).hexdigest()
    assert set(ADVICE_TEMPLATES) == {
        "near_transfer",
        "heldout_transfer",
        "false_positive_sentinels",
    }


def test_signed_advice_preserves_scope_and_verifies() -> None:
    candidate, inputs = _candidate()
    signed = build_signed_advice(
        candidate=candidate,
        candidate_artifact_sha256="8" * 64,
        source_manifest_artifact_sha256="9" * 64,
        source_manifest_sha256="a" * 64,
        authorization_id="authorization-1",
        authorization_statement_sha256="b" * 64,
        signed_at=NOW,
        mentor_identity=inputs[3],
        signer=_Signer(),
    )

    assert (
        validate_signed_advice(
            signed,
            candidate=candidate,
            candidate_artifact_sha256="8" * 64,
            source_manifest_artifact_sha256="9" * 64,
            source_manifest_sha256="a" * 64,
            authorization_id="authorization-1",
            authorization_statement_sha256="b" * 64,
            mentor_identity=inputs[3],
        )
        == []
    )
    assert signed["leakage_guard"] == candidate["leakage_guard"]
    assert signed["execution_boundary"]["advice_signature_only"] is True
    assert signed["execution_boundary"]["runtime_projection_allowed"] is False


def test_signed_advice_rejects_post_signature_tamper() -> None:
    candidate, inputs = _candidate()
    signed = build_signed_advice(
        candidate=candidate,
        candidate_artifact_sha256="8" * 64,
        source_manifest_artifact_sha256="9" * 64,
        source_manifest_sha256="a" * 64,
        authorization_id="authorization-1",
        authorization_statement_sha256="b" * 64,
        signed_at=NOW,
        mentor_identity=inputs[3],
        signer=_Signer(),
    )
    changed = copy.deepcopy(signed)
    changed["leakage_guard"]["ground_truth_copied"] = True
    changed["signed_advice_sha256"] = canonical_sha256(
        {key: item for key, item in changed.items() if key != "signed_advice_sha256"}
    )

    failures = validate_signed_advice(
        changed,
        candidate=candidate,
        candidate_artifact_sha256="8" * 64,
        source_manifest_artifact_sha256="9" * 64,
        source_manifest_sha256="a" * 64,
        authorization_id="authorization-1",
        authorization_statement_sha256="b" * 64,
        mentor_identity=inputs[3],
    )

    assert "signed_outcome_advice_leakage_guard_invalid" in failures
    assert "signed_outcome_advice_signature_unverified" in failures
