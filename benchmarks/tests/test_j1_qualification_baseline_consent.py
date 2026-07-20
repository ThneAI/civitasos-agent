from __future__ import annotations

import copy
import hashlib

from nacl.signing import SigningKey

from benchmarks.j1.controlled_comparison import canonical_sha256
from benchmarks.j1.qualification_baseline_consent import (
    build_cognitive_baseline,
    build_participant_consent,
    reviewer_did,
    validate_cognitive_baseline,
    validate_participant_consent,
)
from benchmarks.j1.qualification_participant_provisioning import (
    participant_did,
    participant_id,
)


class _Signer:
    def __init__(self, key: SigningKey) -> None:
        self.key = key

    @property
    def public_key_hex(self) -> str:
        return self.key.verify_key.encode().hex()

    def sign(self, message: bytes) -> bytes:
        return self.key.sign(message).signature


def _participant(seed: bytes) -> tuple[SigningKey, dict]:
    key = SigningKey(seed)
    public_key = key.verify_key.encode().hex()
    return key, {
        "participant_id": participant_id(public_key),
        "execution_did": participant_did(public_key),
        "public_key_hex": public_key,
    }


def _state(participant: str) -> dict:
    state = {
        "schema_version": "j1-qualification-initial-state:v1",
        "participant_id": participant,
        "qualification_protocol_sha256": "1" * 64,
        "agent_revision": "a" * 40,
        "runtime_revision": "b" * 40,
        "prior_mentorship_exposure": False,
        "memory_entry_count": 0,
        "relation_count": 0,
        "model_invocation_count": 0,
        "tick_count": 0,
        "execution_authorized": False,
    }
    state["initial_state_sha256"] = canonical_sha256(state)
    return state


def test_builds_signed_zero_execution_baseline_and_individual_consent() -> None:
    participant_key, participant = _participant(b"p" * 32)
    _, peer = _participant(b"q" * 32)
    reviewer_key = SigningKey(b"r" * 32)
    baseline = build_cognitive_baseline(
        pair_id="j1q-pair-01",
        reviewed_pairing_sha256="2" * 64,
        qualification_protocol_sha256="1" * 64,
        owner_authorization_id="owner-auth-r1",
        owner_authorization_statement_sha256="3" * 64,
        attested_at="2026-07-21T16:30:00+08:00",
        participants=[
            {
                "participant_id": item["participant_id"],
                "participant_profile_sha256": hashlib.sha256(item["public_key_hex"].encode()).hexdigest(),
                "initial_state_artifact_sha256": hashlib.sha256(item["participant_id"].encode()).hexdigest(),
                "initial_state": _state(item["participant_id"]),
            }
            for item in (participant, peer)
        ],
        reviewer={
            "did": reviewer_did(reviewer_key.verify_key.encode().hex()),
            "public_key_hex": reviewer_key.verify_key.encode().hex(),
            "signer_kind": "pkcs11_ed25519",
            "credential_version": 1,
        },
        signer=_Signer(reviewer_key),
    )
    consent = build_participant_consent(
        participant=participant,
        pair_id="j1q-pair-01",
        participant_profile_sha256=baseline["participants"][0]["participant_profile_sha256"],
        reviewed_pairing_sha256="2" * 64,
        qualification_protocol_sha256="1" * 64,
        owner_authorization_id="owner-auth-r1",
        owner_authorization_statement_sha256="3" * 64,
        attested_at="2026-07-21T16:31:00+08:00",
        consent_nonce=b"n" * 32,
        signer=_Signer(participant_key),
    )

    assert validate_cognitive_baseline(baseline) == []
    assert validate_participant_consent(consent) == []
    assert baseline["performance_measurement_performed"] is False
    assert consent["model_execution_authorized"] is False


def test_rejects_baseline_state_and_consent_signature_tampering() -> None:
    participant_key, participant = _participant(b"p" * 32)
    consent = build_participant_consent(
        participant=participant,
        pair_id="j1q-pair-01",
        participant_profile_sha256="4" * 64,
        reviewed_pairing_sha256="2" * 64,
        qualification_protocol_sha256="1" * 64,
        owner_authorization_id="owner-auth-r1",
        owner_authorization_statement_sha256="3" * 64,
        attested_at="2026-07-21T16:31:00+08:00",
        consent_nonce=b"n" * 32,
        signer=_Signer(participant_key),
    )
    tampered = copy.deepcopy(consent)
    tampered["pair_id"] = "j1q-pair-02"

    assert "participant_consent_signature_payload_hash_mismatch" in validate_participant_consent(tampered)
    assert "participant_consent_signature_invalid" in validate_participant_consent(tampered)
