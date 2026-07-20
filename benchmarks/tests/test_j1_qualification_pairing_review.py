from __future__ import annotations

import copy
import hashlib
import json

from nacl.signing import SigningKey

from benchmarks.j1.qualification_pairing_review import (
    build_pairing_review_receipt,
    build_public_state_evidence,
    build_reviewed_pairing,
    validate_pairing_review_receipt,
    validate_reviewed_pairing,
)
from benchmarks.j1.qualification_participant_evidence import (
    validate_evidence_artifact,
)
from benchmarks.j1.qualification_participant_provisioning import (
    build_pairing_proposal,
    build_participant_profile,
)
from benchmarks.j1.qualification_reviewer_identity import (
    build_reviewer_identity_profile,
)


CREATED_AT = "2026-07-21T05:00:00+08:00"
PROTOCOL_HASH = "11" * 32
REVIEW_IMPLEMENTATION = {
    "agent_revision": "a" * 40,
    "contract_source_sha256": "bb" * 32,
    "operation_source_sha256": "cc" * 32,
}


class _Signer:
    def __init__(self, key: SigningKey) -> None:
        self.key = key

    @property
    def public_key_hex(self) -> str:
        return self.key.verify_key.encode().hex()

    def sign(self, message: bytes) -> bytes:
        return self.key.sign(message).signature


def _participant(index: int) -> dict:
    key = SigningKey.generate()
    public_key_hex = key.verify_key.encode().hex()
    challenge = hashlib.sha256(f"participant:{index}".encode()).digest()
    return build_participant_profile(
        created_at=CREATED_AT,
        qualification_protocol_sha256=PROTOCOL_HASH,
        authorization_id="j1q-provisioning-authorization",
        authorization_statement_sha256="22" * 32,
        public_key_hex=public_key_hex,
        credential_version=1,
        module_path="/usr/lib/softhsm/libsofthsm2.so",
        module_sha256="33" * 32,
        token_label="dev-token",
        token_serial="serial",
        key_label=f"participant-{index:02d}",
        key_id_hex=f"{index:032x}",
        key_reference_sha256=hashlib.sha256(f"key:{index}".encode()).hexdigest(),
        challenge=challenge,
        signature=key.sign(challenge).signature,
        private_key_sensitive=True,
        private_key_extractable=False,
        initial_state={
            "prior_mentorship_exposure": False,
            "memory_entry_count": 0,
            "relation_count": 0,
            "model_invocation_count": 0,
            "tick_count": 0,
        },
        isolation={
            "isolation_id": f"container-{index:02d}",
            "container_config_sha256": hashlib.sha256(
                f"container:{index}".encode()
            ).hexdigest(),
            "network_mode": "none",
            "read_only_rootfs": True,
            "cap_drop_all": True,
            "no_new_privileges": True,
            "exclusive_assignment": True,
            "container_started": False,
        },
    )


def _reviewer(key: SigningKey) -> dict:
    challenge = b"r" * 32
    return build_reviewer_identity_profile(
        created_at=CREATED_AT,
        public_key_hex=key.verify_key.encode().hex(),
        credential_version=1,
        module_path="/usr/lib/softhsm/libsofthsm2.so",
        module_bytes=b"module",
        token_label="dev-token",
        token_serial="serial",
        token_model="SoftHSM v2",
        token_manufacturer="SoftHSM project",
        key_label="reviewer-key",
        key_id_hex="4a31",
        key_reference="pkcs11:reviewer-key",
        challenge=challenge,
        signature=key.sign(challenge).signature,
        private_key_sensitive=True,
        private_key_extractable=False,
    )


def _inputs() -> tuple[list[dict], dict, dict, _Signer]:
    profiles = [_participant(index) for index in range(1, 41)]
    proposal = build_pairing_proposal(
        proposal_id="j1q-pairing-proposal-20260721-r1",
        created_at=CREATED_AT,
        qualification_protocol_sha256=PROTOCOL_HASH,
        profiles=profiles,
        assignment_nonce=b"p" * 32,
    )
    key = SigningKey.generate()
    return profiles, proposal, _reviewer(key), _Signer(key)


def test_signed_review_binds_exact_proposal_and_preserves_execution_boundary() -> None:
    _, proposal, reviewer, signer = _inputs()
    proposal_raw = json.dumps(proposal, sort_keys=True).encode()
    reviewer_raw = json.dumps(reviewer, sort_keys=True).encode()
    receipt = build_pairing_review_receipt(
        review_id="j1q-pairing-review-20260721-r1",
        reviewed_at=CREATED_AT,
        authorization_id="j1q-pairing-owner-approval-20260721-r1",
        authorization_statement_sha256="44" * 32,
        proposal=proposal,
        proposal_artifact_sha256=hashlib.sha256(proposal_raw).hexdigest(),
        reviewer_profile=reviewer,
        reviewer_profile_sha256=hashlib.sha256(reviewer_raw).hexdigest(),
        review_implementation=REVIEW_IMPLEMENTATION,
        signer=signer,
    )

    assert (
        validate_pairing_review_receipt(
            receipt,
            proposal=proposal,
            proposal_artifact_sha256=hashlib.sha256(proposal_raw).hexdigest(),
            reviewer_profile=reviewer,
            reviewer_profile_sha256=hashlib.sha256(reviewer_raw).hexdigest(),
            review_implementation=REVIEW_IMPLEMENTATION,
        )
        == []
    )
    boundary = receipt["execution_boundary"]
    assert boundary["pairing_approved"] is True
    assert boundary["participant_consent_created"] is False
    assert boundary["model_invocation_allowed"] is False

    expanded = copy.deepcopy(receipt)
    expanded["execution_boundary"]["model_budget_authorized"] = True
    assert "pairing_review_boundary_fields_invalid" in validate_pairing_review_receipt(
        expanded,
        proposal=proposal,
        proposal_artifact_sha256=hashlib.sha256(proposal_raw).hexdigest(),
        reviewer_profile=reviewer,
        reviewer_profile_sha256=hashlib.sha256(reviewer_raw).hexdigest(),
        review_implementation=REVIEW_IMPLEMENTATION,
    )


def test_reviewed_pairing_is_copy_on_write_and_still_not_execution_ready() -> None:
    _, proposal, reviewer, signer = _inputs()
    source = copy.deepcopy(proposal)
    receipt = build_pairing_review_receipt(
        review_id="j1q-pairing-review-20260721-r1",
        reviewed_at=CREATED_AT,
        authorization_id="j1q-pairing-owner-approval-20260721-r1",
        authorization_statement_sha256="44" * 32,
        proposal=proposal,
        proposal_artifact_sha256="55" * 32,
        reviewer_profile=reviewer,
        reviewer_profile_sha256="66" * 32,
        review_implementation=REVIEW_IMPLEMENTATION,
        signer=signer,
    )
    reviewed = build_reviewed_pairing(
        proposal=proposal,
        receipt=receipt,
        receipt_sha256="77" * 32,
    )

    assert proposal == source
    assert validate_reviewed_pairing(reviewed) == []
    assert all(pair["status"] == "operator_reviewed" for pair in reviewed["pairs"])
    assert reviewed["readiness"]["pairing_operator_reviewed"] is True
    assert reviewed["readiness"]["controlled_experiment_execution_ready"] is False


def test_review_receipt_rejects_different_proposal() -> None:
    _, proposal, reviewer, signer = _inputs()
    receipt = build_pairing_review_receipt(
        review_id="j1q-pairing-review-20260721-r1",
        reviewed_at=CREATED_AT,
        authorization_id="j1q-pairing-owner-approval-20260721-r1",
        authorization_statement_sha256="44" * 32,
        proposal=proposal,
        proposal_artifact_sha256="55" * 32,
        reviewer_profile=reviewer,
        reviewer_profile_sha256="66" * 32,
        review_implementation=REVIEW_IMPLEMENTATION,
        signer=signer,
    )
    different = copy.deepcopy(proposal)
    different["pairs"][0]["participant_ids"].reverse()
    different["proposal_sha256"] = "88" * 32

    failures = validate_pairing_review_receipt(
        receipt,
        proposal=different,
        proposal_artifact_sha256="99" * 32,
        reviewer_profile=reviewer,
        reviewer_profile_sha256="66" * 32,
        review_implementation=REVIEW_IMPLEMENTATION,
    )

    assert "pairing_review_proposal_binding_invalid" in failures


def test_public_state_evidence_excludes_baseline_consent_and_packet() -> None:
    profiles, proposal, _, _ = _inputs()
    participant_id = profiles[0]["participant"]["participant_id"]
    pair_id = next(
        pair["pair_id"]
        for pair in proposal["pairs"]
        if participant_id in pair["participant_ids"]
    )

    artifacts = build_public_state_evidence(
        profile=profiles[0],
        pair_id=pair_id,
        attested_at=CREATED_AT,
        operator_attestation_sha256="aa" * 32,
    )

    assert set(artifacts) == {
        "identity_snapshot",
        "custody_provenance",
        "isolation_root",
    }
    packet = {
        "participant_id": participant_id,
        "execution_did": profiles[0]["participant"]["execution_did"],
        "pair_id": pair_id,
        "credential_version": 1,
        "signer_kind": "pkcs11",
    }
    for kind, artifact in artifacts.items():
        assert (
            validate_evidence_artifact(
                kind,
                artifact,
                packet=packet,
                qualification_protocol_sha256=PROTOCOL_HASH,
            )
            == []
        )
