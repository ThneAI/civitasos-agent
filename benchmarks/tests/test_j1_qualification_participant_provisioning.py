from __future__ import annotations

import copy
import hashlib
from pathlib import Path

import pytest
from nacl.signing import SigningKey

from benchmarks.j1.controlled_comparison import canonical_sha256
from benchmarks.j1.qualification_participant_provisioning import (
    build_pairing_proposal,
    build_participant_profile,
    validate_pairing_proposal,
    validate_participant_profile,
)
from benchmarks.j1_qualification_participant_provisioning import (
    _collection_failures,
    _container_name,
    _create_container,
    _key_specs,
    _preflight_container_inventory,
)


CREATED_AT = "2026-07-21T10:00:00+08:00"
PROTOCOL_HASH = "11" * 32
AUTHORIZATION_HASH = "22" * 32


def _profile(index: int) -> dict:
    signing_key = SigningKey.generate()
    public_key_hex = signing_key.verify_key.encode().hex()
    challenge = hashlib.sha256(f"challenge:{index}".encode()).digest()
    signature = signing_key.sign(challenge).signature
    return build_participant_profile(
        created_at=CREATED_AT,
        qualification_protocol_sha256=PROTOCOL_HASH,
        authorization_id="j1q-owner-authorization-20260721-r1",
        authorization_statement_sha256=AUTHORIZATION_HASH,
        public_key_hex=public_key_hex,
        credential_version=1,
        module_path="/usr/lib/softhsm/libsofthsm2.so",
        module_sha256="33" * 32,
        token_label="dev-token",
        token_serial="24ba6efbb2b9e2b3",
        key_label=f"j1q-participant-{index:02d}",
        key_id_hex=f"{index:032x}",
        key_reference_sha256=hashlib.sha256(
            f"key-reference:{index}".encode()
        ).hexdigest(),
        challenge=challenge,
        signature=signature,
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
            "network_mode": "none",
            "read_only_rootfs": True,
            "cap_drop_all": True,
            "no_new_privileges": True,
            "exclusive_assignment": True,
            "container_started": False,
        },
    )


def test_profile_binds_identity_to_valid_possession_proof() -> None:
    profile = _profile(1)

    assert validate_participant_profile(profile) == []
    assert profile["participant"]["participant_id"].startswith("j1q-agent-")
    assert profile["participant"]["execution_did"].startswith("did:civ:qualification:z")
    assert profile["custody_boundary"]["token_store_copyable"] is True
    assert profile["execution_boundary"]["agent_execution_allowed"] is False


def test_profile_rejects_tampered_possession_proof() -> None:
    profile = _profile(2)
    tampered = copy.deepcopy(profile)
    tampered["possession_proof"]["signature_hex"] = "00" * 64

    failures = validate_participant_profile(tampered)

    assert "possession_signature_verification_failed" in failures
    assert "profile_hash_mismatch" in failures


def test_pairing_proposal_has_20_unique_review_required_pairs() -> None:
    profiles = [_profile(index) for index in range(1, 41)]

    proposal = build_pairing_proposal(
        proposal_id="j1q-pairing-proposal-20260721-r1",
        created_at=CREATED_AT,
        qualification_protocol_sha256=PROTOCOL_HASH,
        profiles=profiles,
        assignment_nonce=b"n" * 32,
    )

    assert validate_pairing_proposal(proposal) == []
    assert len(proposal["pairs"]) == 20
    participant_ids = [
        participant_id
        for pair in proposal["pairs"]
        for participant_id in pair["participant_ids"]
    ]
    assert len(set(participant_ids)) == 40
    assert all(pair["status"] == "review_required" for pair in proposal["pairs"])
    assert proposal["operator_review"] is None
    assert proposal["readiness"]["controlled_experiment_execution_ready"] is False


def test_pairing_proposal_rejects_duplicate_identity() -> None:
    profile = _profile(1)

    with pytest.raises(ValueError, match="40 unique participant identities"):
        build_pairing_proposal(
            proposal_id="j1q-pairing-proposal-20260721-r1",
            created_at=CREATED_AT,
            qualification_protocol_sha256=PROTOCOL_HASH,
            profiles=[profile] * 40,
            assignment_nonce=b"n" * 32,
        )


def test_container_preflight_uses_exact_provisioning_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inspected_names: list[str] = []

    def fake_run(command: list[str], **_: object) -> object:
        inspected_names.append(command[-1])
        return type("Result", (), {"returncode": 1})()

    monkeypatch.setattr("subprocess.run", fake_run)
    provisioning_id = "j1q-participant-provisioning-20260721-r1"

    _preflight_container_inventory(_key_specs(provisioning_id), provisioning_id)

    assert inspected_names == [
        _container_name(index, provisioning_id) for index in range(1, 41)
    ]


def test_collection_preflight_requires_open_frozen_collection() -> None:
    manifest = {
        "schema_version": "j1-qualification-participant-collection:v1",
        "passed": True,
        "status": "collection_open_real_participant_evidence_required",
        "qualification_protocol_sha256": PROTOCOL_HASH,
        "readiness": {
            "qualification_protocol_frozen": True,
            "participant_evidence_complete": False,
            "independent_roster_review_required": False,
            "real_participant_roster_bound": False,
            "single_use_authorization_issued": False,
            "controlled_experiment_execution_ready": False,
        },
    }
    manifest["manifest_sha256"] = canonical_sha256(manifest)

    assert _collection_failures(manifest, PROTOCOL_HASH) == []

    manifest["status"] = "collection_closed"
    body = {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    manifest["manifest_sha256"] = canonical_sha256(body)
    assert "collection_manifest_status_invalid" in _collection_failures(
        manifest, PROTOCOL_HASH
    )


def test_container_bind_mount_uses_docker_mount_key_value_syntax(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    captured: list[str] = []

    def fake_run(command: list[str]) -> str:
        captured.extend(command)
        return "container-id\n"

    monkeypatch.setattr(
        "benchmarks.j1_qualification_participant_provisioning._run", fake_run
    )

    assert (
        _create_container(
            name="j1q-container",
            participant="j1q-agent-1",
            provisioning_id="j1q-provisioning",
            image="python:3.11-slim",
            state_root=tmp_path,
        )
        == "container-id"
    )
    mount = captured[captured.index("--mount") + 1]
    assert mount.endswith("dst=/app/data")
    assert ",rw" not in mount
