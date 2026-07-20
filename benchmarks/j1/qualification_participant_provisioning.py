"""Controlled-beta participant identity and isolation provisioning contracts."""

from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Any

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from .controlled_comparison import canonical_sha256


PROFILE_SCHEMA = "j1-qualification-participant-profile:v1"
PAIRING_SCHEMA = "j1-qualification-pairing-proposal:v1"
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def participant_did(public_key_hex: str) -> str:
    try:
        payload = b"\xed\x01" + bytes.fromhex(public_key_hex)
    except ValueError:
        return ""
    if len(payload) != 34:
        return ""
    number = int.from_bytes(payload, "big")
    encoded = ""
    while number:
        number, remainder = divmod(number, 58)
        encoded = BASE58_ALPHABET[remainder] + encoded
    return f"did:civ:qualification:z{encoded}"


def participant_id(public_key_hex: str) -> str:
    try:
        public_key = bytes.fromhex(public_key_hex)
    except ValueError:
        return ""
    if len(public_key) != 32:
        return ""
    return f"j1q-agent-{hashlib.sha256(public_key).hexdigest()[:20]}"


def build_participant_profile(
    *,
    created_at: str,
    qualification_protocol_sha256: str,
    authorization_id: str,
    authorization_statement_sha256: str,
    public_key_hex: str,
    credential_version: int,
    module_path: str,
    module_sha256: str,
    token_label: str,
    token_serial: str,
    key_label: str,
    key_id_hex: str,
    key_reference_sha256: str,
    challenge: bytes,
    signature: bytes,
    private_key_sensitive: bool,
    private_key_extractable: bool,
    initial_state: dict[str, Any],
    isolation: dict[str, Any],
) -> dict[str, Any]:
    profile = {
        "schema_version": PROFILE_SCHEMA,
        "profile": "controlled_beta_soft_token_participant",
        "created_at": created_at,
        "qualification_protocol_sha256": qualification_protocol_sha256,
        "participant": {
            "participant_id": participant_id(public_key_hex),
            "execution_did": participant_did(public_key_hex),
            "public_key_hex": public_key_hex,
            "public_key_sha256": hashlib.sha256(
                bytes.fromhex(public_key_hex)
            ).hexdigest(),
            "credential_version": credential_version,
            "signer_kind": "pkcs11",
            "prior_mentorship_exposure": False,
        },
        "pkcs11_key": {
            "module_path": module_path,
            "module_sha256": module_sha256,
            "token_label": token_label,
            "token_serial": token_serial,
            "key_label": key_label,
            "key_id_hex": key_id_hex,
            "key_reference_sha256": key_reference_sha256,
            "key_type": "CKK_EC_EDWARDS",
            "mechanism": "CKM_EDDSA",
        },
        "possession_proof": {
            "challenge_hex": challenge.hex(),
            "challenge_sha256": hashlib.sha256(challenge).hexdigest(),
            "signature_hex": signature.hex(),
            "signature_verified": True,
        },
        "custody_boundary": {
            "provider": "SoftHSM v2",
            "physical_hsm_claimed": False,
            "production_custody_claimed": False,
            "token_store_copyable": True,
            "private_key_sensitive": private_key_sensitive,
            "private_key_extractable": private_key_extractable,
            "seed_exported": False,
            "pin_recorded": False,
        },
        "initial_state": initial_state,
        "isolation": isolation,
        "authorization": {
            "authorization_id": authorization_id,
            "authorization_statement_sha256": authorization_statement_sha256,
            "source": "interactive_owner_authorization",
            "cryptographically_signed": False,
            "provisioning_only": True,
        },
        "execution_boundary": {
            "identity_provisioned": True,
            "container_started": False,
            "pairing_operator_reviewed": False,
            "participant_evidence_activated": False,
            "model_invocation_allowed": False,
            "agent_execution_allowed": False,
            "backend_fact_append_allowed": False,
            "ledger_append_allowed": False,
        },
    }
    profile["profile_sha256"] = canonical_sha256(profile)
    failures = validate_participant_profile(profile)
    if failures:
        raise ValueError(f"participant profile invalid: {failures}")
    return profile


def validate_participant_profile(value: Any) -> list[str]:
    profile = value if isinstance(value, dict) else {}
    failures: list[str] = []
    _require(
        profile.get("schema_version") == PROFILE_SCHEMA,
        "profile_schema_invalid",
        failures,
    )
    _require(
        profile.get("profile") == "controlled_beta_soft_token_participant",
        "profile_kind_invalid",
        failures,
    )
    _require(
        _rfc3339(profile.get("created_at")), "profile_created_at_invalid", failures
    )
    _require(
        _sha256(profile.get("qualification_protocol_sha256")),
        "profile_protocol_hash_invalid",
        failures,
    )
    participant = _object(profile.get("participant"))
    public_key_hex = _text(participant.get("public_key_hex"))
    _require(_hex_bytes(public_key_hex, 32), "participant_public_key_invalid", failures)
    _require(
        participant.get("participant_id") == participant_id(public_key_hex),
        "participant_id_key_mismatch",
        failures,
    )
    _require(
        participant.get("execution_did") == participant_did(public_key_hex),
        "participant_did_key_mismatch",
        failures,
    )
    _require(
        participant.get("public_key_sha256") == _hash_hex(public_key_hex),
        "participant_public_key_hash_mismatch",
        failures,
    )
    _require(
        participant.get("credential_version") == 1,
        "participant_credential_version_invalid",
        failures,
    )
    _require(
        participant.get("signer_kind") == "pkcs11",
        "participant_signer_kind_invalid",
        failures,
    )
    _require(
        participant.get("prior_mentorship_exposure") is False,
        "participant_prior_mentorship_invalid",
        failures,
    )
    key = _object(profile.get("pkcs11_key"))
    for field in ("module_path", "token_label", "token_serial", "key_label"):
        _require(_text(key.get(field)), f"participant_{field}_invalid", failures)
    for field in ("module_sha256", "key_reference_sha256"):
        _require(_sha256(key.get(field)), f"participant_{field}_invalid", failures)
    _require(
        _variable_hex(key.get("key_id_hex")), "participant_key_id_invalid", failures
    )
    _require(
        key.get("key_type") == "CKK_EC_EDWARDS",
        "participant_key_type_invalid",
        failures,
    )
    _require(
        key.get("mechanism") == "CKM_EDDSA",
        "participant_key_mechanism_invalid",
        failures,
    )
    _validate_possession(profile, public_key_hex, failures)
    custody = _object(profile.get("custody_boundary"))
    for field in (
        "physical_hsm_claimed",
        "production_custody_claimed",
        "private_key_extractable",
        "seed_exported",
        "pin_recorded",
    ):
        _require(
            custody.get(field) is False, f"participant_{field}_must_be_false", failures
        )
    for field in ("token_store_copyable", "private_key_sensitive"):
        _require(
            custody.get(field) is True, f"participant_{field}_must_be_true", failures
        )
    initial = _object(profile.get("initial_state"))
    _require(
        initial.get("prior_mentorship_exposure") is False,
        "initial_state_mentorship_invalid",
        failures,
    )
    for field in (
        "memory_entry_count",
        "relation_count",
        "model_invocation_count",
        "tick_count",
    ):
        _require(
            initial.get(field) == 0, f"initial_state_{field}_must_be_zero", failures
        )
    isolation = _object(profile.get("isolation"))
    _require(
        isolation.get("network_mode") == "none", "isolation_network_invalid", failures
    )
    for field in (
        "read_only_rootfs",
        "cap_drop_all",
        "no_new_privileges",
        "exclusive_assignment",
    ):
        _require(isolation.get(field) is True, f"isolation_{field}_required", failures)
    _require(
        isolation.get("container_started") is False,
        "isolation_container_must_not_be_started",
        failures,
    )
    authorization = _object(profile.get("authorization"))
    _require(
        _text(authorization.get("authorization_id")),
        "authorization_id_missing",
        failures,
    )
    _require(
        _sha256(authorization.get("authorization_statement_sha256")),
        "authorization_statement_hash_invalid",
        failures,
    )
    _require(
        authorization.get("provisioning_only") is True,
        "authorization_scope_invalid",
        failures,
    )
    boundary = _object(profile.get("execution_boundary"))
    _require(
        boundary.get("identity_provisioned") is True,
        "identity_not_provisioned",
        failures,
    )
    for field in (
        "container_started",
        "pairing_operator_reviewed",
        "participant_evidence_activated",
        "model_invocation_allowed",
        "agent_execution_allowed",
        "backend_fact_append_allowed",
        "ledger_append_allowed",
    ):
        _require(
            boundary.get(field) is False, f"boundary_{field}_must_be_false", failures
        )
    declared_hash = profile.get("profile_sha256")
    body = {key: item for key, item in profile.items() if key != "profile_sha256"}
    _require(declared_hash == canonical_sha256(body), "profile_hash_mismatch", failures)
    return list(dict.fromkeys(failures))


def build_pairing_proposal(
    *,
    proposal_id: str,
    created_at: str,
    qualification_protocol_sha256: str,
    profiles: list[dict[str, Any]],
    assignment_nonce: bytes,
) -> dict[str, Any]:
    if len(profiles) != 40:
        raise ValueError("pairing proposal requires exactly 40 participant profiles")
    if any(validate_participant_profile(profile) for profile in profiles):
        raise ValueError("pairing proposal contains invalid participant profile")
    participant_ids = [profile["participant"]["participant_id"] for profile in profiles]
    execution_dids = [profile["participant"]["execution_did"] for profile in profiles]
    key_references = [
        profile["pkcs11_key"]["key_reference_sha256"] for profile in profiles
    ]
    if any(
        len(set(values)) != len(values)
        for values in (participant_ids, execution_dids, key_references)
    ):
        raise ValueError("pairing proposal requires 40 unique participant identities")
    ordered = sorted(
        profiles,
        key=lambda profile: hashlib.sha256(
            assignment_nonce
            + _text(_object(profile.get("participant")).get("participant_id")).encode()
        ).hexdigest(),
    )
    pairs = []
    for index in range(20):
        members = ordered[index * 2 : index * 2 + 2]
        pairs.append(
            {
                "pair_id": f"j1q-pair-{index + 1:02d}",
                "participant_ids": [
                    member["participant"]["participant_id"] for member in members
                ],
                "execution_dids": [
                    member["participant"]["execution_did"] for member in members
                ],
                "status": "review_required",
                "cognitive_baseline_evidence_created": False,
                "random_assignment_consent_created": False,
            }
        )
    proposal = {
        "schema_version": PAIRING_SCHEMA,
        "proposal_id": proposal_id,
        "status": "review_required",
        "created_at": created_at,
        "qualification_protocol_sha256": qualification_protocol_sha256,
        "assignment_method": "nonce_randomized_fresh_baseline_pairing_proposal:v1",
        "assignment_nonce_hex": assignment_nonce.hex(),
        "participant_profile_sha256": sorted(
            profile["profile_sha256"] for profile in profiles
        ),
        "pairs": pairs,
        "operator_review": None,
        "readiness": {
            "all_participant_identities_provisioned": True,
            "pairing_operator_reviewed": False,
            "participant_evidence_complete": False,
            "real_participant_roster_bound": False,
            "single_use_authorization_issued": False,
            "controlled_experiment_execution_ready": False,
        },
    }
    proposal["proposal_sha256"] = canonical_sha256(proposal)
    failures = validate_pairing_proposal(proposal)
    if failures:
        raise ValueError(f"pairing proposal invalid: {failures}")
    return proposal


def validate_pairing_proposal(value: Any) -> list[str]:
    proposal = value if isinstance(value, dict) else {}
    failures: list[str] = []
    _require(
        proposal.get("schema_version") == PAIRING_SCHEMA,
        "pairing_schema_invalid",
        failures,
    )
    _require(
        _text(proposal.get("proposal_id")), "pairing_proposal_id_missing", failures
    )
    _require(
        proposal.get("status") == "review_required", "pairing_status_invalid", failures
    )
    _require(
        _rfc3339(proposal.get("created_at")), "pairing_created_at_invalid", failures
    )
    _require(
        _sha256(proposal.get("qualification_protocol_sha256")),
        "pairing_protocol_hash_invalid",
        failures,
    )
    _require(
        proposal.get("assignment_method")
        == "nonce_randomized_fresh_baseline_pairing_proposal:v1",
        "pairing_assignment_method_invalid",
        failures,
    )
    _require(
        _hex_bytes(proposal.get("assignment_nonce_hex"), 32),
        "pairing_assignment_nonce_invalid",
        failures,
    )
    profile_hashes = proposal.get("participant_profile_sha256")
    _require(
        isinstance(profile_hashes, list)
        and len(profile_hashes) == 40
        and all(_sha256(item) for item in profile_hashes),
        "pairing_profile_hashes_invalid",
        failures,
    )
    if isinstance(profile_hashes, list):
        _require(
            len({_text(item) for item in profile_hashes}) == 40,
            "pairing_profile_hashes_invalid",
            failures,
        )
    pairs = proposal.get("pairs")
    _require(
        isinstance(pairs, list) and len(pairs) == 20,
        "pairing_pair_count_invalid",
        failures,
    )
    participant_ids: list[str] = []
    execution_dids: list[str] = []
    if isinstance(pairs, list):
        for index, pair_value in enumerate(pairs, start=1):
            pair = _object(pair_value)
            _require(
                pair.get("pair_id") == f"j1q-pair-{index:02d}",
                "pairing_pair_id_invalid",
                failures,
            )
            ids = pair.get("participant_ids")
            dids = pair.get("execution_dids")
            _require(
                isinstance(ids, list)
                and len(ids) == 2
                and all(_text(item) for item in ids),
                "pairing_pair_participants_invalid",
                failures,
            )
            _require(
                isinstance(dids, list)
                and len(dids) == 2
                and all(_text(item) for item in dids),
                "pairing_pair_dids_invalid",
                failures,
            )
            if isinstance(ids, list):
                participant_ids.extend(_text(item) for item in ids)
            if isinstance(dids, list):
                execution_dids.extend(_text(item) for item in dids)
            _require(
                pair.get("status") == "review_required",
                "pairing_pair_status_invalid",
                failures,
            )
            for field in (
                "cognitive_baseline_evidence_created",
                "random_assignment_consent_created",
            ):
                _require(
                    pair.get(field) is False, f"pairing_{field}_must_be_false", failures
                )
    _require(
        len(participant_ids) == 40 and len(set(participant_ids)) == 40,
        "pairing_participant_uniqueness_invalid",
        failures,
    )
    _require(
        len(execution_dids) == 40 and len(set(execution_dids)) == 40,
        "pairing_did_uniqueness_invalid",
        failures,
    )
    _require(
        proposal.get("operator_review") is None,
        "pairing_operator_review_must_be_null",
        failures,
    )
    readiness = _object(proposal.get("readiness"))
    _require(
        readiness.get("all_participant_identities_provisioned") is True,
        "pairing_identities_not_provisioned",
        failures,
    )
    for field in (
        "pairing_operator_reviewed",
        "participant_evidence_complete",
        "real_participant_roster_bound",
        "single_use_authorization_issued",
        "controlled_experiment_execution_ready",
    ):
        _require(
            readiness.get(field) is False, f"pairing_{field}_must_be_false", failures
        )
    declared_hash = proposal.get("proposal_sha256")
    body = {key: item for key, item in proposal.items() if key != "proposal_sha256"}
    _require(
        declared_hash == canonical_sha256(body),
        "pairing_proposal_hash_mismatch",
        failures,
    )
    return list(dict.fromkeys(failures))


def _validate_possession(
    profile: dict[str, Any], public_key_hex: str, failures: list[str]
) -> None:
    proof = _object(profile.get("possession_proof"))
    challenge_hex = _text(proof.get("challenge_hex"))
    signature_hex = _text(proof.get("signature_hex"))
    _require(_hex_bytes(challenge_hex, 32), "possession_challenge_invalid", failures)
    _require(_hex_bytes(signature_hex, 64), "possession_signature_invalid", failures)
    _require(
        proof.get("challenge_sha256") == _hash_hex(challenge_hex),
        "possession_challenge_hash_mismatch",
        failures,
    )
    _require(
        proof.get("signature_verified") is True, "possession_not_verified", failures
    )
    try:
        VerifyKey(bytes.fromhex(public_key_hex)).verify(
            bytes.fromhex(challenge_hex), bytes.fromhex(signature_hex)
        )
    except (BadSignatureError, ValueError):
        failures.append("possession_signature_verification_failed")


def _hash_hex(value: str) -> str:
    try:
        return hashlib.sha256(bytes.fromhex(value)).hexdigest()
    except ValueError:
        return ""


def _rfc3339(value: Any) -> bool:
    try:
        parsed = datetime.fromisoformat(_text(value).replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None


def _sha256(value: Any) -> bool:
    return _hex_bytes(value, 32)


def _hex_bytes(value: Any, size: int) -> bool:
    text = _text(value)
    return len(text) == size * 2 and all(char in "0123456789abcdef" for char in text)


def _variable_hex(value: Any) -> bool:
    text = _text(value)
    return (
        bool(text)
        and len(text) % 2 == 0
        and all(char in "0123456789abcdef" for char in text)
    )


def _text(value: Any) -> str:
    return str(value or "").strip()


def _object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _require(condition: bool, code: str, failures: list[str]) -> None:
    if not condition and code not in failures:
        failures.append(code)
