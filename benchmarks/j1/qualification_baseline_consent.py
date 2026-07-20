"""Cryptographic contracts for J1-D baselines and participant consent."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any, Protocol

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from .controlled_comparison import canonical_sha256
from .qualification_participant_provisioning import participant_did, participant_id


BASELINE_SCHEMA = "j1-qualification-cognitive-baseline:v2"
CONSENT_SCHEMA = "j1-qualification-consent-receipt:v2"
ASSESSMENT_METHOD = "pre-execution-cognitive-state-baseline:v1"
CONSENT_STATEMENT = (
    "I consent this execution identity to the reviewed random assignment for "
    "J1-D qualification evidence preparation. This consent does not authorize "
    "model or agent execution."
)
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
SIGNATURE_FIELDS = {"algorithm", "signed_payload_sha256", "signature_hex"}
REVIEWER_FIELDS = {"did", "public_key_hex", "signer_kind", "credential_version"}
BASELINE_PARTICIPANT_FIELDS = {
    "participant_id",
    "participant_profile_sha256",
    "initial_state_artifact_sha256",
    "initial_state",
}
INITIAL_STATE_FIELDS = {
    "schema_version",
    "participant_id",
    "qualification_protocol_sha256",
    "agent_revision",
    "runtime_revision",
    "prior_mentorship_exposure",
    "memory_entry_count",
    "relation_count",
    "model_invocation_count",
    "tick_count",
    "execution_authorized",
    "initial_state_sha256",
}
BASELINE_FIELDS = {
    "schema_version",
    "qualification_protocol_sha256",
    "attested_at",
    "public_only",
    "secret_material_included",
    "pair_id",
    "reviewed_pairing_sha256",
    "owner_authorization_id",
    "owner_authorization_statement_sha256",
    "assessment_method",
    "performance_measurement_performed",
    "participants",
    "baseline_commitment_sha256",
    "reviewer",
    "signature",
}
CONSENT_FIELDS = {
    "schema_version",
    "qualification_protocol_sha256",
    "attested_at",
    "public_only",
    "secret_material_included",
    "participant_id",
    "execution_did",
    "pair_id",
    "reviewed_pairing_sha256",
    "owner_authorization_id",
    "owner_authorization_statement_sha256",
    "participant_profile_sha256",
    "public_key_hex",
    "consent_nonce_hex",
    "consent_statement",
    "consent_statement_sha256",
    "random_assignment_consented",
    "model_execution_authorized",
    "signature",
}


class EvidenceSigner(Protocol):
    @property
    def public_key_hex(self) -> str: ...

    def sign(self, message: bytes) -> bytes: ...


def signature_payload(value: dict[str, Any]) -> bytes:
    body = {key: item for key, item in value.items() if key != "signature"}
    return json.dumps(
        body, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")


def build_cognitive_baseline(
    *,
    pair_id: str,
    reviewed_pairing_sha256: str,
    qualification_protocol_sha256: str,
    owner_authorization_id: str,
    owner_authorization_statement_sha256: str,
    attested_at: str,
    participants: list[dict[str, Any]],
    reviewer: dict[str, Any],
    signer: EvidenceSigner,
) -> dict[str, Any]:
    if signer.public_key_hex.lower() != str(reviewer.get("public_key_hex", "")).lower():
        raise ValueError("baseline signer does not match reviewer identity")
    baseline = {
        "schema_version": BASELINE_SCHEMA,
        "qualification_protocol_sha256": qualification_protocol_sha256,
        "attested_at": attested_at,
        "public_only": True,
        "secret_material_included": False,
        "pair_id": pair_id,
        "reviewed_pairing_sha256": reviewed_pairing_sha256,
        "owner_authorization_id": owner_authorization_id,
        "owner_authorization_statement_sha256": owner_authorization_statement_sha256,
        "assessment_method": ASSESSMENT_METHOD,
        "performance_measurement_performed": False,
        "participants": participants,
        "baseline_commitment_sha256": canonical_sha256(
            _baseline_commitment_payload(
                pair_id=pair_id,
                reviewed_pairing_sha256=reviewed_pairing_sha256,
                qualification_protocol_sha256=qualification_protocol_sha256,
                participants=participants,
            )
        ),
        "reviewer": reviewer,
    }
    baseline["signature"] = _signature(signer, signature_payload(baseline))
    failures = validate_cognitive_baseline(baseline)
    if failures:
        raise ValueError(f"cognitive baseline invalid: {failures}")
    return baseline


def build_participant_consent(
    *,
    participant: dict[str, Any],
    pair_id: str,
    participant_profile_sha256: str,
    reviewed_pairing_sha256: str,
    qualification_protocol_sha256: str,
    owner_authorization_id: str,
    owner_authorization_statement_sha256: str,
    attested_at: str,
    consent_nonce: bytes,
    signer: EvidenceSigner,
) -> dict[str, Any]:
    public_key_hex = str(participant.get("public_key_hex", ""))
    if signer.public_key_hex.lower() != public_key_hex.lower():
        raise ValueError("consent signer does not match participant identity")
    consent = {
        "schema_version": CONSENT_SCHEMA,
        "qualification_protocol_sha256": qualification_protocol_sha256,
        "attested_at": attested_at,
        "public_only": True,
        "secret_material_included": False,
        "participant_id": participant.get("participant_id"),
        "execution_did": participant.get("execution_did"),
        "pair_id": pair_id,
        "reviewed_pairing_sha256": reviewed_pairing_sha256,
        "owner_authorization_id": owner_authorization_id,
        "owner_authorization_statement_sha256": owner_authorization_statement_sha256,
        "participant_profile_sha256": participant_profile_sha256,
        "public_key_hex": public_key_hex,
        "consent_nonce_hex": consent_nonce.hex(),
        "consent_statement": CONSENT_STATEMENT,
        "consent_statement_sha256": hashlib.sha256(
            CONSENT_STATEMENT.encode("utf-8")
        ).hexdigest(),
        "random_assignment_consented": True,
        "model_execution_authorized": False,
    }
    consent["signature"] = _signature(signer, signature_payload(consent))
    failures = validate_participant_consent(consent)
    if failures:
        raise ValueError(f"participant consent invalid: {failures}")
    return consent


def validate_cognitive_baseline(value: Any) -> list[str]:
    baseline = value if isinstance(value, dict) else {}
    failures: list[str] = []
    _require(set(baseline) == BASELINE_FIELDS, "participant_baseline_fields_invalid", failures)
    _require(baseline.get("schema_version") == BASELINE_SCHEMA, "participant_baseline_schema_invalid", failures)
    _validate_public_common(baseline, "participant_baseline", failures)
    _require(bool(str(baseline.get("pair_id", "")).strip()), "participant_baseline_pair_id_invalid", failures)
    _require(_sha256(baseline.get("qualification_protocol_sha256")), "participant_baseline_protocol_hash_invalid", failures)
    _require(_sha256(baseline.get("reviewed_pairing_sha256")), "participant_baseline_pairing_hash_invalid", failures)
    _require(bool(str(baseline.get("owner_authorization_id", "")).strip()), "participant_baseline_owner_authorization_id_invalid", failures)
    _require(_sha256(baseline.get("owner_authorization_statement_sha256")), "participant_baseline_owner_authorization_hash_invalid", failures)
    _require(baseline.get("assessment_method") == ASSESSMENT_METHOD, "participant_baseline_assessment_method_invalid", failures)
    _require(baseline.get("performance_measurement_performed") is False, "participant_baseline_performance_claim_forbidden", failures)
    participants = baseline.get("participants")
    _require(isinstance(participants, list) and len(participants) == 2, "participant_baseline_participants_invalid", failures)
    if isinstance(participants, list):
        for record in participants:
            _validate_baseline_participant(record, baseline, failures)
        identifiers = [str(_object(record).get("participant_id", "")) for record in participants]
        _require(len(set(identifiers)) == 2, "participant_baseline_participants_duplicate", failures)
    expected_commitment = canonical_sha256(
        _baseline_commitment_payload(
            pair_id=str(baseline.get("pair_id", "")),
            reviewed_pairing_sha256=str(baseline.get("reviewed_pairing_sha256", "")),
            qualification_protocol_sha256=str(baseline.get("qualification_protocol_sha256", "")),
            participants=participants if isinstance(participants, list) else [],
        )
    )
    _require(baseline.get("baseline_commitment_sha256") == expected_commitment, "participant_baseline_commitment_mismatch", failures)
    _validate_reviewer(_object(baseline.get("reviewer")), failures)
    _validate_signature(baseline, _object(baseline.get("reviewer")).get("public_key_hex"), "participant_baseline", failures)
    return list(dict.fromkeys(failures))


def validate_participant_consent(value: Any) -> list[str]:
    consent = value if isinstance(value, dict) else {}
    failures: list[str] = []
    _require(set(consent) == CONSENT_FIELDS, "participant_consent_fields_invalid", failures)
    _require(consent.get("schema_version") == CONSENT_SCHEMA, "participant_consent_schema_invalid", failures)
    _validate_public_common(consent, "participant_consent", failures)
    _require(bool(str(consent.get("pair_id", "")).strip()), "participant_consent_pair_id_invalid", failures)
    public_key = str(consent.get("public_key_hex", ""))
    _require(_hex_bytes(public_key, 32), "participant_consent_public_key_invalid", failures)
    _require(consent.get("participant_id") == participant_id(public_key), "participant_consent_participant_id_key_mismatch", failures)
    _require(consent.get("execution_did") == participant_did(public_key), "participant_consent_did_key_mismatch", failures)
    for field in (
        "qualification_protocol_sha256",
        "reviewed_pairing_sha256",
        "participant_profile_sha256",
        "owner_authorization_statement_sha256",
    ):
        _require(_sha256(consent.get(field)), f"participant_consent_{field}_invalid", failures)
    _require(bool(str(consent.get("owner_authorization_id", "")).strip()), "participant_consent_owner_authorization_id_invalid", failures)
    _require(_hex_bytes(consent.get("consent_nonce_hex"), 32), "participant_consent_nonce_invalid", failures)
    _require(consent.get("consent_statement") == CONSENT_STATEMENT, "participant_consent_statement_invalid", failures)
    _require(
        consent.get("consent_statement_sha256") == hashlib.sha256(CONSENT_STATEMENT.encode("utf-8")).hexdigest(),
        "participant_consent_statement_hash_mismatch",
        failures,
    )
    _require(consent.get("random_assignment_consented") is True, "participant_random_assignment_consent_missing", failures)
    _require(consent.get("model_execution_authorized") is False, "participant_model_execution_must_be_false", failures)
    _validate_signature(consent, public_key, "participant_consent", failures)
    return list(dict.fromkeys(failures))


def _baseline_commitment_payload(
    *,
    pair_id: str,
    reviewed_pairing_sha256: str,
    qualification_protocol_sha256: str,
    participants: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "pair_id": pair_id,
        "reviewed_pairing_sha256": reviewed_pairing_sha256,
        "qualification_protocol_sha256": qualification_protocol_sha256,
        "assessment_method": ASSESSMENT_METHOD,
        "performance_measurement_performed": False,
        "participants": participants,
    }


def _validate_baseline_participant(value: Any, baseline: dict[str, Any], failures: list[str]) -> None:
    record = _object(value)
    _require(set(record) == BASELINE_PARTICIPANT_FIELDS, "participant_baseline_record_fields_invalid", failures)
    for field in ("participant_profile_sha256", "initial_state_artifact_sha256"):
        _require(_sha256(record.get(field)), f"participant_baseline_{field}_invalid", failures)
    state = _object(record.get("initial_state"))
    _require(set(state) == INITIAL_STATE_FIELDS, "participant_baseline_initial_state_fields_invalid", failures)
    _require(state.get("schema_version") == "j1-qualification-initial-state:v1", "participant_baseline_initial_state_schema_invalid", failures)
    _require(state.get("participant_id") == record.get("participant_id"), "participant_baseline_initial_state_participant_mismatch", failures)
    _require(state.get("qualification_protocol_sha256") == baseline.get("qualification_protocol_sha256"), "participant_baseline_initial_state_protocol_mismatch", failures)
    for field in ("memory_entry_count", "relation_count", "model_invocation_count", "tick_count"):
        _require(state.get(field) == 0, f"participant_baseline_{field}_must_be_zero", failures)
    _require(state.get("prior_mentorship_exposure") is False, "participant_baseline_prior_mentorship_must_be_false", failures)
    _require(state.get("execution_authorized") is False, "participant_baseline_execution_authorized_must_be_false", failures)
    expected = canonical_sha256({key: item for key, item in state.items() if key != "initial_state_sha256"})
    _require(state.get("initial_state_sha256") == expected, "participant_baseline_initial_state_hash_mismatch", failures)


def _validate_reviewer(reviewer: dict[str, Any], failures: list[str]) -> None:
    _require(set(reviewer) == REVIEWER_FIELDS, "participant_baseline_reviewer_fields_invalid", failures)
    _require(_hex_bytes(reviewer.get("public_key_hex"), 32), "participant_baseline_reviewer_key_invalid", failures)
    _require(
        reviewer.get("did") == reviewer_did(str(reviewer.get("public_key_hex", ""))),
        "participant_baseline_reviewer_did_invalid",
        failures,
    )
    _require(reviewer.get("signer_kind") == "pkcs11_ed25519", "participant_baseline_reviewer_signer_invalid", failures)
    _require(reviewer.get("credential_version") == 1, "participant_baseline_reviewer_credential_invalid", failures)


def _signature(signer: EvidenceSigner, payload: bytes) -> dict[str, str]:
    signature = signer.sign(payload)
    if len(signature) != 64:
        raise ValueError("Ed25519 signature must be 64 bytes")
    return {
        "algorithm": "Ed25519",
        "signed_payload_sha256": hashlib.sha256(payload).hexdigest(),
        "signature_hex": signature.hex(),
    }


def _validate_signature(value: dict[str, Any], public_key: Any, label: str, failures: list[str]) -> None:
    signature = _object(value.get("signature"))
    _require(set(signature) == SIGNATURE_FIELDS, f"{label}_signature_fields_invalid", failures)
    _require(signature.get("algorithm") == "Ed25519", f"{label}_signature_algorithm_invalid", failures)
    payload = signature_payload(value)
    _require(signature.get("signed_payload_sha256") == hashlib.sha256(payload).hexdigest(), f"{label}_signature_payload_hash_mismatch", failures)
    try:
        VerifyKey(bytes.fromhex(str(public_key))).verify(payload, bytes.fromhex(str(signature.get("signature_hex"))))
    except (BadSignatureError, ValueError, TypeError):
        _require(False, f"{label}_signature_invalid", failures)


def _hex_bytes(value: Any, size: int) -> bool:
    try:
        decoded = bytes.fromhex(str(value or ""))
    except ValueError:
        return False
    return len(decoded) == size


def reviewer_did(public_key_hex: str) -> str:
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
    return f"did:civ:testnet:z{encoded}"


def _validate_public_common(value: dict[str, Any], label: str, failures: list[str]) -> None:
    try:
        attested_at = datetime.fromisoformat(
            str(value.get("attested_at", "")).replace("Z", "+00:00")
        )
    except ValueError:
        attested_at = None
    _require(attested_at is not None and attested_at.tzinfo is not None, f"{label}_attested_at_invalid", failures)
    _require(value.get("public_only") is True, f"{label}_must_be_public_only", failures)
    _require(value.get("secret_material_included") is False, f"{label}_secret_material_forbidden", failures)


def _sha256(value: Any) -> bool:
    return _hex_bytes(value, 32) and str(value) == str(value).lower()


def _object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _require(condition: bool, code: str, failures: list[str]) -> None:
    if not condition and code not in failures:
        failures.append(code)
