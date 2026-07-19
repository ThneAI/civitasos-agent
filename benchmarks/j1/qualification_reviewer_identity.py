"""Validate controlled-beta SoftHSM reviewer identity evidence."""

from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Any

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey


REVIEWER_IDENTITY_SCHEMA = "j1-controlled-beta-reviewer-identity:v1"
PROFILE_FIELDS = {
    "schema_version",
    "profile",
    "created_at",
    "reviewer",
    "pkcs11_key",
    "possession_proof",
    "custody_boundary",
    "authorization_boundary",
}
REVIEWER_FIELDS = {"did", "public_key_hex", "signer_kind", "credential_version"}
KEY_FIELDS = {
    "module_path",
    "module_sha256",
    "token_label",
    "token_serial",
    "token_model",
    "token_manufacturer",
    "key_label",
    "key_id_hex",
    "key_reference",
    "key_type",
    "mechanism",
}
PROOF_FIELDS = {
    "challenge_hex",
    "challenge_sha256",
    "signature_hex",
    "signature_verified",
}
CUSTODY_FIELDS = {
    "provider",
    "physical_hsm_claimed",
    "production_custody_claimed",
    "token_store_copyable",
    "private_key_sensitive",
    "private_key_extractable",
    "seed_exported",
    "pin_recorded",
}
AUTHORIZATION_FIELDS = {
    "operator_decision_automated",
    "qualification_materials_approved",
    "review_receipt_created",
    "protocol_freeze_authorized",
    "model_invocation_allowed",
}
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def build_reviewer_identity_profile(
    *,
    created_at: str,
    public_key_hex: str,
    credential_version: int,
    module_path: str,
    module_bytes: bytes,
    token_label: str,
    token_serial: str,
    token_model: str,
    token_manufacturer: str,
    key_label: str,
    key_id_hex: str,
    key_reference: str,
    challenge: bytes,
    signature: bytes,
    private_key_sensitive: bool,
    private_key_extractable: bool,
) -> dict[str, Any]:
    profile = {
        "schema_version": REVIEWER_IDENTITY_SCHEMA,
        "profile": "controlled_beta_soft_token",
        "created_at": created_at,
        "reviewer": {
            "did": _did(public_key_hex),
            "public_key_hex": public_key_hex,
            "signer_kind": "pkcs11_ed25519",
            "credential_version": credential_version,
        },
        "pkcs11_key": {
            "module_path": module_path,
            "module_sha256": hashlib.sha256(module_bytes).hexdigest(),
            "token_label": token_label,
            "token_serial": token_serial,
            "token_model": token_model,
            "token_manufacturer": token_manufacturer,
            "key_label": key_label,
            "key_id_hex": key_id_hex.lower(),
            "key_reference": key_reference,
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
        "authorization_boundary": {
            "operator_decision_automated": False,
            "qualification_materials_approved": False,
            "review_receipt_created": False,
            "protocol_freeze_authorized": False,
            "model_invocation_allowed": False,
        },
    }
    failures = validate_reviewer_identity_profile(profile)
    if failures:
        raise ValueError(f"reviewer identity profile invalid: {failures}")
    return profile


def validate_reviewer_identity_profile(value: Any) -> list[str]:
    failures: list[str] = []
    profile = value if isinstance(value, dict) else {}
    _require(
        set(profile) == PROFILE_FIELDS, "reviewer_profile_fields_invalid", failures
    )
    _require(
        profile.get("schema_version") == REVIEWER_IDENTITY_SCHEMA,
        "reviewer_profile_schema_invalid",
        failures,
    )
    _require(
        profile.get("profile") == "controlled_beta_soft_token",
        "reviewer_profile_kind_invalid",
        failures,
    )
    _require(
        _rfc3339(profile.get("created_at")), "reviewer_profile_time_invalid", failures
    )
    reviewer = _object(profile.get("reviewer"))
    _require(
        set(reviewer) == REVIEWER_FIELDS, "reviewer_profile_reviewer_invalid", failures
    )
    public_key_hex = _text(reviewer.get("public_key_hex"))
    _require(_bytes_hex(public_key_hex, 32), "reviewer_public_key_invalid", failures)
    _require(
        reviewer.get("did") == _did(public_key_hex),
        "reviewer_profile_did_key_mismatch",
        failures,
    )
    _require(
        reviewer.get("signer_kind") == "pkcs11_ed25519",
        "reviewer_profile_signer_kind_invalid",
        failures,
    )
    _require(
        type(reviewer.get("credential_version")) is int
        and reviewer.get("credential_version") > 0,
        "reviewer_profile_credential_version_invalid",
        failures,
    )
    key = _object(profile.get("pkcs11_key"))
    _require(set(key) == KEY_FIELDS, "reviewer_profile_key_fields_invalid", failures)
    for field in (
        "module_path",
        "token_label",
        "token_serial",
        "token_model",
        "token_manufacturer",
        "key_label",
        "key_reference",
    ):
        _require(_text(key.get(field)), f"reviewer_profile_{field}_invalid", failures)
    _require(
        _sha256(key.get("module_sha256")),
        "reviewer_profile_module_hash_invalid",
        failures,
    )
    _require(
        _variable_hex(key.get("key_id_hex")),
        "reviewer_profile_key_id_invalid",
        failures,
    )
    _require(
        key.get("key_type") == "CKK_EC_EDWARDS",
        "reviewer_profile_key_type_invalid",
        failures,
    )
    _require(
        key.get("mechanism") == "CKM_EDDSA",
        "reviewer_profile_mechanism_invalid",
        failures,
    )
    proof = _object(profile.get("possession_proof"))
    _require(
        set(proof) == PROOF_FIELDS, "reviewer_profile_proof_fields_invalid", failures
    )
    challenge_hex = _text(proof.get("challenge_hex"))
    signature_hex = _text(proof.get("signature_hex"))
    _require(
        _bytes_hex(challenge_hex, 32), "reviewer_profile_challenge_invalid", failures
    )
    try:
        challenge = bytes.fromhex(challenge_hex)
    except ValueError:
        challenge = b""
    _require(
        proof.get("challenge_sha256") == hashlib.sha256(challenge).hexdigest(),
        "reviewer_profile_challenge_hash_mismatch",
        failures,
    )
    _require(
        _bytes_hex(signature_hex, 64), "reviewer_profile_signature_invalid", failures
    )
    _require(
        proof.get("signature_verified") is True,
        "reviewer_profile_signature_not_verified",
        failures,
    )
    try:
        VerifyKey(bytes.fromhex(public_key_hex)).verify(
            challenge, bytes.fromhex(signature_hex)
        )
    except (BadSignatureError, ValueError):
        failures.append("reviewer_profile_signature_verification_failed")
    custody = _object(profile.get("custody_boundary"))
    _require(
        set(custody) == CUSTODY_FIELDS,
        "reviewer_profile_custody_fields_invalid",
        failures,
    )
    _require(
        custody.get("provider") == "SoftHSM v2",
        "reviewer_profile_provider_invalid",
        failures,
    )
    for field in (
        "physical_hsm_claimed",
        "production_custody_claimed",
        "private_key_extractable",
        "seed_exported",
        "pin_recorded",
    ):
        _require(
            custody.get(field) is False,
            f"reviewer_profile_{field}_must_be_false",
            failures,
        )
    for field in ("token_store_copyable", "private_key_sensitive"):
        _require(
            custody.get(field) is True,
            f"reviewer_profile_{field}_must_be_true",
            failures,
        )
    authorization = _object(profile.get("authorization_boundary"))
    _require(
        set(authorization) == AUTHORIZATION_FIELDS,
        "reviewer_profile_authorization_fields_invalid",
        failures,
    )
    for field in AUTHORIZATION_FIELDS:
        _require(
            authorization.get(field) is False,
            f"reviewer_profile_{field}_must_be_false",
            failures,
        )
    return list(dict.fromkeys(failures))


def _did(public_key_hex: str) -> str:
    try:
        payload = b"\xed\x01" + bytes.fromhex(public_key_hex)
    except ValueError:
        return ""
    number = int.from_bytes(payload, "big")
    encoded = ""
    while number:
        number, remainder = divmod(number, 58)
        encoded = BASE58_ALPHABET[remainder] + encoded
    return f"did:civ:testnet:z{encoded}"


def _rfc3339(value: Any) -> bool:
    try:
        parsed = datetime.fromisoformat(_text(value).replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None


def _bytes_hex(value: Any, size: int) -> bool:
    text = _text(value)
    return len(text) == size * 2 and all(char in "0123456789abcdef" for char in text)


def _variable_hex(value: Any) -> bool:
    text = _text(value)
    return (
        bool(text)
        and len(text) % 2 == 0
        and all(char in "0123456789abcdef" for char in text)
    )


def _sha256(value: Any) -> bool:
    return _bytes_hex(value, 32)


def _text(value: Any) -> str:
    return str(value or "").strip()


def _object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _require(condition: bool, code: str, failures: list[str]) -> None:
    if not condition and code not in failures:
        failures.append(code)
