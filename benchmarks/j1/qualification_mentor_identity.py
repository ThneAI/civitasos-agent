"""Controlled-beta J1-D mentor signing identity contract."""

from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Any

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from .controlled_comparison import canonical_sha256


SCHEMA = "j1-qualification-mentor-identity:v1"
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def mentor_did(public_key_hex: str) -> str:
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
    return f"did:civ:mentor:z{encoded}"


def mentor_id(public_key_hex: str) -> str:
    try:
        public_key = bytes.fromhex(public_key_hex)
    except ValueError:
        return ""
    if len(public_key) != 32:
        return ""
    return f"j1q-mentor-{hashlib.sha256(public_key).hexdigest()[:20]}"


def build_mentor_identity_profile(
    *,
    created_at: str,
    plan: dict[str, Any],
    plan_artifact_sha256: str,
    owner_authorization_id: str,
    owner_statement_sha256: str,
    public_key_hex: str,
    module_path: str,
    module_sha256: str,
    token_label: str,
    token_serial: str,
    token_model: str,
    token_manufacturer: str,
    key_label: str,
    key_id_hex: str,
    key_reference_sha256: str,
    challenge: bytes,
    signature: bytes,
    private_key_sensitive: bool,
    private_key_extractable: bool,
    implementation: dict[str, str],
) -> dict[str, Any]:
    profile = {
        "schema_version": SCHEMA,
        "profile": "controlled_beta_soft_token_qualification_mentor",
        "created_at": created_at,
        "source_binding": {
            "provisioning_plan_sha256": plan["plan_sha256"],
            "provisioning_plan_artifact_sha256": plan_artifact_sha256,
            "reviewed_design_sha256": plan["source_binding"]["reviewed_design_sha256"],
            "participant_identity_set_sha256": plan["source_binding"][
                "participant_identity_set_sha256"
            ],
            "owner_authorization_id": owner_authorization_id,
            "owner_statement_sha256": owner_statement_sha256,
        },
        "mentor": {
            "mentor_id": mentor_id(public_key_hex),
            "did": mentor_did(public_key_hex),
            "public_key_hex": public_key_hex,
            "public_key_sha256": hashlib.sha256(
                bytes.fromhex(public_key_hex)
            ).hexdigest(),
            "credential_version": 1,
            "signer_kind": "pkcs11_ed25519",
            "role": "qualification_treatment_advice_signer",
        },
        "pkcs11_key": {
            "module_path": module_path,
            "module_sha256": module_sha256,
            "token_label": token_label,
            "token_serial": token_serial,
            "token_model": token_model,
            "token_manufacturer": token_manufacturer,
            "key_label": key_label,
            "key_id_hex": key_id_hex.lower(),
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
        "implementation": implementation,
        "authorization_boundary": {
            "identity_provisioned": True,
            "possession_proof_created": True,
            "treatment_advice_signing_allowed": False,
            "provider_api_call_allowed": False,
            "model_invocation_allowed": False,
            "agent_execution_allowed": False,
            "backend_fact_append_allowed": False,
            "ledger_append_allowed": False,
        },
    }
    profile["profile_sha256"] = canonical_sha256(profile)
    failures = validate_mentor_identity_profile(profile, plan=plan)
    if failures:
        raise ValueError(f"mentor identity profile invalid: {failures}")
    return profile


def validate_mentor_identity_profile(value: Any, *, plan: dict[str, Any]) -> list[str]:
    profile = value if isinstance(value, dict) else {}
    failures: list[str] = []
    _require(
        set(profile)
        == {
            "schema_version",
            "profile",
            "created_at",
            "source_binding",
            "mentor",
            "pkcs11_key",
            "possession_proof",
            "custody_boundary",
            "implementation",
            "authorization_boundary",
            "profile_sha256",
        },
        "mentor_identity_fields_invalid",
        failures,
    )
    _require(
        profile.get("schema_version") == SCHEMA,
        "mentor_identity_schema_invalid",
        failures,
    )
    _require(
        profile.get("profile") == "controlled_beta_soft_token_qualification_mentor",
        "mentor_identity_kind_invalid",
        failures,
    )
    _require(
        _rfc3339(profile.get("created_at")), "mentor_identity_time_invalid", failures
    )
    source = _object(profile.get("source_binding"))
    _require(
        source
        == {
            "provisioning_plan_sha256": plan.get("plan_sha256"),
            "provisioning_plan_artifact_sha256": source.get(
                "provisioning_plan_artifact_sha256"
            ),
            "reviewed_design_sha256": plan.get("source_binding", {}).get(
                "reviewed_design_sha256"
            ),
            "participant_identity_set_sha256": plan.get("source_binding", {}).get(
                "participant_identity_set_sha256"
            ),
            "owner_authorization_id": source.get("owner_authorization_id"),
            "owner_statement_sha256": source.get("owner_statement_sha256"),
        }
        and _sha256(source.get("provisioning_plan_artifact_sha256"))
        and _text(source.get("owner_authorization_id"))
        and _sha256(source.get("owner_statement_sha256")),
        "mentor_identity_source_binding_invalid",
        failures,
    )
    mentor = _object(profile.get("mentor"))
    public_key_hex = str(mentor.get("public_key_hex") or "")
    _require(
        set(mentor)
        == {
            "mentor_id",
            "did",
            "public_key_hex",
            "public_key_sha256",
            "credential_version",
            "signer_kind",
            "role",
        }
        and _hex_bytes(public_key_hex, 32)
        and mentor.get("mentor_id") == mentor_id(public_key_hex)
        and mentor.get("did") == mentor_did(public_key_hex)
        and mentor.get("public_key_sha256")
        == hashlib.sha256(bytes.fromhex(public_key_hex)).hexdigest()
        and mentor.get("credential_version") == 1
        and mentor.get("signer_kind") == "pkcs11_ed25519"
        and mentor.get("role") == "qualification_treatment_advice_signer",
        "mentor_identity_subject_invalid",
        failures,
    )
    participants = plan.get("mentor_role", {}).get("participant_identity_set", [])
    _require(
        mentor.get("did")
        not in {
            item.get("execution_did") for item in participants if isinstance(item, dict)
        }
        and mentor.get("public_key_sha256")
        not in {
            item.get("public_key_sha256")
            for item in participants
            if isinstance(item, dict)
        },
        "mentor_identity_participant_collision",
        failures,
    )
    proposed = plan.get("proposed_identity", {})
    key = _object(profile.get("pkcs11_key"))
    _require(
        set(key)
        == {
            "module_path",
            "module_sha256",
            "token_label",
            "token_serial",
            "token_model",
            "token_manufacturer",
            "key_label",
            "key_id_hex",
            "key_reference_sha256",
            "key_type",
            "mechanism",
        }
        and key.get("module_path") == proposed.get("module_path")
        and key.get("module_sha256") == proposed.get("module_sha256")
        and key.get("token_label") == proposed.get("token_label")
        and key.get("token_serial") == proposed.get("token_serial")
        and key.get("token_model") == proposed.get("token_model")
        and key.get("key_label") == proposed.get("key_label")
        and key.get("key_id_hex") == proposed.get("key_id_hex")
        and _sha256(key.get("key_reference_sha256"))
        and key.get("key_type") == "CKK_EC_EDWARDS"
        and key.get("mechanism") == "CKM_EDDSA",
        "mentor_identity_key_binding_invalid",
        failures,
    )
    proof = _object(profile.get("possession_proof"))
    challenge_hex = str(proof.get("challenge_hex") or "")
    signature_hex = str(proof.get("signature_hex") or "")
    _require(
        set(proof)
        == {"challenge_hex", "challenge_sha256", "signature_hex", "signature_verified"}
        and _hex_bytes(challenge_hex, 32)
        and _hex_bytes(signature_hex, 64)
        and proof.get("challenge_sha256")
        == hashlib.sha256(bytes.fromhex(challenge_hex)).hexdigest()
        and proof.get("signature_verified") is True,
        "mentor_identity_possession_proof_invalid",
        failures,
    )
    try:
        VerifyKey(bytes.fromhex(public_key_hex)).verify(
            bytes.fromhex(challenge_hex), bytes.fromhex(signature_hex)
        )
    except (BadSignatureError, ValueError):
        failures.append("mentor_identity_possession_signature_invalid")
    custody = _object(profile.get("custody_boundary"))
    _require(
        custody
        == {
            "provider": "SoftHSM v2",
            "physical_hsm_claimed": False,
            "production_custody_claimed": False,
            "token_store_copyable": True,
            "private_key_sensitive": True,
            "private_key_extractable": False,
            "seed_exported": False,
            "pin_recorded": False,
        },
        "mentor_identity_custody_invalid",
        failures,
    )
    implementation = _object(profile.get("implementation"))
    _require(
        set(implementation)
        == {
            "agent_revision",
            "contract_source_sha256",
            "operation_source_sha256",
            "gate_source_sha256",
        }
        and _text(implementation.get("agent_revision"))
        and all(
            _sha256(implementation.get(field))
            for field in (
                "contract_source_sha256",
                "operation_source_sha256",
                "gate_source_sha256",
            )
        ),
        "mentor_identity_implementation_invalid",
        failures,
    )
    boundary = _object(profile.get("authorization_boundary"))
    _require(
        len(boundary) == 8
        and boundary.get("identity_provisioned") is True
        and boundary.get("possession_proof_created") is True
        and all(
            item is False
            for key_name, item in boundary.items()
            if key_name not in {"identity_provisioned", "possession_proof_created"}
        ),
        "mentor_identity_authorization_boundary_invalid",
        failures,
    )
    body = {
        key_name: item
        for key_name, item in profile.items()
        if key_name != "profile_sha256"
    }
    _require(
        profile.get("profile_sha256") == canonical_sha256(body),
        "mentor_identity_hash_mismatch",
        failures,
    )
    return list(dict.fromkeys(failures))


def _object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(char in "0123456789abcdef" for char in value.lower())
    )


def _hex_bytes(value: Any, length: int) -> bool:
    return (
        isinstance(value, str)
        and len(value) == length * 2
        and all(char in "0123456789abcdef" for char in value.lower())
    )


def _rfc3339(value: Any) -> bool:
    if not _text(value):
        return False
    try:
        return (
            datetime.fromisoformat(str(value).replace("Z", "+00:00")).tzinfo is not None
        )
    except ValueError:
        return False


def _require(condition: bool, code: str, failures: list[str]) -> None:
    if not condition and code not in failures:
        failures.append(code)
