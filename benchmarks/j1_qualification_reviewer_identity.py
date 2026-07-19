"""Provision a controlled-beta SoftHSM Ed25519 reviewer identity."""

from __future__ import annotations

import argparse
import hashlib
import json
import secrets
from datetime import datetime
from pathlib import Path
from typing import Any

import pkcs11
from civitasos import Pkcs11Ed25519Signer
from nacl.signing import VerifyKey

from benchmarks.j1.controlled_comparison import write_private_json
from benchmarks.j1.qualification_reviewer_identity import (
    build_reviewer_identity_profile,
)
from scripts.pkcs11_identity_probe import DEFAULT_MODULE, read_pin


USER_PIN_RISK_FLAGS = {
    "USER_PIN_COUNT_LOW",
    "USER_PIN_FINAL_TRY",
    "USER_PIN_LOCKED",
}
SO_PIN_RISK_FLAGS = {"SO_PIN_COUNT_LOW", "SO_PIN_FINAL_TRY", "SO_PIN_LOCKED"}


def inspect_token_pin_state(*, module_path: str, token_label: str) -> dict[str, Any]:
    module = Path(module_path).resolve()
    library = pkcs11.lib(str(module))
    token = library.get_token(token_label=token_label)
    flags = {flag.name for flag in pkcs11.TokenFlag if flag in token.flags}
    user_risks = sorted(flags & USER_PIN_RISK_FLAGS)
    so_risks = sorted(flags & SO_PIN_RISK_FLAGS)
    return {
        "schema_version": "j1-soft-token-pin-state:v1",
        "token_label": token.label,
        "token_serial": _decode(token.serial),
        "token_model": token.model,
        "token_initialized": "TOKEN_INITIALIZED" in flags,
        "user_pin_initialized": "USER_PIN_INITIALIZED" in flags,
        "user_pin_risk_flags": user_risks,
        "so_pin_risk_flags": so_risks,
        "safe_to_attempt_user_login": not user_risks,
        "safe_to_attempt_so_login": not so_risks,
        "pin_read": False,
        "login_attempted": False,
    }


def provision_reviewer_identity(
    *,
    module_path: str,
    token_label: str,
    key_label: str,
    key_id_hex: str,
    credential_version: int,
    pin: str,
    output_path: Path,
    limitations_acknowledged: bool,
    created_at: str | None = None,
) -> dict[str, Any]:
    if not limitations_acknowledged:
        raise ValueError("SoftHSM limitations must be explicitly acknowledged")
    if output_path.exists():
        raise ValueError(f"output already exists: {output_path}")
    if not pin:
        raise ValueError("SoftHSM user PIN is empty")
    key_id = _key_id(key_id_hex)
    if credential_version <= 0:
        raise ValueError("credential version must be positive")
    module = Path(module_path).resolve()
    module_bytes = module.read_bytes()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.parent.chmod(0o700)
    library = pkcs11.lib(str(module))
    token = library.get_token(token_label=token_label)
    if token.model != "SoftHSM v2":
        raise ValueError(f"token is not SoftHSM v2: {token.model}")
    pin_state = inspect_token_pin_state(
        module_path=str(module), token_label=token_label
    )
    if not pin_state["safe_to_attempt_user_login"]:
        raise ValueError(
            "token user PIN retry risk; SO PIN reset required before login: "
            f"{pin_state['user_pin_risk_flags']}"
        )
    with token.open(user_pin=pin, rw=True) as session:
        if list(session.get_objects({pkcs11.Attribute.LABEL: key_label})):
            raise ValueError(f"PKCS#11 key label already exists: {key_label}")
        if list(session.get_objects({pkcs11.Attribute.ID: key_id})):
            raise ValueError(f"PKCS#11 key ID already exists: {key_id_hex.lower()}")
        public_key, private_key = session.generate_keypair(
            pkcs11.KeyType.EC_EDWARDS,
            public_template={
                pkcs11.Attribute.EC_PARAMS: bytes.fromhex("06032b6570"),
                pkcs11.Attribute.VERIFY: True,
            },
            private_template={
                pkcs11.Attribute.SIGN: True,
                pkcs11.Attribute.SENSITIVE: True,
                pkcs11.Attribute.EXTRACTABLE: False,
            },
            label=key_label,
            id=key_id,
            store=True,
        )
        encoded_point = bytes(public_key[pkcs11.Attribute.EC_POINT])
        if encoded_point[:2] != b"\x04\x20" or len(encoded_point) != 34:
            raise RuntimeError("SoftHSM returned an unsupported Ed25519 public key")
        public_key_hex = encoded_point[2:].hex()
        private_key_sensitive = bool(private_key[pkcs11.Attribute.SENSITIVE])
        private_key_extractable = bool(private_key[pkcs11.Attribute.EXTRACTABLE])
    challenge = secrets.token_bytes(32)
    with Pkcs11Ed25519Signer(
        str(module),
        token_label,
        key_label,
        public_key_hex,
        pin,
        key_id=key_id_hex,
    ) as signer:
        signature = signer.sign(challenge)
        VerifyKey(bytes.fromhex(public_key_hex)).verify(challenge, signature)
        key_reference = signer.key_reference
    profile = build_reviewer_identity_profile(
        created_at=created_at or _timestamp(),
        public_key_hex=public_key_hex,
        credential_version=credential_version,
        module_path=str(module),
        module_bytes=module_bytes,
        token_label=token.label,
        token_serial=_decode(token.serial),
        token_model=token.model,
        token_manufacturer=token.manufacturer_id,
        key_label=key_label,
        key_id_hex=key_id_hex,
        key_reference=key_reference,
        challenge=challenge,
        signature=signature,
        private_key_sensitive=private_key_sensitive,
        private_key_extractable=private_key_extractable,
    )
    write_private_json(output_path, profile)
    return {
        "schema_version": "j1-controlled-beta-reviewer-provision:v1",
        "passed": True,
        "state": "controlled_beta_reviewer_identity_ready_operator_review_required",
        "identity_profile": {
            "path": str(output_path.resolve()),
            "sha256": hashlib.sha256(output_path.read_bytes()).hexdigest(),
        },
        "reviewer_did": profile["reviewer"]["did"],
        "public_key_hex": public_key_hex,
        "key_reference": key_reference,
        "custody_boundary": profile["custody_boundary"],
        "authorization_boundary": profile["authorization_boundary"],
    }


def _key_id(value: str) -> bytes:
    text = value.strip().lower()
    if (
        not text
        or len(text) % 2
        or any(char not in "0123456789abcdef" for char in text)
    ):
        raise ValueError("key ID must be an even-length hexadecimal value")
    return bytes.fromhex(text)


def _decode(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("ascii").strip()
    return str(value).strip()


def _timestamp() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--module", default=DEFAULT_MODULE)
    parser.add_argument("--token-label", required=True)
    parser.add_argument("--key-label", required=True)
    parser.add_argument("--key-id", required=True, help="unique CKA_ID as hex")
    parser.add_argument("--credential-version", type=int, default=1)
    parser.add_argument("--pin-file", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--acknowledge-soft-token-limitations",
        action="store_true",
        help="acknowledge this is copyable software-token custody, not a physical HSM",
    )
    args = parser.parse_args()
    if not args.acknowledge_soft_token_limitations:
        parser.error("--acknowledge-soft-token-limitations is required")
    try:
        pin_state = inspect_token_pin_state(
            module_path=args.module, token_label=args.token_label
        )
    except (OSError, pkcs11.PKCS11Error) as error:
        print(
            json.dumps(
                {
                    "schema_version": "j1-controlled-beta-reviewer-provision:v1",
                    "passed": False,
                    "state": "blocked_soft_token_inspection",
                    "error_class": type(error).__name__,
                    "pin_read": False,
                    "login_attempted": False,
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 1
    if not pin_state["safe_to_attempt_user_login"]:
        print(
            json.dumps(
                {
                    "schema_version": "j1-controlled-beta-reviewer-provision:v1",
                    "passed": False,
                    "state": "blocked_user_pin_retry_risk_so_reset_required",
                    "token_pin_state": pin_state,
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 1
    pin = read_pin(args.pin_file)
    try:
        try:
            report = provision_reviewer_identity(
                module_path=args.module,
                token_label=args.token_label,
                key_label=args.key_label,
                key_id_hex=args.key_id,
                credential_version=args.credential_version,
                pin=pin,
                output_path=args.output,
                limitations_acknowledged=args.acknowledge_soft_token_limitations,
            )
        except pkcs11.exceptions.PinIncorrect:
            report = {
                "schema_version": "j1-controlled-beta-reviewer-provision:v1",
                "passed": False,
                "state": "blocked_user_pin_incorrect_stop_retrying",
                "error_class": "PinIncorrect",
                "pin_recorded": False,
                "reviewer_key_created": False,
            }
    finally:
        pin = ""
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
