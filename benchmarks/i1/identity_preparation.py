"""Create or reuse local Ed25519 identities for I.1 preparation."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any


BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def prepare_identities(
    identities: list[dict[str, Any]],
    identity_root: Path,
) -> list[dict[str, Any]]:
    from civitasos import CivitasAgent

    identity_root.mkdir(parents=True, exist_ok=True)
    prepared = []
    for identity in identities:
        alias = str(identity["identity_alias"])
        key_path = identity_root / f"{alias}.key"
        agent = CivitasAgent(auto_discover=False)
        if key_path.exists():
            public_key = agent.load_identity(str(key_path))
        else:
            public_key = agent.generate_keys()
            agent.save_identity(str(key_path))
        os.chmod(key_path, 0o600)
        prepared.append(
            {
                **identity,
                "did": did_from_public_key(public_key),
                "public_key_hex": public_key,
                "identity_key_path": str(key_path.resolve()),
                "identity_key_mode": "0600",
                "registration_state": "local_key_ready_unregistered",
                "signature_control_proof": "required_before_i1",
            }
        )
    return prepared


def did_from_public_key(public_key_hex: str) -> str:
    payload = b"\xed\x01" + bytes.fromhex(public_key_hex)
    return f"did:civ:devnet:z{_base58_encode(payload)}"


def _base58_encode(data: bytes) -> str:
    zeros = len(data) - len(data.lstrip(b"\x00"))
    value = int.from_bytes(data, "big")
    encoded = ""
    while value:
        value, remainder = divmod(value, 58)
        encoded = BASE58_ALPHABET[remainder] + encoded
    return "1" * zeros + (encoded or "1")
