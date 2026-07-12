#!/usr/bin/env python3
"""Exercise Pkcs11Ed25519Signer against an isolated SoftHSM token."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path

import pkcs11
from civitasos import Pkcs11Ed25519Signer
from nacl.signing import VerifyKey


MODULE = os.environ.get("CIVITASOS_PKCS11_MODULE", "/usr/lib/softhsm/libsofthsm2.so")


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="civitasos-softhsm-") as temporary:
        root = Path(temporary)
        token_dir = root / "tokens"
        token_dir.mkdir()
        config = root / "softhsm2.conf"
        config.write_text(f"directories.tokendir = {token_dir}\nobjectstore.backend = file\n")
        env = os.environ | {"SOFTHSM2_CONF": str(config)}
        subprocess.run(
            [
                "softhsm2-util", "--init-token", "--free", "--label", "civitas-test",
                "--so-pin", "12345678", "--pin", "123456",
            ],
            env=env,
            check=True,
            capture_output=True,
            text=True,
        )
        previous_config = os.environ.get("SOFTHSM2_CONF")
        os.environ["SOFTHSM2_CONF"] = str(config)
        try:
            library = pkcs11.lib(MODULE)
            token = library.get_token(token_label="civitas-test")
            with token.open(user_pin="123456", rw=True) as session:
                public_key, _private_key = session.generate_keypair(
                    pkcs11.KeyType.EC_EDWARDS,
                    public_template={
                        pkcs11.Attribute.EC_PARAMS: bytes.fromhex("06032b6570")
                    },
                    label="agent-key",
                    store=True,
                )
                encoded_point = bytes(public_key[pkcs11.Attribute.EC_POINT])
                if encoded_point[:2] != b"\x04\x20" or len(encoded_point) != 34:
                    raise RuntimeError(f"unexpected Ed25519 EC_POINT: {encoded_point.hex()}")
                public_key_hex = encoded_point[2:].hex()

            message = b"civitasos-softhsm-pkcs11-smoke:v1"
            with Pkcs11Ed25519Signer(
                MODULE,
                "civitas-test",
                "agent-key",
                public_key_hex,
                "123456",
            ) as signer:
                signature = signer.sign(message)
                VerifyKey(bytes.fromhex(signer.public_key_hex)).verify(message, signature)
                if hasattr(signer, "export_seed_hex"):
                    raise RuntimeError("PKCS#11 signer unexpectedly exposes seed export")

            print(
                json.dumps(
                    {
                        "schema_version": "p3-softhsm-pkcs11-smoke:v1",
                        "passed": True,
                        "module": MODULE,
                        "mechanism": "CKM_EDDSA",
                        "key_type": "CKK_EC_EDWARDS",
                        "signature_bytes": len(signature),
                        "seed_exported": False,
                        "hardware_claimed": False,
                        "production_claimed": False,
                    },
                    indent=2,
                )
            )
            return 0
        finally:
            if previous_config is None:
                os.environ.pop("SOFTHSM2_CONF", None)
            else:
                os.environ["SOFTHSM2_CONF"] = previous_config


if __name__ == "__main__":
    raise SystemExit(main())
