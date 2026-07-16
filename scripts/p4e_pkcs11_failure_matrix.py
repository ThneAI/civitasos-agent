#!/usr/bin/env python3
"""Exercise the PKCS#11 identity boundary and rotation failure matrix with SoftHSM."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Callable

import pkcs11
from civitasos import CivitasError, Pkcs11Ed25519Signer
from nacl.signing import VerifyKey


DEFAULT_MODULE = os.environ.get(
    "CIVITASOS_PKCS11_MODULE", "/usr/lib/softhsm/libsofthsm2.so"
)


def write_private_report(path: Path, report: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def expect_civitas_error(
    name: str,
    operation: Callable[[], object],
    expected_text: str,
) -> dict[str, object]:
    try:
        operation()
    except CivitasError as error:
        if expected_text not in str(error):
            raise RuntimeError(f"{name} returned an unexpected error: {error}") from error
        return {"name": name, "passed": True, "error_class": "CivitasError"}
    raise RuntimeError(f"{name} did not fail closed")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--module", default=DEFAULT_MODULE)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="civitasos-p4e-pkcs11-") as temporary:
        root = Path(temporary)
        token_dir = root / "tokens"
        token_dir.mkdir()
        config = root / "softhsm2.conf"
        config.write_text(f"directories.tokendir = {token_dir}\nobjectstore.backend = file\n")
        softhsm_env = os.environ | {"SOFTHSM2_CONF": str(config)}
        subprocess.run(
            [
                "softhsm2-util",
                "--init-token",
                "--free",
                "--label",
                "civitas-p4e",
                "--so-pin",
                "12345678",
                "--pin",
                "123456",
            ],
            env=softhsm_env,
            check=True,
            capture_output=True,
            text=True,
        )

        previous_config = os.environ.get("SOFTHSM2_CONF")
        os.environ["SOFTHSM2_CONF"] = str(config)
        try:
            library = pkcs11.lib(args.module)
            token = library.get_token(token_label="civitas-p4e")
            public_keys: dict[bytes, str] = {}
            with token.open(user_pin="123456", rw=True) as session:
                for key_id in (b"\x01", b"\x02"):
                    public_key, _ = session.generate_keypair(
                        pkcs11.KeyType.EC_EDWARDS,
                        public_template={
                            pkcs11.Attribute.EC_PARAMS: bytes.fromhex("06032b6570")
                        },
                        label="agent-signing",
                        id=key_id,
                        store=True,
                    )
                    encoded = bytes(public_key[pkcs11.Attribute.EC_POINT])
                    if encoded[:2] != b"\x04\x20" or len(encoded) != 34:
                        raise RuntimeError("SoftHSM returned an unsupported Ed25519 point")
                    public_keys[key_id] = encoded[2:].hex()

            failures = [
                expect_civitas_error(
                    "ambiguous_label_without_key_id",
                    lambda: Pkcs11Ed25519Signer(
                        args.module, "civitas-p4e", "agent-signing", None, "123456"
                    ),
                    "key ID is required",
                ),
                expect_civitas_error(
                    "unknown_key_id",
                    lambda: Pkcs11Ed25519Signer(
                        args.module,
                        "civitas-p4e",
                        "agent-signing",
                        None,
                        "123456",
                        key_id="03",
                    ),
                    "initialization failed",
                ),
                expect_civitas_error(
                    "incorrect_pin",
                    lambda: Pkcs11Ed25519Signer(
                        args.module,
                        "civitas-p4e",
                        "agent-signing",
                        None,
                        "incorrect",
                        key_id="01",
                    ),
                    "initialization failed",
                ),
                expect_civitas_error(
                    "inventory_public_key_mismatch",
                    lambda: Pkcs11Ed25519Signer(
                        args.module,
                        "civitas-p4e",
                        "agent-signing",
                        "00" * 32,
                        "123456",
                        key_id="01",
                    ),
                    "does not match",
                ),
                expect_civitas_error(
                    "unknown_token",
                    lambda: Pkcs11Ed25519Signer(
                        args.module,
                        "missing-token",
                        "agent-signing",
                        None,
                        "123456",
                        key_id="01",
                    ),
                    "initialization failed",
                ),
                expect_civitas_error(
                    "missing_module",
                    lambda: Pkcs11Ed25519Signer(
                        str(root / "missing-pkcs11.so"),
                        "civitas-p4e",
                        "agent-signing",
                        None,
                        "123456",
                        key_id="01",
                    ),
                    "initialization failed",
                ),
            ]

            message = b"civitasos-p4e-pkcs11-rotation:v1"
            old = Pkcs11Ed25519Signer(
                args.module,
                "civitas-p4e",
                "agent-signing",
                public_keys[b"\x01"],
                "123456",
                key_id="01",
            )
            try:
                old_signature = old.sign(message)
                VerifyKey(bytes.fromhex(old.public_key_hex)).verify(message, old_signature)
                old_reference = old.key_reference
                old.close()
                failures.append(
                    expect_civitas_error(
                        "retired_signer_rejected",
                        lambda: old.sign(message),
                        "closed",
                    )
                )
                if old.private_key_exportable:
                    raise RuntimeError("PKCS#11 signer reported an exportable private key")
            finally:
                old.close()

            replacement = Pkcs11Ed25519Signer(
                args.module,
                "civitas-p4e",
                "agent-signing",
                public_keys[b"\x02"],
                "123456",
                key_id="02",
            )
            try:
                replacement_signature = replacement.sign(message)
                VerifyKey(bytes.fromhex(replacement.public_key_hex)).verify(
                    message, replacement_signature
                )
                if public_keys[b"\x01"] == replacement.public_key_hex:
                    raise RuntimeError("rotation keys unexpectedly share one public key")
                post_retirement_signature = replacement.sign(message + b":post-retirement")
                VerifyKey(bytes.fromhex(replacement.public_key_hex)).verify(
                    message + b":post-retirement", post_retirement_signature
                )
                references = [old_reference, replacement.key_reference]
                if replacement.private_key_exportable:
                    raise RuntimeError("PKCS#11 signer reported an exportable private key")
            finally:
                replacement.close()

            report = {
                "schema_version": "civitasos-p4e-pkcs11-failure-matrix:v1",
                "passed": all(item["passed"] for item in failures),
                "module": args.module,
                "provider": "pkcs11",
                "mechanism": "CKM_EDDSA",
                "key_type": "CKK_EC_EDWARDS",
                "checks": failures,
                "check_count": len(failures) + 4,
                "key_references": references,
                "duplicate_label_requires_key_id": True,
                "old_and_replacement_signatures_verified": True,
                "replacement_signed_after_old_retirement": True,
                "private_key_exportable": False,
                "software_fallback_used": False,
                "physical_hsm_claimed": False,
                "production_authorized": False,
            }
            if args.output:
                write_private_report(args.output, report)
            print(json.dumps(report, indent=2, sort_keys=True))
            return 0 if report["passed"] else 1
        finally:
            if previous_config is None:
                os.environ.pop("SOFTHSM2_CONF", None)
            else:
                os.environ["SOFTHSM2_CONF"] = previous_config


if __name__ == "__main__":
    raise SystemExit(main())
