#!/usr/bin/env python3
"""Probe a PKCS#11 Ed25519 identity without exporting private key material."""

from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import os
import secrets
import stat
from pathlib import Path

from civitasos import Pkcs11Ed25519Signer
from nacl.signing import VerifyKey


DEFAULT_MODULE = os.environ.get(
    "CIVITASOS_PKCS11_MODULE", "/usr/lib/softhsm/libsofthsm2.so"
)


def read_pin(pin_file: Path | None) -> str:
    if pin_file is None:
        return getpass.getpass("PKCS#11 user PIN: ")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    descriptor = os.open(pin_file, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"PIN path must be a regular file: {pin_file}")
        if metadata.st_uid != os.geteuid():
            raise ValueError(f"PIN file must be owned by the current service user: {pin_file}")
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            raise ValueError(f"PIN file must not grant group/other access: {pin_file}")
        encoded_pin = os.read(descriptor, 4097)
        if len(encoded_pin) > 4096:
            raise ValueError("PIN file is unexpectedly large")
        pin = encoded_pin.decode("utf-8").strip()
    finally:
        os.close(descriptor)
    if not pin:
        raise ValueError("PIN file is empty")
    return pin


def write_report(path: Path, report: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--module", default=DEFAULT_MODULE)
    parser.add_argument("--token-label", required=True)
    parser.add_argument("--key-label", required=True)
    parser.add_argument("--key-id", required=True, help="CKA_ID as hex")
    parser.add_argument("--expected-public-key", help="expected raw Ed25519 public key hex")
    parser.add_argument("--pin-file", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    pin = read_pin(args.pin_file)
    try:
        with Pkcs11Ed25519Signer(
            args.module,
            args.token_label,
            args.key_label,
            args.expected_public_key,
            pin,
            key_id=args.key_id,
        ) as signer:
            challenge = secrets.token_bytes(32)
            signature = signer.sign(challenge)
            VerifyKey(bytes.fromhex(signer.public_key_hex)).verify(challenge, signature)
            report = {
                "schema_version": "civitasos-pkcs11-identity-probe:v1",
                "passed": True,
                "token_label": args.token_label,
                "key_label": args.key_label,
                "key_id": args.key_id.lower() if args.key_id else None,
                "key_reference": signer.key_reference,
                "public_key_hex": signer.public_key_hex,
                "public_key_sha256": hashlib.sha256(
                    bytes.fromhex(signer.public_key_hex)
                ).hexdigest(),
                "signature_verified": True,
                "seed_exported": False,
                "private_key_exportable": signer.private_key_exportable,
                "physical_hsm_claimed": False,
                "production_authorized": False,
            }
    finally:
        pin = ""

    if args.output is not None:
        write_report(args.output, report)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
