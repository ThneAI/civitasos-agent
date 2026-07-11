#!/usr/bin/env python3
"""Operate legacy file-backed CivitasOS identities without exposing seed material."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import tempfile
from pathlib import Path

from nacl import pwhash, secret, utils
from nacl.signing import SigningKey

SCHEMA = "civitasos-identity-backup:v1"


def _passphrase(confirm: bool = False) -> bytes:
    value = os.environ.get("CIVITASOS_IDENTITY_PASSPHRASE")
    if value is None:
        value = getpass.getpass("Backup passphrase: ")
        if confirm and value != getpass.getpass("Confirm passphrase: "):
            raise ValueError("passphrases do not match")
    if len(value) < 12:
        raise ValueError("passphrase must contain at least 12 characters")
    return value.encode()


def _identity(path: Path) -> dict:
    data = json.loads(path.read_text())
    seed = bytes.fromhex(data.get("seed_hex", ""))
    if len(seed) != 32:
        raise ValueError("identity seed must be 32 bytes")
    public_key = SigningKey(seed).verify_key.encode().hex()
    if data.get("public_key_hex") not in (None, public_key):
        raise ValueError("identity public key does not match seed")
    return {"seed_hex": seed.hex(), "public_key_hex": public_key, "agent_id": data.get("agent_id")}


def _atomic_private_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as handle:
            json.dump(data, handle, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def create(path: Path, agent_id: str | None) -> dict:
    if path.exists():
        raise FileExistsError(f"refusing to overwrite identity: {path}")
    key = SigningKey.generate()
    identity = {
        "seed_hex": bytes(key).hex(),
        "public_key_hex": key.verify_key.encode().hex(),
        "agent_id": agent_id,
    }
    _atomic_private_json(path, identity)
    return {"created": True, "path": str(path), "public_key_hex": identity["public_key_hex"], "agent_id": agent_id}


def backup(identity_path: Path, output: Path) -> dict:
    identity = _identity(identity_path)
    salt = utils.random(pwhash.argon2id.SALTBYTES)
    key = pwhash.argon2id.kdf(
        secret.SecretBox.KEY_SIZE,
        _passphrase(confirm=True),
        salt,
        opslimit=pwhash.argon2id.OPSLIMIT_MODERATE,
        memlimit=pwhash.argon2id.MEMLIMIT_MODERATE,
    )
    nonce = utils.random(secret.SecretBox.NONCE_SIZE)
    ciphertext = secret.SecretBox(key).encrypt(json.dumps(identity).encode(), nonce).ciphertext
    envelope = {
        "schema_version": SCHEMA,
        "kdf": "argon2id-moderate",
        "cipher": "xsalsa20-poly1305",
        "salt_hex": salt.hex(),
        "nonce_hex": nonce.hex(),
        "ciphertext_hex": ciphertext.hex(),
        "public_key_hex": identity["public_key_hex"],
        "agent_id": identity["agent_id"],
    }
    _atomic_private_json(output, envelope)
    return {"backed_up": True, "path": str(output), "public_key_hex": identity["public_key_hex"], "agent_id": identity["agent_id"]}


def restore(backup_path: Path, output: Path) -> dict:
    if output.exists():
        raise FileExistsError(f"refusing to overwrite identity: {output}")
    envelope = json.loads(backup_path.read_text())
    if envelope.get("schema_version") != SCHEMA:
        raise ValueError("unsupported identity backup schema")
    salt = bytes.fromhex(envelope["salt_hex"])
    key = pwhash.argon2id.kdf(
        secret.SecretBox.KEY_SIZE,
        _passphrase(),
        salt,
        opslimit=pwhash.argon2id.OPSLIMIT_MODERATE,
        memlimit=pwhash.argon2id.MEMLIMIT_MODERATE,
    )
    plaintext = secret.SecretBox(key).decrypt(
        bytes.fromhex(envelope["ciphertext_hex"]),
        bytes.fromhex(envelope["nonce_hex"]),
    )
    identity = json.loads(plaintext)
    _atomic_private_json(output, identity)
    verified = _identity(output)
    return {"restored": True, "path": str(output), "public_key_hex": verified["public_key_hex"], "agent_id": verified["agent_id"]}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    create_parser = commands.add_parser("create")
    create_parser.add_argument("--identity", type=Path, required=True)
    create_parser.add_argument("--agent-id")
    backup_parser = commands.add_parser("backup")
    backup_parser.add_argument("--identity", type=Path, required=True)
    backup_parser.add_argument("--output", type=Path, required=True)
    restore_parser = commands.add_parser("restore")
    restore_parser.add_argument("--backup", type=Path, required=True)
    restore_parser.add_argument("--output", type=Path, required=True)
    inspect_parser = commands.add_parser("inspect")
    inspect_parser.add_argument("--identity", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "create":
        result = create(args.identity, args.agent_id)
    elif args.command == "backup":
        result = backup(args.identity, args.output)
    elif args.command == "restore":
        result = restore(args.backup, args.output)
    else:
        identity = _identity(args.identity)
        result = {"valid": True, "path": str(args.identity), "public_key_hex": identity["public_key_hex"], "agent_id": identity["agent_id"]}
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
