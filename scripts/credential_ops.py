#!/usr/bin/env python3
"""Operate CivitasOS online credentials without placing secrets in CLI arguments."""

from __future__ import annotations

import argparse
import json
import os
import tempfile
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from nacl.signing import SigningKey


def _token(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise ValueError(f"required token environment variable is empty: {name}")
    return value


def _base_url(value: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("base URL must be an absolute HTTP(S) URL")
    if parsed.scheme != "https" and parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("non-local credential operations require HTTPS")
    return value.rstrip("/")


def _request(base_url: str, path: str, body: dict, token: str | None = None) -> dict:
    request = Request(
        f"{_base_url(base_url)}{path}",
        data=json.dumps(body).encode(),
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    try:
        with urlopen(request, timeout=15) as response:
            payload = json.loads(response.read())
    except HTTPError as error:
        payload = json.loads(error.read() or b"{}")
        raise RuntimeError(f"credential API returned HTTP {error.code}: {payload}") from error
    if payload.get("success") is not True:
        raise RuntimeError(f"credential API rejected operation: {payload}")
    return payload.get("data") or {}


def _load_identity(path: Path) -> tuple[SigningKey, str]:
    data = json.loads(path.read_text())
    seed = bytes.fromhex(data.get("seed_hex", ""))
    if len(seed) != 32:
        raise ValueError("identity seed must be 32 bytes")
    key = SigningKey(seed)
    if data.get("public_key_hex") not in (None, key.verify_key.encode().hex()):
        raise ValueError("identity public key does not match seed")
    agent_id = str(data.get("agent_id") or "").strip()
    if not agent_id:
        raise ValueError("identity agent_id is required for online credential operations")
    return key, agent_id


def _write_staged_identity(path: Path, key: SigningKey, agent_id: str) -> None:
    if path.exists():
        raise FileExistsError(f"refusing to overwrite staged identity: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as handle:
            json.dump(
                {
                    "seed_hex": bytes(key).hex(),
                    "public_key_hex": key.verify_key.encode().hex(),
                    "agent_id": agent_id,
                },
                handle,
                indent=2,
            )
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


def _challenge(base_url: str, agent_id: str) -> tuple[str, str, bytes]:
    data = _request(base_url, "/api/v1/auth/challenge", {"agent_id": agent_id})
    message_hex = str(data.get("message") or "")
    try:
        message = bytes.fromhex(message_hex)
    except ValueError as error:
        raise RuntimeError("backend returned a non-hex challenge") from error
    if not data.get("challenge_id") or not message:
        raise RuntimeError("backend returned an incomplete challenge")
    return str(data["challenge_id"]), message_hex, message


def rotate(base_url: str, identity_path: Path, staged_path: Path, token_env: str) -> dict:
    current_key, agent_id = _load_identity(identity_path)
    new_key = SigningKey.generate()
    _write_staged_identity(staged_path, new_key, agent_id)
    challenge_id, message_hex, message = _challenge(base_url, agent_id)
    data = _request(
        base_url,
        "/api/v1/auth/credential/rotate",
        {
            "challenge_id": challenge_id,
            "message": message_hex,
            "current_signature": current_key.sign(message).signature.hex(),
            "new_public_key": new_key.verify_key.encode().hex(),
            "new_signature": new_key.sign(message).signature.hex(),
        },
        _token(token_env),
    )
    if data.get("rotated") is not True or not data.get("fact_id"):
        raise RuntimeError(f"rotation response lacks completion evidence: {data}")
    return {**data, "staged_identity": str(staged_path), "active_identity_replaced": False}


def revoke(base_url: str, identity_path: Path, token_env: str) -> dict:
    key, agent_id = _load_identity(identity_path)
    challenge_id, message_hex, message = _challenge(base_url, agent_id)
    data = _request(
        base_url,
        "/api/v1/auth/credential/revoke",
        {
            "challenge_id": challenge_id,
            "message": message_hex,
            "current_signature": key.sign(message).signature.hex(),
        },
        _token(token_env),
    )
    if data.get("revoked") is not True or not data.get("fact_id"):
        raise RuntimeError(f"revocation response lacks completion evidence: {data}")
    return data


def emergency_revoke(base_url: str, agent_id: str, reason: str, token_env: str) -> dict:
    if len(reason.strip()) < 8:
        raise ValueError("emergency revocation reason must contain at least 8 characters")
    data = _request(
        base_url,
        "/api/v1/auth/credential/emergency-revoke",
        {"agent_id": agent_id, "reason": reason},
        _token(token_env),
    )
    if data.get("emergency_revoked") is not True or not data.get("fact_id"):
        raise RuntimeError(f"emergency revocation response lacks completion evidence: {data}")
    return data


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default=os.environ.get("CIVITASOS_BASE_URL", "http://127.0.0.1:8080"))
    commands = parser.add_subparsers(dest="command", required=True)
    rotation = commands.add_parser("rotate")
    rotation.add_argument("--identity", type=Path, required=True)
    rotation.add_argument("--staged-identity", type=Path, required=True)
    rotation.add_argument("--token-env", default="CIVITASOS_AGENT_TOKEN")
    revocation = commands.add_parser("revoke")
    revocation.add_argument("--identity", type=Path, required=True)
    revocation.add_argument("--token-env", default="CIVITASOS_AGENT_TOKEN")
    emergency = commands.add_parser("emergency-revoke")
    emergency.add_argument("--agent-id", required=True)
    emergency.add_argument("--reason", required=True)
    emergency.add_argument("--token-env", default="CIVITASOS_OPERATOR_TOKEN")
    args = parser.parse_args()
    if args.command == "rotate":
        result = rotate(args.base_url, args.identity, args.staged_identity, args.token_env)
    elif args.command == "revoke":
        result = revoke(args.base_url, args.identity, args.token_env)
    else:
        result = emergency_revoke(args.base_url, args.agent_id, args.reason, args.token_env)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
