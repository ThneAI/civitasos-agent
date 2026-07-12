#!/usr/bin/env python3
"""Exercise WebAuthn ES256 registration, assertion, and replay rejection."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import subprocess
import tempfile
from pathlib import Path

from beta_runtime_identity_task_smoke import registered_agent, request, start_backend


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def assertion(root: Path, challenge: dict, credential_id: str, sign_count: int) -> dict:
    client_data = json.dumps(
        {
            "type": "webauthn.get",
            "challenge": challenge["challenge"],
            "origin": challenge["origin"],
        },
        separators=(",", ":"),
    ).encode()
    authenticator_data = (
        hashlib.sha256(challenge["rp_id"].encode()).digest()
        + b"\x01"
        + sign_count.to_bytes(4, "big")
    )
    signed_data = authenticator_data + hashlib.sha256(client_data).digest()
    data_path = root / "assertion.bin"
    signature_path = root / "assertion.der"
    data_path.write_bytes(signed_data)
    subprocess.run(
        [
            "openssl",
            "dgst",
            "-sha256",
            "-sign",
            str(root / "authenticator.key"),
            "-out",
            str(signature_path),
            str(data_path),
        ],
        check=True,
        capture_output=True,
    )
    return {
        "credential_id": credential_id,
        "client_data_json": b64url(client_data),
        "authenticator_data": b64url(authenticator_data),
        "signature": b64url(signature_path.read_bytes()),
    }


def main() -> int:
    service_secret = secrets.token_urlsafe(32)
    with tempfile.TemporaryDirectory(prefix="civitasos-webauthn-") as temporary:
        root = Path(temporary)
        env = os.environ | {
            "CIVITASOS_DATA_DIR": str(root / "data"),
            "CIVITASOS_STORAGE_DATA_DIR": str(root / "storage"),
            "CIVITASOS_JWT_SECRET": secrets.token_urlsafe(32),
            "CIVITASOS_JWT_ENFORCE": "true",
            "CIVITASOS_AUTH_MODE": "production",
            "CIVITASOS_DEMO_LOGIN_ENABLED": "false",
            "CIVITASOS_INSTITUTIONAL_IDENTITY_ENABLED": "false",
            "CIVITASOS_SERVICE_TOKEN_SECRET": service_secret,
            "CIVITASOS_SERVICE_TOKEN_SCOPES": (
                "agents:write,pool:post,pool:read,pool:claim,pool:write,audit:read"
            ),
            "CIVITASOS_A2A_SEED_TASKS": "false",
        }
        subprocess.run(
            ["openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256",
             "-out", str(root / "authenticator.key")],
            check=True,
            capture_output=True,
        )
        public_der = subprocess.run(
            ["openssl", "pkey", "-in", str(root / "authenticator.key"), "-pubout", "-outform", "DER"],
            check=True,
            capture_output=True,
        ).stdout
        public_key = public_der[-65:]
        if len(public_key) != 65 or public_key[0] != 4:
            raise RuntimeError("unexpected P-256 SubjectPublicKeyInfo encoding")

        process = start_backend(env)
        try:
            operator = registered_agent("webauthn-operator", service_secret)
            credential_id = b64url(secrets.token_bytes(24))
            status, body = request(
                "/api/v1/auth/webauthn/register",
                {
                    "credential_id": credential_id,
                    "agent_id": str(operator.agent_id),
                    "rp_id": "localhost",
                    "origin": "https://localhost",
                    "public_key_sec1_hex": public_key.hex(),
                },
                operator._jwt_token,  # noqa: SLF001
            )
            if status != 200 or body.get("registered") is not True:
                raise RuntimeError(f"WebAuthn registration failed: {status} {body}")

            status, challenge = request(
                "/api/v1/auth/webauthn/challenge", {"credential_id": credential_id}
            )
            if status != 200:
                raise RuntimeError(f"WebAuthn challenge failed: {status} {challenge}")
            token_request = {
                "challenge_id": challenge["challenge_id"],
                "assertion": assertion(root, challenge, credential_id, 1),
            }
            status, token = request("/api/v1/auth/webauthn/token", token_request)
            if status != 200 or token.get("auth_method") != "webauthn_assertion":
                raise RuntimeError(f"WebAuthn token failed: {status} {token}")
            resource_status, _ = request(
                "/api/v1/a2a/pool/tasks", token=token["token"]
            )
            if resource_status != 200:
                raise RuntimeError("WebAuthn bearer token was rejected")
            replay_status, _ = request("/api/v1/auth/webauthn/token", token_request)
            if replay_status != 401:
                raise RuntimeError("consumed WebAuthn challenge was replayable")

            _, second_challenge = request(
                "/api/v1/auth/webauthn/challenge", {"credential_id": credential_id}
            )
            counter_replay_status, _ = request(
                "/api/v1/auth/webauthn/token",
                {
                    "challenge_id": second_challenge["challenge_id"],
                    "assertion": assertion(root, second_challenge, credential_id, 1),
                },
            )
            if counter_replay_status != 401:
                raise RuntimeError("WebAuthn sign counter replay was accepted")

            print(
                json.dumps(
                    {
                        "schema_version": "p3-webauthn-e2e-smoke:v1",
                        "passed": True,
                        "token_auth_method": "webauthn_assertion",
                        "resource_status": resource_status,
                        "challenge_replay_status": replay_status,
                        "counter_replay_status": counter_replay_status,
                        "production_claimed": False,
                    },
                    indent=2,
                )
            )
            return 0
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


if __name__ == "__main__":
    raise SystemExit(main())
