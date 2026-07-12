#!/usr/bin/env python3
"""Verify staged peer-key rotation and durable revocation."""

from __future__ import annotations

import json
import os
import secrets
import subprocess
import tempfile
from pathlib import Path

from beta_runtime_identity_task_smoke import registered_agent, request, start_backend
from nacl.signing import SigningKey


def stage(token: str, node_id: str, key: SigningKey) -> dict:
    public_key = key.verify_key.encode().hex()
    proof = f"civitasos-peer-key-stage:v1\0{node_id}\0{public_key}".encode()
    status, response = request(
        "/api/v1/operator/peer-keys/stage",
        {
            "node_id": node_id,
            "public_key_hex": public_key,
            "possession_signature": key.sign(proof).signature.hex(),
        },
        token,
    )
    if status != 200:
        raise RuntimeError(f"peer key stage failed: {status} {response}")
    return response["record"]


def main() -> int:
    service_secret = secrets.token_urlsafe(32)
    with tempfile.TemporaryDirectory(prefix="civitasos-peer-rotation-") as state_dir:
        env = os.environ | {
            "CIVITASOS_DATA_DIR": state_dir,
            "CIVITASOS_STORAGE_DATA_DIR": str(Path(state_dir) / "storage"),
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
        process = start_backend(env)
        try:
            operator = registered_agent("peer-key-operator", service_secret)
            token = operator._jwt_token  # noqa: SLF001
            node_id = "rotation-peer"
            old_key = SigningKey.generate()
            new_key = SigningKey.generate()
            old_record = stage(token, node_id, old_key)
            new_record = stage(token, node_id, new_key)
            proof = (
                f"civitasos-peer-key-revoke:v1\0{node_id}\0"
                f"{old_record['key_id']}\0{new_record['key_id']}"
            ).encode()
            status, response = request(
                "/api/v1/operator/peer-keys/revoke",
                {
                    "node_id": node_id,
                    "key_id": old_record["key_id"],
                    "authorizing_key_id": new_record["key_id"],
                    "authorization_signature": new_key.sign(proof).signature.hex(),
                },
                token,
            )
            if status != 200 or response["record"].get("status") != "revoked":
                raise RuntimeError(f"peer key revoke failed: {status} {response}")

            process.terminate()
            process.wait(timeout=5)
            process = start_backend(env)
            operator = registered_agent("peer-key-reader", service_secret)
            status, registry = request(
                "/api/v1/operator/peer-keys",
                token=operator._jwt_token,  # noqa: SLF001
            )
            records = {record["key_id"]: record for record in registry.get("keys") or []}
            if (
                status != 200
                or records.get(old_record["key_id"], {}).get("status") != "revoked"
                or records.get(new_record["key_id"], {}).get("status") != "active"
            ):
                raise RuntimeError(f"rotation state did not survive restart: {registry}")
            print(
                json.dumps(
                    {
                        "schema_version": "p3-peer-key-rotation-smoke:v1",
                        "passed": True,
                        "node_id": node_id,
                        "old_key_status": "revoked",
                        "new_key_status": "active",
                        "restart_recovered": True,
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
