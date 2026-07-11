#!/usr/bin/env python3
"""Authenticate against a real backend through the non-exportable signer contract."""

from __future__ import annotations

import json
import os
import secrets
import subprocess
import tempfile
from pathlib import Path

from civitasos import CallbackSigner, CivitasAgent
from nacl.signing import SigningKey

from beta_runtime_identity_task_smoke import BASE_URL, request, start_backend


def main() -> int:
    service_secret = secrets.token_urlsafe(32)
    jwt_secret = secrets.token_urlsafe(32)
    with tempfile.TemporaryDirectory(prefix="civitasos-external-signer-smoke-") as state_dir:
        env = os.environ | {
            "CIVITASOS_DATA_DIR": state_dir,
            "CIVITASOS_STORAGE_DATA_DIR": str(Path(state_dir) / "storage"),
            "CIVITASOS_JWT_SECRET": jwt_secret,
            "CIVITASOS_JWT_ENFORCE": "true",
            "CIVITASOS_AUTH_MODE": "production",
            "CIVITASOS_DEMO_LOGIN_ENABLED": "false",
            "CIVITASOS_INSTITUTIONAL_IDENTITY_ENABLED": "false",
            "CIVITASOS_SERVICE_TOKEN_SECRET": service_secret,
            "CIVITASOS_SERVICE_TOKEN_SCOPES": "agents:write,pool:read",
            "CIVITASOS_A2A_SEED_TASKS": "false",
        }
        process = start_backend(env)
        try:
            device_key = SigningKey.generate()
            sign_count = 0

            def device_sign(message: bytes) -> bytes:
                nonlocal sign_count
                sign_count += 1
                return device_key.sign(message).signature

            agent = CivitasAgent(base_url=BASE_URL, auto_discover=False)
            signer = CallbackSigner(device_key.verify_key.encode().hex(), device_sign)
            public_key = agent.set_signer(signer)
            agent.authenticate_service_token(
                service_id="external-signer-bootstrap",
                secret=service_secret,
                scopes=["agents:write", "pool:read"],
            )
            agent.a2a_quickstart(
                alias="external-signer-agent",
                name="External Signer Agent",
                endpoint="",
                public_key=public_key,
            )
            agent.authenticate(allow_legacy_fallback=False)
            status, _ = request(
                "/api/v1/a2a/pool/tasks",
                token=agent._jwt_token,  # noqa: SLF001
            )
            if status != 200 or sign_count != 1 or agent._signing_key is not None:  # noqa: SLF001
                raise RuntimeError(
                    f"external signer contract failed: status={status}, signs={sign_count}, "
                    f"legacy_key_visible={agent._signing_key is not None}"  # noqa: SLF001
                )
            try:
                agent.save_identity(str(Path(state_dir) / "forbidden-identity.json"))
            except Exception as error:
                if "non-exportable" not in str(error):
                    raise
            else:
                raise RuntimeError("non-exportable signer was persisted as a seed")

            print(
                json.dumps(
                    {
                        "schema_version": "p2-external-signer-auth-smoke:v1",
                        "passed": True,
                        "challenge_sign_count": sign_count,
                        "legacy_seed_visible": False,
                        "identity_export_rejected": True,
                        "hardware_claimed": False,
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
