#!/usr/bin/env python3
"""Verify an applied settlement effect is not replayed after interruption."""

from __future__ import annotations

import json
import os
import secrets
import subprocess
import tempfile
from pathlib import Path

from beta_runtime_identity_task_smoke import registered_agent, request, start_backend


def gas_effect(token: str, task_id: str) -> dict:
    status, response = request(
        "/api/v1/a2a/facts/settlement-effects",
        token=token,
    )
    if status != 200:
        raise RuntimeError(f"effect ledger unavailable: {response}")
    for effect in response.get("effects") or []:
        if effect.get("task_id") == task_id and effect.get("effect_kind") == "gas_charge":
            return effect
    raise RuntimeError(f"gas effect not found: {response}")


def main() -> int:
    service_secret = secrets.token_urlsafe(32)
    jwt_secret = secrets.token_urlsafe(32)
    with tempfile.TemporaryDirectory(prefix="civitasos-effect-uncertainty-") as state_dir:
        base_env = os.environ | {
            "CIVITASOS_DATA_DIR": state_dir,
            "CIVITASOS_STORAGE_DATA_DIR": str(Path(state_dir) / "storage"),
            "CIVITASOS_JWT_SECRET": jwt_secret,
            "CIVITASOS_JWT_ENFORCE": "true",
            "CIVITASOS_AUTH_MODE": "production",
            "CIVITASOS_DEMO_LOGIN_ENABLED": "false",
            "CIVITASOS_INSTITUTIONAL_IDENTITY_ENABLED": "false",
            "CIVITASOS_SERVICE_TOKEN_SECRET": service_secret,
            "CIVITASOS_SERVICE_TOKEN_SCOPES": (
                "agents:write,pool:post,pool:read,pool:claim,pool:write,audit:read"
            ),
            "CIVITASOS_TASK_CHALLENGE_WINDOW_ENABLED": "false",
            "CIVITASOS_A2A_SEED_TASKS": "false",
        }
        process = start_backend(
            base_env | {"CIVITASOS_TEST_SETTLEMENT_FAIL_AFTER_EFFECT": "gas_charge"}
        )
        try:
            requester = registered_agent("effect-requester", service_secret)
            worker = registered_agent("effect-worker", service_secret)
            posted = requester.pool_post("general", {"brief": "effect uncertainty"}, reward=1)
            task_id = str(posted["task_id"])
            worker.pool_claim(task_id)
            worker.pool_complete(task_id, output={"result": "effect interruption"})
            request(
                f"/api/v1/a2a/pool/confirm/{task_id}",
                {},
                requester._jwt_token,  # noqa: SLF001
            )

            before_restart = gas_effect(requester._jwt_token, task_id)  # noqa: SLF001
            if before_restart.get("status") != "applied" or before_restart.get("attempts") != 1:
                raise RuntimeError(f"gas effect was not durably applied: {before_restart}")
            saga_status, saga_response = request(
                "/api/v1/a2a/facts/settlement-sagas",
                token=requester._jwt_token,  # noqa: SLF001
            )
            sagas = saga_response.get("sagas") or []
            if (
                saga_status != 200
                or saga_response.get("blocked_count") != 1
                or len(sagas) != 1
                or sagas[0].get("phase") != "effects_started"
            ):
                raise RuntimeError(f"uncertain saga was not blocked: {saga_response}")

            process.terminate()
            process.wait(timeout=5)
            process = start_backend(base_env)
            settlement_request = {
                "task_id": task_id,
                "requester_agent": str(requester.agent_id),
                "worker_agent": str(worker.agent_id),
                "success": True,
                "reward_amount": 1,
                "result": {"result": "effect interruption"},
            }
            retry_status, retry_response = request(
                "/api/v1/a2a/task/settle",
                settlement_request,
                requester._jwt_token,  # noqa: SLF001
            )
            if retry_status == 200:
                raise RuntimeError(f"uncertain settlement replayed unexpectedly: {retry_response}")
            after_restart = gas_effect(requester._jwt_token, task_id)  # noqa: SLF001
            if after_restart.get("status") != "applied" or after_restart.get("attempts") != 1:
                raise RuntimeError(f"applied effect changed during blocked retry: {after_restart}")

            resolve_status, resolve_response = request(
                "/api/v1/a2a/operator/settlement-effects/resolve",
                {
                    "task_id": task_id,
                    "request_hash": after_restart["request_hash"],
                    "effect_kind": "gas_charge",
                    "expected_status": "applied",
                    "resolution_ref": "smoke://verified-gas-ledger-entry",
                },
                requester._jwt_token,  # noqa: SLF001
            )
            if resolve_status != 200 or resolve_response.get("retryable") is not True:
                raise RuntimeError(f"operator resolution failed: {resolve_response}")
            resumed_status, resumed_response = request(
                "/api/v1/a2a/task/settle",
                settlement_request,
                requester._jwt_token,  # noqa: SLF001
            )
            if resumed_status != 200 or resumed_response.get("settled") is not True:
                raise RuntimeError(f"resolved settlement did not resume: {resumed_response}")
            after_resolution = gas_effect(requester._jwt_token, task_id)  # noqa: SLF001
            if (
                after_resolution.get("status") != "applied"
                or after_resolution.get("attempts") != 1
                or after_resolution.get("resolution_ref")
                != "smoke://verified-gas-ledger-entry"
            ):
                raise RuntimeError(
                    f"resolved effect was replayed or lost its audit ref: {after_resolution}"
                )

            print(
                json.dumps(
                    {
                        "schema_version": "p3-settlement-effect-uncertainty-smoke:v1",
                        "passed": True,
                        "task_id": task_id,
                        "blocked_phase": "effects_started",
                        "effect_kind": "gas_charge",
                        "effect_status": after_restart.get("status"),
                        "effect_attempts": after_resolution.get("attempts"),
                        "retry_status": retry_status,
                        "resolved_retry_status": resumed_status,
                        "resolution_ref_persisted": True,
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
