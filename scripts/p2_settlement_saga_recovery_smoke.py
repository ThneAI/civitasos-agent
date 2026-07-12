#!/usr/bin/env python3
"""Verify prepared settlement sagas recover without replaying started effects."""

from __future__ import annotations

import json
import os
import secrets
import subprocess
import tempfile
from pathlib import Path

from beta_runtime_identity_task_smoke import registered_agent, request, start_backend


def main() -> int:
    service_secret = secrets.token_urlsafe(32)
    jwt_secret = secrets.token_urlsafe(32)
    with tempfile.TemporaryDirectory(prefix="civitasos-settlement-saga-smoke-") as state_dir:
        base_env = os.environ | {
            "CIVITASOS_DATA_DIR": state_dir,
            "CIVITASOS_STORAGE_DATA_DIR": str(Path(state_dir) / "storage"),
            "CIVITASOS_JWT_SECRET": jwt_secret,
            "CIVITASOS_JWT_ENFORCE": "true",
            "CIVITASOS_AUTH_MODE": "production",
            "CIVITASOS_DEMO_LOGIN_ENABLED": "false",
            "CIVITASOS_INSTITUTIONAL_IDENTITY_ENABLED": "false",
            "CIVITASOS_SERVICE_TOKEN_SECRET": service_secret,
            "CIVITASOS_SERVICE_TOKEN_SCOPES": "agents:write,pool:post,pool:read,pool:claim,pool:write,audit:read",
            "CIVITASOS_TASK_CHALLENGE_WINDOW_ENABLED": "false",
            "CIVITASOS_A2A_SEED_TASKS": "false",
        }
        process = start_backend(
            base_env | {"CIVITASOS_TEST_SETTLEMENT_FAIL_AFTER_PHASE": "saga_started"}
        )
        try:
            requester = registered_agent("saga-requester", service_secret)
            worker = registered_agent("saga-worker", service_secret)
            posted = requester.pool_post("general", {"brief": "saga recovery"}, reward=1)
            task_id = str(posted["task_id"])
            worker.pool_claim(task_id)
            worker.pool_complete(task_id, output={"result": "prepared saga"})
            confirm_status, confirm_response = request(
                f"/api/v1/a2a/pool/confirm/{task_id}",
                {},
                requester._jwt_token,  # noqa: SLF001
            )
            if confirm_status != 200:
                raise RuntimeError(f"confirmation did not preserve task state: {confirm_response}")

            status_code, status_response = request(
                "/api/v1/a2a/facts/settlement-sagas",
                token=requester._jwt_token,  # noqa: SLF001
            )
            sagas = status_response.get("sagas") or []
            if (
                status_code != 200
                or status_response.get("blocked_count") != 1
                or len(sagas) != 1
                or sagas[0].get("phase") != "prepared"
            ):
                raise RuntimeError(f"prepared saga was not exposed: {status_response}")
            effect_status, effect_response = request(
                "/api/v1/a2a/facts/settlement-effects",
                token=requester._jwt_token,  # noqa: SLF001
            )
            if (
                effect_status != 200
                or effect_response.get("effect_count") != 9
                or effect_response.get("planned_count") != 9
            ):
                raise RuntimeError(f"settlement effect plan was not persisted: {effect_response}")

            process.terminate()
            process.wait(timeout=5)
            process = start_backend(base_env)
            settlement_request = {
                "task_id": task_id,
                "requester_agent": str(requester.agent_id),
                "worker_agent": str(worker.agent_id),
                "success": True,
                "reward_amount": 1,
                "result": {"result": "prepared saga"},
            }
            settle_status, settle_response = request(
                "/api/v1/a2a/task/settle",
                settlement_request,
                requester._jwt_token,  # noqa: SLF001
            )
            if settle_status != 200 or settle_response.get("settled") is not True:
                raise RuntimeError(f"safe prepared saga retry failed: {settle_response}")

            _, final_status = request(
                "/api/v1/a2a/facts/settlement-sagas",
                token=requester._jwt_token,  # noqa: SLF001
            )
            final_sagas = final_status.get("sagas") or []
            if (
                final_status.get("blocked_count") != 0
                or len(final_sagas) != 1
                or final_sagas[0].get("phase") != "completed"
                or final_sagas[0].get("replayable_response") is not True
            ):
                raise RuntimeError(f"completed saga status invalid: {final_status}")
            _, final_effects = request(
                "/api/v1/a2a/facts/settlement-effects",
                token=requester._jwt_token,  # noqa: SLF001
            )
            if final_effects.get("effect_count") != 9:
                raise RuntimeError(f"settlement effect plan did not survive restart: {final_effects}")
            effects_by_kind = {
                effect["effect_kind"]: effect for effect in final_effects.get("effects") or []
            }
            for effect_kind in ("gas_charge", "escrow_release", "reputation"):
                if effects_by_kind.get(effect_kind, {}).get("status") != "applied":
                    raise RuntimeError(
                        f"critical effect {effect_kind} was not applied: {final_effects}"
                    )
            if effects_by_kind.get("cold_start_bonus", {}).get("status") not in {
                "applied",
                "skipped",
            }:
                raise RuntimeError(f"cold-start effect is not terminal: {final_effects}")

            replay_status, replay = request(
                "/api/v1/a2a/task/settle",
                settlement_request,
                requester._jwt_token,  # noqa: SLF001
            )
            if replay_status != 200 or replay != settle_response:
                raise RuntimeError(f"settlement response was not replayed: {replay}")

            print(
                json.dumps(
                    {
                        "schema_version": "p2-settlement-saga-recovery-smoke:v1",
                        "passed": True,
                        "task_id": task_id,
                        "prepared_phase_recovered": True,
                        "completed_response_replayed": True,
                        "effect_plan_count": final_effects.get("effect_count"),
                        "effect_applied_count": final_effects.get("applied_count"),
                        "effect_skipped_count": final_effects.get("skipped_count"),
                        "blocked_after_recovery": 0,
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
