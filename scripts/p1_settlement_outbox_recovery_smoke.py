#!/usr/bin/env python3
"""Verify durable settlement marker recovers a deferred settlement Fact."""

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
    with tempfile.TemporaryDirectory(prefix="civitasos-settlement-outbox-smoke-") as state_dir:
        base_env = os.environ | {
            "CIVITASOS_DATA_DIR": state_dir,
            "CIVITASOS_STORAGE_DATA_DIR": str(Path(state_dir) / "storage"),
            "CIVITASOS_JWT_SECRET": jwt_secret,
            "CIVITASOS_JWT_ENFORCE": "true",
            "CIVITASOS_AUTH_MODE": "private_beta",
            "CIVITASOS_DEMO_LOGIN_ENABLED": "false",
            "CIVITASOS_INSTITUTIONAL_IDENTITY_ENABLED": "false",
            "CIVITASOS_SERVICE_TOKEN_SECRET": service_secret,
            "CIVITASOS_SERVICE_TOKEN_SCOPES": "agents:write,pool:post,pool:read,pool:claim,pool:write,audit:read",
            "CIVITASOS_TASK_CHALLENGE_WINDOW_ENABLED": "false",
            "CIVITASOS_A2A_SEED_TASKS": "false",
        }
        process = start_backend(base_env | {
            "CIVITASOS_TEST_FACT_COMMIT_FAIL_EVENT": "settlement.completed",
        })
        try:
            requester = registered_agent("settlement-requester", service_secret)
            worker = registered_agent("settlement-worker", service_secret)
            posted = requester.pool_post("general", {"brief": "settlement recovery"}, reward=1)
            task_id = str(posted["task_id"])
            worker.pool_claim(task_id)
            worker.pool_complete(task_id, output={"result": "durable settlement"})
            confirm_status, confirm_response = request(
                f"/api/v1/a2a/pool/confirm/{task_id}",
                {},
                requester._jwt_token,  # noqa: SLF001
            )
            if confirm_status != 500:
                raise RuntimeError(f"settlement failpoint did not trigger: {confirm_status} {confirm_response}")
            task = requester.pool_get_task(task_id)
            if task.get("status") != "Completed":
                raise RuntimeError(f"completed task state missing: {task}")
            _, before_response = request(
                "/api/v1/a2a/facts/integrity", token=requester._jwt_token  # noqa: SLF001
            )
            before = before_response.get("data", {})
            if before.get("pending_outbox_count") != 1:
                raise RuntimeError(f"settlement intent missing: {before_response}")

            process.terminate()
            process.wait(timeout=5)
            process = start_backend(base_env)
            receipt_status, receipt_response = request(
                f"/api/v1/a2a/facts/tasks/{task_id}/receipt",
                token=requester._jwt_token,  # noqa: SLF001
            )
            receipt = receipt_response.get("data", {})
            if receipt_status != 200 or receipt.get("complete") is not True:
                raise RuntimeError(f"settlement Fact did not recover: {receipt_response}")
            events = [fact.get("event_type") for fact in receipt.get("facts", [])]
            if events[-1:] != ["settlement.completed"]:
                raise RuntimeError(f"settlement Fact ordering invalid: {events}")

            settle_status, settle_response = request(
                "/api/v1/a2a/task/settle",
                {
                    "task_id": task_id,
                    "requester_agent": str(requester.agent_id),
                    "worker_agent": str(worker.agent_id),
                    "success": True,
                    "reward_amount": 1,
                    "result": {"result": "durable settlement"},
                },
                requester._jwt_token,  # noqa: SLF001
            )
            if settle_status != 200 or settle_response.get("settled") is not True:
                raise RuntimeError(f"settlement marker replay failed: {settle_response}")
            _, after_response = request(
                "/api/v1/a2a/facts/integrity", token=requester._jwt_token  # noqa: SLF001
            )
            after = after_response.get("data", {})
            if after.get("valid") is not True or after.get("pending_outbox_count") != 0:
                raise RuntimeError(f"settlement recovery integrity failed: {after_response}")

            print(json.dumps({
                "schema_version": "p1-settlement-outbox-recovery-smoke:v1",
                "passed": True,
                "task_id": task_id,
                "marker_replayed": True,
                "receipt_complete": receipt.get("complete"),
                "pending_before_restart": before.get("pending_outbox_count"),
                "pending_after_restart": after.get("pending_outbox_count"),
                "fact_chain_valid": after.get("valid"),
                "production_claimed": False,
            }, indent=2))
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
