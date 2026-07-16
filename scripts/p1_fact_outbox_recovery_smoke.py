#!/usr/bin/env python3
"""Verify task state/outbox recovery when Fact commit fails after transition."""

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
    with tempfile.TemporaryDirectory(prefix="civitasos-fact-outbox-smoke-") as state_dir:
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
        failing_env = base_env | {
            "CIVITASOS_TEST_FACT_COMMIT_FAIL_EVENT": "task.claimed",
        }
        process = start_backend(failing_env)
        try:
            requester = registered_agent("outbox-requester", service_secret)
            worker = registered_agent("outbox-worker", service_secret)
            posted = requester.pool_post("general", {"brief": "outbox recovery"}, reward=1)
            task_id = str(posted["task_id"])

            claim_status, claim_response = request(
                "/api/v1/a2a/pool/claim",
                {"task_id": task_id, "agent_id": str(worker.agent_id), "stake_amount": 0},
                worker._jwt_token,  # noqa: SLF001
            )
            if claim_status != 500:
                raise RuntimeError(f"claim failpoint did not trigger: {claim_status} {claim_response}")
            task = requester.pool_get_task(task_id)
            if task.get("status") != "Claimed":
                raise RuntimeError(f"claim state was not persisted: {task}")
            integrity_status, integrity_response = request(
                "/api/v1/a2a/facts/integrity",
                token=requester._jwt_token,  # noqa: SLF001
            )
            before = integrity_response.get("data", {})
            if integrity_status != 200 or before.get("pending_outbox_count") != 1:
                raise RuntimeError(f"pending outbox not observable: {integrity_response}")

            process.terminate()
            process.wait(timeout=5)
            process = start_backend(base_env)

            receipt_status, receipt_response = request(
                f"/api/v1/a2a/facts/tasks/{task_id}/receipt",
                token=requester._jwt_token,  # noqa: SLF001
            )
            receipt = receipt_response.get("data", {})
            event_types = [fact.get("event_type") for fact in receipt.get("facts", [])]
            if receipt_status != 200 or event_types != ["task.posted", "task.claimed"]:
                raise RuntimeError(f"outbox was not reconciled: {receipt_response}")
            _, final_integrity_response = request(
                "/api/v1/a2a/facts/integrity",
                token=requester._jwt_token,  # noqa: SLF001
            )
            after = final_integrity_response.get("data", {})
            if after.get("valid") is not True or after.get("pending_outbox_count") != 0:
                raise RuntimeError(f"integrity did not recover: {final_integrity_response}")

            print(json.dumps({
                "schema_version": "p1-fact-outbox-recovery-smoke:v1",
                "passed": True,
                "task_id": task_id,
                "injected_event": "task.claimed",
                "state_persisted_before_restart": True,
                "pending_before_restart": before.get("pending_outbox_count"),
                "reconciled_events": event_types,
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
