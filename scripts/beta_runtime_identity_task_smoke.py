#!/usr/bin/env python3
"""Fresh-state HTTP smoke for DID auth, task review, rotation, and revocation."""

from __future__ import annotations

import json
import os
import secrets
import subprocess
import tempfile
import time
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from civitasos import CivitasAgent
from nacl.signing import SigningKey

ROOT = Path(__file__).resolve().parents[2]
BACKEND = ROOT / "civitasos-backend" / "target" / "debug" / "api_only"
BASE_URL = "http://127.0.0.1:18099"


def parse_response(raw: bytes) -> dict:
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {"text": raw.decode("utf-8", errors="replace")}


def request(path: str, body: dict | None = None, token: str | None = None) -> tuple[int, dict]:
    data = json.dumps(body).encode() if body is not None else None
    req = Request(f"{BASE_URL}{path}", data=data, method="POST" if body is not None else "GET")
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urlopen(req, timeout=10) as response:
            return response.status, parse_response(response.read())
    except HTTPError as error:
        return error.code, parse_response(error.read() or b"{}")


def wait_for_backend() -> None:
    for _ in range(100):
        try:
            if request("/healthz")[0] == 200:
                return
        except OSError:
            pass
        time.sleep(0.05)
    raise RuntimeError("backend did not become healthy")


def registered_agent(alias: str, service_secret: str) -> CivitasAgent:
    agent = CivitasAgent(base_url=BASE_URL, auto_discover=False)
    public_key = agent.generate_keys()
    agent.authenticate_service_token(
        service_id=f"smoke-{alias}",
        secret=service_secret,
        scopes=["agents:write", "pool:post", "pool:read", "pool:claim", "pool:write"],
    )
    agent.a2a_quickstart(alias=alias, name=alias, endpoint="", public_key=public_key)
    agent.authenticate(allow_legacy_fallback=False)
    return agent


def challenge(agent_id: str) -> dict:
    status, response = request("/api/v1/auth/challenge", {"agent_id": agent_id})
    if status != 200:
        raise RuntimeError(response)
    return response["data"]


def main() -> int:
    service_secret = secrets.token_urlsafe(32)
    jwt_secret = secrets.token_urlsafe(32)
    with tempfile.TemporaryDirectory(prefix="civitasos-identity-task-smoke-") as state_dir:
        env = os.environ | {
            "CIVITASOS_DATA_DIR": state_dir,
            "CIVITASOS_STORAGE_DATA_DIR": str(Path(state_dir) / "storage"),
            "CIVITASOS_JWT_SECRET": jwt_secret,
            "CIVITASOS_JWT_ENFORCE": "true",
            "CIVITASOS_AUTH_MODE": "production",
            "CIVITASOS_DEMO_LOGIN_ENABLED": "false",
            "CIVITASOS_INSTITUTIONAL_IDENTITY_ENABLED": "false",
            "CIVITASOS_SERVICE_TOKEN_SECRET": service_secret,
            "CIVITASOS_SERVICE_TOKEN_SCOPES": "agents:write,pool:post,pool:read,pool:claim,pool:write",
            "CIVITASOS_TASK_CHALLENGE_WINDOW_ENABLED": "false",
            "CIVITASOS_A2A_SEED_TASKS": "false",
        }
        process = subprocess.Popen(
            [str(BACKEND), "--api-port", "18099"],
            cwd=BACKEND.parents[2],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            wait_for_backend()
            requester = registered_agent("smoke-requester", service_secret)
            worker = registered_agent("smoke-worker", service_secret)

            posted = requester.pool_post("general", {"brief": "fresh-state identity task smoke"}, reward=1)
            task_id = str(posted.get("task_id") or posted.get("id"))
            receipt_status, receipt_response = request(
                f"/api/v1/a2a/facts/tasks/{task_id}/receipt",
                token=requester._jwt_token,  # noqa: SLF001
            )
            receipt = receipt_response.get("data", {})
            if receipt_status != 200 or receipt.get("fact_count") != 1:
                raise RuntimeError(f"task receipt projection failed: {receipt_response}")
            worker.pool_claim(task_id)
            worker.pool_complete(task_id, output={"result": "verified delivery"})
            requester.pool_confirm(task_id)
            completed = requester.pool_get_task(task_id)
            if completed.get("status") != "Completed":
                raise RuntimeError(f"task did not complete: {completed}")
            final_receipt_status, final_receipt_response = request(
                f"/api/v1/a2a/facts/tasks/{task_id}/receipt",
                token=requester._jwt_token,  # noqa: SLF001
            )
            final_receipt = final_receipt_response.get("data", {})
            event_types = [fact.get("event_type") for fact in final_receipt.get("facts", [])]
            expected_events = [
                "task.posted",
                "task.claimed",
                "task.delivered",
                "task.confirmed",
                "settlement.completed",
            ]
            if final_receipt_status != 200 or event_types != expected_events:
                raise RuntimeError(f"task lifecycle receipt incomplete: {final_receipt_response}")
            lifecycle = final_receipt.get("lifecycle", {})
            if lifecycle.get("status") != "completed" or lifecycle.get("settled") is not True:
                raise RuntimeError(f"task lifecycle projection incomplete: {lifecycle}")
            evidence_status, evidence_response = request(
                f"/api/v1/a2a/facts/tasks/{task_id}/evidence",
                token=requester._jwt_token,  # noqa: SLF001
            )
            evidence = evidence_response.get("data", {})
            if (
                evidence_status != 200
                or evidence.get("receipt_hash") != final_receipt.get("receipt_hash")
                or len(evidence.get("fact_refs", [])) != len(expected_events)
                or evidence.get("export_mode") != "operator_controlled_append"
            ):
                raise RuntimeError(f"task evidence projection incomplete: {evidence_response}")

            old_token = requester._jwt_token  # noqa: SLF001 - smoke verifies token invalidation.
            old_signing_key = requester._signing_key  # noqa: SLF001
            new_signing_key = SigningKey.generate()
            rotation = challenge(str(requester.agent_id))
            message = bytes.fromhex(rotation["message"])
            status, rotation_result = request(
                "/api/v1/auth/credential/rotate",
                {
                    "challenge_id": rotation["challenge_id"],
                    "message": rotation["message"],
                    "current_signature": old_signing_key.sign(message).signature.hex(),
                    "new_public_key": new_signing_key.verify_key.encode().hex(),
                    "new_signature": new_signing_key.sign(message).signature.hex(),
                },
                old_token,
            )
            if status != 200 or rotation_result.get("data", {}).get("rotated") is not True:
                raise RuntimeError(rotation_result)
            if not rotation_result.get("data", {}).get("fact_id"):
                raise RuntimeError(f"rotation fact missing: {rotation_result}")
            old_token_status, _ = request("/api/v1/a2a/pool/tasks", token=old_token)
            if old_token_status != 401:
                raise RuntimeError(f"old token remained valid after rotation: {old_token_status}")

            requester.load_keys(bytes(new_signing_key).hex())
            requester.authenticate(allow_legacy_fallback=False)
            new_token = requester._jwt_token  # noqa: SLF001
            revocation = challenge(str(requester.agent_id))
            revoke_message = bytes.fromhex(revocation["message"])
            status, revoke_result = request(
                "/api/v1/auth/credential/revoke",
                {
                    "challenge_id": revocation["challenge_id"],
                    "message": revocation["message"],
                    "current_signature": new_signing_key.sign(revoke_message).signature.hex(),
                },
                new_token,
            )
            if status != 200 or revoke_result.get("data", {}).get("revoked") is not True:
                raise RuntimeError(revoke_result)
            if not revoke_result.get("data", {}).get("fact_id"):
                raise RuntimeError(f"revocation fact missing: {revoke_result}")
            revoked_token_status, _ = request("/api/v1/a2a/pool/tasks", token=new_token)
            if revoked_token_status != 401:
                raise RuntimeError(f"token remained valid after revocation: {revoked_token_status}")

            print(json.dumps({
                "schema_version": "beta-runtime-identity-task-smoke:v1",
                "passed": True,
                "task_id": task_id,
                "task_status": completed.get("status"),
                "initial_receipt_fact_count": receipt.get("fact_count"),
                "initial_receipt_hash_present": len(str(receipt.get("receipt_hash") or "")) == 64,
                "final_receipt_events": event_types,
                "final_receipt_status": lifecycle.get("status"),
                "final_receipt_settled": lifecycle.get("settled"),
                "evidence_id": evidence.get("evidence_id"),
                "evidence_export_mode": evidence.get("export_mode"),
                "did_challenge_auth": True,
                "old_token_invalidated_after_rotation": True,
                "new_key_authentication": True,
                "token_invalidated_after_revocation": True,
                "fresh_state": True,
                "model_invoked": False,
                "production_claimed": False,
            }, indent=2))
            return 0
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()


if __name__ == "__main__":
    raise SystemExit(main())
