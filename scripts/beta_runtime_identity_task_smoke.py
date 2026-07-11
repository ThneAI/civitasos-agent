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


def wait_for_backend(process: subprocess.Popen) -> None:
    for _ in range(400):
        if process.poll() is not None:
            raise RuntimeError(f"backend exited during startup with code {process.returncode}")
        try:
            if request("/healthz")[0] == 200:
                return
        except OSError:
            pass
        time.sleep(0.05)
    raise RuntimeError("backend did not become healthy")


def start_backend(env: dict[str, str]) -> subprocess.Popen:
    process = subprocess.Popen(
        [str(BACKEND), "--api-port", "18099"],
        cwd=BACKEND.parents[2],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    wait_for_backend(process)
    return process


def restart_backend(process: subprocess.Popen, env: dict[str, str]) -> subprocess.Popen:
    process.terminate()
    process.wait(timeout=5)
    return start_backend(env)


def process_metrics(process: subprocess.Popen, state_dir: str) -> dict:
    status = Path(f"/proc/{process.pid}/status").read_text(errors="replace")
    rss_kib = 0
    for line in status.splitlines():
        if line.startswith("VmRSS:"):
            rss_kib = int(line.split()[1])
            break
    fd_count = len(list(Path(f"/proc/{process.pid}/fd").iterdir()))
    state_bytes = sum(path.stat().st_size for path in Path(state_dir).rglob("*") if path.is_file())
    return {"backend_rss_kib": rss_kib, "backend_fd_count": fd_count, "state_bytes": state_bytes}


def registered_agent(alias: str, service_secret: str) -> CivitasAgent:
    agent = CivitasAgent(base_url=BASE_URL, auto_discover=False)
    public_key = agent.generate_keys()
    agent.authenticate_service_token(
        service_id=f"smoke-{alias}",
        secret=service_secret,
        scopes=["agents:write", "pool:post", "pool:read", "pool:claim", "pool:write", "audit:read"],
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
    restart_point = os.environ.get("CIVITASOS_SOAK_RESTART_POINT", "posted")
    if restart_point not in {"posted", "claimed", "delivered"}:
        raise ValueError(f"unsupported restart point: {restart_point}")
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
            "CIVITASOS_SERVICE_TOKEN_SCOPES": "agents:write,pool:post,pool:read,pool:claim,pool:write,audit:read",
            "CIVITASOS_TASK_CHALLENGE_WINDOW_ENABLED": "true",
            "CIVITASOS_TASK_CHALLENGE_WINDOW_SECS": "2",
            "CIVITASOS_A2A_SEED_TASKS": "false",
        }
        process = start_backend(env)
        try:
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
            initial_receipt_hash = receipt.get("receipt_hash")
            audit_status, audit_response = request(
                "/api/v1/audit/events", token=requester._jwt_token  # noqa: SLF001
            )
            if audit_status != 200:
                raise RuntimeError(f"initial audit read failed: {audit_response}")
            initial_audit_count = len(audit_response.get("data") or [])

            if restart_point == "posted":
                process = restart_backend(process, env)
                restored_status, restored_response = request(
                    f"/api/v1/a2a/facts/tasks/{task_id}/receipt",
                    token=requester._jwt_token,  # noqa: SLF001
                )
                restored_receipt = restored_response.get("data", {})
                if restored_status != 200 or restored_receipt.get("receipt_hash") != initial_receipt_hash:
                    raise RuntimeError(f"receipt did not survive restart: {restored_response}")

            worker.pool_claim(task_id)
            if restart_point == "claimed":
                process = restart_backend(process, env)
                claimed = requester.pool_get_task(task_id)
                if claimed.get("status") != "Claimed":
                    raise RuntimeError(f"claimed task did not survive restart: {claimed}")
            retry_status, _ = request(
                "/api/v1/a2a/task/execute",
                {"task_id": task_id, "agent_id": str(worker.agent_id), "output": {}, "success": True},
                worker._jwt_token,  # noqa: SLF001
            )
            if retry_status != 400:
                raise RuntimeError(f"empty delivery did not fail closed: {retry_status}")
            delivery = worker.pool_complete(task_id, output={"result": "verified delivery"})
            if delivery.get("challenge_window_enabled") is not True:
                raise RuntimeError(f"challenge window was not enabled: {delivery}")
            if restart_point == "delivered":
                process = restart_backend(process, env)
                delivered = requester.pool_get_task(task_id)
                if delivered.get("status") != "Delivered":
                    raise RuntimeError(f"delivered task did not survive restart: {delivered}")
            early_confirm_status, _ = request(
                f"/api/v1/a2a/pool/confirm/{task_id}",
                {},
                token=requester._jwt_token,  # noqa: SLF001
            )
            if early_confirm_status != 409:
                raise RuntimeError(f"challenge window did not block early confirmation: {early_confirm_status}")
            time.sleep(2.1)
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
            operation_ids = [fact.get("operation_id") for fact in final_receipt.get("facts", [])]
            if (
                final_receipt.get("complete") is not True
                or final_receipt.get("consistency_status") != "complete"
                or final_receipt.get("missing_event_types") != []
                or any(not operation_id for operation_id in operation_ids)
                or len(set(operation_ids)) != len(operation_ids)
            ):
                raise RuntimeError(f"task receipt consistency contract failed: {final_receipt}")
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
            integrity_status, integrity_response = request(
                "/api/v1/a2a/facts/integrity",
                token=requester._jwt_token,  # noqa: SLF001
            )
            integrity = integrity_response.get("data", {})
            if (
                integrity_status != 200
                or integrity.get("valid") is not True
                or integrity.get("pending_outbox_count") != 0
            ):
                raise RuntimeError(f"fact integrity contract failed: {integrity_response}")

            worker_token = worker._jwt_token  # noqa: SLF001
            operator = CivitasAgent(base_url=BASE_URL, auto_discover=False)
            operator.authenticate_service_token(
                service_id="smoke-emergency-operator",
                secret=service_secret,
                scopes=["agents:write"],
            )
            emergency_status, emergency_response = request(
                "/api/v1/auth/credential/emergency-revoke",
                {"agent_id": str(worker.agent_id), "reason": "fresh-state emergency revocation drill"},
                operator._jwt_token,  # noqa: SLF001
            )
            emergency_data = emergency_response.get("data", {})
            if emergency_status != 200 or not emergency_data.get("fact_id"):
                raise RuntimeError(f"emergency revocation failed: {emergency_response}")
            worker_token_status, _ = request("/api/v1/a2a/pool/tasks", token=worker_token)
            if worker_token_status != 401:
                raise RuntimeError(f"worker token remained valid after emergency revocation: {worker_token_status}")
            final_audit_status, final_audit_response = request(
                "/api/v1/audit/events", token=requester._jwt_token  # noqa: SLF001
            )
            final_audit_count = len(final_audit_response.get("data") or [])
            if final_audit_status != 200 or final_audit_count < initial_audit_count:
                raise RuntimeError(f"audit continuity failed: {final_audit_response}")

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

            metrics = process_metrics(process, state_dir)
            print(json.dumps({
                "schema_version": "beta-runtime-identity-task-smoke:v1",
                "passed": True,
                "task_id": task_id,
                "task_status": completed.get("status"),
                "initial_receipt_fact_count": receipt.get("fact_count"),
                "initial_receipt_hash_present": len(str(receipt.get("receipt_hash") or "")) == 64,
                "restart_recovery": True,
                "restart_point": restart_point,
                "failed_delivery_retry": True,
                "challenge_window": True,
                "audit_continuity": True,
                "final_receipt_events": event_types,
                "final_receipt_status": lifecycle.get("status"),
                "final_receipt_settled": lifecycle.get("settled"),
                "final_receipt_hash": final_receipt.get("receipt_hash"),
                "receipt_consistency_status": final_receipt.get("consistency_status"),
                "idempotent_operation_ids": True,
                "evidence_id": evidence.get("evidence_id"),
                "evidence_export_mode": evidence.get("export_mode"),
                "fact_chain_valid": integrity.get("valid"),
                "pending_outbox_count": integrity.get("pending_outbox_count"),
                "emergency_revocation": True,
                "emergency_revocation_fact_id": emergency_data.get("fact_id"),
                "did_challenge_auth": True,
                "old_token_invalidated_after_rotation": True,
                "new_key_authentication": True,
                "token_invalidated_after_revocation": True,
                "fresh_state": True,
                "model_invoked": False,
                "production_claimed": False,
                **metrics,
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
