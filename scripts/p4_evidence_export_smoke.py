#!/usr/bin/env python3
"""Exercise durable backend Evidence export through operator Ledger import."""

from __future__ import annotations

import json
import os
import secrets
import subprocess
import tempfile
import time
from pathlib import Path

from civitasos import CivitasAgent

from beta_runtime_identity_task_smoke import (
    BASE_URL,
    registered_agent,
    request,
    restart_backend,
    start_backend,
)


ROOT = Path(__file__).resolve().parents[2]
AGENT = ROOT / "civitasos-agent"
LEDGER = ROOT / "civitasos-evidence-ledger"
LEDGER_CLI = LEDGER / ".venv" / "bin" / "civitasos-evidence-ledger"


def run(command: list[str]) -> None:
    subprocess.run(command, check=True, text=True, capture_output=True)


def main() -> int:
    service_secret = secrets.token_urlsafe(32)
    jwt_secret = secrets.token_urlsafe(32)
    with tempfile.TemporaryDirectory(prefix="civitasos-p4-evidence-") as temporary:
        root = Path(temporary)
        state = root / "backend"
        ledger_run = root / "ledger-run"
        staging = root / "staging"
        token_file = root / "evidence-operator.jwt"
        bridge_report = root / "bridge-report.json"
        env = os.environ | {
            "CIVITASOS_DATA_DIR": str(state),
            "CIVITASOS_STORAGE_DATA_DIR": str(state / "storage"),
            "CIVITASOS_JWT_SECRET": jwt_secret,
            "CIVITASOS_JWT_ENFORCE": "true",
            "CIVITASOS_AUTH_MODE": "private_beta",
            "CIVITASOS_DEMO_LOGIN_ENABLED": "false",
            "CIVITASOS_INSTITUTIONAL_IDENTITY_ENABLED": "false",
            "CIVITASOS_SERVICE_TOKEN_SECRET": service_secret,
            "CIVITASOS_SERVICE_TOKEN_SCOPES": (
                "agents:write,pool:post,pool:read,pool:claim,pool:write,"
                "audit:read,evidence:read,evidence:write"
            ),
            "CIVITASOS_TASK_CHALLENGE_WINDOW_ENABLED": "false",
            "CIVITASOS_A2A_SEED_TASKS": "false",
            "CIVITASOS_EVIDENCE_EXPORT_LAG_THRESHOLD_SECS": "1",
        }
        process = start_backend(env)
        try:
            requester = registered_agent("p4-evidence-requester", service_secret)
            worker = registered_agent("p4-evidence-worker", service_secret)
            posted = requester.pool_post(
                "general", {"brief": "P4 durable evidence export smoke"}, reward=1
            )
            task_id = str(posted.get("task_id") or posted.get("id"))
            worker.pool_claim(task_id)
            worker.pool_complete(task_id, output={"result": "evidence export ready"})
            requester.pool_confirm(task_id)

            operator = CivitasAgent(base_url=BASE_URL, auto_discover=False)
            operator.authenticate_service_token(
                service_id="p4-evidence-operator",
                secret=service_secret,
                scopes=["evidence:read", "evidence:write"],
            )
            token_file.write_text(operator._jwt_token + "\n")  # noqa: SLF001
            os.chmod(token_file, 0o600)

            status, pending_response = request(
                "/api/v1/a2a/operator/evidence-exports?pending_only=true",
                token=operator._jwt_token,  # noqa: SLF001
            )
            pending = pending_response.get("data", {}).get("records", [])
            if status != 200 or len(pending) != 1 or pending[0].get("task_id") != task_id:
                raise RuntimeError(f"durable evidence export was not queued: {pending_response}")
            time.sleep(1.05)
            health_status, pending_health_response = request(
                "/api/v1/a2a/operator/evidence-exports/health",
                token=operator._jwt_token,  # noqa: SLF001
            )
            pending_health = pending_health_response.get("data", {})
            if (
                health_status != 200
                or pending_health.get("pending_count") != 1
                or pending_health.get("lagging_count") != 1
                or pending_health.get("healthy") is not False
            ):
                raise RuntimeError(f"evidence outbox health missed pending export: {pending_health_response}")

            run([
                str(LEDGER_CLI), "init-run",
                "--run-root", str(ledger_run),
                "--goal-id", "p4-evidence-export-smoke",
            ])
            run([
                str(LEDGER_CLI), "register-actor",
                "--run-root", str(ledger_run),
                "--actor-id", "evidence-operator-1",
                "--actor-role", "evidence_operator",
                "--display-name", "Evidence Operator",
            ])
            bridge_command = [
                str(AGENT / ".venv" / "bin" / "python"),
                str(AGENT / "scripts" / "p4_evidence_export_bridge.py"),
                "--backend-url", BASE_URL,
                "--service-token-file", str(token_file),
                "--ledger-run-root", str(ledger_run),
                "--actor-id", "evidence-operator-1",
                "--staging-root", str(staging),
                "--output", str(bridge_report),
            ]
            run(bridge_command)
            first_bridge = json.loads(bridge_report.read_text())
            if first_bridge.get("processed_count") != 1 or first_bridge.get("passed") is not True:
                raise RuntimeError(f"evidence bridge failed: {first_bridge}")

            process = restart_backend(process, env)
            operator.authenticate_service_token(
                service_id="p4-evidence-operator-restart",
                secret=service_secret,
                scopes=["evidence:read", "evidence:write"],
            )
            token_file.write_text(operator._jwt_token + "\n")  # noqa: SLF001
            os.chmod(token_file, 0o600)
            status, restored_response = request(
                "/api/v1/a2a/operator/evidence-exports",
                token=operator._jwt_token,  # noqa: SLF001
            )
            restored = restored_response.get("data", {}).get("records", [])
            if status != 200 or len(restored) != 1 or restored[0].get("status") != "acknowledged":
                raise RuntimeError(f"evidence acknowledgement did not survive restart: {restored_response}")
            health_status, acknowledged_health_response = request(
                "/api/v1/a2a/operator/evidence-exports/health",
                token=operator._jwt_token,  # noqa: SLF001
            )
            acknowledged_health = acknowledged_health_response.get("data", {})
            if health_status != 200 or acknowledged_health.get("pending_count") != 0:
                raise RuntimeError(
                    f"evidence outbox health retained acknowledged export as pending: {acknowledged_health_response}"
                )

            run(bridge_command)
            repeated_bridge = json.loads(bridge_report.read_text())
            if repeated_bridge.get("processed_count") != 0:
                raise RuntimeError(f"repeated bridge was not idempotent: {repeated_bridge}")
            run([str(LEDGER_CLI), "verify-ledger", "--run-root", str(ledger_run)])

            report = {
                "schema_version": "civitasos-p4-evidence-export-smoke:v1",
                "passed": True,
                "task_id": task_id,
                "pending_exports_before_import": 1,
                "processed_exports": 1,
                "acknowledgement_survived_restart": True,
                "repeat_processed_exports": 0,
                "ledger_event_count": 1,
                "outbox_health_pending_before_import": 1,
                "outbox_health_pending_after_acknowledgement": 0,
                "outbox_lag_alert_observed": True,
                "automatic_ledger_append": False,
                "externally_verified": False,
                "production_evidence": False,
            }
            print(json.dumps(report, indent=2, sort_keys=True))
            return 0
        finally:
            process.terminate()
            process.wait(timeout=5)


if __name__ == "__main__":
    raise SystemExit(main())
