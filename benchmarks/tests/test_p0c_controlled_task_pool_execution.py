from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from benchmarks.p0c_controlled_execution_authorization_gate import run_gate as run_p0c_authorization
from benchmarks.p0c_controlled_task_pool_execution import run_execution
from benchmarks.tests.test_p0c_controlled_execution_authorization_gate import _run_p0b, _write_service_env


class FakeClient:
    def __init__(self, *, auth_method: str = "service_token") -> None:
        self.auth_method = auth_method
        self.posts: list[tuple[str, dict[str, Any]]] = []
        self.tasks: dict[str, dict[str, Any]] = {}
        self.counter = 0

    def healthz(self) -> None:
        return None

    def auth_report(self) -> dict[str, Any]:
        return {
            "passed": True,
            "token": "<redacted>",
            "token_recorded": False,
            "schema_version": "civitasos-auth-context:v1",
            "auth_method": self.auth_method,
            "service_id": "p0c_controlled_task_pool_execution",
            "scopes": ["agents:read", "agents:write", "audit:read", "pool:claim", "pool:post", "pool:read", "pool:write", "webhooks:write"],
            "production_allowed": False,
            "evidence_allowed": False,
        }

    def post(self, path: str, payload: dict[str, Any]) -> Any:
        self.posts.append((path, payload))
        if path == "/api/v1/a2a/quickstart":
            alias = str(payload["alias"])
            return {"success": True, "agent": {"did": f"did:civ:test:{alias}", "name": payload.get("name")}}
        if path == "/api/v1/a2a/pool/post":
            self.counter += 1
            task_id = f"p0c-task-{self.counter}"
            self.tasks[task_id] = {
                "id": task_id,
                "requester": payload["requester"],
                "required_capability": payload["required_capability"],
                "status": "Open",
                "claimed_by": None,
                "posted_at": "2026-06-20T00:00:00+00:00",
                "claimed_at": None,
                "delivered_at": None,
                "challenge_deadline_at": None,
                "challenge_window_secs": 300,
                "output": None,
            }
            return {"success": True, "task_id": task_id}
        if path == "/api/v1/a2a/pool/claim":
            task = self.tasks[payload["task_id"]]
            task["status"] = "Claimed"
            task["claimed_by"] = payload["agent_id"]
            task["claimed_at"] = "2026-06-20T00:01:00+00:00"
            return {"success": True, "task_id": payload["task_id"]}
        if path == "/api/v1/a2a/task/execute":
            task = self.tasks[payload["task_id"]]
            task["status"] = "Delivered"
            task["output"] = payload["output"]
            task["delivered_at"] = "2026-06-20T00:02:00+00:00"
            task["challenge_deadline_at"] = "2026-06-20T00:07:00+00:00"
            return {"success": True, "task_id": payload["task_id"], "status": "Delivered"}
        raise AssertionError(f"unexpected POST {path}")

    def get(self, path: str) -> Any:
        prefix = "/api/v1/a2a/pool/tasks/"
        if path.startswith(prefix):
            task_id = path[len(prefix) :]
            return {"task": self.tasks[task_id]}
        raise AssertionError(f"unexpected GET {path}")


def test_p0c_execution_posts_claims_delivers_one_task(tmp_path: Path) -> None:
    p0c_summary = _write_p0c_summary(tmp_path)
    client = FakeClient()

    summary = run_execution(p0c_summary_path=p0c_summary, output_root=tmp_path / "execution", client=client)

    assert summary["passed"] is True
    assert summary["readiness"]["p0c_execution_performed"] is True
    assert summary["readiness"]["p0d_preview_smoke_ready"] is True
    assert summary["boundary"]["service_token_used"] is True
    assert summary["boundary"]["task_pool_post_performed"] is True
    assert summary["boundary"]["vm_contact_performed"] is False
    assert summary["boundary"]["production_receipt_write_allowed"] is False
    assert [path for path, _ in client.posts].count("/api/v1/a2a/pool/post") == 1
    receipt = json.loads((tmp_path / "execution" / "p0c_task_pool_execution_receipt.json").read_text(encoding="utf-8"))
    assert receipt["delivery_observed"] is True
    assert receipt["auth_context"]["auth_method"] == "service_token"
    execute_payload = next(payload for path, payload in client.posts if path == "/api/v1/a2a/task/execute")
    assert isinstance(execute_payload["output"], str)
    assert "生产执行不授权" in execute_payload["output"]
    assert "production_transition_allowed" not in execute_payload["output"]
    preview = json.loads((tmp_path / "execution" / "p0c_preview_artifact.json").read_text(encoding="utf-8"))
    assert preview["schema_version"] == "p0c-pilot-status-evidence-index-preview:v1"


def test_p0c_execution_blocks_authorization_reuse(tmp_path: Path) -> None:
    p0c_summary = _write_p0c_summary(tmp_path)

    first = run_execution(p0c_summary_path=p0c_summary, output_root=tmp_path / "execution1", client=FakeClient())
    second_client = FakeClient()
    second = run_execution(p0c_summary_path=p0c_summary, output_root=tmp_path / "execution2", client=second_client)

    assert first["passed"] is True
    assert second["passed"] is False
    assert second["blocked_stage"] == "single_use_authorization_consumption"
    assert any("authorization_already_consumed" in item for item in second["failure_reasons"])
    assert not second_client.posts


def test_p0c_execution_blocks_demo_login_auth(tmp_path: Path) -> None:
    p0c_summary = _write_p0c_summary(tmp_path)
    client = FakeClient(auth_method="demo_login")

    summary = run_execution(p0c_summary_path=p0c_summary, output_root=tmp_path / "execution", client=client)

    assert summary["passed"] is False
    assert summary["blocked_stage"] == "service_token_auth_policy"
    assert "service_token_required_demo_login_forbidden" in summary["failure_reasons"]
    assert not client.posts


def test_p0c_execution_blocks_authorization_hash_drift(tmp_path: Path) -> None:
    p0c_summary = _write_p0c_summary(tmp_path)
    payload = json.loads(p0c_summary.read_text(encoding="utf-8"))
    auth_path = Path(payload["artifacts"]["authorization"]["path"])
    auth = json.loads(auth_path.read_text(encoding="utf-8"))
    auth["passed"] = False
    auth_path.write_text(json.dumps(auth, indent=2, sort_keys=True), encoding="utf-8")
    client = FakeClient()

    summary = run_execution(p0c_summary_path=p0c_summary, output_root=tmp_path / "execution", client=client)

    assert summary["passed"] is False
    assert summary["blocked_stage"] == "authorization_chain_validation"
    assert "authorization_hash_valid" in summary["failure_reasons"]
    assert not client.posts


def _write_p0c_summary(tmp_path: Path) -> Path:
    p0b = _run_p0b(tmp_path)
    env_file = _write_service_env(tmp_path)
    run_p0c_authorization(p0b_summary_path=p0b, output_root=tmp_path / "p0c", service_token_env_file=env_file)
    return tmp_path / "p0c" / "p0c_controlled_execution_authorization_chain_summary.json"
