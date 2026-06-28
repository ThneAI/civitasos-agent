from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from benchmarks.post_h3_first_internal_runtime_execution_gate import REQUIRED_SERVICE_SCOPES, run_execution
from benchmarks.post_h3_rollback_abort_drill_gate import run_gate as run_post_h3c
from benchmarks.tests.test_post_h3_rollback_abort_drill_gate import _write_post_h3b


def test_post_h3d_executes_first_internal_runtime_task(tmp_path: Path, monkeypatch: Any) -> None:
    monkeypatch.setattr(
        "benchmarks.post_h3_first_internal_runtime_execution_gate._public_key_hex",
        lambda seed: f"pubkey-{seed}",
    )
    post_h3a, post_h3b, post_h3c = _write_post_h3_chain(tmp_path)

    summary = run_execution(
        post_h3a_summary_path=post_h3a,
        post_h3b_summary_path=post_h3b,
        post_h3c_summary_path=post_h3c,
        output_root=tmp_path / "post_h3d",
        client=FakeClient(),
    )

    assert summary["passed"] is True
    assert summary["readiness"]["post_h3d_first_internal_runtime_execution_complete"] is True
    assert summary["readiness"]["post_h3e_production_receipt_write_authorization_ready"] is True
    assert summary["readiness"]["runtime_execution_performed"] is True
    assert summary["readiness"]["production_runtime_receipt_write_allowed"] is False
    assert summary["boundary"]["service_token_used"] is True
    assert summary["boundary"]["demo_login_used"] is False
    assert summary["boundary"]["task_pool_post_performed"] is True
    assert summary["boundary"]["task_pool_claim_performed"] is True
    assert summary["boundary"]["task_pool_execute_performed"] is True
    assert summary["boundary"]["vm_contact_performed"] is False
    assert summary["boundary"]["deploy_performed"] is False
    assert summary["boundary"]["external_public_ingress_opened"] is False
    assert summary["boundary"]["production_runtime_receipt_written"] is False


def test_post_h3d_blocks_when_post_h3c_readiness_drifts(tmp_path: Path) -> None:
    post_h3a, post_h3b, post_h3c = _write_post_h3_chain(tmp_path)
    payload = json.loads(post_h3c.read_text(encoding="utf-8"))
    payload["readiness"]["first_internal_runtime_execution_ready"] = False
    post_h3c.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    summary = run_execution(
        post_h3a_summary_path=post_h3a,
        post_h3b_summary_path=post_h3b,
        post_h3c_summary_path=post_h3c,
        output_root=tmp_path / "post_h3d",
        client=FakeClient(),
    )

    assert summary["passed"] is False
    assert "post_h3c_first_execution_ready" in summary["failure_reasons"]
    assert summary["readiness"]["runtime_execution_performed"] is False


def test_post_h3d_requires_service_token_auth(tmp_path: Path) -> None:
    post_h3a, post_h3b, post_h3c = _write_post_h3_chain(tmp_path)

    summary = run_execution(
        post_h3a_summary_path=post_h3a,
        post_h3b_summary_path=post_h3b,
        post_h3c_summary_path=post_h3c,
        output_root=tmp_path / "post_h3d",
        client=FakeClient(auth_method="demo_login"),
    )

    assert summary["passed"] is False
    assert "service_token_required_demo_login_forbidden" in summary["failure_reasons"]
    assert summary["boundary"]["authorization_consumed"] is False


def _write_post_h3_chain(tmp_path: Path) -> tuple[Path, Path, Path]:
    post_h3b = _write_post_h3b(tmp_path)
    post_h3a = tmp_path / "post_h3a" / "post_h3a_internal_runtime_authorization_summary.json"
    run_post_h3c(
        post_h3b_summary_path=post_h3b,
        output_root=tmp_path / "post_h3c",
        ack_rollback_abort_drill=True,
    )
    post_h3c = tmp_path / "post_h3c" / "post_h3c_rollback_abort_drill_summary.json"
    return post_h3a, post_h3b, post_h3c


class FakeClient:
    def __init__(self, *, auth_method: str = "service_token") -> None:
        self.auth_method = auth_method
        self.tasks: dict[str, dict[str, Any]] = {}
        self.next_task_id = 1

    def healthz(self) -> None:
        return None

    def auth_report(self) -> dict[str, Any]:
        return {
            "passed": True,
            "auth_method": self.auth_method,
            "token_recorded": False,
            "production_allowed": False,
            "scopes": sorted(REQUIRED_SERVICE_SCOPES),
        }

    def post(self, path: str, payload: dict[str, Any]) -> Any:
        if path == "/api/v1/a2a/quickstart":
            alias = str(payload["alias"])
            return {"success": True, "agent": {"did": f"did:civ:test:{alias}", "name": payload["name"]}}
        if path == "/api/v1/a2a/pool/post":
            task_id = f"post-h3d-test-task-{self.next_task_id}"
            self.next_task_id += 1
            self.tasks[task_id] = {
                "id": task_id,
                "requester": payload["requester"],
                "required_capability": payload["required_capability"],
                "status": "Open",
                "posted_at": _now(),
                "challenge_window_secs": 60,
            }
            return {"task_id": task_id}
        if path == "/api/v1/a2a/pool/claim":
            task = self.tasks[str(payload["task_id"])]
            task["status"] = "Claimed"
            task["claimed_by"] = payload["agent_id"]
            task["claimed_at"] = _now()
            return {"success": True, "task_id": payload["task_id"]}
        if path == "/api/v1/a2a/task/execute":
            task = self.tasks[str(payload["task_id"])]
            task["status"] = "Delivered"
            task["output"] = payload["output"]
            task["delivered_at"] = _now()
            return {"success": True, "task_id": payload["task_id"]}
        raise AssertionError(f"unexpected POST {path}")

    def get(self, path: str) -> Any:
        prefix = "/api/v1/a2a/pool/tasks/"
        if path.startswith(prefix):
            return {"task": self.tasks[path.removeprefix(prefix)]}
        raise AssertionError(f"unexpected GET {path}")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
