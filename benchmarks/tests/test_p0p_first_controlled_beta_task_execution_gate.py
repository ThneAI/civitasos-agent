from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from benchmarks.p0o_first_controlled_beta_task_authorization_gate import run_gate as run_p0o
from benchmarks.p0p_first_controlled_beta_task_execution_gate import run_execution
from benchmarks.tests.test_p0o_first_controlled_beta_task_authorization_gate import _write_p0n_summary


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
            "service_id": "p0p_first_controlled_beta_task_execution",
            "scopes": [
                "agents:read",
                "agents:write",
                "a2a:pool:read",
                "a2a:pool:post",
                "a2a:pool:claim",
                "a2a:task:execute",
                "pool:read",
                "pool:post",
                "pool:claim",
                "pool:write",
                "audit:read",
                "operator:read-model",
            ],
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
            task_id = f"p0p-task-{self.counter}"
            self.tasks[task_id] = {
                "id": task_id,
                "requester": payload["requester"],
                "required_capability": payload["required_capability"],
                "status": "Open",
                "claimed_by": None,
                "posted_at": "2026-06-28T00:00:00+00:00",
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
            task["claimed_at"] = "2026-06-28T00:01:00+00:00"
            return {"success": True, "task_id": payload["task_id"]}
        if path == "/api/v1/a2a/task/execute":
            task = self.tasks[payload["task_id"]]
            task["status"] = "Delivered"
            task["output"] = payload["output"]
            task["delivered_at"] = "2026-06-28T00:02:00+00:00"
            task["challenge_deadline_at"] = "2026-06-28T00:07:00+00:00"
            return {"success": True, "task_id": payload["task_id"], "status": "Delivered"}
        raise AssertionError(f"unexpected POST {path}")

    def get(self, path: str) -> Any:
        prefix = "/api/v1/a2a/pool/tasks/"
        if path.startswith(prefix):
            task_id = path[len(prefix) :]
            return {"task": self.tasks[task_id]}
        raise AssertionError(f"unexpected GET {path}")


def test_p0p_execution_posts_claims_delivers_one_task(tmp_path: Path) -> None:
    p0o_summary = _write_p0o_summary(tmp_path)
    client = FakeClient()

    summary = run_execution(p0o_summary_path=p0o_summary, output_root=tmp_path / "p0p", client=client)

    assert summary["passed"] is True
    assert summary["readiness"]["p0p_first_controlled_beta_task_execution_complete"] is True
    assert summary["readiness"]["p1_h3_source_ref_collection_ready"] is True
    assert summary["boundary"]["service_token_used"] is True
    assert summary["boundary"]["authorization_consumed"] is True
    assert summary["boundary"]["task_pool_post_performed"] is True
    assert summary["boundary"]["task_pool_execute_performed"] is True
    assert summary["boundary"]["vm_contact_performed"] is False
    assert summary["boundary"]["production_receipt_write_allowed"] is False
    assert [path for path, _ in client.posts].count("/api/v1/a2a/pool/post") == 1
    receipt = json.loads((tmp_path / "p0p" / "p0p_task_pool_execution_receipt.json").read_text(encoding="utf-8"))
    assert receipt["delivery_observed"] is True
    assert receipt["h3_evidence_candidate"]["satisfies_production_origin"] is False
    artifact = json.loads((tmp_path / "p0p" / "p0p_controlled_beta_status_evidence_index.json").read_text(encoding="utf-8"))
    assert artifact["schema_version"] == "p0p-controlled-beta-status-evidence-index:v1"


def test_p0p_execution_blocks_authorization_reuse(tmp_path: Path) -> None:
    p0o_summary = _write_p0o_summary(tmp_path)

    first = run_execution(p0o_summary_path=p0o_summary, output_root=tmp_path / "p0p1", client=FakeClient())
    second_client = FakeClient()
    second = run_execution(p0o_summary_path=p0o_summary, output_root=tmp_path / "p0p2", client=second_client)

    assert first["passed"] is True
    assert second["passed"] is False
    assert second["blocked_stage"] == "single_use_authorization_consumption"
    assert any("authorization_already_consumed" in item for item in second["failure_reasons"])
    assert not second_client.posts


def test_p0p_execution_blocks_demo_login_auth(tmp_path: Path) -> None:
    p0o_summary = _write_p0o_summary(tmp_path)
    client = FakeClient(auth_method="demo_login")

    summary = run_execution(p0o_summary_path=p0o_summary, output_root=tmp_path / "p0p", client=client)

    assert summary["passed"] is False
    assert summary["blocked_stage"] == "service_token_auth_policy"
    assert "service_token_required_demo_login_forbidden" in summary["failure_reasons"]
    assert not client.posts


def test_p0p_execution_blocks_p0o_receipt_hash_drift(tmp_path: Path) -> None:
    p0o_summary = _write_p0o_summary(tmp_path)
    payload = json.loads(p0o_summary.read_text(encoding="utf-8"))
    receipt_path = Path(payload["artifacts"]["authorization_receipt"]["path"])
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["consumed"] = True
    receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    summary = run_execution(p0o_summary_path=p0o_summary, output_root=tmp_path / "p0p", client=FakeClient())

    assert summary["passed"] is False
    assert summary["blocked_stage"] == "p0o_context_validation"
    assert "p0o_authorization_receipt_hash_valid" in summary["failure_reasons"]


def test_p0p_execution_blocks_p0o_production_boundary_drift(tmp_path: Path) -> None:
    p0o_summary = _write_p0o_summary(tmp_path)
    payload = json.loads(p0o_summary.read_text(encoding="utf-8"))
    payload["boundary"]["production_transition_allowed"] = True
    p0o_summary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    summary = run_execution(p0o_summary_path=p0o_summary, output_root=tmp_path / "p0p", client=FakeClient())

    assert summary["passed"] is False
    assert summary["blocked_stage"] == "p0o_context_validation"
    assert "p0o_boundary_pre_execution_closed" in summary["failure_reasons"]


def _write_p0o_summary(tmp_path: Path) -> Path:
    p0n_summary = _write_p0n_summary(tmp_path)
    run_p0o(
        p0n_summary_path=p0n_summary,
        output_root=tmp_path / "p0o",
        ack_first_task_authorization=True,
    )
    return tmp_path / "p0o" / "p0o_first_controlled_beta_task_authorization_summary.json"


def test_p0p_callback_sink_blocks_when_no_callback_observed(tmp_path: Path) -> None:
    p0o_summary = _write_p0o_summary(tmp_path)

    summary = run_execution(
        p0o_summary_path=p0o_summary,
        output_root=tmp_path / "p0p",
        client=FakeClient(),
        enable_callback_sink=True,
        callback_wait_seconds=0.01,
    )

    assert summary["passed"] is False
    assert "callback_sink_delivery_observed" in summary["failure_reasons"]
    assert summary["boundary"]["callback_sink_started"] is True
    assert summary["boundary"]["callback_delivery_observed"] is False
    callback = json.loads((tmp_path / "p0p" / "p0p_callback_sink_receipt.json").read_text(encoding="utf-8"))
    assert callback["schema_version"] == "p0p-callback-sink-receipt:v1"
    assert callback["passed"] is False
