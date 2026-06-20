from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from benchmarks.i_gate_evidence import artifact_ref
from benchmarks.p0c_controlled_task_pool_execution import CALLBACK_SINK_SCHEMA
from benchmarks.p0c_controlled_task_pool_execution import run_execution
from benchmarks.p0d_preview_smoke_gate import run_gate
from benchmarks.tests.test_p0c_controlled_task_pool_execution import FakeClient, _write_p0c_summary


class FakeP0DClient(FakeClient):
    def __init__(self, *, auth_method: str = "service_token", task_readback: bool = True) -> None:
        super().__init__(auth_method=auth_method)
        self.task_readback = task_readback

    def get(self, path: str) -> Any:
        if path.startswith("/api/v1/a2a/pool/tasks/"):
            if not self.task_readback:
                raise RuntimeError("task readback unavailable")
            return super().get(path)
        if path == "/api/v1/status":
            return {"status": "ok"}
        if path == "/api/v1/a2a/pool/tasks":
            return {"tasks": list(self.tasks.values())}
        if path == "/api/v1/a2a/pool/failures?since=0&limit=100":
            return {"failures": []}
        if path == "/api/v1/audit/events":
            return {"events": [{"event_type": "task_delivered"}]}
        if path == "/api/v1/a2a/operator/read-model":
            return {
                "data": {
                    "schema_version": "operator-read-model:v1",
                    "summary": {
                        "task_count": len(self.tasks),
                        "wake_trace_task_count": 0,
                        "contract_rejection_task_count": 0,
                    },
                    "scope_denial": {},
                }
            }
        if path == "/api/v1/audit/log":
            return {"events": [{"event_type": "auth.service_token.used"}]}
        raise AssertionError(f"unexpected GET {path}")


def test_p0d_preview_smoke_passes_after_p0c_task_delivery(tmp_path: Path) -> None:
    client = FakeP0DClient()
    p0c_execution_summary = _write_p0c_execution_summary(tmp_path, client)

    summary = run_gate(
        p0c_execution_summary_path=p0c_execution_summary,
        output_root=tmp_path / "p0d",
        client=client,
        backend_url="http://127.0.0.1:8099",
        operator_id="operator-test",
    )

    assert summary["passed"] is True
    assert summary["readiness"]["p0d_preview_smoke_complete"] is True
    assert summary["readiness"]["owner_audit_review_required"] is True
    assert summary["readiness"]["p0e_rollback_drill_ready"] is False
    assert summary["boundary"]["preview_artifact_verified"] is True
    assert summary["boundary"]["backend_read_model_checked"] is True
    assert summary["boundary"]["audit_endpoint_checked"] is True
    packet = json.loads((tmp_path / "p0d" / "p0d_owner_audit_review_packet.json").read_text(encoding="utf-8"))
    assert packet["review_packet"]["owner_id"] == "product_owner"
    assert packet["review_packet"]["audit_owner_id"] == "audit_owner"
    assert packet["review_packet"]["rollback_owner_id"] == "rollback_owner"
    assert packet["review_packet"]["vm_target_ids"] == ["vm1", "vm2", "vm3"]


def test_p0d_callback_sink_receipt_removes_callback_review_block(tmp_path: Path) -> None:
    client = FakeP0DClient()
    p0c_execution_summary = _write_p0c_execution_summary(tmp_path, client)
    _attach_callback_sink_receipt(p0c_execution_summary, task_id="p0c-task-1")

    summary = run_gate(
        p0c_execution_summary_path=p0c_execution_summary,
        output_root=tmp_path / "p0d",
        client=client,
        backend_url="http://127.0.0.1:8099",
        operator_id="operator-test",
    )

    assert summary["passed"] is True
    assert summary["readiness"]["p0e_rollback_drill_ready"] is True
    assert summary["boundary"]["callback_delivery_observed"] is True
    backend = json.loads((tmp_path / "p0d" / "p0d_backend_smoke_receipt.json").read_text(encoding="utf-8"))
    assert backend["callback_sink_evidence_present"] is True
    packet = json.loads((tmp_path / "p0d" / "p0d_owner_audit_review_packet.json").read_text(encoding="utf-8"))
    assert packet["review_packet"]["callback_sink_review_required"] is False


def test_p0d_blocks_demo_login_auth(tmp_path: Path) -> None:
    execution_client = FakeP0DClient()
    p0c_execution_summary = _write_p0c_execution_summary(tmp_path, execution_client)

    summary = run_gate(
        p0c_execution_summary_path=p0c_execution_summary,
        output_root=tmp_path / "p0d",
        client=FakeP0DClient(auth_method="demo_login"),
        backend_url="http://127.0.0.1:8099",
    )

    assert summary["passed"] is False
    assert "service_token_used" in summary["failure_reasons"]
    assert summary["boundary"]["service_token_used"] is False


def test_p0d_blocks_task_readback_failure(tmp_path: Path) -> None:
    client = FakeP0DClient()
    p0c_execution_summary = _write_p0c_execution_summary(tmp_path, client)
    blocked_client = FakeP0DClient(task_readback=False)
    blocked_client.tasks = client.tasks

    summary = run_gate(
        p0c_execution_summary_path=p0c_execution_summary,
        output_root=tmp_path / "p0d",
        client=blocked_client,
        backend_url="http://127.0.0.1:8099",
    )

    assert summary["passed"] is False
    assert any(item.startswith("endpoint_failed:task_readback") for item in summary["failure_reasons"])
    assert "task_readback_delivered" in summary["failure_reasons"]


def test_p0d_blocks_p0c_artifact_hash_drift(tmp_path: Path) -> None:
    client = FakeP0DClient()
    p0c_execution_summary = _write_p0c_execution_summary(tmp_path, client)
    payload = json.loads(p0c_execution_summary.read_text(encoding="utf-8"))
    preview_path = Path(payload["artifacts"]["preview_artifact"]["path"])
    preview = json.loads(preview_path.read_text(encoding="utf-8"))
    preview["passed"] = False
    preview_path.write_text(json.dumps(preview, indent=2, sort_keys=True), encoding="utf-8")

    summary = run_gate(
        p0c_execution_summary_path=p0c_execution_summary,
        output_root=tmp_path / "p0d",
        client=client,
        backend_url="http://127.0.0.1:8099",
    )

    assert summary["passed"] is False
    assert "preview_artifact_hash_valid" in summary["failure_reasons"]
    assert "preview_passed" in summary["failure_reasons"]


def _write_p0c_execution_summary(tmp_path: Path, client: FakeP0DClient) -> Path:
    p0c_summary = _write_p0c_summary(tmp_path)
    run_execution(p0c_summary_path=p0c_summary, output_root=tmp_path / "execution", client=client)
    return tmp_path / "execution" / "p0c_controlled_task_pool_execution_chain_summary.json"


def _attach_callback_sink_receipt(p0c_execution_summary: Path, *, task_id: str) -> None:
    receipt_path = p0c_execution_summary.parent / "p0c_callback_sink_receipt.json"
    receipt_path.write_text(
        json.dumps(
            {
                "schema_version": CALLBACK_SINK_SCHEMA,
                "enabled": True,
                "passed": True,
                "failure_reasons": [],
                "checks": {
                    "callback_sink_enabled": True,
                    "callback_sink_endpoint_private": True,
                    "callback_event_for_task_observed": True,
                    "task_completed_callback_observed": True,
                },
                "task_id": task_id,
                "endpoint": "http://127.0.0.1:12345/p0c-callback-sink",
                "received_event_count": 1,
                "task_event_count": 1,
                "task_completed_event_count": 1,
                "events": [
                    {
                        "body": {
                            "event": "task_completed",
                            "task_id": task_id,
                        }
                    }
                ],
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    summary = json.loads(p0c_execution_summary.read_text(encoding="utf-8"))
    summary["artifacts"]["callback_sink_receipt"] = artifact_ref(receipt_path)
    p0c_execution_summary.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
