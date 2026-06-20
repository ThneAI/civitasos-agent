from __future__ import annotations

import json
from pathlib import Path

from benchmarks.p0d_preview_smoke_gate import run_gate as run_p0d
from benchmarks.p0e_rollback_abort_drill_gate import run_gate
from benchmarks.tests.test_p0d_preview_smoke_gate import FakeP0DClient, _attach_callback_sink_receipt, _write_p0c_execution_summary


def test_p0e_rollback_abort_drill_passes_with_callback_backed_p0d(tmp_path: Path) -> None:
    p0d_summary = _write_p0d_summary(tmp_path, with_callback=True)

    summary = run_gate(p0d_summary_path=p0d_summary, output_root=tmp_path / "p0e", operator_id="operator-test")

    assert summary["passed"] is True
    assert summary["readiness"]["p0e_rollback_abort_drill_complete"] is True
    assert summary["readiness"]["p0f_vm_preview_preflight_ready"] is True
    assert summary["boundary"]["callback_delivery_observed"] is True
    assert summary["boundary"]["deploy_performed"] is False
    receipt = json.loads((tmp_path / "p0e" / "p0e_rollback_abort_drill_receipt.json").read_text(encoding="utf-8"))
    assert receipt["drill_mode"] == "abort_only_no_deploy_rollback_not_required"
    assert receipt["rollback_performed"] is False
    assert receipt["abort_receipt_written"] is True


def test_p0e_blocks_without_callback_backed_p0d(tmp_path: Path) -> None:
    p0d_summary = _write_p0d_summary(tmp_path, with_callback=False)

    summary = run_gate(p0d_summary_path=p0d_summary, output_root=tmp_path / "p0e")

    assert summary["passed"] is False
    assert "p0d_ready_for_p0e" in summary["failure_reasons"]
    assert "callback_sink_evidence_present" in summary["failure_reasons"]


def test_p0e_blocks_owner_rejection(tmp_path: Path) -> None:
    p0d_summary = _write_p0d_summary(tmp_path, with_callback=True)

    summary = run_gate(
        p0d_summary_path=p0d_summary,
        output_root=tmp_path / "p0e",
        owner_decision="request_revision",
    )

    assert summary["passed"] is False
    assert "owner_decision_approves_drill" in summary["failure_reasons"]


def test_p0e_blocks_p0d_boundary_drift(tmp_path: Path) -> None:
    p0d_summary = _write_p0d_summary(tmp_path, with_callback=True)
    payload = json.loads(p0d_summary.read_text(encoding="utf-8"))
    payload["boundary"]["deploy_performed"] = True
    p0d_summary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    summary = run_gate(p0d_summary_path=p0d_summary, output_root=tmp_path / "p0e")

    assert summary["passed"] is False
    assert "p0d_boundary_closed" in summary["failure_reasons"]


def _write_p0d_summary(tmp_path: Path, *, with_callback: bool) -> Path:
    client = FakeP0DClient()
    p0c_execution_summary = _write_p0c_execution_summary(tmp_path, client)
    if with_callback:
        _attach_callback_sink_receipt(p0c_execution_summary, task_id="p0c-task-1")
    run_p0d(
        p0c_execution_summary_path=p0c_execution_summary,
        output_root=tmp_path / "p0d",
        client=client,
        backend_url="http://127.0.0.1:8099",
        operator_id="operator-test",
    )
    return tmp_path / "p0d" / "p0d_preview_smoke_chain_summary.json"
