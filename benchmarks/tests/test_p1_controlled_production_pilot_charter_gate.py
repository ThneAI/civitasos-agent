from __future__ import annotations

import json
from pathlib import Path

from benchmarks.p0o_first_controlled_beta_task_authorization_gate import run_gate as run_p0o
from benchmarks.p1_controlled_production_pilot_charter_gate import run_gate
from benchmarks.tests.test_p0o_first_controlled_beta_task_authorization_gate import _write_p0n_summary


def test_p1_controlled_production_pilot_charter_passes(tmp_path: Path) -> None:
    p0o_summary = _write_p0o_summary(tmp_path)

    summary = run_gate(
        p0o_summary_path=p0o_summary,
        output_root=tmp_path / "p1",
        operator_id="operator-test",
        ack_p1_charter=True,
    )

    assert summary["passed"] is True
    assert summary["readiness"]["p1_charter_ready"] is True
    assert summary["readiness"]["h3_production_evidence_collection_ready"] is True
    assert summary["readiness"]["runtime_execution_allowed"] is False
    assert summary["boundary"]["charter_written"] is True
    assert summary["boundary"]["production_transition_allowed"] is False


def test_p1_requires_operator_ack(tmp_path: Path) -> None:
    p0o_summary = _write_p0o_summary(tmp_path)

    summary = run_gate(
        p0o_summary_path=p0o_summary,
        output_root=tmp_path / "p1",
        operator_id="operator-test",
        ack_p1_charter=False,
    )

    assert summary["passed"] is False
    assert "explicit_operator_ack" in summary["failure_reasons"]
    assert summary["readiness"]["production_transition_allowed"] is False


def test_p1_blocks_consumed_p0o_authorization(tmp_path: Path) -> None:
    p0o_summary = _write_p0o_summary(tmp_path)
    payload = json.loads(p0o_summary.read_text(encoding="utf-8"))
    payload["authorization"]["consumed"] = True
    p0o_summary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    summary = run_gate(
        p0o_summary_path=p0o_summary,
        output_root=tmp_path / "p1",
        operator_id="operator-test",
        ack_p1_charter=True,
    )

    assert summary["passed"] is False
    assert "authorization_not_consumed" in summary["failure_reasons"]


def test_p1_blocks_p0o_production_boundary_drift(tmp_path: Path) -> None:
    p0o_summary = _write_p0o_summary(tmp_path)
    payload = json.loads(p0o_summary.read_text(encoding="utf-8"))
    payload["boundary"]["task_pool_post_performed"] = True
    p0o_summary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    summary = run_gate(
        p0o_summary_path=p0o_summary,
        output_root=tmp_path / "p1",
        operator_id="operator-test",
        ack_p1_charter=True,
    )

    assert summary["passed"] is False
    assert "p0o_boundary_closed" in summary["failure_reasons"]


def _write_p0o_summary(tmp_path: Path) -> Path:
    p0n_summary = _write_p0n_summary(tmp_path)
    run_p0o(
        p0n_summary_path=p0n_summary,
        output_root=tmp_path / "p0o",
        operator_id="operator-test",
        ack_first_task_authorization=True,
    )
    return tmp_path / "p0o" / "p0o_first_controlled_beta_task_authorization_summary.json"
