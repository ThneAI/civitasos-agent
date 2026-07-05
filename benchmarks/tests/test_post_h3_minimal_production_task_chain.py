from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from benchmarks.post_h3_minimal_production_task_chain import ORDERED_STAGES, run_gate
from benchmarks.post_h3_observer_mode_readiness_gate import run_gate as run_post_h3ac
from benchmarks.tests.test_post_h3_observer_mode_readiness_gate import _write_post_h3ab_fixture


def test_minimal_production_task_chain_accepts_ac_observer_readiness(tmp_path: Path, monkeypatch: Any) -> None:
    post_h3ac = _write_post_h3ac_fixture(tmp_path, monkeypatch)

    summary = run_gate(
        post_h3ac_summary_path=post_h3ac,
        output_root=tmp_path / "minimal_chain",
    )

    assert summary["passed"] is True
    assert summary["ordered_stages"] == list(ORDERED_STAGES)
    assert summary["readiness"]["minimal_production_task_chain_blueprint_ready"] is True
    assert summary["readiness"]["production_task_execution_allowed"] is False
    assert summary["readiness"]["next_single_use_gate_input_ready"] is False
    assert summary["boundary"]["runtime_execution_performed"] is False

    blueprint = json.loads((tmp_path / "minimal_chain" / "post_h3_minimal_production_task_chain_blueprint.json").read_text(encoding="utf-8"))
    assert [stage["stage"] for stage in blueprint["ordered_stages"]] == list(ORDERED_STAGES)
    assert blueprint["transition_rules"]["each_stage_consumes_previous_stage_receipt"] is True


def test_minimal_production_task_chain_rejects_ac_next_single_use_ready(tmp_path: Path, monkeypatch: Any) -> None:
    post_h3ac = _write_post_h3ac_fixture(tmp_path, monkeypatch)
    payload = json.loads(post_h3ac.read_text(encoding="utf-8"))
    payload["readiness"]["next_single_use_gate_input_ready"] = True
    post_h3ac.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    summary = run_gate(
        post_h3ac_summary_path=post_h3ac,
        output_root=tmp_path / "minimal_chain",
    )

    assert summary["passed"] is False
    assert "post_h3ac_no_next_single_use_input" in summary["failure_reasons"]
    assert summary["readiness"]["production_task_execution_allowed"] is False


def test_minimal_production_task_chain_blocks_ac_artifact_hash_drift(tmp_path: Path, monkeypatch: Any) -> None:
    post_h3ac = _write_post_h3ac_fixture(tmp_path, monkeypatch)
    snapshot_path = tmp_path / "post_h3ac" / "post_h3ac_observer_mode_evidence_snapshot.json"
    payload = json.loads(snapshot_path.read_text(encoding="utf-8"))
    payload["passed"] = False
    snapshot_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    summary = run_gate(
        post_h3ac_summary_path=post_h3ac,
        output_root=tmp_path / "minimal_chain",
    )

    assert summary["passed"] is False
    assert "post_h3ac_observer_evidence_snapshot_hash_valid" in summary["failure_reasons"]


def test_minimal_production_task_chain_rejects_ac_runtime_execution_claim(tmp_path: Path, monkeypatch: Any) -> None:
    post_h3ac = _write_post_h3ac_fixture(tmp_path, monkeypatch)
    payload = json.loads(post_h3ac.read_text(encoding="utf-8"))
    payload["boundary"]["runtime_execution_performed"] = True
    post_h3ac.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    summary = run_gate(
        post_h3ac_summary_path=post_h3ac,
        output_root=tmp_path / "minimal_chain",
    )

    assert summary["passed"] is False
    assert "post_h3ac_summary_runtime_execution_performed_false" in summary["failure_reasons"]


def _write_post_h3ac_fixture(tmp_path: Path, monkeypatch: Any) -> Path:
    post_h3ab = _write_post_h3ab_fixture(tmp_path, monkeypatch)
    post_h3ac_root = tmp_path / "post_h3ac"
    run_post_h3ac(
        post_h3ab_summary_path=post_h3ab,
        output_root=post_h3ac_root,
        ack_observer_readiness=True,
    )
    return post_h3ac_root / "post_h3ac_observer_mode_readiness_summary.json"
