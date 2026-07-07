from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from benchmarks.post_h3_limited_external_usage_feedback_closeout_strategy_gate import (
    HIGHER_PERMISSION_AUDIT_DECISION,
    HIGHER_PERMISSION_MONITORING_DECISION,
    HIGHER_PERMISSION_ROLLBACK_DECISION,
    REQUEST_HIGHER_PERMISSION_DECISION,
    run_gate as run_closeout_strategy,
)
from benchmarks.post_h3_observer_mode_baseline_gate import run_gate
from benchmarks.tests.test_post_h3_limited_feedback_closeout_strategy_gate import (
    _write_limited_feedback_execution_fixture,
)


def test_observer_mode_baseline_accepts_continued_observer_mode(tmp_path: Path, monkeypatch: Any) -> None:
    closeout = _write_observer_closeout(tmp_path, monkeypatch)

    summary = run_gate(
        closeout_strategy_summary_path=closeout,
        output_root=tmp_path / "observer_baseline",
        ack_baseline=True,
    )

    assert summary["passed"] is True
    assert summary["readiness"]["post_h3_observer_mode_baseline_ready"] is True
    assert summary["readiness"]["observer_mode_continues"] is True
    assert summary["readiness"]["higher_permission_review_request_ready"] is False
    assert summary["readiness"]["next_single_use_gate_input_ready"] is False
    assert summary["readiness"]["external_user_usage_allowed"] is False
    assert summary["readiness"]["runtime_execution_performed"] is False
    assert summary["readiness"]["production_runtime_receipt_write_allowed"] is False
    assert summary["boundary"]["baseline_written"] is True
    assert summary["boundary"]["external_public_ingress_opened"] is False
    assert summary["boundary"]["source_tree_write_performed"] is False
    assert summary["boundary"]["git_write_performed"] is False


def test_observer_mode_baseline_requires_ack(tmp_path: Path, monkeypatch: Any) -> None:
    closeout = _write_observer_closeout(tmp_path, monkeypatch)

    summary = run_gate(
        closeout_strategy_summary_path=closeout,
        output_root=tmp_path / "observer_baseline",
        ack_baseline=False,
    )

    assert summary["passed"] is False
    assert "explicit_baseline_ack" in summary["failure_reasons"]


def test_observer_mode_baseline_rejects_higher_permission_ready(tmp_path: Path, monkeypatch: Any) -> None:
    execution = _write_limited_feedback_execution_fixture(tmp_path, monkeypatch)
    root = tmp_path / "limited_feedback_closeout_strategy"
    run_closeout_strategy(
        limited_feedback_collection_execution_summary_path=execution,
        output_root=root,
        operator_decision=REQUEST_HIGHER_PERMISSION_DECISION,
        audit_decision=HIGHER_PERMISSION_AUDIT_DECISION,
        monitoring_decision=HIGHER_PERMISSION_MONITORING_DECISION,
        rollback_decision=HIGHER_PERMISSION_ROLLBACK_DECISION,
        operator_statement="Prepare higher permission review only.",
        ack_strategy_review=True,
    )

    summary = run_gate(
        closeout_strategy_summary_path=root / "post_h3_limited_feedback_closeout_strategy_summary.json",
        output_root=tmp_path / "observer_baseline",
        ack_baseline=True,
    )

    assert summary["passed"] is False
    assert "operator_decision_continues_observer" in summary["failure_reasons"]
    assert "summary_observer_mode_continues" in summary["failure_reasons"]
    assert "summary_higher_permission_not_ready" in summary["failure_reasons"]


def test_observer_mode_baseline_rejects_boundary_drift(tmp_path: Path, monkeypatch: Any) -> None:
    closeout = _write_observer_closeout(tmp_path, monkeypatch)
    payload = json.loads(closeout.read_text(encoding="utf-8"))
    payload["boundary"]["git_write_performed"] = True
    closeout.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    summary = run_gate(
        closeout_strategy_summary_path=closeout,
        output_root=tmp_path / "observer_baseline",
        ack_baseline=True,
    )

    assert summary["passed"] is False
    assert "boundary_git_write_performed_false" in summary["failure_reasons"]


def _write_observer_closeout(tmp_path: Path, monkeypatch: Any) -> Path:
    execution = _write_limited_feedback_execution_fixture(tmp_path, monkeypatch)
    root = tmp_path / "limited_feedback_closeout_strategy"
    run_closeout_strategy(
        limited_feedback_collection_execution_summary_path=execution,
        output_root=root,
        ack_strategy_review=True,
    )
    return root / "post_h3_limited_feedback_closeout_strategy_summary.json"
