from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from benchmarks.post_h3_minimal_production_task_path_stability_index import build_index
from benchmarks.post_h3_minimal_production_task_repeated_validation import run_repeated_validation
from benchmarks.post_h3_operator_feedback_index_update_repeated_validation import (
    run_repeated_validation as run_feedback_update_repeated_validation,
)
from benchmarks.post_h3_operator_feedback_index_update_task import EXECUTION_GATE_NAME, run_chain as run_feedback_update
from benchmarks.tests.test_post_h3_minimal_production_task_intake_authorization import _write_readiness_index_fixture


def test_minimal_path_stability_index_accepts_repeated_validation(tmp_path: Path, monkeypatch: Any) -> None:
    repeated = _write_repeated_validation_fixture(tmp_path, monkeypatch)

    report = build_index(
        repeated_validation_summary_paths=[repeated],
        output=tmp_path / "stability_index.json",
        min_total_rounds=3,
    )

    assert report["passed"] is True
    assert report["total_rounds"] == 3
    assert report["readiness"]["minimal_production_task_path_stable"] is True
    assert report["readiness"]["production_task_execution_allowed"] is False
    assert report["boundary"]["runtime_execution_performed"] is False


def test_minimal_path_stability_index_rejects_insufficient_rounds(tmp_path: Path, monkeypatch: Any) -> None:
    repeated = _write_repeated_validation_fixture(tmp_path, monkeypatch)

    report = build_index(
        repeated_validation_summary_paths=[repeated],
        output=tmp_path / "stability_index.json",
        min_total_rounds=4,
    )

    assert report["passed"] is False
    assert "total_rounds_meet_threshold" in report["failure_reasons"]
    assert report["readiness"]["minimal_production_task_path_stable"] is False


def test_operator_feedback_index_update_runs_bounded_task_chain(tmp_path: Path, monkeypatch: Any) -> None:
    readiness_index = _write_readiness_index_fixture(tmp_path, monkeypatch)
    repeated = _write_repeated_validation_fixture(tmp_path, monkeypatch, readiness_index=readiness_index)

    summary = run_feedback_update(
        readiness_index_path=readiness_index,
        repeated_validation_summary_path=repeated,
        output_root=tmp_path / "feedback_update",
        operator_statement="Authorize one bounded operator feedback update for test-specific evidence.",
        ack_bounded_task=True,
    )

    assert summary["passed"] is True
    assert summary["task_class"] == "operator_feedback_index_update"
    assert summary["readiness"]["operator_feedback_index_update_complete"] is True
    assert summary["readiness"]["authorization_consumed"] is True
    assert summary["readiness"]["feedback_index_update_written"] is True
    assert summary["readiness"]["production_task_execution_allowed"] is False
    assert summary["boundary"]["bounded_task_execution_performed"] is True
    assert summary["boundary"]["backend_task_pool_mutation_performed"] is False
    assert summary["boundary"]["source_tree_write_performed"] is False
    request = json.loads(
        (tmp_path / "feedback_update" / "authorization" / "post_h3_minimal_task_authorization_request.json").read_text(
            encoding="utf-8"
        )
    )
    receipt = json.loads(
        (tmp_path / "feedback_update" / "authorization" / "post_h3_minimal_task_authorization_receipt.json").read_text(
            encoding="utf-8"
        )
    )
    assert request["required_next_gate"] == EXECUTION_GATE_NAME
    assert receipt["consumption_required_by"] == EXECUTION_GATE_NAME
    decision = json.loads(
        (tmp_path / "feedback_update" / "authorization" / "post_h3_minimal_task_authorization_decision.json").read_text(
            encoding="utf-8"
        )
    )
    assert decision["operator_statement"] == "Authorize one bounded operator feedback update for test-specific evidence."
    assert summary["operator_statement"] == "Authorize one bounded operator feedback update for test-specific evidence."


def test_operator_feedback_index_update_requires_ack(tmp_path: Path, monkeypatch: Any) -> None:
    readiness_index = _write_readiness_index_fixture(tmp_path, monkeypatch)
    repeated = _write_repeated_validation_fixture(tmp_path, monkeypatch, readiness_index=readiness_index)

    summary = run_feedback_update(
        readiness_index_path=readiness_index,
        repeated_validation_summary_path=repeated,
        output_root=tmp_path / "feedback_update",
        ack_bounded_task=False,
    )

    assert summary["passed"] is False
    assert "explicit_bounded_task_ack" in summary["failure_reasons"]
    assert summary["readiness"]["operator_feedback_index_update_complete"] is False


def test_operator_feedback_index_update_repeated_validation_requires_fresh_closeout(
    tmp_path: Path, monkeypatch: Any
) -> None:
    readiness_index = _write_readiness_index_fixture(tmp_path, monkeypatch)
    repeated = _write_repeated_validation_fixture(tmp_path, monkeypatch, readiness_index=readiness_index)

    summary = run_feedback_update_repeated_validation(
        readiness_index_path=readiness_index,
        repeated_validation_summary_path=repeated,
        output_root=tmp_path / "feedback_update_repeated",
        rounds=3,
        start_index=10,
        ack_repeated_validation=True,
    )

    assert summary["passed"] is True
    assert summary["round_count"] == 3
    assert summary["unique_task_id_count"] == 3
    assert summary["unique_authorization_id_count"] == 3
    assert summary["unique_operator_statement_count"] == 3
    assert summary["readiness"]["fresh_authorization_per_round_verified"] is True
    assert summary["readiness"]["authorization_consumed_per_round_verified"] is True
    assert summary["readiness"]["closeout_per_round_verified"] is True
    assert summary["readiness"]["strategy_review_per_round_verified"] is True
    assert summary["boundary"]["production_task_execution_allowed"] is False
    assert all(round_report["readiness"]["closeout_receipt_written"] is True for round_report in summary["rounds"])


def test_operator_feedback_index_update_repeated_validation_requires_ack(tmp_path: Path, monkeypatch: Any) -> None:
    readiness_index = _write_readiness_index_fixture(tmp_path, monkeypatch)
    repeated = _write_repeated_validation_fixture(tmp_path, monkeypatch, readiness_index=readiness_index)

    summary = run_feedback_update_repeated_validation(
        readiness_index_path=readiness_index,
        repeated_validation_summary_path=repeated,
        output_root=tmp_path / "feedback_update_repeated",
        rounds=3,
        ack_repeated_validation=False,
    )

    assert summary["passed"] is False
    assert "explicit_operator_feedback_repeated_validation_ack" in summary["failure_reasons"]


def _write_repeated_validation_fixture(
    tmp_path: Path,
    monkeypatch: Any,
    readiness_index: Path | None = None,
) -> Path:
    readiness = readiness_index or _write_readiness_index_fixture(tmp_path, monkeypatch)
    root = tmp_path / "repeated_validation"
    run_repeated_validation(
        readiness_index_path=readiness,
        output_root=root,
        rounds=3,
        start_index=3,
        ack_repeated_validation=True,
    )
    return root / "post_h3_minimal_task_repeated_validation_summary.json"
