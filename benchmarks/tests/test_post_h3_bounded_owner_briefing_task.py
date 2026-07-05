from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from benchmarks.post_h3_bounded_owner_briefing_task import EXECUTION_GATE_NAME, run_chain as run_owner_briefing
from benchmarks.post_h3_operator_feedback_index_update_repeated_validation import run_repeated_validation as run_feedback_repeated
from benchmarks.tests.test_post_h3_minimal_path_stability_and_feedback_update import _write_repeated_validation_fixture
from benchmarks.tests.test_post_h3_minimal_production_task_intake_authorization import _write_readiness_index_fixture


def test_bounded_owner_briefing_runs_artifact_only_chain(tmp_path: Path, monkeypatch: Any) -> None:
    readiness_index = _write_readiness_index_fixture(tmp_path, monkeypatch)
    feedback_repeated = _write_feedback_repeated_fixture(tmp_path, monkeypatch, readiness_index=readiness_index)

    summary = run_owner_briefing(
        readiness_index_path=readiness_index,
        feedback_repeated_validation_summary_path=feedback_repeated,
        output_root=tmp_path / "owner_briefing",
        operator_statement="Authorize one bounded owner briefing for test evidence.",
        ack_bounded_task=True,
    )

    assert summary["passed"] is True
    assert summary["task_class"] == "bounded_owner_briefing"
    assert summary["readiness"]["bounded_owner_briefing_complete"] is True
    assert summary["readiness"]["authorization_consumed"] is True
    assert summary["readiness"]["owner_briefing_written"] is True
    assert summary["readiness"]["closeout_receipt_written"] is True
    assert summary["readiness"]["strategy_review_complete"] is True
    assert summary["readiness"]["production_task_execution_allowed"] is False
    assert summary["boundary"]["bounded_task_execution_performed"] is True
    assert summary["boundary"]["backend_task_pool_mutation_performed"] is False
    assert summary["boundary"]["source_tree_write_performed"] is False
    assert summary["boundary"]["git_write_performed"] is False

    request = json.loads(
        (tmp_path / "owner_briefing" / "authorization" / "post_h3_minimal_task_authorization_request.json").read_text(
            encoding="utf-8"
        )
    )
    receipt = json.loads(
        (tmp_path / "owner_briefing" / "authorization" / "post_h3_minimal_task_authorization_receipt.json").read_text(
            encoding="utf-8"
        )
    )
    briefing = json.loads((tmp_path / "owner_briefing" / "post_h3_bounded_owner_briefing.json").read_text(encoding="utf-8"))
    assert request["required_next_gate"] == EXECUTION_GATE_NAME
    assert receipt["consumption_required_by"] == EXECUTION_GATE_NAME
    assert briefing["owner_recommendation"]["decision"] == "keep_bounded_artifact_only_path_and_prepare_next_reversible_task"
    assert "public_ingress" in briefing["owner_recommendation"]["blocked_expansions"]


def test_bounded_owner_briefing_requires_ack(tmp_path: Path, monkeypatch: Any) -> None:
    readiness_index = _write_readiness_index_fixture(tmp_path, monkeypatch)
    feedback_repeated = _write_feedback_repeated_fixture(tmp_path, monkeypatch, readiness_index=readiness_index)

    summary = run_owner_briefing(
        readiness_index_path=readiness_index,
        feedback_repeated_validation_summary_path=feedback_repeated,
        output_root=tmp_path / "owner_briefing",
        ack_bounded_task=False,
    )

    assert summary["passed"] is False
    assert "explicit_bounded_owner_briefing_ack" in summary["failure_reasons"]
    assert summary["readiness"]["bounded_owner_briefing_complete"] is False


def _write_feedback_repeated_fixture(tmp_path: Path, monkeypatch: Any, readiness_index: Path) -> Path:
    minimal_repeated = _write_repeated_validation_fixture(tmp_path, monkeypatch, readiness_index=readiness_index)
    root = tmp_path / "feedback_repeated"
    run_feedback_repeated(
        readiness_index_path=readiness_index,
        repeated_validation_summary_path=minimal_repeated,
        output_root=root,
        rounds=3,
        start_index=20,
        ack_repeated_validation=True,
    )
    return root / "post_h3_operator_feedback_index_update_repeated_validation_summary.json"
