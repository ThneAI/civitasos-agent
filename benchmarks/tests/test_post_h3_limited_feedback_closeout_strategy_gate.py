from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from benchmarks.post_h3_limited_external_usage_feedback_closeout_strategy_gate import (
    HIGHER_PERMISSION_AUDIT_DECISION,
    HIGHER_PERMISSION_MONITORING_DECISION,
    HIGHER_PERMISSION_ROLLBACK_DECISION,
    REQUEST_HIGHER_PERMISSION_DECISION,
    run_gate,
)
from benchmarks.post_h3_limited_external_usage_feedback_collection_execution_gate import (
    run_gate as run_limited_feedback_collection_execution,
)
from benchmarks.tests.test_post_h3_bounded_owner_briefing_task import (
    _write_limited_feedback_authorization_decision_fixture,
)


def test_limited_feedback_closeout_strategy_continues_observer_mode(
    tmp_path: Path, monkeypatch: Any
) -> None:
    execution = _write_limited_feedback_execution_fixture(tmp_path, monkeypatch)

    summary = run_gate(
        limited_feedback_collection_execution_summary_path=execution,
        output_root=tmp_path / "limited_feedback_closeout_strategy",
        ack_strategy_review=True,
    )

    assert summary["passed"] is True
    assert summary["readiness"]["limited_feedback_closeout_strategy_complete"] is True
    assert summary["readiness"]["limited_feedback_execution_closed"] is True
    assert summary["readiness"]["limited_feedback_evidence_index_complete"] is True
    assert summary["readiness"]["strategy_review_complete"] is True
    assert summary["readiness"]["observer_mode_continues"] is True
    assert summary["readiness"]["higher_permission_review_request_ready"] is False
    assert summary["readiness"]["next_single_use_gate_input_ready"] is False
    assert summary["readiness"]["external_user_usage_allowed"] is False
    assert summary["readiness"]["runtime_execution_performed"] is False
    assert summary["readiness"]["production_runtime_receipt_write_allowed"] is False
    assert summary["boundary"]["observer_mode_continues"] is True
    assert summary["boundary"]["external_user_usage_performed"] is False
    assert summary["boundary"]["external_public_ingress_opened"] is False
    assert summary["boundary"]["source_tree_write_performed"] is False
    assert summary["boundary"]["git_write_performed"] is False


def test_limited_feedback_closeout_strategy_requires_ack(tmp_path: Path, monkeypatch: Any) -> None:
    execution = _write_limited_feedback_execution_fixture(tmp_path, monkeypatch)

    summary = run_gate(
        limited_feedback_collection_execution_summary_path=execution,
        output_root=tmp_path / "limited_feedback_closeout_strategy",
        ack_strategy_review=False,
    )

    assert summary["passed"] is False
    assert "explicit_operator_ack" in summary["failure_reasons"]
    assert summary["readiness"]["limited_feedback_closeout_strategy_complete"] is False


def test_limited_feedback_closeout_strategy_can_prepare_higher_permission_review(
    tmp_path: Path, monkeypatch: Any
) -> None:
    execution = _write_limited_feedback_execution_fixture(tmp_path, monkeypatch)

    summary = run_gate(
        limited_feedback_collection_execution_summary_path=execution,
        output_root=tmp_path / "limited_feedback_closeout_strategy",
        operator_decision=REQUEST_HIGHER_PERMISSION_DECISION,
        audit_decision=HIGHER_PERMISSION_AUDIT_DECISION,
        monitoring_decision=HIGHER_PERMISSION_MONITORING_DECISION,
        rollback_decision=HIGHER_PERMISSION_ROLLBACK_DECISION,
        operator_statement="Prepare a higher-permission review request only; do not grant execution.",
        ack_strategy_review=True,
    )

    assert summary["passed"] is True
    assert summary["higher_permission_review_request_ready"] is True
    assert summary["readiness"]["higher_permission_review_request_ready"] is True
    assert summary["readiness"]["observer_mode_continues"] is False
    assert summary["readiness"]["next_single_use_gate_input_ready"] is False
    assert summary["readiness"]["external_user_usage_allowed"] is False
    assert summary["boundary"]["higher_permission_review_request_ready"] is True
    assert summary["boundary"]["runtime_execution_performed"] is False


def test_limited_feedback_closeout_strategy_blocks_feedback_hash_drift(
    tmp_path: Path, monkeypatch: Any
) -> None:
    execution = _write_limited_feedback_execution_fixture(tmp_path, monkeypatch)
    execution_summary = json.loads(execution.read_text(encoding="utf-8"))
    feedback_receipt = Path(execution_summary["artifacts"]["feedback_receipt"]["path"])
    payload = json.loads(feedback_receipt.read_text(encoding="utf-8"))
    payload["passed"] = False
    feedback_receipt.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    summary = run_gate(
        limited_feedback_collection_execution_summary_path=execution,
        output_root=tmp_path / "limited_feedback_closeout_strategy",
        ack_strategy_review=True,
    )

    assert summary["passed"] is False
    assert "feedback_receipt_hash_valid" in summary["failure_reasons"]


def _write_limited_feedback_execution_fixture(tmp_path: Path, monkeypatch: Any) -> Path:
    decision = _write_limited_feedback_authorization_decision_fixture(tmp_path, monkeypatch)
    root = tmp_path / "limited_feedback_collection_execution_fixture"
    run_limited_feedback_collection_execution(
        limited_feedback_authorization_decision_summary_path=decision,
        output_root=root,
        feedback_text="External user feedback fixture: close out this limited feedback collection.",
        authorization_consumption_path=tmp_path / "limited_feedback_execution_consumption_lease.json",
        ack_feedback_collection=True,
    )
    return root / "post_h3_limited_feedback_collection_execution_summary.json"
