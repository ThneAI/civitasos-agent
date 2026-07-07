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
from benchmarks.post_h3_limited_feedback_higher_permission_review_request_gate import run_gate
from benchmarks.tests.test_post_h3_limited_feedback_closeout_strategy_gate import (
    _write_limited_feedback_execution_fixture,
)


def test_limited_feedback_higher_permission_review_request_consumes_strategy_without_authorization(
    tmp_path: Path, monkeypatch: Any
) -> None:
    strategy = _write_higher_permission_strategy_fixture(tmp_path, monkeypatch)

    summary = run_gate(
        limited_feedback_closeout_strategy_summary_path=strategy,
        output_root=tmp_path / "higher_permission_review_request",
        operator_statement="Request higher permission review only; no execution.",
        ack_review_request=True,
    )

    assert summary["passed"] is True
    assert summary["readiness"]["higher_permission_review_request_complete"] is True
    assert summary["readiness"]["higher_permission_review_ready"] is True
    assert summary["readiness"]["authorization_granted"] is False
    assert summary["readiness"]["execution_authorization_ready"] is False
    assert summary["readiness"]["external_user_usage_allowed"] is False
    assert summary["readiness"]["public_ingress_authorized"] is False
    assert summary["readiness"]["runtime_expansion_authorized"] is False
    assert summary["readiness"]["production_runtime_receipt_write_allowed"] is False
    assert summary["boundary"]["higher_permission_review_ready"] is True
    assert summary["boundary"]["external_public_ingress_opened"] is False
    assert summary["boundary"]["runtime_execution_performed"] is False
    assert summary["boundary"]["source_tree_write_performed"] is False
    assert summary["boundary"]["git_write_performed"] is False


def test_limited_feedback_higher_permission_review_request_requires_ack(
    tmp_path: Path, monkeypatch: Any
) -> None:
    strategy = _write_higher_permission_strategy_fixture(tmp_path, monkeypatch)

    summary = run_gate(
        limited_feedback_closeout_strategy_summary_path=strategy,
        output_root=tmp_path / "higher_permission_review_request",
        ack_review_request=False,
    )

    assert summary["passed"] is False
    assert "explicit_higher_permission_review_request_ack" in summary["failure_reasons"]
    assert summary["readiness"]["higher_permission_review_ready"] is False


def test_limited_feedback_higher_permission_review_request_blocks_observer_strategy(
    tmp_path: Path, monkeypatch: Any
) -> None:
    execution = _write_limited_feedback_execution_fixture(tmp_path, monkeypatch)
    observer = tmp_path / "observer_strategy"
    run_closeout_strategy(
        limited_feedback_collection_execution_summary_path=execution,
        output_root=observer,
        ack_strategy_review=True,
    )

    summary = run_gate(
        limited_feedback_closeout_strategy_summary_path=observer / "post_h3_limited_feedback_closeout_strategy_summary.json",
        output_root=tmp_path / "higher_permission_review_request",
        ack_review_request=True,
    )

    assert summary["passed"] is False
    assert "summary_requests_higher_permission" in summary["failure_reasons"]
    assert "summary_higher_permission_ready" in summary["failure_reasons"]
    assert summary["readiness"]["higher_permission_review_ready"] is False


def test_limited_feedback_higher_permission_review_request_blocks_hash_drift(
    tmp_path: Path, monkeypatch: Any
) -> None:
    strategy = _write_higher_permission_strategy_fixture(tmp_path, monkeypatch)
    strategy_summary = json.loads(strategy.read_text(encoding="utf-8"))
    reconciliation_path = Path(strategy_summary["artifacts"]["strategy_reconciliation"]["path"])
    reconciliation = json.loads(reconciliation_path.read_text(encoding="utf-8"))
    reconciliation["operator_statement"] = "tampered after hash ref"
    reconciliation_path.write_text(
        json.dumps(reconciliation, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    summary = run_gate(
        limited_feedback_closeout_strategy_summary_path=strategy,
        output_root=tmp_path / "higher_permission_review_request",
        ack_review_request=True,
    )

    assert summary["passed"] is False
    assert "closeout_strategy_reconciliation_hash_valid" in summary["failure_reasons"]


def _write_higher_permission_strategy_fixture(tmp_path: Path, monkeypatch: Any) -> Path:
    execution = _write_limited_feedback_execution_fixture(tmp_path, monkeypatch)
    root = tmp_path / "higher_permission_strategy"
    run_closeout_strategy(
        limited_feedback_collection_execution_summary_path=execution,
        output_root=root,
        operator_decision=REQUEST_HIGHER_PERMISSION_DECISION,
        audit_decision=HIGHER_PERMISSION_AUDIT_DECISION,
        monitoring_decision=HIGHER_PERMISSION_MONITORING_DECISION,
        rollback_decision=HIGHER_PERMISSION_ROLLBACK_DECISION,
        operator_statement="Prepare higher-permission review request only; do not grant execution.",
        ack_strategy_review=True,
    )
    return root / "post_h3_limited_feedback_closeout_strategy_summary.json"
