from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from benchmarks.post_h3_external_user_feedback_closeout_gate import run_gate as run_post_h3aa
from benchmarks.post_h3_next_external_usage_strategy_review_gate import (
    ALLOWED_USAGE_SCOPE,
    AUTHORIZE_SECOND_USAGE_DECISION,
    SECOND_USAGE_AUDIT_DECISION,
    SECOND_USAGE_MONITORING_DECISION,
    SECOND_USAGE_ROLLBACK_DECISION,
    run_gate,
)
from benchmarks.tests.test_post_h3_external_user_feedback_closeout_gate import _write_post_h3z_fixture


def test_post_h3ab_continues_observer_mode_by_default(tmp_path: Path, monkeypatch: Any) -> None:
    post_h3aa = _write_post_h3aa_fixture(tmp_path, monkeypatch)

    summary = run_gate(
        post_h3aa_summary_path=post_h3aa,
        output_root=tmp_path / "post_h3ab",
        ack_strategy_review=True,
    )

    assert summary["passed"] is True
    assert summary["next_external_usage_strategy_review_id"]
    assert summary["readiness"]["next_external_usage_strategy_review_complete"] is True
    assert summary["readiness"]["observer_mode_continues"] is True
    assert summary["readiness"]["second_external_user_usage_execution_ready"] is False
    assert summary["readiness"]["external_user_feedback_collection_ready"] is False
    assert summary["readiness"]["external_user_usage_allowed"] is False
    assert summary["readiness"]["runtime_execution_performed"] is False


def test_post_h3ab_requires_explicit_strategy_ack(tmp_path: Path, monkeypatch: Any) -> None:
    post_h3aa = _write_post_h3aa_fixture(tmp_path, monkeypatch)

    summary = run_gate(
        post_h3aa_summary_path=post_h3aa,
        output_root=tmp_path / "post_h3ab",
        ack_strategy_review=False,
    )

    assert summary["passed"] is False
    assert "explicit_operator_ack" in summary["failure_reasons"]
    assert summary["readiness"]["next_external_usage_strategy_review_complete"] is False


def test_post_h3ab_can_prepare_second_usage_authorization_once(tmp_path: Path, monkeypatch: Any) -> None:
    post_h3aa = _write_post_h3aa_fixture(tmp_path, monkeypatch)

    summary = run_gate(
        post_h3aa_summary_path=post_h3aa,
        output_root=tmp_path / "post_h3ab",
        operator_decision=AUTHORIZE_SECOND_USAGE_DECISION,
        audit_decision=SECOND_USAGE_AUDIT_DECISION,
        monitoring_decision=SECOND_USAGE_MONITORING_DECISION,
        rollback_decision=SECOND_USAGE_ROLLBACK_DECISION,
        operator_statement="Prepare one more bounded invite-only status/read-only external usage after feedback closeout; execution remains a separate gate.",
        max_external_users=1,
        requested_usage_scope=ALLOWED_USAGE_SCOPE,
        ack_strategy_review=True,
    )

    assert summary["passed"] is True
    assert summary["second_external_user_usage_allowed"] is True
    assert summary["readiness"]["second_external_user_usage_execution_ready"] is True
    assert summary["readiness"]["external_public_ingress_opened"] is False
    assert summary["readiness"]["runtime_execution_performed"] is False


def test_post_h3ab_blocks_aa_evidence_index_hash_drift(tmp_path: Path, monkeypatch: Any) -> None:
    post_h3aa = _write_post_h3aa_fixture(tmp_path, monkeypatch)
    evidence_index = tmp_path / "post_h3aa" / "post_h3aa_external_user_feedback_evidence_index.json"
    payload = json.loads(evidence_index.read_text(encoding="utf-8"))
    payload["passed"] = False
    evidence_index.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    summary = run_gate(
        post_h3aa_summary_path=post_h3aa,
        output_root=tmp_path / "post_h3ab",
        ack_strategy_review=True,
    )

    assert summary["passed"] is False
    assert "post_h3aa_evidence_index_hash_valid" in summary["failure_reasons"]


def _write_post_h3aa_fixture(tmp_path: Path, monkeypatch: Any) -> Path:
    post_h3z = _write_post_h3z_fixture(tmp_path, monkeypatch)
    post_h3aa_root = tmp_path / "post_h3aa"
    run_post_h3aa(
        post_h3z_summary_path=post_h3z,
        output_root=post_h3aa_root,
        ack_feedback_closeout=True,
    )
    return post_h3aa_root / "post_h3aa_external_user_feedback_closeout_summary.json"
