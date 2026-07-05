from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from benchmarks.post_h3_external_user_usage_closeout_gate import run_gate as run_post_h3x
from benchmarks.post_h3_next_external_usage_review_gate import (
    ALLOWED_USAGE_SCOPE,
    AUTHORIZE_SECOND_USAGE_ONCE_DECISION,
    FEEDBACK_ONLY_SCOPE,
    AUTHORIZE_FEEDBACK_COLLECTION_ONCE_DECISION,
    FEEDBACK_AUDIT_DECISION,
    FEEDBACK_MONITORING_DECISION,
    FEEDBACK_ROLLBACK_DECISION,
    SECOND_USAGE_AUDIT_DECISION,
    SECOND_USAGE_MONITORING_DECISION,
    SECOND_USAGE_ROLLBACK_DECISION,
    run_gate,
)
from benchmarks.tests.test_post_h3_external_user_usage_closeout_gate import _write_post_h3w_fixture


def test_post_h3y_requests_followup_review_by_default(tmp_path: Path, monkeypatch: Any) -> None:
    post_h3x = _write_post_h3x_fixture(tmp_path, monkeypatch)

    summary = run_gate(
        post_h3x_summary_path=post_h3x,
        output_root=tmp_path / "post_h3y",
        ack_next_external_usage_review=True,
    )

    assert summary["passed"] is True
    assert summary["next_external_usage_review_id"]
    assert summary["readiness"]["next_external_usage_review_complete"] is True
    assert summary["readiness"]["second_limited_usage_authorized"] is False
    assert summary["readiness"]["external_user_feedback_collection_ready"] is False
    assert summary["readiness"]["external_user_usage_allowed"] is False
    assert summary["readiness"]["runtime_execution_performed"] is False


def test_post_h3y_requires_explicit_review_ack(tmp_path: Path, monkeypatch: Any) -> None:
    post_h3x = _write_post_h3x_fixture(tmp_path, monkeypatch)

    summary = run_gate(
        post_h3x_summary_path=post_h3x,
        output_root=tmp_path / "post_h3y",
        ack_next_external_usage_review=False,
    )

    assert summary["passed"] is False
    assert "explicit_operator_ack" in summary["failure_reasons"]
    assert summary["readiness"]["second_limited_usage_authorized"] is False


def test_post_h3y_can_authorize_second_limited_usage_once(tmp_path: Path, monkeypatch: Any) -> None:
    post_h3x = _write_post_h3x_fixture(tmp_path, monkeypatch)

    summary = run_gate(
        post_h3x_summary_path=post_h3x,
        output_root=tmp_path / "post_h3y",
        operator_decision=AUTHORIZE_SECOND_USAGE_ONCE_DECISION,
        audit_decision=SECOND_USAGE_AUDIT_DECISION,
        monitoring_decision=SECOND_USAGE_MONITORING_DECISION,
        rollback_decision=SECOND_USAGE_ROLLBACK_DECISION,
        operator_statement="Authorize one more bounded invite-only status/read-only external usage; execution remains a separate gate.",
        max_external_users=1,
        requested_usage_scope=ALLOWED_USAGE_SCOPE,
        ack_next_external_usage_review=True,
    )

    assert summary["passed"] is True
    assert summary["second_external_user_usage_allowed"] is True
    assert summary["external_user_feedback_collection_allowed"] is False
    assert summary["readiness"]["second_external_user_usage_execution_ready"] is True
    assert summary["readiness"]["external_public_ingress_opened"] is False
    assert summary["readiness"]["runtime_execution_performed"] is False


def test_post_h3y_can_authorize_feedback_collection_once(tmp_path: Path, monkeypatch: Any) -> None:
    post_h3x = _write_post_h3x_fixture(tmp_path, monkeypatch)

    summary = run_gate(
        post_h3x_summary_path=post_h3x,
        output_root=tmp_path / "post_h3y_feedback",
        operator_decision=AUTHORIZE_FEEDBACK_COLLECTION_ONCE_DECISION,
        audit_decision=FEEDBACK_AUDIT_DECISION,
        monitoring_decision=FEEDBACK_MONITORING_DECISION,
        rollback_decision=FEEDBACK_ROLLBACK_DECISION,
        operator_statement="Authorize one feedback-only collection step; no second usage execution in this gate.",
        max_external_users=1,
        requested_usage_scope=FEEDBACK_ONLY_SCOPE,
        ack_next_external_usage_review=True,
    )

    assert summary["passed"] is True
    assert summary["second_external_user_usage_allowed"] is False
    assert summary["external_user_feedback_collection_allowed"] is True
    assert summary["readiness"]["external_user_feedback_collection_ready"] is True
    assert summary["readiness"]["external_user_usage_allowed"] is False


def test_post_h3y_blocks_x_evidence_index_hash_drift(tmp_path: Path, monkeypatch: Any) -> None:
    post_h3x = _write_post_h3x_fixture(tmp_path, monkeypatch)
    evidence_index = tmp_path / "post_h3x" / "post_h3x_external_user_usage_evidence_index.json"
    payload = json.loads(evidence_index.read_text(encoding="utf-8"))
    payload["passed"] = False
    evidence_index.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    summary = run_gate(
        post_h3x_summary_path=post_h3x,
        output_root=tmp_path / "post_h3y",
        ack_next_external_usage_review=True,
    )

    assert summary["passed"] is False
    assert "post_h3x_evidence_index_hash_valid" in summary["failure_reasons"]


def _write_post_h3x_fixture(tmp_path: Path, monkeypatch: Any) -> Path:
    post_h3w = _write_post_h3w_fixture(tmp_path, monkeypatch)
    post_h3x_root = tmp_path / "post_h3x"
    run_post_h3x(
        post_h3w_summary_path=post_h3w,
        output_root=post_h3x_root,
        ack_external_user_usage_closeout=True,
    )
    return post_h3x_root / "post_h3x_external_user_usage_closeout_summary.json"
