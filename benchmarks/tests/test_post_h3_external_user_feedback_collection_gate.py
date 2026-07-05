from __future__ import annotations

from pathlib import Path
from typing import Any

from benchmarks.post_h3_external_user_feedback_collection_gate import FEEDBACK_ONLY_SCOPE, run_gate
from benchmarks.post_h3_external_user_usage_closeout_gate import run_gate as run_post_h3x
from benchmarks.post_h3_next_external_usage_review_gate import (
    AUTHORIZE_FEEDBACK_COLLECTION_ONCE_DECISION,
    FEEDBACK_AUDIT_DECISION,
    FEEDBACK_MONITORING_DECISION,
    FEEDBACK_ROLLBACK_DECISION,
    run_gate as run_post_h3y,
)
from benchmarks.tests.test_post_h3_external_user_usage_closeout_gate import _write_post_h3w_fixture


def test_post_h3z_collects_one_feedback_record(tmp_path: Path, monkeypatch: Any) -> None:
    post_h3y = _write_feedback_authorized_post_h3y_fixture(tmp_path, monkeypatch)

    summary = run_gate(
        post_h3y_summary_path=post_h3y,
        output_root=tmp_path / "post_h3z",
        external_user_handle="external-user",
        feedback_scope=FEEDBACK_ONLY_SCOPE,
        feedback_text="External user requests feedback-only collection before any second limited usage.",
        feedback_source="test_external_user_feedback",
        ack_feedback_collection=True,
    )

    assert summary["passed"] is True
    assert summary["external_user_feedback_collection_id"]
    assert summary["readiness"]["external_user_feedback_collection_complete"] is True
    assert summary["readiness"]["feedback_authorization_consumed"] is True
    assert summary["readiness"]["feedback_receipt_written"] is True
    assert summary["readiness"]["second_external_user_usage_execution_ready"] is False
    assert summary["readiness"]["external_user_usage_allowed"] is False
    assert summary["readiness"]["runtime_execution_performed"] is False
    assert summary["boundary"]["external_user_usage_performed"] is False


def test_post_h3z_requires_explicit_feedback_ack(tmp_path: Path, monkeypatch: Any) -> None:
    post_h3y = _write_feedback_authorized_post_h3y_fixture(tmp_path, monkeypatch)

    summary = run_gate(
        post_h3y_summary_path=post_h3y,
        output_root=tmp_path / "post_h3z",
        external_user_handle="external-user",
        feedback_text="External user requests feedback-only collection before second usage.",
        ack_feedback_collection=False,
    )

    assert summary["passed"] is False
    assert "explicit_operator_ack" in summary["failure_reasons"]
    assert summary["readiness"]["external_user_feedback_collection_complete"] is False


def test_post_h3z_blocks_y_without_feedback_authorization(tmp_path: Path, monkeypatch: Any) -> None:
    post_h3x = _write_post_h3x_fixture(tmp_path, monkeypatch)
    post_h3y_root = tmp_path / "post_h3y_followup"
    run_post_h3y(
        post_h3x_summary_path=post_h3x,
        output_root=post_h3y_root,
        ack_next_external_usage_review=True,
    )

    summary = run_gate(
        post_h3y_summary_path=post_h3y_root / "post_h3y_next_external_usage_review_summary.json",
        output_root=tmp_path / "post_h3z",
        external_user_handle="external-user",
        feedback_text="External user requests feedback-only collection before second usage.",
        ack_feedback_collection=True,
    )

    assert summary["passed"] is False
    assert "post_h3y_feedback_ready" in summary["failure_reasons"]
    assert "y_feedback_allowed" in summary["failure_reasons"]


def test_post_h3z_blocks_replay_of_same_feedback_authorization(tmp_path: Path, monkeypatch: Any) -> None:
    post_h3y = _write_feedback_authorized_post_h3y_fixture(tmp_path, monkeypatch)

    first = run_gate(
        post_h3y_summary_path=post_h3y,
        output_root=tmp_path / "post_h3z_first",
        external_user_handle="external-user",
        feedback_text="External user requests feedback-only collection before second usage.",
        ack_feedback_collection=True,
    )
    second = run_gate(
        post_h3y_summary_path=post_h3y,
        output_root=tmp_path / "post_h3z_second",
        external_user_handle="external-user",
        feedback_text="External user requests feedback-only collection before second usage.",
        ack_feedback_collection=True,
    )

    assert first["passed"] is True
    assert second["passed"] is False
    assert any("external_user_feedback_authorization_already_consumed" in item for item in second["failure_reasons"])


def test_post_h3z_blocks_feedback_with_forbidden_token(tmp_path: Path, monkeypatch: Any) -> None:
    post_h3y = _write_feedback_authorized_post_h3y_fixture(tmp_path, monkeypatch)

    summary = run_gate(
        post_h3y_summary_path=post_h3y,
        output_root=tmp_path / "post_h3z",
        external_user_handle="external-user",
        feedback_text="This should fail because it includes sk-test-secret-token.",
        ack_feedback_collection=True,
    )

    assert summary["passed"] is False
    assert "feedback_has_no_forbidden_tokens" in summary["failure_reasons"]


def _write_feedback_authorized_post_h3y_fixture(tmp_path: Path, monkeypatch: Any) -> Path:
    post_h3x = _write_post_h3x_fixture(tmp_path, monkeypatch)
    post_h3y_root = tmp_path / "post_h3y_feedback"
    run_post_h3y(
        post_h3x_summary_path=post_h3x,
        output_root=post_h3y_root,
        operator_decision=AUTHORIZE_FEEDBACK_COLLECTION_ONCE_DECISION,
        audit_decision=FEEDBACK_AUDIT_DECISION,
        monitoring_decision=FEEDBACK_MONITORING_DECISION,
        rollback_decision=FEEDBACK_ROLLBACK_DECISION,
        operator_statement="Authorize one feedback-only collection step; no second usage execution in this gate.",
        max_external_users=1,
        requested_usage_scope=FEEDBACK_ONLY_SCOPE,
        ack_next_external_usage_review=True,
    )
    return post_h3y_root / "post_h3y_next_external_usage_review_summary.json"


def _write_post_h3x_fixture(tmp_path: Path, monkeypatch: Any) -> Path:
    post_h3w = _write_post_h3w_fixture(tmp_path, monkeypatch)
    post_h3x_root = tmp_path / "post_h3x"
    run_post_h3x(
        post_h3w_summary_path=post_h3w,
        output_root=post_h3x_root,
        ack_external_user_usage_closeout=True,
    )
    return post_h3x_root / "post_h3x_external_user_usage_closeout_summary.json"
