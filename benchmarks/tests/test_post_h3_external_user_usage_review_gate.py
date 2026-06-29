from __future__ import annotations

from pathlib import Path
from typing import Any

from benchmarks.post_h3_external_user_usage_review_gate import AUTHORIZE_ONCE_DECISION, REQUEST_REVISION_DECISION, run_gate
from benchmarks.post_h3_qr_execution_closeout_gate import run_gate as run_post_h3s
from benchmarks.tests.test_post_h3_qr_execution_closeout_gate import _write_post_h3q_r_fixtures


def test_post_h3t_requests_revision_by_default(tmp_path: Path, monkeypatch: Any) -> None:
    post_h3s = _write_post_h3s_fixture(tmp_path, monkeypatch)

    summary = run_gate(
        post_h3s_summary_path=post_h3s,
        output_root=tmp_path / "post_h3t",
        ack_external_user_usage_review=True,
    )

    assert summary["passed"] is True
    assert summary["external_user_usage_allowed"] is False
    assert summary["readiness"]["external_user_usage_review_complete"] is True
    assert summary["readiness"]["external_user_usage_revision_required"] is True
    assert summary["readiness"]["external_public_ingress_opened"] is False
    assert summary["readiness"]["runtime_execution_performed"] is False


def test_post_h3t_requires_explicit_review_ack(tmp_path: Path, monkeypatch: Any) -> None:
    post_h3s = _write_post_h3s_fixture(tmp_path, monkeypatch)

    summary = run_gate(
        post_h3s_summary_path=post_h3s,
        output_root=tmp_path / "post_h3t",
        ack_external_user_usage_review=False,
    )

    assert summary["passed"] is False
    assert "explicit_operator_ack" in summary["failure_reasons"]
    assert summary["readiness"]["external_user_usage_allowed"] is False


def test_post_h3t_can_record_one_time_usage_allowance_without_execution(tmp_path: Path, monkeypatch: Any) -> None:
    post_h3s = _write_post_h3s_fixture(tmp_path, monkeypatch)

    summary = run_gate(
        post_h3s_summary_path=post_h3s,
        output_root=tmp_path / "post_h3t",
        operator_decision=AUTHORIZE_ONCE_DECISION,
        audit_decision="accept_limited_external_user_usage_once",
        monitoring_decision="accept_limited_external_user_monitoring_once",
        rollback_decision="accept_limited_external_user_abort_runbook_once",
        operator_statement="Authorize one limited external user usage review result; no execution in this gate.",
        max_external_users=1,
        allowed_usage_scope="invite-only-status-task",
        ack_external_user_usage_review=True,
    )

    assert summary["passed"] is True
    assert summary["external_user_usage_allowed"] is True
    assert summary["readiness"]["external_user_usage_execution_ready"] is True
    assert summary["readiness"]["external_public_ingress_opened"] is False
    assert summary["readiness"]["runtime_execution_performed"] is False
    assert summary["boundary"]["external_user_usage_allowed"] is True


def test_post_h3t_blocks_allowance_without_usage_scope(tmp_path: Path, monkeypatch: Any) -> None:
    post_h3s = _write_post_h3s_fixture(tmp_path, monkeypatch)

    summary = run_gate(
        post_h3s_summary_path=post_h3s,
        output_root=tmp_path / "post_h3t",
        operator_decision=AUTHORIZE_ONCE_DECISION,
        audit_decision="accept_limited_external_user_usage_once",
        monitoring_decision="accept_limited_external_user_monitoring_once",
        rollback_decision="accept_limited_external_user_abort_runbook_once",
        max_external_users=1,
        allowed_usage_scope="none",
        ack_external_user_usage_review=True,
    )

    assert summary["passed"] is False
    assert "allowed_usage_scope_present" in summary["failure_reasons"]
    assert summary["external_user_usage_allowed"] is False


def _write_post_h3s_fixture(tmp_path: Path, monkeypatch: Any) -> Path:
    post_h3q, post_h3r = _write_post_h3q_r_fixtures(tmp_path, monkeypatch)
    post_h3s_root = tmp_path / "post_h3s"
    run_post_h3s(
        post_h3q_summary_path=post_h3q,
        post_h3r_summary_path=post_h3r,
        output_root=post_h3s_root,
        ack_qr_execution_closeout=True,
    )
    return post_h3s_root / "post_h3s_qr_execution_closeout_summary.json"
