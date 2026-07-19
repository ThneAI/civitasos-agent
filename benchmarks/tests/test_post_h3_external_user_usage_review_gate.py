from __future__ import annotations

from pathlib import Path
from typing import Any

from benchmarks.post_h3_external_user_identity_consent_gate import run_gate as run_post_h3u
from benchmarks.post_h3_external_user_usage_review_gate import AUTHORIZE_ONCE_DECISION, run_gate
from benchmarks.post_h3_limited_external_usage_scope_binding_gate import run_gate as run_post_h3v
from benchmarks.post_h3_qr_execution_closeout_gate import run_gate as run_post_h3s
from benchmarks.tests.post_h3_consent_test_fixtures import write_signed_consent_package
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


def test_post_h3t_blocks_authorization_without_u_v_evidence(tmp_path: Path, monkeypatch: Any) -> None:
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

    assert summary["passed"] is False
    assert "identity_consent_evidence_valid" in summary["failure_reasons"]
    assert "usage_scope_evidence_valid" in summary["failure_reasons"]
    assert summary["external_user_usage_allowed"] is False


def test_post_h3t_can_record_one_time_usage_allowance_with_u_v_evidence(tmp_path: Path, monkeypatch: Any) -> None:
    post_h3s = _write_post_h3s_fixture(tmp_path, monkeypatch)
    post_h3u = _write_post_h3u_fixture(tmp_path, monkeypatch, post_h3s)
    post_h3v = _write_post_h3v_fixture(tmp_path, post_h3u)

    summary = run_gate(
        post_h3s_summary_path=post_h3s,
        post_h3u_summary_path=post_h3u,
        post_h3v_summary_path=post_h3v,
        output_root=tmp_path / "post_h3t_authorized",
        operator_decision=AUTHORIZE_ONCE_DECISION,
        audit_decision="accept_limited_external_user_usage_once",
        monitoring_decision="accept_limited_external_user_monitoring_once",
        rollback_decision="accept_limited_external_user_abort_runbook_once",
        operator_statement="Authorize one limited external user usage review result; no execution in this gate.",
        max_external_users=1,
        allowed_usage_scope="invite-only-status-read-only-task",
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


def _write_post_h3u_fixture(tmp_path: Path, monkeypatch: Any, post_h3s: Path) -> Path:
    post_h3t_root = tmp_path / "post_h3t_revision_for_u"
    run_gate(
        post_h3s_summary_path=post_h3s,
        output_root=post_h3t_root,
        ack_external_user_usage_review=True,
    )
    package = write_signed_consent_package(tmp_path, handle="external-user")
    post_h3u_root = tmp_path / "post_h3u"
    run_post_h3u(
        post_h3t_summary_path=post_h3t_root / "post_h3t_external_user_usage_review_summary.json",
        consent_path=package["consent"],
        signature_path=package["signature"],
        allowed_signers_path=package["allowed_signers"],
        identity_provider_keys_path=package["identity_provider_keys"],
        output_root=post_h3u_root,
        external_user_handle="external-user",
    )
    return post_h3u_root / "post_h3u_external_user_identity_consent_summary.json"


def _write_post_h3v_fixture(tmp_path: Path, post_h3u: Path) -> Path:
    post_h3v_root = tmp_path / "post_h3v"
    run_post_h3v(
        post_h3u_summary_path=post_h3u,
        output_root=post_h3v_root,
        external_user_handle="external-user",
        ack_limited_usage_scope_binding=True,
    )
    return post_h3v_root / "post_h3v_limited_external_usage_scope_binding_summary.json"
