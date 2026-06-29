from __future__ import annotations

from pathlib import Path
from typing import Any

from benchmarks.post_h3_external_user_identity_consent_gate import run_gate as run_post_h3u
from benchmarks.post_h3_external_user_usage_execution_gate import run_gate
from benchmarks.post_h3_external_user_usage_review_gate import AUTHORIZE_ONCE_DECISION, run_gate as run_post_h3t
from benchmarks.post_h3_limited_external_usage_scope_binding_gate import run_gate as run_post_h3v
from benchmarks.tests.post_h3_consent_test_fixtures import write_signed_consent_package
from benchmarks.tests.test_post_h3_external_user_usage_review_gate import _write_post_h3s_fixture


def test_post_h3w_executes_one_limited_external_user_usage(tmp_path: Path, monkeypatch: Any) -> None:
    post_h3t, post_h3v = _write_post_h3t_v_authorized_fixture(tmp_path, monkeypatch)

    summary = run_gate(
        post_h3t_summary_path=post_h3t,
        post_h3v_summary_path=post_h3v,
        output_root=tmp_path / "post_h3w",
        external_user_handle="external-user",
        ack_external_user_usage_execution=True,
    )

    assert summary["passed"] is True
    assert summary["external_user_usage_execution_id"]
    assert summary["readiness"]["external_user_usage_execution_complete"] is True
    assert summary["readiness"]["external_user_usage_authorization_consumed"] is True
    assert summary["readiness"]["external_user_usage_performed"] is True
    assert summary["readiness"]["external_user_usage_closed"] is True
    assert summary["readiness"]["runtime_execution_performed"] is False
    assert summary["readiness"]["production_runtime_receipt_write_allowed"] is False
    assert summary["boundary"]["external_public_ingress_opened"] is False


def test_post_h3w_requires_explicit_execution_ack(tmp_path: Path, monkeypatch: Any) -> None:
    post_h3t, post_h3v = _write_post_h3t_v_authorized_fixture(tmp_path, monkeypatch)

    summary = run_gate(
        post_h3t_summary_path=post_h3t,
        post_h3v_summary_path=post_h3v,
        output_root=tmp_path / "post_h3w",
        external_user_handle="external-user",
        ack_external_user_usage_execution=False,
    )

    assert summary["passed"] is False
    assert "explicit_operator_ack" in summary["failure_reasons"]
    assert summary["readiness"]["external_user_usage_performed"] is False


def test_post_h3w_blocks_user_mismatch(tmp_path: Path, monkeypatch: Any) -> None:
    post_h3t, post_h3v = _write_post_h3t_v_authorized_fixture(tmp_path, monkeypatch)

    summary = run_gate(
        post_h3t_summary_path=post_h3t,
        post_h3v_summary_path=post_h3v,
        output_root=tmp_path / "post_h3w",
        external_user_handle="different-user",
        ack_external_user_usage_execution=True,
    )

    assert summary["passed"] is False
    assert "external_user_handle_matches" in summary["failure_reasons"]


def test_post_h3w_blocks_replay_of_same_t_authorization(tmp_path: Path, monkeypatch: Any) -> None:
    post_h3t, post_h3v = _write_post_h3t_v_authorized_fixture(tmp_path, monkeypatch)

    first = run_gate(
        post_h3t_summary_path=post_h3t,
        post_h3v_summary_path=post_h3v,
        output_root=tmp_path / "post_h3w_first",
        external_user_handle="external-user",
        ack_external_user_usage_execution=True,
    )
    second = run_gate(
        post_h3t_summary_path=post_h3t,
        post_h3v_summary_path=post_h3v,
        output_root=tmp_path / "post_h3w_second",
        external_user_handle="external-user",
        ack_external_user_usage_execution=True,
    )

    assert first["passed"] is True
    assert second["passed"] is False
    assert any("external_user_usage_authorization_already_consumed" in item for item in second["failure_reasons"])


def _write_post_h3t_v_authorized_fixture(tmp_path: Path, monkeypatch: Any) -> tuple[Path, Path]:
    post_h3s = _write_post_h3s_fixture(tmp_path, monkeypatch)
    post_h3t_revision_root = tmp_path / "post_h3t_revision"
    run_post_h3t(
        post_h3s_summary_path=post_h3s,
        output_root=post_h3t_revision_root,
        ack_external_user_usage_review=True,
    )
    package = write_signed_consent_package(tmp_path, handle="external-user")
    post_h3u_root = tmp_path / "post_h3u"
    run_post_h3u(
        post_h3t_summary_path=post_h3t_revision_root / "post_h3t_external_user_usage_review_summary.json",
        consent_path=package["consent"],
        signature_path=package["signature"],
        allowed_signers_path=package["allowed_signers"],
        identity_provider_keys_path=package["identity_provider_keys"],
        output_root=post_h3u_root,
        external_user_handle="external-user",
    )
    post_h3v_root = tmp_path / "post_h3v"
    run_post_h3v(
        post_h3u_summary_path=post_h3u_root / "post_h3u_external_user_identity_consent_summary.json",
        output_root=post_h3v_root,
        external_user_handle="external-user",
        ack_limited_usage_scope_binding=True,
    )
    post_h3t_authorized_root = tmp_path / "post_h3t_authorized"
    run_post_h3t(
        post_h3s_summary_path=post_h3s,
        post_h3u_summary_path=post_h3u_root / "post_h3u_external_user_identity_consent_summary.json",
        post_h3v_summary_path=post_h3v_root / "post_h3v_limited_external_usage_scope_binding_summary.json",
        output_root=post_h3t_authorized_root,
        operator_decision=AUTHORIZE_ONCE_DECISION,
        audit_decision="accept_limited_external_user_usage_once",
        monitoring_decision="accept_limited_external_user_monitoring_once",
        rollback_decision="accept_limited_external_user_abort_runbook_once",
        max_external_users=1,
        allowed_usage_scope="invite-only-status-read-only-task",
        ack_external_user_usage_review=True,
    )
    return (
        post_h3t_authorized_root / "post_h3t_external_user_usage_review_summary.json",
        post_h3v_root / "post_h3v_limited_external_usage_scope_binding_summary.json",
    )
