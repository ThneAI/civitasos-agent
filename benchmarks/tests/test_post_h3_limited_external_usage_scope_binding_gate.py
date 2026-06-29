from __future__ import annotations

from pathlib import Path
from typing import Any

from benchmarks.post_h3_external_user_identity_consent_gate import run_gate as run_post_h3u
from benchmarks.post_h3_limited_external_usage_scope_binding_gate import run_gate
from benchmarks.tests.post_h3_consent_test_fixtures import write_signed_consent_package
from benchmarks.tests.test_post_h3_external_user_identity_consent_gate import _write_post_h3t_fixture


def test_post_h3v_binds_limited_usage_scope_monitoring_and_rollback(tmp_path: Path, monkeypatch: Any) -> None:
    post_h3u = _write_post_h3u_fixture(tmp_path, monkeypatch)

    summary = run_gate(
        post_h3u_summary_path=post_h3u,
        output_root=tmp_path / "post_h3v",
        external_user_handle="external-user",
        ack_limited_usage_scope_binding=True,
    )

    assert summary["passed"] is True
    assert summary["limited_external_usage_scope_binding_id"]
    assert summary["readiness"]["limited_external_usage_scope_bound"] is True
    assert summary["readiness"]["external_user_task_scope_bound"] is True
    assert summary["readiness"]["external_user_monitoring_slo_bound"] is True
    assert summary["readiness"]["external_user_rollback_abort_owner_bound"] is True
    assert summary["readiness"]["external_user_usage_authorization_review_ready"] is True
    assert summary["readiness"]["external_user_usage_allowed"] is False
    assert summary["bounded_requirement_resolution"]["production_grade_public_ingress_required"] is False
    assert summary["remaining_requirements"] == []


def test_post_h3v_requires_explicit_scope_ack(tmp_path: Path, monkeypatch: Any) -> None:
    post_h3u = _write_post_h3u_fixture(tmp_path, monkeypatch)

    summary = run_gate(
        post_h3u_summary_path=post_h3u,
        output_root=tmp_path / "post_h3v",
        external_user_handle="external-user",
        ack_limited_usage_scope_binding=False,
    )

    assert summary["passed"] is False
    assert "explicit_operator_ack" in summary["failure_reasons"]
    assert summary["readiness"]["external_user_usage_authorization_review_ready"] is False


def test_post_h3v_blocks_more_than_one_external_user(tmp_path: Path, monkeypatch: Any) -> None:
    post_h3u = _write_post_h3u_fixture(tmp_path, monkeypatch)

    summary = run_gate(
        post_h3u_summary_path=post_h3u,
        output_root=tmp_path / "post_h3v",
        external_user_handle="external-user",
        max_external_users=2,
        ack_limited_usage_scope_binding=True,
    )

    assert summary["passed"] is False
    assert "max_external_users_one" in summary["failure_reasons"]


def test_post_h3v_requires_separate_monitoring_and_audit_owner(tmp_path: Path, monkeypatch: Any) -> None:
    post_h3u = _write_post_h3u_fixture(tmp_path, monkeypatch)

    summary = run_gate(
        post_h3u_summary_path=post_h3u,
        output_root=tmp_path / "post_h3v",
        external_user_handle="external-user",
        monitoring_owner="same-owner",
        audit_owner="same-owner",
        ack_limited_usage_scope_binding=True,
    )

    assert summary["passed"] is False
    assert "distinct_monitoring_and_audit" in summary["failure_reasons"]


def _write_post_h3u_fixture(tmp_path: Path, monkeypatch: Any) -> Path:
    post_h3t = _write_post_h3t_fixture(tmp_path, monkeypatch)
    package = write_signed_consent_package(tmp_path, handle="external-user")
    post_h3u_root = tmp_path / "post_h3u"
    run_post_h3u(
        post_h3t_summary_path=post_h3t,
        consent_path=package["consent"],
        signature_path=package["signature"],
        allowed_signers_path=package["allowed_signers"],
        identity_provider_keys_path=package["identity_provider_keys"],
        output_root=post_h3u_root,
        external_user_handle="external-user",
    )
    return post_h3u_root / "post_h3u_external_user_identity_consent_summary.json"
