from __future__ import annotations

from pathlib import Path
from typing import Any

from benchmarks.post_h3_external_release_closeout_gate import run_gate as run_post_h3n
from benchmarks.post_h3_public_ingress_authorization_gate import run_gate
from benchmarks.tests.test_post_h3_external_release_closeout_gate import _write_post_h3m_fixture


def test_post_h3o_authorizes_public_ingress_without_opening_it(tmp_path: Path, monkeypatch: Any) -> None:
    post_h3n = _write_post_h3n_fixture(tmp_path, monkeypatch)

    summary = run_gate(
        post_h3n_summary_path=post_h3n,
        output_root=tmp_path / "post_h3o",
        ack_public_ingress_authorization=True,
    )

    assert summary["passed"] is True
    assert summary["public_ingress_authorization_id"]
    assert summary["readiness"]["public_ingress_authorized"] is True
    assert summary["readiness"]["public_ingress_execution_ready"] is True
    assert summary["readiness"]["runtime_expansion_authorized"] is False
    assert summary["readiness"]["external_public_ingress_opened"] is False
    assert summary["boundary"]["public_ingress_authorized"] is True
    assert summary["boundary"]["external_public_ingress_opened"] is False
    assert summary["boundary"]["runtime_execution_performed"] is False


def test_post_h3o_requires_explicit_public_ingress_ack(tmp_path: Path, monkeypatch: Any) -> None:
    post_h3n = _write_post_h3n_fixture(tmp_path, monkeypatch)

    summary = run_gate(
        post_h3n_summary_path=post_h3n,
        output_root=tmp_path / "post_h3o",
        ack_public_ingress_authorization=False,
    )

    assert summary["passed"] is False
    assert "explicit_operator_ack" in summary["failure_reasons"]
    assert summary["readiness"]["public_ingress_authorized"] is False


def test_post_h3o_blocks_unbounded_public_scope(tmp_path: Path, monkeypatch: Any) -> None:
    post_h3n = _write_post_h3n_fixture(tmp_path, monkeypatch)

    summary = run_gate(
        post_h3n_summary_path=post_h3n,
        output_root=tmp_path / "post_h3o",
        allowed_ingress_scope="*",
        ack_public_ingress_authorization=True,
    )

    assert summary["passed"] is False
    assert "allowed_ingress_scope_not_public_wildcard" in summary["failure_reasons"]
    assert summary["readiness"]["public_ingress_authorized"] is False


def _write_post_h3n_fixture(tmp_path: Path, monkeypatch: Any) -> Path:
    post_h3m = _write_post_h3m_fixture(tmp_path, monkeypatch)
    post_h3n_root = tmp_path / "post_h3n"
    run_post_h3n(
        post_h3m_summary_path=post_h3m,
        output_root=post_h3n_root,
        ack_external_release_closeout=True,
    )
    return post_h3n_root / "post_h3n_external_release_closeout_summary.json"
