from __future__ import annotations

from pathlib import Path
from typing import Any

from benchmarks.post_h3_runtime_expansion_authorization_gate import run_gate
from benchmarks.tests.test_post_h3_public_ingress_authorization_gate import _write_post_h3n_fixture


def test_post_h3p_authorizes_runtime_expansion_without_executing_it(tmp_path: Path, monkeypatch: Any) -> None:
    post_h3n = _write_post_h3n_fixture(tmp_path, monkeypatch)

    summary = run_gate(
        post_h3n_summary_path=post_h3n,
        output_root=tmp_path / "post_h3p",
        ack_runtime_expansion_authorization=True,
    )

    assert summary["passed"] is True
    assert summary["runtime_expansion_authorization_id"]
    assert summary["readiness"]["runtime_expansion_authorized"] is True
    assert summary["readiness"]["runtime_expansion_execution_ready"] is True
    assert summary["readiness"]["public_ingress_authorized"] is False
    assert summary["readiness"]["runtime_execution_performed"] is False
    assert summary["boundary"]["runtime_expansion_authorized"] is True
    assert summary["boundary"]["runtime_execution_performed"] is False
    assert summary["boundary"]["external_public_ingress_opened"] is False


def test_post_h3p_requires_explicit_runtime_expansion_ack(tmp_path: Path, monkeypatch: Any) -> None:
    post_h3n = _write_post_h3n_fixture(tmp_path, monkeypatch)

    summary = run_gate(
        post_h3n_summary_path=post_h3n,
        output_root=tmp_path / "post_h3p",
        ack_runtime_expansion_authorization=False,
    )

    assert summary["passed"] is False
    assert "explicit_operator_ack" in summary["failure_reasons"]
    assert summary["readiness"]["runtime_expansion_authorized"] is False


def test_post_h3p_blocks_unbounded_runtime_expansion(tmp_path: Path, monkeypatch: Any) -> None:
    post_h3n = _write_post_h3n_fixture(tmp_path, monkeypatch)

    summary = run_gate(
        post_h3n_summary_path=post_h3n,
        output_root=tmp_path / "post_h3p",
        max_runtime_agents=6,
        ack_runtime_expansion_authorization=True,
    )

    assert summary["passed"] is False
    assert "max_runtime_agents_bounded" in summary["failure_reasons"]
    assert summary["readiness"]["runtime_expansion_authorized"] is False
