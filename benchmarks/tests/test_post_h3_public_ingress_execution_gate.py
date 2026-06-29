from __future__ import annotations

from pathlib import Path
from typing import Any

from benchmarks.post_h3_public_ingress_authorization_gate import run_gate as run_post_h3o
from benchmarks.post_h3_public_ingress_execution_gate import run_gate
from benchmarks.tests.test_post_h3_public_ingress_authorization_gate import _write_post_h3n_fixture


def test_post_h3q_opens_probes_and_closes_bounded_ingress(tmp_path: Path, monkeypatch: Any) -> None:
    post_h3o = _write_post_h3o_fixture(tmp_path, monkeypatch)

    summary = run_gate(
        post_h3o_summary_path=post_h3o,
        output_root=tmp_path / "post_h3q",
        bind_host="127.0.0.1",
        probe_host="127.0.0.1",
        open_seconds=0.05,
        ack_public_ingress_execution=True,
    )

    assert summary["passed"] is True
    assert summary["public_ingress_execution_id"]
    assert summary["execution_receipt_id"]
    assert summary["readiness"]["public_ingress_execution_complete"] is True
    assert summary["readiness"]["external_public_ingress_opened"] is True
    assert summary["readiness"]["external_public_ingress_closed"] is True
    assert summary["readiness"]["runtime_expansion_authorized"] is False
    assert summary["readiness"]["runtime_execution_performed"] is False
    assert summary["boundary"]["authorization_consumed"] is True
    assert summary["boundary"]["external_public_ingress_opened"] is True
    assert summary["boundary"]["external_public_ingress_closed"] is True
    assert summary["boundary"]["runtime_execution_performed"] is False


def test_post_h3q_requires_explicit_public_ingress_execution_ack(tmp_path: Path, monkeypatch: Any) -> None:
    post_h3o = _write_post_h3o_fixture(tmp_path, monkeypatch)

    summary = run_gate(
        post_h3o_summary_path=post_h3o,
        output_root=tmp_path / "post_h3q",
        bind_host="127.0.0.1",
        open_seconds=0.05,
        ack_public_ingress_execution=False,
    )

    assert summary["passed"] is False
    assert "explicit_operator_ack" in summary["failure_reasons"]
    assert summary["readiness"]["external_public_ingress_opened"] is False


def test_post_h3q_blocks_open_seconds_beyond_scope(tmp_path: Path, monkeypatch: Any) -> None:
    post_h3o = _write_post_h3o_fixture(tmp_path, monkeypatch)

    summary = run_gate(
        post_h3o_summary_path=post_h3o,
        output_root=tmp_path / "post_h3q",
        bind_host="127.0.0.1",
        open_seconds=301,
        ack_public_ingress_execution=True,
    )

    assert summary["passed"] is False
    assert "open_seconds_within_scope" in summary["failure_reasons"]
    assert summary["readiness"]["external_public_ingress_opened"] is False


def _write_post_h3o_fixture(tmp_path: Path, monkeypatch: Any) -> Path:
    post_h3n = _write_post_h3n_fixture(tmp_path, monkeypatch)
    post_h3o_root = tmp_path / "post_h3o"
    run_post_h3o(
        post_h3n_summary_path=post_h3n,
        output_root=post_h3o_root,
        ack_public_ingress_authorization=True,
    )
    return post_h3o_root / "post_h3o_public_ingress_authorization_summary.json"
