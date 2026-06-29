from __future__ import annotations

from pathlib import Path
from typing import Any

from benchmarks.post_h3_runtime_expansion_authorization_gate import run_gate as run_post_h3p
from benchmarks.post_h3_runtime_expansion_execution_gate import run_gate
from benchmarks.tests.test_post_h3_public_ingress_authorization_gate import _write_post_h3n_fixture


def test_post_h3r_starts_heartbeats_and_stops_bounded_workers(tmp_path: Path, monkeypatch: Any) -> None:
    post_h3p = _write_post_h3p_fixture(tmp_path, monkeypatch)

    summary = run_gate(
        post_h3p_summary_path=post_h3p,
        output_root=tmp_path / "post_h3r",
        worker_count=2,
        expansion_seconds=0.05,
        ack_runtime_expansion_execution=True,
    )

    assert summary["passed"] is True
    assert summary["runtime_expansion_execution_id"]
    assert summary["execution_receipt_id"]
    assert summary["readiness"]["runtime_expansion_execution_complete"] is True
    assert summary["readiness"]["runtime_expansion_performed"] is True
    assert summary["readiness"]["runtime_workers_started"] is True
    assert summary["readiness"]["runtime_workers_stopped"] is True
    assert summary["readiness"]["runtime_execution_performed"] is False
    assert summary["readiness"]["external_public_ingress_opened"] is False
    assert summary["boundary"]["authorization_consumed"] is True
    assert summary["boundary"]["runtime_expansion_performed"] is True
    assert summary["boundary"]["runtime_workers_stopped"] is True


def test_post_h3r_requires_explicit_runtime_expansion_execution_ack(tmp_path: Path, monkeypatch: Any) -> None:
    post_h3p = _write_post_h3p_fixture(tmp_path, monkeypatch)

    summary = run_gate(
        post_h3p_summary_path=post_h3p,
        output_root=tmp_path / "post_h3r",
        worker_count=2,
        expansion_seconds=0.05,
        ack_runtime_expansion_execution=False,
    )

    assert summary["passed"] is False
    assert "explicit_operator_ack" in summary["failure_reasons"]
    assert summary["readiness"]["runtime_expansion_performed"] is False


def test_post_h3r_blocks_worker_count_beyond_scope(tmp_path: Path, monkeypatch: Any) -> None:
    post_h3p = _write_post_h3p_fixture(tmp_path, monkeypatch)

    summary = run_gate(
        post_h3p_summary_path=post_h3p,
        output_root=tmp_path / "post_h3r",
        worker_count=6,
        expansion_seconds=0.05,
        ack_runtime_expansion_execution=True,
    )

    assert summary["passed"] is False
    assert "worker_count_within_scope" in summary["failure_reasons"]
    assert summary["readiness"]["runtime_expansion_performed"] is False


def _write_post_h3p_fixture(tmp_path: Path, monkeypatch: Any) -> Path:
    post_h3n = _write_post_h3n_fixture(tmp_path, monkeypatch)
    post_h3p_root = tmp_path / "post_h3p"
    run_post_h3p(
        post_h3n_summary_path=post_h3n,
        output_root=post_h3p_root,
        ack_runtime_expansion_authorization=True,
    )
    return post_h3p_root / "post_h3p_runtime_expansion_authorization_summary.json"
