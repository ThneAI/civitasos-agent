from __future__ import annotations

from pathlib import Path
from typing import Any

from benchmarks.post_h3_public_ingress_authorization_gate import run_gate as run_post_h3o
from benchmarks.post_h3_public_ingress_execution_gate import run_gate as run_post_h3q
from benchmarks.post_h3_qr_execution_closeout_gate import run_gate
from benchmarks.post_h3_runtime_expansion_authorization_gate import run_gate as run_post_h3p
from benchmarks.post_h3_runtime_expansion_execution_gate import run_gate as run_post_h3r
from benchmarks.tests.test_post_h3_public_ingress_authorization_gate import _write_post_h3n_fixture


def test_post_h3s_closes_qr_execution_receipts(tmp_path: Path, monkeypatch: Any) -> None:
    post_h3q, post_h3r = _write_post_h3q_r_fixtures(tmp_path, monkeypatch)

    summary = run_gate(
        post_h3q_summary_path=post_h3q,
        post_h3r_summary_path=post_h3r,
        output_root=tmp_path / "post_h3s",
        ack_qr_execution_closeout=True,
    )

    assert summary["passed"] is True
    assert summary["qr_closeout_id"]
    assert summary["readiness"]["post_h3_qr_execution_closeout_complete"] is True
    assert summary["readiness"]["external_user_usage_review_ready"] is True
    assert summary["readiness"]["external_user_usage_allowed"] is False
    assert summary["readiness"]["external_public_ingress_currently_open"] is False
    assert summary["readiness"]["runtime_workers_currently_running"] is False
    assert summary["boundary"]["external_public_ingress_previously_opened"] is True
    assert summary["boundary"]["runtime_expansion_previously_performed"] is True
    assert summary["boundary"]["runtime_execution_performed"] is False


def test_post_h3s_requires_explicit_closeout_ack(tmp_path: Path, monkeypatch: Any) -> None:
    post_h3q, post_h3r = _write_post_h3q_r_fixtures(tmp_path, monkeypatch)

    summary = run_gate(
        post_h3q_summary_path=post_h3q,
        post_h3r_summary_path=post_h3r,
        output_root=tmp_path / "post_h3s",
        ack_qr_execution_closeout=False,
    )

    assert summary["passed"] is False
    assert "explicit_operator_ack" in summary["failure_reasons"]
    assert summary["readiness"]["external_user_usage_review_ready"] is False


def test_post_h3s_blocks_q_receipt_hash_drift(tmp_path: Path, monkeypatch: Any) -> None:
    post_h3q, post_h3r = _write_post_h3q_r_fixtures(tmp_path, monkeypatch)
    receipt_path = tmp_path / "post_h3q" / "post_h3q_public_ingress_execution_receipt.json"
    receipt_path.write_text(receipt_path.read_text(encoding="utf-8").replace("true", "false", 1), encoding="utf-8")

    summary = run_gate(
        post_h3q_summary_path=post_h3q,
        post_h3r_summary_path=post_h3r,
        output_root=tmp_path / "post_h3s",
        ack_qr_execution_closeout=True,
    )

    assert summary["passed"] is False
    assert "post_h3q_execution_receipt_hash_valid" in summary["failure_reasons"]


def _write_post_h3q_r_fixtures(tmp_path: Path, monkeypatch: Any) -> tuple[Path, Path]:
    post_h3n = _write_post_h3n_fixture(tmp_path, monkeypatch)
    post_h3o_root = tmp_path / "post_h3o"
    post_h3p_root = tmp_path / "post_h3p"
    run_post_h3o(post_h3n_summary_path=post_h3n, output_root=post_h3o_root, ack_public_ingress_authorization=True)
    run_post_h3p(post_h3n_summary_path=post_h3n, output_root=post_h3p_root, ack_runtime_expansion_authorization=True)
    post_h3q_root = tmp_path / "post_h3q"
    post_h3r_root = tmp_path / "post_h3r"
    run_post_h3q(
        post_h3o_summary_path=post_h3o_root / "post_h3o_public_ingress_authorization_summary.json",
        output_root=post_h3q_root,
        bind_host="127.0.0.1",
        probe_host="127.0.0.1",
        open_seconds=0.05,
        ack_public_ingress_execution=True,
    )
    run_post_h3r(
        post_h3p_summary_path=post_h3p_root / "post_h3p_runtime_expansion_authorization_summary.json",
        output_root=post_h3r_root,
        worker_count=2,
        expansion_seconds=0.05,
        ack_runtime_expansion_execution=True,
    )
    return post_h3q_root / "post_h3q_public_ingress_execution_summary.json", post_h3r_root / "post_h3r_runtime_expansion_execution_summary.json"
