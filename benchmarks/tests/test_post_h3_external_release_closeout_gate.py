from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from benchmarks.post_h3_external_limited_release_execution_gate import run_gate as run_post_h3m
from benchmarks.post_h3_external_release_closeout_gate import run_gate
from benchmarks.tests.test_post_h3_external_limited_release_execution_gate import _write_post_h3l_fixture


def test_post_h3n_closes_external_release_after_m(tmp_path: Path, monkeypatch: Any) -> None:
    post_h3m = _write_post_h3m_fixture(tmp_path, monkeypatch)

    summary = run_gate(
        post_h3m_summary_path=post_h3m,
        output_root=tmp_path / "post_h3n",
        ack_external_release_closeout=True,
    )

    assert summary["passed"] is True
    assert summary["release_closeout_id"]
    assert summary["readiness"]["external_release_closeout_complete"] is True
    assert summary["readiness"]["public_ingress_authorization_ready"] is True
    assert summary["readiness"]["runtime_expansion_authorization_ready"] is True
    assert summary["readiness"]["public_ingress_authorized"] is False
    assert summary["readiness"]["runtime_expansion_authorized"] is False
    assert summary["boundary"]["external_release_closeout_complete"] is True
    assert summary["boundary"]["external_public_ingress_opened"] is False
    assert summary["boundary"]["runtime_execution_performed"] is False


def test_post_h3n_requires_explicit_closeout_ack(tmp_path: Path, monkeypatch: Any) -> None:
    post_h3m = _write_post_h3m_fixture(tmp_path, monkeypatch)

    summary = run_gate(
        post_h3m_summary_path=post_h3m,
        output_root=tmp_path / "post_h3n",
        ack_external_release_closeout=False,
    )

    assert summary["passed"] is False
    assert "explicit_operator_ack" in summary["failure_reasons"]
    assert summary["readiness"]["public_ingress_authorization_ready"] is False


def test_post_h3n_blocks_m_public_ingress_drift(tmp_path: Path, monkeypatch: Any) -> None:
    post_h3m = _write_post_h3m_fixture(tmp_path, monkeypatch)
    copied = tmp_path / "post_h3m_summary_drift.json"
    payload = json.loads(post_h3m.read_text(encoding="utf-8"))
    payload["boundary"]["external_public_ingress_opened"] = True
    copied.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    summary = run_gate(
        post_h3m_summary_path=copied,
        output_root=tmp_path / "post_h3n",
        ack_external_release_closeout=True,
    )

    assert summary["passed"] is False
    assert "no_external_public_ingress_opened" in summary["failure_reasons"]
    assert summary["readiness"]["external_release_closeout_complete"] is False


def _write_post_h3m_fixture(tmp_path: Path, monkeypatch: Any) -> Path:
    post_h3l = _write_post_h3l_fixture(tmp_path, monkeypatch)
    post_h3m_root = tmp_path / "post_h3m"
    run_post_h3m(
        post_h3l_summary_path=post_h3l,
        output_root=post_h3m_root,
        ack_external_limited_release_execution=True,
    )
    return post_h3m_root / "post_h3m_external_limited_release_execution_summary.json"
