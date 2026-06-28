from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from benchmarks.post_h3_external_limited_release_execution_authorization_review_gate import run_gate as run_post_h3l
from benchmarks.post_h3_external_limited_release_execution_gate import run_gate
from benchmarks.tests.test_post_h3_external_limited_release_execution_authorization_review_gate import _write_post_h3k_fixture


def test_post_h3m_executes_controlled_release_boundary_action(tmp_path: Path, monkeypatch: Any) -> None:
    post_h3l = _write_post_h3l_fixture(tmp_path, monkeypatch)

    summary = run_gate(
        post_h3l_summary_path=post_h3l,
        output_root=tmp_path / "post_h3m",
        ack_external_limited_release_execution=True,
    )

    assert summary["passed"] is True
    assert summary["authorization_id"]
    assert summary["release_action_id"]
    assert summary["execution_receipt_id"]
    assert summary["readiness"]["external_limited_release_execution_complete"] is True
    assert summary["readiness"]["external_limited_release_performed"] is True
    assert summary["readiness"]["external_limited_release_ready"] is True
    assert summary["readiness"]["external_participant_count"] == 0
    assert summary["readiness"]["public_ingress_authorized"] is False
    assert summary["readiness"]["runtime_expansion_authorized"] is False
    assert summary["boundary"]["authorization_consumed"] is True
    assert summary["boundary"]["external_limited_release_execution_authorized"] is True
    assert summary["boundary"]["release_action_written"] is True
    assert summary["boundary"]["execution_receipt_written"] is True
    assert summary["boundary"]["external_limited_release_performed"] is True
    assert summary["boundary"]["external_limited_release_ready"] is True
    assert summary["boundary"]["external_public_ingress_opened"] is False
    assert summary["boundary"]["runtime_execution_performed"] is False
    assert summary["boundary"]["deploy_performed"] is False


def test_post_h3m_requires_explicit_execution_ack(tmp_path: Path, monkeypatch: Any) -> None:
    post_h3l = _write_post_h3l_fixture(tmp_path, monkeypatch)

    summary = run_gate(
        post_h3l_summary_path=post_h3l,
        output_root=tmp_path / "post_h3m",
        ack_external_limited_release_execution=False,
    )

    assert summary["passed"] is False
    assert "explicit_operator_ack" in summary["failure_reasons"]
    assert summary["readiness"]["external_limited_release_execution_complete"] is False
    assert summary["readiness"]["external_limited_release_ready"] is False


def test_post_h3m_blocks_external_participant_count_beyond_scope(tmp_path: Path, monkeypatch: Any) -> None:
    post_h3l = _write_post_h3l_fixture(tmp_path, monkeypatch)

    summary = run_gate(
        post_h3l_summary_path=post_h3l,
        output_root=tmp_path / "post_h3m",
        external_participant_count=1,
        ack_external_limited_release_execution=True,
    )

    assert summary["passed"] is False
    assert "external_participant_count_within_scope" in summary["failure_reasons"]
    assert summary["readiness"]["external_participant_count"] == 0
    assert summary["boundary"]["external_limited_release_performed"] is False


def test_post_h3m_blocks_upstream_public_ingress_drift(tmp_path: Path, monkeypatch: Any) -> None:
    post_h3l = _write_post_h3l_fixture(tmp_path, monkeypatch)
    copied = tmp_path / "post_h3l_summary_drift.json"
    payload = json.loads(post_h3l.read_text(encoding="utf-8"))
    payload["boundary"]["external_public_ingress_opened"] = True
    copied.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    summary = run_gate(
        post_h3l_summary_path=copied,
        output_root=tmp_path / "post_h3m",
        ack_external_limited_release_execution=True,
    )

    assert summary["passed"] is False
    assert "no_external_public_ingress_opened" in summary["failure_reasons"]
    assert summary["readiness"]["external_limited_release_ready"] is False


def _write_post_h3l_fixture(tmp_path: Path, monkeypatch: Any) -> Path:
    post_h3k = _write_post_h3k_fixture(tmp_path, monkeypatch)
    post_h3l_root = tmp_path / "post_h3l"
    run_post_h3l(
        post_h3k_summary_path=post_h3k,
        output_root=post_h3l_root,
        ack_execution_authorization_review=True,
    )
    return post_h3l_root / "post_h3l_execution_authorization_review_summary.json"
