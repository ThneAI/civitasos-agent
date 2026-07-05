from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from benchmarks.post_h3_external_user_usage_closeout_gate import run_gate
from benchmarks.post_h3_external_user_usage_execution_gate import run_gate as run_post_h3w
from benchmarks.tests.test_post_h3_external_user_usage_execution_gate import _write_post_h3t_v_authorized_fixture


def test_post_h3x_closes_first_external_user_usage(tmp_path: Path, monkeypatch: Any) -> None:
    post_h3w = _write_post_h3w_fixture(tmp_path, monkeypatch)

    summary = run_gate(
        post_h3w_summary_path=post_h3w,
        output_root=tmp_path / "post_h3x",
        ack_external_user_usage_closeout=True,
    )

    assert summary["passed"] is True
    assert summary["external_user_usage_closeout_id"]
    assert summary["readiness"]["external_user_usage_closeout_complete"] is True
    assert summary["readiness"]["first_external_user_usage_closed"] is True
    assert summary["readiness"]["post_h3w_evidence_index_complete"] is True
    assert summary["readiness"]["next_usage_review_input_ready"] is True
    assert summary["readiness"]["external_user_usage_allowed"] is False
    assert summary["readiness"]["second_limited_usage_authorized"] is False
    assert summary["readiness"]["runtime_execution_performed"] is False
    assert summary["boundary"]["limited_usage_endpoint_currently_open"] is False


def test_post_h3x_requires_explicit_closeout_ack(tmp_path: Path, monkeypatch: Any) -> None:
    post_h3w = _write_post_h3w_fixture(tmp_path, monkeypatch)

    summary = run_gate(
        post_h3w_summary_path=post_h3w,
        output_root=tmp_path / "post_h3x",
        ack_external_user_usage_closeout=False,
    )

    assert summary["passed"] is False
    assert "explicit_operator_ack" in summary["failure_reasons"]
    assert summary["readiness"]["external_user_usage_closeout_complete"] is False
    assert summary["readiness"]["external_user_usage_allowed"] is False


def test_post_h3x_blocks_usage_receipt_hash_drift(tmp_path: Path, monkeypatch: Any) -> None:
    post_h3w = _write_post_h3w_fixture(tmp_path, monkeypatch)
    usage_receipt = tmp_path / "post_h3w" / "post_h3w_external_user_usage_receipt.json"
    payload = json.loads(usage_receipt.read_text(encoding="utf-8"))
    payload["passed"] = False
    usage_receipt.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    summary = run_gate(
        post_h3w_summary_path=post_h3w,
        output_root=tmp_path / "post_h3x",
        ack_external_user_usage_closeout=True,
    )

    assert summary["passed"] is False
    assert "post_h3w_usage_receipt_hash_valid" in summary["failure_reasons"]


def test_post_h3x_blocks_runtime_boundary_drift(tmp_path: Path, monkeypatch: Any) -> None:
    post_h3w = _write_post_h3w_fixture(tmp_path, monkeypatch)
    summary_payload = json.loads(post_h3w.read_text(encoding="utf-8"))
    summary_payload["boundary"]["runtime_execution_performed"] = True
    post_h3w.write_text(json.dumps(summary_payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    summary = run_gate(
        post_h3w_summary_path=post_h3w,
        output_root=tmp_path / "post_h3x",
        ack_external_user_usage_closeout=True,
    )

    assert summary["passed"] is False
    assert "post_h3w_no_runtime_execution_performed" in summary["failure_reasons"]


def _write_post_h3w_fixture(tmp_path: Path, monkeypatch: Any) -> Path:
    post_h3t, post_h3v = _write_post_h3t_v_authorized_fixture(tmp_path, monkeypatch)
    post_h3w_root = tmp_path / "post_h3w"
    run_post_h3w(
        post_h3t_summary_path=post_h3t,
        post_h3v_summary_path=post_h3v,
        output_root=post_h3w_root,
        external_user_handle="external-user",
        authorization_consumption_path=tmp_path / "post_h3w_authorization_consumption_lease.json",
        usage_seconds=0.01,
        ack_external_user_usage_execution=True,
    )
    return post_h3w_root / "post_h3w_external_user_usage_execution_summary.json"
