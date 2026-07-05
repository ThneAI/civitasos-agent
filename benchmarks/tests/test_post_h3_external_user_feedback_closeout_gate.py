from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from benchmarks.post_h3_external_user_feedback_closeout_gate import run_gate
from benchmarks.post_h3_external_user_feedback_collection_gate import run_gate as run_post_h3z
from benchmarks.tests.test_post_h3_external_user_feedback_collection_gate import _write_feedback_authorized_post_h3y_fixture


def test_post_h3aa_closes_feedback_collection(tmp_path: Path, monkeypatch: Any) -> None:
    post_h3z = _write_post_h3z_fixture(tmp_path, monkeypatch)

    summary = run_gate(
        post_h3z_summary_path=post_h3z,
        output_root=tmp_path / "post_h3aa",
        ack_feedback_closeout=True,
    )

    assert summary["passed"] is True
    assert summary["external_user_feedback_closeout_id"]
    assert summary["readiness"]["external_user_feedback_closeout_complete"] is True
    assert summary["readiness"]["post_h3z_feedback_closed"] is True
    assert summary["readiness"]["next_external_usage_strategy_review_input_ready"] is True
    assert summary["readiness"]["external_user_feedback_collection_allowed"] is False
    assert summary["readiness"]["external_user_usage_allowed"] is False
    assert summary["readiness"]["second_external_user_usage_execution_ready"] is False
    assert summary["boundary"]["feedback_collection_endpoint_currently_open"] is False
    assert summary["boundary"]["external_public_ingress_opened"] is False


def test_post_h3aa_requires_explicit_feedback_closeout_ack(tmp_path: Path, monkeypatch: Any) -> None:
    post_h3z = _write_post_h3z_fixture(tmp_path, monkeypatch)

    summary = run_gate(
        post_h3z_summary_path=post_h3z,
        output_root=tmp_path / "post_h3aa",
        ack_feedback_closeout=False,
    )

    assert summary["passed"] is False
    assert "explicit_operator_ack" in summary["failure_reasons"]
    assert summary["readiness"]["external_user_feedback_closeout_complete"] is False


def test_post_h3aa_blocks_feedback_receipt_hash_drift(tmp_path: Path, monkeypatch: Any) -> None:
    post_h3z = _write_post_h3z_fixture(tmp_path, monkeypatch)
    feedback_receipt = tmp_path / "post_h3z" / "post_h3z_external_user_feedback_receipt.json"
    payload = json.loads(feedback_receipt.read_text(encoding="utf-8"))
    payload["passed"] = False
    feedback_receipt.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    summary = run_gate(
        post_h3z_summary_path=post_h3z,
        output_root=tmp_path / "post_h3aa",
        ack_feedback_closeout=True,
    )

    assert summary["passed"] is False
    assert "post_h3z_feedback_receipt_hash_valid" in summary["failure_reasons"]


def test_post_h3aa_blocks_usage_boundary_drift(tmp_path: Path, monkeypatch: Any) -> None:
    post_h3z = _write_post_h3z_fixture(tmp_path, monkeypatch)
    summary_payload = json.loads(post_h3z.read_text(encoding="utf-8"))
    summary_payload["boundary"]["external_user_usage_performed"] = True
    post_h3z.write_text(json.dumps(summary_payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    summary = run_gate(
        post_h3z_summary_path=post_h3z,
        output_root=tmp_path / "post_h3aa",
        ack_feedback_closeout=True,
    )

    assert summary["passed"] is False
    assert "post_h3z_no_external_user_usage_performed" in summary["failure_reasons"]


def _write_post_h3z_fixture(tmp_path: Path, monkeypatch: Any) -> Path:
    post_h3y = _write_feedback_authorized_post_h3y_fixture(tmp_path, monkeypatch)
    post_h3z_root = tmp_path / "post_h3z"
    run_post_h3z(
        post_h3y_summary_path=post_h3y,
        output_root=post_h3z_root,
        external_user_handle="external-user",
        feedback_text="External user requests feedback-only closeout before strategy review.",
        authorization_consumption_path=tmp_path / "post_h3z_feedback_consumption_lease.json",
        ack_feedback_collection=True,
    )
    return post_h3z_root / "post_h3z_external_user_feedback_collection_summary.json"
