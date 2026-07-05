from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from benchmarks.post_h3_next_external_usage_strategy_review_gate import (
    ALLOWED_USAGE_SCOPE,
    AUTHORIZE_SECOND_USAGE_DECISION,
    SECOND_USAGE_AUDIT_DECISION,
    SECOND_USAGE_MONITORING_DECISION,
    SECOND_USAGE_ROLLBACK_DECISION,
    run_gate as run_post_h3ab,
)
from benchmarks.post_h3_observer_mode_readiness_gate import run_gate
from benchmarks.tests.test_post_h3_next_external_usage_strategy_review_gate import _write_post_h3aa_fixture


def test_post_h3ac_observer_readiness_accepts_ab_observer_mode(tmp_path: Path, monkeypatch: Any) -> None:
    post_h3ab = _write_post_h3ab_fixture(tmp_path, monkeypatch)

    summary = run_gate(
        post_h3ab_summary_path=post_h3ab,
        output_root=tmp_path / "post_h3ac",
        ack_observer_readiness=True,
    )

    assert summary["passed"] is True
    assert summary["observer_mode_evidence_collection_complete"] is True
    assert summary["observer_mode_readiness_accepted"] is True
    assert summary["readiness"]["observer_mode_continues"] is True
    assert summary["readiness"]["next_single_use_gate_input_ready"] is False
    assert summary["readiness"]["external_user_usage_allowed"] is False
    assert summary["readiness"]["runtime_execution_performed"] is False


def test_post_h3ac_requires_explicit_observer_ack(tmp_path: Path, monkeypatch: Any) -> None:
    post_h3ab = _write_post_h3ab_fixture(tmp_path, monkeypatch)

    summary = run_gate(
        post_h3ab_summary_path=post_h3ab,
        output_root=tmp_path / "post_h3ac",
        ack_observer_readiness=False,
    )

    assert summary["passed"] is False
    assert "explicit_observer_readiness_ack" in summary["failure_reasons"]
    assert summary["readiness"]["observer_mode_readiness_review_complete"] is False


def test_post_h3ac_rejects_ab_second_usage_authorization(tmp_path: Path, monkeypatch: Any) -> None:
    post_h3aa = _write_post_h3aa_fixture(tmp_path, monkeypatch)
    post_h3ab_root = tmp_path / "post_h3ab_second_usage"
    run_post_h3ab(
        post_h3aa_summary_path=post_h3aa,
        output_root=post_h3ab_root,
        operator_decision=AUTHORIZE_SECOND_USAGE_DECISION,
        audit_decision=SECOND_USAGE_AUDIT_DECISION,
        monitoring_decision=SECOND_USAGE_MONITORING_DECISION,
        rollback_decision=SECOND_USAGE_ROLLBACK_DECISION,
        operator_statement="Prepare a second bounded usage; execution remains separate.",
        max_external_users=1,
        requested_usage_scope=ALLOWED_USAGE_SCOPE,
        ack_strategy_review=True,
    )

    summary = run_gate(
        post_h3ab_summary_path=post_h3ab_root / "post_h3ab_next_external_usage_strategy_review_summary.json",
        output_root=tmp_path / "post_h3ac",
        ack_observer_readiness=True,
    )

    assert summary["passed"] is False
    assert "post_h3ab_observer_mode" in summary["failure_reasons"]
    assert summary["readiness"]["observer_mode_continues"] is False


def test_post_h3ac_blocks_ab_artifact_hash_drift(tmp_path: Path, monkeypatch: Any) -> None:
    post_h3ab = _write_post_h3ab_fixture(tmp_path, monkeypatch)
    packet_path = tmp_path / "post_h3ab" / "post_h3ab_next_external_usage_strategy_packet.json"
    payload = json.loads(packet_path.read_text(encoding="utf-8"))
    payload["passed"] = False
    packet_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    summary = run_gate(
        post_h3ab_summary_path=post_h3ab,
        output_root=tmp_path / "post_h3ac",
        ack_observer_readiness=True,
    )

    assert summary["passed"] is False
    assert "post_h3ab_strategy_packet_hash_valid" in summary["failure_reasons"]


def _write_post_h3ab_fixture(tmp_path: Path, monkeypatch: Any) -> Path:
    post_h3aa = _write_post_h3aa_fixture(tmp_path, monkeypatch)
    post_h3ab_root = tmp_path / "post_h3ab"
    run_post_h3ab(
        post_h3aa_summary_path=post_h3aa,
        output_root=post_h3ab_root,
        ack_strategy_review=True,
    )
    return post_h3ab_root / "post_h3ab_next_external_usage_strategy_review_summary.json"
