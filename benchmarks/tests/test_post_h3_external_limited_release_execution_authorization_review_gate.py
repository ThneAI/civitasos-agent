from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from benchmarks.post_h3_external_limited_release_execution_authorization_request_gate import run_gate as run_post_h3k
from benchmarks.post_h3_external_limited_release_execution_authorization_review_gate import OPERATOR_REJECT, run_gate
from benchmarks.tests.test_post_h3_external_limited_release_execution_authorization_request_gate import _write_post_h3j_fixture


def test_post_h3l_authorizes_execution_once_when_all_owners_accept(tmp_path: Path, monkeypatch: Any) -> None:
    post_h3k = _write_post_h3k_fixture(tmp_path, monkeypatch)

    summary = run_gate(
        post_h3k_summary_path=post_h3k,
        output_root=tmp_path / "post_h3l",
        ack_execution_authorization_review=True,
    )

    assert summary["passed"] is True
    assert summary["authorization_granted"] is True
    assert summary["authorization_id"]
    assert summary["readiness"]["operator_execution_authorization_review_complete"] is True
    assert summary["readiness"]["external_limited_release_execution_authorized"] is True
    assert summary["readiness"]["external_limited_release_execution_ready"] is True
    assert summary["readiness"]["external_limited_release_ready"] is False
    assert summary["readiness"]["public_ingress_authorized"] is False
    assert summary["boundary"]["external_limited_release_execution_authorized"] is True
    assert summary["boundary"]["external_limited_release_performed"] is False
    assert summary["boundary"]["external_public_ingress_opened"] is False


def test_post_h3l_records_explicit_rejection_without_authorization(tmp_path: Path, monkeypatch: Any) -> None:
    post_h3k = _write_post_h3k_fixture(tmp_path, monkeypatch)

    summary = run_gate(
        post_h3k_summary_path=post_h3k,
        output_root=tmp_path / "post_h3l",
        operator_decision=OPERATOR_REJECT,
        ack_execution_authorization_review=True,
    )

    assert summary["passed"] is True
    assert summary["authorization_granted"] is False
    assert summary["authorization_id"] is None
    assert summary["readiness"]["operator_execution_authorization_review_complete"] is True
    assert summary["readiness"]["external_limited_release_execution_authorized"] is False
    assert summary["boundary"]["external_limited_release_execution_authorized"] is False


def test_post_h3l_requires_explicit_ack(tmp_path: Path, monkeypatch: Any) -> None:
    post_h3k = _write_post_h3k_fixture(tmp_path, monkeypatch)

    summary = run_gate(
        post_h3k_summary_path=post_h3k,
        output_root=tmp_path / "post_h3l",
        ack_execution_authorization_review=False,
    )

    assert summary["passed"] is False
    assert "explicit_operator_ack" in summary["failure_reasons"]
    assert summary["readiness"]["external_limited_release_execution_authorized"] is False


def test_post_h3l_blocks_public_ingress_drift(tmp_path: Path, monkeypatch: Any) -> None:
    source = _write_post_h3k_fixture(tmp_path, monkeypatch)
    copied = tmp_path / "post_h3k_summary_drift.json"
    payload = json.loads(source.read_text(encoding="utf-8"))
    payload["boundary"]["external_public_ingress_opened"] = True
    copied.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    summary = run_gate(
        post_h3k_summary_path=copied,
        output_root=tmp_path / "post_h3l",
        ack_execution_authorization_review=True,
    )

    assert summary["passed"] is False
    assert "no_external_public_ingress_opened" in summary["failure_reasons"]
    assert summary["readiness"]["external_limited_release_execution_authorized"] is False


def _write_post_h3k_fixture(tmp_path: Path, monkeypatch: Any) -> Path:
    post_h3j = _write_post_h3j_fixture(tmp_path, monkeypatch)
    post_h3k_root = tmp_path / "post_h3k"
    run_post_h3k(
        post_h3j_summary_path=post_h3j,
        output_root=post_h3k_root,
        ack_execution_authorization_request=True,
    )
    return post_h3k_root / "post_h3k_external_limited_release_execution_authorization_request_summary.json"
