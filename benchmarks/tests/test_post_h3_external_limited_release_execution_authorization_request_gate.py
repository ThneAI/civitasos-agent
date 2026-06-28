from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from benchmarks.post_h3_external_limited_release_execution_authorization_request_gate import run_gate
from benchmarks.post_h3_external_limited_release_preflight_gate import run_gate as run_post_h3j
from benchmarks.tests.test_post_h3_external_limited_release_preflight_gate import _write_post_h3i_fixture


def test_post_h3k_prepares_execution_authorization_request_only(tmp_path: Path, monkeypatch: Any) -> None:
    post_h3j = _write_post_h3j_fixture(tmp_path, monkeypatch)

    summary = run_gate(
        post_h3j_summary_path=post_h3j,
        output_root=tmp_path / "post_h3k",
        ack_execution_authorization_request=True,
    )

    assert summary["passed"] is True
    assert summary["readiness"]["external_limited_release_execution_authorization_request_ready"] is True
    assert summary["readiness"]["operator_execution_authorization_review_ready"] is True
    assert summary["readiness"]["external_limited_release_execution_authorized"] is False
    assert summary["readiness"]["external_limited_release_ready"] is False
    assert summary["readiness"]["public_ingress_authorized"] is False
    assert summary["boundary"]["execution_authorization_request_written"] is True
    assert summary["boundary"]["external_limited_release_execution_authorized"] is False
    assert summary["boundary"]["external_limited_release_performed"] is False
    assert summary["boundary"]["external_public_ingress_opened"] is False
    assert summary["boundary"]["runtime_execution_performed"] is False


def test_post_h3k_requires_explicit_ack(tmp_path: Path, monkeypatch: Any) -> None:
    post_h3j = _write_post_h3j_fixture(tmp_path, monkeypatch)

    summary = run_gate(
        post_h3j_summary_path=post_h3j,
        output_root=tmp_path / "post_h3k",
        ack_execution_authorization_request=False,
    )

    assert summary["passed"] is False
    assert "explicit_operator_ack" in summary["failure_reasons"]
    assert summary["readiness"]["external_limited_release_execution_authorization_request_ready"] is False


def test_post_h3k_blocks_public_ingress_drift(tmp_path: Path, monkeypatch: Any) -> None:
    source = _write_post_h3j_fixture(tmp_path, monkeypatch)
    copied = tmp_path / "post_h3j_summary_drift.json"
    payload = json.loads(source.read_text(encoding="utf-8"))
    payload["boundary"]["external_public_ingress_opened"] = True
    copied.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    summary = run_gate(
        post_h3j_summary_path=copied,
        output_root=tmp_path / "post_h3k",
        ack_execution_authorization_request=True,
    )

    assert summary["passed"] is False
    assert "no_external_public_ingress_opened" in summary["failure_reasons"]
    assert summary["readiness"]["external_limited_release_ready"] is False


def _write_post_h3j_fixture(tmp_path: Path, monkeypatch: Any) -> Path:
    post_h3i = _write_post_h3i_fixture(tmp_path, monkeypatch)
    post_h3j_root = tmp_path / "post_h3j"
    run_post_h3j(
        post_h3i_summary_path=post_h3i,
        output_root=post_h3j_root,
        ack_external_limited_release_preflight=True,
    )
    return post_h3j_root / "post_h3j_external_limited_release_preflight_summary.json"
