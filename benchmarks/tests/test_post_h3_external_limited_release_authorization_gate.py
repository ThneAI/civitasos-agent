from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from benchmarks.post_h3_external_limited_release_authorization_gate import run_gate
from benchmarks.post_h3_release_boundary_request_gate import run_gate as run_post_h3h
from benchmarks.tests.test_post_h3_release_boundary_request_gate import _write_post_h3g_fixture


def test_post_h3i_authorizes_external_limited_release_preflight_only(tmp_path: Path, monkeypatch: Any) -> None:
    post_h3h = _write_post_h3h_fixture(tmp_path, monkeypatch)

    summary = run_gate(
        post_h3h_summary_path=post_h3h,
        output_root=tmp_path / "post_h3i",
        ack_external_limited_release_preflight=True,
    )

    assert summary["passed"] is True
    assert summary["readiness"]["external_limited_release_preflight_authorized"] is True
    assert summary["readiness"]["external_limited_release_preflight_ready"] is True
    assert summary["readiness"]["external_limited_release_ready"] is False
    assert summary["readiness"]["public_ingress_authorized"] is False
    assert summary["readiness"]["runtime_expansion_authorized"] is False
    assert summary["boundary"]["external_limited_release_preflight_authorized"] is True
    assert summary["boundary"]["external_limited_release_performed"] is False
    assert summary["boundary"]["public_ingress_authorized"] is False
    assert summary["boundary"]["external_public_ingress_opened"] is False
    assert summary["boundary"]["runtime_execution_performed"] is False


def test_post_h3i_requires_explicit_ack(tmp_path: Path, monkeypatch: Any) -> None:
    post_h3h = _write_post_h3h_fixture(tmp_path, monkeypatch)

    summary = run_gate(
        post_h3h_summary_path=post_h3h,
        output_root=tmp_path / "post_h3i",
        ack_external_limited_release_preflight=False,
    )

    assert summary["passed"] is False
    assert "explicit_operator_ack" in summary["failure_reasons"]
    assert summary["readiness"]["external_limited_release_preflight_authorized"] is False


def test_post_h3i_blocks_public_ingress_drift(tmp_path: Path, monkeypatch: Any) -> None:
    source = _write_post_h3h_fixture(tmp_path, monkeypatch)
    copied = tmp_path / "post_h3h_summary_drift.json"
    payload = json.loads(source.read_text(encoding="utf-8"))
    payload["boundary"]["external_public_ingress_opened"] = True
    copied.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    summary = run_gate(
        post_h3h_summary_path=copied,
        output_root=tmp_path / "post_h3i",
        ack_external_limited_release_preflight=True,
    )

    assert summary["passed"] is False
    assert "no_external_public_ingress_opened" in summary["failure_reasons"]
    assert summary["readiness"]["external_limited_release_ready"] is False


def _write_post_h3h_fixture(tmp_path: Path, monkeypatch: Any) -> Path:
    post_h3g = _write_post_h3g_fixture(tmp_path, monkeypatch)
    post_h3h_root = tmp_path / "post_h3h"
    run_post_h3h(
        post_h3g_summary_path=post_h3g,
        output_root=post_h3h_root,
        ack_release_boundary_request=True,
    )
    return post_h3h_root / "post_h3h_release_boundary_request_summary.json"
