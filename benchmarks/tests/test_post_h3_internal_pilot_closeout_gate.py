from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from benchmarks.post_h3_first_internal_runtime_execution_gate import run_execution as run_post_h3d
from benchmarks.post_h3_internal_pilot_closeout_gate import run_gate
from benchmarks.post_h3_production_receipt_write_authorization_gate import run_gate as run_post_h3e
from benchmarks.post_h3_production_runtime_receipt_write_gate import run_gate as run_post_h3f
from benchmarks.tests.test_post_h3_first_internal_runtime_execution_gate import FakeClient, _write_post_h3_chain


def test_post_h3g_closes_internal_pilot_slice(tmp_path: Path, monkeypatch: Any) -> None:
    paths = _write_post_h3_a_f_fixture(tmp_path, monkeypatch)

    summary = run_gate(**paths, output_root=tmp_path / "post_h3g", ack_internal_pilot_closeout=True)

    assert summary["passed"] is True
    assert summary["readiness"]["post_h3_internal_pilot_closed"] is True
    assert summary["readiness"]["next_stage_request_ready"] is True
    assert summary["readiness"]["external_limited_release_ready"] is False
    assert summary["readiness"]["public_ingress_authorized"] is False
    assert summary["boundary"]["receipt_index_written"] is True
    assert summary["boundary"]["boundary_reconciliation_written"] is True
    assert summary["boundary"]["owner_audit_closeout_written"] is True
    assert summary["boundary"]["next_stage_request_written"] is True
    assert summary["boundary"]["runtime_execution_performed"] is False
    assert summary["boundary"]["external_public_ingress_opened"] is False


def test_post_h3g_requires_explicit_ack(tmp_path: Path, monkeypatch: Any) -> None:
    paths = _write_post_h3_a_f_fixture(tmp_path, monkeypatch)

    summary = run_gate(**paths, output_root=tmp_path / "post_h3g", ack_internal_pilot_closeout=False)

    assert summary["passed"] is False
    assert "explicit_operator_ack" in summary["failure_reasons"]
    assert summary["readiness"]["next_stage_request_ready"] is False


def test_post_h3g_blocks_public_ingress_drift(tmp_path: Path, monkeypatch: Any) -> None:
    paths = _write_post_h3_a_f_fixture(tmp_path, monkeypatch)
    copied = tmp_path / "post_h3f_summary_drift.json"
    payload = json.loads(paths["post_h3f_summary_path"].read_text(encoding="utf-8"))
    payload["boundary"]["external_public_ingress_opened"] = True
    copied.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    paths["post_h3f_summary_path"] = copied

    summary = run_gate(**paths, output_root=tmp_path / "post_h3g", ack_internal_pilot_closeout=True)

    assert summary["passed"] is False
    assert "post_h3f_no_public_ingress" in summary["failure_reasons"]
    assert "all_no_public_ingress" in summary["failure_reasons"]


def _write_post_h3_a_f_fixture(tmp_path: Path, monkeypatch: Any) -> dict[str, Path]:
    monkeypatch.setattr(
        "benchmarks.post_h3_first_internal_runtime_execution_gate._public_key_hex",
        lambda seed: f"pubkey-{seed}",
    )
    post_h3a, post_h3b, post_h3c = _write_post_h3_chain(tmp_path)
    post_h3d_root = tmp_path / "post_h3d"
    post_h3e_root = tmp_path / "post_h3e"
    post_h3f_root = tmp_path / "post_h3f"
    run_post_h3d(
        post_h3a_summary_path=post_h3a,
        post_h3b_summary_path=post_h3b,
        post_h3c_summary_path=post_h3c,
        output_root=post_h3d_root,
        client=FakeClient(),
    )
    run_post_h3e(
        post_h3d_summary_path=post_h3d_root / "post_h3d_first_internal_runtime_execution_summary.json",
        output_root=post_h3e_root,
        ack_receipt_write_authorization=True,
    )
    run_post_h3f(
        post_h3e_summary_path=post_h3e_root / "post_h3e_production_receipt_write_authorization_summary.json",
        output_root=post_h3f_root,
        ack_production_runtime_receipt_write=True,
    )
    return {
        "post_h3a_summary_path": post_h3a,
        "post_h3b_summary_path": post_h3b,
        "post_h3c_summary_path": post_h3c,
        "post_h3d_summary_path": post_h3d_root / "post_h3d_first_internal_runtime_execution_summary.json",
        "post_h3e_summary_path": post_h3e_root / "post_h3e_production_receipt_write_authorization_summary.json",
        "post_h3f_summary_path": post_h3f_root / "post_h3f_production_runtime_receipt_write_summary.json",
    }
