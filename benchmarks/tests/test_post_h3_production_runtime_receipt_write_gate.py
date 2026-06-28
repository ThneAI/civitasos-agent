from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from benchmarks.post_h3_first_internal_runtime_execution_gate import run_execution as run_post_h3d
from benchmarks.post_h3_production_receipt_write_authorization_gate import run_gate as run_post_h3e
from benchmarks.post_h3_production_runtime_receipt_write_gate import run_gate
from benchmarks.tests.test_post_h3_first_internal_runtime_execution_gate import FakeClient, _write_post_h3_chain


def test_post_h3f_writes_single_controlled_production_runtime_receipt(tmp_path: Path, monkeypatch: Any) -> None:
    post_h3e = _write_post_h3e_fixture(tmp_path, monkeypatch)

    summary = run_gate(
        post_h3e_summary_path=post_h3e,
        output_root=tmp_path / "post_h3f",
        ack_production_runtime_receipt_write=True,
    )

    assert summary["passed"] is True
    assert summary["readiness"]["post_h3f_production_runtime_receipt_written"] is True
    assert summary["readiness"]["production_runtime_receipt_written"] is True
    assert summary["readiness"]["production_runtime_receipt_write_allowed"] is False
    assert summary["readiness"]["public_ingress_authorized"] is False
    assert summary["readiness"]["external_limited_release_ready"] is False
    assert summary["boundary"]["authorization_consumed"] is True
    assert summary["boundary"]["production_runtime_receipt_written"] is True
    assert summary["boundary"]["runtime_execution_performed"] is False
    assert summary["boundary"]["vm_contact_performed"] is False
    assert summary["boundary"]["deploy_performed"] is False
    assert summary["boundary"]["external_public_ingress_opened"] is False


def test_post_h3f_requires_explicit_ack(tmp_path: Path, monkeypatch: Any) -> None:
    post_h3e = _write_post_h3e_fixture(tmp_path, monkeypatch)

    summary = run_gate(
        post_h3e_summary_path=post_h3e,
        output_root=tmp_path / "post_h3f",
        ack_production_runtime_receipt_write=False,
    )

    assert summary["passed"] is False
    assert "explicit_operator_ack" in summary["failure_reasons"]
    assert summary["readiness"]["production_runtime_receipt_written"] is False


def test_post_h3f_blocks_public_ingress_drift(tmp_path: Path, monkeypatch: Any) -> None:
    source = _write_post_h3e_fixture(tmp_path, monkeypatch)
    copied = tmp_path / "post_h3e_summary.json"
    payload = json.loads(source.read_text(encoding="utf-8"))
    payload["boundary"]["external_public_ingress_opened"] = True
    copied.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    summary = run_gate(
        post_h3e_summary_path=copied,
        output_root=tmp_path / "post_h3f",
        ack_production_runtime_receipt_write=True,
    )

    assert summary["passed"] is False
    assert "no_public_ingress" in summary["failure_reasons"]
    assert summary["readiness"]["production_runtime_receipt_written"] is False


def _write_post_h3e_fixture(tmp_path: Path, monkeypatch: Any) -> Path:
    monkeypatch.setattr(
        "benchmarks.post_h3_first_internal_runtime_execution_gate._public_key_hex",
        lambda seed: f"pubkey-{seed}",
    )
    post_h3a, post_h3b, post_h3c = _write_post_h3_chain(tmp_path)
    run_post_h3d(
        post_h3a_summary_path=post_h3a,
        post_h3b_summary_path=post_h3b,
        post_h3c_summary_path=post_h3c,
        output_root=tmp_path / "post_h3d",
        client=FakeClient(),
    )
    run_post_h3e(
        post_h3d_summary_path=tmp_path / "post_h3d" / "post_h3d_first_internal_runtime_execution_summary.json",
        output_root=tmp_path / "post_h3e",
        ack_receipt_write_authorization=True,
    )
    return tmp_path / "post_h3e" / "post_h3e_production_receipt_write_authorization_summary.json"
