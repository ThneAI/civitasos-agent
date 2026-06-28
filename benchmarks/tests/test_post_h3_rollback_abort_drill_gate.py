from __future__ import annotations

import json
from pathlib import Path

from benchmarks.post_h3_deployment_boundary_gate import run_gate as run_post_h3b
from benchmarks.post_h3_rollback_abort_drill_gate import run_gate
from benchmarks.tests.test_post_h3_deployment_boundary_gate import _write_post_h3a


def test_post_h3c_completes_rollback_abort_drill(tmp_path: Path) -> None:
    post_h3b = _write_post_h3b(tmp_path)

    summary = run_gate(
        post_h3b_summary_path=post_h3b,
        output_root=tmp_path / "post_h3c",
        ack_rollback_abort_drill=True,
    )

    assert summary["passed"] is True
    assert summary["readiness"]["post_h3_rollback_abort_drill_complete"] is True
    assert summary["readiness"]["first_internal_runtime_execution_ready"] is True
    assert summary["readiness"]["runtime_execution_allowed"] is True
    assert summary["readiness"]["runtime_execution_performed"] is False
    assert summary["readiness"]["production_runtime_receipt_write_allowed"] is False
    assert summary["boundary"]["abort_path_verified"] is True
    assert summary["boundary"]["rollback_path_verified"] is True
    assert summary["boundary"]["vm_contact_performed"] is False
    assert summary["boundary"]["deploy_performed"] is False
    assert summary["boundary"]["external_public_ingress_opened"] is False


def test_post_h3c_requires_explicit_operator_ack(tmp_path: Path) -> None:
    post_h3b = _write_post_h3b(tmp_path)

    summary = run_gate(
        post_h3b_summary_path=post_h3b,
        output_root=tmp_path / "post_h3c",
        ack_rollback_abort_drill=False,
    )

    assert summary["passed"] is False
    assert "explicit_operator_ack" in summary["failure_reasons"]
    assert summary["readiness"]["first_internal_runtime_execution_ready"] is False


def test_post_h3c_blocks_public_ingress_drift(tmp_path: Path) -> None:
    post_h3b = _write_post_h3b(tmp_path)
    payload = json.loads(post_h3b.read_text(encoding="utf-8"))
    payload["boundary"]["external_public_ingress_opened"] = True
    post_h3b.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    summary = run_gate(
        post_h3b_summary_path=post_h3b,
        output_root=tmp_path / "post_h3c",
        ack_rollback_abort_drill=True,
    )

    assert summary["passed"] is False
    assert "post_h3b_no_public_ingress" in summary["failure_reasons"]
    assert summary["boundary"]["abort_path_verified"] is False


def _write_post_h3b(tmp_path: Path) -> Path:
    post_h3a = _write_post_h3a(tmp_path)
    run_post_h3b(
        post_h3a_summary_path=post_h3a,
        output_root=tmp_path / "post_h3b",
    )
    return tmp_path / "post_h3b" / "post_h3b_deployment_boundary_summary.json"
