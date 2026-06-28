from __future__ import annotations

import json
from pathlib import Path

from benchmarks.post_h3_deployment_boundary_gate import run_gate
from benchmarks.post_h3_internal_runtime_authorization_gate import REQUIRED_OPERATOR_DECISION
from benchmarks.post_h3_internal_runtime_authorization_gate import run_gate as run_post_h3a
from benchmarks.tests.test_post_h3_internal_runtime_authorization_gate import _write_h3_transition


def test_post_h3b_accepts_private_vm_boundary(tmp_path: Path) -> None:
    post_h3a = _write_post_h3a(tmp_path)

    summary = run_gate(
        post_h3a_summary_path=post_h3a,
        output_root=tmp_path / "post_h3b",
    )

    assert summary["passed"] is True
    assert summary["readiness"]["post_h3_deployment_boundary_ready"] is True
    assert summary["readiness"]["rollback_abort_drill_ready"] is True
    assert summary["boundary"]["private_vm_targets_verified"] is True
    assert summary["boundary"]["external_public_ingress_opened"] is False
    assert summary["boundary"]["deploy_performed"] is False


def test_post_h3b_blocks_public_ip_boundary(tmp_path: Path) -> None:
    post_h3a = _write_post_h3a(tmp_path)

    summary = run_gate(
        post_h3a_summary_path=post_h3a,
        output_root=tmp_path / "post_h3b",
        vm_targets=["vm1"],
        private_ips=["8.8.8.8"],
    )

    assert summary["passed"] is False
    assert "private_ips_are_private" in summary["failure_reasons"]
    assert summary["boundary"]["private_vm_targets_verified"] is False


def test_post_h3b_blocks_post_h3a_drift(tmp_path: Path) -> None:
    post_h3a = _write_post_h3a(tmp_path)
    payload = json.loads(post_h3a.read_text(encoding="utf-8"))
    payload["boundary"]["external_public_ingress_opened"] = True
    post_h3a.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    summary = run_gate(
        post_h3a_summary_path=post_h3a,
        output_root=tmp_path / "post_h3b",
    )

    assert summary["passed"] is False
    assert "post_h3a_no_public_ingress" in summary["failure_reasons"]
    assert summary["readiness"]["post_h3_deployment_boundary_ready"] is False


def _write_post_h3a(tmp_path: Path) -> Path:
    h3_transition = _write_h3_transition(tmp_path)
    run_post_h3a(
        h3_transition_path=h3_transition,
        output_root=tmp_path / "post_h3a",
        operator_id="operator-alpha",
        operator_decision=REQUIRED_OPERATOR_DECISION,
        operator_statement="Authorize internal controlled runtime after H.3 transition.",
        ack_internal_runtime=True,
    )
    return tmp_path / "post_h3a" / "post_h3a_internal_runtime_authorization_summary.json"
