from __future__ import annotations

import json
from pathlib import Path

from benchmarks.p0k_private_preview_soak_gate import run_gate as run_p0k
from benchmarks.p0l_external_preview_evidence_gate import run_gate
from benchmarks.tests.test_p0g_single_vm_private_preview_gate import _py
from benchmarks.tests.test_p0k_private_preview_soak_gate import _smoke_code_with_latency, _write_p0j_summary


def test_p0l_external_preview_evidence_passes(tmp_path: Path) -> None:
    p0k_summary = _write_p0k_summary(tmp_path)

    summary = run_gate(
        p0k_summary_path=p0k_summary,
        output_root=tmp_path / "p0l",
        operator_id="operator-test",
        ack_external_preview_evidence=True,
    )

    assert summary["passed"] is True
    assert summary["readiness"]["p0m_controlled_beta_readiness_review_ready"] is True
    assert summary["boundary"]["owner_feedback_written"] is True
    assert summary["boundary"]["audit_review_written"] is True
    assert summary["boundary"]["environment_proof_written"] is True
    assert summary["boundary"]["rollback_proof_written"] is True
    assert summary["boundary"]["no_production_boundary_evidence_written"] is True
    assert summary["boundary"]["preview_command_executed"] is False
    assert summary["boundary"]["production_receipt_write_allowed"] is False


def test_p0l_requires_operator_ack(tmp_path: Path) -> None:
    p0k_summary = _write_p0k_summary(tmp_path)

    summary = run_gate(
        p0k_summary_path=p0k_summary,
        output_root=tmp_path / "p0l",
        operator_id="operator-test",
        ack_external_preview_evidence=False,
    )

    assert summary["passed"] is False
    assert "explicit_operator_ack" in summary["failure_reasons"]
    assert summary["boundary"]["production_transition_allowed"] is False


def test_p0l_blocks_p0k_artifact_hash_drift(tmp_path: Path) -> None:
    p0k_summary = _write_p0k_summary(tmp_path)
    payload = json.loads(p0k_summary.read_text(encoding="utf-8"))
    soak_path = Path(payload["artifacts"]["soak_receipt"]["path"])
    soak = json.loads(soak_path.read_text(encoding="utf-8"))
    soak["completed_cycles"] = 999
    soak_path.write_text(json.dumps(soak, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    summary = run_gate(
        p0k_summary_path=p0k_summary,
        output_root=tmp_path / "p0l",
        operator_id="operator-test",
        ack_external_preview_evidence=True,
    )

    assert summary["passed"] is False
    assert "p0k_soak_receipt_hash_valid" in summary["failure_reasons"]


def test_p0l_blocks_production_boundary_drift(tmp_path: Path) -> None:
    p0k_summary = _write_p0k_summary(tmp_path)
    payload = json.loads(p0k_summary.read_text(encoding="utf-8"))
    payload["boundary"]["external_public_ingress_opened"] = True
    p0k_summary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    summary = run_gate(
        p0k_summary_path=p0k_summary,
        output_root=tmp_path / "p0l",
        operator_id="operator-test",
        ack_external_preview_evidence=True,
    )

    assert summary["passed"] is False
    assert "p0k_boundary_closed" in summary["failure_reasons"]


def _write_p0k_summary(tmp_path: Path) -> Path:
    p0j_summary = _write_p0j_summary(tmp_path)
    run_p0k(
        p0j_summary_path=p0j_summary,
        output_root=tmp_path / "p0k",
        deploy_command=_py("print('deploy')"),
        smoke_command=_py(_smoke_code_with_latency(["vm1", "vm2", "vm3"], 12.5)),
        rollback_command=_py("print('rollback')"),
        rollback_health_command=_py("print('rollback-health')"),
        expected_nodes=["vm1", "vm2", "vm3"],
        cycles=2,
        interval_seconds=0,
        max_latency_ms=100,
        operator_id="operator-test",
        ack_private_preview_soak=True,
        working_directory=tmp_path,
    )
    return tmp_path / "p0k" / "p0k_private_preview_soak_chain_summary.json"
