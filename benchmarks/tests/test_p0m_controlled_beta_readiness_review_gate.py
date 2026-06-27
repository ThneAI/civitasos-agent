from __future__ import annotations

import json
from pathlib import Path

from benchmarks.p0l_external_preview_evidence_gate import run_gate as run_p0l
from benchmarks.p0m_controlled_beta_readiness_review_gate import run_gate
from benchmarks.tests.test_p0l_external_preview_evidence_gate import _write_p0k_summary


def test_p0m_controlled_beta_readiness_passes(tmp_path: Path) -> None:
    p0l_summary = _write_p0l_summary(tmp_path)

    summary = run_gate(
        p0l_summary_path=p0l_summary,
        output_root=tmp_path / "p0m",
        operator_id="operator-test",
        ack_controlled_beta_readiness=True,
    )

    assert summary["passed"] is True
    assert summary["readiness"]["controlled_beta_candidate_ready"] is True
    assert summary["review"]["gate_count"] == 13
    assert summary["review"]["evidence_count"] == 5
    assert summary["boundary"]["chain_validation_written"] is True
    assert summary["boundary"]["readiness_review_written"] is True
    assert summary["boundary"]["beta_scope_written"] is True
    assert summary["boundary"]["operator_reconciliation_written"] is True
    assert summary["boundary"]["production_transition_allowed"] is False


def test_p0m_requires_operator_ack(tmp_path: Path) -> None:
    p0l_summary = _write_p0l_summary(tmp_path)

    summary = run_gate(
        p0l_summary_path=p0l_summary,
        output_root=tmp_path / "p0m",
        operator_id="operator-test",
        ack_controlled_beta_readiness=False,
    )

    assert summary["passed"] is False
    assert "explicit_operator_ack" in summary["failure_reasons"]
    assert summary["readiness"]["production_transition_allowed"] is False


def test_p0m_blocks_source_chain_hash_drift(tmp_path: Path) -> None:
    p0l_summary = _write_p0l_summary(tmp_path)
    payload = json.loads(p0l_summary.read_text(encoding="utf-8"))
    p0k_path = Path(payload["source_artifacts"]["p0k_summary"]["path"])
    p0k = json.loads(p0k_path.read_text(encoding="utf-8"))
    p0k["passed"] = False
    p0k_path.write_text(json.dumps(p0k, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    summary = run_gate(
        p0l_summary_path=p0l_summary,
        output_root=tmp_path / "p0m",
        operator_id="operator-test",
        ack_controlled_beta_readiness=True,
    )

    assert summary["passed"] is False
    assert "p0l_source_p0k_summary_hash_valid" in summary["failure_reasons"]


def test_p0m_blocks_public_ingress_boundary_drift(tmp_path: Path) -> None:
    p0l_summary = _write_p0l_summary(tmp_path)
    payload = json.loads(p0l_summary.read_text(encoding="utf-8"))
    payload["boundary"]["external_public_ingress_opened"] = True
    p0l_summary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    summary = run_gate(
        p0l_summary_path=p0l_summary,
        output_root=tmp_path / "p0m",
        operator_id="operator-test",
        ack_controlled_beta_readiness=True,
    )

    assert summary["passed"] is False
    assert "p0l_boundary_no_production_violation" in summary["failure_reasons"]


def _write_p0l_summary(tmp_path: Path) -> Path:
    p0k_summary = _write_p0k_summary(tmp_path)
    run_p0l(
        p0k_summary_path=p0k_summary,
        output_root=tmp_path / "p0l",
        operator_id="operator-test",
        ack_external_preview_evidence=True,
    )
    return tmp_path / "p0l" / "p0l_external_preview_evidence_chain_summary.json"
