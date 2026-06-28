from __future__ import annotations

import json
from pathlib import Path

from benchmarks.p0p_first_controlled_beta_task_execution_gate import run_execution as run_p0p
from benchmarks.p0q_p1_source_ref_collection_gate import run_gate
from benchmarks.p1_controlled_production_pilot_charter_gate import run_gate as run_p1
from benchmarks.tests.test_p0p_first_controlled_beta_task_execution_gate import FakeClient
from benchmarks.tests.test_p1_controlled_production_pilot_charter_gate import _write_p0o_summary


def test_p0q_p1_source_ref_collection_passes_candidate_only(tmp_path: Path) -> None:
    p0p_summary, p1_summary = _write_inputs(tmp_path)

    summary = run_gate(
        p0p_summary_path=p0p_summary,
        p1_summary_path=p1_summary,
        output_root=tmp_path / "p0q",
        operator_id="operator-test",
    )

    assert summary["passed"] is True
    assert summary["readiness"]["p0q_p1_source_ref_collection_complete"] is True
    assert summary["readiness"]["h3_bundle_validation_ready"] is False
    assert summary["boundary"]["source_ref_collection_written"] is True
    assert summary["boundary"]["production_transition_allowed"] is False
    assert summary["source_ref_count"] == 4
    for name in (
        "owner_source_ref",
        "audit_source_ref",
        "monitoring_source_ref",
        "rollback_source_ref",
    ):
        ref = json.loads(Path(summary["artifacts"][name]["path"]).read_text(encoding="utf-8"))
        assert ref["schema_version"] == "p0q-p1-source-ref:v1"
        assert ref["candidate_only"] is True
        assert ref["satisfies_production_origin"] is False
        assert ref["requires_real_external_confirmation"] is True


def test_p0q_blocks_p0p_hash_drift(tmp_path: Path) -> None:
    p0p_summary, p1_summary = _write_inputs(tmp_path)
    payload = json.loads(p0p_summary.read_text(encoding="utf-8"))
    receipt_path = Path(payload["artifacts"]["task_pool_execution_receipt"]["path"])
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["delivery_observed"] = False
    receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    summary = run_gate(p0p_summary_path=p0p_summary, p1_summary_path=p1_summary, output_root=tmp_path / "p0q")

    assert summary["passed"] is False
    assert summary["readiness"]["production_transition_allowed"] is False
    assert "p0p_task_pool_execution_receipt_hash_valid" in summary["failure_reasons"]


def test_p0q_blocks_p0p_production_boundary_drift(tmp_path: Path) -> None:
    p0p_summary, p1_summary = _write_inputs(tmp_path)
    payload = json.loads(p0p_summary.read_text(encoding="utf-8"))
    payload["boundary"]["production_transition_allowed"] = True
    p0p_summary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    summary = run_gate(p0p_summary_path=p0p_summary, p1_summary_path=p1_summary, output_root=tmp_path / "p0q")

    assert summary["passed"] is False
    assert "p0p_boundary_closed" in summary["failure_reasons"]


def test_p0q_blocks_p1_source_mismatch(tmp_path: Path) -> None:
    p0p_summary, p1_summary = _write_inputs(tmp_path)
    payload = json.loads(p1_summary.read_text(encoding="utf-8"))
    payload["source_artifacts"]["p0o_summary"]["sha256"] = "0" * 64
    p1_summary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    summary = run_gate(p0p_summary_path=p0p_summary, p1_summary_path=p1_summary, output_root=tmp_path / "p0q")

    assert summary["passed"] is False
    assert "p0p_p1_share_p0o_source" in summary["failure_reasons"]


def _write_inputs(tmp_path: Path) -> tuple[Path, Path]:
    p0o_summary = _write_p0o_summary(tmp_path)
    run_p0p(p0o_summary_path=p0o_summary, output_root=tmp_path / "p0p", client=FakeClient())
    run_p1(
        p0o_summary_path=p0o_summary,
        output_root=tmp_path / "p1",
        operator_id="operator-test",
        ack_p1_charter=True,
    )
    return (
        tmp_path / "p0p" / "p0p_first_controlled_beta_task_execution_summary.json",
        tmp_path / "p1" / "p1_controlled_production_pilot_charter_summary.json",
    )
