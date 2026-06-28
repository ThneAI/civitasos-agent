from __future__ import annotations

import json
from pathlib import Path

from benchmarks.p1r_real_source_confirmation_collection_packet import write_collection_packet
from benchmarks.p1r_real_source_confirmation_gate import run_gate
from benchmarks.tests.test_p1r_real_source_confirmation_gate import _write_p0q_inputs


def test_p1r_collection_packet_writes_four_templates(tmp_path: Path) -> None:
    p0q_summary, p1_summary = _write_p0q_inputs(tmp_path)

    summary = write_collection_packet(
        output_root=tmp_path / "packet",
        p0q_summary_path=p0q_summary,
        p1_summary_path=p1_summary,
    )

    assert summary["passed"] is True
    assert summary["ready_for_p1r_gate"] is False
    assert summary["template_record_count"] == 16
    assert (tmp_path / "packet" / "run_p1r_gate.sh").is_file()
    for role in ("owner", "audit", "monitoring", "rollback"):
        path = tmp_path / "packet" / "inputs" / f"{role}_confirmation.json"
        payload = json.loads(path.read_text(encoding="utf-8"))
        assert payload["confirmation_role"] == role
        assert payload["production_origin_confirmed"] is False
        assert payload["candidate_ref_promoted"] is False
        assert payload["records"]


def test_p1r_collection_templates_fail_closed_until_filled(tmp_path: Path) -> None:
    p0q_summary, p1_summary = _write_p0q_inputs(tmp_path)
    write_collection_packet(
        output_root=tmp_path / "packet",
        p0q_summary_path=p0q_summary,
        p1_summary_path=p1_summary,
    )

    summary = run_gate(
        p0q_summary_path=p0q_summary,
        p1_summary_path=p1_summary,
        owner_confirmation_path=tmp_path / "packet" / "inputs" / "owner_confirmation.json",
        audit_confirmation_path=tmp_path / "packet" / "inputs" / "audit_confirmation.json",
        monitoring_confirmation_path=tmp_path / "packet" / "inputs" / "monitoring_confirmation.json",
        rollback_confirmation_path=tmp_path / "packet" / "inputs" / "rollback_confirmation.json",
        output_root=tmp_path / "p1r",
    )

    assert summary["passed"] is False
    assert "production_evidence_submission" not in summary["artifacts"]
    assert summary["readiness"]["production_transition_allowed"] is False
