from __future__ import annotations

import json
from pathlib import Path

from benchmarks.h3_goal_emission_runtime_production_evidence_gate import PRODUCTION_EVIDENCE_SCHEMA_VERSION
from benchmarks.h3_production_evidence_gap_mapper import run_mapper
from benchmarks.p1_controlled_production_pilot_charter_gate import run_gate as run_p1
from benchmarks.p0p_first_controlled_beta_task_execution_gate import run_execution as run_p0p
from benchmarks.tests.test_p0p_first_controlled_beta_task_execution_gate import FakeClient
from benchmarks.tests.test_p1_controlled_production_pilot_charter_gate import _write_p0o_summary


def test_h3_gap_mapper_marks_p0_p1_refs_as_candidates_not_satisfied(tmp_path: Path) -> None:
    p1_summary = _write_p1_summary(tmp_path)
    p1_payload = json.loads(p1_summary.read_text(encoding="utf-8"))
    p0o_summary = Path(p1_payload["source_artifacts"]["p0o_summary"]["path"])
    p0o_payload = json.loads(p0o_summary.read_text(encoding="utf-8"))
    p0n_summary = Path(p0o_payload["source_artifacts"]["p0n_summary"]["path"])

    summary = run_mapper(
        output=tmp_path / "h3_gap_map.json",
        p0n_summary_path=p0n_summary,
        p0o_summary_path=p0o_summary,
        p1_summary_path=p1_summary,
    )

    assert summary["passed"] is True
    assert summary["counts"]["required_evidence_count"] == 16
    assert summary["counts"]["production_satisfied_count"] == 0
    assert summary["counts"]["production_missing_count"] == 16
    assert summary["counts"]["candidate_ref_count"] > 0
    assert summary["readiness"]["h3_bundle_validation_ready"] is False
    assert all(item["production_satisfied"] is False for item in summary["gap_items"])


def test_h3_gap_mapper_maps_p0p_execution_as_candidate_only(tmp_path: Path) -> None:
    p1_summary = _write_p1_summary(tmp_path)
    p1_payload = json.loads(p1_summary.read_text(encoding="utf-8"))
    p0o_summary = Path(p1_payload["source_artifacts"]["p0o_summary"]["path"])
    p0o_payload = json.loads(p0o_summary.read_text(encoding="utf-8"))
    p0n_summary = Path(p0o_payload["source_artifacts"]["p0n_summary"]["path"])
    run_p0p(p0o_summary_path=p0o_summary, output_root=tmp_path / "p0p", client=FakeClient())
    p0p_summary = tmp_path / "p0p" / "p0p_first_controlled_beta_task_execution_summary.json"

    summary = run_mapper(
        output=tmp_path / "h3_gap_map.json",
        p0n_summary_path=p0n_summary,
        p0o_summary_path=p0o_summary,
        p0p_summary_path=p0p_summary,
        p1_summary_path=p1_summary,
    )

    assert summary["counts"]["production_satisfied_count"] == 0
    assert summary["source_artifacts"]["p0p_summary"]["path"] == str(p0p_summary.resolve())
    flattened_refs = [
        ref
        for item in summary["gap_items"]
        for ref in item["candidate_refs"]
        if ref["label"] == "p0p_first_controlled_beta_task_execution"
    ]
    assert flattened_refs
    assert {ref["satisfies_production_origin"] for ref in flattened_refs} == {"false"}


def test_h3_gap_mapper_counts_real_production_record_when_supplied(tmp_path: Path) -> None:
    p1_summary = _write_p1_summary(tmp_path)
    production_path = tmp_path / "production_evidence_submission.json"
    production_path.write_text(
        json.dumps(
            {
                "schema_version": PRODUCTION_EVIDENCE_SCHEMA_VERSION,
                "goal_id": "p1-production-pilot:civitasos-status-evidence-index",
                "production_evidence_records": [
                    {
                        "artifact_id": "prod-human-review-001",
                        "goal_id": "p1-production-pilot:civitasos-status-evidence-index",
                        "evidence_kind": "external_human_review_approval",
                        "reviewer": "owner@example.org",
                        "reviewer_role": "human_governance_reviewer",
                        "source": "production_change_management_system",
                        "status": "approved",
                        "attestation_ref": "chg-prod-001#human-review",
                        "human_review_ref": "chg-prod-001#human-review",
                    }
                ],
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    summary = run_mapper(
        output=tmp_path / "h3_gap_map.json",
        p1_summary_path=p1_summary,
        production_evidence_path=production_path,
    )

    assert summary["counts"]["production_satisfied_count"] == 1
    item = next(item for item in summary["gap_items"] if item["evidence_kind"] == "external_human_review_approval")
    assert item["production_satisfied"] is True
    assert item["gap_reason"] == "satisfied_by_real_production_record"


def _write_p1_summary(tmp_path: Path) -> Path:
    p0o_summary = _write_p0o_summary(tmp_path)
    run_p1(
        p0o_summary_path=p0o_summary,
        output_root=tmp_path / "p1",
        operator_id="operator-test",
        ack_p1_charter=True,
    )
    return tmp_path / "p1" / "p1_controlled_production_pilot_charter_summary.json"


def test_h3_gap_mapper_maps_p0q_source_refs_as_candidate_only(tmp_path: Path) -> None:
    p1_summary = _write_p1_summary(tmp_path)
    p1_payload = json.loads(p1_summary.read_text(encoding="utf-8"))
    p0o_summary = Path(p1_payload["source_artifacts"]["p0o_summary"]["path"])
    p0o_payload = json.loads(p0o_summary.read_text(encoding="utf-8"))
    p0n_summary = Path(p0o_payload["source_artifacts"]["p0n_summary"]["path"])
    run_p0p(p0o_summary_path=p0o_summary, output_root=tmp_path / "p0p", client=FakeClient())
    p0p_summary = tmp_path / "p0p" / "p0p_first_controlled_beta_task_execution_summary.json"

    from benchmarks.p0q_p1_source_ref_collection_gate import run_gate as run_p0q

    run_p0q(p0p_summary_path=p0p_summary, p1_summary_path=p1_summary, output_root=tmp_path / "p0q")
    p0q_summary = tmp_path / "p0q" / "p0q_p1_source_ref_collection_summary.json"

    summary = run_mapper(
        output=tmp_path / "h3_gap_map.json",
        p0n_summary_path=p0n_summary,
        p0o_summary_path=p0o_summary,
        p0p_summary_path=p0p_summary,
        p0q_summary_path=p0q_summary,
        p1_summary_path=p1_summary,
    )

    assert summary["counts"]["production_satisfied_count"] == 0
    assert summary["source_artifacts"]["p0q_summary"]["path"] == str(p0q_summary.resolve())
    flattened_refs = [
        ref
        for item in summary["gap_items"]
        for ref in item["candidate_refs"]
        if ref["label"] == "p0q_p1_source_ref_collection"
    ]
    assert flattened_refs
    assert {ref["satisfies_production_origin"] for ref in flattened_refs} == {"false"}
