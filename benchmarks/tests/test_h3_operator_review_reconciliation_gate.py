from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from benchmarks.h3_operator_review_reconciliation_gate import (
    create_review_packet,
    reconcile_operator_reviews,
)
from benchmarks.tests.test_h3_read_only_goal_proposal_gate import (
    _write_h2_report,
)
from benchmarks.h3_read_only_goal_proposal_gate import (
    build_h3_read_only_goal_proposal_gate,
)


def test_init_binds_all_proposals_as_pending_reviews(tmp_path: Path) -> None:
    proposal_path = _write_proposal_report(tmp_path)
    packet_path = tmp_path / "reviews.json"

    packet = create_review_packet(
        proposal_report_path=proposal_path,
        output_path=packet_path,
        agent_root=tmp_path,
    )

    assert packet["proposal_count"] == 6
    assert len(packet["reviews"]) == 6
    assert {review["decision"] for review in packet["reviews"]} == {"pending"}
    assert all(len(review["proposal_sha256"]) == 64 for review in packet["reviews"])
    assert packet["boundary"]["goal_emission_allowed"] is False


def test_complete_reviews_reconcile_without_execution_authority(
    tmp_path: Path,
) -> None:
    proposal_path = _write_proposal_report(tmp_path)
    packet_path = _write_completed_packet(tmp_path, proposal_path)
    output = tmp_path / "reconciliation.json"

    report = reconcile_operator_reviews(
        proposal_report_path=proposal_path,
        review_packet_path=packet_path,
        output_path=output,
        agent_root=tmp_path,
    )

    assert report["passed"] is True
    assert report["review_summary"] == {
        "proposal_count": 6,
        "review_count": 6,
        "accepted_count": 2,
        "rejected_count": 1,
        "merged_count": 1,
        "need_more_evidence_count": 2,
    }
    assert report["readiness"]["bounded_plan_draft_input_ready"] is True
    assert report["boundary"]["bounded_plan_draft_input_ready"] is True
    assert report["boundary"]["goal_emission_allowed"] is False
    assert report["boundary"]["runtime_execution_allowed"] is False


def test_pending_or_missing_review_blocks_reconciliation(tmp_path: Path) -> None:
    proposal_path = _write_proposal_report(tmp_path)
    packet_path = tmp_path / "reviews.json"
    packet = create_review_packet(
        proposal_report_path=proposal_path,
        output_path=packet_path,
        agent_root=tmp_path,
    )
    packet["reviews"].pop()
    packet_path.write_text(json.dumps(packet), encoding="utf-8")

    report = reconcile_operator_reviews(
        proposal_report_path=proposal_path,
        review_packet_path=packet_path,
        output_path=tmp_path / "reconciliation.json",
        agent_root=tmp_path,
    )

    assert report["passed"] is False
    assert report["checks"]["all_proposals_reviewed_exactly_once"] is False
    assert report["reconciliation"]["reviews"] == []


def test_tampered_proposal_report_breaks_packet_hash_binding(tmp_path: Path) -> None:
    proposal_path = _write_proposal_report(tmp_path)
    packet_path = _write_completed_packet(tmp_path, proposal_path)
    proposal = json.loads(proposal_path.read_text(encoding="utf-8"))
    proposal["proposal_surface"]["proposals"][0]["rationale"] = "tampered"
    proposal_path.write_text(json.dumps(proposal), encoding="utf-8")

    report = reconcile_operator_reviews(
        proposal_report_path=proposal_path,
        review_packet_path=packet_path,
        output_path=tmp_path / "reconciliation.json",
        agent_root=tmp_path,
    )

    assert report["passed"] is False
    assert report["checks"]["review_packet_source_binding"] is False
    assert report["checks"]["review_fields_valid"] is False


def test_merge_must_target_an_accepted_proposal(tmp_path: Path) -> None:
    proposal_path = _write_proposal_report(tmp_path)
    packet_path = _write_completed_packet(tmp_path, proposal_path)
    packet = json.loads(packet_path.read_text(encoding="utf-8"))
    packet["reviews"][2]["merge_into_proposal_id"] = packet["reviews"][1][
        "proposal_id"
    ]
    packet_path.write_text(json.dumps(packet), encoding="utf-8")

    report = reconcile_operator_reviews(
        proposal_report_path=proposal_path,
        review_packet_path=packet_path,
        output_path=tmp_path / "reconciliation.json",
        agent_root=tmp_path,
    )

    assert report["passed"] is False
    assert report["checks"]["merge_graph_valid"] is False


def test_source_execution_boundary_regression_blocks_review(tmp_path: Path) -> None:
    proposal_path = _write_proposal_report(tmp_path)
    packet_path = _write_completed_packet(tmp_path, proposal_path)
    proposal = json.loads(proposal_path.read_text(encoding="utf-8"))
    proposal["h3_boundary"]["goal_emission_allowed"] = True
    proposal_path.write_text(json.dumps(proposal), encoding="utf-8")

    report = reconcile_operator_reviews(
        proposal_report_path=proposal_path,
        review_packet_path=packet_path,
        output_path=tmp_path / "reconciliation.json",
        agent_root=tmp_path,
    )

    assert report["passed"] is False
    assert report["checks"]["proposal_report_boundary"] is False


def _write_proposal_report(tmp_path: Path) -> Path:
    h2_path = _write_h2_report(tmp_path / "h2.json")
    report = build_h3_read_only_goal_proposal_gate(
        h2_evidence_report_path=h2_path,
        agent_root=tmp_path,
    )
    path = tmp_path / "proposals.json"
    path.write_text(json.dumps(report), encoding="utf-8")
    return path


def _write_completed_packet(tmp_path: Path, proposal_path: Path) -> Path:
    path = tmp_path / "reviews.json"
    packet = create_review_packet(
        proposal_report_path=proposal_path,
        output_path=path,
        agent_root=tmp_path,
    )
    decisions = (
        "accept",
        "reject",
        "merge",
        "need_more_evidence",
        "accept",
        "need_more_evidence",
    )
    accepted_target = packet["reviews"][0]["proposal_id"]
    reviewed_at = datetime.now(timezone.utc).isoformat()
    for review, decision in zip(packet["reviews"], decisions):
        review.update(
            {
                "decision": decision,
                "reason": f"operator rationale for {decision}",
                "reviewer_id": "operator-001",
                "reviewer_role": "operator",
                "reviewed_at": reviewed_at,
                "merge_into_proposal_id": (
                    accepted_target if decision == "merge" else None
                ),
                "evidence_request": (
                    "collect another bounded consequence observation"
                    if decision == "need_more_evidence"
                    else None
                ),
            }
        )
    path.write_text(json.dumps(packet), encoding="utf-8")
    return path
