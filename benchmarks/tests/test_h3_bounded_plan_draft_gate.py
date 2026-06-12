from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from benchmarks.h3_bounded_plan_draft_gate import (
    build_h3_bounded_plan_draft_gate,
)
from benchmarks.h3_operator_review_reconciliation_gate import (
    create_review_packet,
    reconcile_operator_reviews,
)
from benchmarks.h3_read_only_goal_proposal_gate import (
    build_h3_read_only_goal_proposal_gate,
)
from benchmarks.tests.test_h3_read_only_goal_proposal_gate import (
    _write_h2_report,
)


def test_reconciled_proposals_build_two_non_executable_drafts(
    tmp_path: Path,
) -> None:
    proposal_path, reconciliation_path = _write_inputs(tmp_path)

    report = build_h3_bounded_plan_draft_gate(
        proposal_report_path=proposal_path,
        reconciliation_report_path=reconciliation_path,
        agent_root=tmp_path,
    )

    assert report["passed"] is True
    assert report["draft_surface"]["draft_count"] == 2
    assert report["readiness"]["bounded_plan_drafts_ready_for_review"] is True
    assert report["boundary"]["goal_emission_allowed"] is False
    for draft in report["draft_surface"]["drafts"]:
        assert draft["state"] == "bounded_plan_draft_review_required"
        assert draft["source_binding"]["evidence_refs"]
        assert draft["challenge_window"]["required"] is True
        assert draft["rollback_plan"]
        assert draft["stop_conditions"]
        assert draft["review_policy"]["operator_review_required"] is True
        assert not any(
            value
            for key, value in draft["execution_policy"].items()
            if key != "draft_only"
        )


def test_plan_groups_preserve_merged_evidence(tmp_path: Path) -> None:
    proposal_path, reconciliation_path = _write_inputs(tmp_path)

    report = build_h3_bounded_plan_draft_gate(
        proposal_report_path=proposal_path,
        reconciliation_report_path=reconciliation_path,
        agent_root=tmp_path,
    )

    drafts = report["draft_surface"]["drafts"]
    success = next(
        item
        for item in drafts
        if item["proposal_kind"]
        == "review_conditions_for_preserving_successful_relations"
    )
    risk = next(
        item
        for item in drafts
        if item["proposal_kind"]
        == "review_relation_risk_and_verification_policy"
    )
    assert len(success["source_binding"]["proposal_ids"]) == 2
    assert len(success["source_binding"]["evidence_refs"]) == 2
    assert len(risk["source_binding"]["proposal_ids"]) == 4
    assert len(risk["source_binding"]["evidence_refs"]) == 4


def test_tampered_proposal_report_breaks_reconciliation_binding(
    tmp_path: Path,
) -> None:
    proposal_path, reconciliation_path = _write_inputs(tmp_path)
    proposal = json.loads(proposal_path.read_text(encoding="utf-8"))
    proposal["proposal_surface"]["proposals"][0]["rationale"] = "tampered"
    proposal_path.write_text(json.dumps(proposal), encoding="utf-8")

    report = build_h3_bounded_plan_draft_gate(
        proposal_report_path=proposal_path,
        reconciliation_report_path=reconciliation_path,
        agent_root=tmp_path,
    )

    assert report["passed"] is False
    assert report["checks"]["reconciliation_source_proposal_binding"] is False
    assert report["draft_surface"]["drafts"] == []


def test_reconciliation_boundary_regression_blocks_drafts(
    tmp_path: Path,
) -> None:
    proposal_path, reconciliation_path = _write_inputs(tmp_path)
    reconciliation = json.loads(reconciliation_path.read_text(encoding="utf-8"))
    reconciliation["boundary"]["runtime_execution_allowed"] = True
    reconciliation_path.write_text(json.dumps(reconciliation), encoding="utf-8")

    report = build_h3_bounded_plan_draft_gate(
        proposal_report_path=proposal_path,
        reconciliation_report_path=reconciliation_path,
        agent_root=tmp_path,
    )

    assert report["passed"] is False
    assert report["checks"]["reconciliation_boundary"] is False


def test_merge_target_kind_mismatch_blocks_drafts(tmp_path: Path) -> None:
    proposal_path, reconciliation_path = _write_inputs(tmp_path)
    proposal_report = json.loads(proposal_path.read_text(encoding="utf-8"))
    proposal_kind_by_id = {
        item["proposal_id"]: item["proposal_kind"]
        for item in proposal_report["proposal_surface"]["proposals"]
    }
    reconciliation = json.loads(reconciliation_path.read_text(encoding="utf-8"))
    merged = reconciliation["reconciliation"]["merged_proposals"]
    accepted = reconciliation["reconciliation"]["accepted_proposal_ids"]
    edge = merged[0]
    wrong_target = next(
        proposal_id
        for proposal_id in accepted
        if proposal_kind_by_id[proposal_id]
        != proposal_kind_by_id[edge["proposal_id"]]
    )
    edge["merge_into_proposal_id"] = wrong_target
    for review in reconciliation["reconciliation"]["reviews"]:
        if review["proposal_id"] == edge["proposal_id"]:
            review["merge_into_proposal_id"] = wrong_target
    reconciliation_path.write_text(json.dumps(reconciliation), encoding="utf-8")

    report = build_h3_bounded_plan_draft_gate(
        proposal_report_path=proposal_path,
        reconciliation_report_path=reconciliation_path,
        agent_root=tmp_path,
    )

    assert report["passed"] is False
    assert report["checks"]["merged_proposal_kinds_match_targets"] is False


def test_tampered_review_proposal_hash_blocks_drafts(tmp_path: Path) -> None:
    proposal_path, reconciliation_path = _write_inputs(tmp_path)
    reconciliation = json.loads(reconciliation_path.read_text(encoding="utf-8"))
    reconciliation["reconciliation"]["reviews"][0]["proposal_sha256"] = "0" * 64
    reconciliation_path.write_text(json.dumps(reconciliation), encoding="utf-8")

    report = build_h3_bounded_plan_draft_gate(
        proposal_report_path=proposal_path,
        reconciliation_report_path=reconciliation_path,
        agent_root=tmp_path,
    )

    assert report["passed"] is False
    assert report["checks"]["review_proposal_hashes_match"] is False


def test_review_packet_hash_mismatch_blocks_drafts(tmp_path: Path) -> None:
    proposal_path, reconciliation_path = _write_inputs(tmp_path)
    reconciliation = json.loads(reconciliation_path.read_text(encoding="utf-8"))
    review_packet_path = Path(reconciliation["source_review_packet"]["path"])
    packet = json.loads(review_packet_path.read_text(encoding="utf-8"))
    packet["state"] = "tampered"
    review_packet_path.write_text(json.dumps(packet), encoding="utf-8")

    report = build_h3_bounded_plan_draft_gate(
        proposal_report_path=proposal_path,
        reconciliation_report_path=reconciliation_path,
        agent_root=tmp_path,
    )

    assert report["passed"] is False
    assert report["checks"]["review_packet_hash_matches"] is False


def _write_inputs(tmp_path: Path) -> tuple[Path, Path]:
    h2_path = _write_h2_report(tmp_path / "h2.json")
    proposal_report = build_h3_read_only_goal_proposal_gate(
        h2_evidence_report_path=h2_path,
        agent_root=tmp_path,
    )
    proposal_path = tmp_path / "proposals.json"
    proposal_path.write_text(json.dumps(proposal_report), encoding="utf-8")

    packet_path = tmp_path / "reviews.json"
    packet = create_review_packet(
        proposal_report_path=proposal_path,
        output_path=packet_path,
        agent_root=tmp_path,
    )
    proposals = proposal_report["proposal_surface"]["proposals"]
    success_ids = [
        item["proposal_id"]
        for item in proposals
        if item["proposal_kind"]
        == "review_conditions_for_preserving_successful_relations"
    ]
    risk_ids = [
        item["proposal_id"]
        for item in proposals
        if item["proposal_kind"]
        == "review_relation_risk_and_verification_policy"
    ]
    accepted = {success_ids[0], risk_ids[0]}
    merge_targets = {
        **{item: success_ids[0] for item in success_ids[1:]},
        **{item: risk_ids[0] for item in risk_ids[1:]},
    }
    reviewed_at = datetime.now(timezone.utc).isoformat()
    for review in packet["reviews"]:
        proposal_id = review["proposal_id"]
        decision = "accept" if proposal_id in accepted else "merge"
        review.update(
            {
                "decision": decision,
                "reason": f"operator decision for {proposal_id}",
                "reviewer_id": "operator-001",
                "reviewer_role": "human_operator",
                "reviewed_at": reviewed_at,
                "merge_into_proposal_id": merge_targets.get(proposal_id),
                "evidence_request": None,
            }
        )
    packet_path.write_text(json.dumps(packet), encoding="utf-8")

    reconciliation_path = tmp_path / "reconciliation.json"
    reconciliation = reconcile_operator_reviews(
        proposal_report_path=proposal_path,
        review_packet_path=packet_path,
        output_path=reconciliation_path,
        agent_root=tmp_path,
    )
    assert reconciliation["passed"] is True
    return proposal_path, reconciliation_path
