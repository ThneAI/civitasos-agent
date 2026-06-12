from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from benchmarks.h3_bounded_plan_challenge_review_gate import (
    challenge_review_status,
    create_challenge_review_packet,
    record_challenge_review,
    reconcile_challenge_reviews,
)
from benchmarks.h3_bounded_plan_draft_gate import (
    build_h3_bounded_plan_draft_gate,
)
from benchmarks.tests.test_h3_bounded_plan_draft_gate import _write_inputs


OPENED_AT = datetime(2026, 6, 9, 0, 0, tzinfo=timezone.utc)


def test_init_creates_three_role_reviews_per_draft(tmp_path: Path) -> None:
    source_path = _write_bounded_plan(tmp_path)
    packet_path = tmp_path / "challenge_packet.json"

    packet = create_challenge_review_packet(
        bounded_plan_report_path=source_path,
        output_path=packet_path,
        agent_root=tmp_path,
        opened_at=OPENED_AT,
    )

    assert packet["state"] == "challenge_window_open"
    assert packet["validation_profile"] == "qualification"
    assert packet["development_only"] is False
    assert packet["valid_for_qualification"] is True
    assert packet["draft_count"] == 2
    assert packet["required_review_count"] == 6
    assert packet["minimum_duration_seconds"] == 86400
    assert packet["closes_at"] == (OPENED_AT + timedelta(days=1)).isoformat()
    assert {item["reviewer_role"] for item in packet["reviews"]} == {
        "operator",
        "audit_owner",
        "affected_relation_owner",
    }


def test_development_profile_uses_short_non_qualification_window(
    tmp_path: Path,
) -> None:
    source_path = _write_bounded_plan(tmp_path)
    packet_path = tmp_path / "development_packet.json"

    packet = create_challenge_review_packet(
        bounded_plan_report_path=source_path,
        output_path=packet_path,
        agent_root=tmp_path,
        opened_at=OPENED_AT,
        validation_profile="development",
        development_window_seconds=60,
    )

    assert packet["validation_profile"] == "development"
    assert packet["development_only"] is True
    assert packet["valid_for_qualification"] is False
    assert packet["minimum_duration_seconds"] == 60
    assert packet["qualification_minimum_duration_seconds"] == 86400
    assert packet["closes_at"] == (OPENED_AT + timedelta(seconds=60)).isoformat()


def test_development_reconciliation_never_claims_qualification_ready(
    tmp_path: Path,
) -> None:
    source_path, packet_path = _write_completed_packet(
        tmp_path,
        validation_profile="development",
        window_seconds=60,
    )

    report = reconcile_challenge_reviews(
        bounded_plan_report_path=source_path,
        review_packet_path=packet_path,
        output_path=tmp_path / "development_reconciliation.json",
        agent_root=tmp_path,
        current_time=OPENED_AT + timedelta(seconds=61),
    )

    assert report["passed"] is True
    assert report["validation_profile"] == "development"
    assert report["development_only"] is True
    assert report["valid_for_qualification"] is False
    assert (
        report["readiness"]["decision"]
        == "h3_development_authorization_request_flow_validated"
    )
    assert (
        report["readiness"]["development_authorization_request_input_ready"]
        is True
    )
    assert (
        report["readiness"]["controlled_pilot_authorization_request_ready"]
        is False
    )
    assert (
        report["boundary"]["controlled_pilot_authorization_request_ready"]
        is False
    )
    assert report["boundary"]["controlled_pilot_execution_allowed"] is False


def test_legacy_packet_without_profile_remains_qualification_compatible(
    tmp_path: Path,
) -> None:
    source_path, packet_path = _write_completed_packet(tmp_path)
    packet = json.loads(packet_path.read_text(encoding="utf-8"))
    packet.pop("validation_profile")
    packet.pop("development_only")
    packet.pop("valid_for_qualification")
    packet.pop("qualification_minimum_duration_seconds")
    packet_path.write_text(json.dumps(packet), encoding="utf-8")

    report = reconcile_challenge_reviews(
        bounded_plan_report_path=source_path,
        review_packet_path=packet_path,
        output_path=tmp_path / "legacy_reconciliation.json",
        agent_root=tmp_path,
        current_time=OPENED_AT + timedelta(days=1, minutes=1),
    )

    assert report["passed"] is True
    assert report["validation_profile"] == "qualification"
    assert report["development_only"] is False
    assert report["valid_for_qualification"] is True
    assert (
        report["readiness"]["controlled_pilot_authorization_request_ready"]
        is True
    )


def test_reconciliation_before_window_close_fails_closed(tmp_path: Path) -> None:
    source_path, packet_path = _write_completed_packet(tmp_path)

    report = reconcile_challenge_reviews(
        bounded_plan_report_path=source_path,
        review_packet_path=packet_path,
        output_path=tmp_path / "reconciliation.json",
        agent_root=tmp_path,
        current_time=OPENED_AT + timedelta(hours=23),
    )

    assert report["passed"] is False
    assert report["checks"]["challenge_window_closed"] is False
    assert report["readiness"]["decision"] == "challenge_window_open"
    assert (
        report["readiness"]["next_action"]
        == "wait for the minimum challenge window to close"
    )
    assert (
        report["boundary"]["controlled_pilot_authorization_request_ready"]
        is False
    )


def test_status_reports_remaining_time_and_pending_reviews(tmp_path: Path) -> None:
    source_path = _write_bounded_plan(tmp_path)
    packet_path = tmp_path / "challenge_packet.json"
    create_challenge_review_packet(
        bounded_plan_report_path=source_path,
        output_path=packet_path,
        agent_root=tmp_path,
        opened_at=OPENED_AT,
    )

    report = challenge_review_status(
        review_packet_path=packet_path,
        agent_root=tmp_path,
        current_time=OPENED_AT + timedelta(hours=2),
    )

    assert report["time_state"] == "WAITING"
    assert report["remaining_seconds"] == 22 * 3600
    assert report["pending_review_count"] == 6


def test_record_completes_one_review_slot_atomically(tmp_path: Path) -> None:
    source_path = _write_bounded_plan(tmp_path)
    packet_path = tmp_path / "challenge_packet.json"
    packet = create_challenge_review_packet(
        bounded_plan_report_path=source_path,
        output_path=packet_path,
        agent_root=tmp_path,
        opened_at=OPENED_AT,
    )
    draft_id = packet["reviews"][0]["draft_id"]

    result = record_challenge_review(
        review_packet_path=packet_path,
        agent_root=tmp_path,
        draft_id=draft_id,
        reviewer_role="operator",
        reviewer_id="operator-001",
        decision="approve_for_authorization_request",
        reason="bounded draft is suitable for authorization review",
        current_time=OPENED_AT + timedelta(hours=1),
    )

    assert result["recorded"] is True
    updated = json.loads(packet_path.read_text(encoding="utf-8"))
    review = next(
        item
        for item in updated["reviews"]
        if item["draft_id"] == draft_id and item["reviewer_role"] == "operator"
    )
    assert review["decision"] == "approve_for_authorization_request"
    assert review["reviewer_id"] == "operator-001"


def test_record_rejects_duplicate_and_incomplete_revision(tmp_path: Path) -> None:
    source_path = _write_bounded_plan(tmp_path)
    packet_path = tmp_path / "challenge_packet.json"
    packet = create_challenge_review_packet(
        bounded_plan_report_path=source_path,
        output_path=packet_path,
        agent_root=tmp_path,
        opened_at=OPENED_AT,
    )
    draft_id = packet["reviews"][0]["draft_id"]

    try:
        record_challenge_review(
            review_packet_path=packet_path,
            agent_root=tmp_path,
            draft_id=draft_id,
            reviewer_role="operator",
            reviewer_id="operator-001",
            decision="request_revision",
            reason="scope needs revision before authorization review",
            current_time=OPENED_AT + timedelta(hours=1),
        )
    except ValueError as exc:
        assert "requested changes" in str(exc)
    else:
        raise AssertionError("incomplete revision must be rejected")

    record_challenge_review(
        review_packet_path=packet_path,
        agent_root=tmp_path,
        draft_id=draft_id,
        reviewer_role="operator",
        reviewer_id="operator-001",
        decision="reject",
        reason="evidence does not justify a controlled pilot request",
        current_time=OPENED_AT + timedelta(hours=1),
    )
    try:
        record_challenge_review(
            review_packet_path=packet_path,
            agent_root=tmp_path,
            draft_id=draft_id,
            reviewer_role="operator",
            reviewer_id="operator-001",
            decision="reject",
            reason="duplicate review must not overwrite the first decision",
            current_time=OPENED_AT + timedelta(hours=2),
        )
    except FileExistsError:
        pass
    else:
        raise AssertionError("completed review slot must not be overwritten")


def test_three_role_approval_only_enables_authorization_request(
    tmp_path: Path,
) -> None:
    source_path, packet_path = _write_completed_packet(tmp_path)

    report = reconcile_challenge_reviews(
        bounded_plan_report_path=source_path,
        review_packet_path=packet_path,
        output_path=tmp_path / "reconciliation.json",
        agent_root=tmp_path,
        current_time=OPENED_AT + timedelta(days=1, minutes=1),
    )

    assert report["passed"] is True
    assert report["review_summary"]["approved_draft_count"] == 2
    assert (
        report["readiness"]["controlled_pilot_authorization_request_ready"]
        is True
    )
    assert (
        report["readiness"]["decision"]
        == "h3_controlled_pilot_authorization_request_inputs_ready"
    )
    assert report["boundary"]["controlled_pilot_execution_allowed"] is False
    assert report["boundary"]["goal_emission_allowed"] is False
    assert report["boundary"]["runtime_execution_allowed"] is False


def test_revision_request_blocks_only_affected_draft(tmp_path: Path) -> None:
    source_path, packet_path = _write_completed_packet(tmp_path)
    packet = json.loads(packet_path.read_text(encoding="utf-8"))
    draft_id = packet["reviews"][0]["draft_id"]
    packet["reviews"][0].update(
        {
            "decision": "request_revision",
            "reason": "scope needs a narrower counterexample test",
            "requested_changes": "reduce trial scope and define causal falsification",
        }
    )
    packet_path.write_text(json.dumps(packet), encoding="utf-8")

    report = reconcile_challenge_reviews(
        bounded_plan_report_path=source_path,
        review_packet_path=packet_path,
        output_path=tmp_path / "reconciliation.json",
        agent_root=tmp_path,
        current_time=OPENED_AT + timedelta(days=1, minutes=1),
    )

    assert report["passed"] is True
    assert report["review_summary"]["approved_draft_count"] == 1
    blocked = next(
        item
        for item in report["reconciliation"]["draft_results"]
        if item["draft_id"] == draft_id
    )
    assert blocked["decision"] == "revision_required"
    assert blocked["execution_allowed"] is False


def test_missing_required_role_fails_closed(tmp_path: Path) -> None:
    source_path, packet_path = _write_completed_packet(tmp_path)
    packet = json.loads(packet_path.read_text(encoding="utf-8"))
    packet["reviews"].pop()
    packet_path.write_text(json.dumps(packet), encoding="utf-8")

    report = reconcile_challenge_reviews(
        bounded_plan_report_path=source_path,
        review_packet_path=packet_path,
        output_path=tmp_path / "reconciliation.json",
        agent_root=tmp_path,
        current_time=OPENED_AT + timedelta(days=1, minutes=1),
    )

    assert report["passed"] is False
    assert report["checks"]["challenge_review_keys_unique_and_complete"] is False


def test_tampered_draft_hash_fails_closed(tmp_path: Path) -> None:
    source_path, packet_path = _write_completed_packet(tmp_path)
    packet = json.loads(packet_path.read_text(encoding="utf-8"))
    packet["reviews"][0]["draft_sha256"] = "0" * 64
    packet_path.write_text(json.dumps(packet), encoding="utf-8")

    report = reconcile_challenge_reviews(
        bounded_plan_report_path=source_path,
        review_packet_path=packet_path,
        output_path=tmp_path / "reconciliation.json",
        agent_root=tmp_path,
        current_time=OPENED_AT + timedelta(days=1, minutes=1),
    )

    assert report["passed"] is False
    assert report["checks"]["challenge_review_fields_valid"] is False


def test_tampered_source_breaks_packet_binding(tmp_path: Path) -> None:
    source_path, packet_path = _write_completed_packet(tmp_path)
    source = json.loads(source_path.read_text(encoding="utf-8"))
    source["draft_surface"]["drafts"][0]["objective"] = "tampered"
    source_path.write_text(json.dumps(source), encoding="utf-8")

    report = reconcile_challenge_reviews(
        bounded_plan_report_path=source_path,
        review_packet_path=packet_path,
        output_path=tmp_path / "reconciliation.json",
        agent_root=tmp_path,
        current_time=OPENED_AT + timedelta(days=1, minutes=1),
    )

    assert report["passed"] is False
    assert report["checks"]["challenge_review_source_binding"] is False


def _write_bounded_plan(tmp_path: Path) -> Path:
    proposal_path, reconciliation_path = _write_inputs(tmp_path)
    report = build_h3_bounded_plan_draft_gate(
        proposal_report_path=proposal_path,
        reconciliation_report_path=reconciliation_path,
        agent_root=tmp_path,
    )
    assert report["passed"] is True
    path = tmp_path / "bounded_plan.json"
    path.write_text(json.dumps(report), encoding="utf-8")
    return path


def _write_completed_packet(
    tmp_path: Path,
    *,
    validation_profile: str = "qualification",
    window_seconds: int = 60,
) -> tuple[Path, Path]:
    source_path = _write_bounded_plan(tmp_path)
    packet_path = tmp_path / "challenge_packet.json"
    packet = create_challenge_review_packet(
        bounded_plan_report_path=source_path,
        output_path=packet_path,
        agent_root=tmp_path,
        opened_at=OPENED_AT,
        validation_profile=validation_profile,
        development_window_seconds=window_seconds,
    )
    reviewed_at = (
        OPENED_AT
        + (
            timedelta(seconds=10)
            if validation_profile == "development"
            else timedelta(hours=1)
        )
    ).isoformat()
    reviewer_ids = {
        "operator": "operator-001",
        "audit_owner": "audit-owner-001",
        "affected_relation_owner": "relation-owner-001",
    }
    for review in packet["reviews"]:
        review.update(
            {
                "reviewer_id": reviewer_ids[review["reviewer_role"]],
                "decision": "approve_for_authorization_request",
                "reason": "bounded draft is suitable for authorization review",
                "reviewed_at": reviewed_at,
            }
        )
    packet_path.write_text(json.dumps(packet), encoding="utf-8")
    return source_path, packet_path
