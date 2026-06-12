from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from benchmarks.h3_bounded_plan_challenge_review_gate import (
    create_challenge_review_packet,
    reconcile_challenge_reviews,
)
from benchmarks.h3_bounded_plan_draft_gate import (
    build_h3_bounded_plan_draft_gate,
)
from benchmarks.h3_controlled_pilot_authorization_request_gate import (
    build_authorization_request_gate,
)
from benchmarks.tests.test_h3_bounded_plan_draft_gate import _write_inputs


OPENED_AT = datetime(2026, 6, 9, 0, 0, tzinfo=timezone.utc)


def test_development_reconciliation_builds_review_only_requests(
    tmp_path: Path,
) -> None:
    bounded_path, reconciliation_path = _write_sources(
        tmp_path,
        profile="development",
    )

    report = build_authorization_request_gate(
        bounded_plan_report_path=bounded_path,
        challenge_reconciliation_path=reconciliation_path,
        agent_root=tmp_path,
    )

    assert report["passed"] is True
    assert report["validation_profile"] == "development"
    assert report["development_only"] is True
    assert report["valid_for_qualification"] is False
    assert (
        report["readiness"]["decision"]
        == "h3_development_authorization_requests_ready_for_review"
    )
    assert report["readiness"]["authorization_granted"] is False
    assert report["boundary"]["controlled_pilot_execution_allowed"] is False
    requests = report["authorization_request_surface"]["requests"]
    assert len(requests) == 2
    assert all(item["requested_scope"]["max_tasks"] == 1 for item in requests)
    assert all(
        item["requested_scope"]["max_duration_seconds"] <= 1800
        for item in requests
    )
    assert "development_request_is_not_qualification_evidence" in report[
        "non_claims"
    ]
    assert all(
        item["authorization_state"]["execution_allowed"] is False
        for item in requests
    )


def test_qualification_reconciliation_preserves_bounded_scope(
    tmp_path: Path,
) -> None:
    bounded_path, reconciliation_path = _write_sources(
        tmp_path,
        profile="qualification",
    )

    report = build_authorization_request_gate(
        bounded_plan_report_path=bounded_path,
        challenge_reconciliation_path=reconciliation_path,
        agent_root=tmp_path,
    )

    assert report["passed"] is True
    assert report["validation_profile"] == "qualification"
    assert report["development_only"] is False
    assert report["valid_for_qualification"] is True
    assert (
        "qualification_request_does_not_grant_execution_authorization"
        in report["non_claims"]
    )
    assert "development_request_is_not_qualification_evidence" not in report[
        "non_claims"
    ]
    assert all(
        item["requested_scope"]["max_tasks"] == 3
        for item in report["authorization_request_surface"]["requests"]
    )


def test_open_window_reconciliation_is_rejected(tmp_path: Path) -> None:
    bounded_path, reconciliation_path = _write_sources(
        tmp_path,
        profile="development",
        close_window=False,
    )

    report = build_authorization_request_gate(
        bounded_plan_report_path=bounded_path,
        challenge_reconciliation_path=reconciliation_path,
        agent_root=tmp_path,
    )

    assert report["passed"] is False
    assert report["checks"]["challenge_reconciliation_passed"] is False
    assert report["authorization_request_surface"]["requests"] == []


def test_tampered_bounded_plan_breaks_source_binding(tmp_path: Path) -> None:
    bounded_path, reconciliation_path = _write_sources(
        tmp_path,
        profile="development",
    )
    bounded = json.loads(bounded_path.read_text(encoding="utf-8"))
    bounded["draft_surface"]["drafts"][0]["objective"] = "tampered"
    bounded_path.write_text(json.dumps(bounded), encoding="utf-8")

    report = build_authorization_request_gate(
        bounded_plan_report_path=bounded_path,
        challenge_reconciliation_path=reconciliation_path,
        agent_root=tmp_path,
    )

    assert report["passed"] is False
    assert report["checks"]["challenge_reconciliation_source_binding"] is False


def _write_sources(
    tmp_path: Path,
    *,
    profile: str,
    close_window: bool = True,
) -> tuple[Path, Path]:
    proposal_path, proposal_reconciliation_path = _write_inputs(tmp_path)
    bounded = build_h3_bounded_plan_draft_gate(
        proposal_report_path=proposal_path,
        reconciliation_report_path=proposal_reconciliation_path,
        agent_root=tmp_path,
    )
    bounded_path = tmp_path / "bounded.json"
    bounded_path.write_text(json.dumps(bounded), encoding="utf-8")
    packet_path = tmp_path / "challenge.json"
    packet = create_challenge_review_packet(
        bounded_plan_report_path=bounded_path,
        output_path=packet_path,
        agent_root=tmp_path,
        opened_at=OPENED_AT,
        validation_profile=profile,
        development_window_seconds=60,
    )
    reviewed_at = (OPENED_AT + timedelta(seconds=10)).isoformat()
    for review in packet["reviews"]:
        review.update(
            {
                "reviewer_id": f"{review['reviewer_role']}-001",
                "decision": "approve_for_authorization_request",
                "reason": "review accepts only an authorization request artifact",
                "reviewed_at": reviewed_at,
            }
        )
    packet_path.write_text(json.dumps(packet), encoding="utf-8")
    current_time = (
        OPENED_AT
        + (
            timedelta(seconds=61)
            if profile == "development" and close_window
            else timedelta(days=1, seconds=1)
            if close_window
            else timedelta(seconds=30)
        )
    )
    reconciliation_path = tmp_path / "challenge_reconciliation.json"
    reconcile_challenge_reviews(
        bounded_plan_report_path=bounded_path,
        review_packet_path=packet_path,
        output_path=reconciliation_path,
        agent_root=tmp_path,
        current_time=current_time,
    )
    return bounded_path, reconciliation_path
