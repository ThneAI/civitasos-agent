from __future__ import annotations

import json
from pathlib import Path

from benchmarks.h2_h3_readiness_summary import build_h2_h3_readiness_summary


def test_blocked_h2_report_lists_only_remaining_requirements(tmp_path: Path) -> None:
    h2 = _write_h2_report(tmp_path / "h2.json", ready=False)

    report = build_h2_h3_readiness_summary(
        h2_evidence_report_path=h2,
        agent_root=tmp_path,
    )

    assert report["passed"] is True
    assert report["status"] == "blocked_collecting_h2_delayed_consequence_evidence"
    missing = {
        item.get("metric"): item
        for item in report["h2"]["missing_requirements"]
        if item["kind"] == "threshold"
    }
    assert missing["owner_count"]["remaining"] == 1
    assert missing["task_count"]["remaining"] == 3
    assert missing["observation_day_count"]["remaining"] == 1
    assert missing["observation_span_seconds"]["remaining"] == 86399.0


def test_ready_h2_report_requests_read_only_h3_gate(tmp_path: Path) -> None:
    h2 = _write_h2_report(tmp_path / "h2.json", ready=True)

    report = build_h2_h3_readiness_summary(
        h2_evidence_report_path=h2,
        agent_root=tmp_path,
    )

    assert report["passed"] is True
    assert report["status"] == "ready_to_run_h3_read_only_goal_proposal_gate"
    assert report["h2"]["missing_requirements"] == []
    assert report["h3_read_only_proposal"]["decision"] == "not_run"


def test_ready_h3_report_is_summarized_without_execution_authority(tmp_path: Path) -> None:
    h2 = _write_h2_report(tmp_path / "h2.json", ready=True)
    h3 = tmp_path / "h3.json"
    h3.write_text(
        json.dumps(
            {
                "schema_version": "h3-read-only-goal-proposal-gate:v1",
                "passed": True,
                "readiness": {
                    "read_only_proposal_surface_ready": True,
                    "decision": "h3_read_only_goal_proposals_ready_for_review",
                },
                "proposal_surface": {"proposal_count": 4},
            }
        ),
        encoding="utf-8",
    )

    report = build_h2_h3_readiness_summary(
        h2_evidence_report_path=h2,
        h3_proposal_report_path=h3,
        agent_root=tmp_path,
    )

    assert report["passed"] is True
    assert report["status"] == "h3_read_only_goal_proposals_ready_for_review"
    assert report["h3_read_only_proposal"]["proposal_count"] == 4
    assert report["boundary"]["goal_emission_allowed"] is False
    assert report["boundary"]["goal_execution_allowed"] is False


def _write_h2_report(path: Path, *, ready: bool) -> Path:
    metrics = {
        "owner_count": 2 if ready else 1,
        "task_count": 6 if ready else 3,
        "observation_day_count": 2 if ready else 1,
        "observation_span_seconds": 86400.0 if ready else 1.0,
        "iem_change_ratio": 1.0,
        "relation_change_ratio": 1.0,
        "authorization_change_count": 6 if ready else 3,
        "negative_authorization_change_count": 4 if ready else 2,
        "normative_local_update_blocked_ratio": 1.0,
    }
    checks = {
        "minimum_owner_count": ready,
        "minimum_task_count": ready,
        "minimum_observation_days": ready,
        "minimum_observation_span_seconds": ready,
        "minimum_iem_change_ratio": True,
        "minimum_relation_change_ratio": True,
        "minimum_authorization_change_count": True,
        "minimum_normative_blocked_ratio": True,
        "record_evidence_integrity": True,
    }
    path.write_text(
        json.dumps(
            {
                "schema_version": "h2-delayed-consequence-evidence-check:v1",
                "passed": ready,
                "metrics": metrics,
                "thresholds": {
                    "min_owner_count": 2,
                    "min_task_count": 6,
                    "min_observation_days": 2,
                    "min_observation_span_seconds": 86400,
                    "min_iem_change_ratio": 1.0,
                    "min_relation_change_ratio": 1.0,
                    "min_authorization_change_count": 2,
                    "min_normative_blocked_ratio": 1.0,
                },
                "checks": checks,
                "h3_readiness": {
                    "ready": ready,
                    "decision": (
                        "ready_for_h3_read_only_goal_proposal_gate"
                        if ready
                        else "blocked_collecting_h2_delayed_consequence_evidence"
                    ),
                },
            }
        ),
        encoding="utf-8",
    )
    return path
