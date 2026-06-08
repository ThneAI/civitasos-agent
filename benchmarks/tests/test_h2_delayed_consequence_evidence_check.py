from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from benchmarks.h2_delayed_consequence_evidence_check import (
    check_delayed_consequence_evidence,
)


def test_cross_day_evidence_passes_with_distinct_owners_and_tasks(
    tmp_path: Path,
) -> None:
    first = _source_report(
        tmp_path / "day1.json",
        owner_id="owner-a",
        day="2026-06-01",
        task_prefix="a",
    )
    second = _source_report(
        tmp_path / "day2.json",
        owner_id="owner-b",
        day="2026-06-03",
        task_prefix="b",
    )

    report = check_delayed_consequence_evidence(
        source_reports=[first, second],
        agent_root=tmp_path,
        checked_at=datetime(2026, 6, 4, tzinfo=timezone.utc),
    )

    assert report["passed"] is True
    assert report["failure_class"] == "none"
    assert report["metrics"]["owner_count"] == 2
    assert report["metrics"]["task_count"] == 6
    assert report["metrics"]["iem_change_ratio"] == 1.0
    assert report["metrics"]["relation_change_ratio"] == 1.0
    assert report["metrics"]["negative_authorization_change_count"] == 4
    assert report["metrics"]["record_integrity_pass_ratio"] == 1.0
    assert report["checks"]["task_ids_unique"] is True
    assert report["checks"]["source_owner_ids_unique"] is True
    assert report["h3_readiness"]["decision"] == (
        "ready_for_h3_read_only_goal_proposal_gate"
    )


def test_same_day_single_owner_evidence_remains_blocked(tmp_path: Path) -> None:
    source = _source_report(
        tmp_path / "day1.json",
        owner_id="owner-a",
        day="2026-06-01",
        task_prefix="a",
    )

    report = check_delayed_consequence_evidence(
        source_reports=[source],
        agent_root=tmp_path,
        checked_at=datetime(2026, 6, 2, tzinfo=timezone.utc),
    )

    assert report["passed"] is False
    assert report["failure_class"] == "evidence_maturity"
    assert report["checks"]["minimum_owner_count"] is False
    assert report["checks"]["minimum_task_count"] is False
    assert report["checks"]["minimum_observation_days"] is False
    assert report["checks"]["minimum_observation_span_seconds"] is False
    assert report["h3_readiness"]["ready"] is False


def test_duplicate_report_owner_and_tasks_are_rejected(tmp_path: Path) -> None:
    first = _source_report(
        tmp_path / "day1.json",
        owner_id="owner-a",
        day="2026-06-01",
        task_prefix="same",
    )
    second = _source_report(
        tmp_path / "day2.json",
        owner_id="owner-a",
        day="2026-06-03",
        task_prefix="same",
    )

    report = check_delayed_consequence_evidence(
        source_reports=[first, second],
        agent_root=tmp_path,
        checked_at=datetime(2026, 6, 4, tzinfo=timezone.utc),
    )

    assert report["passed"] is False
    assert report["failure_class"] == "evidence_integrity"
    assert report["checks"]["source_owner_ids_unique"] is False
    assert report["checks"]["task_ids_unique"] is False


def test_duplicate_source_content_is_rejected(tmp_path: Path) -> None:
    first = _source_report(
        tmp_path / "day1.json",
        owner_id="owner-a",
        day="2026-06-01",
        task_prefix="a",
    )
    duplicate = tmp_path / "copied.json"
    duplicate.write_bytes(first.read_bytes())

    report = check_delayed_consequence_evidence(
        source_reports=[first, duplicate],
        agent_root=tmp_path,
        checked_at=datetime(2026, 6, 4, tzinfo=timezone.utc),
    )

    assert report["passed"] is False
    assert report["failure_class"] == "evidence_integrity"
    assert report["checks"]["source_report_hashes_unique"] is False


def test_future_or_pre_shutdown_observation_is_rejected(tmp_path: Path) -> None:
    first = _source_report(
        tmp_path / "day1.json",
        owner_id="owner-a",
        day="2026-06-01",
        task_prefix="a",
    )
    second = _source_report(
        tmp_path / "day2.json",
        owner_id="owner-b",
        day="2026-06-03",
        task_prefix="b",
    )
    payload = json.loads(second.read_text(encoding="utf-8"))
    payload["worker_summaries"]["alpha"]["observed_at"] = "2026-06-03T11:59:59+00:00"
    payload["worker_summaries"]["beta"]["observed_at"] = "2026-07-03T12:00:01+00:00"
    second.write_text(json.dumps(payload), encoding="utf-8")

    report = check_delayed_consequence_evidence(
        source_reports=[first, second],
        agent_root=tmp_path,
        checked_at=datetime(2026, 6, 4, tzinfo=timezone.utc),
    )

    assert report["passed"] is False
    assert report["failure_class"] == "evidence_integrity"
    assert report["checks"]["record_evidence_integrity"] is False
    assert any("event_after_shutdown" in reason for reason in report["failure_reasons"])
    assert any("observed_at_not_future" in reason for reason in report["failure_reasons"])


def test_action_bias_mismatch_is_rejected(tmp_path: Path) -> None:
    first = _source_report(
        tmp_path / "day1.json",
        owner_id="owner-a",
        day="2026-06-01",
        task_prefix="a",
    )
    second = _source_report(
        tmp_path / "day2.json",
        owner_id="owner-b",
        day="2026-06-03",
        task_prefix="b",
    )
    payload = json.loads(second.read_text(encoding="utf-8"))
    payload["worker_summaries"]["gamma"]["relation_update"]["action_bias"][
        "verification_level"
    ] = "baseline"
    second.write_text(json.dumps(payload), encoding="utf-8")

    report = check_delayed_consequence_evidence(
        source_reports=[first, second],
        agent_root=tmp_path,
        checked_at=datetime(2026, 6, 4, tzinfo=timezone.utc),
    )

    assert report["passed"] is False
    assert report["failure_class"] == "evidence_integrity"
    assert report["checks"]["record_evidence_integrity"] is False
    assert any(
        "authorization_matches_action_bias" in reason
        for reason in report["failure_reasons"]
    )


def _source_report(
    path: Path,
    *,
    owner_id: str,
    day: str,
    task_prefix: str,
) -> Path:
    workers = {
        "alpha": "settlement_confirmed",
        "beta": "post_delivery_dispute",
        "gamma": "post_delivery_failure",
    }
    checks = {
        f"{worker}_{check_name}": True
        for worker in workers
        for check_name in (
            "event_after_shutdown",
            "event_from_backend",
            "event_matches_task",
            "expected_event_kind",
            "iem_anchor_matches_state",
            "iem_state_changed",
            "relation_persisted_in_iem",
            "authorization_profile_changed",
            "authorization_matches_action_bias",
            "normative_local_update_blocked",
        )
    }
    summaries = {}
    for index, (worker, event_kind) in enumerate(workers.items()):
        relation_key = f"rel:{task_prefix}:{worker}"
        summaries[worker] = {
            "agent_id": f"did:civ:{worker}",
            "task_id": f"task-{task_prefix}-{worker}",
            "event_kind": event_kind,
            "observed_at": f"{day}T12:00:0{index}+00:00",
            "shutdown_at": f"{day}T11:59:59+00:00",
            "reports_present": True,
            "relation_update": {
                "relation_key": relation_key,
                "before": {"expected_trust": 0.72},
                "after": {"expected_trust": 0.76 if worker == "alpha" else 0.60},
                "action_bias": {
                    "verification_level": (
                        "baseline" if worker == "alpha" else "elevated"
                    ),
                    "required_stake_multiplier": (
                        1.1 if worker == "alpha" else 1.7
                    ),
                    "direct_match_allowed": True,
                },
            },
            "iem_update": {
                "before_state_hash": f"sha256:before-{task_prefix}-{worker}",
                "after_state_hash": f"sha256:after-{task_prefix}-{worker}",
                "relation_entry_persisted": True,
                "anchor": {
                    "state_hash": f"sha256:after-{task_prefix}-{worker}",
                },
            },
            "authorization_change": {
                "before": {
                    "verification_level": "baseline",
                    "required_stake_multiplier": 1.2,
                    "direct_match_allowed": True,
                },
                "after": {
                    "verification_level": (
                        "baseline" if worker == "alpha" else "elevated"
                    ),
                    "required_stake_multiplier": (
                        1.1 if worker == "alpha" else 1.7
                    ),
                    "direct_match_allowed": True,
                },
                "changed": True,
            },
        }
    path.write_text(
        json.dumps(
            {
                "schema_version": "h2-multi-agent-backend-continuity-gate:v1",
                "evidence_class": "controlled_pilot_backend",
                "passed": True,
                "owner_id": owner_id,
                "checks": checks,
                "worker_summaries": summaries,
            }
        ),
        encoding="utf-8",
    )
    return path
