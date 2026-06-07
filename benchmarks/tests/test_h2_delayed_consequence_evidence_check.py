from __future__ import annotations

import json
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
    )

    assert report["passed"] is True
    assert report["metrics"]["owner_count"] == 2
    assert report["metrics"]["task_count"] == 6
    assert report["metrics"]["iem_change_ratio"] == 1.0
    assert report["metrics"]["relation_change_ratio"] == 1.0
    assert report["metrics"]["negative_authorization_change_count"] == 4
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
    )

    assert report["passed"] is False
    assert report["checks"]["minimum_owner_count"] is False
    assert report["checks"]["minimum_task_count"] is False
    assert report["checks"]["minimum_observation_days"] is False
    assert report["checks"]["minimum_observation_span_seconds"] is False
    assert report["h3_readiness"]["ready"] is False


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
        f"{worker}_normative_local_update_blocked": True for worker in workers
    }
    summaries = {}
    for index, (worker, event_kind) in enumerate(workers.items()):
        relation_key = f"rel:{task_prefix}:{worker}"
        summaries[worker] = {
            "agent_id": f"did:civ:{worker}",
            "task_id": f"task-{task_prefix}-{worker}",
            "event_kind": event_kind,
            "observed_at": f"{day}T12:00:0{index}+00:00",
            "relation_update": {
                "relation_key": relation_key,
                "before": {"expected_trust": 0.72},
                "after": {"expected_trust": 0.76 if worker == "alpha" else 0.60},
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
                "before": {"verification_level": "baseline"},
                "after": {
                    "verification_level": (
                        "baseline" if worker == "alpha" else "elevated"
                    )
                },
                "changed": True,
            },
        }
    path.write_text(
        json.dumps(
            {
                "schema_version": "h2-multi-agent-backend-continuity-gate:v1",
                "passed": True,
                "owner_id": owner_id,
                "checks": checks,
                "worker_summaries": summaries,
            }
        ),
        encoding="utf-8",
    )
    return path
