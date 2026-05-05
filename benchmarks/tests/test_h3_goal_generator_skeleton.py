from __future__ import annotations

import json
from pathlib import Path

from benchmarks.h3_goal_generator_skeleton import (
    STANDARD_REQUIRED_REPEATED_OUTCOME_EVENT_KINDS,
    build_h3_goal_generator_skeleton,
)


def test_h3_goal_generator_skeleton_passes_for_minimum_h2_closure(tmp_path: Path) -> None:
    closure = _write_h2_closure(tmp_path, backend_kinds=["post_delivery_failure"])

    report = build_h3_goal_generator_skeleton(
        h2_closure_report_path=closure,
        agent_root=tmp_path,
    )

    assert report["passed"] is True
    assert report["readiness"]["minimum_skeleton_ready"] is True
    assert report["readiness"]["full_goal_generator_behavior_ready"] is False
    assert report["h3_boundary"]["goal_emission_allowed"] is False
    assert report["goal_generator_state"]["candidate_goals"] == []
    assert report["evidence"]["backend_sourced_repeated_outcome_event_kinds"] == ["post_delivery_failure"]
    assert report["evidence"]["missing_full_backend_sourced_repeated_outcome_event_kinds"] == [
        "post_delivery_dispute",
        "relation_repair_relapse",
        "governance_rollback",
        "economic_deviation",
    ]


def test_h3_goal_generator_skeleton_marks_full_behavior_ready_for_five_backend_kinds(tmp_path: Path) -> None:
    closure = _write_h2_closure(tmp_path, backend_kinds=STANDARD_REQUIRED_REPEATED_OUTCOME_EVENT_KINDS)

    report = build_h3_goal_generator_skeleton(
        h2_closure_report_path=closure,
        agent_root=tmp_path,
    )

    assert report["passed"] is True
    assert report["readiness"]["minimum_skeleton_ready"] is True
    assert report["readiness"]["full_goal_generator_behavior_ready"] is True
    assert report["h3_boundary"]["goal_emission_allowed"] is False
    assert report["evidence"]["missing_full_backend_sourced_repeated_outcome_event_kinds"] == []


def test_h3_goal_generator_skeleton_blocks_failed_h2_closure(tmp_path: Path) -> None:
    closure = _write_h2_closure(
        tmp_path,
        passed=False,
        ready=False,
        decision="blocked_before_h3",
        backend_kinds=[],
    )

    report = build_h3_goal_generator_skeleton(
        h2_closure_report_path=closure,
        agent_root=tmp_path,
    )

    assert report["passed"] is False
    assert report["readiness"]["minimum_skeleton_ready"] is False
    assert report["readiness"]["decision"] == "blocked_before_h3_skeleton"
    assert report["checks"]["h2_closure_passed"] is False
    assert report["checks"]["h2_readiness_ready"] is False
    assert report["checks"]["h2_readiness_decision"] is False


def test_h3_goal_generator_skeleton_requires_no_mutation_boundary(tmp_path: Path) -> None:
    closure = _write_h2_closure(
        tmp_path,
        backend_kinds=["post_delivery_failure"],
        closure_boundary={"runtime_mutation_allowed": True},
    )

    report = build_h3_goal_generator_skeleton(
        h2_closure_report_path=closure,
        agent_root=tmp_path,
    )

    assert report["passed"] is False
    assert report["checks"]["h2_runtime_mutation_disallowed"] is False
    assert report["h3_boundary"]["runtime_execution_allowed"] is False


def _write_h2_closure(
    tmp_path: Path,
    *,
    backend_kinds: list[str],
    passed: bool = True,
    ready: bool = True,
    decision: str = "ready_for_h3_goal_generator_skeleton",
    closure_boundary: dict | None = None,
) -> Path:
    default_boundary = {
        "artifact_only": True,
        "runtime_mutation_allowed": False,
        "llm_training_allowed": False,
        "normative_local_mutation_allowed": False,
        "seed_patterns_count_as_h3_backend_readiness": False,
    }
    default_boundary.update(closure_boundary or {})
    path = tmp_path / "h2_value_calibration_closure.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": "h2-value-calibration-closure:v1",
                "passed": passed,
                "failure_reasons": [] if passed else ["fixture closure failure"],
                "checks": {},
                "closure_boundary": default_boundary,
                "h3_goal_generator_readiness": {
                    "ready": ready,
                    "decision": decision,
                    "next_stage": "H.3 Goal Generator skeleton",
                },
                "evidence": {
                    "backend_sourced_repeated_outcome_event_kinds": backend_kinds,
                },
            }
        ),
        encoding="utf-8",
    )
    return path
