from __future__ import annotations

import json
from pathlib import Path

from benchmarks.h3_goal_candidate_draft_report import (
    STANDARD_REQUIRED_REPEATED_OUTCOME_EVENT_KINDS,
    build_h3_goal_candidate_draft_report,
)


def test_h3_goal_candidate_draft_report_emits_non_executable_candidates(tmp_path: Path) -> None:
    skeleton = _write_h3_skeleton(
        tmp_path,
        full_ready=True,
        repeated_patterns=[_pattern(event_kind) for event_kind in STANDARD_REQUIRED_REPEATED_OUTCOME_EVENT_KINDS],
    )

    report = build_h3_goal_candidate_draft_report(
        h3_skeleton_report_path=skeleton,
        agent_root=tmp_path,
    )

    assert report["passed"] is True
    assert report["readiness"]["decision"] == "h3_draft_goal_candidates_ready"
    assert report["h3_boundary"]["goal_emission_allowed"] is False
    assert report["h3_boundary"]["executable_plan_allowed"] is False
    assert report["goal_candidate_surface"]["candidate_goal_count"] == 5
    assert report["vmv_stage_gate"]["passed"] is True
    first = report["goal_candidate_surface"]["candidate_goals"][0]
    assert first["state"] == "draft_review_required"
    assert first["trigger_event_kind"] == "post_delivery_dispute"
    assert first["review_policy"]["human_review_required"] is True
    assert first["review_policy"]["governance_review_required"] is True
    assert first["execution_policy"]["runtime_execution_allowed"] is False
    assert first["execution_policy"]["normative_local_mutation_allowed"] is False
    assert first["evidence"]["backend_sourced"] is True
    assert first["evidence"]["record_ids"] == ["alpha:post_delivery_dispute:01", "alpha:post_delivery_dispute:02"]


def test_h3_goal_candidate_draft_report_blocks_without_full_behavior_evidence(tmp_path: Path) -> None:
    skeleton = _write_h3_skeleton(
        tmp_path,
        full_ready=False,
        repeated_patterns=[_pattern("post_delivery_failure")],
    )

    report = build_h3_goal_candidate_draft_report(
        h3_skeleton_report_path=skeleton,
        agent_root=tmp_path,
    )

    assert report["passed"] is False
    assert report["checks"]["h3_full_behavior_evidence_ready"] is False
    assert report["goal_candidate_surface"]["candidate_goals"] == []
    assert report["readiness"]["decision"] == "blocked_before_h3_draft_goal_candidates"


def test_h3_goal_candidate_draft_report_blocks_boundary_regression(tmp_path: Path) -> None:
    skeleton = _write_h3_skeleton(
        tmp_path,
        full_ready=True,
        repeated_patterns=[_pattern(event_kind) for event_kind in STANDARD_REQUIRED_REPEATED_OUTCOME_EVENT_KINDS],
        h3_boundary={"goal_emission_allowed": True},
    )

    report = build_h3_goal_candidate_draft_report(
        h3_skeleton_report_path=skeleton,
        agent_root=tmp_path,
    )

    assert report["passed"] is False
    assert report["checks"]["h3_goal_emission_disallowed"] is False
    assert report["goal_candidate_surface"]["candidate_goals"] == []


def test_h3_goal_candidate_draft_report_requires_backend_sourced_standard_kinds(tmp_path: Path) -> None:
    skeleton = _write_h3_skeleton(
        tmp_path,
        full_ready=True,
        repeated_patterns=[
            _pattern("post_delivery_dispute"),
            _pattern("post_delivery_failure"),
            _pattern("relation_repair_relapse"),
            _pattern("governance_rollback", sources=["benchmark_seed"]),
        ],
    )

    report = build_h3_goal_candidate_draft_report(
        h3_skeleton_report_path=skeleton,
        agent_root=tmp_path,
    )

    assert report["passed"] is False
    assert report["checks"]["standard_backend_sourced_repeated_outcome_event_kinds"] is False
    assert report["evidence"]["missing_backend_sourced_repeated_outcome_event_kinds"] == [
        "governance_rollback",
        "economic_deviation",
    ]
    assert report["goal_candidate_surface"]["candidate_goals"] == []


def test_h3_goal_candidate_draft_report_can_limit_candidates(tmp_path: Path) -> None:
    skeleton = _write_h3_skeleton(
        tmp_path,
        full_ready=True,
        repeated_patterns=[_pattern(event_kind) for event_kind in STANDARD_REQUIRED_REPEATED_OUTCOME_EVENT_KINDS],
    )

    report = build_h3_goal_candidate_draft_report(
        h3_skeleton_report_path=skeleton,
        agent_root=tmp_path,
        max_candidate_goals=2,
    )

    assert report["passed"] is True
    assert report["goal_candidate_surface"]["candidate_goal_count"] == 2
    assert [candidate["trigger_event_kind"] for candidate in report["goal_candidate_surface"]["candidate_goals"]] == [
        "post_delivery_dispute",
        "post_delivery_failure",
    ]


def _write_h3_skeleton(
    tmp_path: Path,
    *,
    full_ready: bool,
    repeated_patterns: list[dict],
    h3_boundary: dict | None = None,
) -> Path:
    closure_path = tmp_path / "h2_value_calibration_closure.json"
    backend_kinds = sorted(
        {
            pattern["event_kind"]
            for pattern in repeated_patterns
            if any(source.startswith("backend_") for source in pattern.get("sources", []))
        }
    )
    closure_path.write_text(
        json.dumps(
            {
                "schema_version": "h2-value-calibration-closure:v1",
                "passed": True,
                "closure_boundary": {
                    "artifact_only": True,
                    "runtime_mutation_allowed": False,
                    "llm_training_allowed": False,
                    "normative_local_mutation_allowed": False,
                    "seed_patterns_count_as_h3_backend_readiness": False,
                },
                "evidence": {
                    "backend_sourced_repeated_outcome_event_kinds": backend_kinds,
                    "value_report": {
                        "passed": True,
                        "metrics": {
                            "repeated_outcome_patterns": repeated_patterns,
                        },
                    },
                },
            }
        ),
        encoding="utf-8",
    )
    default_boundary = {
        "artifact_only": True,
        "goal_emission_allowed": False,
        "runtime_execution_allowed": False,
        "llm_planning_allowed": False,
        "iem_value_mutation_allowed": False,
        "normative_local_mutation_allowed": False,
        "full_behavior_requires_standard_backend_sourced_repeated_kinds": True,
    }
    default_boundary.update(h3_boundary or {})
    skeleton_path = tmp_path / "h3_goal_generator_skeleton.json"
    skeleton_path.write_text(
        json.dumps(
            {
                "schema_version": "h3-goal-generator-skeleton:v1",
                "passed": True,
                "h2_closure_report_path": str(closure_path),
                "readiness": {
                    "minimum_skeleton_ready": True,
                    "full_goal_generator_behavior_ready": full_ready,
                },
                "h3_boundary": default_boundary,
            }
        ),
        encoding="utf-8",
    )
    return skeleton_path


def _pattern(event_kind: str, *, sources: list[str] | None = None) -> dict:
    return {
        "identity": "alpha",
        "event_kind": event_kind,
        "max_pattern_count": 2,
        "candidate_count": 2,
        "record_ids": [f"alpha:{event_kind}:01", f"alpha:{event_kind}:02"],
        "sources": sources or ["backend_task_pool_read_model"],
    }