from __future__ import annotations

import json
from pathlib import Path

from benchmarks.h3_external_review_artifacts_fixture import build_h3_external_review_artifacts_fixture
from benchmarks.h3_goal_approval_gate import build_h3_goal_approval_gate


def test_h3_external_review_fixture_defaults_to_pending_records(tmp_path: Path) -> None:
    lifecycle = _write_lifecycle_gate(tmp_path, [_packet("post_delivery_failure")])

    report = build_h3_external_review_artifacts_fixture(lifecycle_gate_path=lifecycle, agent_root=tmp_path)

    assert report["passed"] is True
    assert report["schema_version"] == "h3-external-review-artifacts:v1"
    assert report["fixture_policy"]["synthetic_review_fixture"] is True
    assert report["fixture_policy"]["not_real_human_or_governance_approval"] is True
    assert report["metrics"]["external_review_record_count"] == 5
    assert report["metrics"]["accepted_like_record_count"] == 0
    assert {record["artifact_kind"] for record in report["records"]} == {
        "human_review_record",
        "governance_review_record",
        "challenge_window_result",
        "rollback_plan_record",
        "r2r_accountability_record",
    }
    assert all(record["goal_emission_allowed"] is False for record in report["records"])


def test_h3_external_review_fixture_approved_mode_requires_ack(tmp_path: Path) -> None:
    lifecycle = _write_lifecycle_gate(tmp_path, [_packet("economic_deviation")])

    report = build_h3_external_review_artifacts_fixture(
        lifecycle_gate_path=lifecycle,
        agent_root=tmp_path,
        fixture_mode="approved",
    )

    assert report["passed"] is False
    assert report["checks"]["synthetic_approval_fixture_acknowledged"] is False
    assert report["records"] == []


def test_h3_external_review_fixture_drives_synthetic_approval_without_execution(tmp_path: Path) -> None:
    packets = [_packet("post_delivery_dispute"), _packet("economic_deviation")]
    lifecycle = _write_lifecycle_gate(tmp_path, packets)
    fixture = build_h3_external_review_artifacts_fixture(
        lifecycle_gate_path=lifecycle,
        agent_root=tmp_path,
        fixture_mode="approved",
        acknowledged_synthetic_approval_fixture=True,
    )
    fixture_path = tmp_path / "h3_external_review_artifacts_fixture.json"
    fixture_path.write_text(json.dumps(fixture), encoding="utf-8")

    report = build_h3_goal_approval_gate(
        lifecycle_gate_path=lifecycle,
        agent_root=tmp_path,
        review_artifacts_path=fixture_path,
    )

    assert fixture["passed"] is True
    assert fixture["metrics"]["external_review_record_count"] == 10
    assert fixture["metrics"]["accepted_like_record_count"] == 10
    assert report["passed"] is True
    assert report["readiness"]["decision"] == "synthetic_approved_candidate_surface_ready"
    assert report["readiness"]["synthetic_approved_candidate_ready"] is True
    assert report["readiness"]["production_approved_candidate_ready"] is False
    assert report["approval_boundary"]["candidate_approval_allowed"] is False
    assert report["approval_boundary"]["synthetic_candidate_surface_allowed"] is True
    assert report["metrics"]["approved_candidate_count"] == 2
    assert report["metrics"]["executable_goal_ready_count"] == 0
    assert report["approval_boundary"]["goal_emission_allowed"] is False
    assert report["approval_boundary"]["runtime_execution_allowed"] is False
    assert all(
        candidate["gate_status"]["runtime_execution_ready"] is False
        for candidate in report["approval_surface"]["approved_candidates"]
    )


def test_h3_external_review_fixture_blocks_lifecycle_boundary_regression(tmp_path: Path) -> None:
    lifecycle = _write_lifecycle_gate(
        tmp_path,
        [_packet("relation_repair_relapse")],
        boundary={"runtime_execution_allowed": True},
    )

    report = build_h3_external_review_artifacts_fixture(lifecycle_gate_path=lifecycle, agent_root=tmp_path)

    assert report["passed"] is False
    assert report["checks"]["lifecycle_boundary_runtime_execution_allowed_false"] is False
    assert report["records"] == []


def _write_lifecycle_gate(
    tmp_path: Path,
    packets: list[dict],
    *,
    passed: bool = True,
    boundary: dict | None = None,
) -> Path:
    default_boundary = {
        "artifact_only": True,
        "review_packets_allowed": True,
        "approval_allowed": False,
        "goal_emission_allowed": False,
        "executable_plan_allowed": False,
        "runtime_execution_allowed": False,
        "llm_planning_allowed": False,
        "iem_value_mutation_allowed": False,
        "normative_local_mutation_allowed": False,
    }
    default_boundary.update(boundary or {})
    path = tmp_path / "h3_goal_lifecycle_gate.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": "h3-goal-lifecycle-gate:v1",
                "passed": passed,
                "readiness": {
                    "decision": "h3_review_lifecycle_ready" if passed else "blocked_before_h3_review_lifecycle",
                },
                "lifecycle_boundary": default_boundary,
                "review_packet_surface": {
                    "mode": "review_only",
                    "review_packet_count": len(packets),
                    "review_packets": packets,
                },
            }
        ),
        encoding="utf-8",
    )
    return path


def _packet(event_kind: str) -> dict:
    goal_id = f"h3-draft-goal:{event_kind}:alpha"
    return {
        "packet_id": f"h3-review-packet:{goal_id}",
        "goal_id": goal_id,
        "candidate_state": "draft_review_required",
        "lifecycle_state": "review_packet_ready",
        "trigger_event_kind": event_kind,
        "identity": "alpha",
        "risk_class": "critical" if event_kind == "economic_deviation" else "high",
        "evidence_ref": {
            "backend_sourced": True,
            "event_kind": event_kind,
            "identity": "alpha",
            "max_pattern_count": 2,
            "record_ids": [f"alpha:{event_kind}:01", f"alpha:{event_kind}:02"],
            "sources": ["backend_task_pool_read_model"],
        },
        "execution_policy": {
            "goal_emission_allowed": False,
            "executable_plan_allowed": False,
            "runtime_execution_allowed": False,
            "llm_planning_allowed": False,
            "iem_value_mutation_allowed": False,
            "normative_local_mutation_allowed": False,
        },
        "required_external_artifacts": {
            "human_review_record": "required_before_approval",
            "governance_review_record": "required_before_approval",
            "challenge_window_result": "required_before_approval",
            "rollback_plan_record": "required_before_approval",
            "r2r_accountability_record": "required_before_approval",
        },
    }