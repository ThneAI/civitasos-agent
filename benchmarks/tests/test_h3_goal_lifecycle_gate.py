from __future__ import annotations

import json
from pathlib import Path

from benchmarks.h3_goal_lifecycle_gate import build_h3_goal_lifecycle_gate


def test_h3_goal_lifecycle_gate_emits_review_packets_without_approval(tmp_path: Path) -> None:
    draft_report = _write_draft_report(tmp_path, [_candidate("post_delivery_failure"), _candidate("economic_deviation")])

    report = build_h3_goal_lifecycle_gate(draft_report_path=draft_report, agent_root=tmp_path)

    assert report["passed"] is True
    assert report["readiness"]["decision"] == "h3_review_lifecycle_ready"
    assert report["readiness"]["approval_ready"] is False
    assert report["lifecycle_boundary"]["approval_allowed"] is False
    assert report["lifecycle_boundary"]["goal_emission_allowed"] is False
    assert report["metrics"] == {
        "draft_candidate_count": 2,
        "review_packet_count": 2,
        "approval_ready_count": 0,
        "executable_goal_ready_count": 0,
        "runtime_execution_ready_count": 0,
    }
    packet = report["review_packet_surface"]["review_packets"][0]
    assert packet["lifecycle_state"] == "review_packet_ready"
    assert packet["gate_status"]["review_packet_ready"] is True
    assert packet["gate_status"]["approval_ready"] is False
    assert packet["gate_status"]["runtime_execution_ready"] is False
    assert "review_packet_ready -> approved_candidate" in {
        item["transition"] for item in packet["blocked_transitions"]
    }
    assert packet["required_external_artifacts"]["human_review_record"] == "required_before_approval"


def test_h3_goal_lifecycle_gate_blocks_failed_draft_report(tmp_path: Path) -> None:
    draft_report = _write_draft_report(tmp_path, [_candidate("post_delivery_failure")], passed=False)

    report = build_h3_goal_lifecycle_gate(draft_report_path=draft_report, agent_root=tmp_path)

    assert report["passed"] is False
    assert report["checks"]["draft_report_passed"] is False
    assert report["review_packet_surface"]["review_packets"] == []
    assert report["readiness"]["decision"] == "blocked_before_h3_review_lifecycle"


def test_h3_goal_lifecycle_gate_blocks_execution_policy_regression(tmp_path: Path) -> None:
    candidate = _candidate("post_delivery_failure")
    candidate["execution_policy"]["runtime_execution_allowed"] = True
    draft_report = _write_draft_report(tmp_path, [candidate])

    report = build_h3_goal_lifecycle_gate(draft_report_path=draft_report, agent_root=tmp_path)

    assert report["passed"] is False
    assert report["checks"]["candidate_execution_policy_disabled"] is False
    assert report["review_packet_surface"]["review_packets"] == []


def test_h3_goal_lifecycle_gate_blocks_incomplete_review_policy(tmp_path: Path) -> None:
    candidate = _candidate("economic_deviation")
    candidate["review_policy"]["governance_review_required"] = False
    draft_report = _write_draft_report(tmp_path, [candidate])

    report = build_h3_goal_lifecycle_gate(draft_report_path=draft_report, agent_root=tmp_path)

    assert report["passed"] is False
    assert report["checks"]["candidate_review_policy_complete"] is False
    assert report["lifecycle_boundary"]["approval_allowed"] is False


def test_h3_goal_lifecycle_gate_blocks_missing_refusal_condition(tmp_path: Path) -> None:
    candidate = _candidate("relation_repair_relapse")
    candidate["refusal_conditions"].remove("attempts_runtime_execution_from_draft")
    draft_report = _write_draft_report(tmp_path, [candidate])

    report = build_h3_goal_lifecycle_gate(draft_report_path=draft_report, agent_root=tmp_path)

    assert report["passed"] is False
    assert report["checks"]["candidate_refusal_conditions_complete"] is False
    assert report["metrics"]["approval_ready_count"] == 0


def _write_draft_report(tmp_path: Path, candidates: list[dict], *, passed: bool = True) -> Path:
    path = tmp_path / "h3_goal_candidate_draft_report.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": "h3-goal-candidate-draft-report:v1",
                "passed": passed,
                "readiness": {
                    "decision": "h3_draft_goal_candidates_ready" if passed else "blocked_before_h3_draft_goal_candidates",
                },
                "h3_boundary": {
                    "artifact_only": True,
                    "draft_goal_candidates_allowed": True,
                    "goal_emission_allowed": False,
                    "executable_plan_allowed": False,
                    "runtime_execution_allowed": False,
                    "llm_planning_allowed": False,
                    "iem_value_mutation_allowed": False,
                    "normative_local_mutation_allowed": False,
                },
                "goal_candidate_surface": {
                    "mode": "draft_only",
                    "candidate_goal_count": len(candidates),
                    "candidate_goals": candidates,
                },
                "vmv_stage_gate": {"passed": True, "checks": {}},
            }
        ),
        encoding="utf-8",
    )
    return path


def _candidate(event_kind: str) -> dict:
    return {
        "goal_id": f"h3-draft-goal:{event_kind}:alpha",
        "state": "draft_review_required",
        "trigger_event_kind": event_kind,
        "identity": "alpha",
        "risk_class": "critical" if event_kind == "economic_deviation" else "high",
        "evidence": {
            "backend_sourced": True,
            "event_kind": event_kind,
            "identity": "alpha",
            "max_pattern_count": 2,
            "candidate_count": 2,
            "record_ids": [f"alpha:{event_kind}:01", f"alpha:{event_kind}:02"],
            "sources": ["backend_task_pool_read_model"],
        },
        "review_policy": {
            "human_review_required": True,
            "governance_review_required": True,
            "challenge_window_required": True,
            "rollback_plan_required": True,
            "r2r_accountability_required": True,
        },
        "execution_policy": {
            "goal_emission_allowed": False,
            "executable_plan_allowed": False,
            "runtime_execution_allowed": False,
            "llm_planning_allowed": False,
            "iem_value_mutation_allowed": False,
            "normative_local_mutation_allowed": False,
        },
        "refusal_conditions": [
            "missing_h1_or_h2_gate_evidence",
            "missing_human_or_governance_review",
            "missing_challenge_window",
            "attempts_normative_local_mutation",
            "attempts_runtime_execution_from_draft",
        ],
    }