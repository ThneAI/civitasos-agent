from __future__ import annotations

import json
from pathlib import Path

from benchmarks.h3_goal_emission_activation_gate import build_h3_goal_emission_activation_gate


def test_activation_gate_blocks_without_emission_preflight(tmp_path: Path) -> None:
    emission_gate = _write_emission_gate(tmp_path, decision="goal_emission_blocked_pending_production_approval")

    report = build_h3_goal_emission_activation_gate(emission_gate_path=emission_gate, agent_root=tmp_path)

    assert report["passed"] is True
    assert report["readiness"]["decision"] == "goal_emission_activation_blocked_no_preflight"
    assert report["readiness"]["activation_review_packets_ready"] is False
    assert report["activation_boundary"]["activation_allowed"] is False
    assert report["activation_boundary"]["goal_emission_allowed"] is False
    assert report["metrics"]["activation_packet_count"] == 0
    assert report["metrics"]["emitted_goal_count"] == 0


def test_activation_gate_blocks_synthetic_emission_candidates(tmp_path: Path) -> None:
    emission_gate = _write_emission_gate(
        tmp_path,
        decision="goal_emission_blocked_synthetic_approval_only",
        synthetic_observed=True,
        blocked_candidates=[_blocked_candidate("post_delivery_failure")],
    )

    report = build_h3_goal_emission_activation_gate(emission_gate_path=emission_gate, agent_root=tmp_path)

    assert report["passed"] is True
    assert report["readiness"]["decision"] == "goal_emission_activation_blocked_synthetic_or_blocked_emission"
    assert report["metrics"]["blocked_activation_candidate_count"] == 1
    assert report["metrics"]["activation_packet_count"] == 0
    assert report["activation_surface"]["blocked_activation_candidates"][0]["synthetic_review_fixture"] is True


def test_activation_gate_creates_review_packets_without_activation(tmp_path: Path) -> None:
    emission_gate = _write_emission_gate(
        tmp_path,
        decision="goal_emission_preflight_ready_no_emission",
        production_observed=True,
        preflight_candidates=[_preflight_candidate("economic_deviation")],
    )

    report = build_h3_goal_emission_activation_gate(emission_gate_path=emission_gate, agent_root=tmp_path)

    assert report["passed"] is True
    assert report["readiness"]["decision"] == "goal_emission_activation_review_packets_ready_no_activation"
    assert report["readiness"]["activation_review_packets_ready"] is True
    assert report["readiness"]["activation_ready"] is False
    assert report["activation_boundary"]["activation_review_packets_allowed"] is True
    assert report["activation_boundary"]["activation_allowed"] is False
    assert report["activation_boundary"]["emitted_goal_allowed"] is False
    assert report["metrics"]["activation_packet_count"] == 1
    assert report["metrics"]["emitted_goal_count"] == 0
    packet = report["activation_surface"]["activation_packets"][0]
    assert packet["state"] == "goal_emission_activation_review_required"
    assert packet["execution_policy"]["runtime_execution_allowed"] is False
    assert set(packet["required_activation_artifacts"]) == {
        "human_activation_record",
        "governance_activation_record",
        "h1_h2_replay_attestation",
        "rollback_activation_ack",
        "runtime_non_execution_ack",
    }


def test_activation_gate_blocks_emission_boundary_regression(tmp_path: Path) -> None:
    emission_gate = _write_emission_gate(
        tmp_path,
        decision="goal_emission_preflight_ready_no_emission",
        production_observed=True,
        preflight_candidates=[_preflight_candidate("post_delivery_dispute")],
        boundary={"runtime_execution_allowed": True},
    )

    report = build_h3_goal_emission_activation_gate(emission_gate_path=emission_gate, agent_root=tmp_path)

    assert report["passed"] is False
    assert report["checks"]["emission_boundary_runtime_execution_allowed_false"] is False
    assert report["activation_boundary"]["runtime_execution_allowed"] is False
    assert report["metrics"]["emitted_goal_count"] == 0


def test_activation_gate_blocks_preflight_decision_without_candidates(tmp_path: Path) -> None:
    emission_gate = _write_emission_gate(
        tmp_path,
        decision="goal_emission_preflight_ready_no_emission",
        production_observed=True,
    )

    report = build_h3_goal_emission_activation_gate(emission_gate_path=emission_gate, agent_root=tmp_path)

    assert report["passed"] is False
    assert report["checks"]["preflight_candidate_decision_consistent"] is False
    assert report["activation_boundary"]["activation_allowed"] is False
    assert report["metrics"]["activation_packet_count"] == 0


def _write_emission_gate(
    tmp_path: Path,
    *,
    decision: str,
    preflight_candidates: list[dict] | None = None,
    blocked_candidates: list[dict] | None = None,
    production_observed: bool = False,
    synthetic_observed: bool = False,
    boundary: dict | None = None,
) -> Path:
    preflight_candidates = preflight_candidates or []
    blocked_candidates = blocked_candidates or []
    default_boundary = {
        "artifact_only": True,
        "goal_emission_preflight_allowed": bool(preflight_candidates),
        "goal_emission_allowed": False,
        "emitted_goal_allowed": False,
        "executable_plan_allowed": False,
        "runtime_execution_allowed": False,
        "llm_planning_allowed": False,
        "iem_value_mutation_allowed": False,
        "normative_local_mutation_allowed": False,
    }
    default_boundary.update(boundary or {})
    path = tmp_path / "h3_goal_emission_gate.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": "h3-goal-emission-gate:v1",
                "passed": True,
                "readiness": {
                    "goal_emission_gate_evaluated": True,
                    "production_approval_observed": production_observed,
                    "synthetic_approval_observed": synthetic_observed,
                    "goal_emission_preflight_ready": bool(preflight_candidates),
                    "emitted_goal_ready": False,
                    "executable_goal_ready": False,
                    "runtime_execution_ready": False,
                    "decision": decision,
                },
                "emission_boundary": default_boundary,
                "emission_surface": {
                    "mode": "preflight_only_no_goal_emission",
                    "emission_preflight_candidate_count": len(preflight_candidates),
                    "emission_preflight_candidates": preflight_candidates,
                    "blocked_candidate_count": len(blocked_candidates),
                    "blocked_candidates": blocked_candidates,
                    "emitted_goals": [],
                },
            }
        ),
        encoding="utf-8",
    )
    return path


def _preflight_candidate(event_kind: str) -> dict:
    goal_id = f"h3-draft-goal:{event_kind}:alpha"
    return {
        "preflight_id": f"h3-goal-emission-preflight:{goal_id}",
        "goal_id": goal_id,
        "approval_id": f"h3-approved-candidate:{goal_id}",
        "state": "goal_emission_preflight_ready",
        "identity": "alpha",
        "trigger_event_kind": event_kind,
        "risk_class": "critical" if event_kind == "economic_deviation" else "high",
        "production_approval_ready": True,
        "synthetic_review_fixture": False,
        "external_artifact_refs": {
            "human_review_record": f"human-review:{goal_id}",
            "governance_review_record": f"governance-review:{goal_id}",
            "challenge_window_result": f"challenge-window:{goal_id}",
            "rollback_plan_record": f"rollback-plan:{goal_id}",
            "r2r_accountability_record": f"r2r-accountability:{goal_id}",
        },
        "execution_policy": {
            "goal_emission_allowed": False,
            "executable_plan_allowed": False,
            "runtime_execution_allowed": False,
            "llm_planning_allowed": False,
            "iem_value_mutation_allowed": False,
            "normative_local_mutation_allowed": False,
        },
    }


def _blocked_candidate(event_kind: str) -> dict:
    goal_id = f"h3-draft-goal:{event_kind}:alpha"
    return {
        "goal_id": goal_id,
        "approval_id": f"h3-approved-candidate:{goal_id}",
        "state": "goal_emission_blocked",
        "synthetic_review_fixture": True,
        "blocked_reason": "synthetic approval cannot enter goal emission",
    }