from __future__ import annotations

import json
from pathlib import Path

from benchmarks.h3_goal_emission_gate import build_h3_goal_emission_gate


def test_h3_goal_emission_gate_blocks_pending_approval(tmp_path: Path) -> None:
    approval_gate = _write_approval_gate(tmp_path, decision="approval_blocked_pending_external_review_artifacts")

    report = build_h3_goal_emission_gate(approval_gate_path=approval_gate, agent_root=tmp_path)

    assert report["passed"] is True
    assert report["readiness"]["decision"] == "goal_emission_blocked_pending_production_approval"
    assert report["readiness"]["goal_emission_preflight_ready"] is False
    assert report["emission_boundary"]["goal_emission_allowed"] is False
    assert report["metrics"]["emitted_goal_count"] == 0
    assert report["emission_surface"]["emitted_goals"] == []


def test_h3_goal_emission_gate_blocks_synthetic_approval(tmp_path: Path) -> None:
    approval_gate = _write_approval_gate(
        tmp_path,
        decision="synthetic_approved_candidate_surface_ready",
        approved_candidates=[_approved_candidate("post_delivery_failure", synthetic=True)],
        synthetic_approved=True,
    )

    report = build_h3_goal_emission_gate(approval_gate_path=approval_gate, agent_root=tmp_path)

    assert report["passed"] is True
    assert report["readiness"]["decision"] == "goal_emission_blocked_synthetic_approval_only"
    assert report["readiness"]["synthetic_approval_observed"] is True
    assert report["readiness"]["production_approval_observed"] is False
    assert report["metrics"]["blocked_candidate_count"] == 1
    assert report["metrics"]["emission_preflight_candidate_count"] == 0
    assert report["emission_surface"]["blocked_candidates"][0]["blocked_reason"] == "synthetic approval cannot enter goal emission"
    assert report["emission_boundary"]["goal_emission_allowed"] is False


def test_h3_goal_emission_gate_surfaces_production_preflight_without_emission(tmp_path: Path) -> None:
    approval_gate = _write_approval_gate(
        tmp_path,
        decision="approved_candidate_surface_ready",
        approved_candidates=[_approved_candidate("economic_deviation", synthetic=False)],
        production_approved=True,
    )

    report = build_h3_goal_emission_gate(approval_gate_path=approval_gate, agent_root=tmp_path)

    assert report["passed"] is True
    assert report["readiness"]["decision"] == "goal_emission_preflight_ready_no_emission"
    assert report["readiness"]["production_approval_observed"] is True
    assert report["readiness"]["goal_emission_preflight_ready"] is True
    assert report["readiness"]["emitted_goal_ready"] is False
    assert report["emission_boundary"]["goal_emission_preflight_allowed"] is True
    assert report["emission_boundary"]["goal_emission_allowed"] is False
    assert report["metrics"]["emission_preflight_candidate_count"] == 1
    assert report["metrics"]["emitted_goal_count"] == 0
    preflight = report["emission_surface"]["emission_preflight_candidates"][0]
    assert preflight["state"] == "goal_emission_preflight_ready"
    assert preflight["execution_policy"]["runtime_execution_allowed"] is False
    assert preflight["blocked_transitions"][0]["transition"] == "goal_emission_preflight_ready -> executable_goal_emitted"


def test_h3_goal_emission_gate_blocks_approval_boundary_regression(tmp_path: Path) -> None:
    approval_gate = _write_approval_gate(
        tmp_path,
        decision="approved_candidate_surface_ready",
        approved_candidates=[_approved_candidate("post_delivery_dispute", synthetic=False)],
        production_approved=True,
        boundary={"goal_emission_allowed": True},
    )

    report = build_h3_goal_emission_gate(approval_gate_path=approval_gate, agent_root=tmp_path)

    assert report["passed"] is False
    assert report["checks"]["approval_boundary_goal_emission_allowed_false"] is False
    assert report["emission_boundary"]["goal_emission_allowed"] is False
    assert report["metrics"]["emitted_goal_count"] == 0


def _write_approval_gate(
    tmp_path: Path,
    *,
    decision: str,
    approved_candidates: list[dict] | None = None,
    production_approved: bool = False,
    synthetic_approved: bool = False,
    boundary: dict | None = None,
) -> Path:
    approved_candidates = approved_candidates or []
    default_boundary = {
        "artifact_only": True,
        "candidate_approval_allowed": production_approved,
        "synthetic_candidate_surface_allowed": synthetic_approved,
        "production_candidate_approval_allowed": production_approved,
        "goal_emission_allowed": False,
        "executable_plan_allowed": False,
        "runtime_execution_allowed": False,
        "llm_planning_allowed": False,
        "iem_value_mutation_allowed": False,
        "normative_local_mutation_allowed": False,
    }
    default_boundary.update(boundary or {})
    path = tmp_path / "h3_goal_approval_gate.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": "h3-goal-approval-gate:v1",
                "passed": True,
                "readiness": {
                    "approval_gate_evaluated": True,
                    "approved_candidate_ready": bool(approved_candidates),
                    "production_approved_candidate_ready": production_approved,
                    "synthetic_approved_candidate_ready": synthetic_approved,
                    "executable_goal_ready": False,
                    "decision": decision,
                },
                "approval_boundary": default_boundary,
                "approval_surface": {
                    "mode": "approval_only_no_execution",
                    "approved_candidate_count": len(approved_candidates),
                    "approved_candidates": approved_candidates,
                    "pending_review_packet_count": 0,
                    "pending_review_packets": [],
                },
            }
        ),
        encoding="utf-8",
    )
    return path


def _approved_candidate(event_kind: str, *, synthetic: bool) -> dict:
    goal_id = f"h3-draft-goal:{event_kind}:alpha"
    return {
        "approval_id": f"h3-approved-candidate:{goal_id}",
        "goal_id": goal_id,
        "packet_id": f"h3-review-packet:{goal_id}",
        "state": "approved_candidate",
        "identity": "alpha",
        "trigger_event_kind": event_kind,
        "risk_class": "critical" if event_kind == "economic_deviation" else "high",
        "synthetic_review_fixture": synthetic,
        "production_approval_ready": not synthetic,
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
        "gate_status": {
            "approved_candidate_ready": True,
            "executable_goal_ready": False,
            "runtime_execution_ready": False,
        },
    }