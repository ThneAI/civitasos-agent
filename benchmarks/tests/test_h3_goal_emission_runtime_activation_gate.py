from __future__ import annotations

import json
from pathlib import Path

from benchmarks.h3_goal_emission_runtime_activation_gate import build_h3_goal_emission_runtime_activation_gate


def test_runtime_activation_gate_blocks_without_reviewed_artifacts(tmp_path: Path) -> None:
    artifact_gate = _write_artifact_gate(
        tmp_path,
        decision="activation_artifacts_blocked_no_activation_packets",
    )

    report = build_h3_goal_emission_runtime_activation_gate(
        activation_artifact_gate_path=artifact_gate,
        agent_root=tmp_path,
    )

    assert report["passed"] is True
    assert report["readiness"]["decision"] == "runtime_activation_blocked_no_reviewed_activation_artifacts"
    assert report["readiness"]["runtime_activation_ready"] is False
    assert report["runtime_activation_boundary"]["runtime_activation_allowed"] is False
    assert report["runtime_activation_boundary"]["runtime_execution_allowed"] is False
    assert report["metrics"]["runtime_activation_review_packet_count"] == 0
    assert report["metrics"]["runtime_execution_ready_count"] == 0


def test_runtime_activation_gate_blocks_pending_activation_artifacts(tmp_path: Path) -> None:
    artifact_gate = _write_artifact_gate(
        tmp_path,
        decision="activation_artifacts_blocked_pending_required_artifacts",
        pending_packets=[_pending_packet("post_delivery_failure")],
    )

    report = build_h3_goal_emission_runtime_activation_gate(
        activation_artifact_gate_path=artifact_gate,
        agent_root=tmp_path,
    )

    assert report["passed"] is True
    assert report["readiness"]["decision"] == "runtime_activation_blocked_pending_activation_artifacts"
    assert report["metrics"]["blocked_runtime_activation_candidate_count"] == 1
    assert report["metrics"]["runtime_activation_review_packet_count"] == 0
    assert report["runtime_activation_surface"]["blocked_runtime_activation_candidates"][0]["state"] == "runtime_activation_blocked"


def test_runtime_activation_gate_blocks_synthetic_or_blocked_activation(tmp_path: Path) -> None:
    artifact_gate = _write_artifact_gate(
        tmp_path,
        decision="activation_artifacts_blocked_synthetic_or_blocked_emission",
        blocked_candidates=[_blocked_activation_candidate("post_delivery_dispute")],
    )

    report = build_h3_goal_emission_runtime_activation_gate(
        activation_artifact_gate_path=artifact_gate,
        agent_root=tmp_path,
    )

    assert report["passed"] is True
    assert report["readiness"]["decision"] == "runtime_activation_blocked_synthetic_or_blocked_activation"
    assert report["metrics"]["blocked_runtime_activation_candidate_count"] == 1
    assert report["metrics"]["runtime_execution_ready_count"] == 0


def test_runtime_activation_gate_creates_review_packets_without_runtime(tmp_path: Path) -> None:
    artifact_gate = _write_artifact_gate(
        tmp_path,
        decision="production_activation_artifacts_reviewed_no_activation",
        reviewed_packets=[_reviewed_packet("economic_deviation", synthetic=False)],
    )

    report = build_h3_goal_emission_runtime_activation_gate(
        activation_artifact_gate_path=artifact_gate,
        agent_root=tmp_path,
    )

    assert report["passed"] is True
    assert report["readiness"]["decision"] == "runtime_activation_review_packets_ready_no_runtime"
    assert report["readiness"]["runtime_activation_review_packets_ready"] is True
    assert report["readiness"]["runtime_activation_ready"] is False
    assert report["runtime_activation_boundary"]["runtime_activation_review_packets_allowed"] is True
    assert report["runtime_activation_boundary"]["runtime_activation_allowed"] is False
    assert report["runtime_activation_boundary"]["runtime_execution_allowed"] is False
    assert report["metrics"]["runtime_activation_review_packet_count"] == 1
    assert report["metrics"]["runtime_execution_ready_count"] == 0
    packet = report["runtime_activation_surface"]["runtime_activation_review_packets"][0]
    assert packet["state"] == "runtime_activation_review_required"
    assert packet["gate_status"]["runtime_activation_ready"] is False
    assert packet["execution_policy"]["runtime_execution_allowed"] is False
    assert set(packet["required_runtime_activation_artifacts"]) == {
        "runtime_safety_envelope",
        "rollout_window_approval",
        "live_monitoring_attestation",
        "rollback_drill_attestation",
        "operator_oncall_ack",
        "kill_switch_attestation",
        "post_activation_audit_plan",
    }


def test_runtime_activation_gate_blocks_synthetic_reviewed_artifacts(tmp_path: Path) -> None:
    artifact_gate = _write_artifact_gate(
        tmp_path,
        decision="synthetic_activation_artifacts_reviewed_no_activation",
        reviewed_packets=[_reviewed_packet("economic_deviation", synthetic=True)],
    )

    report = build_h3_goal_emission_runtime_activation_gate(
        activation_artifact_gate_path=artifact_gate,
        agent_root=tmp_path,
    )

    assert report["passed"] is True
    assert report["readiness"]["decision"] == "runtime_activation_blocked_synthetic_or_blocked_activation"
    assert report["metrics"]["runtime_activation_review_packet_count"] == 0
    assert report["metrics"]["blocked_runtime_activation_candidate_count"] == 1
    assert report["runtime_activation_surface"]["blocked_runtime_activation_candidates"][0]["synthetic_activation_fixture"] is True


def test_runtime_activation_gate_blocks_artifact_boundary_regression(tmp_path: Path) -> None:
    artifact_gate = _write_artifact_gate(
        tmp_path,
        decision="production_activation_artifacts_reviewed_no_activation",
        reviewed_packets=[_reviewed_packet("relation_repair_relapse", synthetic=False)],
        boundary={"runtime_execution_allowed": True},
    )

    report = build_h3_goal_emission_runtime_activation_gate(
        activation_artifact_gate_path=artifact_gate,
        agent_root=tmp_path,
    )

    assert report["passed"] is False
    assert report["checks"]["activation_artifact_boundary_runtime_execution_allowed_false"] is False
    assert report["runtime_activation_boundary"]["runtime_execution_allowed"] is False
    assert report["metrics"]["runtime_execution_ready_count"] == 0


def _write_artifact_gate(
    tmp_path: Path,
    *,
    decision: str,
    reviewed_packets: list[dict] | None = None,
    pending_packets: list[dict] | None = None,
    blocked_candidates: list[dict] | None = None,
    boundary: dict | None = None,
) -> Path:
    reviewed_packets = reviewed_packets or []
    pending_packets = pending_packets or []
    blocked_candidates = blocked_candidates or []
    synthetic_complete = bool(reviewed_packets) and any(packet.get("synthetic_activation_fixture") is True for packet in reviewed_packets)
    production_complete = bool(reviewed_packets) and not synthetic_complete
    default_boundary = {
        "artifact_only": True,
        "activation_artifact_review_allowed": bool(reviewed_packets),
        "production_activation_artifact_review_allowed": production_complete,
        "synthetic_activation_artifact_surface_allowed": synthetic_complete,
        "activation_allowed": False,
        "goal_emission_allowed": False,
        "emitted_goal_allowed": False,
        "executable_plan_allowed": False,
        "runtime_execution_allowed": False,
        "llm_planning_allowed": False,
        "iem_value_mutation_allowed": False,
        "normative_local_mutation_allowed": False,
    }
    default_boundary.update(boundary or {})
    path = tmp_path / "h3_goal_emission_activation_artifact_gate.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": "h3-goal-emission-activation-artifact-gate:v1",
                "passed": True,
                "readiness": {
                    "activation_artifact_gate_evaluated": True,
                    "activation_artifacts_complete": bool(reviewed_packets) and not pending_packets,
                    "production_activation_artifacts_complete": production_complete,
                    "synthetic_activation_artifacts_complete": synthetic_complete,
                    "activation_ready": False,
                    "emitted_goal_ready": False,
                    "executable_goal_ready": False,
                    "runtime_execution_ready": False,
                    "decision": decision,
                },
                "activation_artifact_boundary": default_boundary,
                "activation_artifact_surface": {
                    "mode": "activation_artifacts_review_only_no_activation",
                    "reviewed_activation_packet_count": len(reviewed_packets),
                    "reviewed_activation_packets": reviewed_packets,
                    "pending_activation_packet_count": len(pending_packets),
                    "pending_activation_packets": pending_packets,
                    "blocked_activation_candidate_count": len(blocked_candidates),
                    "blocked_activation_candidates": blocked_candidates,
                    "emitted_goals": [],
                },
            }
        ),
        encoding="utf-8",
    )
    return path


def _reviewed_packet(event_kind: str, *, synthetic: bool) -> dict:
    goal_id = f"h3-draft-goal:{event_kind}:alpha"
    return {
        "artifact_review_id": f"h3-activation-artifact-review:{goal_id}",
        "activation_packet_id": f"h3-goal-emission-activation:{goal_id}",
        "goal_id": goal_id,
        "preflight_id": f"h3-goal-emission-preflight:{goal_id}",
        "approval_id": f"h3-approved-candidate:{goal_id}",
        "state": "activation_artifacts_reviewed_no_activation",
        "synthetic_activation_fixture": synthetic,
        "production_activation_artifacts_ready": not synthetic,
        "activation_artifact_refs": {
            "human_activation_record": f"human-activation:{goal_id}",
            "governance_activation_record": f"governance-activation:{goal_id}",
            "h1_h2_replay_attestation": f"h1-h2-replay:{goal_id}",
            "rollback_activation_ack": f"rollback-activation:{goal_id}",
            "runtime_non_execution_ack": f"runtime-non-execution:{goal_id}",
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
            "activation_artifacts_complete": True,
            "activation_ready": False,
            "emitted_goal_ready": False,
            "runtime_execution_ready": False,
        },
    }


def _pending_packet(event_kind: str) -> dict:
    goal_id = f"h3-draft-goal:{event_kind}:alpha"
    return {
        "activation_packet_id": f"h3-goal-emission-activation:{goal_id}",
        "goal_id": goal_id,
        "state": "goal_emission_activation_review_required",
        "activation_artifacts_complete": False,
        "missing_or_rejected_activation_artifacts": ["human_activation_record"],
    }


def _blocked_activation_candidate(event_kind: str) -> dict:
    goal_id = f"h3-draft-goal:{event_kind}:alpha"
    return {
        "goal_id": goal_id,
        "activation_packet_id": f"h3-goal-emission-activation:{goal_id}",
        "state": "goal_emission_activation_blocked",
        "blocked_reason": "synthetic approval cannot enter goal emission",
        "synthetic_review_fixture": True,
    }