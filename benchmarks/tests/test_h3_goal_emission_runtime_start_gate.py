from __future__ import annotations

import json
from pathlib import Path

from benchmarks.h3_goal_emission_runtime_start_gate import build_h3_goal_emission_runtime_start_gate


def test_runtime_start_gate_blocks_without_reviewed_runtime_activation_artifacts(tmp_path: Path) -> None:
    artifact_gate = _write_runtime_activation_artifact_gate(
        tmp_path,
        decision="runtime_activation_artifacts_blocked_no_runtime_activation_packets",
    )

    report = build_h3_goal_emission_runtime_start_gate(
        runtime_activation_artifact_gate_path=artifact_gate,
        agent_root=tmp_path,
    )

    assert report["passed"] is True
    assert report["readiness"]["decision"] == "runtime_start_blocked_no_reviewed_runtime_activation_artifacts"
    assert report["runtime_start_boundary"]["runtime_start_allowed"] is False
    assert report["runtime_start_boundary"]["runtime_execution_allowed"] is False
    assert report["metrics"]["runtime_start_review_packet_count"] == 0
    assert report["metrics"]["runtime_execution_ready_count"] == 0


def test_runtime_start_gate_blocks_pending_runtime_activation_artifacts(tmp_path: Path) -> None:
    pending = _pending_runtime_activation_packet("economic_deviation")
    artifact_gate = _write_runtime_activation_artifact_gate(
        tmp_path,
        decision="runtime_activation_artifacts_blocked_pending_required_artifacts",
        pending_packets=[pending],
    )

    report = build_h3_goal_emission_runtime_start_gate(
        runtime_activation_artifact_gate_path=artifact_gate,
        agent_root=tmp_path,
    )

    assert report["passed"] is True
    assert report["readiness"]["decision"] == "runtime_start_blocked_pending_runtime_activation_artifacts"
    assert report["metrics"]["blocked_runtime_start_candidate_count"] == 1
    assert report["runtime_start_surface"]["blocked_runtime_start_candidates"][0]["state"] == "runtime_start_blocked"


def test_runtime_start_gate_blocks_synthetic_or_blocked_runtime_activation(tmp_path: Path) -> None:
    artifact_gate = _write_runtime_activation_artifact_gate(
        tmp_path,
        decision="runtime_activation_artifacts_blocked_synthetic_or_blocked_activation",
        blocked_candidates=[_blocked_runtime_activation_candidate("post_delivery_failure")],
    )

    report = build_h3_goal_emission_runtime_start_gate(
        runtime_activation_artifact_gate_path=artifact_gate,
        agent_root=tmp_path,
    )

    assert report["passed"] is True
    assert report["readiness"]["decision"] == "runtime_start_blocked_synthetic_or_blocked_runtime_activation"
    assert report["metrics"]["blocked_runtime_start_candidate_count"] == 1
    assert report["metrics"]["runtime_start_review_packet_count"] == 0


def test_runtime_start_gate_creates_review_packets_without_runtime_start(tmp_path: Path) -> None:
    reviewed = _reviewed_runtime_activation_packet("relation_repair_relapse")
    artifact_gate = _write_runtime_activation_artifact_gate(
        tmp_path,
        decision="production_runtime_activation_artifacts_reviewed_no_runtime",
        reviewed_packets=[reviewed],
    )

    report = build_h3_goal_emission_runtime_start_gate(
        runtime_activation_artifact_gate_path=artifact_gate,
        agent_root=tmp_path,
    )

    assert report["passed"] is True
    assert report["readiness"]["decision"] == "runtime_start_review_packets_ready_no_runtime"
    assert report["readiness"]["runtime_start_review_packets_ready"] is True
    assert report["readiness"]["runtime_start_ready"] is False
    assert report["runtime_start_boundary"]["runtime_start_review_packets_allowed"] is True
    assert report["runtime_start_boundary"]["runtime_start_allowed"] is False
    assert report["runtime_start_boundary"]["runtime_activation_allowed"] is False
    assert report["runtime_start_boundary"]["runtime_execution_allowed"] is False
    assert report["metrics"]["runtime_start_review_packet_count"] == 1
    assert report["metrics"]["runtime_start_ready_count"] == 0
    assert report["metrics"]["runtime_execution_ready_count"] == 0
    packet = report["runtime_start_surface"]["runtime_start_review_packets"][0]
    assert packet["state"] == "runtime_start_review_required"
    assert packet["gate_status"]["runtime_start_ready"] is False
    assert packet["gate_status"]["runtime_execution_ready"] is False
    assert packet["execution_policy"]["runtime_execution_allowed"] is False
    assert set(packet["required_runtime_start_controls"]) == {
        "runtime_start_change_ticket",
        "runtime_start_dual_operator_ack",
        "runtime_start_final_monitoring_green",
        "runtime_start_final_kill_switch_check",
        "runtime_start_rollback_checkpoint",
        "runtime_start_audit_sink_ready",
    }


def test_runtime_start_gate_blocks_synthetic_reviewed_runtime_activation_artifacts(tmp_path: Path) -> None:
    reviewed = _reviewed_runtime_activation_packet("post_delivery_dispute", synthetic=True)
    artifact_gate = _write_runtime_activation_artifact_gate(
        tmp_path,
        decision="synthetic_runtime_activation_artifacts_reviewed_no_runtime",
        reviewed_packets=[reviewed],
    )

    report = build_h3_goal_emission_runtime_start_gate(
        runtime_activation_artifact_gate_path=artifact_gate,
        agent_root=tmp_path,
    )

    assert report["passed"] is True
    assert report["readiness"]["decision"] == "runtime_start_blocked_synthetic_or_blocked_runtime_activation"
    assert report["metrics"]["runtime_start_review_packet_count"] == 0
    assert report["runtime_start_surface"]["blocked_runtime_start_candidates"][0]["state"] == "runtime_start_blocked"


def test_runtime_start_gate_blocks_runtime_boundary_regression(tmp_path: Path) -> None:
    artifact_gate = _write_runtime_activation_artifact_gate(
        tmp_path,
        decision="production_runtime_activation_artifacts_reviewed_no_runtime",
        reviewed_packets=[_reviewed_runtime_activation_packet("governance_rollback")],
        boundary={"runtime_execution_allowed": True},
    )

    report = build_h3_goal_emission_runtime_start_gate(
        runtime_activation_artifact_gate_path=artifact_gate,
        agent_root=tmp_path,
    )

    assert report["passed"] is False
    assert report["checks"]["runtime_activation_artifact_boundary_runtime_execution_allowed_false"] is False
    assert report["runtime_start_boundary"]["runtime_start_allowed"] is False
    assert report["runtime_start_boundary"]["runtime_execution_allowed"] is False


def _write_runtime_activation_artifact_gate(
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
    default_boundary = {
        "artifact_only": True,
        "runtime_activation_artifact_review_allowed": bool(reviewed_packets),
        "production_runtime_activation_artifact_review_allowed": decision == "production_runtime_activation_artifacts_reviewed_no_runtime",
        "synthetic_runtime_activation_artifact_surface_allowed": decision == "synthetic_runtime_activation_artifacts_reviewed_no_runtime",
        "runtime_activation_allowed": False,
        "runtime_execution_allowed": False,
        "activation_allowed": False,
        "goal_emission_allowed": False,
        "emitted_goal_allowed": False,
        "executable_plan_allowed": False,
        "llm_planning_allowed": False,
        "iem_value_mutation_allowed": False,
        "normative_local_mutation_allowed": False,
    }
    default_boundary.update(boundary or {})
    path = tmp_path / "h3_goal_emission_runtime_activation_artifact_gate.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": "h3-goal-emission-runtime-activation-artifact-gate:v1",
                "passed": True,
                "readiness": {
                    "runtime_activation_artifact_gate_evaluated": True,
                    "runtime_activation_artifacts_complete": bool(reviewed_packets),
                    "production_runtime_activation_artifacts_complete": decision == "production_runtime_activation_artifacts_reviewed_no_runtime",
                    "synthetic_runtime_activation_artifacts_complete": decision == "synthetic_runtime_activation_artifacts_reviewed_no_runtime",
                    "runtime_activation_ready": False,
                    "runtime_execution_ready": False,
                    "activation_ready": False,
                    "emitted_goal_ready": False,
                    "executable_goal_ready": False,
                    "decision": decision,
                },
                "runtime_activation_artifact_boundary": default_boundary,
                "runtime_activation_artifact_surface": {
                    "mode": "runtime_activation_artifacts_review_only_no_runtime",
                    "reviewed_runtime_activation_packet_count": len(reviewed_packets),
                    "reviewed_runtime_activation_packets": reviewed_packets,
                    "pending_runtime_activation_packet_count": len(pending_packets),
                    "pending_runtime_activation_packets": pending_packets,
                    "blocked_runtime_activation_candidate_count": len(blocked_candidates),
                    "blocked_runtime_activation_candidates": blocked_candidates,
                    "runtime_executions": [],
                    "emitted_goals": [],
                },
            }
        ),
        encoding="utf-8",
    )
    return path


def _reviewed_runtime_activation_packet(event_kind: str, *, synthetic: bool = False) -> dict:
    goal_id = f"h3-draft-goal:{event_kind}:alpha"
    return {
        "artifact_review_id": f"h3-runtime-activation-artifact-review:{goal_id}",
        "runtime_activation_packet_id": f"h3-runtime-activation-review:{goal_id}",
        "activation_packet_id": f"h3-goal-emission-activation:{goal_id}",
        "preflight_id": f"h3-goal-emission-preflight:{goal_id}",
        "approval_id": f"h3-approved-candidate:{goal_id}",
        "goal_id": goal_id,
        "state": "runtime_activation_artifacts_reviewed_no_runtime",
        "synthetic_runtime_activation_fixture": synthetic,
        "production_runtime_activation_artifacts_ready": not synthetic,
        "runtime_activation_artifact_refs": {
            "runtime_safety_envelope": f"runtime-activation:runtime_safety_envelope:{goal_id}",
            "rollout_window_approval": f"runtime-activation:rollout_window_approval:{goal_id}",
            "live_monitoring_attestation": f"runtime-activation:live_monitoring_attestation:{goal_id}",
            "rollback_drill_attestation": f"runtime-activation:rollback_drill_attestation:{goal_id}",
            "operator_oncall_ack": f"runtime-activation:operator_oncall_ack:{goal_id}",
            "kill_switch_attestation": f"runtime-activation:kill_switch_attestation:{goal_id}",
            "post_activation_audit_plan": f"runtime-activation:post_activation_audit_plan:{goal_id}",
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
            "runtime_activation_artifacts_complete": True,
            "runtime_activation_ready": False,
            "runtime_execution_ready": False,
        },
    }


def _pending_runtime_activation_packet(event_kind: str) -> dict:
    goal_id = f"h3-draft-goal:{event_kind}:alpha"
    return {
        "runtime_activation_packet_id": f"h3-runtime-activation-review:{goal_id}",
        "goal_id": goal_id,
        "state": "runtime_activation_review_required",
        "runtime_activation_artifacts_complete": False,
        "missing_or_rejected_runtime_activation_artifacts": ["runtime_safety_envelope"],
    }


def _blocked_runtime_activation_candidate(event_kind: str) -> dict:
    goal_id = f"h3-draft-goal:{event_kind}:alpha"
    return {
        "goal_id": goal_id,
        "activation_packet_id": f"h3-goal-emission-activation:{goal_id}",
        "state": "runtime_activation_blocked",
        "blocked_reason": "synthetic runtime activation fixture cannot enter runtime start",
    }