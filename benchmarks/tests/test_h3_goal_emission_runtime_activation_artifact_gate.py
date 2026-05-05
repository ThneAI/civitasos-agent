from __future__ import annotations

import json
from pathlib import Path

from benchmarks.h3_goal_emission_runtime_activation_artifact_gate import (
    build_h3_goal_emission_runtime_activation_artifact_gate,
)


def test_runtime_activation_artifact_gate_blocks_without_runtime_packets(tmp_path: Path) -> None:
    runtime_gate = _write_runtime_activation_gate(
        tmp_path,
        decision="runtime_activation_blocked_no_reviewed_activation_artifacts",
    )

    report = build_h3_goal_emission_runtime_activation_artifact_gate(
        runtime_activation_gate_path=runtime_gate,
        agent_root=tmp_path,
    )

    assert report["passed"] is True
    assert report["readiness"]["decision"] == "runtime_activation_artifacts_blocked_no_runtime_activation_packets"
    assert report["readiness"]["runtime_activation_ready"] is False
    assert report["runtime_activation_artifact_boundary"]["runtime_activation_allowed"] is False
    assert report["runtime_activation_artifact_boundary"]["runtime_execution_allowed"] is False
    assert report["metrics"]["reviewed_runtime_activation_packet_count"] == 0
    assert report["metrics"]["runtime_execution_ready_count"] == 0


def test_runtime_activation_artifact_gate_blocks_synthetic_or_blocked_activation(tmp_path: Path) -> None:
    runtime_gate = _write_runtime_activation_gate(
        tmp_path,
        decision="runtime_activation_blocked_synthetic_or_blocked_activation",
        blocked_candidates=[_blocked_runtime_candidate("post_delivery_failure")],
    )

    report = build_h3_goal_emission_runtime_activation_artifact_gate(
        runtime_activation_gate_path=runtime_gate,
        agent_root=tmp_path,
    )

    assert report["passed"] is True
    assert report["readiness"]["decision"] == "runtime_activation_artifacts_blocked_synthetic_or_blocked_activation"
    assert report["metrics"]["blocked_runtime_activation_candidate_count"] == 1
    assert report["metrics"]["reviewed_runtime_activation_packet_count"] == 0
    assert report["runtime_activation_artifact_surface"]["blocked_runtime_activation_candidates"][0]["state"] == "runtime_activation_blocked"


def test_runtime_activation_artifact_gate_keeps_packets_pending_without_artifacts(tmp_path: Path) -> None:
    packet = _runtime_activation_packet("economic_deviation")
    runtime_gate = _write_runtime_activation_gate(
        tmp_path,
        decision="runtime_activation_review_packets_ready_no_runtime",
        runtime_packets=[packet],
    )

    report = build_h3_goal_emission_runtime_activation_artifact_gate(
        runtime_activation_gate_path=runtime_gate,
        agent_root=tmp_path,
    )

    assert report["passed"] is True
    assert report["readiness"]["decision"] == "runtime_activation_artifacts_blocked_pending_required_artifacts"
    assert report["metrics"]["pending_runtime_activation_packet_count"] == 1
    assert report["metrics"]["reviewed_runtime_activation_packet_count"] == 0
    pending = report["runtime_activation_artifact_surface"]["pending_runtime_activation_packets"][0]
    assert pending["missing_or_rejected_runtime_activation_artifacts"] == [
        "runtime_safety_envelope",
        "rollout_window_approval",
        "live_monitoring_attestation",
        "rollback_drill_attestation",
        "operator_oncall_ack",
        "kill_switch_attestation",
        "post_activation_audit_plan",
    ]


def test_runtime_activation_artifact_gate_reviews_production_artifacts_without_runtime(tmp_path: Path) -> None:
    packet = _runtime_activation_packet("relation_repair_relapse")
    runtime_gate = _write_runtime_activation_gate(
        tmp_path,
        decision="runtime_activation_review_packets_ready_no_runtime",
        runtime_packets=[packet],
    )
    runtime_artifacts = _write_runtime_activation_artifacts(tmp_path, packet)

    report = build_h3_goal_emission_runtime_activation_artifact_gate(
        runtime_activation_gate_path=runtime_gate,
        agent_root=tmp_path,
        runtime_activation_artifacts_path=runtime_artifacts,
    )

    assert report["passed"] is True
    assert report["readiness"]["decision"] == "production_runtime_activation_artifacts_reviewed_no_runtime"
    assert report["readiness"]["production_runtime_activation_artifacts_complete"] is True
    assert report["readiness"]["runtime_activation_ready"] is False
    assert report["runtime_activation_artifact_boundary"]["production_runtime_activation_artifact_review_allowed"] is True
    assert report["runtime_activation_artifact_boundary"]["runtime_activation_allowed"] is False
    assert report["runtime_activation_artifact_boundary"]["runtime_execution_allowed"] is False
    assert report["metrics"]["reviewed_runtime_activation_packet_count"] == 1
    assert report["metrics"]["runtime_execution_ready_count"] == 0
    reviewed = report["runtime_activation_artifact_surface"]["reviewed_runtime_activation_packets"][0]
    assert reviewed["state"] == "runtime_activation_artifacts_reviewed_no_runtime"
    assert reviewed["gate_status"]["runtime_activation_ready"] is False
    assert reviewed["gate_status"]["runtime_execution_ready"] is False
    assert reviewed["execution_policy"]["runtime_execution_allowed"] is False
    assert set(reviewed["runtime_activation_artifact_refs"]) == {
        "runtime_safety_envelope",
        "rollout_window_approval",
        "live_monitoring_attestation",
        "rollback_drill_attestation",
        "operator_oncall_ack",
        "kill_switch_attestation",
        "post_activation_audit_plan",
    }


def test_runtime_activation_artifact_gate_rejects_missing_provenance(tmp_path: Path) -> None:
    packet = _runtime_activation_packet("post_delivery_dispute")
    runtime_gate = _write_runtime_activation_gate(
        tmp_path,
        decision="runtime_activation_review_packets_ready_no_runtime",
        runtime_packets=[packet],
    )
    runtime_artifacts = _write_runtime_activation_artifacts(tmp_path, packet, remove_field="attestation_ref")

    report = build_h3_goal_emission_runtime_activation_artifact_gate(
        runtime_activation_gate_path=runtime_gate,
        agent_root=tmp_path,
        runtime_activation_artifacts_path=runtime_artifacts,
    )

    assert report["passed"] is False
    assert report["checks"]["runtime_activation_artifact_common_provenance_present"] is False
    assert report["runtime_activation_artifact_boundary"]["runtime_activation_allowed"] is False
    assert report["metrics"]["reviewed_runtime_activation_packet_count"] == 0


def test_runtime_activation_artifact_gate_blocks_runtime_boundary_regression(tmp_path: Path) -> None:
    runtime_gate = _write_runtime_activation_gate(
        tmp_path,
        decision="runtime_activation_review_packets_ready_no_runtime",
        runtime_packets=[_runtime_activation_packet("post_delivery_failure")],
        boundary={"runtime_activation_allowed": True},
    )

    report = build_h3_goal_emission_runtime_activation_artifact_gate(
        runtime_activation_gate_path=runtime_gate,
        agent_root=tmp_path,
    )

    assert report["passed"] is False
    assert report["checks"]["runtime_activation_boundary_runtime_activation_allowed_false"] is False
    assert report["runtime_activation_artifact_boundary"]["runtime_activation_allowed"] is False
    assert report["metrics"]["runtime_execution_ready_count"] == 0


def _write_runtime_activation_gate(
    tmp_path: Path,
    *,
    decision: str,
    runtime_packets: list[dict] | None = None,
    blocked_candidates: list[dict] | None = None,
    boundary: dict | None = None,
) -> Path:
    runtime_packets = runtime_packets or []
    blocked_candidates = blocked_candidates or []
    default_boundary = {
        "artifact_only": True,
        "runtime_activation_review_packets_allowed": bool(runtime_packets),
        "runtime_activation_allowed": False,
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
    path = tmp_path / "h3_goal_emission_runtime_activation_gate.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": "h3-goal-emission-runtime-activation-gate:v1",
                "passed": True,
                "readiness": {
                    "runtime_activation_gate_evaluated": True,
                    "runtime_activation_review_packets_ready": bool(runtime_packets),
                    "runtime_activation_ready": False,
                    "activation_ready": False,
                    "emitted_goal_ready": False,
                    "executable_goal_ready": False,
                    "runtime_execution_ready": False,
                    "decision": decision,
                },
                "runtime_activation_boundary": default_boundary,
                "runtime_activation_surface": {
                    "mode": "runtime_activation_review_only_no_runtime",
                    "runtime_activation_review_packet_count": len(runtime_packets),
                    "runtime_activation_review_packets": runtime_packets,
                    "blocked_runtime_activation_candidate_count": len(blocked_candidates),
                    "blocked_runtime_activation_candidates": blocked_candidates,
                    "emitted_goals": [],
                    "runtime_executions": [],
                },
            }
        ),
        encoding="utf-8",
    )
    return path


def _write_runtime_activation_artifacts(
    tmp_path: Path,
    packet: dict,
    *,
    remove_field: str = "",
) -> Path:
    records = []
    for artifact_kind in (
        "runtime_safety_envelope",
        "rollout_window_approval",
        "live_monitoring_attestation",
        "rollback_drill_attestation",
        "operator_oncall_ack",
        "kill_switch_attestation",
        "post_activation_audit_plan",
    ):
        record = {
            "artifact_id": f"runtime-activation:{artifact_kind}:{packet['goal_id']}",
            "artifact_kind": artifact_kind,
            "runtime_activation_packet_id": packet["runtime_activation_packet_id"],
            "goal_id": packet["goal_id"],
            "reviewer": "did:civ:runtime-reviewer:alpha",
            "reviewer_role": artifact_kind,
            "source": "h3_runtime_activation_registry",
            "attestation_ref": f"runtime-attestation:{artifact_kind}:{packet['goal_id']}",
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
        if artifact_kind == "runtime_safety_envelope":
            record["status"] = "approved"
            record["runtime_safety_ref"] = f"runtime-safety:{packet['goal_id']}"
        elif artifact_kind == "rollout_window_approval":
            record["decision"] = "approved_for_runtime_activation"
            record["rollout_window_ref"] = f"rollout-window:{packet['goal_id']}"
        elif artifact_kind == "live_monitoring_attestation":
            record["status"] = "ready"
            record["live_monitoring_ref"] = f"live-monitoring:{packet['goal_id']}"
        elif artifact_kind == "rollback_drill_attestation":
            record["status"] = "passed"
            record["rollback_drill_ref"] = f"rollback-drill:{packet['goal_id']}"
        elif artifact_kind == "operator_oncall_ack":
            record["status"] = "acknowledged"
            record["operator_oncall_ref"] = f"operator-oncall:{packet['goal_id']}"
        elif artifact_kind == "kill_switch_attestation":
            record["status"] = "armed"
            record["kill_switch_ref"] = f"kill-switch:{packet['goal_id']}"
        elif artifact_kind == "post_activation_audit_plan":
            record["status"] = "ready"
            record["post_activation_audit_ref"] = f"post-activation-audit:{packet['goal_id']}"
        if remove_field:
            record.pop(remove_field, None)
        records.append(record)
    path = tmp_path / "h3_goal_emission_runtime_activation_artifacts.json"
    path.write_text(
        json.dumps({"schema_version": "h3-goal-emission-runtime-activation-artifacts:v1", "records": records}),
        encoding="utf-8",
    )
    return path


def _runtime_activation_packet(event_kind: str) -> dict:
    goal_id = f"h3-draft-goal:{event_kind}:alpha"
    return {
        "runtime_activation_packet_id": f"h3-runtime-activation-review:{goal_id}",
        "artifact_review_id": f"h3-activation-artifact-review:{goal_id}",
        "activation_packet_id": f"h3-goal-emission-activation:{goal_id}",
        "preflight_id": f"h3-goal-emission-preflight:{goal_id}",
        "approval_id": f"h3-approved-candidate:{goal_id}",
        "goal_id": goal_id,
        "state": "runtime_activation_review_required",
        "production_activation_artifacts_ready": True,
        "required_runtime_activation_artifacts": {
            "runtime_safety_envelope": "required_before_runtime_activation",
            "rollout_window_approval": "required_before_runtime_activation",
            "live_monitoring_attestation": "required_before_runtime_activation",
            "rollback_drill_attestation": "required_before_runtime_activation",
            "operator_oncall_ack": "required_before_runtime_activation",
            "kill_switch_attestation": "required_before_runtime_activation",
            "post_activation_audit_plan": "required_before_runtime_activation",
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
            "runtime_activation_review_ready": True,
            "runtime_activation_ready": False,
            "runtime_execution_ready": False,
        },
    }


def _blocked_runtime_candidate(event_kind: str) -> dict:
    goal_id = f"h3-draft-goal:{event_kind}:alpha"
    return {
        "goal_id": goal_id,
        "activation_packet_id": f"h3-goal-emission-activation:{goal_id}",
        "state": "runtime_activation_blocked",
        "blocked_reason": "synthetic activation artifacts cannot enter runtime activation",
        "synthetic_activation_fixture": True,
    }