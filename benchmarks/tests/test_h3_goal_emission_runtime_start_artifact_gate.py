from __future__ import annotations

import json
from pathlib import Path

from benchmarks.h3_goal_emission_runtime_start_artifact_gate import (
    build_h3_goal_emission_runtime_start_artifact_gate,
)


def test_runtime_start_artifact_gate_blocks_without_start_packets(tmp_path: Path) -> None:
    start_gate = _write_runtime_start_gate(
        tmp_path,
        decision="runtime_start_blocked_no_reviewed_runtime_activation_artifacts",
    )

    report = build_h3_goal_emission_runtime_start_artifact_gate(
        runtime_start_gate_path=start_gate,
        agent_root=tmp_path,
    )

    assert report["passed"] is True
    assert report["readiness"]["decision"] == "runtime_start_artifacts_blocked_no_runtime_start_packets"
    assert report["readiness"]["runtime_start_ready"] is False
    assert report["runtime_start_artifact_boundary"]["runtime_start_allowed"] is False
    assert report["runtime_start_artifact_boundary"]["runtime_execution_allowed"] is False
    assert report["metrics"]["reviewed_runtime_start_packet_count"] == 0
    assert report["metrics"]["runtime_execution_ready_count"] == 0


def test_runtime_start_artifact_gate_blocks_synthetic_or_blocked_start(tmp_path: Path) -> None:
    start_gate = _write_runtime_start_gate(
        tmp_path,
        decision="runtime_start_blocked_synthetic_or_blocked_runtime_activation",
        blocked_candidates=[_blocked_runtime_start_candidate("post_delivery_failure")],
    )

    report = build_h3_goal_emission_runtime_start_artifact_gate(
        runtime_start_gate_path=start_gate,
        agent_root=tmp_path,
    )

    assert report["passed"] is True
    assert report["readiness"]["decision"] == "runtime_start_artifacts_blocked_synthetic_or_blocked_start"
    assert report["metrics"]["blocked_runtime_start_candidate_count"] == 1
    assert report["metrics"]["reviewed_runtime_start_packet_count"] == 0
    assert report["runtime_start_artifact_surface"]["blocked_runtime_start_candidates"][0]["state"] == "runtime_start_blocked"


def test_runtime_start_artifact_gate_keeps_packets_pending_without_artifacts(tmp_path: Path) -> None:
    packet = _runtime_start_packet("economic_deviation")
    start_gate = _write_runtime_start_gate(
        tmp_path,
        decision="runtime_start_review_packets_ready_no_runtime",
        start_packets=[packet],
    )

    report = build_h3_goal_emission_runtime_start_artifact_gate(
        runtime_start_gate_path=start_gate,
        agent_root=tmp_path,
    )

    assert report["passed"] is True
    assert report["readiness"]["decision"] == "runtime_start_artifacts_blocked_pending_required_artifacts"
    assert report["metrics"]["pending_runtime_start_packet_count"] == 1
    pending = report["runtime_start_artifact_surface"]["pending_runtime_start_packets"][0]
    assert pending["missing_or_rejected_runtime_start_artifacts"] == [
        "runtime_start_change_ticket",
        "runtime_start_dual_operator_ack",
        "runtime_start_final_monitoring_green",
        "runtime_start_final_kill_switch_check",
        "runtime_start_rollback_checkpoint",
        "runtime_start_audit_sink_ready",
    ]


def test_runtime_start_artifact_gate_reviews_production_artifacts_without_runtime(tmp_path: Path) -> None:
    packet = _runtime_start_packet("relation_repair_relapse")
    start_gate = _write_runtime_start_gate(
        tmp_path,
        decision="runtime_start_review_packets_ready_no_runtime",
        start_packets=[packet],
    )
    start_artifacts = _write_runtime_start_artifacts(tmp_path, packet)

    report = build_h3_goal_emission_runtime_start_artifact_gate(
        runtime_start_gate_path=start_gate,
        agent_root=tmp_path,
        runtime_start_artifacts_path=start_artifacts,
    )

    assert report["passed"] is True
    assert report["readiness"]["decision"] == "production_runtime_start_artifacts_reviewed_no_runtime"
    assert report["readiness"]["production_runtime_start_artifacts_complete"] is True
    assert report["readiness"]["runtime_start_ready"] is False
    assert report["runtime_start_artifact_boundary"]["production_runtime_start_artifact_review_allowed"] is True
    assert report["runtime_start_artifact_boundary"]["runtime_start_allowed"] is False
    assert report["runtime_start_artifact_boundary"]["runtime_execution_allowed"] is False
    assert report["metrics"]["reviewed_runtime_start_packet_count"] == 1
    assert report["metrics"]["runtime_start_ready_count"] == 0
    assert report["metrics"]["runtime_execution_ready_count"] == 0
    reviewed = report["runtime_start_artifact_surface"]["reviewed_runtime_start_packets"][0]
    assert reviewed["state"] == "runtime_start_artifacts_reviewed_no_runtime"
    assert reviewed["gate_status"]["runtime_start_ready"] is False
    assert reviewed["gate_status"]["runtime_execution_ready"] is False
    assert reviewed["execution_policy"]["runtime_execution_allowed"] is False
    assert set(reviewed["runtime_start_artifact_refs"]) == {
        "runtime_start_change_ticket",
        "runtime_start_dual_operator_ack",
        "runtime_start_final_monitoring_green",
        "runtime_start_final_kill_switch_check",
        "runtime_start_rollback_checkpoint",
        "runtime_start_audit_sink_ready",
    }


def test_runtime_start_artifact_gate_reviews_synthetic_artifacts_without_runtime(tmp_path: Path) -> None:
    packet = _runtime_start_packet("post_delivery_dispute")
    start_gate = _write_runtime_start_gate(
        tmp_path,
        decision="runtime_start_review_packets_ready_no_runtime",
        start_packets=[packet],
    )
    start_artifacts = _write_runtime_start_artifacts(tmp_path, packet, synthetic=True)

    report = build_h3_goal_emission_runtime_start_artifact_gate(
        runtime_start_gate_path=start_gate,
        agent_root=tmp_path,
        runtime_start_artifacts_path=start_artifacts,
    )

    assert report["passed"] is True
    assert report["readiness"]["decision"] == "synthetic_runtime_start_artifacts_reviewed_no_runtime"
    assert report["readiness"]["production_runtime_start_artifacts_complete"] is False
    assert report["runtime_start_artifact_boundary"]["synthetic_runtime_start_artifact_surface_allowed"] is True
    assert report["runtime_start_artifact_boundary"]["runtime_start_allowed"] is False


def test_runtime_start_artifact_gate_reviews_local_controlled_artifacts_without_production(tmp_path: Path) -> None:
    packet = _runtime_start_packet("post_delivery_failure")
    start_gate = _write_runtime_start_gate(
        tmp_path,
        decision="runtime_start_review_packets_ready_no_runtime",
        start_packets=[packet],
    )
    start_artifacts = _write_runtime_start_artifacts(tmp_path, packet, local_controlled=True)

    report = build_h3_goal_emission_runtime_start_artifact_gate(
        runtime_start_gate_path=start_gate,
        agent_root=tmp_path,
        runtime_start_artifacts_path=start_artifacts,
    )

    assert report["passed"] is True
    assert report["readiness"]["decision"] == "local_controlled_runtime_start_artifacts_reviewed_no_runtime"
    assert report["readiness"]["production_runtime_start_artifacts_complete"] is False
    assert report["readiness"]["local_controlled_runtime_start_artifacts_complete"] is True
    assert report["runtime_start_artifact_boundary"]["production_runtime_start_artifact_review_allowed"] is False
    assert report["runtime_start_artifact_boundary"]["local_controlled_runtime_start_artifact_surface_allowed"] is True
    reviewed = report["runtime_start_artifact_surface"]["reviewed_runtime_start_packets"][0]
    assert reviewed["production_runtime_start_artifacts_ready"] is False
    assert reviewed["local_controlled_runtime_start_artifacts_ready"] is True


def test_runtime_start_artifact_gate_rejects_missing_provenance(tmp_path: Path) -> None:
    packet = _runtime_start_packet("governance_rollback")
    start_gate = _write_runtime_start_gate(
        tmp_path,
        decision="runtime_start_review_packets_ready_no_runtime",
        start_packets=[packet],
    )
    start_artifacts = _write_runtime_start_artifacts(tmp_path, packet, remove_field="attestation_ref")

    report = build_h3_goal_emission_runtime_start_artifact_gate(
        runtime_start_gate_path=start_gate,
        agent_root=tmp_path,
        runtime_start_artifacts_path=start_artifacts,
    )

    assert report["passed"] is False
    assert report["checks"]["runtime_start_artifact_common_provenance_present"] is False
    assert report["runtime_start_artifact_boundary"]["runtime_start_allowed"] is False
    assert report["metrics"]["reviewed_runtime_start_packet_count"] == 0


def test_runtime_start_artifact_gate_blocks_start_boundary_regression(tmp_path: Path) -> None:
    start_gate = _write_runtime_start_gate(
        tmp_path,
        decision="runtime_start_review_packets_ready_no_runtime",
        start_packets=[_runtime_start_packet("post_delivery_failure")],
        boundary={"runtime_start_allowed": True},
    )

    report = build_h3_goal_emission_runtime_start_artifact_gate(
        runtime_start_gate_path=start_gate,
        agent_root=tmp_path,
    )

    assert report["passed"] is False
    assert report["checks"]["runtime_start_boundary_runtime_start_allowed_false"] is False
    assert report["runtime_start_artifact_boundary"]["runtime_start_allowed"] is False
    assert report["metrics"]["runtime_execution_ready_count"] == 0


def _write_runtime_start_gate(
    tmp_path: Path,
    *,
    decision: str,
    start_packets: list[dict] | None = None,
    blocked_candidates: list[dict] | None = None,
    boundary: dict | None = None,
) -> Path:
    start_packets = start_packets or []
    blocked_candidates = blocked_candidates or []
    default_boundary = {
        "artifact_only": True,
        "runtime_start_review_packets_allowed": bool(start_packets),
        "runtime_start_allowed": False,
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
    path = tmp_path / "h3_goal_emission_runtime_start_gate.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": "h3-goal-emission-runtime-start-gate:v1",
                "passed": True,
                "readiness": {
                    "runtime_start_gate_evaluated": True,
                    "runtime_start_review_packets_ready": bool(start_packets),
                    "runtime_start_ready": False,
                    "runtime_activation_ready": False,
                    "runtime_execution_ready": False,
                    "activation_ready": False,
                    "emitted_goal_ready": False,
                    "executable_goal_ready": False,
                    "decision": decision,
                },
                "runtime_start_boundary": default_boundary,
                "runtime_start_surface": {
                    "mode": "runtime_start_review_only_no_runtime",
                    "runtime_start_review_packet_count": len(start_packets),
                    "runtime_start_review_packets": start_packets,
                    "blocked_runtime_start_candidate_count": len(blocked_candidates),
                    "blocked_runtime_start_candidates": blocked_candidates,
                    "runtime_executions": [],
                    "emitted_goals": [],
                },
            }
        ),
        encoding="utf-8",
    )
    return path


def _write_runtime_start_artifacts(
    tmp_path: Path,
    packet: dict,
    *,
    synthetic: bool = False,
    local_controlled: bool = False,
    remove_field: str = "",
) -> Path:
    records = []
    for artifact_kind in (
        "runtime_start_change_ticket",
        "runtime_start_dual_operator_ack",
        "runtime_start_final_monitoring_green",
        "runtime_start_final_kill_switch_check",
        "runtime_start_rollback_checkpoint",
        "runtime_start_audit_sink_ready",
    ):
        record = {
            "artifact_id": f"runtime-start:{artifact_kind}:{packet['goal_id']}",
            "artifact_kind": artifact_kind,
            "runtime_start_packet_id": packet["runtime_start_packet_id"],
            "goal_id": packet["goal_id"],
            "runtime_start_allowed": False,
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
        if synthetic:
            record["synthetic_fixture"] = True
        else:
            record.update(
                {
                    "reviewer": "did:civ:runtime-start-reviewer:alpha",
                    "reviewer_role": artifact_kind,
                    "source": "h3_local_operator_start_registry" if local_controlled else "h3_runtime_start_registry",
                    "attestation_ref": f"runtime-start-attestation:{artifact_kind}:{packet['goal_id']}",
                }
            )
        if artifact_kind == "runtime_start_change_ticket":
            record["decision"] = "approved_for_runtime_start"
            record["change_ticket_ref"] = f"change-ticket:{packet['goal_id']}"
        elif artifact_kind == "runtime_start_dual_operator_ack":
            record["status"] = "acknowledged"
            record["dual_operator_ack_ref"] = f"dual-operator-ack:{packet['goal_id']}"
        elif artifact_kind == "runtime_start_final_monitoring_green":
            record["status"] = "green"
            record["final_monitoring_ref"] = f"final-monitoring:{packet['goal_id']}"
        elif artifact_kind == "runtime_start_final_kill_switch_check":
            record["status"] = "armed"
            record["final_kill_switch_ref"] = f"final-kill-switch:{packet['goal_id']}"
        elif artifact_kind == "runtime_start_rollback_checkpoint":
            record["status"] = "ready"
            record["rollback_checkpoint_ref"] = f"rollback-checkpoint:{packet['goal_id']}"
        elif artifact_kind == "runtime_start_audit_sink_ready":
            record["status"] = "ready"
            record["audit_sink_ref"] = f"audit-sink:{packet['goal_id']}"
        if remove_field:
            record.pop(remove_field, None)
        records.append(record)
    payload = {"schema_version": "h3-goal-emission-runtime-start-artifacts:v1", "records": records}
    if synthetic:
        payload["fixture_policy"] = {
            "synthetic_runtime_start_fixture": True,
            "not_valid_for_production_runtime_start": True,
        }
    if local_controlled:
        payload["local_fixture_policy"] = {
            "local_controlled_execution_fixture": True,
            "not_external_production_deployment": True,
        }
    path = tmp_path / "h3_goal_emission_runtime_start_artifacts.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _runtime_start_packet(event_kind: str) -> dict:
    goal_id = f"h3-draft-goal:{event_kind}:alpha"
    return {
        "runtime_start_packet_id": f"h3-runtime-start-review:{goal_id}",
        "runtime_activation_artifact_review_id": f"h3-runtime-activation-artifact-review:{goal_id}",
        "runtime_activation_packet_id": f"h3-runtime-activation-review:{goal_id}",
        "activation_packet_id": f"h3-goal-emission-activation:{goal_id}",
        "preflight_id": f"h3-goal-emission-preflight:{goal_id}",
        "approval_id": f"h3-approved-candidate:{goal_id}",
        "goal_id": goal_id,
        "state": "runtime_start_review_required",
        "production_runtime_activation_artifacts_ready": True,
        "required_runtime_start_controls": {
            "runtime_start_change_ticket": "required_before_runtime_start",
            "runtime_start_dual_operator_ack": "required_before_runtime_start",
            "runtime_start_final_monitoring_green": "required_before_runtime_start",
            "runtime_start_final_kill_switch_check": "required_before_runtime_start",
            "runtime_start_rollback_checkpoint": "required_before_runtime_start",
            "runtime_start_audit_sink_ready": "required_before_runtime_start",
        },
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
            "runtime_start_review_ready": True,
            "runtime_start_ready": False,
            "runtime_activation_ready": False,
            "runtime_execution_ready": False,
        },
    }


def _blocked_runtime_start_candidate(event_kind: str) -> dict:
    goal_id = f"h3-draft-goal:{event_kind}:alpha"
    return {
        "goal_id": goal_id,
        "runtime_activation_artifact_review_id": f"h3-runtime-activation-artifact-review:{goal_id}",
        "state": "runtime_start_blocked",
        "blocked_reason": "synthetic runtime activation fixture cannot enter runtime start",
        "runtime_start_allowed": False,
        "runtime_execution_allowed": False,
    }