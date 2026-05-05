from __future__ import annotations

import json
from pathlib import Path

from benchmarks.h3_goal_emission_activation_artifact_gate import build_h3_goal_emission_activation_artifact_gate


def test_activation_artifact_gate_blocks_without_activation_packets(tmp_path: Path) -> None:
    activation_gate = _write_activation_gate(
        tmp_path,
        decision="goal_emission_activation_blocked_no_preflight",
    )

    report = build_h3_goal_emission_activation_artifact_gate(
        activation_gate_path=activation_gate,
        agent_root=tmp_path,
    )

    assert report["passed"] is True
    assert report["readiness"]["decision"] == "activation_artifacts_blocked_no_activation_packets"
    assert report["readiness"]["activation_ready"] is False
    assert report["activation_artifact_boundary"]["activation_allowed"] is False
    assert report["metrics"]["reviewed_activation_packet_count"] == 0
    assert report["metrics"]["emitted_goal_count"] == 0


def test_activation_artifact_gate_blocks_synthetic_activation_candidates(tmp_path: Path) -> None:
    activation_gate = _write_activation_gate(
        tmp_path,
        decision="goal_emission_activation_blocked_synthetic_or_blocked_emission",
        blocked_candidates=[_blocked_activation_candidate("post_delivery_dispute")],
    )

    report = build_h3_goal_emission_activation_artifact_gate(
        activation_gate_path=activation_gate,
        agent_root=tmp_path,
    )

    assert report["passed"] is True
    assert report["readiness"]["decision"] == "activation_artifacts_blocked_synthetic_or_blocked_emission"
    assert report["metrics"]["blocked_activation_candidate_count"] == 1
    assert report["metrics"]["reviewed_activation_packet_count"] == 0
    assert report["activation_artifact_surface"]["blocked_activation_candidates"][0]["synthetic_review_fixture"] is True


def test_activation_artifact_gate_keeps_packets_pending_without_artifacts(tmp_path: Path) -> None:
    packet = _activation_packet("economic_deviation")
    activation_gate = _write_activation_gate(
        tmp_path,
        decision="goal_emission_activation_review_packets_ready_no_activation",
        activation_packets=[packet],
    )

    report = build_h3_goal_emission_activation_artifact_gate(
        activation_gate_path=activation_gate,
        agent_root=tmp_path,
    )

    assert report["passed"] is True
    assert report["readiness"]["decision"] == "activation_artifacts_blocked_pending_required_artifacts"
    assert report["metrics"]["pending_activation_packet_count"] == 1
    assert report["metrics"]["reviewed_activation_packet_count"] == 0
    assert report["activation_artifact_boundary"]["activation_allowed"] is False
    pending = report["activation_artifact_surface"]["pending_activation_packets"][0]
    assert pending["missing_or_rejected_activation_artifacts"] == [
        "human_activation_record",
        "governance_activation_record",
        "h1_h2_replay_attestation",
        "rollback_activation_ack",
        "runtime_non_execution_ack",
    ]


def test_activation_artifact_gate_reviews_complete_production_artifacts_without_activation(tmp_path: Path) -> None:
    packet = _activation_packet("economic_deviation")
    activation_gate = _write_activation_gate(
        tmp_path,
        decision="goal_emission_activation_review_packets_ready_no_activation",
        activation_packets=[packet],
    )
    activation_artifacts = _write_activation_artifacts(tmp_path, packet)

    report = build_h3_goal_emission_activation_artifact_gate(
        activation_gate_path=activation_gate,
        agent_root=tmp_path,
        activation_artifacts_path=activation_artifacts,
    )

    assert report["passed"] is True
    assert report["readiness"]["decision"] == "production_activation_artifacts_reviewed_no_activation"
    assert report["readiness"]["production_activation_artifacts_complete"] is True
    assert report["readiness"]["activation_ready"] is False
    assert report["activation_artifact_boundary"]["production_activation_artifact_review_allowed"] is True
    assert report["activation_artifact_boundary"]["activation_allowed"] is False
    assert report["activation_artifact_boundary"]["emitted_goal_allowed"] is False
    assert report["metrics"]["reviewed_activation_packet_count"] == 1
    assert report["metrics"]["emitted_goal_count"] == 0
    reviewed = report["activation_artifact_surface"]["reviewed_activation_packets"][0]
    assert reviewed["state"] == "activation_artifacts_reviewed_no_activation"
    assert reviewed["gate_status"]["activation_ready"] is False
    assert reviewed["execution_policy"]["runtime_execution_allowed"] is False
    assert set(reviewed["activation_artifact_refs"]) == {
        "human_activation_record",
        "governance_activation_record",
        "h1_h2_replay_attestation",
        "rollback_activation_ack",
        "runtime_non_execution_ack",
    }


def test_activation_artifact_gate_rejects_missing_provenance(tmp_path: Path) -> None:
    packet = _activation_packet("post_delivery_failure")
    activation_gate = _write_activation_gate(
        tmp_path,
        decision="goal_emission_activation_review_packets_ready_no_activation",
        activation_packets=[packet],
    )
    activation_artifacts = _write_activation_artifacts(tmp_path, packet, remove_field="attestation_ref")

    report = build_h3_goal_emission_activation_artifact_gate(
        activation_gate_path=activation_gate,
        agent_root=tmp_path,
        activation_artifacts_path=activation_artifacts,
    )

    assert report["passed"] is False
    assert report["checks"]["activation_artifact_common_provenance_present"] is False
    assert report["activation_artifact_boundary"]["activation_allowed"] is False
    assert report["metrics"]["reviewed_activation_packet_count"] == 0


def test_activation_artifact_gate_blocks_activation_boundary_regression(tmp_path: Path) -> None:
    activation_gate = _write_activation_gate(
        tmp_path,
        decision="goal_emission_activation_review_packets_ready_no_activation",
        activation_packets=[_activation_packet("relation_repair_relapse")],
        boundary={"activation_allowed": True},
    )

    report = build_h3_goal_emission_activation_artifact_gate(
        activation_gate_path=activation_gate,
        agent_root=tmp_path,
    )

    assert report["passed"] is False
    assert report["checks"]["activation_boundary_activation_allowed_false"] is False
    assert report["activation_artifact_boundary"]["activation_allowed"] is False
    assert report["metrics"]["emitted_goal_count"] == 0


def _write_activation_gate(
    tmp_path: Path,
    *,
    decision: str,
    activation_packets: list[dict] | None = None,
    blocked_candidates: list[dict] | None = None,
    boundary: dict | None = None,
) -> Path:
    activation_packets = activation_packets or []
    blocked_candidates = blocked_candidates or []
    default_boundary = {
        "artifact_only": True,
        "activation_review_packets_allowed": bool(activation_packets),
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
    path = tmp_path / "h3_goal_emission_activation_gate.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": "h3-goal-emission-activation-gate:v1",
                "passed": True,
                "readiness": {
                    "activation_gate_evaluated": True,
                    "activation_review_packets_ready": bool(activation_packets),
                    "activation_ready": False,
                    "emitted_goal_ready": False,
                    "executable_goal_ready": False,
                    "runtime_execution_ready": False,
                    "decision": decision,
                },
                "activation_boundary": default_boundary,
                "activation_surface": {
                    "mode": "activation_review_only_no_emission",
                    "activation_packet_count": len(activation_packets),
                    "activation_packets": activation_packets,
                    "blocked_activation_candidate_count": len(blocked_candidates),
                    "blocked_activation_candidates": blocked_candidates,
                    "emitted_goals": [],
                },
            }
        ),
        encoding="utf-8",
    )
    return path


def _write_activation_artifacts(
    tmp_path: Path,
    packet: dict,
    *,
    remove_field: str = "",
) -> Path:
    records = []
    for artifact_kind in (
        "human_activation_record",
        "governance_activation_record",
        "h1_h2_replay_attestation",
        "rollback_activation_ack",
        "runtime_non_execution_ack",
    ):
        record = {
            "artifact_id": f"activation:{artifact_kind}:{packet['goal_id']}",
            "artifact_kind": artifact_kind,
            "activation_packet_id": packet["activation_packet_id"],
            "goal_id": packet["goal_id"],
            "reviewer": "did:civ:activation-reviewer:alpha",
            "reviewer_role": artifact_kind,
            "source": "h3_activation_artifact_registry",
            "attestation_ref": f"activation-attestation:{artifact_kind}:{packet['goal_id']}",
            "activation_allowed": False,
            "goal_emission_allowed": False,
            "emitted_goal_allowed": False,
            "executable_plan_allowed": False,
            "runtime_execution_allowed": False,
            "llm_planning_allowed": False,
            "iem_value_mutation_allowed": False,
            "normative_local_mutation_allowed": False,
        }
        if artifact_kind in {"human_activation_record", "governance_activation_record"}:
            record["decision"] = "approved_for_emission_activation"
        elif artifact_kind == "h1_h2_replay_attestation":
            record["status"] = "valid"
        elif artifact_kind == "rollback_activation_ack":
            record["status"] = "ready"
        elif artifact_kind == "runtime_non_execution_ack":
            record["status"] = "acknowledged"
        if artifact_kind == "human_activation_record":
            record["human_activation_ref"] = f"human-activation:{packet['goal_id']}"
        elif artifact_kind == "governance_activation_record":
            record["governance_activation_ref"] = f"governance-activation:{packet['goal_id']}"
        elif artifact_kind == "h1_h2_replay_attestation":
            record["h1_h2_replay_ref"] = f"h1-h2-replay:{packet['goal_id']}"
        elif artifact_kind == "rollback_activation_ack":
            record["rollback_activation_ref"] = f"rollback-activation:{packet['goal_id']}"
        elif artifact_kind == "runtime_non_execution_ack":
            record["runtime_non_execution_ref"] = f"runtime-non-execution:{packet['goal_id']}"
        if remove_field:
            record.pop(remove_field, None)
        records.append(record)
    path = tmp_path / "h3_goal_emission_activation_artifacts.json"
    path.write_text(
        json.dumps({"schema_version": "h3-goal-emission-activation-artifacts:v1", "records": records}),
        encoding="utf-8",
    )
    return path


def _activation_packet(event_kind: str) -> dict:
    goal_id = f"h3-draft-goal:{event_kind}:alpha"
    return {
        "activation_packet_id": f"h3-goal-emission-activation:{goal_id}",
        "preflight_id": f"h3-goal-emission-preflight:{goal_id}",
        "goal_id": goal_id,
        "approval_id": f"h3-approved-candidate:{goal_id}",
        "state": "goal_emission_activation_review_required",
        "identity": "alpha",
        "trigger_event_kind": event_kind,
        "risk_class": "critical" if event_kind == "economic_deviation" else "high",
        "required_activation_artifacts": {
            "human_activation_record": "required_before_emission_activation",
            "governance_activation_record": "required_before_emission_activation",
            "h1_h2_replay_attestation": "required_before_emission_activation",
            "rollback_activation_ack": "required_before_emission_activation",
            "runtime_non_execution_ack": "required_before_emission_activation",
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


def _blocked_activation_candidate(event_kind: str) -> dict:
    goal_id = f"h3-draft-goal:{event_kind}:alpha"
    return {
        "goal_id": goal_id,
        "approval_id": f"h3-approved-candidate:{goal_id}",
        "state": "goal_emission_activation_blocked",
        "blocked_reason": "synthetic approval cannot enter goal emission",
        "synthetic_review_fixture": True,
    }