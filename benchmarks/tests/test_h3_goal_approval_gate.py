from __future__ import annotations

import json
from pathlib import Path

from benchmarks.h3_goal_approval_gate import build_h3_goal_approval_gate


def test_h3_goal_approval_gate_blocks_without_review_artifacts(tmp_path: Path) -> None:
    lifecycle = _write_lifecycle_gate(tmp_path, [_packet("post_delivery_failure")])

    report = build_h3_goal_approval_gate(lifecycle_gate_path=lifecycle, agent_root=tmp_path)

    assert report["passed"] is True
    assert report["readiness"]["decision"] == "approval_blocked_pending_external_review_artifacts"
    assert report["readiness"]["approved_candidate_ready"] is False
    assert report["approval_boundary"]["candidate_approval_allowed"] is False
    assert report["approval_boundary"]["goal_emission_allowed"] is False
    assert report["metrics"]["approved_candidate_count"] == 0
    assert report["metrics"]["pending_review_packet_count"] == 1
    assert report["approval_surface"]["pending_review_packets"][0]["missing_or_rejected_external_artifacts"] == [
        "human_review_record",
        "governance_review_record",
        "challenge_window_result",
        "rollback_plan_record",
        "r2r_accountability_record",
    ]


def test_h3_goal_approval_gate_approves_candidate_with_complete_review_artifacts(tmp_path: Path) -> None:
    packet = _packet("economic_deviation")
    lifecycle = _write_lifecycle_gate(tmp_path, [packet])
    review_artifacts = _write_review_artifacts(tmp_path, packet)

    report = build_h3_goal_approval_gate(
        lifecycle_gate_path=lifecycle,
        agent_root=tmp_path,
        review_artifacts_path=review_artifacts,
    )

    assert report["passed"] is True
    assert report["readiness"]["decision"] == "approved_candidate_surface_ready"
    assert report["readiness"]["approved_candidate_ready"] is True
    assert report["readiness"]["production_approved_candidate_ready"] is True
    assert report["readiness"]["synthetic_approved_candidate_ready"] is False
    assert report["readiness"]["executable_goal_ready"] is False
    assert report["approval_boundary"]["candidate_approval_allowed"] is True
    assert report["approval_boundary"]["production_candidate_approval_allowed"] is True
    assert report["approval_boundary"]["synthetic_candidate_surface_allowed"] is False
    assert report["approval_boundary"]["goal_emission_allowed"] is False
    assert report["metrics"]["approved_candidate_count"] == 1
    approved = report["approval_surface"]["approved_candidates"][0]
    assert approved["state"] == "approved_candidate"
    assert approved["execution_policy"]["executable_plan_allowed"] is False
    assert approved["gate_status"]["runtime_execution_ready"] is False
    assert set(approved["external_artifact_refs"]) == {
        "human_review_record",
        "governance_review_record",
        "challenge_window_result",
        "rollback_plan_record",
        "r2r_accountability_record",
    }


def test_h3_goal_approval_gate_keeps_candidate_pending_for_partial_review(tmp_path: Path) -> None:
    packet = _packet("relation_repair_relapse")
    lifecycle = _write_lifecycle_gate(tmp_path, [packet])
    review_artifacts = _write_review_artifacts(tmp_path, packet, omit={"rollback_plan_record"})

    report = build_h3_goal_approval_gate(
        lifecycle_gate_path=lifecycle,
        agent_root=tmp_path,
        review_artifacts_path=review_artifacts,
    )

    assert report["passed"] is True
    assert report["readiness"]["decision"] == "approval_blocked_pending_external_review_artifacts"
    assert report["metrics"]["approved_candidate_count"] == 0
    pending = report["approval_surface"]["pending_review_packets"][0]
    assert pending["approval_ready"] is False
    assert pending["missing_or_rejected_external_artifacts"] == ["rollback_plan_record"]


def test_h3_goal_approval_gate_rejects_review_artifacts_without_provenance(tmp_path: Path) -> None:
    packet = _packet("post_delivery_dispute")
    lifecycle = _write_lifecycle_gate(tmp_path, [packet])
    review_artifacts = _write_review_artifacts(tmp_path, packet, remove_field="attestation_ref")

    report = build_h3_goal_approval_gate(
        lifecycle_gate_path=lifecycle,
        agent_root=tmp_path,
        review_artifacts_path=review_artifacts,
    )

    assert report["passed"] is False
    assert report["checks"]["review_artifact_common_provenance_present"] is False
    assert report["approval_boundary"]["candidate_approval_allowed"] is False
    assert report["metrics"]["approved_candidate_count"] == 0


def test_h3_goal_approval_gate_blocks_lifecycle_boundary_regression(tmp_path: Path) -> None:
    lifecycle = _write_lifecycle_gate(
        tmp_path,
        [_packet("post_delivery_dispute")],
        boundary={"goal_emission_allowed": True},
    )

    report = build_h3_goal_approval_gate(lifecycle_gate_path=lifecycle, agent_root=tmp_path)

    assert report["passed"] is False
    assert report["checks"]["lifecycle_boundary_goal_emission_allowed_false"] is False
    assert report["approval_boundary"]["candidate_approval_allowed"] is False
    assert report["approval_boundary"]["goal_emission_allowed"] is False


def test_h3_goal_approval_gate_rejects_invalid_review_artifact_schema(tmp_path: Path) -> None:
    packet = _packet("post_delivery_failure")
    lifecycle = _write_lifecycle_gate(tmp_path, [packet])
    bad_review_artifacts = tmp_path / "bad_review_artifacts.json"
    bad_review_artifacts.write_text(json.dumps({"schema_version": "wrong", "records": []}), encoding="utf-8")

    report = build_h3_goal_approval_gate(
        lifecycle_gate_path=lifecycle,
        agent_root=tmp_path,
        review_artifacts_path=bad_review_artifacts,
    )

    assert report["passed"] is False
    assert report["checks"]["review_artifacts_schema_version"] is False
    assert report["checks"]["review_artifacts_records_present"] is False


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


def _write_review_artifacts(
    tmp_path: Path,
    packet: dict,
    *,
    omit: set[str] | None = None,
    remove_field: str = "",
) -> Path:
    omit = omit or set()
    records = []
    for artifact_kind in (
        "human_review_record",
        "governance_review_record",
        "challenge_window_result",
        "rollback_plan_record",
        "r2r_accountability_record",
    ):
        if artifact_kind in omit:
            continue
        record = {
            "artifact_id": f"review:{artifact_kind}:{packet['goal_id']}",
            "artifact_kind": artifact_kind,
            "packet_id": packet["packet_id"],
            "goal_id": packet["goal_id"],
            "reviewer": "did:civ:reviewer:alpha",
            "reviewer_role": artifact_kind,
            "source": "h3_external_review_registry",
            "attestation_ref": f"attestation:{artifact_kind}:{packet['goal_id']}",
            "goal_emission_allowed": False,
            "executable_plan_allowed": False,
            "runtime_execution_allowed": False,
            "llm_planning_allowed": False,
            "iem_value_mutation_allowed": False,
            "normative_local_mutation_allowed": False,
        }
        if artifact_kind in {"human_review_record", "governance_review_record"}:
            record["decision"] = "approved_for_candidate"
        elif artifact_kind == "challenge_window_result":
            record["status"] = "closed_no_blocking_challenge"
        else:
            record["status"] = "ready"
        if artifact_kind == "human_review_record":
            record["human_review_ref"] = f"human-review:{packet['goal_id']}"
        elif artifact_kind == "governance_review_record":
            record["governance_ref"] = f"governance-review:{packet['goal_id']}"
        elif artifact_kind == "challenge_window_result":
            record["challenge_window_ref"] = f"challenge-window:{packet['goal_id']}"
        elif artifact_kind == "rollback_plan_record":
            record["rollback_plan_ref"] = f"rollback-plan:{packet['goal_id']}"
        elif artifact_kind == "r2r_accountability_record":
            record["r2r_accountability_ref"] = f"r2r-accountability:{packet['goal_id']}"
        if remove_field:
            record.pop(remove_field, None)
        records.append(record)
    path = tmp_path / "h3_external_review_artifacts.json"
    path.write_text(
        json.dumps({"schema_version": "h3-external-review-artifacts:v1", "records": records}),
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