from __future__ import annotations

import json
from pathlib import Path

from benchmarks.h3_goal_emission_runtime_execution_gate import (
    build_h3_goal_emission_runtime_execution_gate,
)
from benchmarks.h3_goal_emission_runtime_execution_local_fixture import (
    build_h3_goal_emission_runtime_execution_local_fixture,
)
from benchmarks.h3_goal_emission_runtime_executor import (
    build_h3_goal_emission_runtime_executor_report,
)


def test_runtime_execution_gate_blocks_without_reviewed_start_artifacts(tmp_path: Path) -> None:
    start_artifact_gate = _write_runtime_start_artifact_gate(
        tmp_path,
        decision="runtime_start_artifacts_blocked_no_runtime_start_packets",
    )

    report = build_h3_goal_emission_runtime_execution_gate(
        runtime_start_artifact_gate_path=start_artifact_gate,
        agent_root=tmp_path,
    )

    assert report["passed"] is True
    assert report["readiness"]["decision"] == "runtime_execution_blocked_no_reviewed_start_artifacts"
    assert report["runtime_execution_boundary"]["runtime_execution_allowed"] is False
    assert report["metrics"]["runtime_execution_packet_count"] == 0


def test_runtime_execution_gate_requires_operator_ack(tmp_path: Path) -> None:
    packet = _reviewed_runtime_start_packet("economic_deviation")
    start_artifact_gate = _write_runtime_start_artifact_gate(
        tmp_path,
        decision="production_runtime_start_artifacts_reviewed_no_runtime",
        reviewed_packets=[packet],
    )

    report = build_h3_goal_emission_runtime_execution_gate(
        runtime_start_artifact_gate_path=start_artifact_gate,
        agent_root=tmp_path,
    )

    assert report["passed"] is True
    assert report["readiness"]["decision"] == "runtime_execution_blocked_pending_operator_ack"
    assert report["runtime_execution_boundary"]["runtime_execution_allowed"] is False
    assert report["metrics"]["pending_runtime_execution_ack_count"] == 1
    pending = report["runtime_execution_surface"]["pending_runtime_execution_ack_packets"][0]
    assert pending["missing_ack"] == "ack-runtime-execution"


def test_runtime_execution_gate_creates_execution_packet_with_ack(tmp_path: Path) -> None:
    packet = _reviewed_runtime_start_packet("relation_repair_relapse")
    start_artifact_gate = _write_runtime_start_artifact_gate(
        tmp_path,
        decision="production_runtime_start_artifacts_reviewed_no_runtime",
        reviewed_packets=[packet],
    )

    report = build_h3_goal_emission_runtime_execution_gate(
        runtime_start_artifact_gate_path=start_artifact_gate,
        agent_root=tmp_path,
        ack_runtime_execution=True,
    )

    assert report["passed"] is True
    assert report["readiness"]["decision"] == "runtime_execution_packets_ready"
    assert report["readiness"]["runtime_execution_ready"] is True
    assert report["runtime_execution_boundary"]["runtime_execution_allowed"] is True
    assert report["runtime_execution_boundary"]["executable_plan_allowed"] is False
    assert report["metrics"]["runtime_execution_packet_count"] == 1
    execution_packet = report["runtime_execution_surface"]["runtime_execution_packets"][0]
    assert execution_packet["state"] == "runtime_execution_packet_ready"
    assert execution_packet["action"] == "record_h3_controlled_runtime_execution_receipt"
    assert execution_packet["execution_policy"]["runtime_execution_allowed"] is True
    assert execution_packet["execution_policy"]["llm_planning_allowed"] is False


def test_runtime_execution_gate_rejects_synthetic_reviewed_start_packet(tmp_path: Path) -> None:
    packet = _reviewed_runtime_start_packet(
        "post_delivery_dispute",
        synthetic=True,
    )
    start_artifact_gate = _write_runtime_start_artifact_gate(
        tmp_path,
        decision="synthetic_runtime_start_artifacts_reviewed_no_runtime",
        reviewed_packets=[packet],
    )

    report = build_h3_goal_emission_runtime_execution_gate(
        runtime_start_artifact_gate_path=start_artifact_gate,
        agent_root=tmp_path,
        ack_runtime_execution=True,
    )

    assert report["passed"] is False
    assert report["checks"]["reviewed_runtime_start_packet_origin_known"] is False
    assert report["runtime_execution_boundary"]["runtime_execution_allowed"] is False


def test_runtime_execution_gate_blocks_local_controlled_start_without_allow_flag(tmp_path: Path) -> None:
    packet = _reviewed_runtime_start_packet(
        "post_delivery_failure",
        local_controlled=True,
    )
    start_artifact_gate = _write_runtime_start_artifact_gate(
        tmp_path,
        decision="local_controlled_runtime_start_artifacts_reviewed_no_runtime",
        reviewed_packets=[packet],
    )

    report = build_h3_goal_emission_runtime_execution_gate(
        runtime_start_artifact_gate_path=start_artifact_gate,
        agent_root=tmp_path,
        ack_runtime_execution=True,
    )

    assert report["passed"] is True
    assert report["readiness"]["decision"] == "runtime_execution_blocked_synthetic_or_blocked_start"
    assert report["readiness"]["production_runtime_start_artifacts_complete"] is False
    assert report["readiness"]["local_controlled_runtime_start_artifacts_complete"] is True
    assert report["runtime_execution_boundary"]["runtime_execution_allowed"] is False
    blocked = report["runtime_execution_surface"]["blocked_runtime_execution_candidates"][0]
    assert "--allow-local-controlled-execution" in blocked["blocked_reason"]


def test_runtime_execution_gate_creates_local_controlled_packet_with_allow_flag(tmp_path: Path) -> None:
    packet = _reviewed_runtime_start_packet(
        "post_delivery_failure",
        local_controlled=True,
    )
    start_artifact_gate = _write_runtime_start_artifact_gate(
        tmp_path,
        decision="local_controlled_runtime_start_artifacts_reviewed_no_runtime",
        reviewed_packets=[packet],
    )

    report = build_h3_goal_emission_runtime_execution_gate(
        runtime_start_artifact_gate_path=start_artifact_gate,
        agent_root=tmp_path,
        ack_runtime_execution=True,
        allow_local_controlled_execution=True,
    )

    assert report["passed"] is True
    assert report["readiness"]["decision"] == "local_controlled_runtime_execution_packets_ready"
    assert report["runtime_execution_boundary"]["production_runtime_execution_packet_allowed"] is False
    assert report["runtime_execution_boundary"]["local_controlled_runtime_execution_packet_allowed"] is True
    execution_packet = report["runtime_execution_surface"]["runtime_execution_packets"][0]
    assert execution_packet["execution_origin"] == "local_controlled"
    assert execution_packet["production_runtime_execution"] is False
    assert execution_packet["local_controlled_runtime_execution"] is True


def test_runtime_execution_gate_blocks_boundary_regression(tmp_path: Path) -> None:
    packet = _reviewed_runtime_start_packet("governance_rollback")
    start_artifact_gate = _write_runtime_start_artifact_gate(
        tmp_path,
        decision="production_runtime_start_artifacts_reviewed_no_runtime",
        reviewed_packets=[packet],
        boundary={"runtime_execution_allowed": True},
    )

    report = build_h3_goal_emission_runtime_execution_gate(
        runtime_start_artifact_gate_path=start_artifact_gate,
        agent_root=tmp_path,
        ack_runtime_execution=True,
    )

    assert report["passed"] is False
    assert report["checks"]["runtime_start_artifact_boundary_runtime_execution_allowed_false"] is False
    assert report["runtime_execution_boundary"]["runtime_execution_allowed"] is False


def test_runtime_executor_blocks_without_local_ack(tmp_path: Path) -> None:
    execution_gate = _write_runtime_execution_gate(tmp_path)

    report = build_h3_goal_emission_runtime_executor_report(
        runtime_execution_gate_path=execution_gate,
        agent_root=tmp_path,
    )

    assert report["passed"] is True
    assert report["readiness"]["decision"] == "runtime_execution_blocked_pending_local_executor_ack"
    assert report["runtime_executor_boundary"]["runtime_execution_performed"] is False
    assert report["metrics"]["runtime_execution_completed_count"] == 0


def test_runtime_executor_writes_execution_receipt_with_local_ack(tmp_path: Path) -> None:
    execution_gate = _write_runtime_execution_gate(tmp_path)
    receipt_dir = tmp_path / "receipts"

    report = build_h3_goal_emission_runtime_executor_report(
        runtime_execution_gate_path=execution_gate,
        agent_root=tmp_path,
        ack_local_runtime_execution=True,
        receipt_dir=receipt_dir,
    )

    assert report["passed"] is True
    assert report["readiness"]["decision"] == "runtime_execution_completed_with_receipts"
    assert report["readiness"]["local_controlled_runtime_execution_completed"] is True
    assert report["readiness"]["production_runtime_execution_completed"] is False
    assert report["runtime_executor_boundary"]["runtime_execution_performed"] is True
    assert report["runtime_executor_boundary"]["local_controlled_receipt_write_performed"] is True
    assert report["runtime_executor_boundary"]["production_runtime_receipt_write_performed"] is False
    assert report["metrics"]["runtime_execution_completed_count"] == 1
    assert report["metrics"]["blocked_runtime_execution_packet_count"] == 0
    receipt = report["runtime_execution_receipts"][0]
    assert receipt["state"] == "runtime_execution_completed"
    assert receipt["execution_origin"] == "local_controlled"
    assert receipt["side_effects"]["receipt_written"] is True
    assert receipt["side_effects"]["llm_calls"] == 0
    assert Path(receipt["receipt_path"]).exists()


def test_runtime_executor_blocks_production_origin_with_local_ack(tmp_path: Path) -> None:
    execution_gate = _write_runtime_execution_gate(tmp_path, origin="production")
    receipt_dir = tmp_path / "receipts"

    report = build_h3_goal_emission_runtime_executor_report(
        runtime_execution_gate_path=execution_gate,
        agent_root=tmp_path,
        ack_local_runtime_execution=True,
        receipt_dir=receipt_dir,
    )

    assert report["passed"] is True
    assert report["readiness"]["decision"] == "runtime_execution_blocked_requires_production_executor_evidence"
    assert report["readiness"]["runtime_execution_completed"] is False
    assert report["readiness"]["production_runtime_execution_completed"] is False
    assert report["runtime_executor_boundary"]["runtime_execution_performed"] is False
    assert report["runtime_executor_boundary"]["production_runtime_receipt_write_performed"] is False
    assert report["metrics"]["runtime_execution_completed_count"] == 0
    assert report["metrics"]["blocked_runtime_execution_packet_count"] == 1
    assert report["runtime_execution_receipts"] == []
    blocked = report["runtime_executor_surface"]["blocked_runtime_execution_packets"][0]
    assert blocked["execution_origin"] == "production"
    assert "production executor evidence gate" in blocked["blocked_reason"]


def test_local_execution_fixture_requires_ack_and_writes_start_inputs(tmp_path: Path) -> None:
    blocked = build_h3_goal_emission_runtime_execution_local_fixture(
        output_dir=tmp_path / "local-input",
        agent_root=tmp_path,
    )
    assert blocked["passed"] is False
    assert blocked["readiness"]["decision"] == "blocked_before_local_runtime_start_inputs"

    report = build_h3_goal_emission_runtime_execution_local_fixture(
        output_dir=tmp_path / "local-input",
        agent_root=tmp_path,
        ack_local_production_shaped_start=True,
    )

    assert report["passed"] is True
    assert report["readiness"]["decision"] == "local_runtime_start_inputs_ready"
    assert Path(report["paths"]["runtime_start_gate"]).exists()
    assert Path(report["paths"]["runtime_start_artifacts"]).exists()
    assert report["fixture_policy"]["not_external_production_deployment"] is True


def _write_runtime_start_artifact_gate(
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
        "runtime_start_artifact_review_allowed": bool(reviewed_packets),
        "production_runtime_start_artifact_review_allowed": bool(reviewed_packets),
        "synthetic_runtime_start_artifact_surface_allowed": False,
        "local_controlled_runtime_start_artifact_surface_allowed": decision.startswith("local_controlled_"),
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
    path = tmp_path / "h3_goal_emission_runtime_start_artifact_gate.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": "h3-goal-emission-runtime-start-artifact-gate:v1",
                "passed": True,
                "readiness": {
                    "runtime_start_artifact_gate_evaluated": True,
                    "runtime_start_artifacts_complete": bool(reviewed_packets),
                    "production_runtime_start_artifacts_complete": bool(reviewed_packets) and decision.startswith("production_"),
                    "synthetic_runtime_start_artifacts_complete": bool(reviewed_packets) and decision.startswith("synthetic_"),
                    "local_controlled_runtime_start_artifacts_complete": bool(reviewed_packets) and decision.startswith("local_controlled_"),
                    "runtime_start_ready": False,
                    "runtime_activation_ready": False,
                    "runtime_execution_ready": False,
                    "activation_ready": False,
                    "emitted_goal_ready": False,
                    "executable_goal_ready": False,
                    "decision": decision,
                },
                "runtime_start_artifact_boundary": default_boundary,
                "runtime_start_artifact_surface": {
                    "mode": "runtime_start_artifacts_review_only_no_runtime",
                    "reviewed_runtime_start_packet_count": len(reviewed_packets),
                    "reviewed_runtime_start_packets": reviewed_packets,
                    "pending_runtime_start_packet_count": len(pending_packets),
                    "pending_runtime_start_packets": pending_packets,
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


def _write_runtime_execution_gate(tmp_path: Path, *, origin: str = "local_controlled") -> Path:
    packet = _runtime_execution_packet("post_delivery_failure", origin=origin)
    local_controlled = origin == "local_controlled"
    production = origin == "production"
    path = tmp_path / "h3_goal_emission_runtime_execution_gate.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": "h3-goal-emission-runtime-execution-gate:v1",
                "passed": True,
                "readiness": {
                    "runtime_execution_gate_evaluated": True,
                    "runtime_execution_acknowledged": True,
                    "runtime_start_ready": True,
                    "runtime_execution_ready": True,
                    "runtime_execution_started": False,
                    "runtime_execution_completed": False,
                    "decision": "local_controlled_runtime_execution_packets_ready" if local_controlled else "runtime_execution_packets_ready",
                },
                "runtime_execution_boundary": {
                    "artifact_only": False,
                    "controlled_runtime_execution_packet_allowed": True,
                    "runtime_start_allowed": True,
                    "runtime_execution_allowed": True,
                    "production_runtime_execution_packet_allowed": production,
                    "local_controlled_runtime_execution_packet_allowed": local_controlled,
                    "runtime_execution_performed": False,
                    "goal_emission_allowed": True,
                    "emitted_goal_allowed": False,
                    "executable_plan_allowed": False,
                    "llm_planning_allowed": False,
                    "iem_value_mutation_allowed": False,
                    "normative_local_mutation_allowed": False,
                    "external_system_mutation_allowed": False,
                },
                "runtime_execution_surface": {
                    "mode": "controlled_runtime_execution_packet_gate",
                    "runtime_execution_packet_count": 1,
                    "runtime_execution_packets": [packet],
                    "runtime_execution_receipts": [],
                },
            }
        ),
        encoding="utf-8",
    )
    return path


def _reviewed_runtime_start_packet(event_kind: str, *, synthetic: bool = False, local_controlled: bool = False) -> dict:
    goal_id = f"h3-draft-goal:{event_kind}:alpha"
    return {
        "artifact_review_id": f"h3-runtime-start-artifact-review:{goal_id}",
        "runtime_start_packet_id": f"h3-runtime-start-review:{goal_id}",
        "runtime_activation_artifact_review_id": f"h3-runtime-activation-artifact-review:{goal_id}",
        "runtime_activation_packet_id": f"h3-runtime-activation-review:{goal_id}",
        "activation_packet_id": f"h3-goal-emission-activation:{goal_id}",
        "preflight_id": f"h3-goal-emission-preflight:{goal_id}",
        "approval_id": f"h3-approved-candidate:{goal_id}",
        "goal_id": goal_id,
        "state": "runtime_start_artifacts_reviewed_no_runtime",
        "synthetic_runtime_start_fixture": synthetic,
        "local_controlled_runtime_start_fixture": local_controlled,
        "production_runtime_start_artifacts_ready": not synthetic and not local_controlled,
        "local_controlled_runtime_start_artifacts_ready": local_controlled,
        "runtime_start_artifact_refs": _runtime_start_artifact_refs(goal_id),
        "execution_policy": {
            "goal_emission_allowed": False,
            "executable_plan_allowed": False,
            "runtime_execution_allowed": False,
            "llm_planning_allowed": False,
            "iem_value_mutation_allowed": False,
            "normative_local_mutation_allowed": False,
        },
        "gate_status": {
            "runtime_start_artifacts_complete": True,
            "runtime_start_ready": False,
            "runtime_activation_ready": False,
            "runtime_execution_ready": False,
        },
    }


def _runtime_execution_packet(event_kind: str, *, origin: str = "local_controlled") -> dict:
    goal_id = f"h3-draft-goal:{event_kind}:alpha"
    local_controlled = origin == "local_controlled"
    production = origin == "production"
    return {
        "runtime_execution_packet_id": f"h3-runtime-execution:{goal_id}",
        "runtime_start_artifact_review_id": f"h3-runtime-start-artifact-review:{goal_id}",
        "runtime_start_packet_id": f"h3-runtime-start-review:{goal_id}",
        "goal_id": goal_id,
        "state": "runtime_execution_packet_ready",
        "execution_origin": origin,
        "production_runtime_execution": production,
        "local_controlled_runtime_execution": local_controlled,
        "action": "record_h3_controlled_runtime_execution_receipt",
        "runtime_start_artifact_refs": _runtime_start_artifact_refs(goal_id),
        "execution_scope": {
            "mode": "local_controlled_receipt_execution",
            "allowed_actions": ["write_runtime_execution_receipt"],
            "forbidden_actions": [
                "llm_call",
                "agent_loop_start",
                "iem_value_mutation",
                "normative_local_mutation",
                "external_system_mutation",
            ],
        },
        "execution_policy": {
            "runtime_start_allowed": True,
            "runtime_execution_allowed": True,
            "goal_emission_allowed": True,
            "emitted_goal_allowed": False,
            "executable_plan_allowed": False,
            "llm_planning_allowed": False,
            "iem_value_mutation_allowed": False,
            "normative_local_mutation_allowed": False,
        },
    }


def _runtime_start_artifact_refs(goal_id: str) -> dict[str, str]:
    return {
        "runtime_start_change_ticket": f"runtime-start:runtime_start_change_ticket:{goal_id}",
        "runtime_start_dual_operator_ack": f"runtime-start:runtime_start_dual_operator_ack:{goal_id}",
        "runtime_start_final_monitoring_green": f"runtime-start:runtime_start_final_monitoring_green:{goal_id}",
        "runtime_start_final_kill_switch_check": f"runtime-start:runtime_start_final_kill_switch_check:{goal_id}",
        "runtime_start_rollback_checkpoint": f"runtime-start:runtime_start_rollback_checkpoint:{goal_id}",
        "runtime_start_audit_sink_ready": f"runtime-start:runtime_start_audit_sink_ready:{goal_id}",
    }