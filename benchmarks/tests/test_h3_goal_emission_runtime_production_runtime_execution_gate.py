from __future__ import annotations

import hashlib
import json
from pathlib import Path

from benchmarks.h3_goal_emission_runtime_production_runtime_execution_gate import (
    build_h3_goal_emission_runtime_production_runtime_execution_gate,
)


def test_execution_blocks_when_handoff_upstream_blocked_without_runtime(tmp_path: Path) -> None:
    handoff_gate = _write_handoff_gate_report(tmp_path, decision="production_runtime_execution_handoff_blocked_upstream_executor_permission")

    report = build_h3_goal_emission_runtime_production_runtime_execution_gate(
        production_runtime_execution_handoff_gate_path=handoff_gate,
        agent_root=tmp_path,
    )

    assert report["passed"] is True
    assert report["readiness"]["decision"] == "production_runtime_execution_blocked_upstream_handoff"
    assert report["readiness"]["production_runtime_execution_ready"] is False
    assert report["runtime_production_execution_boundary"]["production_runtime_execution_allowed"] is False
    assert report["metrics"]["production_runtime_execution_gap_count"] == 1


def test_execution_waits_for_execution_artifact_after_handoff_review(tmp_path: Path) -> None:
    summary = _handoff_summary("economic_deviation")
    handoff_gate = _write_handoff_gate_report(
        tmp_path,
        decision="production_runtime_execution_handoff_reviewed_no_runtime_execution",
        summary=summary,
        gaps=[],
    )

    report = build_h3_goal_emission_runtime_production_runtime_execution_gate(
        production_runtime_execution_handoff_gate_path=handoff_gate,
        agent_root=tmp_path,
    )

    assert report["passed"] is True
    assert report["readiness"]["decision"] == "production_runtime_execution_blocked_pending_execution_artifact"
    gap = report["runtime_production_execution_surface"]["production_runtime_execution_gaps"][0]
    assert gap["missing_execution_goal_ids"] == summary["handoff_goal_ids"]
    assert report["readiness"]["production_runtime_receipt_ready"] is False


def test_execution_reviews_complete_execution_without_runtime_start(tmp_path: Path) -> None:
    summary = _handoff_summary("governance_rollback")
    handoff_gate = _write_handoff_gate_report(
        tmp_path,
        decision="production_runtime_execution_handoff_reviewed_no_runtime_execution",
        summary=summary,
        gaps=[],
    )
    execution = _write_execution(tmp_path, summary)

    report = build_h3_goal_emission_runtime_production_runtime_execution_gate(
        production_runtime_execution_handoff_gate_path=handoff_gate,
        agent_root=tmp_path,
        production_runtime_execution_path=execution,
    )

    execution_summary = report["runtime_production_execution_surface"]["production_runtime_execution_summary"]
    assert report["passed"] is True
    assert report["readiness"]["decision"] == "production_runtime_execution_reviewed_no_runtime_start"
    assert report["readiness"]["production_runtime_execution_ready"] is False
    assert execution_summary["execution_sha256"] == hashlib.sha256(execution.read_bytes()).hexdigest()
    assert report["metrics"]["production_runtime_execution_gap_count"] == 0


def test_execution_fails_closed_on_local_execution_source(tmp_path: Path) -> None:
    summary = _handoff_summary("relation_repair_relapse")
    handoff_gate = _write_handoff_gate_report(
        tmp_path,
        decision="production_runtime_execution_handoff_reviewed_no_runtime_execution",
        summary=summary,
        gaps=[],
    )
    execution = _write_execution(tmp_path, summary, source="local_runtime_execution_fixture")

    report = build_h3_goal_emission_runtime_production_runtime_execution_gate(
        production_runtime_execution_handoff_gate_path=handoff_gate,
        agent_root=tmp_path,
        production_runtime_execution_path=execution,
    )

    assert report["passed"] is False
    assert report["checks"]["production_runtime_execution_sources_production"] is False
    assert report["runtime_production_execution_boundary"]["production_runtime_execution_allowed"] is False


def test_execution_fails_closed_on_handoff_boundary_regression(tmp_path: Path) -> None:
    handoff_gate = _write_handoff_gate_report(
        tmp_path,
        decision="production_runtime_execution_handoff_blocked_upstream_executor_permission",
        boundary={"production_runtime_execution_allowed": True},
    )

    report = build_h3_goal_emission_runtime_production_runtime_execution_gate(
        production_runtime_execution_handoff_gate_path=handoff_gate,
        agent_root=tmp_path,
    )

    assert report["passed"] is False
    assert report["checks"]["production_runtime_execution_handoff_boundary_production_runtime_execution_allowed_false"] is False


def test_execution_fails_closed_when_execution_arrives_before_handoff_review(tmp_path: Path) -> None:
    summary = _handoff_summary("post_delivery_dispute")
    handoff_gate = _write_handoff_gate_report(
        tmp_path,
        decision="production_runtime_execution_handoff_blocked_upstream_executor_permission",
        summary=summary,
    )
    execution = _write_execution(tmp_path, summary)

    report = build_h3_goal_emission_runtime_production_runtime_execution_gate(
        production_runtime_execution_handoff_gate_path=handoff_gate,
        agent_root=tmp_path,
        production_runtime_execution_path=execution,
    )

    assert report["passed"] is False
    assert report["checks"]["production_runtime_execution_requires_handoff_review"] is False


def _write_handoff_gate_report(
    tmp_path: Path,
    *,
    decision: str,
    summary: dict | None = None,
    gaps: list[dict] | None = None,
    boundary: dict | None = None,
    readiness: dict | None = None,
    non_claims: list[str] | None = None,
) -> Path:
    default_boundary = {
        "artifact_only": True,
        "production_runtime_execution_handoff_review_allowed": True,
        "production_runtime_execution_handoff_allowed": False,
        "production_runtime_execution_allowed": False,
        "production_runtime_receipt_allowed": False,
        "agent_loop_start_allowed": False,
        "llm_planning_allowed": False,
        "external_system_mutation_allowed": False,
        "iem_value_mutation_allowed": False,
        "normative_local_mutation_allowed": False,
    }
    default_boundary.update(boundary or {})
    default_readiness = {
        "production_runtime_execution_handoff_evaluated": True,
        "production_runtime_execution_handoff_present": bool(summary),
        "production_runtime_execution_handoff_complete": bool(summary) and not gaps,
        "production_runtime_execution_handoff_ready": False,
        "production_runtime_execution_ready": False,
        "production_runtime_receipt_ready": False,
        "decision": decision,
    }
    default_readiness.update(readiness or {})
    default_gaps = gaps if gaps is not None else [_handoff_gap()]
    path = tmp_path / "h3_goal_emission_runtime_production_runtime_execution_handoff_gate.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": "h3-goal-emission-runtime-production-runtime-execution-handoff-gate:v1",
                "passed": True,
                "failure_reasons": [],
                "readiness": default_readiness,
                "runtime_production_execution_handoff_boundary": default_boundary,
                "runtime_production_execution_handoff_surface": {
                    "mode": "production_runtime_execution_handoff_review_only_no_runtime",
                    "production_runtime_execution_handoff_summary": summary or {},
                    "production_runtime_execution_handoff_gaps": default_gaps,
                },
                "non_claims": non_claims
                if non_claims is not None
                else [
                    "does_not_treat_runtime_execution_handoff_review_as_runtime_execution_permission",
                    "does_not_start_runtime_or_agent_loop",
                    "does_not_mutate_iem_or_normative_state",
                ],
            }
        ),
        encoding="utf-8",
    )
    return path


def _handoff_summary(event_kind: str) -> dict:
    goal_id = f"h3-draft-goal:{event_kind}:alpha"
    handoff_sha256 = hashlib.sha256(f"handoff:{goal_id}".encode("utf-8")).hexdigest()
    return {
        "state": "production_runtime_execution_handoff_reviewed_no_runtime_execution",
        "handoff_path": f"/handoff/{goal_id}.json",
        "handoff_sha256": handoff_sha256,
        "handoff_record_count": 1,
        "handoff_goal_ids": [goal_id],
        "handoff_refs": [f"production-runtime-execution-handoff:{goal_id}"],
        "production_runtime_execution_handoff_ready": False,
        "production_runtime_execution_ready": False,
        "production_runtime_receipt_ready": False,
    }


def _handoff_gap() -> dict:
    return {
        "goal_id": "h3-draft-goal:post_delivery_failure:alpha",
        "state": "production_runtime_execution_handoff_blocked_by_executor_permission_gap",
        "gap_reason": "production executor permission has not been reviewed",
    }


def _write_execution(
    tmp_path: Path,
    handoff_summary: dict,
    *,
    source: str = "h3_production_runtime_execution_board",
) -> Path:
    goal_id = handoff_summary["handoff_goal_ids"][0]
    path = tmp_path / "h3_goal_emission_runtime_production_runtime_execution.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": "h3-goal-emission-runtime-production-runtime-execution:v1",
                "production_runtime_execution_records": [
                    {
                        "execution_id": f"production-runtime-execution:{goal_id}",
                        "goal_id": goal_id,
                        "runtime_executor": "h3-production-runtime-executor",
                        "runtime_executor_role": "production_runtime_executor",
                        "source": source,
                        "status": "execution_ready",
                        "attestation_ref": f"runtime-execution-attestation:{goal_id}",
                        "runtime_execution_handoff_ref": handoff_summary["handoff_path"],
                        "runtime_execution_handoff_sha256": handoff_summary["handoff_sha256"],
                        "final_change_ticket_ref": f"final-change-ticket:{goal_id}",
                        "final_dual_operator_ack_ref": f"final-dual-operator-ack:{goal_id}",
                        "final_kill_switch_ref": f"final-kill-switch:{goal_id}",
                        "final_rollback_checkpoint_ref": f"final-rollback-checkpoint:{goal_id}",
                        "final_monitoring_green_ref": f"final-monitoring-green:{goal_id}",
                        "final_audit_sink_ref": f"final-audit-sink:{goal_id}",
                        "receipt_sink_ref": f"receipt-sink:{goal_id}",
                        "production_runtime_execution_allowed": False,
                        "production_runtime_receipt_allowed": False,
                        "agent_loop_start_allowed": False,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return path