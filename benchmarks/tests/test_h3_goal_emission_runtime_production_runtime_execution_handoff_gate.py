from __future__ import annotations

import hashlib
import json
from pathlib import Path

from benchmarks.h3_goal_emission_runtime_production_runtime_execution_handoff_gate import (
    build_h3_goal_emission_runtime_production_runtime_execution_handoff_gate,
)


def test_handoff_blocks_when_executor_permission_upstream_blocked_without_runtime(tmp_path: Path) -> None:
    permission_gate = _write_permission_gate_report(tmp_path, decision="production_executor_permission_blocked_upstream_goal_alignment")

    report = build_h3_goal_emission_runtime_production_runtime_execution_handoff_gate(
        production_executor_permission_gate_path=permission_gate,
        agent_root=tmp_path,
    )

    assert report["passed"] is True
    assert report["readiness"]["decision"] == "production_runtime_execution_handoff_blocked_upstream_executor_permission"
    assert report["readiness"]["production_runtime_execution_ready"] is False
    assert report["runtime_production_execution_handoff_boundary"]["production_runtime_execution_allowed"] is False
    assert report["metrics"]["production_runtime_execution_handoff_gap_count"] == 1


def test_handoff_waits_for_handoff_artifact_after_permission_review(tmp_path: Path) -> None:
    summary = _permission_summary("economic_deviation")
    permission_gate = _write_permission_gate_report(
        tmp_path,
        decision="production_executor_permission_reviewed_no_runtime_execution",
        summary=summary,
        gaps=[],
    )

    report = build_h3_goal_emission_runtime_production_runtime_execution_handoff_gate(
        production_executor_permission_gate_path=permission_gate,
        agent_root=tmp_path,
    )

    assert report["passed"] is True
    assert report["readiness"]["decision"] == "production_runtime_execution_handoff_blocked_pending_handoff_artifact"
    gap = report["runtime_production_execution_handoff_surface"]["production_runtime_execution_handoff_gaps"][0]
    assert gap["missing_handoff_goal_ids"] == summary["permitted_goal_ids"]
    assert report["readiness"]["production_runtime_execution_ready"] is False


def test_handoff_reviews_complete_handoff_without_runtime_execution(tmp_path: Path) -> None:
    summary = _permission_summary("governance_rollback")
    permission_gate = _write_permission_gate_report(
        tmp_path,
        decision="production_executor_permission_reviewed_no_runtime_execution",
        summary=summary,
        gaps=[],
    )
    handoff = _write_handoff(tmp_path, summary)

    report = build_h3_goal_emission_runtime_production_runtime_execution_handoff_gate(
        production_executor_permission_gate_path=permission_gate,
        agent_root=tmp_path,
        production_runtime_execution_handoff_path=handoff,
    )

    handoff_summary = report["runtime_production_execution_handoff_surface"]["production_runtime_execution_handoff_summary"]
    assert report["passed"] is True
    assert report["readiness"]["decision"] == "production_runtime_execution_handoff_reviewed_no_runtime_execution"
    assert report["readiness"]["production_runtime_execution_handoff_ready"] is False
    assert handoff_summary["handoff_sha256"] == hashlib.sha256(handoff.read_bytes()).hexdigest()
    assert report["metrics"]["production_runtime_execution_handoff_gap_count"] == 0


def test_handoff_fails_closed_on_local_handoff_source(tmp_path: Path) -> None:
    summary = _permission_summary("relation_repair_relapse")
    permission_gate = _write_permission_gate_report(
        tmp_path,
        decision="production_executor_permission_reviewed_no_runtime_execution",
        summary=summary,
        gaps=[],
    )
    handoff = _write_handoff(tmp_path, summary, source="local_runtime_handoff_fixture")

    report = build_h3_goal_emission_runtime_production_runtime_execution_handoff_gate(
        production_executor_permission_gate_path=permission_gate,
        agent_root=tmp_path,
        production_runtime_execution_handoff_path=handoff,
    )

    assert report["passed"] is False
    assert report["checks"]["production_runtime_execution_handoff_sources_production"] is False
    assert report["runtime_production_execution_handoff_boundary"]["production_runtime_execution_allowed"] is False


def test_handoff_fails_closed_on_permission_boundary_regression(tmp_path: Path) -> None:
    permission_gate = _write_permission_gate_report(
        tmp_path,
        decision="production_executor_permission_blocked_upstream_goal_alignment",
        boundary={"production_runtime_execution_allowed": True},
    )

    report = build_h3_goal_emission_runtime_production_runtime_execution_handoff_gate(
        production_executor_permission_gate_path=permission_gate,
        agent_root=tmp_path,
    )

    assert report["passed"] is False
    assert report["checks"]["production_executor_permission_boundary_production_runtime_execution_allowed_false"] is False


def test_handoff_fails_closed_when_handoff_arrives_before_permission_review(tmp_path: Path) -> None:
    summary = _permission_summary("post_delivery_dispute")
    permission_gate = _write_permission_gate_report(
        tmp_path,
        decision="production_executor_permission_blocked_upstream_goal_alignment",
        summary=summary,
    )
    handoff = _write_handoff(tmp_path, summary)

    report = build_h3_goal_emission_runtime_production_runtime_execution_handoff_gate(
        production_executor_permission_gate_path=permission_gate,
        agent_root=tmp_path,
        production_runtime_execution_handoff_path=handoff,
    )

    assert report["passed"] is False
    assert report["checks"]["production_runtime_execution_handoff_requires_permission_review"] is False


def _write_permission_gate_report(
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
        "production_executor_permission_review_allowed": True,
        "production_executor_permission_allowed": False,
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
        "production_executor_permission_evaluated": True,
        "production_executor_permission_present": bool(summary),
        "production_executor_permission_complete": bool(summary) and not gaps,
        "production_executor_permission_ready": False,
        "production_runtime_execution_ready": False,
        "production_runtime_receipt_ready": False,
        "decision": decision,
    }
    default_readiness.update(readiness or {})
    default_gaps = gaps if gaps is not None else [_permission_gap()]
    path = tmp_path / "h3_goal_emission_runtime_production_executor_permission_gate.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": "h3-goal-emission-runtime-production-executor-permission-gate:v1",
                "passed": True,
                "failure_reasons": [],
                "readiness": default_readiness,
                "runtime_production_executor_permission_boundary": default_boundary,
                "runtime_production_executor_permission_surface": {
                    "mode": "production_executor_permission_review_only_no_runtime",
                    "production_executor_permission_summary": summary or {},
                    "production_executor_permission_gaps": default_gaps,
                },
                "non_claims": non_claims
                if non_claims is not None
                else [
                    "does_not_grant_production_executor_permission",
                    "does_not_treat_executor_permission_review_as_runtime_execution_permission",
                    "does_not_mutate_iem_or_normative_state",
                ],
            }
        ),
        encoding="utf-8",
    )
    return path


def _permission_summary(event_kind: str) -> dict:
    goal_id = f"h3-draft-goal:{event_kind}:alpha"
    permission_sha256 = hashlib.sha256(f"permission:{goal_id}".encode("utf-8")).hexdigest()
    return {
        "state": "production_executor_permission_reviewed_no_runtime_execution",
        "permission_path": f"/permission/{goal_id}.json",
        "permission_sha256": permission_sha256,
        "permission_record_count": 1,
        "permitted_goal_ids": [goal_id],
        "permission_refs": [f"production-executor-permission:{goal_id}"],
        "production_executor_permission_ready": False,
        "production_runtime_execution_ready": False,
        "production_runtime_receipt_ready": False,
    }


def _permission_gap() -> dict:
    return {
        "goal_id": "h3-draft-goal:post_delivery_failure:alpha",
        "state": "production_executor_permission_blocked_by_goal_alignment_gap",
        "gap_reason": "production goal alignment has not reached executor permission handoff",
    }


def _write_handoff(
    tmp_path: Path,
    permission_summary: dict,
    *,
    source: str = "h3_production_runtime_handoff_board",
) -> Path:
    goal_id = permission_summary["permitted_goal_ids"][0]
    path = tmp_path / "h3_goal_emission_runtime_production_runtime_execution_handoff.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": "h3-goal-emission-runtime-production-runtime-execution-handoff:v1",
                "production_runtime_execution_handoff_records": [
                    {
                        "handoff_id": f"production-runtime-execution-handoff:{goal_id}",
                        "goal_id": goal_id,
                        "runtime_executor": "h3-production-runtime-executor",
                        "runtime_executor_role": "production_runtime_executor",
                        "source": source,
                        "status": "handoff_ready",
                        "attestation_ref": f"runtime-handoff-attestation:{goal_id}",
                        "executor_permission_ref": permission_summary["permission_path"],
                        "executor_permission_sha256": permission_summary["permission_sha256"],
                        "change_ticket_ref": f"change-ticket:{goal_id}",
                        "dual_operator_ack_ref": f"dual-operator-ack:{goal_id}",
                        "kill_switch_ref": f"kill-switch:{goal_id}",
                        "rollback_checkpoint_ref": f"rollback-checkpoint:{goal_id}",
                        "monitoring_green_ref": f"monitoring-green:{goal_id}",
                        "audit_sink_ref": f"audit-sink:{goal_id}",
                        "runtime_window_ref": f"runtime-window:{goal_id}",
                        "receipt_sink_ref": f"receipt-sink:{goal_id}",
                        "production_runtime_execution_handoff_allowed": False,
                        "production_runtime_execution_allowed": False,
                        "production_runtime_receipt_allowed": False,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return path