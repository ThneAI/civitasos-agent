from __future__ import annotations

import hashlib
import json
from pathlib import Path

from benchmarks.h3_goal_emission_runtime_production_executor_permission_gate import (
    build_h3_goal_emission_runtime_production_executor_permission_gate,
)


def test_permission_blocks_when_goal_alignment_upstream_blocked_without_runtime(tmp_path: Path) -> None:
    alignment_gate = _write_goal_alignment_gate_report(tmp_path, decision="production_goal_alignment_preserved_upstream_blocked")

    report = build_h3_goal_emission_runtime_production_executor_permission_gate(
        production_goal_alignment_gate_path=alignment_gate,
        agent_root=tmp_path,
    )

    assert report["passed"] is True
    assert report["readiness"]["decision"] == "production_executor_permission_blocked_upstream_goal_alignment"
    assert report["readiness"]["production_executor_permission_ready"] is False
    assert report["runtime_production_executor_permission_boundary"]["production_executor_permission_allowed"] is False
    assert report["runtime_production_executor_permission_boundary"]["production_runtime_execution_allowed"] is False
    assert report["metrics"]["production_executor_permission_gap_count"] == 1


def test_permission_waits_for_permission_artifact_after_goal_alignment_handoff(tmp_path: Path) -> None:
    summary = _authorization_summary("economic_deviation")
    alignment_gate = _write_goal_alignment_gate_report(
        tmp_path,
        decision="production_goal_alignment_preserved_requires_executor_permission_layer",
        summary=summary,
        gaps=[],
    )

    report = build_h3_goal_emission_runtime_production_executor_permission_gate(
        production_goal_alignment_gate_path=alignment_gate,
        agent_root=tmp_path,
    )

    assert report["passed"] is True
    assert report["readiness"]["decision"] == "production_executor_permission_blocked_pending_permission_artifact"
    gap = report["runtime_production_executor_permission_surface"]["production_executor_permission_gaps"][0]
    assert gap["missing_permission_goal_ids"] == summary["authorized_goal_ids"]
    assert report["readiness"]["production_runtime_execution_ready"] is False


def test_permission_reviews_complete_permission_without_runtime_execution(tmp_path: Path) -> None:
    summary = _authorization_summary("governance_rollback")
    alignment_gate = _write_goal_alignment_gate_report(
        tmp_path,
        decision="production_goal_alignment_preserved_requires_executor_permission_layer",
        summary=summary,
        gaps=[],
    )
    permission = _write_permission(tmp_path, alignment_gate, summary)

    report = build_h3_goal_emission_runtime_production_executor_permission_gate(
        production_goal_alignment_gate_path=alignment_gate,
        agent_root=tmp_path,
        production_executor_permission_path=permission,
    )

    permission_summary = report["runtime_production_executor_permission_surface"]["production_executor_permission_summary"]
    assert report["passed"] is True
    assert report["readiness"]["decision"] == "production_executor_permission_reviewed_no_runtime_execution"
    assert report["readiness"]["production_executor_permission_ready"] is False
    assert permission_summary["permission_sha256"] == hashlib.sha256(permission.read_bytes()).hexdigest()
    assert permission_summary["source_goal_alignment_sha256"] == hashlib.sha256(alignment_gate.read_bytes()).hexdigest()
    assert report["metrics"]["production_executor_permission_gap_count"] == 0


def test_permission_fails_closed_on_local_permission_source(tmp_path: Path) -> None:
    summary = _authorization_summary("relation_repair_relapse")
    alignment_gate = _write_goal_alignment_gate_report(
        tmp_path,
        decision="production_goal_alignment_preserved_requires_executor_permission_layer",
        summary=summary,
        gaps=[],
    )
    permission = _write_permission(tmp_path, alignment_gate, summary, source="local_permission_fixture")

    report = build_h3_goal_emission_runtime_production_executor_permission_gate(
        production_goal_alignment_gate_path=alignment_gate,
        agent_root=tmp_path,
        production_executor_permission_path=permission,
    )

    assert report["passed"] is False
    assert report["checks"]["production_executor_permission_sources_production"] is False
    assert report["runtime_production_executor_permission_boundary"]["production_runtime_execution_allowed"] is False


def test_permission_fails_closed_on_goal_alignment_boundary_regression(tmp_path: Path) -> None:
    alignment_gate = _write_goal_alignment_gate_report(
        tmp_path,
        decision="production_goal_alignment_preserved_upstream_blocked",
        boundary={"production_runtime_execution_allowed": True},
    )

    report = build_h3_goal_emission_runtime_production_executor_permission_gate(
        production_goal_alignment_gate_path=alignment_gate,
        agent_root=tmp_path,
    )

    assert report["passed"] is False
    assert report["checks"]["production_goal_alignment_boundary_production_runtime_execution_allowed_false"] is False


def test_permission_fails_closed_when_permission_arrives_before_alignment_handoff(tmp_path: Path) -> None:
    summary = _authorization_summary("post_delivery_dispute")
    alignment_gate = _write_goal_alignment_gate_report(
        tmp_path,
        decision="production_goal_alignment_preserved_upstream_blocked",
        summary=summary,
    )
    permission = _write_permission(tmp_path, alignment_gate, summary)

    report = build_h3_goal_emission_runtime_production_executor_permission_gate(
        production_goal_alignment_gate_path=alignment_gate,
        agent_root=tmp_path,
        production_executor_permission_path=permission,
    )

    assert report["passed"] is False
    assert report["checks"]["production_executor_permission_requires_goal_alignment_handoff"] is False


def _write_goal_alignment_gate_report(
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
        "goal_alignment_review_allowed": True,
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
        "production_goal_alignment_evaluated": True,
        "production_goal_alignment_preserved": True,
        "production_executor_permission_ready": False,
        "production_runtime_execution_ready": False,
        "production_runtime_receipt_ready": False,
        "decision": decision,
    }
    default_readiness.update(readiness or {})
    default_gaps = gaps if gaps is not None else [_authorization_gap()]
    path = tmp_path / "h3_goal_emission_runtime_production_goal_alignment_gate.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": "h3-goal-emission-runtime-production-goal-alignment-gate:v1",
                "passed": True,
                "failure_reasons": [],
                "readiness": default_readiness,
                "runtime_production_goal_alignment_boundary": default_boundary,
                "runtime_production_goal_alignment_policy": {
                    "north_star_values": [
                        "human_sovereignty",
                        "rules_before_capability",
                        "verifiable_truth",
                        "non_disappearing_accountability",
                        "safety_over_efficiency",
                        "long_termism",
                        "incremental_evolution",
                        "open_collaboration_with_security_boundaries",
                    ],
                    "blocked_drift_vectors": ["authorization_review -> executor_permission"],
                },
                "runtime_production_goal_alignment_surface": {
                    "mode": "production_goal_alignment_review_only_no_runtime",
                    "source_production_execution_authorization_summary": summary or {},
                    "source_production_execution_authorization_gaps": default_gaps,
                },
                "non_claims": non_claims
                if non_claims is not None
                else [
                    "does_not_grant_production_executor_permission",
                    "does_not_treat_goal_alignment_as_runtime_execution_permission",
                    "does_not_mutate_iem_or_normative_state",
                ],
            }
        ),
        encoding="utf-8",
    )
    return path


def _authorization_summary(event_kind: str) -> dict:
    goal_id = f"h3-draft-goal:{event_kind}:alpha"
    authorization_sha256 = hashlib.sha256(f"authorization:{goal_id}".encode("utf-8")).hexdigest()
    return {
        "state": "production_execution_authorization_reviewed_no_runtime_execution",
        "authorization_path": f"/authorization/{goal_id}.json",
        "authorization_sha256": authorization_sha256,
        "authorization_record_count": 1,
        "authorized_goal_ids": [goal_id],
        "authorization_refs": [f"production-execution-authorization:{goal_id}"],
        "production_runtime_execution_ready": False,
        "production_runtime_receipt_ready": False,
    }


def _authorization_gap() -> dict:
    return {
        "goal_id": "h3-draft-goal:post_delivery_failure:alpha",
        "state": "production_execution_authorization_blocked_by_submission_manifest_gap",
        "gap_reason": "production evidence submission manifest is incomplete",
    }


def _write_permission(
    tmp_path: Path,
    alignment_gate: Path,
    authorization_summary: dict,
    *,
    source: str = "h3_production_executor_permission_board",
) -> Path:
    goal_id = authorization_summary["authorized_goal_ids"][0]
    path = tmp_path / "h3_goal_emission_runtime_production_executor_permission.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": "h3-goal-emission-runtime-production-executor-permission:v1",
                "production_executor_permission_records": [
                    {
                        "permission_id": f"production-executor-permission:{goal_id}",
                        "goal_id": goal_id,
                        "executor": "h3-production-runtime-executor",
                        "executor_role": "production_runtime_executor",
                        "source": source,
                        "status": "permitted",
                        "attestation_ref": f"executor-permission-attestation:{goal_id}",
                        "authorization_ref": authorization_summary["authorization_path"],
                        "authorization_sha256": authorization_summary["authorization_sha256"],
                        "goal_alignment_ref": str(alignment_gate),
                        "goal_alignment_sha256": hashlib.sha256(alignment_gate.read_bytes()).hexdigest(),
                        "change_ticket_ref": f"change-ticket:{goal_id}",
                        "dual_operator_ack_ref": f"dual-operator-ack:{goal_id}",
                        "kill_switch_ref": f"kill-switch:{goal_id}",
                        "rollback_checkpoint_ref": f"rollback-checkpoint:{goal_id}",
                        "monitoring_green_ref": f"monitoring-green:{goal_id}",
                        "audit_sink_ref": f"audit-sink:{goal_id}",
                        "execution_window_ref": f"execution-window:{goal_id}",
                        "production_executor_permission_allowed": False,
                        "production_runtime_execution_allowed": False,
                        "production_runtime_receipt_allowed": False,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return path