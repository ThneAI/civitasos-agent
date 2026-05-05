from __future__ import annotations

import hashlib
import json
from pathlib import Path

from benchmarks.h3_goal_emission_runtime_production_runtime_actuation_gate import (
    build_h3_goal_emission_runtime_production_runtime_actuation_gate,
)


def test_actuation_blocks_when_execution_upstream_blocked_without_runtime(tmp_path: Path) -> None:
    execution_gate = _write_execution_gate_report(tmp_path, decision="production_runtime_execution_blocked_upstream_handoff")

    report = build_h3_goal_emission_runtime_production_runtime_actuation_gate(
        production_runtime_execution_gate_path=execution_gate,
        agent_root=tmp_path,
    )

    assert report["passed"] is True
    assert report["readiness"]["decision"] == "production_runtime_actuation_blocked_upstream_execution"
    assert report["readiness"]["production_runtime_actuation_ready"] is False
    assert report["runtime_production_actuation_boundary"]["production_runtime_execution_allowed"] is False
    assert report["metrics"]["production_runtime_actuation_gap_count"] == 1


def test_actuation_waits_for_actuation_artifact_after_execution_review(tmp_path: Path) -> None:
    summary = _execution_summary("economic_deviation")
    execution_gate = _write_execution_gate_report(
        tmp_path,
        decision="production_runtime_execution_reviewed_no_runtime_start",
        summary=summary,
        gaps=[],
    )

    report = build_h3_goal_emission_runtime_production_runtime_actuation_gate(
        production_runtime_execution_gate_path=execution_gate,
        agent_root=tmp_path,
    )

    assert report["passed"] is True
    assert report["readiness"]["decision"] == "production_runtime_actuation_blocked_pending_actuation_artifact"
    gap = report["runtime_production_actuation_surface"]["production_runtime_actuation_gaps"][0]
    assert gap["missing_actuation_goal_ids"] == summary["execution_goal_ids"]
    assert report["readiness"]["production_runtime_execution_ready"] is False


def test_actuation_reviews_complete_actuation_without_runtime_start(tmp_path: Path) -> None:
    summary = _execution_summary("governance_rollback")
    execution_gate = _write_execution_gate_report(
        tmp_path,
        decision="production_runtime_execution_reviewed_no_runtime_start",
        summary=summary,
        gaps=[],
    )
    actuation = _write_actuation(tmp_path, summary)

    report = build_h3_goal_emission_runtime_production_runtime_actuation_gate(
        production_runtime_execution_gate_path=execution_gate,
        agent_root=tmp_path,
        production_runtime_actuation_path=actuation,
    )

    actuation_summary = report["runtime_production_actuation_surface"]["production_runtime_actuation_summary"]
    assert report["passed"] is True
    assert report["readiness"]["decision"] == "production_runtime_actuation_reviewed_no_runtime_start"
    assert report["readiness"]["production_runtime_actuation_ready"] is False
    assert actuation_summary["actuation_sha256"] == hashlib.sha256(actuation.read_bytes()).hexdigest()
    assert report["metrics"]["production_runtime_actuation_gap_count"] == 0


def test_actuation_fails_closed_on_local_actuation_source(tmp_path: Path) -> None:
    summary = _execution_summary("relation_repair_relapse")
    execution_gate = _write_execution_gate_report(
        tmp_path,
        decision="production_runtime_execution_reviewed_no_runtime_start",
        summary=summary,
        gaps=[],
    )
    actuation = _write_actuation(tmp_path, summary, source="local_runtime_actuation_fixture")

    report = build_h3_goal_emission_runtime_production_runtime_actuation_gate(
        production_runtime_execution_gate_path=execution_gate,
        agent_root=tmp_path,
        production_runtime_actuation_path=actuation,
    )

    assert report["passed"] is False
    assert report["checks"]["production_runtime_actuation_sources_production"] is False
    assert report["runtime_production_actuation_boundary"]["production_runtime_execution_allowed"] is False


def test_actuation_fails_closed_on_execution_boundary_regression(tmp_path: Path) -> None:
    execution_gate = _write_execution_gate_report(
        tmp_path,
        decision="production_runtime_execution_blocked_upstream_handoff",
        boundary={"production_runtime_execution_allowed": True},
    )

    report = build_h3_goal_emission_runtime_production_runtime_actuation_gate(
        production_runtime_execution_gate_path=execution_gate,
        agent_root=tmp_path,
    )

    assert report["passed"] is False
    assert report["checks"]["production_runtime_execution_boundary_production_runtime_execution_allowed_false"] is False


def test_actuation_fails_closed_when_actuation_arrives_before_execution_review(tmp_path: Path) -> None:
    summary = _execution_summary("post_delivery_dispute")
    execution_gate = _write_execution_gate_report(
        tmp_path,
        decision="production_runtime_execution_blocked_upstream_handoff",
        summary=summary,
    )
    actuation = _write_actuation(tmp_path, summary)

    report = build_h3_goal_emission_runtime_production_runtime_actuation_gate(
        production_runtime_execution_gate_path=execution_gate,
        agent_root=tmp_path,
        production_runtime_actuation_path=actuation,
    )

    assert report["passed"] is False
    assert report["checks"]["production_runtime_actuation_requires_execution_review"] is False


def _write_execution_gate_report(
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
        "production_runtime_execution_review_allowed": True,
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
        "production_runtime_execution_evaluated": True,
        "production_runtime_execution_artifact_present": bool(summary),
        "production_runtime_execution_artifact_complete": bool(summary) and not gaps,
        "production_runtime_execution_ready": False,
        "production_runtime_receipt_ready": False,
        "decision": decision,
    }
    default_readiness.update(readiness or {})
    default_gaps = gaps if gaps is not None else [_execution_gap()]
    path = tmp_path / "h3_goal_emission_runtime_production_runtime_execution_gate.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": "h3-goal-emission-runtime-production-runtime-execution-gate:v1",
                "passed": True,
                "failure_reasons": [],
                "readiness": default_readiness,
                "runtime_production_execution_boundary": default_boundary,
                "runtime_production_execution_surface": {
                    "mode": "production_runtime_execution_review_only_no_runtime",
                    "production_runtime_execution_summary": summary or {},
                    "production_runtime_execution_gaps": default_gaps,
                },
                "non_claims": non_claims
                if non_claims is not None
                else [
                    "does_not_treat_runtime_execution_review_as_runtime_start",
                    "does_not_start_runtime_or_agent_loop",
                    "does_not_mutate_iem_or_normative_state",
                ],
            }
        ),
        encoding="utf-8",
    )
    return path


def _execution_summary(event_kind: str) -> dict:
    goal_id = f"h3-draft-goal:{event_kind}:alpha"
    execution_sha256 = hashlib.sha256(f"execution:{goal_id}".encode("utf-8")).hexdigest()
    return {
        "state": "production_runtime_execution_reviewed_no_runtime_start",
        "execution_path": f"/execution/{goal_id}.json",
        "execution_sha256": execution_sha256,
        "execution_record_count": 1,
        "execution_goal_ids": [goal_id],
        "execution_refs": [f"production-runtime-execution:{goal_id}"],
        "production_runtime_execution_ready": False,
        "production_runtime_receipt_ready": False,
    }


def _execution_gap() -> dict:
    return {
        "goal_id": "h3-draft-goal:post_delivery_failure:alpha",
        "state": "production_runtime_execution_blocked_by_handoff_gap",
        "gap_reason": "production runtime execution handoff has not been reviewed",
    }


def _write_actuation(
    tmp_path: Path,
    execution_summary: dict,
    *,
    source: str = "h3_production_runtime_actuation_board",
) -> Path:
    goal_id = execution_summary["execution_goal_ids"][0]
    path = tmp_path / "h3_goal_emission_runtime_production_runtime_actuation.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": "h3-goal-emission-runtime-production-runtime-actuation:v1",
                "production_runtime_actuation_records": [
                    {
                        "actuation_id": f"production-runtime-actuation:{goal_id}",
                        "goal_id": goal_id,
                        "runtime_executor": "h3-production-runtime-executor",
                        "runtime_executor_role": "production_runtime_executor",
                        "source": source,
                        "status": "actuation_ready",
                        "attestation_ref": f"runtime-actuation-attestation:{goal_id}",
                        "runtime_execution_ref": execution_summary["execution_path"],
                        "runtime_execution_sha256": execution_summary["execution_sha256"],
                        "deployment_environment_ref": f"deployment-environment:{goal_id}",
                        "operator_console_ref": f"operator-console:{goal_id}",
                        "process_supervisor_ref": f"process-supervisor:{goal_id}",
                        "start_command_ref": f"start-command:{goal_id}",
                        "kill_switch_ref": f"kill-switch:{goal_id}",
                        "rollback_checkpoint_ref": f"rollback-checkpoint:{goal_id}",
                        "audit_sink_ref": f"audit-sink:{goal_id}",
                        "receipt_sink_ref": f"receipt-sink:{goal_id}",
                        "production_runtime_actuation_allowed": False,
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