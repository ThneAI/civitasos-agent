from __future__ import annotations

import hashlib
import json
from pathlib import Path

from benchmarks.h3_goal_emission_runtime_production_runtime_receipt_gate import (
    build_h3_goal_emission_runtime_production_runtime_receipt_gate,
)


def test_receipt_blocks_when_actuation_upstream_blocked_without_runtime(tmp_path: Path) -> None:
    actuation_gate = _write_actuation_gate_report(tmp_path, decision="production_runtime_actuation_blocked_upstream_execution")

    report = build_h3_goal_emission_runtime_production_runtime_receipt_gate(
        production_runtime_actuation_gate_path=actuation_gate,
        agent_root=tmp_path,
    )

    assert report["passed"] is True
    assert report["readiness"]["decision"] == "production_runtime_receipt_blocked_upstream_actuation"
    assert report["readiness"]["production_runtime_receipt_ready"] is False
    assert report["runtime_production_receipt_boundary"]["production_runtime_receipt_write_allowed"] is False
    assert report["metrics"]["production_runtime_receipt_gap_count"] == 1


def test_receipt_waits_for_receipt_artifact_after_actuation_review(tmp_path: Path) -> None:
    summary = _actuation_summary("economic_deviation")
    actuation_gate = _write_actuation_gate_report(
        tmp_path,
        decision="production_runtime_actuation_reviewed_no_runtime_start",
        summary=summary,
        gaps=[],
    )

    report = build_h3_goal_emission_runtime_production_runtime_receipt_gate(
        production_runtime_actuation_gate_path=actuation_gate,
        agent_root=tmp_path,
    )

    assert report["passed"] is True
    assert report["readiness"]["decision"] == "production_runtime_receipt_blocked_pending_receipt_artifact"
    gap = report["runtime_production_receipt_surface"]["production_runtime_receipt_gaps"][0]
    assert gap["missing_receipt_goal_ids"] == summary["actuation_goal_ids"]
    assert report["readiness"]["production_runtime_execution_ready"] is False


def test_receipt_reviews_complete_receipt_without_writing_receipt(tmp_path: Path) -> None:
    summary = _actuation_summary("governance_rollback")
    actuation_gate = _write_actuation_gate_report(
        tmp_path,
        decision="production_runtime_actuation_reviewed_no_runtime_start",
        summary=summary,
        gaps=[],
    )
    receipt = _write_receipt(tmp_path, summary)

    report = build_h3_goal_emission_runtime_production_runtime_receipt_gate(
        production_runtime_actuation_gate_path=actuation_gate,
        agent_root=tmp_path,
        production_runtime_receipt_path=receipt,
    )

    receipt_summary = report["runtime_production_receipt_surface"]["production_runtime_receipt_summary"]
    assert report["passed"] is True
    assert report["readiness"]["decision"] == "production_runtime_receipt_reviewed_no_receipt_write"
    assert report["readiness"]["production_runtime_receipt_ready"] is False
    assert receipt_summary["receipt_sha256"] == hashlib.sha256(receipt.read_bytes()).hexdigest()
    assert report["metrics"]["production_runtime_receipt_gap_count"] == 0


def test_receipt_fails_closed_on_local_receipt_source(tmp_path: Path) -> None:
    summary = _actuation_summary("relation_repair_relapse")
    actuation_gate = _write_actuation_gate_report(
        tmp_path,
        decision="production_runtime_actuation_reviewed_no_runtime_start",
        summary=summary,
        gaps=[],
    )
    receipt = _write_receipt(tmp_path, summary, source="local_runtime_receipt_fixture")

    report = build_h3_goal_emission_runtime_production_runtime_receipt_gate(
        production_runtime_actuation_gate_path=actuation_gate,
        agent_root=tmp_path,
        production_runtime_receipt_path=receipt,
    )

    assert report["passed"] is False
    assert report["checks"]["production_runtime_receipt_sources_production"] is False
    assert report["runtime_production_receipt_boundary"]["production_runtime_receipt_write_allowed"] is False


def test_receipt_fails_closed_on_actuation_boundary_regression(tmp_path: Path) -> None:
    actuation_gate = _write_actuation_gate_report(
        tmp_path,
        decision="production_runtime_actuation_blocked_upstream_execution",
        boundary={"production_runtime_receipt_allowed": True},
    )

    report = build_h3_goal_emission_runtime_production_runtime_receipt_gate(
        production_runtime_actuation_gate_path=actuation_gate,
        agent_root=tmp_path,
    )

    assert report["passed"] is False
    assert report["checks"]["production_runtime_actuation_boundary_production_runtime_receipt_allowed_false"] is False


def test_receipt_fails_closed_when_receipt_arrives_before_actuation_review(tmp_path: Path) -> None:
    summary = _actuation_summary("post_delivery_dispute")
    actuation_gate = _write_actuation_gate_report(
        tmp_path,
        decision="production_runtime_actuation_blocked_upstream_execution",
        summary=summary,
    )
    receipt = _write_receipt(tmp_path, summary)

    report = build_h3_goal_emission_runtime_production_runtime_receipt_gate(
        production_runtime_actuation_gate_path=actuation_gate,
        agent_root=tmp_path,
        production_runtime_receipt_path=receipt,
    )

    assert report["passed"] is False
    assert report["checks"]["production_runtime_receipt_requires_actuation_review"] is False


def _write_actuation_gate_report(
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
        "production_runtime_actuation_review_allowed": True,
        "production_runtime_actuation_allowed": False,
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
        "production_runtime_actuation_evaluated": True,
        "production_runtime_actuation_artifact_present": bool(summary),
        "production_runtime_actuation_artifact_complete": bool(summary) and not gaps,
        "production_runtime_actuation_ready": False,
        "production_runtime_execution_ready": False,
        "production_runtime_receipt_ready": False,
        "decision": decision,
    }
    default_readiness.update(readiness or {})
    default_gaps = gaps if gaps is not None else [_actuation_gap()]
    path = tmp_path / "h3_goal_emission_runtime_production_runtime_actuation_gate.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": "h3-goal-emission-runtime-production-runtime-actuation-gate:v1",
                "passed": True,
                "failure_reasons": [],
                "readiness": default_readiness,
                "runtime_production_actuation_boundary": default_boundary,
                "runtime_production_actuation_surface": {
                    "mode": "production_runtime_actuation_review_only_no_runtime",
                    "production_runtime_actuation_summary": summary or {},
                    "production_runtime_actuation_gaps": default_gaps,
                },
                "non_claims": non_claims
                if non_claims is not None
                else [
                    "does_not_treat_runtime_actuation_review_as_runtime_start",
                    "does_not_start_runtime_or_agent_loop",
                    "does_not_mutate_iem_or_normative_state",
                ],
            }
        ),
        encoding="utf-8",
    )
    return path


def _actuation_summary(event_kind: str) -> dict:
    goal_id = f"h3-draft-goal:{event_kind}:alpha"
    actuation_sha256 = hashlib.sha256(f"actuation:{goal_id}".encode("utf-8")).hexdigest()
    return {
        "state": "production_runtime_actuation_reviewed_no_runtime_start",
        "actuation_path": f"/actuation/{goal_id}.json",
        "actuation_sha256": actuation_sha256,
        "actuation_record_count": 1,
        "actuation_goal_ids": [goal_id],
        "actuation_refs": [f"production-runtime-actuation:{goal_id}"],
        "production_runtime_actuation_ready": False,
        "production_runtime_execution_ready": False,
        "production_runtime_receipt_ready": False,
    }


def _actuation_gap() -> dict:
    return {
        "goal_id": "h3-draft-goal:post_delivery_failure:alpha",
        "state": "production_runtime_actuation_blocked_by_execution_gap",
        "gap_reason": "production runtime execution has not been reviewed",
    }


def _write_receipt(
    tmp_path: Path,
    actuation_summary: dict,
    *,
    source: str = "h3_production_runtime_receipt_board",
) -> Path:
    goal_id = actuation_summary["actuation_goal_ids"][0]
    path = tmp_path / "h3_goal_emission_runtime_production_runtime_receipt.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": "h3-goal-emission-runtime-production-runtime-receipt:v1",
                "production_runtime_receipt_records": [
                    {
                        "receipt_id": f"production-runtime-receipt:{goal_id}",
                        "goal_id": goal_id,
                        "runtime_executor": "h3-production-runtime-executor",
                        "runtime_executor_role": "production_runtime_executor",
                        "source": source,
                        "status": "verified",
                        "attestation_ref": f"runtime-receipt-attestation:{goal_id}",
                        "runtime_actuation_ref": actuation_summary["actuation_path"],
                        "runtime_actuation_sha256": actuation_summary["actuation_sha256"],
                        "runtime_start_ref": f"runtime-start:{goal_id}",
                        "runtime_process_ref": f"runtime-process:{goal_id}",
                        "started_at_ref": f"started-at:{goal_id}",
                        "health_probe_ref": f"health-probe:{goal_id}",
                        "audit_sink_ref": f"audit-sink:{goal_id}",
                        "receipt_sink_ref": f"receipt-sink:{goal_id}",
                        "production_runtime_receipt_write_allowed": False,
                        "production_runtime_execution_allowed": False,
                        "agent_loop_start_allowed": False,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return path