from __future__ import annotations

import json
from pathlib import Path

from benchmarks.h3_goal_emission_runtime_production_goal_alignment_gate import (
    NORTH_STAR_VALUES,
    build_h3_goal_emission_runtime_production_goal_alignment_gate,
)


def test_alignment_preserves_blocked_pending_authorization_without_runtime_permission(tmp_path: Path) -> None:
    authorization_gate = _write_authorization_gate_report(tmp_path, decision="production_execution_authorization_blocked_pending_submission_manifest")

    report = build_h3_goal_emission_runtime_production_goal_alignment_gate(
        production_execution_authorization_gate_path=authorization_gate,
        agent_root=tmp_path,
    )

    assert report["passed"] is True
    assert report["readiness"]["decision"] == "production_goal_alignment_preserved_upstream_blocked"
    assert report["readiness"]["production_executor_permission_ready"] is False
    assert report["runtime_production_goal_alignment_boundary"]["production_runtime_execution_allowed"] is False
    assert report["metrics"]["north_star_value_present_count"] == len(NORTH_STAR_VALUES)


def test_alignment_preserves_reviewed_authorization_but_requires_future_executor_permission(tmp_path: Path) -> None:
    authorization_gate = _write_authorization_gate_report(
        tmp_path,
        decision="production_execution_authorization_reviewed_no_runtime_execution",
        summary={
            "state": "production_execution_authorization_reviewed_no_runtime_execution",
            "authorized_goal_ids": ["h3-draft-goal:economic_deviation:alpha"],
            "production_runtime_execution_ready": False,
            "production_runtime_receipt_ready": False,
        },
        gaps=[],
    )

    report = build_h3_goal_emission_runtime_production_goal_alignment_gate(
        production_execution_authorization_gate_path=authorization_gate,
        agent_root=tmp_path,
    )

    assert report["passed"] is True
    assert report["readiness"]["decision"] == "production_goal_alignment_preserved_requires_executor_permission_layer"
    assert report["runtime_production_goal_alignment_boundary"]["production_executor_permission_allowed"] is False
    assert report["runtime_production_goal_alignment_surface"]["goal_alignment_state"] == "aligned_but_runtime_blocked"


def test_alignment_fails_closed_on_authorization_runtime_boundary_regression(tmp_path: Path) -> None:
    authorization_gate = _write_authorization_gate_report(
        tmp_path,
        decision="production_execution_authorization_blocked_pending_submission_manifest",
        boundary={"production_runtime_execution_allowed": True},
    )

    report = build_h3_goal_emission_runtime_production_goal_alignment_gate(
        production_execution_authorization_gate_path=authorization_gate,
        agent_root=tmp_path,
    )

    assert report["passed"] is False
    assert report["checks"]["production_execution_authorization_boundary_production_runtime_execution_allowed_false"] is False


def test_alignment_fails_closed_on_authorization_readiness_regression(tmp_path: Path) -> None:
    authorization_gate = _write_authorization_gate_report(
        tmp_path,
        decision="production_execution_authorization_reviewed_no_runtime_execution",
        readiness={"production_runtime_execution_ready": True},
    )

    report = build_h3_goal_emission_runtime_production_goal_alignment_gate(
        production_execution_authorization_gate_path=authorization_gate,
        agent_root=tmp_path,
    )

    assert report["passed"] is False
    assert report["checks"]["production_execution_authorization_execution_blocked"] is False


def test_alignment_fails_closed_when_upstream_non_claims_disappear(tmp_path: Path) -> None:
    authorization_gate = _write_authorization_gate_report(
        tmp_path,
        decision="production_execution_authorization_blocked_pending_submission_manifest",
        non_claims=["does_not_start_runtime_or_agent_loop"],
    )

    report = build_h3_goal_emission_runtime_production_goal_alignment_gate(
        production_execution_authorization_gate_path=authorization_gate,
        agent_root=tmp_path,
    )

    assert report["passed"] is False
    assert report["checks"]["production_execution_authorization_non_claims_preserved"] is False


def _write_authorization_gate_report(
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
        "production_execution_authorization_review_allowed": True,
        "production_execution_authorization_runtime_permission_allowed": False,
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
        "production_execution_authorization_evaluated": True,
        "production_execution_authorization_present": bool(summary),
        "production_execution_authorization_complete": bool(summary) and not gaps,
        "production_runtime_execution_ready": False,
        "production_runtime_receipt_ready": False,
        "decision": decision,
    }
    default_readiness.update(readiness or {})
    default_gaps = gaps if gaps is not None else [_authorization_gap()]
    path = tmp_path / "h3_goal_emission_runtime_production_execution_authorization_gate.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": "h3-goal-emission-runtime-production-execution-authorization-gate:v1",
                "passed": True,
                "failure_reasons": [],
                "readiness": default_readiness,
                "runtime_production_execution_authorization_boundary": default_boundary,
                "runtime_production_execution_authorization_surface": {
                    "mode": "production_execution_authorization_review_only_no_runtime",
                    "production_execution_authorization_summary": summary or {},
                    "production_execution_authorization_gaps": default_gaps,
                },
                "non_claims": non_claims
                if non_claims is not None
                else [
                    "does_not_validate_evidence_truth_or_attestation_authenticity",
                    "does_not_treat_authorization_review_as_runtime_execution_permission",
                    "does_not_mutate_iem_or_normative_state",
                ],
            }
        ),
        encoding="utf-8",
    )
    return path


def _authorization_gap() -> dict:
    return {
        "goal_id": "h3-draft-goal:post_delivery_failure:alpha",
        "state": "production_execution_authorization_blocked_by_submission_manifest_gap",
        "gap_reason": "production evidence submission manifest is incomplete",
    }