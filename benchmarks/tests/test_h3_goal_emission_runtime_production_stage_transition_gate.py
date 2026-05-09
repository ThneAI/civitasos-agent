from __future__ import annotations

import json
from pathlib import Path

from benchmarks.h3_goal_emission_runtime_production_stage_transition_gate import (
    build_h3_goal_emission_runtime_production_stage_transition_gate,
)


def test_stage_transition_reports_not_ready_at_round_two_without_runtime(tmp_path: Path) -> None:
    paths = _write_transition_chain(tmp_path)

    report = build_h3_goal_emission_runtime_production_stage_transition_gate(agent_root=tmp_path, **paths)

    assert report["passed"] is True
    assert report["readiness"]["decision"] == "not_ready_for_next_stage"
    assert report["readiness"]["next_stage_ready"] is False
    assert report["readiness"]["next_blocking_round"] == 2
    assert report["runtime_production_stage_transition_boundary"]["production_runtime_execution_allowed"] is False
    assert report["metrics"]["production_runtime_receipt_write_ready_count"] == 0
    open_nodes = {item["node"] for item in report["runtime_production_stage_transition_surface"]["open_requirements"]}
    assert "production_evidence_submission_manifest" in open_nodes
    assert "production_evidence_bundle_review" in open_nodes
    assert "production_runtime_receipt" in open_nodes


def test_stage_transition_blocks_complete_chain_without_bundle_review(tmp_path: Path) -> None:
    paths = _write_transition_chain(tmp_path, complete=True)

    report = build_h3_goal_emission_runtime_production_stage_transition_gate(agent_root=tmp_path, **paths)

    assert report["passed"] is True
    assert report["readiness"]["decision"] == "not_ready_for_next_stage"
    assert report["readiness"]["next_stage_ready"] is False
    assert report["readiness"]["next_blocking_round"] == 2
    assert report["metrics"]["stage_transition_open_requirement_count"] == 1
    node = report["runtime_production_stage_transition_surface"]["stage_nodes"]["production_evidence_bundle_review"]
    assert node["complete"] is False
    assert node["decision"] == "h3_production_evidence_bundle_blocked_pending_review"
    assert report["runtime_production_stage_transition_boundary"]["production_runtime_execution_allowed"] is False
    assert report["runtime_production_stage_transition_boundary"]["production_runtime_receipt_write_allowed"] is False


def test_stage_transition_reviews_complete_chain_with_bundle_review_without_starting_runtime(tmp_path: Path) -> None:
    paths = _write_transition_chain(tmp_path, complete=True)
    paths["production_evidence_bundle_review_path"] = _write_bundle_review(tmp_path)

    report = build_h3_goal_emission_runtime_production_stage_transition_gate(agent_root=tmp_path, **paths)

    assert report["passed"] is True
    assert report["readiness"]["decision"] == "ready_for_production_runtime_stage_review_no_runtime_start"
    assert report["readiness"]["next_stage_ready"] is True
    assert report["readiness"]["completed_rounds"] == [1, 2, 3, 4, 5]
    assert report["metrics"]["stage_transition_open_requirement_count"] == 0
    assert report["runtime_production_stage_transition_boundary"]["production_runtime_execution_allowed"] is False
    assert report["runtime_production_stage_transition_boundary"]["production_runtime_receipt_write_allowed"] is False
    assert report["metrics"]["agent_loop_start_ready_count"] == 0


def test_stage_transition_accepts_pending_bundle_report_as_round_two_gap(tmp_path: Path) -> None:
    paths = _write_transition_chain(tmp_path, complete=True)
    paths["production_evidence_bundle_review_path"] = _write_bundle_review(tmp_path, complete=False)

    report = build_h3_goal_emission_runtime_production_stage_transition_gate(agent_root=tmp_path, **paths)

    assert report["passed"] is True
    assert report["readiness"]["decision"] == "not_ready_for_next_stage"
    assert report["readiness"]["next_blocking_round"] == 2
    node = report["runtime_production_stage_transition_surface"]["stage_nodes"]["production_evidence_bundle_review"]
    assert node["passed"] is True
    assert node["complete"] is False
    assert node["gap_count"] >= 1


def test_stage_transition_fails_closed_on_invalid_bundle_report(tmp_path: Path) -> None:
    paths = _write_transition_chain(tmp_path, complete=True)
    paths["production_evidence_bundle_review_path"] = _write_bundle_review(tmp_path, passed=False, complete=False)

    report = build_h3_goal_emission_runtime_production_stage_transition_gate(agent_root=tmp_path, **paths)

    assert report["passed"] is False
    assert report["checks"]["production_evidence_bundle_review_passed"] is False
    assert report["readiness"]["decision"] == "blocked_before_production_stage_transition_review"


def test_stage_transition_fails_closed_on_forged_complete_bundle_review(tmp_path: Path) -> None:
    paths = _write_transition_chain(tmp_path, complete=True)
    paths["production_evidence_bundle_review_path"] = _write_bundle_review(tmp_path, require_bundle=False)

    report = build_h3_goal_emission_runtime_production_stage_transition_gate(agent_root=tmp_path, **paths)

    assert report["passed"] is False
    assert report["checks"]["production_evidence_bundle_review_complete_report_valid"] is False
    assert report["readiness"]["decision"] == "blocked_before_production_stage_transition_review"


def test_stage_transition_fails_closed_on_runtime_flag_regression(tmp_path: Path) -> None:
    paths = _write_transition_chain(tmp_path)
    receipt_gate_path = paths["production_runtime_receipt_gate_path"]
    receipt_gate = json.loads(receipt_gate_path.read_text(encoding="utf-8"))
    receipt_gate["runtime_boundary"]["production_runtime_receipt_write_allowed"] = True
    receipt_gate_path.write_text(json.dumps(receipt_gate), encoding="utf-8")

    report = build_h3_goal_emission_runtime_production_stage_transition_gate(agent_root=tmp_path, **paths)

    assert report["passed"] is False
    assert report["checks"]["production_runtime_receipt_runtime_flags_safe"] is False
    assert report["readiness"]["decision"] == "blocked_before_production_stage_transition_review"


def test_stage_transition_fails_closed_on_missing_node(tmp_path: Path) -> None:
    paths = _write_transition_chain(tmp_path)
    paths["production_runtime_actuation_gate_path"].unlink()

    report = build_h3_goal_emission_runtime_production_stage_transition_gate(agent_root=tmp_path, **paths)

    assert report["passed"] is False
    assert report["checks"]["production_runtime_actuation_present"] is False
    assert report["runtime_production_stage_transition_surface"]["stage_nodes"]["production_runtime_actuation"]["complete"] is False


def _write_transition_chain(tmp_path: Path, *, complete: bool = False) -> dict[str, Path]:
    manifest = _write_report(
        tmp_path,
        "h3_goal_emission_runtime_production_evidence_submission_manifest.json",
        schema="h3-goal-emission-runtime-production-evidence-submission-manifest:v1",
        decision="production_evidence_submission_manifest_reviewed_no_runtime_execution" if complete else "production_evidence_submission_manifest_blocked_pending_submission",
        readiness={"production_evidence_submission_manifest_complete": complete},
        surface_key="runtime_production_evidence_submission_manifest_surface",
        gap_state="production_evidence_submission_manifest_gap",
    )
    authorization = _write_report(
        tmp_path,
        "h3_goal_emission_runtime_production_execution_authorization_gate.json",
        schema="h3-goal-emission-runtime-production-execution-authorization-gate:v1",
        decision="production_execution_authorization_reviewed_no_runtime_execution" if complete else "production_execution_authorization_blocked_pending_submission_manifest",
        readiness={"production_execution_authorization_complete": complete},
        surface_key="runtime_production_execution_authorization_surface",
        gap_state="production_execution_authorization_blocked_by_submission_manifest_gap",
    )
    goal_alignment = _write_report(
        tmp_path,
        "h3_goal_emission_runtime_production_goal_alignment_gate.json",
        schema="h3-goal-emission-runtime-production-goal-alignment-gate:v1",
        decision="production_goal_alignment_preserved_requires_executor_permission_layer" if complete else "production_goal_alignment_preserved_upstream_blocked",
        readiness={"production_goal_alignment_preserved": True},
        surface_key="runtime_production_goal_alignment_surface",
        gap_state="production_execution_authorization_gap",
    )
    permission = _write_report(
        tmp_path,
        "h3_goal_emission_runtime_production_executor_permission_gate.json",
        schema="h3-goal-emission-runtime-production-executor-permission-gate:v1",
        decision="production_executor_permission_reviewed_no_runtime_execution" if complete else "production_executor_permission_blocked_upstream_goal_alignment",
        readiness={"production_executor_permission_complete": complete},
        surface_key="runtime_production_executor_permission_surface",
        gap_state="production_executor_permission_blocked_by_goal_alignment_gap",
    )
    handoff = _write_report(
        tmp_path,
        "h3_goal_emission_runtime_production_runtime_execution_handoff_gate.json",
        schema="h3-goal-emission-runtime-production-runtime-execution-handoff-gate:v1",
        decision="production_runtime_execution_handoff_reviewed_no_runtime_execution" if complete else "production_runtime_execution_handoff_blocked_upstream_executor_permission",
        readiness={"production_runtime_execution_handoff_complete": complete},
        surface_key="runtime_production_execution_handoff_surface",
        gap_state="production_runtime_execution_handoff_blocked_by_permission_gap",
    )
    execution = _write_report(
        tmp_path,
        "h3_goal_emission_runtime_production_runtime_execution_gate.json",
        schema="h3-goal-emission-runtime-production-runtime-execution-gate:v1",
        decision="production_runtime_execution_reviewed_no_runtime_start" if complete else "production_runtime_execution_blocked_upstream_handoff",
        readiness={"production_runtime_execution_artifact_complete": complete},
        surface_key="runtime_production_execution_surface",
        gap_state="production_runtime_execution_blocked_by_handoff_gap",
    )
    actuation = _write_report(
        tmp_path,
        "h3_goal_emission_runtime_production_runtime_actuation_gate.json",
        schema="h3-goal-emission-runtime-production-runtime-actuation-gate:v1",
        decision="production_runtime_actuation_reviewed_no_runtime_start" if complete else "production_runtime_actuation_blocked_upstream_execution",
        readiness={"production_runtime_actuation_artifact_complete": complete},
        surface_key="runtime_production_actuation_surface",
        gap_state="production_runtime_actuation_blocked_by_execution_gap",
    )
    receipt = _write_report(
        tmp_path,
        "h3_goal_emission_runtime_production_runtime_receipt_gate.json",
        schema="h3-goal-emission-runtime-production-runtime-receipt-gate:v1",
        decision="production_runtime_receipt_reviewed_no_receipt_write" if complete else "production_runtime_receipt_blocked_upstream_actuation",
        readiness={"production_runtime_receipt_artifact_complete": complete},
        surface_key="runtime_production_receipt_surface",
        gap_state="production_runtime_receipt_blocked_by_actuation_gap",
    )
    return {
        "production_evidence_submission_manifest_path": manifest,
        "production_execution_authorization_gate_path": authorization,
        "production_goal_alignment_gate_path": goal_alignment,
        "production_executor_permission_gate_path": permission,
        "production_runtime_execution_handoff_gate_path": handoff,
        "production_runtime_execution_gate_path": execution,
        "production_runtime_actuation_gate_path": actuation,
        "production_runtime_receipt_gate_path": receipt,
    }


def _write_bundle_review(
    tmp_path: Path,
    *,
    passed: bool = True,
    complete: bool = True,
    require_bundle: bool = True,
) -> Path:
    path = tmp_path / "h3_production_bundle_review.json"
    decision = (
        "h3_production_evidence_bundle_review_complete_no_runtime_execution"
        if complete
        else "h3_production_evidence_bundle_blocked_pending_review"
    )
    path.write_text(
        json.dumps(
            {
                "schema_version": "h3-production-evidence-bundle-review-runner:v1",
                "passed": passed,
                "review_state": "bundle_validation_passed" if complete else "blocked_pending_production_evidence_bundle",
                "failure_reasons": [] if passed else ["bundle validation failed"],
                "require_bundle": require_bundle,
                "bundle_inputs_present": complete,
                "inputs": {
                    "round2_submission": str(tmp_path / "production_evidence_submission.json") if complete else None,
                    "anchor": str(tmp_path / "l2_external_anchor.json") if complete else None,
                    "verification": str(tmp_path / "l2_external_anchor_verification.json") if complete else None,
                },
                "readiness": {
                    "decision": decision,
                    "production_evidence_bundle_review_complete": complete,
                    "production_runtime_execution_allowed": False,
                    "production_runtime_receipt_allowed": False,
                },
                "bundle_report": _bundle_validation_report(tmp_path) if complete else None,
                "non_claims": [
                    "does_not_start_runtime_or_agent_loop",
                    "does_not_authorize_production_runtime_execution",
                    "bundle_validation_does_not_replace_governance_acceptance",
                ],
            }
        ),
        encoding="utf-8",
    )
    return path


def _bundle_validation_report(tmp_path: Path) -> dict:
    return {
        "schema_version": "h3-production-evidence-bundle-validation-report:v1",
        "passed": True,
        "failure_reasons": [],
        "checks": {
            "round2_submission_passed": True,
            "round2_readiness_complete": True,
            "l2_anchor_passed": True,
            "l2_anchor_verification_passed": True,
            "round2_single_goal_present": True,
            "anchor_goal_matches_round2_goal": True,
            "goal_id_matches_requested": True,
            "anchor_artifact_type_supported": True,
            "artifact_hash_bound_to_round2_submission": True,
            "verification_artifact_hash_bound_to_round2_submission": True,
            "verification_anchor_hash_bound_to_anchor_record": True,
            "runtime_execution_not_authorized": True,
        },
        "inputs": {
            "round2_submission_path": str(tmp_path / "production_evidence_submission.json"),
            "anchor_path": str(tmp_path / "l2_external_anchor.json"),
            "verification_path": str(tmp_path / "l2_external_anchor_verification.json"),
        },
        "readiness": {
            "decision": "h3_production_evidence_bundle_review_no_runtime_execution",
            "production_evidence_bundle_hash_chain_complete": True,
            "production_runtime_execution_allowed": False,
            "production_runtime_receipt_allowed": False,
        },
    }


def _write_report(
    tmp_path: Path,
    filename: str,
    *,
    schema: str,
    decision: str,
    readiness: dict,
    surface_key: str,
    gap_state: str,
) -> Path:
    path = tmp_path / filename
    complete = any(value is True for value in readiness.values()) and "blocked" not in decision and "pending" not in decision
    gap_list = [] if complete else [{"state": gap_state, "gap_reason": "upstream production artifact is not reviewed"}]
    path.write_text(
        json.dumps(
            {
                "schema_version": schema,
                "passed": True,
                "failure_reasons": [],
                "readiness": {
                    **readiness,
                    "decision": decision,
                    "production_runtime_execution_ready": False,
                    "production_runtime_actuation_ready": False,
                    "production_runtime_receipt_ready": False,
                },
                surface_key: {
                    "mode": "review_only_no_runtime",
                    "gaps": gap_list,
                },
                "runtime_boundary": {
                    "artifact_only": True,
                    "production_runtime_execution_allowed": False,
                    "production_runtime_actuation_allowed": False,
                    "production_runtime_receipt_allowed": False,
                    "production_runtime_receipt_write_allowed": False,
                    "agent_loop_start_allowed": False,
                    "llm_planning_allowed": False,
                    "external_system_mutation_allowed": False,
                    "iem_value_mutation_allowed": False,
                    "normative_local_mutation_allowed": False,
                },
                "non_claims": [
                    "does_not_start_runtime_or_agent_loop",
                    "does_not_mutate_iem_or_normative_state",
                ],
            }
        ),
        encoding="utf-8",
    )
    return path
