from __future__ import annotations

import hashlib
import json
from pathlib import Path

from benchmarks.h3_goal_emission_runtime_production_execution_authorization_gate import (
    build_h3_goal_emission_runtime_production_execution_authorization_gate,
)


def test_authorization_waits_for_submission_manifest_without_runtime_permission(tmp_path: Path) -> None:
    manifest = _write_submission_manifest_report(tmp_path, manifest={}, gaps=[_manifest_gap("post_delivery_failure")])

    report = build_h3_goal_emission_runtime_production_execution_authorization_gate(
        production_evidence_submission_manifest_path=manifest,
        agent_root=tmp_path,
    )

    assert report["passed"] is True
    assert report["readiness"]["decision"] == "production_execution_authorization_blocked_pending_submission_manifest"
    assert report["readiness"]["production_execution_authorization_present"] is False
    assert report["runtime_production_execution_authorization_boundary"]["production_runtime_execution_allowed"] is False
    assert report["metrics"]["production_execution_authorization_gap_count"] == 1


def test_authorization_waits_for_independent_authorization_after_complete_manifest(tmp_path: Path) -> None:
    source_manifest = _complete_manifest("economic_deviation")
    manifest = _write_submission_manifest_report(tmp_path, manifest=source_manifest, gaps=[])

    report = build_h3_goal_emission_runtime_production_execution_authorization_gate(
        production_evidence_submission_manifest_path=manifest,
        agent_root=tmp_path,
    )

    assert report["passed"] is True
    assert report["readiness"]["decision"] == "production_execution_authorization_blocked_pending_authorization_artifact"
    gap = report["runtime_production_execution_authorization_surface"]["production_execution_authorization_gaps"][0]
    assert gap["missing_authorization_goal_ids"] == ["h3-draft-goal:economic_deviation:alpha"]
    assert report["readiness"]["production_runtime_execution_ready"] is False


def test_authorization_reviews_complete_authorization_without_runtime_permission(tmp_path: Path) -> None:
    source_manifest = _complete_manifest("governance_rollback")
    manifest = _write_submission_manifest_report(tmp_path, manifest=source_manifest, gaps=[])
    authorization = _write_authorization(tmp_path, source_manifest)

    report = build_h3_goal_emission_runtime_production_execution_authorization_gate(
        production_evidence_submission_manifest_path=manifest,
        agent_root=tmp_path,
        production_execution_authorization_path=authorization,
    )

    summary = report["runtime_production_execution_authorization_surface"]["production_execution_authorization_summary"]
    assert report["passed"] is True
    assert report["readiness"]["decision"] == "production_execution_authorization_reviewed_no_runtime_execution"
    assert report["readiness"]["production_runtime_execution_ready"] is False
    assert summary["authorization_sha256"] == hashlib.sha256(authorization.read_bytes()).hexdigest()
    assert summary["source_manifest_sha256"] == source_manifest["submission_sha256"]
    assert report["metrics"]["production_execution_authorization_gap_count"] == 0


def test_authorization_fails_closed_on_local_authorization_source(tmp_path: Path) -> None:
    source_manifest = _complete_manifest("relation_repair_relapse")
    manifest = _write_submission_manifest_report(tmp_path, manifest=source_manifest, gaps=[])
    authorization = _write_authorization(tmp_path, source_manifest, source="local_authorization_fixture")

    report = build_h3_goal_emission_runtime_production_execution_authorization_gate(
        production_evidence_submission_manifest_path=manifest,
        agent_root=tmp_path,
        production_execution_authorization_path=authorization,
    )

    assert report["passed"] is False
    assert report["checks"]["production_execution_authorization_sources_production"] is False
    assert report["runtime_production_execution_authorization_boundary"]["production_runtime_execution_allowed"] is False


def test_authorization_fails_closed_on_manifest_hash_mismatch(tmp_path: Path) -> None:
    source_manifest = _complete_manifest("post_delivery_dispute")
    manifest = _write_submission_manifest_report(tmp_path, manifest=source_manifest, gaps=[])
    authorization = _write_authorization(tmp_path, source_manifest, manifest_sha256="0" * 64)

    report = build_h3_goal_emission_runtime_production_execution_authorization_gate(
        production_evidence_submission_manifest_path=manifest,
        agent_root=tmp_path,
        production_execution_authorization_path=authorization,
    )

    assert report["passed"] is False
    assert report["checks"]["production_execution_authorization_records_match_manifest_sha256"] is False


def test_authorization_fails_closed_on_manifest_boundary_regression(tmp_path: Path) -> None:
    source_manifest = _complete_manifest("post_delivery_failure")
    manifest = _write_submission_manifest_report(
        tmp_path,
        manifest=source_manifest,
        gaps=[],
        boundary={"production_runtime_execution_allowed": True},
    )

    report = build_h3_goal_emission_runtime_production_execution_authorization_gate(
        production_evidence_submission_manifest_path=manifest,
        agent_root=tmp_path,
    )

    assert report["passed"] is False
    assert report["checks"]["production_evidence_submission_manifest_boundary_production_runtime_execution_allowed_false"] is False


def _write_submission_manifest_report(
    tmp_path: Path,
    *,
    manifest: dict,
    gaps: list[dict],
    boundary: dict | None = None,
) -> Path:
    default_boundary = {
        "artifact_only": True,
        "production_evidence_submission_manifest_allowed": bool(manifest),
        "production_evidence_truth_validation_allowed": False,
        "valid_production_evidence_record_generation_allowed": False,
        "production_evidence_ingestion_allowed": False,
        "production_evidence_forwarding_allowed": False,
        "production_runtime_execution_allowed": False,
        "production_runtime_receipt_allowed": False,
        "agent_loop_start_allowed": False,
        "llm_planning_allowed": False,
        "external_system_mutation_allowed": False,
        "iem_value_mutation_allowed": False,
        "normative_local_mutation_allowed": False,
    }
    default_boundary.update(boundary or {})
    decision = "production_evidence_submission_manifest_reviewed_no_runtime_execution" if manifest and not gaps else "production_evidence_submission_manifest_blocked_pending_submission"
    path = tmp_path / "h3_goal_emission_runtime_production_evidence_submission_manifest.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": "h3-goal-emission-runtime-production-evidence-submission-manifest:v1",
                "passed": True,
                "failure_reasons": [],
                "readiness": {
                    "production_evidence_submission_manifest_evaluated": True,
                    "production_evidence_submission_manifest_present": bool(manifest),
                    "production_evidence_submission_manifest_complete": bool(manifest) and not gaps,
                    "production_runtime_execution_ready": False,
                    "production_runtime_receipt_ready": False,
                    "decision": decision,
                },
                "runtime_production_evidence_submission_manifest_boundary": default_boundary,
                "runtime_production_evidence_submission_manifest_surface": {
                    "mode": "production_evidence_submission_manifest_only_no_runtime",
                    "production_evidence_submission_manifest": manifest,
                    "production_evidence_submission_manifest_gap_count": len(gaps),
                    "production_evidence_submission_manifest_gaps": gaps,
                },
            }
        ),
        encoding="utf-8",
    )
    return path


def _complete_manifest(event_kind: str) -> dict:
    goal_id = f"h3-draft-goal:{event_kind}:alpha"
    return {
        "state": "production_evidence_submission_manifest_reviewed_no_runtime_execution",
        "submission_path": f"/evidence/{goal_id}.json",
        "submission_sha256": hashlib.sha256(goal_id.encode("utf-8")).hexdigest(),
        "submission_schema_version": "h3-goal-emission-runtime-production-evidence:v1",
        "submitted_record_count": 16,
        "submitted_goal_ids": [goal_id],
        "submitted_evidence_kinds": ["external_human_review_approval", "governance_runtime_execution_approval"],
        "production_runtime_execution_ready": False,
        "production_runtime_receipt_ready": False,
    }


def _manifest_gap(event_kind: str) -> dict:
    return {
        "goal_id": f"h3-draft-goal:{event_kind}:alpha",
        "state": "production_evidence_submission_manifest_gap",
        "gap_reason": "production evidence submission artifact is absent",
        "missing_production_evidence_kinds": ["external_human_review_approval"],
    }


def _write_authorization(
    tmp_path: Path,
    manifest: dict,
    *,
    source: str = "h3_production_control_board",
    manifest_sha256: str | None = None,
) -> Path:
    goal_id = manifest["submitted_goal_ids"][0]
    path = tmp_path / "h3_goal_emission_runtime_production_execution_authorization.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": "h3-goal-emission-runtime-production-execution-authorization:v1",
                "production_execution_authorization_records": [
                    {
                        "authorization_id": f"production-execution-authorization:{goal_id}",
                        "goal_id": goal_id,
                        "authorizer": "h3-production-execution-board",
                        "authorizer_role": "production_execution_authority",
                        "source": source,
                        "status": "authorized",
                        "attestation_ref": f"authorization-attestation:{goal_id}",
                        "manifest_ref": manifest["submission_path"],
                        "manifest_sha256": manifest_sha256 or manifest["submission_sha256"],
                        "change_ticket_ref": f"change-ticket:{goal_id}",
                        "dual_operator_ack_ref": f"dual-operator-ack:{goal_id}",
                        "kill_switch_ref": f"kill-switch:{goal_id}",
                        "rollback_checkpoint_ref": f"rollback-checkpoint:{goal_id}",
                        "monitoring_green_ref": f"monitoring-green:{goal_id}",
                        "audit_sink_ref": f"audit-sink:{goal_id}",
                        "production_runtime_execution_allowed": False,
                        "production_runtime_receipt_allowed": False,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return path