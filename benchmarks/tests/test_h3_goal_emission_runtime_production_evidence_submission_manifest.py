from __future__ import annotations

import hashlib
import json
from pathlib import Path

from benchmarks.h3_goal_emission_runtime_production_evidence_gate import (
    PRODUCTION_EVIDENCE_KIND_REF_FIELDS,
    REQUIRED_PRODUCTION_EVIDENCE_KINDS,
)
from benchmarks.h3_goal_emission_runtime_production_evidence_submission_manifest import (
    build_h3_goal_emission_runtime_production_evidence_submission_manifest,
)


def test_manifest_waits_for_real_submission_without_runtime_permission(tmp_path: Path) -> None:
    template = _write_template_report(tmp_path, [_template_packet("post_delivery_failure")])

    report = build_h3_goal_emission_runtime_production_evidence_submission_manifest(
        production_evidence_submission_template_path=template,
        agent_root=tmp_path,
    )

    assert report["passed"] is True
    assert report["readiness"]["decision"] == "production_evidence_submission_manifest_blocked_pending_submission"
    assert report["readiness"]["production_evidence_submission_manifest_present"] is False
    assert report["runtime_production_evidence_submission_manifest_boundary"]["production_runtime_execution_allowed"] is False
    assert report["metrics"]["production_evidence_submission_manifest_gap_count"] == 1
    assert report["metrics"]["missing_template_evidence_item_count"] == len(REQUIRED_PRODUCTION_EVIDENCE_KINDS)


def test_manifest_reviews_complete_submission_hash_without_runtime_permission(tmp_path: Path) -> None:
    packet = _template_packet("economic_deviation")
    template = _write_template_report(tmp_path, [packet])
    submission = _write_submission(tmp_path, packet["goal_id"])

    report = build_h3_goal_emission_runtime_production_evidence_submission_manifest(
        production_evidence_submission_template_path=template,
        agent_root=tmp_path,
        production_evidence_submission_path=submission,
    )

    manifest = report["runtime_production_evidence_submission_manifest_surface"]["production_evidence_submission_manifest"]
    assert report["passed"] is True
    assert report["readiness"]["decision"] == "production_evidence_submission_manifest_reviewed_no_runtime_execution"
    assert report["readiness"]["production_runtime_execution_ready"] is False
    assert manifest["submission_sha256"] == hashlib.sha256(submission.read_bytes()).hexdigest()
    assert manifest["submitted_record_count"] == len(REQUIRED_PRODUCTION_EVIDENCE_KINDS)
    assert report["metrics"]["production_evidence_submission_manifest_gap_count"] == 0


def test_manifest_reports_partial_submission_gap(tmp_path: Path) -> None:
    packet = _template_packet("governance_rollback")
    template = _write_template_report(tmp_path, [packet])
    submission = _write_submission(tmp_path, packet["goal_id"], omit_kind="operator_oncall_ack")

    report = build_h3_goal_emission_runtime_production_evidence_submission_manifest(
        production_evidence_submission_template_path=template,
        agent_root=tmp_path,
        production_evidence_submission_path=submission,
    )

    assert report["passed"] is True
    assert report["readiness"]["decision"] == "production_evidence_submission_manifest_gap_detected"
    gap = report["runtime_production_evidence_submission_manifest_surface"]["production_evidence_submission_manifest_gaps"][0]
    assert gap["missing_production_evidence_kinds"] == ["operator_oncall_ack"]
    assert report["runtime_production_evidence_submission_manifest_boundary"]["production_evidence_ingestion_allowed"] is False


def test_manifest_fails_closed_on_local_submission_source(tmp_path: Path) -> None:
    packet = _template_packet("relation_repair_relapse")
    template = _write_template_report(tmp_path, [packet])
    submission = _write_submission(tmp_path, packet["goal_id"], source="local_template_fixture")

    report = build_h3_goal_emission_runtime_production_evidence_submission_manifest(
        production_evidence_submission_template_path=template,
        agent_root=tmp_path,
        production_evidence_submission_path=submission,
    )

    assert report["passed"] is False
    assert report["checks"]["production_evidence_submission_sources_production"] is False
    assert report["runtime_production_evidence_submission_manifest_boundary"]["production_runtime_execution_allowed"] is False


def test_manifest_fails_closed_when_template_artifact_is_submitted(tmp_path: Path) -> None:
    template = _write_template_report(tmp_path, [_template_packet("post_delivery_dispute")])

    report = build_h3_goal_emission_runtime_production_evidence_submission_manifest(
        production_evidence_submission_template_path=template,
        agent_root=tmp_path,
        production_evidence_submission_path=template,
    )

    assert report["passed"] is False
    assert report["checks"]["production_evidence_submission_schema_version"] is False
    assert report["metrics"]["submitted_production_evidence_record_count"] == 0


def test_manifest_fails_closed_on_template_boundary_regression(tmp_path: Path) -> None:
    template = _write_template_report(
        tmp_path,
        [_template_packet("post_delivery_failure")],
        boundary={"production_runtime_execution_allowed": True},
    )

    report = build_h3_goal_emission_runtime_production_evidence_submission_manifest(
        production_evidence_submission_template_path=template,
        agent_root=tmp_path,
    )

    assert report["passed"] is False
    assert report["checks"]["production_evidence_submission_template_boundary_production_runtime_execution_allowed_false"] is False


def _write_template_report(
    tmp_path: Path,
    packets: list[dict],
    *,
    boundary: dict | None = None,
) -> Path:
    default_boundary = {
        "artifact_only": True,
        "production_evidence_submission_template_allowed": bool(packets),
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
    path = tmp_path / "h3_goal_emission_runtime_production_evidence_submission_template.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": "h3-goal-emission-runtime-production-evidence-submission-template:v1",
                "passed": True,
                "failure_reasons": [],
                "readiness": {
                    "production_evidence_submission_template_evaluated": True,
                    "production_evidence_submission_templates_open": bool(packets),
                    "production_evidence_submission_template_not_required": not packets,
                    "production_runtime_execution_ready": False,
                    "production_runtime_receipt_ready": False,
                    "decision": "production_evidence_submission_template_open" if packets else "production_evidence_submission_template_not_required_no_intake_gaps",
                },
                "runtime_production_evidence_submission_template_boundary": default_boundary,
                "runtime_production_evidence_submission_template_surface": {
                    "mode": "production_evidence_submission_template_only_no_runtime",
                    "production_evidence_submission_template_packet_count": len(packets),
                    "production_evidence_submission_template_packets": packets,
                },
            }
        ),
        encoding="utf-8",
    )
    return path


def _template_packet(event_kind: str) -> dict:
    goal_id = f"h3-draft-goal:{event_kind}:alpha"
    return {
        "submission_template_packet_id": f"h3-runtime-production-evidence-submission-template:{goal_id}",
        "goal_id": goal_id,
        "state": "production_evidence_submission_template_open",
        "submission_schema": "h3-goal-emission-runtime-production-evidence:v1",
        "submission_template_item_count": len(REQUIRED_PRODUCTION_EVIDENCE_KINDS),
        "submission_template_items": [
            {
                "evidence_kind": kind,
                "state": "production_evidence_submission_template_item",
                "required_common_fields": [
                    "artifact_id",
                    "goal_id",
                    "evidence_kind",
                    "reviewer",
                    "reviewer_role",
                    "source",
                    "status",
                    "attestation_ref",
                ],
                "required_kind_ref_field": PRODUCTION_EVIDENCE_KIND_REF_FIELDS[kind],
                "placeholder_record": {
                    "template_only": True,
                    "valid_production_evidence_record": False,
                },
            }
            for kind in REQUIRED_PRODUCTION_EVIDENCE_KINDS
        ],
    }


def _write_submission(
    tmp_path: Path,
    goal_id: str,
    *,
    source: str = "h3_production_control_registry",
    omit_kind: str = "",
) -> Path:
    records = []
    for kind in REQUIRED_PRODUCTION_EVIDENCE_KINDS:
        if kind == omit_kind:
            continue
        ref_field = PRODUCTION_EVIDENCE_KIND_REF_FIELDS[kind]
        records.append(
            {
                "artifact_id": f"production-evidence:{kind}:{goal_id}",
                "goal_id": goal_id,
                "evidence_kind": kind,
                "reviewer": "h3-production-reviewer",
                "reviewer_role": "production_safety_controller",
                "source": source,
                "status": "ready",
                "attestation_ref": f"attestation:{kind}:{goal_id}",
                ref_field: f"{kind}:{goal_id}",
            }
        )
    path = tmp_path / "h3_goal_emission_runtime_production_evidence_submission.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": "h3-goal-emission-runtime-production-evidence:v1",
                "production_evidence_records": records,
            }
        ),
        encoding="utf-8",
    )
    return path