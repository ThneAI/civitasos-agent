from __future__ import annotations

import json
from pathlib import Path

from benchmarks.h3_goal_emission_runtime_production_evidence_gate import (
    PRODUCTION_EVIDENCE_KIND_REF_FIELDS,
    REQUIRED_PRODUCTION_EVIDENCE_KINDS,
)
from benchmarks.h3_goal_emission_runtime_production_evidence_intake import (
    build_h3_goal_emission_runtime_production_evidence_intake,
)


def test_intake_waits_for_submission_without_runtime_permission(tmp_path: Path) -> None:
    request = _write_request_bundle(tmp_path, [_request_packet("post_delivery_failure")])

    report = build_h3_goal_emission_runtime_production_evidence_intake(
        production_evidence_request_path=request,
        agent_root=tmp_path,
    )

    assert report["passed"] is True
    assert report["readiness"]["decision"] == "production_evidence_intake_blocked_pending_submission"
    assert report["readiness"]["production_evidence_submission_complete"] is False
    assert report["runtime_production_evidence_intake_boundary"]["production_runtime_execution_allowed"] is False
    assert report["metrics"]["production_evidence_intake_gap_count"] == 1
    assert report["metrics"]["missing_production_evidence_item_count"] == len(REQUIRED_PRODUCTION_EVIDENCE_KINDS)


def test_intake_reviews_complete_submission_without_runtime_permission(tmp_path: Path) -> None:
    packet = _request_packet("economic_deviation")
    request = _write_request_bundle(tmp_path, [packet])
    submission = _write_submission(tmp_path, packet["goal_id"])

    report = build_h3_goal_emission_runtime_production_evidence_intake(
        production_evidence_request_path=request,
        agent_root=tmp_path,
        production_evidence_submission_path=submission,
    )

    assert report["passed"] is True
    assert report["readiness"]["decision"] == "production_evidence_intake_reviewed_no_runtime_execution"
    assert report["readiness"]["production_evidence_submission_complete"] is True
    assert report["readiness"]["production_runtime_execution_ready"] is False
    assert report["metrics"]["reviewed_production_evidence_intake_packet_count"] == 1
    assert report["metrics"]["production_evidence_intake_gap_count"] == 0
    reviewed = report["runtime_production_evidence_intake_surface"]["reviewed_production_evidence_intake_packets"][0]
    assert reviewed["state"] == "production_evidence_intake_reviewed_no_runtime_execution"
    assert set(reviewed["production_evidence_refs"]) == set(REQUIRED_PRODUCTION_EVIDENCE_KINDS)
    assert reviewed["gate_status"]["production_runtime_receipt_ready"] is False


def test_intake_reports_missing_requested_submission_record(tmp_path: Path) -> None:
    packet = _request_packet("governance_rollback")
    request = _write_request_bundle(tmp_path, [packet])
    submission = _write_submission(tmp_path, packet["goal_id"], omit_kind="operator_oncall_ack")

    report = build_h3_goal_emission_runtime_production_evidence_intake(
        production_evidence_request_path=request,
        agent_root=tmp_path,
        production_evidence_submission_path=submission,
    )

    assert report["passed"] is True
    assert report["readiness"]["decision"] == "production_evidence_intake_gap_detected"
    assert report["readiness"]["production_evidence_submission_complete"] is False
    assert report["metrics"]["production_evidence_intake_gap_count"] == 1
    gap = report["runtime_production_evidence_intake_surface"]["production_evidence_intake_gaps"][0]
    assert gap["missing_production_evidence_kinds"] == ["operator_oncall_ack"]


def test_intake_fails_closed_on_local_submission_source(tmp_path: Path) -> None:
    packet = _request_packet("relation_repair_relapse")
    request = _write_request_bundle(tmp_path, [packet])
    submission = _write_submission(tmp_path, packet["goal_id"], source="h3_local_operator_fixture")

    report = build_h3_goal_emission_runtime_production_evidence_intake(
        production_evidence_request_path=request,
        agent_root=tmp_path,
        production_evidence_submission_path=submission,
    )

    assert report["passed"] is False
    assert report["checks"]["production_evidence_submission_sources_production"] is False
    assert report["runtime_production_evidence_intake_boundary"]["production_runtime_execution_allowed"] is False
    assert report["metrics"]["reviewed_production_evidence_intake_packet_count"] == 0


def test_intake_fails_closed_on_request_boundary_regression(tmp_path: Path) -> None:
    request = _write_request_bundle(
        tmp_path,
        [_request_packet("post_delivery_dispute")],
        boundary={"production_runtime_execution_allowed": True},
    )

    report = build_h3_goal_emission_runtime_production_evidence_intake(
        production_evidence_request_path=request,
        agent_root=tmp_path,
    )

    assert report["passed"] is False
    assert report["checks"]["production_evidence_request_boundary_production_runtime_execution_allowed_false"] is False
    assert report["runtime_production_evidence_intake_boundary"]["production_runtime_execution_allowed"] is False


def _write_request_bundle(
    tmp_path: Path,
    packets: list[dict],
    *,
    boundary: dict | None = None,
) -> Path:
    default_boundary = {
        "artifact_only": True,
        "production_evidence_request_allowed": bool(packets),
        "production_evidence_ingestion_allowed": False,
        "production_runtime_execution_allowed": False,
        "production_runtime_receipt_allowed": False,
        "agent_loop_start_allowed": False,
        "llm_planning_allowed": False,
        "external_system_mutation_allowed": False,
        "iem_value_mutation_allowed": False,
        "normative_local_mutation_allowed": False,
    }
    default_boundary.update(boundary or {})
    path = tmp_path / "h3_goal_emission_runtime_production_evidence_request.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": "h3-goal-emission-runtime-production-evidence-request:v1",
                "passed": True,
                "failure_reasons": [],
                "readiness": {
                    "production_evidence_request_evaluated": True,
                    "production_evidence_requests_open": bool(packets),
                    "production_evidence_review_complete_without_runtime": False,
                    "production_runtime_execution_ready": False,
                    "production_runtime_receipt_ready": False,
                    "decision": "production_evidence_request_open" if packets else "production_evidence_request_blocked_no_runtime_targets",
                },
                "runtime_production_evidence_request_boundary": default_boundary,
                "runtime_production_evidence_request_surface": {
                    "mode": "production_evidence_request_only_no_runtime",
                    "production_evidence_request_packet_count": len(packets),
                    "production_evidence_request_packets": packets,
                    "closed_production_evidence_review_count": 0,
                    "closed_production_evidence_reviews": [],
                },
            }
        ),
        encoding="utf-8",
    )
    return path


def _request_packet(event_kind: str) -> dict:
    goal_id = f"h3-draft-goal:{event_kind}:alpha"
    return {
        "request_packet_id": f"h3-runtime-production-evidence-request:{goal_id}",
        "goal_id": goal_id,
        "state": "production_evidence_request_open",
        "submission_schema": "h3-goal-emission-runtime-production-evidence:v1",
        "requested_evidence_item_count": len(REQUIRED_PRODUCTION_EVIDENCE_KINDS),
        "requested_evidence_items": [
            {
                "evidence_kind": kind,
                "state": "production_evidence_item_required",
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
                "accepted_statuses": ["acknowledged", "approved", "armed", "attested", "complete", "green", "ready"],
                "forbidden_source_tokens": ["fixture", "synthetic", "mock", "test", "local"],
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