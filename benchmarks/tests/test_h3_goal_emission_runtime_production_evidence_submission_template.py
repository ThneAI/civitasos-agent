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
from benchmarks.h3_goal_emission_runtime_production_evidence_submission_template import (
    build_h3_goal_emission_runtime_production_evidence_submission_template,
)


def test_submission_template_opens_for_pending_intake_gap(tmp_path: Path) -> None:
    intake = _write_intake_report(tmp_path, [_intake_gap("post_delivery_failure")])

    report = build_h3_goal_emission_runtime_production_evidence_submission_template(
        production_evidence_intake_path=intake,
        agent_root=tmp_path,
    )

    assert report["passed"] is True
    assert report["readiness"]["decision"] == "production_evidence_submission_template_open"
    assert report["runtime_production_evidence_submission_template_boundary"]["production_runtime_execution_allowed"] is False
    assert report["runtime_production_evidence_submission_template_boundary"]["valid_production_evidence_record_generation_allowed"] is False
    assert report["metrics"]["production_evidence_submission_template_packet_count"] == 1
    assert report["metrics"]["production_evidence_submission_template_item_count"] == len(REQUIRED_PRODUCTION_EVIDENCE_KINDS)
    packet = report["runtime_production_evidence_submission_template_surface"]["production_evidence_submission_template_packets"][0]
    assert packet["state"] == "production_evidence_submission_template_open"
    assert packet["gate_status"]["valid_production_evidence_record_count"] == 0


def test_submission_template_items_are_not_valid_evidence_records(tmp_path: Path) -> None:
    intake = _write_intake_report(tmp_path, [_intake_gap("post_delivery_dispute")])

    report = build_h3_goal_emission_runtime_production_evidence_submission_template(
        production_evidence_intake_path=intake,
        agent_root=tmp_path,
    )

    item = report["runtime_production_evidence_submission_template_surface"]["production_evidence_submission_template_packets"][0]["submission_template_items"][0]
    kind = item["evidence_kind"]
    placeholder = item["placeholder_record"]
    assert item["required_kind_ref_field"] == PRODUCTION_EVIDENCE_KIND_REF_FIELDS[kind]
    assert placeholder["template_only"] is True
    assert placeholder["valid_production_evidence_record"] is False
    assert placeholder["source"] == "template_local_placeholder_not_production"
    assert placeholder["status"] == "<required:accepted-production-status>"


def test_submission_template_not_required_when_intake_reviewed(tmp_path: Path) -> None:
    intake = _write_intake_report(
        tmp_path,
        [],
        reviewed_packets=[_reviewed_packet("governance_rollback")],
        decision="production_evidence_intake_reviewed_no_runtime_execution",
        submission_complete=True,
    )

    report = build_h3_goal_emission_runtime_production_evidence_submission_template(
        production_evidence_intake_path=intake,
        agent_root=tmp_path,
    )

    assert report["passed"] is True
    assert report["readiness"]["decision"] == "production_evidence_submission_template_not_required_reviewed_no_runtime"
    assert report["metrics"]["production_evidence_submission_template_packet_count"] == 0
    assert report["runtime_production_evidence_submission_template_boundary"]["production_runtime_receipt_allowed"] is False


def test_submission_template_fails_closed_on_intake_boundary_regression(tmp_path: Path) -> None:
    intake = _write_intake_report(
        tmp_path,
        [_intake_gap("economic_deviation")],
        boundary={"production_runtime_execution_allowed": True},
    )

    report = build_h3_goal_emission_runtime_production_evidence_submission_template(
        production_evidence_intake_path=intake,
        agent_root=tmp_path,
    )

    assert report["passed"] is False
    assert report["checks"]["production_evidence_intake_boundary_production_runtime_execution_allowed_false"] is False
    assert report["runtime_production_evidence_submission_template_boundary"]["production_runtime_execution_allowed"] is False


def test_submission_template_fails_closed_on_unknown_missing_kind(tmp_path: Path) -> None:
    gap = _intake_gap("relation_repair_relapse")
    gap["missing_production_evidence_kinds"] = ["unknown_runtime_attestation"]
    intake = _write_intake_report(tmp_path, [gap])

    report = build_h3_goal_emission_runtime_production_evidence_submission_template(
        production_evidence_intake_path=intake,
        agent_root=tmp_path,
    )

    assert report["passed"] is False
    assert report["checks"]["production_evidence_intake_gap_missing_kinds_known"] is False
    assert report["metrics"]["production_evidence_submission_template_packet_count"] == 0


def test_submission_template_file_cannot_be_submitted_as_production_evidence(tmp_path: Path) -> None:
    intake = _write_intake_report(tmp_path, [_intake_gap("post_delivery_failure")])
    template_report = build_h3_goal_emission_runtime_production_evidence_submission_template(
        production_evidence_intake_path=intake,
        agent_root=tmp_path,
    )
    template_path = tmp_path / "h3_goal_emission_runtime_production_evidence_submission_template.json"
    template_path.write_text(json.dumps(template_report), encoding="utf-8")

    intake_review = build_h3_goal_emission_runtime_production_evidence_intake(
        production_evidence_request_path=_write_request_bundle(tmp_path, [_request_packet("post_delivery_failure")]),
        agent_root=tmp_path,
        production_evidence_submission_path=template_path,
    )

    assert intake_review["passed"] is False
    assert intake_review["checks"]["production_evidence_submission_schema_version"] is False
    assert intake_review["runtime_production_evidence_intake_boundary"]["production_runtime_execution_allowed"] is False


def _write_intake_report(
    tmp_path: Path,
    gaps: list[dict],
    *,
    reviewed_packets: list[dict] | None = None,
    decision: str = "production_evidence_intake_blocked_pending_submission",
    submission_complete: bool = False,
    boundary: dict | None = None,
) -> Path:
    default_boundary = {
        "artifact_only": True,
        "production_evidence_submission_review_allowed": False,
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
    path = tmp_path / "h3_goal_emission_runtime_production_evidence_intake.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": "h3-goal-emission-runtime-production-evidence-intake:v1",
                "passed": True,
                "failure_reasons": [],
                "readiness": {
                    "production_evidence_intake_evaluated": True,
                    "production_evidence_submission_present": submission_complete,
                    "production_evidence_submission_complete": submission_complete,
                    "production_runtime_execution_ready": False,
                    "production_runtime_receipt_ready": False,
                    "decision": decision,
                },
                "runtime_production_evidence_intake_boundary": default_boundary,
                "runtime_production_evidence_intake_surface": {
                    "mode": "production_evidence_intake_review_only_no_runtime",
                    "reviewed_production_evidence_intake_packet_count": len(reviewed_packets or []),
                    "reviewed_production_evidence_intake_packets": reviewed_packets or [],
                    "production_evidence_intake_gap_count": len(gaps),
                    "production_evidence_intake_gaps": gaps,
                },
            }
        ),
        encoding="utf-8",
    )
    return path


def _intake_gap(event_kind: str) -> dict:
    goal_id = f"h3-draft-goal:{event_kind}:alpha"
    return {
        "goal_id": goal_id,
        "state": "production_evidence_intake_gap",
        "gap_reason": "missing requested production evidence submission records",
        "missing_production_evidence_kinds": list(REQUIRED_PRODUCTION_EVIDENCE_KINDS),
        "request_packet_id": f"h3-runtime-production-evidence-request:{goal_id}",
    }


def _reviewed_packet(event_kind: str) -> dict:
    goal_id = f"h3-draft-goal:{event_kind}:alpha"
    return {
        "production_evidence_intake_packet_id": f"h3-runtime-production-evidence-intake:{goal_id}",
        "goal_id": goal_id,
        "state": "production_evidence_intake_reviewed_no_runtime_execution",
        "production_evidence_refs": {kind: f"production-evidence:{kind}:{goal_id}" for kind in REQUIRED_PRODUCTION_EVIDENCE_KINDS},
        "gate_status": {
            "production_evidence_submission_complete": True,
            "production_runtime_execution_ready": False,
            "production_runtime_receipt_ready": False,
        },
    }


def _write_request_bundle(tmp_path: Path, packets: list[dict]) -> Path:
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
                    "decision": "production_evidence_request_open",
                },
                "runtime_production_evidence_request_boundary": {
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
                },
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