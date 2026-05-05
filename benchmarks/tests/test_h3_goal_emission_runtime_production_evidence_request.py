from __future__ import annotations

import json
from pathlib import Path

from benchmarks.h3_goal_emission_runtime_production_evidence_gate import (
    PRODUCTION_EVIDENCE_KIND_REF_FIELDS,
    REQUIRED_PRODUCTION_EVIDENCE_KINDS,
)
from benchmarks.h3_goal_emission_runtime_production_evidence_request import (
    PRODUCTION_EVIDENCE_COMMON_FIELDS,
    PRODUCTION_EVIDENCE_SCHEMA_VERSION,
    build_h3_goal_emission_runtime_production_evidence_request,
)


def test_request_bundle_opens_for_local_controlled_gap(tmp_path: Path) -> None:
    gap = _gap("post_delivery_failure", "local controlled execution receipt is not production evidence")
    evidence_gate = _write_production_evidence_gate(
        tmp_path,
        decision="production_evidence_blocked_local_controlled_only",
        gaps=[gap],
    )

    report = build_h3_goal_emission_runtime_production_evidence_request(
        production_evidence_gate_path=evidence_gate,
        agent_root=tmp_path,
    )

    assert report["passed"] is True
    assert report["readiness"]["decision"] == "production_evidence_request_open_local_controlled_not_production"
    assert report["readiness"]["production_runtime_execution_ready"] is False
    assert report["runtime_production_evidence_request_boundary"]["production_runtime_execution_allowed"] is False
    assert report["metrics"]["production_evidence_request_packet_count"] == 1
    assert report["metrics"]["requested_production_evidence_item_count"] == len(REQUIRED_PRODUCTION_EVIDENCE_KINDS)
    packet = report["runtime_production_evidence_request_surface"]["production_evidence_request_packets"][0]
    assert packet["requires_production_origin_runtime_execution_target"] is True
    assert packet["submission_schema"] == PRODUCTION_EVIDENCE_SCHEMA_VERSION
    assert packet["collection_policy"]["local_controlled_receipts_count_as_production"] is False


def test_request_bundle_describes_required_fields_for_missing_items(tmp_path: Path) -> None:
    missing = ["runtime_safety_envelope", "operator_oncall_ack"]
    evidence_gate = _write_production_evidence_gate(
        tmp_path,
        decision="production_evidence_gap_detected",
        gaps=[_gap("economic_deviation", "missing required production evidence records", missing=missing)],
    )

    report = build_h3_goal_emission_runtime_production_evidence_request(
        production_evidence_gate_path=evidence_gate,
        agent_root=tmp_path,
    )

    assert report["passed"] is True
    assert report["readiness"]["decision"] == "production_evidence_request_open"
    packet = report["runtime_production_evidence_request_surface"]["production_evidence_request_packets"][0]
    items = {item["evidence_kind"]: item for item in packet["requested_evidence_items"]}
    assert set(items) == set(missing)
    assert items["runtime_safety_envelope"]["required_common_fields"] == PRODUCTION_EVIDENCE_COMMON_FIELDS
    assert items["runtime_safety_envelope"]["required_kind_ref_field"] == PRODUCTION_EVIDENCE_KIND_REF_FIELDS["runtime_safety_envelope"]
    assert "local" in items["operator_oncall_ack"]["forbidden_source_tokens"]


def test_request_bundle_closes_when_evidence_reviewed_without_runtime(tmp_path: Path) -> None:
    reviewed = _reviewed_packet("relation_repair_relapse")
    evidence_gate = _write_production_evidence_gate(
        tmp_path,
        decision="production_evidence_reviewed_no_runtime_execution",
        reviewed_packets=[reviewed],
        production_evidence_complete=True,
    )

    report = build_h3_goal_emission_runtime_production_evidence_request(
        production_evidence_gate_path=evidence_gate,
        agent_root=tmp_path,
    )

    assert report["passed"] is True
    assert report["readiness"]["decision"] == "production_evidence_request_closed_no_runtime_execution"
    assert report["readiness"]["production_evidence_requests_open"] is False
    assert report["readiness"]["production_runtime_execution_ready"] is False
    assert report["metrics"]["production_evidence_request_packet_count"] == 0
    assert report["metrics"]["closed_production_evidence_review_count"] == 1
    assert report["runtime_production_evidence_request_boundary"]["production_evidence_ingestion_allowed"] is False


def test_request_bundle_fails_closed_on_boundary_regression(tmp_path: Path) -> None:
    evidence_gate = _write_production_evidence_gate(
        tmp_path,
        decision="production_evidence_gap_detected",
        gaps=[_gap("governance_rollback", "missing required production evidence records")],
        boundary={"production_runtime_execution_allowed": True},
    )

    report = build_h3_goal_emission_runtime_production_evidence_request(
        production_evidence_gate_path=evidence_gate,
        agent_root=tmp_path,
    )

    assert report["passed"] is False
    assert report["checks"]["production_evidence_boundary_production_runtime_execution_allowed_false"] is False
    assert report["runtime_production_evidence_request_boundary"]["production_runtime_execution_allowed"] is False
    assert report["metrics"]["production_evidence_request_packet_count"] == 0


def test_request_bundle_fails_closed_on_unknown_missing_kind(tmp_path: Path) -> None:
    evidence_gate = _write_production_evidence_gate(
        tmp_path,
        decision="production_evidence_gap_detected",
        gaps=[_gap("post_delivery_dispute", "missing required production evidence records", missing=["unknown_kind"])],
    )

    report = build_h3_goal_emission_runtime_production_evidence_request(
        production_evidence_gate_path=evidence_gate,
        agent_root=tmp_path,
    )

    assert report["passed"] is False
    assert report["checks"]["production_evidence_gap_missing_kinds_known"] is False
    assert report["runtime_production_evidence_request_surface"]["production_evidence_request_packets"] == []


def _write_production_evidence_gate(
    tmp_path: Path,
    *,
    decision: str,
    gaps: list[dict] | None = None,
    reviewed_packets: list[dict] | None = None,
    production_evidence_complete: bool = False,
    boundary: dict | None = None,
) -> Path:
    gaps = gaps or []
    reviewed_packets = reviewed_packets or []
    default_boundary = {
        "artifact_only": True,
        "production_evidence_review_allowed": production_evidence_complete,
        "local_controlled_evidence_counted_as_production": False,
        "production_runtime_execution_allowed": False,
        "production_runtime_receipt_allowed": False,
        "agent_loop_start_allowed": False,
        "llm_planning_allowed": False,
        "external_system_mutation_allowed": False,
        "iem_value_mutation_allowed": False,
        "normative_local_mutation_allowed": False,
    }
    default_boundary.update(boundary or {})
    path = tmp_path / "h3_goal_emission_runtime_production_evidence_gate.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": "h3-goal-emission-runtime-production-evidence-gate:v1",
                "passed": True,
                "failure_reasons": [],
                "readiness": {
                    "runtime_production_evidence_gate_evaluated": True,
                    "production_evidence_complete": production_evidence_complete,
                    "production_runtime_execution_ready": False,
                    "production_runtime_receipt_ready": False,
                    "decision": decision,
                },
                "runtime_production_evidence_boundary": default_boundary,
                "runtime_production_evidence_surface": {
                    "mode": "production_evidence_gap_review_only_no_runtime",
                    "reviewed_production_evidence_packet_count": len(reviewed_packets),
                    "reviewed_production_evidence_packets": reviewed_packets,
                    "production_evidence_gap_count": len(gaps),
                    "production_evidence_gaps": gaps,
                    "rejected_production_evidence_record_count": 0,
                    "rejected_production_evidence_records": [],
                    "local_controlled_non_production_receipts": [],
                    "production_origin_blocked_executor_packets": [],
                },
            }
        ),
        encoding="utf-8",
    )
    return path


def _gap(event_kind: str, reason: str, *, missing: list[str] | None = None) -> dict:
    goal_id = f"h3-draft-goal:{event_kind}:alpha"
    return {
        "goal_id": goal_id,
        "state": "production_evidence_gap",
        "gap_reason": reason,
        "missing_production_evidence_kinds": missing or REQUIRED_PRODUCTION_EVIDENCE_KINDS,
    }


def _reviewed_packet(event_kind: str) -> dict:
    goal_id = f"h3-draft-goal:{event_kind}:alpha"
    return {
        "production_evidence_packet_id": f"h3-runtime-production-evidence:{goal_id}",
        "goal_id": goal_id,
        "state": "production_evidence_reviewed_no_runtime_execution",
        "production_evidence_refs": {kind: f"production-evidence:{kind}:{goal_id}" for kind in REQUIRED_PRODUCTION_EVIDENCE_KINDS},
        "gate_status": {
            "production_evidence_complete": True,
            "production_runtime_execution_ready": False,
            "production_runtime_receipt_ready": False,
        },
    }