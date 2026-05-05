from __future__ import annotations

import json
from pathlib import Path

from benchmarks.h3_goal_emission_runtime_production_evidence_gate import (
    PRODUCTION_EVIDENCE_KIND_REF_FIELDS,
    REQUIRED_PRODUCTION_EVIDENCE_KINDS,
    build_h3_goal_emission_runtime_production_evidence_gate,
)


def test_production_evidence_gate_blocks_local_controlled_receipt_only(tmp_path: Path) -> None:
    executor_report = _write_executor_report(tmp_path, receipts=[_local_receipt("post_delivery_failure")])

    report = build_h3_goal_emission_runtime_production_evidence_gate(
        runtime_executor_path=executor_report,
        agent_root=tmp_path,
    )

    assert report["passed"] is True
    assert report["readiness"]["decision"] == "production_evidence_blocked_local_controlled_only"
    assert report["readiness"]["local_controlled_runtime_execution_receipts_present"] is True
    assert report["readiness"]["production_evidence_complete"] is False
    assert report["readiness"]["production_runtime_execution_ready"] is False
    assert report["runtime_production_evidence_boundary"]["local_controlled_evidence_counted_as_production"] is False
    assert report["runtime_production_evidence_boundary"]["production_runtime_execution_allowed"] is False
    assert report["metrics"]["local_controlled_runtime_receipt_count"] == 1
    assert report["metrics"]["production_evidence_gap_count"] == 1
    gap = report["runtime_production_evidence_surface"]["production_evidence_gaps"][0]
    assert gap["gap_reason"] == "local controlled execution receipt is not production evidence"
    assert gap["missing_production_evidence_kinds"] == REQUIRED_PRODUCTION_EVIDENCE_KINDS


def test_production_evidence_gate_reports_missing_production_artifacts(tmp_path: Path) -> None:
    executor_report = _write_executor_report(
        tmp_path,
        blocked_packets=[_production_blocked_packet("economic_deviation")],
        decision="runtime_execution_blocked_requires_production_executor_evidence",
    )

    report = build_h3_goal_emission_runtime_production_evidence_gate(
        runtime_executor_path=executor_report,
        agent_root=tmp_path,
    )

    assert report["passed"] is True
    assert report["readiness"]["decision"] == "production_evidence_gap_detected"
    assert report["readiness"]["production_origin_runtime_execution_packets_present"] is True
    assert report["metrics"]["production_origin_blocked_packet_count"] == 1
    assert report["metrics"]["production_evidence_gap_count"] == 1
    gap = report["runtime_production_evidence_surface"]["production_evidence_gaps"][0]
    assert gap["missing_production_evidence_kinds"] == REQUIRED_PRODUCTION_EVIDENCE_KINDS
    assert report["runtime_production_evidence_boundary"]["production_runtime_receipt_allowed"] is False


def test_production_evidence_gate_reviews_complete_evidence_without_runtime(tmp_path: Path) -> None:
    packet = _production_blocked_packet("relation_repair_relapse")
    executor_report = _write_executor_report(
        tmp_path,
        blocked_packets=[packet],
        decision="runtime_execution_blocked_requires_production_executor_evidence",
    )
    production_evidence = _write_production_evidence(tmp_path, packet["goal_id"])

    report = build_h3_goal_emission_runtime_production_evidence_gate(
        runtime_executor_path=executor_report,
        agent_root=tmp_path,
        production_evidence_path=production_evidence,
    )

    assert report["passed"] is True
    assert report["readiness"]["decision"] == "production_evidence_reviewed_no_runtime_execution"
    assert report["readiness"]["production_evidence_complete"] is True
    assert report["readiness"]["production_runtime_execution_ready"] is False
    assert report["runtime_production_evidence_boundary"]["production_evidence_review_allowed"] is True
    assert report["runtime_production_evidence_boundary"]["production_runtime_execution_allowed"] is False
    assert report["metrics"]["reviewed_production_evidence_packet_count"] == 1
    assert report["metrics"]["production_evidence_gap_count"] == 0
    reviewed = report["runtime_production_evidence_surface"]["reviewed_production_evidence_packets"][0]
    assert reviewed["state"] == "production_evidence_reviewed_no_runtime_execution"
    assert reviewed["gate_status"]["production_runtime_receipt_ready"] is False
    assert set(reviewed["production_evidence_refs"]) == set(REQUIRED_PRODUCTION_EVIDENCE_KINDS)


def test_production_evidence_gate_rejects_local_or_fixture_evidence(tmp_path: Path) -> None:
    packet = _production_blocked_packet("governance_rollback")
    executor_report = _write_executor_report(
        tmp_path,
        blocked_packets=[packet],
        decision="runtime_execution_blocked_requires_production_executor_evidence",
    )
    production_evidence = _write_production_evidence(tmp_path, packet["goal_id"], source="h3_local_operator_start_registry")

    report = build_h3_goal_emission_runtime_production_evidence_gate(
        runtime_executor_path=executor_report,
        agent_root=tmp_path,
        production_evidence_path=production_evidence,
    )

    assert report["passed"] is False
    assert report["checks"]["production_evidence_not_fixture_or_local"] is False
    assert report["runtime_production_evidence_boundary"]["production_runtime_execution_allowed"] is False


def test_production_evidence_gate_fails_closed_on_executor_boundary_regression(tmp_path: Path) -> None:
    executor_report = _write_executor_report(
        tmp_path,
        blocked_packets=[_production_blocked_packet("post_delivery_dispute")],
        decision="runtime_execution_blocked_requires_production_executor_evidence",
        boundary={"production_runtime_receipt_write_performed": True},
    )

    report = build_h3_goal_emission_runtime_production_evidence_gate(
        runtime_executor_path=executor_report,
        agent_root=tmp_path,
    )

    assert report["passed"] is False
    assert report["checks"]["executor_boundary_production_receipt_not_written"] is False
    assert report["readiness"]["production_runtime_execution_ready"] is False
    assert report["runtime_production_evidence_boundary"]["production_runtime_receipt_allowed"] is False


def _write_executor_report(
    tmp_path: Path,
    *,
    receipts: list[dict] | None = None,
    blocked_packets: list[dict] | None = None,
    decision: str = "runtime_execution_completed_with_receipts",
    boundary: dict | None = None,
) -> Path:
    receipts = receipts or []
    blocked_packets = blocked_packets or []
    default_boundary = {
        "runtime_execution_performed": bool(receipts),
        "receipt_write_performed": bool(receipts),
        "local_controlled_receipt_write_performed": bool(receipts),
        "production_runtime_receipt_write_performed": False,
        "production_runtime_receipt_allowed": False,
        "agent_loop_started": False,
        "llm_called": False,
        "external_system_mutated": False,
        "iem_value_mutation_allowed": False,
        "normative_local_mutation_allowed": False,
    }
    default_boundary.update(boundary or {})
    path = tmp_path / "h3_goal_emission_runtime_executor.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": "h3-goal-emission-runtime-executor:v1",
                "passed": True,
                "failure_reasons": [],
                "readiness": {
                    "runtime_executor_evaluated": True,
                    "local_runtime_execution_acknowledged": True,
                    "runtime_execution_started": bool(receipts),
                    "runtime_execution_completed": bool(receipts),
                    "local_controlled_runtime_execution_completed": bool(receipts),
                    "production_runtime_execution_completed": False,
                    "decision": decision,
                },
                "runtime_executor_boundary": default_boundary,
                "runtime_executor_surface": {
                    "mode": "local_controlled_runtime_receipt_executor",
                    "blocked_runtime_execution_packet_count": len(blocked_packets),
                    "blocked_runtime_execution_packets": blocked_packets,
                },
                "runtime_execution_receipts": receipts,
            }
        ),
        encoding="utf-8",
    )
    return path


def _local_receipt(event_kind: str) -> dict:
    goal_id = f"h3-draft-goal:{event_kind}:local-execution"
    return {
        "receipt_id": f"h3-runtime-execution-receipt:{goal_id}",
        "runtime_execution_packet_id": f"h3-runtime-execution:{goal_id}",
        "execution_origin": "local_controlled",
        "goal_id": goal_id,
        "state": "runtime_execution_completed",
        "action": "record_h3_controlled_runtime_execution_receipt",
        "side_effects": {
            "receipt_written": True,
            "agent_loop_started": False,
            "llm_calls": 0,
            "external_system_mutations": 0,
            "iem_mutations": 0,
            "normative_mutations": 0,
        },
    }


def _production_blocked_packet(event_kind: str) -> dict:
    goal_id = f"h3-draft-goal:{event_kind}:alpha"
    return {
        "runtime_execution_packet_id": f"h3-runtime-execution:{goal_id}",
        "goal_id": goal_id,
        "execution_origin": "production",
        "state": "runtime_execution_blocked",
        "blocked_reason": "production-origin execution packets require a future production executor evidence gate",
        "receipt_written": False,
    }


def _write_production_evidence(tmp_path: Path, goal_id: str, *, source: str = "h3_production_control_registry") -> Path:
    records = []
    for kind in REQUIRED_PRODUCTION_EVIDENCE_KINDS:
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
    path = tmp_path / "h3_goal_emission_runtime_production_evidence.json"
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
