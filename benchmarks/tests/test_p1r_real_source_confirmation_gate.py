from __future__ import annotations

import json
from pathlib import Path

from benchmarks.p0p_first_controlled_beta_task_execution_gate import run_execution as run_p0p
from benchmarks.p0q_p1_source_ref_collection_gate import run_gate as run_p0q
from benchmarks.p1_controlled_production_pilot_charter_gate import run_gate as run_p1
from benchmarks.p1r_real_source_confirmation_gate import CONFIRMATION_SCHEMA, EVENT_CATALOG, run_gate
from benchmarks.tests.test_p0p_first_controlled_beta_task_execution_gate import FakeClient
from benchmarks.tests.test_p1_controlled_production_pilot_charter_gate import _write_p0o_summary


def test_p1r_builds_round2_submission_and_gap_map_reaches_16(tmp_path: Path) -> None:
    p0q_summary, p1_summary = _write_p0q_inputs(tmp_path)
    confirmations = _write_confirmations(tmp_path)

    summary = run_gate(
        p0q_summary_path=p0q_summary,
        p1_summary_path=p1_summary,
        owner_confirmation_path=confirmations["owner"],
        audit_confirmation_path=confirmations["audit"],
        monitoring_confirmation_path=confirmations["monitoring"],
        rollback_confirmation_path=confirmations["rollback"],
        output_root=tmp_path / "p1r",
    )

    assert summary["passed"] is True
    assert summary["readiness"]["round2_production_evidence_submission_ready"] is True
    assert summary["readiness"]["l2_external_anchor_input_ready"] is True
    assert summary["readiness"]["h3_bundle_validation_ready"] is False
    assert summary["readiness"]["production_transition_allowed"] is False
    assert summary["production_satisfied_count"] == 16
    assert summary["production_missing_count"] == 0

    production_path = Path(summary["artifacts"]["production_evidence_submission"]["path"])
    production = json.loads(production_path.read_text(encoding="utf-8"))
    assert len(production["production_evidence_records"]) == 16
    assert {record["source"] for record in production["production_evidence_records"]} == {
        "civitasos_internal_change_control",
        "civitasos_internal_audit_control",
        "civitasos_internal_observability",
        "civitasos_internal_runtime_control",
    }


def test_p1r_blocks_missing_round2_event_kind(tmp_path: Path) -> None:
    p0q_summary, p1_summary = _write_p0q_inputs(tmp_path)
    confirmations = _write_confirmations(tmp_path)
    owner = json.loads(confirmations["owner"].read_text(encoding="utf-8"))
    owner["records"] = [
        record for record in owner["records"] if record["source_event_kind"] != "human_review_approved"
    ]
    confirmations["owner"].write_text(json.dumps(owner, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    summary = run_gate(
        p0q_summary_path=p0q_summary,
        p1_summary_path=p1_summary,
        owner_confirmation_path=confirmations["owner"],
        audit_confirmation_path=confirmations["audit"],
        monitoring_confirmation_path=confirmations["monitoring"],
        rollback_confirmation_path=confirmations["rollback"],
        output_root=tmp_path / "p1r",
    )

    assert summary["passed"] is False
    assert summary["readiness"]["production_transition_allowed"] is False
    assert any("missing_round2_event_kinds" in reason for reason in summary["failure_reasons"])


def test_p1r_blocks_non_production_source_token(tmp_path: Path) -> None:
    p0q_summary, p1_summary = _write_p0q_inputs(tmp_path)
    confirmations = _write_confirmations(tmp_path)
    monitoring = json.loads(confirmations["monitoring"].read_text(encoding="utf-8"))
    monitoring["source"] = "local_monitoring_console"
    confirmations["monitoring"].write_text(json.dumps(monitoring, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    summary = run_gate(
        p0q_summary_path=p0q_summary,
        p1_summary_path=p1_summary,
        owner_confirmation_path=confirmations["owner"],
        audit_confirmation_path=confirmations["audit"],
        monitoring_confirmation_path=confirmations["monitoring"],
        rollback_confirmation_path=confirmations["rollback"],
        output_root=tmp_path / "p1r",
    )

    assert summary["passed"] is False
    assert any("source_not_non_production" in reason for reason in summary["failure_reasons"])
    assert "production_evidence_submission" not in summary["artifacts"]


def test_p1r_operator_attested_production_overlays_pending_markers(tmp_path: Path) -> None:
    p0q_summary, p1_summary = _write_p0q_inputs(tmp_path)
    confirmations = _write_confirmations(tmp_path)
    _mark_confirmations_pending(confirmations)

    strict_summary = run_gate(
        p0q_summary_path=p0q_summary,
        p1_summary_path=p1_summary,
        owner_confirmation_path=confirmations["owner"],
        audit_confirmation_path=confirmations["audit"],
        monitoring_confirmation_path=confirmations["monitoring"],
        rollback_confirmation_path=confirmations["rollback"],
        output_root=tmp_path / "p1r_strict",
    )
    assert strict_summary["passed"] is False
    assert any("source_not_non_production" in reason for reason in strict_summary["failure_reasons"])

    attested_summary = run_gate(
        p0q_summary_path=p0q_summary,
        p1_summary_path=p1_summary,
        owner_confirmation_path=confirmations["owner"],
        audit_confirmation_path=confirmations["audit"],
        monitoring_confirmation_path=confirmations["monitoring"],
        rollback_confirmation_path=confirmations["rollback"],
        output_root=tmp_path / "p1r_attested",
        operator_attested_production=True,
        operator_attester="operator-alpha",
        operator_attestation_statement="These P1-R inputs are production data for H.3 transition.",
    )

    assert attested_summary["passed"] is True
    assert attested_summary["evidence_profile"] == "operator_attested_production"
    assert attested_summary["operator_attested_production"] is True
    assert attested_summary["production_satisfied_count"] == 16
    assert attested_summary["readiness"]["production_transition_allowed"] is False

    packet_path = Path(attested_summary["artifacts"]["confirmation_packet"]["path"])
    packet = json.loads(packet_path.read_text(encoding="utf-8"))
    assert packet["raw_pending_marker_event_count"] == 16


def _write_p0q_inputs(tmp_path: Path) -> tuple[Path, Path]:
    p0o_summary = _write_p0o_summary(tmp_path)
    run_p0p(p0o_summary_path=p0o_summary, output_root=tmp_path / "p0p", client=FakeClient())
    p0p_summary = tmp_path / "p0p" / "p0p_first_controlled_beta_task_execution_summary.json"
    run_p1(
        p0o_summary_path=p0o_summary,
        output_root=tmp_path / "p1",
        operator_id="operator-alpha",
        ack_p1_charter=True,
    )
    p1_summary = tmp_path / "p1" / "p1_controlled_production_pilot_charter_summary.json"
    run_p0q(
        p0p_summary_path=p0p_summary,
        p1_summary_path=p1_summary,
        output_root=tmp_path / "p0q",
        operator_id="operator-alpha",
    )
    return tmp_path / "p0q" / "p0q_p1_source_ref_collection_summary.json", p1_summary


def _write_confirmations(tmp_path: Path) -> dict[str, Path]:
    role_sources = {
        "owner": "civitasos_internal_change_control",
        "audit": "civitasos_internal_audit_control",
        "monitoring": "civitasos_internal_observability",
        "rollback": "civitasos_internal_runtime_control",
    }
    role_events: dict[str, list[str]] = {"owner": [], "audit": [], "monitoring": [], "rollback": []}
    for event_kind, catalog in EVENT_CATALOG.items():
        role_events[catalog["role"]].append(event_kind)

    paths: dict[str, Path] = {}
    for role, events in role_events.items():
        payload = {
            "schema_version": CONFIRMATION_SCHEMA,
            "confirmation_role": role,
            "confirmed_by": f"{role}-reviewer-alpha",
            "production_origin_confirmed": True,
            "candidate_ref_promoted": False,
            "source": role_sources[role],
            "source_provider": role_sources[role],
            "source_uri": f"civitasos-prod://p1r/{role}/batch-alpha",
            "captured_at": "2026-06-28T02:00:00+00:00",
            "records": [_record(role, event_kind) for event_kind in events],
        }
        path = tmp_path / f"{role}_confirmation.json"
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        paths[role] = path
    return paths


def _record(role: str, event_kind: str) -> dict[str, object]:
    catalog = EVENT_CATALOG[event_kind]
    ref = f"p1r-prod-{role}-{event_kind}-alpha"
    return {
        "source_event_kind": event_kind,
        "reviewer": f"{role}-reviewer-alpha",
        "attestation_ref": ref,
        catalog["ref_field"]: ref,
        "source_uri": f"civitasos-prod://p1r/{role}/{event_kind}/alpha",
        "captured_at": "2026-06-28T02:00:00+00:00",
        "evidence_summary": f"P1-R production-origin confirmation for {event_kind}",
        "risk_level": "low",
        "rollback_required": True,
    }


def _mark_confirmations_pending(paths: dict[str, Path]) -> None:
    for path in paths.values():
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload["confirmed_by"] = "verification"
        for record in payload["records"]:
            record["reviewer"] = "verification-unassigned"
            record["evidence_summary"] = (
                f"Verification pending: no real production-origin evidence was supplied for "
                f"{record['source_event_kind']}. This generated intake marker is not an approval or attestation."
            )
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
