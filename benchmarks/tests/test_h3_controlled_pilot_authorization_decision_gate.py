from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from benchmarks.h3_controlled_pilot_authorization_decision_gate import (
    create_authorization_decision_packet,
    reconcile_authorization_decisions,
    record_authorization_decision,
)
from benchmarks.h3_controlled_pilot_authorization_request_gate import (
    build_authorization_request_gate,
)
from benchmarks.tests.test_h3_controlled_pilot_authorization_request_gate import (
    _write_sources,
)


DECIDED_AT = datetime(2026, 6, 9, 8, 0, tzinfo=timezone.utc)


def test_pending_decisions_fail_closed(tmp_path: Path) -> None:
    request_path = _write_request_report(tmp_path)
    packet_path = tmp_path / "authorization_decisions.json"
    create_authorization_decision_packet(
        authorization_request_report_path=request_path,
        output_path=packet_path,
        agent_root=tmp_path,
    )

    report = reconcile_authorization_decisions(
        authorization_request_report_path=request_path,
        decision_packet_path=packet_path,
        output_path=tmp_path / "reconciliation.json",
        agent_root=tmp_path,
        current_time=DECIDED_AT,
    )

    assert report["passed"] is False
    assert report["checks"]["authorization_decisions_complete"] is False
    assert report["authorization_receipts"] == []
    assert report["boundary"]["controlled_pilot_execution_allowed"] is False


def test_authorize_once_writes_receipts_but_does_not_execute(
    tmp_path: Path,
) -> None:
    request_path, packet_path = _write_completed_packet(
        tmp_path,
        decision="authorize_once",
    )

    report = reconcile_authorization_decisions(
        authorization_request_report_path=request_path,
        decision_packet_path=packet_path,
        output_path=tmp_path / "reconciliation.json",
        agent_root=tmp_path,
        current_time=DECIDED_AT + timedelta(seconds=10),
    )

    assert report["passed"] is True
    assert report["development_only"] is True
    assert report["valid_for_qualification"] is False
    assert report["decision_summary"]["authorized_once_count"] == 2
    assert report["readiness"]["one_time_authorization_receipts_ready"] is True
    assert (
        report["readiness"]["controlled_pilot_execution_preflight_input_ready"]
        is True
    )
    assert report["readiness"]["controlled_pilot_execution_ready"] is False
    assert len(report["authorization_receipts"]) == 2
    assert all(
        receipt["single_use"] is True
        and receipt["consumed"] is False
        and receipt["controlled_pilot_execution_allowed"] is False
        for receipt in report["authorization_receipts"]
    )


def test_rejections_complete_gate_without_authorization_receipts(
    tmp_path: Path,
) -> None:
    request_path, packet_path = _write_completed_packet(
        tmp_path,
        decision="reject",
    )

    report = reconcile_authorization_decisions(
        authorization_request_report_path=request_path,
        decision_packet_path=packet_path,
        output_path=tmp_path / "reconciliation.json",
        agent_root=tmp_path,
        current_time=DECIDED_AT + timedelta(seconds=10),
    )

    assert report["passed"] is True
    assert report["decision_summary"]["rejected_count"] == 2
    assert report["authorization_receipts"] == []
    assert report["readiness"]["one_time_authorization_receipts_ready"] is False
    assert report["readiness"]["controlled_pilot_execution_ready"] is False


def test_qualification_decision_preserves_profile_and_requires_preflight(
    tmp_path: Path,
) -> None:
    bounded_path, challenge_path = _write_sources(
        tmp_path,
        profile="qualification",
    )
    request = build_authorization_request_gate(
        bounded_plan_report_path=bounded_path,
        challenge_reconciliation_path=challenge_path,
        agent_root=tmp_path,
    )
    request_path = tmp_path / "qualification_request.json"
    request_path.write_text(json.dumps(request), encoding="utf-8")
    packet_path = tmp_path / "qualification_decisions.json"
    packet = create_authorization_decision_packet(
        authorization_request_report_path=request_path,
        output_path=packet_path,
        agent_root=tmp_path,
    )
    for item in packet["decisions"]:
        record_authorization_decision(
            decision_packet_path=packet_path,
            agent_root=tmp_path,
            request_id=item["request_id"],
            decision="authorize_once",
            operator_id="operator-cc",
            reason="authorize one bounded qualification trial",
            monitoring_owner_id="observability_owner",
            audit_owner_id="audit_owner",
            valid_for_seconds=3600,
            preflight_ref="preflight://h3/qualification/a7",
            kill_switch_ref="operator://operator-cc/h3-qualification/stop",
            rollback_checkpoint_ref="rollback://h3/qualification/a7",
            post_run_receipt_sink_ref="receipt://h3/qualification/a8",
            current_time=DECIDED_AT,
        )

    report = reconcile_authorization_decisions(
        authorization_request_report_path=request_path,
        decision_packet_path=packet_path,
        output_path=tmp_path / "qualification_reconciliation.json",
        agent_root=tmp_path,
        current_time=DECIDED_AT + timedelta(seconds=10),
    )

    assert report["passed"] is True
    assert report["validation_profile"] == "qualification"
    assert report["development_only"] is False
    assert report["valid_for_qualification"] is True
    assert (
        "qualification_authorization_requires_qualification_execution_preflight"
        in report["non_claims"]
    )
    assert "development_authorization_is_not_qualification_evidence" not in report[
        "non_claims"
    ]
    assert report["readiness"]["controlled_pilot_execution_ready"] is False


def test_authorization_duration_cannot_exceed_requested_scope(
    tmp_path: Path,
) -> None:
    request_path = _write_request_report(tmp_path)
    packet_path = tmp_path / "authorization_decisions.json"
    packet = create_authorization_decision_packet(
        authorization_request_report_path=request_path,
        output_path=packet_path,
        agent_root=tmp_path,
    )

    with pytest.raises(ValueError, match="between 1 and 1800 seconds"):
        record_authorization_decision(
            decision_packet_path=packet_path,
            agent_root=tmp_path,
            request_id=packet["decisions"][0]["request_id"],
            decision="authorize_once",
            operator_id="operator-cc",
            reason="authorize one bounded development trial",
            monitoring_owner_id="observability_owner",
            audit_owner_id="audit_owner",
            valid_for_seconds=1801,
            preflight_ref="preflight://h3/a7",
            kill_switch_ref="kill-switch://h3/a7",
            rollback_checkpoint_ref="rollback://h3/a7",
            post_run_receipt_sink_ref="receipt://h3/a7",
            current_time=DECIDED_AT,
        )


def test_tampered_request_report_breaks_packet_binding(tmp_path: Path) -> None:
    request_path = _write_request_report(tmp_path)
    packet_path = tmp_path / "authorization_decisions.json"
    create_authorization_decision_packet(
        authorization_request_report_path=request_path,
        output_path=packet_path,
        agent_root=tmp_path,
    )
    request = json.loads(request_path.read_text(encoding="utf-8"))
    request["authorization_request_surface"]["requests"][0]["requested_scope"][
        "max_tasks"
    ] = 2
    request_path.write_text(json.dumps(request), encoding="utf-8")

    report = reconcile_authorization_decisions(
        authorization_request_report_path=request_path,
        decision_packet_path=packet_path,
        output_path=tmp_path / "reconciliation.json",
        agent_root=tmp_path,
        current_time=DECIDED_AT,
    )

    assert report["passed"] is False
    assert report["checks"]["authorization_decision_source_binding"] is False
    assert report["authorization_receipts"] == []


def _write_request_report(tmp_path: Path) -> Path:
    bounded_path, challenge_path = _write_sources(
        tmp_path,
        profile="development",
    )
    request = build_authorization_request_gate(
        bounded_plan_report_path=bounded_path,
        challenge_reconciliation_path=challenge_path,
        agent_root=tmp_path,
    )
    request_path = tmp_path / "authorization_request.json"
    request_path.write_text(json.dumps(request), encoding="utf-8")
    return request_path


def _write_completed_packet(
    tmp_path: Path,
    *,
    decision: str,
) -> tuple[Path, Path]:
    request_path = _write_request_report(tmp_path)
    packet_path = tmp_path / "authorization_decisions.json"
    packet = create_authorization_decision_packet(
        authorization_request_report_path=request_path,
        output_path=packet_path,
        agent_root=tmp_path,
    )
    for item in packet["decisions"]:
        kwargs = {}
        if decision == "authorize_once":
            kwargs = {
                "monitoring_owner_id": "observability_owner",
                "audit_owner_id": "audit_owner",
                "valid_for_seconds": 900,
                "preflight_ref": "preflight://h3/a7",
                "kill_switch_ref": "kill-switch://h3/a7",
                "rollback_checkpoint_ref": "rollback://h3/a7",
                "post_run_receipt_sink_ref": "receipt://h3/a7",
            }
        record_authorization_decision(
            decision_packet_path=packet_path,
            agent_root=tmp_path,
            request_id=item["request_id"],
            decision=decision,
            operator_id="operator-cc",
            reason="explicit bounded development authorization decision",
            current_time=DECIDED_AT,
            **kwargs,
        )
    return request_path, packet_path
