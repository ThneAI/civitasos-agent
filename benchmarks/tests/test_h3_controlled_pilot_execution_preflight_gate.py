from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from benchmarks.h3_controlled_pilot_authorization_decision_gate import (
    create_authorization_decision_packet,
    reconcile_authorization_decisions,
    record_authorization_decision,
)
from benchmarks.h3_controlled_pilot_authorization_request_gate import (
    build_authorization_request_gate,
)
from benchmarks.h3_controlled_pilot_execution_preflight_gate import (
    build_execution_preflight,
)
from benchmarks.h3_controlled_pilot_receipts import (
    AUTHORIZATION_RECEIPT_SCHEMA_VERSION,
)
from benchmarks.tests.test_h3_controlled_pilot_authorization_request_gate import (
    _write_sources,
)


DECIDED_AT = datetime(2026, 6, 9, 8, 0, tzinfo=timezone.utc)


def test_valid_receipt_builds_runner_input_without_execution(tmp_path: Path) -> None:
    reconciliation_path, receipt_id, preflight_path = _write_authorization(tmp_path)

    report = build_execution_preflight(
        authorization_reconciliation_path=reconciliation_path,
        authorization_receipt_id=receipt_id,
        output_path=preflight_path,
        agent_root=tmp_path,
        current_time=DECIDED_AT + timedelta(seconds=10),
    )

    assert report["passed"] is True
    assert report["readiness"]["controlled_runner_input_ready"] is True
    assert report["readiness"]["controlled_pilot_execution_ready"] is False
    assert report["boundary"]["controlled_runner_input_ready"] is True
    assert report["boundary"]["agent_dispatch_allowed"] is False
    assert report["boundary"]["runtime_execution_allowed"] is False
    assert (
        report["authorization_receipt"]["schema_version"]
        == AUTHORIZATION_RECEIPT_SCHEMA_VERSION
    )
    assert Path(report["rollback_checkpoint"]["path"]).is_file()


def test_expired_receipt_fails_closed(tmp_path: Path) -> None:
    reconciliation_path, receipt_id, preflight_path = _write_authorization(tmp_path)

    report = build_execution_preflight(
        authorization_reconciliation_path=reconciliation_path,
        authorization_receipt_id=receipt_id,
        output_path=preflight_path,
        agent_root=tmp_path,
        current_time=DECIDED_AT + timedelta(seconds=901),
    )

    assert report["passed"] is False
    assert report["checks"]["authorization_receipt_currently_valid"] is False
    assert report["readiness"]["controlled_runner_input_ready"] is False


def test_tampered_decision_packet_fails_hash_binding(tmp_path: Path) -> None:
    reconciliation_path, receipt_id, preflight_path = _write_authorization(tmp_path)
    reconciliation = json.loads(reconciliation_path.read_text(encoding="utf-8"))
    packet_path = Path(reconciliation["source_decision_packet"]["path"])
    packet = json.loads(packet_path.read_text(encoding="utf-8"))
    packet["decisions"][0]["reason"] = "tampered authorization reason"
    packet_path.write_text(json.dumps(packet), encoding="utf-8")

    report = build_execution_preflight(
        authorization_reconciliation_path=reconciliation_path,
        authorization_receipt_id=receipt_id,
        output_path=preflight_path,
        agent_root=tmp_path,
        current_time=DECIDED_AT + timedelta(seconds=10),
    )

    assert report["passed"] is False
    assert report["checks"]["authorization_decision_packet_hash"] is False
    assert report["authorization_receipt"] is None


def test_qualification_receipt_builds_qualification_runner_input(
    tmp_path: Path,
) -> None:
    reconciliation_path, receipt_id, preflight_path = _write_authorization(
        tmp_path,
        profile="qualification",
        valid_for_seconds=3600,
    )

    report = build_execution_preflight(
        authorization_reconciliation_path=reconciliation_path,
        authorization_receipt_id=receipt_id,
        output_path=preflight_path,
        agent_root=tmp_path,
        current_time=DECIDED_AT + timedelta(seconds=10),
    )

    assert report["passed"] is True
    assert report["validation_profile"] == "qualification"
    assert report["development_only"] is False
    assert report["valid_for_qualification"] is True
    assert (
        report["readiness"]["decision"]
        == "h3_qualification_controlled_runner_input_ready"
    )
    assert report["readiness"]["controlled_pilot_execution_ready"] is False
    assert (
        "qualification_preflight_does_not_itself_execute_the_controlled_pilot"
        in report["non_claims"]
    )


def test_qualification_receipt_rejects_development_scope(
    tmp_path: Path,
) -> None:
    reconciliation_path, receipt_id, preflight_path = _write_authorization(
        tmp_path,
        profile="qualification",
        valid_for_seconds=3600,
    )
    reconciliation = json.loads(reconciliation_path.read_text(encoding="utf-8"))
    reconciliation["authorization_receipts"][0]["authorized_scope"][
        "environment"
    ] = "development_local_controlled_only"
    reconciliation_path.write_text(json.dumps(reconciliation), encoding="utf-8")

    report = build_execution_preflight(
        authorization_reconciliation_path=reconciliation_path,
        authorization_receipt_id=receipt_id,
        output_path=preflight_path,
        agent_root=tmp_path,
        current_time=DECIDED_AT + timedelta(seconds=10),
    )

    assert report["passed"] is False
    assert report["checks"]["authorization_scope_profile_valid"] is False


def _write_authorization(
    tmp_path: Path,
    *,
    profile: str = "development",
    valid_for_seconds: int = 900,
) -> tuple[Path, str, Path]:
    bounded_path, challenge_path = _write_sources(
        tmp_path,
        profile=profile,
    )
    request = build_authorization_request_gate(
        bounded_plan_report_path=bounded_path,
        challenge_reconciliation_path=challenge_path,
        agent_root=tmp_path,
    )
    request_path = tmp_path / "authorization_request.json"
    request_path.write_text(json.dumps(request), encoding="utf-8")
    packet_path = tmp_path / "authorization_decisions.json"
    packet = create_authorization_decision_packet(
        authorization_request_report_path=request_path,
        output_path=packet_path,
        agent_root=tmp_path,
    )
    preflight_path = tmp_path / "execution_preflight.json"
    rollback_path = tmp_path / "rollback_checkpoint.json"
    receipt_path = tmp_path / "post_run_receipt.json"
    for item in packet["decisions"]:
        record_authorization_decision(
            decision_packet_path=packet_path,
            agent_root=tmp_path,
            request_id=item["request_id"],
            decision="authorize_once",
            operator_id="operator-cc",
            reason=f"authorize one bounded {profile} controlled pilot",
            monitoring_owner_id="observability_owner",
            audit_owner_id="audit_owner",
            valid_for_seconds=valid_for_seconds,
            preflight_ref=str(preflight_path),
            kill_switch_ref=f"operator://operator-cc/h3-{profile}-pilot/stop",
            rollback_checkpoint_ref=str(rollback_path),
            post_run_receipt_sink_ref=str(receipt_path),
            current_time=DECIDED_AT,
        )
    reconciliation_path = tmp_path / "authorization_reconciliation.json"
    reconciliation = reconcile_authorization_decisions(
        authorization_request_report_path=request_path,
        decision_packet_path=packet_path,
        output_path=reconciliation_path,
        agent_root=tmp_path,
        current_time=DECIDED_AT + timedelta(seconds=1),
    )
    receipt_id = reconciliation["authorization_receipts"][0][
        "authorization_receipt_id"
    ]
    return reconciliation_path, receipt_id, preflight_path
