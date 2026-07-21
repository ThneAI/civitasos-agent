from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from benchmarks.j1.controlled_comparison import write_private_json
from benchmarks.j1.qualification_execution_authorization import (
    build_execution_authorization,
)
from benchmarks.j1_qualification_execution_authorization_gate import (
    GATE_SCHEMA,
    run_gate,
)
from benchmarks.tests.test_j1_qualification_execution_authorization import (
    IMPLEMENTATION,
    NOW,
    _context,
    _reviewer,
    _Signer,
)
from nacl.signing import SigningKey


def _source(tmp_path: Path) -> tuple[dict, dict, dict]:
    key = SigningKey.generate()
    reviewer = _reviewer(key)
    context = _context(tmp_path)
    return context, reviewer, {"key": key}


def _receipt_path(
    tmp_path: Path, context: dict, reviewer: dict, key: SigningKey
) -> Path:
    profile_hash = hashlib.sha256(
        json.dumps(reviewer, sort_keys=True).encode()
    ).hexdigest()
    receipt = build_execution_authorization(
        authorization_id="j1d-execution-authorization-20260722-r1",
        issued_at=NOW.isoformat(),
        ttl_seconds=1800,
        owner_authorization_id="j1d-owner-execution-approval-20260722-r1",
        owner_statement_sha256="a" * 64,
        context=context,
        reviewer_profile=reviewer,
        reviewer_profile_sha256=profile_hash,
        implementation=IMPLEMENTATION,
        signer=_Signer(key),
    )
    path = tmp_path / "authorization.json"
    write_private_json(path, receipt)
    return path


def test_gate_accepts_current_signed_unconsumed_authorization(
    tmp_path: Path, monkeypatch
) -> None:
    context, reviewer, holder = _source(tmp_path)
    receipt_path = _receipt_path(tmp_path, context, reviewer, holder["key"])
    monkeypatch.setattr(
        "benchmarks.j1_qualification_execution_authorization_gate.load_authorization_source_context",
        lambda **_: {
            "context": context,
            "reviewer_profile": reviewer,
            "reviewer_profile_sha256": json.loads(
                receipt_path.read_text(encoding="utf-8")
            )["reviewer"]["identity_profile_sha256"],
            "implementation": IMPLEMENTATION,
            "artifacts": {},
        },
    )

    report = run_gate(
        authorization_receipt_path=receipt_path,
        qualification_protocol_path=tmp_path / "protocol.json",
        reviewed_roster_path=tmp_path / "roster.json",
        roster_gate_report_path=tmp_path / "roster-gate.json",
        reviewed_assignment_path=tmp_path / "assignment.json",
        assignment_gate_report_path=tmp_path / "assignment-gate.json",
        admission_request_path=tmp_path / "request.json",
        provider_admission_report_path=tmp_path / "admission.json",
        provider_env_path=tmp_path / ".env",
        reviewer_profile_path=tmp_path / "reviewer.json",
        evidence_root=tmp_path / "evidence",
        run_id="j1d-qualification-run-20260722-r1",
        execution_root=tmp_path / "execution",
        consumption_path=tmp_path / "authorization-consumption.json",
        agent_revision="a" * 40,
        output_path=tmp_path / "gate-report.json",
        current_time=NOW,
    )

    assert report["schema_version"] == GATE_SCHEMA
    assert report["passed"] is True
    assert report["readiness"]["controlled_experiment_execution_ready"] is True
    assert report["execution_boundary"]["authorization_consumed"] is False


def test_gate_rejects_existing_consumption_and_expired_receipt(
    tmp_path: Path, monkeypatch
) -> None:
    context, reviewer, holder = _source(tmp_path)
    receipt_path = _receipt_path(tmp_path, context, reviewer, holder["key"])
    consumption = tmp_path / "authorization-consumption.json"
    consumption.write_text("claimed\n", encoding="utf-8")
    monkeypatch.setattr(
        "benchmarks.j1_qualification_execution_authorization_gate.load_authorization_source_context",
        lambda **_: {
            "context": context,
            "reviewer_profile": reviewer,
            "reviewer_profile_sha256": json.loads(
                receipt_path.read_text(encoding="utf-8")
            )["reviewer"]["identity_profile_sha256"],
            "implementation": IMPLEMENTATION,
            "artifacts": {},
        },
    )

    report = run_gate(
        authorization_receipt_path=receipt_path,
        qualification_protocol_path=tmp_path / "protocol.json",
        reviewed_roster_path=tmp_path / "roster.json",
        roster_gate_report_path=tmp_path / "roster-gate.json",
        reviewed_assignment_path=tmp_path / "assignment.json",
        assignment_gate_report_path=tmp_path / "assignment-gate.json",
        admission_request_path=tmp_path / "request.json",
        provider_admission_report_path=tmp_path / "admission.json",
        provider_env_path=tmp_path / ".env",
        reviewer_profile_path=tmp_path / "reviewer.json",
        evidence_root=tmp_path / "evidence",
        run_id="j1d-qualification-run-20260722-r1",
        execution_root=tmp_path / "execution",
        consumption_path=consumption,
        agent_revision="a" * 40,
        output_path=tmp_path / "gate-report.json",
        current_time=datetime(2026, 7, 22, 1, 0, tzinfo=timezone.utc),
    )

    assert report["passed"] is False
    assert "authorization_not_current" in report["failure_reasons"]
    assert "authorization_already_consumed" in report["failure_reasons"]
    assert report["readiness"]["controlled_experiment_execution_ready"] is False
