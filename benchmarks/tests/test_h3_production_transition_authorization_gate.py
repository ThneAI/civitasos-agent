from __future__ import annotations

from pathlib import Path

from benchmarks.h3_production_transition_authorization_gate import REQUIRED_OPERATOR_DECISION, run_gate
from benchmarks.p1r_real_source_confirmation_gate import run_gate as run_p1r
from benchmarks.tests.test_p1r_real_source_confirmation_gate import _write_confirmations, _write_p0q_inputs


def test_h3_production_transition_authorization_allows_next_stage_after_p1r_16(tmp_path: Path) -> None:
    p1r_summary = _write_p1r_summary(tmp_path)

    report = run_gate(
        p1r_summary_path=p1r_summary,
        output=tmp_path / "h3_transition.json",
        operator_id="operator-alpha",
        operator_decision=REQUIRED_OPERATOR_DECISION,
        operator_statement="Authorize H.3 production transition after P1-R reaches 16/16.",
    )

    assert report["passed"] is True
    assert report["readiness"]["h3_production_transition_authorized"] is True
    assert report["readiness"]["production_transition_allowed"] is True
    assert report["boundary"]["production_transition_allowed"] is True
    assert report["boundary"]["runtime_execution_allowed"] is False
    assert report["boundary"]["production_receipt_write_allowed"] is False


def test_h3_production_transition_authorization_blocks_wrong_operator_decision(tmp_path: Path) -> None:
    p1r_summary = _write_p1r_summary(tmp_path)

    report = run_gate(
        p1r_summary_path=p1r_summary,
        output=tmp_path / "h3_transition.json",
        operator_id="operator-alpha",
        operator_decision="approve_notes_only",
        operator_statement="Authorize H.3 production transition after P1-R reaches 16/16.",
    )

    assert report["passed"] is False
    assert report["readiness"]["production_transition_allowed"] is False
    assert report["boundary"]["production_transition_allowed"] is False
    assert "operator_decision_authorizes_transition" in report["failure_reasons"]


def _write_p1r_summary(tmp_path: Path) -> Path:
    p0q_summary, p1_summary = _write_p0q_inputs(tmp_path)
    confirmations = _write_confirmations(tmp_path)
    run_p1r(
        p0q_summary_path=p0q_summary,
        p1_summary_path=p1_summary,
        owner_confirmation_path=confirmations["owner"],
        audit_confirmation_path=confirmations["audit"],
        monitoring_confirmation_path=confirmations["monitoring"],
        rollback_confirmation_path=confirmations["rollback"],
        output_root=tmp_path / "p1r",
    )
    return tmp_path / "p1r" / "p1r_real_source_confirmation_summary.json"
