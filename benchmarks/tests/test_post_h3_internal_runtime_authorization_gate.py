from __future__ import annotations

import json
from pathlib import Path

from benchmarks.h3_production_transition_authorization_gate import REQUIRED_OPERATOR_DECISION as H3_TRANSITION_DECISION
from benchmarks.h3_production_transition_authorization_gate import run_gate as run_h3_transition
from benchmarks.post_h3_internal_runtime_authorization_gate import REQUIRED_OPERATOR_DECISION, run_gate
from benchmarks.tests.test_h3_production_transition_authorization_gate import _write_p1r_summary


def test_post_h3_authorizes_internal_runtime_after_transition(tmp_path: Path) -> None:
    h3_transition = _write_h3_transition(tmp_path)

    summary = run_gate(
        h3_transition_path=h3_transition,
        output_root=tmp_path / "post_h3a",
        operator_id="operator-alpha",
        operator_decision=REQUIRED_OPERATOR_DECISION,
        operator_statement="Authorize internal controlled runtime after H.3 transition.",
        ack_internal_runtime=True,
    )

    assert summary["passed"] is True
    assert summary["readiness"]["post_h3_internal_runtime_authorized"] is True
    assert summary["readiness"]["runtime_execution_allowed"] is True
    assert summary["readiness"]["runtime_execution_performed"] is False
    assert summary["readiness"]["production_runtime_receipt_write_allowed"] is False
    assert summary["boundary"]["authorization_request_written"] is True
    assert summary["boundary"]["authorization_decision_written"] is True
    assert summary["boundary"]["authorization_receipt_written"] is True
    assert summary["boundary"]["internal_runtime_execution_authorized"] is True
    assert summary["boundary"]["runtime_execution_performed"] is False
    assert summary["boundary"]["external_public_ingress_opened"] is False


def test_post_h3_requires_operator_ack(tmp_path: Path) -> None:
    h3_transition = _write_h3_transition(tmp_path)

    summary = run_gate(
        h3_transition_path=h3_transition,
        output_root=tmp_path / "post_h3a",
        operator_id="operator-alpha",
        operator_decision=REQUIRED_OPERATOR_DECISION,
        operator_statement="Authorize internal controlled runtime after H.3 transition.",
        ack_internal_runtime=False,
    )

    assert summary["passed"] is False
    assert "explicit_operator_ack" in summary["failure_reasons"]
    assert summary["readiness"]["runtime_execution_allowed"] is False


def test_post_h3_blocks_if_transition_authorization_drifts(tmp_path: Path) -> None:
    h3_transition = _write_h3_transition(tmp_path)
    payload = json.loads(h3_transition.read_text(encoding="utf-8"))
    payload["readiness"]["production_transition_allowed"] = False
    h3_transition.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    summary = run_gate(
        h3_transition_path=h3_transition,
        output_root=tmp_path / "post_h3a",
        operator_id="operator-alpha",
        operator_decision=REQUIRED_OPERATOR_DECISION,
        operator_statement="Authorize internal controlled runtime after H.3 transition.",
        ack_internal_runtime=True,
    )

    assert summary["passed"] is False
    assert "production_transition_allowed" in summary["failure_reasons"]
    assert summary["boundary"]["internal_runtime_execution_authorized"] is False


def _write_h3_transition(tmp_path: Path) -> Path:
    p1r_summary = _write_p1r_summary(tmp_path)
    output = tmp_path / "h3_transition.json"
    run_h3_transition(
        p1r_summary_path=p1r_summary,
        output=output,
        operator_id="operator-alpha",
        operator_decision=H3_TRANSITION_DECISION,
        operator_statement="Authorize H.3 production transition after P1-R reaches 16/16.",
    )
    return output
