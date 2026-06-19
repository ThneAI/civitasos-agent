from __future__ import annotations

import json
from pathlib import Path

from benchmarks.i2a_controlled_command_chain import run_chain, write_operator_review


def test_i2a_chain_passes_without_real_external_commanding(tmp_path: Path) -> None:
    request = _write_i2_request(tmp_path, passed=True)

    summary = run_chain(i2_request_path=request, output_root=tmp_path / "i2a")

    assert summary["passed"] is True
    assert summary["readiness"]["i2a_protocol_smoke_complete"] is True
    assert summary["readiness"]["real_external_agent_command_allowed"] is False
    assert summary["boundary"]["production_transition_allowed"] is False

    execution = json.loads((tmp_path / "i2a" / "i2a_command_execution_receipt.json").read_text())
    assert execution["passed"] is True
    assert execution["execution"]["command_consumed"] is True
    assert execution["execution"]["external_side_effect_observed"] is False
    output_ref = execution["execution"]["output_artifact"]
    assert Path(output_ref["path"]).is_file()

    reconciliation = json.loads((tmp_path / "i2a" / "i2a_operator_reconciliation.json").read_text())
    assert reconciliation["readiness"]["i2b_real_external_command_discussion_ready"] is True
    assert reconciliation["readiness"]["real_task_command_allowed"] is False


def test_i2a_operator_review_blocks_failed_i2_request(tmp_path: Path) -> None:
    request = _write_i2_request(tmp_path, passed=False)

    report = write_operator_review(
        i2_request_path=request,
        output=tmp_path / "operator_review.json",
        operator_id="operator-cc",
    )

    assert report["passed"] is False
    assert report["checks"]["i2_request_passed"] is False
    assert report["readiness"]["i2_execution_allowed"] is False


def _write_i2_request(tmp_path: Path, *, passed: bool) -> Path:
    path = tmp_path / "i2_request.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": "i2-external-command-gate-request:v1",
                "passed": passed,
                "request": {
                    "request_id": "i2-request:test",
                    "required_future_evidence": [
                        "external_agent_registration_receipt",
                        "scoped_command_authorization_request",
                        "external_agent_acceptance_receipt",
                        "isolation_policy_preflight",
                        "command_execution_receipt",
                        "rollback_or_abort_receipt",
                        "operator_reconciliation",
                    ],
                },
                "readiness": {
                    "i2_gate_requested": True,
                    "operator_authorization_required": True,
                    "i2_execution_allowed": False,
                },
                "boundary": {"external_agent_command_allowed": False},
            }
        ),
        encoding="utf-8",
    )
    return path
