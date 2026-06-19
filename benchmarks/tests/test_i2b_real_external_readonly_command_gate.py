from __future__ import annotations

import json
from pathlib import Path

import benchmarks.i2b_real_external_readonly_command_gate as gate
from benchmarks.i2b_real_external_readonly_command_gate import run_gate, write_operator_review
from benchmarks.tests.i_gate_fixtures import i2b_response, write_external_env, write_i2a_summary


def test_i2b_chain_uses_mock_external_response_without_granting_write_authority(tmp_path: Path) -> None:
    i2a = write_i2a_summary(tmp_path, passed=True)
    env_file = write_external_env(tmp_path / ".env.beta6.external.local")
    response = i2b_response(recommendation="remain_blocked_for_real_task_commanding")

    summary = run_gate(
        i2a_summary_path=i2a,
        env_file=env_file,
        output_root=tmp_path / "i2b",
        api_response_override=response,
    )

    assert summary["passed"] is True
    assert summary["readiness"]["i2b_read_only_external_command_complete"] is True
    assert summary["readiness"]["real_task_command_allowed"] is False
    assert summary["boundary"]["scoped_external_agent_command_allowed"] is True
    assert summary["boundary"]["source_tree_write_allowed"] is False
    assert summary["boundary"]["git_write_allowed"] is False
    assert summary["boundary"]["production_transition_allowed"] is False
    assert "secret-test-key" not in (tmp_path / "i2b" / "i2b_chain_summary.json").read_text()

    execution = json.loads((tmp_path / "i2b" / "i2b_command_execution_receipt.json").read_text())
    assert execution["execution"]["provider_api_network_used"] is True
    assert execution["execution"]["external_side_effect_observed"] is False


def test_i2b_operator_review_blocks_failed_i2a(tmp_path: Path) -> None:
    i2a = write_i2a_summary(tmp_path, passed=False)

    report = write_operator_review(
        i2a_summary_path=i2a,
        output=tmp_path / "operator_review.json",
        operator_id="operator-cc",
    )

    assert report["passed"] is False
    assert report["checks"]["i2a_summary_passed"] is False


def test_i2b_provider_exception_writes_fail_closed_receipts(tmp_path: Path, monkeypatch) -> None:
    i2a = write_i2a_summary(tmp_path, passed=True)
    env_file = write_external_env(tmp_path / ".env.beta6.external.local")

    def fail_provider(**_: object) -> tuple[str, int]:
        raise RuntimeError("provider unavailable")

    monkeypatch.setattr(gate, "_call_openai_compatible", fail_provider)

    summary = run_gate(
        i2a_summary_path=i2a,
        env_file=env_file,
        output_root=tmp_path / "i2b_fail_closed",
    )

    assert summary["passed"] is False
    api_call = json.loads((tmp_path / "i2b_fail_closed" / "i2b_real_external_agent_api_call_report.json").read_text())
    assert api_call["passed"] is False
    assert "external provider call failed: provider unavailable" in api_call["failure_reasons"]
    assert summary["readiness"]["real_task_command_allowed"] is False
