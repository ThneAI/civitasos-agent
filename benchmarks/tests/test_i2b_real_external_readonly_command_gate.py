from __future__ import annotations

import json
import os
from pathlib import Path

from benchmarks.i2b_real_external_readonly_command_gate import RESPONSE_SCHEMA, run_gate, write_operator_review


def test_i2b_chain_uses_mock_external_response_without_granting_write_authority(tmp_path: Path) -> None:
    i2a = _write_i2a_summary(tmp_path, passed=True)
    env_file = _write_env(tmp_path)
    response = json.dumps(
        {
            "schema_version": RESPONSE_SCHEMA,
            "command_id": "__COMMAND_ID__",
            "accepted": True,
            "verdict": "accepted_scope_executed_read_only",
            "summary": "Read-only review completed.",
            "observations": ["I.2-A remained no-side-effect.", "A separate operator gate is still required."],
            "recommendation": "remain_blocked_for_real_task_commanding",
            "boundary_attestation": {
                "network_used_only_for_provider_api": True,
                "source_tree_modified": False,
                "git_used": False,
                "runtime_state_mutated": False,
                "production_touched": False,
            },
        }
    )

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
    i2a = _write_i2a_summary(tmp_path, passed=False)

    report = write_operator_review(
        i2a_summary_path=i2a,
        output=tmp_path / "operator_review.json",
        operator_id="operator-cc",
    )

    assert report["passed"] is False
    assert report["checks"]["i2a_summary_passed"] is False


def _write_i2a_summary(tmp_path: Path, *, passed: bool) -> Path:
    path = tmp_path / "i2a_summary.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": "i2a-controlled-command-chain:v1",
                "passed": passed,
                "readiness": {
                    "operator_discussion_required_for_i2b": True,
                    "real_task_command_allowed": False,
                },
                "boundary": {"real_task_command_allowed": False},
            }
        ),
        encoding="utf-8",
    )
    return path


def _write_env(tmp_path: Path) -> Path:
    path = tmp_path / ".env.beta6.external.local"
    path.write_text(
        "\n".join(
            [
                "BETA6_EXTERNAL_AGENT_PROVIDER=openai_compatible",
                "BETA6_EXTERNAL_AGENT_API_BASE_URL=https://api.example.test",
                "BETA6_EXTERNAL_AGENT_MODEL=example-model",
                "BETA6_EXTERNAL_AGENT_API_KEY=secret-test-key",
            ]
        ),
        encoding="utf-8",
    )
    os.chmod(path, 0o600)
    return path
