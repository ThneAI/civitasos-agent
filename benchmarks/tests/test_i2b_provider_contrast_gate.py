from __future__ import annotations

import json
import os
from pathlib import Path

from benchmarks.i2b_real_external_readonly_command_gate import RESPONSE_SCHEMA
from benchmarks.i2b_provider_contrast_gate import run_contrast


def test_i2b_provider_contrast_passes_with_two_distinct_mocked_providers(tmp_path: Path) -> None:
    i2a = _write_i2a_summary(tmp_path)
    env_a = _write_env(tmp_path / "a.env", provider="openai_compatible", base_url="https://api.example.test", model="remote-model")
    env_b = _write_env(tmp_path / "b.env", provider="local_ollama_gpu", base_url="http://127.0.0.1:11434/v1", model="local-model", allow_local=True)
    overrides = {
        "deepseek-api-agent": _response(),
        "local-gpu-agent": _response(),
    }

    report = run_contrast(
        i2a_summary_path=i2a,
        provider_specs=[f"deepseek-api-agent={env_a}", f"local-gpu-agent={env_b}"],
        output_root=tmp_path / "contrast",
        api_response_overrides=overrides,
    )

    assert report["passed"] is True
    assert report["metrics"]["passed_provider_count"] == 2
    assert report["checks"]["provider_diversity_observed"] is True
    assert report["readiness"]["real_task_command_allowed"] is False
    assert report["boundary"]["source_tree_write_allowed"] is False


def _write_i2a_summary(tmp_path: Path) -> Path:
    path = tmp_path / "i2a_summary.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": "i2a-controlled-command-chain:v1",
                "passed": True,
                "readiness": {"operator_discussion_required_for_i2b": True, "real_task_command_allowed": False},
                "boundary": {"real_task_command_allowed": False},
            }
        ),
        encoding="utf-8",
    )
    return path


def _write_env(path: Path, *, provider: str, base_url: str, model: str, allow_local: bool = False) -> Path:
    lines = [
        f"BETA6_EXTERNAL_AGENT_PROVIDER={provider}",
        f"BETA6_EXTERNAL_AGENT_API_BASE_URL={base_url}",
        f"BETA6_EXTERNAL_AGENT_MODEL={model}",
        "BETA6_EXTERNAL_AGENT_API_KEY=secret-test-key",
    ]
    if allow_local:
        lines.append("BETA6_EXTERNAL_AGENT_ALLOW_LOCAL_HTTP=true")
    path.write_text("\n".join(lines), encoding="utf-8")
    os.chmod(path, 0o600)
    return path


def _response() -> str:
    return json.dumps(
        {
            "schema_version": RESPONSE_SCHEMA,
            "command_id": "__COMMAND_ID__",
            "accepted": True,
            "verdict": "accepted_scope_executed_read_only",
            "summary": "Read-only provider contrast completed.",
            "observations": ["Boundary remained closed.", "Operator review is required for the next gate."],
            "recommendation": "operator_review_before_next_gate",
            "boundary_attestation": {
                "network_used_only_for_provider_api": True,
                "source_tree_modified": False,
                "git_used": False,
                "runtime_state_mutated": False,
                "production_touched": False,
            },
        }
    )
