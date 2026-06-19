from __future__ import annotations

from pathlib import Path

from benchmarks.i2b_provider_contrast_gate import run_contrast
from benchmarks.tests.i_gate_fixtures import i2b_response, write_external_env, write_i2a_summary


def test_i2b_provider_contrast_passes_with_two_distinct_mocked_providers(tmp_path: Path) -> None:
    i2a = write_i2a_summary(tmp_path)
    env_a = write_external_env(tmp_path / "a.env", provider="openai_compatible", base_url="https://api.example.test", model="remote-model")
    env_b = write_external_env(tmp_path / "b.env", provider="local_ollama_gpu", base_url="http://127.0.0.1:11434/v1", model="local-model", allow_local=True)
    overrides = {
        "deepseek-api-agent": i2b_response(),
        "local-gpu-agent": i2b_response(),
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
