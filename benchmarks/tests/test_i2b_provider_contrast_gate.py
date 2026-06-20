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


def test_i2b_provider_contrast_blocks_single_provider_and_keeps_boundaries_closed(tmp_path: Path) -> None:
    i2a = write_i2a_summary(tmp_path)
    env_a = write_external_env(
        tmp_path / "a.env",
        provider="openai_compatible",
        base_url="https://api.example.test",
        model="remote-model",
    )

    report = run_contrast(
        i2a_summary_path=i2a,
        provider_specs=[f"deepseek-api-agent={env_a}"],
        output_root=tmp_path / "contrast",
        api_response_overrides={"deepseek-api-agent": i2b_response()},
    )

    assert report["passed"] is False
    assert "provider count must be >= min_passed_providers" in report["failure_reasons"]
    assert report["metrics"]["provider_count"] == 1
    assert report["metrics"]["passed_provider_count"] == 1
    assert report["checks"]["minimum_providers_passed"] is False
    assert report["readiness"]["i2b_provider_contrast_complete"] is False
    assert report["readiness"]["i2c_bounded_apply_discussion_ready"] is False
    assert report["readiness"]["real_task_command_allowed"] is False
    assert report["readiness"]["source_or_git_write_allowed"] is False
    assert report["readiness"]["production_transition_allowed"] is False
    assert report["boundary"]["source_tree_write_allowed"] is False
    assert report["boundary"]["git_write_allowed"] is False
    assert report["boundary"]["runtime_state_mutation_allowed"] is False
    assert report["boundary"]["deploy_allowed"] is False
    assert report["boundary"]["production_transition_allowed"] is False


def test_i2b_provider_contrast_blocks_same_provider_host_and_model(tmp_path: Path) -> None:
    i2a = write_i2a_summary(tmp_path)
    env_a = write_external_env(
        tmp_path / "a.env",
        provider="openai_compatible",
        base_url="https://api.example.test",
        model="same-model",
    )
    env_b = write_external_env(
        tmp_path / "b.env",
        provider="openai_compatible",
        base_url="https://api.example.test",
        model="same-model",
    )

    report = run_contrast(
        i2a_summary_path=i2a,
        provider_specs=[f"deepseek-api-agent={env_a}", f"second-api-agent={env_b}"],
        output_root=tmp_path / "contrast",
        api_response_overrides={
            "deepseek-api-agent": i2b_response(),
            "second-api-agent": i2b_response(),
        },
    )

    assert report["passed"] is False
    assert report["metrics"]["provider_count"] == 2
    assert report["metrics"]["passed_provider_count"] == 2
    assert report["metrics"]["provider_host_count"] == 1
    assert report["metrics"]["model_count"] == 1
    assert report["checks"]["minimum_providers_passed"] is True
    assert report["checks"]["provider_diversity_observed"] is False
    assert "provider_diversity_observed" in report["failure_reasons"]
    assert report["readiness"]["i2b_provider_contrast_complete"] is False
    assert report["readiness"]["source_or_git_write_allowed"] is False
    assert report["boundary"]["source_tree_write_allowed"] is False
    assert report["boundary"]["git_write_allowed"] is False
