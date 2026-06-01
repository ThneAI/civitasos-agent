from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


module = _load("beta_external_provider_env_preflight", SCRIPTS / "beta_external_provider_env_preflight.py")


def test_provider_env_preflight_accepts_https_and_local_gpu(tmp_path: Path, monkeypatch) -> None:
    first = _write_env(
        tmp_path / "external.env",
        provider="openai_compatible",
        base_url="https://external-agent.example/v1",
        model="external-reviewer-model",
        key="sk-test-secret-not-recorded",
    )
    second = _write_env(
        tmp_path / "local.env",
        provider="local_ollama_gpu",
        base_url="http://127.0.0.1:11434/v1",
        model="qwen3.6:latest",
        key="local-ollama-loopback-token",
        allow_local_http=True,
    )
    monkeypatch.setattr(
        module.beta6,
        "_probe_models_endpoint",
        lambda *, base_url, api_key, model: {
            "provider_probe_attempted": True,
            "reachable": True,
            "http_status": 200,
            "models_endpoint": f"{base_url}/models",
            "requested_model_visible": True,
            "model_count": 1,
            "error_class": None,
        },
    )

    report = module.inspect_provider_envs(
        env_files=[first, second],
        output_path=tmp_path / "preflight.json",
        min_providers=2,
        require_distinct_providers=True,
    )
    report_text = json.dumps(report, sort_keys=True)

    assert report["passed"] is True
    assert report["unique_provider_identity_count"] == 2
    assert report["api_key_recorded"] is False
    assert "sk-test-secret-not-recorded" not in report_text
    assert report["providers"][1]["local_http_allowed"] is True


def test_provider_env_preflight_blocks_public_http(tmp_path: Path) -> None:
    env_file = _write_env(
        tmp_path / "bad.env",
        provider="bad_http_provider",
        base_url="http://example.com/v1",
        model="bad-model",
        key="bad-secret",
        allow_local_http=True,
    )

    report = module.inspect_provider_envs(
        env_files=[env_file],
        output_path=tmp_path / "preflight.json",
        probe_models=False,
    )

    assert report["passed"] is False
    assert any("local HTTP opt-in only allows loopback/private hosts" in reason for reason in report["failure_reasons"])


def _write_env(
    path: Path,
    *,
    provider: str,
    base_url: str,
    model: str,
    key: str,
    allow_local_http: bool = False,
) -> Path:
    lines = [
        f"BETA6_EXTERNAL_AGENT_PROVIDER={provider}",
        f"BETA6_EXTERNAL_AGENT_API_BASE_URL={base_url}",
        f"BETA6_EXTERNAL_AGENT_MODEL={model}",
        f"BETA6_EXTERNAL_AGENT_API_KEY={key}",
    ]
    if allow_local_http:
        lines.append("BETA6_EXTERNAL_AGENT_ALLOW_LOCAL_HTTP=true")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path
