from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "beta_runtime_lifecycle.py"


def _load():
    spec = importlib.util.spec_from_file_location("beta_runtime_lifecycle", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


module = _load()


def test_local_beta_runtime_lifecycle_preserves_then_cleans_state(tmp_path: Path, monkeypatch) -> None:
    backend_root = tmp_path / "backend"
    frontend_root = tmp_path / "frontend"
    agent_root = tmp_path / "agent"
    state_root = tmp_path / "state"
    backend_root.mkdir()
    (frontend_root / "build").mkdir(parents=True)
    agent_root.mkdir()

    backend = backend_root / "api_only"
    _write_executable(backend, _fake_backend_source())
    (frontend_root / "build" / "index.html").write_text("beta frontend", encoding="utf-8")
    (agent_root / "agent.py").write_text(_fake_agent_source(), encoding="utf-8")
    env_file = agent_root / ".env.beta.local"
    env_file.write_text(
        "\n".join(
            (
                "CIVITASOS_SERVICE_TOKEN_SECRET=test-service-secret",
                "CIVITASOS_WAKE_CALLBACK_SECRET=test-wake-secret",
                "AGENT_LLM=ollama:test-model",
                "LLM_BASE_URL=http://127.0.0.1:11434/v1",
            )
        )
        + "\n",
        encoding="utf-8",
    )
    os.chmod(env_file, 0o600)

    real_spawn = module._spawn

    def spawn_without_network(config, name, _command, cwd, env):
        real_spawn(config, name, [sys.executable, str(agent_root / "agent.py")], cwd, env)

    config = module.RuntimeConfig.from_env(
        {
            "CIVITASOS_BETA_RUNTIME_STATE_ROOT": str(state_root),
            "CIVITASOS_BETA_RUNTIME_ENV_FILE": str(env_file),
            "CIVITASOS_BETA_BACKEND_ROOT": str(backend_root),
            "CIVITASOS_BETA_BACKEND_BIN": str(backend),
            "CIVITASOS_BETA_FRONTEND_ROOT": str(frontend_root),
            "CIVITASOS_BETA_AGENT_ROOT": str(agent_root),
            "CIVITASOS_BETA_AGENT_PYTHON": sys.executable,
            "CIVITASOS_BETA_BACKEND_PORT": "18181",
            "CIVITASOS_BETA_FRONTEND_PORT": "18182",
            "CIVITASOS_BETA_AGENT_GATEWAY_PORT": "18300",
        }
    )
    monkeypatch.setattr(module, "_spawn", spawn_without_network)
    monkeypatch.setattr(module, "_wait_for_url", lambda *_args, **_kwargs: None)

    def owned_endpoint_is_healthy(url: str) -> bool:
        if str(config.backend_port) in url:
            return module._service_running(config, "backend")
        if str(config.frontend_port) in url:
            return module._service_running(config, "frontend")
        return False

    monkeypatch.setattr(module, "_url_healthy", owned_endpoint_is_healthy)

    try:
        assert module.preflight(config)["passed"] is True
        started = module.start(config)
        assert started["passed"] is True
        assert all(item["running"] for item in started["processes"].values())
        assert state_root.stat().st_mode & 0o777 == 0o700
        serialized = json.dumps(started)
        assert "test-service-secret" not in serialized
        assert "test-wake-secret" not in serialized
        assert module.status(config)["passed"] is True

        marker = state_root / "agent" / "data" / "memory-marker"
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text("preserve", encoding="utf-8")
        stopped = module.stop(config)
        assert stopped["passed"] is True
        assert stopped["state_preserved"] is True
        assert marker.is_file()
        assert module.status(config)["passed"] is False

        refused = module.cleanup(config, confirm=False)
        assert refused["passed"] is False
        assert state_root.exists()
        cleaned = module.cleanup(config, confirm=True)
        assert cleaned["passed"] is True
        assert cleaned["state_removed"] is True
    finally:
        if state_root.exists():
            module.cleanup(config, confirm=True)


def test_preflight_rejects_readable_secret_file(tmp_path: Path) -> None:
    config = module.RuntimeConfig.from_env(
        {
            "CIVITASOS_BETA_RUNTIME_STATE_ROOT": str(tmp_path / "state"),
            "CIVITASOS_BETA_RUNTIME_ENV_FILE": str(tmp_path / "env"),
            "CIVITASOS_BETA_BACKEND_ROOT": str(tmp_path),
            "CIVITASOS_BETA_BACKEND_BIN": "missing-backend",
            "CIVITASOS_BETA_FRONTEND_ROOT": str(tmp_path),
            "CIVITASOS_BETA_AGENT_ROOT": str(tmp_path),
        }
    )
    config.env_file.write_text("AGENT_LLM=ollama:test\n", encoding="utf-8")
    os.chmod(config.env_file, 0o644)

    report = module.preflight(config)

    assert report["passed"] is False
    assert any("permissions must be 0600" in reason for reason in report["failure_reasons"])
    assert any("CIVITASOS_SERVICE_TOKEN_SECRET" in reason for reason in report["failure_reasons"])


def test_start_refuses_unowned_existing_endpoint(tmp_path: Path, monkeypatch) -> None:
    config = module.RuntimeConfig.from_env(
        {"CIVITASOS_BETA_RUNTIME_STATE_ROOT": str(tmp_path / "state")}
    )
    monkeypatch.setattr(module, "preflight", lambda _config: {"passed": True})
    monkeypatch.setattr(module, "_service_running", lambda _config, _name: False)
    monkeypatch.setattr(module, "_url_healthy", lambda _url: True)

    report = module.start(config)

    assert report["passed"] is False
    assert any("refusing unowned existing endpoints" in reason for reason in report["failure_reasons"])


def _write_executable(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    os.chmod(path, 0o755)


def _fake_backend_source() -> str:
    return """#!/usr/bin/env python3
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

parser = argparse.ArgumentParser()
parser.add_argument('--api-port', type=int, required=True)
args = parser.parse_args()

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'{}')
    def log_message(self, format, *args):
        return

ThreadingHTTPServer(('127.0.0.1', args.api_port), Handler).serve_forever()
"""


def _fake_agent_source() -> str:
    return """import signal
import time

running = True
def stop(*_args):
    global running
    running = False
signal.signal(signal.SIGTERM, stop)
while running:
    time.sleep(0.05)
"""
