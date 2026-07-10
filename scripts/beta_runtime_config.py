"""Configuration and secret-boundary validation for the Private Beta runtime."""

from __future__ import annotations

import ast
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "civitasos-beta-runtime-lifecycle:v1"
SERVICES = ("backend", "frontend", "agent")
REQUIRED_ENV_KEYS = (
    "CIVITASOS_SERVICE_TOKEN_SECRET",
    "CIVITASOS_WAKE_CALLBACK_SECRET",
    "AGENT_LLM",
    "LLM_BASE_URL",
)


@dataclass(frozen=True)
class RuntimeConfig:
    workspace_root: Path
    state_root: Path
    env_file: Path
    backend_root: Path
    backend_bin: Path
    frontend_root: Path
    frontend_build_dir: Path
    agent_root: Path
    agent_python: Path
    agent_entry: Path
    backend_port: int
    frontend_port: int
    agent_gateway_port: int

    @property
    def backend_url(self) -> str:
        return f"http://127.0.0.1:{self.backend_port}"

    @property
    def frontend_url(self) -> str:
        return f"http://127.0.0.1:{self.frontend_port}"

    @classmethod
    def from_env(cls, environ: dict[str, str] | None = None) -> "RuntimeConfig":
        env = os.environ if environ is None else environ
        agent_root = Path(__file__).resolve().parents[1]
        workspace = agent_root.parent
        backend_root = Path(env.get("CIVITASOS_BETA_BACKEND_ROOT", workspace / "civitasos-backend"))
        frontend_root = Path(env.get("CIVITASOS_BETA_FRONTEND_ROOT", workspace / "civitasos-frontend"))
        configured_agent_root = Path(env.get("CIVITASOS_BETA_AGENT_ROOT", agent_root))
        return cls(
            workspace_root=workspace.resolve(),
            state_root=Path(env.get("CIVITASOS_BETA_RUNTIME_STATE_ROOT", "/tmp/civitasos-beta-runtime")).resolve(),
            env_file=Path(env.get("CIVITASOS_BETA_RUNTIME_ENV_FILE", configured_agent_root / ".env.beta0.local")).resolve(),
            backend_root=backend_root.resolve(),
            backend_bin=_resolve_under(backend_root, env.get("CIVITASOS_BETA_BACKEND_BIN", "target/debug/api_only")),
            frontend_root=frontend_root.resolve(),
            frontend_build_dir=_resolve_under(frontend_root, env.get("CIVITASOS_BETA_FRONTEND_BUILD_DIR", "build")),
            agent_root=configured_agent_root.resolve(),
            agent_python=_resolve_under(configured_agent_root, env.get("CIVITASOS_BETA_AGENT_PYTHON", ".venv/bin/python")),
            agent_entry=_resolve_under(configured_agent_root, env.get("CIVITASOS_BETA_AGENT_ENTRY", "agent.py")),
            backend_port=int(env.get("CIVITASOS_BETA_BACKEND_PORT", "8099")),
            frontend_port=int(env.get("CIVITASOS_BETA_FRONTEND_PORT", "3001")),
            agent_gateway_port=int(env.get("CIVITASOS_BETA_AGENT_GATEWAY_PORT", "8300")),
        )


def preflight(config: RuntimeConfig) -> dict[str, Any]:
    failures: list[str] = []
    env = load_private_env(config.env_file, failures)
    for key in REQUIRED_ENV_KEYS:
        if not env.get(key):
            failures.append(f"private env file must define {key}")
    if env.get("AGENT_LLM", "").startswith("ollama:") is False and not env.get("LLM_API_KEY"):
        failures.append("external AGENT_LLM requires LLM_API_KEY")
    _require_executable(config.backend_bin, failures, "backend binary")
    _require_file(config.frontend_build_dir / "index.html", failures, "frontend build index")
    _require_executable(config.agent_python, failures, "agent Python")
    _require_file(config.agent_entry, failures, "AgentRunner entry")
    for port, label in (
        (config.backend_port, "backend port"),
        (config.frontend_port, "frontend port"),
        (config.agent_gateway_port, "agent gateway port"),
    ):
        if not 1 <= port <= 65535:
            failures.append(f"{label} must be between 1 and 65535")
    return report(config, not failures, failures, "preflight")


def load_private_env(path: Path, failures: list[str]) -> dict[str, str]:
    if not path.is_file():
        failures.append(f"private env file not found: {path}")
        return {}
    if path.stat().st_mode & 0o077:
        failures.append(f"private env file permissions must be 0600 or stricter: {path}")
    values: dict[str, str] = {}
    for line_number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].strip()
        if "=" not in line:
            failures.append(f"invalid private env line {line_number}")
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if not key.replace("_", "a").isalnum() or key[0].isdigit():
            failures.append(f"invalid private env key on line {line_number}")
            continue
        values[key] = _unquote(value.strip(), failures, line_number)
    return values


def report(config: RuntimeConfig, passed: bool, failures: list[str], action: str) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "checked_at": now(),
        "action": action,
        "passed": passed,
        "failure_reasons": failures,
        "state_root": str(config.state_root),
        "endpoints": {
            "backend": config.backend_url,
            "frontend": config.frontend_url,
            "agent_gateway": f"http://127.0.0.1:{config.agent_gateway_port}",
        },
        "boundary": {
            "private_beta_local_runtime_only": True,
            "demo_login_allowed": False,
            "public_ingress_allowed": False,
            "production_runtime_execution_allowed": False,
            "production_receipt_write_allowed": False,
        },
    }


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _unquote(value: str, failures: list[str], line_number: int) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        try:
            parsed = ast.literal_eval(value)
        except (SyntaxError, ValueError):
            failures.append(f"invalid quoted private env value on line {line_number}")
            return ""
        return str(parsed)
    return value


def _require_file(path: Path, failures: list[str], label: str) -> None:
    if not path.is_file():
        failures.append(f"{label} not found: {path}")


def _require_executable(path: Path, failures: list[str], label: str) -> None:
    if not path.is_file() or not os.access(path, os.X_OK):
        failures.append(f"{label} is not executable: {path}")


def _resolve_under(root: Path, value: str | os.PathLike[str]) -> Path:
    path = Path(value)
    return path.resolve() if path.is_absolute() else (root / path).resolve()
