#!/usr/bin/env python3
"""Operate the local CivitasOS Private Beta runtime path.

The lifecycle owns three local processes: backend, static frontend, and one
AgentRunner. Secrets are loaded from a private env file and are never written
to the process manifest or command line.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import time
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from beta_runtime_config import RuntimeConfig, SERVICES, load_private_env, now, preflight, report
from beta_runtime_processes import (
    process_snapshot as _process_snapshot,
    service_running as _service_running,
    spawn_service as _spawn,
    stop_services as _stop_services,
    url_healthy as _url_healthy,
    wait_for_url as _wait_for_url,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("preflight", help="validate assets and the private env file")
    subparsers.add_parser("start", help="start backend, frontend, and AgentRunner")
    subparsers.add_parser("status", help="report process and endpoint health")
    subparsers.add_parser("stop", help="stop processes and preserve runtime state")
    cleanup_parser = subparsers.add_parser("cleanup", help="stop processes and delete local runtime state")
    cleanup_parser.add_argument("--confirm-cleanup", action="store_true")
    args = parser.parse_args(argv)

    config = RuntimeConfig.from_env()
    actions = {
        "preflight": lambda: preflight(config),
        "start": lambda: start(config),
        "status": lambda: status(config),
        "stop": lambda: stop(config),
        "cleanup": lambda: cleanup(config, confirm=bool(args.confirm_cleanup)),
    }
    result = actions[args.command]()
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if result.get("passed") is True else 1


def start(config: RuntimeConfig) -> dict[str, Any]:
    preflight_report = preflight(config)
    if preflight_report["passed"] is not True:
        return preflight_report
    running = [name for name in SERVICES if _service_running(config, name)]
    if running:
        return report(config, False, [f"services already running: {', '.join(running)}"], "start")
    unowned_endpoints = []
    if _url_healthy(f"{config.backend_url}/healthz"):
        unowned_endpoints.append(config.backend_url)
    if _url_healthy(f"{config.frontend_url}/"):
        unowned_endpoints.append(config.frontend_url)
    if unowned_endpoints:
        return report(config, False, [f"refusing unowned existing endpoints: {', '.join(unowned_endpoints)}"], "start")

    config.state_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(config.state_root, 0o700)
    env = os.environ.copy()
    env.update(load_private_env(config.env_file, []))
    started: list[str] = []
    try:
        _start_backend(config, env)
        started.append("backend")
        _wait_for_url(f"{config.backend_url}/healthz", config, "backend")
        _start_frontend(config, env)
        started.append("frontend")
        _wait_for_url(f"{config.frontend_url}/", config, "frontend")
        _start_agent(config, env)
        started.append("agent")
        time.sleep(0.5)
        if not _service_running(config, "agent"):
            raise RuntimeError("AgentRunner exited during startup")
    except Exception as exc:  # noqa: BLE001 - lifecycle must roll back partial starts.
        _stop_services(config, reversed(started))
        return report(config, False, [f"startup failed: {exc}"], "start")

    manifest = report(config, True, [], "start")
    manifest["started_at"] = now()
    manifest["processes"] = _process_snapshot(config)
    _write_json(config.state_root / "runtime-manifest.json", manifest)
    return manifest


def status(config: RuntimeConfig) -> dict[str, Any]:
    processes = _process_snapshot(config)
    endpoint_health = {
        "backend_healthz": _url_healthy(f"{config.backend_url}/healthz"),
        "backend_readyz": _url_healthy(f"{config.backend_url}/readyz"),
        "frontend": _url_healthy(f"{config.frontend_url}/"),
    }
    passed = all(item["running"] for item in processes.values()) and all(endpoint_health.values())
    result = report(config, passed, [] if passed else ["one or more runtime services are not healthy"], "status")
    result["processes"] = processes
    result["endpoint_health"] = endpoint_health
    return result


def stop(config: RuntimeConfig) -> dict[str, Any]:
    stopped = _stop_services(config, reversed(SERVICES))
    result = report(config, True, [], "stop")
    result["stopped_services"] = stopped
    result["state_preserved"] = config.state_root.exists()
    manifest_path = config.state_root / "runtime-manifest.json"
    if manifest_path.is_file():
        manifest = _read_json(manifest_path)
        manifest["stopped_at"] = now()
        manifest["processes"] = _process_snapshot(config)
        _write_json(manifest_path, manifest)
    return result


def cleanup(config: RuntimeConfig, *, confirm: bool) -> dict[str, Any]:
    if not confirm:
        return report(config, False, ["cleanup requires --confirm-cleanup"], "cleanup")
    try:
        _validate_cleanup_root(config.state_root, config.workspace_root)
    except ValueError as exc:
        return report(config, False, [str(exc)], "cleanup")
    _stop_services(config, reversed(SERVICES))
    if config.state_root.exists():
        shutil.rmtree(config.state_root)
    result = report(config, True, [], "cleanup")
    result["state_removed"] = not config.state_root.exists()
    return result


def _start_backend(config: RuntimeConfig, env: dict[str, str]) -> None:
    backend_env = env | {
        "CIVITASOS_DATA_DIR": str(config.state_root / "backend-data"),
        "CIVITASOS_STORAGE_DATA_DIR": str(config.state_root / "backend-data" / "storage"),
        "CIVITASOS_NODE_ID": "private-beta-local",
        "CIVITASOS_BOOT_NODES": "",
        "CIVITASOS_JWT_SECRET": env.get("CIVITASOS_JWT_SECRET", f"{env['CIVITASOS_SERVICE_TOKEN_SECRET']}-jwt-private-beta-local"),
        "CIVITASOS_JWT_ENFORCE": "true",
        "CIVITASOS_SERVICE_TOKEN_SCOPES": env.get(
            "CIVITASOS_SERVICE_TOKEN_SCOPES",
            env.get("L1_PILOT_001_SERVICE_SCOPES", "pool:post,pool:read,pool:claim,pool:write,audit:read"),
        ),
        "CIVITASOS_AUTH_MODE": "production",
        "CIVITASOS_DEMO_LOGIN_ENABLED": "false",
        "CIVITASOS_DEMO_AUTO_REGISTER": "false",
        "CIVITASOS_A2A_SEED_TASKS": "false",
        "CIVITASOS_A2A_ALLOW_PRIVATE_CALLBACKS": "true",
        "CIVITASOS_TASK_CHALLENGE_WINDOW_ENABLED": "true",
        "CIVITASOS_POOL_SWEEP_AUTO_ENABLED": "true",
    }
    _spawn(config, "backend", [str(config.backend_bin), "--api-port", str(config.backend_port)], config.backend_root, backend_env)


def _start_frontend(config: RuntimeConfig, env: dict[str, str]) -> None:
    command = [sys.executable, "-m", "http.server", str(config.frontend_port), "--bind", "127.0.0.1", "--directory", str(config.frontend_build_dir)]
    _spawn(config, "frontend", command, config.frontend_root, env)


def _start_agent(config: RuntimeConfig, env: dict[str, str]) -> None:
    agent_env = env | {
        "CIVITASOS_URL": config.backend_url,
        "AGENT_IDENTITY": str(config.state_root / "agent" / "identity.key"),
        "AGENT_DATA_DIR": str(config.state_root / "agent" / "data"),
        "AGENT_ENDPOINT": f"http://127.0.0.1:{config.agent_gateway_port}",
        "GATEWAY_PORT": str(config.agent_gateway_port),
    }
    (config.state_root / "agent").mkdir(parents=True, exist_ok=True, mode=0o700)
    _spawn(config, "agent", [str(config.agent_python), str(config.agent_entry)], config.agent_root, agent_env)


def _validate_cleanup_root(state_root: Path, workspace_root: Path) -> None:
    forbidden = {Path("/").resolve(), Path.home().resolve(), workspace_root.resolve()}
    if state_root in forbidden or len(state_root.parts) < 3:
        raise ValueError(f"refusing unsafe cleanup root: {state_root}")


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
