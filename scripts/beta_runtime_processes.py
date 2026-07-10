"""Local process primitives for the Private Beta runtime lifecycle."""

from __future__ import annotations

import os
import signal
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Iterable

from beta_runtime_config import RuntimeConfig, SERVICES


def spawn_service(
    config: RuntimeConfig,
    name: str,
    command: list[str],
    cwd: Path,
    env: dict[str, str],
) -> None:
    log_path = config.state_root / f"{name}.log"
    with log_path.open("ab") as log_handle:
        process = subprocess.Popen(
            command,
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=log_handle,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    (config.state_root / f"{name}.pid").write_text(f"{process.pid}\n", encoding="ascii")


def wait_for_url(url: str, config: RuntimeConfig, service: str, timeout: float = 30.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if url_healthy(url):
            return
        if not service_running(config, service):
            raise RuntimeError(f"{service} exited before health check passed")
        time.sleep(0.1)
    raise RuntimeError(f"{service} health check timed out: {url}")


def url_healthy(url: str) -> bool:
    try:
        with urllib.request.urlopen(url, timeout=0.5) as response:  # noqa: S310 - local operator endpoints only.
            return 200 <= response.status < 400
    except (OSError, urllib.error.URLError):
        return False


def service_running(config: RuntimeConfig, name: str) -> bool:
    pid = read_pid(config.state_root / f"{name}.pid")
    return pid is not None and pid_exists(pid)


def stop_services(config: RuntimeConfig, names: Iterable[str]) -> list[str]:
    stopped: list[str] = []
    for name in names:
        pid_path = config.state_root / f"{name}.pid"
        pid = read_pid(pid_path)
        if pid is not None and pid_exists(pid):
            try:
                os.killpg(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            deadline = time.monotonic() + 5.0
            while pid_exists(pid) and time.monotonic() < deadline:
                time.sleep(0.05)
            if pid_exists(pid):
                try:
                    os.killpg(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            stopped.append(name)
        pid_path.unlink(missing_ok=True)
    return stopped


def process_snapshot(config: RuntimeConfig) -> dict[str, dict[str, Any]]:
    snapshot: dict[str, dict[str, Any]] = {}
    for name in SERVICES:
        pid = read_pid(config.state_root / f"{name}.pid")
        snapshot[name] = {"pid": pid, "running": pid is not None and pid_exists(pid)}
    return snapshot


def read_pid(path: Path) -> int | None:
    try:
        return int(path.read_text(encoding="ascii").strip())
    except (FileNotFoundError, ValueError, OSError):
        return None


def pid_exists(pid: int) -> bool:
    try:
        reaped_pid, _ = os.waitpid(pid, os.WNOHANG)
        if reaped_pid == pid:
            return False
    except ChildProcessError:
        pass
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
