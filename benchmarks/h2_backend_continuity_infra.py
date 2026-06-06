"""Infrastructure adapters for H.2 backend continuity drills."""

from __future__ import annotations

import os
import socket
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from urllib.request import urlopen

from benchmarks.h2_backend_outcome_export import _demo_login_token


@dataclass
class BackendSandbox:
    process: subprocess.Popen[str]
    base_url: str
    stdout_path: Path
    stderr_path: Path

    def stop(self) -> None:
        if self.process.poll() is not None:
            return
        self.process.terminate()
        try:
            self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=5)


def start_backend_sandbox(
    *,
    backend_binary: Path,
    data_dir: Path,
    startup_timeout_s: float = 20.0,
) -> BackendSandbox:
    if not backend_binary.is_file():
        raise FileNotFoundError(f"backend binary not found: {backend_binary}")
    data_dir.mkdir(parents=True, exist_ok=True)
    port = _free_port()
    base_url = f"http://127.0.0.1:{port}"
    stdout_path = data_dir / "backend.stdout.log"
    stderr_path = data_dir / "backend.stderr.log"
    env = os.environ.copy()
    env.update(
        {
            "CIVITASOS_DEMO_LOGIN_ENABLED": "true",
            "CIVITASOS_DEV_FAUCET": "true",
            "CIVITASOS_TASK_CHALLENGE_WINDOW_ENABLED": "false",
            "CIVITASOS_POOL_SWEEP_AUTO_ENABLED": "false",
            "RUST_LOG": env.get("RUST_LOG", "warn"),
        }
    )
    stdout_handle = stdout_path.open("w", encoding="utf-8")
    stderr_handle = stderr_path.open("w", encoding="utf-8")
    process = subprocess.Popen(
        [str(backend_binary), "--api-port", str(port)],
        cwd=data_dir,
        env=env,
        text=True,
        stdout=stdout_handle,
        stderr=stderr_handle,
    )
    stdout_handle.close()
    stderr_handle.close()
    sandbox = BackendSandbox(
        process=process,
        base_url=base_url,
        stdout_path=stdout_path,
        stderr_path=stderr_path,
    )
    try:
        _wait_for_health(sandbox, timeout_s=startup_timeout_s)
    except Exception:
        sandbox.stop()
        raise
    return sandbox


def authenticated_agent(
    *,
    base_url: str,
    login_agent_id: str,
    identity_path: Path | None = None,
) -> Any:
    from civitasos import CivitasAgent

    hostname = (urlsplit(base_url).hostname or "").lower()
    if hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError(
            "H.2 controlled demo-login adapter only accepts loopback backends"
        )
    agent = CivitasAgent(base_url, auto_discover=False)
    if identity_path is not None:
        agent.load_identity(str(identity_path))
    token = _demo_login_token(
        backend_url=base_url,
        agent_id=login_agent_id,
        timeout_s=10.0,
    )
    if not token:
        raise RuntimeError(f"demo-login did not return a token for {login_agent_id}")
    agent._jwt_token = token  # noqa: SLF001 - controlled dev/test backend
    agent._jwt_expires_at = time.time() + 3600  # noqa: SLF001 - demo token session
    return agent


def provision_agent(
    *,
    base_url: str,
    alias: str,
    name: str,
    identity_path: Path,
) -> dict[str, Any]:
    agent = authenticated_agent(base_url=base_url, login_agent_id=f"provision:{alias}")
    public_key = agent.generate_keys()
    response = agent.a2a_quickstart(
        name=name,
        endpoint=f"http://127.0.0.1:0/h2/{alias}",
        description="H.2 controlled restart continuity identity",
        alias=alias,
        public_key=public_key,
    )
    if not agent.agent_id:
        raise RuntimeError(f"quickstart response missing agent DID for {alias}: {response}")
    identity_path.parent.mkdir(parents=True, exist_ok=True)
    agent.save_identity(str(identity_path))
    return {
        "alias": alias,
        "agent_id": str(agent.agent_id),
        "public_key_hex": public_key,
        "identity_path": str(identity_path),
        "quickstart_response": response,
    }


def _wait_for_health(sandbox: BackendSandbox, *, timeout_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    last_error = "backend did not answer"
    while time.monotonic() < deadline:
        if sandbox.process.poll() is not None:
            raise RuntimeError(
                f"backend exited during startup with code {sandbox.process.returncode}"
            )
        try:
            with urlopen(f"{sandbox.base_url}/healthz", timeout=1.0) as response:
                response.read()
            return
        except OSError as exc:
            last_error = str(exc)
            time.sleep(0.1)
    raise TimeoutError(f"backend health check timed out: {last_error}")


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])
