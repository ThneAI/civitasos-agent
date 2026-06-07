"""SSH and deployment adapters for the H.2 VM/CSP soak runner."""

from __future__ import annotations

import json
import shlex
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence
from urllib.request import urlopen


@dataclass(frozen=True)
class VmHost:
    role: str
    ssh_alias: str
    address: str


@dataclass(frozen=True)
class VmTopology:
    core: VmHost
    csp: VmHost
    agent: VmHost
    backend_port: int = 8099
    csp_port: int = 8200
    remote_root: str = "civitasos-h2"

    @property
    def backend_url(self) -> str:
        return f"http://{self.core.address}:{self.backend_port}"

    @property
    def csp_url(self) -> str:
        return f"http://{self.csp.address}:{self.csp_port}"


DEFAULT_TOPOLOGY = VmTopology(
    core=VmHost(role="core", ssh_alias="vm1", address="192.168.56.4"),
    csp=VmHost(role="csp", ssh_alias="vm2", address="192.168.56.5"),
    agent=VmHost(role="agent", ssh_alias="vm3", address="192.168.56.6"),
)


@dataclass(frozen=True)
class CommandResult:
    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    duration_seconds: float


class CommandError(RuntimeError):
    def __init__(self, result: CommandResult) -> None:
        command = shlex.join(result.argv)
        detail = result.stderr.strip() or result.stdout.strip()
        super().__init__(
            f"command failed ({result.returncode}): {command}\n{detail}"
        )
        self.result = result


class CommandRunner:
    def run(
        self,
        argv: Sequence[str],
        *,
        cwd: Path | None = None,
        timeout: float | None = None,
        check: bool = True,
    ) -> CommandResult:
        started = time.monotonic()
        completed = subprocess.run(
            list(argv),
            cwd=cwd,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        result = CommandResult(
            argv=tuple(str(item) for item in argv),
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
            duration_seconds=time.monotonic() - started,
        )
        if check and result.returncode != 0:
            raise CommandError(result)
        return result

    def ssh(
        self,
        host: VmHost,
        command: str,
        *,
        timeout: float | None = None,
        check: bool = True,
    ) -> CommandResult:
        return self.run(
            [
                "ssh",
                "-o",
                "BatchMode=yes",
                "-o",
                "ConnectTimeout=10",
                host.ssh_alias,
                command,
            ],
            timeout=timeout,
            check=check,
        )

    def scp(
        self,
        source: Path,
        host: VmHost,
        destination: str,
        *,
        timeout: float | None = None,
    ) -> CommandResult:
        return self.run(
            ["scp", "-q", str(source), f"{host.ssh_alias}:{destination}"],
            timeout=timeout,
        )

    def rsync(
        self,
        source: Path,
        host: VmHost,
        destination: str,
        *,
        timeout: float | None = None,
    ) -> CommandResult:
        return self.run(
            [
                "rsync",
                "-az",
                "--delete",
                "--exclude=.git",
                "--exclude=.venv",
                "--exclude=__pycache__",
                "--exclude=.pytest_cache",
                "--exclude=runs",
                f"{source}/",
                f"{host.ssh_alias}:{destination}/",
            ],
            timeout=timeout,
        )

    def pull_rsync(
        self,
        host: VmHost,
        source: str,
        destination: Path,
        *,
        timeout: float | None = None,
    ) -> CommandResult:
        destination.mkdir(parents=True, exist_ok=True)
        return self.run(
            [
                "rsync",
                "-az",
                "--delete",
                "--delete-excluded",
                "--exclude=identity/",
                "--exclude=memory.db-wal",
                "--exclude=memory.db-shm",
                f"{host.ssh_alias}:{source}/",
                f"{destination}/",
            ],
            timeout=timeout,
        )


def load_topology(path: Path | None) -> VmTopology:
    if path is None:
        return DEFAULT_TOPOLOGY
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("topology config must be a JSON object")

    def host(role: str) -> VmHost:
        value = payload.get(role)
        if not isinstance(value, dict):
            raise ValueError(f"topology config missing object: {role}")
        return VmHost(
            role=role,
            ssh_alias=str(value["ssh_alias"]),
            address=str(value["address"]),
        )

    return VmTopology(
        core=host("core"),
        csp=host("csp"),
        agent=host("agent"),
        backend_port=int(payload.get("backend_port", 8099)),
        csp_port=int(payload.get("csp_port", 8200)),
        remote_root=str(payload.get("remote_root", "civitasos-h2")).strip("/"),
    )


def wait_for_url(
    url: str,
    *,
    timeout_seconds: float = 30.0,
    expected_core_reachable: bool | None = None,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    last_error = "no response"
    while time.monotonic() < deadline:
        try:
            with urlopen(url, timeout=2.0) as response:
                raw = response.read().decode("utf-8")
                payload = (
                    json.loads(raw)
                    if raw.strip()
                    else {"status": "healthy", "http_status": response.status}
                )
            if expected_core_reachable is not None:
                if payload.get("core_reachable") is not expected_core_reachable:
                    last_error = f"core_reachable={payload.get('core_reachable')}"
                    time.sleep(0.25)
                    continue
            return payload
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            last_error = str(exc)
            time.sleep(0.25)
    raise TimeoutError(f"health check timed out for {url}: {last_error}")


def shell_path(remote_home: str, *parts: str) -> str:
    clean = [part.strip("/") for part in parts if part.strip("/")]
    return str(Path(remote_home).joinpath(*clean))


def quote_command(argv: Sequence[str]) -> str:
    return shlex.join([str(item) for item in argv])
