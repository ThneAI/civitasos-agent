"""Host-side controller for one reusable, network-isolated participant runner."""

from __future__ import annotations

import json
import os
import subprocess
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any


Command = Callable[[list[str]], subprocess.CompletedProcess[str]]


class ParticipantContainerClient:
    def __init__(
        self,
        *,
        isolations: dict[str, dict[str, Any]],
        timeout_seconds: float = 30.0,
        command: Command | None = None,
    ) -> None:
        self.isolations = isolations
        self.timeout_seconds = timeout_seconds
        self.command = command or _run
        self.start_count = 0
        self.stop_count = 0

    def start(
        self, task: dict[str, Any], envelope: dict[str, Any]
    ) -> dict[str, Any]:
        isolation = self._isolation(task)
        before = self._inspect(isolation["container_name"])
        self._validate_container(before, task=task, isolation=isolation, running=False)
        self._stage(isolation, envelope)
        self._require_success(["docker", "start", isolation["container_name"]])
        self.start_count += 1
        output = self._wait_output(isolation)
        after = self._inspect(isolation["container_name"])
        self._validate_container(after, task=task, isolation=isolation, running=True)
        return output

    def exchange(
        self, task: dict[str, Any], envelope: dict[str, Any]
    ) -> dict[str, Any]:
        isolation = self._isolation(task)
        current = self._inspect(isolation["container_name"])
        running = bool(current["State"]["Running"])
        self._validate_container(
            current, task=task, isolation=isolation, running=running
        )
        self._stage(isolation, envelope)
        if not running:
            self._require_success(["docker", "start", isolation["container_name"]])
            self.start_count += 1
        return self._wait_output(isolation)

    def restart(
        self, task: dict[str, Any], envelope: dict[str, Any]
    ) -> dict[str, Any]:
        self.stop(task)
        return self.start(task, envelope)

    def stop(self, task: dict[str, Any]) -> None:
        isolation = self._isolation(task)
        current = self._inspect(isolation["container_name"])
        if current["State"]["Running"]:
            self._require_success(
                ["docker", "stop", "--time", "2", isolation["container_name"]]
            )
            self.stop_count += 1
        self._clear(isolation)

    def _stage(
        self, isolation: dict[str, Any], envelope: dict[str, Any]
    ) -> None:
        self._clear(isolation)
        input_path = Path(isolation["input_root"]) / "request.json"
        payload = (
            json.dumps(
                envelope,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        ).encode()
        temporary = input_path.with_name(f".{input_path.name}.{os.getpid()}.tmp")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, input_path)
        _fsync_directory(input_path.parent)

    def _wait_output(self, isolation: dict[str, Any]) -> dict[str, Any]:
        output_path = Path(isolation["output_root"]) / "response.json"
        deadline = time.monotonic() + self.timeout_seconds
        while time.monotonic() < deadline:
            if output_path.is_file() and not output_path.is_symlink():
                value = json.loads(output_path.read_bytes())
                if not isinstance(value, dict):
                    raise ValueError("participant container output is not an object")
                return value
            state = self._inspect(isolation["container_name"])["State"]
            if not state["Running"]:
                raise RuntimeError(
                    "participant container exited before producing output: "
                    f"{state.get('ExitCode')}"
                )
            time.sleep(0.05)
        raise TimeoutError("participant container output timed out")

    def _clear(self, isolation: dict[str, Any]) -> None:
        for root, name in (
            (isolation["input_root"], "request.json"),
            (isolation["output_root"], "response.json"),
        ):
            path = Path(root) / name
            if path.exists() or path.is_symlink():
                if path.is_symlink() or not path.is_file():
                    raise ValueError(f"participant IPC path is not a regular file: {path}")
                path.unlink()
                _fsync_directory(path.parent)

    def _isolation(self, task: dict[str, Any]) -> dict[str, Any]:
        isolation = self.isolations.get(task["participant_id"])
        if isolation is None:
            raise ValueError("participant isolation is not bound")
        if isolation["container_name"] != task["container"]["container_name"]:
            raise ValueError("participant isolation container binding mismatch")
        return isolation

    def _inspect(self, name: str) -> dict[str, Any]:
        result = self.command(["docker", "container", "inspect", name])
        if result.returncode != 0:
            raise RuntimeError(f"docker inspect failed: {result.stderr.strip()}")
        values = json.loads(result.stdout)
        if not isinstance(values, list) or len(values) != 1:
            raise ValueError("docker inspect returned an invalid result")
        return values[0]

    def _require_success(self, command: list[str]) -> None:
        result = self.command(command)
        if result.returncode != 0:
            raise RuntimeError(
                f"{' '.join(command[:2])} failed: {result.stderr.strip()}"
            )

    @staticmethod
    def _validate_container(
        value: dict[str, Any],
        *,
        task: dict[str, Any],
        isolation: dict[str, Any],
        running: bool,
    ) -> None:
        config = value.get("Config", {})
        host = value.get("HostConfig", {})
        state = value.get("State", {})
        labels = config.get("Labels", {})
        if not (
            value.get("Image") == task["container"]["image_id"]
            and host.get("NetworkMode") == "none"
            and host.get("ReadonlyRootfs") is True
            and host.get("CapDrop") == ["ALL"]
            and state.get("Running") is running
            and labels.get("civitasos.j1d.participant") == task["participant_id"]
            and labels.get("civitasos.j1d.pair") == task["pair_id"]
            and labels.get("civitasos.j1d.cohort") == task["cohort"]
            and Path(isolation["input_root"]).is_dir()
            and Path(isolation["output_root"]).is_dir()
        ):
            raise ValueError("participant container boundary drifted")


def isolation_index(activation: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        item["participant_id"]: {
            "container_name": item["container"]["container_name"],
            "input_root": next(
                mount["source"]
                for mount in item["container"]["mounts"]
                if mount["destination"] == "/input"
            ),
            "output_root": next(
                mount["source"]
                for mount in item["container"]["mounts"]
                if mount["destination"] == "/output"
            ),
        }
        for item in activation["containers"]
    }


def _run(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=False, capture_output=True, text=True)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
