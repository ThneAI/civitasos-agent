#!/usr/bin/env python3
"""Run the offline P5-B3e process kill/restart contract matrix."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import select
import signal
import socket
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from civitasos_runtime.checkpoint_observer import CheckpointRestoreMilestone


EVENT_SCHEMA = "civitasos-p5b3e-fault-event:v1"
RESULT_SCHEMA = "civitasos-p5b3e-fault-result:v1"
SUMMARY_SCHEMA = "civitasos-p5b3e-local-fault-gate:v1"
KILL_POINTS = tuple(
    milestone.value
    for milestone in CheckpointRestoreMilestone
    if milestone != CheckpointRestoreMilestone.RUNTIME_TICK_LATCH_RELEASED
)
ALL_MILESTONES = {milestone.value for milestone in CheckpointRestoreMilestone}
EVENT_FIELDS = {
    "schema_version",
    "case_id",
    "attempt",
    "milestone",
    "checkpoint_id",
    "manifest_hash",
    "sequence",
    "identity_id",
    "node_id",
    "status",
    "backend_status",
    "activation_fact_id",
}
REJECTION_CASES = (
    "credential_rotation_interrupted",
    "credential_revoked",
    "stale_sequence_replay",
    "partial_manifest_write",
)


def _write_private_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    temporary = path.with_suffix(f"{path.suffix}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(descriptor, "w") as stream:
            json.dump(payload, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if temporary.exists():
            temporary.unlink()


def _command_digest(command: list[str]) -> str:
    encoded = b"\0".join(part.encode() for part in command)
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def _file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def _command_file_digests(command: list[str]) -> dict[str, str]:
    return {
        str(index): _file_digest(path)
        for index, value in enumerate(command)
        if (path := Path(value).expanduser()).is_file()
    }


def validate_local_run_root(run_root: Path) -> Path:
    resolved = run_root.expanduser().resolve()
    lowered = str(resolved).lower()
    if "p4eg" in lowered or "/civitasos-p4" in lowered:
        raise ValueError("B3e local run root must not overlap a P4 soak path")
    if resolved.exists():
        if not resolved.is_dir():
            raise ValueError("B3e local run root must be a directory")
        if any(resolved.iterdir()):
            raise ValueError("B3e local run root must be empty")
    return resolved


@dataclass
class WorkerSession:
    process: subprocess.Popen[bytes]
    control: socket.socket
    log_stream: Any
    buffer: bytes = field(default=b"")

    def read_event(self, deadline: float) -> dict[str, Any] | None:
        while b"\n" not in self.buffer:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("worker milestone timeout")
            readable, _, _ = select.select([self.control], [], [], min(remaining, 0.1))
            if not readable:
                if self.process.poll() is not None:
                    chunk = self.control.recv(65536)
                    if not chunk:
                        return None
                    self.buffer += chunk
                continue
            chunk = self.control.recv(65536)
            if not chunk:
                return None
            self.buffer += chunk
        line, self.buffer = self.buffer.split(b"\n", 1)
        try:
            event = json.loads(line)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("worker emitted an invalid milestone event") from error
        if not isinstance(event, dict):
            raise ValueError("worker milestone event must be an object")
        return event

    def acknowledge(self) -> None:
        self.control.sendall(b"C")

    def kill(self) -> int:
        os.killpg(self.process.pid, signal.SIGKILL)
        return self.process.wait(timeout=5)

    def close(self) -> None:
        self.control.close()
        self.log_stream.close()


def _launch_worker(
    command: list[str],
    case_root: Path,
    case_id: str,
    fault_point: str,
    attempt: int,
) -> WorkerSession:
    parent, child = socket.socketpair()
    child.set_inheritable(True)
    environment = os.environ.copy()
    environment.update(
        {
            "CIVITASOS_P5B3E_CONTROL_FD": str(child.fileno()),
            "CIVITASOS_P5B3E_CASE_ROOT": str(case_root),
            "CIVITASOS_P5B3E_CASE_ID": case_id,
            "CIVITASOS_P5B3E_FAULT_POINT": fault_point,
            "CIVITASOS_P5B3E_ATTEMPT": str(attempt),
        }
    )
    log_path = case_root / f"attempt-{attempt}.log"
    log_fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    log_stream = os.fdopen(log_fd, "ab", buffering=0)
    try:
        process = subprocess.Popen(
            command,
            env=environment,
            pass_fds=(child.fileno(),),
            start_new_session=True,
            stdout=log_stream,
            stderr=subprocess.STDOUT,
        )
    except Exception:
        parent.close()
        log_stream.close()
        raise
    finally:
        child.close()
    return WorkerSession(process, parent, log_stream)


def _validate_event(
    event: dict[str, Any], case_id: str, attempt: int
) -> dict[str, Any]:
    if (
        not set(event) <= EVENT_FIELDS
        or event.get("schema_version") != EVENT_SCHEMA
        or event.get("case_id") != case_id
        or event.get("attempt") != attempt
        or event.get("milestone") not in ALL_MILESTONES
        or not str(event.get("checkpoint_id", "")).startswith("aic:v1:")
        or not str(event.get("manifest_hash", "")).startswith("sha256:")
        or isinstance(event.get("sequence"), bool)
        or not isinstance(event.get("sequence"), int)
        or event.get("sequence", 0) < 1
        or not str(event.get("identity_id", "")).startswith("did:civ:")
    ):
        raise ValueError("worker milestone binding is invalid")
    return event


def _kill_first_attempt(
    command: list[str],
    case_root: Path,
    case_id: str,
    fault_point: str,
    timeout: float,
) -> tuple[int, list[dict[str, Any]]]:
    session = _launch_worker(command, case_root, case_id, fault_point, 1)
    events: list[dict[str, Any]] = []
    deadline = time.monotonic() + timeout
    try:
        while True:
            event = session.read_event(deadline)
            if event is None:
                code = session.process.wait(timeout=1)
                raise RuntimeError(
                    f"worker exited with {code} before {fault_point}"
                )
            event = _validate_event(event, case_id, 1)
            events.append(event)
            if event["milestone"] == fault_point:
                return session.kill(), events
            session.acknowledge()
    finally:
        if session.process.poll() is None:
            session.kill()
        session.close()


def _complete_attempt(
    command: list[str],
    case_root: Path,
    case_id: str,
    fault_point: str,
    timeout: float,
    attempt: int,
) -> tuple[int, list[dict[str, Any]]]:
    session = _launch_worker(command, case_root, case_id, fault_point, attempt)
    events: list[dict[str, Any]] = []
    deadline = time.monotonic() + timeout
    try:
        while True:
            event = session.read_event(deadline)
            if event is None:
                return session.process.wait(timeout=1), events
            events.append(_validate_event(event, case_id, attempt))
            session.acknowledge()
    finally:
        if session.process.poll() is None:
            session.kill()
        session.close()


def _validate_result(
    path: Path,
    case_id: str,
    fault_point: str,
    events: list[dict[str, Any]],
) -> dict[str, Any]:
    result = json.loads(path.read_text())
    bindings = {
        (event["checkpoint_id"], event["manifest_hash"], event["sequence"], event["identity_id"])
        for event in events
    }
    expected_binding = (
        result.get("checkpoint_id"),
        result.get("manifest_hash"),
        result.get("sequence"),
        result.get("identity_id"),
    )
    if (
        result.get("schema_version") != RESULT_SCHEMA
        or result.get("case_id") != case_id
        or result.get("fault_point") != fault_point
        or result.get("status") != "activated"
        or result.get("recovered") is not True
        or result.get("pre_activation_tick_count") != 0
        or not isinstance(result.get("post_activation_tick_count"), int)
        or result.get("post_activation_tick_count", 0) < 1
        or result.get("activation_fact_count") != 1
        or not str(result.get("activation_fact_id", "")).strip()
        or result.get("runtime_journal_status") != "activated"
        or result.get("runtime_intent_status") != "activated"
        or result.get("audit_sequence_contiguous") is not True
        or bindings != {expected_binding}
    ):
        raise ValueError("worker recovery result failed B3e invariants")
    return result


def run_fault_case(
    command: list[str],
    run_root: Path,
    fault_point: str,
    *,
    timeout: float,
) -> dict[str, Any]:
    if fault_point not in KILL_POINTS:
        raise ValueError(f"unsupported B3e fault point: {fault_point}")
    case_id = f"p5b3e:{KILL_POINTS.index(fault_point) + 1:02d}:{fault_point}"
    case_root = run_root / "cases" / fault_point
    case_root.mkdir(parents=True, mode=0o700)
    os.chmod(case_root, 0o700)
    killed_code, first_events = _kill_first_attempt(
        command, case_root, case_id, fault_point, timeout
    )
    if killed_code != -signal.SIGKILL:
        raise RuntimeError(f"worker was not killed by SIGKILL: {killed_code}")
    restart_code, restart_events = _complete_attempt(
        command, case_root, case_id, fault_point, timeout, 2
    )
    if restart_code != 0:
        raise RuntimeError(f"worker restart failed with exit code {restart_code}")
    result_path = case_root / "result.json"
    if not result_path.is_file():
        raise RuntimeError("worker restart did not write result.json")
    result = _validate_result(
        result_path, case_id, fault_point, first_events + restart_events
    )
    return {
        "case_id": case_id,
        "fault_point": fault_point,
        "first_exit_code": killed_code,
        "restart_exit_code": restart_code,
        "first_event_count": len(first_events),
        "restart_event_count": len(restart_events),
        "activation_fact_id": result["activation_fact_id"],
        "passed": True,
    }


def run_rejection_case(
    command: list[str],
    run_root: Path,
    rejection_case: str,
    *,
    timeout: float,
) -> dict[str, Any]:
    if rejection_case not in REJECTION_CASES:
        raise ValueError(f"unsupported B3e rejection case: {rejection_case}")
    case_id = f"p5b3e:reject:{rejection_case}"
    case_root = run_root / "rejections" / rejection_case
    case_root.mkdir(parents=True, mode=0o700)
    os.chmod(case_root, 0o700)
    return_code, events = _complete_attempt(
        command, case_root, case_id, rejection_case, timeout, 1
    )
    if return_code != 0:
        raise RuntimeError(f"rejection worker failed with exit code {return_code}")
    result_path = case_root / "result.json"
    if not result_path.is_file():
        raise RuntimeError("rejection worker did not write result.json")
    result = json.loads(result_path.read_text())
    if (
        events
        or result.get("schema_version") != RESULT_SCHEMA
        or result.get("case_id") != case_id
        or result.get("fault_point") != rejection_case
        or result.get("status") != "rejected"
        or result.get("fail_closed") is not True
        or result.get("mutation_count") != 0
        or result.get("activation_fact_count") != 0
        or result.get("pre_activation_tick_count") != 0
        or result.get("failure_audit_recorded") is not True
    ):
        raise ValueError("worker rejection result failed B3e invariants")
    return {
        "case_id": case_id,
        "rejection_case": rejection_case,
        "exit_code": return_code,
        "passed": True,
    }


def execute_local_matrix(
    command: list[str],
    run_root: Path,
    *,
    fault_points: tuple[str, ...] = KILL_POINTS,
    timeout: float = 10.0,
) -> dict[str, Any]:
    if not command:
        raise ValueError("B3e worker command is required")
    if timeout <= 0:
        raise ValueError("B3e worker timeout must be positive")
    root = validate_local_run_root(run_root)
    root.mkdir(parents=True, mode=0o700)
    os.chmod(root, 0o700)
    lock_fd = os.open(root / "gate.lock", os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        started = time.time()
        cases = [
            run_fault_case(command, root, point, timeout=timeout)
            for point in fault_points
        ]
        rejections = [
            run_rejection_case(command, root, case, timeout=timeout)
            for case in REJECTION_CASES
        ]
        summary = {
            "schema_version": SUMMARY_SCHEMA,
            "status": "passed",
            "passed": True,
            "started_at": int(started),
            "completed_at": int(time.time()),
            "worker_command_sha256": _command_digest(command),
            "controller_source_sha256": _file_digest(Path(__file__)),
            "worker_command_file_sha256": _command_file_digests(command),
            "kill_points": list(fault_points),
            "cases": cases,
            "rejection_cases": rejections,
            "sigkill_exercised": bool(cases),
            "local_synthetic_only": True,
            "network_used": False,
            "real_tls_executed": False,
            "backend_sled_executed": False,
            "p4_soak_resources_used": False,
        }
        _write_private_json(root / "summary.json", summary)
        return summary
    finally:
        os.close(lock_fd)


def matrix() -> int:
    print(
        json.dumps(
            {
                "kill_points": KILL_POINTS,
                "rejection_cases": REJECTION_CASES,
                "local_only": True,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def execute(args: argparse.Namespace) -> int:
    if not args.ack_local_synthetic_only:
        raise SystemExit("explicit --ack-local-synthetic-only is required")
    command = list(args.worker)
    if command and command[0] == "--":
        command.pop(0)
    summary = execute_local_matrix(
        command,
        Path(args.run_root),
        timeout=args.timeout_seconds,
    )
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    subparsers = root.add_subparsers(dest="command", required=True)
    show = subparsers.add_parser("matrix")
    show.set_defaults(func=lambda _args: matrix())
    run = subparsers.add_parser("execute-local")
    run.add_argument("--run-root", required=True)
    run.add_argument("--timeout-seconds", type=float, default=10.0)
    run.add_argument("--ack-local-synthetic-only", action="store_true")
    run.add_argument("worker", nargs=argparse.REMAINDER)
    run.set_defaults(func=execute)
    return root


def main() -> int:
    args = parser().parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
