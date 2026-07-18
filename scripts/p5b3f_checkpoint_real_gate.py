#!/usr/bin/env python3
"""Run the isolated P5-B3 real TLS/sled/SQLite checkpoint fault gate."""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import socket
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.p5b3e_checkpoint_fault_gate import (
    KILL_POINTS,
    REJECTION_CASES,
    _command_digest,
    _command_file_digests,
    _file_digest,
    _write_private_json,
    run_fault_case,
    run_rejection_case,
    validate_local_run_root,
)


SUMMARY_SCHEMA = "civitasos-p5b3f-real-checkpoint-fault-gate:v1"
P4_PORTS = {18443, 18444}


def validate_real_resources(run_root: Path, backend_port: int) -> Path:
    root = validate_local_run_root(run_root)
    if backend_port in P4_PORTS:
        raise ValueError("P5-B3f backend port must not overlap P4 soak ports")
    if not 1024 <= backend_port <= 65535:
        raise ValueError("P5-B3f backend port must be an unprivileged TCP port")
    probe = socket.socket()
    try:
        probe.bind(("127.0.0.1", backend_port))
    except OSError as error:
        raise ValueError(f"P5-B3f backend port is unavailable: {backend_port}") from error
    finally:
        probe.close()
    return root


def _case_evidence(run_root: Path, fault_point: str) -> dict[str, Any]:
    result = json.loads(
        (run_root / "cases" / fault_point / "result.json").read_text()
    )
    required_true = (
        "fact_integrity_valid",
        "real_tls_executed",
        "backend_sled_executed",
        "runtime_sqlite_executed",
    )
    if any(result.get(field) is not True for field in required_true):
        raise ValueError(f"P5-B3f case lacks real execution evidence: {fault_point}")
    if (
        result.get("tick_probe_only") is not True
        or result.get("externally_verified") is not False
        or result.get("production_evidence") is not False
    ):
        raise ValueError(f"P5-B3f case boundary is invalid: {fault_point}")
    return {
        "receipt_hash": result["receipt_hash"],
        "evidence_manifest_hash": result["evidence_manifest_hash"],
        "fact_integrity_valid": True,
        "runtime_sqlite_executed": True,
    }


def _rejection_evidence(run_root: Path, rejection_case: str) -> dict[str, Any]:
    result = json.loads(
        (run_root / "rejections" / rejection_case / "result.json").read_text()
    )
    if (
        result.get("real_tls_executed") is not True
        or result.get("backend_sled_executed") is not True
        or result.get("runtime_sqlite_executed") is not True
        or result.get("fact_integrity_valid") is not True
        or result.get("activation_receipt_status") != 404
        or result.get("failure_audit_boundary") != "local_gate_only"
        or result.get("externally_verified") is not False
        or result.get("production_evidence") is not False
    ):
        raise ValueError(f"P5-B3f rejection lacks real evidence: {rejection_case}")
    return {
        "failure_audit_source": result["failure_audit_source"],
        "failure_audit_boundary": "local_gate_only",
        "activation_receipt_status": 404,
        "fact_integrity_valid": True,
        "runtime_sqlite_executed": True,
    }


def execute_real_matrix(
    *,
    run_root: Path,
    backend_bin: Path,
    backend_port: int,
    worker: Path,
    fault_points: tuple[str, ...] = KILL_POINTS,
    rejection_cases: tuple[str, ...] = REJECTION_CASES,
    timeout: float = 60.0,
) -> dict[str, Any]:
    if timeout <= 0:
        raise ValueError("P5-B3f worker timeout must be positive")
    binary = backend_bin.expanduser().resolve()
    worker_path = worker.expanduser().resolve()
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise ValueError(f"P5-B3f backend binary is not executable: {binary}")
    if not worker_path.is_file():
        raise ValueError(f"P5-B3f worker is missing: {worker_path}")
    unsupported = set(fault_points) - set(KILL_POINTS)
    unsupported_rejections = set(rejection_cases) - set(REJECTION_CASES)
    if unsupported or unsupported_rejections or not (fault_points or rejection_cases):
        raise ValueError(
            "unsupported P5-B3f matrix selection: "
            f"faults={sorted(unsupported)}, rejections={sorted(unsupported_rejections)}"
        )
    root = validate_real_resources(run_root, backend_port)
    root.mkdir(parents=True, mode=0o700)
    os.chmod(root, 0o700)
    command = [
        sys.executable,
        str(worker_path),
        "--backend-bin",
        str(binary),
        "--backend-port",
        str(backend_port),
    ]
    lock_fd = os.open(root / "gate.lock", os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        started = time.time()
        cases = []
        for fault_point in fault_points:
            result = run_fault_case(
                command, root, fault_point, timeout=timeout
            )
            result["evidence"] = _case_evidence(root, fault_point)
            cases.append(result)
        rejections = []
        for rejection_case in rejection_cases:
            result = run_rejection_case(
                command, root, rejection_case, timeout=timeout
            )
            result["evidence"] = _rejection_evidence(root, rejection_case)
            rejections.append(result)
        status = (
            "real_matrix_passed"
            if cases and rejections
            else "positive_matrix_passed"
            if cases
            else "rejection_matrix_passed"
        )
        summary = {
            "schema_version": SUMMARY_SCHEMA,
            "status": status,
            "passed": True,
            "started_at": int(started),
            "completed_at": int(time.time()),
            "backend_port": backend_port,
            "backend_binary_sha256": _file_digest(binary),
            "worker_command_sha256": _command_digest(command),
            "worker_command_file_sha256": _command_file_digests(command),
            "controller_source_sha256": _file_digest(Path(__file__)),
            "kill_points": list(fault_points),
            "cases": cases,
            "rejection_cases": rejections,
            "sigkill_exercised": bool(cases),
            "local_synthetic_only": False,
            "network_used": True,
            "network_scope": "loopback_only",
            "real_tls_executed": True,
            "backend_sled_executed": True,
            "runtime_sqlite_executed": True,
            "real_rejection_matrix_executed": bool(rejections),
            "tick_probe_only": True,
            "agent_runner_started": False,
            "p4_soak_resources_used": False,
            "externally_verified": False,
            "production_evidence": False,
        }
        _write_private_json(root / "summary.json", summary)
        return summary
    finally:
        os.close(lock_fd)


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    root.add_argument("--run-root", required=True, type=Path)
    root.add_argument("--backend-bin", required=True, type=Path)
    root.add_argument("--backend-port", required=True, type=int)
    root.add_argument("--timeout-seconds", type=float, default=60.0)
    root.add_argument(
        "--worker",
        type=Path,
        default=Path(__file__).with_name("p5b3f_checkpoint_real_worker.py"),
    )
    root.add_argument(
        "--fault-point",
        action="append",
        choices=KILL_POINTS,
        dest="fault_points",
    )
    root.add_argument(
        "--rejection-case",
        action="append",
        choices=REJECTION_CASES,
        dest="rejection_cases",
    )
    root.add_argument("--positive-only", action="store_true")
    root.add_argument("--rejection-only", action="store_true")
    root.add_argument("--ack-real-local-gate", action="store_true")
    return root


def main() -> int:
    args = parser().parse_args()
    if not args.ack_real_local_gate:
        raise SystemExit("explicit --ack-real-local-gate is required")
    if args.positive_only and args.rejection_only:
        raise SystemExit("--positive-only and --rejection-only are mutually exclusive")
    summary = execute_real_matrix(
        run_root=args.run_root,
        backend_bin=args.backend_bin,
        backend_port=args.backend_port,
        worker=args.worker,
        fault_points=()
        if args.rejection_only
        else tuple(args.fault_points or KILL_POINTS),
        rejection_cases=()
        if args.positive_only
        else tuple(args.rejection_cases or REJECTION_CASES),
        timeout=args.timeout_seconds,
    )
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
