#!/usr/bin/env python3
"""Run the authorized P4-EG 1h, 8h, and 24h stages in order."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from p4ef_multivm_tls_drill import sha256, tree_digest, validate_materials, write_json
from p4eg_tls_soak import SUMMARY_SCHEMA, source_digest, validate_previous_summary

CHAIN_AUTH_SCHEMA = "civitasos-p4eg-soak-chain-authorization:v1"
CHAIN_SUMMARY_SCHEMA = "civitasos-p4eg-soak-chain-summary:v1"
STAGES = (1, 8, 24)
RUNNER_SOURCE_FILES = (
    Path(__file__).resolve(),
    (SCRIPT_DIR / "p4eg_tls_soak.py").resolve(),
    (SCRIPT_DIR / "p4ef_multivm_tls_drill.py").resolve(),
)


def now() -> int:
    return int(time.time())


def authorize(args: argparse.Namespace) -> int:
    if not args.ack_private_beta_soak_chain:
        raise SystemExit("explicit --ack-private-beta-soak-chain is required")
    candidate = Path(args.candidate_bin).resolve()
    frontend = Path(args.frontend_build_dir).resolve()
    materials = Path(args.materials_dir).resolve()
    if not candidate.is_file() or not (frontend / "index.html").is_file():
        raise SystemExit("candidate binary and frontend build are required")
    validate_materials(materials)
    issued_at = now()
    hashes = {
        "candidate_sha256": sha256(candidate),
        "frontend_sha256": tree_digest(frontend),
        "material_manifest_sha256": sha256(materials / "manifest.json"),
        "runner_source_sha256": source_digest(RUNNER_SOURCE_FILES),
    }
    identifier = hashlib.sha256(
        ":".join([*hashes.values(), str(issued_at), args.operator_id]).encode()
    ).hexdigest()[:24]
    payload = {
        "schema_version": CHAIN_AUTH_SCHEMA,
        "authorization_id": f"p4eg-chain:{identifier}",
        "issued_at": issued_at,
        "operator_id": args.operator_id,
        "stages_hours": list(STAGES),
        **hashes,
        "remote_root": args.remote_root,
        "backend_port": args.backend_port,
        "frontend_port": args.frontend_port,
        "round_interval_seconds": args.round_interval_seconds,
        "browser_every_rounds": args.browser_every_rounds,
        "restart_every_rounds": args.restart_every_rounds,
        "public_ingress_allowed": False,
        "production_data_allowed": False,
        "automatic_ledger_append_allowed": False,
    }
    output = Path(args.output).resolve()
    if output.exists():
        raise SystemExit(f"refusing to overwrite chain authorization: {output}")
    write_json(output, payload)
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def validate_chain_authorization(auth: dict[str, Any], args: argparse.Namespace) -> None:
    candidate = Path(args.candidate_bin).resolve()
    frontend = Path(args.frontend_build_dir).resolve()
    materials = Path(args.materials_dir).resolve()
    validate_materials(materials)
    checks = {
        "schema": auth.get("schema_version") == CHAIN_AUTH_SCHEMA,
        "stages": auth.get("stages_hours") == list(STAGES),
        "candidate": auth.get("candidate_sha256") == sha256(candidate),
        "frontend": auth.get("frontend_sha256") == tree_digest(frontend),
        "materials": auth.get("material_manifest_sha256") == sha256(materials / "manifest.json"),
        "runner_source": auth.get("runner_source_sha256")
        == source_digest(RUNNER_SOURCE_FILES),
        "remote_root": auth.get("remote_root") == args.remote_root,
        "ports": auth.get("backend_port") == args.backend_port
        and auth.get("frontend_port") == args.frontend_port,
        "intervals": auth.get("round_interval_seconds") == args.round_interval_seconds
        and auth.get("browser_every_rounds") == args.browser_every_rounds
        and auth.get("restart_every_rounds") == args.restart_every_rounds,
    }
    failed = [name for name, passed in checks.items() if not passed]
    if failed:
        raise SystemExit(f"P4-EG chain authorization validation failed: {failed}")


def read_passed_stage(path: Path, hours: int) -> dict[str, Any] | None:
    if not path.exists():
        return None
    summary = json.loads(path.read_text())
    if summary.get("status") == "failed":
        raise SystemExit(f"P4-EG {hours}h stage has failed; chain will not advance")
    if (
        summary.get("schema_version") != SUMMARY_SCHEMA
        or summary.get("passed") is not True
        or summary.get("tier_hours") != hours
        or summary.get("cleanup", {}).get("passed") is not True
    ):
        raise SystemExit(f"P4-EG {hours}h stage summary is not closed and passed")
    return summary


def command_common(args: argparse.Namespace) -> list[str]:
    return [
        "--candidate-bin", str(Path(args.candidate_bin).resolve()),
        "--frontend-build-dir", str(Path(args.frontend_build_dir).resolve()),
        "--materials-dir", str(Path(args.materials_dir).resolve()),
        "--remote-root", args.remote_root,
        "--backend-port", str(args.backend_port),
        "--frontend-port", str(args.frontend_port),
        "--round-interval-seconds", str(args.round_interval_seconds),
        "--browser-every-rounds", str(args.browser_every_rounds),
        "--restart-every-rounds", str(args.restart_every_rounds),
    ]


def execute(args: argparse.Namespace) -> int:
    chain_auth_path = Path(args.authorization).resolve()
    auth = json.loads(chain_auth_path.read_text())
    validate_chain_authorization(auth, args)
    chain_root = Path(args.chain_root).resolve()
    chain_root.mkdir(parents=True, exist_ok=True)
    os.chmod(chain_root, 0o700)
    lock_fd = os.open(chain_root / "chain.lock", os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as error:
        os.close(lock_fd)
        raise SystemExit("another P4-EG chain coordinator is active") from error

    previous_summary: Path | None = None
    stage_results = []
    runner = SCRIPT_DIR / "p4eg_tls_soak.py"
    try:
        for hours in STAGES:
            validate_chain_authorization(auth, args)
            stage_root = chain_root / f"stage-{hours}h"
            summary_path = stage_root / "summary.json"
            existing = read_passed_stage(summary_path, hours)
            if existing is not None:
                stage_results.append({"hours": hours, "summary": str(summary_path), "sha256": sha256(summary_path)})
                previous_summary = summary_path
                continue

            auth_path = chain_root / f"stage-{hours}h-authorization.json"
            if not auth_path.exists():
                command = [
                    sys.executable, str(runner), "authorize", "--hours", str(hours),
                    *command_common(args), "--output", str(auth_path),
                    "--operator-id", auth["operator_id"], "--ack-private-beta-soak",
                ]
                if previous_summary:
                    validate_previous_summary(previous_summary, hours)
                    command.extend(["--previous-summary", str(previous_summary)])
                subprocess.run(command, check=True)

            command = [
                sys.executable, str(runner), "execute", "--authorization", str(auth_path),
                "--hours", str(hours), *command_common(args), "--run-root", str(stage_root),
            ]
            if previous_summary:
                command.extend(["--previous-summary", str(previous_summary)])
            completed = subprocess.run(command, check=False)
            if completed.returncode != 0:
                raise SystemExit(f"P4-EG {hours}h stage failed with exit code {completed.returncode}")
            read_passed_stage(summary_path, hours)
            stage_results.append({"hours": hours, "summary": str(summary_path), "sha256": sha256(summary_path)})
            previous_summary = summary_path

        summary = {
            "schema_version": CHAIN_SUMMARY_SCHEMA,
            "passed": True,
            "status": "passed",
            "authorization_id": auth["authorization_id"],
            "authorization_sha256": sha256(chain_auth_path),
            "stages": stage_results,
            "completed_at": now(),
        }
        write_json(chain_root / "summary.json", summary)
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 0
    finally:
        os.close(lock_fd)


def add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--candidate-bin", required=True)
    parser.add_argument("--frontend-build-dir", required=True)
    parser.add_argument("--materials-dir", required=True)
    parser.add_argument("--remote-root", default="/tmp/civitasos-p4eg-soak")
    parser.add_argument("--backend-port", type=int, default=18444)
    parser.add_argument("--frontend-port", type=int, default=18443)
    parser.add_argument("--round-interval-seconds", type=float, default=60.0)
    parser.add_argument("--browser-every-rounds", type=int, default=15)
    parser.add_argument("--restart-every-rounds", type=int, default=15)


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    subparsers = root.add_subparsers(dest="command", required=True)
    auth = subparsers.add_parser("authorize")
    add_common(auth)
    auth.add_argument("--output", required=True)
    auth.add_argument("--operator-id", default="local-operator-cc")
    auth.add_argument("--ack-private-beta-soak-chain", action="store_true")
    auth.set_defaults(func=authorize)
    run = subparsers.add_parser("execute")
    add_common(run)
    run.add_argument("--authorization", required=True)
    run.add_argument("--chain-root", required=True)
    run.set_defaults(func=execute)
    return root


def main() -> int:
    args = parser().parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
