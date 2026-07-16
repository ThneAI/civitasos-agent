#!/usr/bin/env python3
"""Run resumable 1h, 8h, or 24h P4-E TLS multi-VM soak stages."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import subprocess
import sys
import tarfile
import time
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from beta5_real_multivm_preview_prepare import parse_node
from p4ef_multivm_tls_drill import (
    DEFAULT_NODES,
    PROXY_SOURCE,
    api_request,
    candidate_task_smoke,
    deploy_node,
    remote_stop,
    sha256,
    tls_smoke,
    tree_digest,
    validate_materials,
    write_json,
)

AGENT = SCRIPT_DIR.parent
WORKSPACE = AGENT.parent
LEDGER_CLI = (
    WORKSPACE
    / "civitasos-evidence-ledger"
    / ".venv"
    / "bin"
    / "civitasos-evidence-ledger"
)
AUTH_SCHEMA = "civitasos-p4eg-soak-authorization:v1"
STATE_SCHEMA = "civitasos-p4eg-soak-state:v1"
ROUND_SCHEMA = "civitasos-p4eg-soak-round:v1"
SUMMARY_SCHEMA = "civitasos-p4eg-soak-summary:v1"


def now() -> int:
    return int(time.time())


def journal_payload_sha256(value: dict[str, Any]) -> str:
    payload = {key: item for key, item in value.items() if key != "journal_payload_sha256"}
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode()).hexdigest()


def append_jsonl(path: Path, value: dict[str, Any]) -> None:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(descriptor, encoded.encode())
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def load_rounds(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rounds = []
    for line_number, line in enumerate(path.read_text().splitlines(), 1):
        record = json.loads(line)
        if record.get("schema_version") != ROUND_SCHEMA:
            raise RuntimeError(f"invalid round schema at line {line_number}")
        if record.get("round") != line_number:
            raise RuntimeError(f"non-contiguous round sequence at line {line_number}")
        if record.get("journal_payload_sha256") != journal_payload_sha256(record):
            raise RuntimeError(f"round journal payload hash mismatch at line {line_number}")
        evidence = Path(record["evidence"])
        if not evidence.is_file() or sha256(evidence) != record["evidence_sha256"]:
            raise RuntimeError(f"round evidence hash mismatch at line {line_number}")
        rounds.append(record)
    return rounds


def validate_previous_summary(path: Path | None, hours: int) -> str | None:
    expected = {1: None, 8: 1, 24: 8}[hours]
    if expected is None:
        if path:
            raise SystemExit("1h soak must not consume a previous-stage summary")
        return None
    if not path or not path.is_file():
        raise SystemExit(f"{hours}h soak requires a passed {expected}h summary")
    summary = json.loads(path.read_text())
    if (
        summary.get("schema_version") != SUMMARY_SCHEMA
        or summary.get("passed") is not True
        or summary.get("status") != "passed"
        or summary.get("tier_hours") != expected
        or summary.get("elapsed_seconds", 0)
        < summary.get("requested_duration_seconds", 1)
        or summary.get("cleanup", {}).get("passed") is not True
    ):
        raise SystemExit(f"previous {expected}h soak summary is not a passed closed stage")
    return sha256(path)


def authorize(args: argparse.Namespace) -> int:
    if not args.ack_private_beta_soak:
        raise SystemExit("explicit --ack-private-beta-soak is required")
    candidate = Path(args.candidate_bin).resolve()
    frontend = Path(args.frontend_build_dir).resolve()
    materials = Path(args.materials_dir).resolve()
    previous = Path(args.previous_summary).resolve() if args.previous_summary else None
    if not candidate.is_file() or not (frontend / "index.html").is_file():
        raise SystemExit("candidate binary and frontend build are required")
    manifest = validate_materials(materials)
    previous_sha = validate_previous_summary(previous, args.hours)
    issued_at = now()
    duration = args.hours * 3600
    hashes = [
        sha256(candidate),
        tree_digest(frontend),
        sha256(materials / "manifest.json"),
        previous_sha or "none",
    ]
    material = ":".join([*hashes, str(args.hours), str(issued_at), args.operator_id])
    payload = {
        "schema_version": AUTH_SCHEMA,
        "authorization_id": f"p4eg-{args.hours}h:{hashlib.sha256(material.encode()).hexdigest()[:24]}",
        "issued_at": issued_at,
        "expires_at": issued_at + duration + args.authorization_grace_seconds,
        "single_use": True,
        "consumed": False,
        "operator_id": args.operator_id,
        "tier_hours": args.hours,
        "requested_duration_seconds": duration,
        "candidate_sha256": hashes[0],
        "frontend_sha256": hashes[1],
        "material_manifest_sha256": hashes[2],
        "material_file_sha256": {
            name: metadata["sha256"]
            for name, metadata in manifest["files"].items()
        },
        "previous_summary_sha256": previous_sha,
        "nodes": ["vm1", "vm2", "vm3"],
        "remote_root": args.remote_root,
        "backend_port": args.backend_port,
        "frontend_port": args.frontend_port,
        "round_interval_seconds": args.round_interval_seconds,
        "browser_every_rounds": args.browser_every_rounds,
        "restart_every_rounds": args.restart_every_rounds,
        "public_ingress_allowed": False,
        "production_data_allowed": False,
        "production_evidence_allowed": False,
        "automatic_ledger_append_allowed": False,
    }
    output = Path(args.output).resolve()
    if output.exists():
        raise SystemExit(f"refusing to overwrite authorization: {output}")
    write_json(output, payload)
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def validate_authorization(
    auth: dict[str, Any],
    args: argparse.Namespace,
    *,
    resume: bool,
) -> None:
    candidate = Path(args.candidate_bin).resolve()
    frontend = Path(args.frontend_build_dir).resolve()
    materials = Path(args.materials_dir).resolve()
    manifest = validate_materials(materials)
    previous = Path(args.previous_summary).resolve() if args.previous_summary else None
    previous_sha = validate_previous_summary(previous, args.hours)
    checks = {
        "schema": auth.get("schema_version") == AUTH_SCHEMA,
        "single_use": auth.get("single_use") is True and auth.get("consumed") is False,
        "candidate": auth.get("candidate_sha256") == sha256(candidate),
        "frontend": auth.get("frontend_sha256") == tree_digest(frontend),
        "manifest": (
            auth.get("material_manifest_sha256")
            == sha256(materials / "manifest.json")
        ),
        "material_files": auth.get("material_file_sha256")
        == {
            name: metadata["sha256"]
            for name, metadata in manifest["files"].items()
        },
        "previous": auth.get("previous_summary_sha256") == previous_sha,
        "hours": auth.get("tier_hours") == args.hours,
        "duration": auth.get("requested_duration_seconds")
        == args.duration_seconds,
        "remote_root": auth.get("remote_root") == args.remote_root,
        "ports": (
            auth.get("backend_port") == args.backend_port
            and auth.get("frontend_port") == args.frontend_port
        ),
        "intervals": (
            auth.get("round_interval_seconds") == args.round_interval_seconds
            and auth.get("browser_every_rounds") == args.browser_every_rounds
            and auth.get("restart_every_rounds") == args.restart_every_rounds
        ),
        "fresh": resume or auth.get("expires_at", 0) >= now(),
    }
    failed = [name for name, passed in checks.items() if not passed]
    if failed:
        raise SystemExit(f"P4-EG authorization validation failed: {failed}")


def wait_for_nodes(nodes: list[Any], timeout: int = 900) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if all(
            subprocess.run(
                ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=3", node.ssh_host, "true"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            ).returncode
            == 0
            for node in nodes
        ):
            return
        time.sleep(5)
    raise RuntimeError("VM SSH targets did not become ready before timeout")


def initialize_ledger(run_root: Path, node_id: str) -> Path:
    ledger_root = run_root / "private" / "ledger" / node_id
    marker = ledger_root / ".p4eg-initialized"
    if marker.exists():
        return ledger_root
    ledger_root.parent.mkdir(parents=True, exist_ok=True)
    commands = [
        [
            str(LEDGER_CLI),
            "init-run",
            "--run-root",
            str(ledger_root),
            "--goal-id",
            f"p4eg-soak-{node_id}",
        ],
        [
            str(LEDGER_CLI),
            "register-actor",
            "--run-root",
            str(ledger_root),
            "--actor-id",
            f"p4eg-evidence-{node_id}",
            "--actor-role",
            "evidence_operator",
            "--display-name",
            f"P4-EG Evidence {node_id}",
        ],
    ]
    for command in commands:
        completed = subprocess.run(
            command,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
        if completed.returncode != 0:
            raise RuntimeError(
                f"ledger initialization failed for {node_id}: {completed.stdout[-2000:]}"
            )
    marker.write_text("initialized\n")
    os.chmod(marker, 0o600)
    return ledger_root


def recover_evidence(
    run_root: Path,
    nodes: list[Any],
    materials: Path,
    frontend_port: int,
    round_number: int,
) -> list[dict[str, Any]]:
    observations = []
    private_root = run_root / "private"
    private_root.mkdir(parents=True, exist_ok=True)
    os.chmod(private_root, 0o700)
    for node in nodes:
        secret = (materials / f"{node.node_id}.service").read_text().strip()
        status, service = api_request(
            node,
            frontend_port,
            "/api/v1/auth/service-token",
            {
                "service_id": f"p4eg-evidence-{node.node_id}",
                "secret": secret,
                "scopes": ["evidence:read", "evidence:write"],
            },
        )
        token = service.get("data", {}).get("token")
        if status != 200 or not token:
            raise RuntimeError(f"{node.node_id} evidence service token failed")
        token_path = private_root / f"{node.node_id}.evidence.jwt"
        token_path.write_text(token + "\n")
        os.chmod(token_path, 0o600)
        ledger_root = initialize_ledger(run_root, node.node_id)
        staging = private_root / "staging" / node.node_id
        bridge_report = private_root / f"{node.node_id}.bridge.json"
        command = [
            sys.executable,
            str(SCRIPT_DIR / "p4_evidence_export_bridge.py"),
            "--backend-url",
            f"https://{node.node_ip}:{frontend_port}",
            "--service-token-file",
            str(token_path),
            "--ca-cert",
            str(materials / "ca.crt"),
            "--ledger-run-root",
            str(ledger_root),
            "--actor-id",
            f"p4eg-evidence-{node.node_id}",
            "--staging-root",
            str(staging),
            "--output",
            str(bridge_report),
            "--max-attempts",
            "3",
            "--retry-delay-secs",
            "1",
        ]
        completed = subprocess.run(
            command,
            cwd=AGENT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
        token_path.unlink(missing_ok=True)
        if completed.returncode != 0:
            raise RuntimeError(
                f"{node.node_id} evidence bridge failed: {completed.stdout[-2000:]}"
            )
        bridge = json.loads(bridge_report.read_text())
        health_status, health_response = api_request(
            node,
            frontend_port,
            "/api/v1/a2a/operator/evidence-exports/health",
            token=token,
        )
        health = health_response.get("data", {})
        if (
            health_status != 200
            or health.get("pending_count") != 0
            or health.get("healthy") is not True
        ):
            raise RuntimeError(
                f"{node.node_id} Evidence health did not recover: {health_response}"
            )
        observations.append(
            {
                "node_id": node.node_id,
                "processed_count": bridge.get("processed_count"),
                "retry_count": bridge.get("retry_count"),
                "pending_after": health.get("pending_count"),
                "healthy_after": health.get("healthy"),
                "round": round_number,
                "passed": True,
            }
        )
    return observations


def run_browser_smoke(
    run_root: Path,
    nodes: list[Any],
    materials: Path,
    frontend_port: int,
    round_number: int,
) -> dict[str, Any]:
    targets = run_root / "private" / f"browser-targets-{round_number}.json"
    output = run_root / "round-artifacts" / f"browser-{round_number}.json"
    write_json(
        targets,
        [
            {
                "node_id": node.node_id,
                "ip": node.node_ip,
                "hostname": f"{node.node_id}.civitas.internal",
                "frontend_port": frontend_port,
                "service_secret_file": str(
                    materials / f"{node.node_id}.service"
                ),
            }
            for node in nodes
        ],
    )
    completed = subprocess.run(
        [
            "node",
            str(SCRIPT_DIR / "p4ef_multivm_browser_smoke.js"),
            "--targets",
            str(targets),
            "--output",
            str(output),
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=300,
        check=False,
    )
    targets.unlink(missing_ok=True)
    if completed.returncode != 0:
        raise RuntimeError(
            f"round {round_number} browser smoke failed: {completed.stdout[-3000:]}"
        )
    report = json.loads(output.read_text())
    if report.get("passed") is not True:
        raise RuntimeError(f"round {round_number} browser report failed")
    return {
        "report": str(output),
        "sha256": sha256(output),
        "node_count": report.get("node_count"),
        "passed": True,
    }


def run_round(
    run_root: Path,
    nodes: list[Any],
    candidate: Path,
    archive: Path,
    proxy: Path,
    materials: Path,
    args: argparse.Namespace,
    round_number: int,
) -> dict[str, Any]:
    restarted = False
    if round_number > 1 and round_number % args.restart_every_rounds == 0:
        for node in nodes:
            deploy_node(
                node,
                candidate,
                archive,
                proxy,
                materials,
                args.remote_root,
                args.backend_port,
                args.frontend_port,
                preserve_state=True,
            )
        restarted = True
    tls = tls_smoke(
        nodes, materials, args.backend_port, args.frontend_port
    )
    artifact_root = run_root / "round-artifacts"
    artifact_root.mkdir(parents=True, exist_ok=True)
    task_path = artifact_root / f"tasks-{round_number}.json"
    task = candidate_task_smoke(
        nodes, materials, args.frontend_port, task_path
    )
    evidence = recover_evidence(
        run_root,
        nodes,
        materials,
        args.frontend_port,
        round_number,
    )
    browser = None
    if round_number == 1 or round_number % args.browser_every_rounds == 0:
        browser = run_browser_smoke(
            run_root,
            nodes,
            materials,
            args.frontend_port,
            round_number,
        )
    report = {
        "schema_version": "civitasos-p4eg-round-evidence:v1",
        "passed": True,
        "round": round_number,
        "restarted": restarted,
        "tls": tls,
        "task_receipt": task,
        "task_receipt_sha256": sha256(task_path),
        "evidence_recovery": evidence,
        "browser": browser,
        "recorded_at": now(),
        "boundaries": {
            "public_ingress_opened": False,
            "production_data_used": False,
            "automatic_ledger_append_enabled": False,
        },
    }
    evidence_path = artifact_root / f"round-{round_number}.json"
    write_json(evidence_path, report)
    return {
        "schema_version": ROUND_SCHEMA,
        "round": round_number,
        "passed": True,
        "restarted": restarted,
        "browser_executed": browser is not None,
        "evidence": str(evidence_path),
        "evidence_sha256": sha256(evidence_path),
        "recorded_at": now(),
    }


def checkpoint_state(path: Path, state: dict[str, Any]) -> None:
    state["updated_at"] = now()
    write_json(path, state)


def active_sleep(
    seconds: float,
    state_path: Path,
    state: dict[str, Any],
) -> None:
    remaining = seconds
    while remaining > 0:
        duration = min(5.0, remaining)
        started = time.monotonic()
        time.sleep(duration)
        state["elapsed_seconds"] += time.monotonic() - started
        checkpoint_state(state_path, state)
        remaining -= duration


def execute(args: argparse.Namespace) -> int:
    args.duration_seconds = (
        args.duration_seconds
        if args.duration_seconds is not None
        else args.hours * 3600
    )
    auth_path = Path(args.authorization).resolve()
    auth = json.loads(auth_path.read_text())
    run_root = Path(args.run_root).resolve()
    state_path = run_root / "state.json"
    rounds_path = run_root / "rounds.jsonl"
    resume = state_path.exists()
    validate_authorization(auth, args, resume=resume)
    run_root.mkdir(parents=True, exist_ok=True)
    os.chmod(run_root, 0o700)
    lock_path = run_root / "runner.lock"
    lock_descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(lock_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as error:
        os.close(lock_descriptor)
        raise SystemExit("another P4-EG runner already owns this run root") from error

    nodes = [parse_node(raw) for raw in (args.node or DEFAULT_NODES)]
    candidate = Path(args.candidate_bin).resolve()
    frontend = Path(args.frontend_build_dir).resolve()
    materials = Path(args.materials_dir).resolve()
    assets = run_root / "private" / "assets"
    assets.mkdir(parents=True, exist_ok=True)
    os.chmod(run_root / "private", 0o700)
    archive = assets / "frontend.tgz"
    proxy = assets / "tls_proxy.py"
    if not archive.exists():
        with tarfile.open(archive, "w:gz") as tar:
            tar.add(frontend, arcname="build")
    if not proxy.exists():
        proxy.write_text(PROXY_SOURCE)
        os.chmod(proxy, 0o700)

    if resume:
        state = json.loads(state_path.read_text())
        if (
            state.get("schema_version") != STATE_SCHEMA
            or state.get("authorization_id") != auth["authorization_id"]
            or state.get("status") != "running"
        ):
            raise SystemExit("run root is not a resumable state for this authorization")
        rounds = load_rounds(rounds_path)
        if state.get("round_count") != len(rounds):
            raise SystemExit("state and append-only round journal disagree")
    else:
        if any(run_root.iterdir()) and not all(
            item.name in {"private", "runner.lock"} for item in run_root.iterdir()
        ):
            raise SystemExit("refusing to start in a non-empty run root")
        state = {
            "schema_version": STATE_SCHEMA,
            "authorization_id": auth["authorization_id"],
            "authorization_sha256": sha256(auth_path),
            "status": "running",
            "tier_hours": args.hours,
            "requested_duration_seconds": args.duration_seconds,
            "elapsed_seconds": 0.0,
            "round_count": 0,
            "started_at": now(),
            "updated_at": now(),
            "resume_count": 0,
            "failure": None,
        }
        checkpoint_state(state_path, state)
        rounds = []

    summary_path = run_root / "summary.json"
    cleanup = {"passed": False, "nodes": []}
    failure = None
    try:
        wait_for_nodes(nodes)
        for node in nodes:
            deploy_node(
                node,
                candidate,
                archive,
                proxy,
                materials,
                args.remote_root,
                args.backend_port,
                args.frontend_port,
                preserve_state=resume or bool(rounds),
            )
        if resume:
            state["resume_count"] += 1
            checkpoint_state(state_path, state)

        while state["elapsed_seconds"] < args.duration_seconds:
            round_number = len(rounds) + 1
            round_started = time.monotonic()
            record = run_round(
                run_root,
                nodes,
                candidate,
                archive,
                proxy,
                materials,
                args,
                round_number,
            )
            state["elapsed_seconds"] += time.monotonic() - round_started
            record["active_elapsed_seconds"] = round(
                state["elapsed_seconds"], 3
            )
            record["journal_payload_sha256"] = journal_payload_sha256(record)
            append_jsonl(rounds_path, record)
            rounds.append(record)
            state["round_count"] = len(rounds)
            checkpoint_state(state_path, state)
            print(
                f"[P4-EG {args.hours}h round {round_number}] PASS "
                f"active_elapsed={state['elapsed_seconds']:.3f}s",
                flush=True,
            )
            remaining = args.duration_seconds - state["elapsed_seconds"]
            if remaining > 0:
                active_sleep(
                    min(args.round_interval_seconds, remaining),
                    state_path,
                    state,
                )
    except BaseException as exception:  # cleanup also applies to interruption
        failure = f"{type(exception).__name__}: {exception}"
        state["failure"] = failure
        state["status"] = "failed"
        checkpoint_state(state_path, state)
    finally:
        cleanup_nodes = []
        for node in nodes:
            try:
                remote_stop(
                    node,
                    args.remote_root,
                    args.backend_port,
                    args.frontend_port,
                    remove=True,
                )
                cleanup_nodes.append(
                    {"node_id": node.node_id, "passed": True}
                )
            except Exception as exception:  # noqa: BLE001
                cleanup_nodes.append(
                    {
                        "node_id": node.node_id,
                        "passed": False,
                        "error": str(exception),
                    }
                )
        cleanup = {
            "passed": all(item["passed"] for item in cleanup_nodes),
            "nodes": cleanup_nodes,
        }
        write_json(run_root / "cleanup.json", cleanup)

    passed = (
        failure is None
        and state["elapsed_seconds"] >= args.duration_seconds
        and len(rounds) > 0
        and all(item["passed"] for item in rounds)
        and cleanup["passed"]
    )
    state["status"] = "passed" if passed else "failed"
    checkpoint_state(state_path, state)
    summary = {
        "schema_version": SUMMARY_SCHEMA,
        "passed": passed,
        "status": state["status"],
        "decision": (
            f"go_p4eg_{args.hours}h_complete" if passed else "no_go"
        ),
        "authorization_id": auth["authorization_id"],
        "authorization_consumed": True,
        "tier_hours": args.hours,
        "requested_duration_seconds": args.duration_seconds,
        "elapsed_seconds": round(state["elapsed_seconds"], 3),
        "round_count": len(rounds),
        "round_journal": str(rounds_path),
        "round_journal_sha256": (
            sha256(rounds_path) if rounds_path.exists() else None
        ),
        "resume_count": state["resume_count"],
        "failure": failure,
        "cleanup": cleanup,
        "candidate_sha256": auth["candidate_sha256"],
        "frontend_sha256": auth["frontend_sha256"],
        "material_manifest_sha256": auth["material_manifest_sha256"],
        "previous_summary_sha256": auth["previous_summary_sha256"],
        "boundaries": {
            "public_ingress_opened": False,
            "production_data_used": False,
            "production_evidence_claimed": False,
            "automatic_ledger_append_enabled": False,
            "physical_authenticator_provenance_verified": False,
            "physical_hsm_provenance_verified": False,
        },
    }
    write_json(summary_path, summary)
    print(
        f"P4-EG {args.hours}h soak: {summary['status']}; "
        f"rounds={len(rounds)}; report={summary_path}",
        flush=True,
    )
    os.close(lock_descriptor)
    return 0 if passed else 1


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    subparsers = root.add_subparsers(dest="command", required=True)
    auth = subparsers.add_parser("authorize")
    auth.add_argument("--hours", type=int, required=True, choices=(1, 8, 24))
    auth.add_argument("--candidate-bin", required=True)
    auth.add_argument("--frontend-build-dir", required=True)
    auth.add_argument("--materials-dir", required=True)
    auth.add_argument("--previous-summary")
    auth.add_argument("--output", required=True)
    auth.add_argument("--operator-id", default="local-operator-cc")
    auth.add_argument("--remote-root", default="/tmp/civitasos-p4eg-soak")
    auth.add_argument("--backend-port", type=int, default=18444)
    auth.add_argument("--frontend-port", type=int, default=18443)
    auth.add_argument("--round-interval-seconds", type=float, default=60.0)
    auth.add_argument("--browser-every-rounds", type=int, default=15)
    auth.add_argument("--restart-every-rounds", type=int, default=15)
    auth.add_argument(
        "--authorization-grace-seconds", type=int, default=21600
    )
    auth.add_argument("--ack-private-beta-soak", action="store_true")
    auth.set_defaults(func=authorize)
    run = subparsers.add_parser("execute")
    run.add_argument("--authorization", required=True)
    run.add_argument("--hours", type=int, required=True, choices=(1, 8, 24))
    run.add_argument("--duration-seconds", type=int)
    run.add_argument("--candidate-bin", required=True)
    run.add_argument("--frontend-build-dir", required=True)
    run.add_argument("--materials-dir", required=True)
    run.add_argument("--previous-summary")
    run.add_argument("--run-root", required=True)
    run.add_argument("--remote-root", default="/tmp/civitasos-p4eg-soak")
    run.add_argument("--backend-port", type=int, default=18444)
    run.add_argument("--frontend-port", type=int, default=18443)
    run.add_argument("--round-interval-seconds", type=float, default=60.0)
    run.add_argument("--browser-every-rounds", type=int, default=15)
    run.add_argument("--restart-every-rounds", type=int, default=15)
    run.add_argument("--node", action="append", default=[])
    run.set_defaults(func=execute)
    return root


def main() -> int:
    args = parser().parse_args()
    if getattr(args, "browser_every_rounds", 1) < 1:
        raise SystemExit("browser interval must be positive")
    if getattr(args, "restart_every_rounds", 1) < 1:
        raise SystemExit("restart interval must be positive")
    if getattr(args, "round_interval_seconds", 1) <= 0:
        raise SystemExit("round interval must be positive")
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
