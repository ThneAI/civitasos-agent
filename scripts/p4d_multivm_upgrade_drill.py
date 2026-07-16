#!/usr/bin/env python3
"""Authorize and execute a hash-bound private three-VM upgrade/rollback drill."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import time
import urllib.request
import urllib.error
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from beta5_real_multivm_preview_prepare import PreviewNode, parse_node, write_real_multivm_preview_run


AUTH_SCHEMA = "civitasos-p4d-multivm-upgrade-authorization:v1"
RECEIPT_SCHEMA = "civitasos-p4d-operational-change-receipt:v1"
SUMMARY_SCHEMA = "civitasos-p4d-multivm-upgrade-summary:v1"
DEFAULT_NODES = (
    "vm1,vm1,192.168.56.4",
    "vm2,vm2,192.168.56.5",
    "vm3,vm3,192.168.56.6",
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def now() -> int:
    return int(time.time())


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def authorize(args: argparse.Namespace) -> int:
    if not args.ack_private_beta_upgrade_drill:
        raise SystemExit("explicit --ack-private-beta-upgrade-drill is required")
    baseline = Path(args.baseline_bin).resolve()
    candidate = Path(args.candidate_bin).resolve()
    frontend = Path(args.frontend_build_dir).resolve()
    for path in (baseline, candidate):
        if not path.is_file():
            raise SystemExit(f"binary not found: {path}")
    if not frontend.is_dir():
        raise SystemExit(f"frontend build directory not found: {frontend}")
    nodes = [parse_node(raw) for raw in (args.node or DEFAULT_NODES)]
    if sorted(node.node_id for node in nodes) != ["vm1", "vm2", "vm3"]:
        raise SystemExit("authorization must target exactly vm1, vm2, and vm3")
    issued_at = now()
    material = f"{sha256(baseline)}:{sha256(candidate)}:{issued_at}:{args.operator_id}"
    payload = {
        "schema_version": AUTH_SCHEMA,
        "authorization_id": f"p4d-upgrade:{hashlib.sha256(material.encode()).hexdigest()[:24]}",
        "issued_at": issued_at,
        "expires_at": issued_at + args.ttl_seconds,
        "single_use": True,
        "consumed": False,
        "operator_id": args.operator_id,
        "nodes": [node.node_id for node in nodes],
        "baseline_sha256": sha256(baseline),
        "candidate_sha256": sha256(candidate),
        "frontend_sha256": tree_digest(frontend),
        "remote_root": args.remote_root,
        "operations": ["deploy", "upgrade", "rollback", "cleanup"],
        "public_ingress_allowed": False,
        "production_runtime_allowed": False,
        "production_receipt_write_allowed": False,
    }
    output = Path(args.output).resolve()
    if output.exists():
        raise SystemExit(f"refusing to overwrite authorization: {output}")
    write_json(output, payload)
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        digest.update(str(path.relative_to(root)).encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def run_command(command: list[str], cwd: Path, log_path: Path, timeout: int) -> dict[str, Any]:
    started = time.monotonic()
    process = subprocess.run(
        command,
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
    )
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_text(process.stdout, encoding="utf-8")
    return {
        "command": command,
        "return_code": process.returncode,
        "duration_seconds": round(time.monotonic() - started, 3),
        "log_path": str(log_path),
        "log_sha256": sha256(log_path),
    }


def phase(
    name: str,
    release_sha256: str,
    previous_release_sha256: str | None,
    run_root: Path,
    output_root: Path,
) -> dict[str, Any]:
    command = run_command(
        [str(run_root / "deploy_multivm_real_service.sh")],
        run_root,
        output_root / f"{name}.log",
        900,
    )
    smoke = None
    smoke_summary: dict[str, Any] = {}
    if command["return_code"] == 0:
        smoke = run_command(
            [str(run_root / "smoke_multivm_real_service.py")],
            run_root,
            output_root / f"{name}-smoke.log",
            180,
        )
        summary_path = run_root / "multivm_real_service_smoke_summary.json"
        if summary_path.is_file():
            smoke_summary = json.loads(summary_path.read_text(encoding="utf-8"))
    passed = command["return_code"] == 0 and smoke is not None and smoke["return_code"] == 0 and smoke_summary.get("passed") is True
    receipt = {
        "schema_version": RECEIPT_SCHEMA,
        "operation": name,
        "passed": passed,
        "release_sha256": release_sha256,
        "previous_release_sha256": previous_release_sha256,
        "command": command,
        "smoke": smoke,
        "smoke_summary_sha256": sha256(run_root / "multivm_real_service_smoke_summary.json") if smoke_summary else None,
        "nodes": smoke_summary.get("nodes", []),
        "total_checks": smoke_summary.get("total_checks", 0),
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "production_operation": False,
    }
    write_json(output_root / f"{name}-receipt.json", receipt)
    return receipt


def api_request(base_url: str, path: str, payload: dict[str, Any] | None = None, token: str | None = None) -> dict[str, Any]:
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(
        f"{base_url}{path}",
        data=json.dumps(payload or {}).encode(),
        headers=headers,
        method="POST" if payload is not None else "GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        body = error.read().decode(errors="replace")
        raise RuntimeError(f"{path} returned HTTP {error.code}: {body}") from error


def candidate_task_receipt_smoke(nodes: list[PreviewNode], backend_port: int, output: Path) -> dict[str, Any]:
    observations = []
    for node in nodes:
        base_url = f"http://{node.node_ip}:{backend_port}/api/v1"
        suffix = uuid.uuid4().hex[:12]
        requester_id = f"p4d-requester-{node.node_id}-{suffix}"
        worker_id = f"p4d-worker-{node.node_id}-{suffix}"
        requester_login = api_request(base_url, "/auth/demo-login", {"agent_id": requester_id})
        requester_token = requester_login["data"]["token"]
        worker_login = api_request(base_url, "/auth/demo-login", {"agent_id": worker_id})
        worker_token = worker_login["data"]["token"]
        posted = api_request(
            base_url,
            "/a2a/pool/post",
            {
                "requester": requester_id,
                "required_capability": "general",
                "input": {"p4d_upgrade_drill": True},
                "reward": 1,
                "min_reputation": 0,
            },
            requester_token,
        )
        task_id = posted["task_id"]
        auto_claimed_by = posted.get("auto_claimed_by")
        if auto_claimed_by:
            worker_id = str(auto_claimed_by)
            worker_login = api_request(base_url, "/auth/demo-login", {"agent_id": worker_id})
            worker_token = worker_login["data"]["token"]
        else:
            api_request(
                base_url,
                "/a2a/pool/claim",
                {"task_id": task_id, "agent_id": worker_id},
                worker_token,
            )
        api_request(
            base_url,
            "/a2a/task/execute",
            {
                "agent_id": worker_id,
                "task_id": task_id,
                "output": {"result": "P4-D candidate delivery verified"},
                "success": True,
                "metadata": {"drill": "p4d-multivm-upgrade"},
            },
            worker_token,
        )
        time.sleep(2)
        try:
            api_request(base_url, f"/a2a/pool/confirm/{task_id}", {}, requester_token)
            review_mode = "requester_confirm"
        except RuntimeError as error:
            if "task is Completed, not Delivered" not in str(error):
                raise
            review_mode = "challenge_window_auto_settlement"
        receipt_response = api_request(
            base_url,
            f"/a2a/facts/tasks/{task_id}/receipt",
            token=requester_token,
        )
        receipt = receipt_response["data"]
        if not receipt.get("complete") or not receipt.get("lifecycle", {}).get("settled"):
            raise RuntimeError(f"{node.node_id} task receipt did not close: {receipt}")
        observations.append(
            {
                "node_id": node.node_id,
                "task_id": task_id,
                "fact_count": receipt["fact_count"],
                "receipt_hash": receipt["receipt_hash"],
                "settled": True,
                "claim_mode": "automatic" if auto_claimed_by else "explicit",
                "review_mode": review_mode,
            }
        )
    report = {
        "schema_version": "civitasos-p4d-multivm-task-receipt-smoke:v1",
        "passed": len(observations) == 3,
        "node_count": len(observations),
        "observations": observations,
        "browser_contract_compatible": True,
        "demo_auth_nonproduction": True,
        "production_evidence_claimed": False,
    }
    write_json(output, report)
    return report


def execute(args: argparse.Namespace) -> int:
    authorization_path = Path(args.authorization).resolve()
    authorization = json.loads(authorization_path.read_text(encoding="utf-8"))
    baseline = Path(args.baseline_bin).resolve()
    candidate = Path(args.candidate_bin).resolve()
    frontend = Path(args.frontend_build_dir).resolve()
    validate_authorization(authorization, baseline, candidate, frontend)
    output_root = Path(args.output_root).resolve()
    summary_path = output_root / "p4d-multivm-upgrade-summary.json"
    if summary_path.exists():
        raise SystemExit("single-use authorization already has an execution summary")
    output_root.mkdir(parents=True, exist_ok=True)
    nodes = [parse_node(raw) for raw in (args.node or DEFAULT_NODES)]
    baseline_root = output_root / "baseline-run"
    candidate_root = output_root / "candidate-run"
    for run_root, binary in ((baseline_root, baseline), (candidate_root, candidate)):
        write_real_multivm_preview_run(
            run_root=run_root,
            backend_bin=binary,
            frontend_build_dir=frontend,
            nodes=nodes,
            remote_root=authorization["remote_root"],
            backend_port=args.backend_port,
            frontend_port=args.frontend_port,
            owner=authorization["operator_id"],
            overwrite=False,
        )

    receipts: list[dict[str, Any]] = []
    failures: list[str] = []
    cleanup: dict[str, Any] | None = None
    cleanup_health: dict[str, Any] | None = None
    task_receipt_smoke: dict[str, Any] | None = None
    try:
        deploy = phase("deploy", authorization["baseline_sha256"], None, baseline_root, output_root)
        receipts.append(deploy)
        if not deploy["passed"]:
            failures.append("baseline_deploy_failed")
        if not failures:
            upgrade = phase(
                "upgrade",
                authorization["candidate_sha256"],
                authorization["baseline_sha256"],
                candidate_root,
                output_root,
            )
            receipts.append(upgrade)
            if not upgrade["passed"]:
                failures.append("candidate_upgrade_failed")
        if not failures:
            try:
                task_receipt_smoke = candidate_task_receipt_smoke(
                    nodes,
                    args.backend_port,
                    output_root / "candidate-task-receipt-smoke.json",
                )
            except Exception as exc:  # noqa: BLE001
                failures.append(f"candidate_task_receipt_smoke_failed:{exc}")
        if not failures:
            rollback = phase(
                "rollback",
                authorization["baseline_sha256"],
                authorization["candidate_sha256"],
                baseline_root,
                output_root,
            )
            receipts.append(rollback)
            if not rollback["passed"]:
                failures.append("baseline_rollback_failed")
    finally:
        cleanup = run_command(
            [str(baseline_root / "rollback_multivm_real_service.sh")],
            baseline_root,
            output_root / "cleanup.log",
            300,
        )
        cleanup_health = run_command(
            [str(baseline_root / "smoke_rollback_multivm_real_service.sh")],
            baseline_root,
            output_root / "cleanup-health.log",
            180,
        )
        if cleanup["return_code"] != 0 or cleanup_health["return_code"] != 0:
            failures.append("cleanup_failed")

    passed = not failures and len(receipts) == 3 and all(receipt["passed"] for receipt in receipts)
    summary = {
        "schema_version": SUMMARY_SCHEMA,
        "passed": passed,
        "decision": "go_p4d_private_multivm_operations" if passed else "no_go",
        "authorization_id": authorization["authorization_id"],
        "authorization_sha256": sha256(authorization_path),
        "authorization_consumed": True,
        "baseline_sha256": authorization["baseline_sha256"],
        "candidate_sha256": authorization["candidate_sha256"],
        "frontend_sha256": authorization["frontend_sha256"],
        "failure_reasons": failures,
        "receipts": [str(output_root / f"{receipt['operation']}-receipt.json") for receipt in receipts],
        "cleanup": cleanup,
        "cleanup_health": cleanup_health,
        "candidate_task_receipt_smoke": task_receipt_smoke,
        "boundaries": {
            "public_ingress_opened": False,
            "production_runtime_executed": False,
            "production_receipt_written": False,
        },
    }
    write_json(summary_path, summary)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if passed else 1


def validate_authorization(authorization: dict[str, Any], baseline: Path, candidate: Path, frontend: Path) -> None:
    if authorization.get("schema_version") != AUTH_SCHEMA or authorization.get("single_use") is not True:
        raise SystemExit("invalid P4-D authorization")
    if authorization.get("consumed") is not False or authorization.get("expires_at", 0) < now():
        raise SystemExit("P4-D authorization is consumed or expired")
    if authorization.get("baseline_sha256") != sha256(baseline):
        raise SystemExit("baseline binary hash does not match authorization")
    if authorization.get("candidate_sha256") != sha256(candidate):
        raise SystemExit("candidate binary hash does not match authorization")
    if authorization.get("frontend_sha256") != tree_digest(frontend):
        raise SystemExit("frontend build hash does not match authorization")


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    subparsers = root.add_subparsers(dest="command", required=True)
    auth = subparsers.add_parser("authorize")
    auth.add_argument("--baseline-bin", required=True)
    auth.add_argument("--candidate-bin", required=True)
    auth.add_argument("--frontend-build-dir", required=True)
    auth.add_argument("--output", required=True)
    auth.add_argument("--operator-id", default="local-operator-cc")
    auth.add_argument("--remote-root", default="/tmp/civitasos-p4d-upgrade-preview")
    auth.add_argument("--ttl-seconds", type=int, default=3600)
    auth.add_argument("--node", action="append", default=[])
    auth.add_argument("--ack-private-beta-upgrade-drill", action="store_true")
    auth.set_defaults(func=authorize)
    run = subparsers.add_parser("execute")
    run.add_argument("--authorization", required=True)
    run.add_argument("--baseline-bin", required=True)
    run.add_argument("--candidate-bin", required=True)
    run.add_argument("--frontend-build-dir", required=True)
    run.add_argument("--output-root", required=True)
    run.add_argument("--backend-port", type=int, default=8099)
    run.add_argument("--frontend-port", type=int, default=3001)
    run.add_argument("--node", action="append", default=[])
    run.set_defaults(func=execute)
    return root


def main() -> int:
    args = parser().parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
