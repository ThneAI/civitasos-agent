#!/usr/bin/env python3
"""Run a bounded three-VM Fact convergence, restart, and catch-up soak."""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import secrets
import subprocess
import time
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[2]
BACKEND = ROOT / "civitasos-backend" / "target" / "debug" / "api_only"
REMOTE_ROOT = "/home/cal/civitasos_p2_fact_soak"
PORT = 18099
NODES = {
    "vm1": "192.168.56.4",
    "vm2": "192.168.56.5",
    "vm3": "192.168.56.6",
}


def run(command: list[str], *, input_text: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(command, input=input_text, text=True, check=True, capture_output=True)


def remote(host: str, script: str) -> None:
    run(["ssh", "-o", "BatchMode=yes", host, "bash", "-s"], input_text=script)


def request(node: str, path: str, body: dict | None = None) -> tuple[int, dict]:
    payload = json.dumps(body).encode() if body is not None else None
    req = Request(
        f"http://{NODES[node]}:{PORT}{path}",
        data=payload,
        method="POST" if body is not None else "GET",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urlopen(req, timeout=10) as response:
            return response.status, json.loads(response.read() or b"{}")
    except HTTPError as error:
        return error.code, json.loads(error.read() or b"{}")


def start_node(node: str, jwt_secret: str, cluster_token: str) -> None:
    peers = ",".join(
        f"http://{address}:{PORT}" for peer, address in NODES.items() if peer != node
    )
    remote(
        node,
        f"""
set -euo pipefail
ROOT={REMOTE_ROOT!r}
test -x "$ROOT/api_only"
if test -f "$ROOT/server.pid" && kill -0 "$(cat "$ROOT/server.pid")" 2>/dev/null; then
  exit 0
fi
nohup env \
  CIVITASOS_DATA_DIR="$ROOT/data" \
  CIVITASOS_STORAGE_DATA_DIR="$ROOT/storage" \
  CIVITASOS_NODE_ID="p2-{node}" \
  CIVITASOS_BOOT_NODES={peers!r} \
  CIVITASOS_CLUSTER_SYNC_TOKEN={cluster_token!r} \
  CIVITASOS_JWT_SECRET={jwt_secret!r} \
  CIVITASOS_JWT_ENFORCE=false \
  CIVITASOS_DEMO_LOGIN_ENABLED=false \
  CIVITASOS_INSTITUTIONAL_IDENTITY_ENABLED=false \
  CIVITASOS_A2A_SEED_TASKS=false \
  CIVITASOS_EPOCH_AUTO_ENABLED=false \
  CIVITASOS_POOL_SWEEP_AUTO_ENABLED=false \
  "$ROOT/api_only" --api-port {PORT} >"$ROOT/server.log" 2>&1 &
echo $! >"$ROOT/server.pid"
""",
    )


def stop_node(node: str) -> None:
    remote(
        node,
        f"""
ROOT={REMOTE_ROOT!r}
if test -f "$ROOT/server.pid"; then
  kill "$(cat "$ROOT/server.pid")" 2>/dev/null || true
  for _ in $(seq 1 50); do
    kill -0 "$(cat "$ROOT/server.pid")" 2>/dev/null || break
    sleep 0.1
  done
fi
""",
    )


def wait_healthy(node: str, timeout: float = 15) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if request(node, "/healthz")[0] == 200:
                return
        except OSError:
            pass
        time.sleep(0.2)
    raise RuntimeError(f"{node} did not become healthy")


def wait_receipt(node: str, task_id: str, count: int, timeout: float = 12) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            status, body = request(node, f"/api/v1/a2a/facts/tasks/{task_id}/receipt")
            receipt = body.get("data") or {}
            if status == 200 and receipt.get("fact_count") == count:
                return receipt
        except OSError:
            pass
        time.sleep(0.2)
    raise RuntimeError(f"{node} receipt {task_id} did not reach {count} facts")


def quickstart(node: str, alias: str) -> str:
    from nacl.signing import SigningKey

    key = SigningKey.generate()
    status, body = request(
        node,
        "/api/v1/a2a/quickstart",
        {
            "public_key": key.verify_key.encode().hex(),
            "alias": alias,
            "name": alias,
            "endpoint": "",
        },
    )
    if status not in {200, 201}:
        raise RuntimeError(f"quickstart failed: {status} {body}")
    return str(body["agent"]["did"])


def post_task(requester: str, brief: str) -> str:
    status, body = request(
        "vm1",
        "/api/v1/a2a/pool/post",
        {
            "requester": requester,
            "required_capability": "general",
            "input": {"brief": brief},
            "deadline_secs": 60,
            "reward": 1,
            "min_reputation": 0.0,
            "required_stake": 0,
        },
    )
    if status not in {200, 201}:
        raise RuntimeError(f"post failed: {status} {body}")
    return str(body["task_id"])


def fail_task(requester: str, worker: str, brief: str) -> str:
    task_id = post_task(requester, brief)
    status, body = request(
        "vm1",
        "/api/v1/a2a/pool/claim",
        {"agent_id": worker, "task_id": task_id, "stake_amount": 0},
    )
    if status != 200:
        raise RuntimeError(f"claim failed: {status} {body}")
    status, body = request(
        "vm1",
        "/api/v1/a2a/task/execute",
        {
            "agent_id": worker,
            "task_id": task_id,
            "output": {"result": "failed"},
            "success": False,
        },
    )
    if status != 200:
        raise RuntimeError(f"failed delivery failed: {status} {body}")
    return task_id


def cleanup() -> None:
    for node in NODES:
        try:
            remote(
                node,
                f"""
ROOT={REMOTE_ROOT!r}
if test -f "$ROOT/server.pid"; then kill "$(cat "$ROOT/server.pid")" 2>/dev/null || true; fi
sleep 0.2
rm -rf "$ROOT"
""",
            )
        except Exception:
            pass


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--concurrent-tasks", type=int, default=12)
    parser.add_argument("--output", type=Path, default=Path("/tmp/civitasos-p2-multivm-soak.json"))
    args = parser.parse_args()
    if args.concurrent_tasks < 1:
        parser.error("--concurrent-tasks must be positive")
    if not BACKEND.is_file():
        raise FileNotFoundError(f"backend binary not found: {BACKEND}")

    started = time.monotonic()
    jwt_secret = secrets.token_urlsafe(32)
    cluster_token = secrets.token_urlsafe(32)
    cleanup()
    try:
        for node in NODES:
            remote(node, f"mkdir -p {REMOTE_ROOT!r}")
            run(["scp", "-q", str(BACKEND), f"{node}:{REMOTE_ROOT}/api_only"])
        for node in ("vm2", "vm3", "vm1"):
            start_node(node, jwt_secret, cluster_token)
            wait_healthy(node)

        requester = quickstart("vm1", "p2-vm-requester")
        worker = quickstart("vm1", "p2-vm-worker")
        baseline_task = fail_task(requester, worker, "three-node convergence")
        baseline = [wait_receipt(node, baseline_task, 3) for node in NODES]
        if len({receipt["receipt_hash"] for receipt in baseline}) != 1:
            raise RuntimeError("baseline receipt hashes diverged")

        stop_node("vm2")
        start_node("vm2", jwt_secret, cluster_token)
        wait_healthy("vm2")
        restarted = wait_receipt("vm2", baseline_task, 3)
        if restarted["receipt_hash"] != baseline[0]["receipt_hash"]:
            raise RuntimeError("vm2 restart changed receipt hash")

        stop_node("vm3")
        catchup_worker = quickstart("vm1", "p2-vm-catchup-worker")
        catchup_task = fail_task(requester, catchup_worker, "offline peer catchup")
        wait_receipt("vm1", catchup_task, 3)
        wait_receipt("vm2", catchup_task, 3)
        start_node("vm3", jwt_secret, cluster_token)
        wait_healthy("vm3")
        catchup = wait_receipt("vm3", catchup_task, 3)
        if catchup["receipt_hash"] != wait_receipt("vm1", catchup_task, 3)["receipt_hash"]:
            raise RuntimeError("vm3 anti-entropy receipt hash diverged")

        with concurrent.futures.ThreadPoolExecutor(max_workers=min(16, args.concurrent_tasks)) as pool:
            concurrent_ids = list(
                pool.map(
                    lambda index: post_task(requester, f"concurrent-{index}"),
                    range(args.concurrent_tasks),
                )
            )
        for task_id in concurrent_ids:
            hashes = {wait_receipt(node, task_id, 1)["receipt_hash"] for node in NODES}
            if len(hashes) != 1:
                raise RuntimeError(f"concurrent task receipt diverged: {task_id}")

        integrity = {}
        for node in NODES:
            status, body = request(node, "/api/v1/a2a/facts/integrity")
            data = body.get("data") or {}
            if status != 200 or data.get("valid") is not True or data.get("pending_outbox_count") != 0:
                raise RuntimeError(f"{node} integrity failed: {body}")
            integrity[node] = data.get("fact_count")

        report = {
            "schema_version": "civitasos-p2-multivm-fact-soak:v1",
            "passed": True,
            "nodes": list(NODES),
            "baseline_converged": True,
            "stateful_restart_recovered": True,
            "offline_peer_catchup_converged": True,
            "concurrent_task_count": len(concurrent_ids),
            "fact_counts": integrity,
            "duration_seconds": round(time.monotonic() - started, 3),
            "public_ingress_authorized": False,
            "production_runtime_authorized": False,
            "production_evidence_claimed": False,
        }
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    finally:
        cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
