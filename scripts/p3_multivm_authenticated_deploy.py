#!/usr/bin/env python3
"""Deploy and verify a bounded three-VM signed-peer and mTLS cluster."""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import hashlib
import json
import os
import secrets
import ssl
import subprocess
import tempfile
import time
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from nacl.signing import SigningKey

ROOT = Path(__file__).resolve().parents[2]
BACKEND = ROOT / "civitasos-backend" / "target" / "debug" / "api_only"
REMOTE_ROOT = "/home/cal/civitasos_p3_auth_soak"
PORT = 18443
NODES = {"vm1": "192.168.56.4", "vm2": "192.168.56.5", "vm3": "192.168.56.6"}
PARTITION_COMMENT = "civitasos-p3-partition"


def run(command: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(command, check=True, text=True, capture_output=True, **kwargs)


def remote(node: str, script: str) -> None:
    run(["ssh", "-o", "BatchMode=yes", node, "bash", "-s"], input=script)


def cleanup() -> None:
    clear_kernel_partition()
    for node in NODES:
        try:
            remote(node, f'''set +e
ROOT={REMOTE_ROOT!r}
test -f "$ROOT/server.pid" && kill "$(cat "$ROOT/server.pid")" 2>/dev/null
sleep 0.2
rm -rf "$ROOT"
''')
        except Exception:
            pass


def clear_kernel_partition() -> None:
    vm3 = NODES["vm3"]
    for node in NODES:
        peers = (NODES["vm1"], NODES["vm2"]) if node == "vm3" else (vm3,)
        for peer in peers:
            for chain, direction in (("INPUT", "-s"), ("OUTPUT", "-d")):
                rule = (
                    f"-p tcp {direction} {peer} --dport {PORT} "
                    f"-m comment --comment {PARTITION_COMMENT} -j REJECT"
                )
                try:
                    remote(node, f"while sudo -n /usr/sbin/iptables -C {chain} {rule} 2>/dev/null; do sudo -n /usr/sbin/iptables -D {chain} {rule}; done")
                except Exception:
                    pass


def apply_kernel_partition() -> None:
    vm3 = NODES["vm3"]
    for node in NODES:
        peers = (NODES["vm1"], NODES["vm2"]) if node == "vm3" else (vm3,)
        for peer in peers:
            remote(node, f'''set -e
sudo -n /usr/sbin/iptables -I INPUT -p tcp -s {peer} --dport {PORT} -m comment --comment {PARTITION_COMMENT} -j REJECT
sudo -n /usr/sbin/iptables -I OUTPUT -p tcp -d {peer} --dport {PORT} -m comment --comment {PARTITION_COMMENT} -j REJECT
''')


def openssl(directory: Path, *args: str) -> None:
    subprocess.run(["openssl", *args], cwd=directory, check=True, capture_output=True)


def create_certificates(directory: Path) -> None:
    openssl(directory, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-subj", "/CN=CivitasOS P3 Cluster CA", "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-keyout", "ca.key", "-out", "ca.crt")
    for node, address in NODES.items():
        openssl(directory, "req", "-newkey", "rsa:2048", "-nodes", "-subj", f"/CN=p3-{node}",
                "-keyout", f"{node}.key", "-out", f"{node}.csr")
        (directory / f"{node}.ext").write_text(
            f"subjectAltName=DNS:{node},IP:{address}\nextendedKeyUsage=serverAuth,clientAuth\n"
        )
        openssl(directory, "x509", "-req", "-days", "1", "-in", f"{node}.csr",
                "-CA", "ca.crt", "-CAkey", "ca.key", "-CAcreateserial",
                "-extfile", f"{node}.ext", "-out", f"{node}.crt")
    openssl(directory, "req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=p3-controller",
            "-keyout", "controller.key", "-out", "controller.csr")
    (directory / "controller.ext").write_text("extendedKeyUsage=clientAuth\n")
    openssl(directory, "x509", "-req", "-days", "1", "-in", "controller.csr",
            "-CA", "ca.crt", "-CAkey", "ca.key", "-CAcreateserial",
            "-extfile", "controller.ext", "-out", "controller.crt")


def request(address: str, path: str, context: ssl.SSLContext, body: dict | None = None) -> tuple[int, dict]:
    payload = json.dumps(body, separators=(",", ":")).encode() if body is not None else None
    req = Request(f"https://{address}:{PORT}{path}", data=payload,
                  method="POST" if body is not None else "GET",
                  headers={"Content-Type": "application/json"})
    try:
        with urlopen(req, context=context, timeout=5) as response:
            raw = response.read()
            return response.status, json.loads(raw) if raw else {}
    except HTTPError as error:
        raw = error.read()
        return error.code, json.loads(raw) if raw else {}


def wait_receipt(address: str, task_id: str, count: int, context: ssl.SSLContext, timeout: float = 15) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        status, body = request(address, f"/api/v1/a2a/facts/tasks/{task_id}/receipt", context)
        receipt = body.get("data") or {}
        if status == 200 and receipt.get("fact_count") == count:
            return receipt
        time.sleep(0.2)
    raise RuntimeError(f"receipt {task_id} did not reach {count} facts on {address}")


def failed_task(address: str, context: ssl.SSLContext, suffix: str) -> str:
    agent_ids = []
    for role in ("requester", "worker"):
        public_key = SigningKey.generate().verify_key.encode().hex()
        status, agent = request(address, "/api/v1/a2a/quickstart", context, {
            "public_key": public_key, "alias": f"p3-{suffix}-{role}",
            "name": f"p3-{suffix}-{role}", "endpoint": "",
        })
        if status not in {200, 201}:
            raise RuntimeError(f"quickstart failed: {status} {agent}")
        agent_ids.append(str(agent["agent"]["did"]))
    requester_id, worker_id = agent_ids
    status, posted = request(address, "/api/v1/a2a/pool/post", context, {
        "requester": requester_id, "required_capability": "general", "input": {"brief": suffix},
        "deadline_secs": 60, "reward": 1, "min_reputation": 0.0, "required_stake": 0,
    })
    if status not in {200, 201}:
        raise RuntimeError(f"task post failed: {status} {posted}")
    task_id = str(posted["task_id"])
    status, claimed = request(address, "/api/v1/a2a/pool/claim", context, {
        "agent_id": worker_id, "task_id": task_id, "stake_amount": 0,
    })
    if status != 200:
        raise RuntimeError(f"task claim failed: {status} {claimed}")
    status, completed = request(address, "/api/v1/a2a/task/execute", context, {
        "agent_id": worker_id, "task_id": task_id, "output": {"result": "failed"}, "success": False,
    })
    if status != 200:
        raise RuntimeError(f"task completion failed: {status} {completed}")
    return task_id


def unknown_envelope() -> dict:
    key = SigningKey.generate()
    public_key = key.verify_key.encode()
    node_id = "unknown-peer"
    key_id = hashlib.sha256(public_key).digest()[:16].hex()
    nonce = secrets.token_hex(16)
    timestamp = int(time.time())
    payload = json.dumps(
        {"AgentRegistered": {"id": "unknown", "name": "unknown", "capabilities": [], "stake": 0}},
        separators=(",", ":"),
    ).encode()
    canonical = b"civitasos-peer-envelope:v1\0"
    for part in (node_id.encode(), key_id.encode(), nonce.encode(), payload):
        canonical += len(part).to_bytes(8, "big") + part
    canonical += timestamp.to_bytes(8, "big")
    return {
        "payload": list(payload),
        "signature": list(key.sign(canonical).signature),
        "signer_pubkey": public_key.hex(),
        "node_id": node_id,
        "key_id": key_id,
        "timestamp": timestamp,
        "nonce": nonce,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keep-running", action="store_true")
    parser.add_argument("--partition-heal", action="store_true")
    parser.add_argument("--kernel-partition", action="store_true")
    parser.add_argument("--partition-tasks", type=int, default=4)
    parser.add_argument("--output", type=Path, default=Path("/tmp/civitasos-p3-auth-deploy.json"))
    args = parser.parse_args()
    if args.partition_tasks < 1:
        parser.error("--partition-tasks must be positive")
    if args.kernel_partition:
        args.partition_heal = True
    if os.environ.get("CIVITASOS_P3_MULTIVM_EXECUTION_ACK") != "1":
        parser.error("set CIVITASOS_P3_MULTIVM_EXECUTION_ACK=1 to authorize vm1/vm2/vm3 deployment")
    if not BACKEND.is_file():
        raise FileNotFoundError(f"backend binary not found: {BACKEND}")

    cleanup()
    with tempfile.TemporaryDirectory(prefix="civitasos-p3-auth-") as temporary:
        artifacts = Path(temporary)
        create_certificates(artifacts)
        seeds = {node: SigningKey.generate() for node in NODES}
        trusted = {f"p3-{node}": [key.verify_key.encode().hex()] for node, key in seeds.items()}
        jwt_secret = secrets.token_urlsafe(32)
        cluster_token = secrets.token_urlsafe(32)
        try:
            for node in NODES:
                (artifacts / f"{node}.seed").write_text(seeds[node].encode().hex())
                remote(node, f"mkdir -p {REMOTE_ROOT!r} && chmod 700 {REMOTE_ROOT!r}")
                run(["scp", "-q", str(BACKEND), f"{node}:{REMOTE_ROOT}/api_only"])
                for filename in ("ca.crt", f"{node}.crt", f"{node}.key", f"{node}.seed"):
                    run(["scp", "-q", str(artifacts / filename), f"{node}:{REMOTE_ROOT}/{filename}"])
                remote(node, f"chmod 600 {REMOTE_ROOT!r}/*.key {REMOTE_ROOT!r}/*.seed")

            trusted_json = json.dumps(trusted, separators=(",", ":"))
            for node, address in NODES.items():
                peers = ",".join(
                    f"https://{peer_address}:{PORT}"
                    for peer, peer_address in NODES.items() if peer != node
                )
                start_script = f'''#!/bin/bash
set -euo pipefail
ROOT={REMOTE_ROOT!r}
nohup env \
  CIVITASOS_DATA_DIR="$ROOT/data" \
  CIVITASOS_STORAGE_DATA_DIR="$ROOT/storage" \
  CIVITASOS_NODE_ID="p3-{node}" \
  CIVITASOS_BOOT_NODES={peers!r} \
  CIVITASOS_NODE_SIGNING_SEED_FILE="$ROOT/{node}.seed" \
  CIVITASOS_PEER_AUTH_REQUIRED=true \
  CIVITASOS_TRUSTED_PEER_KEYS={trusted_json!r} \
  CIVITASOS_TLS_CERT="$ROOT/{node}.crt" \
  CIVITASOS_TLS_KEY="$ROOT/{node}.key" \
  CIVITASOS_MTLS_CA_CERT="$ROOT/ca.crt" \
  CIVITASOS_MTLS_CLIENT_CERT="$ROOT/{node}.crt" \
  CIVITASOS_MTLS_CLIENT_KEY="$ROOT/{node}.key" \
  CIVITASOS_JWT_SECRET={jwt_secret!r} \
  CIVITASOS_CLUSTER_SYNC_TOKEN={cluster_token!r} \
  CIVITASOS_JWT_ENFORCE=false \
  CIVITASOS_A2A_SEED_TASKS=false \
  CIVITASOS_EPOCH_AUTO_ENABLED=false \
  CIVITASOS_POOL_SWEEP_AUTO_ENABLED=false \
  "$ROOT/api_only" --api-port {PORT} >"$ROOT/server.log" 2>&1 &
echo $! >"$ROOT/server.pid"
'''
                encoded = base64.b64encode(start_script.encode()).decode()
                remote(node, f"echo {encoded!r} | base64 -d > {REMOTE_ROOT!r}/start.sh; chmod 700 {REMOTE_ROOT!r}/start.sh; {REMOTE_ROOT!r}/start.sh")

            context = ssl.create_default_context(cafile=str(artifacts / "ca.crt"))
            context.load_cert_chain(artifacts / "controller.crt", artifacts / "controller.key")
            health = {}
            for node, address in NODES.items():
                deadline = time.monotonic() + 20
                while time.monotonic() < deadline:
                    try:
                        status, _ = request(address, "/healthz", context)
                        if status == 200:
                            health[node] = status
                            break
                    except OSError:
                        time.sleep(0.2)
                else:
                    raise RuntimeError(f"{node} did not become mTLS healthy")

            anonymous = ssl.create_default_context(cafile=str(artifacts / "ca.crt"))
            anonymous_rejected = {}
            unknown_rejected = {}
            for node, address in NODES.items():
                try:
                    request(address, "/healthz", anonymous)
                    anonymous_rejected[node] = False
                except OSError:
                    anonymous_rejected[node] = True
                status, _ = request(address, "/api/v1/sync/events", context, unknown_envelope())
                unknown_rejected[node] = status == 401
            if not all(anonymous_rejected.values()) or not all(unknown_rejected.values()):
                raise RuntimeError("mTLS or unknown-peer rejection failed")

            partition_report = None
            if args.partition_heal:
                baseline_task = failed_task(NODES["vm1"], context, "baseline")
                baseline = {
                    node: wait_receipt(address, baseline_task, 3, context)
                    for node, address in NODES.items()
                }
                if len({item["receipt_hash"] for item in baseline.values()}) != 1:
                    raise RuntimeError("authenticated baseline receipt hashes diverged")

                vm3_url = f"https://{NODES['vm3']}:{PORT}"
                if args.kernel_partition:
                    apply_kernel_partition()
                else:
                    for node in ("vm1", "vm2"):
                        request(NODES[node], "/api/v1/cluster/leave", context, {"url": vm3_url})
                    for peer in ("vm1", "vm2"):
                        request(NODES["vm3"], "/api/v1/cluster/leave", context, {
                            "url": f"https://{NODES[peer]}:{PORT}"
                        })
                with concurrent.futures.ThreadPoolExecutor(max_workers=args.partition_tasks) as pool:
                    partition_tasks = list(pool.map(
                        lambda index: failed_task(NODES["vm1"], context, f"partition-{index}"),
                        range(args.partition_tasks),
                    ))
                majority_hashes = {}
                isolated_statuses = {}
                for partition_task in partition_tasks:
                    majority = {
                        node: wait_receipt(NODES[node], partition_task, 3, context)
                        for node in ("vm1", "vm2")
                    }
                    hashes = {item["receipt_hash"] for item in majority.values()}
                    if len(hashes) != 1:
                        raise RuntimeError(f"majority receipt diverged: {partition_task}")
                    majority_hashes[partition_task] = next(iter(hashes))
                    isolated_status, _ = request(
                        NODES["vm3"], f"/api/v1/a2a/facts/tasks/{partition_task}/receipt", context
                    )
                    isolated_statuses[partition_task] = isolated_status
                    if isolated_status != 404:
                        raise RuntimeError(f"isolated vm3 observed partition task: {isolated_status}")

                if args.kernel_partition:
                    clear_kernel_partition()
                else:
                    for node in ("vm1", "vm2"):
                        request(NODES[node], "/api/v1/cluster/join", context, {"url": vm3_url})
                    for peer in ("vm1", "vm2"):
                        request(NODES["vm3"], "/api/v1/cluster/join", context, {
                            "url": f"https://{NODES[peer]}:{PORT}"
                        })
                remote("vm3", f'''set -e
ROOT={REMOTE_ROOT!r}
kill "$(cat "$ROOT/server.pid")"
for _ in $(seq 1 50); do kill -0 "$(cat "$ROOT/server.pid")" 2>/dev/null || break; sleep 0.1; done
"$ROOT/start.sh"
''')
                deadline = time.monotonic() + 20
                while time.monotonic() < deadline:
                    try:
                        if request(NODES["vm3"], "/healthz", context)[0] == 200:
                            break
                    except OSError:
                        time.sleep(0.2)
                for partition_task in partition_tasks:
                    healed = wait_receipt(NODES["vm3"], partition_task, 3, context, 20)
                    if healed["receipt_hash"] != majority_hashes[partition_task]:
                        raise RuntimeError(f"healed receipt hash diverged: {partition_task}")
                integrity = {}
                for node, address in NODES.items():
                    status, body = request(address, "/api/v1/a2a/facts/integrity", context)
                    data = body.get("data") or {}
                    if status != 200 or data.get("valid") is not True:
                        raise RuntimeError(f"{node} Fact integrity failed: {body}")
                    integrity[node] = data.get("fact_count")
                partition_report = {
                    "mode": "kernel_tcp_partition" if args.kernel_partition else "application_peer_partition",
                    "baseline_converged": True,
                    "concurrent_task_count": len(partition_tasks),
                    "isolated_statuses": isolated_statuses,
                    "heal_converged": True,
                    "integrity_fact_counts": integrity,
                }

            report = {
                "schema_version": "p3-multivm-authenticated-deploy:v1",
                "passed": True,
                "nodes": list(NODES),
                "health": health,
                "anonymous_rejected": anonymous_rejected,
                "unknown_peer_rejected": unknown_rejected,
                "partition_heal": partition_report,
                "kept_running": args.keep_running,
                "production_claimed": False,
            }
            args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
            print(json.dumps(report, indent=2))
            return 0
        finally:
            if not args.keep_running:
                cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
