#!/usr/bin/env python3
"""Deploy and verify a bounded three-VM signed-peer and mTLS cluster."""

from __future__ import annotations

import argparse
import base64
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


def run(command: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(command, check=True, text=True, capture_output=True, **kwargs)


def remote(node: str, script: str) -> None:
    run(["ssh", "-o", "BatchMode=yes", node, "bash", "-s"], input=script)


def cleanup() -> None:
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
    parser.add_argument("--output", type=Path, default=Path("/tmp/civitasos-p3-auth-deploy.json"))
    args = parser.parse_args()
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
                remote(node, f'''set -euo pipefail
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
  CIVITASOS_JWT_ENFORCE=false \
  CIVITASOS_A2A_SEED_TASKS=false \
  CIVITASOS_EPOCH_AUTO_ENABLED=false \
  CIVITASOS_POOL_SWEEP_AUTO_ENABLED=false \
  "$ROOT/api_only" --api-port {PORT} >"$ROOT/server.log" 2>&1 &
echo $! >"$ROOT/server.pid"
''')

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

            report = {
                "schema_version": "p3-multivm-authenticated-deploy:v1",
                "passed": True,
                "nodes": list(NODES),
                "health": health,
                "anonymous_rejected": anonymous_rejected,
                "unknown_peer_rejected": unknown_rejected,
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
