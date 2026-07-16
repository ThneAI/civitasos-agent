#!/usr/bin/env python3
"""Authorize and execute a hash-bound three-VM production-config TLS drill."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import ssl
import subprocess
import sys
import tarfile
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from nacl.signing import SigningKey

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from beta5_real_multivm_preview_prepare import PreviewNode, parse_node

MATERIAL_SCHEMA = "civitasos-p4ef-tls-material-manifest:v1"
AUTH_SCHEMA = "civitasos-p4ef-multivm-tls-authorization:v1"
RECEIPT_SCHEMA = "civitasos-p4ef-operational-change-receipt:v1"
SUMMARY_SCHEMA = "civitasos-p4ef-multivm-tls-summary:v1"
DEFAULT_NODES = (
    "vm1,vm1,192.168.56.4",
    "vm2,vm2,192.168.56.5",
    "vm3,vm3,192.168.56.6",
)
PROXY_SOURCE = r'''#!/usr/bin/env python3
import argparse, http.client, http.server, ssl
from functools import partial

parser = argparse.ArgumentParser()
parser.add_argument("--listen-port", type=int, required=True)
parser.add_argument("--backend-port", type=int, required=True)
parser.add_argument("--site", required=True)
parser.add_argument("--cert", required=True)
parser.add_argument("--key", required=True)
args = parser.parse_args()

class Handler(http.server.SimpleHTTPRequestHandler):
    def _proxy(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length) if length else None
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        connection = http.client.HTTPSConnection("127.0.0.1", args.backend_port, context=context, timeout=15)
        headers = {key: value for key, value in self.headers.items() if key.lower() not in {"host", "connection"}}
        connection.request(self.command, self.path, body=body, headers=headers)
        upstream = connection.getresponse()
        payload = upstream.read()
        self.send_response(upstream.status)
        for key, value in upstream.getheaders():
            if key.lower() not in {"connection", "transfer-encoding", "content-length"}:
                self.send_header(key, value)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)
        connection.close()

    def do_GET(self):
        if self.path.startswith("/api/") or self.path in {"/healthz", "/metrics"}:
            self._proxy()
        else:
            super().do_GET()

    def do_POST(self): self._proxy()
    def do_PUT(self): self._proxy()
    def do_DELETE(self): self._proxy()

server = http.server.ThreadingHTTPServer(("0.0.0.0", args.listen_port), partial(Handler, directory=args.site))
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(args.cert, args.key)
server.socket = context.wrap_socket(server.socket, server_side=True)
server.serve_forever()
'''


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        digest.update(str(path.relative_to(root)).encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def now() -> int:
    return int(time.time())


def write_json(path: Path, payload: Any, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    os.chmod(temporary, mode)
    os.replace(temporary, path)


def run(command: list[str], *, input_text: str | None = None, timeout: int = 300) -> subprocess.CompletedProcess:
    return subprocess.run(
        command,
        input=input_text,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        check=False,
    )


def require_success(command: list[str], *, input_text: str | None = None, timeout: int = 300) -> str:
    completed = run(command, input_text=input_text, timeout=timeout)
    if completed.returncode != 0:
        raise RuntimeError(
            f"command failed ({completed.returncode}): {command}\n{completed.stdout[-3000:]}"
        )
    return completed.stdout


def prepare_materials(args: argparse.Namespace) -> int:
    output = Path(args.output_dir).resolve()
    if output.exists():
        raise SystemExit(f"refusing to overwrite TLS material directory: {output}")
    output.mkdir(parents=True, mode=0o700)
    os.chmod(output, 0o700)
    nodes = [parse_node(raw) for raw in (args.node or DEFAULT_NODES)]
    valid_days = getattr(args, "valid_days", 2)
    if valid_days < 1:
        raise SystemExit("TLS material validity must be at least one day")
    ca_key = output / "ca.key"
    ca_cert = output / "ca.crt"
    require_success(["openssl", "genrsa", "-out", str(ca_key), "2048"])
    require_success([
        "openssl", "req", "-x509", "-new", "-key", str(ca_key), "-days", str(valid_days),
        "-subj", "/CN=CivitasOS P4-EF Test CA",
        "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign",
        "-addext", "subjectKeyIdentifier=hash",
        "-out", str(ca_cert),
    ])
    os.chmod(ca_key, 0o600)
    for node in nodes:
        hostname = f"{node.node_id}.civitas.internal"
        key = output / f"{node.node_id}.key"
        csr = output / f"{node.node_id}.csr"
        cert = output / f"{node.node_id}.crt"
        ext = output / f"{node.node_id}.ext"
        require_success(["openssl", "genrsa", "-out", str(key), "2048"])
        require_success([
            "openssl", "req", "-new", "-key", str(key), "-subj", f"/CN={hostname}",
            "-out", str(csr),
        ])
        ext.write_text(
            f"subjectAltName=DNS:{hostname},IP:{node.node_ip}\n"
            "basicConstraints=critical,CA:FALSE\n"
            "keyUsage=critical,digitalSignature,keyEncipherment\n"
            "extendedKeyUsage=serverAuth\n"
        )
        require_success([
            "openssl", "x509", "-req", "-in", str(csr), "-CA", str(ca_cert),
            "-CAkey", str(ca_key), "-CAcreateserial", "-days", str(valid_days),
            "-extfile", str(ext), "-out", str(cert),
        ])
        csr.unlink()
        ext.unlink()
        os.chmod(key, 0o600)
        for kind in ("jwt", "service"):
            secret_path = output / f"{node.node_id}.{kind}"
            secret_path.write_text(secrets.token_urlsafe(48) + "\n")
            os.chmod(secret_path, 0o600)
    serial = output / "ca.srl"
    if serial.exists():
        serial.unlink()
    files = sorted(path for path in output.iterdir() if path.is_file())
    manifest = {
        "schema_version": MATERIAL_SCHEMA,
        "created_at": now(),
        "valid_days": valid_days,
        "nodes": [
            {
                "node_id": node.node_id,
                "ip": node.node_ip,
                "hostname": f"{node.node_id}.civitas.internal",
            }
            for node in nodes
        ],
        "files": {
            path.name: {
                "sha256": sha256(path),
                "mode": oct(path.stat().st_mode & 0o777),
            }
            for path in files
        },
        "test_only": True,
        "public_ingress_allowed": False,
        "production_data_allowed": False,
        "secret_values_recorded": False,
    }
    write_json(output / "manifest.json", manifest)
    print(json.dumps({**manifest, "material_directory": str(output)}, indent=2, sort_keys=True))
    return 0


def validate_materials(root: Path) -> dict[str, Any]:
    manifest_path = root / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    if manifest.get("schema_version") != MATERIAL_SCHEMA:
        raise SystemExit("invalid P4-EF material manifest")
    for name, metadata in manifest.get("files", {}).items():
        path = root / name
        if not path.is_file() or sha256(path) != metadata.get("sha256"):
            raise SystemExit(f"P4-EF material hash mismatch: {name}")
    return manifest


def authorize(args: argparse.Namespace) -> int:
    if not args.ack_private_beta_tls_drill:
        raise SystemExit("explicit --ack-private-beta-tls-drill is required")
    baseline = Path(args.baseline_bin).resolve()
    candidate = Path(args.candidate_bin).resolve()
    frontend = Path(args.frontend_build_dir).resolve()
    materials = Path(args.materials_dir).resolve()
    for binary in (baseline, candidate):
        if not binary.is_file():
            raise SystemExit(f"binary not found: {binary}")
    if not (frontend / "index.html").is_file():
        raise SystemExit("frontend build must contain index.html")
    manifest = validate_materials(materials)
    nodes = [parse_node(raw) for raw in (args.node or DEFAULT_NODES)]
    if sorted(node.node_id for node in nodes) != ["vm1", "vm2", "vm3"]:
        raise SystemExit("authorization must target exactly vm1, vm2, vm3")
    issued_at = now()
    hashes = [
        sha256(baseline),
        sha256(candidate),
        tree_digest(frontend),
        sha256(materials / "manifest.json"),
    ]
    material = ":".join([*hashes, str(issued_at), args.operator_id])
    payload = {
        "schema_version": AUTH_SCHEMA,
        "authorization_id": f"p4ef-tls:{hashlib.sha256(material.encode()).hexdigest()[:24]}",
        "issued_at": issued_at,
        "expires_at": issued_at + args.ttl_seconds,
        "single_use": True,
        "consumed": False,
        "operator_id": args.operator_id,
        "nodes": [node.node_id for node in nodes],
        "baseline_sha256": hashes[0],
        "candidate_sha256": hashes[1],
        "frontend_sha256": hashes[2],
        "material_manifest_sha256": hashes[3],
        "material_file_sha256": {
            name: data["sha256"] for name, data in manifest["files"].items()
        },
        "remote_root": args.remote_root,
        "backend_port": args.backend_port,
        "frontend_port": args.frontend_port,
        "operations": [
            "deploy", "upgrade", "tls_browser_identity",
            "task_receipt", "rollback", "cleanup",
        ],
        "public_ingress_allowed": False,
        "production_data_allowed": False,
        "production_evidence_allowed": False,
    }
    output = Path(args.output).resolve()
    if output.exists():
        raise SystemExit(f"refusing to overwrite authorization: {output}")
    write_json(output, payload)
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def validate_authorization(auth: dict[str, Any], args: argparse.Namespace) -> None:
    baseline = Path(args.baseline_bin).resolve()
    candidate = Path(args.candidate_bin).resolve()
    frontend = Path(args.frontend_build_dir).resolve()
    materials = Path(args.materials_dir).resolve()
    manifest = validate_materials(materials)
    checks = {
        "schema": auth.get("schema_version") == AUTH_SCHEMA,
        "single_use": auth.get("single_use") is True and auth.get("consumed") is False,
        "fresh": auth.get("expires_at", 0) >= now(),
        "baseline": auth.get("baseline_sha256") == sha256(baseline),
        "candidate": auth.get("candidate_sha256") == sha256(candidate),
        "frontend": auth.get("frontend_sha256") == tree_digest(frontend),
        "materials": (
            auth.get("material_manifest_sha256")
            == sha256(materials / "manifest.json")
        ),
        "material_files": auth.get("material_file_sha256")
        == {name: data["sha256"] for name, data in manifest["files"].items()},
        "remote_root": auth.get("remote_root") == args.remote_root,
        "backend_port": auth.get("backend_port") == args.backend_port,
        "frontend_port": auth.get("frontend_port") == args.frontend_port,
    }
    failed = [name for name, passed in checks.items() if not passed]
    if failed:
        raise SystemExit(f"P4-EF authorization validation failed: {failed}")


def make_frontend_archive(frontend: Path, output: Path) -> None:
    with tarfile.open(output, "w:gz") as archive:
        archive.add(frontend, arcname="build")


def remote_stop(
    node: PreviewNode,
    remote_root: str,
    backend_port: int,
    frontend_port: int,
    *,
    remove: bool,
) -> str:
    removal = 'rm -rf "$ROOT"' if remove else "true"
    script = f'''set -euo pipefail
ROOT={remote_root!r}
if test -f "$ROOT/backend.pid"; then kill "$(cat "$ROOT/backend.pid")" 2>/dev/null || true; fi
if test -f "$ROOT/frontend.pid"; then kill "$(cat "$ROOT/frontend.pid")" 2>/dev/null || true; fi
pkill -f "api_only --api-port {backend_port}" 2>/dev/null || true
pkill -f "tls_proxy.py --listen-port {frontend_port}" 2>/dev/null || true
{removal}
'''
    return require_success(["ssh", node.ssh_host, "bash -s"], input_text=script)


def deploy_node(
    node: PreviewNode,
    binary: Path,
    archive: Path,
    proxy: Path,
    materials: Path,
    remote_root: str,
    backend_port: int,
    frontend_port: int,
    *,
    preserve_state: bool,
) -> str:
    remote_stop(
        node, remote_root, backend_port, frontend_port, remove=not preserve_state
    )
    require_success(["ssh", node.ssh_host, "mkdir", "-p", remote_root])
    copies = [
        (binary, "api_only"),
        (archive, "frontend.tgz"),
        (proxy, "tls_proxy.py"),
        (materials / "ca.crt", "ca.crt"),
        (materials / f"{node.node_id}.crt", "node.crt"),
        (materials / f"{node.node_id}.key", "node.key"),
        (materials / f"{node.node_id}.jwt", "jwt.secret"),
        (materials / f"{node.node_id}.service", "service.secret"),
    ]
    for source, name in copies:
        require_success(
            ["scp", str(source), f"{node.ssh_host}:{remote_root}/{name}"],
            timeout=120,
        )
    hostname = f"{node.node_id}.civitas.internal"
    origin = f"https://{hostname}:{frontend_port}"
    script = f'''set -euo pipefail
ROOT={remote_root!r}
mkdir -p "$ROOT/site" "$ROOT/data" "$ROOT/storage" "$ROOT/logs"
rm -rf "$ROOT/site"/*
tar -xzf "$ROOT/frontend.tgz" -C "$ROOT/site" --strip-components=1
chmod 700 "$ROOT"
chmod 600 "$ROOT/node.key" "$ROOT/jwt.secret" "$ROOT/service.secret"
chmod +x "$ROOT/api_only" "$ROOT/tls_proxy.py"
(
  cd "$ROOT"
  CIVITASOS_AUTH_MODE=production \
  CIVITASOS_WEBAUTHN_RP_ID={hostname!r} \
  CIVITASOS_WEBAUTHN_ORIGIN={origin!r} \
  CIVITASOS_TLS_CERT="$ROOT/node.crt" \
  CIVITASOS_TLS_KEY="$ROOT/node.key" \
  CIVITASOS_JWT_SECRET="$(cat "$ROOT/jwt.secret")" \
  CIVITASOS_CORS_ORIGINS={origin!r} \
  CIVITASOS_TRUST_PROXY_HEADERS=false \
  CIVITASOS_JWT_ENFORCE=true \
  CIVITASOS_DEMO_LOGIN_ENABLED=false \
  CIVITASOS_DEMO_AUTO_REGISTER=false \
  CIVITASOS_INSTITUTIONAL_IDENTITY_ENABLED=false \
  CIVITASOS_SERVICE_TOKEN_SECRET="$(cat "$ROOT/service.secret")" \
  CIVITASOS_SERVICE_TOKEN_SCOPES='agents:write,pool:post,pool:read,pool:claim,pool:write,evidence:read,evidence:write,metrics:read' \
  CIVITASOS_DATA_DIR="$ROOT/data" \
  CIVITASOS_STORAGE_DATA_DIR="$ROOT/storage" \
  CIVITASOS_NODE_ID='p4ef-{node.node_id}' \
  CIVITASOS_A2A_SEED_TASKS=false \
  CIVITASOS_POOL_SWEEP_AUTO_ENABLED=true \
  CIVITASOS_POOL_SWEEP_INTERVAL_SECS=1 \
  CIVITASOS_TASK_CHALLENGE_WINDOW_ENABLED=true \
  CIVITASOS_TASK_CHALLENGE_WINDOW_SECS=1 \
  CIVITASOS_POOL_SWEEP_SETTLE_CHALLENGE_ENABLED=true \
  nohup ./api_only --api-port {backend_port} >"$ROOT/logs/backend.log" 2>&1 & echo $! >"$ROOT/backend.pid"
)
nohup python3 "$ROOT/tls_proxy.py" --listen-port {frontend_port} --backend-port {backend_port} --site "$ROOT/site" --cert "$ROOT/node.crt" --key "$ROOT/node.key" >"$ROOT/logs/frontend.log" 2>&1 & echo $! >"$ROOT/frontend.pid"
for attempt in $(seq 1 100); do
  if curl -kfsS "https://127.0.0.1:{backend_port}/healthz" >/dev/null && curl -kfsS "https://127.0.0.1:{frontend_port}/" >/dev/null; then exit 0; fi
  if ! kill -0 "$(cat "$ROOT/backend.pid")" 2>/dev/null; then tail -100 "$ROOT/logs/backend.log"; exit 1; fi
  sleep 0.2
done
tail -100 "$ROOT/logs/backend.log"
tail -100 "$ROOT/logs/frontend.log"
exit 1
'''
    return require_success(
        ["ssh", node.ssh_host, "bash -s"], input_text=script, timeout=180
    )


def tls_smoke(
    nodes: list[PreviewNode],
    materials: Path,
    backend_port: int,
    frontend_port: int,
) -> list[dict[str, Any]]:
    observations = []
    for node in nodes:
        hostname = f"{node.node_id}.civitas.internal"
        common = [
            "curl", "-fsS", "--noproxy", "*", "--max-time", "5",
            "--cacert", str(materials / "ca.crt"),
        ]
        require_success([
            *common,
            "--resolve", f"{hostname}:{backend_port}:{node.node_ip}",
            f"https://{hostname}:{backend_port}/healthz",
        ])
        html = require_success([
            *common,
            "--resolve", f"{hostname}:{frontend_port}:{node.node_ip}",
            f"https://{hostname}:{frontend_port}/",
        ])
        if '<div id="root"' not in html and "<!doctype html" not in html.lower():
            raise RuntimeError(f"{node.node_id} frontend build was not served")
        plaintext = run([
            "curl", "-fsS", "--noproxy", "*", "--max-time", "2",
            f"http://{node.node_ip}:{backend_port}/healthz",
        ])
        if plaintext.returncode == 0:
            raise RuntimeError(
                f"{node.node_id} accepted plaintext HTTP on the TLS backend port"
            )
        observations.append({
            "node_id": node.node_id,
            "hostname": hostname,
            "backend_tls_verified": True,
            "frontend_tls_verified": True,
            "plaintext_backend_rejected": True,
            "passed": True,
        })
    return observations


def phase(
    name: str,
    binary: Path,
    previous_sha: str | None,
    nodes: list[PreviewNode],
    archive: Path,
    proxy: Path,
    materials: Path,
    args: argparse.Namespace,
    output_root: Path,
) -> dict[str, Any]:
    started = time.monotonic()
    logs = []
    observations = []
    error = None
    try:
        for node in nodes:
            logs.append(
                deploy_node(
                    node,
                    binary,
                    archive,
                    proxy,
                    materials,
                    args.remote_root,
                    args.backend_port,
                    args.frontend_port,
                    preserve_state=name != "deploy",
                )
            )
        observations = tls_smoke(
            nodes, materials, args.backend_port, args.frontend_port
        )
    except Exception as exception:  # noqa: BLE001
        error = str(exception)
    log_path = output_root / f"{name}.log"
    log_path.write_text(
        "\n".join(logs) + (f"\nERROR: {error}\n" if error else "")
    )
    receipt = {
        "schema_version": RECEIPT_SCHEMA,
        "operation": name,
        "passed": error is None and len(observations) == 3,
        "release_sha256": sha256(binary),
        "previous_release_sha256": previous_sha,
        "duration_seconds": round(time.monotonic() - started, 3),
        "log_sha256": sha256(log_path),
        "nodes": observations,
        "total_checks": len(observations) * 3,
        "error": error,
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "production_operation": False,
    }
    write_json(output_root / f"{name}-receipt.json", receipt)
    return receipt


def api_request(
    node: PreviewNode,
    frontend_port: int,
    path: str,
    payload: dict[str, Any] | None = None,
    token: str | None = None,
) -> tuple[int, dict[str, Any]]:
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(
        f"https://{node.node_ip}:{frontend_port}{path}",
        data=json.dumps(payload).encode() if payload is not None else None,
        headers=headers,
        method="POST" if payload is not None else "GET",
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(
            request, context=context, timeout=10
        ) as response:
            return response.status, json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read() or b"{}")


def api_text_request(
    node: PreviewNode,
    frontend_port: int,
    path: str,
    token: str,
    ca_cert: Path,
) -> tuple[int, str]:
    request = urllib.request.Request(
        f"https://{node.node_ip}:{frontend_port}{path}",
        headers={"Authorization": f"Bearer {token}"},
    )
    context = ssl.create_default_context(cafile=str(ca_cert.resolve()))
    try:
        with urllib.request.urlopen(
            request, context=context, timeout=10
        ) as response:
            return response.status, response.read().decode("utf-8")
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode("utf-8", errors="replace")


def identity_token(
    node: PreviewNode,
    frontend_port: int,
    service_token: str,
    alias: str,
) -> tuple[str, str]:
    signing_key = SigningKey.generate()
    status, quickstart = api_request(
        node,
        frontend_port,
        "/api/v1/a2a/quickstart",
        {
            "public_key": signing_key.verify_key.encode().hex(),
            "alias": alias,
            "name": alias,
            "endpoint": "",
        },
        service_token,
    )
    agent_id = (
        quickstart.get("agent", {}).get("did")
        or quickstart.get("data", {}).get("agent", {}).get("did")
    )
    if status not in (200, 201) or not agent_id:
        raise RuntimeError(
            f"{node.node_id} quickstart failed: {status} {quickstart}"
        )
    status, challenge = api_request(
        node,
        frontend_port,
        "/api/v1/auth/challenge",
        {"agent_id": agent_id},
    )
    data = challenge.get("data", {})
    if status != 200:
        raise RuntimeError(f"{node.node_id} auth challenge failed")
    signature = signing_key.sign(bytes.fromhex(data["message"])).signature.hex()
    status, token = api_request(
        node,
        frontend_port,
        "/api/v1/auth/token",
        {
            "agent_id": agent_id,
            "message": data["message"],
            "signature": signature,
            "challenge_id": data["challenge_id"],
        },
    )
    jwt = token.get("data", {}).get("token")
    if status != 200 or not jwt:
        raise RuntimeError(f"{node.node_id} DID token failed: {status} {token}")
    return agent_id, jwt


def candidate_task_smoke(
    nodes: list[PreviewNode],
    materials: Path,
    frontend_port: int,
    output: Path,
) -> dict[str, Any]:
    observations = []
    for node in nodes:
        service_secret = (
            materials / f"{node.node_id}.service"
        ).read_text().strip()
        status, service = api_request(
            node,
            frontend_port,
            "/api/v1/auth/service-token",
            {
                "service_id": f"p4ef-task-{node.node_id}",
                "secret": service_secret,
                "scopes": [
                    "agents:write", "pool:post", "pool:read",
                    "pool:claim", "pool:write", "metrics:read",
                ],
            },
        )
        service_token = service.get("data", {}).get("token")
        if status != 200 or not service_token:
            raise RuntimeError(f"{node.node_id} service token failed")
        suffix = uuid.uuid4().hex[:10]
        requester_id, requester_token = identity_token(
            node, frontend_port, service_token, f"p4ef-requester-{suffix}"
        )
        worker_id, worker_token = identity_token(
            node, frontend_port, service_token, f"p4ef-worker-{suffix}"
        )
        status, posted = api_request(
            node,
            frontend_port,
            "/api/v1/a2a/pool/post",
            {
                "requester": requester_id,
                "required_capability": "general",
                "input": {"p4ef_tls_drill": True},
                "reward": 1,
                "min_reputation": 0,
            },
            requester_token,
        )
        if status not in (200, 201):
            raise RuntimeError(f"{node.node_id} task post failed: {posted}")
        task_id = posted["task_id"]
        auto_claimed = posted.get("auto_claimed_by")
        if not auto_claimed:
            status, body = api_request(
                node,
                frontend_port,
                "/api/v1/a2a/pool/claim",
                {"task_id": task_id, "agent_id": worker_id},
                worker_token,
            )
            if status != 200:
                raise RuntimeError(f"{node.node_id} task claim failed: {body}")
        else:
            worker_id = str(auto_claimed)
        status, body = api_request(
            node,
            frontend_port,
            "/api/v1/a2a/task/execute",
            {
                "agent_id": worker_id,
                "task_id": task_id,
                "output": {"result": "P4-EF TLS candidate delivery"},
                "success": True,
                "metadata": {"drill": "p4ef-multivm-tls"},
            },
            worker_token,
        )
        if status != 200:
            raise RuntimeError(f"{node.node_id} task delivery failed: {body}")
        time.sleep(2)
        status, receipt_response = api_request(
            node,
            frontend_port,
            f"/api/v1/a2a/facts/tasks/{task_id}/receipt",
            token=requester_token,
        )
        receipt = receipt_response.get("data", {})
        if (
            status != 200
            or not receipt.get("complete")
            or not receipt.get("lifecycle", {}).get("settled")
        ):
            raise RuntimeError(
                f"{node.node_id} task receipt incomplete: {receipt_response}"
            )
        metrics_status, metrics = api_text_request(
            node,
            frontend_port,
            "/metrics",
            service_token,
            materials / "ca.crt",
        )
        if (
            metrics_status != 200
            or "civitasos_evidence_export_pending" not in metrics
        ):
            raise RuntimeError(
                f"{node.node_id} Evidence metrics were not exposed"
            )
        observations.append({
            "node_id": node.node_id,
            "task_id": task_id,
            "fact_count": receipt.get("fact_count"),
            "receipt_hash": receipt.get("receipt_hash"),
            "settled": True,
            "evidence_metrics_exposed": True,
        })
    report = {
        "schema_version": "civitasos-p4ef-multivm-task-receipt:v1",
        "passed": (
            len(observations) == 3
            and all(item["fact_count"] == 5 for item in observations)
        ),
        "node_count": len(observations),
        "observations": observations,
        "demo_auth_used": False,
        "production_evidence_claimed": False,
    }
    write_json(output, report)
    if not report["passed"]:
        raise RuntimeError(f"P4-EF task receipt report failed: {report}")
    return report


def execute(args: argparse.Namespace) -> int:
    auth_path = Path(args.authorization).resolve()
    auth = json.loads(auth_path.read_text())
    validate_authorization(auth, args)
    output_root = Path(args.output_root).resolve()
    summary_path = output_root / "p4ef-multivm-tls-summary.json"
    if summary_path.exists():
        raise SystemExit(
            "single-use authorization already has an execution summary"
        )
    output_root.mkdir(parents=True, exist_ok=True)
    nodes = [parse_node(raw) for raw in (args.node or DEFAULT_NODES)]
    baseline = Path(args.baseline_bin).resolve()
    candidate = Path(args.candidate_bin).resolve()
    frontend = Path(args.frontend_build_dir).resolve()
    materials = Path(args.materials_dir).resolve()
    archive = output_root / "frontend.tgz"
    proxy = output_root / "tls_proxy.py"
    make_frontend_archive(frontend, archive)
    proxy.write_text(PROXY_SOURCE)
    os.chmod(proxy, 0o700)
    receipts = []
    failures = []
    task_report = None
    browser_report = None
    cleanup = {"passed": False, "nodes": []}
    try:
        deploy = phase(
            "deploy", baseline, None, nodes, archive, proxy,
            materials, args, output_root,
        )
        receipts.append(deploy)
        if not deploy["passed"]:
            failures.append("baseline_deploy_failed")
        if not failures:
            upgrade = phase(
                "upgrade", candidate, sha256(baseline), nodes, archive,
                proxy, materials, args, output_root,
            )
            receipts.append(upgrade)
            if not upgrade["passed"]:
                failures.append("candidate_upgrade_failed")
        if not failures:
            try:
                task_report = candidate_task_smoke(
                    nodes,
                    materials,
                    args.frontend_port,
                    output_root / "candidate-task-receipt.json",
                )
                targets_path = output_root / "browser-targets.json"
                write_json(targets_path, [
                    {
                        "node_id": node.node_id,
                        "ip": node.node_ip,
                        "hostname": f"{node.node_id}.civitas.internal",
                        "frontend_port": args.frontend_port,
                        "service_secret_file": str(
                            materials / f"{node.node_id}.service"
                        ),
                    }
                    for node in nodes
                ])
                browser_output = (
                    output_root / "candidate-browser-webauthn.json"
                )
                completed = run([
                    "node",
                    str(SCRIPT_DIR / "p4ef_multivm_browser_smoke.js"),
                    "--targets", str(targets_path),
                    "--output", str(browser_output),
                ], timeout=300)
                (
                    output_root / "candidate-browser-webauthn.log"
                ).write_text(completed.stdout)
                if completed.returncode != 0:
                    raise RuntimeError(
                        f"browser smoke failed: {completed.stdout[-3000:]}"
                    )
                browser_report = json.loads(browser_output.read_text())
                if browser_report.get("passed") is not True:
                    raise RuntimeError("browser smoke report failed")
                targets_path.unlink()
            except Exception as exception:  # noqa: BLE001
                failures.append(
                    f"candidate_identity_receipt_failed:{exception}"
                )
        if not failures:
            rollback = phase(
                "rollback", baseline, sha256(candidate), nodes, archive,
                proxy, materials, args, output_root,
            )
            receipts.append(rollback)
            if not rollback["passed"]:
                failures.append("baseline_rollback_failed")
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
                verify_script = f'''set -euo pipefail
test ! -e {args.remote_root!r}
if ss -ltnH | grep -Eq ':({args.backend_port}|{args.frontend_port})[[:space:]]'; then exit 1; fi
'''
                require_success(
                    ["ssh", node.ssh_host, "bash -s"],
                    input_text=verify_script,
                )
                cleanup_nodes.append({
                    "node_id": node.node_id,
                    "passed": True,
                })
            except Exception as exception:  # noqa: BLE001
                cleanup_nodes.append({
                    "node_id": node.node_id,
                    "passed": False,
                    "error": str(exception),
                })
                failures.append(f"cleanup_failed:{node.node_id}")
        cleanup = {
            "passed": all(item["passed"] for item in cleanup_nodes),
            "nodes": cleanup_nodes,
        }
        write_json(output_root / "cleanup-receipt.json", cleanup)
    passed = (
        not failures
        and len(receipts) == 3
        and all(item["passed"] for item in receipts)
        and task_report is not None
        and browser_report is not None
        and cleanup["passed"]
    )
    summary = {
        "schema_version": SUMMARY_SCHEMA,
        "passed": passed,
        "decision": (
            "go_p4ef_private_tls_operations" if passed else "no_go"
        ),
        "authorization_id": auth["authorization_id"],
        "authorization_sha256": sha256(auth_path),
        "authorization_consumed": True,
        "baseline_sha256": auth["baseline_sha256"],
        "candidate_sha256": auth["candidate_sha256"],
        "frontend_sha256": auth["frontend_sha256"],
        "material_manifest_sha256": auth["material_manifest_sha256"],
        "receipts": [
            str(output_root / f"{item['operation']}-receipt.json")
            for item in receipts
        ],
        "candidate_task_receipt": task_report,
        "candidate_browser_webauthn": browser_report,
        "cleanup": cleanup,
        "failure_reasons": failures,
        "boundaries": {
            "public_ingress_opened": False,
            "production_data_used": False,
            "production_evidence_claimed": False,
            "automatic_ledger_append_enabled": False,
            "virtual_authenticator_proves_hardware_provenance": False,
        },
    }
    write_json(summary_path, summary)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if passed else 1


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    subparsers = root.add_subparsers(dest="command", required=True)
    material = subparsers.add_parser("prepare-materials")
    material.add_argument("--output-dir", required=True)
    material.add_argument("--node", action="append", default=[])
    material.add_argument("--valid-days", type=int, default=2)
    material.set_defaults(func=prepare_materials)
    auth = subparsers.add_parser("authorize")
    auth.add_argument("--baseline-bin", required=True)
    auth.add_argument("--candidate-bin", required=True)
    auth.add_argument("--frontend-build-dir", required=True)
    auth.add_argument("--materials-dir", required=True)
    auth.add_argument("--output", required=True)
    auth.add_argument("--operator-id", default="local-operator-cc")
    auth.add_argument(
        "--remote-root", default="/tmp/civitasos-p4ef-tls"
    )
    auth.add_argument("--backend-port", type=int, default=18444)
    auth.add_argument("--frontend-port", type=int, default=18443)
    auth.add_argument("--ttl-seconds", type=int, default=3600)
    auth.add_argument("--node", action="append", default=[])
    auth.add_argument(
        "--ack-private-beta-tls-drill", action="store_true"
    )
    auth.set_defaults(func=authorize)
    execute_parser = subparsers.add_parser("execute")
    execute_parser.add_argument("--authorization", required=True)
    execute_parser.add_argument("--baseline-bin", required=True)
    execute_parser.add_argument("--candidate-bin", required=True)
    execute_parser.add_argument("--frontend-build-dir", required=True)
    execute_parser.add_argument("--materials-dir", required=True)
    execute_parser.add_argument("--output-root", required=True)
    execute_parser.add_argument(
        "--remote-root", default="/tmp/civitasos-p4ef-tls"
    )
    execute_parser.add_argument(
        "--backend-port", type=int, default=18444
    )
    execute_parser.add_argument(
        "--frontend-port", type=int, default=18443
    )
    execute_parser.add_argument("--node", action="append", default=[])
    execute_parser.set_defaults(func=execute)
    return root


def main() -> int:
    args = parser().parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
