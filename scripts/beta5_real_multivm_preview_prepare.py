#!/usr/bin/env python3
"""Prepare a repeatable Beta-5 real backend/frontend multi-VM preview run root.

The generated run root contains only non-production preview scripts and an
external environment proof. It does not execute deploy, rollback, or production
runtime actions. Operators still have to pass the generated artifacts through
beta5_external_deploy_evidence_executor.py and beta5_external_deploy_rollback_drill.py.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import tarfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from beta5_external_deploy_evidence_executor import ENVIRONMENT_PROOF_SCHEMA, NON_CLAIMS

PREPARE_SCHEMA = "beta5-real-multivm-preview-prepare-report:v1"
DEFAULT_REMOTE_ROOT = "/home/cal/civitasos_beta5_real_multivm_preview"
DEFAULT_BACKEND_PORT = 18181
DEFAULT_FRONTEND_PORT = 18182
DEFAULT_OWNER = "local-operator-cc"


@dataclass(frozen=True)
class PreviewNode:
    ssh_host: str
    node_id: str
    node_ip: str


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-root", required=True)
    parser.add_argument("--backend-bin", required=True)
    parser.add_argument("--frontend-build-dir", required=True)
    parser.add_argument("--node", action="append", required=True, help="node tuple as ssh_host,node_id,node_ip")
    parser.add_argument("--remote-root", default=DEFAULT_REMOTE_ROOT)
    parser.add_argument("--backend-port", type=int, default=DEFAULT_BACKEND_PORT)
    parser.add_argument("--frontend-port", type=int, default=DEFAULT_FRONTEND_PORT)
    parser.add_argument("--owner", default=DEFAULT_OWNER)
    parser.add_argument("--environment-id")
    parser.add_argument("--overwrite", action="store_true")
    args = parser.parse_args(argv)

    report = write_real_multivm_preview_run(
        run_root=Path(args.run_root),
        backend_bin=Path(args.backend_bin),
        frontend_build_dir=Path(args.frontend_build_dir),
        nodes=[parse_node(raw) for raw in args.node],
        remote_root=args.remote_root,
        backend_port=args.backend_port,
        frontend_port=args.frontend_port,
        owner=args.owner,
        environment_id=args.environment_id,
        overwrite=bool(args.overwrite),
    )
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


def parse_node(raw: str) -> PreviewNode:
    parts = [part.strip() for part in raw.split(",")]
    if len(parts) != 3 or any(not part for part in parts):
        raise ValueError("--node must be formatted as ssh_host,node_id,node_ip")
    return PreviewNode(ssh_host=parts[0], node_id=parts[1], node_ip=parts[2])


def write_real_multivm_preview_run(
    *,
    run_root: Path,
    backend_bin: Path,
    frontend_build_dir: Path,
    nodes: Iterable[PreviewNode],
    remote_root: str = DEFAULT_REMOTE_ROOT,
    backend_port: int = DEFAULT_BACKEND_PORT,
    frontend_port: int = DEFAULT_FRONTEND_PORT,
    owner: str = DEFAULT_OWNER,
    environment_id: str | None = None,
    overwrite: bool = False,
) -> dict[str, Any]:
    node_list = list(nodes)
    _validate_inputs(run_root, backend_bin, frontend_build_dir, node_list, overwrite)
    run_root.mkdir(parents=True, exist_ok=True)
    artifacts = run_root / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)

    frontend_archive = artifacts / "civitasos_frontend_build.tgz"
    _write_frontend_archive(frontend_build_dir, frontend_archive)
    backend_hash = _sha256(backend_bin)
    frontend_hash = _sha256(frontend_archive)
    (artifacts / "backend_api_only.sha256").write_text(backend_hash + "\n", encoding="utf-8")
    (artifacts / "frontend_build_tgz.sha256").write_text(frontend_hash + "\n", encoding="utf-8")

    environment_path = run_root / "environment_proof.json"
    environment = _environment_proof(
        run_root=run_root,
        nodes=node_list,
        remote_root=remote_root,
        backend_port=backend_port,
        frontend_port=frontend_port,
        owner=owner,
        environment_id=environment_id,
        backend_hash=backend_hash,
        frontend_hash=frontend_hash,
    )
    _write_json(environment_path, environment)

    deploy_script = run_root / "deploy_multivm_real_service.sh"
    smoke_script = run_root / "smoke_multivm_real_service.py"
    rollback_script = run_root / "rollback_multivm_real_service.sh"
    rollback_smoke_script = run_root / "smoke_rollback_multivm_real_service.sh"
    operator_script = run_root / "operator_commands.sh"

    _write_executable(deploy_script, _deploy_script(backend_bin, frontend_archive, node_list, remote_root, backend_port, frontend_port))
    _write_executable(smoke_script, _smoke_script(run_root, node_list, backend_port, frontend_port))
    _write_executable(rollback_script, _rollback_script(node_list, remote_root, backend_port, frontend_port))
    _write_executable(operator_script, _operator_commands(run_root))
    _write_executable(rollback_smoke_script, _rollback_smoke_script(node_list, remote_root, backend_port, frontend_port))

    report = {
        "schema_version": PREPARE_SCHEMA,
        "prepared": True,
        "run_root": str(run_root),
        "nodes": [node.__dict__ for node in node_list],
        "remote_root": remote_root,
        "backend_port": backend_port,
        "frontend_port": frontend_port,
        "backend_bin": str(backend_bin),
        "backend_sha256": backend_hash,
        "frontend_build_dir": str(frontend_build_dir),
        "frontend_archive": str(frontend_archive),
        "frontend_archive_sha256": frontend_hash,
        "environment_proof": str(environment_path),
        "deploy_script": str(deploy_script),
        "smoke_script": str(smoke_script),
        "rollback_script": str(rollback_script),
        "rollback_smoke_script": str(rollback_smoke_script),
        "operator_commands": str(operator_script),
        "production_deploy_allowed": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
        "h3_production_readiness_claimed": False,
    }
    _write_json(run_root / "prepare_report.json", report)
    return report


def _validate_inputs(
    run_root: Path,
    backend_bin: Path,
    frontend_build_dir: Path,
    nodes: list[PreviewNode],
    overwrite: bool,
) -> None:
    if run_root.exists() and any(run_root.iterdir()) and not overwrite:
        raise FileExistsError(f"refusing to overwrite non-empty run root: {run_root}")
    if not backend_bin.is_file():
        raise FileNotFoundError(f"backend binary not found: {backend_bin}")
    if not os.access(backend_bin, os.X_OK):
        raise PermissionError(f"backend binary must be executable: {backend_bin}")
    if not frontend_build_dir.is_dir():
        raise FileNotFoundError(f"frontend build directory not found: {frontend_build_dir}")
    if not (frontend_build_dir / "index.html").is_file():
        raise FileNotFoundError(f"frontend build directory must contain index.html: {frontend_build_dir}")
    if not nodes:
        raise ValueError("at least one preview node is required")


def _write_frontend_archive(frontend_build_dir: Path, output: Path) -> None:
    with tarfile.open(output, "w:gz") as archive:
        archive.add(frontend_build_dir, arcname=frontend_build_dir.name)


def _environment_proof(
    *,
    run_root: Path,
    nodes: list[PreviewNode],
    remote_root: str,
    backend_port: int,
    frontend_port: int,
    owner: str,
    environment_id: str | None,
    backend_hash: str,
    frontend_hash: str,
) -> dict[str, Any]:
    node_urls = ",".join(f"{node.node_id}=http://{node.node_ip}:{backend_port}" for node in nodes)
    node_ids = ",".join(node.node_id for node in nodes)
    ssh_hosts = ",".join(node.ssh_host for node in nodes)
    return {
        "schema_version": ENVIRONMENT_PROOF_SCHEMA,
        "recorded_at": _now(),
        "environment_id": environment_id or f"virtualbox-real-backend-frontend-preview-{run_root.name}",
        "environment_kind": "preview",
        "environment_classification": "external_preview",
        "environment_url": f"{node_urls}; frontend_port={frontend_port}",
        "owner": owner,
        "proof_ref": (
            f"ssh-config:{ssh_hosts}; node_ids:{node_ids}; remote_root:{remote_root}; "
            f"backend_sha256:{backend_hash}; frontend_sha256:{frontend_hash}"
        ),
        "production_environment": False,
        "customer_traffic_allowed": False,
        "production_data_allowed": False,
        "destructive_action_allowed": False,
        "secret_material_included": False,
        "no_production_flags": _no_production_flags(),
        "non_claims": list(NON_CLAIMS),
    }


def _deploy_script(
    backend_bin: Path,
    frontend_archive: Path,
    nodes: list[PreviewNode],
    remote_root: str,
    backend_port: int,
    frontend_port: int,
) -> str:
    node_lines = "\n".join(f"{node.ssh_host} {node.node_id} {node.node_ip}" for node in nodes)
    return f'''#!/usr/bin/env bash
set -euo pipefail
REMOTE_ROOT="${{BETA5_REMOTE_ROOT:-{remote_root}}}"
BACKEND_PORT="${{BETA5_BACKEND_PORT:-{backend_port}}}"
FRONTEND_PORT="${{BETA5_FRONTEND_PORT:-{frontend_port}}}"
BACKEND_BIN="{backend_bin.resolve()}"
FRONTEND_TGZ="{frontend_archive.resolve()}"
while read -r SSH_HOST NODE_ID NODE_IP; do
  ssh -n "$SSH_HOST" "mkdir -p '$REMOTE_ROOT/backend' '$REMOTE_ROOT/frontend' '$REMOTE_ROOT/data' '$REMOTE_ROOT/storage' '$REMOTE_ROOT/logs'"
  scp "$BACKEND_BIN" "$SSH_HOST:$REMOTE_ROOT/backend/api_only.next" >/dev/null
  scp "$FRONTEND_TGZ" "$SSH_HOST:$REMOTE_ROOT/frontend/build.tgz" >/dev/null
  ssh "$SSH_HOST" REMOTE_ROOT="$REMOTE_ROOT" BACKEND_PORT="$BACKEND_PORT" FRONTEND_PORT="$FRONTEND_PORT" NODE_ID="$NODE_ID" 'bash -s' <<'REMOTE'
set -euo pipefail
if [ -f "$REMOTE_ROOT/backend/api_only.pid" ]; then kill "$(cat "$REMOTE_ROOT/backend/api_only.pid")" 2>/dev/null || true; fi
if [ -f "$REMOTE_ROOT/frontend/http.pid" ]; then kill "$(cat "$REMOTE_ROOT/frontend/http.pid")" 2>/dev/null || true; fi
pkill -f "api_only --api-port $BACKEND_PORT" 2>/dev/null || true
pkill -f "python3 -m http.server $FRONTEND_PORT" 2>/dev/null || true
mv "$REMOTE_ROOT/backend/api_only.next" "$REMOTE_ROOT/backend/api_only"
rm -rf "$REMOTE_ROOT/frontend/site"
mkdir -p "$REMOTE_ROOT/frontend/site" "$REMOTE_ROOT/data" "$REMOTE_ROOT/storage" "$REMOTE_ROOT/logs"
tar -xzf "$REMOTE_ROOT/frontend/build.tgz" -C "$REMOTE_ROOT/frontend/site" --strip-components=1
chmod +x "$REMOTE_ROOT/backend/api_only"
(
  cd "$REMOTE_ROOT/backend"
  RUST_LOG=info \
  PORT="$BACKEND_PORT" \
  CIVITASOS_DATA_DIR="$REMOTE_ROOT/data" \
  CIVITASOS_STORAGE_DATA_DIR="$REMOTE_ROOT/storage" \
  CIVITASOS_NODE_ID="beta5-real-preview-$NODE_ID" \
  CIVITASOS_BOOT_NODES="" \
  CIVITASOS_JWT_SECRET="beta5-real-preview-jwt-secret-32bytes" \
  CIVITASOS_DEMO_LOGIN_ENABLED=true \
  CIVITASOS_DEMO_AUTO_REGISTER=true \
  CIVITASOS_DEV_FAUCET=true \
  CIVITASOS_INSTITUTIONAL_IDENTITY_ENABLED=true \
  CIVITASOS_EPOCH_AUTO_ENABLED=false \
  CIVITASOS_POOL_SWEEP_AUTO_ENABLED=true \
  CIVITASOS_POOL_SWEEP_INTERVAL_SECS=1 \
  CIVITASOS_TASK_CHALLENGE_WINDOW_ENABLED=true \
  CIVITASOS_TASK_CHALLENGE_WINDOW_SECS=1 \
  CIVITASOS_POOL_SWEEP_SETTLE_CHALLENGE_ENABLED=true \
  nohup ./api_only --api-port "$BACKEND_PORT" > "$REMOTE_ROOT/logs/backend.log" 2>&1 & echo $! > "$REMOTE_ROOT/backend/api_only.pid"
)
(
  cd "$REMOTE_ROOT/frontend/site"
  nohup python3 -m http.server "$FRONTEND_PORT" --bind 0.0.0.0 > "$REMOTE_ROOT/logs/frontend.log" 2>&1 & echo $! > "$REMOTE_ROOT/frontend/http.pid"
)
for i in $(seq 1 80); do
  if curl -fsS "http://127.0.0.1:$BACKEND_PORT/healthz" >/dev/null \
    && curl -fsS "http://127.0.0.1:$BACKEND_PORT/api/v1/runtime/health" >/dev/null \
    && curl -fsS "http://127.0.0.1:$FRONTEND_PORT/" >/dev/null; then
    exit 0
  fi
  sleep 1
done
tail -80 "$REMOTE_ROOT/logs/backend.log" >&2 || true
tail -80 "$REMOTE_ROOT/logs/frontend.log" >&2 || true
exit 1
REMOTE
done <<'EOF'
{node_lines}
EOF
'''


def _smoke_script(run_root: Path, nodes: list[PreviewNode], backend_port: int, frontend_port: int) -> str:
    url_rows = ",\n".join(
        f'    ("{node.node_id}", "http://{node.node_ip}:{backend_port}/healthz", "http://{node.node_ip}:{backend_port}/api/v1/runtime/health", "http://{node.node_ip}:{frontend_port}/")'
        for node in nodes
    )
    return f'''#!/usr/bin/env python3
import json, statistics, time, urllib.request
from pathlib import Path
run_root = Path(r"{run_root.resolve()}")
urls = [
{url_rows},
]
latencies = []
observations = []
for cycle in range(1, 6):
    for node_id, healthz_url, runtime_url, frontend_url in urls:
        start = time.time()
        with urllib.request.urlopen(healthz_url, timeout=5) as resp:
            resp.read()
        with urllib.request.urlopen(runtime_url, timeout=5) as resp:
            runtime = json.load(resp)
        with urllib.request.urlopen(frontend_url, timeout=5) as resp:
            html = resp.read().decode("utf-8", errors="ignore")
        elapsed_ms = round((time.time() - start) * 1000, 3)
        latencies.append(elapsed_ms)
        data = runtime.get("data") if isinstance(runtime.get("data"), dict) else runtime
        for field in ("supervisor_live_attached", "daemon_health_forward_enabled"):
            if field not in data:
                raise AssertionError(f"{{node_id}} missing runtime health field: {{field}}")
        if "<!doctype html" not in html.lower() and '<div id="root"' not in html.lower():
            raise AssertionError(f"{{node_id}} frontend build root not served")
        observations.append({{"cycle": cycle, "node_id": node_id, "elapsed_ms": elapsed_ms}})
summary = {{
    "schema_version": "beta5-real-backend-frontend-multivm-smoke:v1",
    "passed": True,
    "cycles": 5,
    "nodes": [node[0] for node in urls],
    "total_checks": len(observations),
    "latency_ms_min": min(latencies),
    "latency_ms_median": round(statistics.median(latencies), 3),
    "latency_ms_max": max(latencies),
    "backend_port": {backend_port},
    "frontend_port": {frontend_port},
    "production_deploy_allowed": False,
    "production_runtime_execution_allowed": False,
    "production_receipt_write_allowed": False,
    "h3_production_readiness_claimed": False,
    "observations": observations,
}}
(run_root / "multivm_real_service_smoke_summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(json.dumps(summary, sort_keys=True))
'''


def _rollback_script(nodes: list[PreviewNode], remote_root: str, backend_port: int, frontend_port: int) -> str:
    hosts = " ".join(node.ssh_host for node in nodes)
    return f'''#!/usr/bin/env bash
set -euo pipefail
REMOTE_ROOT="${{BETA5_REMOTE_ROOT:-{remote_root}}}"
BACKEND_PORT="${{BETA5_BACKEND_PORT:-{backend_port}}}"
FRONTEND_PORT="${{BETA5_FRONTEND_PORT:-{frontend_port}}}"
for SSH_HOST in {hosts}; do
  ssh "$SSH_HOST" REMOTE_ROOT="$REMOTE_ROOT" BACKEND_PORT="$BACKEND_PORT" FRONTEND_PORT="$FRONTEND_PORT" 'bash -s' <<'REMOTE'
set -euo pipefail
if [ -f "$REMOTE_ROOT/backend/api_only.pid" ]; then kill "$(cat "$REMOTE_ROOT/backend/api_only.pid")" 2>/dev/null || true; fi
if [ -f "$REMOTE_ROOT/frontend/http.pid" ]; then kill "$(cat "$REMOTE_ROOT/frontend/http.pid")" 2>/dev/null || true; fi
pkill -f "api_only --api-port $BACKEND_PORT" 2>/dev/null || true
pkill -f "python3 -m http.server $FRONTEND_PORT" 2>/dev/null || true
rm -rf "$REMOTE_ROOT"
REMOTE
done
'''


def _rollback_smoke_script(nodes: list[PreviewNode], remote_root: str, backend_port: int, frontend_port: int) -> str:
    hosts = " ".join(node.ssh_host for node in nodes)
    return f'''#!/usr/bin/env bash
set -euo pipefail
REMOTE_ROOT="${{BETA5_REMOTE_ROOT:-{remote_root}}}"
BACKEND_PORT="${{BETA5_BACKEND_PORT:-{backend_port}}}"
FRONTEND_PORT="${{BETA5_FRONTEND_PORT:-{frontend_port}}}"
for SSH_HOST in {hosts}; do
  if ssh "$SSH_HOST" "curl -fsS --max-time 2 http://127.0.0.1:$BACKEND_PORT/healthz >/dev/null"; then
    echo "$SSH_HOST backend still reachable after rollback" >&2
    exit 1
  fi
  if ssh "$SSH_HOST" "curl -fsS --max-time 2 http://127.0.0.1:$FRONTEND_PORT/ >/dev/null"; then
    echo "$SSH_HOST frontend still reachable after rollback" >&2
    exit 1
  fi
  ssh "$SSH_HOST" "test ! -e '$REMOTE_ROOT'"
done
'''


def _operator_commands(run_root: Path) -> str:
    return f'''#!/usr/bin/env bash
set -euo pipefail
RUN_ROOT="$(cd "$(dirname "${{BASH_SOURCE[0]}}")" && pwd)"
AGENT_ROOT="${{CIVITASOS_AGENT_ROOT:-$(cd "$RUN_ROOT/../.." && pwd)}}"
PYTHON="${{CIVITASOS_AGENT_PYTHON:-$AGENT_ROOT/.venv/bin/python}}"
LOCAL_RECEIPT="${{BETA5_LOCAL_DEPLOY_RECEIPT:?set BETA5_LOCAL_DEPLOY_RECEIPT to beta5_local_controlled_deploy_receipt.json}}"
OPERATOR_ID="${{BETA5_OPERATOR_ID:-local-operator-cc}}"
cd "$AGENT_ROOT"
"$PYTHON" scripts/beta5_external_deploy_evidence_executor.py validate-environment-proof \
  --environment-proof "$RUN_ROOT/environment_proof.json" \
  --output "$RUN_ROOT/environment_proof_validation.json"
"$PYTHON" scripts/beta5_external_deploy_evidence_executor.py record-authorization \
  --local-deploy-receipt "$LOCAL_RECEIPT" \
  --environment-proof "$RUN_ROOT/environment_proof.json" \
  --deploy-target "real-multivm-preview:$RUN_ROOT" \
  --deploy-command "$RUN_ROOT/deploy_multivm_real_service.sh" \
  --external-smoke-command "$RUN_ROOT/smoke_multivm_real_service.py" \
  --working-directory "$AGENT_ROOT" \
  --output "$RUN_ROOT/external_deploy_authorization.json" \
  --operator-id "$OPERATOR_ID" \
  --reason "Run Beta-5 real backend/frontend multi-VM non-production preview" \
  --rollback-evidence-ref "rollback:required-before-production" \
  --ack-external-controlled-deploy
"$PYTHON" scripts/beta5_external_deploy_evidence_executor.py deploy \
  --authorization "$RUN_ROOT/external_deploy_authorization.json" \
  --output-root "$RUN_ROOT"
"$PYTHON" scripts/beta5_external_deploy_evidence_executor.py validate-receipt \
  --receipt "$RUN_ROOT/beta5_external_deploy_receipt.json" \
  --output "$RUN_ROOT/beta5_external_deploy_receipt_validation.json"
"$PYTHON" scripts/beta5_external_deploy_rollback_drill.py record-authorization \
  --external-deploy-receipt "$RUN_ROOT/beta5_external_deploy_receipt.json" \
  --rollback-command "$RUN_ROOT/rollback_multivm_real_service.sh" \
  --rollback-smoke-command "$RUN_ROOT/smoke_rollback_multivm_real_service.sh" \
  --working-directory "$AGENT_ROOT" \
  --output "$RUN_ROOT/rollback_drill_authorization.json" \
  --operator-id "$OPERATOR_ID" \
  --reason "Verify rollback for Beta-5 real backend/frontend multi-VM preview" \
  --ack-rollback-drill
"$PYTHON" scripts/beta5_external_deploy_rollback_drill.py execute \
  --authorization "$RUN_ROOT/rollback_drill_authorization.json" \
  --output-root "$RUN_ROOT"
"$PYTHON" scripts/beta5_external_deploy_rollback_drill.py validate-receipt \
  --receipt "$RUN_ROOT/beta5_external_deploy_rollback_drill_receipt.json" \
  --output "$RUN_ROOT/beta5_external_deploy_rollback_drill_receipt_validation.json"
'''


def _no_production_flags() -> dict[str, bool]:
    return {
        "production_environment": False,
        "customer_traffic_allowed": False,
        "production_data_allowed": False,
        "production_deploy_allowed": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
        "h3_production_readiness_claimed": False,
    }


def _write_executable(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


if __name__ == "__main__":
    raise SystemExit(main())
