"""Concrete non-fault phases for the P5-B4 multi-VM checkpoint Gate."""

from __future__ import annotations

import hashlib
import json
import os
import shlex
import tarfile
import time
from pathlib import Path
from typing import Any

from p5b4_multivm_checkpoint_executor import RemoteTransport
from p5b4_multivm_checkpoint_gate import PreviewNode, git_snapshot, sha256
from p5b4_multivm_materials import validate_materials


def _private_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        stream.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
        stream.flush()
        os.fsync(stream.fileno())


def _result(stdout: str, operation: str) -> dict[str, Any]:
    lines = [line for line in stdout.splitlines() if line.strip()]
    if not lines:
        raise RuntimeError(f"P5-B4 {operation} returned no JSON evidence")
    try:
        value = json.loads(lines[-1])
    except json.JSONDecodeError as error:
        raise RuntimeError(f"P5-B4 {operation} returned invalid JSON") from error
    if not isinstance(value, dict):
        raise RuntimeError(f"P5-B4 {operation} evidence must be an object")
    return value


class BuiltInPhaseHandlers:
    """Deploy and verify the implemented P5-B4 phase subset."""

    def __init__(
        self,
        *,
        plan: dict[str, Any],
        transport: RemoteTransport,
        state_root: Path,
    ) -> None:
        self.plan = plan
        self.transport = transport
        self.state_root = state_root.expanduser().resolve()
        self.nodes = [PreviewNode(**node) for node in plan["nodes"]]
        self.node_by_id = {node.node_id: node for node in self.nodes}
        self.authoritative = self.node_by_id[plan["authoritative_node"]]
        self.remote_root = str(plan["remote_root"])
        self.port = int(plan["backend_port"])
        self.candidate = plan["candidate"]
        self.material_manifest = Path(self.candidate["materials_manifest_path"])
        self.materials_root = self.material_manifest.parent

    def handlers(self) -> dict[str, Any]:
        return {
            "local_preflight": self.local_preflight,
            "deploy_isolated_candidate": self.deploy_isolated_candidate,
            "capture_authoritative_checkpoint": self.capture_authoritative_checkpoint,
            "establish_follower_projection": self.establish_follower_projection,
            "restore_with_real_agent_runner": self.restore_with_real_agent_runner,
            "process_kill_retry_matrix": self.process_kill_retry_matrix,
            "authoritative_node_reboot": self.authoritative_node_reboot,
            "partition_follower": self.partition_follower,
            "heal_and_reject_stale_replay": self.heal_and_reject_stale_replay,
            "converge_receipt_evidence": self.converge_receipt_evidence,
        }

    def local_preflight(self, _phase: dict[str, Any]) -> dict[str, Any]:
        validate_materials(self.material_manifest)
        checks: dict[str, bool] = {
            "backend_binary": sha256(Path(self.candidate["backend_binary_path"]))
            == self.candidate["backend_binary_sha256"],
            "materials_manifest": sha256(self.material_manifest)
            == self.candidate["materials_manifest_sha256"],
        }
        for name in ("agent", "runtime"):
            revision, clean = git_snapshot(Path(self.candidate[f"{name}_repo"]))
            checks[f"{name}_revision"] = revision == self.candidate[f"{name}_revision"]
            checks[f"{name}_clean"] = clean
        if not all(checks.values()):
            raise RuntimeError(f"P5-B4 local execution preflight failed: {checks}")
        return {"passed": True, "checks": checks, "vm_contact_performed": False}

    def _runtime_archive(self) -> Path:
        output = self.state_root / "runtime-source.tgz"
        if output.exists():
            return output
        runtime_repo = Path(self.candidate["runtime_repo"])
        package = runtime_repo / "civitasos_runtime"
        temporary = output.with_suffix(".tmp")
        with tarfile.open(temporary, "w:gz") as archive:
            for path in sorted(package.rglob("*")):
                if "__pycache__" in path.parts or not path.is_file():
                    continue
                archive.add(path, arcname=path.relative_to(runtime_repo), recursive=False)
        os.chmod(temporary, 0o600)
        os.replace(temporary, output)
        return output

    def _remote(self, node: PreviewNode, command: str, *, timeout: int = 120) -> str:
        return self.transport.run(node, command, timeout=timeout).stdout

    def _worker_command(self, node: PreviewNode, action: str) -> str:
        root = shlex.quote(self.remote_root)
        base_url = shlex.quote(f"https://{node.node_ip}:{self.port}")
        return f"""set -euo pipefail
ROOT={root}
PYTHONPATH="$ROOT/runtime-source" python3 "$ROOT/worker.py" {shlex.quote(action)} \
  --root "$ROOT/worker-state" \
  --base-url {base_url} \
  --ca "$ROOT/ca.crt" \
  --cert "$ROOT/{node.node_id}.crt" \
  --key "$ROOT/{node.node_id}.key" \
  --service-secret-file "$ROOT/service.secret"
"""

    def _start_script(self, node: PreviewNode, materials: dict[str, Any]) -> str:
        root = shlex.quote(self.remote_root)
        peers = ",".join(
            f"https://{peer.node_ip}:{self.port}"
            for peer in self.nodes
            if peer.node_id != node.node_id
        )
        trusted = json.dumps(materials["trusted_peer_keys"], separators=(",", ":"))
        return f"""#!/bin/bash
set -euo pipefail
ROOT={root}
BOOT_NODES={shlex.quote(peers)}
if test "$#" -ge 1; then BOOT_NODES="$1"; fi
nohup env \
  CIVITASOS_AUTH_MODE=private_beta \
  CIVITASOS_DATA_DIR="$ROOT/data" \
  CIVITASOS_STORAGE_DATA_DIR="$ROOT/storage" \
  CIVITASOS_NODE_ID={shlex.quote(f'p5b4-{node.node_id}')} \
  CIVITASOS_BOOT_NODES="$BOOT_NODES" \
  CIVITASOS_NODE_SIGNING_SEED_FILE="$ROOT/{node.node_id}.seed" \
  CIVITASOS_PEER_AUTH_REQUIRED=true \
  CIVITASOS_TRUSTED_PEER_KEYS={shlex.quote(trusted)} \
  CIVITASOS_TLS_CERT="$ROOT/{node.node_id}.crt" \
  CIVITASOS_TLS_KEY="$ROOT/{node.node_id}.key" \
  CIVITASOS_MTLS_CA_CERT="$ROOT/ca.crt" \
  CIVITASOS_MTLS_CLIENT_CERT="$ROOT/{node.node_id}.crt" \
  CIVITASOS_MTLS_CLIENT_KEY="$ROOT/{node.node_id}.key" \
  CIVITASOS_JWT_SECRET="$(cat "$ROOT/jwt.secret")" \
  CIVITASOS_SERVICE_TOKEN_SECRET="$(cat "$ROOT/service.secret")" \
  CIVITASOS_SERVICE_TOKEN_SCOPES='agents:read,agents:write,audit:read,checkpoints:read,checkpoints:write,pool:read' \
  CIVITASOS_CLUSTER_SYNC_TOKEN="$(cat "$ROOT/cluster.secret")" \
  CIVITASOS_FACT_ANTI_ENTROPY_INTERVAL_SECS=1 \
  CIVITASOS_JWT_ENFORCE=true \
  CIVITASOS_TRUST_PROXY_HEADERS=false \
  CIVITASOS_A2A_SEED_TASKS=false \
  CIVITASOS_DEMO_LOGIN_ENABLED=false \
  CIVITASOS_INSTITUTIONAL_IDENTITY_ENABLED=false \
  CIVITASOS_EPOCH_AUTO_ENABLED=false \
  CIVITASOS_POOL_SWEEP_AUTO_ENABLED=false \
  "$ROOT/api_only" --api-port {self.port} >"$ROOT/backend.log" 2>&1 &
echo $! >"$ROOT/backend.pid"
"""

    def deploy_isolated_candidate(self, _phase: dict[str, Any]) -> dict[str, Any]:
        materials = validate_materials(self.material_manifest)
        runtime_archive = self._runtime_archive()
        worker = Path(self.candidate["agent_repo"]) / "scripts/p5b4_remote_checkpoint_worker.py"
        backend = Path(self.candidate["backend_binary_path"])
        observations = []
        for node in self.nodes:
            root = shlex.quote(self.remote_root)
            self._remote(
                node,
                f"""set -euo pipefail
ROOT={root}
test ! -e "$ROOT"
if command -v ss >/dev/null 2>&1; then ! ss -H -ltn 'sport = :{self.port}' | grep -q .; fi
sudo -n true
test -x /usr/sbin/iptables
test -x /usr/sbin/iptables-save
command -v systemctl >/dev/null
command -v ss >/dev/null
command -v curl >/dev/null
command -v tar >/dev/null
command -v sha256sum >/dev/null
command -v sort >/dev/null
command -v xargs >/dev/null
python3 -c 'import sys; assert sys.version_info >= (3, 11)'
mkdir -m 700 "$ROOT"
""",
            )
            copies = [
                (backend, "api_only"),
                (worker, "worker.py"),
                (runtime_archive, "runtime-source.tgz"),
                (self.materials_root / "ca.crt", "ca.crt"),
                (self.materials_root / f"{node.node_id}.crt", f"{node.node_id}.crt"),
                (self.materials_root / f"{node.node_id}.key", f"{node.node_id}.key"),
                (self.materials_root / f"{node.node_id}.seed", f"{node.node_id}.seed"),
                (self.materials_root / "jwt.secret", "jwt.secret"),
                (self.materials_root / "service.secret", "service.secret"),
                (self.materials_root / "cluster.secret", "cluster.secret"),
            ]
            if node.node_id == self.authoritative.node_id:
                copies.append((self.materials_root / "identity.seed", "identity.seed"))
            for source, name in copies:
                self.transport.copy(node, source, f"{self.remote_root}/{name}")
            start = self._start_script(node, materials)
            self._remote(
                node,
                f"""set -euo pipefail
ROOT={root}
chmod 700 "$ROOT/api_only" "$ROOT/worker.py"
chmod 600 "$ROOT"/*.crt "$ROOT"/*.key "$ROOT"/*.seed "$ROOT"/*.secret
mkdir -m 700 "$ROOT/runtime-source" "$ROOT/worker-state"
if test -f "$ROOT/identity.seed"; then
  mv "$ROOT/identity.seed" "$ROOT/worker-state/identity.seed"
  chmod 600 "$ROOT/worker-state/identity.seed"
fi
tar -xzf "$ROOT/runtime-source.tgz" -C "$ROOT/runtime-source"
python3 -c 'import nacl'
PYTHONPATH="$ROOT/runtime-source" python3 -c 'import civitasos_runtime'
cat >"$ROOT/start.sh" <<'P5B4_START'
{start}P5B4_START
chmod 700 "$ROOT/start.sh"
"$ROOT/start.sh"
for attempt in $(seq 1 100); do
  if curl --silent --show-error --fail --noproxy '*' \
      --cacert "$ROOT/ca.crt" --cert "$ROOT/{node.node_id}.crt" \
      --key "$ROOT/{node.node_id}.key" \
      "https://{node.node_ip}:{self.port}/healthz" >/dev/null; then exit 0; fi
  if ! kill -0 "$(cat "$ROOT/backend.pid")" 2>/dev/null; then tail -100 "$ROOT/backend.log"; exit 1; fi
  sleep 0.2
done
tail -100 "$ROOT/backend.log"
exit 1
""",
                timeout=180,
            )
            observations.append({"node_id": node.node_id, "ready": True})
        return {
            "passed": True,
            "nodes": observations,
            "backend_sha256": self.candidate["backend_binary_sha256"],
            "runtime_archive_sha256": sha256(runtime_archive),
            "remote_root": self.remote_root,
            "backend_port": self.port,
        }

    def capture_authoritative_checkpoint(self, _phase: dict[str, Any]) -> dict[str, Any]:
        result = _result(
            self._remote(
                self.authoritative,
                self._worker_command(self.authoritative, "capture"),
                timeout=180,
            ),
            "authoritative capture",
        )
        return self._record_and_sync_fixture(result)

    def _record_and_sync_fixture(
        self, result: dict[str, Any], *, include_authoritative: bool = False
    ) -> dict[str, Any]:
        fixture_path = self.state_root / "fixture.json"
        fixture_path.unlink(missing_ok=True)
        _private_json(fixture_path, result)
        for node in self.nodes:
            if not include_authoritative and node.node_id == self.authoritative.node_id:
                continue
            self._remote(
                node,
                f"mkdir -p {shlex.quote(self.remote_root + '/worker-state')}",
            )
            self.transport.copy(
                node,
                fixture_path,
                f"{self.remote_root}/worker-state/fixture.json",
            )
        return {
            "passed": True,
            "identity_id": result.get("identity_id"),
            "checkpoint_id": result.get("checkpoint_id"),
            "manifest_hash": result.get("manifest_hash"),
            "sequence": result.get("sequence"),
            "fixture_sha256": sha256(fixture_path),
        }

    def _capture_next(self) -> dict[str, Any]:
        result = _result(
            self._remote(
                self.authoritative,
                self._worker_command(self.authoritative, "capture-next"),
                timeout=180,
            ),
            "next authoritative capture",
        )
        return self._record_and_sync_fixture(result)

    def _restart_authoritative_backend(self, *, isolated: bool = False) -> None:
        node = self.authoritative
        root = shlex.quote(self.remote_root)
        self._remote(
            node,
            f"""set -euo pipefail
ROOT={root}
if test -f "$ROOT/backend.pid" && kill -0 "$(cat "$ROOT/backend.pid")" 2>/dev/null; then
  exit 81
fi
{"$ROOT/start.sh ''" if isolated else '"$ROOT/start.sh"'}
for attempt in $(seq 1 100); do
  if curl --silent --show-error --fail --noproxy '*' \
      --cacert "$ROOT/ca.crt" --cert "$ROOT/{node.node_id}.crt" \
      --key "$ROOT/{node.node_id}.key" \
      "https://{node.node_ip}:{self.port}/healthz" >/dev/null; then exit 0; fi
  sleep 0.2
done
tail -100 "$ROOT/backend.log"
exit 1
""",
            timeout=60,
        )

    def _run_agent_checked(self) -> dict[str, Any]:
        result = _result(
            self._remote(
                self.authoritative,
                self._worker_command(self.authoritative, "run-agent"),
                timeout=180,
            ),
            "AgentRunner retry",
        )
        checks = {
            "agent_runner_started": result.get("agent_runner_started") is True,
            "pre_activation_tick_count": result.get("pre_activation_tick_count") == 0,
            "post_activation_tick_count": result.get("post_activation_tick_count") == 1,
            "external_llm_calls": result.get("external_llm_calls") == 0,
        }
        if not all(checks.values()):
            raise RuntimeError(f"P5-B4 AgentRunner retry evidence failed: {checks}")
        return result

    def _authoritative_projection(self) -> dict[str, Any]:
        projection = _result(
            self._remote(
                self.authoritative,
                self._worker_command(self.authoritative, "projection"),
            ),
            "authoritative checkpoint projection",
        )
        if (
            projection.get("passed") is not True
            or (projection.get("receipt") or {}).get("fact_count") != 1
        ):
            raise RuntimeError("P5-B4 authoritative projection is not exactly-once")
        return projection

    def _fault_marker(self, name: str) -> dict[str, Any]:
        root = shlex.quote(self.remote_root)
        return _result(
            self._remote(
                self.authoritative,
                f"cat {root}/{shlex.quote(name)}\n",
            ),
            f"{name} fault marker",
        )

    def establish_follower_projection(self, _phase: dict[str, Any]) -> dict[str, Any]:
        observations = []
        for node in self.nodes:
            root = shlex.quote(self.remote_root)
            stdout = self._remote(
                node,
                f"""set -euo pipefail
ROOT={root}
{{ printf 'X-CivitasOS-Cluster-Token: '; cat "$ROOT/cluster.secret"; printf '\n'; }} \
  >"$ROOT/sync-header"
chmod 600 "$ROOT/sync-header"
curl --silent --show-error --fail --noproxy '*' \
  --cacert "$ROOT/ca.crt" --cert "$ROOT/{node.node_id}.crt" \
  --key "$ROOT/{node.node_id}.key" \
  --header @"$ROOT/sync-header" \
  "https://{node.node_ip}:{self.port}/api/v1/sync/state"
""",
            )
            snapshot = _result(stdout, f"{node.node_id} baseline sync")
            observations.append(
                {
                    "node_id": node.node_id,
                    "snapshot_sha256": hashlib.sha256(
                        json.dumps(snapshot, sort_keys=True).encode()
                    ).hexdigest(),
                }
            )
        return {"passed": True, "nodes": observations}

    def restore_with_real_agent_runner(self, _phase: dict[str, Any]) -> dict[str, Any]:
        result = _result(
            self._remote(
                self.authoritative,
                self._worker_command(self.authoritative, "run-agent"),
                timeout=180,
            ),
            "real AgentRunner restore",
        )
        checks = {
            "agent_runner_started": result.get("agent_runner_started") is True,
            "pre_activation_tick_count": result.get("pre_activation_tick_count") == 0,
            "post_activation_tick_count": result.get("post_activation_tick_count") == 1,
            "checkpoint_latch_released": result.get("checkpoint_latch_released") is True,
            "external_llm_calls": result.get("external_llm_calls") == 0,
            "memory_hash": result.get("memory_sha256_at_latch_release")
            == result.get("expected_memory_sha256"),
        }
        if not all(checks.values()):
            raise RuntimeError(f"P5-B4 real AgentRunner evidence failed: {checks}")
        output = self.state_root / "agent-runner-result.json"
        _private_json(output, result)
        return {"passed": True, "checks": checks, "result_sha256": sha256(output)}

    def process_kill_retry_matrix(self, _phase: dict[str, Any]) -> dict[str, Any]:
        cases = []
        for case_id, fault_point, marker_name, restart_backend in (
            (
                "authoritative_backend_sigkill_before_activation_ack",
                "backend_sigkill_before_activation_ack",
                "backend-fault-triggered.json",
                True,
            ),
            (
                "agent_runner_sigkill_after_runtime_sqlite_commit",
                "agent_runner_sigkill_after_runtime_sqlite_commit",
                "runner-fault-triggered.json",
                False,
            ),
        ):
            fixture = self._capture_next()
            command = self._worker_command(
                self.authoritative, "run-agent"
            ).rstrip()
            command += f" --fault-point {shlex.quote(fault_point)}\n"
            failure = ""
            try:
                self._remote(self.authoritative, command, timeout=180)
            except Exception as error:  # the injected process death is required evidence
                failure = f"{type(error).__name__}:{error}"
            if not failure:
                raise RuntimeError(f"P5-B4 fault was not injected: {fault_point}")
            marker = self._fault_marker(marker_name)
            if marker.get("fault_point") != fault_point:
                raise RuntimeError(f"P5-B4 fault marker mismatch: {fault_point}")
            if not restart_backend and (
                marker.get("checkpoint_id") != fixture["checkpoint_id"]
                or marker.get("sequence") != fixture["sequence"]
                or marker.get("runtime_sqlite_committed") is not True
            ):
                raise RuntimeError("P5-B4 AgentRunner fault marker binding failed")
            if restart_backend:
                self._restart_authoritative_backend()
            retry = self._run_agent_checked()
            projection = self._authoritative_projection()
            cases.append(
                {
                    "case_id": case_id,
                    "fault_point": fault_point,
                    "checkpoint_id": fixture["checkpoint_id"],
                    "sequence": fixture["sequence"],
                    "injected_process_failure": failure,
                    "fault_marker": marker,
                    "backend_restarted": restart_backend,
                    "retry_activation_fact_id": (
                        retry["restore_milestones"][-2]["event"].get(
                            "activation_fact_id"
                        )
                    ),
                    "receipt_hash": projection["receipt"]["receipt_hash"],
                    "activation_fact_count": projection["receipt"]["fact_count"],
                    "passed": True,
                }
            )
        return {"passed": True, "cases": cases}

    def _worker_state_digest(self, node: PreviewNode) -> str:
        root = shlex.quote(self.remote_root)
        output = self._remote(
            node,
            f"""set -euo pipefail
ROOT={root}
test -d "$ROOT/worker-state"
find "$ROOT/worker-state" -type f -print0 | sort -z | xargs -0 sha256sum | sha256sum
""",
        )
        digest = output.strip().split()[0]
        if len(digest) != 64:
            raise RuntimeError("P5-B4 worker-state digest is invalid")
        return digest

    def authoritative_node_reboot(self, _phase: dict[str, Any]) -> dict[str, Any]:
        node = self.authoritative
        before_projection = self._authoritative_projection()
        before_state = self._worker_state_digest(node)
        try:
            self._remote(node, "sudo -n systemctl reboot\n", timeout=15)
        except Exception:
            pass
        observed_down = False
        recovered = False
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            try:
                self._remote(node, "true\n", timeout=8)
                if observed_down:
                    recovered = True
                    break
            except Exception:
                observed_down = True
            time.sleep(2)
        if not observed_down or not recovered:
            raise RuntimeError(
                f"P5-B4 authoritative reboot transition failed: down={observed_down} up={recovered}"
            )
        self._restart_authoritative_backend(isolated=True)
        after_state = self._worker_state_digest(node)
        isolated_projection = self._authoritative_projection()
        checks = {
            "worker_state_persisted": before_state == after_state,
            "receipt_hash_persisted": before_projection["receipt"].get("receipt_hash")
            == isolated_projection["receipt"].get("receipt_hash"),
            "evidence_hash_persisted": before_projection["evidence_manifest"].get(
                "manifest_hash"
            )
            == isolated_projection["evidence_manifest"].get("manifest_hash"),
            "fact_integrity_valid": isolated_projection["fact_integrity"].get(
                "valid"
            )
            is True,
            "peer_catchup_disabled_during_probe": True,
        }
        if not all(checks.values()):
            raise RuntimeError(f"P5-B4 reboot persistence failed: {checks}")
        root = shlex.quote(self.remote_root)
        self._remote(
            node,
            f"""set -euo pipefail
ROOT={root}
kill "$(cat "$ROOT/backend.pid")"
for attempt in $(seq 1 100); do
  ! kill -0 "$(cat "$ROOT/backend.pid")" 2>/dev/null && exit 0
  sleep 0.1
done
exit 82
""",
            timeout=30,
        )
        self._restart_authoritative_backend()
        clustered_projection = self._authoritative_projection()
        if (
            clustered_projection["receipt"].get("receipt_hash")
            != isolated_projection["receipt"].get("receipt_hash")
        ):
            raise RuntimeError("P5-B4 reboot projection changed after peer reconnect")
        return {
            "passed": True,
            "case_id": "authoritative_node_reboot_after_activation",
            "node_id": node.node_id,
            "observed_down": observed_down,
            "recovered": recovered,
            "checks": checks,
        }

    def _partition_edges(self) -> list[tuple[PreviewNode, str]]:
        partitioned = self.node_by_id[self.plan["partitioned_follower"]]
        edges: list[tuple[PreviewNode, str]] = []
        for node in self.nodes:
            if node.node_id == partitioned.node_id:
                edges.extend(
                    (node, peer.node_ip)
                    for peer in self.nodes
                    if peer.node_id != partitioned.node_id
                )
            else:
                edges.append((node, partitioned.node_ip))
        return edges

    def _partition_rule_script(self, peer_ip: str, *, apply: bool) -> str:
        operation = "-I" if apply else "-D"
        condition = "" if apply else "!"
        comment = shlex.quote(str(self.plan["partition_comment"]))
        commands = []
        for chain, direction in (("INPUT", "-s"), ("OUTPUT", "-d")):
            rule = (
                f"-p tcp {direction} {shlex.quote(peer_ip)} --dport {self.port} "
                f"-m comment --comment {comment} -j REJECT"
            )
            if apply:
                commands.append(
                    f"if ! sudo -n /usr/sbin/iptables -C {chain} {rule} 2>/dev/null; "
                    f"then sudo -n /usr/sbin/iptables {operation} {chain} {rule}; fi"
                )
            else:
                commands.append(
                    f"while sudo -n /usr/sbin/iptables -C {chain} {rule} 2>/dev/null; "
                    f"do sudo -n /usr/sbin/iptables {operation} {chain} {rule}; done"
                )
            commands.append(
                f"{condition} sudo -n /usr/sbin/iptables -C {chain} {rule} 2>/dev/null"
            )
        return "set -euo pipefail\n" + "\n".join(commands) + "\n"

    def partition_follower(self, _phase: dict[str, Any]) -> dict[str, Any]:
        observations = []
        for node, peer_ip in self._partition_edges():
            self._remote(node, self._partition_rule_script(peer_ip, apply=True))
            observations.append({"node_id": node.node_id, "peer_ip": peer_ip})
        return {
            "passed": True,
            "case_id": "follower_partition_during_projection",
            "partitioned_follower": self.plan["partitioned_follower"],
            "comment": self.plan["partition_comment"],
            "edges": observations,
        }

    def _heal_partition(self) -> list[dict[str, str]]:
        observations = []
        for node, peer_ip in self._partition_edges():
            self._remote(node, self._partition_rule_script(peer_ip, apply=False))
            observations.append({"node_id": node.node_id, "peer_ip": peer_ip})
        return observations

    def heal_and_reject_stale_replay(self, _phase: dict[str, Any]) -> dict[str, Any]:
        partitioned = self.node_by_id[self.plan["partitioned_follower"]]
        accepted_fixture = self._capture_next()
        self._run_agent_checked()
        majority_projection = self._authoritative_projection()
        isolated_failure = ""
        try:
            self._remote(
                partitioned,
                self._worker_command(partitioned, "projection"),
                timeout=30,
            )
        except Exception as error:
            isolated_failure = f"{type(error).__name__}:{error}"
        if not isolated_failure:
            raise RuntimeError("P5-B4 partitioned follower observed activation too early")
        healed_edges = self._heal_partition()
        converged = self.converge_receipt_evidence(_phase)
        stale = _result(
            self._remote(
                self.authoritative,
                self._worker_command(self.authoritative, "stale-replay"),
            ),
            "stale checkpoint replay",
        )
        if stale.get("passed") is not True:
            raise RuntimeError("P5-B4 stale replay rejection did not pass")

        accepted_fixture_payload = json.loads(
            (self.state_root / "fixture.json").read_text()
        )
        rejected_fixture = self._capture_next()
        rotation_command = self._worker_command(
            self.authoritative, "run-agent"
        ).rstrip()
        rotation_command += " --fault-point credential_rotation_after_preflight\n"
        rotation_failure = ""
        try:
            self._remote(self.authoritative, rotation_command, timeout=180)
        except Exception as error:
            rotation_failure = f"{type(error).__name__}:{error}"
        if not rotation_failure:
            raise RuntimeError("P5-B4 credential rotation did not interrupt restore")
        no_projection = _result(
            self._remote(
                self.authoritative,
                self._worker_command(
                    self.authoritative, "assert-no-projection"
                ).rstrip()
                + " --require-rotation-marker\n",
            ),
            "credential rotation no-Receipt assertion",
        )
        if no_projection.get("passed") is not True:
            raise RuntimeError("P5-B4 credential rotation created an activation Receipt")
        self._record_and_sync_fixture(
            accepted_fixture_payload, include_authoritative=True
        )
        return {
            "passed": True,
            "partition_case": {
                "case_id": "follower_partition_during_projection",
                "checkpoint_id": accepted_fixture["checkpoint_id"],
                "isolated_follower": partitioned.node_id,
                "isolated_projection_failure": isolated_failure,
                "majority_receipt_hash": majority_projection["receipt"]["receipt_hash"],
                "healed_edges": healed_edges,
                "converged_receipt_hash": converged["receipt_hash"],
            },
            "stale_replay": {
                **stale,
                "case_id": "stale_sequence_replay_after_heal",
            },
            "credential_rotation": {
                "case_id": "credential_rotation_during_remote_restore",
                "checkpoint_id": rejected_fixture["checkpoint_id"],
                "restore_failure": rotation_failure,
                "activation_receipt_status": no_projection["receipt_status"],
                "rotation_marker": no_projection["credential_rotation"],
                "passed": True,
            },
        }

    def converge_receipt_evidence(self, _phase: dict[str, Any]) -> dict[str, Any]:
        deadline = time.monotonic() + 60
        latest: dict[str, dict[str, Any]] = {}
        while time.monotonic() < deadline:
            latest = {}
            for node in self.nodes:
                try:
                    latest[node.node_id] = _result(
                        self._remote(node, self._worker_command(node, "projection")),
                        f"{node.node_id} checkpoint projection",
                    )
                except Exception:
                    latest = {}
                    break
            if len(latest) == len(self.nodes) and all(
                projection.get("passed") is True for projection in latest.values()
            ):
                receipt_hashes = {
                    projection["receipt"].get("receipt_hash")
                    for projection in latest.values()
                }
                evidence_hashes = {
                    projection["evidence_manifest"].get("manifest_hash")
                    for projection in latest.values()
                }
                if len(receipt_hashes) == len(evidence_hashes) == 1:
                    return {
                        "passed": True,
                        "receipt_hash": receipt_hashes.pop(),
                        "evidence_manifest_hash": evidence_hashes.pop(),
                        "nodes": latest,
                    }
            time.sleep(1)
        raise RuntimeError(
            f"P5-B4 checkpoint projections did not converge: {sorted(latest)}"
        )
