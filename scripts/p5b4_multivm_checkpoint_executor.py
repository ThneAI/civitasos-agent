#!/usr/bin/env python3
"""Execute a hash-bound P5-B4 multi-VM checkpoint Gate authorization."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shlex
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Protocol

from p5b4_multivm_checkpoint_gate import (
    AUTH_SCHEMA,
    P4_PORTS,
    PreviewNode,
    canonical_digest,
    detect_active_p4_processes,
    git_snapshot,
    load_json,
    sha256,
    validate_plan,
    validate_preflight,
)


EXECUTION_SCHEMA = "civitasos-p5b4-multivm-checkpoint-execution:v1"
CLAIM_SCHEMA = "civitasos-p5b4-multivm-checkpoint-claim:v1"
JOURNAL_SCHEMA = "civitasos-p5b4-multivm-checkpoint-journal:v1"
SUMMARY_SCHEMA = "civitasos-p5b4-multivm-checkpoint-summary:v1"
EXECUTION_ACK_ENV = "CIVITASOS_P5B4_MULTIVM_EXECUTION_ACK"
ZERO_HASH = "0" * 64


def _now() -> int:
    return int(time.time())


def _canonical_bytes(payload: dict[str, Any], omitted: str | None = None) -> bytes:
    material = {key: value for key, value in payload.items() if key != omitted}
    return json.dumps(material, sort_keys=True, separators=(",", ":")).encode()


def _private_write_once(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w") as stream:
            stream.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


@dataclass(frozen=True)
class RemoteResult:
    stdout: str
    stderr: str = ""


class RemoteTransport(Protocol):
    def copy(self, node: PreviewNode, source: Path, destination: str) -> None: ...

    def run(self, node: PreviewNode, script: str, *, timeout: int) -> RemoteResult: ...


class SubprocessRemoteTransport:
    """SSH transport used only after the execution authorization is consumed."""

    def __init__(self, *, ssh_config: Path | None = None) -> None:
        self._ssh_config = ssh_config

    def _ssh_prefix(self) -> list[str]:
        command = ["ssh"]
        if self._ssh_config is not None:
            command.extend(["-F", str(self._ssh_config)])
        command.extend(["-o", "BatchMode=yes", "-o", "ConnectTimeout=8"])
        return command

    def copy(self, node: PreviewNode, source: Path, destination: str) -> None:
        command = ["scp"]
        if self._ssh_config is not None:
            command.extend(["-F", str(self._ssh_config)])
        command.extend(
            ["-o", "BatchMode=yes", "-o", "ConnectTimeout=8", str(source), f"{node.ssh_host}:{destination}"]
        )
        subprocess.run(command, check=True, capture_output=True, text=True, timeout=120)

    def run(self, node: PreviewNode, script: str, *, timeout: int) -> RemoteResult:
        completed = subprocess.run(
            [*self._ssh_prefix(), node.ssh_host, "bash -s"],
            input=script,
            check=True,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return RemoteResult(completed.stdout, completed.stderr)


class ExecutionJournal:
    """Append-only, hash-chained execution evidence."""

    def __init__(self, path: Path, execution_id: str) -> None:
        self.path = path
        self.execution_id = execution_id
        self.entries = self._load()

    def _load(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        entries: list[dict[str, Any]] = []
        previous_hash = ZERO_HASH
        for line_number, line in enumerate(self.path.read_text().splitlines(), start=1):
            if not line.strip():
                raise ValueError(f"P5-B4 journal contains a blank line at {line_number}")
            entry = json.loads(line)
            expected_hash = hashlib.sha256(_canonical_bytes(entry, "entry_hash")).hexdigest()
            failures = []
            if entry.get("schema_version") != JOURNAL_SCHEMA:
                failures.append("schema_version")
            if entry.get("execution_id") != self.execution_id:
                failures.append("execution_id")
            if entry.get("sequence") != line_number:
                failures.append("sequence")
            if entry.get("previous_hash") != previous_hash:
                failures.append("previous_hash")
            if entry.get("entry_hash") != expected_hash:
                failures.append("entry_hash")
            if failures:
                raise ValueError(f"P5-B4 journal validation failed at {line_number}: {failures}")
            entries.append(entry)
            previous_hash = expected_hash
        return entries

    def append(self, *, event: str, phase_id: str | None, evidence: dict[str, Any]) -> dict[str, Any]:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.path.parent, 0o700)
        entry: dict[str, Any] = {
            "schema_version": JOURNAL_SCHEMA,
            "execution_id": self.execution_id,
            "sequence": len(self.entries) + 1,
            "recorded_at": _now(),
            "event": event,
            "phase_id": phase_id,
            "previous_hash": self.entries[-1]["entry_hash"] if self.entries else ZERO_HASH,
            "evidence": evidence,
        }
        entry["entry_hash"] = hashlib.sha256(_canonical_bytes(entry, "entry_hash")).hexdigest()
        descriptor = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(descriptor, "a") as stream:
            stream.write(json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        self.entries.append(entry)
        return entry

    def current_entries(self) -> list[dict[str, Any]]:
        reset_index = max(
            (
                index
                for index, entry in enumerate(self.entries)
                if entry["event"] == "execution_recovery_reset"
            ),
            default=-1,
        )
        return self.entries[reset_index + 1 :]

    def passed_phases(self) -> set[str]:
        return {
            str(entry["phase_id"])
            for entry in self.current_entries()
            if entry["event"] == "phase_passed" and entry.get("phase_id")
        }

    @property
    def terminal(self) -> bool:
        return any(entry["event"] in {"execution_passed", "execution_failed"} for entry in self.entries)


def _validate_authorization(
    *,
    authorization: dict[str, Any],
    authorization_path: Path,
    plan: dict[str, Any],
    plan_path: Path,
    preflight: dict[str, Any],
    preflight_path: Path,
    state_root: Path,
    clock: Callable[[], int],
) -> None:
    expected_id = f"p5b4-auth:{canonical_digest(authorization, 'authorization_id')[:24]}"
    expected_operations = [phase["phase_id"] for phase in plan["phases"] if phase["ordinal"] > 1]
    checks = {
        "schema_version": authorization.get("schema_version") == AUTH_SCHEMA,
        "authorization_id": authorization.get("authorization_id") == expected_id,
        "single_use": authorization.get("single_use") is True,
        "unconsumed_artifact": authorization.get("consumed") is False,
        "remote_execution_allowed": authorization.get("remote_execution_allowed") is True,
        "public_ingress_forbidden": authorization.get("public_ingress_allowed") is False,
        "production_data_forbidden": authorization.get("production_data_allowed") is False,
        "production_evidence_forbidden": authorization.get("production_evidence_allowed") is False,
        "plan_id": authorization.get("plan_id") == plan.get("plan_id"),
        "plan_sha256": authorization.get("plan_sha256") == sha256(plan_path),
        "preflight_id": authorization.get("preflight_id") == preflight.get("preflight_id"),
        "preflight_sha256": authorization.get("preflight_sha256") == sha256(preflight_path),
        "preflight_ready": preflight.get("execution_ready") is True and not preflight.get("blockers"),
        "nodes": authorization.get("nodes") == [node["node_id"] for node in plan["nodes"]],
        "authoritative_node": authorization.get("authoritative_node") == plan.get("authoritative_node"),
        "remote_root": authorization.get("remote_root") == plan.get("remote_root"),
        "backend_port": authorization.get("backend_port") == plan.get("backend_port"),
        "operations": authorization.get("operations") == expected_operations,
        "fault_cases": authorization.get("fault_cases") == [case["case_id"] for case in plan["fault_matrix"]],
        "claim_path": authorization.get("claim_path") == str(authorization_path.with_suffix(".claim.json")),
        "materials_manifest_sha256": authorization.get("materials_manifest_sha256")
        == plan["candidate"].get("materials_manifest_sha256"),
        "material_file_sha256": authorization.get("material_file_sha256")
        == plan["candidate"].get("material_file_sha256"),
    }
    claim_path = Path(str(authorization.get("claim_path", "")))
    if not claim_path.exists():
        checks["fresh"] = int(authorization.get("issued_at", 0)) <= clock() <= int(
            authorization.get("expires_at", 0)
        )
    if state_root.resolve() in {Path("/"), Path("/tmp"), Path.home()}:
        checks["dedicated_state_root"] = False
    failed = [name for name, passed in checks.items() if not passed]
    if failed:
        raise ValueError(f"P5-B4 execution authorization validation failed: {failed}")


def _claim_authorization(
    authorization: dict[str, Any], authorization_path: Path, state_root: Path
) -> dict[str, Any]:
    claim_path = authorization_path.with_suffix(".claim.json")
    payload = {
        "schema_version": CLAIM_SCHEMA,
        "authorization_id": authorization["authorization_id"],
        "authorization_sha256": sha256(authorization_path),
        "claimed_at": _now(),
        "state_root": str(state_root),
    }
    payload["claim_id"] = f"p5b4-claim:{hashlib.sha256(_canonical_bytes(payload)).hexdigest()[:24]}"
    if claim_path.exists():
        existing = load_json(claim_path)
        stable_keys = ("schema_version", "authorization_id", "authorization_sha256", "state_root")
        if any(existing.get(key) != payload.get(key) for key in stable_keys):
            raise ValueError("P5-B4 authorization is already claimed by another execution")
        return existing
    _private_write_once(claim_path, payload)
    return payload


def _cleanup_script(plan: dict[str, Any], node: PreviewNode) -> str:
    root = shlex.quote(str(plan["remote_root"]))
    port = int(plan["backend_port"])
    comment = shlex.quote(str(plan["partition_comment"]))
    partitioned_id = str(plan["partitioned_follower"])
    partitioned = next(
        item for item in plan["nodes"] if item["node_id"] == partitioned_id
    )
    if node.node_id == partitioned_id:
        peer_ips = [
            item["node_ip"]
            for item in plan["nodes"]
            if item["node_id"] != node.node_id
        ]
    else:
        peer_ips = [partitioned["node_ip"]]
    rule_cleanup = []
    for peer_ip in peer_ips:
        for chain, direction in (("INPUT", "-s"), ("OUTPUT", "-d")):
            rule = (
                f"-p tcp {direction} {shlex.quote(peer_ip)} --dport {port} "
                f"-m comment --comment {comment} -j REJECT"
            )
            rule_cleanup.append(
                f"while sudo -n /usr/sbin/iptables -C {chain} {rule} 2>/dev/null; "
                f"do sudo -n /usr/sbin/iptables -D {chain} {rule}; done"
            )
    rule_cleanup_script = "\n".join(rule_cleanup)
    return rf"""set -euo pipefail
ROOT={root}
PORT={port}
COMMENT={comment}
if test -f "$ROOT/backend.pid"; then
  pid=$(cat "$ROOT/backend.pid")
  case "$pid" in (*[!0-9]*|'') exit 71;; esac
  if test -r "/proc/$pid/cmdline" && tr '\0' ' ' <"/proc/$pid/cmdline" | grep -F -- "$ROOT/api_only" >/dev/null; then
    kill "$pid" 2>/dev/null || true
  fi
fi
if test -f "$ROOT/runner.pid"; then
  pid=$(cat "$ROOT/runner.pid")
  case "$pid" in (*[!0-9]*|'') exit 72;; esac
  if test -r "/proc/$pid/cmdline" && tr '\0' ' ' <"/proc/$pid/cmdline" | grep -F -- "$ROOT/worker.py" >/dev/null; then
    kill "$pid" 2>/dev/null || true
  fi
fi
if test -x /usr/sbin/iptables && test -x /usr/sbin/iptables-save; then
  sudo -n /usr/sbin/iptables-save >/dev/null
{rule_cleanup_script}
fi
rm -rf -- "$ROOT"
test ! -e "$ROOT"
if command -v ss >/dev/null 2>&1; then
  ! ss -H -ltn "sport = :$PORT" | grep -q .
fi
if test -x /usr/sbin/iptables && test -x /usr/sbin/iptables-save; then
  ! sudo -n /usr/sbin/iptables-save | grep -F -- "--comment $COMMENT" >/dev/null
fi
"""


class GateExecutor:
    def __init__(
        self,
        *,
        plan: dict[str, Any],
        transport: RemoteTransport,
        journal: ExecutionJournal,
        phase_handlers: dict[str, Callable[[dict[str, Any]], dict[str, Any]]],
    ) -> None:
        self.plan = plan
        self.transport = transport
        self.journal = journal
        self.nodes = [PreviewNode(**node) for node in plan["nodes"]]
        self.phase_handlers = phase_handlers

    @staticmethod
    def _case_ids(value: Any) -> set[str]:
        if isinstance(value, dict):
            found = {
                value["case_id"]
                for key in ("case_id",)
                if isinstance(value.get(key), str)
            }
            for nested in value.values():
                found.update(GateExecutor._case_ids(nested))
            return found
        if isinstance(value, list):
            found: set[str] = set()
            for nested in value:
                found.update(GateExecutor._case_ids(nested))
            return found
        return set()

    def _acceptance_evidence(self) -> dict[str, Any]:
        expected_phases = {
            phase["phase_id"]
            for phase in self.plan["phases"]
            if phase["phase_id"] != "cleanup_and_verify"
        }
        passed_phases = self.journal.passed_phases()
        missing_phases = sorted(expected_phases - passed_phases)
        phase_evidence = [
            entry["evidence"]
            for entry in self.journal.current_entries()
            if entry["event"] == "phase_passed"
            and entry.get("phase_id") in passed_phases
        ]
        observed_cases = self._case_ids(phase_evidence)
        expected_cases = {case["case_id"] for case in self.plan["fault_matrix"]}
        missing_cases = sorted(expected_cases - observed_cases)
        if missing_phases or missing_cases:
            raise RuntimeError(
                "P5-B4 acceptance coverage failed: "
                f"missing_phases={missing_phases} missing_cases={missing_cases}"
            )
        return {
            "passed": True,
            "phase_ids": sorted(passed_phases),
            "fault_case_ids": sorted(observed_cases),
            "expected_fault_case_ids": sorted(expected_cases),
        }

    def cleanup(self) -> dict[str, Any]:
        observations: list[dict[str, Any]] = []
        failures: list[str] = []
        for node in self.nodes:
            try:
                script = _cleanup_script(self.plan, node)
                result = self.transport.run(node, script, timeout=120)
                observations.append(
                    {
                        "node_id": node.node_id,
                        "passed": True,
                        "stdout_sha256": hashlib.sha256(
                            result.stdout.encode()
                        ).hexdigest(),
                    }
                )
            except (OSError, subprocess.SubprocessError) as error:
                failures.append(f"{node.node_id}:{type(error).__name__}:{error}")
                observations.append({"node_id": node.node_id, "passed": False})
        evidence = {"all_nodes_clean": not failures, "nodes": observations, "failures": failures}
        self.journal.append(
            event="cleanup_passed" if not failures else "cleanup_failed",
            phase_id="cleanup_and_verify",
            evidence=evidence,
        )
        if failures:
            raise RuntimeError(f"P5-B4 cleanup verification failed: {failures}")
        return evidence

    def execute(self) -> dict[str, Any]:
        if self.journal.terminal:
            raise ValueError("P5-B4 execution journal is already terminal")
        if len(self.journal.entries) > 1:
            recovery_cleanup = self.cleanup()
            self.journal.append(
                event="execution_recovery_reset",
                phase_id=None,
                evidence={"cleanup": recovery_cleanup, "restart_from_phase_one": True},
            )
        passed = self.journal.passed_phases()
        failure: Exception | None = None
        cleanup_evidence: dict[str, Any] | None = None
        try:
            for phase in self.plan["phases"]:
                phase_id = phase["phase_id"]
                if phase_id in passed or phase_id == "cleanup_and_verify":
                    continue
                handler = self.phase_handlers.get(phase_id)
                if handler is None:
                    raise RuntimeError(f"P5-B4 phase handler is missing: {phase_id}")
                self.journal.append(event="phase_started", phase_id=phase_id, evidence={})
                evidence = handler(phase)
                if not isinstance(evidence, dict) or evidence.get("passed") is not True:
                    raise RuntimeError(f"P5-B4 phase did not return passing evidence: {phase_id}")
                self.journal.append(event="phase_passed", phase_id=phase_id, evidence=evidence)
            acceptance = self._acceptance_evidence()
            self.journal.append(
                event="gate_acceptance_passed",
                phase_id=None,
                evidence=acceptance,
            )
        except Exception as error:
            failure = error
            self.journal.append(
                event="phase_failed",
                phase_id=phase_id if "phase_id" in locals() else None,
                evidence={"error_type": type(error).__name__, "error": str(error)},
            )
        try:
            cleanup_evidence = self.cleanup()
        except Exception as cleanup_error:
            if failure is None:
                failure = cleanup_error
        if failure is not None:
            self.journal.append(
                event="execution_failed",
                phase_id=None,
                evidence={"error_type": type(failure).__name__, "error": str(failure)},
            )
            raise failure
        self.journal.append(
            event="execution_passed",
            phase_id=None,
            evidence={"cleanup": cleanup_evidence, "production_evidence": False},
        )
        return {"passed": True, "cleanup": cleanup_evidence}


def prepare_execution(
    *,
    authorization_path: Path,
    plan_path: Path,
    preflight_path: Path,
    state_root: Path,
    acknowledged: bool,
    environment: dict[str, str] | None = None,
    clock: Callable[[], int] = _now,
) -> tuple[dict[str, Any], dict[str, Any], ExecutionJournal]:
    if not acknowledged or (environment or os.environ).get(EXECUTION_ACK_ENV) != "1":
        raise ValueError(f"P5-B4 execution requires --ack and {EXECUTION_ACK_ENV}=1")
    resolved_auth = authorization_path.expanduser().resolve()
    resolved_plan = plan_path.expanduser().resolve()
    resolved_preflight = preflight_path.expanduser().resolve()
    resolved_state = state_root.expanduser().resolve()
    plan = load_json(resolved_plan)
    preflight = load_json(resolved_preflight)
    authorization = load_json(resolved_auth)
    validate_plan(plan)
    validate_preflight(preflight, resolved_plan)
    _validate_authorization(
        authorization=authorization,
        authorization_path=resolved_auth,
        plan=plan,
        plan_path=resolved_plan,
        preflight=preflight,
        preflight_path=resolved_preflight,
        state_root=resolved_state,
        clock=clock,
    )
    for name in ("agent", "runtime"):
        revision, clean = git_snapshot(Path(plan["candidate"][f"{name}_repo"]))
        if revision != plan["candidate"][f"{name}_revision"] or not clean:
            raise ValueError(f"P5-B4 execution refused for changed {name} candidate")
    if int(plan["backend_port"]) in P4_PORTS:
        raise ValueError("P5-B4 execution port overlaps P4")
    if detect_active_p4_processes():
        raise ValueError("P5-B4 execution refused while P4 soak is active")
    execution_id = f"p5b4-execution:{hashlib.sha256(_canonical_bytes({'authorization_id': authorization['authorization_id'], 'state_root': str(resolved_state)})).hexdigest()[:24]}"
    claim = _claim_authorization(authorization, resolved_auth, resolved_state)
    journal = ExecutionJournal(resolved_state / "journal.jsonl", execution_id)
    if not journal.entries:
        journal.append(
            event="authorization_consumed",
            phase_id=None,
            evidence={"authorization_id": authorization["authorization_id"], "claim_id": claim["claim_id"]},
        )
    return plan, authorization, journal


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    root.add_argument("--authorization", required=True)
    root.add_argument("--plan", required=True)
    root.add_argument("--preflight", required=True)
    root.add_argument("--state-root", required=True)
    root.add_argument("--ssh-config")
    root.add_argument("--ack-p5b4-multivm-execution", action="store_true")
    return root


def main() -> int:
    args = parser().parse_args()
    plan, authorization, journal = prepare_execution(
        authorization_path=Path(args.authorization),
        plan_path=Path(args.plan),
        preflight_path=Path(args.preflight),
        state_root=Path(args.state_root),
        acknowledged=args.ack_p5b4_multivm_execution,
    )
    from p5b4_multivm_phases import BuiltInPhaseHandlers

    transport = SubprocessRemoteTransport(
        ssh_config=(
            Path(args.ssh_config).expanduser().resolve() if args.ssh_config else None
        )
    )
    phases = BuiltInPhaseHandlers(
        plan=plan,
        transport=transport,
        state_root=Path(args.state_root),
    )
    result = GateExecutor(
        plan=plan,
        transport=transport,
        journal=journal,
        phase_handlers=phases.handlers(),
    ).execute()
    summary = {
        "schema_version": SUMMARY_SCHEMA,
        "execution_schema_version": EXECUTION_SCHEMA,
        "execution_id": journal.execution_id,
        "authorization_id": authorization["authorization_id"],
        "plan_id": plan["plan_id"],
        "completed_at": _now(),
        "passed": result["passed"],
        "status": "passed" if result["passed"] else "failed",
        "journal_sha256": sha256(journal.path),
        "journal_entry_count": len(journal.entries),
        "cleanup": result["cleanup"],
        "vm_contact_performed": True,
        "network_mutation_performed": True,
        "production_evidence": False,
        "externally_verified": False,
    }
    summary_path = Path(args.state_root).expanduser().resolve() / "summary.json"
    _private_write_once(summary_path, summary)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
