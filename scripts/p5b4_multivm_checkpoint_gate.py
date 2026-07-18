#!/usr/bin/env python3
"""Prepare the offline P5-B4 multi-VM checkpoint gate control plane."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path, PurePosixPath
from typing import Any, Callable

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from beta5_real_multivm_preview_prepare import PreviewNode, parse_node  # noqa: E402


PLAN_SCHEMA = "civitasos-p5b4-multivm-checkpoint-plan:v1"
PREFLIGHT_SCHEMA = "civitasos-p5b4-multivm-checkpoint-preflight:v1"
DRY_RUN_SCHEMA = "civitasos-p5b4-multivm-checkpoint-dry-run:v1"
AUTH_SCHEMA = "civitasos-p5b4-multivm-checkpoint-authorization:v1"
B3F_SCHEMA = "civitasos-p5b3f-real-checkpoint-fault-gate:v1"
DEFAULT_NODES = (
    "vm1,vm1,192.168.56.4",
    "vm2,vm2,192.168.56.5",
    "vm3,vm3,192.168.56.6",
)
EXPECTED_NODE_IDS = ("vm1", "vm2", "vm3")
P4_PORTS = {18443, 18444}
DEFAULT_BACKEND_PORT = 19454
DEFAULT_REMOTE_ROOT = "/tmp/civitasos-p5b4-checkpoint"
DEFAULT_PARTITION_COMMENT = "civitasos-p5b4-partition"
REQUIRED_LOCAL_TOOLS = ("ssh", "scp", "openssl")
REVISION_PATTERN = re.compile(r"[0-9a-f]{40}")

FAULT_MATRIX = (
    {
        "case_id": "authoritative_backend_sigkill_before_activation_ack",
        "target": "authoritative",
        "fault": "backend_process_sigkill",
        "acceptance": "restore retry yields one activation Fact and one stable Receipt",
    },
    {
        "case_id": "agent_runner_sigkill_after_runtime_sqlite_commit",
        "target": "authoritative",
        "fault": "agent_runner_process_sigkill",
        "acceptance": "no pre-activation tick side effect and restart resumes the same intent",
    },
    {
        "case_id": "authoritative_node_reboot_after_activation",
        "target": "authoritative",
        "fault": "vm_reboot",
        "acceptance": "sled, SQLite, Receipt and Evidence survive node reboot",
    },
    {
        "case_id": "follower_partition_during_projection",
        "target": "vm3",
        "fault": "bounded_network_partition",
        "acceptance": "partitioned follower cannot activate a mixed or partial checkpoint",
    },
    {
        "case_id": "stale_sequence_replay_after_heal",
        "target": "vm2",
        "fault": "stale_checkpoint_replay",
        "acceptance": "stale sequence is rejected after authoritative state converges",
    },
    {
        "case_id": "credential_rotation_during_remote_restore",
        "target": "authoritative",
        "fault": "credential_rotation",
        "acceptance": "old credential cannot finish restore and no activation Receipt exists",
    },
)

PHASES = (
    ("local_preflight", False, "local plan, assets, tools and isolation checks"),
    ("deploy_isolated_candidate", True, "hash-bound candidate on three isolated VM roots"),
    ("capture_authoritative_checkpoint", False, "one six-domain checkpoint on authoritative node"),
    ("establish_follower_projection", False, "followers observe the authoritative baseline"),
    ("restore_with_real_agent_runner", False, "real AgentRunner remains latched until activation"),
    ("process_kill_retry_matrix", True, "backend and AgentRunner kill/retry cases"),
    ("authoritative_node_reboot", True, "authoritative VM reboot and durable recovery"),
    ("partition_follower", True, "bounded vm3 partition with tagged firewall rules"),
    ("heal_and_reject_stale_replay", True, "remove only tagged rules and reject stale replay"),
    ("converge_receipt_evidence", False, "Fact, Receipt, Evidence and journal convergence"),
    ("cleanup_and_verify", True, "remove B4 services, state and tagged network rules"),
)

AGENT_SOURCE_FILES = (
    "scripts/p5b3f_checkpoint_real_gate.py",
    "scripts/p5b3f_checkpoint_real_worker.py",
    "scripts/p5b4_multivm_checkpoint_gate.py",
)
RUNTIME_SOURCE_FILES = (
    "civitasos_runtime/runner.py",
    "civitasos_runtime/checkpoint_restore.py",
    "civitasos_runtime/checkpoint_runtime.py",
)


def now() -> int:
    return int(time.time())


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical_digest(payload: dict[str, Any], omitted: str) -> str:
    material = {key: value for key, value in payload.items() if key != omitted}
    encoded = json.dumps(material, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def write_private_json(path: Path, payload: dict[str, Any]) -> None:
    if path.exists():
        raise ValueError(f"refusing to overwrite P5-B4 artifact: {path}")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def _validate_revision(name: str, revision: str) -> None:
    if not REVISION_PATTERN.fullmatch(revision):
        raise ValueError(f"{name} revision must be a full 40-character Git SHA")


def git_snapshot(repo: Path) -> tuple[str, bool]:
    resolved = repo.expanduser().resolve()
    revision = subprocess.run(
        ["git", "-C", str(resolved), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    dirty = subprocess.run(
        ["git", "-C", str(resolved), "status", "--porcelain"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    _validate_revision(resolved.name, revision)
    return revision, not bool(dirty)


def _source_hashes(root: Path, relative_paths: tuple[str, ...]) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for relative in relative_paths:
        path = root / relative
        if not path.is_file():
            raise ValueError(f"P5-B4 required source file is missing: {path}")
        hashes[relative] = sha256(path)
    return hashes


def validate_nodes(nodes: list[PreviewNode], authoritative_node: str) -> None:
    if tuple(sorted(node.node_id for node in nodes)) != EXPECTED_NODE_IDS:
        raise ValueError("P5-B4 requires exactly vm1, vm2 and vm3")
    if authoritative_node not in EXPECTED_NODE_IDS:
        raise ValueError("P5-B4 authoritative node must be vm1, vm2 or vm3")
    if len({node.ssh_host for node in nodes}) != 3:
        raise ValueError("P5-B4 SSH hosts must be distinct")
    if len({node.node_ip for node in nodes}) != 3:
        raise ValueError("P5-B4 node addresses must be distinct")
    for node in nodes:
        address = ipaddress.ip_address(node.node_ip)
        if address.is_loopback or address.is_unspecified or address.is_multicast:
            raise ValueError(f"P5-B4 node address is not usable: {node.node_ip}")


def validate_isolation(remote_root: str, backend_port: int, paths: list[Path]) -> None:
    root = PurePosixPath(remote_root)
    if not root.is_absolute() or str(root) in {"/", "/tmp", "/home"}:
        raise ValueError("P5-B4 remote root must be a dedicated absolute directory")
    lowered = str(root).lower()
    if any(marker in lowered for marker in ("p4eg", "p4ef", "p4-soak", "p4_soak")):
        raise ValueError("P5-B4 remote root must not reference P4 resources")
    if backend_port in P4_PORTS or not 1024 <= backend_port <= 65535:
        raise ValueError("P5-B4 backend port is invalid or overlaps P4")
    for path in paths:
        parts = (part.lower() for part in path.expanduser().resolve().parts)
        if any(part.startswith("p4eg-") or part.startswith("p4ef-") for part in parts):
            raise ValueError(f"P5-B4 local asset must not reference P4 resources: {path}")


def validate_b3f_summary(summary: dict[str, Any], backend_hash: str) -> None:
    required = {
        "schema_version": B3F_SCHEMA,
        "status": "real_matrix_passed",
        "passed": True,
        "local_synthetic_only": False,
        "network_scope": "loopback_only",
        "real_tls_executed": True,
        "backend_sled_executed": True,
        "runtime_sqlite_executed": True,
        "real_rejection_matrix_executed": True,
        "tick_probe_only": True,
        "agent_runner_started": False,
        "p4_soak_resources_used": False,
        "externally_verified": False,
        "production_evidence": False,
    }
    failed = [name for name, expected in required.items() if summary.get(name) != expected]
    recorded_hash = str(summary.get("backend_binary_sha256", "")).removeprefix("sha256:")
    if recorded_hash != backend_hash:
        failed.append("backend_binary_sha256")
    cases = summary.get("cases")
    rejections = summary.get("rejection_cases")
    if not isinstance(cases, list) or len(cases) != 8 or not all(case.get("passed") for case in cases):
        failed.append("positive_matrix")
    if not isinstance(rejections, list) or len(rejections) != 4 or not all(
        case.get("passed") for case in rejections
    ):
        failed.append("rejection_matrix")
    if failed:
        raise ValueError(f"P5-B3f prerequisite validation failed: {sorted(set(failed))}")


def prepare_plan(
    *,
    output: Path,
    b3f_summary_path: Path,
    backend_bin: Path,
    agent_repo: Path,
    runtime_repo: Path,
    agent_revision: str,
    runtime_revision: str,
    nodes: list[PreviewNode],
    authoritative_node: str,
    remote_root: str,
    backend_port: int,
    operator_id: str,
    partition_comment: str = DEFAULT_PARTITION_COMMENT,
) -> dict[str, Any]:
    summary_path = b3f_summary_path.expanduser().resolve()
    binary = backend_bin.expanduser().resolve()
    agent_root = agent_repo.expanduser().resolve()
    runtime_root = runtime_repo.expanduser().resolve()
    if not summary_path.is_file() or not binary.is_file() or not os.access(binary, os.X_OK):
        raise ValueError("P5-B4 requires an existing B3f summary and executable Backend")
    _validate_revision("agent", agent_revision)
    _validate_revision("runtime", runtime_revision)
    validate_nodes(nodes, authoritative_node)
    validate_isolation(remote_root, backend_port, [summary_path, binary, output])
    if not operator_id.strip():
        raise ValueError("P5-B4 operator id is required")
    if not re.fullmatch(r"[a-zA-Z0-9._:-]+", partition_comment):
        raise ValueError("P5-B4 partition comment contains unsupported characters")

    backend_hash = sha256(binary)
    summary = load_json(summary_path)
    validate_b3f_summary(summary, backend_hash)
    payload: dict[str, Any] = {
        "schema_version": PLAN_SCHEMA,
        "created_at": now(),
        "operator_id": operator_id,
        "prerequisite": {
            "b3f_summary_path": str(summary_path),
            "b3f_summary_sha256": sha256(summary_path),
            "b3f_status": summary["status"],
            "b3f_controller_source_sha256": summary["controller_source_sha256"],
        },
        "candidate": {
            "backend_binary_path": str(binary),
            "backend_binary_sha256": backend_hash,
            "agent_repo": str(agent_root),
            "agent_revision": agent_revision,
            "agent_source_sha256": _source_hashes(agent_root, AGENT_SOURCE_FILES),
            "runtime_repo": str(runtime_root),
            "runtime_revision": runtime_revision,
            "runtime_source_sha256": _source_hashes(runtime_root, RUNTIME_SOURCE_FILES),
        },
        "nodes": [node.__dict__ for node in sorted(nodes, key=lambda item: item.node_id)],
        "authoritative_node": authoritative_node,
        "partitioned_follower": "vm3" if authoritative_node != "vm3" else "vm2",
        "remote_root": remote_root,
        "backend_port": backend_port,
        "partition_comment": partition_comment,
        "phases": [
            {
                "ordinal": ordinal,
                "phase_id": phase_id,
                "disruptive": disruptive,
                "expected_evidence": evidence,
            }
            for ordinal, (phase_id, disruptive, evidence) in enumerate(PHASES, start=1)
        ],
        "fault_matrix": list(FAULT_MATRIX),
        "acceptance": {
            "real_agent_runner_started": True,
            "activation_fact_exactly_once": True,
            "checkpoint_receipt_stable": True,
            "evidence_manifest_stable": True,
            "six_domain_version_mixing": False,
            "pre_activation_side_effects": 0,
            "stale_sequence_accepted": False,
            "fact_integrity_valid_all_nodes": True,
            "cleanup_complete_all_nodes": True,
            "audit_continuity_valid": True,
        },
        "isolation": {
            "forbidden_ports": sorted(P4_PORTS),
            "forbidden_resource_markers": ["p4eg", "p4ef", "p4-soak", "p4_soak"],
            "requires_tagged_partition_rules": True,
            "requires_exact_remote_root_cleanup": True,
        },
        "authorization_required": True,
        "remote_execution_authorized": False,
        "vm_contact_performed": False,
        "network_mutation_performed": False,
        "public_ingress_allowed": False,
        "production_data_allowed": False,
        "production_evidence_allowed": False,
        "externally_verified": False,
    }
    payload["plan_id"] = f"p5b4-plan:{canonical_digest(payload, 'plan_id')[:24]}"
    write_private_json(output.expanduser().resolve(), payload)
    return payload


def validate_plan(plan: dict[str, Any]) -> None:
    failures: list[str] = []
    if plan.get("schema_version") != PLAN_SCHEMA:
        failures.append("schema_version")
    expected_id = f"p5b4-plan:{canonical_digest(plan, 'plan_id')[:24]}"
    if plan.get("plan_id") != expected_id:
        failures.append("plan_id")
    try:
        nodes = [PreviewNode(**node) for node in plan.get("nodes", [])]
        validate_nodes(nodes, str(plan.get("authoritative_node", "")))
        candidate = plan["candidate"]
        prerequisite = plan["prerequisite"]
        binary = Path(candidate["backend_binary_path"])
        summary_path = Path(prerequisite["b3f_summary_path"])
        validate_isolation(
            str(plan["remote_root"]), int(plan["backend_port"]), [binary, summary_path]
        )
        if sha256(binary) != candidate["backend_binary_sha256"]:
            failures.append("backend_binary_sha256")
        if sha256(summary_path) != prerequisite["b3f_summary_sha256"]:
            failures.append("b3f_summary_sha256")
        validate_b3f_summary(load_json(summary_path), candidate["backend_binary_sha256"])
        for root_key, hashes_key in (
            ("agent_repo", "agent_source_sha256"),
            ("runtime_repo", "runtime_source_sha256"),
        ):
            root = Path(candidate[root_key])
            for relative, expected in candidate[hashes_key].items():
                if sha256(root / relative) != expected:
                    failures.append(f"{hashes_key}:{relative}")
    except (KeyError, TypeError, ValueError, OSError) as error:
        failures.append(f"structure:{error}")
    expected_boundaries = {
        "authorization_required": True,
        "remote_execution_authorized": False,
        "vm_contact_performed": False,
        "network_mutation_performed": False,
        "public_ingress_allowed": False,
        "production_data_allowed": False,
        "production_evidence_allowed": False,
        "externally_verified": False,
    }
    failures.extend(
        key for key, expected in expected_boundaries.items() if plan.get(key) != expected
    )
    if failures:
        raise ValueError(f"P5-B4 plan validation failed: {failures}")


def detect_active_p4_processes() -> list[dict[str, Any]]:
    active: list[dict[str, Any]] = []
    for command_path in Path("/proc").glob("[0-9]*/cmdline"):
        try:
            arguments = [
                part.decode(errors="replace")
                for part in command_path.read_bytes().split(b"\0")
                if part
            ]
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
        script = next(
            (
                Path(argument).name
                for argument in arguments
                if Path(argument).name in {"p4eg_soak_chain.py", "p4eg_tls_soak.py"}
            ),
            None,
        )
        if script and "execute" in arguments:
            active.append({"pid": int(command_path.parent.name), "script": script})
    return sorted(active, key=lambda item: item["pid"])


def inspect_p4_run_root(run_root: Path | None) -> dict[str, Any]:
    if run_root is None:
        return {"configured": False, "closed": False, "passed": False}
    root = run_root.expanduser().resolve()
    summary_path = root / "stage-24h" / "summary.json"
    latest_round: dict[str, Any] | None = None
    rounds_path = root / "stage-24h" / "rounds.jsonl"
    if rounds_path.is_file():
        lines = [line for line in rounds_path.read_text().splitlines() if line.strip()]
        if lines:
            candidate = json.loads(lines[-1])
            latest_round = {
                "round": candidate.get("round"),
                "passed": candidate.get("passed"),
                "recorded_at": candidate.get("recorded_at"),
            }
    if not summary_path.is_file():
        return {
            "configured": True,
            "run_root": str(root),
            "closed": False,
            "passed": False,
            "latest_round": latest_round,
        }
    summary = load_json(summary_path)
    return {
        "configured": True,
        "run_root": str(root),
        "closed": summary.get("status") in {"passed", "completed"} or summary.get("passed") is True,
        "passed": summary.get("passed") is True,
        "summary_sha256": sha256(summary_path),
        "latest_round": latest_round,
    }


def run_preflight(
    *,
    plan_path: Path,
    output: Path,
    p4_run_root: Path | None = None,
    repository_probe: Callable[[Path], tuple[str, bool]] = git_snapshot,
    active_process_probe: Callable[[], list[dict[str, Any]]] = detect_active_p4_processes,
    tool_probe: Callable[[str], str | None] = shutil.which,
) -> dict[str, Any]:
    resolved_plan = plan_path.expanduser().resolve()
    plan = load_json(resolved_plan)
    validate_plan(plan)
    candidate = plan["candidate"]
    agent_revision, agent_clean = repository_probe(Path(candidate["agent_repo"]))
    runtime_revision, runtime_clean = repository_probe(Path(candidate["runtime_repo"]))
    tools = {tool: tool_probe(tool) for tool in REQUIRED_LOCAL_TOOLS}
    checks = {
        "plan_integrity": True,
        "backend_asset_integrity": True,
        "b3f_prerequisite_integrity": True,
        "agent_revision_matches": agent_revision == candidate["agent_revision"],
        "agent_worktree_clean": agent_clean,
        "runtime_revision_matches": runtime_revision == candidate["runtime_revision"],
        "runtime_worktree_clean": runtime_clean,
        "required_local_tools_present": all(tools.values()),
        "p4_resource_overlap_absent": True,
    }
    active = active_process_probe()
    p4_state = inspect_p4_run_root(p4_run_root)
    blockers: list[str] = []
    if active:
        blockers.append("active_p4_soak_processes")
    if not p4_state["configured"]:
        blockers.append("p4_24h_soak_closure_not_provided")
    elif not (p4_state["closed"] and p4_state["passed"]):
        blockers.append("p4_24h_soak_not_closed")
    local_passed = all(checks.values())
    if not local_passed:
        blockers.append("local_preflight_failed")
    payload: dict[str, Any] = {
        "schema_version": PREFLIGHT_SCHEMA,
        "checked_at": now(),
        "plan_id": plan["plan_id"],
        "plan_path": str(resolved_plan),
        "plan_sha256": sha256(resolved_plan),
        "checks": checks,
        "local_tools": tools,
        "active_p4_processes": active,
        "p4_state": p4_state,
        "blockers": blockers,
        "local_preflight_passed": local_passed,
        "execution_ready": local_passed and not blockers,
        "status": "ready_for_authorization" if local_passed and not blockers else "deferred",
        "authorization_issued": False,
        "vm_contact_performed": False,
        "network_probe_performed": False,
        "network_mutation_performed": False,
        "production_evidence": False,
    }
    payload["preflight_id"] = f"p5b4-preflight:{canonical_digest(payload, 'preflight_id')[:24]}"
    write_private_json(output.expanduser().resolve(), payload)
    return payload


def validate_preflight(preflight: dict[str, Any], plan_path: Path) -> None:
    failures: list[str] = []
    if preflight.get("schema_version") != PREFLIGHT_SCHEMA:
        failures.append("schema_version")
    expected_id = f"p5b4-preflight:{canonical_digest(preflight, 'preflight_id')[:24]}"
    if preflight.get("preflight_id") != expected_id:
        failures.append("preflight_id")
    if preflight.get("plan_sha256") != sha256(plan_path):
        failures.append("plan_sha256")
    for boundary in ("vm_contact_performed", "network_probe_performed", "network_mutation_performed"):
        if preflight.get(boundary) is not False:
            failures.append(boundary)
    if failures:
        raise ValueError(f"P5-B4 preflight validation failed: {failures}")


def run_dry_run(*, plan_path: Path, preflight_path: Path, output: Path) -> dict[str, Any]:
    resolved_plan = plan_path.expanduser().resolve()
    resolved_preflight = preflight_path.expanduser().resolve()
    plan = load_json(resolved_plan)
    preflight = load_json(resolved_preflight)
    validate_plan(plan)
    validate_preflight(preflight, resolved_plan)
    if preflight.get("plan_id") != plan.get("plan_id"):
        raise ValueError("P5-B4 dry-run plan/preflight binding mismatch")
    ready = preflight.get("execution_ready") is True
    payload: dict[str, Any] = {
        "schema_version": DRY_RUN_SCHEMA,
        "created_at": now(),
        "plan_id": plan["plan_id"],
        "plan_sha256": sha256(resolved_plan),
        "preflight_id": preflight["preflight_id"],
        "preflight_sha256": sha256(resolved_preflight),
        "authoritative_node": plan["authoritative_node"],
        "nodes": [node["node_id"] for node in plan["nodes"]],
        "phase_preview": plan["phases"],
        "fault_case_preview": [case["case_id"] for case in plan["fault_matrix"]],
        "cleanup_invariants": {
            "remove_only_exact_remote_root": plan["remote_root"],
            "remove_only_partition_comment": plan["partition_comment"],
            "verify_no_remote_listener": plan["backend_port"],
            "preserve_p4_ports": sorted(P4_PORTS),
        },
        "dry_run_passed": True,
        "execution_decision": (
            "ready_for_separate_single_use_authorization"
            if ready
            else "defer_until_preflight_blockers_clear"
        ),
        "preflight_blockers": preflight.get("blockers", []),
        "authorization_issued": False,
        "authorization_consumed": False,
        "execution_performed": False,
        "vm_contact_performed": False,
        "network_probe_performed": False,
        "network_mutation_performed": False,
        "production_evidence": False,
    }
    payload["dry_run_id"] = f"p5b4-dry-run:{canonical_digest(payload, 'dry_run_id')[:24]}"
    write_private_json(output.expanduser().resolve(), payload)
    return payload


def authorize(
    *,
    plan_path: Path,
    preflight_path: Path,
    output: Path,
    operator_id: str,
    ttl_seconds: int,
    acknowledged: bool,
    active_process_probe: Callable[[], list[dict[str, Any]]] = detect_active_p4_processes,
    repository_probe: Callable[[Path], tuple[str, bool]] = git_snapshot,
    tool_probe: Callable[[str], str | None] = shutil.which,
) -> dict[str, Any]:
    if not acknowledged:
        raise ValueError("explicit --ack-p5b4-disruptive-gate is required")
    if not 300 <= ttl_seconds <= 86400:
        raise ValueError("P5-B4 authorization TTL must be between 300 and 86400 seconds")
    resolved_plan = plan_path.expanduser().resolve()
    resolved_preflight = preflight_path.expanduser().resolve()
    plan = load_json(resolved_plan)
    preflight = load_json(resolved_preflight)
    validate_plan(plan)
    validate_preflight(preflight, resolved_plan)
    if preflight.get("plan_id") != plan.get("plan_id"):
        raise ValueError("P5-B4 authorization plan/preflight binding mismatch")
    if preflight.get("execution_ready") is not True or preflight.get("blockers"):
        raise ValueError("P5-B4 preflight is not ready for disruptive authorization")
    if active_process_probe():
        raise ValueError("P5-B4 authorization refused while P4 soak is active")
    candidate = plan["candidate"]
    for name in ("agent", "runtime"):
        revision, clean = repository_probe(Path(candidate[f"{name}_repo"]))
        if revision != candidate[f"{name}_revision"] or not clean:
            raise ValueError(f"P5-B4 authorization refused for changed {name} candidate")
    if not all(tool_probe(tool) for tool in REQUIRED_LOCAL_TOOLS):
        raise ValueError("P5-B4 authorization refused because local tools changed")
    if operator_id != plan.get("operator_id"):
        raise ValueError("P5-B4 authorization operator does not match the plan")
    issued_at = now()
    payload: dict[str, Any] = {
        "schema_version": AUTH_SCHEMA,
        "issued_at": issued_at,
        "expires_at": issued_at + ttl_seconds,
        "single_use": True,
        "consumed": False,
        "operator_id": operator_id,
        "plan_id": plan["plan_id"],
        "plan_sha256": sha256(resolved_plan),
        "preflight_id": preflight["preflight_id"],
        "preflight_sha256": sha256(resolved_preflight),
        "nodes": [node["node_id"] for node in plan["nodes"]],
        "authoritative_node": plan["authoritative_node"],
        "remote_root": plan["remote_root"],
        "backend_port": plan["backend_port"],
        "operations": [phase["phase_id"] for phase in plan["phases"] if phase["ordinal"] > 1],
        "fault_cases": [case["case_id"] for case in plan["fault_matrix"]],
        "remote_execution_allowed": True,
        "public_ingress_allowed": False,
        "production_data_allowed": False,
        "production_evidence_allowed": False,
        "vm_contact_performed": False,
    }
    material = canonical_digest(payload, "authorization_id")
    payload["authorization_id"] = f"p5b4-auth:{material[:24]}"
    write_private_json(output.expanduser().resolve(), payload)
    return payload


def _nodes(raw_nodes: list[str]) -> list[PreviewNode]:
    return [parse_node(raw) for raw in (raw_nodes or DEFAULT_NODES)]


def _prepare_command(args: argparse.Namespace) -> dict[str, Any]:
    if not args.ack_offline_p5b4_plan:
        raise ValueError("explicit --ack-offline-p5b4-plan is required")
    agent_revision, agent_clean = git_snapshot(Path(args.agent_repo))
    runtime_revision, runtime_clean = git_snapshot(Path(args.runtime_repo))
    if not agent_clean or not runtime_clean:
        raise ValueError("P5-B4 candidate repositories must have clean worktrees")
    return prepare_plan(
        output=Path(args.output),
        b3f_summary_path=Path(args.b3f_summary),
        backend_bin=Path(args.backend_bin),
        agent_repo=Path(args.agent_repo),
        runtime_repo=Path(args.runtime_repo),
        agent_revision=agent_revision,
        runtime_revision=runtime_revision,
        nodes=_nodes(args.node),
        authoritative_node=args.authoritative_node,
        remote_root=args.remote_root,
        backend_port=args.backend_port,
        operator_id=args.operator_id,
        partition_comment=args.partition_comment,
    )


def _preflight_command(args: argparse.Namespace) -> dict[str, Any]:
    return run_preflight(
        plan_path=Path(args.plan),
        output=Path(args.output),
        p4_run_root=Path(args.p4_run_root) if args.p4_run_root else None,
    )


def _dry_run_command(args: argparse.Namespace) -> dict[str, Any]:
    return run_dry_run(
        plan_path=Path(args.plan),
        preflight_path=Path(args.preflight),
        output=Path(args.output),
    )


def _authorize_command(args: argparse.Namespace) -> dict[str, Any]:
    return authorize(
        plan_path=Path(args.plan),
        preflight_path=Path(args.preflight),
        output=Path(args.output),
        operator_id=args.operator_id,
        ttl_seconds=args.ttl_seconds,
        acknowledged=args.ack_p5b4_disruptive_gate,
    )


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    commands = root.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("prepare")
    prepare.add_argument("--output", required=True)
    prepare.add_argument("--b3f-summary", required=True)
    prepare.add_argument("--backend-bin", required=True)
    prepare.add_argument("--agent-repo", required=True)
    prepare.add_argument("--runtime-repo", required=True)
    prepare.add_argument("--node", action="append", default=[])
    prepare.add_argument("--authoritative-node", default="vm1")
    prepare.add_argument("--remote-root", default=DEFAULT_REMOTE_ROOT)
    prepare.add_argument("--backend-port", type=int, default=DEFAULT_BACKEND_PORT)
    prepare.add_argument("--operator-id", default="local-operator-cc")
    prepare.add_argument("--partition-comment", default=DEFAULT_PARTITION_COMMENT)
    prepare.add_argument("--ack-offline-p5b4-plan", action="store_true")
    prepare.set_defaults(func=_prepare_command)

    preflight = commands.add_parser("preflight")
    preflight.add_argument("--plan", required=True)
    preflight.add_argument("--output", required=True)
    preflight.add_argument("--p4-run-root", required=True)
    preflight.set_defaults(func=_preflight_command)

    dry_run = commands.add_parser("dry-run")
    dry_run.add_argument("--plan", required=True)
    dry_run.add_argument("--preflight", required=True)
    dry_run.add_argument("--output", required=True)
    dry_run.set_defaults(func=_dry_run_command)

    auth = commands.add_parser("authorize")
    auth.add_argument("--plan", required=True)
    auth.add_argument("--preflight", required=True)
    auth.add_argument("--output", required=True)
    auth.add_argument("--operator-id", default="local-operator-cc")
    auth.add_argument("--ttl-seconds", type=int, default=3600)
    auth.add_argument("--ack-p5b4-disruptive-gate", action="store_true")
    auth.set_defaults(func=_authorize_command)
    return root


def main() -> int:
    args = parser().parse_args()
    try:
        result = args.func(args)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        raise SystemExit(str(error)) from error
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
