from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from scripts.p5b4_multivm_checkpoint_gate import (
    DEFAULT_BACKEND_PORT,
    DEFAULT_REMOTE_ROOT,
    PreviewNode,
    authorize,
    prepare_plan,
    run_dry_run,
    run_preflight,
    validate_plan,
)


REVISION_A = "a" * 40
REVISION_B = "b" * 40
NODES = [
    PreviewNode("vm1", "vm1", "192.168.56.4"),
    PreviewNode("vm2", "vm2", "192.168.56.5"),
    PreviewNode("vm3", "vm3", "192.168.56.6"),
]


def write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, sort_keys=True) + "\n")


def assets(tmp_path: Path) -> dict[str, Path]:
    backend = tmp_path / "api_only"
    backend.write_bytes(b"p5b4-backend")
    backend.chmod(0o700)
    backend_hash = hashlib.sha256(backend.read_bytes()).hexdigest()
    summary = tmp_path / "b3f-summary.json"
    write_json(
        summary,
        {
            "schema_version": "civitasos-p5b3f-real-checkpoint-fault-gate:v1",
            "status": "real_matrix_passed",
            "passed": True,
            "backend_binary_sha256": f"sha256:{backend_hash}",
            "controller_source_sha256": "sha256:controller",
            "cases": [{"passed": True} for _ in range(8)],
            "rejection_cases": [{"passed": True} for _ in range(4)],
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
        },
    )
    agent = tmp_path / "agent"
    runtime = tmp_path / "runtime"
    for relative in (
        "scripts/p5b3f_checkpoint_real_gate.py",
        "scripts/p5b3f_checkpoint_real_worker.py",
        "scripts/p5b4_multivm_checkpoint_gate.py",
    ):
        path = agent / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(relative)
    for relative in (
        "civitasos_runtime/runner.py",
        "civitasos_runtime/checkpoint_restore.py",
        "civitasos_runtime/checkpoint_runtime.py",
    ):
        path = runtime / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(relative)
    return {"backend": backend, "summary": summary, "agent": agent, "runtime": runtime}


def plan(tmp_path: Path) -> tuple[Path, dict]:
    item = assets(tmp_path)
    output = tmp_path / "plan.json"
    payload = prepare_plan(
        output=output,
        b3f_summary_path=item["summary"],
        backend_bin=item["backend"],
        agent_repo=item["agent"],
        runtime_repo=item["runtime"],
        agent_revision=REVISION_A,
        runtime_revision=REVISION_B,
        nodes=NODES,
        authoritative_node="vm1",
        remote_root=DEFAULT_REMOTE_ROOT,
        backend_port=DEFAULT_BACKEND_PORT,
        operator_id="test-operator",
    )
    return output, payload


def clean_repo_probe(path: Path) -> tuple[str, bool]:
    return (REVISION_A if path.name == "agent" else REVISION_B), True


def tool_probe(tool: str) -> str:
    return f"/usr/bin/{tool}"


def closed_p4_root(tmp_path: Path) -> Path:
    root = tmp_path / "p4-run"
    stage = root / "stage-24h"
    stage.mkdir(parents=True)
    write_json(stage / "summary.json", {"status": "passed", "passed": True})
    return root


def test_plan_binds_prerequisite_candidate_nodes_and_nonclaims(tmp_path: Path) -> None:
    output, payload = plan(tmp_path)

    validate_plan(payload)
    assert payload["authoritative_node"] == "vm1"
    assert [node["node_id"] for node in payload["nodes"]] == ["vm1", "vm2", "vm3"]
    assert len(payload["fault_matrix"]) == 6
    assert payload["acceptance"]["real_agent_runner_started"] is True
    assert payload["acceptance"]["six_domain_version_mixing"] is False
    assert payload["remote_execution_authorized"] is False
    assert payload["vm_contact_performed"] is False
    assert output.stat().st_mode & 0o777 == 0o600


def test_plan_rejects_p4_resources_and_invalid_b3f_boundary(tmp_path: Path) -> None:
    item = assets(tmp_path)
    common = dict(
        output=tmp_path / "plan.json",
        b3f_summary_path=item["summary"],
        backend_bin=item["backend"],
        agent_repo=item["agent"],
        runtime_repo=item["runtime"],
        agent_revision=REVISION_A,
        runtime_revision=REVISION_B,
        nodes=NODES,
        authoritative_node="vm1",
        operator_id="test-operator",
    )
    with pytest.raises(ValueError, match="overlaps P4"):
        prepare_plan(**common, remote_root=DEFAULT_REMOTE_ROOT, backend_port=18444)

    summary = json.loads(item["summary"].read_text())
    summary["agent_runner_started"] = True
    write_json(item["summary"], summary)
    with pytest.raises(ValueError, match="prerequisite"):
        prepare_plan(**common, remote_root=DEFAULT_REMOTE_ROOT, backend_port=DEFAULT_BACKEND_PORT)


def test_plan_tampering_is_detected(tmp_path: Path) -> None:
    output, _payload = plan(tmp_path)
    tampered = json.loads(output.read_text())
    tampered["backend_port"] += 1
    with pytest.raises(ValueError, match="plan validation failed"):
        validate_plan(tampered)


def test_preflight_defers_for_active_p4_without_vm_contact(tmp_path: Path) -> None:
    plan_path, _payload = plan(tmp_path)
    output = tmp_path / "preflight.json"
    report = run_preflight(
        plan_path=plan_path,
        output=output,
        repository_probe=clean_repo_probe,
        active_process_probe=lambda: [{"pid": 10, "script": "p4eg_tls_soak.py"}],
        tool_probe=tool_probe,
    )

    assert report["local_preflight_passed"] is True
    assert report["execution_ready"] is False
    assert report["blockers"] == [
        "active_p4_soak_processes",
        "p4_24h_soak_closure_not_provided",
    ]
    assert report["vm_contact_performed"] is False
    assert report["network_probe_performed"] is False
    assert output.stat().st_mode & 0o777 == 0o600


def test_dry_run_is_offline_and_preserves_p4_resources(tmp_path: Path) -> None:
    plan_path, _payload = plan(tmp_path)
    preflight_path = tmp_path / "preflight.json"
    run_preflight(
        plan_path=plan_path,
        output=preflight_path,
        p4_run_root=closed_p4_root(tmp_path),
        repository_probe=clean_repo_probe,
        active_process_probe=lambda: [],
        tool_probe=tool_probe,
    )
    output = tmp_path / "dry-run.json"
    report = run_dry_run(
        plan_path=plan_path,
        preflight_path=preflight_path,
        output=output,
    )

    assert report["dry_run_passed"] is True
    assert report["execution_decision"] == "ready_for_separate_single_use_authorization"
    assert report["execution_performed"] is False
    assert report["vm_contact_performed"] is False
    assert report["cleanup_invariants"]["preserve_p4_ports"] == [18443, 18444]
    assert len(report["phase_preview"]) == 11


def test_authorization_is_single_use_bound_and_refuses_active_soak(tmp_path: Path) -> None:
    plan_path, _payload = plan(tmp_path)
    preflight_path = tmp_path / "preflight.json"
    run_preflight(
        plan_path=plan_path,
        output=preflight_path,
        p4_run_root=closed_p4_root(tmp_path),
        repository_probe=clean_repo_probe,
        active_process_probe=lambda: [],
        tool_probe=tool_probe,
    )
    with pytest.raises(ValueError, match="P4 soak is active"):
        authorize(
            plan_path=plan_path,
            preflight_path=preflight_path,
            output=tmp_path / "auth.json",
            operator_id="test-operator",
            ttl_seconds=3600,
            acknowledged=True,
            active_process_probe=lambda: [{"pid": 10}],
            repository_probe=clean_repo_probe,
            tool_probe=tool_probe,
        )

    output = tmp_path / "auth.json"
    authorization = authorize(
        plan_path=plan_path,
        preflight_path=preflight_path,
        output=output,
        operator_id="test-operator",
        ttl_seconds=3600,
        acknowledged=True,
        active_process_probe=lambda: [],
        repository_probe=clean_repo_probe,
        tool_probe=tool_probe,
    )
    assert authorization["single_use"] is True
    assert authorization["consumed"] is False
    assert authorization["remote_execution_allowed"] is True
    assert authorization["public_ingress_allowed"] is False
    assert authorization["vm_contact_performed"] is False
    assert output.stat().st_mode & 0o777 == 0o600
