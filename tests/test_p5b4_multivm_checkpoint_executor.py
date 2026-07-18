from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import scripts.p5b4_multivm_checkpoint_executor as executor_module
from scripts.p5b4_multivm_checkpoint_executor import (
    EXECUTION_ACK_ENV,
    ExecutionJournal,
    GateExecutor,
    RemoteResult,
    _cleanup_script,
    prepare_execution,
)
from scripts.p5b4_multivm_checkpoint_gate import (
    DEFAULT_BACKEND_PORT,
    DEFAULT_REMOTE_ROOT,
    PreviewNode,
    authorize,
    prepare_plan,
    run_preflight,
)
from scripts.p5b4_multivm_materials import MATERIALS_SCHEMA


REVISION_A = "a" * 40
REVISION_B = "b" * 40
NODES = [
    PreviewNode("vm1", "vm1", "192.168.56.4"),
    PreviewNode("vm2", "vm2", "192.168.56.5"),
    PreviewNode("vm3", "vm3", "192.168.56.6"),
]


def _write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, sort_keys=True) + "\n")


def _fake_materials(tmp_path: Path) -> Path:
    root = tmp_path / "materials"
    root.mkdir(mode=0o700)
    names = {
        "ca.crt",
        "ca.key",
        "controller.crt",
        "controller.key",
        "jwt.secret",
        "service.secret",
        "cluster.secret",
        "identity.seed",
        *(f"{node}.{suffix}" for node in ("vm1", "vm2", "vm3") for suffix in ("crt", "key", "seed")),
    }
    files = {}
    for name in names:
        path = root / name
        path.write_text(name)
        path.chmod(0o600)
        files[name] = {"sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "mode": "0600"}
    payload = {
        "schema_version": MATERIALS_SCHEMA,
        "created_at": 1,
        "expires_after_seconds": 172800,
        "nodes": {"vm1": "192.168.56.4", "vm2": "192.168.56.5", "vm3": "192.168.56.6"},
        "trusted_peer_keys": {},
        "files": files,
        "private_material_exported_to_vm": True,
        "isolated_gate_only": True,
        "production_identity": False,
        "production_evidence": False,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    payload["materials_id"] = f"p5b4-materials:{hashlib.sha256(encoded).hexdigest()[:24]}"
    manifest = root / "manifest.json"
    _write_json(manifest, payload)
    manifest.chmod(0o600)
    return manifest


def _artifacts(tmp_path: Path) -> tuple[Path, Path, Path, Path, Path]:
    backend = tmp_path / "api_only"
    backend.write_bytes(b"p5b4-backend")
    backend.chmod(0o700)
    backend_hash = hashlib.sha256(backend.read_bytes()).hexdigest()
    summary = tmp_path / "b3f-summary.json"
    _write_json(
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
        "scripts/p5b4_multivm_checkpoint_executor.py",
        "scripts/p5b4_remote_checkpoint_worker.py",
        "scripts/p5b4_multivm_materials.py",
        "scripts/p5b4_multivm_phases.py",
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
    return backend, summary, agent, runtime, _fake_materials(tmp_path)


def _closed_p4_root(tmp_path: Path) -> Path:
    root = tmp_path / "p4-run"
    stage = root / "stage-24h"
    stage.mkdir(parents=True)
    _write_json(stage / "summary.json", {"status": "passed", "passed": True})
    return root


def _clean_repo_probe(path: Path) -> tuple[str, bool]:
    return (REVISION_A if path.name == "agent" else REVISION_B), True


def _control_plane(tmp_path: Path) -> tuple[Path, Path, Path, dict]:
    backend, summary, agent, runtime, materials = _artifacts(tmp_path)
    plan_path = tmp_path / "plan.json"
    plan = prepare_plan(
        output=plan_path,
        b3f_summary_path=summary,
        backend_bin=backend,
        materials_manifest=materials,
        agent_repo=agent,
        runtime_repo=runtime,
        agent_revision=REVISION_A,
        runtime_revision=REVISION_B,
        nodes=NODES,
        authoritative_node="vm1",
        remote_root=DEFAULT_REMOTE_ROOT,
        backend_port=DEFAULT_BACKEND_PORT,
        operator_id="test-operator",
    )
    preflight_path = tmp_path / "preflight.json"
    run_preflight(
        plan_path=plan_path,
        output=preflight_path,
        p4_run_root=_closed_p4_root(tmp_path),
        repository_probe=_clean_repo_probe,
        active_process_probe=lambda: [],
        tool_probe=lambda tool: f"/usr/bin/{tool}",
    )
    authorization_path = tmp_path / "authorization.json"
    authorize(
        plan_path=plan_path,
        preflight_path=preflight_path,
        output=authorization_path,
        operator_id="test-operator",
        ttl_seconds=3600,
        acknowledged=True,
        active_process_probe=lambda: [],
        repository_probe=_clean_repo_probe,
        tool_probe=lambda tool: f"/usr/bin/{tool}",
    )
    return authorization_path, plan_path, preflight_path, plan


def _prepare(tmp_path: Path, monkeypatch, state_name: str = "state"):
    authorization, plan, preflight, _payload = _control_plane(tmp_path)
    monkeypatch.setattr(executor_module, "git_snapshot", _clean_repo_probe)
    return prepare_execution(
        authorization_path=authorization,
        plan_path=plan,
        preflight_path=preflight,
        state_root=tmp_path / state_name,
        acknowledged=True,
        environment={EXECUTION_ACK_ENV: "1"},
    )


def test_prepare_requires_dual_ack_without_consuming_authorization(tmp_path: Path) -> None:
    authorization, plan, preflight, _payload = _control_plane(tmp_path)
    with pytest.raises(ValueError, match="requires --ack"):
        prepare_execution(
            authorization_path=authorization,
            plan_path=plan,
            preflight_path=preflight,
            state_root=tmp_path / "state",
            acknowledged=True,
            environment={},
        )
    assert not authorization.with_suffix(".claim.json").exists()


def test_prepare_consumes_once_and_resumes_same_state_after_expiry(tmp_path: Path, monkeypatch) -> None:
    plan, authorization, journal = _prepare(tmp_path, monkeypatch)
    claim_path = tmp_path / "authorization.claim.json"
    assert claim_path.is_file()
    assert journal.entries[0]["event"] == "authorization_consumed"
    assert plan["plan_id"] == authorization["plan_id"]

    resumed_plan, _authorization, resumed = prepare_execution(
        authorization_path=tmp_path / "authorization.json",
        plan_path=tmp_path / "plan.json",
        preflight_path=tmp_path / "preflight.json",
        state_root=tmp_path / "state",
        acknowledged=True,
        environment={EXECUTION_ACK_ENV: "1"},
        clock=lambda: 2**62,
    )
    assert resumed_plan["plan_id"] == plan["plan_id"]
    assert len(resumed.entries) == 1


def test_claim_refuses_replay_from_another_state_root(tmp_path: Path, monkeypatch) -> None:
    _prepare(tmp_path, monkeypatch)
    with pytest.raises(ValueError, match="already claimed"):
        prepare_execution(
            authorization_path=tmp_path / "authorization.json",
            plan_path=tmp_path / "plan.json",
            preflight_path=tmp_path / "preflight.json",
            state_root=tmp_path / "other-state",
            acknowledged=True,
            environment={EXECUTION_ACK_ENV: "1"},
        )


def test_journal_tampering_is_detected(tmp_path: Path, monkeypatch) -> None:
    _plan, _authorization, journal = _prepare(tmp_path, monkeypatch)
    value = journal.path.read_text().replace("authorization_consumed", "authorization_reused")
    journal.path.write_text(value)
    with pytest.raises(ValueError, match="entry_hash"):
        ExecutionJournal(journal.path, journal.execution_id)


class _FakeTransport:
    def __init__(self, *, fail_cleanup_node: str | None = None) -> None:
        self.runs: list[tuple[str, str]] = []
        self.fail_cleanup_node = fail_cleanup_node

    def copy(self, node: PreviewNode, source: Path, destination: str) -> None:
        raise AssertionError("copy was not expected")

    def run(self, node: PreviewNode, script: str, *, timeout: int) -> RemoteResult:
        del timeout
        self.runs.append((node.node_id, script))
        if node.node_id == self.fail_cleanup_node:
            raise OSError("injected cleanup failure")
        return RemoteResult(stdout=f"clean:{node.node_id}")


def test_phase_failure_still_cleans_every_node_and_records_terminal_failure(
    tmp_path: Path, monkeypatch
) -> None:
    plan, _authorization, journal = _prepare(tmp_path, monkeypatch)
    transport = _FakeTransport()
    handlers = {
        "local_preflight": lambda _phase: {"passed": True},
        "deploy_isolated_candidate": lambda _phase: (_ for _ in ()).throw(
            RuntimeError("injected phase failure")
        ),
    }
    gate = GateExecutor(
        plan=plan,
        transport=transport,
        journal=journal,
        phase_handlers=handlers,
    )

    with pytest.raises(RuntimeError, match="injected phase failure"):
        gate.execute()

    assert [node for node, _script in transport.runs] == ["vm1", "vm2", "vm3"]
    events = [entry["event"] for entry in journal.entries]
    assert "cleanup_passed" in events
    assert events[-1] == "execution_failed"
    assert all(str(DEFAULT_BACKEND_PORT) in script for _node, script in transport.runs)
    assert all(DEFAULT_REMOTE_ROOT in script for _node, script in transport.runs)


def test_cleanup_failure_prevents_passing_summary(tmp_path: Path, monkeypatch) -> None:
    plan, _authorization, journal = _prepare(tmp_path, monkeypatch)
    transport = _FakeTransport(fail_cleanup_node="vm2")
    case_evidence = [{"case_id": case["case_id"]} for case in plan["fault_matrix"]]
    handlers = {
        phase["phase_id"]: (
            lambda _phase: {"passed": True, "cases": case_evidence}
        )
        for phase in plan["phases"]
        if phase["phase_id"] != "cleanup_and_verify"
    }
    gate = GateExecutor(
        plan=plan,
        transport=transport,
        journal=journal,
        phase_handlers=handlers,
    )

    with pytest.raises(RuntimeError, match="cleanup verification failed"):
        gate.execute()

    assert journal.entries[-1]["event"] == "execution_failed"
    assert not any(entry["event"] == "execution_passed" for entry in journal.entries)


def test_missing_fault_evidence_fails_acceptance_and_cleans(
    tmp_path: Path, monkeypatch
) -> None:
    plan, _authorization, journal = _prepare(tmp_path, monkeypatch)
    transport = _FakeTransport()
    handlers = {
        phase["phase_id"]: (lambda _phase: {"passed": True})
        for phase in plan["phases"]
        if phase["phase_id"] != "cleanup_and_verify"
    }
    gate = GateExecutor(
        plan=plan,
        transport=transport,
        journal=journal,
        phase_handlers=handlers,
    )

    with pytest.raises(RuntimeError, match="missing_cases"):
        gate.execute()

    assert len(transport.runs) == 3
    assert journal.entries[-1]["event"] == "execution_failed"


def test_cleanup_script_is_exact_and_has_no_broad_process_kill(
    tmp_path: Path, monkeypatch
) -> None:
    plan, _authorization, _journal = _prepare(tmp_path, monkeypatch)
    vm1 = NODES[0]
    script = _cleanup_script(plan, vm1)

    assert "pkill" not in script
    assert "killall" not in script
    assert 'rm -rf -- "$ROOT"' in script
    assert "192.168.56.6 --dport 19454" in script
    assert "192.168.56.4 --dport 19454" not in script
    assert "--comment civitasos-p5b4-partition" in script


def test_interrupted_execution_cleans_and_restarts_all_phases(
    tmp_path: Path, monkeypatch
) -> None:
    plan, _authorization, journal = _prepare(tmp_path, monkeypatch)
    journal.append(
        event="phase_started", phase_id="local_preflight", evidence={}
    )
    journal.append(
        event="phase_passed",
        phase_id="local_preflight",
        evidence={"passed": True},
    )
    journal.append(
        event="phase_started", phase_id="deploy_isolated_candidate", evidence={}
    )
    transport = _FakeTransport()
    calls: list[str] = []
    handlers = {}
    for phase in plan["phases"]:
        if phase["phase_id"] == "cleanup_and_verify":
            continue

        def handler(_phase, phase_id=phase["phase_id"]):  # noqa: ANN001
            calls.append(phase_id)
            return {
                "passed": True,
                "cases": [
                    {"case_id": case["case_id"]} for case in plan["fault_matrix"]
                ],
            }

        handlers[phase["phase_id"]] = handler
    gate = GateExecutor(
        plan=plan,
        transport=transport,
        journal=journal,
        phase_handlers=handlers,
    )

    result = gate.execute()

    assert result["passed"] is True
    assert calls[0] == "local_preflight"
    assert calls == [
        phase["phase_id"]
        for phase in plan["phases"]
        if phase["phase_id"] != "cleanup_and_verify"
    ]
    assert [entry["event"] for entry in journal.entries].count(
        "execution_recovery_reset"
    ) == 1
    assert len(transport.runs) == 6
