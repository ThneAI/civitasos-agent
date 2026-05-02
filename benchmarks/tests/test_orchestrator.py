"""Orchestrator state-machine tests using the fake agent."""
from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from benchmarks.backend_task_client import BackendTaskState
from benchmarks.orchestrator import (
    EXIT_ABNORMAL, EXIT_AGENT_DONE, EXIT_AGENT_FAILED, EXIT_AGENT_GAVE_UP,
    EXIT_TICK_LIMIT, EXIT_WALL_CLOCK,
    Orchestrator, OrchestratorConfig, _build_backend_client, _load_cached_result,
    _count_llm_mode_selected_after, _tail_actions_all_pool_claim, _tail_last_action,
)
from benchmarks.task_loader import load_manifest

MANIFEST = Path(__file__).resolve().parents[1] / "v1" / "manifest.yaml"


def _orch(tmp_path: Path, *, wall_clock_per_tick_s: float = 5.0, extra_env: dict[str, str] | None = None) -> Orchestrator:
    cmd = f"{sys.executable} -m benchmarks._fake_agent"
    cfg = OrchestratorConfig(
        agent_command=cmd,
        runs_root=tmp_path / "runs",
        wall_clock_per_tick_s=wall_clock_per_tick_s,
        sigterm_grace_s=2.0,
        poll_interval_s=0.05,
        extra_env=extra_env or {},
    )
    return Orchestrator(load_manifest(MANIFEST), cfg)


def test_done_sentinel(tmp_path: Path) -> None:
    o = _orch(tmp_path, extra_env={"BENCHMARK_FAKE_TICKS": "3", "BENCHMARK_FAKE_SENTINEL": "done"})
    res = o.run(task_ids=["R01_happy_01"])
    t = res.tasks[0]
    assert t.exit_code == EXIT_AGENT_DONE
    assert t.sentinel_kind == "done"
    assert t.agent_self_reported_success is True
    assert t.tick_count == 3


def test_failed_sentinel(tmp_path: Path) -> None:
    o = _orch(tmp_path, extra_env={"BENCHMARK_FAKE_TICKS": "2", "BENCHMARK_FAKE_SENTINEL": "failed"})
    res = o.run(task_ids=["R01_happy_01"])
    t = res.tasks[0]
    assert t.exit_code == EXIT_AGENT_FAILED
    assert t.agent_self_reported_success is False


def test_give_up_sentinel(tmp_path: Path) -> None:
    o = _orch(tmp_path, extra_env={"BENCHMARK_FAKE_TICKS": "2", "BENCHMARK_FAKE_SENTINEL": "give_up"})
    res = o.run(task_ids=["R01_happy_01"])
    assert res.tasks[0].exit_code == EXIT_AGENT_GAVE_UP


def test_abnormal_exit(tmp_path: Path) -> None:
    o = _orch(tmp_path, extra_env={
        "BENCHMARK_FAKE_TICKS": "5",
        "BENCHMARK_FAKE_SENTINEL": "none",
        "BENCHMARK_FAKE_ABORT_AFTER": "2",
    })
    res = o.run(task_ids=["R01_happy_01"])
    assert res.tasks[0].exit_code == EXIT_ABNORMAL


def test_tick_limit(tmp_path: Path) -> None:
    # R01_happy_01 has max_ticks=20; force fake agent to write 25 with small sleep.
    o = _orch(tmp_path, extra_env={
        "BENCHMARK_FAKE_TICKS": "25",
        "BENCHMARK_FAKE_SLEEP_S": "0.05",
        "BENCHMARK_FAKE_SENTINEL": "none",
    })
    res = o.run(task_ids=["R01_happy_01"])
    t = res.tasks[0]
    assert t.exit_code == EXIT_TICK_LIMIT
    assert t.tick_count >= 20


def test_wall_clock(tmp_path: Path) -> None:
    # Force wall clock = max_ticks * 0.1 = 2.0s for R01 (max_ticks=20).
    o = _orch(tmp_path, wall_clock_per_tick_s=0.1, extra_env={
        "BENCHMARK_FAKE_TICKS": "1",
        "BENCHMARK_FAKE_SENTINEL": "none",
        "BENCHMARK_FAKE_HANG": "1",
    })
    res = o.run(task_ids=["R01_happy_01"])
    assert res.tasks[0].exit_code == EXIT_WALL_CLOCK


def test_summary_written(tmp_path: Path) -> None:
    o = _orch(tmp_path, extra_env={"BENCHMARK_FAKE_TICKS": "3", "BENCHMARK_FAKE_SENTINEL": "done"})
    res = o.run(task_ids=["R01_happy_01"])
    summary_path = tmp_path / "runs" / res.run_id / "summary.json"
    assert summary_path.exists()
    payload = json.loads(summary_path.read_text(encoding="utf-8"))
    assert payload["tasks_total"] == 1
    assert payload["tasks"][0]["agent_self_reported_success"] is True


def test_tail_actions_all_pool_claim_true(tmp_path: Path) -> None:
    p = tmp_path / "ticks.csv"
    p.write_text(
        (
            "run_id,agent_id,task_id,tick_seq,tick_id,timestamp,phase_reached,"
            "decision_action,decision_source,decision_reasoning,served_intent_layer,"
            "conscience_allowed,conscience_reason,eval_success,eval_cost,eval_duration_ms,"
            "aspect_gap,peer_trust_avg,balance,mode,is_wait,lessons_count,wait_references_telos\n"
            "r,a,t,1,x,ts,reflect,pool_claim,rules,,,"
            ",false,0,1,0.1,0.5,1,active,false,0,false\n"
            "r,a,t,2,x,ts,reflect,pool_claim,rules,,,"
            ",false,0,1,0.1,0.5,1,active,false,0,false\n"
            "r,a,t,3,x,ts,reflect,pool_claim,rules,,,"
            ",false,0,1,0.1,0.5,1,active,false,0,false\n"
        ),
        encoding="utf-8",
    )
    assert _tail_actions_all_pool_claim(p, window=3) is True


def test_tail_actions_all_pool_claim_false_when_mixed_actions(tmp_path: Path) -> None:
    p = tmp_path / "ticks.csv"
    p.write_text(
        (
            "run_id,agent_id,task_id,tick_seq,tick_id,timestamp,phase_reached,"
            "decision_action,decision_source,decision_reasoning,served_intent_layer,"
            "conscience_allowed,conscience_reason,eval_success,eval_cost,eval_duration_ms,"
            "aspect_gap,peer_trust_avg,balance,mode,is_wait,lessons_count,wait_references_telos\n"
            "r,a,t,1,x,ts,reflect,pool_claim,rules,,,,false,0,1,0.1,0.5,1,active,false,0,false\n"
            "r,a,t,2,x,ts,reflect,task_execute,llm,,,,true,1,3,0.1,0.5,1,active,false,0,false\n"
            "r,a,t,3,x,ts,reflect,pool_claim,rules,,,,false,0,1,0.1,0.5,1,active,false,0,false\n"
        ),
        encoding="utf-8",
    )
    assert _tail_actions_all_pool_claim(p, window=3) is False


def test_tail_last_action_returns_identity_probe(tmp_path: Path) -> None:
    p = tmp_path / "ticks.csv"
    p.write_text(
        (
            "run_id,agent_id,task_id,tick_seq,tick_id,timestamp,phase_reached,"
            "decision_action,decision_source,decision_reasoning,served_intent_layer,"
            "conscience_allowed,conscience_reason,eval_success,eval_cost,eval_duration_ms,"
            "aspect_gap,peer_trust_avg,balance,mode,is_wait,lessons_count,wait_references_telos\n"
            "r,a,t,1,x,ts,reflect,pool_claim,rules,,,,false,0,1,0.1,0.5,1,active,false,0,false\n"
            "r,a,t,2,x,ts,reflect,identity_probe_scholar,rules,,,,true,1,3,0.1,0.5,1,active,false,0,false\n"
        ),
        encoding="utf-8",
    )
    assert _tail_last_action(p) == "identity_probe_scholar"


def test_count_llm_mode_selected_after_ignores_rules_ticks(tmp_path: Path) -> None:
    p = tmp_path / "ticks.csv"
    p.write_text(
        (
            "run_id,agent_id,task_id,tick_seq,tick_id,timestamp,phase_reached,"
            "decision_action,decision_source,llm_mode_selected\n"
            "r,a,t,1,x,ts,reflect,wait,rules,false\n"
            "r,a,t,2,x,ts,reflect,mode_request,llm,true\n"
            "r,a,t,3,x,ts,reflect,task_execute,llm,false\n"
        ),
        encoding="utf-8",
    )
    assert _count_llm_mode_selected_after(p, start_seq=0) == 1
    assert _count_llm_mode_selected_after(p, start_seq=1) == 1
    assert _count_llm_mode_selected_after(p, start_seq=2) == 0


def test_identity_probe_grace_requires_claimed_backend_state(tmp_path: Path) -> None:
    p = tmp_path / "ticks.csv"
    p.write_text(
        (
            "run_id,agent_id,task_id,tick_seq,tick_id,timestamp,phase_reached,"
            "decision_action,decision_source,decision_reasoning,served_intent_layer,"
            "conscience_allowed,conscience_reason,eval_success,eval_cost,eval_duration_ms,"
            "aspect_gap,peer_trust_avg,balance,mode,is_wait,lessons_count,wait_references_telos\n"
            "r,a,t,1,x,ts,reflect,pool_claim,rules,,,,false,0,1,0.1,0.5,1,active,false,0,false\n"
            "r,a,t,2,x,ts,reflect,identity_probe_scholar,rules,,,,true,1,3,0.1,0.5,1,active,false,0,false\n"
        ),
        encoding="utf-8",
    )

    class FakeClient:
        def get_state(self, task_id: str) -> BackendTaskState:
            return BackendTaskState(
                task_id=task_id,
                status="Claimed",
                output=None,
                raw={},
            )

    orch = object.__new__(Orchestrator)
    orch._cfg = SimpleNamespace(backend_client=FakeClient())

    eligible, reason = orch._can_grant_identity_probe_grace(
        backend_task_id="task-1",
        raw_csv=p,
    )
    assert eligible is True
    assert "Claimed" in reason


def test_load_cached_result_drops_abnormal_without_sentinel(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    task_dir = run_dir / "tasks" / "R01_happy_01"
    task_dir.mkdir(parents=True)
    (task_dir / "result.json").write_text(
        json.dumps(
            {
                "task_id": "R01_happy_01",
                "exit_code": EXIT_TICK_LIMIT,
                "tick_count": 20,
                "wall_clock_ms": 1000.0,
                "raw_csv_rows": 20,
                "agent_self_reported_success": None,
                "sentinel_kind": None,
                "sentinel_reason": "",
            }
        ),
        encoding="utf-8",
    )
    assert _load_cached_result(run_dir, "R01_happy_01") is None


def test_build_backend_client_uses_birth_proposal_when_institutional_enabled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity_path = tmp_path / "orch.key"

    class FakeSDK:
        last_instance = None

        def __init__(self, base_url: str) -> None:
            self.base_url = base_url
            self._agent_id = None
            self.public_key_hex = None
            self.saved_agent_id = None
            self.birth_payload = None
            self.quickstart_called = False
            FakeSDK.last_instance = self

        def generate_keys(self) -> str:
            self.public_key_hex = "ab" * 32
            return self.public_key_hex

        def load_identity(self, path: str) -> str:
            raise AssertionError("load_identity should not be called for a fresh path")

        def save_identity(self, path: str) -> None:
            self.saved_agent_id = self._agent_id
            Path(path).write_text(
                json.dumps({"public_key_hex": self.public_key_hex, "agent_id": self._agent_id}),
                encoding="utf-8",
            )

        def _post(self, path: str, body):
            self.birth_payload = (path, body)
            return SimpleNamespace(
                success=True,
                data={"agent": {"did": "did:civ:devnet:orch-build"}},
                error=None,
                hint=None,
            )

        def a2a_quickstart(self, **kwargs):
            self.quickstart_called = True
            raise AssertionError("a2a_quickstart should not be used under Institutional ON")

    monkeypatch.setenv("CIVITASOS_INSTITUTIONAL_IDENTITY_ENABLED", "true")
    monkeypatch.setenv("BENCHMARK_BIRTH_SPONSOR", "@guardian")
    monkeypatch.setattr(
        "benchmarks.orchestrator._bootstrap_demo_jwt",
        lambda sdk, backend_url, agent_id: True,
    )
    monkeypatch.setitem(sys.modules, "civitasos", SimpleNamespace(CivitasAgent=FakeSDK))

    client = _build_backend_client(
        backend_url="http://localhost:8099",
        orch_agent_id=None,
        orch_agent_name="bench-orch",
        orch_identity_path=str(identity_path),
    )

    sdk = client._sdk
    assert sdk._agent_id == "did:civ:devnet:orch-build"
    assert sdk.saved_agent_id == "did:civ:devnet:orch-build"
    assert sdk.birth_payload is not None
    assert sdk.birth_payload[0] == "/agents/birth-proposal"
    assert sdk.birth_payload[1]["sponsor"] == "@guardian"
    assert sdk.quickstart_called is False
    assert identity_path.exists()


def test_rotate_orchestrator_identity_uses_birth_proposal_when_institutional_enabled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity_path = tmp_path / "orchestrator.key"
    identity_path.write_text("old", encoding="utf-8")

    class FakeSDK:
        instances = []

        def __init__(self, base_url: str) -> None:
            self.base_url = base_url
            self._agent_id = None
            self.public_key_hex = None
            self.birth_payload = None
            self.quickstart_called = False
            FakeSDK.instances.append(self)

        def generate_keys(self) -> str:
            self.public_key_hex = "cd" * 32
            return self.public_key_hex

        def save_identity(self, path: str) -> None:
            Path(path).write_text(
                json.dumps({"public_key_hex": self.public_key_hex, "agent_id": self._agent_id}),
                encoding="utf-8",
            )

        def _post(self, path: str, body):
            self.birth_payload = (path, body)
            return SimpleNamespace(
                success=True,
                data={"agent": {"did": "did:civ:devnet:orch-rotated"}},
                error=None,
                hint=None,
            )

        def a2a_quickstart(self, **kwargs):
            self.quickstart_called = True
            raise AssertionError("a2a_quickstart should not be used under Institutional ON")

    monkeypatch.setenv("CIVITASOS_INSTITUTIONAL_IDENTITY_ENABLED", "true")
    monkeypatch.setenv("BENCHMARK_BIRTH_SPONSOR", "@guardian")
    monkeypatch.setattr(
        "benchmarks.orchestrator._bootstrap_demo_jwt",
        lambda sdk, backend_url, agent_id: True,
    )
    monkeypatch.setitem(sys.modules, "civitasos", SimpleNamespace(CivitasAgent=FakeSDK))

    orch = object.__new__(Orchestrator)
    orch._cfg = SimpleNamespace(
        backend_client=SimpleNamespace(_sdk=SimpleNamespace()),
        orch_identity_path=str(identity_path),
        backend_url="http://localhost:8099",
        orch_agent_name="bench-orch",
    )

    orch._rotate_orchestrator_identity()

    sdk = orch._cfg.backend_client._sdk
    assert sdk._agent_id == "did:civ:devnet:orch-rotated"
    assert sdk.birth_payload is not None
    assert sdk.birth_payload[0] == "/agents/birth-proposal"
    assert sdk.birth_payload[1]["alias"].startswith("bench-orch-r")
    assert sdk.quickstart_called is False
    archived = list(tmp_path.glob("orchestrator.key.drained-*"))
    assert archived


def test_seed_backend_relation_failures_uses_task_metadata(tmp_path: Path) -> None:
    class FakeClient:
        def __init__(self) -> None:
            self.calls = []

        def seed_failure(self, **kwargs):
            self.calls.append(kwargs)
            return f"seed-{len(self.calls)}"

    client = FakeClient()
    orch = object.__new__(Orchestrator)
    orch._cfg = SimpleNamespace(
        backend_mode="backend-tasks",
        backend_client=client,
        target_agent_id="did:civ:worker",
        backend_capability="general",
    )
    task = SimpleNamespace(
        id="G03_happy_01",
        briefing="relation repair accountability",
        backend_seed_failures=2,
    )

    seeded = orch._seed_backend_relation_failures(task, task_dir=tmp_path)

    assert seeded == ["seed-1", "seed-2"]
    assert len(client.calls) == 2
    assert client.calls[0]["target_agent_id"] == "did:civ:worker"
    assert client.calls[0]["capability"] == "general"
    payload = json.loads((tmp_path / "backend_seed_failure_ids.json").read_text())
    assert payload == seeded


def test_seed_backend_relation_repairs_uses_task_metadata(tmp_path: Path) -> None:
    class FakeClient:
        def __init__(self) -> None:
            self.calls = []

        def seed_repair(self, **kwargs):
            self.calls.append(kwargs)
            return f"repair-{len(self.calls)}"

    client = FakeClient()
    orch = object.__new__(Orchestrator)
    orch._cfg = SimpleNamespace(
        backend_mode="backend-tasks",
        backend_client=client,
        target_agent_id="did:civ:worker",
        backend_capability="general",
    )
    task = SimpleNamespace(
        id="G03_happy_01",
        briefing="relation repair accountability",
        backend_seed_repairs=2,
    )

    seeded = orch._seed_backend_relation_repairs(
        task,
        task_dir=tmp_path,
        repaired_failure_ids=["failure-1"],
    )

    assert seeded == ["repair-1", "repair-2"]
    assert len(client.calls) == 2
    assert client.calls[0]["target_agent_id"] == "did:civ:worker"
    assert client.calls[0]["repaired_failure_ids"] == ["failure-1"]
    payload = json.loads((tmp_path / "backend_seed_repair_ids.json").read_text())
    assert payload == seeded

    extra_input = orch._backend_task_extra_input(
        task,
        task_dir=tmp_path,
        relation_repair_task_ids=seeded,
        repaired_failure_ids=["failure-1"],
    )
    assert extra_input["relation_repair_context"] == {
        "benchmark_task_id": "G03_happy_01",
        "repair_task_ids": ["repair-1", "repair-2"],
        "repaired_failure_task_ids": ["failure-1"],
        "source": "backend_relation_repair_seed_task",
    }


class _FakeH0ESDK:
    _agent_id = "did:civ:orch"


class _FakeH0EClient:
    def __init__(self) -> None:
        self._sdk = _FakeH0ESDK()
        self.replay = None
        self.votes = []

    def create_normative_revision(self, **kwargs):
        self.replay = kwargs["iem_anchor_replay"]
        return {
            "proposal": {"id": "prop-1"},
            "governed_revision_context": {
                "proposal_id": "prop-1",
                "revision_id": "rev-1",
                "iem_anchor": kwargs["iem_anchor"],
                "iem_anchor_replay": kwargs["iem_anchor_replay"],
                "source": "backend_governance_read_model",
            },
        }

    def cast_governance_vote(self, proposal_id: str, **kwargs) -> None:
        self.votes.append({"proposal_id": proposal_id, **kwargs})

    def finalize_governance_proposal(self, proposal_id: str, *, approved: bool):
        return {
            "governed_revision_context": {
                "proposal_id": proposal_id,
                "revision_id": "rev-1",
                "approved": approved,
                "status": "approved",
                "source": "backend_governance_read_model",
                "iem_anchor_replay": self.replay,
                "decision_proof": {"proof_hash": "sha256:test"},
            }
        }


def test_h0e_backend_revision_embeds_replay_without_sidecar_by_default(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("BENCHMARK_H0E_WRITE_LEGACY_REPLAY_SIDECAR", raising=False)
    client = _FakeH0EClient()
    orch = object.__new__(Orchestrator)
    orch._cfg = SimpleNamespace(
        backend_client=client,
        orch_agent_name="orch",
        target_agent_id="did:civ:worker",
    )
    task = SimpleNamespace(id="G08_h0e_governed_revision_01")

    extra_input = orch._backend_task_extra_input(task, task_dir=tmp_path)

    assert extra_input == {
        "benchmark_task_id": "G08_h0e_governed_revision_01",
        "governed_revision_id": "rev-1",
        "governance_proposal_id": "prop-1",
    }
    assert not (tmp_path / "h0e_iem_anchor_replay.json").exists()
    evidence = json.loads((tmp_path / "h0e_governed_revision.json").read_text())
    assert evidence["iem_anchor_replay"]["update_log"][0]["rule"] == "governed_revision"
    assert client.votes


def test_h0e_legacy_replay_sidecar_is_explicit_opt_in(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("BENCHMARK_H0E_WRITE_LEGACY_REPLAY_SIDECAR", "1")
    client = _FakeH0EClient()
    orch = object.__new__(Orchestrator)
    orch._cfg = SimpleNamespace(
        backend_client=client,
        orch_agent_name="orch",
        target_agent_id="did:civ:worker",
    )
    task = SimpleNamespace(id="G08_h0e_governed_revision_01")

    orch._backend_task_extra_input(task, task_dir=tmp_path)

    sidecar = json.loads((tmp_path / "h0e_iem_anchor_replay.json").read_text())
    assert sidecar["update_log"][0]["rule"] == "governed_revision"


def test_build_backend_client_rotates_alias_on_birth_proposal_conflict(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity_path = tmp_path / "orch.key"

    class FakeSDK:
        def __init__(self, base_url: str) -> None:
            self.base_url = base_url
            self._agent_id = None
            self.public_key_hex = None
            self.saved_agent_id = None
            self.calls = []

        def generate_keys(self) -> str:
            self.public_key_hex = "ef" * 32
            return self.public_key_hex

        def load_identity(self, path: str) -> str:
            raise AssertionError("load_identity should not be called for a fresh path")

        def save_identity(self, path: str) -> None:
            self.saved_agent_id = self._agent_id
            Path(path).write_text(
                json.dumps({"public_key_hex": self.public_key_hex, "agent_id": self._agent_id}),
                encoding="utf-8",
            )

        def _post(self, path: str, body):
            self.calls.append((path, body))
            if len(self.calls) == 1:
                return SimpleNamespace(
                    success=False,
                    data=None,
                    error="alias 'f1c-orchestrator' is already registered to DID did:civ:devnet:existing",
                    hint="Use the existing keypair for this alias, or choose a different alias",
                )
            return SimpleNamespace(
                success=True,
                data={"agent": {"did": "did:civ:devnet:orch-conflict-rotated"}},
                error=None,
                hint=None,
            )

        def a2a_quickstart(self, **kwargs):
            raise AssertionError("a2a_quickstart should not be used under Institutional ON")

    monkeypatch.setenv("CIVITASOS_INSTITUTIONAL_IDENTITY_ENABLED", "true")
    monkeypatch.setenv("BENCHMARK_BIRTH_SPONSOR", "@guardian")
    monkeypatch.setattr(
        "benchmarks.orchestrator._bootstrap_demo_jwt",
        lambda sdk, backend_url, agent_id: True,
    )
    monkeypatch.setitem(sys.modules, "civitasos", SimpleNamespace(CivitasAgent=FakeSDK))

    client = _build_backend_client(
        backend_url="http://localhost:8099",
        orch_agent_id="f1c_orchestrator",
        orch_agent_name="f1c-orchestrator",
        orch_identity_path=str(identity_path),
    )

    sdk = client._sdk
    assert sdk._agent_id == "did:civ:devnet:orch-conflict-rotated"
    assert len(sdk.calls) == 2
    assert sdk.calls[0][1]["alias"] == "f1c-orchestrator"
    assert sdk.calls[1][1]["alias"].startswith("f1c-orchestrator-r")
