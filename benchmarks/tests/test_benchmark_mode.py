"""Tests for benchmarks/benchmark_mode.py — install hook semantics."""
from __future__ import annotations

import os
from types import SimpleNamespace
from typing import Any

import pytest

from benchmarks import benchmark_mode


class FakeRuleEngine:
    def __init__(self) -> None:
        self.registered: list[tuple[int, str, Any]] = []

    def rule(self, *, priority: int = 50, name: str = ""):
        def decorator(fn):
            self.registered.append((priority, name, fn))
            return fn
        return decorator


class FakeRunner:
    def __init__(self) -> None:
        self._rules = FakeRuleEngine()
        self._on_reflect_fn = None
        self._on_perceive_fn = None
        self._on_remember_fn = None
        self._loop = None  # set later to simulate post-start
        self._agent = None
        self._name = "test-agent"
        self._tools_registered: dict[str, Any] = {}

    def rule(self, priority: int = 50, name: str = ""):
        return self._rules.rule(priority=priority, name=name)

    def on_reflect(self, fn):
        self._on_reflect_fn = fn
        return fn

    def on_perceive(self, fn):
        self._on_perceive_fn = fn
        return fn

    def on_remember(self, fn):
        self._on_remember_fn = fn
        return fn

    def tool(
        self,
        *,
        name: str,
        description: str = "",
        requires_conscience: bool = False,
        estimated_cost: float = 0.0,
    ):
        def decorator(fn):
            self._tools_registered[name] = fn
            return fn
        return decorator


class FakeBackendAgent:
    def __init__(self) -> None:
        self.pool_get_task_calls: list[str] = []
        self.pool_failures_calls: list[dict[str, Any]] = []

    def pool_get_task(self, task_id: str) -> dict[str, Any]:
        self.pool_get_task_calls.append(task_id)
        return {
            "task": {
                "id": task_id,
                "requester": "did:civ:devnet:requester",
                "allowed_agents": ["did:civ:devnet:worker"],
                "r2r_relation_id": "rel:did:civ:devnet:requester:did:civ:devnet:worker",
                "relation_pair": {
                    "requester": "did:civ:devnet:requester",
                    "worker": "did:civ:devnet:worker",
                    "agents": ["did:civ:devnet:requester", "did:civ:devnet:worker"],
                },
                "r2r_relation": {
                    "id": "rel:did:civ:devnet:requester:did:civ:devnet:worker",
                    "state": "Active",
                    "source": "r2r_registry",
                },
                "status": "Open",
                "posted_at": "2026-05-01T09:55:00Z",
                "challenge_deadline_at": "2026-05-01T10:00:00Z",
            }
        }

    def pool_failures(
        self,
        agent_id: str | None = None,
        requester_id: str | None = None,
        relation_id: str | None = None,
        since: str | None = None,
        limit: int | None = None,
    ) -> dict[str, Any]:
        self.pool_failures_calls.append({
            "agent_id": agent_id,
            "requester_id": requester_id,
            "relation_id": relation_id,
            "since": since,
            "limit": limit,
        })
        return {
            "failures": [
                {
                    "task_id": "failed_1",
                    "agent_id": agent_id,
                    "requester": requester_id,
                    "relation_id": relation_id,
                    "r2r_relation_id": relation_id,
                    "failed_at": "2026-04-30T23:59:00Z",
                    "failure_reason": "challenge_disputed",
                }
            ]
        }


class FakeRepairBackendAgent(FakeBackendAgent):
    def pool_get_task(self, task_id: str) -> dict[str, Any]:
        if task_id == "repair_1":
            self.pool_get_task_calls.append(task_id)
            return {
                "task": {
                    "id": task_id,
                    "requester": "did:civ:devnet:requester",
                    "allowed_agents": ["did:civ:devnet:worker"],
                    "claimed_by": "did:civ:devnet:worker",
                    "status": "Delivered",
                    "delivered_at": "2026-05-01T10:02:00Z",
                    "output": {
                        "status": "relation_repair_completed",
                        "repaired_failure_task_ids": ["failed_1"],
                    },
                }
            }
        payload = super().pool_get_task(task_id)
        payload["task"]["input"] = {
            "description": "relation repair accountability",
            "relation_repair_context": {
                "repair_task_ids": ["repair_1"],
                "repaired_failure_task_ids": ["failed_1"],
                "source": "backend_relation_repair_seed_task",
            },
        }
        return payload


class FakeRevisionBackendAgent(FakeBackendAgent):
    def pool_get_task(self, task_id: str) -> dict[str, Any]:
        payload = super().pool_get_task(task_id)
        payload["task"]["governed_revision_context"] = {
            "approved": True,
            "status": "approved",
            "authority": "governance_council",
            "source": "backend_governance_read_model",
            "revision_id": "rev-backend-1",
            "proposal_id": "prop-backend-1",
            "decision_id": "prop-backend-1",
            "rule_id": "h0e_constitutional_guard",
            "old_value": "review_required_v1",
            "new_value": "review_required_v2",
            "iem_anchor_hash": "sha256:anchor",
            "iem_anchor_replay": {
                "anchor": {"state_hash": "sha256:state", "latest_update_log_hash": "sha256:log"},
                "state": {"identity_id": "benchmark:G08_h0e_governed_revision_01"},
                "update_log": [{"rule": "governed_revision"}],
            },
            "decision_proof": {"proof_hash": "sha256:proof"},
        }
        return payload


# ── install_if_present ──────────────────────────────────────────────

def test_install_no_op_when_env_unset(monkeypatch):
    monkeypatch.delenv("BENCHMARK_TASK_ID", raising=False)
    runner = FakeRunner()
    benchmark_mode.install(runner)
    assert runner._rules.registered == []
    assert runner._on_reflect_fn is None
    assert runner._on_perceive_fn is None
    assert not getattr(runner, "_benchmark_mode_installed", False)


def test_install_registers_rule_at_priority_one(monkeypatch):
    monkeypatch.setenv("BENCHMARK_TASK_ID", "R01_test_01")
    monkeypatch.setenv("BENCHMARK_BACKEND_TASK_ID", "backend_42")
    monkeypatch.delenv("BENCHMARK_RAW_CSV", raising=False)
    runner = FakeRunner()
    benchmark_mode.install(runner)
    assert len(runner._rules.registered) == 1
    priority, name, _fn = runner._rules.registered[0]
    assert priority == 1, "must beat default rules (priority=10/20/30)"
    assert name == "benchmark_prefer_target_task"
    assert runner._on_perceive_fn is not None
    assert "report_blocked" in runner._tools_registered
    assert "abandon" in runner._tools_registered
    assert "address_diff" in runner._tools_registered
    assert "verifier_compare" in runner._tools_registered


def test_install_skips_rule_when_no_backend_task_id(monkeypatch):
    monkeypatch.setenv("BENCHMARK_TASK_ID", "R01_test_01")
    monkeypatch.delenv("BENCHMARK_BACKEND_TASK_ID", raising=False)
    monkeypatch.delenv("BENCHMARK_RAW_CSV", raising=False)
    runner = FakeRunner()
    benchmark_mode.install(runner)
    # No rule installed because no backend task to lock onto.
    assert runner._rules.registered == []


def test_install_is_idempotent(monkeypatch):
    monkeypatch.setenv("BENCHMARK_TASK_ID", "R01_test_01")
    monkeypatch.setenv("BENCHMARK_BACKEND_TASK_ID", "backend_42")
    runner = FakeRunner()
    benchmark_mode.install(runner)
    benchmark_mode.install(runner)
    assert len(runner._rules.registered) == 1


# ── prefer_target_task rule behavior ────────────────────────────────

def _get_rule_fn(runner: FakeRunner):
    return runner._rules.registered[0][2]


def test_prefer_target_rule_picks_matching_task(monkeypatch):
    monkeypatch.setenv("BENCHMARK_TASK_ID", "R01_test_01")
    monkeypatch.setenv("BENCHMARK_BACKEND_TASK_ID", "backend_42")
    runner = FakeRunner()
    benchmark_mode.install(runner)
    rule_fn = _get_rule_fn(runner)

    briefing = {"pool_tasks": [
        {"id": "other_task", "required_capability": "x"},
        {"task_id": "backend_42", "required_capability": "general"},
    ]}
    decision = rule_fn(briefing, {})
    assert decision is not None
    assert decision.action == "pool_claim"
    assert decision.params["task_id"] == "backend_42"


def test_prefer_target_rule_injects_g3_relation_context_for_v2_tasks(monkeypatch):
    monkeypatch.setenv("BENCHMARK_TASK_ID", "G01_happy_01")
    monkeypatch.setenv("BENCHMARK_BACKEND_TASK_ID", "backend_42")
    monkeypatch.setenv("BENCHMARK_G3_BACKEND_CONTEXT_ENABLED", "0")
    runner = FakeRunner()
    benchmark_mode.install(runner)
    rule_fn = _get_rule_fn(runner)

    briefing = {"pool_tasks": [{"task_id": "backend_42"}]}
    decision = rule_fn(briefing, {})

    assert decision is not None
    assert decision.action == "pool_claim"
    assert briefing["relation_context"]["id"] == (
        "bench-relation:G01:alpha-beta-gamma:G01_happy_01"
    )
    assert briefing["relation_context"]["memory_refs"] == [
        "relation:G01:prior_success",
        "challenge:G01_happy_01:latest",
    ]
    assert briefing["relation_context"]["source"] == "synthetic_benchmark"
    assert briefing["time_window"]["id"] == "bench-window:G01_happy_01"
    assert briefing["time_window"]["source"] == "synthetic_benchmark"


def test_prefer_target_rule_prefers_backend_g3_relation_context(monkeypatch):
    monkeypatch.setenv("BENCHMARK_TASK_ID", "G01_happy_01")
    monkeypatch.setenv("BENCHMARK_BACKEND_TASK_ID", "backend_42")
    runner = FakeRunner()
    backend_agent = FakeBackendAgent()
    runner._agent = backend_agent
    benchmark_mode.install(runner)
    rule_fn = _get_rule_fn(runner)

    briefing = {"pool_tasks": [{"task_id": "backend_42"}]}
    decision = rule_fn(briefing, {})

    assert decision is not None
    assert decision.action == "pool_claim"
    assert backend_agent.pool_get_task_calls == ["backend_42"]
    assert briefing["relation_context"]["source"] == "backend_read_model"
    assert briefing["relation_context"]["relation_id"] == (
        "rel:did:civ:devnet:requester:did:civ:devnet:worker"
    )
    assert briefing["relation_context"]["relation_id_source"] == "r2r_registry"
    assert briefing["relation_context"]["relation_pair"] == {
        "requester": "did:civ:devnet:requester",
        "worker": "did:civ:devnet:worker",
        "agents": ["did:civ:devnet:requester", "did:civ:devnet:worker"],
    }
    assert briefing["relation_context"]["peer_did"] == "did:civ:devnet:requester"
    assert briefing["relation_context"]["task_id"] == "backend_42"
    assert "task:backend_42" in briefing["relation_context"]["memory_refs"]
    assert (
        "failure:rel:did:civ:devnet:requester:did:civ:devnet:worker:"
        "failed_1:2026-04-30T23_59_00Z"
    ) in briefing["relation_context"]["memory_refs"]
    assert briefing["time_window"]["id"] == "backend-window:G01_happy_01:challenge_deadline_at"
    assert briefing["time_window"]["backend_task_id"] == "backend_42"
    assert backend_agent.pool_failures_calls == [
        {
            "agent_id": "did:civ:devnet:worker",
            "requester_id": "did:civ:devnet:requester",
            "relation_id": "rel:did:civ:devnet:requester:did:civ:devnet:worker",
            "since": None,
            "limit": 10,
        }
    ]


def test_prefer_target_rule_injects_backend_relation_repair_context(monkeypatch):
    monkeypatch.setenv("BENCHMARK_TASK_ID", "G03_happy_01")
    monkeypatch.setenv("BENCHMARK_BACKEND_TASK_ID", "backend_42")
    runner = FakeRunner()
    backend_agent = FakeRepairBackendAgent()
    runner._agent = backend_agent
    benchmark_mode.install(runner)
    rule_fn = _get_rule_fn(runner)

    briefing = {"pool_tasks": [{"task_id": "backend_42"}]}
    decision = rule_fn(briefing, {})

    assert decision is not None
    assert decision.action == "pool_claim"
    relation = briefing["relation_context"]
    assert relation["source"] == "backend_read_model"
    assert relation["recent_repairs"] == [
        {
            "task_id": "repair_1",
            "relation_id": "rel:did:civ:devnet:requester:did:civ:devnet:worker",
            "r2r_relation_id": "rel:did:civ:devnet:requester:did:civ:devnet:worker",
            "repaired_failure_task_ids": ["failed_1"],
            "source": "backend_relation_repair_seed_task",
            "status": "Delivered",
            "repaired_at": "2026-05-01T10:02:00Z",
            "delivered_at": "2026-05-01T10:02:00Z",
            "completed_at": "",
        }
    ]
    assert (
        "failure:rel:did:civ:devnet:requester:did:civ:devnet:worker:"
        "failed_1:2026-04-30T23_59_00Z"
    ) in relation["memory_refs"]
    assert (
        "repair:rel:did:civ:devnet:requester:did:civ:devnet:worker:"
        "repair_1:2026-05-01T10_02_00Z"
    ) in relation["memory_refs"]
    assert backend_agent.pool_get_task_calls == ["backend_42", "repair_1"]


def test_pre_expect_hook_injects_g3_relation_context_before_decide(monkeypatch):
    monkeypatch.setenv("BENCHMARK_TASK_ID", "G01_happy_01")
    monkeypatch.setenv("BENCHMARK_BACKEND_TASK_ID", "backend_42")
    runner = FakeRunner()
    backend_agent = FakeBackendAgent()
    runner._agent = backend_agent
    benchmark_mode.install(runner)
    rule_fn = _get_rule_fn(runner)

    briefing: dict[str, Any] = {"pool_tasks": [{"task_id": "backend_42"}]}
    assert runner._on_perceive_fn is not None
    runner._on_perceive_fn(briefing)

    assert briefing["relation_context"]["source"] == "backend_read_model"
    assert briefing["relation_context"]["benchmark_task_id"] == "G01_happy_01"
    assert backend_agent.pool_get_task_calls == ["backend_42"]

    decision = rule_fn(briefing, {})

    assert decision is not None
    assert decision.action == "pool_claim"
    assert backend_agent.pool_get_task_calls == ["backend_42"]


def test_pre_expect_hook_injects_h0c_identity_context(monkeypatch):
    monkeypatch.setenv("BENCHMARK_TASK_ID", "G06_h0c_normative_01")
    monkeypatch.setenv("BENCHMARK_BACKEND_TASK_ID", "backend_42")
    runner = FakeRunner()
    runner._agent = FakeBackendAgent()
    energy_state = SimpleNamespace(balance=500.0, balance_cap=10000.0, risk_score=0.0)
    runner._loop = SimpleNamespace(_energy=SimpleNamespace(state=energy_state))
    benchmark_mode.install(runner)

    briefing: dict[str, Any] = {"pool_tasks": [{"task_id": "backend_42"}]}
    assert runner._on_perceive_fn is not None
    runner._on_perceive_fn(briefing)

    assert briefing["h0c_expectation_context"]["source"] == "benchmark_h0c_smoke"
    assert briefing["identity"]["at_risk"] is True
    assert briefing["identity"]["remaining_epochs"] == 0
    assert briefing["normative_context"]["breach"] is True
    assert briefing["normative_context"]["rule_id"] == "h0c_smoke_constitutional_guard"


def test_h0c_economic_context_updates_loop_energy(monkeypatch):
    monkeypatch.setenv("BENCHMARK_TASK_ID", "G06_h0c_economic_01")
    monkeypatch.setenv("BENCHMARK_BACKEND_TASK_ID", "backend_42")
    runner = FakeRunner()
    runner._agent = FakeBackendAgent()
    energy_state = SimpleNamespace(balance=500.0, balance_cap=10000.0, risk_score=0.0)
    runner._loop = SimpleNamespace(_energy=SimpleNamespace(state=energy_state))
    benchmark_mode.install(runner)

    briefing: dict[str, Any] = {"pool_tasks": [{"task_id": "backend_42"}]}
    assert runner._on_perceive_fn is not None
    runner._on_perceive_fn(briefing)

    assert briefing["economics"]["balance"] == 20.0
    assert briefing["economics"]["balance_cap"] == 1000.0
    assert energy_state.balance == 20.0
    assert energy_state.balance_cap == 1000.0


def test_pre_expect_hook_injects_h0d_expanded_context(monkeypatch):
    monkeypatch.setenv("BENCHMARK_TASK_ID", "G07_h0d_governance_01")
    monkeypatch.setenv("BENCHMARK_BACKEND_TASK_ID", "backend_42")
    runner = FakeRunner()
    runner._agent = FakeBackendAgent()
    energy_state = SimpleNamespace(
        balance=500.0,
        balance_cap=10000.0,
        risk_score=0.0,
        reputation=0.5,
    )
    runner._loop = SimpleNamespace(_energy=SimpleNamespace(state=energy_state))
    benchmark_mode.install(runner)

    briefing: dict[str, Any] = {"pool_tasks": [{"task_id": "backend_42"}]}
    assert runner._on_perceive_fn is not None
    runner._on_perceive_fn(briefing)

    assert briefing["h0d_expectation_context"]["source"] == "benchmark_h0d_smoke"
    assert briefing["reputation_context"]["recent_failures"] == 1
    assert briefing["task_context"]["missing_inputs"] == 1
    assert briefing["governance_context"]["actual_participation"] == 0.10
    assert energy_state.reputation == 0.25


def test_pre_expect_hook_injects_h0e_governed_revision(monkeypatch):
    monkeypatch.setenv("BENCHMARK_TASK_ID", "G08_h0e_governed_revision_01")
    monkeypatch.setenv("BENCHMARK_BACKEND_TASK_ID", "backend_42")
    runner = FakeRunner()
    runner._agent = FakeBackendAgent()
    energy_state = SimpleNamespace(
        balance=500.0,
        balance_cap=10000.0,
        risk_score=0.0,
        reputation=0.5,
    )
    runner._loop = SimpleNamespace(_energy=SimpleNamespace(state=energy_state))
    benchmark_mode.install(runner)

    briefing: dict[str, Any] = {"pool_tasks": [{"task_id": "backend_42"}]}
    assert runner._on_perceive_fn is not None
    runner._on_perceive_fn(briefing)

    revision = briefing["governed_revision_context"]
    assert briefing["h0e_expectation_context"]["source"] == "benchmark_h0e_smoke"
    assert revision["approved"] is True
    assert revision["authority"] == "governance_council"
    assert revision["rule_id"] == "h0e_constitutional_guard"
    assert energy_state.reputation == 0.55


def test_pre_expect_hook_prefers_backend_h0e_governed_revision(monkeypatch):
    monkeypatch.setenv("BENCHMARK_TASK_ID", "G08_h0e_governed_revision_01")
    monkeypatch.setenv("BENCHMARK_BACKEND_TASK_ID", "backend_42")
    runner = FakeRunner()
    runner._agent = FakeRevisionBackendAgent()
    runner._loop = SimpleNamespace(
        _energy=SimpleNamespace(
            state=SimpleNamespace(
                balance=500.0,
                balance_cap=10000.0,
                risk_score=0.0,
                reputation=0.5,
            )
        )
    )
    benchmark_mode.install(runner)

    briefing: dict[str, Any] = {"pool_tasks": [{"task_id": "backend_42"}]}
    assert runner._on_perceive_fn is not None
    runner._on_perceive_fn(briefing)

    revision = briefing["governed_revision_context"]
    assert briefing["h0e_expectation_context"]["source"] == "backend_governance_read_model"
    assert revision["revision_id"] == "rev-backend-1"
    assert revision["proposal_id"] == "prop-backend-1"
    assert revision["iem_anchor_replay"]["update_log"][0]["rule"] == "governed_revision"
    assert revision["decision_proof"]["proof_hash"] == "sha256:proof"


def test_h0f_runtime_iem_audit_payload_uses_persisted_memory() -> None:
    state = {
        "schema_version": "iem:v1",
        "identity_id": "did:civ:devnet:worker",
        "expectation_vector": {},
        "precision_vector": {},
        "desire_vector": {},
        "domain_weight_matrix": {},
        "drift_parameters": {},
        "relation_expectation_matrix": {},
    }
    update_log = [
        {
            "target": "normative_state",
            "parameter_name": "h0e_constitutional_guard",
            "rule": "governed_revision",
            "reason_event": "rev-1",
            "local_update_blocked": False,
        }
    ]
    from civitasos_runtime.iem_anchor import build_iem_anchor, normalize_iem_payload

    anchor = normalize_iem_payload(
        build_iem_anchor(
            identity_id="did:civ:devnet:worker",
            state=state,
            update_log=update_log,
        )
    )
    memory = SimpleNamespace(
        recall=lambda key: {
            "identity_iem_state": state,
            "expectation_update_log": update_log,
            "identity_iem_anchor": anchor,
        }.get(key)
    )
    loop = SimpleNamespace(
        _memory=memory,
        _agent=SimpleNamespace(_agent_id="did:civ:devnet:worker"),
    )
    ctx = SimpleNamespace(tick_id="tick-1", expectation_updates=update_log)

    payload = benchmark_mode._h0f_runtime_iem_audit_payload(
        ctx,
        loop=loop,
        task_id="G08_h0e_governed_revision_01",
    )

    assert payload is not None
    assert payload["source"] == "runtime_identity_iem_audit_log"
    assert payload["did_anchor"] == "did:civ:devnet:worker"
    assert payload["identity_iem_anchor"] == anchor
    assert payload["governed_revision_updates"][0]["reason_event"] == "rev-1"


def test_backend_g3_time_window_is_comparable_across_backend_tasks(monkeypatch):
    monkeypatch.setenv("BENCHMARK_TASK_ID", "G02_happy_01")
    runner = FakeRunner()
    runner._agent = FakeBackendAgent()

    first = benchmark_mode._build_backend_g3_relation_context(
        {},
        task_id="G02_happy_01",
        runner=runner,
        backend_task_id="backend_alpha",
    )
    second = benchmark_mode._build_backend_g3_relation_context(
        {},
        task_id="G02_happy_01",
        runner=runner,
        backend_task_id="backend_beta",
    )

    assert first is not None
    assert second is not None
    _, first_window = first
    _, second_window = second
    assert first_window["id"] == "backend-window:G02_happy_01:challenge_deadline_at"
    assert second_window["id"] == first_window["id"]
    assert first_window["backend_task_id"] == "backend_alpha"
    assert second_window["backend_task_id"] == "backend_beta"


def test_backend_g3_relation_context_enabled_for_expanded_v2_tasks(monkeypatch):
    monkeypatch.setenv("BENCHMARK_TASK_ID", "G05_adversarial_01")
    monkeypatch.setenv("BENCHMARK_BACKEND_TASK_ID", "backend_42")
    runner = FakeRunner()
    runner._agent = FakeBackendAgent()
    benchmark_mode.install(runner)
    rule_fn = _get_rule_fn(runner)

    briefing = {"pool_tasks": [{"task_id": "backend_42"}]}
    decision = rule_fn(briefing, {})

    assert decision is not None
    assert briefing["relation_context"]["source"] == "backend_read_model"
    assert briefing["time_window"]["id"] == "backend-window:G05_adversarial_01:challenge_deadline_at"


def test_prefer_target_rule_claims_even_when_pool_snapshot_has_no_match(monkeypatch):
    monkeypatch.setenv("BENCHMARK_TASK_ID", "R01_test_01")
    monkeypatch.setenv("BENCHMARK_BACKEND_TASK_ID", "backend_42")
    runner = FakeRunner()
    benchmark_mode.install(runner)
    rule_fn = _get_rule_fn(runner)
    d1 = rule_fn({"pool_tasks": [{"id": "other"}]}, {})
    d2 = rule_fn({}, {})
    d3 = rule_fn({"pool_tasks": []}, {})
    assert d1 is not None and d1.action == "pool_claim"
    assert d2 is not None and d2.action == "pool_claim"
    assert d3 is not None and d3.action == "pool_claim"


def test_prefer_target_rule_accepts_id_or_task_id_field(monkeypatch):
    monkeypatch.setenv("BENCHMARK_TASK_ID", "R01_test_01")
    monkeypatch.setenv("BENCHMARK_BACKEND_TASK_ID", "backend_42")
    runner = FakeRunner()
    benchmark_mode.install(runner)
    rule_fn = _get_rule_fn(runner)
    # backend task present in active_tasks (either id or task_id) -> rule yields to LLM.
    d_id = rule_fn({"active_tasks": [{"id": "backend_42"}]}, {})
    d_tid = rule_fn({"active_tasks": [{"task_id": "backend_42"}]}, {})
    assert d_id is None
    assert d_tid is None


def test_prefer_target_rule_emits_h1_verifier_before_llm(monkeypatch):
    monkeypatch.setenv("BENCHMARK_TASK_ID", "V04_h1_verifier_before_delivery_01")
    monkeypatch.setenv("BENCHMARK_BACKEND_TASK_ID", "backend_42")
    runner = FakeRunner()
    benchmark_mode.install(runner)
    rule_fn = _get_rule_fn(runner)
    briefing = {"active_tasks": [{"task_id": "backend_42", "poster_id": "did:poster"}]}

    d1 = rule_fn(briefing, {})
    assert d1 is not None
    assert d1.action == "address_diff"
    assert d1.params["task_id"] == "backend_42"
    assert d1.params["benchmark_task_id"] == "V04_h1_verifier_before_delivery_01"

    d2 = rule_fn(briefing, {})
    assert d2 is None


def test_prefer_target_rule_emits_relation_h1_verifier_before_llm(monkeypatch):
    monkeypatch.setenv("BENCHMARK_TASK_ID", "G03_h1_repair_verifier_before_delivery_01")
    monkeypatch.setenv("BENCHMARK_BACKEND_TASK_ID", "backend_42")
    runner = FakeRunner()
    benchmark_mode.install(runner)
    rule_fn = _get_rule_fn(runner)
    briefing = {"active_tasks": [{"task_id": "backend_42", "poster_id": "did:poster"}]}

    d1 = rule_fn(briefing, {})
    assert d1 is not None
    assert d1.action == "relation_repair_audit"
    assert d1.params["task_id"] == "backend_42"

    d2 = rule_fn(briefing, {})
    assert d2 is None


def test_prefer_target_rule_emits_verification_probe_once_for_adversarial(monkeypatch):
    monkeypatch.setenv("BENCHMARK_TASK_ID", "A01_adversarial_01")
    monkeypatch.setenv("BENCHMARK_BACKEND_TASK_ID", "backend_42")
    monkeypatch.setenv("BENCHMARK_VERIFICATION_PROBE_RATE", "1")
    monkeypatch.setenv("BENCHMARK_VERIFICATION_PROBE_ACTIONS", "query_reputation")
    runner = FakeRunner()
    benchmark_mode.install(runner)
    rule_fn = _get_rule_fn(runner)
    briefing = {"active_tasks": [{"task_id": "backend_42", "poster_id": "did:poster"}]}

    d1 = rule_fn(briefing, {})
    assert d1 is not None
    # query_reputation is coerced to get_reputation in benchmark mode.
    assert d1.action == "get_reputation"
    assert d1.params["agent_id"] == "did:poster"

    # Next tick on same active target falls through to LLM path.
    d2 = rule_fn(briefing, {})
    assert d2 is None


def test_prefer_target_rule_skips_probe_when_rate_zero(monkeypatch):
    monkeypatch.setenv("BENCHMARK_TASK_ID", "A01_adversarial_01")
    monkeypatch.setenv("BENCHMARK_BACKEND_TASK_ID", "backend_42")
    monkeypatch.setenv("BENCHMARK_VERIFICATION_PROBE_RATE", "0")
    runner = FakeRunner()
    benchmark_mode.install(runner)
    rule_fn = _get_rule_fn(runner)
    briefing = {"active_tasks": [{"task_id": "backend_42", "poster_id": "did:poster"}]}

    # Probe disabled -> directly yield to LLM execute path.
    d1 = rule_fn(briefing, {})
    assert d1 is None


def test_prefer_target_rule_supports_get_reputation_probe(monkeypatch):
    monkeypatch.setenv("BENCHMARK_TASK_ID", "A01_adversarial_01")
    monkeypatch.setenv("BENCHMARK_BACKEND_TASK_ID", "backend_42")
    monkeypatch.setenv("BENCHMARK_VERIFICATION_PROBE_RATE", "1")
    monkeypatch.setenv("BENCHMARK_VERIFICATION_PROBE_ACTIONS", "get_reputation")
    runner = FakeRunner()
    benchmark_mode.install(runner)
    rule_fn = _get_rule_fn(runner)
    briefing = {"active_tasks": [{"task_id": "backend_42", "poster_id": "did:poster"}]}

    d1 = rule_fn(briefing, {})
    assert d1 is not None
    assert d1.action == "get_reputation"
    assert d1.params["agent_id"] == "did:poster"


def test_prefer_target_rule_bridges_resource_blocked_task(monkeypatch):
    monkeypatch.setenv("BENCHMARK_TASK_ID", "A02_adversarial_01")
    monkeypatch.setenv("BENCHMARK_BACKEND_TASK_ID", "backend_42")
    runner = FakeRunner()
    benchmark_mode.install(runner)
    rule_fn = _get_rule_fn(runner)
    briefing = {"active_tasks": [{"task_id": "backend_42", "poster_id": "did:poster"}]}

    d1 = rule_fn(briefing, {})
    assert d1 is not None
    assert d1.action == "report_blocked"
    assert d1.params["task_id"] == "backend_42"

    # Bridge action only once per target task, then yield to LLM.
    d2 = rule_fn(briefing, {})
    assert d2 is None


def test_prefer_target_rule_emits_identity_probe_when_enabled(monkeypatch):
    monkeypatch.setenv("BENCHMARK_TASK_ID", "R01_happy_01")
    monkeypatch.setenv("BENCHMARK_BACKEND_TASK_ID", "backend_42")
    monkeypatch.setenv("BENCHMARK_IDENTITY_PROBE_ENABLED", "1")
    monkeypatch.setenv("AGENT_CAPABILITIES", "trading,analysis")
    runner = FakeRunner()
    benchmark_mode.install(runner)
    rule_fn = _get_rule_fn(runner)
    briefing = {"active_tasks": [{"task_id": "backend_42", "poster_id": "did:poster"}]}

    d1 = rule_fn(briefing, {})
    assert d1 is not None
    assert d1.action == "identity_probe_market"
    assert d1.params["task_id"] == "backend_42"
    assert d1.params["benchmark_task_id"] == "R01_happy_01"

    d2 = rule_fn(briefing, {})
    assert d2 is None


def test_install_registers_identity_probe_bridge_tools(monkeypatch):
    monkeypatch.setenv("BENCHMARK_TASK_ID", "R01_happy_01")
    monkeypatch.setenv("BENCHMARK_BACKEND_TASK_ID", "backend_42")
    runner = FakeRunner()
    benchmark_mode.install(runner)

    for tool_name in (
        "identity_probe_market",
        "identity_probe_field",
        "identity_probe_scholar",
        "identity_probe_general",
    ):
        assert tool_name in runner._tools_registered


def test_prefer_target_rule_no_reclaim_after_active_disappears(monkeypatch):
    monkeypatch.setenv("BENCHMARK_TASK_ID", "R01_test_01")
    monkeypatch.setenv("BENCHMARK_BACKEND_TASK_ID", "backend_42")
    runner = FakeRunner()
    benchmark_mode.install(runner)
    rule_fn = _get_rule_fn(runner)
    # First tick: task is active -> let LLM execute.
    assert rule_fn({"active_tasks": [{"task_id": "backend_42"}]}, {}) is None
    # Next tick: task disappeared -> mark finished and wait (do not re-claim).
    d = rule_fn({"active_tasks": []}, {})
    assert d is not None
    assert d.action == "wait"


def test_g2_mode_probe_delegates_to_llm_before_backend_target(monkeypatch, tmp_path):
    task_file = tmp_path / "task_id.txt"
    backend_file = tmp_path / "backend_task_id.txt"
    task_file.write_text("R01_test_01", encoding="utf-8")
    backend_file.write_text("", encoding="utf-8")
    monkeypatch.setenv("BENCHMARK_TASK_ID", "R01_test_01")
    monkeypatch.setenv("BENCHMARK_BACKEND_TASK_ID", "bootstrap-target")
    monkeypatch.setenv("BENCHMARK_TASK_ID_FILE", str(task_file))
    monkeypatch.setenv("BENCHMARK_BACKEND_TASK_ID_FILE", str(backend_file))
    monkeypatch.setenv("BENCHMARK_G2_MODE_PROBE_ENABLED", "1")
    monkeypatch.setenv("BENCHMARK_G2_MODE_PROBE_MAX_TICKS", "1")
    runner = FakeRunner()
    benchmark_mode.install(runner)
    rule_fn = _get_rule_fn(runner)
    briefing = {
        "pool_tasks": [{"task_id": "seed"}],
        "active_tasks": [{"task_id": "not-target"}],
        "opportunities": [{"id": "opp"}],
        "urgency": [{"task_id": "urgent"}],
    }

    d1 = rule_fn(briefing, {})
    assert d1 is None
    assert briefing["benchmark_g2_mode_probe"]["enabled"] is True
    assert briefing["active_tasks"] == []
    assert briefing["pool_tasks"] == []
    assert briefing["opportunities"] == []
    assert briefing["urgency"] == []

    d2 = rule_fn(briefing, {})
    assert d2 is not None
    assert d2.action == "wait"


# ── on_reflect installation ─────────────────────────────────────────

def test_install_registers_on_reflect_when_csv_env_present(monkeypatch, tmp_path):
    monkeypatch.setenv("BENCHMARK_TASK_ID", "R01_test_01")
    monkeypatch.setenv("BENCHMARK_BACKEND_TASK_ID", "backend_42")
    monkeypatch.setenv("BENCHMARK_RUN_ID", "run-xyz")
    monkeypatch.setenv("BENCHMARK_RAW_CSV", str(tmp_path / "raw.csv"))
    runner = FakeRunner()
    benchmark_mode.install(runner)
    assert runner._on_reflect_fn is not None


def test_install_skips_on_reflect_without_csv_env(monkeypatch):
    monkeypatch.setenv("BENCHMARK_TASK_ID", "R01_test_01")
    monkeypatch.setenv("BENCHMARK_BACKEND_TASK_ID", "backend_42")
    monkeypatch.delenv("BENCHMARK_RAW_CSV", raising=False)
    monkeypatch.delenv("BENCHMARK_RUN_ID", raising=False)
    runner = FakeRunner()
    benchmark_mode.install(runner)
    assert runner._on_reflect_fn is None


# ── _resolve_agent_id ───────────────────────────────────────────────

def test_resolve_agent_id_prefers_sdk_id(monkeypatch):
    monkeypatch.delenv("AGENT_NAME", raising=False)
    runner = FakeRunner()
    class FakeAgent:
        _agent_id = "alpha-bench"
    runner._agent = FakeAgent()
    assert benchmark_mode._resolve_agent_id(runner) == "alpha-bench"


def test_resolve_agent_id_falls_back_to_name():
    runner = FakeRunner()
    runner._name = "Beta Bench"
    assert benchmark_mode._resolve_agent_id(runner) == "beta_bench"


def test_resolve_agent_id_falls_back_to_placeholder(monkeypatch):
    monkeypatch.delenv("AGENT_NAME", raising=False)
    runner = FakeRunner()
    runner._name = None
    assert benchmark_mode._resolve_agent_id(runner) == "unknown-agent"
