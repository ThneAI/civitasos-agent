"""Tests for benchmarks/benchmark_mode.py — install hook semantics."""
from __future__ import annotations

import os
from typing import Any
from unittest.mock import patch

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
        self._loop = None  # set later to simulate post-start
        self._agent = None
        self._name = "test-agent"

    def rule(self, priority: int = 50, name: str = ""):
        return self._rules.rule(priority=priority, name=name)

    def on_reflect(self, fn):
        self._on_reflect_fn = fn
        return fn


# ── install_if_present ──────────────────────────────────────────────

def test_install_no_op_when_env_unset(monkeypatch):
    monkeypatch.delenv("BENCHMARK_TASK_ID", raising=False)
    runner = FakeRunner()
    benchmark_mode.install(runner)
    assert runner._rules.registered == []
    assert runner._on_reflect_fn is None
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
