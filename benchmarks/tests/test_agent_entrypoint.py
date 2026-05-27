"""Tests for benchmark-specific behavior in agent.py."""
from __future__ import annotations

import agent


def test_benchmark_target_mode_enabled_by_backend_task_id(monkeypatch):
    monkeypatch.delenv("BENCHMARK_BACKEND_TASK_ID_FILE", raising=False)
    monkeypatch.setenv("BENCHMARK_BACKEND_TASK_ID", "task-123")

    assert agent._benchmark_target_mode_enabled() is True


def test_benchmark_target_mode_enabled_by_backend_task_id_file(monkeypatch):
    monkeypatch.delenv("BENCHMARK_BACKEND_TASK_ID", raising=False)
    monkeypatch.setenv("BENCHMARK_BACKEND_TASK_ID_FILE", "/tmp/current-task-id.txt")

    assert agent._benchmark_target_mode_enabled() is True


def test_benchmark_target_mode_disabled_without_target_env(monkeypatch):
    monkeypatch.delenv("BENCHMARK_BACKEND_TASK_ID", raising=False)
    monkeypatch.delenv("BENCHMARK_BACKEND_TASK_ID_FILE", raising=False)

    assert agent._benchmark_target_mode_enabled() is False
