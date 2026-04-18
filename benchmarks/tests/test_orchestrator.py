"""Orchestrator state-machine tests using the fake agent."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from benchmarks.orchestrator import (
    EXIT_ABNORMAL, EXIT_AGENT_DONE, EXIT_AGENT_FAILED, EXIT_AGENT_GAVE_UP,
    EXIT_TICK_LIMIT, EXIT_WALL_CLOCK,
    Orchestrator, OrchestratorConfig,
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
