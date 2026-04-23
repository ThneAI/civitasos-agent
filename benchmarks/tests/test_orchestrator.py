"""Orchestrator state-machine tests using the fake agent."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from benchmarks.orchestrator import (
    EXIT_ABNORMAL, EXIT_AGENT_DONE, EXIT_AGENT_FAILED, EXIT_AGENT_GAVE_UP,
    EXIT_TICK_LIMIT, EXIT_WALL_CLOCK,
    Orchestrator, OrchestratorConfig, _load_cached_result, _tail_actions_all_pool_claim,
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
