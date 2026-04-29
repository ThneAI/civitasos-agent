#!/usr/bin/env python3
"""G.1 single-machine agent-runner task-state smoke.

Run from the backend drill hook while the three localhost backend nodes are
still alive. The script starts a real AgentRunner for one cognitive tick, then
uses the runner-owned SDK client to read the exact task ids written to the G.1
summary file.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
AIS_ROOT = ROOT.parent
for path in (
    AIS_ROOT / "civitasos-runtime",
    AIS_ROOT / "civitasos-sdk" / "python",
    ROOT,
):
    text = str(path)
    if text not in sys.path:
        sys.path.insert(0, text)

from civitasos_runtime import AgentRunner  # noqa: E402
from civitasos_runtime.llm import LLMAdapter  # noqa: E402
from civitasos_runtime.models import Decision, DecisionSource, LLMResponse  # noqa: E402


class WaitLLM(LLMAdapter):
    """Deterministic no-op LLM; rules should win before this is called."""

    async def _do_chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.3,
    ) -> LLMResponse:
        return LLMResponse(content="wait", tool_calls=[], usage={})


def _load_summary(path: str) -> dict[str, Any]:
    if not path:
        raise SystemExit("G1_SUMMARY_PATH is required")
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _expected_task_ids(summary: dict[str, Any]) -> dict[str, str]:
    latest = summary.get("cycles", [])[-1]
    return {
        "two_node_delivered": latest["two_node"]["delivered_task"],
        "two_node_failed": latest["two_node"]["failed_task"],
        "three_node_failed": latest["three_node"]["failed_task"],
    }


async def _start_runner_for_one_tick(base_url: str) -> tuple[AgentRunner, dict[str, Any]]:
    captured: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="civitasos_g1_agent_runner_") as data_dir:
        runner = AgentRunner(
            base_url=base_url,
            name=f"G1AgentRunnerSmoke-{int(time.time())}",
            capabilities=["general"],
            llm=WaitLLM(max_retries=1, timeout=1),
            heartbeat_interval=3600,
            data_dir=data_dir,
        )

        @runner.rule(priority=0, name="g1_smoke_capture_and_wait")
        def capture_and_wait(briefing: dict[str, Any], _memories: dict[str, Any]) -> Decision:
            captured["briefing_keys"] = sorted(briefing.keys())
            captured["pool_task_count"] = len(briefing.get("pool_tasks", []))
            captured["active_task_count"] = len(briefing.get("active_tasks", []))
            return Decision(
                action="wait",
                reasoning="G.1 smoke: capture one runner briefing without mutating tasks",
                confidence=1.0,
                source=DecisionSource.RULES,
            )

        task = asyncio.create_task(runner.start())
        try:
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                if captured and runner.agent is not None:
                    return runner, captured
                await asyncio.sleep(0.1)
            raise TimeoutError("AgentRunner did not complete one tick in 20s")
        finally:
            await runner.stop()
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass


def _assert_task_state(agent: Any, task_id: str, expected_status: str) -> dict[str, Any]:
    task = agent.pool_get_task(task_id)
    status = task.get("status")
    if status != expected_status:
        raise AssertionError(
            f"task {task_id} expected {expected_status}, got {status}: {task}"
        )
    return task


def _assert_failure_index(agent: Any, task_id: str) -> dict[str, Any]:
    failures = agent.pool_failures(limit=100)
    rows = failures.get("failures", []) if isinstance(failures, dict) else failures
    for row in rows:
        if isinstance(row, dict) and row.get("task_id") == task_id:
            if row.get("failure_reason") != "worker_failed":
                raise AssertionError(f"unexpected failure row for {task_id}: {row}")
            return row
    raise AssertionError(f"failure index missing task {task_id}: {failures}")


async def main() -> int:
    base_url = os.environ.get("NODE_B_URL") or os.environ.get("CIVITASOS_URL")
    if not base_url:
        raise SystemExit("NODE_B_URL or CIVITASOS_URL is required")
    summary = _load_summary(os.environ.get("G1_SUMMARY_PATH", ""))
    task_ids = _expected_task_ids(summary)

    runner, captured = await _start_runner_for_one_tick(base_url)
    agent = runner.agent
    if agent is None:
        raise AssertionError("AgentRunner did not create an SDK agent")

    delivered = _assert_task_state(agent, task_ids["two_node_delivered"], "Completed")
    failed_two = _assert_task_state(agent, task_ids["two_node_failed"], "Failed")
    failed_three = _assert_task_state(agent, task_ids["three_node_failed"], "Failed")
    _assert_failure_index(agent, task_ids["two_node_failed"])
    _assert_failure_index(agent, task_ids["three_node_failed"])

    result = {
        "base_url": base_url,
        "runner_briefing": captured,
        "tasks": {
            "two_node_delivered": {
                "id": delivered.get("id"),
                "status": delivered.get("status"),
                "challenge_deadline_at": delivered.get("challenge_deadline_at"),
            },
            "two_node_failed": {
                "id": failed_two.get("id"),
                "status": failed_two.get("status"),
                "failure_reason": failed_two.get("failure_reason"),
            },
            "three_node_failed": {
                "id": failed_three.get("id"),
                "status": failed_three.get("status"),
                "failure_reason": failed_three.get("failure_reason"),
            },
        },
    }
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    print("[g1-agent-smoke] PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
