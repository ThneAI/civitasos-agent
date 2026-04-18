"""M5: latency distribution.

Per-tick:  P50/P95/P99 of eval_duration_ms across all ticks of all tasks
            in the category.
Per-task:  P50/P95 of (last_tick.timestamp - first_tick.timestamp) across
            tasks in the category. Timestamps are ISO8601.
"""
from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime
from statistics import quantiles

from ._loader import TaskRun


def compute(tasks: Iterable[TaskRun]) -> dict[str, float | None]:
    tasks = list(tasks)
    tick_durations: list[int] = []
    task_wall_ms: list[float] = []
    for t in tasks:
        for tick in t.ticks:
            if tick.eval_duration_ms is not None:
                tick_durations.append(tick.eval_duration_ms)
        wall = _task_wall_clock_ms(t)
        if wall is not None:
            task_wall_ms.append(wall)
    return {
        "m5_tick_latency_p50_ms": _pct(tick_durations, 0.50),
        "m5_tick_latency_p95_ms": _pct(tick_durations, 0.95),
        "m5_tick_latency_p99_ms": _pct(tick_durations, 0.99),
        "m5_task_latency_p50_ms": _pct(task_wall_ms, 0.50),
        "m5_task_latency_p95_ms": _pct(task_wall_ms, 0.95),
    }


def _task_wall_clock_ms(task: TaskRun) -> float | None:
    if len(task.ticks) < 2:
        return None
    try:
        t0 = _parse_iso(task.ticks[0].timestamp)
        tn = _parse_iso(task.ticks[-1].timestamp)
    except ValueError:
        return None
    return (tn - t0).total_seconds() * 1000.0


def _parse_iso(ts: str) -> datetime:
    # Accept both `Z` and `+00:00` forms.
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    return datetime.fromisoformat(ts)


def _pct(values: list[float] | list[int], p: float) -> float | None:
    if not values:
        return None
    if len(values) == 1:
        return float(values[0])
    # quantiles uses a 1-indexed n-cut method; for percentiles use n=100.
    qs = quantiles(values, n=100, method="inclusive")
    # qs has 99 cut points; index = round(p*100) - 1.
    idx = max(0, min(98, round(p * 100) - 1))
    return float(qs[idx])
