"""M4: lessons_impact_rate (H.2-lite).

Operational definition:
  Eligible task:
    - contains at least one failed tick (eval_success=False),
    - then recovers (later eval_success=True),
    - and exposes lessons_count signal (max lessons_count > 0).

  Impacted task:
    lessons_count at first recovery tick > lessons_count at first failure tick.

Metric:
  impacted / eligible
"""
from __future__ import annotations

from collections.abc import Iterable

from ._loader import TaskRun, TickRow


def _first_failure_idx(ticks: list[TickRow]) -> int | None:
    for i, t in enumerate(ticks):
        if t.eval_success is False:
            return i
    return None


def _first_recovery_idx(ticks: list[TickRow], after_idx: int) -> int | None:
    for i in range(after_idx + 1, len(ticks)):
        if ticks[i].eval_success is True:
            return i
    return None


def compute(tasks: Iterable[TaskRun]) -> tuple[float | None, str]:
    eligible = 0
    impacted = 0
    for t in tasks:
        ticks = t.ticks
        if not ticks:
            continue
        fail_idx = _first_failure_idx(ticks)
        if fail_idx is None:
            continue
        recover_idx = _first_recovery_idx(ticks, fail_idx)
        if recover_idx is None:
            continue
        if max((x.lessons_count for x in ticks), default=0) <= 0:
            continue

        eligible += 1
        if ticks[recover_idx].lessons_count > ticks[fail_idx].lessons_count:
            impacted += 1

    if eligible == 0:
        return None, "insufficient M4 signal (need fail->success + lessons_count>0)"

    return impacted / eligible, f"computed from {eligible} eligible task(s)"
