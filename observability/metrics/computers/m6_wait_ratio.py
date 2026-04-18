"""M6: wait_ratio (F.0 弱化版).

Total wait ticks / total ticks across the category.
"""
from __future__ import annotations

from collections.abc import Iterable

from ._loader import TaskRun


def compute(tasks: Iterable[TaskRun]) -> float | None:
    total = 0
    waits = 0
    for t in tasks:
        for tick in t.ticks:
            total += 1
            if tick.is_wait:
                waits += 1
    if total == 0:
        return None
    return waits / total
