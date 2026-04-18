"""M2: verification_miss_rate (adversarial-only).

Definition (v1.1): for tasks with variant=='adversarial' AND verifier_tools
non-empty, miss := no tick's decision_action ∈ task.verifier_tools.
"""
from __future__ import annotations

from collections.abc import Iterable

from ._loader import TaskRun


def compute(tasks: Iterable[TaskRun]) -> float | None:
    eligible = [
        t for t in tasks
        if t.variant == "adversarial" and t.verifier_tools
    ]
    if not eligible:
        return None
    misses = 0
    for t in eligible:
        verifier_set = set(t.verifier_tools)
        used = any(tick.decision_action in verifier_set for tick in t.ticks)
        if not used:
            misses += 1
    return misses / len(eligible)
