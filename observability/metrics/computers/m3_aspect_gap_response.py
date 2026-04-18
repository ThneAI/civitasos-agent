"""M3: aspect_gap_response_rate.

Definition (v1.1, F.0 operationalisation):
    For each task, walk ticks chronologically; find the first tick t where
    aspect_gap >= THETA (0.7). Build action multisets:
        W_pre  = {decision_action of tick[t-N..t-1]}   (N=3, drop empties)
        W_post = {decision_action of tick[t+1..t+N]}
    If both windows non-empty AND Jaccard(W_pre, W_post) < J_MAX (0.5),
    count this task as "responded".
    Indicator = responded_count / triggered_count
"""
from __future__ import annotations

from collections.abc import Iterable

from ._loader import TaskRun, TickRow

THETA = 0.7
N = 3
J_MAX = 0.5


def compute(tasks: Iterable[TaskRun]) -> float | None:
    triggered = 0
    responded = 0
    for t in tasks:
        idx = _first_threshold_crossing(t.ticks)
        if idx is None:
            continue
        triggered += 1
        pre = _action_set(t.ticks, idx - N, idx)
        post = _action_set(t.ticks, idx + 1, idx + 1 + N)
        if not pre or not post:
            continue
        if _jaccard(pre, post) < J_MAX:
            responded += 1
    if triggered == 0:
        return None
    return responded / triggered


def _first_threshold_crossing(ticks: list[TickRow]) -> int | None:
    for i, t in enumerate(ticks):
        if t.aspect_gap >= THETA:
            return i
    return None


def _action_set(ticks: list[TickRow], start: int, stop: int) -> set[str]:
    start = max(0, start)
    stop = min(len(ticks), stop)
    return {ticks[i].decision_action for i in range(start, stop) if ticks[i].decision_action}


def _jaccard(a: set[str], b: set[str]) -> float:
    union = a | b
    if not union:
        return 0.0
    return len(a & b) / len(union)
