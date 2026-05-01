"""G.3: relation-memory and relation-time observability.

G.3 is empty for the frozen v1 benchmark unless a task emits relation context.
When relation-aware tasks exist, the metrics verify that decisions can be tied
back to concrete relation memories and a comparable time window.
"""
from __future__ import annotations

from collections.abc import Iterable

from ._loader import TaskRun

_RELATION_REASONING_MARKERS = (
    "relation",
    "peer",
    "trust",
    "challenge",
    "failure",
    "memory",
)


def compute(tasks: Iterable[TaskRun]) -> dict[str, float | None]:
    relation_tasks = []
    for task in tasks:
        if any(_has_relation_context(tick) for tick in task.ticks):
            relation_tasks.append(task)

    if not relation_tasks:
        return {
            "g3_relation_memory_hit_ratio": None,
            "g3_relation_aware_decision_ratio": None,
            "g3_cross_agent_time_consistency_ratio": None,
            "g3_r2r_relation_id_ratio": None,
            "g3_relation_pair_context_ratio": None,
            "g3_relation_pair_failure_ref_ratio": None,
        }

    total = len(relation_tasks)
    memory_hits = sum(1 for task in relation_tasks if _task_has_memory_refs(task))
    relation_aware = sum(1 for task in relation_tasks if _task_has_relation_evidence(task))
    time_windows = sum(1 for task in relation_tasks if _task_has_time_window(task))
    r2r_relation_ids = sum(1 for task in relation_tasks if _task_has_r2r_relation_id(task))
    relation_pairs = sum(1 for task in relation_tasks if _task_has_relation_pair(task))
    failure_event_tasks = [
        task for task in relation_tasks if _task_has_relation_pair_failure_events(task)
    ]
    return {
        "g3_relation_memory_hit_ratio": memory_hits / total,
        "g3_relation_aware_decision_ratio": relation_aware / total,
        "g3_cross_agent_time_consistency_ratio": time_windows / total,
        "g3_r2r_relation_id_ratio": r2r_relation_ids / total,
        "g3_relation_pair_context_ratio": relation_pairs / total,
        "g3_relation_pair_failure_ref_ratio": (
            _ratio(_task_has_relation_pair_failure_ref(task) for task in failure_event_tasks)
            if failure_event_tasks else None
        ),
    }


def _has_relation_context(tick) -> bool:
    return any(
        str(getattr(tick, attr, "") or "").strip()
        for attr in (
            "relation_context_id",
            "relation_memory_refs",
            "time_window_id",
            "challenge_deadline_bucket",
        )
    )


def _task_has_memory_refs(task: TaskRun) -> bool:
    return any(str(tick.relation_memory_refs or "").strip() for tick in task.ticks)


def _task_has_time_window(task: TaskRun) -> bool:
    return any(str(tick.time_window_id or "").strip() for tick in task.ticks)


def _task_has_r2r_relation_id(task: TaskRun) -> bool:
    return any(tick.relation_id_source == "r2r_registry" for tick in task.ticks)


def _task_has_relation_pair(task: TaskRun) -> bool:
    return any(tick.relation_pair_present for tick in task.ticks)


def _task_has_relation_pair_failure_events(task: TaskRun) -> bool:
    return any(tick.relation_pair_failure_events_present for tick in task.ticks)


def _task_has_relation_pair_failure_ref(task: TaskRun) -> bool:
    return any(tick.relation_pair_failure_ref_present for tick in task.ticks)


def _task_has_relation_evidence(task: TaskRun) -> bool:
    for tick in task.ticks:
        if str(tick.relation_memory_refs or "").strip():
            return True
        reasoning = str(tick.decision_reasoning or "").lower()
        if any(marker in reasoning for marker in _RELATION_REASONING_MARKERS):
            return True
    return False


def _ratio(values) -> float:
    items = list(values)
    if not items:
        return 0.0
    return sum(1 for value in items if value) / len(items)
