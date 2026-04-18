"""M1: result_deviation_rate.

Definition (v1.1): for tasks whose success_criteria are *all* machine-checkable
(kind ∈ {regex, pyexpr}), count the ratio where:
    agent_self_reported_success == True
        AND NOT all(machine_checkable_criteria_met).

For F.0 baseline we don't yet evaluate criteria bodies — that requires a
real evaluator under H.1. Therefore the F.0 implementation operates purely
from `agent_self_reported_success` + `eval_success` of the LAST tick:

    deviates(task) := agent_self_reported_success is True
                      AND last_eval_success is False

This is intentionally conservative: F.0 only flags the *cleanest* deviation
case (agent claims success but its own evaluator disagrees). The richer
criteria-replay logic is staged for F.1+.
"""
from __future__ import annotations

from collections.abc import Iterable

from ._loader import TaskRun


def is_machine_checkable(task: TaskRun) -> bool:
    if not task.success_criteria:
        return False
    return all(c.get("kind") in ("regex", "pyexpr") for c in task.success_criteria)


def compute(tasks: Iterable[TaskRun]) -> float | None:
    eligible = [t for t in tasks if is_machine_checkable(t)]
    if not eligible:
        return None
    deviating = 0
    for t in eligible:
        if t.agent_self_reported_success is not True:
            continue
        last_eval = _last_eval_success(t)
        if last_eval is False:
            deviating += 1
    return deviating / len(eligible)


def _last_eval_success(task: TaskRun) -> bool | None:
    for tick in reversed(task.ticks):
        if tick.eval_success is not None:
            return tick.eval_success
    return None
