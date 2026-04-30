"""G.2: LLM subjective-mode choice observability.

The raw signal is emitted only when the LLM explicitly chooses
`mode_request: waiting|deep_think`. Aggregation keeps the metric separate from
M6 wait_ratio so G.2 can prove autonomous mode choice without redefining F.1.
"""
from __future__ import annotations

from collections.abc import Iterable

from ._loader import TaskRun


def compute(tasks: Iterable[TaskRun]) -> dict[str, float | None]:
    total_wait_ticks = 0
    selected = 0
    selected_waiting = 0
    selected_deep_think = 0

    for task in tasks:
        for tick in task.ticks:
            if tick.is_wait:
                total_wait_ticks += 1
            if not tick.llm_mode_selected:
                continue
            selected += 1
            if tick.llm_mode_request == "waiting":
                selected_waiting += 1
            elif tick.llm_mode_request == "deep_think":
                selected_deep_think += 1

    if total_wait_ticks == 0:
        observable_ratio = None
    else:
        observable_ratio = selected / total_wait_ticks

    if selected == 0:
        return {
            "g2_mode_choice_observable_ratio": observable_ratio,
            "g2_llm_waiting_ratio": None,
            "g2_llm_deep_think_ratio": None,
        }

    return {
        "g2_mode_choice_observable_ratio": observable_ratio,
        "g2_llm_waiting_ratio": selected_waiting / selected,
        "g2_llm_deep_think_ratio": selected_deep_think / selected,
    }
