"""H1 Telos metrics for served intent and verifier-before-delivery gates."""
from __future__ import annotations

from collections.abc import Iterable

from ._loader import TaskRun, TickRow
from .m2_verification_miss import is_verification_observed

_PURPOSEFUL_WAIT_LAYERS = frozenset({"short", "mid", "long", "telos"})
_DELIVERY_ACTIONS = frozenset({
    "bridge_release",
    "csp_buy",
    "confirm",
    "confirm_transfer",
    "deliver",
    "finalize",
    "task_execute",
    "transfer",
    "transfer_executed",
})
_DELIVERY_HINTS = (
    "confirm",
    "deliver",
    "execute",
    "finalize",
    "release",
    "transfer",
)


def compute(tasks: Iterable[TaskRun]) -> dict[str, float | None]:
    task_list = list(tasks)
    total_ticks = 0
    idle_waits = 0
    purposeful_waits = 0
    non_wait = 0
    non_wait_with_layer = 0
    h1_signal = False

    for task in task_list:
        for tick in task.ticks:
            total_ticks += 1
            if tick.served_intent_layer or tick.wait_references_telos:
                h1_signal = True
            if tick.is_wait:
                if _is_purposeful_wait(tick):
                    purposeful_waits += 1
                else:
                    idle_waits += 1
                continue
            non_wait += 1
            if tick.served_intent_layer:
                non_wait_with_layer += 1

    eligible_verifier_tasks = [task for task in task_list if task.verifier_tools]
    verifier_hits = sum(
        1
        for task in eligible_verifier_tasks
        if verifier_before_delivery_observed(
            verifier_tools=task.verifier_tools,
            decision_actions=[tick.decision_action for tick in task.ticks],
        )
    )

    return {
        "m6_idle_thinking_ratio": _ratio(idle_waits, total_ticks),
        "m6_purposeful_wait_ratio": _ratio(purposeful_waits, total_ticks),
        "h1_served_intent_layer_coverage_ratio": (
            _ratio(non_wait_with_layer, non_wait) if h1_signal else None
        ),
        "h1_verifier_before_delivery_ratio": (
            _ratio(verifier_hits, len(eligible_verifier_tasks)) if h1_signal else None
        ),
    }


def verifier_before_delivery_observed(
    *,
    verifier_tools: Iterable[str],
    decision_actions: Iterable[str],
) -> bool:
    actions = [action for action in decision_actions if action]
    cutoff = _first_delivery_index(actions)
    prefix = actions[:cutoff] if cutoff is not None else actions
    return is_verification_observed(
        verifier_tools=verifier_tools,
        decision_actions=prefix,
    )


def _is_purposeful_wait(tick: TickRow) -> bool:
    layer = (tick.served_intent_layer or "").strip().lower()
    return tick.wait_references_telos or layer in _PURPOSEFUL_WAIT_LAYERS


def _first_delivery_index(actions: list[str]) -> int | None:
    for idx, action in enumerate(actions):
        if _is_delivery_action(action):
            return idx
    return None


def _is_delivery_action(action: str) -> bool:
    value = action.strip().lower()
    return value in _DELIVERY_ACTIONS or any(hint in value for hint in _DELIVERY_HINTS)


def _ratio(numerator: int, denominator: int) -> float | None:
    if denominator == 0:
        return None
    return numerator / denominator