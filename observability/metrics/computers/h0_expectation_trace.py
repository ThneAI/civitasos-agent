"""H.0: IEM / expectation trace observability skeleton.

The computer is intentionally nullable until H.0 is enabled. It should not
penalise existing G.2/G.3 runs that emit no expectation trace yet.
"""
from __future__ import annotations

from collections.abc import Iterable

from ._loader import TaskRun


def compute(tasks: Iterable[TaskRun]) -> dict[str, float | None]:
    ticks = [tick for task in tasks for tick in task.ticks]
    traced = [tick for tick in ticks if tick.h0_expectation_trace_present]
    if not traced:
        return {
            "h0_expectation_trace_ratio": None,
            "h0_hard_domain_trace_ratio": None,
            "h0_drive_constitution_verdict_ratio": None,
            "h0_iem_update_log_ratio": None,
            "h0_relation_action_bias_ratio": None,
            "h0_normative_guard_ratio": None,
            "h0_identity_domain_trace_ratio": None,
            "h0_identity_action_bias_ratio": None,
            "h0_constitutional_surprise_ratio": None,
            "h0_normative_governance_trigger_ratio": None,
            "h0_predicted_update_ratio": None,
            "h0_desired_slow_drift_ratio": None,
        }

    denom = len(traced)
    return {
        "h0_expectation_trace_ratio": len(traced) / len(ticks) if ticks else None,
        "h0_hard_domain_trace_ratio": _ratio(
            tick.h0_survival_surprise_present
            and tick.h0_economic_surprise_present
            and tick.h0_relation_surprise_present
            for tick in traced
        ),
        "h0_drive_constitution_verdict_ratio": _ratio(
            tick.h0_drive_constitution_verdict_present for tick in traced
        ),
        "h0_iem_update_log_ratio": _ratio(
            tick.h0_iem_update_log_present for tick in traced
        ),
        "h0_relation_action_bias_ratio": _ratio(
            tick.h0_relation_action_bias_present for tick in traced
        ),
        "h0_normative_guard_ratio": _ratio(
            tick.h0_normative_local_update_blocked for tick in traced
        ),
        "h0_identity_domain_trace_ratio": _ratio(
            tick.h0_survival_surprise_present and tick.h0_economic_surprise_present
            for tick in traced
        ),
        "h0_identity_action_bias_ratio": _ratio(
            tick.h0_identity_action_bias_present for tick in traced
        ),
        "h0_constitutional_surprise_ratio": _ratio(
            tick.h0_constitutional_surprise_present for tick in traced
        ),
        "h0_normative_governance_trigger_ratio": _ratio(
            tick.h0_normative_governance_trigger_present for tick in traced
        ),
        "h0_predicted_update_ratio": _ratio(
            tick.h0_predicted_update_present for tick in traced
        ),
        "h0_desired_slow_drift_ratio": _ratio(
            tick.h0_desired_slow_drift_present for tick in traced
        ),
    }


def _ratio(values) -> float:
    items = list(values)
    if not items:
        return 0.0
    return sum(1 for value in items if value) / len(items)