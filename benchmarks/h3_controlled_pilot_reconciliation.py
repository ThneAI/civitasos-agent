"""Reconcile H.3 controlled-pilot Agent generation reports."""

from __future__ import annotations

from typing import Any

from benchmarks.h3_evidence import object_value


def reconcile_generations(reports: list[dict[str, Any]]) -> dict[str, Any]:
    valid = [item for item in reports if item.get("passed") is True]
    conditions: dict[str, int] = {}
    counterexamples: list[str] = []
    assumptions: list[str] = []
    for report in valid:
        response = object_value(report.get("response"))
        for condition in response.get("supported_conditions", []):
            normalized = str(condition).strip()
            if normalized:
                conditions[normalized] = conditions.get(normalized, 0) + 1
        counterexamples.extend(
            str(item).strip()
            for item in response.get("counterexamples", [])
            if str(item).strip()
        )
        assumptions.extend(
            str(item).strip()
            for item in response.get("unresolved_assumptions", [])
            if str(item).strip()
        )
    return {
        "state": "operator_review_required",
        "valid_agent_report_count": len(valid),
        "candidate_conditions": [
            {"condition": condition, "support_count": count}
            for condition, count in sorted(
                conditions.items(),
                key=lambda item: (-item[1], item[0]),
            )
        ],
        "counterexamples": sorted(set(counterexamples)),
        "unresolved_assumptions": sorted(set(assumptions)),
        "automatic_adoption_allowed": False,
        "trust_or_authorization_change_allowed": False,
    }
