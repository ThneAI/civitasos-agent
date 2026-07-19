"""Paired J1-D outcome evaluation with synthetic-evidence isolation."""

from __future__ import annotations

import random
from collections import defaultdict
from statistics import fmean
from typing import Any

from .controlled_comparison import (
    REQUIRED_SCENARIOS,
    canonical_sha256,
    validate_protocol,
)
from .matched_assignment import ASSIGNMENT_SCHEMA


EVALUATION_SCHEMA = "j1-controlled-comparison-evaluation:v1"


def evaluate_cohorts(
    protocol: dict[str, Any],
    assignment: dict[str, Any],
    records: list[dict[str, Any]],
) -> dict[str, Any]:
    failures = validate_protocol(protocol)
    protocol_hash = canonical_sha256(protocol)
    if (
        assignment.get("schema_version") != ASSIGNMENT_SCHEMA
        or assignment.get("passed") is not True
    ):
        failures.append("assignment_manifest_invalid")
    if assignment.get("protocol_sha256") != protocol_hash:
        failures.append("assignment_protocol_hash_mismatch")
    expected_assignment_hash = canonical_sha256(
        {
            "protocol_sha256": assignment.get("protocol_sha256"),
            "assignments": assignment.get("assignments"),
        }
    )
    if assignment.get("assignment_sha256") != expected_assignment_hash:
        failures.append("assignment_manifest_hash_mismatch")

    assigned = _assignment_index(assignment, failures)
    budget = protocol.get("frozen_stack", {}).get("budget", {})
    max_tasks = _positive_limit(budget.get("max_tasks"))
    observed: dict[str, dict[str, Any]] = {}
    for record in records:
        participant_id = str(record.get("participant_id") or "")
        if participant_id in observed:
            failures.append("duplicate_result_record")
        elif participant_id not in assigned:
            failures.append("unassigned_result_record")
        else:
            _validate_record(
                record,
                cohort=assigned[participant_id]["cohort"],
                protocol_sha256=protocol_hash,
                assignment_sha256=expected_assignment_hash,
                max_tasks=max_tasks,
                budget=budget,
                failures=failures,
            )
            observed[participant_id] = record
    if set(observed) != set(assigned):
        failures.append("result_record_set_incomplete")

    pairs: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)
    for participant_id, item in assigned.items():
        record = observed.get(participant_id)
        if record is not None:
            pairs[item["pair_id"]][item["cohort"]] = record
    if any(set(pair) != {"mentor", "control"} for pair in pairs.values()):
        failures.append("paired_results_incomplete")

    metrics = _metrics(protocol, list(pairs.values())) if not failures else {}
    safeguards = _safeguards(records)
    coverage = _scenario_coverage(records)
    if safeguards["sovereignty_violation_count"] != 0:
        failures.append("sovereignty_violation_observed")
    if safeguards["direct_trust_increment_count"] != 0:
        failures.append("direct_trust_increment_observed")
    if safeguards["provenance_completeness"] != 1.0:
        failures.append("advice_provenance_incomplete")
    if set(coverage) != REQUIRED_SCENARIOS or not all(coverage.values()):
        failures.append("required_scenario_coverage_incomplete")

    structural_passed = not failures
    thresholds_met = structural_passed and _thresholds_met(
        protocol, metrics, safeguards
    )
    synthetic = assignment.get("synthetic_dry_run_only") is True
    return {
        "schema_version": EVALUATION_SCHEMA,
        "passed": structural_passed,
        "failure_reasons": list(dict.fromkeys(failures)),
        "protocol_sha256": protocol_hash,
        "assignment_sha256": assignment.get("assignment_sha256"),
        "records_sha256": canonical_sha256(records),
        "matched_pair_count": len(pairs),
        "metrics": metrics,
        "safeguards": safeguards,
        "scenario_coverage": coverage,
        "effectiveness_thresholds_met": thresholds_met,
        "synthetic_dry_run_only": synthetic,
        "valid_for_qualification": False,
        "state": (
            "synthetic_evaluator_validated_effectiveness_not_verified"
            if structural_passed and synthetic
            else "blocked_j1_controlled_comparison_evaluation"
        ),
    }


def _assignment_index(
    assignment: dict[str, Any], failures: list[str]
) -> dict[str, dict[str, Any]]:
    values = assignment.get("assignments")
    if not isinstance(values, list):
        failures.append("assignment_entries_invalid")
        return {}
    assigned: dict[str, dict[str, Any]] = {}
    pairs: dict[str, set[str]] = defaultdict(set)
    pair_counts: dict[str, int] = defaultdict(int)
    for item in values:
        if not isinstance(item, dict):
            failures.append("assignment_entry_invalid")
            continue
        participant_id = str(item.get("participant_id") or "").strip()
        pair_id = str(item.get("pair_id") or "").strip()
        cohort = item.get("cohort")
        if (
            not participant_id
            or not pair_id
            or cohort not in {"mentor", "control"}
            or not str(item.get("strata_sha256") or "").strip()
        ):
            failures.append("assignment_entry_invalid")
            continue
        if participant_id in assigned:
            failures.append("assignment_participant_duplicate")
            continue
        assigned[participant_id] = item
        pairs[pair_id].add(cohort)
        pair_counts[pair_id] += 1
    if any(
        cohorts != {"mentor", "control"} or pair_counts[pair_id] != 2
        for pair_id, cohorts in pairs.items()
    ):
        failures.append("assignment_pairs_invalid")
    if assignment.get("participant_count") != len(assigned):
        failures.append("assignment_participant_count_mismatch")
    if assignment.get("matched_pair_count") != len(pairs):
        failures.append("assignment_pair_count_mismatch")
    return assigned


def _validate_record(
    record: dict[str, Any],
    *,
    cohort: str,
    protocol_sha256: str,
    assignment_sha256: str,
    max_tasks: int,
    budget: dict[str, Any],
    failures: list[str],
) -> None:
    if record.get("protocol_sha256") != protocol_sha256:
        failures.append("result_protocol_hash_mismatch")
    if record.get("assignment_sha256") != assignment_sha256:
        failures.append("result_assignment_hash_mismatch")
    if record.get("evidence_mode") != "synthetic_dry_run":
        failures.append("result_evidence_mode_invalid")
    count_fields = (
        "active_runtime_seconds",
        "token_count",
        "cost_microunits",
        "repeated_error_count",
        "repeated_error_opportunities",
        "pattern_prediction_count",
        "pattern_false_positive_count",
        "expected_provenance_count",
        "complete_provenance_count",
        "sovereignty_violation_count",
        "direct_trust_increment_count",
    )
    invalid_counts = [
        field for field in count_fields if not _is_nonnegative_int(record.get(field))
    ]
    if invalid_counts:
        failures.extend(f"result_{field}_invalid" for field in invalid_counts)
        return
    if record["repeated_error_count"] > record["repeated_error_opportunities"]:
        failures.append("result_repeated_error_counts_invalid")
    if record["pattern_false_positive_count"] > record["pattern_prediction_count"]:
        failures.append("result_pattern_prediction_counts_invalid")
    if record["complete_provenance_count"] > record["expected_provenance_count"]:
        failures.append("result_provenance_counts_invalid")
    if record["active_runtime_seconds"] > _positive_limit(
        budget.get("max_active_seconds")
    ):
        failures.append("result_active_runtime_budget_exceeded")
    if record["token_count"] > _positive_limit(budget.get("max_tokens")):
        failures.append("result_token_budget_exceeded")
    if record["cost_microunits"] > _positive_limit(budget.get("max_cost_microunits")):
        failures.append("result_cost_budget_exceeded")
    if cohort == "mentor" and record["expected_provenance_count"] == 0:
        failures.append("mentor_provenance_expectation_missing")
    if cohort == "control" and (
        record["expected_provenance_count"] != 0
        or record["complete_provenance_count"] != 0
        or record["pattern_prediction_count"] != 0
        or record["pattern_false_positive_count"] != 0
    ):
        failures.append("control_cohort_mentor_data_observed")
    maturity = record.get("maturity_task_count")
    if maturity is not None and (
        type(maturity) is not int or not 1 <= maturity <= max_tasks
    ):
        failures.append("result_maturity_task_count_invalid")
    if maturity is not None and _maturity(record, max_tasks) == max_tasks + 1:
        failures.append("result_maturity_criteria_invalid")
    scenarios = record.get("scenario_results")
    if not isinstance(scenarios, dict) or set(scenarios) != REQUIRED_SCENARIOS:
        failures.append("result_scenario_set_invalid")
    elif any(type(value) is not bool for value in scenarios.values()):
        failures.append("result_scenario_value_invalid")


def _is_nonnegative_int(value: Any) -> bool:
    return type(value) is int and value >= 0


def _positive_limit(value: Any) -> int:
    return value if type(value) is int and value > 0 else 0


def _metrics(
    protocol: dict[str, Any], pairs: list[dict[str, dict[str, Any]]]
) -> dict[str, Any]:
    max_tasks = protocol["frozen_stack"]["budget"]["max_tasks"]
    mentor_times = [_maturity(pair["mentor"], max_tasks) for pair in pairs]
    control_times = [_maturity(pair["control"], max_tasks) for pair in pairs]
    mentor_mean = fmean(mentor_times)
    control_mean = fmean(control_times)
    reduction = 1.0 - mentor_mean / control_mean if control_mean else 0.0
    bootstrap = _paired_bootstrap(protocol, mentor_times, control_times)
    mentor_errors, mentor_opportunities = _error_totals(pairs, "mentor")
    control_errors, control_opportunities = _error_totals(pairs, "control")
    mentor_rate = mentor_errors / mentor_opportunities if mentor_opportunities else 0.0
    control_rate = (
        control_errors / control_opportunities if control_opportunities else 0.0
    )
    predictions = sum(
        int(pair["mentor"].get("pattern_prediction_count", 0)) for pair in pairs
    )
    false_positives = sum(
        int(pair["mentor"].get("pattern_false_positive_count", 0)) for pair in pairs
    )
    mentor_cost = sum(int(pair["mentor"].get("cost_microunits", 0)) for pair in pairs)
    control_cost = sum(int(pair["control"].get("cost_microunits", 0)) for pair in pairs)
    avoided_errors = control_errors - mentor_errors
    return {
        "strategy_maturity_time": {
            "mentor_mean_tasks": mentor_mean,
            "control_mean_tasks": control_mean,
            "mentor_mean_active_runtime_seconds": _cohort_mean(
                pairs, "mentor", "active_runtime_seconds"
            ),
            "control_mean_active_runtime_seconds": _cohort_mean(
                pairs, "control", "active_runtime_seconds"
            ),
            "mentor_mean_token_count": _cohort_mean(pairs, "mentor", "token_count"),
            "control_mean_token_count": _cohort_mean(pairs, "control", "token_count"),
            "relative_reduction": reduction,
            "paired_bootstrap_95pct": bootstrap,
        },
        "repeated_error_rate": {
            "mentor": mentor_rate,
            "control": control_rate,
            "absolute_reduction": control_rate - mentor_rate,
            "relative_reduction": 1.0 - mentor_rate / control_rate
            if control_rate
            else 0.0,
        },
        "mentor_pattern_prediction_count": predictions,
        "mentor_pattern_false_positive_rate": (
            false_positives / predictions if predictions else 0.0
        ),
        "unit_improvement_cost": {
            "mentor_cost_microunits": mentor_cost,
            "control_cost_microunits": control_cost,
            "incremental_cost_per_avoided_error": (
                (mentor_cost - control_cost) / avoided_errors
                if avoided_errors > 0
                else None
            ),
        },
    }


def _paired_bootstrap(
    protocol: dict[str, Any], mentor: list[int], control: list[int]
) -> list[float]:
    iterations = protocol["analysis"]["bootstrap_iterations"]
    rng = random.Random(canonical_sha256([protocol["assignment"]["seed"], "bootstrap"]))
    values = []
    for _ in range(iterations):
        indices = [rng.randrange(len(mentor)) for _ in mentor]
        mentor_mean = fmean(mentor[index] for index in indices)
        control_mean = fmean(control[index] for index in indices)
        values.append(1.0 - mentor_mean / control_mean if control_mean else 0.0)
    values.sort()
    return [values[int(iterations * 0.025)], values[int(iterations * 0.975) - 1]]


def _maturity(record: dict[str, Any], max_tasks: int) -> int:
    value = record.get("maturity_task_count")
    criteria = record.get("maturity_criteria")
    expected = {
        "consecutive_verified_tasks": 3,
        "hard_violation_count": 0,
        "repeated_error_free_window": True,
        "evidence_complete": True,
        "operator_override_used": False,
    }
    return (
        value
        if type(value) is int and 1 <= value <= max_tasks and criteria == expected
        else max_tasks + 1
    )


def _cohort_mean(
    pairs: list[dict[str, dict[str, Any]]], cohort: str, field: str
) -> float:
    return fmean(pair[cohort][field] for pair in pairs)


def _error_totals(
    pairs: list[dict[str, dict[str, Any]]], cohort: str
) -> tuple[int, int]:
    return (
        sum(int(pair[cohort].get("repeated_error_count", 0)) for pair in pairs),
        sum(int(pair[cohort].get("repeated_error_opportunities", 0)) for pair in pairs),
    )


def _safeguards(records: list[dict[str, Any]]) -> dict[str, Any]:
    expected = sum(_count(record, "expected_provenance_count") for record in records)
    complete = sum(_count(record, "complete_provenance_count") for record in records)
    return {
        "sovereignty_violation_count": sum(
            _count(record, "sovereignty_violation_count") for record in records
        ),
        "direct_trust_increment_count": sum(
            _count(record, "direct_trust_increment_count") for record in records
        ),
        "provenance_completeness": complete / expected if expected else 1.0,
    }


def _count(record: dict[str, Any], field: str) -> int:
    value = record.get(field)
    return value if _is_nonnegative_int(value) else 0


def _scenario_coverage(records: list[dict[str, Any]]) -> dict[str, bool]:
    observed = {scenario: False for scenario in REQUIRED_SCENARIOS}
    for record in records:
        scenarios = record.get("scenario_results")
        if isinstance(scenarios, dict):
            for scenario in observed:
                observed[scenario] = (
                    observed[scenario] or scenarios.get(scenario) is True
                )
    return observed


def _thresholds_met(
    protocol: dict[str, Any], metrics: dict[str, Any], safeguards: dict[str, Any]
) -> bool:
    thresholds = protocol["metrics"]
    return (
        metrics["strategy_maturity_time"]["relative_reduction"]
        >= thresholds["strategy_maturity_time"]["minimum_relative_reduction"]
        and metrics["repeated_error_rate"]["absolute_reduction"] > 0
        and metrics["mentor_pattern_prediction_count"] > 0
        and metrics["mentor_pattern_false_positive_rate"]
        <= thresholds["mentor_pattern_false_positive_rate"]["maximum_rate"]
        and safeguards["provenance_completeness"]
        == thresholds["advice_provenance_completeness"]["required_ratio"]
        and safeguards["sovereignty_violation_count"] == 0
        and safeguards["direct_trust_increment_count"] == 0
    )
