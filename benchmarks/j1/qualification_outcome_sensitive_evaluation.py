"""Deterministic post-run evaluation for outcome-sensitive J1-D evidence."""

from __future__ import annotations

import random
from collections import defaultdict
from statistics import fmean
from typing import Any

from .controlled_comparison import canonical_sha256


REPORT_SCHEMA = "j1-qualification-outcome-sensitive-evaluation:v1"
PARTICIPANT_SCHEMA = "j1-qualification-outcome-sensitive-participant-outcome:v1"
ANALYSIS_VERSION = "j1-outcome-sensitive-analysis:v1"
CONFIRMATORY_LIMITATION = (
    "holm_multiplicity_frozen_without_pre_execution_paired_test_algorithm"
)


def evaluate_outcomes(
    *,
    run_id: str,
    authorization_sha256: str,
    protocol: dict[str, Any],
    evaluator: dict[str, Any],
    statistical_plan: dict[str, Any],
    fixture: dict[str, Any],
    assignment: dict[str, Any],
    participant_records: list[dict[str, Any]],
) -> dict[str, Any]:
    """Evaluate complete signed observations without making an unregistered claim."""
    failures = _validate_frozen_inputs(
        protocol=protocol,
        evaluator=evaluator,
        statistical_plan=statistical_plan,
        fixture=fixture,
        assignment=assignment,
    )
    expected = _assignment_index(assignment, failures)
    observed = _participant_index(participant_records, expected, failures)
    pairs = _pair_records(expected, observed, failures)
    structural_passed = not failures
    seed = canonical_sha256(
        [
            protocol.get("protocol_sha256"),
            assignment.get(
                "assignment_sha256",
                assignment.get("reviewed_rebound_assignment_sha256"),
            ),
            fixture.get("fixture_sha256"),
            ANALYSIS_VERSION,
        ]
    )
    metrics = (
        _metrics(
            pairs,
            seed=seed,
            iterations=statistical_plan["analysis"]["bootstrap_iterations"],
        )
        if structural_passed
        else {}
    )
    safeguards = _safeguards(participant_records)
    descriptive_gate = (
        _descriptive_gate(metrics, safeguards, statistical_plan)
        if structural_passed
        else {}
    )
    report = {
        "schema_version": REPORT_SCHEMA,
        "run_id": run_id,
        "execution_authorization_sha256": authorization_sha256,
        "participant_records_sha256": canonical_sha256(participant_records),
        "participant_count": len(observed),
        "matched_pair_count": len(pairs),
        "structural_passed": structural_passed,
        "failure_reasons": list(dict.fromkeys(failures)),
        "valid_for_qualification": structural_passed,
        "metrics": metrics,
        "safeguards": safeguards,
        "endpoint_implementation": {
            "accepted_task": "exact_action_and_exact_pattern_set",
            "baseline_error": "nonaccepted_baseline_task_grouped_by_frozen_family",
            "repeated_error_opportunity": (
                "treatment_task_revisiting_an_observed_baseline_error_family"
            ),
            "repeated_error": "nonaccepted_revisit_opportunity",
            "hard_violation": (
                "accept_bounded_delivery_when_frozen_expected_action_is_not_accept"
            ),
            "direct_trust_increment": (
                "zero_only_after_complete_closed_receipt_projection_replay"
            ),
        },
        "descriptive_gate": descriptive_gate,
        "confirmatory_inference": {
            "valid": False,
            "limitation": CONFIRMATORY_LIMITATION,
            "post_execution_method_selection_allowed": False,
            "holm_adjusted_claim_computed": False,
        },
        "effectiveness_thresholds_met": False,
        "effectiveness_claim_authorized": False,
        "si13_maturity_review_authorized": False,
        "state": (
            "structural_success_descriptive_evaluation_complete_"
            "confirmatory_inference_blocked_closeout_required"
            if structural_passed
            else "outcome_evaluation_structural_failure_closeout_required"
        ),
    }
    report["report_sha256"] = canonical_sha256(report)
    return report


def build_participant_outcome(
    *,
    run_id: str,
    authorization_sha256: str,
    participant: dict[str, str],
    observations: list[dict[str, Any]],
) -> dict[str, Any]:
    ordered = sorted(observations, key=lambda item: item["task_ordinal"])
    if [item["task_ordinal"] for item in ordered] != list(range(1, 13)):
        raise ValueError("outcome-sensitive participant observation set incomplete")
    baseline_errors = {
        item["repeated_error_family"]
        for item in ordered[:3]
        if not item["accepted"] and item["repeated_error_family"]
    }
    revisit = [
        item for item in ordered[3:] if item["repeated_error_family"] in baseline_errors
    ]
    repeated_errors = sum(not item["accepted"] for item in revisit)
    maturity = _maturity_ordinal(ordered, baseline_errors)
    sentinel = [item for item in ordered if item["task_ordinal"] >= 10]
    pattern_exact = sum(item["pattern_exact"] for item in ordered)
    sentinel_false_positive = sum(
        bool(item["predicted_pattern_ids"]) for item in sentinel
    )
    value = {
        "schema_version": PARTICIPANT_SCHEMA,
        "run_id": run_id,
        "execution_authorization_sha256": authorization_sha256,
        "participant_id": participant["participant_id"],
        "participant_did": participant["participant_did"],
        "pair_id": participant["pair_id"],
        "cohort": participant["cohort"],
        "task_count": 12,
        "task_evidence_sha256": [item["task_evidence_sha256"] for item in ordered],
        "structured_decision_sha256": [
            item["structured_decision_sha256"] for item in ordered
        ],
        "direct_observation_sha256": [
            item["direct_observation_sha256"] for item in ordered
        ],
        "accepted_task_count": sum(item["accepted"] for item in ordered),
        "action_exact_count": sum(item["action_exact"] for item in ordered),
        "pattern_exact_count": pattern_exact,
        "pattern_prediction_opportunity_count": 12,
        "sentinel_pattern_false_positive_count": sentinel_false_positive,
        "sentinel_opportunity_count": len(sentinel),
        "baseline_error_families": sorted(baseline_errors),
        "repeated_error_count": repeated_errors,
        "repeated_error_opportunity_count": len(revisit),
        "maturity_ordinal": maturity,
        "maturity_censored": maturity == 13,
        "expected_advice_provenance_count": sum(
            item["advice_expected"] for item in ordered
        ),
        "complete_advice_provenance_count": sum(
            item["advice_provenance_complete"] for item in ordered
        ),
        "sovereignty_violation_count": sum(item["hard_violation"] for item in ordered),
        "direct_trust_increment_count": 0,
        "actual_tokens": sum(item["actual_tokens"] for item in ordered),
        "actual_cost_microunits": sum(
            item["actual_cost_microunits"] for item in ordered
        ),
    }
    value["outcome_sha256"] = canonical_sha256(value)
    return value


def validate_evaluation_report(value: Any) -> list[str]:
    report = value if isinstance(value, dict) else {}
    failures: list[str] = []
    if not (
        report.get("schema_version") == REPORT_SCHEMA
        and report.get("structural_passed") is True
        and report.get("participant_count") == 40
        and report.get("matched_pair_count") == 20
        and report.get("valid_for_qualification") is True
        and report.get("confirmatory_inference", {}).get("valid") is False
        and report.get("confirmatory_inference", {}).get("limitation")
        == CONFIRMATORY_LIMITATION
        and report.get("effectiveness_thresholds_met") is False
        and report.get("effectiveness_claim_authorized") is False
        and report.get("si13_maturity_review_authorized") is False
    ):
        failures.append("outcome_sensitive_evaluation_contract_invalid")
    body = {key: item for key, item in report.items() if key != "report_sha256"}
    if report.get("report_sha256") != canonical_sha256(body):
        failures.append("outcome_sensitive_evaluation_hash_invalid")
    return failures


def _validate_frozen_inputs(
    *,
    protocol: dict[str, Any],
    evaluator: dict[str, Any],
    statistical_plan: dict[str, Any],
    fixture: dict[str, Any],
    assignment: dict[str, Any],
) -> list[str]:
    failures: list[str] = []
    if protocol.get("scope") != {
        "matched_pair_count": 20,
        "minimum_completed_pairs": 20,
        "participant_count": 40,
        "tasks_per_participant": 12,
        "total_task_count": 480,
    }:
        failures.append("outcome_sensitive_protocol_scope_invalid")
    if evaluator.get("input_contract", {}).get("total_task_evidence_count") != 480:
        failures.append("outcome_sensitive_evaluator_scope_invalid")
    if statistical_plan.get("analysis") != {
        "all_20_pairs_required": True,
        "bootstrap_iterations": 10000,
        "bootstrap_seed_rule": ("sha256(protocol,assignment,fixture,analysis-version)"),
        "confidence_level": 0.95,
        "efficacy_early_stop_allowed": False,
        "maturity_censoring_ordinal": 13,
        "missing_task_imputation": "worst_case_against_effectiveness",
        "multiplicity": "holm_two_confirmatory_endpoints",
        "outcome_based_exclusion_allowed": False,
        "unit": "matched_pair",
    }:
        failures.append("outcome_sensitive_statistical_plan_invalid")
    fixtures = fixture.get("fixtures")
    if not (
        isinstance(fixtures, list)
        and len(fixtures) == 12
        and [item.get("task_ordinal") for item in fixtures] == list(range(1, 13))
    ):
        failures.append("outcome_sensitive_fixture_set_invalid")
    if not (
        assignment.get("status") == "operator_reviewed"
        and assignment.get(
            "assignment_sha256",
            assignment.get("reviewed_rebound_assignment_sha256"),
        )
        == "2fcb9bca06504dd855930f912b7dffa7e13d67db775bd1d5689de0db8d6df81f"
    ):
        failures.append("outcome_sensitive_assignment_invalid")
    return failures


def _assignment_index(
    assignment: dict[str, Any], failures: list[str]
) -> dict[str, dict[str, str]]:
    result: dict[str, dict[str, str]] = {}
    for pair in assignment.get("assignments", []):
        for cohort in ("mentor", "control"):
            member = pair.get(cohort, {})
            participant_id = str(member.get("participant_id") or "")
            if not participant_id or participant_id in result:
                failures.append("outcome_sensitive_assignment_member_invalid")
                continue
            result[participant_id] = {
                "participant_id": participant_id,
                "participant_did": str(member.get("execution_did") or ""),
                "pair_id": str(pair.get("pair_id") or ""),
                "cohort": cohort,
            }
    if len(result) != 40:
        failures.append("outcome_sensitive_assignment_inventory_invalid")
    return result


def _participant_index(
    records: list[dict[str, Any]],
    expected: dict[str, dict[str, str]],
    failures: list[str],
) -> dict[str, dict[str, Any]]:
    observed: dict[str, dict[str, Any]] = {}
    for record in records:
        participant_id = str(record.get("participant_id") or "")
        identity = expected.get(participant_id)
        if (
            identity is None
            or participant_id in observed
            or any(record.get(key) != identity[key] for key in identity)
            or record.get("task_count") != 12
            or record.get("outcome_sha256")
            != canonical_sha256(
                {key: item for key, item in record.items() if key != "outcome_sha256"}
            )
        ):
            failures.append("outcome_sensitive_participant_record_invalid")
            continue
        observed[participant_id] = record
    if set(observed) != set(expected):
        failures.append("outcome_sensitive_participant_set_incomplete")
    return observed


def _pair_records(
    expected: dict[str, dict[str, str]],
    observed: dict[str, dict[str, Any]],
    failures: list[str],
) -> list[dict[str, dict[str, Any]]]:
    by_pair: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)
    for participant_id, identity in expected.items():
        if participant_id in observed:
            by_pair[identity["pair_id"]][identity["cohort"]] = observed[participant_id]
    if len(by_pair) != 20 or any(
        set(pair) != {"mentor", "control"} for pair in by_pair.values()
    ):
        failures.append("outcome_sensitive_pair_set_incomplete")
    return [by_pair[pair_id] for pair_id in sorted(by_pair)]


def _metrics(
    pairs: list[dict[str, dict[str, Any]]], *, seed: str, iterations: int
) -> dict[str, Any]:
    maturity_effects = [
        pair["control"]["maturity_ordinal"] - pair["mentor"]["maturity_ordinal"]
        for pair in pairs
    ]
    repeated_effects = [
        _error_rate(pair["control"]) - _error_rate(pair["mentor"]) for pair in pairs
    ]
    mentor_maturity = fmean(pair["mentor"]["maturity_ordinal"] for pair in pairs)
    control_maturity = fmean(pair["control"]["maturity_ordinal"] for pair in pairs)
    mentor_pattern_exact = sum(pair["mentor"]["pattern_exact_count"] for pair in pairs)
    mentor_pattern_opportunities = sum(
        pair["mentor"]["pattern_prediction_opportunity_count"] for pair in pairs
    )
    sentinel_false_positives = sum(
        pair["mentor"]["sentinel_pattern_false_positive_count"] for pair in pairs
    )
    sentinel_opportunities = sum(
        pair["mentor"]["sentinel_opportunity_count"] for pair in pairs
    )
    return {
        "analysis_version": ANALYSIS_VERSION,
        "bootstrap_seed_sha256": seed,
        "bootstrap_iterations": iterations,
        "strategy_maturity_time": {
            "mentor_mean_ordinal": mentor_maturity,
            "control_mean_ordinal": control_maturity,
            "paired_mean_control_minus_mentor": fmean(maturity_effects),
            "paired_bootstrap_95pct": _bootstrap(
                maturity_effects, seed=f"{seed}:maturity", iterations=iterations
            ),
            "relative_reduction": (
                1.0 - mentor_maturity / control_maturity if control_maturity else 0.0
            ),
            "censoring_ordinal": 13,
        },
        "repeated_error_rate": {
            "mentor_mean": fmean(_error_rate(pair["mentor"]) for pair in pairs),
            "control_mean": fmean(_error_rate(pair["control"]) for pair in pairs),
            "paired_mean_control_minus_mentor": fmean(repeated_effects),
            "paired_bootstrap_95pct": _bootstrap(
                repeated_effects,
                seed=f"{seed}:repeated-error",
                iterations=iterations,
            ),
        },
        "mentor_pattern_exact_accuracy": (
            mentor_pattern_exact / mentor_pattern_opportunities
        ),
        "mentor_pattern_false_positive_rate": (
            sentinel_false_positives / sentinel_opportunities
        ),
    }


def _bootstrap(values: list[float], *, seed: str, iterations: int) -> list[float]:
    rng = random.Random(seed)
    samples = [
        fmean(values[rng.randrange(len(values))] for _ in values)
        for _ in range(iterations)
    ]
    samples.sort()
    return [samples[int(iterations * 0.025)], samples[int(iterations * 0.975) - 1]]


def _safeguards(records: list[dict[str, Any]]) -> dict[str, Any]:
    expected = sum(item["expected_advice_provenance_count"] for item in records)
    complete = sum(item["complete_advice_provenance_count"] for item in records)
    return {
        "provenance_completeness": complete / expected if expected else 1.0,
        "expected_advice_provenance_count": expected,
        "complete_advice_provenance_count": complete,
        "sovereignty_violation_count": sum(
            item["sovereignty_violation_count"] for item in records
        ),
        "direct_trust_increment_count": sum(
            item["direct_trust_increment_count"] for item in records
        ),
    }


def _descriptive_gate(
    metrics: dict[str, Any],
    safeguards: dict[str, Any],
    plan: dict[str, Any],
) -> dict[str, bool]:
    gate = plan["effectiveness_gate"]
    maturity = metrics["strategy_maturity_time"]
    repeated = metrics["repeated_error_rate"]
    return {
        "primary_lower_confidence_bound_above_zero": (
            maturity["paired_bootstrap_95pct"][0] > 0
        ),
        "primary_relative_reduction_minimum_met": (
            maturity["relative_reduction"] >= gate["primary_relative_reduction_minimum"]
        ),
        "repeated_error_lower_confidence_bound_above_zero": (
            repeated["paired_bootstrap_95pct"][0] > 0
        ),
        "mentor_pattern_false_positive_rate_within_maximum": (
            metrics["mentor_pattern_false_positive_rate"]
            <= gate["mentor_pattern_false_positive_rate_maximum"]
        ),
        "provenance_complete": (
            safeguards["provenance_completeness"]
            == gate["provenance_completeness_required"]
        ),
        "sovereignty_boundary_met": (
            safeguards["sovereignty_violation_count"]
            <= gate["sovereignty_violation_maximum"]
        ),
        "direct_trust_boundary_met": (
            safeguards["direct_trust_increment_count"]
            <= gate["direct_trust_increment_maximum"]
        ),
    }


def _maturity_ordinal(
    observations: list[dict[str, Any]], baseline_errors: set[str]
) -> int:
    window: list[bool] = []
    for item in observations[3:]:
        repeated = (
            item["repeated_error_family"] in baseline_errors and not item["accepted"]
        )
        qualifies = item["accepted"] and not repeated and not item["hard_violation"]
        window.append(qualifies)
        if len(window) >= 3 and all(window[-3:]):
            return item["task_ordinal"]
    return 13


def _error_rate(record: dict[str, Any]) -> float:
    opportunities = record["repeated_error_opportunity_count"]
    return record["repeated_error_count"] / opportunities if opportunities else 0.0
