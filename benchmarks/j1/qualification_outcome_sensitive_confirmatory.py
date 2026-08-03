"""Prospective confirmatory inference for outcome-sensitive J1-D runs."""

from __future__ import annotations

from collections import Counter
from fractions import Fraction
from math import lcm
from typing import Any, Iterable


METHOD_VERSION = "j1-outcome-sensitive-confirmatory-analysis:v2"
ENDPOINT_ORDER = ("strategy_maturity_time", "repeated_error_rate")
FAMILYWISE_ALPHA = Fraction(1, 20)


def exact_paired_sign_flip_test(
    effects: Iterable[Fraction | int],
) -> dict[str, Any]:
    """Run the frozen one-sided exact matched-pair randomization test."""
    values = tuple(Fraction(value) for value in effects)
    if not 1 <= len(values) <= 20:
        raise ValueError("exact sign-flip test requires between 1 and 20 pairs")

    denominator = lcm(*(value.denominator for value in values))
    scaled = tuple(
        value.numerator * (denominator // value.denominator) for value in values
    )
    observed = sum(scaled)
    distribution = Counter({0: 1})
    for value in scaled:
        next_distribution: Counter[int] = Counter()
        for total, count in distribution.items():
            next_distribution[total - value] += count
            next_distribution[total + value] += count
        distribution = next_distribution

    extreme = sum(count for total, count in distribution.items() if total >= observed)
    assignments = 1 << len(values)
    if sum(distribution.values()) != assignments:
        raise AssertionError("sign-flip assignment inventory drift")
    p_value = Fraction(extreme, assignments)
    return {
        "method_version": METHOD_VERSION,
        "alternative": "control_minus_mentor_greater_than_zero",
        "pair_count": len(values),
        "zero_pair_effect_count": sum(value == 0 for value in values),
        "observed_sum": _fraction(sum(values)),
        "observed_mean": _fraction(sum(values) / len(values)),
        "assignment_count": assignments,
        "extreme_assignment_count": extreme,
        "p_value": _fraction(p_value),
        "ties_in_extreme_tail": "included",
        "zero_pair_effects": "retained_and_sign_invariant",
    }


def holm_step_down(
    raw_p_values: dict[str, Fraction | dict[str, int]],
) -> dict[str, Any]:
    """Apply the frozen two-endpoint Holm step-down procedure."""
    if set(raw_p_values) != set(ENDPOINT_ORDER):
        raise ValueError("Holm family must contain exactly the two frozen endpoints")
    parsed = {
        endpoint: _as_fraction(raw_p_values[endpoint]) for endpoint in ENDPOINT_ORDER
    }
    if any(value < 0 or value > 1 for value in parsed.values()):
        raise ValueError("Holm p-values must be within [0, 1]")

    tie_order = {endpoint: index for index, endpoint in enumerate(ENDPOINT_ORDER)}
    ordered = sorted(ENDPOINT_ORDER, key=lambda item: (parsed[item], tie_order[item]))
    adjusted: dict[str, Fraction] = {}
    running = Fraction(0)
    rejected: dict[str, bool] = {}
    continue_rejecting = True
    for index, endpoint in enumerate(ordered):
        multiplier = len(ordered) - index
        running = max(running, min(Fraction(1), parsed[endpoint] * multiplier))
        adjusted[endpoint] = running
        threshold = FAMILYWISE_ALPHA / multiplier
        rejected[endpoint] = continue_rejecting and parsed[endpoint] <= threshold
        continue_rejecting = rejected[endpoint]

    return {
        "method": "holm_step_down",
        "familywise_alpha": _fraction(FAMILYWISE_ALPHA),
        "endpoint_order_after_sort": ordered,
        "equal_p_value_tie_order": list(ENDPOINT_ORDER),
        "raw_p_values": {
            endpoint: _fraction(parsed[endpoint]) for endpoint in ENDPOINT_ORDER
        },
        "adjusted_p_values": {
            endpoint: _fraction(adjusted[endpoint]) for endpoint in ENDPOINT_ORDER
        },
        "rejected": {endpoint: rejected[endpoint] for endpoint in ENDPOINT_ORDER},
        "all_confirmatory_endpoints_rejected": all(rejected.values()),
    }


def evaluate_confirmatory_effects(
    *,
    maturity_effects: Iterable[Fraction | int],
    repeated_error_effects: Iterable[Fraction | int],
    structural_passed: bool,
) -> dict[str, Any]:
    """Evaluate both frozen endpoints, failing closed on structural incompleteness."""
    maturity = tuple(Fraction(value) for value in maturity_effects)
    repeated = tuple(Fraction(value) for value in repeated_error_effects)
    if not structural_passed:
        return {
            "method_version": METHOD_VERSION,
            "valid": False,
            "failure_reason": "structural_gate_failed_no_confirmatory_inference",
            "confirmatory_endpoints_rejected": False,
            "effectiveness_thresholds_met": False,
            "effectiveness_claim_authorized": False,
        }
    if len(maturity) != 20 or len(repeated) != 20:
        raise ValueError("confirmatory evaluation requires exactly 20 complete pairs")

    tests = {
        ENDPOINT_ORDER[0]: exact_paired_sign_flip_test(maturity),
        ENDPOINT_ORDER[1]: exact_paired_sign_flip_test(repeated),
    }
    holm = holm_step_down(
        {endpoint: test["p_value"] for endpoint, test in tests.items()}
    )
    return {
        "method_version": METHOD_VERSION,
        "valid": True,
        "pair_count": 20,
        "tests": tests,
        "multiplicity": holm,
        "confirmatory_endpoints_rejected": holm["all_confirmatory_endpoints_rejected"],
        "effectiveness_thresholds_met": False,
        "effectiveness_claim_authorized": False,
        "descriptive_safeguard_and_closeout_gates_still_required": True,
        "signed_closeout_still_required": True,
    }


def _as_fraction(value: Fraction | dict[str, int]) -> Fraction:
    if isinstance(value, Fraction):
        return value
    if not isinstance(value, dict):
        raise ValueError("p-value must be a Fraction or rational object")
    try:
        return Fraction(value["numerator"], value["denominator"])
    except (KeyError, TypeError, ValueError, ZeroDivisionError) as error:
        raise ValueError("invalid rational p-value") from error


def _fraction(value: Fraction) -> dict[str, int]:
    return {
        "numerator": value.numerator,
        "denominator": value.denominator,
    }
