"""Prospective confirmatory execution contract for J1-D qualification."""

from __future__ import annotations

import copy
from typing import Any

from .controlled_comparison import canonical_sha256
from .qualification_outcome_sensitive_confirmatory_provider_admission import (
    SOURCE_NAMES as ADMISSION_SOURCE_NAMES,
)
from .qualification_outcome_sensitive_execution_contract import (
    EXECUTION_BOUNDARY,
    build_execution_contract,
    validate_execution_contract,
)


CONTRACT_SCHEMA = (
    "j1-qualification-outcome-sensitive-confirmatory-execution-contract:v1"
)
SOURCE_NAMES = ADMISSION_SOURCE_NAMES | {
    "provider_admission_plan",
    "provider_admission_preflight",
    "provider_admission_receipt",
    "provider_admission_gate",
}
EXECUTION_BOUNDARY = {
    **EXECUTION_BOUNDARY,
    "prospective_confirmatory_method_bound": True,
    "prior_run_reanalysis_performed": False,
    "advice_adherence_inferred": False,
}


def build_confirmatory_execution_contract(
    *,
    contract_id: str,
    created_at: str,
    source_artifacts: dict[str, dict[str, str]],
    protocol: dict[str, Any],
    design: dict[str, Any],
    evaluator: dict[str, Any],
    task_fixture: dict[str, Any],
    roster: dict[str, Any],
    assignment: dict[str, Any],
    signed_advice_manifest: dict[str, Any],
    activation: dict[str, Any],
    provider_admission_receipt: dict[str, Any],
    provider_admission_gate: dict[str, Any],
    confirmatory_method: dict[str, Any],
    confirmatory_promotion_gate: dict[str, Any],
    consent_gate: dict[str, Any],
    roster_assignment_gate: dict[str, Any],
    mentor_advice_gate: dict[str, Any],
    activation_gate: dict[str, Any],
    implementation: dict[str, str],
) -> dict[str, Any]:
    contract = build_execution_contract(
        contract_id=contract_id,
        created_at=created_at,
        source_artifacts=source_artifacts,
        protocol=protocol,
        design=design,
        evaluator=evaluator,
        task_fixture=task_fixture,
        roster=roster,
        assignment=assignment,
        signed_advice_manifest=signed_advice_manifest,
        activation=activation,
        provider_admission_receipt=provider_admission_receipt,
        provider_admission_gate=provider_admission_gate,
        implementation=implementation,
        contract_schema=CONTRACT_SCHEMA,
        required_source_names=SOURCE_NAMES,
        execution_boundary=EXECUTION_BOUNDARY,
    )
    contract["confirmatory_method_binding"] = _method_binding(
        method=confirmatory_method,
        promotion_gate=confirmatory_promotion_gate,
        consent_gate=consent_gate,
        roster_assignment_gate=roster_assignment_gate,
        mentor_advice_gate=mentor_advice_gate,
        activation_gate=activation_gate,
        provider_admission_receipt=provider_admission_receipt,
        provider_admission_gate=provider_admission_gate,
    )
    contract["contract_sha256"] = canonical_sha256(
        {key: value for key, value in contract.items() if key != "contract_sha256"}
    )
    failures = validate_confirmatory_execution_contract(
        contract,
        protocol=protocol,
        design=design,
        evaluator=evaluator,
        task_fixture=task_fixture,
        roster=roster,
        assignment=assignment,
        signed_advice_manifest=signed_advice_manifest,
        activation=activation,
        provider_admission_receipt=provider_admission_receipt,
        provider_admission_gate=provider_admission_gate,
        confirmatory_method=confirmatory_method,
        confirmatory_promotion_gate=confirmatory_promotion_gate,
        consent_gate=consent_gate,
        roster_assignment_gate=roster_assignment_gate,
        mentor_advice_gate=mentor_advice_gate,
        activation_gate=activation_gate,
        expected_source_artifacts=source_artifacts,
        expected_implementation=implementation,
    )
    if failures:
        raise ValueError(f"confirmatory execution contract invalid: {failures}")
    return contract


def validate_confirmatory_execution_contract(
    value: Any,
    *,
    protocol: dict[str, Any],
    design: dict[str, Any],
    evaluator: dict[str, Any],
    task_fixture: dict[str, Any],
    roster: dict[str, Any],
    assignment: dict[str, Any],
    signed_advice_manifest: dict[str, Any],
    activation: dict[str, Any],
    provider_admission_receipt: dict[str, Any],
    provider_admission_gate: dict[str, Any],
    confirmatory_method: dict[str, Any],
    confirmatory_promotion_gate: dict[str, Any],
    consent_gate: dict[str, Any],
    roster_assignment_gate: dict[str, Any],
    mentor_advice_gate: dict[str, Any],
    activation_gate: dict[str, Any],
    expected_source_artifacts: dict[str, dict[str, str]],
    expected_implementation: dict[str, str],
) -> list[str]:
    contract = value if isinstance(value, dict) else {}
    failures = validate_execution_contract(
        contract,
        protocol=protocol,
        design=design,
        evaluator=evaluator,
        task_fixture=task_fixture,
        roster=roster,
        assignment=assignment,
        signed_advice_manifest=signed_advice_manifest,
        activation=activation,
        provider_admission_receipt=provider_admission_receipt,
        provider_admission_gate=provider_admission_gate,
        expected_source_artifacts=expected_source_artifacts,
        expected_implementation=expected_implementation,
        contract_schema=CONTRACT_SCHEMA,
        required_source_names=SOURCE_NAMES,
        expected_execution_boundary=EXECUTION_BOUNDARY,
    )
    expected_binding = _method_binding(
        method=confirmatory_method,
        promotion_gate=confirmatory_promotion_gate,
        consent_gate=consent_gate,
        roster_assignment_gate=roster_assignment_gate,
        mentor_advice_gate=mentor_advice_gate,
        activation_gate=activation_gate,
        provider_admission_receipt=provider_admission_receipt,
        provider_admission_gate=provider_admission_gate,
    )
    _require(
        contract.get("confirmatory_method_binding") == expected_binding,
        "confirmatory_execution_method_binding_invalid",
        failures,
    )
    _require(
        _valid_exact_method(confirmatory_method),
        "confirmatory_execution_exact_method_invalid",
        failures,
    )
    _require(
        confirmatory_promotion_gate.get("passed") is True
        and consent_gate.get("passed") is True
        and roster_assignment_gate.get("passed") is True
        and mentor_advice_gate.get("passed") is True
        and activation_gate.get("passed") is True
        and provider_admission_gate.get("passed") is True,
        "confirmatory_execution_gate_chain_invalid",
        failures,
    )
    body = {key: item for key, item in contract.items() if key != "contract_sha256"}
    _require(
        contract.get("contract_sha256") == canonical_sha256(body),
        "confirmatory_execution_contract_hash_invalid",
        failures,
    )
    return list(dict.fromkeys(failures))


def _method_binding(
    *,
    method: dict[str, Any],
    promotion_gate: dict[str, Any],
    consent_gate: dict[str, Any],
    roster_assignment_gate: dict[str, Any],
    mentor_advice_gate: dict[str, Any],
    activation_gate: dict[str, Any],
    provider_admission_receipt: dict[str, Any],
    provider_admission_gate: dict[str, Any],
) -> dict[str, Any]:
    return {
        "method_sha256": method.get("method_sha256"),
        "promotion_gate_sha256": promotion_gate.get("report_sha256"),
        "consent_gate_sha256": consent_gate.get("report_sha256"),
        "roster_assignment_gate_sha256": roster_assignment_gate.get("report_sha256"),
        "mentor_advice_gate_sha256": mentor_advice_gate.get("report_sha256"),
        "activation_gate_sha256": activation_gate.get("report_sha256"),
        "provider_admission_receipt_sha256": provider_admission_receipt.get(
            "receipt_sha256"
        ),
        "provider_admission_gate_sha256": provider_admission_gate.get("report_sha256"),
        "test": copy.deepcopy(method.get("test")),
        "multiplicity": copy.deepcopy(method.get("multiplicity")),
        "missingness_and_censoring": copy.deepcopy(
            method.get("missingness_and_censoring")
        ),
        "claim_gate": copy.deepcopy(method.get("claim_gate")),
        "measurement_boundary": copy.deepcopy(method.get("measurement_boundary")),
        "prior_run_reanalysis_allowed": False,
        "advice_adherence_inference_allowed": False,
    }


def _valid_exact_method(method: dict[str, Any]) -> bool:
    test = method.get("test", {})
    multiplicity = method.get("multiplicity", {})
    missingness = method.get("missingness_and_censoring", {})
    measurement = method.get("measurement_boundary", {})
    return (
        method.get("schema_version") == "j1-outcome-sensitive-confirmatory-method:v1"
        and _sha256(method.get("method_sha256"))
        and test.get("name") == "exact_matched_pair_sign_flip_randomization_test"
        and test.get("assignment_count") == 1_048_576
        and test.get("numeric_representation") == "exact_rational_no_binary_float"
        and test.get("zero_pair_effects") == "retained_and_sign_invariant"
        and test.get("tail_ties") == "included"
        and multiplicity.get("method") == "holm_step_down"
        and multiplicity.get("familywise_alpha") == {"numerator": 1, "denominator": 20}
        and multiplicity.get("equal_p_value_tie_order")
        == ["strategy_maturity_time", "repeated_error_rate"]
        and missingness.get("all_20_complete_pairs_required") is True
        and missingness.get("all_480_terminal_task_evidence_required") is True
        and missingness.get("outcome_imputation_for_claim_allowed") is False
        and measurement.get("advice_adherence_observed") is False
        and measurement.get(
            "advice_adherence_change_deferred_to_separate_protocol_schema_review"
        )
        is True
    )


def _sha256(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


def _require(condition: bool, reason: str, failures: list[str]) -> None:
    if not condition and reason not in failures:
        failures.append(reason)
