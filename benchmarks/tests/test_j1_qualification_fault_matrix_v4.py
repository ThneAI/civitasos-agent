from __future__ import annotations

import copy
from pathlib import Path

from benchmarks.j1.qualification_fault_matrix_v4 import (
    EXPECTED_SCENARIOS,
    run_fault_matrix,
    validate_fault_matrix,
)
from benchmarks.tests.test_j1_qualification_execution_contract_v4 import _contract


def test_fault_matrix_covers_and_passes_all_required_failures(
    tmp_path: Path,
) -> None:
    contract, _ = _contract()

    report = run_fault_matrix(contract=contract, root=tmp_path / "faults")

    assert report["passed"] is True
    assert validate_fault_matrix(report) == []
    assert {item["scenario"] for item in report["results"]} == EXPECTED_SCENARIOS
    ambiguous = next(
        item
        for item in report["results"]
        if item["scenario"] == "crash_after_dispatch_intent_before_response_commit"
    )
    assert ambiguous["observed_status"] == "failed"
    assert ambiguous["observed_provider_calls"] == 1
    assert ambiguous["observed_budget_states"] == {"provider_outcome_unknown": 1}


def test_fault_matrix_rejects_boundary_or_result_tamper(tmp_path: Path) -> None:
    contract, _ = _contract()
    report = run_fault_matrix(contract=contract, root=tmp_path / "faults")
    tampered = copy.deepcopy(report)
    tampered["results"][0]["passed"] = False
    tampered["execution_boundary"]["provider_api_call_performed"] = True

    failures = validate_fault_matrix(tampered)
    assert "r4_fault_matrix_scenarios_invalid" in failures
    assert "r4_fault_matrix_boundary_invalid" in failures
    assert "r4_fault_matrix_hash_invalid" in failures
