from __future__ import annotations

from copy import deepcopy

from benchmarks.j1.controlled_comparison import canonical_sha256
from benchmarks.j1.qualification_transport_reliability import (
    FAULT_SCENARIOS,
    SOAK_CALL_COUNT,
    build_fault_matrix_report,
    build_soak_plan,
    build_soak_preflight,
    build_transport_contract,
    validate_fault_matrix_report,
    validate_soak_plan,
    validate_transport_contract,
)
from benchmarks.j1_qualification_transport_reliability import run_fault_matrix


def _ref(name: str, canonical: str = "b" * 64) -> dict[str, str]:
    return {
        "path": f"/private/{name}.json",
        "sha256": "a" * 64,
        "canonical_sha256": canonical,
    }


def _implementation() -> dict[str, str]:
    return {
        "source_revision": "1" * 40,
        "domain_source_sha256": "2" * 64,
        "operation_source_sha256": "3" * 64,
        "transport_source_sha256": "4" * 64,
    }


def _contract() -> dict:
    return build_transport_contract(
        contract_id="j1d-transport-r4",
        created_at="2026-07-31T13:00:00+00:00",
        source_binding={
            "r2_terminal_gate": _ref("r2"),
            "r3_terminal_gate": _ref("r3"),
        },
        implementation=_implementation(),
    )


def _scenarios() -> list[dict]:
    return [
        {
            "scenario": name,
            "expected": "bounded reviewed outcome",
            "observed": "bounded reviewed outcome",
            "observed_connect_attempt_count": 3 if "connect" in name else 1,
            "observed_http_request_count": (
                0 if "before_dispatch" in name else 1
            ),
            "observed_post_dispatch_retry_count": 0,
            "passed": True,
        }
        for name in FAULT_SCENARIOS
    ]


def test_transport_contract_freezes_phase_and_retry_boundary() -> None:
    contract = _contract()

    assert validate_transport_contract(contract) == []
    assert contract["transport_policy"]["connect_attempts"] == 3
    assert contract["transport_policy"]["http_request_retry_allowed"] is False
    assert contract["transport_policy"]["ambiguous_dispatch_retry_allowed"] is False
    assert contract["phase_boundary"]["dispatch_starts_before"] == (
        "http_request_write"
    )


def test_transport_contract_rejects_post_dispatch_retry() -> None:
    contract = deepcopy(_contract())
    contract["transport_policy"]["ambiguous_dispatch_retry_allowed"] = True
    contract["contract_sha256"] = canonical_sha256(
        {key: item for key, item in contract.items() if key != "contract_sha256"}
    )

    assert "transport_contract_policy_invalid" in validate_transport_contract(contract)


def test_transport_fault_matrix_requires_all_eight_scenarios() -> None:
    contract = _contract()
    report = build_fault_matrix_report(
        checked_at="2026-07-31T13:01:00+00:00",
        contract_ref=_ref("contract", contract["contract_sha256"]),
        scenarios=_scenarios(),
        implementation=_implementation(),
    )

    assert validate_fault_matrix_report(report) == []
    assert report["summary"]["scenario_count"] == 8
    assert report["summary"]["passed_count"] == 8
    assert report["summary"]["post_dispatch_retry_count"] == 0

    report["scenarios"][3]["observed_post_dispatch_retry_count"] = 1
    report["report_sha256"] = canonical_sha256(
        {key: item for key, item in report.items() if key != "report_sha256"}
    )
    assert "transport_fault_matrix_scenarios_invalid" in (
        validate_fault_matrix_report(report)
    )


def test_real_deterministic_transport_fault_matrix_passes() -> None:
    contract = _contract()
    report = run_fault_matrix(
        checked_at="2026-07-31T13:01:00+00:00",
        contract_ref=_ref("contract", contract["contract_sha256"]),
        implementation=_implementation(),
    )

    assert validate_fault_matrix_report(report) == []
    assert report["summary"] == {
        "scenario_count": 8,
        "passed_count": 8,
        "http_request_count": 6,
        "post_dispatch_retry_count": 0,
    }


def test_transport_soak_plan_is_content_free_bounded_and_review_required() -> None:
    contract = _contract()
    fault = build_fault_matrix_report(
        checked_at="2026-07-31T13:01:00+00:00",
        contract_ref=_ref("contract", contract["contract_sha256"]),
        scenarios=_scenarios(),
        implementation=_implementation(),
    )
    plan = build_soak_plan(
        plan_id="j1d-transport-soak-r4",
        created_at="2026-07-31T13:02:00+00:00",
        contract_ref=_ref("contract", contract["contract_sha256"]),
        fault_matrix_ref=_ref("fault", fault["report_sha256"]),
        provider_design_ref=_ref("provider-design"),
        provider={
            "provider_id": "openai_compatible",
            "base_url": "https://api.deepseek.com",
            "endpoint": "/chat/completions",
            "model": "deepseek-v4-pro",
        },
        implementation=_implementation(),
    )

    assert validate_soak_plan(plan) == []
    assert plan["synthetic_requests"]["call_count"] == SOAK_CALL_COUNT
    assert len(plan["synthetic_requests"]["request_body_canonical_sha256"]) == 64
    assert len(set(plan["synthetic_requests"]["request_body_canonical_sha256"])) == 64
    assert plan["synthetic_requests"]["participant_data_present"] is False
    assert plan["execution_policy"]["http_request_attempts_per_call"] == 1
    assert plan["execution_policy"]["ambiguous_dispatch_retry_count"] == 0
    assert plan["budget"] == {
        "per_call_reserved_tokens": 1128,
        "aggregate_reserved_tokens": 72192,
        "per_call_max_microunits": 926,
        "aggregate_max_microunits": 59264,
    }
    assert plan["authorization_boundary"]["provider_or_model_call_authorized"] is False

    preflight = build_soak_preflight(
        checked_at="2026-07-31T13:03:00+00:00",
        plan_ref=_ref("plan", plan["plan_sha256"]),
        plan=plan,
        validation_failures=validate_soak_plan(plan),
    )
    assert preflight["passed"] is True
    assert preflight["state"] == (
        "transport_soak_materials_ready_independent_review_required"
    )
    assert preflight["readiness"]["provider_or_model_call_allowed"] is False


def test_transport_soak_plan_rejects_participant_data_and_retry() -> None:
    contract = _contract()
    fault = build_fault_matrix_report(
        checked_at="2026-07-31T13:01:00+00:00",
        contract_ref=_ref("contract", contract["contract_sha256"]),
        scenarios=_scenarios(),
        implementation=_implementation(),
    )
    plan = build_soak_plan(
        plan_id="j1d-transport-soak-r4",
        created_at="2026-07-31T13:02:00+00:00",
        contract_ref=_ref("contract", contract["contract_sha256"]),
        fault_matrix_ref=_ref("fault", fault["report_sha256"]),
        provider_design_ref=_ref("provider-design"),
        provider={
            "provider_id": "openai_compatible",
            "base_url": "https://api.deepseek.com",
            "endpoint": "/chat/completions",
            "model": "deepseek-v4-pro",
        },
        implementation=_implementation(),
    )
    plan["synthetic_requests"]["participant_data_present"] = True
    plan["execution_policy"]["http_request_attempts_per_call"] = 2
    plan["plan_sha256"] = canonical_sha256(
        {key: item for key, item in plan.items() if key != "plan_sha256"}
    )

    failures = validate_soak_plan(plan)
    assert "transport_soak_plan_requests_invalid" in failures
    assert "transport_soak_plan_execution_policy_invalid" in failures
