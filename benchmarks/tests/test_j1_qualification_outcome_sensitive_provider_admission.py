from __future__ import annotations

import copy
import hashlib

from benchmarks.j1.qualification_outcome_sensitive_provider_admission import (
    OFFLINE_BOUNDARY,
    SOURCE_NAMES,
    build_plan,
    build_preflight,
    probe_authorization_statement,
    validate_plan,
    validate_probe_sources,
)


def _refs() -> dict[str, dict[str, str]]:
    return {
        name: {
            "path": f"/private/{name}.json",
            "sha256": hashlib.sha256(f"raw:{name}".encode()).hexdigest(),
            "canonical_sha256": hashlib.sha256(
                f"canonical:{name}".encode()
            ).hexdigest(),
        }
        for name in SOURCE_NAMES
    }


def _design() -> dict:
    return {
        "amended_design_sha256": "d" * 64,
        "preserved_provider_call": {
            "provider_id": "openai_compatible",
            "base_url": "https://api.deepseek.com",
            "model_id": "deepseek-v4-pro",
            "temperature": 0,
        },
        "preserved_pricing": {
            "billing_currency": "USD",
            "cost_unit": "usd_microunit",
            "rate_basis_tokens": 1_000_000,
            "price_drift_requires_new_reviewed_design": True,
            "rates_microunits": {
                "input_cache_hit": 3_625,
                "input_cache_miss": 435_000,
                "output": 870_000,
            },
        },
    }


def _plan() -> dict:
    return build_plan(
        admission_id="outcome-admission-r1",
        created_at="2026-07-29T15:00:00+08:00",
        source_binding=_refs(),
        protocol={"protocol_sha256": "a" * 64},
        evaluator={"evaluator_sha256": "b" * 64},
        design=_design(),
        activation={"activation_sha256": "c" * 64},
        inventory_snapshot={
            "participant_count": 40,
            "container_count": 40,
            "created_count": 40,
            "running_count": 0,
            "container_set_sha256": "e" * 64,
            "container_details_persisted": False,
        },
        implementation={"source_revision": "f" * 40},
    )


def test_outcome_admission_plan_binds_current_stack_and_narrow_probe() -> None:
    plan = _plan()

    assert validate_plan(plan) == []
    assert plan["frozen_stack"]["protocol_sha256"] == "a" * 64
    assert plan["frozen_stack"]["evaluator_sha256"] == "b" * 64
    assert plan["frozen_stack"]["activation_sha256"] == "c" * 64
    assert (
        plan["frozen_stack"]["transport_gate_sha256"]
        == _refs()["transport_gate"]["canonical_sha256"]
    )
    assert plan["probe_contract"]["call_count"] == 1
    assert plan["pricing_and_budget"]["maximum_cost_microunits"] == 926
    assert plan["preserved_design_reuse_scope"] == {
        "provider_identity_and_pricing_only": True,
        "prior_execution_call_count_or_budget_inherited": False,
        "new_execution_stack_review_required": True,
    }
    assert plan["execution_boundary"] == OFFLINE_BOUNDARY
    assert plan["authorization_contract"]["pre_dispatch_connect_attempts"] == 3
    assert plan["authorization_contract"]["http_request_attempts"] == 1
    assert (
        plan["authorization_contract"]["ambiguous_dispatch_retry_allowed"] is False
    )


def test_outcome_admission_plan_rejects_budget_and_scope_expansion() -> None:
    plan = _plan()
    tampered = copy.deepcopy(plan)
    tampered["probe_contract"]["call_count"] = 2
    tampered["pricing_and_budget"]["maximum_cost_microunits"] = 927
    tampered["authorization_contract"]["participant_container_start_allowed"] = True
    tampered["authorization_contract"]["ambiguous_dispatch_retry_allowed"] = True
    tampered["frozen_stack"]["transport_gate_sha256"] = ""

    failures = validate_plan(tampered)

    assert "outcome_admission_plan_identity_invalid" in failures
    assert "outcome_admission_probe_contract_invalid" in failures
    assert "outcome_admission_budget_invalid" in failures
    assert "outcome_admission_authorization_boundary_invalid" in failures


def test_outcome_admission_preflight_requires_exact_owner_statement() -> None:
    plan = _plan()
    preflight = build_preflight(
        plan_path="/private/plan.json",
        plan_raw_sha256="1" * 64,
        plan=plan,
        created_at="2026-07-29T15:00:00+08:00",
    )
    statement = probe_authorization_statement(
        plan_raw_sha256="1" * 64,
        plan=plan,
    )

    assert (
        validate_probe_sources(
            plan=plan,
            plan_raw_sha256="1" * 64,
            preflight=preflight,
            authorization_statement=statement,
        )
        == []
    )
    assert "outcome-sensitive live-provider admission probe" in statement
    assert plan["frozen_stack"]["activation_sha256"] in statement
    assert plan["frozen_stack"]["transport_gate_sha256"] in statement
    assert "exactly one HTTPS POST" in statement
    assert "at most 3 connection-setup attempts" in statement
    assert "after dispatch is ambiguous and must never be retried" in statement
    assert "926 USD microunits" in statement
    assert "execution-stack promotion" in statement

    assert "outcome_probe_owner_authorization_mismatch" in validate_probe_sources(
        plan=plan,
        plan_raw_sha256="1" * 64,
        preflight=preflight,
        authorization_statement=f"{statement} ",
    )
