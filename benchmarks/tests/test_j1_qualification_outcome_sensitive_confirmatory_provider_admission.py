from __future__ import annotations

import copy
import hashlib

import pytest

from benchmarks.j1.qualification_outcome_sensitive_confirmatory_provider_admission import (
    OFFLINE_BOUNDARY,
    SOURCE_NAMES,
    build_plan,
    build_preflight,
    probe_authorization_statement,
    validate_plan,
    validate_probe_sources,
)
from benchmarks.j1_qualification_provider_admission_probe import (
    _validate_bound_implementation,
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
        admission_id="confirmatory-admission-r1",
        created_at="2026-08-11T15:00:00+08:00",
        source_binding=_refs(),
        protocol={"protocol_sha256": "a" * 64},
        evaluator={"evaluator_sha256": "b" * 64},
        design=_design(),
        confirmatory_method={"method_sha256": "c" * 64},
        activation={"activation_sha256": "e" * 64},
        inventory_snapshot={
            "participant_count": 40,
            "container_count": 40,
            "created_count": 40,
            "running_count": 0,
            "container_set_sha256": "f" * 64,
            "container_details_persisted": False,
        },
        implementation={"source_revision": "1" * 40},
    )


def test_confirmatory_admission_plan_freezes_stack_and_narrow_probe() -> None:
    plan = _plan()

    assert validate_plan(plan) == []
    stack = plan["frozen_stack"]
    assert stack["confirmatory_method_sha256"] == "c" * 64
    assert stack["activation_sha256"] == "e" * 64
    assert (
        stack["confirmatory_consent_gate_sha256"]
        == _refs()["consent_gate"]["canonical_sha256"]
    )
    assert plan["probe_contract"]["call_count"] == 1
    assert plan["pricing_and_budget"]["maximum_cost_microunits"] == 926
    assert plan["authorization_contract"]["pre_dispatch_connect_attempts"] == 3
    assert plan["authorization_contract"]["http_request_attempts"] == 1
    assert plan["authorization_contract"]["http_request_retry_allowed"] is False
    assert (
        plan["authorization_contract"]["ambiguous_dispatch_retry_allowed"] is False
    )
    assert plan["execution_boundary"] == OFFLINE_BOUNDARY


def test_confirmatory_admission_plan_rejects_scope_and_budget_expansion() -> None:
    plan = _plan()
    tampered = copy.deepcopy(plan)
    tampered["probe_contract"]["call_count"] = 2
    tampered["pricing_and_budget"]["maximum_cost_microunits"] = 927
    tampered["authorization_contract"]["http_request_retry_allowed"] = True
    tampered["execution_boundary"]["provider_api_call_performed"] = True

    failures = validate_plan(tampered)

    assert "confirmatory_admission_plan_identity_invalid" in failures
    assert "confirmatory_admission_probe_contract_invalid" in failures
    assert "confirmatory_admission_budget_invalid" in failures
    assert "confirmatory_admission_authorization_boundary_invalid" in failures


def test_confirmatory_preflight_requires_exact_owner_statement() -> None:
    plan = _plan()
    preflight = build_preflight(
        plan_path="/private/plan.json",
        plan_raw_sha256="2" * 64,
        plan=plan,
        created_at="2026-08-11T15:00:00+08:00",
    )
    statement = probe_authorization_statement(
        plan_raw_sha256="2" * 64,
        plan=plan,
    )

    assert (
        validate_probe_sources(
            plan=plan,
            plan_raw_sha256="2" * 64,
            preflight=preflight,
            authorization_statement=statement,
        )
        == []
    )
    assert "prospective confirmatory live-provider admission probe" in statement
    assert plan["frozen_stack"]["confirmatory_method_sha256"] in statement
    assert plan["frozen_stack"]["confirmatory_consent_gate_sha256"] in statement
    assert "exactly one HTTPS POST" in statement
    assert "at most 3 connection-setup attempts" in statement
    assert "after dispatch is ambiguous and must never be retried" in statement
    assert "926 USD microunits" in statement
    assert "r4 reanalysis" in statement

    assert (
        "confirmatory_probe_owner_authorization_mismatch"
        in validate_probe_sources(
            plan=plan,
            plan_raw_sha256="2" * 64,
            preflight=preflight,
            authorization_statement=f"{statement} ",
        )
    )


def test_bound_implementation_rejects_revision_and_source_drift(tmp_path) -> None:
    source = tmp_path / "source.py"
    source.write_text("frozen = True\n", encoding="utf-8")
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    plan = {
        "implementation": {
            "source_revision": "a" * 40,
            "domain_source_sha256": digest,
        }
    }

    _validate_bound_implementation(
        plan,
        revision="a" * 40,
        sources={"domain_source_sha256": source},
        label="confirmatory",
    )
    with pytest.raises(ValueError, match="revision drift"):
        _validate_bound_implementation(
            plan,
            revision="b" * 40,
            sources={"domain_source_sha256": source},
            label="confirmatory",
        )
    source.write_text("frozen = False\n", encoding="utf-8")
    with pytest.raises(ValueError, match="source drift"):
        _validate_bound_implementation(
            plan,
            revision="a" * 40,
            sources={"domain_source_sha256": source},
            label="confirmatory",
        )
