from __future__ import annotations

import copy
import hashlib

from benchmarks.j1.qualification_provider_admission_v4 import (
    BOUNDARY,
    SOURCE_NAMES,
    build_admission_plan,
    build_preflight,
    validate_admission_plan,
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


def _plan() -> dict:
    design = {
        "preserved_provider_call": {
            "provider_id": "openai_compatible",
            "base_url": "https://api.deepseek.com",
            "model_id": "deepseek-v4-pro",
            "temperature": 0,
        },
        "preserved_pricing": {
            "rate_basis_tokens": 1_000_000,
            "rates_microunits": {
                "input_cache_hit": 3625,
                "input_cache_miss": 435000,
                "output": 870000,
            },
        },
    }
    return build_admission_plan(
        admission_id="r4-admission-r1",
        created_at="2026-07-25T12:00:00+08:00",
        source_artifacts=_refs(),
        frozen_stack={"frozen_stack_sha256": "a" * 64},
        design=design,
        inventory_snapshot={
            "participant_container_count": 40,
            "created_count": 40,
            "running_count": 0,
        },
        implementation={
            "source_revision": "b" * 40,
            "domain_source_sha256": "c" * 64,
            "operation_source_sha256": "d" * 64,
        },
    )


def test_r4_provider_plan_binds_stack_single_call_and_ceiling() -> None:
    plan = _plan()

    assert validate_admission_plan(plan) == []
    assert plan["probe_contract"]["call_count"] == 1
    assert plan["pricing_and_budget"]["maximum_cost_microunits"] == 926
    assert plan["single_use_contract"]["provider_retry_allowed"] is False
    assert plan["execution_boundary"] == BOUNDARY


def test_r4_provider_plan_rejects_scope_or_boundary_tamper() -> None:
    plan = _plan()
    tampered = copy.deepcopy(plan)
    tampered["probe_contract"]["call_count"] = 2
    tampered["execution_boundary"]["provider_api_call_performed"] = True

    failures = validate_admission_plan(tampered)
    assert "r4_admission_probe_contract_invalid" in failures
    assert "r4_admission_single_use_or_boundary_invalid" in failures
    assert "r4_admission_plan_hash_invalid" in failures


def test_r4_provider_preflight_requires_exact_owner_authorization() -> None:
    plan = _plan()
    preflight = build_preflight(
        plan_path="/private/plan.json",
        plan_raw_sha256="e" * 64,
        plan=plan,
        created_at="2026-07-25T12:00:00+08:00",
    )

    statement = preflight["owner_authorization"]["required_exact_statement"]
    assert plan["frozen_r4_stack_sha256"] in statement
    assert "exactly one HTTPS POST" in statement
    assert "926 USD microunits" in statement
    assert preflight["execution_boundary"] == BOUNDARY
