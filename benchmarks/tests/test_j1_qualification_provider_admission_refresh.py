from __future__ import annotations

import copy
import hashlib

import benchmarks.j1_qualification_provider_admission_refresh as refresh_operation
from benchmarks.j1.controlled_comparison import canonical_sha256
from benchmarks.j1.qualification_infrastructure_activation import inspect_projection
from benchmarks.j1.qualification_provider_admission_refresh import (
    OFFLINE_BOUNDARY,
    PROBE_PROMPT,
    build_refresh_plan,
    probe_authorization_statement,
    probe_maximum_cost_microunits,
    validate_refresh_plan,
)
from benchmarks.tests.test_j1_qualification_infrastructure_activation import (
    AUTHORIZATION_SHA256,
    REVIEWED_SHA256,
    _inspect,
)
from benchmarks.tests.test_j1_qualification_infrastructure_rebind import (
    _plan as infrastructure_plan,
)


def _protocol() -> dict:
    return {
        "amended_protocol_sha256": "1" * 64,
        "amended_frozen_stack": {
            "provider_id": "openai_compatible",
            "model_id": "deepseek-v4-pro",
            "temperature": 0,
        },
    }


def _design() -> dict:
    return {
        "amended_design_sha256": "2" * 64,
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
            "rates_microunits": {
                "input_cache_hit": 3_625,
                "input_cache_miss": 435_000,
                "output": 870_000,
            },
            "price_drift_requires_new_reviewed_design": True,
        },
    }


def _plan() -> dict:
    return build_refresh_plan(
        refresh_id="refresh-r1",
        created_at="2026-07-23T21:00:00+08:00",
        source_binding={"activation": {"sha256": "a" * 64}},
        protocol=_protocol(),
        design=_design(),
        inventory_snapshot={
            "participant_count": 40,
            "container_count": 40,
            "created_count": 40,
            "running_count": 0,
        },
        implementation={"source_revision": "b" * 40},
    )


def test_probe_budget_is_ceil_of_reviewed_cache_miss_ceiling() -> None:
    assert (
        probe_maximum_cost_microunits(
            input_rate=435_000,
            output_rate=870_000,
            rate_basis_tokens=1_000_000,
        )
        == 63
    )


def test_refresh_plan_freezes_one_synthetic_call_and_offline_boundary() -> None:
    plan = _plan()

    assert validate_refresh_plan(plan) == []
    assert plan["probe_contract"]["call_count"] == 1
    assert plan["probe_contract"]["request_body"]["messages"] == [
        {"role": "user", "content": PROBE_PROMPT}
    ]
    assert plan["probe_contract"]["participant_data_allowed"] is False
    assert plan["pricing_and_budget"]["maximum_cost_microunits"] == 63
    assert plan["execution_boundary"] == OFFLINE_BOUNDARY
    assert plan["credential_contract"]["credential_value_persisted"] is False


def test_refresh_plan_rejects_call_budget_and_boundary_expansion() -> None:
    plan = _plan()
    plan["probe_contract"]["call_count"] = 2
    plan["pricing_and_budget"]["maximum_cost_microunits"] = 64
    plan["authorization_contract"]["participant_container_start_allowed"] = True
    plan["plan_sha256"] = canonical_sha256(
        {key: item for key, item in plan.items() if key != "plan_sha256"}
    )

    failures = validate_refresh_plan(plan)

    assert "refresh_probe_contract_invalid" in failures
    assert "refresh_probe_budget_invalid" in failures
    assert "refresh_authorization_boundary_invalid" in failures


def test_refresh_plan_self_hash_detects_tampering() -> None:
    plan = _plan()
    tampered = copy.deepcopy(plan)
    tampered["frozen_stack"]["model_id"] = "other-model"

    assert "refresh_plan_identity_invalid" in validate_refresh_plan(tampered)


def test_authorization_binds_plan_request_cost_and_narrow_non_permissions() -> None:
    plan = _plan()
    statement = probe_authorization_statement(
        plan_raw_sha256="3" * 64,
        plan_canonical_sha256=plan["plan_sha256"],
        provider_id=plan["frozen_stack"]["provider_id"],
        base_url=plan["frozen_stack"]["base_url"],
        model_id=plan["frozen_stack"]["model_id"],
        request_body_sha256=plan["probe_contract"]["request_body_sha256"],
        maximum_cost_microunits=63,
    )

    assert "exactly one bounded J1-D live-provider admission probe" in statement
    assert "one HTTPS POST" in statement
    assert "63 USD microunits" in statement
    assert "does not permit starting, creating, or removing" in statement
    assert "execution authorization issuance or consumption" in statement
    assert hashlib.sha256(statement.encode()).hexdigest()


def test_live_inventory_revalidation_accepts_exact_stopped_set_and_rejects_drift(
    monkeypatch,
) -> None:
    isolations = infrastructure_plan()[0]["isolations"]
    inspect_values = {}
    activation_records = []
    for index, isolation in enumerate(isolations):
        value = _inspect(isolation)
        value["Id"] = f"{index + 1:064x}"
        projection, failures = inspect_projection(
            value,
            isolation=isolation,
            rebind_id="rebind-r1",
            reviewed_canonical_sha256=REVIEWED_SHA256,
            authorization_sha256=AUTHORIZATION_SHA256,
            uid=1000,
            gid=1000,
        )
        assert failures == []
        inspect_values[value["Id"]] = value
        activation_records.append(
            {
                "participant_id": isolation["participant_id"],
                "container": projection,
            }
        )
    infrastructure = {
        "rebind_id": "rebind-r1",
        "reviewed_infrastructure_rebind_sha256": REVIEWED_SHA256,
        "isolations": isolations,
    }
    activation = {
        "authorization": {"statement_sha256": AUTHORIZATION_SHA256},
        "containers": activation_records,
    }
    monkeypatch.setattr(refresh_operation.os, "getuid", lambda: 1000)
    monkeypatch.setattr(refresh_operation.os, "getgid", lambda: 1000)
    monkeypatch.setattr(
        refresh_operation,
        "_docker_inspect",
        lambda container_id: inspect_values[container_id],
    )

    snapshot, failures = refresh_operation._inspect_current_inventory(
        infrastructure=infrastructure,
        activation=activation,
    )

    assert failures == []
    assert snapshot["created_count"] == 40
    assert snapshot["running_count"] == 0

    first_id = activation_records[0]["container"]["container_id"]
    inspect_values[first_id]["State"] = {"Status": "running", "Running": True}
    _, failures = refresh_operation._inspect_current_inventory(
        infrastructure=infrastructure,
        activation=activation,
    )
    assert "activation_container_started_or_state_invalid" in failures
    assert "refresh_inventory_activation_projection_drift" in failures
    assert "refresh_inventory_complete_set_invalid" in failures
