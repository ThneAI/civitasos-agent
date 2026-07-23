"""Contracts for a single-use J1-D live-provider admission probe."""

from __future__ import annotations

import hashlib
from typing import Any

from .controlled_comparison import canonical_sha256
from .qualification_provider_admission_refresh import (
    PREFLIGHT_SCHEMA,
    PREFLIGHT_SCHEMA_V1,
    probe_authorization_statement,
    validate_refresh_plan,
)
from .qualification_provider_broker import calculate_cost_microunits


CLAIM_SCHEMA = "j1-qualification-provider-admission-probe-claim:v1"
RECEIPT_SCHEMA = "j1-qualification-provider-admission-probe-receipt:v1"
GATE_SCHEMA = "j1-qualification-provider-admission-probe-gate:v1"
PROBE_BOUNDARY = {
    "provider_admission_probe_only": True,
    "provider_admission_refreshed": True,
    "credential_file_accessed_once": True,
    "credential_value_or_hash_persisted": False,
    "provider_api_call_count": 1,
    "model_invocation_count": 1,
    "participant_data_used": False,
    "participant_container_created": False,
    "participant_container_started": False,
    "participant_task_execution_performed": False,
    "agent_execution_performed": False,
    "backend_fact_append_performed": False,
    "ledger_append_performed": False,
    "execution_authorization_issued_or_consumed": False,
}


def validate_probe_sources(
    *,
    plan: dict[str, Any],
    plan_raw_sha256: str,
    preflight: dict[str, Any],
    authorization_statement: str,
) -> list[str]:
    failures = validate_refresh_plan(plan)
    preflight_body = {
        key: item for key, item in preflight.items() if key != "preflight_sha256"
    }
    expected_statement = probe_authorization_statement(
        plan_raw_sha256=plan_raw_sha256,
        plan_canonical_sha256=str(plan.get("plan_sha256", "")),
        provider_id=str(_object(plan.get("frozen_stack")).get("provider_id", "")),
        base_url=str(_object(plan.get("frozen_stack")).get("base_url", "")),
        model_id=str(_object(plan.get("frozen_stack")).get("model_id", "")),
        request_body_sha256=str(
            _object(plan.get("probe_contract")).get("request_body_sha256", "")
        ),
        maximum_cost_microunits=int(
            _object(plan.get("pricing_and_budget")).get("maximum_cost_microunits", -1)
        ),
        max_input_tokens=int(
            _object(plan.get("probe_contract")).get("max_input_tokens", -1)
        ),
        max_output_tokens=int(
            _object(plan.get("probe_contract")).get("max_output_tokens", -1)
        ),
    )
    statement_sha256 = hashlib.sha256(expected_statement.encode()).hexdigest()
    owner = _object(preflight.get("owner_authorization"))
    plan_ref = _object(preflight.get("plan"))
    _require(
        preflight.get("schema_version") in {PREFLIGHT_SCHEMA_V1, PREFLIGHT_SCHEMA}
        and preflight.get("passed") is True
        and preflight.get("failure_reasons") == []
        and preflight.get("state")
        == "provider_admission_refresh_candidate_ready_owner_authorization_required"
        and preflight.get("preflight_sha256") == canonical_sha256(preflight_body),
        "probe_preflight_invalid",
        failures,
    )
    _require(
        plan_ref.get("sha256") == plan_raw_sha256
        and plan_ref.get("canonical_sha256") == plan.get("plan_sha256"),
        "probe_plan_binding_invalid",
        failures,
    )
    _require(
        owner.get("required") is True
        and owner.get("statement") == expected_statement
        and owner.get("statement_sha256") == statement_sha256
        and authorization_statement == expected_statement,
        "probe_owner_authorization_mismatch",
        failures,
    )
    readiness = _object(preflight.get("readiness"))
    _require(
        readiness.get("offline_preflight_complete") is True
        and readiness.get("owner_probe_authorization_required") is True
        and readiness.get("live_provider_admission_refreshed") is False
        and readiness.get("controlled_experiment_execution_ready") is False,
        "probe_preflight_readiness_invalid",
        failures,
    )
    return list(dict.fromkeys(failures))


def build_claim(
    *,
    probe_id: str,
    claimed_at: str,
    authorization_statement_sha256: str,
    plan_raw_sha256: str,
    plan_canonical_sha256: str,
    preflight_raw_sha256: str,
    preflight_canonical_sha256: str,
    output_root_sha256: str,
    plan: dict[str, Any],
) -> dict[str, Any]:
    probe = _object(plan.get("probe_contract"))
    budget = _object(plan.get("pricing_and_budget"))
    claim = {
        "schema_version": CLAIM_SCHEMA,
        "probe_id": probe_id,
        "claimed_at": claimed_at,
        "state": "authorization_claimed_probe_must_close_out",
        "authorization_statement_sha256": authorization_statement_sha256,
        "plan": {
            "sha256": plan_raw_sha256,
            "canonical_sha256": plan_canonical_sha256,
        },
        "preflight": {
            "sha256": preflight_raw_sha256,
            "canonical_sha256": preflight_canonical_sha256,
        },
        "reservation": {
            "call_count": 1,
            "max_input_tokens": probe["max_input_tokens"],
            "max_output_tokens": probe["max_output_tokens"],
            "max_total_tokens": probe["max_total_tokens"],
            "max_cost_microunits": budget["maximum_cost_microunits"],
        },
        "output_root_sha256": output_root_sha256,
        "single_use": True,
        "immutable": True,
        "claim_must_survive_probe_failure": True,
    }
    claim["claim_sha256"] = canonical_sha256(claim)
    return claim


def normalize_probe_response(
    *,
    status: int,
    body: bytes,
    plan: dict[str, Any],
) -> dict[str, Any]:
    import json

    try:
        response = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("probe provider response is not valid JSON") from error
    if not isinstance(response, dict):
        raise ValueError("probe provider response must be an object")
    if status != _object(plan.get("probe_contract")).get("accepted_http_status"):
        raise ValueError("probe provider HTTP status was not accepted")
    expected_model = _object(plan.get("frozen_stack")).get("model_id")
    if response.get("model") != expected_model:
        raise ValueError("probe provider response model mismatch")
    choices = response.get("choices")
    if not (isinstance(choices, list) and choices and isinstance(choices[0], dict)):
        raise ValueError("probe provider response choices invalid")
    message = _object(choices[0].get("message"))
    content = message.get("content")
    if not isinstance(content, str) or not content:
        raise ValueError("probe provider response content invalid")
    usage = _normalize_usage(response.get("usage"))
    probe = _object(plan.get("probe_contract"))
    if (
        usage["input"] > probe["max_input_tokens"]
        or usage["output"] > probe["max_output_tokens"]
        or usage["total"] > probe["max_total_tokens"]
    ):
        raise ValueError("probe provider usage exceeded token reservation")
    pricing = _object(_object(plan.get("pricing_and_budget")).get("pricing"))
    cost_usage = {
        "input_cache_hit": usage["input_cache_hit"],
        "input_cache_miss": usage["input_cache_miss"],
        "output": usage["output"],
    }
    cost = calculate_cost_microunits(usage=cost_usage, pricing=pricing)
    ceiling = _object(plan.get("pricing_and_budget")).get("maximum_cost_microunits")
    if cost > ceiling:
        raise ValueError("probe provider usage exceeded cost reservation")
    provider_id = response.get("id")
    return {
        "http_status": status,
        "raw_response_sha256": hashlib.sha256(body).hexdigest(),
        "response_id_sha256": (
            hashlib.sha256(str(provider_id).encode()).hexdigest()
            if provider_id is not None
            else None
        ),
        "response_model": response["model"],
        "content_sha256": hashlib.sha256(content.encode()).hexdigest(),
        "content_utf8_bytes": len(content.encode()),
        "response_content_persisted": False,
        "usage": usage,
        "actual_cost_microunits": cost,
    }


def build_probe_receipt(
    *,
    probe_id: str,
    completed_at: str,
    authorization_statement_sha256: str,
    claim_raw_sha256: str,
    claim_canonical_sha256: str,
    plan: dict[str, Any],
    plan_raw_sha256: str,
    preflight_raw_sha256: str,
    provider_result: dict[str, Any],
    inventory_before: dict[str, Any],
    inventory_after: dict[str, Any],
    implementation: dict[str, str],
    credential_basename: str,
) -> dict[str, Any]:
    stack = _object(plan.get("frozen_stack"))
    probe = _object(plan.get("probe_contract"))
    budget = _object(plan.get("pricing_and_budget"))
    receipt = {
        "schema_version": RECEIPT_SCHEMA,
        "probe_id": probe_id,
        "completed_at": completed_at,
        "status": "admitted",
        "authorization": {
            "statement_sha256": authorization_statement_sha256,
            "single_use_claim_sha256": claim_raw_sha256,
            "single_use_claim_canonical_sha256": claim_canonical_sha256,
            "consumed": True,
        },
        "source_binding": {
            "plan_artifact_sha256": plan_raw_sha256,
            "plan_sha256": plan["plan_sha256"],
            "preflight_artifact_sha256": preflight_raw_sha256,
        },
        "provider": {
            "provider_id": stack["provider_id"],
            "base_url_sha256": hashlib.sha256(stack["base_url"].encode()).hexdigest(),
            "model_id": stack["model_id"],
            "response_model": provider_result["response_model"],
            "temperature": stack["temperature"],
        },
        "request": {
            "call_count": 1,
            "request_body_sha256": probe["request_body_sha256"],
            "synthetic_prompt_sha256": probe["synthetic_prompt_sha256"],
            "participant_data_used": False,
        },
        "response": {
            "http_status": provider_result["http_status"],
            "raw_response_sha256": provider_result["raw_response_sha256"],
            "response_id_sha256": provider_result["response_id_sha256"],
            "content_sha256": provider_result["content_sha256"],
            "content_utf8_bytes": provider_result["content_utf8_bytes"],
            "response_content_persisted": False,
        },
        "usage": provider_result["usage"],
        "budget": {
            "reserved_tokens": probe["max_total_tokens"],
            "actual_tokens": provider_result["usage"]["total"],
            "reserved_cost_microunits": budget["maximum_cost_microunits"],
            "actual_cost_microunits": provider_result["actual_cost_microunits"],
            "reconciled": True,
            "within_ceiling": True,
        },
        "credential": {
            "basename": credential_basename,
            "mode": "0600",
            "read_count": 1,
            "value_persisted": False,
            "hash_persisted": False,
        },
        "inventory": {
            "before": inventory_before,
            "after": inventory_after,
            "unchanged": inventory_before == inventory_after,
        },
        "implementation": implementation,
        "execution_boundary": PROBE_BOUNDARY,
    }
    receipt["receipt_sha256"] = canonical_sha256(receipt)
    return receipt


def validate_probe_receipt(
    receipt: dict[str, Any],
    *,
    plan: dict[str, Any],
    expected_authorization_sha256: str,
) -> list[str]:
    failures: list[str] = []
    body = {key: item for key, item in receipt.items() if key != "receipt_sha256"}
    probe = _object(plan.get("probe_contract"))
    budget = _object(receipt.get("budget"))
    usage = _object(receipt.get("usage"))
    credential = _object(receipt.get("credential"))
    inventory = _object(receipt.get("inventory"))
    _require(
        receipt.get("schema_version") == RECEIPT_SCHEMA
        and receipt.get("status") == "admitted"
        and receipt.get("receipt_sha256") == canonical_sha256(body),
        "probe_receipt_identity_invalid",
        failures,
    )
    _require(
        _object(receipt.get("authorization")).get("statement_sha256")
        == expected_authorization_sha256
        and _object(receipt.get("authorization")).get("consumed") is True,
        "probe_receipt_authorization_invalid",
        failures,
    )
    _require(
        _object(receipt.get("request")).get("call_count") == 1
        and _object(receipt.get("request")).get("request_body_sha256")
        == probe.get("request_body_sha256")
        and _object(receipt.get("request")).get("participant_data_used") is False,
        "probe_receipt_request_invalid",
        failures,
    )
    _require(
        type(usage.get("input")) is int
        and type(usage.get("output")) is int
        and type(usage.get("total")) is int
        and 0 < usage["input"] <= probe["max_input_tokens"]
        and 0 < usage["output"] <= probe["max_output_tokens"]
        and usage["total"] == usage["input"] + usage["output"]
        and usage["total"] <= probe["max_total_tokens"],
        "probe_receipt_usage_invalid",
        failures,
    )
    _require(
        budget.get("reserved_tokens") == probe["max_total_tokens"]
        and budget.get("actual_tokens") == usage.get("total")
        and budget.get("reserved_cost_microunits")
        == _object(plan.get("pricing_and_budget")).get("maximum_cost_microunits")
        and type(budget.get("actual_cost_microunits")) is int
        and 0 <= budget["actual_cost_microunits"] <= budget["reserved_cost_microunits"]
        and budget.get("reconciled") is True
        and budget.get("within_ceiling") is True,
        "probe_receipt_budget_invalid",
        failures,
    )
    _require(
        credential.get("mode") == "0600"
        and credential.get("read_count") == 1
        and credential.get("value_persisted") is False
        and credential.get("hash_persisted") is False,
        "probe_receipt_credential_boundary_invalid",
        failures,
    )
    _require(
        inventory.get("unchanged") is True
        and inventory.get("before") == inventory.get("after")
        and _object(inventory.get("after")).get("container_count") == 40
        and _object(inventory.get("after")).get("created_count") == 40
        and _object(inventory.get("after")).get("running_count") == 0,
        "probe_receipt_inventory_invalid",
        failures,
    )
    _require(
        receipt.get("execution_boundary") == PROBE_BOUNDARY,
        "probe_receipt_boundary_invalid",
        failures,
    )
    _require(
        not _contains_forbidden_key(receipt),
        "probe_receipt_secret_field_present",
        failures,
    )
    return list(dict.fromkeys(failures))


def _normalize_usage(value: Any) -> dict[str, int]:
    usage = _object(value)
    prompt = usage.get("prompt_tokens")
    output = usage.get("completion_tokens")
    total = usage.get("total_tokens")
    if any(type(item) is not int or item < 0 for item in (prompt, output, total)):
        raise ValueError("probe provider usage counters invalid")
    if prompt + output != total or prompt == 0 or output == 0:
        raise ValueError("probe provider usage totals invalid")
    hit = usage.get("prompt_cache_hit_tokens")
    miss = usage.get("prompt_cache_miss_tokens")
    if hit is None and miss is None:
        hit, miss = 0, prompt
    if (
        type(hit) is not int
        or type(miss) is not int
        or hit < 0
        or miss < 0
        or hit + miss != prompt
    ):
        raise ValueError("probe provider cache usage invalid")
    return {
        "input": prompt,
        "input_cache_hit": hit,
        "input_cache_miss": miss,
        "output": output,
        "total": total,
    }


def _contains_forbidden_key(value: Any) -> bool:
    if isinstance(value, dict):
        for key, item in value.items():
            normalized = str(key).lower().replace("-", "_")
            if normalized in {"api_key", "secret", "password", "pin", "raw_content"}:
                return True
            if _contains_forbidden_key(item):
                return True
    if isinstance(value, list):
        return any(_contains_forbidden_key(item) for item in value)
    return False


def _object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _require(condition: bool, code: str, failures: list[str]) -> None:
    if not condition and code not in failures:
        failures.append(code)
