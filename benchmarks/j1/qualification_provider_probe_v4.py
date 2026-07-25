"""Single-use live-provider admission evidence for the frozen J1-D r4 stack."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from .controlled_comparison import canonical_sha256
from .qualification_provider_broker import calculate_cost_microunits


CLAIM_SCHEMA = "j1-qualification-r4-provider-admission-claim:v1"
RECEIPT_SCHEMA = "j1-qualification-r4-provider-admission-receipt:v1"
PROBE_BOUNDARY = {
    "r4_provider_admission_probe_only": True,
    "provider_admission_refreshed": True,
    "provider_credential_read_count": 1,
    "credential_value_or_hash_persisted": False,
    "provider_api_call_count": 1,
    "model_invocation_count": 1,
    "participant_data_used": False,
    "participant_container_started": False,
    "participant_task_execution_performed": False,
    "agent_execution_performed": False,
    "backend_fact_append_performed": False,
    "ledger_append_performed": False,
    "execution_authorization_issued_or_consumed": False,
}


def build_claim(
    *,
    probe_id: str,
    claimed_at: str,
    authorization_statement_sha256: str,
    plan_ref: dict[str, str],
    preflight_ref: dict[str, str],
    output_root_sha256: str,
    plan: dict[str, Any],
) -> dict[str, Any]:
    value = {
        "schema_version": CLAIM_SCHEMA,
        "probe_id": probe_id,
        "claimed_at": claimed_at,
        "state": "authorization_claimed_probe_must_close_out",
        "authorization_statement_sha256": authorization_statement_sha256,
        "plan": plan_ref,
        "preflight": preflight_ref,
        "frozen_r4_stack_sha256": plan["frozen_r4_stack_sha256"],
        "reservation": {
            "call_count": 1,
            "max_input_tokens": plan["probe_contract"]["max_input_tokens"],
            "max_output_tokens": plan["probe_contract"]["max_output_tokens"],
            "max_total_tokens": plan["probe_contract"]["max_total_tokens"],
            "max_cost_microunits": plan["pricing_and_budget"][
                "maximum_cost_microunits"
            ],
        },
        "output_root_sha256": output_root_sha256,
        "single_use": True,
        "immutable": True,
        "claim_must_survive_probe_failure": True,
    }
    value["claim_sha256"] = canonical_sha256(value)
    return value


def normalize_response(
    *, status: int, body: bytes, plan: dict[str, Any]
) -> dict[str, Any]:
    try:
        response = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("r4 probe response is not valid JSON") from error
    if not isinstance(response, dict) or status != 200:
        raise ValueError("r4 probe response status or shape invalid")
    if response.get("model") != plan["provider"]["model_id"]:
        raise ValueError("r4 probe response model mismatch")
    choices = response.get("choices")
    if not (isinstance(choices, list) and choices and isinstance(choices[0], dict)):
        raise ValueError("r4 probe response choices invalid")
    message = choices[0].get("message")
    message = message if isinstance(message, dict) else {}
    content = message.get("content")
    if not isinstance(content, str) or not content:
        raise ValueError("r4 probe response content invalid")
    usage = _usage(response.get("usage"))
    probe = plan["probe_contract"]
    if (
        usage["input"] > probe["max_input_tokens"]
        or usage["output"] > probe["max_output_tokens"]
        or usage["total"] > probe["max_total_tokens"]
    ):
        raise ValueError("r4 probe token reservation exceeded")
    cost = calculate_cost_microunits(
        usage={
            "input_cache_hit": usage["input_cache_hit"],
            "input_cache_miss": usage["input_cache_miss"],
            "output": usage["output"],
        },
        pricing=plan["pricing_and_budget"]["pricing"],
    )
    if cost > plan["pricing_and_budget"]["maximum_cost_microunits"]:
        raise ValueError("r4 probe cost reservation exceeded")
    response_id = response.get("id")
    return {
        "http_status": status,
        "raw_response_sha256": hashlib.sha256(body).hexdigest(),
        "response_id_sha256": (
            hashlib.sha256(str(response_id).encode()).hexdigest()
            if response_id is not None
            else None
        ),
        "response_model": response["model"],
        "content_sha256": hashlib.sha256(content.encode()).hexdigest(),
        "content_utf8_bytes": len(content.encode()),
        "usage": usage,
        "actual_cost_microunits": cost,
        "response_content_persisted": False,
    }


def build_receipt(
    *,
    probe_id: str,
    completed_at: str,
    authorization_statement_sha256: str,
    claim_ref: dict[str, str],
    plan_ref: dict[str, str],
    preflight_ref: dict[str, str],
    plan: dict[str, Any],
    provider_result: dict[str, Any],
    inventory_before: dict[str, Any],
    inventory_after: dict[str, Any],
    credential_basename: str,
    implementation: dict[str, str],
) -> dict[str, Any]:
    value = {
        "schema_version": RECEIPT_SCHEMA,
        "probe_id": probe_id,
        "status": "admitted",
        "completed_at": completed_at,
        "authorization": {
            "statement_sha256": authorization_statement_sha256,
            "claim": claim_ref,
            "consumed": True,
            "reusable": False,
        },
        "source_binding": {
            "plan": plan_ref,
            "preflight": preflight_ref,
            "frozen_r4_stack_sha256": plan["frozen_r4_stack_sha256"],
        },
        "provider": {
            **plan["provider"],
            "base_url_sha256": hashlib.sha256(
                plan["provider"]["base_url"].encode()
            ).hexdigest(),
            "base_url": None,
            "response_model": provider_result["response_model"],
        },
        "request": {
            "call_count": 1,
            "request_body_sha256": plan["probe_contract"]["request_body_sha256"],
            "synthetic_prompt_sha256": plan["probe_contract"][
                "synthetic_prompt_sha256"
            ],
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
            "reserved_tokens": plan["probe_contract"]["max_total_tokens"],
            "actual_tokens": provider_result["usage"]["total"],
            "reserved_cost_microunits": plan["pricing_and_budget"][
                "maximum_cost_microunits"
            ],
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
    value["receipt_sha256"] = canonical_sha256(value)
    failures = validate_receipt(
        value,
        plan=plan,
        expected_authorization_sha256=authorization_statement_sha256,
    )
    if failures:
        raise ValueError(f"r4 provider receipt invalid: {failures}")
    return value


def validate_receipt(
    value: Any,
    *,
    plan: dict[str, Any],
    expected_authorization_sha256: str,
) -> list[str]:
    receipt = value if isinstance(value, dict) else {}
    failures: list[str] = []
    body = {key: item for key, item in receipt.items() if key != "receipt_sha256"}
    if not (
        receipt.get("schema_version") == RECEIPT_SCHEMA
        and receipt.get("status") == "admitted"
        and receipt.get("receipt_sha256") == canonical_sha256(body)
        and receipt.get("authorization", {}).get("statement_sha256")
        == expected_authorization_sha256
        and receipt.get("authorization", {}).get("consumed") is True
        and receipt.get("authorization", {}).get("reusable") is False
    ):
        failures.append("r4_probe_receipt_identity_or_authorization_invalid")
    usage = receipt.get("usage", {})
    budget = receipt.get("budget", {})
    if not (
        isinstance(usage, dict)
        and 0 < usage.get("input", 0) <= 128
        and 0 < usage.get("output", 0) <= 1000
        and usage.get("total") == usage.get("input") + usage.get("output")
        and budget.get("reserved_tokens") == 1128
        and budget.get("actual_tokens") == usage.get("total")
        and 0 <= budget.get("actual_cost_microunits", -1) <= 926
        and budget.get("reconciled") is True
    ):
        failures.append("r4_probe_receipt_usage_or_budget_invalid")
    if receipt.get("inventory") != {
        "before": {
            "participant_container_count": 40,
            "created_count": 40,
            "running_count": 0,
        },
        "after": {
            "participant_container_count": 40,
            "created_count": 40,
            "running_count": 0,
        },
        "unchanged": True,
    }:
        failures.append("r4_probe_receipt_inventory_invalid")
    if (
        receipt.get("credential", {}).get("read_count") != 1
        or receipt.get("credential", {}).get("value_persisted") is not False
        or receipt.get("credential", {}).get("hash_persisted") is not False
        or receipt.get("execution_boundary") != PROBE_BOUNDARY
    ):
        failures.append("r4_probe_receipt_secret_or_boundary_invalid")
    return failures


def _usage(value: Any) -> dict[str, int]:
    usage = value if isinstance(value, dict) else {}
    prompt = usage.get("prompt_tokens")
    output = usage.get("completion_tokens")
    total = usage.get("total_tokens")
    if any(type(item) is not int or item < 0 for item in (prompt, output, total)):
        raise ValueError("r4 probe usage counters invalid")
    if prompt == 0 or output == 0 or prompt + output != total:
        raise ValueError("r4 probe usage totals invalid")
    hit = usage.get("prompt_cache_hit_tokens", 0)
    miss = usage.get("prompt_cache_miss_tokens", prompt)
    if (
        type(hit) is not int
        or type(miss) is not int
        or hit < 0
        or miss < 0
        or hit + miss != prompt
    ):
        raise ValueError("r4 probe cache usage invalid")
    return {
        "input": prompt,
        "input_cache_hit": hit,
        "input_cache_miss": miss,
        "output": output,
        "total": total,
    }
