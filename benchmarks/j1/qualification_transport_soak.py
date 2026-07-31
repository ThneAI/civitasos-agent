"""Contracts for the single-use J1-D transport admission soak."""

from __future__ import annotations

import copy
import hashlib
import json
from datetime import datetime
from typing import Any

from .controlled_comparison import canonical_sha256
from .qualification_provider_broker import calculate_cost_microunits
from .qualification_transport_reliability import (
    MAX_INPUT_TOKENS,
    MAX_OUTPUT_TOKENS,
    PER_CALL_MAX_MICROUNITS,
    SOAK_CALL_COUNT,
    synthetic_probe_body,
    validate_soak_plan,
)
from .qualification_transport_review import FROZEN_SCHEMA, GATE_SCHEMA


PLAN_SCHEMA = "j1-qualification-transport-admission-soak-execution-plan:v1"
PREFLIGHT_SCHEMA = "j1-qualification-transport-admission-soak-authorization-preflight:v1"
CLAIM_SCHEMA = "j1-qualification-transport-admission-soak-claim:v1"
REPORT_SCHEMA = "j1-qualification-transport-admission-soak-report:v1"
GATE_REPORT_SCHEMA = "j1-qualification-transport-admission-soak-gate:v1"
SOURCE_NAMES = {"promotion_gate", "frozen_review", "reviewed_soak_plan"}
PLANNING_BOUNDARY = {
    "transport_soak_planning_only": True,
    "provider_credential_read": False,
    "provider_or_model_call_performed": False,
    "participant_container_started_or_modified": False,
    "agent_or_experiment_execution_performed": False,
    "backend_fact_append_performed": False,
    "ledger_append_performed": False,
    "authorization_issued_or_consumed": False,
    "effectiveness_claim_authorized": False,
    "si13_maturity_upgrade_authorized": False,
}


def build_execution_plan(
    *,
    soak_id: str,
    created_at: str,
    source_artifacts: dict[str, dict[str, str]],
    reviewed_plan: dict[str, Any],
    pricing: dict[str, Any],
    implementation: dict[str, str],
) -> dict[str, Any]:
    value = {
        "schema_version": PLAN_SCHEMA,
        "soak_id": soak_id,
        "status": "owner_authorization_required",
        "created_at": created_at,
        "source_artifacts": copy.deepcopy(source_artifacts),
        "provider": copy.deepcopy(reviewed_plan["provider"]),
        "synthetic_requests": copy.deepcopy(reviewed_plan["synthetic_requests"]),
        "execution_policy": copy.deepcopy(reviewed_plan["execution_policy"]),
        "budget": copy.deepcopy(reviewed_plan["budget"]),
        "admission_gate": copy.deepcopy(reviewed_plan["admission_gate"]),
        "pricing": copy.deepcopy(pricing),
        "single_use_contract": {
            "create_exclusive_claim_before_credential_read": True,
            "claim_survives_any_failure": True,
            "credential_file_read_count": 1,
            "provider_request_retry_allowed": False,
            "post_dispatch_retry_allowed": False,
            "stop_after_first_failure": True,
            "new_authorization_required_after_any_claimed_failure": True,
        },
        "implementation": copy.deepcopy(implementation),
        "authorization_boundary": copy.deepcopy(PLANNING_BOUNDARY),
    }
    value["plan_sha256"] = canonical_sha256(value)
    failures = validate_execution_plan(value)
    if failures:
        raise ValueError(f"transport soak execution plan invalid: {failures}")
    return value


def validate_execution_plan(value: Any) -> list[str]:
    plan = value if isinstance(value, dict) else {}
    failures: list[str] = []
    _require(
        plan.get("schema_version") == PLAN_SCHEMA
        and plan.get("status") == "owner_authorization_required"
        and _text(plan.get("soak_id"))
        and _rfc3339(plan.get("created_at"))
        and set(_object(plan.get("source_artifacts"))) == SOURCE_NAMES
        and all(
            _reference(item)
            for item in _object(plan.get("source_artifacts")).values()
        ),
        "transport_soak_plan_identity_or_sources_invalid",
        failures,
    )
    provider = _object(plan.get("provider"))
    _require(
        provider
        == {
            "provider_id": "openai_compatible",
            "base_url": "https://api.deepseek.com",
            "endpoint": "/chat/completions",
            "model": "deepseek-v4-pro",
        },
        "transport_soak_provider_invalid",
        failures,
    )
    requests = _object(plan.get("synthetic_requests"))
    expected_hashes = [
        canonical_sha256(
            synthetic_probe_body(model=provider.get("model", ""), ordinal=ordinal)
        )
        for ordinal in range(1, SOAK_CALL_COUNT + 1)
    ]
    _require(
        requests.get("call_count") == SOAK_CALL_COUNT
        and requests.get("request_body_canonical_sha256") == expected_hashes
        and requests.get("max_input_tokens_per_call") == MAX_INPUT_TOKENS
        and requests.get("max_output_tokens_per_call") == MAX_OUTPUT_TOKENS
        and requests.get("participant_data_present") is False
        and requests.get("advice_or_fixture_data_present") is False,
        "transport_soak_requests_invalid",
        failures,
    )
    _require(
        plan.get("execution_policy")
        == {
            "sequential_calls_only": True,
            "stop_after_first_failure": True,
            "connect_attempts_per_call": 3,
            "http_request_attempts_per_call": 1,
            "ambiguous_dispatch_retry_count": 0,
            "credential_file_read_count": 1,
            "absolute_duration_seconds": 1800,
        },
        "transport_soak_execution_policy_invalid",
        failures,
    )
    _require(
        plan.get("budget")
        == {
            "per_call_reserved_tokens": MAX_INPUT_TOKENS + MAX_OUTPUT_TOKENS,
            "aggregate_reserved_tokens": (
                SOAK_CALL_COUNT * (MAX_INPUT_TOKENS + MAX_OUTPUT_TOKENS)
            ),
            "per_call_max_microunits": PER_CALL_MAX_MICROUNITS,
            "aggregate_max_microunits": (
                SOAK_CALL_COUNT * PER_CALL_MAX_MICROUNITS
            ),
        },
        "transport_soak_budget_invalid",
        failures,
    )
    pricing = _object(plan.get("pricing"))
    _require(
        pricing.get("rate_basis_tokens") == 1_000_000
        and pricing.get("rates_microunits")
        == {
            "input_cache_hit": 3625,
            "input_cache_miss": 435000,
            "output": 870000,
        }
        and calculate_cost_microunits(
            usage={
                "input_cache_hit": 0,
                "input_cache_miss": MAX_INPUT_TOKENS,
                "output": MAX_OUTPUT_TOKENS,
            },
            pricing=pricing,
        )
        == PER_CALL_MAX_MICROUNITS,
        "transport_soak_pricing_invalid",
        failures,
    )
    gate = _object(plan.get("admission_gate"))
    _require(
        gate.get("required_completed_call_count") == SOAK_CALL_COUNT
        and gate.get("required_http_200_count") == SOAK_CALL_COUNT
        and gate.get("provider_outcome_unknown_allowed") == 0
        and gate.get("post_dispatch_retry_allowed") == 0
        and gate.get("response_content_persisted") is False
        and gate.get("credential_value_or_hash_persisted") is False,
        "transport_soak_gate_invalid",
        failures,
    )
    _require(
        plan.get("single_use_contract")
        == {
            "create_exclusive_claim_before_credential_read": True,
            "claim_survives_any_failure": True,
            "credential_file_read_count": 1,
            "provider_request_retry_allowed": False,
            "post_dispatch_retry_allowed": False,
            "stop_after_first_failure": True,
            "new_authorization_required_after_any_claimed_failure": True,
        }
        and plan.get("authorization_boundary") == PLANNING_BOUNDARY,
        "transport_soak_single_use_or_boundary_invalid",
        failures,
    )
    implementation = _object(plan.get("implementation"))
    _require(
        set(implementation)
        == {
            "source_revision",
            "domain_source_sha256",
            "preflight_source_sha256",
            "execution_source_sha256",
        }
        and len(str(implementation.get("source_revision", ""))) == 40
        and all(
            _sha256(implementation.get(name))
            for name in (
                "domain_source_sha256",
                "preflight_source_sha256",
                "execution_source_sha256",
            )
        ),
        "transport_soak_implementation_invalid",
        failures,
    )
    body = {key: item for key, item in plan.items() if key != "plan_sha256"}
    _require(
        plan.get("plan_sha256") == canonical_sha256(body),
        "transport_soak_plan_hash_invalid",
        failures,
    )
    return list(dict.fromkeys(failures))


def validate_reviewed_sources(
    *,
    promotion_gate: dict[str, Any],
    frozen_review: dict[str, Any],
    reviewed_plan: dict[str, Any],
    refs: dict[str, dict[str, str]],
) -> list[str]:
    failures = validate_soak_plan(reviewed_plan)
    _require(
        set(refs) == SOURCE_NAMES and all(_reference(item) for item in refs.values()),
        "transport_soak_reviewed_source_refs_invalid",
        failures,
    )
    _require(
        promotion_gate.get("schema_version") == GATE_SCHEMA
        and promotion_gate.get("passed") is True
        and promotion_gate.get("state")
        == (
            "transport_reliability_materials_frozen_"
            "live_soak_authorization_preflight_allowed"
        )
        and promotion_gate.get("frozen_review") == refs["frozen_review"],
        "transport_soak_promotion_gate_invalid",
        failures,
    )
    frozen_copies = _object(frozen_review.get("frozen_source_copies"))
    _require(
        frozen_review.get("schema_version") == FROZEN_SCHEMA
        and frozen_review.get("status") == "operator_reviewed_frozen"
        and _object(frozen_review.get("readiness")).get(
            "live_soak_authorization_preflight_allowed"
        )
        is True
        and frozen_copies.get("soak_plan") == refs["reviewed_soak_plan"],
        "transport_soak_frozen_review_invalid",
        failures,
    )
    return list(dict.fromkeys(failures))


def build_authorization_preflight(
    *,
    plan_ref: dict[str, str],
    plan: dict[str, Any],
    created_at: str,
) -> dict[str, Any]:
    statement = authorization_statement(
        plan_raw_sha256=plan_ref["sha256"],
        plan=plan,
    )
    value = {
        "schema_version": PREFLIGHT_SCHEMA,
        "soak_id": plan["soak_id"],
        "passed": True,
        "failure_reasons": [],
        "state": "transport_soak_ready_exact_owner_authorization_required",
        "created_at": created_at,
        "plan": copy.deepcopy(plan_ref),
        "checks": {
            "signed_transport_review_gate_bound": True,
            "reviewed_content_free_request_set_bound": True,
            "execution_implementation_revision_bound": True,
            "create_exclusive_claim_before_credential_read_required": True,
            "sixty_four_sequential_single_use_requests_bound": True,
            "post_dispatch_retry_count_zero": True,
            "absolute_duration_and_budget_ceiling_bound": True,
            "no_external_effect_performed": True,
        },
        "owner_authorization": {
            "required": True,
            "required_exact_statement": statement,
            "statement_sha256": hashlib.sha256(statement.encode()).hexdigest(),
        },
        "readiness": {
            "owner_authorization_required": True,
            "authorization_claimed": False,
            "provider_credential_access_allowed": False,
            "provider_or_model_call_allowed": False,
        },
        "execution_boundary": copy.deepcopy(PLANNING_BOUNDARY),
    }
    value["preflight_sha256"] = canonical_sha256(value)
    return value


def authorization_statement(*, plan_raw_sha256: str, plan: dict[str, Any]) -> str:
    provider = plan["provider"]
    budget = plan["budget"]
    implementation = plan["implementation"]
    sources = plan["source_artifacts"]
    return (
        "I authorize exactly one bounded J1-D transport admission soak from execution "
        f"plan raw SHA-256 {plan_raw_sha256}, canonical SHA-256 "
        f"{plan['plan_sha256']}, binding signed transport promotion Gate canonical "
        f"SHA-256 {sources['promotion_gate']['canonical_sha256']}, reviewed 64-call "
        f"soak plan canonical SHA-256 "
        f"{sources['reviewed_soak_plan']['canonical_sha256']}, and execution revision "
        f"{implementation['source_revision']}. I authorize one create-exclusive atomic "
        "claim before any credential access, one read of a private mode-0600 provider "
        f"environment file, and at most {SOAK_CALL_COUNT} sequential HTTPS POSTs to "
        f"{provider['base_url']}{provider['endpoint']} using provider "
        f"{provider['provider_id']} and model {provider['model']} at temperature 0. "
        f"The aggregate reservation is {budget['aggregate_reserved_tokens']} tokens "
        f"and the absolute cost ceiling is {budget['aggregate_max_microunits']} USD "
        "microunits within 1800 seconds. Connection setup may retry only before each "
        "request dispatch; every HTTP request is single-use, the soak stops after the "
        "first failure, and any failure after dispatch is ambiguous and must never be "
        "retried. The credential value and hash, response content, and exception "
        "message must not be persisted; only response hashes, sanitized usage, "
        "connect-attempt counts, and sanitized failure classification may be recorded. "
        "The claim is irreversible and any claimed failure requires a new reviewed "
        "plan and authorization. This authorization permits only the content-free "
        "transport soak. It does not create, start, rename, or remove a participant "
        "container, use participant data, advice, fixtures, or tasks, execute an Agent "
        "or controlled experiment, append Backend Facts or the Ledger, authorize an "
        "effectiveness claim, or upgrade SI-13 maturity."
    )


def build_claim(
    *,
    claimed_at: str,
    authorization_statement_sha256: str,
    plan_ref: dict[str, str],
    preflight_ref: dict[str, str],
    output_root_sha256: str,
    plan: dict[str, Any],
) -> dict[str, Any]:
    value = {
        "schema_version": CLAIM_SCHEMA,
        "soak_id": plan["soak_id"],
        "claimed_at": claimed_at,
        "state": "authorization_claimed_soak_must_close_out",
        "authorization_statement_sha256": authorization_statement_sha256,
        "plan": copy.deepcopy(plan_ref),
        "preflight": copy.deepcopy(preflight_ref),
        "reservation": {
            "call_count": SOAK_CALL_COUNT,
            "tokens": plan["budget"]["aggregate_reserved_tokens"],
            "cost_microunits": plan["budget"]["aggregate_max_microunits"],
            "absolute_duration_seconds": plan["execution_policy"][
                "absolute_duration_seconds"
            ],
        },
        "output_root_sha256": output_root_sha256,
        "single_use": True,
        "immutable": True,
        "claim_survives_any_failure": True,
    }
    value["claim_sha256"] = canonical_sha256(value)
    return value


def normalize_response(
    *,
    status: int,
    body: bytes,
    plan: dict[str, Any],
) -> dict[str, Any]:
    try:
        response = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SoakResponseFailure("parse", "response_json", type(error).__name__) from None
    if not isinstance(response, dict) or status != 200:
        raise SoakResponseFailure(
            "schema", "http_status_or_response_shape", "ProviderResponseShapeError"
        )
    if response.get("model") != plan["provider"]["model"]:
        raise SoakResponseFailure(
            "schema", "response_model", "ProviderResponseModelError"
        )
    choices = response.get("choices")
    if not (isinstance(choices, list) and choices and isinstance(choices[0], dict)):
        raise SoakResponseFailure(
            "schema", "response_choices", "ProviderResponseChoicesError"
        )
    message = _object(choices[0].get("message"))
    content = message.get("content")
    if not isinstance(content, str) or not content:
        raise SoakResponseFailure(
            "schema", "response_content", "ProviderResponseContentError"
        )
    usage = _usage(response.get("usage"))
    if (
        usage["input"] > MAX_INPUT_TOKENS
        or usage["output"] > MAX_OUTPUT_TOKENS
        or usage["total"] > MAX_INPUT_TOKENS + MAX_OUTPUT_TOKENS
    ):
        raise SoakResponseFailure(
            "usage", "token_reservation", "ProviderUsageCeilingError"
        )
    cost = calculate_cost_microunits(
        usage={
            "input_cache_hit": usage["input_cache_hit"],
            "input_cache_miss": usage["input_cache_miss"],
            "output": usage["output"],
        },
        pricing=plan["pricing"],
    )
    if cost > PER_CALL_MAX_MICROUNITS:
        raise SoakResponseFailure(
            "usage", "cost_reservation", "ProviderCostCeilingError"
        )
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
        "response_content_persisted": False,
        "usage": usage,
        "actual_cost_microunits": cost,
    }


class SoakResponseFailure(ValueError):
    def __init__(self, category: str, stage: str, source_exception_type: str) -> None:
        self.failure_category = category
        self.failure_stage = stage
        self.source_exception_type = source_exception_type
        super().__init__(f"sanitized transport soak failure at {category}/{stage}")


def _usage(value: Any) -> dict[str, int]:
    usage = _object(value)
    prompt = usage.get("prompt_tokens")
    output = usage.get("completion_tokens")
    total = usage.get("total_tokens")
    if (
        any(type(item) is not int or item < 0 for item in (prompt, output, total))
        or prompt == 0
        or output == 0
        or prompt + output != total
    ):
        raise SoakResponseFailure(
            "usage", "usage_counters", "ProviderUsageShapeError"
        )
    hit = usage.get("prompt_cache_hit_tokens", 0)
    miss = usage.get("prompt_cache_miss_tokens", prompt)
    if (
        type(hit) is not int
        or type(miss) is not int
        or hit < 0
        or miss < 0
        or hit + miss != prompt
    ):
        raise SoakResponseFailure(
            "usage", "cache_counters", "ProviderCacheUsageShapeError"
        )
    return {
        "input": prompt,
        "input_cache_hit": hit,
        "input_cache_miss": miss,
        "output": output,
        "total": total,
    }


def _reference(value: Any) -> bool:
    item = _object(value)
    return (
        set(item) == {"path", "sha256", "canonical_sha256"}
        and str(item.get("path", "")).startswith("/")
        and _sha256(item.get("sha256"))
        and _sha256(item.get("canonical_sha256"))
    )


def _object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _rfc3339(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).tzinfo is not None
    except ValueError:
        return False


def _sha256(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        bytes.fromhex(value)
        return True
    except ValueError:
        return False


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _require(condition: bool, failure: str, failures: list[str]) -> None:
    if not condition:
        failures.append(failure)
