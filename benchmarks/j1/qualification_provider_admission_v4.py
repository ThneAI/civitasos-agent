"""Offline provider-admission plan bound to the frozen J1-D r4 stack."""

from __future__ import annotations

import copy
import hashlib
import math
from datetime import datetime
from typing import Any

from .controlled_comparison import canonical_sha256


PLAN_SCHEMA = "j1-qualification-r4-provider-admission-plan:v1"
PREFLIGHT_SCHEMA = "j1-qualification-r4-provider-admission-preflight:v1"
PROBE_PROMPT = "Reply with exactly ADMITTED."
MAX_INPUT_TOKENS = 128
MAX_OUTPUT_TOKENS = 1000
SOURCE_NAMES = {
    "frozen_r4_stack",
    "r4_promotion_gate",
    "execution_contract",
    "amended_protocol",
    "amended_design",
    "infrastructure_activation",
}
BOUNDARY = {
    "r4_provider_admission_planning_only": True,
    "provider_credential_read": False,
    "provider_api_call_performed": False,
    "model_invocation_performed": False,
    "participant_container_started": False,
    "participant_task_execution_performed": False,
    "agent_execution_performed": False,
    "backend_fact_append_performed": False,
    "ledger_append_performed": False,
    "execution_authorization_issued_or_consumed": False,
}


def build_admission_plan(
    *,
    admission_id: str,
    created_at: str,
    source_artifacts: dict[str, dict[str, str]],
    frozen_stack: dict[str, Any],
    design: dict[str, Any],
    inventory_snapshot: dict[str, Any],
    implementation: dict[str, str],
) -> dict[str, Any]:
    provider = design["preserved_provider_call"]
    pricing = design["preserved_pricing"]
    rates = pricing["rates_microunits"]
    maximum_cost = math.ceil(
        (
            MAX_INPUT_TOKENS * int(rates["input_cache_miss"])
            + MAX_OUTPUT_TOKENS * int(rates["output"])
        )
        / int(pricing["rate_basis_tokens"])
    )
    request_body = {
        "model": provider["model_id"],
        "messages": [{"role": "user", "content": PROBE_PROMPT}],
        "temperature": 0,
        "max_tokens": MAX_OUTPUT_TOKENS,
        "stream": False,
    }
    value = {
        "schema_version": PLAN_SCHEMA,
        "admission_id": admission_id,
        "status": "owner_authorization_required",
        "created_at": created_at,
        "source_artifacts": copy.deepcopy(source_artifacts),
        "frozen_r4_stack_sha256": frozen_stack["frozen_stack_sha256"],
        "provider": {
            "provider_id": provider["provider_id"],
            "base_url": provider["base_url"],
            "model_id": provider["model_id"],
            "temperature": provider["temperature"],
        },
        "probe_contract": {
            "call_count": 1,
            "method": "POST",
            "path": "/chat/completions",
            "request_body": request_body,
            "request_body_sha256": canonical_sha256(request_body),
            "synthetic_prompt_sha256": hashlib.sha256(
                PROBE_PROMPT.encode()
            ).hexdigest(),
            "participant_data_allowed": False,
            "max_input_tokens": MAX_INPUT_TOKENS,
            "max_output_tokens": MAX_OUTPUT_TOKENS,
            "max_total_tokens": MAX_INPUT_TOKENS + MAX_OUTPUT_TOKENS,
            "response_content_persisted": False,
            "response_content_sha256_persisted": True,
            "provider_usage_required": True,
        },
        "pricing_and_budget": {
            "pricing": copy.deepcopy(pricing),
            "pricing_revalidation_performed": False,
            "maximum_cost_microunits": maximum_cost,
            "absolute_authorization_cost_ceiling_microunits": maximum_cost,
            "reservation_required_before_call": True,
            "actual_usage_reconciliation_required": True,
        },
        "credential_contract": {
            "access_allowed_only_after_exact_owner_authorization": True,
            "private_regular_file_mode_required": "0600",
            "read_count": 1,
            "credential_value_persisted": False,
            "credential_hash_persisted": False,
            "required_configuration_names": [
                "BETA6_EXTERNAL_AGENT_PROVIDER",
                "BETA6_EXTERNAL_AGENT_API_BASE_URL",
                "BETA6_EXTERNAL_AGENT_MODEL",
                "BETA6_EXTERNAL_AGENT_API_KEY",
            ],
        },
        "inventory_snapshot": copy.deepcopy(inventory_snapshot),
        "single_use_contract": {
            "create_exclusive_claim_before_credential_read": True,
            "provider_retry_allowed": False,
            "claimed_failure_requires_new_authorization": True,
        },
        "implementation": copy.deepcopy(implementation),
        "execution_boundary": copy.deepcopy(BOUNDARY),
    }
    value["plan_sha256"] = canonical_sha256(value)
    failures = validate_admission_plan(value)
    if failures:
        raise ValueError(f"r4 provider admission plan invalid: {failures}")
    return value


def validate_admission_plan(value: Any) -> list[str]:
    plan = value if isinstance(value, dict) else {}
    failures: list[str] = []
    if not (
        plan.get("schema_version") == PLAN_SCHEMA
        and plan.get("status") == "owner_authorization_required"
        and _text(plan.get("admission_id"))
        and _rfc3339(plan.get("created_at"))
        and set(plan.get("source_artifacts", {})) == SOURCE_NAMES
        and all(_artifact_ref(item) for item in plan["source_artifacts"].values())
    ):
        failures.append("r4_admission_plan_identity_or_sources_invalid")
    provider = plan.get("provider")
    if provider != {
        "provider_id": "openai_compatible",
        "base_url": "https://api.deepseek.com",
        "model_id": "deepseek-v4-pro",
        "temperature": 0,
    }:
        failures.append("r4_admission_provider_invalid")
    probe = plan.get("probe_contract")
    if not (
        isinstance(probe, dict)
        and probe.get("call_count") == 1
        and probe.get("request_body_sha256")
        == canonical_sha256(probe.get("request_body"))
        and probe.get("max_input_tokens") == 128
        and probe.get("max_output_tokens") == 1000
        and probe.get("participant_data_allowed") is False
        and probe.get("response_content_persisted") is False
    ):
        failures.append("r4_admission_probe_contract_invalid")
    budget = plan.get("pricing_and_budget")
    if not (
        isinstance(budget, dict)
        and budget.get("maximum_cost_microunits") == 926
        and budget.get("absolute_authorization_cost_ceiling_microunits") == 926
        and budget.get("reservation_required_before_call") is True
        and budget.get("actual_usage_reconciliation_required") is True
    ):
        failures.append("r4_admission_budget_invalid")
    if plan.get("inventory_snapshot") != {
        "participant_container_count": 40,
        "created_count": 40,
        "running_count": 0,
    }:
        failures.append("r4_admission_inventory_invalid")
    if plan.get("single_use_contract") != {
        "create_exclusive_claim_before_credential_read": True,
        "provider_retry_allowed": False,
        "claimed_failure_requires_new_authorization": True,
    } or plan.get("execution_boundary") != BOUNDARY:
        failures.append("r4_admission_single_use_or_boundary_invalid")
    body = {key: item for key, item in plan.items() if key != "plan_sha256"}
    if plan.get("plan_sha256") != canonical_sha256(body):
        failures.append("r4_admission_plan_hash_invalid")
    return list(dict.fromkeys(failures))


def build_preflight(
    *,
    plan_path: str,
    plan_raw_sha256: str,
    plan: dict[str, Any],
    created_at: str,
) -> dict[str, Any]:
    statement = authorization_statement(
        plan_raw_sha256=plan_raw_sha256,
        plan=plan,
    )
    value = {
        "schema_version": PREFLIGHT_SCHEMA,
        "admission_id": plan["admission_id"],
        "passed": True,
        "failure_reasons": [],
        "state": "r4_provider_admission_ready_owner_authorization_required",
        "created_at": created_at,
        "plan": {
            "path": plan_path,
            "sha256": plan_raw_sha256,
            "canonical_sha256": plan["plan_sha256"],
        },
        "checks": {
            "operator_reviewed_r4_stack_bound": True,
            "provider_model_and_pricing_bound": True,
            "forty_stopped_participant_containers_verified": True,
            "single_use_claim_before_credential_read_required": True,
            "one_https_post_no_retry_bound": True,
            "no_external_effect_performed": True,
        },
        "owner_authorization": {
            "required": True,
            "required_exact_statement": statement,
            "statement_sha256": hashlib.sha256(statement.encode()).hexdigest(),
        },
        "readiness": {
            "live_provider_admission_refreshed": False,
            "execution_preflight_allowed": False,
            "execution_authorization_issued": False,
        },
        "execution_boundary": copy.deepcopy(BOUNDARY),
    }
    value["preflight_sha256"] = canonical_sha256(value)
    return value


def authorization_statement(*, plan_raw_sha256: str, plan: dict[str, Any]) -> str:
    provider = plan["provider"]
    probe = plan["probe_contract"]
    ceiling = plan["pricing_and_budget"][
        "absolute_authorization_cost_ceiling_microunits"
    ]
    return (
        "I authorize exactly one bounded J1-D r4 live-provider admission probe "
        f"from offline plan raw SHA-256 {plan_raw_sha256}, canonical SHA-256 "
        f"{plan['plan_sha256']}, binding frozen r4 stack "
        f"{plan['frozen_r4_stack_sha256']}. I authorize one read of a private "
        "mode-0600 provider environment file and exactly one HTTPS POST to "
        f"{provider['base_url']}{probe['path']} using provider "
        f"{provider['provider_id']}, model {provider['model_id']}, and frozen "
        f"synthetic request body SHA-256 {probe['request_body_sha256']}, with at "
        f"most {probe['max_input_tokens']} input tokens, "
        f"{probe['max_output_tokens']} output tokens, and an absolute cost ceiling "
        f"of {ceiling} USD microunits. The credential value and hash and response "
        "content must not be persisted; only response SHA-256 and sanitized usage "
        "may be recorded. The authorization is single-use, must be claimed before "
        "credential access, and permits no retry. It permits only this synthetic "
        "admission probe. It does not permit starting, creating, or removing any "
        "participant container, use of participant data, advice, or tasks, Agent or "
        "experiment execution, Backend Fact append, Ledger append, or execution "
        "authorization issuance or consumption."
    )


def _artifact_ref(value: Any) -> bool:
    item = value if isinstance(value, dict) else {}
    return (
        set(item) == {"path", "sha256", "canonical_sha256"}
        and str(item.get("path", "")).startswith("/")
        and all(_sha256(item.get(field)) for field in ("sha256", "canonical_sha256"))
    )


def _rfc3339(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None


def _sha256(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())
