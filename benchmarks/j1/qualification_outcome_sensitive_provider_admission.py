"""Outcome-sensitive J1-D live-provider admission contracts."""

from __future__ import annotations

import copy
import hashlib
from datetime import datetime
from typing import Any

from .controlled_comparison import canonical_sha256
from .qualification_provider_admission_refresh import (
    PROBE_MAX_INPUT_TOKENS,
    PROBE_MAX_OUTPUT_TOKENS,
    PROBE_PROMPT,
    probe_maximum_cost_microunits,
)


PLAN_SCHEMA = "j1-qualification-outcome-sensitive-provider-admission-plan:v1"
PREFLIGHT_SCHEMA = (
    "j1-qualification-outcome-sensitive-provider-admission-preflight:v1"
)
SOURCE_CANONICAL_FIELDS = {
    "protocol": "protocol_sha256",
    "evaluator": "evaluator_sha256",
    "task_fixture": "fixture_sha256",
    "statistical_plan": "statistical_plan_sha256",
    "design": "amended_design_sha256",
    "roster": "reviewed_rebound_roster_sha256",
    "assignment": "reviewed_rebound_assignment_sha256",
    "roster_assignment_gate": "report_sha256",
    "signed_advice_manifest": "manifest_sha256",
    "mentor_advice_gate": "report_sha256",
    "infrastructure": "reviewed_infrastructure_rebind_sha256",
    "infrastructure_promotion_gate": "report_sha256",
    "activation": "activation_sha256",
    "activation_gate": "report_sha256",
    "runner_manifest": "manifest_sha256",
    "material_promotion_gate": "report_sha256",
}
SOURCE_NAMES = set(SOURCE_CANONICAL_FIELDS)
OFFLINE_BOUNDARY = {
    "outcome_sensitive_provider_admission_planning_only": True,
    "credential_file_accessed": False,
    "provider_api_call_performed": False,
    "model_invocation_performed": False,
    "participant_container_created": False,
    "participant_container_started": False,
    "participant_task_execution_performed": False,
    "agent_execution_performed": False,
    "backend_fact_append_performed": False,
    "ledger_append_performed": False,
    "execution_stack_promoted": False,
    "execution_authorization_issued_or_consumed": False,
    "effectiveness_claim_authorized": False,
    "si13_maturity_upgrade_authorized": False,
}


def canonical_source_sha256(name: str, value: dict[str, Any]) -> str:
    field = SOURCE_CANONICAL_FIELDS.get(name, "")
    return str(value.get(field, ""))


def validate_source_chain(
    values: dict[str, dict[str, Any]],
    raw_sha256: dict[str, str],
) -> list[str]:
    failures: list[str] = []
    if set(values) != SOURCE_NAMES or set(raw_sha256) != SOURCE_NAMES:
        failures.append("outcome_admission_source_set_invalid")
        return failures
    for name, value in values.items():
        field = SOURCE_CANONICAL_FIELDS[name]
        body = {key: item for key, item in value.items() if key != field}
        if value.get(field) != canonical_sha256(body):
            failures.append(f"outcome_admission_{name}_self_hash_invalid")

    protocol = values["protocol"]
    evaluator = values["evaluator"]
    fixture = values["task_fixture"]
    statistics = values["statistical_plan"]
    design = values["design"]
    roster = values["roster"]
    assignment = values["assignment"]
    roster_gate = values["roster_assignment_gate"]
    advice = values["signed_advice_manifest"]
    advice_gate = values["mentor_advice_gate"]
    infrastructure = values["infrastructure"]
    infrastructure_gate = values["infrastructure_promotion_gate"]
    activation = values["activation"]
    activation_gate = values["activation_gate"]
    runner = values["runner_manifest"]
    material_gate = values["material_promotion_gate"]

    _require(
        protocol.get("schema_version")
        == "j1-qualification-outcome-sensitive-protocol-amendment:v1"
        and protocol.get("preserved_stack")
        == {
            "model_id": "deepseek-v4-pro",
            "provider_id": "openai_compatible",
            "same_stack_for_both_cohorts": True,
            "temperature": 0,
        }
        and protocol.get("scope")
        == {
            "matched_pair_count": 20,
            "minimum_completed_pairs": 20,
            "participant_count": 40,
            "tasks_per_participant": 12,
            "total_task_count": 480,
        }
        and _object(protocol.get("fresh_bindings_required")).get(
            "provider_admission"
        )
        is True,
        "outcome_admission_protocol_invalid",
        failures,
    )
    _require(
        evaluator.get("schema_version")
        == "j1-qualification-outcome-sensitive-evaluator-amendment:v1"
        and _ref_matches(
            evaluator.get("protocol"),
            raw_sha256["protocol"],
            canonical_source_sha256("protocol", protocol),
        )
        and _ref_matches(
            evaluator.get("task_fixture"),
            raw_sha256["task_fixture"],
            canonical_source_sha256("task_fixture", fixture),
        )
        and _ref_matches(
            evaluator.get("statistical_plan"),
            raw_sha256["statistical_plan"],
            canonical_source_sha256("statistical_plan", statistics),
        ),
        "outcome_admission_evaluator_binding_invalid",
        failures,
    )
    provider = _object(design.get("preserved_provider_call"))
    pricing = _object(design.get("preserved_pricing"))
    _require(
        design.get("schema_version")
        == "j1-qualification-execution-design-amendment:v1"
        and provider.get("provider_id") == "openai_compatible"
        and provider.get("base_url") == "https://api.deepseek.com"
        and provider.get("model_id") == "deepseek-v4-pro"
        and provider.get("temperature") == 0
        and pricing.get("billing_currency") == "USD"
        and pricing.get("cost_unit") == "usd_microunit"
        and pricing.get("rate_basis_tokens") == 1_000_000
        and pricing.get("price_drift_requires_new_reviewed_design") is True,
        "outcome_admission_preserved_provider_or_pricing_invalid",
        failures,
    )
    frozen = _object(_object(assignment.get("source_binding")).get("frozen_materials"))
    _require(
        assignment.get("schema_version")
        == "j1-qualification-outcome-sensitive-assignment-rebound:operator-reviewed:v1"
        and assignment.get("status") == "operator_reviewed"
        and _ref_matches(
            frozen.get("protocol"),
            raw_sha256["protocol"],
            canonical_source_sha256("protocol", protocol),
        )
        and _ref_matches(
            frozen.get("evaluator"),
            raw_sha256["evaluator"],
            canonical_source_sha256("evaluator", evaluator),
        )
        and _ref_matches(
            frozen.get("task_fixture"),
            raw_sha256["task_fixture"],
            canonical_source_sha256("task_fixture", fixture),
        )
        and _ref_matches(
            frozen.get("statistical_plan"),
            raw_sha256["statistical_plan"],
            canonical_source_sha256("statistical_plan", statistics),
        ),
        "outcome_admission_assignment_material_binding_invalid",
        failures,
    )
    reviewed = _object(roster_gate.get("reviewed_artifacts"))
    _require(
        roster.get("schema_version")
        == "j1-qualification-outcome-sensitive-roster-rebound:operator-reviewed:v1"
        and roster.get("status") == "operator_reviewed"
        and roster_gate.get("passed") is True
        and roster_gate.get("failure_reasons") == []
        and _ref_matches(
            reviewed.get("rebound_roster"),
            raw_sha256["roster"],
            canonical_source_sha256("roster", roster),
        )
        and _ref_matches(
            reviewed.get("rebound_assignment"),
            raw_sha256["assignment"],
            canonical_source_sha256("assignment", assignment),
        ),
        "outcome_admission_roster_assignment_gate_invalid",
        failures,
    )
    _require(
        material_gate.get("passed") is True
        and material_gate.get("failure_reasons") == []
        and _object(material_gate.get("readiness")).get(
            "provider_or_model_execution_allowed"
        )
        is False,
        "outcome_admission_material_promotion_gate_invalid",
        failures,
    )
    _require(
        advice.get("schema_version")
        == "j1-qualification-outcome-sensitive-treatment-advice-signed-manifest:v1"
        and advice.get("status") == "signed_non_executable_gate_required"
        and _object(advice.get("inventory")).get("signed_advice_count") == 180
        and advice_gate.get("passed") is True
        and advice_gate.get("failure_reasons") == []
        and _object(advice_gate.get("source_binding")).get("signed_manifest")
        == {
            "path": _object(
                _object(advice_gate.get("source_binding")).get("signed_manifest")
            ).get("path"),
            "sha256": raw_sha256["signed_advice_manifest"],
            "canonical_sha256": canonical_source_sha256(
                "signed_advice_manifest", advice
            ),
        },
        "outcome_admission_advice_gate_invalid",
        failures,
    )
    infra_source = _object(infrastructure.get("source_binding"))
    _require(
        infrastructure.get("schema_version")
        == "j1-qualification-outcome-sensitive-infrastructure-rebind:operator-reviewed:v1"
        and infrastructure.get("status") == "operator_reviewed"
        and _ref_matches(
            infra_source.get("reviewed_assignment"),
            raw_sha256["assignment"],
            canonical_source_sha256("assignment", assignment),
        )
        and _ref_matches(
            infra_source.get("mentor_advice_gate"),
            raw_sha256["mentor_advice_gate"],
            canonical_source_sha256("mentor_advice_gate", advice_gate),
        )
        and _ref_matches(
            infra_source.get("runner_manifest"),
            raw_sha256["runner_manifest"],
            canonical_source_sha256("runner_manifest", runner),
        ),
        "outcome_admission_infrastructure_binding_invalid",
        failures,
    )
    _require(
        infrastructure_gate.get("passed") is True
        and infrastructure_gate.get("failure_reasons") == []
        and _ref_matches(
            infrastructure_gate.get("reviewed_artifact"),
            raw_sha256["infrastructure"],
            canonical_source_sha256("infrastructure", infrastructure),
        ),
        "outcome_admission_infrastructure_promotion_invalid",
        failures,
    )
    activation_source = _object(activation.get("source_binding"))
    _require(
        activation.get("schema_version")
        == "j1-qualification-infrastructure-activation:v1"
        and activation_source.get("reviewed_artifact_sha256")
        == raw_sha256["infrastructure"]
        and activation_source.get("reviewed_infrastructure_sha256")
        == canonical_source_sha256("infrastructure", infrastructure)
        and activation_source.get("promotion_gate_sha256")
        == raw_sha256["infrastructure_promotion_gate"]
        and activation_source.get("promotion_gate_canonical_sha256")
        == canonical_source_sha256(
            "infrastructure_promotion_gate", infrastructure_gate
        )
        and activation_source.get("runner_manifest_sha256")
        == canonical_source_sha256("runner_manifest", runner),
        "outcome_admission_activation_binding_invalid",
        failures,
    )
    _require(
        activation_gate.get("passed") is True
        and activation_gate.get("failure_reasons") == []
        and activation_gate.get("state")
        == "replacement_containers_created_provider_admission_required"
        and activation_gate.get("next_blocker")
        == "live_provider_admission_refresh_required"
        and _ref_matches(
            activation_gate.get("activation"),
            raw_sha256["activation"],
            canonical_source_sha256("activation", activation),
        )
        and activation_gate.get("inventory")
        == {
            "container_created_count": 40,
            "container_started_count": 0,
            "control_count": 20,
            "mentor_count": 20,
            "participant_count": 40,
        },
        "outcome_admission_activation_gate_invalid",
        failures,
    )
    return list(dict.fromkeys(failures))


def build_plan(
    *,
    admission_id: str,
    created_at: str,
    source_binding: dict[str, dict[str, str]],
    protocol: dict[str, Any],
    evaluator: dict[str, Any],
    design: dict[str, Any],
    activation: dict[str, Any],
    inventory_snapshot: dict[str, Any],
    implementation: dict[str, str],
) -> dict[str, Any]:
    provider = copy.deepcopy(design["preserved_provider_call"])
    pricing = copy.deepcopy(design["preserved_pricing"])
    rates = pricing["rates_microunits"]
    maximum_cost = probe_maximum_cost_microunits(
        input_rate=int(rates["input_cache_miss"]),
        output_rate=int(rates["output"]),
        rate_basis_tokens=int(pricing["rate_basis_tokens"]),
    )
    request_body = {
        "model": provider["model_id"],
        "messages": [{"role": "user", "content": PROBE_PROMPT}],
        "temperature": 0,
        "max_tokens": PROBE_MAX_OUTPUT_TOKENS,
        "stream": False,
    }
    plan = {
        "schema_version": PLAN_SCHEMA,
        "admission_id": admission_id,
        "created_at": created_at,
        "status": "owner_authorization_required",
        "source_binding": copy.deepcopy(source_binding),
        "frozen_stack": {
            "provider_id": provider["provider_id"],
            "base_url": provider["base_url"],
            "model_id": provider["model_id"],
            "temperature": provider["temperature"],
            "protocol_sha256": protocol["protocol_sha256"],
            "evaluator_sha256": evaluator["evaluator_sha256"],
            "design_sha256": design["amended_design_sha256"],
            "activation_sha256": activation["activation_sha256"],
        },
        "preserved_design_reuse_scope": {
            "provider_identity_and_pricing_only": True,
            "prior_execution_call_count_or_budget_inherited": False,
            "new_execution_stack_review_required": True,
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
            "max_input_tokens": PROBE_MAX_INPUT_TOKENS,
            "max_output_tokens": PROBE_MAX_OUTPUT_TOKENS,
            "max_total_tokens": PROBE_MAX_INPUT_TOKENS + PROBE_MAX_OUTPUT_TOKENS,
            "accepted_http_status": 200,
            "response_content_persisted": False,
            "response_content_sha256_persisted": True,
            "provider_usage_required": True,
        },
        "pricing_and_budget": {
            "pricing": pricing,
            "pricing_revalidation_performed": False,
            "pricing_basis": "operator_reviewed_preserved_execution_design",
            "input_charge_basis": "input_cache_miss",
            "maximum_cost_microunits": maximum_cost,
            "absolute_authorization_cost_ceiling_microunits": maximum_cost,
            "reservation_required_before_call": True,
            "actual_usage_reconciliation_required": True,
        },
        "credential_contract": {
            "private_regular_file_mode_required": "0600",
            "required_configuration_names": [
                "BETA6_EXTERNAL_AGENT_PROVIDER",
                "BETA6_EXTERNAL_AGENT_API_BASE_URL",
                "BETA6_EXTERNAL_AGENT_MODEL",
                "BETA6_EXTERNAL_AGENT_API_KEY",
            ],
            "credential_value_persisted": False,
            "credential_hash_persisted": False,
            "access_allowed_only_after_exact_owner_authorization": True,
        },
        "inventory_snapshot": copy.deepcopy(inventory_snapshot),
        "authorization_contract": {
            "exact_plan_raw_and_canonical_hashes_required": True,
            "single_use_required": True,
            "maximum_ttl_seconds": 1800,
            "one_credential_read_allowed": True,
            "one_https_provider_call_allowed": True,
            "retry_allowed": False,
            "participant_container_start_allowed": False,
            "execution_stack_promotion_allowed": False,
            "execution_authorization_issuance_or_consumption_allowed": False,
        },
        "implementation": copy.deepcopy(implementation),
        "readiness": {
            "offline_preflight_complete": True,
            "owner_probe_authorization_required": True,
            "live_provider_admission_refreshed": False,
            "outcome_sensitive_execution_stack_reviewed": False,
            "controlled_experiment_execution_ready": False,
        },
        "execution_boundary": copy.deepcopy(OFFLINE_BOUNDARY),
    }
    plan["plan_sha256"] = canonical_sha256(plan)
    failures = validate_plan(plan)
    if failures:
        raise ValueError(f"outcome-sensitive provider admission plan invalid: {failures}")
    return plan


def validate_plan(plan: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    body = {key: item for key, item in plan.items() if key != "plan_sha256"}
    stack = _object(plan.get("frozen_stack"))
    probe = _object(plan.get("probe_contract"))
    budget = _object(plan.get("pricing_and_budget"))
    pricing = _object(budget.get("pricing"))
    rates = _object(pricing.get("rates_microunits"))
    authorization = _object(plan.get("authorization_contract"))
    expected_request = {
        "model": "deepseek-v4-pro",
        "messages": [{"role": "user", "content": PROBE_PROMPT}],
        "temperature": 0,
        "max_tokens": PROBE_MAX_OUTPUT_TOKENS,
        "stream": False,
    }
    _require(
        plan.get("schema_version") == PLAN_SCHEMA
        and plan.get("status") == "owner_authorization_required"
        and _text(plan.get("admission_id"))
        and _rfc3339(plan.get("created_at"))
        and plan.get("plan_sha256") == canonical_sha256(body)
        and set(_object(plan.get("source_binding"))) == SOURCE_NAMES
        and all(
            _artifact_ref(value)
            for value in _object(plan.get("source_binding")).values()
        ),
        "outcome_admission_plan_identity_invalid",
        failures,
    )
    _require(
        stack.get("provider_id") == "openai_compatible"
        and stack.get("base_url") == "https://api.deepseek.com"
        and stack.get("model_id") == "deepseek-v4-pro"
        and stack.get("temperature") == 0
        and all(
            _sha256(stack.get(name))
            for name in (
                "protocol_sha256",
                "evaluator_sha256",
                "design_sha256",
                "activation_sha256",
            )
        ),
        "outcome_admission_frozen_stack_invalid",
        failures,
    )
    _require(
        probe.get("call_count") == 1
        and probe.get("method") == "POST"
        and probe.get("path") == "/chat/completions"
        and probe.get("request_body") == expected_request
        and probe.get("request_body_sha256") == canonical_sha256(expected_request)
        and probe.get("max_input_tokens") == PROBE_MAX_INPUT_TOKENS
        and probe.get("max_output_tokens") == PROBE_MAX_OUTPUT_TOKENS
        and probe.get("max_total_tokens")
        == PROBE_MAX_INPUT_TOKENS + PROBE_MAX_OUTPUT_TOKENS
        and probe.get("participant_data_allowed") is False
        and probe.get("response_content_persisted") is False,
        "outcome_admission_probe_contract_invalid",
        failures,
    )
    try:
        expected_cost = probe_maximum_cost_microunits(
            input_rate=int(rates["input_cache_miss"]),
            output_rate=int(rates["output"]),
            rate_basis_tokens=int(pricing["rate_basis_tokens"]),
        )
    except (KeyError, TypeError, ValueError, ZeroDivisionError):
        expected_cost = -1
    _require(
        expected_cost == 926
        and budget.get("maximum_cost_microunits") == expected_cost
        and budget.get("absolute_authorization_cost_ceiling_microunits")
        == expected_cost
        and budget.get("pricing_revalidation_performed") is False,
        "outcome_admission_budget_invalid",
        failures,
    )
    inventory = _object(plan.get("inventory_snapshot"))
    _require(
        inventory.get("participant_count") == 40
        and inventory.get("container_count") == 40
        and inventory.get("created_count") == 40
        and inventory.get("running_count") == 0
        and _sha256(inventory.get("container_set_sha256")),
        "outcome_admission_inventory_invalid",
        failures,
    )
    _require(
        authorization.get("single_use_required") is True
        and authorization.get("one_credential_read_allowed") is True
        and authorization.get("one_https_provider_call_allowed") is True
        and authorization.get("retry_allowed") is False
        and authorization.get("participant_container_start_allowed") is False
        and authorization.get("execution_stack_promotion_allowed") is False
        and authorization.get(
            "execution_authorization_issuance_or_consumption_allowed"
        )
        is False
        and plan.get("execution_boundary") == OFFLINE_BOUNDARY,
        "outcome_admission_authorization_boundary_invalid",
        failures,
    )
    return list(dict.fromkeys(failures))


def build_preflight(
    *,
    plan_path: str,
    plan_raw_sha256: str,
    plan: dict[str, Any],
    created_at: str,
) -> dict[str, Any]:
    statement = probe_authorization_statement(
        plan_raw_sha256=plan_raw_sha256,
        plan=plan,
    )
    preflight = {
        "schema_version": PREFLIGHT_SCHEMA,
        "passed": True,
        "failure_reasons": [],
        "state": (
            "outcome_sensitive_provider_admission_ready_"
            "owner_authorization_required"
        ),
        "admission_id": plan["admission_id"],
        "created_at": created_at,
        "plan": {
            "path": plan_path,
            "sha256": plan_raw_sha256,
            "canonical_sha256": plan["plan_sha256"],
        },
        "checks": {
            "outcome_sensitive_materials_and_evaluator_bound": True,
            "reviewed_roster_assignment_and_advice_bound": True,
            "reviewed_infrastructure_activation_bound": True,
            "exact_40_stopped_containers_revalidated": True,
            "provider_request_is_synthetic_and_bounded": True,
            "provider_budget_reserved_under_preserved_reviewed_rates": True,
            "credential_not_accessed": True,
            "network_and_model_not_invoked": True,
        },
        "inventory_snapshot": copy.deepcopy(plan["inventory_snapshot"]),
        "owner_authorization": {
            "required": True,
            "statement": statement,
            "statement_sha256": hashlib.sha256(statement.encode()).hexdigest(),
        },
        "readiness": copy.deepcopy(plan["readiness"]),
        "implementation": copy.deepcopy(plan["implementation"]),
        "execution_boundary": copy.deepcopy(OFFLINE_BOUNDARY),
    }
    preflight["preflight_sha256"] = canonical_sha256(preflight)
    return preflight


def probe_authorization_statement(
    *, plan_raw_sha256: str, plan: dict[str, Any]
) -> str:
    stack = plan["frozen_stack"]
    probe = plan["probe_contract"]
    ceiling = plan["pricing_and_budget"][
        "absolute_authorization_cost_ceiling_microunits"
    ]
    return (
        "I authorize exactly one bounded J1-D outcome-sensitive live-provider "
        f"admission probe from offline plan raw SHA-256 {plan_raw_sha256}, "
        f"canonical SHA-256 {plan['plan_sha256']}, binding infrastructure "
        f"activation {stack['activation_sha256']}, outcome-sensitive protocol "
        f"{stack['protocol_sha256']}, evaluator {stack['evaluator_sha256']}, and "
        f"preserved pricing design {stack['design_sha256']}. I authorize one read "
        "of a private mode-0600 provider environment file and exactly one HTTPS "
        f"POST to {stack['base_url']}{probe['path']} using provider "
        f"{stack['provider_id']}, model {stack['model_id']}, and frozen synthetic "
        f"request body SHA-256 {probe['request_body_sha256']}, with at most "
        f"{probe['max_input_tokens']} input tokens, "
        f"{probe['max_output_tokens']} output tokens, and an absolute cost ceiling "
        f"of {ceiling} USD microunits. The credential value and hash and response "
        "content must not be persisted; only response SHA-256 and sanitized usage "
        "may be recorded. The authorization is single-use, must be claimed before "
        "credential access, and permits no retry. It permits only this synthetic "
        "admission probe. It does not permit creating, starting, renaming, or "
        "removing any participant container, use of participant data, advice, "
        "fixtures, or tasks, Agent or experiment execution, execution-stack "
        "promotion, Backend Fact append, Ledger append, execution authorization "
        "issuance or consumption, an effectiveness claim, or an SI-13 maturity "
        "upgrade."
    )


def validate_probe_sources(
    *,
    plan: dict[str, Any],
    plan_raw_sha256: str,
    preflight: dict[str, Any],
    authorization_statement: str,
) -> list[str]:
    failures = validate_plan(plan)
    body = {
        key: item for key, item in preflight.items() if key != "preflight_sha256"
    }
    expected = probe_authorization_statement(
        plan_raw_sha256=plan_raw_sha256,
        plan=plan,
    )
    owner = _object(preflight.get("owner_authorization"))
    plan_ref = _object(preflight.get("plan"))
    readiness = _object(preflight.get("readiness"))
    _require(
        preflight.get("schema_version") == PREFLIGHT_SCHEMA
        and preflight.get("passed") is True
        and preflight.get("failure_reasons") == []
        and preflight.get("state")
        == "outcome_sensitive_provider_admission_ready_owner_authorization_required"
        and preflight.get("preflight_sha256") == canonical_sha256(body),
        "outcome_probe_preflight_invalid",
        failures,
    )
    _require(
        plan_ref.get("sha256") == plan_raw_sha256
        and plan_ref.get("canonical_sha256") == plan.get("plan_sha256"),
        "outcome_probe_plan_binding_invalid",
        failures,
    )
    _require(
        owner.get("required") is True
        and owner.get("statement") == expected
        and owner.get("statement_sha256")
        == hashlib.sha256(expected.encode()).hexdigest()
        and authorization_statement == expected,
        "outcome_probe_owner_authorization_mismatch",
        failures,
    )
    _require(
        readiness.get("offline_preflight_complete") is True
        and readiness.get("owner_probe_authorization_required") is True
        and readiness.get("live_provider_admission_refreshed") is False
        and readiness.get("controlled_experiment_execution_ready") is False,
        "outcome_probe_readiness_invalid",
        failures,
    )
    return list(dict.fromkeys(failures))


def _artifact_ref(value: Any) -> bool:
    ref = _object(value)
    return (
        set(ref) == {"path", "sha256", "canonical_sha256"}
        and str(ref.get("path", "")).startswith("/")
        and _sha256(ref.get("sha256"))
        and _sha256(ref.get("canonical_sha256"))
    )


def _ref_matches(value: Any, raw_sha256: str, canonical_sha256_value: str) -> bool:
    ref = _object(value)
    return (
        ref.get("sha256") == raw_sha256
        and ref.get("canonical_sha256") == canonical_sha256_value
    )


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
        int(value, 16)
    except ValueError:
        return False
    return True


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _require(condition: bool, code: str, failures: list[str]) -> None:
    if not condition and code not in failures:
        failures.append(code)
