"""Contracts for an offline J1-D live-provider admission refresh plan."""

from __future__ import annotations

import hashlib
import math
from typing import Any

from .controlled_comparison import canonical_sha256


PLAN_SCHEMA = "j1-qualification-provider-admission-refresh-plan:v1"
PREFLIGHT_SCHEMA = "j1-qualification-provider-admission-refresh-preflight:v1"
PROBE_PROMPT = "Reply with exactly ADMITTED."
PROBE_MAX_INPUT_TOKENS = 128
PROBE_MAX_OUTPUT_TOKENS = 8
OFFLINE_BOUNDARY = {
    "provider_admission_refresh_planning_only": True,
    "credential_file_accessed": False,
    "provider_api_call_performed": False,
    "model_invocation_performed": False,
    "participant_container_created": False,
    "participant_container_started": False,
    "participant_task_execution_performed": False,
    "agent_execution_performed": False,
    "backend_fact_append_performed": False,
    "ledger_append_performed": False,
    "execution_authorization_issued_or_consumed": False,
}


def validate_source_chain(
    *,
    protocol: dict[str, Any],
    design: dict[str, Any],
    bundle: dict[str, Any],
    roster: dict[str, Any],
    assignment: dict[str, Any],
    roster_assignment_gate: dict[str, Any],
    infrastructure: dict[str, Any],
    activation: dict[str, Any],
    activation_gate: dict[str, Any],
    runner_manifest: dict[str, Any],
    raw_sha256: dict[str, str],
) -> list[str]:
    failures: list[str] = []
    _require_self_hash(
        protocol,
        schema="j1-qualification-protocol-amendment:v1",
        field="amended_protocol_sha256",
        failure="refresh_protocol_invalid",
        failures=failures,
    )
    _require_self_hash(
        design,
        schema="j1-qualification-execution-design-amendment:v1",
        field="amended_design_sha256",
        failure="refresh_design_invalid",
        failures=failures,
    )
    _require_self_hash(
        bundle,
        schema="j1-qualification-protocol-design-amendment-bundle:v1",
        field="bundle_sha256",
        failure="refresh_amendment_bundle_invalid",
        failures=failures,
    )
    _require_self_hash(
        roster,
        schema="j1-qualification-roster-rebound:operator-reviewed:v1",
        field="reviewed_rebound_roster_sha256",
        failure="refresh_reviewed_roster_invalid",
        failures=failures,
        status="operator_reviewed",
    )
    _require_self_hash(
        assignment,
        schema="j1-qualification-cohort-assignment-rebound:operator-reviewed:v1",
        field="reviewed_rebound_assignment_sha256",
        failure="refresh_reviewed_assignment_invalid",
        failures=failures,
        status="operator_reviewed",
    )
    _require_self_hash(
        roster_assignment_gate,
        schema="j1-qualification-roster-assignment-rebind-review-gate:v1",
        field="report_sha256",
        failure="refresh_roster_assignment_gate_invalid",
        failures=failures,
    )
    _require_self_hash(
        infrastructure,
        schema="j1-qualification-infrastructure-rebind:operator-reviewed:v1",
        field="reviewed_infrastructure_rebind_sha256",
        failure="refresh_reviewed_infrastructure_invalid",
        failures=failures,
        status="operator_reviewed",
    )
    _require_self_hash(
        activation,
        schema="j1-qualification-infrastructure-activation:v1",
        field="activation_sha256",
        failure="refresh_activation_invalid",
        failures=failures,
    )
    _require_self_hash(
        activation_gate,
        schema="j1-qualification-infrastructure-activation-gate:v1",
        field="report_sha256",
        failure="refresh_activation_gate_invalid",
        failures=failures,
    )
    _require_self_hash(
        runner_manifest,
        schema="j1-qualification-participant-runner-image:v1",
        field="manifest_sha256",
        failure="refresh_runner_manifest_invalid",
        failures=failures,
    )

    protocol_sha = protocol.get("amended_protocol_sha256")
    design_sha = design.get("amended_design_sha256")
    bundle_sha = bundle.get("bundle_sha256")
    roster_sha = roster.get("reviewed_rebound_roster_sha256")
    assignment_sha = assignment.get("reviewed_rebound_assignment_sha256")
    infrastructure_sha = infrastructure.get("reviewed_infrastructure_rebind_sha256")
    activation_sha = activation.get("activation_sha256")
    runner_sha = runner_manifest.get("manifest_sha256")
    image_id = runner_manifest.get("image", {}).get("image_id")

    _require(
        bundle.get("protocol_amendment")
        == {
            "path": bundle.get("protocol_amendment", {}).get("path"),
            "sha256": raw_sha256.get("protocol"),
            "canonical_sha256": protocol_sha,
        }
        and bundle.get("design_amendment")
        == {
            "path": bundle.get("design_amendment", {}).get("path"),
            "sha256": raw_sha256.get("design"),
            "canonical_sha256": design_sha,
        },
        "refresh_amendment_bundle_binding_invalid",
        failures,
    )
    for name, value in (("roster", roster), ("assignment", assignment)):
        source = _object(value.get("source_binding"))
        _require(
            source.get("protocol_amendment_artifact_sha256")
            == raw_sha256.get("protocol")
            and source.get("protocol_amendment_sha256") == protocol_sha
            and source.get("design_amendment_artifact_sha256")
            == raw_sha256.get("design")
            and source.get("design_amendment_sha256") == design_sha
            and source.get("amendment_bundle_artifact_sha256")
            == raw_sha256.get("bundle")
            and source.get("amendment_bundle_sha256") == bundle_sha,
            f"refresh_{name}_amendment_binding_invalid",
            failures,
        )

    reviewed_artifacts = _object(roster_assignment_gate.get("reviewed_artifacts"))
    _require(
        roster_assignment_gate.get("passed") is True
        and roster_assignment_gate.get("failure_reasons") == []
        and roster_assignment_gate.get("state")
        == "roster_assignment_rebind_passed_infrastructure_rebind_required"
        and _artifact_matches(
            reviewed_artifacts.get("rebound_roster"),
            raw_sha256.get("roster"),
            roster_sha,
        )
        and _artifact_matches(
            reviewed_artifacts.get("rebound_assignment"),
            raw_sha256.get("assignment"),
            assignment_sha,
        ),
        "refresh_roster_assignment_promotion_invalid",
        failures,
    )

    infrastructure_source = _object(infrastructure.get("source_binding"))
    _require(
        infrastructure_source.get("reviewed_roster_artifact_sha256")
        == raw_sha256.get("roster")
        and infrastructure_source.get("reviewed_assignment_artifact_sha256")
        == raw_sha256.get("assignment")
        and infrastructure_source.get("roster_assignment_gate_artifact_sha256")
        == raw_sha256.get("roster_assignment_gate")
        and infrastructure_source.get("runner_manifest_artifact_sha256")
        == raw_sha256.get("runner_manifest")
        and infrastructure.get("runner_image", {}).get("manifest_sha256") == runner_sha
        and infrastructure.get("runner_image", {}).get("image_id") == image_id,
        "refresh_infrastructure_binding_invalid",
        failures,
    )

    activation_source = _object(activation.get("source_binding"))
    activation_ref = _object(activation_gate.get("activation"))
    _require(
        activation_source.get("reviewed_artifact_sha256")
        == raw_sha256.get("infrastructure")
        and activation_source.get("reviewed_infrastructure_sha256")
        == infrastructure_sha
        and activation_source.get("runner_manifest_sha256") == runner_sha
        and activation_source.get("image_id") == image_id
        and activation_gate.get("passed") is True
        and activation_gate.get("failure_reasons") == []
        and activation_gate.get("state")
        == "replacement_containers_created_provider_admission_required"
        and activation_gate.get("next_blocker")
        == "live_provider_admission_refresh_required"
        and _artifact_matches(
            activation_ref,
            raw_sha256.get("activation"),
            activation_sha,
        ),
        "refresh_activation_binding_invalid",
        failures,
    )

    roster_participants = roster.get("participants")
    assignments = assignment.get("assignments")
    isolations = infrastructure.get("isolations")
    containers = activation.get("containers")
    roster_participants = (
        roster_participants if isinstance(roster_participants, list) else []
    )
    assignments = assignments if isinstance(assignments, list) else []
    isolations = isolations if isinstance(isolations, list) else []
    containers = containers if isinstance(containers, list) else []
    participant_sets = [
        {str(item.get("participant_id")) for item in roster_participants},
        {
            str(member.get("participant_id"))
            for pair in assignments
            for member in (_object(pair).get("mentor"), _object(pair).get("control"))
            if isinstance(member, dict)
        },
        {str(item.get("participant_id")) for item in isolations},
        {str(item.get("participant_id")) for item in containers},
    ]
    inventory = activation.get("inventory")
    _require(
        len(roster_participants) == 40
        and len(assignments) == 20
        and len(isolations) == 40
        and len(containers) == 40
        and all(len(value) == 40 for value in participant_sets)
        and all(value == participant_sets[0] for value in participant_sets[1:])
        and inventory
        == {
            "participant_count": 40,
            "mentor_count": 20,
            "control_count": 20,
            "container_created_count": 40,
            "container_started_count": 0,
        },
        "refresh_participant_inventory_invalid",
        failures,
    )

    stack = _object(protocol.get("amended_frozen_stack"))
    provider = _object(design.get("preserved_provider_call"))
    budget = _object(protocol.get("amended_frozen_stack")).get("budget")
    reservation = _object(design.get("preserved_budget_reservation"))
    pricing = _object(design.get("preserved_pricing"))
    _require(
        stack.get("provider_id") == provider.get("provider_id")
        and stack.get("model_id") == provider.get("model_id")
        and stack.get("temperature") == provider.get("temperature") == 0
        and stack.get("same_stack_for_both_cohorts") is True
        and isinstance(budget, dict)
        and budget.get("max_tokens") == 20000
        and budget.get("max_cost_microunits") == 100000
        and reservation.get("within_signed_ceiling") is True
        and reservation.get("reservation_required_before_network_call") is True
        and pricing.get("billing_currency") == "USD"
        and pricing.get("cost_unit") == "usd_microunit"
        and pricing.get("rate_basis_tokens") == 1_000_000
        and pricing.get("price_drift_requires_new_reviewed_design") is True,
        "refresh_provider_budget_binding_invalid",
        failures,
    )
    return list(dict.fromkeys(failures))


def build_refresh_plan(
    *,
    refresh_id: str,
    created_at: str,
    source_binding: dict[str, Any],
    protocol: dict[str, Any],
    design: dict[str, Any],
    inventory_snapshot: dict[str, Any],
    implementation: dict[str, str],
) -> dict[str, Any]:
    provider = _object(design.get("preserved_provider_call"))
    pricing = _object(design.get("preserved_pricing"))
    rates = _object(pricing.get("rates_microunits"))
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
        "refresh_id": refresh_id,
        "created_at": created_at,
        "status": "owner_authorization_required",
        "source_binding": source_binding,
        "frozen_stack": {
            "provider_id": provider["provider_id"],
            "base_url": provider["base_url"],
            "model_id": provider["model_id"],
            "temperature": provider["temperature"],
            "protocol_sha256": protocol["amended_protocol_sha256"],
            "design_sha256": design["amended_design_sha256"],
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
            "pricing_basis": "operator_reviewed_execution_design",
            "input_charge_basis": "input_cache_miss",
            "maximum_cost_microunits": maximum_cost,
            "reservation_required_before_call": True,
            "actual_usage_reconciliation_required": True,
            "absolute_authorization_cost_ceiling_microunits": maximum_cost,
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
            "credential_presence_persisted": True,
            "access_allowed_only_after_exact_owner_authorization": True,
        },
        "inventory_snapshot": inventory_snapshot,
        "authorization_contract": {
            "exact_plan_raw_and_canonical_hashes_required": True,
            "single_use_required": True,
            "maximum_ttl_seconds": 1800,
            "one_credential_read_allowed": True,
            "one_https_provider_call_allowed": True,
            "participant_container_start_allowed": False,
            "experiment_execution_authorization_issued": False,
        },
        "implementation": implementation,
        "readiness": {
            "offline_preflight_complete": True,
            "owner_probe_authorization_required": True,
            "live_provider_admission_refreshed": False,
            "controlled_experiment_execution_ready": False,
        },
        "execution_boundary": OFFLINE_BOUNDARY,
        "non_claims": [
            "reviewed_pricing_was_not_independently_refreshed",
            "provider_credentials_were_not_accessed",
            "provider_or_model_availability_was_not_tested",
            "participant_containers_were_not_started",
            "controlled_experiment_execution_was_not_authorized",
        ],
    }
    plan["plan_sha256"] = canonical_sha256(plan)
    return plan


def validate_refresh_plan(plan: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    body = {key: item for key, item in plan.items() if key != "plan_sha256"}
    stack = _object(plan.get("frozen_stack"))
    probe = _object(plan.get("probe_contract"))
    budget = _object(plan.get("pricing_and_budget"))
    pricing = _object(budget.get("pricing"))
    rates = _object(pricing.get("rates_microunits"))
    authorization = _object(plan.get("authorization_contract"))
    request_body = {
        "model": stack.get("model_id"),
        "messages": [{"role": "user", "content": PROBE_PROMPT}],
        "temperature": 0,
        "max_tokens": PROBE_MAX_OUTPUT_TOKENS,
        "stream": False,
    }
    try:
        expected_cost = probe_maximum_cost_microunits(
            input_rate=int(rates["input_cache_miss"]),
            output_rate=int(rates["output"]),
            rate_basis_tokens=int(pricing["rate_basis_tokens"]),
        )
    except (KeyError, TypeError, ValueError, ZeroDivisionError):
        expected_cost = -1
    _require(
        plan.get("schema_version") == PLAN_SCHEMA
        and plan.get("status") == "owner_authorization_required"
        and plan.get("plan_sha256") == canonical_sha256(body),
        "refresh_plan_identity_invalid",
        failures,
    )
    _require(
        probe.get("call_count") == 1
        and probe.get("method") == "POST"
        and probe.get("path") == "/chat/completions"
        and probe.get("max_input_tokens") == PROBE_MAX_INPUT_TOKENS
        and probe.get("max_output_tokens") == PROBE_MAX_OUTPUT_TOKENS
        and probe.get("participant_data_allowed") is False
        and probe.get("request_body") == request_body
        and probe.get("request_body_sha256") == canonical_sha256(request_body)
        and probe.get("synthetic_prompt_sha256")
        == hashlib.sha256(PROBE_PROMPT.encode()).hexdigest(),
        "refresh_probe_contract_invalid",
        failures,
    )
    _require(
        expected_cost > 0
        and budget.get("maximum_cost_microunits") == expected_cost
        and budget.get("absolute_authorization_cost_ceiling_microunits")
        == expected_cost
        and budget.get("reservation_required_before_call") is True,
        "refresh_probe_budget_invalid",
        failures,
    )
    _require(
        authorization.get("single_use_required") is True
        and authorization.get("one_credential_read_allowed") is True
        and authorization.get("one_https_provider_call_allowed") is True
        and authorization.get("participant_container_start_allowed") is False
        and plan.get("execution_boundary") == OFFLINE_BOUNDARY,
        "refresh_authorization_boundary_invalid",
        failures,
    )
    return failures


def probe_authorization_statement(
    *,
    plan_raw_sha256: str,
    plan_canonical_sha256: str,
    provider_id: str,
    base_url: str,
    model_id: str,
    request_body_sha256: str,
    maximum_cost_microunits: int,
) -> str:
    return (
        "I authorize exactly one bounded J1-D live-provider admission probe from "
        f"offline plan artifact raw SHA-256 {plan_raw_sha256}, canonical SHA-256 "
        f"{plan_canonical_sha256}. I authorize one read of a private mode-0600 "
        "provider environment file and exactly one HTTPS POST to "
        f"{base_url}/chat/completions using provider {provider_id}, model "
        f"{model_id}, and frozen synthetic request body SHA-256 "
        f"{request_body_sha256}, with at most {PROBE_MAX_INPUT_TOKENS} input tokens, "
        f"{PROBE_MAX_OUTPUT_TOKENS} output tokens, and an absolute cost ceiling of "
        f"{maximum_cost_microunits} USD microunits under the operator-reviewed "
        "pricing bound in the plan. I acknowledge that the pricing was not "
        "independently refreshed by the offline preflight and any detected pricing "
        "drift requires a new reviewed execution design. The credential value and "
        "hash must not be persisted; response content must not be persisted, only "
        "its SHA-256 and sanitized provider usage may be recorded. This authorization "
        "permits only the synthetic admission probe. It does not permit starting, "
        "creating, or removing any participant container, use of participant data, "
        "advice, or tasks, Agent or experiment execution, Backend Fact append, "
        "Ledger append, or execution authorization issuance or consumption."
    )


def probe_maximum_cost_microunits(
    *, input_rate: int, output_rate: int, rate_basis_tokens: int
) -> int:
    numerator = (
        PROBE_MAX_INPUT_TOKENS * input_rate + PROBE_MAX_OUTPUT_TOKENS * output_rate
    )
    return math.ceil(numerator / rate_basis_tokens)


def _require_self_hash(
    value: dict[str, Any],
    *,
    schema: str,
    field: str,
    failure: str,
    failures: list[str],
    status: str | None = None,
) -> None:
    body = {key: item for key, item in value.items() if key != field}
    _require(
        value.get("schema_version") == schema
        and (status is None or value.get("status") == status)
        and value.get(field) == canonical_sha256(body),
        failure,
        failures,
    )


def _artifact_matches(value: Any, raw_sha256: Any, canonical_sha256_value: Any) -> bool:
    artifact = _object(value)
    return (
        artifact.get("sha256") == raw_sha256
        and artifact.get("canonical_sha256") == canonical_sha256_value
    )


def _object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _require(condition: bool, code: str, failures: list[str]) -> None:
    if not condition and code not in failures:
        failures.append(code)
