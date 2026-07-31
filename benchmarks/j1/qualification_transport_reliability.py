"""Contracts for J1-D transport qualification and bounded admission soak."""

from __future__ import annotations

from typing import Any

from .controlled_comparison import canonical_sha256
from .qualification_http_transport import HTTPSPostPolicy


CONTRACT_SCHEMA = "j1-qualification-transport-reliability-contract:v1"
FAULT_MATRIX_SCHEMA = "j1-qualification-transport-fault-matrix:v1"
SOAK_PLAN_SCHEMA = "j1-qualification-transport-admission-soak-plan:v1"
SOAK_PREFLIGHT_SCHEMA = "j1-qualification-transport-admission-soak-preflight:v1"
SOAK_CALL_COUNT = 64
MAX_INPUT_TOKENS = 128
MAX_OUTPUT_TOKENS = 1000
PER_CALL_MAX_MICROUNITS = 926
FAULT_SCENARIOS = (
    "tcp_connect_transient_then_success",
    "tcp_connect_exhausted_before_dispatch",
    "tls_handshake_exhausted_before_dispatch",
    "request_write_failure_after_dispatch_start",
    "response_header_timeout_after_dispatch",
    "response_body_timeout_after_dispatch",
    "response_size_ceiling_after_dispatch",
    "single_use_transport_replay_rejected",
)


def build_transport_contract(
    *,
    contract_id: str,
    created_at: str,
    source_binding: dict[str, Any],
    implementation: dict[str, str],
) -> dict[str, Any]:
    contract = {
        "schema_version": CONTRACT_SCHEMA,
        "contract_id": contract_id,
        "created_at": created_at,
        "source_binding": source_binding,
        "transport_policy": HTTPSPostPolicy().as_dict(),
        "phase_boundary": {
            "pre_dispatch": [
                "dns_resolution",
                "tcp_connect",
                "tls_handshake",
            ],
            "dispatch_starts_before": "http_request_write",
            "post_dispatch": [
                "http_request_write",
                "response_headers",
                "response_body",
            ],
        },
        "failure_policy": {
            "pre_dispatch_connect_or_tls_failure": (
                "bounded_connection_setup_retry_then_task_failed_before_dispatch"
            ),
            "post_dispatch_failure": (
                "provider_outcome_unknown_no_retry_signed_closeout"
            ),
            "http_status_or_response_contract_failure": (
                "terminal_no_retry_signed_closeout"
            ),
            "exception_message_persisted": False,
            "response_content_persisted": False,
            "credential_value_or_hash_persisted": False,
        },
        "qualification_scope": {
            "fault_scenario_count": len(FAULT_SCENARIOS),
            "fault_scenarios": list(FAULT_SCENARIOS),
            "live_soak_call_count": SOAK_CALL_COUNT,
            "participant_data_allowed": False,
            "participant_container_start_allowed": False,
        },
        "implementation": implementation,
        "execution_boundary": {
            "offline_contract_only": True,
            "provider_credential_read": False,
            "provider_or_model_call_performed": False,
            "participant_container_started": False,
            "backend_fact_append_performed": False,
            "ledger_append_performed": False,
            "execution_authorization_issued_or_consumed": False,
        },
    }
    contract["contract_sha256"] = canonical_sha256(contract)
    return contract


def validate_transport_contract(value: Any) -> list[str]:
    contract = value if isinstance(value, dict) else {}
    failures: list[str] = []
    _require(
        contract.get("schema_version") == CONTRACT_SCHEMA,
        "transport_contract_schema_invalid",
        failures,
    )
    _require(_text(contract.get("contract_id")), "transport_contract_id_invalid", failures)
    _require(_text(contract.get("created_at")), "transport_contract_time_invalid", failures)
    source = contract.get("source_binding")
    _require(
        isinstance(source, dict)
        and set(source) == {"r2_terminal_gate", "r3_terminal_gate"}
        and all(_reference(item) for item in source.values()),
        "transport_contract_source_binding_invalid",
        failures,
    )
    _require(
        contract.get("transport_policy") == HTTPSPostPolicy().as_dict(),
        "transport_contract_policy_invalid",
        failures,
    )
    phase = contract.get("phase_boundary")
    _require(
        phase
        == {
            "pre_dispatch": ["dns_resolution", "tcp_connect", "tls_handshake"],
            "dispatch_starts_before": "http_request_write",
            "post_dispatch": [
                "http_request_write",
                "response_headers",
                "response_body",
            ],
        },
        "transport_contract_phase_boundary_invalid",
        failures,
    )
    policy = contract.get("failure_policy")
    _require(
        isinstance(policy, dict)
        and policy.get("pre_dispatch_connect_or_tls_failure")
        == "bounded_connection_setup_retry_then_task_failed_before_dispatch"
        and policy.get("post_dispatch_failure")
        == "provider_outcome_unknown_no_retry_signed_closeout"
        and policy.get("http_status_or_response_contract_failure")
        == "terminal_no_retry_signed_closeout"
        and policy.get("exception_message_persisted") is False
        and policy.get("response_content_persisted") is False
        and policy.get("credential_value_or_hash_persisted") is False,
        "transport_contract_failure_policy_invalid",
        failures,
    )
    scope = contract.get("qualification_scope")
    _require(
        scope
        == {
            "fault_scenario_count": len(FAULT_SCENARIOS),
            "fault_scenarios": list(FAULT_SCENARIOS),
            "live_soak_call_count": SOAK_CALL_COUNT,
            "participant_data_allowed": False,
            "participant_container_start_allowed": False,
        },
        "transport_contract_scope_invalid",
        failures,
    )
    _require(
        _implementation(contract.get("implementation")),
        "transport_contract_implementation_invalid",
        failures,
    )
    _require(
        contract.get("execution_boundary")
        == {
            "offline_contract_only": True,
            "provider_credential_read": False,
            "provider_or_model_call_performed": False,
            "participant_container_started": False,
            "backend_fact_append_performed": False,
            "ledger_append_performed": False,
            "execution_authorization_issued_or_consumed": False,
        },
        "transport_contract_execution_boundary_invalid",
        failures,
    )
    body = {key: item for key, item in contract.items() if key != "contract_sha256"}
    _require(
        contract.get("contract_sha256") == canonical_sha256(body),
        "transport_contract_hash_invalid",
        failures,
    )
    return failures


def build_fault_matrix_report(
    *,
    checked_at: str,
    contract_ref: dict[str, str],
    scenarios: list[dict[str, Any]],
    implementation: dict[str, str],
) -> dict[str, Any]:
    report = {
        "schema_version": FAULT_MATRIX_SCHEMA,
        "checked_at": checked_at,
        "contract": contract_ref,
        "scenarios": scenarios,
        "summary": {
            "scenario_count": len(scenarios),
            "passed_count": sum(item.get("passed") is True for item in scenarios),
            "http_request_count": sum(
                int(item.get("observed_http_request_count", 0)) for item in scenarios
            ),
            "post_dispatch_retry_count": sum(
                int(item.get("observed_post_dispatch_retry_count", 0))
                for item in scenarios
            ),
        },
        "implementation": implementation,
        "execution_boundary": {
            "deterministic_offline_fault_injection_only": True,
            "provider_credential_read": False,
            "provider_or_model_call_performed": False,
            "participant_container_started": False,
            "backend_fact_append_performed": False,
            "ledger_append_performed": False,
        },
    }
    report["report_sha256"] = canonical_sha256(report)
    return report


def validate_fault_matrix_report(value: Any) -> list[str]:
    report = value if isinstance(value, dict) else {}
    failures: list[str] = []
    _require(
        report.get("schema_version") == FAULT_MATRIX_SCHEMA,
        "transport_fault_matrix_schema_invalid",
        failures,
    )
    _require(_text(report.get("checked_at")), "transport_fault_matrix_time_invalid", failures)
    _require(
        _reference(report.get("contract")),
        "transport_fault_matrix_contract_invalid",
        failures,
    )
    scenarios = report.get("scenarios")
    _require(
        isinstance(scenarios, list)
        and [item.get("scenario") for item in scenarios] == list(FAULT_SCENARIOS)
        and all(
            set(item)
            == {
                "scenario",
                "expected",
                "observed",
                "observed_connect_attempt_count",
                "observed_http_request_count",
                "observed_post_dispatch_retry_count",
                "passed",
            }
            and item["passed"] is True
            and type(item["observed_connect_attempt_count"]) is int
            and type(item["observed_http_request_count"]) is int
            and item["observed_post_dispatch_retry_count"] == 0
            for item in scenarios
        ),
        "transport_fault_matrix_scenarios_invalid",
        failures,
    )
    summary = report.get("summary")
    _require(
        isinstance(summary, dict)
        and summary.get("scenario_count") == len(FAULT_SCENARIOS)
        and summary.get("passed_count") == len(FAULT_SCENARIOS)
        and summary.get("post_dispatch_retry_count") == 0,
        "transport_fault_matrix_summary_invalid",
        failures,
    )
    _require(
        _implementation(report.get("implementation")),
        "transport_fault_matrix_implementation_invalid",
        failures,
    )
    boundary = report.get("execution_boundary")
    _require(
        isinstance(boundary, dict)
        and boundary.get("deterministic_offline_fault_injection_only") is True
        and all(
            boundary.get(name) is False
            for name in (
                "provider_credential_read",
                "provider_or_model_call_performed",
                "participant_container_started",
                "backend_fact_append_performed",
                "ledger_append_performed",
            )
        ),
        "transport_fault_matrix_boundary_invalid",
        failures,
    )
    body = {key: item for key, item in report.items() if key != "report_sha256"}
    _require(
        report.get("report_sha256") == canonical_sha256(body),
        "transport_fault_matrix_hash_invalid",
        failures,
    )
    return failures


def synthetic_probe_body(*, model: str, ordinal: int) -> dict[str, Any]:
    if not _text(model) or not 1 <= ordinal <= SOAK_CALL_COUNT:
        raise ValueError("transport soak synthetic request identity invalid")
    return {
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": (
                    "Return exactly one JSON object with key status and value ok. "
                    "Do not include any other fields."
                ),
            },
            {
                "role": "user",
                "content": f"Content-free transport qualification probe {ordinal}.",
            },
        ],
        "temperature": 0,
        "max_tokens": MAX_OUTPUT_TOKENS,
        "thinking": {"type": "disabled"},
        "response_format": {"type": "json_object"},
        "stream": False,
    }


def build_soak_plan(
    *,
    plan_id: str,
    created_at: str,
    contract_ref: dict[str, str],
    fault_matrix_ref: dict[str, str],
    provider_design_ref: dict[str, str],
    provider: dict[str, Any],
    implementation: dict[str, str],
) -> dict[str, Any]:
    model = provider["model"]
    request_hashes = [
        canonical_sha256(synthetic_probe_body(model=model, ordinal=ordinal))
        for ordinal in range(1, SOAK_CALL_COUNT + 1)
    ]
    plan = {
        "schema_version": SOAK_PLAN_SCHEMA,
        "plan_id": plan_id,
        "created_at": created_at,
        "source_binding": {
            "transport_contract": contract_ref,
            "fault_matrix": fault_matrix_ref,
            "provider_design": provider_design_ref,
        },
        "provider": provider,
        "synthetic_requests": {
            "call_count": SOAK_CALL_COUNT,
            "request_body_canonical_sha256": request_hashes,
            "max_input_tokens_per_call": MAX_INPUT_TOKENS,
            "max_output_tokens_per_call": MAX_OUTPUT_TOKENS,
            "participant_data_present": False,
            "advice_or_fixture_data_present": False,
        },
        "execution_policy": {
            "sequential_calls_only": True,
            "stop_after_first_failure": True,
            "connect_attempts_per_call": HTTPSPostPolicy().connect_attempts,
            "http_request_attempts_per_call": 1,
            "ambiguous_dispatch_retry_count": 0,
            "credential_file_read_count": 1,
            "absolute_duration_seconds": 1800,
        },
        "budget": {
            "per_call_reserved_tokens": MAX_INPUT_TOKENS + MAX_OUTPUT_TOKENS,
            "aggregate_reserved_tokens": (
                SOAK_CALL_COUNT * (MAX_INPUT_TOKENS + MAX_OUTPUT_TOKENS)
            ),
            "per_call_max_microunits": PER_CALL_MAX_MICROUNITS,
            "aggregate_max_microunits": (
                SOAK_CALL_COUNT * PER_CALL_MAX_MICROUNITS
            ),
        },
        "admission_gate": {
            "required_completed_call_count": SOAK_CALL_COUNT,
            "required_http_200_count": SOAK_CALL_COUNT,
            "provider_outcome_unknown_allowed": 0,
            "post_dispatch_retry_allowed": 0,
            "response_content_persisted": False,
            "credential_value_or_hash_persisted": False,
            "pre_dispatch_connect_attempt_histogram_required": True,
            "sanitized_failure_stage_required_on_failure": True,
        },
        "implementation": implementation,
        "authorization_boundary": {
            "independent_review_required": True,
            "single_use_live_soak_authorization_required": True,
            "credential_access_authorized": False,
            "provider_or_model_call_authorized": False,
            "participant_container_start_authorized": False,
            "experiment_execution_authorized": False,
            "backend_fact_append_authorized": False,
            "ledger_append_authorized": False,
        },
    }
    plan["plan_sha256"] = canonical_sha256(plan)
    return plan


def validate_soak_plan(value: Any) -> list[str]:
    plan = value if isinstance(value, dict) else {}
    failures: list[str] = []
    _require(
        plan.get("schema_version") == SOAK_PLAN_SCHEMA,
        "transport_soak_plan_schema_invalid",
        failures,
    )
    _require(_text(plan.get("plan_id")), "transport_soak_plan_id_invalid", failures)
    source = plan.get("source_binding")
    _require(
        isinstance(source, dict)
        and set(source)
        == {"transport_contract", "fault_matrix", "provider_design"}
        and all(_reference(item) for item in source.values()),
        "transport_soak_plan_source_invalid",
        failures,
    )
    provider = plan.get("provider")
    _require(
        isinstance(provider, dict)
        and set(provider) == {"provider_id", "base_url", "endpoint", "model"}
        and provider.get("provider_id") == "openai_compatible"
        and str(provider.get("base_url", "")).startswith("https://")
        and provider.get("endpoint") == "/chat/completions"
        and _text(provider.get("model")),
        "transport_soak_plan_provider_invalid",
        failures,
    )
    requests = plan.get("synthetic_requests")
    expected_hashes = (
        [
            canonical_sha256(
                synthetic_probe_body(model=provider["model"], ordinal=ordinal)
            )
            for ordinal in range(1, SOAK_CALL_COUNT + 1)
        ]
        if isinstance(provider, dict) and _text(provider.get("model"))
        else []
    )
    _require(
        isinstance(requests, dict)
        and requests.get("call_count") == SOAK_CALL_COUNT
        and requests.get("request_body_canonical_sha256") == expected_hashes
        and requests.get("max_input_tokens_per_call") == MAX_INPUT_TOKENS
        and requests.get("max_output_tokens_per_call") == MAX_OUTPUT_TOKENS
        and requests.get("participant_data_present") is False
        and requests.get("advice_or_fixture_data_present") is False,
        "transport_soak_plan_requests_invalid",
        failures,
    )
    _require(
        plan.get("execution_policy")
        == {
            "sequential_calls_only": True,
            "stop_after_first_failure": True,
            "connect_attempts_per_call": HTTPSPostPolicy().connect_attempts,
            "http_request_attempts_per_call": 1,
            "ambiguous_dispatch_retry_count": 0,
            "credential_file_read_count": 1,
            "absolute_duration_seconds": 1800,
        },
        "transport_soak_plan_execution_policy_invalid",
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
        "transport_soak_plan_budget_invalid",
        failures,
    )
    gate = plan.get("admission_gate")
    _require(
        isinstance(gate, dict)
        and gate.get("required_completed_call_count") == SOAK_CALL_COUNT
        and gate.get("required_http_200_count") == SOAK_CALL_COUNT
        and gate.get("provider_outcome_unknown_allowed") == 0
        and gate.get("post_dispatch_retry_allowed") == 0
        and gate.get("response_content_persisted") is False
        and gate.get("credential_value_or_hash_persisted") is False
        and gate.get("pre_dispatch_connect_attempt_histogram_required") is True
        and gate.get("sanitized_failure_stage_required_on_failure") is True,
        "transport_soak_plan_admission_gate_invalid",
        failures,
    )
    _require(
        _implementation(plan.get("implementation")),
        "transport_soak_plan_implementation_invalid",
        failures,
    )
    boundary = plan.get("authorization_boundary")
    _require(
        isinstance(boundary, dict)
        and boundary.get("independent_review_required") is True
        and boundary.get("single_use_live_soak_authorization_required") is True
        and all(
            boundary.get(name) is False
            for name in (
                "credential_access_authorized",
                "provider_or_model_call_authorized",
                "participant_container_start_authorized",
                "experiment_execution_authorized",
                "backend_fact_append_authorized",
                "ledger_append_authorized",
            )
        ),
        "transport_soak_plan_authorization_boundary_invalid",
        failures,
    )
    body = {key: item for key, item in plan.items() if key != "plan_sha256"}
    _require(
        plan.get("plan_sha256") == canonical_sha256(body),
        "transport_soak_plan_hash_invalid",
        failures,
    )
    return failures


def build_soak_preflight(
    *,
    checked_at: str,
    plan_ref: dict[str, str],
    plan: dict[str, Any],
    validation_failures: list[str],
) -> dict[str, Any]:
    passed = not validation_failures
    preflight = {
        "schema_version": SOAK_PREFLIGHT_SCHEMA,
        "checked_at": checked_at,
        "plan": plan_ref,
        "validation_failures": validation_failures,
        "passed": passed,
        "state": (
            "transport_soak_materials_ready_independent_review_required"
            if passed
            else "transport_soak_materials_invalid"
        ),
        "readiness": {
            "independent_review_allowed": passed,
            "live_soak_authorization_issuance_allowed": False,
            "provider_credential_access_allowed": False,
            "provider_or_model_call_allowed": False,
            "experiment_execution_allowed": False,
        },
        "scope": {
            "call_count": plan.get("synthetic_requests", {}).get("call_count"),
            "aggregate_reserved_tokens": plan.get("budget", {}).get(
                "aggregate_reserved_tokens"
            ),
            "aggregate_max_microunits": plan.get("budget", {}).get(
                "aggregate_max_microunits"
            ),
        },
    }
    preflight["preflight_sha256"] = canonical_sha256(preflight)
    return preflight


def _reference(value: Any) -> bool:
    return (
        isinstance(value, dict)
        and set(value) == {"path", "sha256", "canonical_sha256"}
        and _text(value.get("path"))
        and _sha256(value.get("sha256"))
        and _sha256(value.get("canonical_sha256"))
    )


def _implementation(value: Any) -> bool:
    return (
        isinstance(value, dict)
        and set(value)
        == {
            "source_revision",
            "domain_source_sha256",
            "operation_source_sha256",
            "transport_source_sha256",
        }
        and _git_revision(value.get("source_revision"))
        and all(
            _sha256(value.get(name))
            for name in (
                "domain_source_sha256",
                "operation_source_sha256",
                "transport_source_sha256",
            )
        )
    )


def _sha256(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        bytes.fromhex(value)
        return True
    except ValueError:
        return False


def _git_revision(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 40:
        return False
    try:
        bytes.fromhex(value)
        return True
    except ValueError:
        return False


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _require(condition: bool, code: str, failures: list[str]) -> None:
    if not condition and code not in failures:
        failures.append(code)
