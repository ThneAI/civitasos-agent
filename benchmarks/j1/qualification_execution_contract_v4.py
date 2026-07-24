"""Reviewable execution contract for the J1-D r4 qualification run."""

from __future__ import annotations

import copy
from datetime import datetime
from typing import Any

from .controlled_comparison import canonical_sha256


CONTRACT_SCHEMA = "j1-qualification-r4-execution-contract:v1"
SOURCE_NAMES = {
    "amended_protocol",
    "amended_design",
    "reviewed_verifier",
    "rebound_roster",
    "rebound_assignment",
    "signed_advice_manifest",
    "signed_advice_gate",
    "reviewed_infrastructure",
    "infrastructure_promotion_gate",
    "infrastructure_activation",
    "infrastructure_activation_gate",
    "frozen_real_evaluator",
    "frozen_post_run_contract",
    "frozen_operator_closeout_contract",
    "frozen_evaluation_closeout_bundle",
    "evaluation_closeout_promotion_gate",
}
EXECUTION_BOUNDARY = {
    "contract_generation_only": True,
    "execution_authorization_issued_or_consumed": False,
    "participant_container_started": False,
    "provider_credential_read": False,
    "provider_api_call_performed": False,
    "model_invocation_performed": False,
    "agent_execution_performed": False,
    "participant_signature_performed": False,
    "backend_fact_append_performed": False,
    "ledger_append_performed": False,
    "effectiveness_claim_authorized": False,
}
TASK_STATES = [
    "planned",
    "input_staged",
    "container_started",
    "request_prepared",
    "budget_reserved",
    "dispatch_intent_committed",
    "provider_response_committed",
    "budget_reconciled",
    "response_staged",
    "decision_finalized",
    "decision_signed",
    "event_trace_verified",
    "task_committed",
    "task_failed_before_dispatch",
    "provider_outcome_unknown",
    "task_failed_after_response",
    "task_aborted_before_dispatch",
]
TASK_TERMINAL_STATES = [
    "task_committed",
    "task_failed_before_dispatch",
    "provider_outcome_unknown",
    "task_failed_after_response",
    "task_aborted_before_dispatch",
]
ALLOWED_TRANSITIONS = [
    ["planned", "input_staged"],
    ["input_staged", "container_started"],
    ["container_started", "request_prepared"],
    ["request_prepared", "budget_reserved"],
    ["budget_reserved", "dispatch_intent_committed"],
    ["dispatch_intent_committed", "provider_response_committed"],
    ["provider_response_committed", "budget_reconciled"],
    ["budget_reconciled", "response_staged"],
    ["response_staged", "decision_finalized"],
    ["decision_finalized", "decision_signed"],
    ["decision_signed", "event_trace_verified"],
    ["event_trace_verified", "task_committed"],
]


def build_execution_contract(
    *,
    contract_id: str,
    created_at: str,
    source_artifacts: dict[str, dict[str, str]],
    amended_design: dict[str, Any],
    rebound_roster: dict[str, Any],
    rebound_assignment: dict[str, Any],
    signed_advice_manifest: dict[str, Any],
    infrastructure_activation: dict[str, Any],
    implementation: dict[str, str],
) -> dict[str, Any]:
    """Build the immutable r4 execution contract without performing execution."""
    tasks = _task_index(amended_design)
    roster = _roster_index(rebound_roster)
    advice = _advice_index(signed_advice_manifest)
    containers = _container_index(infrastructure_activation)
    executions = _task_executions(
        assignments=rebound_assignment.get("assignments", []),
        tasks=tasks,
        roster=roster,
        advice=advice,
        containers=containers,
        amended_design=amended_design,
    )
    value = {
        "schema_version": CONTRACT_SCHEMA,
        "contract_id": contract_id,
        "status": "independent_review_required",
        "created_at": created_at,
        "source_artifacts": copy.deepcopy(source_artifacts),
        "scope": {
            "participant_count": 40,
            "mentor_participant_count": 20,
            "control_participant_count": 20,
            "matched_pair_count": 20,
            "task_count_per_participant": 8,
            "task_execution_count": 320,
            "provider_call_count": 320,
            "provider_id": "openai_compatible",
            "model_id": "deepseek-v4-pro",
            "temperature": 0,
            "aggregate_reserved_tokens": 800000,
            "aggregate_reserved_cost_microunits": 487360,
            "aggregate_protocol_max_cost_microunits": 4000000,
        },
        "task_executions": executions,
        "state_machine": _state_machine(),
        "journal_contract": _journal_contract(),
        "budget_contract": _budget_contract(),
        "participant_signature_contract": _signature_contract(),
        "isolation_contract": _isolation_contract(),
        "recovery_contract": _recovery_contract(),
        "run_terminal_contract": _run_terminal_contract(),
        "fault_matrix_requirements": _fault_matrix_requirements(),
        "implementation": copy.deepcopy(implementation),
        "execution_boundary": copy.deepcopy(EXECUTION_BOUNDARY),
    }
    value["contract_sha256"] = canonical_sha256(value)
    failures = validate_execution_contract(
        value,
        amended_design=amended_design,
        rebound_roster=rebound_roster,
        rebound_assignment=rebound_assignment,
        signed_advice_manifest=signed_advice_manifest,
        infrastructure_activation=infrastructure_activation,
        expected_source_artifacts=source_artifacts,
        expected_implementation=implementation,
    )
    if failures:
        raise ValueError(f"r4 execution contract invalid: {failures}")
    return value


def validate_execution_contract(
    value: Any,
    *,
    amended_design: dict[str, Any],
    rebound_roster: dict[str, Any],
    rebound_assignment: dict[str, Any],
    signed_advice_manifest: dict[str, Any],
    infrastructure_activation: dict[str, Any],
    expected_source_artifacts: dict[str, dict[str, str]],
    expected_implementation: dict[str, str],
) -> list[str]:
    contract = value if isinstance(value, dict) else {}
    failures: list[str] = []
    expected_fields = {
        "schema_version",
        "contract_id",
        "status",
        "created_at",
        "source_artifacts",
        "scope",
        "task_executions",
        "state_machine",
        "journal_contract",
        "budget_contract",
        "participant_signature_contract",
        "isolation_contract",
        "recovery_contract",
        "run_terminal_contract",
        "fault_matrix_requirements",
        "implementation",
        "execution_boundary",
        "contract_sha256",
    }
    _require(set(contract) == expected_fields, "r4_contract_fields_invalid", failures)
    _require(
        contract.get("schema_version") == CONTRACT_SCHEMA
        and contract.get("status") == "independent_review_required"
        and _text(contract.get("contract_id"))
        and _rfc3339(contract.get("created_at")),
        "r4_contract_identity_invalid",
        failures,
    )
    _require(
        contract.get("source_artifacts") == expected_source_artifacts
        and set(expected_source_artifacts) == SOURCE_NAMES
        and all(_artifact_ref(item) for item in expected_source_artifacts.values()),
        "r4_contract_sources_invalid",
        failures,
    )
    _require(
        contract.get("scope") == _expected_scope(amended_design),
        "r4_contract_scope_invalid",
        failures,
    )
    expected_executions = _task_executions(
        assignments=rebound_assignment.get("assignments", []),
        tasks=_task_index(amended_design),
        roster=_roster_index(rebound_roster),
        advice=_advice_index(signed_advice_manifest),
        containers=_container_index(infrastructure_activation),
        amended_design=amended_design,
    )
    _require(
        contract.get("task_executions") == expected_executions,
        "r4_contract_task_manifest_invalid",
        failures,
    )
    _require(
        len(expected_executions) == 320
        and len({item["task_execution_id"] for item in expected_executions}) == 320
        and len({item["call_id"] for item in expected_executions}) == 320,
        "r4_contract_exactly_once_identity_invalid",
        failures,
    )
    _require(
        contract.get("state_machine") == _state_machine(),
        "r4_contract_state_machine_invalid",
        failures,
    )
    _require(
        contract.get("journal_contract") == _journal_contract(),
        "r4_contract_journal_invalid",
        failures,
    )
    _require(
        contract.get("budget_contract") == _budget_contract(),
        "r4_contract_budget_invalid",
        failures,
    )
    _require(
        contract.get("participant_signature_contract") == _signature_contract(),
        "r4_contract_signature_invalid",
        failures,
    )
    _require(
        contract.get("isolation_contract") == _isolation_contract(),
        "r4_contract_isolation_invalid",
        failures,
    )
    _require(
        contract.get("recovery_contract") == _recovery_contract(),
        "r4_contract_recovery_invalid",
        failures,
    )
    _require(
        contract.get("run_terminal_contract") == _run_terminal_contract(),
        "r4_contract_terminal_invalid",
        failures,
    )
    _require(
        contract.get("fault_matrix_requirements") == _fault_matrix_requirements(),
        "r4_contract_fault_matrix_invalid",
        failures,
    )
    _require(
        contract.get("implementation") == expected_implementation
        and set(expected_implementation)
        == {"source_revision", "domain_source_sha256", "operation_source_sha256"}
        and _revision(expected_implementation.get("source_revision"))
        and _sha256(expected_implementation.get("domain_source_sha256"))
        and _sha256(expected_implementation.get("operation_source_sha256")),
        "r4_contract_implementation_invalid",
        failures,
    )
    _require(
        contract.get("execution_boundary") == EXECUTION_BOUNDARY,
        "r4_contract_boundary_invalid",
        failures,
    )
    body = {key: item for key, item in contract.items() if key != "contract_sha256"}
    _require(
        contract.get("contract_sha256") == canonical_sha256(body),
        "r4_contract_hash_invalid",
        failures,
    )
    return list(dict.fromkeys(failures))


def _task_executions(
    *,
    assignments: list[Any],
    tasks: dict[str, dict[str, Any]],
    roster: dict[str, dict[str, Any]],
    advice: dict[tuple[str, str], dict[str, Any]],
    containers: dict[str, dict[str, Any]],
    amended_design: dict[str, Any],
) -> list[dict[str, Any]]:
    provider = amended_design.get("preserved_provider_call", {})
    budget = amended_design.get("preserved_budget_reservation", {})
    values: list[dict[str, Any]] = []
    for pair in sorted(assignments, key=lambda item: item.get("pair_id", "")):
        for cohort in ("mentor", "control"):
            assigned = pair.get(cohort, {})
            participant_id = assigned.get("participant_id")
            roster_entry = roster.get(str(participant_id), {})
            activation = containers.get(str(participant_id), {})
            for task_id, task in sorted(tasks.items()):
                seed = {
                    "pair_id": pair.get("pair_id"),
                    "cohort": cohort,
                    "participant_id": participant_id,
                    "execution_did": assigned.get("execution_did"),
                    "task_id": task_id,
                    "task_input_sha256": task.get("task_input_sha256"),
                }
                commitment = canonical_sha256(seed)
                signed_advice = advice.get((str(participant_id), task_id))
                cohort_contract = task.get(cohort, {})
                values.append(
                    {
                        "ordinal": len(values) + 1,
                        "task_execution_id": f"j1q-r4-task-{commitment[:24]}",
                        "call_id": f"j1q-r4-call-{commitment[24:48]}",
                        "pair_id": pair.get("pair_id"),
                        "cohort": cohort,
                        "participant_id": participant_id,
                        "execution_did": assigned.get("execution_did"),
                        "credential_version": roster_entry.get("credential_version"),
                        "task": {
                            "task_id": task_id,
                            "task_input_sha256": task.get("task_input_sha256"),
                            "verifier_case": task.get("verifier_case"),
                            "event_script": copy.deepcopy(
                                cohort_contract.get("event_script")
                            ),
                        },
                        "advice": (
                            {
                                "mode": "mentor_signed",
                                "advice_id": signed_advice.get("advice_id"),
                                "sha256": signed_advice.get("sha256"),
                                "canonical_sha256": signed_advice.get(
                                    "canonical_sha256"
                                ),
                            }
                            if cohort == "mentor" and signed_advice
                            else {"mode": "control_empty", "signed_advice": None}
                        ),
                        "container": {
                            "container_id": activation.get("container", {}).get(
                                "container_id"
                            ),
                            "container_name": activation.get("container", {}).get(
                                "container_name"
                            ),
                            "image_id": activation.get("container", {}).get("image_id"),
                            "network_mode": activation.get("container", {})
                            .get("runtime_boundary", {})
                            .get("network_mode"),
                        },
                        "provider": {
                            "provider_id": provider.get("provider_id"),
                            "model_id": provider.get("model_id"),
                            "temperature": provider.get("temperature"),
                            "max_input_utf8_bytes": provider.get(
                                "max_input_utf8_bytes"
                            ),
                            "max_output_tokens": provider.get("max_output_tokens"),
                        },
                        "reservation": {
                            "tokens": provider.get("reserved_total_tokens_per_call"),
                            "cost_microunits": budget.get("per_call_max_microunits"),
                        },
                        "commitment_sha256": commitment,
                    }
                )
    return values


def _expected_scope(design: dict[str, Any]) -> dict[str, Any]:
    provider = design.get("preserved_provider_call", {})
    budget = design.get("preserved_budget_reservation", {})
    return {
        "participant_count": 40,
        "mentor_participant_count": 20,
        "control_participant_count": 20,
        "matched_pair_count": 20,
        "task_count_per_participant": 8,
        "task_execution_count": 320,
        "provider_call_count": 320,
        "provider_id": provider.get("provider_id"),
        "model_id": provider.get("model_id"),
        "temperature": provider.get("temperature"),
        "aggregate_reserved_tokens": budget.get("aggregate_reserved_tokens"),
        "aggregate_reserved_cost_microunits": budget.get(
            "aggregate_reserved_microunits"
        ),
        "aggregate_protocol_max_cost_microunits": 4000000,
    }


def _state_machine() -> dict[str, Any]:
    return {
        "initial_state": "planned",
        "states": TASK_STATES,
        "terminal_states": TASK_TERMINAL_STATES,
        "success_state": "task_committed",
        "allowed_progress_transitions": ALLOWED_TRANSITIONS,
        "failure_transition_rules": {
            "before_dispatch_intent": [
                "task_failed_before_dispatch",
                "task_aborted_before_dispatch",
            ],
            "dispatch_intent_without_committed_response": [
                "provider_outcome_unknown"
            ],
            "committed_response_before_task_commit": ["task_failed_after_response"],
        },
        "automatic_retry_allowed": False,
        "same_call_id_replay_allowed": False,
        "unknown_provider_outcome_is_terminal": True,
    }


def _journal_contract() -> dict[str, Any]:
    return {
        "storage": "sqlite_wal_append_only_events",
        "transaction_mode": "begin_immediate",
        "synchronous": "full",
        "event_identity": "create_exclusive_event_id",
        "sequence": "strict_monotonic_per_run",
        "integrity": "canonical_sha256_hash_chain",
        "required_fields": [
            "run_id",
            "task_execution_id",
            "call_id",
            "sequence",
            "event_type",
            "occurred_at",
            "payload_sha256",
            "previous_event_sha256",
            "event_sha256",
        ],
        "fsync_before_irreversible_effects": [
            "container_start",
            "provider_dispatch",
            "participant_signature",
        ],
        "fsync_after_materialized_results": [
            "provider_response",
            "budget_reconciliation",
            "participant_signature",
            "task_commit",
        ],
        "raw_prompt_persisted": False,
        "raw_provider_response_persisted": False,
        "provider_credential_or_hash_persisted": False,
    }


def _budget_contract() -> dict[str, Any]:
    return {
        "reservation_key": "call_id",
        "reserve_before_dispatch_intent": True,
        "reservation_tokens_per_call": 2500,
        "reservation_cost_microunits_per_call": 1523,
        "aggregate_reserved_tokens": 800000,
        "aggregate_reserved_cost_microunits": 487360,
        "aggregate_protocol_max_cost_microunits": 4000000,
        "terminal_statuses": [
            "reconciled",
            "failed_before_dispatch",
            "overrun",
            "provider_outcome_unknown",
        ],
        "all_reservations_terminal_before_closeout": True,
        "actual_usage_reconciled_per_call": True,
        "overrun_policy": "fail_stop_and_signed_closeout",
        "provider_outcome_unknown_policy": "retain_full_reservation_and_signed_closeout",
    }


def _signature_contract() -> dict[str, Any]:
    return {
        "algorithm": "ed25519",
        "signer": "participant_execution_identity_pkcs11",
        "signature_location": "trusted_host_only",
        "private_key_exportable": False,
        "pin_available_to_container": False,
        "sign_after_provider_receipt_and_decision_finalization": True,
        "signed_payload_fields": [
            "run_id",
            "execution_authorization_sha256",
            "task_execution_id",
            "call_id",
            "participant_id",
            "execution_did",
            "credential_version",
            "pair_id",
            "cohort",
            "task_id",
            "task_input_sha256",
            "signed_advice_canonical_sha256_or_null",
            "provider_receipt_sha256",
            "decision_sha256",
            "event_trace_sha256",
        ],
        "one_signature_per_task_execution": True,
        "unsigned_or_wrong_identity_decision_accepted": False,
    }


def _isolation_contract() -> dict[str, Any]:
    return {
        "one_container_per_participant": True,
        "container_reuse_across_tasks": True,
        "single_task_active_per_container": True,
        "container_started_only_for_participant_step": True,
        "container_stopped_after_each_task": True,
        "input_output_workspace_cleared_between_tasks": True,
        "empty_workspace_hash_journaled_before_next_task": True,
        "network_mode": "none",
        "read_only_rootfs": True,
        "provider_credential_available_to_container": False,
        "pkcs11_available_to_container": False,
        "docker_socket_available_to_container": False,
        "host_file_ipc_only": True,
    }


def _recovery_contract() -> dict[str, Any]:
    return {
        "planned_through_budget_reserved": (
            "resume_idempotently_with_same_task_execution_id_and_call_id"
        ),
        "dispatch_intent_committed_without_provider_response": (
            "mark_provider_outcome_unknown_do_not_retry"
        ),
        "provider_response_committed_through_event_trace_verified": (
            "resume_local_idempotent_projection_from_persisted_hashes"
        ),
        "task_committed": "skip_and_verify_existing_terminal_evidence",
        "terminal_failure": "do_not_retry_close_out_run_with_new_authorization_required",
        "journal_integrity_failure": "fail_stop_no_external_effect",
        "container_state_drift": "fail_stop_before_dispatch",
        "automatic_provider_retry": False,
    }


def _run_terminal_contract() -> dict[str, Any]:
    return {
        "allowed_states": ["complete", "failed", "aborted"],
        "complete": {
            "committed_task_executions": 320,
            "unattempted_task_executions": 0,
            "unknown_provider_outcomes": 0,
        },
        "failed_or_aborted": {
            "all_320_task_executions_accounted": True,
            "attempted_and_unattempted_reason_required": True,
            "partial_results_promotable": False,
        },
        "required_artifacts": [
            "execution_journal",
            "budget_summary",
            "post_run_receipt",
            "evaluation_report",
            "operator_closeout_receipt",
            "terminal_gate_report",
        ],
        "operator_closeout_signature_required": True,
        "claimed_authorization_reusable": False,
        "backend_fact_append_allowed": False,
        "ledger_append_allowed": False,
        "effectiveness_claim_before_signed_closeout_allowed": False,
    }


def _fault_matrix_requirements() -> list[dict[str, str]]:
    return [
        {
            "fault": "crash_before_budget_reservation",
            "expected": "same_ids_resume_no_provider_call",
        },
        {
            "fault": "crash_after_budget_reservation_before_dispatch_intent",
            "expected": "same_ids_resume_single_reservation",
        },
        {
            "fault": "crash_after_dispatch_intent_before_response_commit",
            "expected": "provider_outcome_unknown_no_retry_signed_closeout",
        },
        {
            "fault": "crash_after_response_commit_before_reconciliation",
            "expected": "local_recovery_no_provider_retry",
        },
        {
            "fault": "crash_after_signature_before_task_commit",
            "expected": "verify_existing_signature_then_commit_once",
        },
        {
            "fault": "duplicate_or_reordered_journal_event",
            "expected": "integrity_failure_fail_stop",
        },
        {
            "fault": "container_or_workspace_drift",
            "expected": "fail_before_dispatch",
        },
        {
            "fault": "budget_or_protocol_ceiling_exceeded",
            "expected": "fail_stop_signed_closeout",
        },
    ]


def _task_index(design: dict[str, Any]) -> dict[str, dict[str, Any]]:
    items = design.get("task_contracts")
    items = items if isinstance(items, list) else []
    return {
        str(item.get("task_id")): item
        for item in items
        if isinstance(item, dict) and _text(item.get("task_id"))
    }


def _roster_index(roster: dict[str, Any]) -> dict[str, dict[str, Any]]:
    items = roster.get("participants")
    items = items if isinstance(items, list) else []
    return {
        str(item.get("participant_id")): item
        for item in items
        if isinstance(item, dict) and _text(item.get("participant_id"))
    }


def _advice_index(manifest: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    items = manifest.get("signed_advice")
    items = items if isinstance(items, list) else []
    return {
        (str(item.get("participant_id")), str(item.get("task_id"))): item
        for item in items
        if isinstance(item, dict)
        and _text(item.get("participant_id"))
        and _text(item.get("task_id"))
    }


def _container_index(activation: dict[str, Any]) -> dict[str, dict[str, Any]]:
    items = activation.get("containers")
    items = items if isinstance(items, list) else []
    return {
        str(item.get("participant_id")): item
        for item in items
        if isinstance(item, dict) and _text(item.get("participant_id"))
    }


def _artifact_ref(value: Any) -> bool:
    item = value if isinstance(value, dict) else {}
    return (
        set(item) == {"path", "sha256", "canonical_sha256"}
        and str(item.get("path", "")).startswith("/")
        and _sha256(item.get("sha256"))
        and _sha256(item.get("canonical_sha256"))
    )


def _rfc3339(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return True


def _revision(value: Any) -> bool:
    return isinstance(value, str) and len(value) in {40, 64} and _hex(value)


def _sha256(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and _hex(value)


def _hex(value: str) -> bool:
    try:
        int(value, 16)
    except (TypeError, ValueError):
        return False
    return True


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _require(condition: bool, reason: str, failures: list[str]) -> None:
    if not condition:
        failures.append(reason)
