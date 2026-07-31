"""Execution contract for the J1-D outcome-sensitive qualification run."""

from __future__ import annotations

import copy
from datetime import datetime
from typing import Any

from .controlled_comparison import canonical_sha256
from .qualification_execution_contract_v4 import (
    ALLOWED_TRANSITIONS,
    TASK_STATES,
    TASK_TERMINAL_STATES,
)


CONTRACT_SCHEMA = "j1-qualification-outcome-sensitive-execution-contract:v1"
SOURCE_NAMES = {
    "activation",
    "activation_gate",
    "assignment",
    "consent_gate",
    "design",
    "evaluator",
    "infrastructure",
    "infrastructure_promotion_gate",
    "material_promotion_gate",
    "mentor_advice_gate",
    "parent_activation",
    "parent_activation_gate",
    "protocol",
    "provider_admission_gate",
    "provider_admission_plan",
    "provider_admission_preflight",
    "provider_admission_receipt",
    "repair_promotion_gate",
    "reviewed_repair",
    "roster",
    "roster_assignment_gate",
    "runner_manifest",
    "signed_advice_manifest",
    "statistical_plan",
    "task_fixture",
    "transport_gate",
    "transport_plan",
    "transport_promotion_gate",
    "transport_report",
}
PARTICIPANT_COUNT = 40
MENTOR_COUNT = 20
CONTROL_COUNT = 20
PAIR_COUNT = 20
TASKS_PER_PARTICIPANT = 12
TASK_EXECUTION_COUNT = PARTICIPANT_COUNT * TASKS_PER_PARTICIPANT
TREATMENT_ORDINALS = list(range(4, 13))
BASELINE_ORDINALS = [1, 2, 3]
RESERVED_TOKENS_PER_CALL = 2500
RESERVED_COST_PER_CALL = 1523
PROTOCOL_MAX_COST = 4_000_000
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
    "si13_maturity_upgrade_authorized": False,
}


def build_execution_contract(
    *,
    contract_id: str,
    created_at: str,
    source_artifacts: dict[str, dict[str, str]],
    protocol: dict[str, Any],
    design: dict[str, Any],
    evaluator: dict[str, Any],
    task_fixture: dict[str, Any],
    roster: dict[str, Any],
    assignment: dict[str, Any],
    signed_advice_manifest: dict[str, Any],
    activation: dict[str, Any],
    provider_admission_receipt: dict[str, Any],
    provider_admission_gate: dict[str, Any],
    implementation: dict[str, str],
) -> dict[str, Any]:
    """Build a 480-task contract without exposing fixture ground truth."""
    executions = _task_executions(
        assignments=assignment.get("assignments", []),
        fixtures=_fixture_index(task_fixture),
        roster=_roster_index(roster),
        advice=_advice_index(signed_advice_manifest),
        containers=_container_index(activation),
        design=design,
    )
    value = {
        "schema_version": CONTRACT_SCHEMA,
        "contract_id": contract_id,
        "status": "independent_review_required",
        "created_at": created_at,
        "source_artifacts": copy.deepcopy(source_artifacts),
        "scope": _expected_scope(design),
        "task_executions": executions,
        "structured_decision_contract": copy.deepcopy(
            protocol.get("decision_contract")
        ),
        "direct_observation_contract": {
            "schema_version": evaluator.get("input_contract", {}).get(
                "direct_observation_schema"
            ),
            "participant_decision_schema": evaluator.get("input_contract", {}).get(
                "participant_decision_schema"
            ),
            "ground_truth_available_to_participant_or_provider": False,
            "ground_truth_commitment_bound_before_execution": True,
            "deterministic_host_verification_required": True,
            "raw_provider_response_allowed_in_terminal_evidence": False,
            "model_judge_allowed": False,
            "operator_override_allowed": False,
        },
        "treatment_contract": copy.deepcopy(protocol.get("treatment_contract")),
        "state_machine": _state_machine(),
        "journal_contract": _journal_contract(),
        "budget_contract": _budget_contract(),
        "participant_signature_contract": _signature_contract(),
        "isolation_contract": _isolation_contract(),
        "recovery_contract": _recovery_contract(),
        "run_terminal_contract": _run_terminal_contract(),
        "fault_matrix_requirements": _fault_matrix_requirements(),
        "provider_admission": {
            "receipt_sha256": provider_admission_receipt.get("receipt_sha256"),
            "gate_sha256": provider_admission_gate.get("report_sha256"),
            "status": provider_admission_receipt.get("status"),
            "gate_passed": provider_admission_gate.get("passed"),
            "provider_id": provider_admission_receipt.get("provider", {}).get(
                "provider_id"
            ),
            "model_id": provider_admission_receipt.get("provider", {}).get("model_id"),
            "temperature": provider_admission_receipt.get("provider", {}).get(
                "temperature"
            ),
        },
        "implementation": copy.deepcopy(implementation),
        "execution_boundary": copy.deepcopy(EXECUTION_BOUNDARY),
    }
    value["contract_sha256"] = canonical_sha256(value)
    failures = validate_execution_contract(
        value,
        protocol=protocol,
        design=design,
        evaluator=evaluator,
        task_fixture=task_fixture,
        roster=roster,
        assignment=assignment,
        signed_advice_manifest=signed_advice_manifest,
        activation=activation,
        provider_admission_receipt=provider_admission_receipt,
        provider_admission_gate=provider_admission_gate,
        expected_source_artifacts=source_artifacts,
        expected_implementation=implementation,
    )
    if failures:
        raise ValueError(f"outcome-sensitive execution contract invalid: {failures}")
    return value


def validate_execution_contract(
    value: Any,
    *,
    protocol: dict[str, Any],
    design: dict[str, Any],
    evaluator: dict[str, Any],
    task_fixture: dict[str, Any],
    roster: dict[str, Any],
    assignment: dict[str, Any],
    signed_advice_manifest: dict[str, Any],
    activation: dict[str, Any],
    provider_admission_receipt: dict[str, Any],
    provider_admission_gate: dict[str, Any],
    expected_source_artifacts: dict[str, dict[str, str]],
    expected_implementation: dict[str, str],
) -> list[str]:
    contract = value if isinstance(value, dict) else {}
    failures: list[str] = []
    _require(
        contract.get("schema_version") == CONTRACT_SCHEMA
        and contract.get("status") == "independent_review_required"
        and _text(contract.get("contract_id"))
        and _rfc3339(contract.get("created_at")),
        "outcome_execution_contract_identity_invalid",
        failures,
    )
    _require(
        contract.get("source_artifacts") == expected_source_artifacts
        and set(expected_source_artifacts) == SOURCE_NAMES
        and all(_artifact_ref(item) for item in expected_source_artifacts.values()),
        "outcome_execution_contract_sources_invalid",
        failures,
    )
    _require(
        protocol.get("scope")
        == {
            "matched_pair_count": 20,
            "minimum_completed_pairs": 20,
            "participant_count": 40,
            "tasks_per_participant": 12,
            "total_task_count": 480,
        },
        "outcome_execution_protocol_scope_invalid",
        failures,
    )
    _require(
        task_fixture.get("inventory", {}).get("task_count") == 12
        and evaluator.get("input_contract", {}).get("total_task_evidence_count") == 480,
        "outcome_execution_material_scope_invalid",
        failures,
    )
    fixture_index = _fixture_index(task_fixture)
    roster_index = _roster_index(roster)
    advice_index = _advice_index(signed_advice_manifest)
    container_index = _container_index(activation)
    assigned_participants = {
        str(pair.get(cohort, {}).get("participant_id"))
        for pair in assignment.get("assignments", [])
        if isinstance(pair, dict)
        for cohort in ("mentor", "control")
    }
    _require(
        set(fixture_index) == set(range(1, 13))
        and all(
            _sha256(item.get("prompt_sha256"))
            and _sha256(item.get("ground_truth_commitment_sha256"))
            and "ground_truth" in item
            for item in fixture_index.values()
        ),
        "outcome_execution_fixture_inventory_invalid",
        failures,
    )
    _require(
        len(roster_index) == PARTICIPANT_COUNT
        and len(assignment.get("assignments", [])) == PAIR_COUNT
        and len(assigned_participants) == PARTICIPANT_COUNT
        and assigned_participants == set(roster_index),
        "outcome_execution_participant_inventory_invalid",
        failures,
    )
    _require(
        len(advice_index) == 180
        and signed_advice_manifest.get("inventory", {}).get(
            "signed_advice_count", 180
        )
        == 180,
        "outcome_execution_advice_inventory_invalid",
        failures,
    )
    _require(
        len(container_index) == PARTICIPANT_COUNT
        and set(container_index) == assigned_participants
        and activation.get("inventory", {}).get("container_created_count", 40)
        == 40
        and activation.get("inventory", {}).get("container_started_count", 0)
        == 0
        and all(
            item.get("container", {}).get("state", {}).get("status", "created")
            == "created"
            and item.get("container", {}).get("state", {}).get("running", False)
            is False
            for item in container_index.values()
        ),
        "outcome_execution_container_inventory_invalid",
        failures,
    )
    _require(
        contract.get("scope") == _expected_scope(design),
        "outcome_execution_contract_scope_invalid",
        failures,
    )
    expected_executions = _task_executions(
        assignments=assignment.get("assignments", []),
        fixtures=_fixture_index(task_fixture),
        roster=_roster_index(roster),
        advice=_advice_index(signed_advice_manifest),
        containers=_container_index(activation),
        design=design,
    )
    _require(
        contract.get("task_executions") == expected_executions
        and len(expected_executions) == TASK_EXECUTION_COUNT
        and len({item["task_execution_id"] for item in expected_executions})
        == TASK_EXECUTION_COUNT
        and len({item["call_id"] for item in expected_executions})
        == TASK_EXECUTION_COUNT,
        "outcome_execution_task_manifest_invalid",
        failures,
    )
    advice_modes = [
        item.get("advice", {}).get("mode") for item in expected_executions
    ]
    _require(
        advice_modes.count("mentor_signed") == 180
        and advice_modes.count("baseline_empty") == 60
        and advice_modes.count("control_empty") == 240,
        "outcome_execution_treatment_projection_invalid",
        failures,
    )
    expected_sections = {
        "structured_decision_contract": protocol.get("decision_contract"),
        "treatment_contract": protocol.get("treatment_contract"),
        "state_machine": _state_machine(),
        "journal_contract": _journal_contract(),
        "budget_contract": _budget_contract(),
        "participant_signature_contract": _signature_contract(),
        "isolation_contract": _isolation_contract(),
        "recovery_contract": _recovery_contract(),
        "run_terminal_contract": _run_terminal_contract(),
        "fault_matrix_requirements": _fault_matrix_requirements(),
    }
    for name, expected in expected_sections.items():
        _require(
            contract.get(name) == expected,
            f"outcome_execution_{name}_invalid",
            failures,
        )
    observation = contract.get("direct_observation_contract", {})
    _require(
        observation.get("schema_version")
        == "j1-qualification-direct-behavior-observation:v1"
        and observation.get("participant_decision_schema")
        == "j1-qualification-structured-decision:v1"
        and observation.get("ground_truth_available_to_participant_or_provider")
        is False
        and observation.get("ground_truth_commitment_bound_before_execution") is True
        and observation.get("deterministic_host_verification_required") is True
        and observation.get("model_judge_allowed") is False
        and observation.get("operator_override_allowed") is False,
        "outcome_execution_observation_contract_invalid",
        failures,
    )
    admission = contract.get("provider_admission", {})
    gate_receipt = provider_admission_gate.get("receipt", {})
    _require(
        admission
        == {
            "receipt_sha256": provider_admission_receipt.get("receipt_sha256"),
            "gate_sha256": provider_admission_gate.get("report_sha256"),
            "status": "admitted",
            "gate_passed": True,
            "provider_id": "openai_compatible",
            "model_id": "deepseek-v4-pro",
            "temperature": 0,
        },
        "outcome_execution_provider_admission_invalid",
        failures,
    )
    _require(
        gate_receipt.get("canonical_sha256")
        == provider_admission_receipt.get("receipt_sha256")
        and provider_admission_gate.get("failure_reasons", []) == []
        and all(provider_admission_gate.get("checks", {"admitted": True}).values()),
        "outcome_execution_provider_admission_gate_binding_invalid",
        failures,
    )
    _require(
        contract.get("implementation") == expected_implementation
        and set(expected_implementation)
        == {
            "source_revision",
            "domain_source_sha256",
            "operation_source_sha256",
        }
        and _revision(expected_implementation.get("source_revision"))
        and _sha256(expected_implementation.get("domain_source_sha256"))
        and _sha256(expected_implementation.get("operation_source_sha256")),
        "outcome_execution_implementation_invalid",
        failures,
    )
    _require(
        contract.get("execution_boundary") == EXECUTION_BOUNDARY,
        "outcome_execution_boundary_invalid",
        failures,
    )
    body = {key: item for key, item in contract.items() if key != "contract_sha256"}
    _require(
        contract.get("contract_sha256") == canonical_sha256(body),
        "outcome_execution_contract_hash_invalid",
        failures,
    )
    return list(dict.fromkeys(failures))


def _task_executions(
    *,
    assignments: list[Any],
    fixtures: dict[int, dict[str, Any]],
    roster: dict[str, dict[str, Any]],
    advice: dict[tuple[str, int], dict[str, Any]],
    containers: dict[str, dict[str, Any]],
    design: dict[str, Any],
) -> list[dict[str, Any]]:
    provider = design.get("preserved_provider_call", {})
    values: list[dict[str, Any]] = []
    for pair in sorted(assignments, key=lambda item: item.get("pair_id", "")):
        assignment_commitment = (
            pair.get("rebind_commitment_sha256")
            or pair.get("assignment_commitment_sha256")
            or canonical_sha256(pair)
        )
        for cohort in ("mentor", "control"):
            assigned = pair.get(cohort, {})
            participant_id = str(assigned.get("participant_id"))
            roster_entry = roster.get(participant_id, {})
            activation = containers.get(participant_id, {})
            for task_ordinal, fixture in sorted(fixtures.items()):
                seed = {
                    "pair_id": pair.get("pair_id"),
                    "cohort": cohort,
                    "participant_id": participant_id,
                    "execution_did": assigned.get("execution_did"),
                    "task_id": fixture.get("task_id"),
                    "task_ordinal": task_ordinal,
                    "prompt_sha256": fixture.get("prompt_sha256"),
                    "ground_truth_commitment_sha256": fixture.get(
                        "ground_truth_commitment_sha256"
                    ),
                    "assignment_commitment_sha256": assignment_commitment,
                }
                commitment = canonical_sha256(seed)
                signed_advice = advice.get((participant_id, task_ordinal))
                advice_value = _advice_projection(
                    cohort=cohort,
                    task_ordinal=task_ordinal,
                    signed_advice=signed_advice,
                )
                values.append(
                    {
                        "ordinal": len(values) + 1,
                        "task_execution_id": f"j1q-outcome-task-{commitment[:24]}",
                        "call_id": f"j1q-outcome-call-{commitment[24:48]}",
                        "pair_id": pair.get("pair_id"),
                        "cohort": cohort,
                        "participant_id": participant_id,
                        "execution_did": assigned.get("execution_did"),
                        "credential_version": roster_entry.get("credential_version"),
                        "assignment_commitment_sha256": assignment_commitment,
                        "task": {
                            "task_id": fixture.get("task_id"),
                            "task_ordinal": task_ordinal,
                            "phase": fixture.get("phase"),
                            "prompt_sha256": fixture.get("prompt_sha256"),
                            "ground_truth_commitment_sha256": fixture.get(
                                "ground_truth_commitment_sha256"
                            ),
                            "allowed_action_ids": copy.deepcopy(
                                fixture.get("allowed_action_ids")
                            ),
                            "allowed_pattern_ids": copy.deepcopy(
                                fixture.get("allowed_pattern_ids")
                            ),
                            "deterministic_verifier": copy.deepcopy(
                                fixture.get("deterministic_verifier")
                            ),
                            "ground_truth_persisted": False,
                        },
                        "advice": advice_value,
                        "container": _container_projection(activation),
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
                            "tokens": RESERVED_TOKENS_PER_CALL,
                            "cost_microunits": RESERVED_COST_PER_CALL,
                        },
                        "commitment_sha256": commitment,
                    }
                )
    return values


def _advice_projection(
    *,
    cohort: str,
    task_ordinal: int,
    signed_advice: dict[str, Any] | None,
) -> dict[str, Any]:
    if cohort == "mentor" and task_ordinal in TREATMENT_ORDINALS:
        if not signed_advice:
            raise ValueError(
                f"mentor advice missing for treatment ordinal {task_ordinal}"
            )
        return {
            "mode": "mentor_signed",
            "advice_id": signed_advice.get("advice_id"),
            "path": signed_advice.get("path"),
            "sha256": signed_advice.get("sha256"),
            "canonical_sha256": signed_advice.get("canonical_sha256"),
        }
    if signed_advice:
        raise ValueError("signed advice present outside mentor treatment scope")
    return {
        "mode": (
            "baseline_empty"
            if cohort == "mentor" and task_ordinal in BASELINE_ORDINALS
            else "control_empty"
        ),
        "signed_advice": None,
    }


def _container_projection(activation: dict[str, Any]) -> dict[str, Any]:
    container = activation.get("container", {})
    boundary = container.get("runtime_boundary", {})
    return {
        "container_id": container.get("container_id"),
        "container_name": container.get("container_name"),
        "image_id": container.get("image_id"),
        "network_mode": boundary.get("network_mode"),
        "read_only_rootfs": boundary.get("read_only_rootfs"),
    }


def _expected_scope(design: dict[str, Any]) -> dict[str, Any]:
    provider = design.get("preserved_provider_call", {})
    return {
        "participant_count": PARTICIPANT_COUNT,
        "mentor_participant_count": MENTOR_COUNT,
        "control_participant_count": CONTROL_COUNT,
        "matched_pair_count": PAIR_COUNT,
        "task_count_per_participant": TASKS_PER_PARTICIPANT,
        "task_execution_count": TASK_EXECUTION_COUNT,
        "participant_decision_count": TASK_EXECUTION_COUNT,
        "direct_observation_count": TASK_EXECUTION_COUNT,
        "provider_call_count": TASK_EXECUTION_COUNT,
        "provider_id": provider.get("provider_id"),
        "model_id": provider.get("model_id"),
        "temperature": provider.get("temperature"),
        "aggregate_reserved_tokens": (
            TASK_EXECUTION_COUNT * RESERVED_TOKENS_PER_CALL
        ),
        "aggregate_reserved_cost_microunits": (
            TASK_EXECUTION_COUNT * RESERVED_COST_PER_CALL
        ),
        "aggregate_protocol_max_cost_microunits": PROTOCOL_MAX_COST,
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
            "direct_behavior_observation",
            "task_commit",
        ],
        "raw_fixture_ground_truth_persisted": False,
        "raw_provider_response_persisted_in_journal": False,
        "provider_credential_or_hash_persisted": False,
    }


def _budget_contract() -> dict[str, Any]:
    return {
        "reservation_key": "call_id",
        "reserve_before_dispatch_intent": True,
        "reservation_tokens_per_call": RESERVED_TOKENS_PER_CALL,
        "reservation_cost_microunits_per_call": RESERVED_COST_PER_CALL,
        "aggregate_reserved_tokens": (
            TASK_EXECUTION_COUNT * RESERVED_TOKENS_PER_CALL
        ),
        "aggregate_reserved_cost_microunits": (
            TASK_EXECUTION_COUNT * RESERVED_COST_PER_CALL
        ),
        "aggregate_protocol_max_cost_microunits": PROTOCOL_MAX_COST,
        "terminal_statuses": [
            "reconciled",
            "failed_before_dispatch",
            "overrun",
            "provider_outcome_unknown",
        ],
        "all_reservations_terminal_before_closeout": True,
        "actual_usage_reconciled_per_call": True,
        "overrun_policy": "fail_stop_and_signed_closeout",
        "provider_outcome_unknown_policy": (
            "retain_full_reservation_and_signed_closeout"
        ),
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
            "task_ordinal",
            "phase",
            "prompt_sha256",
            "ground_truth_commitment_sha256",
            "signed_advice_canonical_sha256_or_null",
            "provider_receipt_sha256",
            "selected_action_id",
            "predicted_pattern_ids",
            "decision_sha256",
        ],
        "direct_observation_created_after_signature": True,
        "task_evidence_binds_signature_and_direct_observation": True,
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
        "fixture_ground_truth_available_to_container": False,
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
        "provider_response_committed_through_direct_observation_verified": (
            "resume_local_idempotent_projection_from_persisted_hashes"
        ),
        "task_committed": "skip_and_verify_existing_terminal_evidence",
        "terminal_failure": (
            "do_not_retry_close_out_run_with_new_authorization_required"
        ),
        "journal_integrity_failure": "fail_stop_no_external_effect",
        "container_state_drift": "fail_stop_before_dispatch",
        "automatic_provider_retry": False,
    }


def _run_terminal_contract() -> dict[str, Any]:
    return {
        "allowed_states": ["complete", "failed", "aborted"],
        "complete": {
            "committed_task_executions": TASK_EXECUTION_COUNT,
            "participant_decisions": TASK_EXECUTION_COUNT,
            "direct_behavior_observations": TASK_EXECUTION_COUNT,
            "complete_pairs": PAIR_COUNT,
            "unattempted_task_executions": 0,
            "unknown_provider_outcomes": 0,
        },
        "failed_or_aborted": {
            "all_480_task_executions_accounted": True,
            "attempted_and_unattempted_reason_required": True,
            "partial_results_promotable": False,
        },
        "required_artifacts": [
            "execution_journal",
            "budget_summary",
            "post_run_receipt",
            "outcome_sensitive_evaluation_report",
            "operator_closeout_receipt",
            "terminal_gate_report",
        ],
        "operator_closeout_signature_required": True,
        "claimed_authorization_reusable": False,
        "backend_fact_append_allowed": False,
        "ledger_append_allowed": False,
        "effectiveness_claim_before_signed_closeout_allowed": False,
        "si13_upgrade_before_signed_effectiveness_gate_allowed": False,
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


def _fixture_index(value: dict[str, Any]) -> dict[int, dict[str, Any]]:
    items = value.get("fixtures")
    items = items if isinstance(items, list) else []
    return {
        int(item["task_ordinal"]): item
        for item in items
        if isinstance(item, dict)
        and isinstance(item.get("task_ordinal"), int)
        and _text(item.get("task_id"))
    }


def _roster_index(value: dict[str, Any]) -> dict[str, dict[str, Any]]:
    items = value.get("participants")
    items = items if isinstance(items, list) else []
    return {
        str(item.get("participant_id")): item
        for item in items
        if isinstance(item, dict) and _text(item.get("participant_id"))
    }


def _advice_index(
    value: dict[str, Any],
) -> dict[tuple[str, int], dict[str, Any]]:
    items = value.get("signed_advice")
    items = items if isinstance(items, list) else []
    return {
        (str(item.get("participant_id")), int(item.get("task_ordinal"))): item
        for item in items
        if isinstance(item, dict)
        and _text(item.get("participant_id"))
        and isinstance(item.get("task_ordinal"), int)
    }


def _container_index(value: dict[str, Any]) -> dict[str, dict[str, Any]]:
    items = value.get("containers")
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
