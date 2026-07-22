"""Non-executable J1-D cohort-aware protocol/design migration contract."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from .controlled_comparison import canonical_sha256
from .qualification_verifier import (
    CASE_CONTRACTS,
    validate_verifier_manifest,
)


SCHEMA = "j1-qualification-cohort-migration-plan:v2"
REQUIRED_BLOCKERS = {
    "protocol_design_amendment_review_required",
    "participant_consent_extension_required",
    "roster_assignment_infrastructure_rebind_required",
}
CONTROL_EVENT_SCRIPTS = {
    "j1q-heldout-scope-delivery-01": [
        "repeated_error_loaded",
        "advice_assignment_absence_observed",
        "apprentice_decision",
        "bounded_delivery",
    ],
    "j1q-heldout-constitution-02": [
        "advice_assignment_absence_observed",
        "apprentice_decision",
        "unsafe_action_gate",
    ],
    "j1q-heldout-independent-decision-03": [
        "advice_assignment_absence_observed",
        "apprentice_decision",
        "decision_signature",
    ],
    "j1q-heldout-revocation-04": [
        "advice_assignment_absence_observed",
        "relation_revocation_processed",
        "post_revocation_read_attempt",
    ],
    "j1q-heldout-restart-continuity-05": [
        "advice_assignment_absence_observed",
        "checkpoint_committed",
        "runtime_restarted",
        "advice_absence_reloaded",
        "apprentice_decision",
    ],
    "j1q-heldout-credential-rotation-06": [
        "advice_assignment_absence_observed",
        "credential_rotated",
        "stale_advice_absence_observed",
        "current_credential_read_attempt",
    ],
    "j1q-heldout-maturity-window-07": [
        "prior_error_window_loaded",
        "advice_assignment_absence_observed",
        "three_task_window_evaluated",
    ],
    "j1q-heldout-refusal-delivery-08": [
        "advice_assignment_absence_observed",
        "apprentice_decision",
        "bounded_delivery",
    ],
}


def build_cohort_migration_plan(
    *,
    amendment_id: str,
    created_at: str,
    source_binding: dict[str, str],
    base_protocol: dict[str, Any],
    base_reviewed_design: dict[str, Any],
    reviewed_assignment: dict[str, Any],
    signed_advice_manifest: dict[str, Any],
    reviewed_verifier_v2: dict[str, Any],
    implementation: dict[str, str],
) -> dict[str, Any]:
    verifier_failures = validate_verifier_manifest(
        reviewed_verifier_v2,
        expected_status="operator_reviewed",
    )
    if verifier_failures:
        raise ValueError(f"reviewed verifier v2 invalid: {verifier_failures}")
    tasks = sorted(
        base_reviewed_design["treatment"]["tasks"],
        key=lambda item: item["task_id"],
    )
    cohort_contracts = []
    for task in tasks:
        case_id = task["verifier_case"]
        cohort_contracts.append(
            {
                "task_id": task["task_id"],
                "task_input_sha256": task["task_input_sha256"],
                "verifier_case": case_id,
                "shared_outcome_assertions": CASE_CONTRACTS[case_id]["shared"],
                "mentor": {
                    "event_script": task["event_script"],
                    "advice_assignment_present": True,
                    "signed_advice_required": True,
                    "exposure_assertions": CASE_CONTRACTS[case_id]["mentor"],
                },
                "control": {
                    "event_script": CONTROL_EVENT_SCRIPTS[task["task_id"]],
                    "advice_assignment_present": False,
                    "signed_advice_required": False,
                    "exposure_assertions": CASE_CONTRACTS[case_id]["control"],
                },
            }
        )
    value = {
        "schema_version": SCHEMA,
        "amendment_id": amendment_id,
        "status": "review_required",
        "created_at": created_at,
        "source_binding": source_binding,
        "base_invariants": {
            "base_protocol_immutable": True,
            "base_reviewed_design_immutable": True,
            "task_corpus_unchanged": True,
            "task_input_hashes_unchanged": True,
            "mentor_event_scripts_unchanged": True,
            "mentor_advice_templates_unchanged": True,
            "provider_model_temperature_unchanged": True,
            "pricing_and_budget_unchanged": True,
            "control_advice_projection_remains_empty": True,
        },
        "completed_prerequisites": {
            "verifier_v2_material_review_gate_passed": True,
            "verifier_v2_operator_reviewed": True,
        },
        "cohort_event_contracts": cohort_contracts,
        "artifact_migration": _artifact_migration(),
        "required_gate_sequence": _required_gate_sequence(),
        "inventory": {
            "task_count": 8,
            "pair_count": 20,
            "participant_count": 40,
            "mentor_participant_count": 20,
            "control_participant_count": 20,
            "existing_signed_advice_count": 160,
            "control_advice_count": 0,
            "participant_consent_extension_count": 40,
        },
        "blockers": sorted(REQUIRED_BLOCKERS),
        "readiness": {
            "migration_contract_complete": True,
            "verifier_v2_operator_reviewed": True,
            "protocol_design_amendment_operator_reviewed": False,
            "participant_consent_extensions_complete": False,
            "downstream_bindings_refreshed": False,
            "controlled_experiment_execution_ready": False,
        },
        "implementation": implementation,
        "execution_boundary": {
            "migration_plan_only": True,
            "review_decision_automated": False,
            "participant_consent_automated": False,
            "artifact_promoted": False,
            "container_created": False,
            "container_started": False,
            "provider_api_call_performed": False,
            "model_invocation_performed": False,
            "agent_execution_performed": False,
            "backend_fact_append_performed": False,
            "ledger_append_performed": False,
        },
    }
    value["plan_sha256"] = canonical_sha256(value)
    failures = validate_cohort_migration_plan(
        value,
        expected_source_binding=source_binding,
        base_protocol=base_protocol,
        base_reviewed_design=base_reviewed_design,
        reviewed_assignment=reviewed_assignment,
        signed_advice_manifest=signed_advice_manifest,
        reviewed_verifier_v2=reviewed_verifier_v2,
        expected_implementation=implementation,
    )
    if failures:
        raise ValueError(f"cohort migration plan invalid: {failures}")
    return value


def validate_cohort_migration_plan(
    value: Any,
    *,
    expected_source_binding: dict[str, str],
    base_protocol: dict[str, Any],
    base_reviewed_design: dict[str, Any],
    reviewed_assignment: dict[str, Any],
    signed_advice_manifest: dict[str, Any],
    reviewed_verifier_v2: dict[str, Any],
    expected_implementation: dict[str, str],
) -> list[str]:
    plan = value if isinstance(value, dict) else {}
    failures: list[str] = []
    _require(
        set(plan)
        == {
            "schema_version",
            "amendment_id",
            "status",
            "created_at",
            "source_binding",
            "base_invariants",
            "completed_prerequisites",
            "cohort_event_contracts",
            "artifact_migration",
            "required_gate_sequence",
            "inventory",
            "blockers",
            "readiness",
            "implementation",
            "execution_boundary",
            "plan_sha256",
        },
        "cohort_migration_fields_invalid",
        failures,
    )
    _require(
        plan.get("schema_version") == SCHEMA,
        "cohort_migration_schema_invalid",
        failures,
    )
    _require(_text(plan.get("amendment_id")), "cohort_migration_id_invalid", failures)
    _require(
        plan.get("status") == "review_required",
        "cohort_migration_status_invalid",
        failures,
    )
    _require(
        _rfc3339(plan.get("created_at")), "cohort_migration_time_invalid", failures
    )
    _require(
        plan.get("source_binding") == expected_source_binding,
        "cohort_migration_source_invalid",
        failures,
    )
    _require(
        plan.get("base_invariants") == _base_invariants(),
        "cohort_migration_invariants_invalid",
        failures,
    )
    _require(
        plan.get("completed_prerequisites")
        == {
            "verifier_v2_material_review_gate_passed": True,
            "verifier_v2_operator_reviewed": True,
        },
        "cohort_migration_prerequisites_invalid",
        failures,
    )
    _require(
        plan.get("artifact_migration") == _artifact_migration(),
        "cohort_migration_artifact_impact_invalid",
        failures,
    )
    _require(
        plan.get("required_gate_sequence") == _required_gate_sequence(),
        "cohort_migration_gate_sequence_invalid",
        failures,
    )
    _require(
        set(plan.get("blockers", [])) == REQUIRED_BLOCKERS,
        "cohort_migration_blockers_invalid",
        failures,
    )
    _require(
        plan.get("implementation") == expected_implementation,
        "cohort_migration_implementation_invalid",
        failures,
    )
    _validate_source_inventory(
        plan,
        base_protocol=base_protocol,
        base_reviewed_design=base_reviewed_design,
        reviewed_assignment=reviewed_assignment,
        signed_advice_manifest=signed_advice_manifest,
        reviewed_verifier_v2=reviewed_verifier_v2,
        failures=failures,
    )
    _require(
        plan.get("readiness")
        == {
            "migration_contract_complete": True,
            "verifier_v2_operator_reviewed": True,
            "protocol_design_amendment_operator_reviewed": False,
            "participant_consent_extensions_complete": False,
            "downstream_bindings_refreshed": False,
            "controlled_experiment_execution_ready": False,
        },
        "cohort_migration_readiness_invalid",
        failures,
    )
    boundary = plan.get("execution_boundary")
    _require(
        isinstance(boundary, dict)
        and boundary.get("migration_plan_only") is True
        and len(boundary) == 11
        and all(
            item is False
            for key, item in boundary.items()
            if key != "migration_plan_only"
        ),
        "cohort_migration_boundary_invalid",
        failures,
    )
    body = {key: item for key, item in plan.items() if key != "plan_sha256"}
    _require(
        plan.get("plan_sha256") == canonical_sha256(body),
        "cohort_migration_hash_invalid",
        failures,
    )
    return list(dict.fromkeys(failures))


def _validate_source_inventory(
    plan: dict[str, Any],
    *,
    base_protocol: dict[str, Any],
    base_reviewed_design: dict[str, Any],
    reviewed_assignment: dict[str, Any],
    signed_advice_manifest: dict[str, Any],
    reviewed_verifier_v2: dict[str, Any],
    failures: list[str],
) -> None:
    tasks = {
        item["task_id"]: item
        for item in base_reviewed_design.get("treatment", {}).get("tasks", [])
        if isinstance(item, dict)
    }
    contracts = plan.get("cohort_event_contracts")
    contracts = contracts if isinstance(contracts, list) else []
    _require(
        len(contracts) == 8 and set(tasks) == set(CONTROL_EVENT_SCRIPTS),
        "cohort_migration_task_inventory_invalid",
        failures,
    )
    for contract in contracts:
        task = (
            tasks.get(contract.get("task_id"), {}) if isinstance(contract, dict) else {}
        )
        case_id = task.get("verifier_case")
        expected = {
            "task_id": task.get("task_id"),
            "task_input_sha256": task.get("task_input_sha256"),
            "verifier_case": case_id,
            "shared_outcome_assertions": CASE_CONTRACTS.get(case_id, {}).get("shared"),
            "mentor": {
                "event_script": task.get("event_script"),
                "advice_assignment_present": True,
                "signed_advice_required": True,
                "exposure_assertions": CASE_CONTRACTS.get(case_id, {}).get("mentor"),
            },
            "control": {
                "event_script": CONTROL_EVENT_SCRIPTS.get(str(task.get("task_id"))),
                "advice_assignment_present": False,
                "signed_advice_required": False,
                "exposure_assertions": CASE_CONTRACTS.get(case_id, {}).get("control"),
            },
        }
        _require(
            contract == expected, "cohort_migration_task_contract_invalid", failures
        )
    assignments = reviewed_assignment.get("assignments", [])
    signed = signed_advice_manifest.get("signed_advice", [])
    mentor_ids = {
        item.get("mentor", {}).get("participant_id")
        for item in assignments
        if isinstance(item, dict) and isinstance(item.get("mentor"), dict)
    }
    expected_signed_keys = {
        (participant_id, task_id) for participant_id in mentor_ids for task_id in tasks
    }
    signed_keys = [
        (item.get("participant_id"), item.get("task_id"))
        for item in signed
        if isinstance(item, dict)
    ]
    _require(
        len(assignments) == 20
        and len(signed) == 160
        and len(set(signed_keys)) == 160
        and set(signed_keys) == expected_signed_keys
        and base_protocol.get("task_corpus", {}).get("task_count") == 8,
        "cohort_migration_source_inventory_invalid",
        failures,
    )
    design_source = base_reviewed_design.get("source_binding", {})
    _require(
        design_source.get("qualification_protocol_sha256")
        == canonical_sha256(base_protocol)
        and design_source.get("corpus_tasks_sha256")
        == base_protocol.get("task_corpus", {}).get("tasks_sha256"),
        "cohort_migration_base_design_protocol_binding_invalid",
        failures,
    )
    verifier_failures = validate_verifier_manifest(
        reviewed_verifier_v2,
        expected_status="operator_reviewed",
    )
    failures.extend(verifier_failures)


def validate_reviewed_verifier_promotion(
    *,
    reviewed_corpus: dict[str, Any],
    reviewed_verifier: dict[str, Any],
    material_review_gate: dict[str, Any],
    reviewed_corpus_artifact: dict[str, str],
    reviewed_verifier_artifact: dict[str, str],
) -> list[str]:
    failures: list[str] = []
    gate = material_review_gate
    _require(
        gate.get("schema_version") == "j1-qualification-material-review-gate:v1"
        and gate.get("passed") is True
        and gate.get("failure_reasons") == []
        and gate.get("state")
        == "j1d_material_review_passed_protocol_freeze_required"
        and gate.get("review_decision") == "approve_qualification_materials"
        and gate.get("review_receipt_signature_valid") is True,
        "cohort_migration_verifier_review_gate_invalid",
        failures,
    )
    _require(
        gate.get("promoted_artifacts")
        == {
            "corpus": reviewed_corpus_artifact,
            "verifier": reviewed_verifier_artifact,
        },
        "cohort_migration_verifier_promotion_binding_invalid",
        failures,
    )
    _require(
        gate.get("readiness", {}).get("qualification_materials_operator_reviewed")
        is True
        and gate.get("readiness", {}).get("controlled_experiment_execution_ready")
        is False,
        "cohort_migration_verifier_review_readiness_invalid",
        failures,
    )
    corpus_review = reviewed_corpus.get("operator_review")
    verifier_review = reviewed_verifier.get("operator_review")
    receipt_sha256 = gate.get("review_receipt", {}).get("sha256")
    _require(
        reviewed_corpus.get("status") == "operator_reviewed"
        and isinstance(corpus_review, dict)
        and corpus_review == verifier_review
        and corpus_review.get("decision") == "approve_qualification_materials"
        and corpus_review.get("review_receipt_sha256") == receipt_sha256,
        "cohort_migration_reviewed_material_binding_invalid",
        failures,
    )
    failures.extend(
        validate_verifier_manifest(
            reviewed_verifier,
            expected_status="operator_reviewed",
        )
    )
    return list(dict.fromkeys(failures))


def _base_invariants() -> dict[str, bool]:
    return {
        "base_protocol_immutable": True,
        "base_reviewed_design_immutable": True,
        "task_corpus_unchanged": True,
        "task_input_hashes_unchanged": True,
        "mentor_event_scripts_unchanged": True,
        "mentor_advice_templates_unchanged": True,
        "provider_model_temperature_unchanged": True,
        "pricing_and_budget_unchanged": True,
        "control_advice_projection_remains_empty": True,
    }


def _artifact_migration() -> dict[str, list[str]]:
    return {
        "reusable_as_immutable_parent_evidence": [
            "base_task_corpus",
            "operator_reviewed_verifier_v2",
            "participant_identity_keys",
            "cognitive_baseline_payloads",
            "reviewed_pair_structure",
            "mentor_identity",
            "signed_mentor_advice_payloads_if_mentor_contract_unchanged",
        ],
        "new_review_or_signature_required": [
            "protocol_design_amendment",
            "participant_consent_extension_40_of_40",
            "reviewed_roster_rebind",
            "reviewed_cohort_assignment_rebind",
            "execution_infrastructure_plan_rebind",
            "live_provider_admission_refresh",
            "single_use_execution_authorization",
        ],
        "forbidden_shortcuts": [
            "mutate_existing_reviewed_artifact",
            "inherit_participant_consent_implicitly",
            "inject_advice_into_control",
            "claim_signed_advice_bound_to_amendment_without_parent_binding_review",
            "reuse_prior_execution_authorization",
        ],
    }


def _required_gate_sequence() -> list[str]:
    return [
        "protocol_design_amendment_independent_review",
        "participant_consent_extension_collection",
        "roster_and_assignment_rebind_gate",
        "runner_and_infrastructure_rebind_gate",
        "live_provider_admission_refresh_gate",
        "no_provider_execution_preflight",
        "single_use_execution_authorization_gate",
    ]


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _rfc3339(value: Any) -> bool:
    if not _text(value):
        return False
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).tzinfo is not None
    except ValueError:
        return False


def _require(condition: bool, code: str, failures: list[str]) -> None:
    if not condition and code not in failures:
        failures.append(code)
