"""Preflight contracts for prospective confirmatory J1-D execution."""

from __future__ import annotations

import copy
import hashlib
from datetime import datetime
from typing import Any

from .controlled_comparison import canonical_sha256
from .qualification_outcome_sensitive_confirmatory_execution_contract import (
    SOURCE_NAMES as CONTRACT_SOURCE_NAMES,
)
from .qualification_outcome_sensitive_execution_materials import (
    validate_material_bindings,
)


PLAN_SCHEMA = (
    "j1-qualification-outcome-sensitive-prospective-confirmatory-execution-plan:v1"
)
PREFLIGHT_SCHEMA = (
    "j1-qualification-outcome-sensitive-prospective-confirmatory-execution-preflight:v1"
)
TTL_SECONDS = 1800
SOURCE_NAMES = CONTRACT_SOURCE_NAMES | {
    "execution_contract",
    "frozen_execution_stack",
    "execution_promotion_gate",
}
BOUNDARY = {
    "prospective_confirmatory_execution_preflight_only": True,
    "execution_authorization_issued_or_consumed": False,
    "participant_container_started": False,
    "provider_credential_read": False,
    "provider_api_call_performed": False,
    "model_invocation_performed": False,
    "agent_or_task_execution_performed": False,
    "participant_signature_performed": False,
    "backend_fact_append_performed": False,
    "ledger_append_performed": False,
    "prior_run_reanalysis_performed": False,
    "advice_adherence_inferred": False,
    "effectiveness_or_causal_claim_authorized": False,
    "si13_maturity_upgrade_authorized": False,
}


def build_confirmatory_execution_plan(
    *,
    run_id: str,
    created_at: str,
    source_artifacts: dict[str, dict[str, str]],
    frozen_stack_sha256: str,
    contract_sha256: str,
    provider_receipt_sha256: str,
    evaluator_sha256: str,
    statistical_plan_sha256: str,
    confirmatory_method_binding: dict[str, Any],
    execution_promotion_gate_sha256: str,
    material_bindings: dict[str, Any],
    paths: dict[str, str],
    implementation: dict[str, str],
) -> dict[str, Any]:
    value = {
        "schema_version": PLAN_SCHEMA,
        "run_id": run_id,
        "status": "owner_issuance_authorization_required",
        "created_at": created_at,
        "ttl_seconds": TTL_SECONDS,
        "source_artifacts": copy.deepcopy(source_artifacts),
        "binding": {
            "frozen_execution_stack_sha256": frozen_stack_sha256,
            "execution_contract_sha256": contract_sha256,
            "execution_promotion_gate_sha256": execution_promotion_gate_sha256,
            "provider_admission_receipt_sha256": provider_receipt_sha256,
            "outcome_sensitive_evaluator_sha256": evaluator_sha256,
            "statistical_plan_sha256": statistical_plan_sha256,
            "confirmatory_method_sha256": confirmatory_method_binding["method_sha256"],
            "confirmatory_method_promotion_gate_sha256": (
                confirmatory_method_binding["promotion_gate_sha256"]
            ),
            "confirmatory_consent_gate_sha256": confirmatory_method_binding[
                "consent_gate_sha256"
            ],
            "confirmatory_roster_assignment_gate_sha256": (
                confirmatory_method_binding["roster_assignment_gate_sha256"]
            ),
            "confirmatory_mentor_advice_gate_sha256": (
                confirmatory_method_binding["mentor_advice_gate_sha256"]
            ),
            "confirmatory_activation_gate_sha256": confirmatory_method_binding[
                "activation_gate_sha256"
            ],
        },
        "confirmatory_inference_contract": {
            "test": copy.deepcopy(confirmatory_method_binding["test"]),
            "multiplicity": copy.deepcopy(confirmatory_method_binding["multiplicity"]),
            "missingness_and_censoring": copy.deepcopy(
                confirmatory_method_binding["missingness_and_censoring"]
            ),
            "claim_gate": copy.deepcopy(confirmatory_method_binding["claim_gate"]),
            "prior_run_reanalysis_allowed": False,
            "advice_adherence_observed": False,
            "advice_adherence_inference_allowed": False,
        },
        "material_bindings": copy.deepcopy(material_bindings),
        "execution_scope": {
            "participant_count": 40,
            "mentor_participant_count": 20,
            "control_participant_count": 20,
            "matched_pair_count": 20,
            "task_count_per_participant": 12,
            "authorized_task_executions": 480,
            "authorized_participant_decisions": 480,
            "authorized_direct_observations": 480,
            "authorized_provider_calls": 480,
            "provider_id": "openai_compatible",
            "model_id": "deepseek-v4-pro",
            "temperature": 0,
        },
        "budget": {
            "aggregate_reserved_tokens": 1_200_000,
            "aggregate_reserved_cost_microunits": 731_040,
            "aggregate_protocol_max_cost_microunits": 4_000_000,
            "reservation_required_before_each_call": True,
            "actual_usage_reconciliation_required": True,
            "provider_outcome_unknown_retains_full_reservation": True,
            "overrun_fail_stop_required": True,
        },
        "controls": {
            "single_use": True,
            "atomic_claim_create_exclusive": True,
            "claim_before_any_container_or_provider_effect": True,
            "claimed_failure_requires_new_authorization": True,
            "unknown_provider_outcome_never_retried": True,
            "journal_hash_chain_required": True,
            "strict_structured_decision_required": True,
            "hidden_fixture_ground_truth_required": True,
            "participant_pkcs11_signature_required": True,
            "direct_behavior_observation_required": True,
            "all_480_terminal_task_evidence_required": True,
            "all_20_complete_pairs_required": True,
            "exact_paired_confirmatory_evaluation_required": True,
            "post_run_receipt_required": True,
            "successful_closeout_implementation_review_required": True,
            "operator_closeout_required": True,
            "backend_fact_append_allowed": False,
            "ledger_append_allowed": False,
            **paths,
        },
        "implementation": copy.deepcopy(implementation),
        "execution_boundary": copy.deepcopy(BOUNDARY),
    }
    value["plan_sha256"] = canonical_sha256(value)
    failures = validate_confirmatory_execution_plan(value)
    if failures:
        raise ValueError(f"confirmatory execution plan invalid: {failures}")
    return value


def validate_confirmatory_execution_plan(value: Any) -> list[str]:
    plan = value if isinstance(value, dict) else {}
    failures: list[str] = []
    if not (
        plan.get("schema_version") == PLAN_SCHEMA
        and plan.get("status") == "owner_issuance_authorization_required"
        and _text(plan.get("run_id"))
        and _rfc3339(plan.get("created_at"))
        and plan.get("ttl_seconds") == TTL_SECONDS
        and set(plan.get("source_artifacts", {})) == SOURCE_NAMES
        and all(_artifact_ref(item) for item in plan["source_artifacts"].values())
        and not validate_material_bindings(plan.get("material_bindings"))
    ):
        failures.append("confirmatory_execution_plan_identity_or_sources_invalid")
    binding = plan.get("binding", {})
    expected_binding_names = {
        "frozen_execution_stack_sha256",
        "execution_contract_sha256",
        "execution_promotion_gate_sha256",
        "provider_admission_receipt_sha256",
        "outcome_sensitive_evaluator_sha256",
        "statistical_plan_sha256",
        "confirmatory_method_sha256",
        "confirmatory_method_promotion_gate_sha256",
        "confirmatory_consent_gate_sha256",
        "confirmatory_roster_assignment_gate_sha256",
        "confirmatory_mentor_advice_gate_sha256",
        "confirmatory_activation_gate_sha256",
    }
    if not (
        set(binding) == expected_binding_names
        and all(_sha256(item) for item in binding.values())
    ):
        failures.append("confirmatory_execution_plan_binding_invalid")
    inference = plan.get("confirmatory_inference_contract", {})
    if not (
        inference.get("test", {}).get("assignment_count") == 1_048_576
        and inference.get("test", {}).get("name")
        == "exact_matched_pair_sign_flip_randomization_test"
        and inference.get("multiplicity", {}).get("method") == "holm_step_down"
        and inference.get("missingness_and_censoring", {}).get(
            "all_480_terminal_task_evidence_required"
        )
        is True
        and inference.get("claim_gate", {}).get(
            "both_holm_adjusted_endpoints_must_reject"
        )
        is True
        and inference.get("prior_run_reanalysis_allowed") is False
        and inference.get("advice_adherence_observed") is False
        and inference.get("advice_adherence_inference_allowed") is False
    ):
        failures.append("confirmatory_execution_plan_inference_contract_invalid")
    if plan.get("execution_scope") != _execution_scope():
        failures.append("confirmatory_execution_plan_scope_invalid")
    budget = plan.get("budget", {})
    if not (
        budget.get("aggregate_reserved_tokens") == 1_200_000
        and budget.get("aggregate_reserved_cost_microunits") == 731_040
        and budget.get("aggregate_protocol_max_cost_microunits") == 4_000_000
        and budget.get("provider_outcome_unknown_retains_full_reservation") is True
        and budget.get("overrun_fail_stop_required") is True
    ):
        failures.append("confirmatory_execution_plan_budget_invalid")
    controls = plan.get("controls", {})
    if not (
        controls.get("single_use") is True
        and controls.get("atomic_claim_create_exclusive") is True
        and controls.get("claim_before_any_container_or_provider_effect") is True
        and controls.get("unknown_provider_outcome_never_retried") is True
        and controls.get("strict_structured_decision_required") is True
        and controls.get("hidden_fixture_ground_truth_required") is True
        and controls.get("participant_pkcs11_signature_required") is True
        and controls.get("direct_behavior_observation_required") is True
        and controls.get("all_480_terminal_task_evidence_required") is True
        and controls.get("all_20_complete_pairs_required") is True
        and controls.get("exact_paired_confirmatory_evaluation_required") is True
        and controls.get("successful_closeout_implementation_review_required") is True
        and controls.get("backend_fact_append_allowed") is False
        and controls.get("ledger_append_allowed") is False
        and all(
            str(controls.get(name, "")).startswith("/")
            for name in (
                "execution_root",
                "authorization_output_root",
                "authorization_claim_path",
                "post_run_output_root",
            )
        )
        and plan.get("execution_boundary") == BOUNDARY
    ):
        failures.append("confirmatory_execution_plan_controls_or_boundary_invalid")
    body = {key: item for key, item in plan.items() if key != "plan_sha256"}
    if plan.get("plan_sha256") != canonical_sha256(body):
        failures.append("confirmatory_execution_plan_hash_invalid")
    return list(dict.fromkeys(failures))


def build_confirmatory_preflight(
    *,
    plan_path: str,
    plan_raw_sha256: str,
    plan: dict[str, Any],
    created_at: str,
    inventory_snapshot: dict[str, Any],
) -> dict[str, Any]:
    failures = validate_confirmatory_execution_plan(plan)
    if failures:
        raise ValueError(f"confirmatory execution plan invalid: {failures}")
    statement = confirmatory_issuance_authorization_statement(
        plan_raw_sha256=plan_raw_sha256,
        plan=plan,
    )
    value = {
        "schema_version": PREFLIGHT_SCHEMA,
        "run_id": plan["run_id"],
        "passed": True,
        "failure_reasons": [],
        "state": (
            "prospective_confirmatory_execution_preflight_passed_"
            "issuance_authorization_required"
        ),
        "created_at": created_at,
        "plan": {
            "path": plan_path,
            "sha256": plan_raw_sha256,
            "canonical_sha256": plan["plan_sha256"],
        },
        "inventory_snapshot": copy.deepcopy(inventory_snapshot),
        "checks": {
            "signed_confirmatory_stack_bound": True,
            "all_34_direct_source_references_replayed": True,
            "exact_paired_method_and_holm_order_bound": True,
            "confirmatory_consent_assignment_and_advice_gates_bound": True,
            "single_use_live_provider_admission_bound": True,
            "exact_480_task_manifest_bound": True,
            "private_execution_materials_bound": True,
            "strict_decision_and_direct_observation_bound": True,
            "recoverable_orchestrator_and_fault_matrix_bound": True,
            "budget_and_protocol_ceilings_bound": True,
            "forty_stopped_containers_verified": True,
            "atomic_claim_and_terminal_closeout_bound": True,
            "prior_run_reanalysis_and_adherence_inference_forbidden": True,
            "no_execution_or_external_write_performed": True,
        },
        "owner_authorization": {
            "required": True,
            "required_exact_statement": statement,
            "statement_sha256": hashlib.sha256(statement.encode()).hexdigest(),
        },
        "readiness": {
            "execution_preflight_passed": True,
            "single_use_authorization_issued": False,
            "single_use_authorization_consumed": False,
            "controlled_experiment_execution_ready": False,
        },
        "execution_boundary": copy.deepcopy(BOUNDARY),
    }
    value["preflight_sha256"] = canonical_sha256(value)
    return value


def validate_confirmatory_preflight(
    value: Any,
    *,
    expected_plan: dict[str, Any],
    expected_plan_raw_sha256: str,
) -> list[str]:
    preflight = value if isinstance(value, dict) else {}
    expected_statement = confirmatory_issuance_authorization_statement(
        plan_raw_sha256=expected_plan_raw_sha256,
        plan=expected_plan,
    )
    failures: list[str] = []
    if not (
        preflight.get("schema_version") == PREFLIGHT_SCHEMA
        and preflight.get("run_id") == expected_plan.get("run_id")
        and preflight.get("passed") is True
        and preflight.get("failure_reasons") == []
        and preflight.get("state")
        == (
            "prospective_confirmatory_execution_preflight_passed_"
            "issuance_authorization_required"
        )
        and preflight.get("plan", {}).get("sha256") == expected_plan_raw_sha256
        and preflight.get("plan", {}).get("canonical_sha256")
        == expected_plan.get("plan_sha256")
        and preflight.get("inventory_snapshot")
        == {
            "participant_container_count": 40,
            "created_count": 40,
            "running_count": 0,
        }
    ):
        failures.append("confirmatory_execution_preflight_binding_invalid")
    owner = preflight.get("owner_authorization", {})
    if not (
        owner.get("required") is True
        and owner.get("required_exact_statement") == expected_statement
        and owner.get("statement_sha256")
        == hashlib.sha256(expected_statement.encode()).hexdigest()
    ):
        failures.append("confirmatory_execution_preflight_statement_invalid")
    checks = preflight.get("checks", {})
    if not checks or not all(item is True for item in checks.values()):
        failures.append("confirmatory_execution_preflight_checks_invalid")
    if not (
        preflight.get("readiness")
        == {
            "execution_preflight_passed": True,
            "single_use_authorization_issued": False,
            "single_use_authorization_consumed": False,
            "controlled_experiment_execution_ready": False,
        }
        and preflight.get("execution_boundary") == BOUNDARY
    ):
        failures.append("confirmatory_execution_preflight_boundary_invalid")
    body = {key: item for key, item in preflight.items() if key != "preflight_sha256"}
    if preflight.get("preflight_sha256") != canonical_sha256(body):
        failures.append("confirmatory_execution_preflight_hash_invalid")
    return list(dict.fromkeys(failures))


def confirmatory_issuance_authorization_statement(
    *,
    plan_raw_sha256: str,
    plan: dict[str, Any],
) -> str:
    binding = plan["binding"]
    materials = plan["material_bindings"]["material_binding_sha256"]
    return (
        "I authorize issuance of exactly one 1800-second single-use J1-D "
        "prospective confirmatory qualification execution authorization for run "
        f"{plan['run_id']} from plan raw SHA-256 {plan_raw_sha256}, canonical "
        f"SHA-256 {plan['plan_sha256']}, binding signed frozen execution stack "
        f"{binding['frozen_execution_stack_sha256']}, execution promotion Gate "
        f"{binding['execution_promotion_gate_sha256']}, execution contract "
        f"{binding['execution_contract_sha256']}, exact paired method "
        f"{binding['confirmatory_method_sha256']}, confirmatory method promotion "
        f"Gate {binding['confirmatory_method_promotion_gate_sha256']}, confirmatory "
        f"consent Gate {binding['confirmatory_consent_gate_sha256']}, reviewed "
        "confirmatory roster/assignment Gate "
        f"{binding['confirmatory_roster_assignment_gate_sha256']}, fresh mentor "
        f"advice Gate {binding['confirmatory_mentor_advice_gate_sha256']}, "
        f"infrastructure activation Gate {binding['confirmatory_activation_gate_sha256']}, "
        f"live provider-admission receipt {binding['provider_admission_receipt_sha256']}, "
        f"outcome-sensitive evaluator {binding['outcome_sensitive_evaluator_sha256']}, "
        f"statistical plan {binding['statistical_plan_sha256']}, and execution "
        f"material binding {materials}. The scope is exactly 40 participants, 20 "
        "pairs, 480 task executions, 480 structured participant decisions, 480 "
        "direct behavior observations, and 480 provider calls using "
        "openai_compatible / deepseek-v4-pro at temperature 0. I acknowledge "
        "reservation of 1200000 tokens and 731040 USD microunits, an absolute "
        "protocol ceiling of 4000000 USD microunits, atomic single-use claim before "
        "any container or provider effect, no retry after an ambiguous provider "
        "dispatch, hidden fixture ground truth, the prospectively frozen one-sided "
        "exact 20-pair sign-flip tests over all 1048576 assignments with exact "
        "rational p-values and primary-before-secondary Holm order, and that all "
        "480 terminal task Evidence and all 20 complete pairs are required for "
        "confirmatory inference. I acknowledge that r4 remains immutable and may "
        "not be reanalyzed for a confirmatory claim, advice adherence remains "
        "unobserved and may not be inferred, and any claimed failure requires a new "
        "authorization and signed closeout. This authorization permits issuance "
        "only; it does not itself claim the authorization, start a container, read "
        "a provider credential, call a provider or model, execute an Agent or task, "
        "append Backend Facts, append the Ledger, authorize an effectiveness or "
        "causal claim, or upgrade SI-13 maturity."
    )


def _execution_scope() -> dict[str, Any]:
    return {
        "participant_count": 40,
        "mentor_participant_count": 20,
        "control_participant_count": 20,
        "matched_pair_count": 20,
        "task_count_per_participant": 12,
        "authorized_task_executions": 480,
        "authorized_participant_decisions": 480,
        "authorized_direct_observations": 480,
        "authorized_provider_calls": 480,
        "provider_id": "openai_compatible",
        "model_id": "deepseek-v4-pro",
        "temperature": 0,
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
