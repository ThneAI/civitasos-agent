"""Authorization preflight for the frozen outcome-sensitive execution stack."""

from __future__ import annotations

import copy
import hashlib
from datetime import datetime
from typing import Any

from .controlled_comparison import canonical_sha256
from .qualification_outcome_sensitive_execution_materials import (
    validate_material_bindings,
)


PLAN_SCHEMA = "j1-qualification-outcome-sensitive-execution-plan:v1"
PREFLIGHT_SCHEMA = "j1-qualification-outcome-sensitive-execution-preflight:v1"
TTL_SECONDS = 1800
SOURCE_NAMES = {
    "activation",
    "activation_gate",
    "assignment",
    "consent_gate",
    "evaluator",
    "execution_contract",
    "frozen_execution_stack",
    "mentor_advice_gate",
    "promotion_gate",
    "protocol",
    "provider_admission_gate",
    "provider_admission_receipt",
    "roster",
    "signed_advice_manifest",
    "statistical_plan",
    "task_fixture",
}
BOUNDARY = {
    "outcome_sensitive_execution_preflight_only": True,
    "execution_authorization_issued_or_consumed": False,
    "participant_container_started": False,
    "provider_credential_read": False,
    "provider_api_call_performed": False,
    "model_invocation_performed": False,
    "agent_or_task_execution_performed": False,
    "participant_signature_performed": False,
    "backend_fact_append_performed": False,
    "ledger_append_performed": False,
    "effectiveness_claim_authorized": False,
    "si13_maturity_upgrade_authorized": False,
}


def build_execution_plan(
    *,
    run_id: str,
    created_at: str,
    source_artifacts: dict[str, dict[str, str]],
    frozen_stack_sha256: str,
    contract_sha256: str,
    provider_receipt_sha256: str,
    evaluator_sha256: str,
    statistical_plan_sha256: str,
    material_bindings: dict[str, Any],
    paths: dict[str, str],
    implementation: dict[str, str],
) -> dict[str, Any]:
    value = {
        "schema_version": PLAN_SCHEMA,
        "run_id": run_id,
        "status": "owner_authorization_required",
        "created_at": created_at,
        "ttl_seconds": TTL_SECONDS,
        "source_artifacts": copy.deepcopy(source_artifacts),
        "binding": {
            "frozen_execution_stack_sha256": frozen_stack_sha256,
            "execution_contract_sha256": contract_sha256,
            "provider_admission_receipt_sha256": provider_receipt_sha256,
            "outcome_sensitive_evaluator_sha256": evaluator_sha256,
            "statistical_plan_sha256": statistical_plan_sha256,
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
            "post_run_receipt_required": True,
            "outcome_sensitive_evaluation_required": True,
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
    failures = validate_execution_plan(value)
    if failures:
        raise ValueError(
            f"outcome-sensitive execution plan invalid: {failures}"
        )
    return value


def validate_execution_plan(value: Any) -> list[str]:
    plan = value if isinstance(value, dict) else {}
    failures: list[str] = []
    if not (
        plan.get("schema_version") == PLAN_SCHEMA
        and plan.get("status") == "owner_authorization_required"
        and _text(plan.get("run_id"))
        and _rfc3339(plan.get("created_at"))
        and plan.get("ttl_seconds") == TTL_SECONDS
        and set(plan.get("source_artifacts", {})) == SOURCE_NAMES
        and all(_artifact_ref(item) for item in plan["source_artifacts"].values())
        and not validate_material_bindings(plan.get("material_bindings"))
    ):
        failures.append("outcome_execution_plan_identity_or_sources_invalid")
    binding = plan.get("binding", {})
    if not (
        set(binding)
        == {
            "frozen_execution_stack_sha256",
            "execution_contract_sha256",
            "provider_admission_receipt_sha256",
            "outcome_sensitive_evaluator_sha256",
            "statistical_plan_sha256",
        }
        and all(_sha256(item) for item in binding.values())
    ):
        failures.append("outcome_execution_plan_binding_invalid")
    if plan.get("execution_scope") != {
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
    }:
        failures.append("outcome_execution_plan_scope_invalid")
    budget = plan.get("budget", {})
    if not (
        budget.get("aggregate_reserved_tokens") == 1_200_000
        and budget.get("aggregate_reserved_cost_microunits") == 731_040
        and budget.get("aggregate_protocol_max_cost_microunits") == 4_000_000
        and budget.get("provider_outcome_unknown_retains_full_reservation") is True
        and budget.get("overrun_fail_stop_required") is True
    ):
        failures.append("outcome_execution_plan_budget_invalid")
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
        and controls.get("successful_closeout_implementation_review_required")
        is True
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
        failures.append("outcome_execution_plan_controls_or_boundary_invalid")
    body = {key: item for key, item in plan.items() if key != "plan_sha256"}
    if plan.get("plan_sha256") != canonical_sha256(body):
        failures.append("outcome_execution_plan_hash_invalid")
    return list(dict.fromkeys(failures))


def build_preflight(
    *,
    plan_path: str,
    plan_raw_sha256: str,
    plan: dict[str, Any],
    created_at: str,
    inventory_snapshot: dict[str, Any],
) -> dict[str, Any]:
    statement = issuance_authorization_statement(
        plan_raw_sha256=plan_raw_sha256,
        plan=plan,
    )
    value = {
        "schema_version": PREFLIGHT_SCHEMA,
        "run_id": plan["run_id"],
        "passed": True,
        "failure_reasons": [],
        "state": (
            "outcome_sensitive_execution_preflight_passed_"
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
            "reviewed_outcome_sensitive_stack_bound": True,
            "live_provider_admission_bound": True,
            "outcome_evaluator_and_statistical_plan_bound": True,
            "exact_480_task_manifest_bound": True,
            "private_execution_materials_bound": True,
            "strict_decision_and_direct_observation_bound": True,
            "recoverable_orchestrator_and_fault_matrix_bound": True,
            "budget_and_protocol_ceilings_bound": True,
            "forty_stopped_containers_verified": True,
            "atomic_claim_and_terminal_closeout_bound": True,
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


def issuance_authorization_statement(
    *,
    plan_raw_sha256: str,
    plan: dict[str, Any],
) -> str:
    binding = plan["binding"]
    materials = plan["material_bindings"]["material_binding_sha256"]
    return (
        "I authorize issuance of exactly one 1800-second single-use J1-D "
        "outcome-sensitive qualification execution authorization for run "
        f"{plan['run_id']} from plan raw SHA-256 {plan_raw_sha256}, canonical "
        f"SHA-256 {plan['plan_sha256']}, binding frozen execution stack "
        f"{binding['frozen_execution_stack_sha256']}, execution contract "
        f"{binding['execution_contract_sha256']}, live provider-admission receipt "
        f"{binding['provider_admission_receipt_sha256']}, outcome-sensitive "
        f"evaluator {binding['outcome_sensitive_evaluator_sha256']}, statistical "
        f"plan {binding['statistical_plan_sha256']}, and execution material binding "
        f"{materials}. The scope is exactly 40 participants, 20 pairs, 480 task "
        "executions, 480 structured participant decisions, 480 direct behavior "
        "observations, and 480 provider calls using openai_compatible / "
        "deepseek-v4-pro at temperature 0. I acknowledge reservation of 1200000 "
        "tokens and 731040 USD microunits, an absolute protocol ceiling of 4000000 "
        "USD microunits, atomic single-use claim before any container or provider "
        "effect, no retry after an ambiguous provider dispatch, hidden fixture "
        "ground truth, and that any claimed failure requires a new authorization "
        "and signed closeout. This authorization permits issuance only; it does not "
        "itself claim the authorization, start a container, read a provider "
        "credential, call a provider or model, execute an Agent or task, append "
        "Backend Facts, append the Ledger, authorize an effectiveness claim, or "
        "upgrade SI-13 maturity."
    )


def _artifact_ref(value: Any) -> bool:
    item = value if isinstance(value, dict) else {}
    return (
        set(item) == {"path", "sha256", "canonical_sha256"}
        and str(item.get("path", "")).startswith("/")
        and all(
            _sha256(item.get(field))
            for field in ("sha256", "canonical_sha256")
        )
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
