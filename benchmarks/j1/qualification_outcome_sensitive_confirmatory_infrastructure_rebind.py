"""Prospective confirmatory J1-D infrastructure rebind contracts."""

from __future__ import annotations

import copy
import hashlib
from typing import Any

from .controlled_comparison import canonical_sha256
from .qualification_outcome_sensitive_infrastructure_rebind import (
    build_rebind_plan as build_parent_rebind_plan,
)


PLAN_SCHEMA = (
    "j1-qualification-outcome-sensitive-confirmatory-infrastructure-rebind-plan:v1"
)
REQUIRED_REVIEW_CHECKS = {
    "confirmatory_roster_assignment_reviewed",
    "confirmatory_consent_40_signature_gate_reviewed",
    "confirmatory_mentor_advice_180_signature_gate_reviewed",
    "exact_paired_method_binding_reviewed",
    "parent_activation_chain_reviewed",
    "current_complete_source_container_inventory_reviewed",
    "content_addressed_runner_image_reviewed",
    "forty_target_names_and_mounts_reviewed",
    "target_runtime_hardening_reviewed",
    "host_only_provider_and_signer_boundary_reviewed",
    "historical_container_deletion_prohibited_reviewed",
    "no_participant_or_cohort_substitution_reviewed",
    "r4_immutable_no_reanalysis_boundary_reviewed",
    "advice_adherence_unobserved_reviewed",
}
EXECUTION_BOUNDARY = {
    "candidate_preparation_only": True,
    "parent_container_mutated": False,
    "parent_container_removed": False,
    "participant_container_created": False,
    "participant_container_started": False,
    "target_directory_created": False,
    "provider_credential_read": False,
    "provider_api_call_performed": False,
    "model_invocation_performed": False,
    "agent_execution_performed": False,
    "participant_task_execution_performed": False,
    "backend_fact_append_performed": False,
    "ledger_append_performed": False,
    "execution_authorization_issued_or_consumed": False,
    "r4_reanalysis_performed": False,
    "advice_adherence_observed": False,
    "effectiveness_or_causal_claim_authorized": False,
    "si13_maturity_upgrade_authorized": False,
}


def build_rebind_plan(
    *,
    rebind_id: str,
    created_at: str,
    source_binding: dict[str, dict[str, str]],
    reviewed_roster: dict[str, Any],
    reviewed_assignment: dict[str, Any],
    signed_advice_manifest: dict[str, Any],
    parent_activation: dict[str, Any],
    observed_sources: dict[str, dict[str, Any]],
    runner_manifest: dict[str, Any],
    target_state_root: str,
    implementation: dict[str, str],
) -> dict[str, Any]:
    value = _assemble_plan(
        rebind_id=rebind_id,
        created_at=created_at,
        source_binding=source_binding,
        reviewed_roster=reviewed_roster,
        reviewed_assignment=reviewed_assignment,
        signed_advice_manifest=signed_advice_manifest,
        parent_activation=parent_activation,
        observed_sources=observed_sources,
        runner_manifest=runner_manifest,
        target_state_root=target_state_root,
        implementation=implementation,
    )
    failures = validate_rebind_plan(
        value,
        expected_source_binding=source_binding,
        reviewed_roster=reviewed_roster,
        reviewed_assignment=reviewed_assignment,
        signed_advice_manifest=signed_advice_manifest,
        parent_activation=parent_activation,
        observed_sources=observed_sources,
        runner_manifest=runner_manifest,
        expected_target_state_root=target_state_root,
        expected_implementation=implementation,
    )
    if failures:
        raise ValueError(f"confirmatory infrastructure plan invalid: {failures}")
    return value


def validate_rebind_plan(
    value: Any,
    *,
    expected_source_binding: dict[str, dict[str, str]],
    reviewed_roster: dict[str, Any],
    reviewed_assignment: dict[str, Any],
    signed_advice_manifest: dict[str, Any],
    parent_activation: dict[str, Any],
    observed_sources: dict[str, dict[str, Any]],
    runner_manifest: dict[str, Any],
    expected_target_state_root: str,
    expected_implementation: dict[str, str],
) -> list[str]:
    plan = value if isinstance(value, dict) else {}
    failures: list[str] = []
    if plan.get("schema_version") != PLAN_SCHEMA:
        failures.append("confirmatory_infrastructure_schema_invalid")
    body = {key: item for key, item in plan.items() if key != "plan_sha256"}
    if plan.get("plan_sha256") != canonical_sha256(body):
        failures.append("confirmatory_infrastructure_hash_invalid")
    expected = _assemble_plan(
        rebind_id=str(plan.get("rebind_id", "")),
        created_at=str(plan.get("created_at", "")),
        source_binding=expected_source_binding,
        reviewed_roster=reviewed_roster,
        reviewed_assignment=reviewed_assignment,
        signed_advice_manifest=signed_advice_manifest,
        parent_activation=parent_activation,
        observed_sources=observed_sources,
        runner_manifest=runner_manifest,
        target_state_root=expected_target_state_root,
        implementation=expected_implementation,
    )
    if plan != expected:
        failures.append("confirmatory_infrastructure_copy_on_write_binding_invalid")
    return list(dict.fromkeys(failures))


def approval_statement(*, plan: dict[str, Any], plan_artifact_sha256: str) -> str:
    sources = plan["source_binding"]
    return (
        "I approve for independent review only the J1-D outcome-sensitive "
        "prospective confirmatory infrastructure rebind plan artifact raw SHA-256 "
        f"{plan_artifact_sha256}, canonical SHA-256 {plan['plan_sha256']}, binding "
        f"reviewed confirmatory assignment "
        f"{sources['reviewed_assignment']['canonical_sha256']}, assignment promotion "
        f"Gate {sources['roster_assignment_gate']['canonical_sha256']}, verified "
        f"180-advice Gate {sources['mentor_advice_gate']['canonical_sha256']}, "
        f"immutable parent activation "
        f"{sources['parent_activation']['canonical_sha256']}, and content-addressed "
        f"runner image {plan['runner_image']['image_id']}. The plan covers exactly "
        "40 present stopped source containers "
        f"({plan['inventory']['parent_container_created_count']} created and "
        f"{plan['inventory']['parent_container_exited_count']} exited), 0 running "
        "source containers, and 40 absent replacement target names for the same 40 "
        "participants in 20 unchanged pairs. I acknowledge that the prospective "
        "exact paired method and 40 confirmatory consents remain bound, r4 remains "
        "immutable and may not be reanalyzed, advice adherence remains unobserved, "
        "all source containers and historical Evidence remain immutable, "
        "source-container deletion is not authorized, participant substitution and "
        "cohort reassignment are forbidden, and independent human review plus a "
        "signed promotion Gate remain required. This approval permits review only. "
        "It does not create, start, rename, or remove any container, create "
        "participant directories, read a provider credential, call a provider or "
        "model, execute an Agent or task, append Backend Facts, append the Ledger, "
        "issue or consume an execution authorization, authorize an effectiveness or "
        "causal claim, or upgrade SI-13 maturity."
    )


def target_container_name(rebind_id: str, participant_id: str) -> str:
    digest = hashlib.sha256(f"{rebind_id}:{participant_id}".encode()).hexdigest()
    return f"civitas-j1q-runner-{digest[:16]}"


def _assemble_plan(
    *,
    rebind_id: str,
    created_at: str,
    source_binding: dict[str, dict[str, str]],
    reviewed_roster: dict[str, Any],
    reviewed_assignment: dict[str, Any],
    signed_advice_manifest: dict[str, Any],
    parent_activation: dict[str, Any],
    observed_sources: dict[str, dict[str, Any]],
    runner_manifest: dict[str, Any],
    target_state_root: str,
    implementation: dict[str, str],
) -> dict[str, Any]:
    normalized_roster = copy.deepcopy(reviewed_roster)
    roster_index = {}
    for participant in normalized_roster["participants"]:
        participant["outcome_sensitive_consent_sha256"] = participant[
            "confirmatory_consent"
        ]["canonical_sha256"]
        roster_index[participant["participant_id"]] = participant
    normalized_assignment = copy.deepcopy(reviewed_assignment)
    for pair in normalized_assignment["assignments"]:
        for cohort in ("mentor", "control"):
            pair[cohort]["outcome_sensitive_consent_sha256"] = pair[cohort][
                "confirmatory_consent_sha256"
            ]
    parent = build_parent_rebind_plan(
        rebind_id=rebind_id,
        created_at=created_at,
        source_binding=source_binding,
        reviewed_roster=normalized_roster,
        reviewed_assignment=normalized_assignment,
        signed_advice_manifest=signed_advice_manifest,
        parent_activation=parent_activation,
        observed_sources=observed_sources,
        runner_manifest=runner_manifest,
        target_state_root=target_state_root,
        implementation=implementation,
    )
    method_sha256 = reviewed_assignment["assignments"][0][
        "confirmatory_method_sha256"
    ]
    for isolation in parent["isolations"]:
        participant = roster_index[isolation["participant_id"]]
        isolation["roster_entry_sha256"] = canonical_sha256(
            {
                key: item
                for key, item in participant.items()
                if key != "outcome_sensitive_consent_sha256"
            }
        )
        isolation["confirmatory_consent_sha256"] = isolation.pop(
            "outcome_sensitive_consent_sha256"
        )
        isolation["mentor_confirmatory_signed_advice_count"] = isolation.pop(
            "mentor_signed_advice_count"
        )
        isolation["confirmatory_method_sha256"] = method_sha256
        isolation["advice_adherence_observed"] = False
    parent["schema_version"] = PLAN_SCHEMA
    inventory = copy.deepcopy(parent["inventory"])
    mentor_advice_count = inventory.pop("mentor_signed_advice_count")
    parent["inventory"] = {
        **inventory,
        "mentor_confirmatory_signed_advice_count": mentor_advice_count,
        "confirmatory_consent_count": 40,
        "tasks_per_participant": 12,
        "total_decision_count": 480,
        "advice_adherence_observation_count": 0,
    }
    parent["review_contract"]["required_checks"] = sorted(REQUIRED_REVIEW_CHECKS)
    parent["review_contract"]["r4_reanalysis_allowed"] = False
    parent["review_contract"]["advice_adherence_observed"] = False
    parent["readiness"] = {
        "confirmatory_roster_assignment_reviewed": True,
        "confirmatory_participant_consents_complete": True,
        "confirmatory_mentor_advice_signatures_verified": True,
        "exact_paired_method_bound": True,
        "runner_image_offline_qualified": True,
        "parent_activation_bound": True,
        "current_source_inventory_verified": True,
        "infrastructure_rebound": False,
        "live_provider_admission_refreshed": False,
        "controlled_experiment_execution_ready": False,
    }
    parent["execution_boundary"] = copy.deepcopy(EXECUTION_BOUNDARY)
    parent["plan_sha256"] = canonical_sha256(
        {key: item for key, item in parent.items() if key != "plan_sha256"}
    )
    return parent
