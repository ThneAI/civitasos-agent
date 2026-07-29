"""Outcome-sensitive J1-D infrastructure rebind contracts."""

from __future__ import annotations

import copy
import hashlib
from datetime import datetime
from typing import Any

from .controlled_comparison import canonical_sha256
from .qualification_participant_runner_image import RUNTIME_BOUNDARY


PLAN_SCHEMA = "j1-qualification-outcome-sensitive-infrastructure-rebind-plan:v1"
REQUIRED_REVIEW_CHECKS = {
    "outcome_sensitive_roster_assignment_reviewed",
    "mentor_advice_180_signature_gate_reviewed",
    "parent_activation_chain_reviewed",
    "current_complete_source_container_inventory_reviewed",
    "content_addressed_runner_image_reviewed",
    "forty_target_names_and_mounts_reviewed",
    "target_runtime_hardening_reviewed",
    "host_only_provider_and_signer_boundary_reviewed",
    "historical_container_deletion_prohibited_reviewed",
    "no_participant_or_cohort_substitution_reviewed",
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
    "effectiveness_claim_authorized": False,
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
    roster = {item["participant_id"]: item for item in reviewed_roster["participants"]}
    assignments = {
        member["participant_id"]: (pair, cohort)
        for pair in reviewed_assignment["assignments"]
        for cohort in ("mentor", "control")
        for member in [pair[cohort]]
    }
    advice_counts: dict[str, int] = {}
    for item in signed_advice_manifest["signed_advice"]:
        participant_id = item["participant_id"]
        advice_counts[participant_id] = advice_counts.get(participant_id, 0) + 1
    parents = {item["participant_id"]: item for item in parent_activation["containers"]}
    isolations = []
    for participant_id in sorted(roster):
        participant = roster[participant_id]
        pair, cohort = assignments[participant_id]
        parent = parents[participant_id]
        target = {
            "container_name": target_container_name(rebind_id, participant_id),
            "image_id": runner_manifest["image"]["image_id"],
            "content_addressed_image": runner_manifest["image"][
                "content_addressed_reference"
            ],
            "entrypoint": copy.deepcopy(runner_manifest["image"]["entrypoint"]),
            "configured_user": runner_manifest["image"]["configured_user"],
            "runtime_user": "host_uid:host_gid",
            "input_root": f"{target_state_root}/{participant_id}/input",
            "output_root": f"{target_state_root}/{participant_id}/output",
            "runtime_boundary": copy.deepcopy(RUNTIME_BOUNDARY),
        }
        target["container_config_sha256"] = canonical_sha256(target)
        isolations.append(
            {
                "participant_id": participant_id,
                "execution_did": participant["execution_did"],
                "credential_version": participant["credential_version"],
                "pair_id": pair["pair_id"],
                "cohort": cohort,
                "roster_entry_sha256": canonical_sha256(participant),
                "assignment_rebind_commitment_sha256": pair["rebind_commitment_sha256"],
                "outcome_sensitive_consent_sha256": pair[cohort][
                    "outcome_sensitive_consent_sha256"
                ],
                "mentor_signed_advice_count": advice_counts.get(participant_id, 0),
                "source_isolation": {
                    "parent_container_id": parent["container"]["container_id"],
                    "parent_container_name": parent["container"]["container_name"],
                    "parent_container_config_sha256": parent["container"][
                        "actual_container_config_sha256"
                    ],
                    "parent_image_id": parent["container"]["image_id"],
                    "observed_state": copy.deepcopy(observed_sources[participant_id]),
                    "immutable_parent_evidence": True,
                    "removal_authorized": False,
                },
                "target_isolation": target,
                "replacement_state": "review_required_not_created",
            }
        )
    value = {
        "schema_version": PLAN_SCHEMA,
        "rebind_id": rebind_id,
        "status": "review_required",
        "created_at": created_at,
        "source_binding": copy.deepcopy(source_binding),
        "runner_image": {
            "manifest_sha256": runner_manifest["manifest_sha256"],
            "image_id": runner_manifest["image"]["image_id"],
            "content_addressed_reference": runner_manifest["image"][
                "content_addressed_reference"
            ],
            "entrypoint": copy.deepcopy(runner_manifest["image"]["entrypoint"]),
        },
        "inventory": {
            "participant_count": 40,
            "pair_count": 20,
            "mentor_count": 20,
            "control_count": 20,
            "mentor_signed_advice_count": 180,
            "parent_container_count": 40,
            "parent_container_present_count": 40,
            "parent_container_exited_count": 40,
            "parent_container_running_count": 0,
            "replacement_candidate_count": 40,
            "target_name_conflict_count": 0,
        },
        "isolations": isolations,
        "review_contract": {
            "required_checks": sorted(REQUIRED_REVIEW_CHECKS),
            "independent_human_review_required": True,
            "copy_on_write_promotion_required": True,
            "participant_substitution_allowed": False,
            "cohort_reassignment_allowed": False,
            "parent_container_removal_allowed": False,
            "container_creation_allowed_before_promotion": False,
        },
        "readiness": {
            "outcome_sensitive_roster_assignment_reviewed": True,
            "mentor_advice_signatures_verified": True,
            "runner_image_offline_qualified": True,
            "parent_activation_bound": True,
            "current_source_inventory_verified": True,
            "infrastructure_rebound": False,
            "live_provider_admission_refreshed": False,
            "controlled_experiment_execution_ready": False,
        },
        "implementation": copy.deepcopy(implementation),
        "execution_boundary": copy.deepcopy(EXECUTION_BOUNDARY),
    }
    value["plan_sha256"] = canonical_sha256(value)
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
        raise ValueError(f"outcome-sensitive infrastructure plan invalid: {failures}")
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
    _require(
        set(plan)
        == {
            "schema_version",
            "rebind_id",
            "status",
            "created_at",
            "source_binding",
            "runner_image",
            "inventory",
            "isolations",
            "review_contract",
            "readiness",
            "implementation",
            "execution_boundary",
            "plan_sha256",
        },
        "outcome_infrastructure_fields_invalid",
        failures,
    )
    _require(
        plan.get("schema_version") == PLAN_SCHEMA
        and _text(plan.get("rebind_id"))
        and plan.get("status") == "review_required"
        and _rfc3339(plan.get("created_at")),
        "outcome_infrastructure_identity_invalid",
        failures,
    )
    _require(
        plan.get("source_binding") == expected_source_binding,
        "outcome_infrastructure_source_binding_invalid",
        failures,
    )
    _require(
        plan.get("runner_image")
        == {
            "manifest_sha256": runner_manifest["manifest_sha256"],
            "image_id": runner_manifest["image"]["image_id"],
            "content_addressed_reference": runner_manifest["image"][
                "content_addressed_reference"
            ],
            "entrypoint": runner_manifest["image"]["entrypoint"],
        },
        "outcome_infrastructure_runner_image_invalid",
        failures,
    )
    roster = {
        item["participant_id"]: item for item in reviewed_roster.get("participants", [])
    }
    assignments = {
        member.get("participant_id"): (pair, cohort)
        for pair in reviewed_assignment.get("assignments", [])
        for cohort in ("mentor", "control")
        for member in [pair.get(cohort, {})]
    }
    parents = {
        item["participant_id"]: item for item in parent_activation.get("containers", [])
    }
    advice_counts: dict[str, int] = {}
    for item in signed_advice_manifest.get("signed_advice", []):
        participant_id = item.get("participant_id")
        advice_counts[participant_id] = advice_counts.get(participant_id, 0) + 1
    isolations = plan.get("isolations")
    isolations = isolations if isinstance(isolations, list) else []
    seen: set[str] = set()
    names: set[str] = set()
    for item in isolations:
        participant_id = item.get("participant_id")
        participant = roster.get(participant_id)
        assignment = assignments.get(participant_id)
        parent = parents.get(participant_id)
        observed = observed_sources.get(participant_id)
        if not all((participant, assignment, parent, observed)):
            failures.append("outcome_infrastructure_participant_source_missing")
            continue
        pair, cohort = assignment
        seen.add(participant_id)
        target = item.get("target_isolation", {})
        target_body = {
            key: nested
            for key, nested in target.items()
            if key != "container_config_sha256"
        }
        names.add(str(target.get("container_name", "")))
        _require(
            item.get("execution_did") == participant["execution_did"]
            and item.get("credential_version") == participant["credential_version"]
            and item.get("pair_id") == pair["pair_id"]
            and item.get("cohort") == cohort
            and item.get("roster_entry_sha256") == canonical_sha256(participant)
            and item.get("assignment_rebind_commitment_sha256")
            == pair["rebind_commitment_sha256"]
            and item.get("outcome_sensitive_consent_sha256")
            == pair[cohort]["outcome_sensitive_consent_sha256"]
            and item.get("mentor_signed_advice_count")
            == (9 if cohort == "mentor" else 0),
            "outcome_infrastructure_participant_binding_invalid",
            failures,
        )
        _require(
            item.get("source_isolation")
            == {
                "parent_container_id": parent["container"]["container_id"],
                "parent_container_name": parent["container"]["container_name"],
                "parent_container_config_sha256": parent["container"][
                    "actual_container_config_sha256"
                ],
                "parent_image_id": parent["container"]["image_id"],
                "observed_state": observed,
                "immutable_parent_evidence": True,
                "removal_authorized": False,
            },
            "outcome_infrastructure_parent_binding_invalid",
            failures,
        )
        _require(
            target_body
            == {
                "container_name": target_container_name(
                    plan.get("rebind_id", ""), participant_id
                ),
                "image_id": runner_manifest["image"]["image_id"],
                "content_addressed_image": runner_manifest["image"][
                    "content_addressed_reference"
                ],
                "entrypoint": runner_manifest["image"]["entrypoint"],
                "configured_user": runner_manifest["image"]["configured_user"],
                "runtime_user": "host_uid:host_gid",
                "input_root": (f"{expected_target_state_root}/{participant_id}/input"),
                "output_root": (
                    f"{expected_target_state_root}/{participant_id}/output"
                ),
                "runtime_boundary": RUNTIME_BOUNDARY,
            }
            and target.get("container_config_sha256") == canonical_sha256(target_body)
            and item.get("replacement_state") == "review_required_not_created",
            "outcome_infrastructure_target_binding_invalid",
            failures,
        )
    _require(
        len(isolations) == len(seen) == len(names) == 40
        and seen == set(roster) == set(assignments) == set(parents),
        "outcome_infrastructure_isolation_inventory_invalid",
        failures,
    )
    _require(
        plan.get("inventory")
        == {
            "participant_count": 40,
            "pair_count": 20,
            "mentor_count": 20,
            "control_count": 20,
            "mentor_signed_advice_count": 180,
            "parent_container_count": 40,
            "parent_container_present_count": 40,
            "parent_container_exited_count": 40,
            "parent_container_running_count": 0,
            "replacement_candidate_count": 40,
            "target_name_conflict_count": 0,
        },
        "outcome_infrastructure_declared_inventory_invalid",
        failures,
    )
    _require(
        plan.get("review_contract")
        == {
            "required_checks": sorted(REQUIRED_REVIEW_CHECKS),
            "independent_human_review_required": True,
            "copy_on_write_promotion_required": True,
            "participant_substitution_allowed": False,
            "cohort_reassignment_allowed": False,
            "parent_container_removal_allowed": False,
            "container_creation_allowed_before_promotion": False,
        },
        "outcome_infrastructure_review_contract_invalid",
        failures,
    )
    _require(
        plan.get("readiness")
        == {
            "outcome_sensitive_roster_assignment_reviewed": True,
            "mentor_advice_signatures_verified": True,
            "runner_image_offline_qualified": True,
            "parent_activation_bound": True,
            "current_source_inventory_verified": True,
            "infrastructure_rebound": False,
            "live_provider_admission_refreshed": False,
            "controlled_experiment_execution_ready": False,
        },
        "outcome_infrastructure_readiness_invalid",
        failures,
    )
    _require(
        plan.get("implementation") == expected_implementation
        and plan.get("execution_boundary") == EXECUTION_BOUNDARY,
        "outcome_infrastructure_implementation_or_boundary_invalid",
        failures,
    )
    body = {key: item for key, item in plan.items() if key != "plan_sha256"}
    _require(
        plan.get("plan_sha256") == canonical_sha256(body),
        "outcome_infrastructure_hash_invalid",
        failures,
    )
    return list(dict.fromkeys(failures))


def approval_statement(
    *,
    plan: dict[str, Any],
    plan_artifact_sha256: str,
) -> str:
    sources = plan["source_binding"]
    return (
        "I approve for independent review only the J1-D outcome-sensitive "
        "infrastructure rebind plan artifact raw SHA-256 "
        f"{plan_artifact_sha256}, canonical SHA-256 {plan['plan_sha256']}, "
        f"binding reviewed outcome-sensitive assignment "
        f"{sources['reviewed_assignment']['canonical_sha256']}, verified 180-advice "
        f"Gate {sources['mentor_advice_gate']['canonical_sha256']}, immutable parent "
        f"activation {sources['parent_activation']['canonical_sha256']}, and "
        f"content-addressed runner image {plan['runner_image']['image_id']}. The "
        "plan covers exactly 40 present exited source containers, 0 running source "
        "containers, and 40 absent replacement target names for the same 40 "
        "participants in 20 unchanged pairs. I acknowledge that all source "
        "containers and historical Evidence remain immutable, source-container "
        "deletion is not authorized, participant substitution and cohort "
        "reassignment are forbidden, and independent human review plus a signed "
        "promotion Gate remain required. This approval permits review only. It does "
        "not create, start, rename, or remove any container, create participant "
        "directories, read a provider credential, call a provider or model, execute "
        "an Agent or task, append Backend Facts, append the Ledger, issue or consume "
        "an execution authorization, authorize an effectiveness claim, or upgrade "
        "SI-13 maturity."
    )


def target_container_name(rebind_id: str, participant_id: str) -> str:
    digest = hashlib.sha256(f"{rebind_id}:{participant_id}".encode()).hexdigest()
    return f"civitas-j1q-runner-{digest[:16]}"


def _rfc3339(value: Any) -> bool:
    if not _text(value):
        return False
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).tzinfo is not None
    except ValueError:
        return False


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _require(condition: bool, code: str, failures: list[str]) -> None:
    if not condition and code not in failures:
        failures.append(code)
