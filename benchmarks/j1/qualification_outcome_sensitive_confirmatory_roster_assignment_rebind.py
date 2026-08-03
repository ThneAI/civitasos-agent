"""Contracts for prospective confirmatory roster and assignment candidates."""

from __future__ import annotations

import copy
import hashlib
from datetime import datetime
from typing import Any

from .controlled_comparison import canonical_sha256


ROSTER_SCHEMA = (
    "j1-qualification-outcome-sensitive-confirmatory-roster-rebind-candidate:v1"
)
ASSIGNMENT_SCHEMA = (
    "j1-qualification-outcome-sensitive-confirmatory-assignment-rebind-candidate:v1"
)
PLAN_SCHEMA = (
    "j1-qualification-outcome-sensitive-confirmatory-roster-assignment-rebind-plan:v1"
)
STATUS = "review_required"
REQUIRED_REVIEW_CHECKS = [
    "confirmatory_material_promotion_gate_reviewed",
    "forty_confirmatory_participant_consent_signatures_reviewed",
    "parent_roster_and_assignment_immutability_reviewed",
    "forty_participant_identity_bindings_reviewed",
    "twenty_pair_cohort_assignments_unchanged_reviewed",
    "twelve_task_and_480_decision_scope_unchanged_reviewed",
    "exact_sign_flip_and_holm_method_binding_reviewed",
    "r4_immutable_no_reanalysis_boundary_reviewed",
    "advice_adherence_unobserved_and_advice_rebind_required_reviewed",
    "no_execution_effect_boundary_reviewed",
]
EXECUTION_BOUNDARY = {
    "candidate_generation_only": True,
    "roster_promoted": False,
    "assignment_promoted": False,
    "mentor_advice_rebound_or_signed": False,
    "infrastructure_rebound": False,
    "container_created_or_started": False,
    "provider_credential_read": False,
    "provider_api_call_performed": False,
    "model_invocation_performed": False,
    "agent_execution_performed": False,
    "backend_fact_append_performed": False,
    "ledger_append_performed": False,
    "execution_authorization_issued_or_consumed": False,
    "effectiveness_or_causal_claim_authorized": False,
    "si13_maturity_upgrade_authorized": False,
}


def build_rebound_roster(
    *,
    rebind_id: str,
    created_at: str,
    source_binding: dict[str, Any],
    reviewed_roster: dict[str, Any],
    reviewed_assignment: dict[str, Any],
    extensions: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build a copy-on-write roster bound to confirmatory consent."""
    extension_by_participant = _extension_index(extensions)
    assignment_by_participant = _assignment_index(reviewed_assignment)
    participants = []
    for base_entry in reviewed_roster["participants"]:
        participant_id = base_entry["participant_id"]
        extension_record = extension_by_participant[participant_id]
        extension = extension_record["value"]
        assignment = assignment_by_participant[participant_id]
        participants.append(
            {
                "participant_id": participant_id,
                "execution_did": base_entry["execution_did"],
                "credential_version": base_entry["credential_version"],
                "pair_id": assignment["pair_id"],
                "cohort": assignment["cohort"],
                "parent_reviewed_roster_entry_sha256": canonical_sha256(base_entry),
                "parent_reviewed_assignment_commitment_sha256": assignment[
                    "assignment_commitment_sha256"
                ],
                "parent_outcome_sensitive_consent": copy.deepcopy(
                    base_entry["outcome_sensitive_consent"]
                ),
                "confirmatory_consent": copy.deepcopy(extension_record["artifact"]),
                "confirmatory_material_binding": copy.deepcopy(
                    extension["confirmatory_material_binding"]
                ),
                "confirmatory_scope_binding": copy.deepcopy(extension["scope_binding"]),
                "runtime_binding": copy.deepcopy(base_entry["runtime_binding"]),
                "advice_adherence_observed": False,
                "model_execution_authorized": False,
            }
        )
    value = {
        "schema_version": ROSTER_SCHEMA,
        "status": STATUS,
        "rebind_id": rebind_id,
        "created_at": created_at,
        "source_binding": copy.deepcopy(source_binding),
        "parent_reviewed_roster": {
            **copy.deepcopy(source_binding["parent_reviewed_roster"]),
            "immutable_parent_evidence": True,
        },
        "confirmatory_material_binding": _material_binding(source_binding),
        "confirmatory_consent_manifest": {
            **copy.deepcopy(source_binding["signed_confirmatory_consent_manifest"]),
            "signature_count": 40,
            "prior_consent_inherited": False,
        },
        "participants": participants,
        "inventory": {
            "participant_count": 40,
            "mentor_participant_count": 20,
            "control_participant_count": 20,
            "confirmatory_consent_extension_count": 40,
            "tasks_per_participant": 12,
            "total_decision_count": 480,
        },
        "invariants": {
            "parent_roster_immutable": True,
            "participant_identity_set_unchanged": True,
            "participant_substitution_performed": False,
            "prior_consent_inherited": False,
            "task_treatment_fixture_and_decision_fields_unchanged": True,
            "r4_reanalysis_allowed": False,
            "advice_adherence_observed": False,
        },
        "execution_boundary": copy.deepcopy(EXECUTION_BOUNDARY),
    }
    value["rebound_roster_sha256"] = canonical_sha256(value)
    return value


def build_rebound_assignment(
    *,
    rebind_id: str,
    created_at: str,
    source_binding: dict[str, Any],
    reviewed_assignment: dict[str, Any],
    rebound_roster: dict[str, Any],
) -> dict[str, Any]:
    """Preserve all reviewed pairs while binding confirmatory consent."""
    roster_by_participant = {
        item["participant_id"]: item for item in rebound_roster["participants"]
    }
    method_sha256 = source_binding["frozen_confirmatory_materials"][
        "confirmatory_method"
    ]["canonical_sha256"]
    assignments = []
    for parent in reviewed_assignment["assignments"]:
        commitment = {
            "rebind_id": rebind_id,
            "pair_id": parent["pair_id"],
            "parent_reviewed_assignment_commitment_sha256": parent[
                "rebind_commitment_sha256"
            ],
            "protocol_sha256": parent["protocol_sha256"],
            "task_fixture_sha256": parent["task_fixture_sha256"],
            "confirmatory_method_sha256": method_sha256,
            "mentor": _rebound_member(
                parent["mentor"], roster_by_participant, "mentor"
            ),
            "control": _rebound_member(
                parent["control"], roster_by_participant, "control"
            ),
        }
        assignments.append(
            {
                **commitment,
                "mentor_advice_required_ordinals": copy.deepcopy(
                    parent["mentor_advice_required_ordinals"]
                ),
                "mentor_confirmatory_advice_rebound": False,
                "control_advice_projection": [],
                "advice_adherence_observed": False,
                "rebind_commitment_sha256": canonical_sha256(commitment),
            }
        )
    value = {
        "schema_version": ASSIGNMENT_SCHEMA,
        "status": STATUS,
        "rebind_id": rebind_id,
        "created_at": created_at,
        "source_binding": copy.deepcopy(source_binding),
        "parent_reviewed_assignment": {
            **copy.deepcopy(source_binding["parent_reviewed_assignment"]),
            "immutable_parent_evidence": True,
        },
        "rebound_roster_sha256": rebound_roster["rebound_roster_sha256"],
        "confirmatory_material_binding": _material_binding(source_binding),
        "method": "preserve-reviewed-pairs-with-confirmatory-rebind:v1",
        "assignments": assignments,
        "inventory": {
            "pair_count": 20,
            "participant_count": 40,
            "mentor_participant_count": 20,
            "control_participant_count": 20,
            "tasks_per_participant": 12,
            "total_decision_count": 480,
            "mentor_advice_rebind_required_count": 180,
            "control_advice_projection_count": 0,
        },
        "invariants": {
            "parent_assignment_immutable": True,
            "reviewed_pair_structure_unchanged": True,
            "cohort_reassignment_performed": False,
            "participant_substitution_performed": False,
            "task_treatment_fixture_and_decision_fields_unchanged": True,
            "baseline_mentor_advice_allowed": False,
            "control_advice_projection_remains_empty": True,
            "r4_reanalysis_allowed": False,
            "advice_adherence_observed": False,
        },
        "execution_boundary": copy.deepcopy(EXECUTION_BOUNDARY),
    }
    value["rebound_assignment_sha256"] = canonical_sha256(value)
    return value


def build_rebind_plan(
    *,
    rebind_id: str,
    created_at: str,
    source_binding: dict[str, Any],
    rebound_roster_artifact: dict[str, str],
    rebound_roster: dict[str, Any],
    rebound_assignment_artifact: dict[str, str],
    rebound_assignment: dict[str, Any],
    implementation: dict[str, str],
) -> dict[str, Any]:
    """Build the review-only plan for both candidate artifacts."""
    value = {
        "schema_version": PLAN_SCHEMA,
        "status": STATUS,
        "rebind_id": rebind_id,
        "created_at": created_at,
        "source_binding": copy.deepcopy(source_binding),
        "candidate_artifacts": {
            "rebound_roster": {
                **copy.deepcopy(rebound_roster_artifact),
                "canonical_sha256": rebound_roster["rebound_roster_sha256"],
            },
            "rebound_assignment": {
                **copy.deepcopy(rebound_assignment_artifact),
                "canonical_sha256": rebound_assignment["rebound_assignment_sha256"],
            },
        },
        "inventory": {
            "candidate_artifact_count": 2,
            "participant_count": 40,
            "pair_count": 20,
            "confirmatory_consent_extension_count": 40,
            "total_decision_count": 480,
            "mentor_advice_rebind_required_count": 180,
        },
        "required_review_checks": copy.deepcopy(REQUIRED_REVIEW_CHECKS),
        "remaining_gate_sequence": [
            "confirmatory_roster_assignment_independent_review",
            "confirmatory_roster_assignment_promotion_gate",
            "confirmatory_mentor_advice_rebind_and_signing_gate",
            "confirmatory_runner_image_and_infrastructure_rebind_gate",
            "confirmatory_live_provider_admission_gate",
            "confirmatory_execution_stack_review_and_fault_matrix_gate",
            "confirmatory_single_use_execution_authorization_gate",
        ],
        "readiness": {
            "confirmatory_materials_reviewed_frozen": True,
            "confirmatory_participant_consents_complete": True,
            "roster_rebind_candidate_complete": True,
            "assignment_rebind_candidate_complete": True,
            "roster_rebound": False,
            "assignment_rebound": False,
            "mentor_advice_rebound_or_signed": False,
            "infrastructure_rebound": False,
            "provider_admission_ready": False,
            "controlled_experiment_execution_ready": False,
        },
        "implementation": copy.deepcopy(implementation),
        "execution_boundary": copy.deepcopy(EXECUTION_BOUNDARY),
    }
    value["plan_sha256"] = canonical_sha256(value)
    return value


def validate_rebound_roster(value: Any, **inputs: Any) -> list[str]:
    expected = build_rebound_roster(**inputs)
    failures = _validate_exact(value, expected, "rebound_roster_sha256", "roster")
    roster = value if isinstance(value, dict) else {}
    participants = roster.get("participants", [])
    ids = [
        item.get("participant_id") for item in participants if isinstance(item, dict)
    ]
    cohorts = [item.get("cohort") for item in participants if isinstance(item, dict)]
    if not (
        len(participants) == 40
        and len(set(ids)) == 40
        and cohorts.count("mentor") == 20
        and cohorts.count("control") == 20
        and all(
            item.get("advice_adherence_observed") is False
            and item.get("model_execution_authorized") is False
            for item in participants
            if isinstance(item, dict)
        )
    ):
        failures.append("confirmatory_rebound_roster_inventory_invalid")
    return list(dict.fromkeys(failures))


def validate_rebound_assignment(value: Any, **inputs: Any) -> list[str]:
    expected = build_rebound_assignment(**inputs)
    failures = _validate_exact(
        value, expected, "rebound_assignment_sha256", "assignment"
    )
    assignment = value if isinstance(value, dict) else {}
    pairs = assignment.get("assignments", [])
    participant_ids = [
        pair.get(cohort, {}).get("participant_id")
        for pair in pairs
        if isinstance(pair, dict)
        for cohort in ("mentor", "control")
    ]
    if not (
        len(pairs) == 20
        and len(participant_ids) == 40
        and len(set(participant_ids)) == 40
        and all(pair.get("mentor", {}).get("cohort") == "mentor" for pair in pairs)
        and all(pair.get("control", {}).get("cohort") == "control" for pair in pairs)
        and all(pair.get("control_advice_projection") == [] for pair in pairs)
        and all(
            pair.get("mentor_confirmatory_advice_rebound") is False
            and pair.get("advice_adherence_observed") is False
            for pair in pairs
        )
    ):
        failures.append("confirmatory_rebound_assignment_inventory_invalid")
    return list(dict.fromkeys(failures))


def validate_rebind_plan(value: Any, **inputs: Any) -> list[str]:
    expected = build_rebind_plan(**inputs)
    return _validate_exact(value, expected, "plan_sha256", "rebind_plan")


def approval_statement(*, plan: dict[str, Any], plan_artifact_sha256: str) -> str:
    candidates = plan["candidate_artifacts"]
    sources = plan["source_binding"]
    return (
        "I approve for independent review only the J1-D outcome-sensitive "
        "confirmatory roster/assignment rebind plan artifact raw SHA-256 "
        f"{plan_artifact_sha256}, canonical SHA-256 {plan['plan_sha256']}, "
        f"candidate roster {candidates['rebound_roster']['canonical_sha256']}, "
        "and candidate assignment "
        f"{candidates['rebound_assignment']['canonical_sha256']}, binding the "
        "40-of-40 prospective confirmatory consent Gate raw SHA-256 "
        f"{sources['confirmatory_consent_gate']['sha256']}, canonical SHA-256 "
        f"{sources['confirmatory_consent_gate']['canonical_sha256']}, signed "
        "confirmatory material-promotion Gate "
        f"{sources['confirmatory_material_promotion_gate']['canonical_sha256']}, "
        "and parent reviewed assignment "
        f"{sources['parent_reviewed_assignment']['canonical_sha256']}. I "
        "acknowledge that independent human review and a signed promotion Gate "
        "remain required, the parent roster, assignment, 20-pair structure, "
        "prior consent, and r4 Evidence remain immutable, and 180 confirmatory "
        "mentor advice signatures, infrastructure rebind, provider admission, "
        "execution-stack review, and a new single-use execution authorization "
        "remain blocked. This approval does not promote either candidate, "
        "reanalyze r4, reassign or substitute any participant, sign or rebind "
        "mentor advice, create or start a container, read a provider credential, "
        "call a provider or model, execute an Agent or task, append Backend "
        "Facts, append the Ledger, issue or consume an execution authorization, "
        "authorize an effectiveness or causal claim, or upgrade SI-13 maturity."
    )


def raw_sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _extension_index(
    extensions: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    return {item["value"]["participant"]["participant_id"]: item for item in extensions}


def _assignment_index(
    assignment: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    result = {}
    for pair in assignment["assignments"]:
        for cohort in ("mentor", "control"):
            member = pair[cohort]
            result[member["participant_id"]] = {
                "pair_id": pair["pair_id"],
                "cohort": cohort,
                "assignment_commitment_sha256": pair["rebind_commitment_sha256"],
            }
    return result


def _rebound_member(
    member: dict[str, Any],
    roster_by_participant: dict[str, dict[str, Any]],
    cohort: str,
) -> dict[str, str]:
    roster_entry = roster_by_participant[member["participant_id"]]
    return {
        "participant_id": member["participant_id"],
        "execution_did": member["execution_did"],
        "cohort": cohort,
        "confirmatory_consent_sha256": roster_entry["confirmatory_consent"][
            "canonical_sha256"
        ],
    }


def _material_binding(source_binding: dict[str, Any]) -> dict[str, Any]:
    return {
        "material_promotion_gate": copy.deepcopy(
            source_binding["confirmatory_material_promotion_gate"]
        ),
        "frozen_review": copy.deepcopy(source_binding["frozen_confirmatory_review"]),
        "frozen_materials": copy.deepcopy(
            source_binding["frozen_confirmatory_materials"]
        ),
    }


def _validate_exact(
    value: Any,
    expected: dict[str, Any],
    hash_field: str,
    label: str,
) -> list[str]:
    actual = value if isinstance(value, dict) else {}
    failures = []
    if actual != expected:
        failures.append(f"confirmatory_{label}_copy_on_write_binding_invalid")
    body = {key: item for key, item in actual.items() if key != hash_field}
    if actual.get(hash_field) != canonical_sha256(body):
        failures.append(f"confirmatory_{label}_hash_invalid")
    if not _rfc3339(actual.get("created_at")):
        failures.append(f"confirmatory_{label}_created_at_invalid")
    return failures


def _rfc3339(value: Any) -> bool:
    if not isinstance(value, str) or not value:
        return False
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).tzinfo is not None
    except ValueError:
        return False
