"""Copy-on-write roster and cohort-assignment rebind contracts for J1-D."""

from __future__ import annotations

import copy
import hashlib
from datetime import datetime
from typing import Any

from .controlled_comparison import canonical_sha256


ROSTER_SCHEMA = "j1-qualification-roster-rebind-candidate:v1"
ASSIGNMENT_SCHEMA = "j1-qualification-cohort-assignment-rebind-candidate:v1"
PLAN_SCHEMA = "j1-qualification-roster-assignment-rebind-plan:v1"
STATUS = "review_required"
REQUIRED_REVIEW_CHECKS = [
    "amended_protocol_and_design_binding_reviewed",
    "base_roster_and_assignment_immutability_reviewed",
    "control_advice_boundary_reviewed",
    "forty_consent_extension_signatures_reviewed",
    "forty_participant_identity_bindings_reviewed",
    "no_participant_substitution_reviewed",
    "twenty_pair_cohort_assignments_unchanged_reviewed",
    "execution_boundary_reviewed",
]
EXECUTION_BOUNDARY = {
    "rebind_candidate_generation_only": True,
    "roster_promoted": False,
    "assignment_promoted": False,
    "infrastructure_rebound": False,
    "container_created": False,
    "container_started": False,
    "provider_api_call_performed": False,
    "model_invocation_performed": False,
    "agent_execution_performed": False,
    "backend_fact_append_performed": False,
    "ledger_append_performed": False,
    "execution_authorization_issued_or_consumed": False,
}


def build_rebound_roster(
    *,
    rebind_id: str,
    created_at: str,
    source_binding: dict[str, str],
    reviewed_roster: dict[str, Any],
    reviewed_assignment: dict[str, Any],
    amendment_bundle: dict[str, Any],
    protocol_amendment: dict[str, Any],
    design_amendment: dict[str, Any],
    extensions: list[dict[str, Any]],
) -> dict[str, Any]:
    extension_by_participant = _extension_index(extensions)
    assignment_by_participant = _assignment_index(reviewed_assignment)
    stack = protocol_amendment["amended_frozen_stack"]
    corpus = protocol_amendment["preserved_protocol"]["task_corpus"]
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
                "base_roster_entry_sha256": canonical_sha256(base_entry),
                "runtime_binding": {
                    "provider_id": stack["provider_id"],
                    "model_id": stack["model_id"],
                    "budget_id": stack["budget_id"],
                    "corpus_id": corpus["corpus_id"],
                    "verifier_id": stack["verifier_id"],
                    "verifier_manifest_sha256": stack["verifier_manifest_sha256"],
                },
                "assignment_commitment_sha256": assignment[
                    "assignment_commitment_sha256"
                ],
                "prior_consent": copy.deepcopy(extension["prior_consent"]),
                "consent_extension": copy.deepcopy(extension_record["artifact"]),
                "model_execution_authorized": False,
            }
        )
    value = {
        "schema_version": ROSTER_SCHEMA,
        "status": STATUS,
        "rebind_id": rebind_id,
        "created_at": created_at,
        "source_binding": copy.deepcopy(source_binding),
        "base_reviewed_roster": {
            "artifact_sha256": source_binding["reviewed_roster_artifact_sha256"],
            "canonical_sha256": reviewed_roster["roster_sha256"],
            "immutable_parent_evidence": True,
        },
        "amendment_binding": _amendment_binding(
            source_binding=source_binding,
            amendment_bundle=amendment_bundle,
            protocol_amendment=protocol_amendment,
            design_amendment=design_amendment,
        ),
        "consent_extension_manifest": {
            "artifact_sha256": source_binding[
                "signed_consent_manifest_artifact_sha256"
            ],
            "canonical_sha256": source_binding["signed_consent_manifest_sha256"],
            "signature_count": 40,
            "prior_consent_inherited": False,
        },
        "participants": participants,
        "inventory": {
            "participant_count": 40,
            "mentor_participant_count": 20,
            "control_participant_count": 20,
            "consent_extension_count": 40,
        },
        "invariants": {
            "base_roster_immutable": True,
            "participant_identity_set_unchanged": True,
            "participant_substitution_performed": False,
            "prior_consent_inherited": False,
            "all_participants_bound_to_amended_stack": True,
        },
        "execution_boundary": copy.deepcopy(EXECUTION_BOUNDARY),
    }
    value["rebound_roster_sha256"] = canonical_sha256(value)
    return value


def build_rebound_assignment(
    *,
    rebind_id: str,
    created_at: str,
    source_binding: dict[str, str],
    reviewed_assignment: dict[str, Any],
    rebound_roster: dict[str, Any],
    amendment_bundle: dict[str, Any],
    protocol_amendment: dict[str, Any],
    design_amendment: dict[str, Any],
) -> dict[str, Any]:
    roster_by_participant = {
        item["participant_id"]: item for item in rebound_roster["participants"]
    }
    assignments = []
    for base_assignment in reviewed_assignment["assignments"]:
        mentor = _rebound_member(
            base_assignment["mentor"], roster_by_participant, "mentor"
        )
        control = _rebound_member(
            base_assignment["control"], roster_by_participant, "control"
        )
        commitment_body = {
            "rebind_id": rebind_id,
            "pair_id": base_assignment["pair_id"],
            "base_assignment_commitment_sha256": base_assignment[
                "assignment_commitment_sha256"
            ],
            "amendment_bundle_sha256": amendment_bundle["bundle_sha256"],
            "protocol_amendment_sha256": protocol_amendment["amended_protocol_sha256"],
            "design_amendment_sha256": design_amendment["amended_design_sha256"],
            "mentor": mentor,
            "control": control,
        }
        assignments.append(
            {
                **commitment_body,
                "rebind_commitment_sha256": canonical_sha256(commitment_body),
            }
        )
    value = {
        "schema_version": ASSIGNMENT_SCHEMA,
        "status": STATUS,
        "rebind_id": rebind_id,
        "created_at": created_at,
        "source_binding": copy.deepcopy(source_binding),
        "base_reviewed_assignment": {
            "artifact_sha256": source_binding["reviewed_assignment_artifact_sha256"],
            "canonical_sha256": reviewed_assignment["reviewed_assignment_sha256"],
            "reviewed_pairing_sha256": reviewed_assignment["reviewed_pairing_sha256"],
            "immutable_parent_evidence": True,
        },
        "rebound_roster_sha256": rebound_roster["rebound_roster_sha256"],
        "amendment_binding": _amendment_binding(
            source_binding=source_binding,
            amendment_bundle=amendment_bundle,
            protocol_amendment=protocol_amendment,
            design_amendment=design_amendment,
        ),
        "method": "preserve-reviewed-assignment-with-amendment-rebind:v1",
        "assignments": assignments,
        "inventory": {
            "pair_count": 20,
            "participant_count": 40,
            "mentor_participant_count": 20,
            "control_participant_count": 20,
        },
        "invariants": {
            "base_assignment_immutable": True,
            "reviewed_pair_structure_unchanged": True,
            "cohort_reassignment_performed": False,
            "participant_substitution_performed": False,
            "control_advice_projection_remains_empty": True,
        },
        "execution_boundary": copy.deepcopy(EXECUTION_BOUNDARY),
    }
    value["rebound_assignment_sha256"] = canonical_sha256(value)
    return value


def build_rebind_plan(
    *,
    rebind_id: str,
    created_at: str,
    source_binding: dict[str, str],
    rebound_roster_artifact: dict[str, str],
    rebound_roster: dict[str, Any],
    rebound_assignment_artifact: dict[str, str],
    rebound_assignment: dict[str, Any],
    implementation: dict[str, str],
) -> dict[str, Any]:
    value = {
        "schema_version": PLAN_SCHEMA,
        "status": STATUS,
        "rebind_id": rebind_id,
        "created_at": created_at,
        "source_binding": copy.deepcopy(source_binding),
        "candidate_artifacts": {
            "rebound_roster": {
                **rebound_roster_artifact,
                "canonical_sha256": rebound_roster["rebound_roster_sha256"],
            },
            "rebound_assignment": {
                **rebound_assignment_artifact,
                "canonical_sha256": rebound_assignment["rebound_assignment_sha256"],
            },
        },
        "inventory": {
            "participant_count": 40,
            "pair_count": 20,
            "consent_extension_count": 40,
            "candidate_artifact_count": 2,
        },
        "required_review_checks": copy.deepcopy(REQUIRED_REVIEW_CHECKS),
        "remaining_gate_sequence": [
            "roster_and_assignment_rebind_independent_review",
            "roster_and_assignment_rebind_gate",
            "runner_and_infrastructure_rebind_gate",
            "live_provider_admission_refresh_gate",
            "no_provider_execution_preflight",
            "single_use_execution_authorization_gate",
        ],
        "readiness": {
            "participant_consent_extensions_complete": True,
            "roster_rebind_candidate_complete": True,
            "assignment_rebind_candidate_complete": True,
            "roster_rebound": False,
            "assignment_rebound": False,
            "infrastructure_rebound": False,
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
            item.get("model_execution_authorized") is False for item in participants
        )
    ):
        failures.append("rebound_roster_inventory_invalid")
    return list(dict.fromkeys(failures))


def validate_rebound_assignment(value: Any, **inputs: Any) -> list[str]:
    expected = build_rebound_assignment(**inputs)
    failures = _validate_exact(
        value, expected, "rebound_assignment_sha256", "assignment"
    )
    assignment = value if isinstance(value, dict) else {}
    pairs = assignment.get("assignments", [])
    participants = [
        member.get("participant_id")
        for pair in pairs
        if isinstance(pair, dict)
        for member in (pair.get("mentor", {}), pair.get("control", {}))
    ]
    if not (
        len(pairs) == 20
        and len(participants) == 40
        and len(set(participants)) == 40
        and all(pair.get("control", {}).get("cohort") == "control" for pair in pairs)
        and all(pair.get("mentor", {}).get("cohort") == "mentor" for pair in pairs)
    ):
        failures.append("rebound_assignment_inventory_invalid")
    return list(dict.fromkeys(failures))


def validate_rebind_plan(value: Any, **inputs: Any) -> list[str]:
    expected = build_rebind_plan(**inputs)
    return _validate_exact(value, expected, "plan_sha256", "rebind_plan")


def approval_statement(
    *,
    plan: dict[str, Any],
    plan_artifact_sha256: str,
) -> str:
    candidates = plan["candidate_artifacts"]
    sources = plan["source_binding"]
    return (
        "I approve for independent review only the J1-D roster/assignment rebind "
        f"plan artifact {plan_artifact_sha256}, canonical plan "
        f"{plan['plan_sha256']}, candidate roster "
        f"{candidates['rebound_roster']['canonical_sha256']}, and candidate "
        f"assignment {candidates['rebound_assignment']['canonical_sha256']}, "
        "binding consent-extension Gate "
        f"{sources['consent_extension_gate_artifact_sha256']} and amendment bundle "
        f"{sources['amendment_bundle_sha256']}. I acknowledge that independent "
        "human review and a promotion Gate remain required, the original roster, "
        "assignment, pair structure, and prior consent remain immutable parent "
        "Evidence, and infrastructure rebind, refreshed provider admission, and a "
        "new single-use execution authorization remain blocked. This approval does "
        "not promote either candidate, reassign or substitute any participant, "
        "authorize provider or model calls, execute any Agent or container, append "
        "Backend Facts, append the Ledger, or issue or consume an execution "
        "authorization."
    )


def _extension_index(extensions: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {item["value"]["participant"]["participant_id"]: item for item in extensions}


def _assignment_index(assignment: dict[str, Any]) -> dict[str, dict[str, Any]]:
    result = {}
    for pair in assignment["assignments"]:
        for cohort in ("mentor", "control"):
            member = pair[cohort]
            result[member["participant_id"]] = {
                "pair_id": pair["pair_id"],
                "cohort": cohort,
                "assignment_commitment_sha256": pair["assignment_commitment_sha256"],
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
        "consent_extension_sha256": roster_entry["consent_extension"][
            "canonical_sha256"
        ],
    }


def _amendment_binding(
    *,
    source_binding: dict[str, str],
    amendment_bundle: dict[str, Any],
    protocol_amendment: dict[str, Any],
    design_amendment: dict[str, Any],
) -> dict[str, str]:
    return {
        "amendment_bundle_artifact_sha256": source_binding[
            "amendment_bundle_artifact_sha256"
        ],
        "amendment_bundle_sha256": amendment_bundle["bundle_sha256"],
        "protocol_amendment_sha256": protocol_amendment["amended_protocol_sha256"],
        "design_amendment_sha256": design_amendment["amended_design_sha256"],
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
        failures.append(f"{label}_copy_on_write_binding_invalid")
    body = {key: item for key, item in actual.items() if key != hash_field}
    if actual.get(hash_field) != canonical_sha256(body):
        failures.append(f"{label}_hash_invalid")
    if not _rfc3339(actual.get("created_at")):
        failures.append(f"{label}_created_at_invalid")
    return failures


def _rfc3339(value: Any) -> bool:
    if not isinstance(value, str) or not value:
        return False
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).tzinfo is not None
    except ValueError:
        return False


def raw_sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()
