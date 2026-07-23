"""Copy-on-write infrastructure rebind plan for J1-D participants."""

from __future__ import annotations

import copy
import hashlib
from typing import Any

from .controlled_comparison import canonical_sha256
from .qualification_participant_runner_image import RUNTIME_BOUNDARY


PLAN_SCHEMA = "j1-qualification-infrastructure-rebind-plan:v1"
EXECUTION_BOUNDARY = {
    "candidate_preparation_only": True,
    "runner_image_built": True,
    "participant_isolation_rebound": False,
    "participant_container_created": False,
    "participant_container_started": False,
    "provider_api_call_performed": False,
    "model_invocation_performed": False,
    "agent_execution_performed": False,
    "backend_fact_append_performed": False,
    "ledger_append_performed": False,
    "execution_authorization_issued_or_consumed": False,
}
REQUIRED_REVIEW_CHECKS = {
    "content_addressed_runner_image_reviewed",
    "forty_participant_identity_bindings_reviewed",
    "historical_isolation_evidence_reviewed",
    "current_source_container_inventory_reviewed",
    "target_container_names_and_mounts_reviewed",
    "target_runtime_hardening_reviewed",
    "host_only_provider_and_signer_boundary_reviewed",
    "no_participant_or_cohort_reassignment_reviewed",
}


def build_infrastructure_rebind_plan(
    *,
    rebind_id: str,
    created_at: str,
    source_binding: dict[str, str],
    reviewed_roster: dict[str, Any],
    reviewed_assignment: dict[str, Any],
    base_roster: dict[str, Any],
    profiles: list[dict[str, Any]],
    isolation_artifacts: dict[str, dict[str, Any]],
    runner_manifest: dict[str, Any],
    source_container_state: dict[str, Any],
    target_state_root: str,
    implementation: dict[str, str],
) -> dict[str, Any]:
    base_index = {item["participant_id"]: item for item in base_roster["participants"]}
    profile_index = {item["participant"]["participant_id"]: item for item in profiles}
    assignment_index = {
        member["participant_id"]: (pair, cohort)
        for pair in reviewed_assignment["assignments"]
        for cohort in ("mentor", "control")
        for member in [pair[cohort]]
    }
    isolations = []
    for participant in sorted(
        reviewed_roster["participants"], key=lambda item: item["participant_id"]
    ):
        participant_id = participant["participant_id"]
        pair, cohort = assignment_index[participant_id]
        profile = profile_index[participant_id]
        historical = isolation_artifacts[participant_id]
        target_name = _target_name(rebind_id, participant_id)
        target = {
            "container_name": target_name,
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
                "assignment_commitment_sha256": participant[
                    "assignment_commitment_sha256"
                ],
                "base_roster_entry_sha256": canonical_sha256(
                    base_index[participant_id]
                ),
                "participant_profile_sha256": profile["profile_sha256"],
                "source_isolation": {
                    "artifact_path": historical["path"],
                    "artifact_sha256": historical["sha256"],
                    "isolation_commitment_sha256": historical["value"][
                        "isolation_commitment_sha256"
                    ],
                    "historical_container_id": profile["isolation"]["isolation_id"],
                    "historical_container_name": profile["isolation"]["container_name"],
                    "historical_container_config_sha256": profile["isolation"][
                        "container_config_sha256"
                    ],
                    "immutable_parent_evidence": True,
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
            "historical_isolation_artifact_count": 40,
            "replacement_candidate_count": 40,
        },
        "source_container_state": copy.deepcopy(source_container_state),
        "isolations": isolations,
        "review_contract": {
            "required_checks": sorted(REQUIRED_REVIEW_CHECKS),
            "independent_human_review_required": True,
            "copy_on_write_promotion_required": True,
            "participant_substitution_allowed": False,
            "cohort_reassignment_allowed": False,
            "container_creation_allowed_before_promotion": False,
        },
        "readiness": {
            "runner_image_offline_qualified": True,
            "roster_rebound": True,
            "assignment_rebound": True,
            "infrastructure_rebound": False,
            "live_provider_admission_refreshed": False,
            "controlled_experiment_execution_ready": False,
        },
        "implementation": copy.deepcopy(implementation),
        "execution_boundary": copy.deepcopy(EXECUTION_BOUNDARY),
    }
    value["plan_sha256"] = canonical_sha256(value)
    failures = validate_infrastructure_rebind_plan(
        value,
        expected_source_binding=source_binding,
        reviewed_roster=reviewed_roster,
        reviewed_assignment=reviewed_assignment,
        base_roster=base_roster,
        profiles=profiles,
        isolation_artifacts=isolation_artifacts,
        runner_manifest=runner_manifest,
        expected_source_container_state=source_container_state,
        expected_target_state_root=target_state_root,
        expected_implementation=implementation,
    )
    if failures:
        raise ValueError(f"infrastructure rebind plan invalid: {failures}")
    return value


def validate_infrastructure_rebind_plan(
    value: Any,
    *,
    expected_source_binding: dict[str, str],
    reviewed_roster: dict[str, Any],
    reviewed_assignment: dict[str, Any],
    base_roster: dict[str, Any],
    profiles: list[dict[str, Any]],
    isolation_artifacts: dict[str, dict[str, Any]],
    runner_manifest: dict[str, Any],
    expected_source_container_state: dict[str, Any],
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
            "source_container_state",
            "isolations",
            "review_contract",
            "readiness",
            "implementation",
            "execution_boundary",
            "plan_sha256",
        },
        "infrastructure_rebind_plan_fields_invalid",
        failures,
    )
    _require(
        plan.get("schema_version") == PLAN_SCHEMA,
        "infrastructure_rebind_plan_schema_invalid",
        failures,
    )
    _require(
        _text(plan.get("rebind_id"))
        and plan.get("status") == "review_required"
        and _text(plan.get("created_at")),
        "infrastructure_rebind_plan_identity_invalid",
        failures,
    )
    _require(
        plan.get("source_binding") == expected_source_binding
        and all(_sha256(item) for item in expected_source_binding.values()),
        "infrastructure_rebind_source_binding_invalid",
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
        "infrastructure_rebind_runner_image_invalid",
        failures,
    )
    roster_index = {
        item["participant_id"]: item
        for item in reviewed_roster.get("participants", [])
        if isinstance(item, dict)
    }
    base_index = {
        item["participant_id"]: item
        for item in base_roster.get("participants", [])
        if isinstance(item, dict)
    }
    profile_index = {
        item.get("participant", {}).get("participant_id"): item
        for item in profiles
        if isinstance(item, dict)
    }
    assignment_index = {
        member.get("participant_id"): (pair, cohort)
        for pair in reviewed_assignment.get("assignments", [])
        if isinstance(pair, dict)
        for cohort in ("mentor", "control")
        for member in [pair.get(cohort, {})]
        if isinstance(member, dict)
    }
    isolations = plan.get("isolations")
    isolations = isolations if isinstance(isolations, list) else []
    seen: set[str] = set()
    names: set[str] = set()
    mentor_count = 0
    control_count = 0
    for item in isolations:
        candidate = item if isinstance(item, dict) else {}
        participant_id = candidate.get("participant_id")
        participant = roster_index.get(participant_id)
        base = base_index.get(participant_id)
        profile = profile_index.get(participant_id)
        assignment = assignment_index.get(participant_id)
        historical = isolation_artifacts.get(str(participant_id))
        if not all((participant, base, profile, assignment, historical)):
            failures.append("infrastructure_rebind_participant_source_missing")
            continue
        pair, cohort = assignment
        seen.add(participant_id)
        mentor_count += int(cohort == "mentor")
        control_count += int(cohort == "control")
        _require(
            (
                candidate.get("execution_did"),
                candidate.get("credential_version"),
                candidate.get("pair_id"),
                candidate.get("cohort"),
                candidate.get("assignment_commitment_sha256"),
                candidate.get("base_roster_entry_sha256"),
                candidate.get("participant_profile_sha256"),
            )
            == (
                participant["execution_did"],
                participant["credential_version"],
                pair["pair_id"],
                cohort,
                participant["assignment_commitment_sha256"],
                canonical_sha256(base),
                profile["profile_sha256"],
            ),
            "infrastructure_rebind_participant_binding_invalid",
            failures,
        )
        _require(
            candidate.get("source_isolation")
            == {
                "artifact_path": historical["path"],
                "artifact_sha256": historical["sha256"],
                "isolation_commitment_sha256": historical["value"][
                    "isolation_commitment_sha256"
                ],
                "historical_container_id": profile["isolation"]["isolation_id"],
                "historical_container_name": profile["isolation"]["container_name"],
                "historical_container_config_sha256": profile["isolation"][
                    "container_config_sha256"
                ],
                "immutable_parent_evidence": True,
            },
            "infrastructure_rebind_historical_isolation_invalid",
            failures,
        )
        target = candidate.get("target_isolation")
        target = target if isinstance(target, dict) else {}
        target_body = {
            key: value
            for key, value in target.items()
            if key != "container_config_sha256"
        }
        name = target.get("container_name")
        names.add(str(name or ""))
        _require(
            target_body
            == {
                "container_name": _target_name(
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
            and candidate.get("replacement_state") == "review_required_not_created",
            "infrastructure_rebind_target_isolation_invalid",
            failures,
        )
    _require(
        len(isolations) == len(seen) == len(names) == 40
        and seen == set(roster_index)
        and mentor_count == control_count == 20,
        "infrastructure_rebind_inventory_invalid",
        failures,
    )
    _require(
        plan.get("inventory")
        == {
            "participant_count": 40,
            "pair_count": 20,
            "mentor_count": 20,
            "control_count": 20,
            "historical_isolation_artifact_count": 40,
            "replacement_candidate_count": 40,
        },
        "infrastructure_rebind_declared_inventory_invalid",
        failures,
    )
    _require(
        plan.get("source_container_state") == expected_source_container_state,
        "infrastructure_rebind_source_container_state_invalid",
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
            "container_creation_allowed_before_promotion": False,
        },
        "infrastructure_rebind_review_contract_invalid",
        failures,
    )
    _require(
        plan.get("readiness")
        == {
            "runner_image_offline_qualified": True,
            "roster_rebound": True,
            "assignment_rebound": True,
            "infrastructure_rebound": False,
            "live_provider_admission_refreshed": False,
            "controlled_experiment_execution_ready": False,
        },
        "infrastructure_rebind_readiness_invalid",
        failures,
    )
    _require(
        plan.get("implementation") == expected_implementation,
        "infrastructure_rebind_implementation_invalid",
        failures,
    )
    _require(
        plan.get("execution_boundary") == EXECUTION_BOUNDARY,
        "infrastructure_rebind_execution_boundary_invalid",
        failures,
    )
    body = {key: item for key, item in plan.items() if key != "plan_sha256"}
    _require(
        plan.get("plan_sha256") == canonical_sha256(body),
        "infrastructure_rebind_plan_hash_invalid",
        failures,
    )
    return list(dict.fromkeys(failures))


def approval_statement(
    *,
    plan: dict[str, Any],
    plan_artifact_sha256: str,
    runner_manifest_artifact_sha256: str,
) -> str:
    source = plan["source_container_state"]
    return (
        "I approve for independent review only the J1-D infrastructure rebind "
        f"plan artifact {plan_artifact_sha256}, canonical plan "
        f"{plan['plan_sha256']}, binding runner image manifest artifact "
        f"{runner_manifest_artifact_sha256}, canonical manifest "
        f"{plan['runner_image']['manifest_sha256']}, and content-addressed image "
        f"{plan['runner_image']['image_id']}, covering exactly 40 participant "
        f"isolation replacement candidates with {source['present_count']} current "
        f"source containers present and {source['missing_count']} absent. I acknowledge "
        "that historical isolation Evidence remains immutable, participant or cohort "
        "substitution is forbidden, and independent human review plus a promotion Gate "
        "remain required. This approval does not create or start any participant "
        "container, refresh provider admission, authorize provider or model calls, "
        "execute any Agent, append Backend Facts, append the Ledger, or issue or consume "
        "an execution authorization."
    )


def _target_name(rebind_id: str, participant_id: str) -> str:
    digest = hashlib.sha256(f"{rebind_id}:{participant_id}".encode()).hexdigest()[:16]
    return f"civitas-j1q-runner-{digest}"


def _sha256(value: Any) -> bool:
    text = str(value or "")
    return len(text) == 64 and all(char in "0123456789abcdef" for char in text)


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _require(condition: bool, code: str, failures: list[str]) -> None:
    if not condition and code not in failures:
        failures.append(code)
