from __future__ import annotations

import copy

from benchmarks.j1.controlled_comparison import canonical_sha256
from benchmarks.j1.qualification_infrastructure_rebind import (
    approval_statement,
    build_infrastructure_rebind_plan,
    validate_infrastructure_rebind_plan,
)
from benchmarks.j1.qualification_participant_runner_image import (
    ENTRYPOINT,
    RUNTIME_BOUNDARY,
)


NOW = "2026-07-23T16:00:00+08:00"
REBIN_ID = "j1d-infrastructure-rebind-r1"
SOURCE_BINDING = {"source_artifact_sha256": "a" * 64}
IMPLEMENTATION = {"source_revision": "b" * 40, "source_sha256": "c" * 64}
TARGET_ROOT = "/private/target"


def _sources() -> tuple[dict, dict, dict, list[dict], dict, dict, dict]:
    base_participants = []
    reviewed_participants = []
    assignments = []
    profiles = []
    isolation_artifacts = {}
    for pair_index in range(20):
        pair = {"pair_id": f"pair-{pair_index:02d}"}
        for cohort_index, cohort in enumerate(("mentor", "control")):
            index = pair_index * 2 + cohort_index
            participant_id = f"participant-{index:02d}"
            did = f"did:civ:qualification:{participant_id}"
            base = {
                "participant_id": participant_id,
                "execution_did": did,
                "credential_version": 1,
                "isolation_root_sha256": f"{index + 1:064x}",
            }
            base_participants.append(base)
            reviewed_participants.append(
                {
                    "participant_id": participant_id,
                    "execution_did": did,
                    "credential_version": 1,
                    "pair_id": pair["pair_id"],
                    "cohort": cohort,
                    "assignment_commitment_sha256": f"{index + 100:064x}",
                    "base_roster_entry_sha256": canonical_sha256(base),
                }
            )
            pair[cohort] = {
                "participant_id": participant_id,
                "execution_did": did,
                "cohort": cohort,
            }
            profile = {
                "participant": {
                    "participant_id": participant_id,
                    "execution_did": did,
                },
                "profile_sha256": f"{index + 200:064x}",
                "isolation": {
                    "isolation_id": f"container-{index:02d}",
                    "container_name": f"old-{index:02d}",
                    "container_config_sha256": f"{index + 300:064x}",
                },
            }
            profiles.append(profile)
            isolation_artifacts[participant_id] = {
                "path": f"/private/{participant_id}.isolation.json",
                "sha256": base["isolation_root_sha256"],
                "value": {
                    "isolation_commitment_sha256": profile["isolation"][
                        "container_config_sha256"
                    ]
                },
            }
        assignments.append(pair)
    runner = {
        "manifest_sha256": "d" * 64,
        "image": {
            "image_id": f"sha256:{'e' * 64}",
            "content_addressed_reference": f"sha256:{'e' * 64}",
            "entrypoint": ENTRYPOINT,
            "configured_user": "65532:65532",
        },
    }
    source_state = {
        "historical_count": 40,
        "present_count": 0,
        "missing_count": 40,
        "running_count": 0,
        "inventory_mode": "all_historical_containers_absent",
        "absence_does_not_rewrite_historical_evidence": True,
    }
    return (
        {"participants": reviewed_participants},
        {"assignments": assignments},
        {"participants": base_participants},
        profiles,
        isolation_artifacts,
        runner,
        source_state,
    )


def _plan() -> tuple:
    sources = _sources()
    plan = build_infrastructure_rebind_plan(
        rebind_id=REBIN_ID,
        created_at=NOW,
        source_binding=SOURCE_BINDING,
        reviewed_roster=sources[0],
        reviewed_assignment=sources[1],
        base_roster=sources[2],
        profiles=sources[3],
        isolation_artifacts=sources[4],
        runner_manifest=sources[5],
        source_container_state=sources[6],
        target_state_root=TARGET_ROOT,
        implementation=IMPLEMENTATION,
    )
    return (plan, *sources)


def test_infrastructure_rebind_binds_40_unique_non_created_targets() -> None:
    plan, roster, assignment, base, profiles, isolations, runner, state = _plan()

    assert (
        validate_infrastructure_rebind_plan(
            plan,
            expected_source_binding=SOURCE_BINDING,
            reviewed_roster=roster,
            reviewed_assignment=assignment,
            base_roster=base,
            profiles=profiles,
            isolation_artifacts=isolations,
            runner_manifest=runner,
            expected_source_container_state=state,
            expected_target_state_root=TARGET_ROOT,
            expected_implementation=IMPLEMENTATION,
        )
        == []
    )
    assert (
        len({item["target_isolation"]["container_name"] for item in plan["isolations"]})
        == 40
    )
    assert all(
        item["target_isolation"]["runtime_boundary"] == RUNTIME_BOUNDARY
        for item in plan["isolations"]
    )
    assert plan["execution_boundary"]["participant_container_created"] is False


def test_infrastructure_rebind_rejects_participant_and_image_tamper() -> None:
    plan, roster, assignment, base, profiles, isolations, runner, state = _plan()
    tampered = copy.deepcopy(plan)
    tampered["isolations"][0]["cohort"] = "control"
    tampered["isolations"][1]["target_isolation"]["image_id"] = "sha256:" + "f" * 64

    failures = validate_infrastructure_rebind_plan(
        tampered,
        expected_source_binding=SOURCE_BINDING,
        reviewed_roster=roster,
        reviewed_assignment=assignment,
        base_roster=base,
        profiles=profiles,
        isolation_artifacts=isolations,
        runner_manifest=runner,
        expected_source_container_state=state,
        expected_target_state_root=TARGET_ROOT,
        expected_implementation=IMPLEMENTATION,
    )

    assert "infrastructure_rebind_participant_binding_invalid" in failures
    assert "infrastructure_rebind_target_isolation_invalid" in failures
    assert "infrastructure_rebind_plan_hash_invalid" in failures


def test_infrastructure_rebind_approval_statement_preserves_boundary() -> None:
    plan, *_ = _plan()
    statement = approval_statement(
        plan=plan,
        plan_artifact_sha256="1" * 64,
        runner_manifest_artifact_sha256="2" * 64,
    )

    assert plan["plan_sha256"] in statement
    assert plan["runner_image"]["image_id"] in statement
    assert "0 current source containers present and 40 absent" in statement
    assert "does not create or start" in statement
