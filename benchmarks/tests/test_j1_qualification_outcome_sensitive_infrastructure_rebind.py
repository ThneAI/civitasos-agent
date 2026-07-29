from __future__ import annotations

import copy

from benchmarks.j1.controlled_comparison import canonical_sha256
from benchmarks.j1.qualification_outcome_sensitive_infrastructure_rebind import (
    EXECUTION_BOUNDARY,
    approval_statement,
    build_rebind_plan,
    validate_rebind_plan,
)
from benchmarks.j1.qualification_participant_runner_image import RUNTIME_BOUNDARY


def _fixtures() -> dict:
    participants = []
    assignments = []
    containers = []
    signed_advice = []
    observed = {}
    for index in range(20):
        pair_id = f"pair-{index:02d}"
        members = {}
        for cohort in ("mentor", "control"):
            participant_id = f"{cohort}-{index:02d}"
            member = {
                "participant_id": participant_id,
                "execution_did": f"did:civ:{participant_id}",
                "outcome_sensitive_consent_sha256": f"consent-{participant_id}",
                "cohort": cohort,
            }
            members[cohort] = member
            participants.append(
                {
                    **member,
                    "pair_id": pair_id,
                    "credential_version": 1,
                }
            )
            container_name = f"parent-{participant_id}"
            container_id = f"container-{participant_id}"
            containers.append(
                {
                    "participant_id": participant_id,
                    "execution_did": member["execution_did"],
                    "pair_id": pair_id,
                    "cohort": cohort,
                    "container": {
                        "container_id": container_id,
                        "container_name": container_name,
                        "actual_container_config_sha256": f"config-{participant_id}",
                        "image_id": "sha256:image",
                    },
                }
            )
            observed[participant_id] = {
                "container_id": container_id,
                "container_name": container_name,
                "image_id": "sha256:image",
                "status": "exited",
                "running": False,
                "exit_code": 137,
                "labels_sha256": f"labels-{participant_id}",
            }
            if cohort == "mentor":
                for ordinal in range(4, 13):
                    signed_advice.append(
                        {
                            "participant_id": participant_id,
                            "pair_id": pair_id,
                            "task_id": f"task-{ordinal:02d}",
                            "task_ordinal": ordinal,
                        }
                    )
        assignments.append(
            {
                "pair_id": pair_id,
                "mentor": members["mentor"],
                "control": members["control"],
                "rebind_commitment_sha256": f"rebind-{pair_id}",
            }
        )
    runner = {
        "manifest_sha256": "runner-manifest",
        "image": {
            "image_id": "sha256:image",
            "content_addressed_reference": "sha256:image",
            "entrypoint": ["python", "-I", "/runner.py"],
            "configured_user": "65532:65532",
        },
    }
    return {
        "source_binding": {
            name: {
                "path": f"/evidence/{name}.json",
                "sha256": f"raw-{name}",
                "canonical_sha256": f"canonical-{name}",
            }
            for name in (
                "mentor_advice_gate",
                "parent_activation",
                "reviewed_assignment",
            )
        },
        "roster": {"participants": participants},
        "assignment": {"assignments": assignments},
        "advice": {"signed_advice": signed_advice},
        "activation": {"containers": containers},
        "observed": observed,
        "runner": runner,
        "target_root": "/state/outcome",
        "implementation": {
            "source_revision": "revision",
            "source_sha256": "source",
        },
    }


def _build(values: dict) -> dict:
    return build_rebind_plan(
        rebind_id="outcome-rebind-r1",
        created_at="2026-07-29T12:00:00+08:00",
        source_binding=values["source_binding"],
        reviewed_roster=values["roster"],
        reviewed_assignment=values["assignment"],
        signed_advice_manifest=values["advice"],
        parent_activation=values["activation"],
        observed_sources=values["observed"],
        runner_manifest=values["runner"],
        target_state_root=values["target_root"],
        implementation=values["implementation"],
    )


def _validate(plan: dict, values: dict) -> list[str]:
    return validate_rebind_plan(
        plan,
        expected_source_binding=values["source_binding"],
        reviewed_roster=values["roster"],
        reviewed_assignment=values["assignment"],
        signed_advice_manifest=values["advice"],
        parent_activation=values["activation"],
        observed_sources=values["observed"],
        runner_manifest=values["runner"],
        expected_target_state_root=values["target_root"],
        expected_implementation=values["implementation"],
    )


def test_builds_review_only_plan_for_complete_exited_set() -> None:
    values = _fixtures()
    plan = _build(values)

    assert _validate(plan, values) == []
    assert plan["inventory"]["participant_count"] == 40
    assert plan["inventory"]["parent_container_exited_count"] == 40
    assert plan["inventory"]["parent_container_running_count"] == 0
    assert plan["inventory"]["mentor_signed_advice_count"] == 180
    assert plan["execution_boundary"] == EXECUTION_BOUNDARY
    assert (
        len({item["target_isolation"]["container_name"] for item in plan["isolations"]})
        == 40
    )
    assert all(
        item["source_isolation"]["removal_authorized"] is False
        for item in plan["isolations"]
    )
    assert all(
        item["target_isolation"]["runtime_boundary"] == RUNTIME_BOUNDARY
        for item in plan["isolations"]
    )


def test_tampered_parent_or_target_is_rejected() -> None:
    values = _fixtures()
    plan = _build(values)
    tampered = copy.deepcopy(plan)
    tampered["isolations"][0]["source_isolation"]["parent_container_id"] = "wrong"
    tampered["isolations"][1]["target_isolation"]["runtime_boundary"][
        "network_mode"
    ] = "bridge"
    tampered["plan_sha256"] = canonical_sha256(
        {key: item for key, item in tampered.items() if key != "plan_sha256"}
    )

    failures = _validate(tampered, values)

    assert "outcome_infrastructure_parent_binding_invalid" in failures
    assert "outcome_infrastructure_target_binding_invalid" in failures


def test_approval_statement_does_not_authorize_container_effects() -> None:
    values = _fixtures()
    statement = approval_statement(
        plan=_build(values),
        plan_artifact_sha256="raw-plan",
    )

    assert "exactly 40 present exited source containers" in statement
    assert "40 absent replacement target names" in statement
    assert "source-container deletion is not authorized" in statement
    assert "does not create, start, rename, or remove any container" in statement
