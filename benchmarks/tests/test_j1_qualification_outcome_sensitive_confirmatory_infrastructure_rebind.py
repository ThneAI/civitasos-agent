from __future__ import annotations

import copy

from benchmarks.j1.controlled_comparison import canonical_sha256
from benchmarks.j1.qualification_outcome_sensitive_confirmatory_infrastructure_rebind import (
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
            consent = f"confirmatory-consent-{participant_id}"
            member = {
                "participant_id": participant_id,
                "execution_did": f"did:civ:{participant_id}",
                "confirmatory_consent_sha256": consent,
                "cohort": cohort,
            }
            members[cohort] = member
            participants.append(
                {
                    "participant_id": participant_id,
                    "execution_did": member["execution_did"],
                    "pair_id": pair_id,
                    "cohort": cohort,
                    "credential_version": 1,
                    "confirmatory_consent": {
                        "path": f"/evidence/{participant_id}.json",
                        "sha256": f"raw-{participant_id}",
                        "canonical_sha256": consent,
                    },
                    "advice_adherence_observed": False,
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
                "exit_code": 0,
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
                            "confirmatory_consent_sha256": consent,
                        }
                    )
        assignments.append(
            {
                "pair_id": pair_id,
                "mentor": members["mentor"],
                "control": members["control"],
                "rebind_commitment_sha256": f"rebind-{pair_id}",
                "confirmatory_method_sha256": "exact-method",
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
                "roster_assignment_gate",
            )
        },
        "roster": {"participants": participants},
        "assignment": {"assignments": assignments},
        "advice": {"signed_advice": signed_advice},
        "activation": {"containers": containers},
        "observed": observed,
        "runner": runner,
        "target_root": "/state/confirmatory",
        "implementation": {
            "source_revision": "revision",
            "source_sha256": "source",
        },
    }


def _build(values: dict) -> dict:
    return build_rebind_plan(
        rebind_id="confirmatory-infrastructure-r1",
        created_at="2026-08-04T12:00:00+08:00",
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


def test_builds_confirmatory_review_only_plan() -> None:
    values = _fixtures()
    plan = _build(values)

    assert _validate(plan, values) == []
    assert plan["inventory"]["participant_count"] == 40
    assert plan["inventory"]["parent_container_exited_count"] == 40
    assert plan["inventory"]["mentor_confirmatory_signed_advice_count"] == 180
    assert "mentor_signed_advice_count" not in plan["inventory"]
    assert plan["inventory"]["confirmatory_consent_count"] == 40
    assert plan["inventory"]["total_decision_count"] == 480
    assert plan["execution_boundary"] == EXECUTION_BOUNDARY
    assert all(
        item["confirmatory_method_sha256"] == "exact-method"
        and item["advice_adherence_observed"] is False
        and item["target_isolation"]["runtime_boundary"] == RUNTIME_BOUNDARY
        for item in plan["isolations"]
    )


def test_tampered_confirmatory_binding_is_rejected() -> None:
    values = _fixtures()
    tampered = copy.deepcopy(_build(values))
    tampered["isolations"][0]["confirmatory_consent_sha256"] = "wrong"
    tampered["plan_sha256"] = canonical_sha256(
        {key: item for key, item in tampered.items() if key != "plan_sha256"}
    )

    assert "confirmatory_infrastructure_copy_on_write_binding_invalid" in _validate(
        tampered, values
    )


def test_approval_statement_preserves_no_effect_boundary() -> None:
    values = _fixtures()
    statement = approval_statement(
        plan=_build(values),
        plan_artifact_sha256="raw-plan",
    )

    assert "prospective confirmatory infrastructure rebind" in statement
    assert "40 present stopped source containers" in statement
    assert "r4 remains immutable and may not be reanalyzed" in statement
    assert "source-container deletion is not authorized" in statement
    assert "does not create, start, rename, or remove any container" in statement
