from __future__ import annotations

import copy

from benchmarks.j1.qualification_outcome_sensitive_confirmatory_roster_assignment_rebind import (
    approval_statement,
    build_rebind_plan,
    build_rebound_assignment,
    build_rebound_roster,
    validate_rebind_plan,
    validate_rebound_assignment,
    validate_rebound_roster,
)


NOW = "2026-08-04T08:00:00+08:00"
REBIND_ID = "j1d-confirmatory-roster-assignment-rebind-r1"
IMPLEMENTATION = {"source_revision": "a" * 40, "source_sha256": "b" * 64}


def _ref(index: int) -> dict[str, str]:
    return {
        "path": f"/private/artifact-{index}.json",
        "sha256": f"{index:064x}",
        "canonical_sha256": f"{index + 100:064x}",
    }


def _sources() -> tuple[dict, dict, list[dict], dict]:
    binding = {
        "confirmatory_material_promotion_gate": _ref(1),
        "frozen_confirmatory_review": _ref(2),
        "frozen_confirmatory_materials": {
            name: _ref(index)
            for index, name in enumerate(
                (
                    "confirmatory_method",
                    "consent_impact",
                    "evaluator_addendum",
                    "protocol_addendum",
                    "verification",
                ),
                start=10,
            )
        },
        "confirmatory_consent_plan": _ref(20),
        "confirmatory_consent_preflight": _ref(21),
        "signed_confirmatory_consent_manifest": _ref(22),
        "confirmatory_consent_signing_operation": _ref(23),
        "confirmatory_consent_gate": _ref(24),
        "parent_reviewed_roster": _ref(25),
        "parent_reviewed_assignment": _ref(26),
        "parent_assignment_gate": _ref(27),
    }
    participants = []
    assignments = []
    extensions = []
    for pair_index in range(20):
        members = {}
        for cohort_index, cohort in enumerate(("mentor", "control")):
            index = pair_index * 2 + cohort_index
            participant_id = f"participant-{index:02d}"
            execution_did = f"did:civ:qualification:participant-{index:02d}"
            prior_consent = _ref(1000 + index)
            participants.append(
                {
                    "participant_id": participant_id,
                    "execution_did": execution_did,
                    "credential_version": 1,
                    "pair_id": f"pair-{pair_index:02d}",
                    "cohort": cohort,
                    "outcome_sensitive_consent": prior_consent,
                    "runtime_binding": {
                        "provider_id": "openai_compatible",
                        "model_id": "deepseek-v4-pro",
                        "temperature": 0,
                        "protocol_sha256": "d" * 64,
                        "task_fixture_sha256": "e" * 64,
                        "statistical_plan_sha256": "f" * 64,
                    },
                }
            )
            members[cohort] = {
                "participant_id": participant_id,
                "execution_did": execution_did,
                "cohort": cohort,
                "outcome_sensitive_consent_sha256": prior_consent["canonical_sha256"],
            }
            extension = {
                "participant": {
                    "participant_id": participant_id,
                    "execution_did": execution_did,
                    "credential_version": 1,
                },
                "cohort_binding": {
                    "pair_id": f"pair-{pair_index:02d}",
                    "cohort": cohort,
                },
                "confirmatory_material_binding": {
                    "promotion_gate_sha256": "a" * 64,
                    "frozen_review_sha256": "b" * 64,
                    "frozen_materials": {},
                },
                "scope_binding": {
                    "consent_scope_sha256": "c" * 64,
                },
                "extension_sha256": f"{index + 400:064x}",
            }
            extensions.append(
                {
                    "artifact": {
                        "path": f"/private/{participant_id}.json",
                        "sha256": f"{index + 500:064x}",
                        "canonical_sha256": extension["extension_sha256"],
                    },
                    "value": extension,
                }
            )
        assignments.append(
            {
                "pair_id": f"pair-{pair_index:02d}",
                "protocol_sha256": "d" * 64,
                "task_fixture_sha256": "e" * 64,
                "mentor_advice_required_ordinals": list(range(4, 13)),
                "rebind_commitment_sha256": f"{pair_index + 600:064x}",
                **members,
            }
        )
    return (
        {"participants": participants},
        {"assignments": assignments},
        extensions,
        binding,
    )


def _candidates() -> tuple[dict, dict, dict]:
    roster, assignment, extensions, binding = _sources()
    rebound_roster = build_rebound_roster(
        rebind_id=REBIND_ID,
        created_at=NOW,
        source_binding=binding,
        reviewed_roster=roster,
        reviewed_assignment=assignment,
        extensions=extensions,
    )
    rebound_assignment = build_rebound_assignment(
        rebind_id=REBIND_ID,
        created_at=NOW,
        source_binding=binding,
        reviewed_assignment=assignment,
        rebound_roster=rebound_roster,
    )
    plan = build_rebind_plan(
        rebind_id=REBIND_ID,
        created_at=NOW,
        source_binding=binding,
        rebound_roster_artifact={
            "path": "/private/roster.json",
            "sha256": "1" * 64,
        },
        rebound_roster=rebound_roster,
        rebound_assignment_artifact={
            "path": "/private/assignment.json",
            "sha256": "2" * 64,
        },
        rebound_assignment=rebound_assignment,
        implementation=IMPLEMENTATION,
    )
    return rebound_roster, rebound_assignment, plan


def test_rebind_preserves_identity_pairs_and_confirmatory_scope() -> None:
    rebound_roster, rebound_assignment, plan = _candidates()
    roster, assignment, extensions, binding = _sources()
    assert (
        validate_rebound_roster(
            rebound_roster,
            rebind_id=REBIND_ID,
            created_at=NOW,
            source_binding=binding,
            reviewed_roster=roster,
            reviewed_assignment=assignment,
            extensions=extensions,
        )
        == []
    )
    assert (
        validate_rebound_assignment(
            rebound_assignment,
            rebind_id=REBIND_ID,
            created_at=NOW,
            source_binding=binding,
            reviewed_assignment=assignment,
            rebound_roster=rebound_roster,
        )
        == []
    )
    assert (
        validate_rebind_plan(
            plan,
            rebind_id=REBIND_ID,
            created_at=NOW,
            source_binding=binding,
            rebound_roster_artifact={
                "path": "/private/roster.json",
                "sha256": "1" * 64,
            },
            rebound_roster=rebound_roster,
            rebound_assignment_artifact={
                "path": "/private/assignment.json",
                "sha256": "2" * 64,
            },
            rebound_assignment=rebound_assignment,
            implementation=IMPLEMENTATION,
        )
        == []
    )
    assert rebound_roster["inventory"]["total_decision_count"] == 480
    assert rebound_assignment["inventory"]["mentor_advice_rebind_required_count"] == 180
    assert plan["readiness"]["assignment_rebound"] is False
    assert plan["execution_boundary"]["provider_api_call_performed"] is False


def test_assignment_rejects_control_projection_or_advice_rebind() -> None:
    rebound_roster, rebound_assignment, _ = _candidates()
    _, assignment, _, binding = _sources()
    changed = copy.deepcopy(rebound_assignment)
    changed["assignments"][0]["control_advice_projection"] = ["advice"]
    changed["assignments"][0]["mentor_confirmatory_advice_rebound"] = True

    failures = validate_rebound_assignment(
        changed,
        rebind_id=REBIND_ID,
        created_at=NOW,
        source_binding=binding,
        reviewed_assignment=assignment,
        rebound_roster=rebound_roster,
    )

    assert "confirmatory_assignment_copy_on_write_binding_invalid" in failures
    assert "confirmatory_assignment_hash_invalid" in failures
    assert "confirmatory_rebound_assignment_inventory_invalid" in failures


def test_roster_rejects_execution_or_adherence_claim() -> None:
    rebound_roster, _, _ = _candidates()
    roster, assignment, extensions, binding = _sources()
    changed = copy.deepcopy(rebound_roster)
    changed["participants"][0]["model_execution_authorized"] = True
    changed["participants"][0]["advice_adherence_observed"] = True

    failures = validate_rebound_roster(
        changed,
        rebind_id=REBIND_ID,
        created_at=NOW,
        source_binding=binding,
        reviewed_roster=roster,
        reviewed_assignment=assignment,
        extensions=extensions,
    )

    assert "confirmatory_roster_copy_on_write_binding_invalid" in failures
    assert "confirmatory_roster_hash_invalid" in failures
    assert "confirmatory_rebound_roster_inventory_invalid" in failures


def test_owner_statement_binds_candidates_and_review_only_boundary() -> None:
    _, _, plan = _candidates()
    statement = approval_statement(plan=plan, plan_artifact_sha256="0" * 64)

    assert plan["plan_sha256"] in statement
    assert (
        plan["candidate_artifacts"]["rebound_roster"]["canonical_sha256"] in statement
    )
    assert (
        plan["candidate_artifacts"]["rebound_assignment"]["canonical_sha256"]
        in statement
    )
    assert (
        plan["source_binding"]["confirmatory_consent_gate"]["canonical_sha256"]
        in statement
    )
    assert "does not promote either candidate" in statement
    assert "does not" in statement
    assert "reanalyze r4" in statement
    assert "upgrade SI-13 maturity" in statement
