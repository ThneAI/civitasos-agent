from __future__ import annotations

import copy

from benchmarks.j1.qualification_roster_assignment_rebind import (
    approval_statement,
    build_rebind_plan,
    build_rebound_assignment,
    build_rebound_roster,
    validate_rebind_plan,
    validate_rebound_assignment,
    validate_rebound_roster,
)


NOW = "2026-07-23T10:00:00+08:00"
REBIN_ID = "j1d-rebind-r1"
IMPLEMENTATION = {"source_revision": "a" * 40, "source_sha256": "b" * 64}


def _sources() -> tuple[dict, dict, dict, dict, dict, list[dict], dict]:
    source_binding = {
        "reviewed_roster_artifact_sha256": "1" * 64,
        "reviewed_assignment_artifact_sha256": "2" * 64,
        "amendment_bundle_artifact_sha256": "3" * 64,
        "amendment_bundle_sha256": "a" * 64,
        "consent_extension_gate_artifact_sha256": "4" * 64,
        "signed_consent_manifest_artifact_sha256": "5" * 64,
        "signed_consent_manifest_sha256": "6" * 64,
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
            base_entry = {
                "participant_id": participant_id,
                "execution_did": execution_did,
                "credential_version": 1,
            }
            participants.append(base_entry)
            members[cohort] = {
                "participant_id": participant_id,
                "execution_did": execution_did,
            }
            extension = {
                "participant": {
                    "participant_id": participant_id,
                    "execution_did": execution_did,
                },
                "cohort_binding": {
                    "pair_id": f"pair-{pair_index:02d}",
                    "cohort": cohort,
                    "assignment_commitment_sha256": f"{pair_index + 10:064x}",
                },
                "prior_consent": {
                    "artifact_sha256": f"{index + 100:064x}",
                    "canonical_sha256": f"{index + 200:064x}",
                    "inherited": False,
                    "immutable_parent_evidence": True,
                },
                "extension_sha256": f"{index + 300:064x}",
            }
            extensions.append(
                {
                    "artifact": {
                        "path": f"/private/{participant_id}.json",
                        "sha256": f"{index + 400:064x}",
                        "canonical_sha256": extension["extension_sha256"],
                    },
                    "value": extension,
                }
            )
        assignments.append(
            {
                "pair_id": f"pair-{pair_index:02d}",
                "assignment_commitment_sha256": f"{pair_index + 10:064x}",
                **members,
            }
        )
    roster = {"participants": participants, "roster_sha256": "7" * 64}
    assignment = {
        "assignments": assignments,
        "reviewed_assignment_sha256": "8" * 64,
        "reviewed_pairing_sha256": "9" * 64,
    }
    bundle = {"bundle_sha256": "a" * 64}
    protocol = {
        "amended_protocol_sha256": "b" * 64,
        "amended_frozen_stack": {
            "provider_id": "provider",
            "model_id": "model",
            "budget_id": "budget",
            "verifier_id": "verifier-v2",
            "verifier_manifest_sha256": "c" * 64,
        },
        "preserved_protocol": {"task_corpus": {"corpus_id": "corpus"}},
    }
    design = {"amended_design_sha256": "d" * 64}
    return roster, assignment, bundle, protocol, design, extensions, source_binding


def _candidates() -> tuple[dict, dict, dict]:
    roster, assignment, bundle, protocol, design, extensions, binding = _sources()
    rebound_roster = build_rebound_roster(
        rebind_id=REBIN_ID,
        created_at=NOW,
        source_binding=binding,
        reviewed_roster=roster,
        reviewed_assignment=assignment,
        amendment_bundle=bundle,
        protocol_amendment=protocol,
        design_amendment=design,
        extensions=extensions,
    )
    rebound_assignment = build_rebound_assignment(
        rebind_id=REBIN_ID,
        created_at=NOW,
        source_binding=binding,
        reviewed_assignment=assignment,
        rebound_roster=rebound_roster,
        amendment_bundle=bundle,
        protocol_amendment=protocol,
        design_amendment=design,
    )
    plan = build_rebind_plan(
        rebind_id=REBIN_ID,
        created_at=NOW,
        source_binding=binding,
        rebound_roster_artifact={"path": "/private/roster.json", "sha256": "e" * 64},
        rebound_roster=rebound_roster,
        rebound_assignment_artifact={
            "path": "/private/assignment.json",
            "sha256": "f" * 64,
        },
        rebound_assignment=rebound_assignment,
        implementation=IMPLEMENTATION,
    )
    return rebound_roster, rebound_assignment, plan


def test_rebind_preserves_participants_pairs_and_non_execution_boundary() -> None:
    rebound_roster, rebound_assignment, plan = _candidates()
    roster, assignment, bundle, protocol, design, extensions, binding = _sources()
    assert (
        validate_rebound_roster(
            rebound_roster,
            rebind_id=REBIN_ID,
            created_at=NOW,
            source_binding=binding,
            reviewed_roster=roster,
            reviewed_assignment=assignment,
            amendment_bundle=bundle,
            protocol_amendment=protocol,
            design_amendment=design,
            extensions=extensions,
        )
        == []
    )
    assert (
        validate_rebound_assignment(
            rebound_assignment,
            rebind_id=REBIN_ID,
            created_at=NOW,
            source_binding=binding,
            reviewed_assignment=assignment,
            rebound_roster=rebound_roster,
            amendment_bundle=bundle,
            protocol_amendment=protocol,
            design_amendment=design,
        )
        == []
    )
    assert (
        validate_rebind_plan(
            plan,
            rebind_id=REBIN_ID,
            created_at=NOW,
            source_binding=binding,
            rebound_roster_artifact={
                "path": "/private/roster.json",
                "sha256": "e" * 64,
            },
            rebound_roster=rebound_roster,
            rebound_assignment_artifact={
                "path": "/private/assignment.json",
                "sha256": "f" * 64,
            },
            rebound_assignment=rebound_assignment,
            implementation=IMPLEMENTATION,
        )
        == []
    )
    assert len(rebound_roster["participants"]) == 40
    assert len(rebound_assignment["assignments"]) == 20
    assert plan["readiness"]["roster_rebound"] is False
    assert plan["execution_boundary"]["model_invocation_performed"] is False


def test_assignment_rejects_cohort_reassignment() -> None:
    rebound_roster, rebound_assignment, _ = _candidates()
    roster, assignment, bundle, protocol, design, _, binding = _sources()
    tampered = copy.deepcopy(rebound_assignment)
    tampered["assignments"][0]["control"]["cohort"] = "mentor"

    failures = validate_rebound_assignment(
        tampered,
        rebind_id=REBIN_ID,
        created_at=NOW,
        source_binding=binding,
        reviewed_assignment=assignment,
        rebound_roster=rebound_roster,
        amendment_bundle=bundle,
        protocol_amendment=protocol,
        design_amendment=design,
    )

    assert "assignment_copy_on_write_binding_invalid" in failures
    assert "rebound_assignment_inventory_invalid" in failures
    assert "assignment_hash_invalid" in failures


def test_owner_statement_is_exactly_candidate_and_gate_bound() -> None:
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
    assert "does not promote either candidate" in statement
    assert "does not" in statement and "model calls" in statement
