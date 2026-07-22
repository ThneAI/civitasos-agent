from __future__ import annotations

import copy

from benchmarks.j1.controlled_comparison import canonical_sha256
from benchmarks.j1.qualification_cohort_migration import (
    CONTROL_EVENT_SCRIPTS,
    REQUIRED_BLOCKERS,
    build_cohort_migration_plan,
    validate_cohort_migration_plan,
)
from benchmarks.j1.qualification_verifier import build_verifier_candidate
from benchmarks.tests.test_j1_qualification_execution_design import _design


NOW = "2026-07-22T23:00:00+08:00"
SOURCE_BINDING = {
    "base_protocol_artifact_sha256": "1" * 64,
    "base_reviewed_design_artifact_sha256": "2" * 64,
    "reviewed_assignment_artifact_sha256": "3" * 64,
    "signed_advice_manifest_artifact_sha256": "4" * 64,
    "verifier_v2_candidate_artifact_sha256": "5" * 64,
}
IMPLEMENTATION = {"source_revision": "6" * 40, "source_sha256": "7" * 64}


def _sources() -> tuple[dict, dict, dict, dict, dict]:
    design, protocol, _, assignment = _design()
    protocol["task_corpus"]["task_count"] = 8
    design["source_binding"]["qualification_protocol_sha256"] = canonical_sha256(
        protocol
    )
    signed_advice = []
    for pair in assignment["assignments"]:
        for task in design["treatment"]["tasks"]:
            key = f"{pair['mentor']['participant_id']}:{task['task_id']}"
            signed_advice.append(
                {
                    "participant_id": pair["mentor"]["participant_id"],
                    "task_id": task["task_id"],
                    "advice_id": key,
                    "sha256": canonical_sha256({"raw": key}),
                    "canonical_sha256": canonical_sha256({"canonical": key}),
                }
            )
    verifier = build_verifier_candidate(
        source_revision="8" * 40,
        implementation_sha256="9" * 64,
    )
    return protocol, design, assignment, {"signed_advice": signed_advice}, verifier


def _plan() -> tuple[dict, tuple[dict, dict, dict, dict, dict]]:
    sources = _sources()
    protocol, design, assignment, advice, verifier = sources
    plan = build_cohort_migration_plan(
        amendment_id="j1d-cohort-migration-20260722-r1",
        created_at=NOW,
        source_binding=SOURCE_BINDING,
        base_protocol=protocol,
        base_reviewed_design=design,
        reviewed_assignment=assignment,
        signed_advice_manifest=advice,
        verifier_v2_candidate=verifier,
        implementation=IMPLEMENTATION,
    )
    return plan, sources


def _validate(plan: dict, sources: tuple[dict, dict, dict, dict, dict]) -> list[str]:
    protocol, design, assignment, advice, verifier = sources
    return validate_cohort_migration_plan(
        plan,
        expected_source_binding=SOURCE_BINDING,
        base_protocol=protocol,
        base_reviewed_design=design,
        reviewed_assignment=assignment,
        signed_advice_manifest=advice,
        verifier_v2_candidate=verifier,
        expected_implementation=IMPLEMENTATION,
    )


def test_migration_preserves_mentor_and_specializes_control_scripts() -> None:
    plan, sources = _plan()
    design = sources[1]
    base_tasks = {item["task_id"]: item for item in design["treatment"]["tasks"]}

    assert _validate(plan, sources) == []
    assert set(plan["blockers"]) == REQUIRED_BLOCKERS
    assert plan["readiness"]["controlled_experiment_execution_ready"] is False
    for contract in plan["cohort_event_contracts"]:
        task_id = contract["task_id"]
        assert contract["mentor"]["event_script"] == base_tasks[task_id]["event_script"]
        assert contract["control"]["event_script"] == CONTROL_EVENT_SCRIPTS[task_id]
        assert contract["control"]["advice_assignment_present"] is False
        assert contract["control"]["signed_advice_required"] is False


def test_migration_rejects_control_advice_event_tamper() -> None:
    plan, sources = _plan()
    tampered = copy.deepcopy(plan)
    tampered["cohort_event_contracts"][0]["control"]["event_script"] = tampered[
        "cohort_event_contracts"
    ][0]["mentor"]["event_script"]
    tampered["plan_sha256"] = canonical_sha256(
        {key: item for key, item in tampered.items() if key != "plan_sha256"}
    )

    assert "cohort_migration_task_contract_invalid" in _validate(tampered, sources)


def test_migration_rejects_implicit_consent_reuse() -> None:
    plan, sources = _plan()
    tampered = copy.deepcopy(plan)
    tampered["artifact_migration"]["new_review_or_signature_required"].remove(
        "participant_consent_extension_40_of_40"
    )
    tampered["plan_sha256"] = canonical_sha256(
        {key: item for key, item in tampered.items() if key != "plan_sha256"}
    )

    assert "cohort_migration_artifact_impact_invalid" in _validate(tampered, sources)


def test_migration_rejects_execution_boundary_escalation() -> None:
    plan, sources = _plan()
    tampered = copy.deepcopy(plan)
    tampered["execution_boundary"]["model_invocation_performed"] = True
    tampered["plan_sha256"] = canonical_sha256(
        {key: item for key, item in tampered.items() if key != "plan_sha256"}
    )

    assert "cohort_migration_boundary_invalid" in _validate(tampered, sources)
