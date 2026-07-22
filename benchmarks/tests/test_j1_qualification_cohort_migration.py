from __future__ import annotations

import copy

from benchmarks.j1.controlled_comparison import canonical_sha256
from benchmarks.j1.qualification_cohort_migration import (
    CONTROL_EVENT_SCRIPTS,
    REQUIRED_BLOCKERS,
    build_cohort_migration_plan,
    validate_cohort_migration_plan,
    validate_reviewed_verifier_promotion,
)
from benchmarks.j1.qualification_verifier import build_verifier_candidate
from benchmarks.tests.test_j1_qualification_execution_design import _design


NOW = "2026-07-22T23:00:00+08:00"
SOURCE_BINDING = {
    "base_protocol_artifact_sha256": "1" * 64,
    "base_reviewed_design_artifact_sha256": "2" * 64,
    "reviewed_assignment_artifact_sha256": "3" * 64,
    "signed_advice_manifest_artifact_sha256": "4" * 64,
    "signed_advice_gate_artifact_sha256": "5" * 64,
    "reviewed_corpus_v2_artifact_sha256": "6" * 64,
    "reviewed_verifier_v2_artifact_sha256": "7" * 64,
    "verifier_v2_material_review_gate_artifact_sha256": "8" * 64,
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
    verifier_candidate = build_verifier_candidate(
        source_revision="8" * 40,
        implementation_sha256="9" * 64,
    )
    verifier = copy.deepcopy(verifier_candidate)
    verifier["status"] = "operator_reviewed"
    verifier["operator_review"] = _operator_review()
    verifier["manifest_sha256"] = canonical_sha256(
        {key: item for key, item in verifier.items() if key != "manifest_sha256"}
    )
    return protocol, design, assignment, {"signed_advice": signed_advice}, verifier


def _plan() -> tuple[dict, tuple[dict, dict, dict, dict, dict]]:
    sources = _sources()
    protocol, design, assignment, advice, verifier = sources
    plan = build_cohort_migration_plan(
        amendment_id="j1d-cohort-migration-20260722-r2",
        created_at=NOW,
        source_binding=SOURCE_BINDING,
        base_protocol=protocol,
        base_reviewed_design=design,
        reviewed_assignment=assignment,
        signed_advice_manifest=advice,
        reviewed_verifier_v2=verifier,
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
        reviewed_verifier_v2=verifier,
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


def test_migration_binds_operator_reviewed_verifier_gate() -> None:
    corpus, verifier, gate, corpus_artifact, verifier_artifact = _promotion()

    assert (
        validate_reviewed_verifier_promotion(
            reviewed_corpus=corpus,
            reviewed_verifier=verifier,
            material_review_gate=gate,
            reviewed_corpus_artifact=corpus_artifact,
            reviewed_verifier_artifact=verifier_artifact,
        )
        == []
    )


def test_migration_rejects_reviewed_verifier_gate_drift() -> None:
    corpus, verifier, gate, corpus_artifact, verifier_artifact = _promotion()
    gate["promoted_artifacts"]["verifier"]["sha256"] = "f" * 64

    failures = validate_reviewed_verifier_promotion(
        reviewed_corpus=corpus,
        reviewed_verifier=verifier,
        material_review_gate=gate,
        reviewed_corpus_artifact=corpus_artifact,
        reviewed_verifier_artifact=verifier_artifact,
    )

    assert "cohort_migration_verifier_promotion_binding_invalid" in failures


def _operator_review() -> dict:
    return {
        "decision": "approve_qualification_materials",
        "review_receipt_sha256": "a" * 64,
    }


def _promotion() -> tuple[dict, dict, dict, dict, dict]:
    verifier = _sources()[4]
    corpus = {"status": "operator_reviewed", "operator_review": _operator_review()}
    corpus_artifact = {"path": "/private/corpus.json", "sha256": "b" * 64}
    verifier_artifact = {"path": "/private/verifier.json", "sha256": "c" * 64}
    gate = {
        "schema_version": "j1-qualification-material-review-gate:v1",
        "passed": True,
        "failure_reasons": [],
        "state": "j1d_material_review_passed_protocol_freeze_required",
        "review_decision": "approve_qualification_materials",
        "review_receipt_signature_valid": True,
        "review_receipt": {"sha256": "a" * 64},
        "promoted_artifacts": {
            "corpus": copy.deepcopy(corpus_artifact),
            "verifier": copy.deepcopy(verifier_artifact),
        },
        "readiness": {
            "qualification_materials_operator_reviewed": True,
            "controlled_experiment_execution_ready": False,
        },
    }
    return corpus, verifier, gate, corpus_artifact, verifier_artifact
