from __future__ import annotations

import copy

from benchmarks.j1.controlled_comparison import REQUIRED_SCENARIOS, canonical_sha256
from benchmarks.j1.qualification_real_evaluator import (
    MATURITY_CRITERIA,
    OUTCOME_SCHEMA,
    SOURCE_FIELDS,
    build_real_evaluator_manifest,
    evaluate_qualification_outcomes,
    validate_real_evaluator_manifest,
)


def _source() -> dict[str, str]:
    return {
        field: canonical_sha256(["source", field]) for field in sorted(SOURCE_FIELDS)
    }


def _implementation() -> dict[str, str]:
    return {
        "source_revision": "a" * 40,
        "evaluator_source_sha256": "b" * 64,
        "freeze_operation_source_sha256": "c" * 64,
    }


def _assignment() -> dict:
    pairs = []
    for index in range(20):
        pair_id = f"pair-{index:02d}"
        pairs.append(
            {
                "pair_id": pair_id,
                "mentor": {
                    "participant_id": f"mentor-{index:02d}",
                    "execution_did": f"did:civ:qualification:mentor-{index:02d}",
                    "cohort": "mentor",
                },
                "control": {
                    "participant_id": f"control-{index:02d}",
                    "execution_did": f"did:civ:qualification:control-{index:02d}",
                    "cohort": "control",
                },
            }
        )
    return {
        "schema_version": (
            "j1-qualification-cohort-assignment-rebound:operator-reviewed:v1"
        ),
        "status": "operator_reviewed",
        "assignments": pairs,
    }


def _records(
    manifest: dict, assignment: dict, *, authorization_sha256: str
) -> list[dict]:
    records = []
    for pair in assignment["assignments"]:
        for cohort in ("mentor", "control"):
            member = pair[cohort]
            participant_id = member["participant_id"]
            records.append(
                {
                    "schema_version": OUTCOME_SCHEMA,
                    "run_id": "run-1",
                    "participant_id": participant_id,
                    "participant_did": member["execution_did"],
                    "pair_id": pair["pair_id"],
                    "cohort": cohort,
                    "source_binding": {
                        "evaluator_manifest_sha256": manifest["manifest_sha256"],
                        "rebound_assignment_sha256": manifest["source_binding"][
                            "rebound_assignment_sha256"
                        ],
                        "execution_authorization_sha256": authorization_sha256,
                    },
                    "task_evidence_sha256": [
                        canonical_sha256([participant_id, task]) for task in range(8)
                    ],
                    "active_runtime_seconds": 80 if cohort == "mentor" else 120,
                    "token_count": 800 if cohort == "mentor" else 900,
                    "cost_microunits": 400 if cohort == "mentor" else 450,
                    "repeated_error_count": 0 if cohort == "mentor" else 2,
                    "repeated_error_opportunities": 8,
                    "pattern_prediction_count": 8 if cohort == "mentor" else 0,
                    "pattern_false_positive_count": 0,
                    "expected_provenance_count": 8 if cohort == "mentor" else 0,
                    "complete_provenance_count": 8 if cohort == "mentor" else 0,
                    "sovereignty_violation_count": 0,
                    "direct_trust_increment_count": 0,
                    "maturity_task_count": 3 if cohort == "mentor" else 8,
                    "maturity_criteria": MATURITY_CRITERIA,
                    "scenario_results": {
                        scenario: True for scenario in REQUIRED_SCENARIOS
                    },
                }
            )
    return records


def test_real_evaluator_manifest_and_paired_evaluation_pass() -> None:
    manifest = build_real_evaluator_manifest(
        evaluator_id="j1q-real-evaluator-r1",
        created_at="2026-07-23T00:00:00+00:00",
        source_binding=_source(),
        implementation=_implementation(),
        status="operator_reviewed_frozen",
    )
    assignment = _assignment()
    authorization_sha256 = "d" * 64
    report = evaluate_qualification_outcomes(
        manifest=manifest,
        reviewed_assignment=assignment,
        records=_records(
            manifest, assignment, authorization_sha256=authorization_sha256
        ),
        run_id="run-1",
        execution_authorization_sha256=authorization_sha256,
    )

    assert report["structural_passed"] is True
    assert report["effectiveness_thresholds_met"] is True
    assert report["effectiveness_claim_authorized"] is False
    assert report["matched_pair_count"] == 20


def test_real_evaluator_rejects_tamper_missing_pair_and_control_mentor_data() -> None:
    manifest = build_real_evaluator_manifest(
        evaluator_id="j1q-real-evaluator-r1",
        created_at="2026-07-23T00:00:00+00:00",
        source_binding=_source(),
        implementation=_implementation(),
        status="operator_reviewed_frozen",
    )
    assignment = _assignment()
    records = _records(manifest, assignment, authorization_sha256="d" * 64)
    records[1]["expected_provenance_count"] = 1
    records.pop()

    report = evaluate_qualification_outcomes(
        manifest=manifest,
        reviewed_assignment=assignment,
        records=records,
        run_id="run-1",
        execution_authorization_sha256="d" * 64,
    )

    assert report["structural_passed"] is False
    assert "outcome_control_mentor_data_present" in report["failure_reasons"]
    assert "outcome_participant_set_incomplete" in report["failure_reasons"]


def test_real_evaluator_manifest_rejects_hash_and_policy_drift() -> None:
    manifest = build_real_evaluator_manifest(
        evaluator_id="j1q-real-evaluator-r1",
        created_at="2026-07-23T00:00:00+00:00",
        source_binding=_source(),
        implementation=_implementation(),
    )
    tampered = copy.deepcopy(manifest)
    tampered["analysis"]["efficacy_early_stop_allowed"] = True

    failures = validate_real_evaluator_manifest(
        tampered,
        expected_source_binding=_source(),
        expected_implementation=_implementation(),
        expected_status="review_required",
    )

    assert "evaluator_analysis_invalid" in failures
    assert "evaluator_manifest_hash_invalid" in failures
