from __future__ import annotations

from benchmarks.j1.controlled_comparison import canonical_sha256
from benchmarks.j1.qualification_outcome_sensitive_evaluation import (
    CONFIRMATORY_LIMITATION,
    build_participant_outcome,
    evaluate_outcomes,
    validate_evaluation_report,
)
from benchmarks.j1.qualification_successful_execution_closeout_v4 import (
    build_preflight,
    validate_preflight,
)


def _assignment() -> dict[str, object]:
    pairs = []
    for index in range(20):
        pairs.append(
            {
                "pair_id": f"pair-{index:02d}",
                "mentor": {
                    "participant_id": f"mentor-{index:02d}",
                    "execution_did": f"did:civ:mentor-{index:02d}",
                },
                "control": {
                    "participant_id": f"control-{index:02d}",
                    "execution_did": f"did:civ:control-{index:02d}",
                },
            }
        )
    return {
        "status": "operator_reviewed",
        "assignment_sha256": (
            "2fcb9bca06504dd855930f912b7dffa7e13d67db775bd1d5689de0db8d6df81f"
        ),
        "assignments": pairs,
    }


def _observations(*, cohort: str) -> list[dict[str, object]]:
    records = []
    for ordinal in range(1, 13):
        baseline = ordinal <= 3
        mentor_treatment = cohort == "mentor" and ordinal >= 4
        accepted = mentor_treatment
        records.append(
            {
                "task_ordinal": ordinal,
                "task_evidence_sha256": f"{ordinal:064x}",
                "structured_decision_sha256": f"{ordinal + 20:064x}",
                "direct_observation_sha256": f"{ordinal + 40:064x}",
                "selected_action_id": "pause_and_request_scope",
                "predicted_pattern_ids": (
                    ["authorization_scope_gap"] if accepted else []
                ),
                "action_exact": accepted,
                "pattern_exact": accepted,
                "accepted": accepted,
                "repeated_error_family": "scope" if ordinal <= 6 else None,
                "hard_violation": False,
                "advice_expected": mentor_treatment,
                "advice_provenance_complete": mentor_treatment,
                "actual_tokens": 10,
                "actual_cost_microunits": 2,
                "baseline": baseline,
            }
        )
    return records


def _inputs() -> tuple[dict[str, object], ...]:
    protocol = {
        "protocol_sha256": "1" * 64,
        "scope": {
            "matched_pair_count": 20,
            "minimum_completed_pairs": 20,
            "participant_count": 40,
            "tasks_per_participant": 12,
            "total_task_count": 480,
        },
    }
    evaluator = {"input_contract": {"total_task_evidence_count": 480}}
    statistical = {
        "analysis": {
            "all_20_pairs_required": True,
            "bootstrap_iterations": 10000,
            "bootstrap_seed_rule": (
                "sha256(protocol,assignment,fixture,analysis-version)"
            ),
            "confidence_level": 0.95,
            "efficacy_early_stop_allowed": False,
            "maturity_censoring_ordinal": 13,
            "missing_task_imputation": "worst_case_against_effectiveness",
            "multiplicity": "holm_two_confirmatory_endpoints",
            "outcome_based_exclusion_allowed": False,
            "unit": "matched_pair",
        },
        "effectiveness_gate": {
            "primary_lower_confidence_bound_above_zero": True,
            "primary_relative_reduction_minimum": 0.5,
            "repeated_error_lower_confidence_bound_above_zero": True,
            "mentor_pattern_false_positive_rate_maximum": 0.1,
            "provenance_completeness_required": 1.0,
            "sovereignty_violation_maximum": 0,
            "direct_trust_increment_maximum": 0,
        },
    }
    fixture = {
        "fixture_sha256": "2" * 64,
        "fixtures": [{"task_ordinal": ordinal} for ordinal in range(1, 13)],
    }
    return protocol, evaluator, statistical, fixture, _assignment()


def test_outcome_evaluation_keeps_post_execution_inference_blocked() -> None:
    protocol, evaluator, statistical, fixture, assignment = _inputs()
    participants = []
    for pair in assignment["assignments"]:
        for cohort in ("mentor", "control"):
            member = pair[cohort]
            participants.append(
                build_participant_outcome(
                    run_id="run-r4",
                    authorization_sha256="a" * 64,
                    participant={
                        "participant_id": member["participant_id"],
                        "participant_did": member["execution_did"],
                        "pair_id": pair["pair_id"],
                        "cohort": cohort,
                    },
                    observations=_observations(cohort=cohort),
                )
            )

    report = evaluate_outcomes(
        run_id="run-r4",
        authorization_sha256="a" * 64,
        protocol=protocol,
        evaluator=evaluator,
        statistical_plan=statistical,
        fixture=fixture,
        assignment=assignment,
        participant_records=participants,
    )

    assert validate_evaluation_report(report) == []
    assert report["structural_passed"] is True
    assert report["confirmatory_inference"] == {
        "valid": False,
        "limitation": CONFIRMATORY_LIMITATION,
        "post_execution_method_selection_allowed": False,
        "holm_adjusted_claim_computed": False,
    }
    assert report["effectiveness_thresholds_met"] is False
    assert report["effectiveness_claim_authorized"] is False
    assert report["report_sha256"] == canonical_sha256(
        {key: value for key, value in report.items() if key != "report_sha256"}
    )


def test_participant_outcome_requires_all_twelve_ordinals() -> None:
    observations = _observations(cohort="mentor")[:-1]

    try:
        build_participant_outcome(
            run_id="run-r4",
            authorization_sha256="a" * 64,
            participant={
                "participant_id": "mentor-00",
                "participant_did": "did:civ:mentor-00",
                "pair_id": "pair-00",
                "cohort": "mentor",
            },
            observations=observations,
        )
    except ValueError as error:
        assert "observation set incomplete" in str(error)
    else:
        raise AssertionError("incomplete observations were accepted")


def test_successful_closeout_preflight_accepts_outcome_sensitive_scope() -> None:
    participants = []
    for pair in _assignment()["assignments"]:
        for cohort in ("mentor", "control"):
            member = pair[cohort]
            participants.append(
                build_participant_outcome(
                    run_id="run-r4",
                    authorization_sha256="a" * 64,
                    participant={
                        "participant_id": member["participant_id"],
                        "participant_did": member["execution_did"],
                        "pair_id": pair["pair_id"],
                        "cohort": cohort,
                    },
                    observations=_observations(cohort=cohort),
                )
            )
    evaluation = {
        "structural_passed": True,
        "participant_count": 40,
        "matched_pair_count": 20,
        "valid_for_qualification": True,
        "effectiveness_thresholds_met": False,
        "effectiveness_claim_authorized": False,
        "report_sha256": "f" * 64,
    }
    preflight = build_preflight(
        run_id="run-r4",
        authorization_id="authorization-r4",
        execution_summary={
            "status": "complete",
            "task_execution_count": 480,
            "committed_task_count": 480,
            "provider_call_count": 480,
            "participant_signature_count": 480,
            "journal_event_count": 5760,
            "validation_failures": [],
        },
        budget_summary={
            "reservation_count": 480,
            "reconciled_count": 480,
            "non_reconciled_count": 0,
            "actual_tokens": 148073,
            "actual_cost_microunits": 19220,
            "reserved_tokens": 1200000,
            "reserved_cost_microunits": 731040,
        },
        terminal_inventory={
            "participant_container_count": 40,
            "created_count": 0,
            "exited_count": 40,
            "running_count": 0,
            "container_set_sha256": "1" * 64,
        },
        outcome_inventory={
            "participant_count": 40,
            "matched_pair_count": 20,
            "task_evidence_count": 480,
            "verified_task_count": 480,
            "participant_outcome_count": 40,
            "task_evidence_set_sha256": "2" * 64,
            "participant_outcome_set_sha256": canonical_sha256(participants),
            "pattern_prediction_observation_policy": (
                "direct_signed_observation_exact_set_scoring"
            ),
        },
        participant_outcomes=participants,
        evaluation_report=evaluation,
        source_binding={
            f"source-{index}": {
                "path": f"/private/source-{index}.json",
                "sha256": f"{index + 1:064x}",
                "canonical_sha256": f"{index + 101:064x}",
            }
            for index in range(12)
        },
        implementation={
            "source_revision": "3" * 40,
            "source_files": {"domain.py": "4" * 64, "operation.py": "5" * 64},
        },
        profile="outcome_sensitive",
    )

    assert validate_preflight(preflight) == []
