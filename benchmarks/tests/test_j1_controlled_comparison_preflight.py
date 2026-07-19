from __future__ import annotations

import copy
import json
from pathlib import Path

from benchmarks.j1.cohort_evaluation import EVALUATION_SCHEMA, evaluate_cohorts
from benchmarks.j1.controlled_comparison import canonical_sha256, validate_protocol
from benchmarks.j1.matched_assignment import ASSIGNMENT_SCHEMA, build_assignment
from benchmarks.j1_controlled_comparison_preflight import (
    DEFAULT_PROTOCOL,
    REPORT_SCHEMA,
    _synthetic_participants,
    _synthetic_records,
    run_gate,
)


def _protocol() -> dict:
    return json.loads(DEFAULT_PROTOCOL.read_text(encoding="utf-8"))


def _assignment_and_records() -> tuple[dict, dict, list[dict]]:
    protocol = _protocol()
    assignment = build_assignment(protocol, _synthetic_participants(protocol))
    return protocol, assignment, _synthetic_records(assignment)


def test_frozen_protocol_is_valid_and_corpus_hash_is_bound() -> None:
    protocol = _protocol()

    assert validate_protocol(protocol) == []
    assert protocol["task_corpus"]["tasks_sha256"] == canonical_sha256(
        protocol["task_corpus"]["tasks"]
    )
    assert protocol["assignment"]["minimum_completed_pairs"] == 20
    assert protocol["analysis"]["efficacy_early_stop_allowed"] is False
    assert protocol["execution_boundary"]["model_invocation_allowed"] is False
    assert protocol["metrics"]["strategy_maturity_time"]["report_dimensions"] == [
        "task_count",
        "active_runtime_seconds",
        "token_count",
        "cost_microunits",
    ]


def test_gate_validates_dry_run_without_starting_experiment(tmp_path: Path) -> None:
    output = tmp_path / "j1d-preflight.json"

    report = run_gate(protocol_path=DEFAULT_PROTOCOL, output_path=output)

    assert report["schema_version"] == REPORT_SCHEMA
    assert report["passed"] is True
    assert report["failure_reasons"] == []
    assert len(report["negative_controls"]) == 8
    assert len(report["evaluation_fault_controls"]) == 8
    assert all(item["rejected"] for item in report["negative_controls"])
    assert all(item["rejected"] for item in report["evaluation_fault_controls"])
    assert report["assignment_summary"]["participant_count"] == 40
    assert report["assignment_summary"]["matched_pair_count"] == 20
    assert report["evaluation"]["effectiveness_thresholds_met"] is True
    assert report["evaluation"]["valid_for_qualification"] is False
    assert report["readiness"] == {
        "state": "j1d_development_preflight_passed_qualification_experiment_not_started",
        "development_protocol_validated": True,
        "matched_assignment_engine_validated": True,
        "cohort_evaluator_validated": True,
        "qualification_protocol_frozen": False,
        "real_participant_roster_bound": False,
        "controlled_experiment_execution_ready": False,
        "effectiveness_verified": False,
    }
    assert report["execution_boundary"]["real_agent_execution_allowed"] is False
    assert output.stat().st_mode & 0o777 == 0o600


def test_protocol_rejects_post_hoc_and_execution_boundary_drift() -> None:
    protocol = _protocol()
    protocol["analysis"]["outcome_based_exclusion_allowed"] = True
    protocol["analysis"]["efficacy_early_stop_allowed"] = True
    protocol["execution_boundary"]["effectiveness_claim_allowed"] = True
    protocol["metrics"]["strategy_maturity_time"]["minimum_relative_reduction"] = 0.1

    failures = validate_protocol(protocol)

    assert "outcome_exclusion_must_be_false" in failures
    assert "efficacy_early_stop_must_be_false" in failures
    assert "effectiveness_claim_allowed_must_be_false" in failures
    assert "maturity_threshold_invalid" in failures


def test_assignment_is_deterministic_balanced_and_order_independent() -> None:
    protocol = _protocol()
    participants = _synthetic_participants(protocol)

    first = build_assignment(protocol, participants)
    second = build_assignment(protocol, list(reversed(participants)))

    assert first["schema_version"] == ASSIGNMENT_SCHEMA
    assert first["passed"] is True
    assert first["assignment_sha256"] == second["assignment_sha256"]
    assert first["assignments"] == second["assignments"]
    assert sum(item["cohort"] == "mentor" for item in first["assignments"]) == 20
    assert sum(item["cohort"] == "control" for item in first["assignments"]) == 20


def test_assignment_rejects_duplicate_and_unmatched_participants() -> None:
    protocol = _protocol()
    participants = _synthetic_participants(protocol)
    duplicate = participants + [copy.deepcopy(participants[0])]
    unmatched = participants[:-1]

    duplicate_report = build_assignment(protocol, duplicate)
    unmatched_report = build_assignment(protocol, unmatched)

    assert duplicate_report["passed"] is False
    assert "participant_id_duplicate" in duplicate_report["failure_reasons"]
    assert unmatched_report["passed"] is False
    assert (
        "each_exact_stratum_must_have_two_participants"
        in unmatched_report["failure_reasons"]
    )


def test_evaluator_computes_registered_metrics_but_never_qualifies_synthetic() -> None:
    protocol, assignment, records = _assignment_and_records()

    report = evaluate_cohorts(protocol, assignment, records)

    assert report["schema_version"] == EVALUATION_SCHEMA
    assert report["passed"] is True
    assert report["matched_pair_count"] == 20
    maturity = report["metrics"]["strategy_maturity_time"]
    assert maturity["mentor_mean_tasks"] == 3
    assert maturity["control_mean_tasks"] == 8
    assert maturity["mentor_mean_active_runtime_seconds"] == 300
    assert maturity["control_mean_active_runtime_seconds"] == 800
    assert maturity["mentor_mean_token_count"] == 1000
    assert maturity["control_mean_token_count"] == 1800
    assert maturity["relative_reduction"] == 0.625
    assert maturity["paired_bootstrap_95pct"] == [0.625, 0.625]
    errors = report["metrics"]["repeated_error_rate"]
    assert errors["mentor"] == 0.1
    assert errors["control"] == 0.4
    assert report["metrics"]["mentor_pattern_false_positive_rate"] == 0.025
    assert report["records_sha256"] == canonical_sha256(records)
    assert report["effectiveness_thresholds_met"] is True
    assert report["synthetic_dry_run_only"] is True
    assert report["valid_for_qualification"] is False
    assert report["state"] == "synthetic_evaluator_validated_effectiveness_not_verified"


def test_evaluator_fails_closed_on_provenance_trust_and_protocol_drift() -> None:
    protocol, assignment, records = _assignment_and_records()
    records[0]["direct_trust_increment_count"] = 1
    mentor = next(item for item in records if item["expected_provenance_count"] > 0)
    mentor["complete_provenance_count"] = 2
    drifted = copy.deepcopy(assignment)
    drifted["protocol_sha256"] = "0" * 64

    report = evaluate_cohorts(protocol, drifted, records)

    assert report["passed"] is False
    assert "assignment_protocol_hash_mismatch" in report["failure_reasons"]
    assert "direct_trust_increment_observed" in report["failure_reasons"]
    assert "advice_provenance_incomplete" in report["failure_reasons"]
    assert report["valid_for_qualification"] is False


def test_evaluator_rejects_manifest_and_result_binding_drift() -> None:
    protocol, assignment, records = _assignment_and_records()
    original = assignment["assignments"][0]["cohort"]
    assignment["assignments"][0]["cohort"] = (
        "control" if original == "mentor" else "mentor"
    )
    records[0]["protocol_sha256"] = "0" * 64

    report = evaluate_cohorts(protocol, assignment, records)

    assert report["passed"] is False
    assert "assignment_manifest_hash_mismatch" in report["failure_reasons"]
    assert "assignment_pairs_invalid" in report["failure_reasons"]
    assert "result_protocol_hash_mismatch" in report["failure_reasons"]


def test_evaluator_rejects_invalid_maturity_control_data_and_counts() -> None:
    protocol, assignment, records = _assignment_and_records()
    mentor = next(item for item in records if item["expected_provenance_count"] > 0)
    mentor["maturity_criteria"]["operator_override_used"] = True
    mentor["token_count"] = -1
    control = next(item for item in records if item["expected_provenance_count"] == 0)
    control["pattern_prediction_count"] = 1

    report = evaluate_cohorts(protocol, assignment, records)

    assert report["passed"] is False
    assert "result_token_count_invalid" in report["failure_reasons"]
    assert "control_cohort_mentor_data_observed" in report["failure_reasons"]


def test_development_schema_rejects_qualification_label() -> None:
    protocol = _protocol()
    protocol["validation_profile"] = "qualification"

    assert "validation_profile_must_be_development_dry_run" in validate_protocol(
        protocol
    )


def test_gate_fails_closed_when_protocol_is_missing(tmp_path: Path) -> None:
    report = run_gate(
        protocol_path=tmp_path / "missing.json",
        output_path=tmp_path / "report.json",
    )

    assert report["passed"] is False
    assert "protocol_artifact_unreadable" in report["failure_reasons"]
    assert report["readiness"]["controlled_experiment_execution_ready"] is False
