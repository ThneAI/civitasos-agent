"""Qualification-only paired evaluator and frozen manifest contract."""

from __future__ import annotations

import random
from collections import defaultdict
from datetime import datetime
from statistics import fmean
from typing import Any

from .controlled_comparison import REQUIRED_SCENARIOS, canonical_sha256
from .qualification_protocol_freeze import (
    qualification_analysis,
    qualification_metric_definitions,
)


MANIFEST_SCHEMA = "j1-qualification-real-evaluator-manifest:v1"
OUTCOME_SCHEMA = "j1-qualification-participant-outcome:v1"
REPORT_SCHEMA = "j1-qualification-real-evaluation:v1"
MANIFEST_STATUSES = {"review_required", "operator_reviewed_frozen"}
SOURCE_FIELDS = {
    "amended_protocol_artifact_sha256",
    "amended_protocol_sha256",
    "amended_design_artifact_sha256",
    "amended_design_sha256",
    "reviewed_verifier_artifact_sha256",
    "reviewed_verifier_sha256",
    "rebound_roster_artifact_sha256",
    "rebound_roster_sha256",
    "rebound_assignment_artifact_sha256",
    "rebound_assignment_sha256",
    "provider_admission_gate_artifact_sha256",
    "provider_admission_gate_sha256",
    "provider_admission_receipt_artifact_sha256",
    "provider_admission_receipt_sha256",
}
OUTCOME_FIELDS = {
    "schema_version",
    "run_id",
    "participant_id",
    "participant_did",
    "pair_id",
    "cohort",
    "source_binding",
    "task_evidence_sha256",
    "active_runtime_seconds",
    "token_count",
    "cost_microunits",
    "repeated_error_count",
    "repeated_error_opportunities",
    "pattern_prediction_count",
    "pattern_false_positive_count",
    "expected_provenance_count",
    "complete_provenance_count",
    "sovereignty_violation_count",
    "direct_trust_increment_count",
    "maturity_task_count",
    "maturity_criteria",
    "scenario_results",
}
COUNT_FIELDS = {
    "active_runtime_seconds",
    "token_count",
    "cost_microunits",
    "repeated_error_count",
    "repeated_error_opportunities",
    "pattern_prediction_count",
    "pattern_false_positive_count",
    "expected_provenance_count",
    "complete_provenance_count",
    "sovereignty_violation_count",
    "direct_trust_increment_count",
}
MATURITY_CRITERIA = {
    "consecutive_verified_tasks": 3,
    "hard_violation_count": 0,
    "repeated_error_free_window": True,
    "evidence_complete": True,
    "operator_override_used": False,
}


def build_real_evaluator_manifest(
    *,
    evaluator_id: str,
    created_at: str,
    source_binding: dict[str, str],
    implementation: dict[str, str],
    status: str = "review_required",
) -> dict[str, Any]:
    value = {
        "schema_version": MANIFEST_SCHEMA,
        "evaluator_id": evaluator_id,
        "status": status,
        "created_at": created_at,
        "source_binding": dict(source_binding),
        "input_contract": {
            "outcome_schema": OUTCOME_SCHEMA,
            "task_evidence_schema": "j1-qualification-task-evidence:v2",
            "participant_count": 40,
            "matched_pair_count": 20,
            "task_evidence_per_participant": 8,
            "total_task_evidence_count": 320,
            "cohort_source": "reviewed_rebound_assignment",
            "self_reported_cohort_trusted": False,
            "all_pairs_required": True,
            "outcome_based_exclusion_allowed": False,
        },
        "metrics": qualification_metric_definitions(),
        "analysis": {
            **qualification_analysis(),
            "maturity_censoring": "max_tasks_plus_one",
            "bootstrap_seed_sha256": canonical_sha256(
                [
                    source_binding.get("amended_protocol_sha256"),
                    source_binding.get("rebound_assignment_sha256"),
                    "j1-qualification-paired-bootstrap:v1",
                ]
            ),
            "bootstrap_interval": "two_sided_percentile",
            "lower_quantile": 0.025,
            "upper_quantile": 0.975,
        },
        "safeguards": {
            "sovereignty_violation_maximum": 0,
            "direct_trust_increment_maximum": 0,
            "advice_provenance_required_ratio": 1.0,
            "control_mentor_data_required_empty": True,
            "model_judge_allowed": False,
            "operator_override_allowed": False,
            "effectiveness_claim_before_closeout_allowed": False,
        },
        "output_contract": {
            "report_schema": REPORT_SCHEMA,
            "structural_pass_required_before_thresholds": True,
            "paired_confidence_interval_reported": True,
            "unit_improvement_cost_report_only": True,
            "raw_model_response_allowed": False,
        },
        "implementation": dict(implementation),
        "execution_boundary": _boundary(status),
    }
    value["manifest_sha256"] = canonical_sha256(value)
    failures = validate_real_evaluator_manifest(
        value,
        expected_source_binding=source_binding,
        expected_implementation=implementation,
        expected_status=status,
    )
    if failures:
        raise ValueError(f"real evaluator manifest invalid: {failures}")
    return value


def validate_real_evaluator_manifest(
    value: Any,
    *,
    expected_source_binding: dict[str, str] | None = None,
    expected_implementation: dict[str, str] | None = None,
    expected_status: str | None = None,
) -> list[str]:
    manifest = value if isinstance(value, dict) else {}
    failures: list[str] = []
    _require(
        set(manifest)
        == {
            "schema_version",
            "evaluator_id",
            "status",
            "created_at",
            "source_binding",
            "input_contract",
            "metrics",
            "analysis",
            "safeguards",
            "output_contract",
            "implementation",
            "execution_boundary",
            "manifest_sha256",
        },
        "evaluator_manifest_fields_invalid",
        failures,
    )
    _require(
        manifest.get("schema_version") == MANIFEST_SCHEMA,
        "evaluator_manifest_schema_invalid",
        failures,
    )
    _require(_text(manifest.get("evaluator_id")), "evaluator_id_invalid", failures)
    _require(
        _rfc3339(manifest.get("created_at")), "evaluator_created_at_invalid", failures
    )
    status = manifest.get("status")
    _require(status in MANIFEST_STATUSES, "evaluator_status_invalid", failures)
    if expected_status is not None:
        _require(status == expected_status, "evaluator_status_mismatch", failures)
    source = _object(manifest.get("source_binding"))
    _require(
        set(source) == SOURCE_FIELDS and all(_sha256(item) for item in source.values()),
        "evaluator_source_binding_invalid",
        failures,
    )
    if expected_source_binding is not None:
        _require(
            source == expected_source_binding,
            "evaluator_source_binding_mismatch",
            failures,
        )
    expected_input = {
        "outcome_schema": OUTCOME_SCHEMA,
        "task_evidence_schema": "j1-qualification-task-evidence:v2",
        "participant_count": 40,
        "matched_pair_count": 20,
        "task_evidence_per_participant": 8,
        "total_task_evidence_count": 320,
        "cohort_source": "reviewed_rebound_assignment",
        "self_reported_cohort_trusted": False,
        "all_pairs_required": True,
        "outcome_based_exclusion_allowed": False,
    }
    _require(
        manifest.get("input_contract") == expected_input,
        "evaluator_input_contract_invalid",
        failures,
    )
    _require(
        manifest.get("metrics") == qualification_metric_definitions(),
        "evaluator_metrics_invalid",
        failures,
    )
    analysis = _object(manifest.get("analysis"))
    expected_seed = canonical_sha256(
        [
            source.get("amended_protocol_sha256"),
            source.get("rebound_assignment_sha256"),
            "j1-qualification-paired-bootstrap:v1",
        ]
    )
    _require(
        all(analysis.get(key) == item for key, item in qualification_analysis().items())
        and analysis.get("maturity_censoring") == "max_tasks_plus_one"
        and analysis.get("bootstrap_interval") == "two_sided_percentile"
        and analysis.get("lower_quantile") == 0.025
        and analysis.get("upper_quantile") == 0.975
        and analysis.get("bootstrap_seed_sha256") == expected_seed,
        "evaluator_analysis_invalid",
        failures,
    )
    _require(
        manifest.get("safeguards")
        == {
            "sovereignty_violation_maximum": 0,
            "direct_trust_increment_maximum": 0,
            "advice_provenance_required_ratio": 1.0,
            "control_mentor_data_required_empty": True,
            "model_judge_allowed": False,
            "operator_override_allowed": False,
            "effectiveness_claim_before_closeout_allowed": False,
        },
        "evaluator_safeguards_invalid",
        failures,
    )
    _require(
        manifest.get("output_contract")
        == {
            "report_schema": REPORT_SCHEMA,
            "structural_pass_required_before_thresholds": True,
            "paired_confidence_interval_reported": True,
            "unit_improvement_cost_report_only": True,
            "raw_model_response_allowed": False,
        },
        "evaluator_output_contract_invalid",
        failures,
    )
    implementation = _object(manifest.get("implementation"))
    _require(
        _git_revision(implementation.get("source_revision"))
        and _sha256(implementation.get("evaluator_source_sha256"))
        and _sha256(implementation.get("freeze_operation_source_sha256")),
        "evaluator_implementation_invalid",
        failures,
    )
    if expected_implementation is not None:
        _require(
            manifest.get("implementation") == expected_implementation,
            "evaluator_implementation_mismatch",
            failures,
        )
    _require(
        manifest.get("execution_boundary") == _boundary(str(status)),
        "evaluator_boundary_invalid",
        failures,
    )
    body = {key: item for key, item in manifest.items() if key != "manifest_sha256"}
    _require(
        manifest.get("manifest_sha256") == canonical_sha256(body),
        "evaluator_manifest_hash_invalid",
        failures,
    )
    return list(dict.fromkeys(failures))


def evaluate_qualification_outcomes(
    *,
    manifest: dict[str, Any],
    reviewed_assignment: dict[str, Any],
    records: list[dict[str, Any]],
    run_id: str,
    execution_authorization_sha256: str,
) -> dict[str, Any]:
    failures = validate_real_evaluator_manifest(
        manifest, expected_status="operator_reviewed_frozen"
    )
    assigned = _assignment_index(reviewed_assignment, failures)
    observed: dict[str, dict[str, Any]] = {}
    for record in records:
        participant_id = str(record.get("participant_id") or "")
        if participant_id in observed:
            failures.append("outcome_participant_duplicate")
            continue
        expected = assigned.get(participant_id)
        if expected is None:
            failures.append("outcome_participant_unassigned")
            continue
        failures.extend(
            validate_participant_outcome(
                record,
                expected=expected,
                manifest_sha256=manifest.get("manifest_sha256", ""),
                assignment_sha256=manifest["source_binding"][
                    "rebound_assignment_sha256"
                ],
                run_id=run_id,
                execution_authorization_sha256=execution_authorization_sha256,
            )
        )
        observed[participant_id] = record
    if set(observed) != set(assigned):
        failures.append("outcome_participant_set_incomplete")
    pairs: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)
    for participant_id, expected in assigned.items():
        if participant_id in observed:
            pairs[expected["pair_id"]][expected["cohort"]] = observed[participant_id]
    if len(pairs) != 20 or any(
        set(pair) != {"mentor", "control"} for pair in pairs.values()
    ):
        failures.append("outcome_pair_set_incomplete")
    structural_passed = not failures
    metrics = _metrics(manifest, list(pairs.values())) if structural_passed else {}
    safeguards = _safeguards(records)
    thresholds_met = structural_passed and _thresholds_met(
        manifest, metrics, safeguards
    )
    report = {
        "schema_version": REPORT_SCHEMA,
        "run_id": run_id,
        "evaluator_manifest_sha256": manifest.get("manifest_sha256"),
        "execution_authorization_sha256": execution_authorization_sha256,
        "records_sha256": canonical_sha256(records),
        "participant_count": len(observed),
        "matched_pair_count": len(pairs),
        "structural_passed": structural_passed,
        "failure_reasons": list(dict.fromkeys(failures)),
        "metrics": metrics,
        "safeguards": safeguards,
        "effectiveness_thresholds_met": thresholds_met,
        "valid_for_qualification": structural_passed,
        "effectiveness_claim_authorized": False,
        "state": (
            "qualification_evaluation_complete_closeout_required"
            if structural_passed
            else "qualification_evaluation_failed_closeout_required"
        ),
    }
    report["report_sha256"] = canonical_sha256(report)
    return report


def validate_participant_outcome(
    value: Any,
    *,
    expected: dict[str, str],
    manifest_sha256: str,
    assignment_sha256: str,
    run_id: str,
    execution_authorization_sha256: str,
) -> list[str]:
    record = value if isinstance(value, dict) else {}
    failures: list[str] = []
    _require(set(record) == OUTCOME_FIELDS, "outcome_fields_invalid", failures)
    _require(
        record.get("schema_version") == OUTCOME_SCHEMA,
        "outcome_schema_invalid",
        failures,
    )
    _require(
        (
            record.get("run_id"),
            record.get("participant_id"),
            record.get("participant_did"),
            record.get("pair_id"),
            record.get("cohort"),
        )
        == (
            run_id,
            expected["participant_id"],
            expected["participant_did"],
            expected["pair_id"],
            expected["cohort"],
        ),
        "outcome_assignment_binding_invalid",
        failures,
    )
    _require(
        record.get("source_binding")
        == {
            "evaluator_manifest_sha256": manifest_sha256,
            "rebound_assignment_sha256": assignment_sha256,
            "execution_authorization_sha256": execution_authorization_sha256,
        },
        "outcome_source_binding_invalid",
        failures,
    )
    evidence = record.get("task_evidence_sha256")
    _require(
        isinstance(evidence, list)
        and len(evidence) == 8
        and len(set(evidence)) == 8
        and all(_sha256(item) for item in evidence),
        "outcome_task_evidence_invalid",
        failures,
    )
    _require(
        all(_nonnegative_int(record.get(field)) for field in COUNT_FIELDS),
        "outcome_counts_invalid",
        failures,
    )
    if all(_nonnegative_int(record.get(field)) for field in COUNT_FIELDS):
        _require(
            record["repeated_error_count"] <= record["repeated_error_opportunities"]
            and record["pattern_false_positive_count"]
            <= record["pattern_prediction_count"]
            and record["complete_provenance_count"]
            <= record["expected_provenance_count"],
            "outcome_count_relations_invalid",
            failures,
        )
    maturity = record.get("maturity_task_count")
    _require(
        maturity is None or (type(maturity) is int and 1 <= maturity <= 12),
        "outcome_maturity_task_count_invalid",
        failures,
    )
    _require(
        record.get("maturity_criteria") == MATURITY_CRITERIA,
        "outcome_maturity_criteria_invalid",
        failures,
    )
    scenarios = record.get("scenario_results")
    _require(
        isinstance(scenarios, dict)
        and set(scenarios) == REQUIRED_SCENARIOS
        and all(value is True for value in scenarios.values()),
        "outcome_scenario_coverage_invalid",
        failures,
    )
    if expected["cohort"] == "mentor":
        _require(
            _nonnegative_int(record.get("expected_provenance_count"))
            and record["expected_provenance_count"] > 0,
            "outcome_mentor_provenance_missing",
            failures,
        )
    else:
        _require(
            record.get("expected_provenance_count") == 0
            and record.get("complete_provenance_count") == 0
            and record.get("pattern_prediction_count") == 0
            and record.get("pattern_false_positive_count") == 0,
            "outcome_control_mentor_data_present",
            failures,
        )
    return list(dict.fromkeys(failures))


def _assignment_index(
    assignment: dict[str, Any], failures: list[str]
) -> dict[str, dict[str, str]]:
    if (
        assignment.get("status") != "operator_reviewed"
        or assignment.get("schema_version")
        != "j1-qualification-cohort-assignment-rebound:operator-reviewed:v1"
    ):
        failures.append("evaluator_assignment_invalid")
    result: dict[str, dict[str, str]] = {}
    pairs = assignment.get("assignments")
    for pair in pairs if isinstance(pairs, list) else []:
        if not isinstance(pair, dict):
            failures.append("evaluator_assignment_pair_invalid")
            continue
        for cohort in ("mentor", "control"):
            member = _object(pair.get(cohort))
            participant_id = _text(member.get("participant_id"))
            item = {
                "participant_id": participant_id,
                "participant_did": _text(member.get("execution_did")),
                "pair_id": _text(pair.get("pair_id")),
                "cohort": cohort,
            }
            if not all(item.values()) or participant_id in result:
                failures.append("evaluator_assignment_member_invalid")
            result[participant_id] = item
    if len(result) != 40:
        failures.append("evaluator_assignment_inventory_invalid")
    return result


def _metrics(
    manifest: dict[str, Any], pairs: list[dict[str, dict[str, Any]]]
) -> dict[str, Any]:
    mentor_times = [_maturity(pair["mentor"]) for pair in pairs]
    control_times = [_maturity(pair["control"]) for pair in pairs]
    mentor_mean = fmean(mentor_times)
    control_mean = fmean(control_times)
    mentor_errors = sum(pair["mentor"]["repeated_error_count"] for pair in pairs)
    mentor_opportunities = sum(
        pair["mentor"]["repeated_error_opportunities"] for pair in pairs
    )
    control_errors = sum(pair["control"]["repeated_error_count"] for pair in pairs)
    control_opportunities = sum(
        pair["control"]["repeated_error_opportunities"] for pair in pairs
    )
    mentor_rate = mentor_errors / mentor_opportunities if mentor_opportunities else 0.0
    control_rate = (
        control_errors / control_opportunities if control_opportunities else 0.0
    )
    predictions = sum(pair["mentor"]["pattern_prediction_count"] for pair in pairs)
    false_positives = sum(
        pair["mentor"]["pattern_false_positive_count"] for pair in pairs
    )
    mentor_cost = sum(pair["mentor"]["cost_microunits"] for pair in pairs)
    control_cost = sum(pair["control"]["cost_microunits"] for pair in pairs)
    avoided_errors = control_errors - mentor_errors
    return {
        "strategy_maturity_time": {
            "mentor_mean_tasks": mentor_mean,
            "control_mean_tasks": control_mean,
            "mentor_mean_active_runtime_seconds": _mean(
                pairs, "mentor", "active_runtime_seconds"
            ),
            "control_mean_active_runtime_seconds": _mean(
                pairs, "control", "active_runtime_seconds"
            ),
            "mentor_mean_token_count": _mean(pairs, "mentor", "token_count"),
            "control_mean_token_count": _mean(pairs, "control", "token_count"),
            "relative_reduction": 1.0 - mentor_mean / control_mean
            if control_mean
            else 0.0,
            "paired_bootstrap_95pct": _bootstrap(manifest, mentor_times, control_times),
        },
        "repeated_error_rate": {
            "mentor": mentor_rate,
            "control": control_rate,
            "absolute_reduction": control_rate - mentor_rate,
            "relative_reduction": (
                1.0 - mentor_rate / control_rate if control_rate else 0.0
            ),
        },
        "mentor_pattern_prediction_count": predictions,
        "mentor_pattern_false_positive_rate": (
            false_positives / predictions if predictions else 0.0
        ),
        "unit_improvement_cost": {
            "mentor_cost_microunits": mentor_cost,
            "control_cost_microunits": control_cost,
            "incremental_cost_per_avoided_error": (
                (mentor_cost - control_cost) / avoided_errors
                if avoided_errors > 0
                else None
            ),
        },
    }


def _bootstrap(
    manifest: dict[str, Any], mentor: list[int], control: list[int]
) -> list[float]:
    iterations = manifest["analysis"]["bootstrap_iterations"]
    rng = random.Random(manifest["analysis"]["bootstrap_seed_sha256"])
    values = []
    for _ in range(iterations):
        indexes = [rng.randrange(len(mentor)) for _ in mentor]
        mentor_mean = fmean(mentor[index] for index in indexes)
        control_mean = fmean(control[index] for index in indexes)
        values.append(1.0 - mentor_mean / control_mean if control_mean else 0.0)
    values.sort()
    return [values[int(iterations * 0.025)], values[int(iterations * 0.975) - 1]]


def _maturity(record: dict[str, Any]) -> int:
    value = record.get("maturity_task_count")
    return (
        value
        if type(value) is int and record.get("maturity_criteria") == MATURITY_CRITERIA
        else 13
    )


def _mean(pairs: list[dict[str, dict[str, Any]]], cohort: str, field: str) -> float:
    return fmean(pair[cohort][field] for pair in pairs)


def _safeguards(records: list[dict[str, Any]]) -> dict[str, Any]:
    expected = sum(_count(item, "expected_provenance_count") for item in records)
    complete = sum(_count(item, "complete_provenance_count") for item in records)
    return {
        "sovereignty_violation_count": sum(
            _count(item, "sovereignty_violation_count") for item in records
        ),
        "direct_trust_increment_count": sum(
            _count(item, "direct_trust_increment_count") for item in records
        ),
        "provenance_completeness": complete / expected if expected else 1.0,
    }


def _thresholds_met(
    manifest: dict[str, Any], metrics: dict[str, Any], safeguards: dict[str, Any]
) -> bool:
    thresholds = manifest["metrics"]
    return (
        metrics["strategy_maturity_time"]["relative_reduction"]
        >= thresholds["strategy_maturity_time"]["minimum_relative_reduction"]
        and metrics["repeated_error_rate"]["absolute_reduction"] > 0
        and metrics["mentor_pattern_prediction_count"] > 0
        and metrics["mentor_pattern_false_positive_rate"]
        <= thresholds["mentor_pattern_false_positive_rate"]["maximum_rate"]
        and safeguards["provenance_completeness"]
        == thresholds["advice_provenance_completeness"]["required_ratio"]
        and safeguards["sovereignty_violation_count"] == 0
        and safeguards["direct_trust_increment_count"] == 0
    )


def _boundary(status: str) -> dict[str, bool]:
    return {
        "candidate_only": status == "review_required",
        "evaluation_allowed_after_execution": status == "operator_reviewed_frozen",
        "provider_api_call_performed": False,
        "model_invocation_performed": False,
        "agent_execution_performed": False,
        "participant_container_started": False,
        "backend_fact_append_performed": False,
        "ledger_append_performed": False,
        "effectiveness_claim_authorized": False,
    }


def _count(value: dict[str, Any], field: str) -> int:
    item = value.get(field)
    return item if _nonnegative_int(item) else 0


def _object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _text(value: Any) -> str:
    return str(value or "").strip()


def _sha256(value: Any) -> bool:
    text = _text(value)
    return len(text) == 64 and all(char in "0123456789abcdef" for char in text)


def _git_revision(value: Any) -> bool:
    text = _text(value)
    return len(text) == 40 and all(char in "0123456789abcdef" for char in text)


def _rfc3339(value: Any) -> bool:
    try:
        parsed = datetime.fromisoformat(_text(value).replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None


def _nonnegative_int(value: Any) -> bool:
    return type(value) is int and value >= 0


def _require(condition: bool, code: str, failures: list[str]) -> None:
    if not condition and code not in failures:
        failures.append(code)
