"""J1-D development protocol, assignment, and evaluator dry-run Gate."""

from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
from typing import Any, Callable

from benchmarks.j1.cohort_evaluation import evaluate_cohorts
from benchmarks.j1.controlled_comparison import (
    artifact_ref,
    canonical_sha256,
    read_json_object,
    validate_protocol,
    write_private_json,
)
from benchmarks.j1.matched_assignment import build_assignment


REPORT_SCHEMA = "j1-controlled-comparison-preflight-report:v1"
DEFAULT_PROTOCOL = (
    Path(__file__).parent / "j1" / "fixtures" / "controlled_comparison_protocol.json"
)
Mutation = Callable[[dict[str, Any]], None]


def run_gate(*, protocol_path: Path, output_path: Path) -> dict[str, Any]:
    failures: list[str] = []
    try:
        protocol = read_json_object(protocol_path)
    except (OSError, ValueError, json.JSONDecodeError):
        protocol = {}
        failures.append("protocol_artifact_unreadable")
    protocol_failures = validate_protocol(protocol)
    failures.extend(protocol_failures)
    negative_controls = (
        _protocol_negative_controls(protocol) if not protocol_failures else []
    )

    participants = _synthetic_participants(protocol) if not protocol_failures else []
    assignment = build_assignment(protocol, participants) if participants else {}
    records = _synthetic_records(assignment) if assignment.get("passed") is True else []
    evaluation = evaluate_cohorts(protocol, assignment, records) if records else {}
    fault_controls = (
        _evaluation_fault_controls(protocol, assignment, records) if records else []
    )
    checks = {
        "protocol_frozen_and_valid": not protocol_failures,
        "all_protocol_negative_controls_rejected": len(negative_controls) == 8
        and all(item["rejected"] for item in negative_controls),
        "matched_assignment_replayable": assignment.get("passed") is True
        and assignment.get("matched_pair_count")
        == protocol.get("assignment", {}).get("minimum_completed_pairs"),
        "synthetic_evaluator_structurally_valid": evaluation.get("passed") is True,
        "synthetic_result_not_qualification": evaluation.get("valid_for_qualification")
        is False,
        "all_evaluation_fault_controls_rejected": len(fault_controls) == 8
        and all(item["rejected"] for item in fault_controls),
    }
    failures.extend(name for name, passed in checks.items() if not passed)
    passed = not failures and all(checks.values())
    report = {
        "schema_version": REPORT_SCHEMA,
        "passed": passed,
        "failure_reasons": list(dict.fromkeys(failures)),
        "checks": checks,
        "source_protocol": artifact_ref(protocol_path)
        if protocol_path.is_file()
        else None,
        "protocol_sha256": canonical_sha256(protocol) if protocol else None,
        "negative_controls": negative_controls,
        "assignment_summary": {
            key: assignment.get(key)
            for key in (
                "schema_version",
                "passed",
                "participant_count",
                "matched_pair_count",
                "assignment_sha256",
                "synthetic_dry_run_only",
            )
        },
        "evaluation": evaluation,
        "evaluation_fault_controls": fault_controls,
        "readiness": {
            "state": (
                "j1d_development_preflight_passed_qualification_experiment_not_started"
                if passed
                else "blocked_j1d_development_preflight"
            ),
            "development_protocol_validated": passed,
            "matched_assignment_engine_validated": passed,
            "cohort_evaluator_validated": passed,
            "qualification_protocol_frozen": False,
            "real_participant_roster_bound": False,
            "controlled_experiment_execution_ready": False,
            "effectiveness_verified": False,
        },
        "execution_boundary": {
            "synthetic_dry_run_only": True,
            "real_agent_execution_allowed": False,
            "model_invocation_allowed": False,
            "backend_fact_append_allowed": False,
            "runtime_advice_injection_allowed": False,
            "external_side_effect_allowed": False,
            "production_evidence_allowed": False,
            "ledger_append_allowed": False,
            "effectiveness_claim_allowed": False,
            "maturity_upgrade_allowed": False,
        },
        "non_claims": [
            "synthetic_threshold_values_do_not_prove_mentorship_effectiveness",
            "development_preflight_does_not_freeze_the_real_model_or_provider",
            "development_preflight_does_not_start_j1d_qualification_execution",
            "j1d_preflight_does_not_satisfy_j1e_real_agent_evidence",
            "j1d_preflight_does_not_claim_sustainable_group_intelligence",
        ],
    }
    write_private_json(output_path, report)
    return report


def _synthetic_participants(protocol: dict[str, Any]) -> list[dict[str, Any]]:
    stack = protocol["frozen_stack"]
    corpus_id = protocol["task_corpus"]["corpus_id"]
    count = protocol["assignment"]["minimum_completed_pairs"]
    participants = []
    for pair in range(1, count + 1):
        identity_hash = canonical_sha256(["synthetic-identity-snapshot", pair])
        for member in ("a", "b"):
            participants.append(
                {
                    "participant_id": f"synthetic:pair:{pair:04d}:{member}",
                    "identity_snapshot_sha256": identity_hash,
                    "model_id": stack["model_id"],
                    "provider_id": stack["provider_id"],
                    "budget_id": stack["budget_id"],
                    "corpus_id": corpus_id,
                    "verifier_id": stack["verifier_id"],
                }
            )
    return participants


def _synthetic_records(assignment: dict[str, Any]) -> list[dict[str, Any]]:
    records = []
    mentor_index = 0
    scenarios = {
        "repeated_error": True,
        "harmful_advice": True,
        "advice_refusal": True,
        "relation_revocation": True,
        "runtime_restart": True,
        "credential_rotation": True,
    }
    for item in assignment["assignments"]:
        mentor = item["cohort"] == "mentor"
        if mentor:
            mentor_index += 1
        records.append(
            {
                "participant_id": item["participant_id"],
                "protocol_sha256": assignment["protocol_sha256"],
                "assignment_sha256": assignment["assignment_sha256"],
                "evidence_mode": "synthetic_dry_run",
                "maturity_task_count": 3 if mentor else 8,
                "maturity_criteria": {
                    "consecutive_verified_tasks": 3,
                    "hard_violation_count": 0,
                    "repeated_error_free_window": True,
                    "evidence_complete": True,
                    "operator_override_used": False,
                },
                "active_runtime_seconds": 300 if mentor else 800,
                "token_count": 1000 if mentor else 1800,
                "repeated_error_count": 1 if mentor else 4,
                "repeated_error_opportunities": 10,
                "pattern_prediction_count": 2 if mentor else 0,
                "pattern_false_positive_count": 1
                if mentor and mentor_index == 1
                else 0,
                "expected_provenance_count": 3 if mentor else 0,
                "complete_provenance_count": 3 if mentor else 0,
                "sovereignty_violation_count": 0,
                "direct_trust_increment_count": 0,
                "cost_microunits": 1200 if mentor else 1000,
                "scenario_results": scenarios,
            }
        )
    return records


def _protocol_negative_controls(protocol: dict[str, Any]) -> list[dict[str, Any]]:
    controls: tuple[tuple[str, str, Mutation], ...] = (
        (
            "corpus_hash_drift",
            "task_corpus_hash_mismatch",
            lambda value: value["task_corpus"].__setitem__("tasks_sha256", "0" * 64),
        ),
        (
            "model_unset",
            "model_id_missing",
            lambda value: value["frozen_stack"].__setitem__("model_id", ""),
        ),
        (
            "sample_too_small",
            "minimum_completed_pairs_too_small",
            lambda value: value["assignment"].__setitem__("minimum_completed_pairs", 4),
        ),
        (
            "automatic_matching",
            "automatic_matching_must_be_false",
            lambda value: value["assignment"].__setitem__(
                "automatic_matching_allowed", True
            ),
        ),
        (
            "threshold_lowered",
            "maturity_threshold_invalid",
            lambda value: value["metrics"]["strategy_maturity_time"].__setitem__(
                "minimum_relative_reduction", 0.1
            ),
        ),
        (
            "efficacy_early_stop",
            "efficacy_early_stop_must_be_false",
            lambda value: value["analysis"].__setitem__(
                "efficacy_early_stop_allowed", True
            ),
        ),
        (
            "outcome_exclusion",
            "outcome_exclusion_must_be_false",
            lambda value: value["analysis"].__setitem__(
                "outcome_based_exclusion_allowed", True
            ),
        ),
        (
            "effectiveness_claim",
            "effectiveness_claim_allowed_must_be_false",
            lambda value: value["execution_boundary"].__setitem__(
                "effectiveness_claim_allowed", True
            ),
        ),
    )
    results = []
    for control_id, expected, mutation in controls:
        candidate = copy.deepcopy(protocol)
        mutation(candidate)
        observed = validate_protocol(candidate)
        results.append(
            {
                "control_id": control_id,
                "expected_failure": expected,
                "observed_failures": observed,
                "rejected": expected in observed,
            }
        )
    return results


def _evaluation_fault_controls(
    protocol: dict[str, Any],
    assignment: dict[str, Any],
    records: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    cases = []
    missing = evaluate_cohorts(protocol, assignment, records[:-1])
    cases.append(("missing_result", "result_record_set_incomplete", missing))
    trust_records = copy.deepcopy(records)
    trust_records[0]["direct_trust_increment_count"] = 1
    cases.append(
        (
            "direct_trust_increment",
            "direct_trust_increment_observed",
            evaluate_cohorts(protocol, assignment, trust_records),
        )
    )
    provenance = copy.deepcopy(records)
    mentor = next(item for item in provenance if item["expected_provenance_count"] > 0)
    mentor["complete_provenance_count"] -= 1
    cases.append(
        (
            "missing_provenance",
            "advice_provenance_incomplete",
            evaluate_cohorts(protocol, assignment, provenance),
        )
    )
    drifted = copy.deepcopy(assignment)
    drifted["protocol_sha256"] = "0" * 64
    cases.append(
        (
            "protocol_assignment_drift",
            "assignment_protocol_hash_mismatch",
            evaluate_cohorts(protocol, drifted, records),
        )
    )
    result_drift = copy.deepcopy(records)
    result_drift[0]["assignment_sha256"] = "0" * 64
    cases.append(
        (
            "result_assignment_drift",
            "result_assignment_hash_mismatch",
            evaluate_cohorts(protocol, assignment, result_drift),
        )
    )
    maturity_drift = copy.deepcopy(records)
    maturity_drift[0]["maturity_criteria"]["evidence_complete"] = False
    cases.append(
        (
            "maturity_criteria_drift",
            "result_maturity_criteria_invalid",
            evaluate_cohorts(protocol, assignment, maturity_drift),
        )
    )
    control_pollution = copy.deepcopy(records)
    control = next(
        item for item in control_pollution if item["expected_provenance_count"] == 0
    )
    control["pattern_prediction_count"] = 1
    cases.append(
        (
            "control_cohort_pollution",
            "control_cohort_mentor_data_observed",
            evaluate_cohorts(protocol, assignment, control_pollution),
        )
    )
    budget_overrun = copy.deepcopy(records)
    budget_overrun[0]["token_count"] = (
        protocol["frozen_stack"]["budget"]["max_tokens"] + 1
    )
    cases.append(
        (
            "token_budget_overrun",
            "result_token_budget_exceeded",
            evaluate_cohorts(protocol, assignment, budget_overrun),
        )
    )
    return [
        {
            "control_id": control_id,
            "expected_failure": expected,
            "observed_failures": report["failure_reasons"],
            "rejected": report["passed"] is False
            and expected in report["failure_reasons"],
        }
        for control_id, expected, report in cases
    ]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--protocol", type=Path, default=DEFAULT_PROTOCOL)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = run_gate(protocol_path=args.protocol, output_path=args.output)
    print(json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
