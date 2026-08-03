"""Build a content-free descriptive postmortem for a complete J1-D run."""

from __future__ import annotations

import copy
import hashlib
from collections import Counter, defaultdict
from typing import Any

from .controlled_comparison import canonical_sha256
from .qualification_outcome_sensitive_evaluation import build_participant_outcome


POSTMORTEM_SCHEMA = "j1-qualification-outcome-sensitive-postmortem:v1"
REVIEW_REQUEST_SCHEMA = "j1-qualification-outcome-sensitive-postmortem-review-request:v1"
HANDOFF_SCHEMA = "j1-qualification-outcome-sensitive-postmortem-review-handoff:v1"
CLOSEOUT_STATE = (
    "successful_run_closed_structural_pass_thresholds_not_met_no_maturity_upgrade"
)
PHASE_ORDINALS = {
    "baseline_replay": (1, 2, 3),
    "near_transfer": (4, 5, 6),
    "heldout_transfer": (7, 8, 9),
    "false_positive_sentinels": (10, 11, 12),
}
REVIEW_CHECKLIST = (
    "immutable_r4_source_chain_replayed",
    "all_480_observations_bound_to_40_participant_outcomes",
    "baseline_balance_recomputed",
    "phase_and_ordinal_aggregates_recomputed",
    "pair_delta_distribution_recomputed",
    "advice_exposure_not_misreported_as_adherence",
    "confirmatory_inference_limitation_preserved",
    "hidden_ground_truth_and_provider_content_not_disclosed",
    "no_causal_or_effectiveness_claim_added",
    "next_gate_does_not_reuse_r4_execution_material",
)
ANALYSIS_BOUNDARY = {
    "offline_replay_only": True,
    "participant_container_started": False,
    "provider_credential_read": False,
    "provider_api_call_performed": False,
    "model_invocation_performed": False,
    "agent_execution_performed": False,
    "backend_fact_append_performed": False,
    "ledger_append_performed": False,
    "hidden_ground_truth_persisted": False,
    "provider_response_content_persisted": False,
    "effectiveness_claim_authorized": False,
    "si13_maturity_upgrade_authorized": False,
}
NON_CLAIMS = [
    "no_mentorship_effectiveness_claim",
    "no_causal_harm_claim",
    "no_causal_null_claim",
    "no_long_term_sustainability_claim",
    "no_si13_maturity_upgrade",
]


def build_postmortem(
    *,
    postmortem_id: str,
    created_at: str,
    source_binding: dict[str, Any],
    implementation: dict[str, Any],
    participant_records: list[dict[str, Any]],
    observations: dict[str, list[dict[str, Any]]],
    evaluation_report: dict[str, Any],
    closeout_gate: dict[str, Any],
) -> dict[str, Any]:
    """Aggregate immutable r4 outcomes without introducing a causal claim."""
    participants = _participant_index(participant_records)
    observation_rows = _observation_rows(participants, observations)
    phase_summary = _phase_summary(observation_rows)
    ordinal_summary = _ordinal_summary(observation_rows)
    pair_summary = _pair_summary(participants)
    cohort_summary = _cohort_summary(participants)
    budget_comparison = _budget_comparison(observation_rows)
    failures = _validate_sources(
        participant_records=participant_records,
        evaluation_report=evaluation_report,
        closeout_gate=closeout_gate,
    )
    if failures:
        raise ValueError(f"outcome-sensitive postmortem source invalid: {failures}")

    report = {
        "schema_version": POSTMORTEM_SCHEMA,
        "postmortem_id": postmortem_id,
        "created_at": created_at,
        "run_id": evaluation_report["run_id"],
        "source_binding": copy.deepcopy(source_binding),
        "implementation": copy.deepcopy(implementation),
        "scope": {
            "participant_count": 40,
            "matched_pair_count": 20,
            "task_execution_count": 480,
            "tasks_per_participant": 12,
            "phase_count": 4,
        },
        "measurement_boundary": {
            "decision_fields_observed": [
                "selected_action_id",
                "predicted_pattern_ids",
            ],
            "direct_behavior_observation_count": 480,
            "advice_exposure_observed": True,
            "advice_provenance_observed": True,
            "advice_adherence_observed": False,
            "advice_adherence_limitation": (
                "frozen_decision_schema_has_no_accept_reject_defer_advice_field"
            ),
            "causal_root_cause_determined": False,
            "confirmatory_inference_valid": False,
        },
        "phase_summary": phase_summary,
        "ordinal_summary": ordinal_summary,
        "cohort_outcome_summary": cohort_summary,
        "pair_summary": pair_summary,
        "budget_comparison": budget_comparison,
        "descriptive_findings": _findings(
            phase_summary=phase_summary,
            ordinal_summary=ordinal_summary,
            pair_summary=pair_summary,
            budget_comparison=budget_comparison,
        ),
        "next_gate_requirements": [
            "do_not_replay_or_reuse_r4_authorization_claim_tasks_or_provider_calls",
            "freeze_exact_paired_test_and_test_statistic_before_new_execution",
            "freeze_resampling_or_permutation_tie_missingness_and_censoring_rules",
            "freeze_holm_family_and_adjustment_order_before_new_execution",
            "independently_review_task_discriminability_and_heldout_pattern_endpoint",
            "treat_explicit_advice_adherence_as_a_protocol_schema_change",
            "obtain_new_participant_consent_if_the_reviewed_scope_changes",
            "require_fresh_infrastructure_provider_preflight_and_single_use_authorization",
        ],
        "non_claims": list(NON_CLAIMS),
        "execution_boundary": copy.deepcopy(ANALYSIS_BOUNDARY),
        "state": "descriptive_postmortem_complete_independent_review_required",
    }
    report["report_sha256"] = canonical_sha256(report)
    failures = validate_postmortem(report)
    if failures:
        raise ValueError(f"outcome-sensitive postmortem invalid: {failures}")
    return report


def validate_postmortem(value: Any) -> list[str]:
    report = value if isinstance(value, dict) else {}
    failures: list[str] = []
    scope = report.get("scope", {})
    measurement = report.get("measurement_boundary", {})
    findings = report.get("descriptive_findings")
    if not (
        report.get("schema_version") == POSTMORTEM_SCHEMA
        and scope.get("participant_count") == 40
        and scope.get("matched_pair_count") == 20
        and scope.get("task_execution_count") == 480
        and scope.get("tasks_per_participant") == 12
        and scope.get("phase_count") == 4
        and measurement.get("direct_behavior_observation_count") == 480
        and measurement.get("advice_exposure_observed") is True
        and measurement.get("advice_provenance_observed") is True
        and measurement.get("advice_adherence_observed") is False
        and measurement.get("causal_root_cause_determined") is False
        and measurement.get("confirmatory_inference_valid") is False
        and isinstance(findings, list)
        and len(findings) == 6
        and all(item.get("causal_claim_allowed") is False for item in findings)
        and report.get("non_claims") == NON_CLAIMS
        and report.get("execution_boundary") == ANALYSIS_BOUNDARY
        and report.get("state")
        == "descriptive_postmortem_complete_independent_review_required"
    ):
        failures.append("outcome_postmortem_contract_invalid")
    phases = report.get("phase_summary")
    if not (
        isinstance(phases, list)
        and [item.get("phase") for item in phases] == list(PHASE_ORDINALS)
        and all(item.get("task_count_per_cohort") == 60 for item in phases)
    ):
        failures.append("outcome_postmortem_phase_summary_invalid")
    ordinals = report.get("ordinal_summary")
    if not (
        isinstance(ordinals, list)
        and [item.get("task_ordinal") for item in ordinals] == list(range(1, 13))
        and all(item.get("task_count_per_cohort") == 20 for item in ordinals)
    ):
        failures.append("outcome_postmortem_ordinal_summary_invalid")
    body = {key: item for key, item in report.items() if key != "report_sha256"}
    if report.get("report_sha256") != canonical_sha256(body):
        failures.append("outcome_postmortem_hash_invalid")
    return list(dict.fromkeys(failures))


def build_review_request(
    *,
    request_id: str,
    created_at: str,
    postmortem_ref: dict[str, str],
    postmortem: dict[str, Any],
) -> dict[str, Any]:
    failures = validate_postmortem(postmortem)
    if failures:
        raise ValueError(f"outcome-sensitive postmortem review source invalid: {failures}")
    request = {
        "schema_version": REVIEW_REQUEST_SCHEMA,
        "request_id": request_id,
        "created_at": created_at,
        "postmortem": copy.deepcopy(postmortem_ref),
        "run_id": postmortem["run_id"],
        "required_decision": "approve_outcome_sensitive_r4_descriptive_postmortem",
        "required_checklist": list(REVIEW_CHECKLIST),
        "execution_boundary": copy.deepcopy(ANALYSIS_BOUNDARY),
    }
    request["request_sha256"] = canonical_sha256(request)
    return request


def owner_review_statement(
    *,
    postmortem_raw_sha256: str,
    postmortem_canonical_sha256: str,
    request_raw_sha256: str,
    request_canonical_sha256: str,
    run_id: str,
) -> str:
    return (
        "I approve for independent review only the J1-D outcome-sensitive r4 "
        f"descriptive postmortem artifact raw SHA-256 {postmortem_raw_sha256}, "
        f"canonical SHA-256 {postmortem_canonical_sha256}, and review request raw "
        f"SHA-256 {request_raw_sha256}, canonical SHA-256 "
        f"{request_canonical_sha256}, bound to completed run {run_id}. I "
        "acknowledge that the postmortem reports aggregate phase, ordinal, pair, "
        "budget, advice-exposure, and provenance observations only; advice "
        "adherence was not directly observed, confirmatory inference remains "
        "invalid, and no causal root cause is determined. This approval permits "
        "only independent human review of the immutable descriptive postmortem. "
        "It does not amend the protocol, fixture, evaluator, statistical plan, "
        "advice, roster, assignment, consent, or infrastructure; start a container, "
        "read a provider credential, call a provider or model, execute an Agent or "
        "task, append Backend Facts or the Ledger, issue or consume an execution "
        "authorization, authorize an effectiveness or causal claim, or upgrade "
        "SI-13 maturity."
    )


def build_review_handoff(
    *,
    postmortem_ref: dict[str, str],
    request_ref: dict[str, str],
    statement: str,
) -> dict[str, Any]:
    handoff = {
        "schema_version": HANDOFF_SCHEMA,
        "status": "owner_review_authorization_required",
        "postmortem": copy.deepcopy(postmortem_ref),
        "review_request": copy.deepcopy(request_ref),
        "required_exact_approval_statement": statement,
        "statement_sha256": hashlib.sha256(statement.encode()).hexdigest(),
        "execution_boundary": copy.deepcopy(ANALYSIS_BOUNDARY),
    }
    handoff["handoff_sha256"] = canonical_sha256(handoff)
    return handoff


def _participant_index(
    records: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for record in records:
        participant_id = str(record.get("participant_id") or "")
        if (
            not participant_id
            or participant_id in result
            or record.get("cohort") not in {"mentor", "control"}
            or record.get("task_count") != 12
            or record.get("outcome_sha256")
            != canonical_sha256(
                {key: item for key, item in record.items() if key != "outcome_sha256"}
            )
        ):
            raise ValueError("outcome-sensitive participant record invalid")
        result[participant_id] = record
    pairs = defaultdict(set)
    for record in result.values():
        pairs[str(record["pair_id"])].add(str(record["cohort"]))
    if (
        len(result) != 40
        or Counter(item["cohort"] for item in result.values())
        != Counter({"mentor": 20, "control": 20})
        or len(pairs) != 20
        or any(cohorts != {"mentor", "control"} for cohorts in pairs.values())
    ):
        raise ValueError("outcome-sensitive participant inventory invalid")
    return result


def _observation_rows(
    participants: dict[str, dict[str, Any]],
    observations: dict[str, list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    if set(observations) != set(participants):
        raise ValueError("outcome-sensitive observation participant set invalid")
    rows = []
    for participant_id, participant in participants.items():
        ordered = sorted(
            observations[participant_id], key=lambda item: item["task_ordinal"]
        )
        if [item.get("task_ordinal") for item in ordered] != list(range(1, 13)):
            raise ValueError("outcome-sensitive observation ordinal set invalid")
        rebuilt = build_participant_outcome(
            run_id=str(participant["run_id"]),
            authorization_sha256=str(
                participant["execution_authorization_sha256"]
            ),
            participant={
                "participant_id": participant_id,
                "participant_did": str(participant["participant_did"]),
                "pair_id": str(participant["pair_id"]),
                "cohort": str(participant["cohort"]),
            },
            observations=ordered,
        )
        if rebuilt != participant:
            raise ValueError("outcome-sensitive participant outcome replay drifted")
        for item in ordered:
            ordinal = item["task_ordinal"]
            rows.append(
                {
                    **copy.deepcopy(item),
                    "participant_id": participant_id,
                    "pair_id": participant["pair_id"],
                    "cohort": participant["cohort"],
                    "phase": _phase_for_ordinal(ordinal),
                }
            )
    if len(rows) != 480:
        raise ValueError("outcome-sensitive observation count invalid")
    return rows


def _phase_summary(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result = []
    for phase, ordinals in PHASE_ORDINALS.items():
        cohorts = {}
        for cohort in ("mentor", "control"):
            selected = [
                item
                for item in rows
                if item["phase"] == phase and item["cohort"] == cohort
            ]
            cohorts[cohort] = _task_aggregate(selected)
        result.append(
            {
                "phase": phase,
                "task_ordinals": list(ordinals),
                "task_count_per_cohort": 60,
                "mentor": cohorts["mentor"],
                "control": cohorts["control"],
                "control_minus_mentor": _aggregate_delta(
                    cohorts["control"], cohorts["mentor"]
                ),
            }
        )
    return result


def _ordinal_summary(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result = []
    for ordinal in range(1, 13):
        cohorts = {}
        for cohort in ("mentor", "control"):
            selected = [
                item
                for item in rows
                if item["task_ordinal"] == ordinal and item["cohort"] == cohort
            ]
            cohorts[cohort] = _task_aggregate(selected)
        result.append(
            {
                "task_ordinal": ordinal,
                "phase": _phase_for_ordinal(ordinal),
                "task_count_per_cohort": 20,
                "mentor": cohorts["mentor"],
                "control": cohorts["control"],
                "control_minus_mentor": _aggregate_delta(
                    cohorts["control"], cohorts["mentor"]
                ),
            }
        )
    return result


def _task_aggregate(rows: list[dict[str, Any]]) -> dict[str, Any]:
    count = len(rows)
    fields = {
        "action_exact_count": sum(bool(item["action_exact"]) for item in rows),
        "pattern_exact_count": sum(bool(item["pattern_exact"]) for item in rows),
        "accepted_count": sum(bool(item["accepted"]) for item in rows),
        "advice_exposure_count": sum(bool(item["advice_expected"]) for item in rows),
        "advice_provenance_complete_count": sum(
            bool(item["advice_provenance_complete"]) for item in rows
        ),
        "hard_violation_count": sum(bool(item["hard_violation"]) for item in rows),
        "actual_tokens": sum(int(item["actual_tokens"]) for item in rows),
        "actual_cost_microunits": sum(
            int(item["actual_cost_microunits"]) for item in rows
        ),
    }
    return {
        "task_count": count,
        **fields,
        "action_exact_rate": _rate(fields["action_exact_count"], count),
        "pattern_exact_rate": _rate(fields["pattern_exact_count"], count),
        "accepted_rate": _rate(fields["accepted_count"], count),
    }


def _aggregate_delta(control: dict[str, Any], mentor: dict[str, Any]) -> dict[str, int]:
    return {
        field: int(control[field]) - int(mentor[field])
        for field in (
            "action_exact_count",
            "pattern_exact_count",
            "accepted_count",
            "actual_tokens",
            "actual_cost_microunits",
        )
    }


def _cohort_summary(
    participants: dict[str, dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    result = {}
    for cohort in ("mentor", "control"):
        rows = [item for item in participants.values() if item["cohort"] == cohort]
        result[cohort] = {
            "participant_count": len(rows),
            "accepted_task_count": sum(item["accepted_task_count"] for item in rows),
            "pattern_exact_count": sum(item["pattern_exact_count"] for item in rows),
            "repeated_error_count": sum(item["repeated_error_count"] for item in rows),
            "repeated_error_opportunity_count": sum(
                item["repeated_error_opportunity_count"] for item in rows
            ),
            "maturity_mean_ordinal": _rate(
                sum(item["maturity_ordinal"] for item in rows), len(rows)
            ),
            "maturity_distribution": _counter(
                item["maturity_ordinal"] for item in rows
            ),
            "maturity_censored_count": sum(
                bool(item["maturity_censored"]) for item in rows
            ),
        }
    return result


def _pair_summary(
    participants: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    pairs: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)
    for participant in participants.values():
        pairs[str(participant["pair_id"])][str(participant["cohort"])] = participant
    accepted_deltas = []
    maturity_deltas = []
    repeated_deltas = []
    for pair in pairs.values():
        mentor = pair["mentor"]
        control = pair["control"]
        accepted_deltas.append(
            control["accepted_task_count"] - mentor["accepted_task_count"]
        )
        maturity_deltas.append(
            control["maturity_ordinal"] - mentor["maturity_ordinal"]
        )
        repeated_deltas.append(
            control["repeated_error_count"] - mentor["repeated_error_count"]
        )
    return {
        "pair_count": len(pairs),
        "accepted_task_delta_control_minus_mentor": {
            "distribution": _counter(accepted_deltas),
            "control_better_pair_count": sum(item > 0 for item in accepted_deltas),
            "tie_pair_count": sum(item == 0 for item in accepted_deltas),
            "mentor_better_pair_count": sum(item < 0 for item in accepted_deltas),
        },
        "maturity_ordinal_delta_control_minus_mentor": {
            "distribution": _counter(maturity_deltas),
            "control_faster_pair_count": sum(item < 0 for item in maturity_deltas),
            "tie_pair_count": sum(item == 0 for item in maturity_deltas),
            "mentor_faster_pair_count": sum(item > 0 for item in maturity_deltas),
        },
        "repeated_error_delta_control_minus_mentor": {
            "distribution": _counter(repeated_deltas),
            "control_lower_pair_count": sum(item < 0 for item in repeated_deltas),
            "tie_pair_count": sum(item == 0 for item in repeated_deltas),
            "mentor_lower_pair_count": sum(item > 0 for item in repeated_deltas),
        },
        "pair_delta_set_sha256": canonical_sha256(
            [
                {
                    "pair_id": pair_id,
                    "accepted_delta": (
                        pair["control"]["accepted_task_count"]
                        - pair["mentor"]["accepted_task_count"]
                    ),
                    "maturity_delta": (
                        pair["control"]["maturity_ordinal"]
                        - pair["mentor"]["maturity_ordinal"]
                    ),
                    "repeated_error_delta": (
                        pair["control"]["repeated_error_count"]
                        - pair["mentor"]["repeated_error_count"]
                    ),
                }
                for pair_id, pair in sorted(pairs.items())
            ]
        ),
    }


def _budget_comparison(rows: list[dict[str, Any]]) -> dict[str, Any]:
    totals = {}
    for cohort in ("mentor", "control"):
        selected = [item for item in rows if item["cohort"] == cohort]
        totals[cohort] = {
            "actual_tokens": sum(item["actual_tokens"] for item in selected),
            "actual_cost_microunits": sum(
                item["actual_cost_microunits"] for item in selected
            ),
        }
    return {
        **totals,
        "mentor_minus_control": {
            field: totals["mentor"][field] - totals["control"][field]
            for field in ("actual_tokens", "actual_cost_microunits")
        },
    }


def _findings(
    *,
    phase_summary: list[dict[str, Any]],
    ordinal_summary: list[dict[str, Any]],
    pair_summary: dict[str, Any],
    budget_comparison: dict[str, Any],
) -> list[dict[str, Any]]:
    phases = {item["phase"]: item for item in phase_summary}
    ceiling = [
        item["task_ordinal"]
        for item in ordinal_summary
        if item["mentor"]["accepted_count"] == 20
        and item["control"]["accepted_count"] == 20
    ]
    floor = [
        item["task_ordinal"]
        for item in ordinal_summary
        if item["mentor"]["accepted_count"] == 0
        and item["control"]["accepted_count"] == 0
    ]
    discriminating = [
        item["task_ordinal"]
        for item in ordinal_summary
        if item["mentor"]["accepted_count"] != item["control"]["accepted_count"]
    ]
    return [
        {
            "finding_id": "baseline_balance",
            "classification": "balanced_on_observed_baseline_scores",
            "mentor_accepted_count": phases["baseline_replay"]["mentor"][
                "accepted_count"
            ],
            "control_accepted_count": phases["baseline_replay"]["control"][
                "accepted_count"
            ],
            "causal_claim_allowed": False,
        },
        {
            "finding_id": "phase_concentration",
            "classification": "descriptive_control_advantage_concentrated_in_transfer",
            "near_transfer_control_minus_mentor_accepted": phases["near_transfer"][
                "control_minus_mentor"
            ]["accepted_count"],
            "heldout_control_minus_mentor_accepted": phases["heldout_transfer"][
                "control_minus_mentor"
            ]["accepted_count"],
            "sentinel_control_minus_mentor_accepted": phases[
                "false_positive_sentinels"
            ]["control_minus_mentor"]["accepted_count"],
            "causal_claim_allowed": False,
        },
        {
            "finding_id": "task_discriminability",
            "classification": "observed_score_separation_is_sparse",
            "joint_ceiling_ordinals": ceiling,
            "joint_floor_ordinals": floor,
            "cohort_differentiating_ordinals": discriminating,
            "causal_claim_allowed": False,
        },
        {
            "finding_id": "pair_distribution",
            "classification": "no_pair_showed_mentor_accepted_task_advantage",
            **pair_summary["accepted_task_delta_control_minus_mentor"],
            "causal_claim_allowed": False,
        },
        {
            "finding_id": "advice_measurement",
            "classification": "exposure_complete_adherence_unobserved",
            "mentor_advice_exposure_count": sum(
                item["mentor"]["advice_exposure_count"] for item in phase_summary
            ),
            "mentor_advice_provenance_complete_count": sum(
                item["mentor"]["advice_provenance_complete_count"]
                for item in phase_summary
            ),
            "advice_adherence_observed": False,
            "causal_claim_allowed": False,
        },
        {
            "finding_id": "budget",
            "classification": "mentor_cohort_used_more_tokens_and_cost",
            **budget_comparison["mentor_minus_control"],
            "causal_claim_allowed": False,
        },
    ]


def _validate_sources(
    *,
    participant_records: list[dict[str, Any]],
    evaluation_report: dict[str, Any],
    closeout_gate: dict[str, Any],
) -> list[str]:
    failures = []
    if not (
        len(participant_records) == 40
        and evaluation_report.get("structural_passed") is True
        and evaluation_report.get("valid_for_qualification") is True
        and evaluation_report.get("effectiveness_thresholds_met") is False
        and evaluation_report.get("effectiveness_claim_authorized") is False
        and evaluation_report.get("confirmatory_inference", {}).get("valid") is False
    ):
        failures.append("outcome_postmortem_evaluation_source_invalid")
    if not (
        closeout_gate.get("passed") is True
        and closeout_gate.get("state") == CLOSEOUT_STATE
        and closeout_gate.get("terminal_summary", {}).get("task_execution_count")
        == 480
        and closeout_gate.get("terminal_summary", {}).get(
            "effectiveness_claim_authorized"
        )
        is False
        and closeout_gate.get("report_sha256")
        == canonical_sha256(
            {
                key: item
                for key, item in closeout_gate.items()
                if key != "report_sha256"
            }
        )
    ):
        failures.append("outcome_postmortem_closeout_source_invalid")
    return failures


def _phase_for_ordinal(ordinal: int) -> str:
    for phase, ordinals in PHASE_ORDINALS.items():
        if ordinal in ordinals:
            return phase
    raise ValueError("outcome-sensitive observation ordinal invalid")


def _counter(values: Any) -> dict[str, int]:
    return {str(key): count for key, count in sorted(Counter(values).items())}


def _rate(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 0.0
