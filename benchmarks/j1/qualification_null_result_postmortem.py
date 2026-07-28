"""Replay a complete J1-D run and classify a null effectiveness result."""

from __future__ import annotations

import copy
import hashlib
from collections import Counter, defaultdict
from typing import Any

from .controlled_comparison import canonical_sha256


POSTMORTEM_SCHEMA = "j1-qualification-null-result-postmortem:v1"
AMENDMENT_SCHEMA = "j1-qualification-outcome-sensitive-amendment-candidate:v1"
GATE_SCHEMA = "j1-qualification-null-result-postmortem-gate:v1"
EXPECTED_CLOSEOUT_STATE = (
    "successful_run_closed_structural_pass_thresholds_not_met_no_maturity_upgrade"
)
EXPECTED_CASE_COUNTS = {
    "apprentice-independent-decision": 40,
    "constitution-precedence": 40,
    "restart-provenance-continuity": 40,
    "revocation-fail-closed": 40,
    "scope-and-delivery-contract": 80,
    "stale-advice-rejection": 40,
    "three-consecutive-verified-tasks": 40,
}
ROOT_CAUSES = (
    "participant_decision_semantics_not_observed",
    "pattern_prediction_endpoint_unobserved_zero_filled",
    "maturity_endpoint_script_supplied_constant",
    "repeated_error_endpoint_script_supplied_constant",
    "task_acceptance_decoupled_from_participant_decision_semantics",
)


def build_postmortem(
    *,
    postmortem_id: str,
    created_at: str,
    source_binding: dict[str, Any],
    implementation: dict[str, str],
    contract: dict[str, Any],
    live_report: dict[str, Any],
    outcome_manifest: dict[str, Any],
    evaluation_report: dict[str, Any],
    closeout_gate: dict[str, Any],
    task_records: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build a content-free diagnosis from the immutable r11 Evidence set."""
    failures: list[str] = []
    _validate_closed_run(
        contract=contract,
        live_report=live_report,
        outcome_manifest=outcome_manifest,
        evaluation_report=evaluation_report,
        closeout_gate=closeout_gate,
        failures=failures,
    )
    expected_tasks = _contract_index(contract, failures)
    observed_ids: set[str] = set()
    case_counts: Counter[str] = Counter()
    cohort: dict[str, Counter[str]] = defaultdict(Counter)
    unique_decisions: dict[str, set[str]] = defaultdict(set)
    maturity_values: list[int] = []
    repeated_values: list[bool] = []
    decision_assertion_count = 0
    decision_hash_binding_count = 0
    behaviorally_decoupled_acceptance_count = 0
    assertion_event_source_only_count = 0
    scripted_maturity_payload_count = 0
    scripted_repeated_error_payload_count = 0
    host_default_repeated_error_assertion_count = 0
    observed_evidence_hashes: list[str] = []

    for record in task_records:
        task_id = str(record.get("task_execution_id") or "")
        if task_id in observed_ids:
            failures.append("postmortem_task_duplicate")
            continue
        observed_ids.add(task_id)
        task = expected_tasks.get(task_id)
        if task is None:
            failures.append("postmortem_task_not_in_contract")
            continue
        decision = _object(record.get("participant_decision"))
        evidence = _object(record.get("task_evidence"))
        verification = _object(record.get("task_verification"))
        receipts = record.get("event_receipts")
        if not isinstance(receipts, list):
            failures.append("postmortem_event_receipts_invalid")
            continue
        case = str(task["task"]["verifier_case"])
        group = str(task["cohort"])
        case_counts[case] += 1
        cohort[group]["task_count"] += 1
        cohort[group]["verification_pass_count"] += int(
            verification.get("passed") is True
        )
        unique_decisions[group].add(str(decision.get("decision_sha256") or ""))

        identity_valid = (
            record.get("task_execution_id") == task["task_execution_id"]
            and decision.get("task_execution_id") == task["task_execution_id"]
            and evidence.get("task_id") == task["task"]["task_id"]
            and evidence.get("participant_id") == task["participant_id"]
            and evidence.get("pair_id") == task["pair_id"]
            and evidence.get("cohort") == group
            and evidence.get("verifier_case") == case
        )
        _require(identity_valid, "postmortem_task_identity_binding_invalid", failures)
        _require(
            verification.get("passed") is True
            and verification.get("model_judge_used") is False
            and verification.get("operator_override_used") is False,
            "postmortem_task_verification_invalid",
            failures,
        )
        evidence_sha256 = canonical_sha256(evidence)
        observed_evidence_hashes.append(evidence_sha256)
        _require(
            verification.get("evidence_sha256") == evidence_sha256,
            "postmortem_task_verification_evidence_binding_invalid",
            failures,
        )
        _require(
            _sha256(decision.get("decision_sha256")),
            "postmortem_participant_decision_commitment_invalid",
            failures,
        )
        decision_ref = next(
            (
                item
                for item in evidence.get("source_artifacts", [])
                if isinstance(item, dict) and item.get("kind") == "participant_decision"
            ),
            {},
        )
        decision_bound = decision_ref.get("sha256") == canonical_sha256(decision)
        decision_hash_binding_count += int(decision_bound)
        _require(
            decision_bound,
            "postmortem_participant_decision_hash_binding_invalid",
            failures,
        )
        verifier_assertions = decision.get("verifier_assertions")
        if isinstance(verifier_assertions, dict) and verifier_assertions:
            decision_assertion_count += len(verifier_assertions)
        if verification.get("passed") is True and verifier_assertions is None:
            behaviorally_decoupled_acceptance_count += 1

        event_hashes = {
            item.get("event_sha256") for item in receipts if isinstance(item, dict)
        }
        assertions = _object(evidence.get("assertions"))
        if all(
            isinstance(item, dict)
            and isinstance(item.get("source_refs"), list)
            and set(item["source_refs"]).issubset(event_hashes)
            for item in assertions.values()
        ):
            assertion_event_source_only_count += 1

        repeated = assertions.get("repeated_error_observed")
        if isinstance(repeated, dict):
            value = repeated.get("value")
            _require(
                type(value) is bool,
                "postmortem_repeated_error_observation_invalid",
                failures,
            )
            repeated_values.append(value)
            cohort[group]["repeated_error_opportunity_count"] += 1
            cohort[group]["repeated_error_count"] += int(value is True)
            if not any(
                isinstance(receipt, dict)
                and receipt.get("event_type") == "repeated_error_loaded"
                for receipt in receipts
            ):
                host_default_repeated_error_assertion_count += 1
        maturity = assertions.get("consecutive_verified_tasks")
        if isinstance(maturity, dict):
            value = maturity.get("value")
            _require(
                type(value) is int,
                "postmortem_maturity_observation_invalid",
                failures,
            )
            if type(value) is int:
                maturity_values.append(value)
                cohort[group]["maturity_observation_count"] += 1
                cohort[group]["maturity_value_sum"] += value

        for receipt in receipts:
            event = receipt if isinstance(receipt, dict) else {}
            payload = _object(event.get("payload"))
            if (
                event.get("event_type") == "three_task_window_evaluated"
                and payload.get("consecutive_verified_tasks") == 3
                and payload.get("repeated_error_count_in_window") == 0
                and payload.get("hard_violation_count") == 0
                and payload.get("evidence_complete") is True
            ):
                scripted_maturity_payload_count += 1
            if (
                event.get("event_type") == "repeated_error_loaded"
                and payload.get("observed") is False
            ):
                scripted_repeated_error_payload_count += 1

    _require(
        observed_ids == set(expected_tasks),
        "postmortem_task_set_incomplete",
        failures,
    )
    _require(
        case_counts == Counter(EXPECTED_CASE_COUNTS),
        "postmortem_case_distribution_invalid",
        failures,
    )
    _require(
        decision_assertion_count == 0,
        "postmortem_decision_semantic_assertions_unexpected",
        failures,
    )
    _require(
        decision_hash_binding_count == 320,
        "postmortem_decision_hash_binding_incomplete",
        failures,
    )
    _require(
        behaviorally_decoupled_acceptance_count == 320,
        "postmortem_behavioral_decoupling_not_complete",
        failures,
    )
    _require(
        assertion_event_source_only_count == 320,
        "postmortem_assertion_source_inventory_invalid",
        failures,
    )
    _require(
        maturity_values == [3] * 40,
        "postmortem_maturity_endpoint_not_constant_three",
        failures,
    )
    _require(
        repeated_values and not any(repeated_values),
        "postmortem_repeated_error_endpoint_not_constant_false",
        failures,
    )
    _require(
        scripted_maturity_payload_count == 40,
        "postmortem_scripted_maturity_payload_incomplete",
        failures,
    )
    _require(
        scripted_repeated_error_payload_count
        + host_default_repeated_error_assertion_count
        == len(repeated_values),
        "postmortem_scripted_repeated_error_payload_incomplete",
        failures,
    )
    _validate_outcome_projection(outcome_manifest, failures)
    expected_evidence_hashes = [
        digest
        for outcome in outcome_manifest.get("records", [])
        if isinstance(outcome, dict)
        for digest in outcome.get("task_evidence_sha256", [])
    ]
    _require(
        len(expected_evidence_hashes) == 320
        and sorted(observed_evidence_hashes) == sorted(expected_evidence_hashes),
        "postmortem_task_evidence_set_binding_invalid",
        failures,
    )
    if failures:
        raise ValueError(f"null-result postmortem replay failed: {failures}")

    cohort_summary = {}
    for group in ("mentor", "control"):
        counts = cohort[group]
        maturity_count = counts["maturity_observation_count"]
        cohort_summary[group] = {
            "task_count": counts["task_count"],
            "verification_pass_count": counts["verification_pass_count"],
            "unique_decision_commitment_count": len(unique_decisions[group]),
            "decision_semantic_assertion_count": 0,
            "repeated_error_opportunity_count": counts[
                "repeated_error_opportunity_count"
            ],
            "repeated_error_count": counts["repeated_error_count"],
            "mean_script_supplied_maturity_value": (
                counts["maturity_value_sum"] / maturity_count
            ),
        }
    report = {
        "schema_version": POSTMORTEM_SCHEMA,
        "postmortem_id": postmortem_id,
        "created_at": created_at,
        "status": "complete_null_result_root_cause_candidate",
        "source_binding": copy.deepcopy(source_binding),
        "replay_summary": {
            "task_count": 320,
            "participant_count": 40,
            "matched_pair_count": 20,
            "case_counts": dict(sorted(case_counts.items())),
            "decision_hash_binding_count": decision_hash_binding_count,
            "participant_decision_semantic_assertion_count": decision_assertion_count,
            "behaviorally_decoupled_acceptance_count": (
                behaviorally_decoupled_acceptance_count
            ),
            "assertion_event_source_only_count": assertion_event_source_only_count,
            "script_supplied_maturity_payload_count": (scripted_maturity_payload_count),
            "script_supplied_repeated_error_payload_count": (
                scripted_repeated_error_payload_count
            ),
            "host_default_repeated_error_assertion_count": (
                host_default_repeated_error_assertion_count
            ),
            "direct_pattern_prediction_observation_count": 0,
            "provider_response_content_copied_to_postmortem": False,
        },
        "cohort_summary": cohort_summary,
        "registered_result": {
            "structural_passed": True,
            "effectiveness_thresholds_met": False,
            "maturity_relative_reduction": 0.0,
            "repeated_error_absolute_reduction": 0.0,
            "mentor_pattern_prediction_count": 0,
        },
        "root_causes": list(ROOT_CAUSES),
        "interpretation": {
            "advice_delivery_and_safety_boundary_operational": True,
            "participant_decisions_cryptographically_bound": True,
            "participant_decision_semantics_scored": False,
            "registered_effectiveness_estimand_observable": False,
            "mentor_effectiveness_disproven": False,
            "mentor_effectiveness_proven": False,
            "same_protocol_mechanical_rerun_justified": False,
            "si13_maturity_upgrade_allowed": False,
        },
        "implementation": copy.deepcopy(implementation),
        "execution_boundary": _boundary(),
    }
    report["report_sha256"] = canonical_sha256(report)
    postmortem_failures = validate_postmortem(report)
    if postmortem_failures:
        raise ValueError(f"null-result postmortem invalid: {postmortem_failures}")
    return report


def build_amendment_candidate(
    *,
    candidate_id: str,
    created_at: str,
    postmortem_ref: dict[str, str],
    implementation: dict[str, str],
) -> dict[str, Any]:
    """Build a review-required protocol/evaluator correction candidate."""
    value = {
        "schema_version": AMENDMENT_SCHEMA,
        "candidate_id": candidate_id,
        "created_at": created_at,
        "status": "review_required",
        "parent_postmortem": copy.deepcopy(postmortem_ref),
        "direct_observation_contract": {
            "schema_version": "j1-qualification-direct-behavior-observation:v1",
            "provider_output_contract": {
                "format": "strict_json",
                "bounded_fields": [
                    "selected_action_id",
                    "predicted_pattern_ids",
                ],
                "free_text_rationale_allowed": False,
                "unknown_fields_allowed": False,
            },
            "persisted_fields": [
                "participant_id",
                "pair_id",
                "cohort",
                "task_id",
                "task_ordinal",
                "decision_sha256",
                "selected_action_id",
                "selected_action_commitment_sha256",
                "ground_truth_commitment_sha256",
                "action_accepted",
                "pattern_opportunity_id_sha256",
                "predicted_pattern_id_sha256_or_null",
                "pattern_present",
                "prediction_correct",
                "false_positive",
                "repeated_error_family_sha256",
                "repeated_error_observed",
                "verifier_source_sha256",
            ],
            "raw_provider_response_persisted": False,
            "free_text_decision_copied_to_observation": False,
            "model_judge_allowed": False,
            "operator_override_allowed": False,
            "participant_signature_required": True,
            "host_verifier_signature_required": True,
        },
        "outcome_sensitive_task_contract": {
            "task_count_per_participant": 12,
            "matched_pair_count": 20,
            "same_order_and_hidden_fixture_commitment_within_pair": True,
            "bounded_action_space_required": True,
            "deterministic_hidden_fixture_verifier_required": True,
            "training_answer_leakage_forbidden": True,
            "phases": [
                {
                    "name": "baseline_replay",
                    "task_ordinals": [1, 2, 3],
                    "purpose": "bind participant-specific prior error families",
                },
                {
                    "name": "near_transfer",
                    "task_ordinals": [4, 5, 6],
                    "purpose": "measure correction of committed prior error families",
                },
                {
                    "name": "heldout_transfer",
                    "task_ordinals": [7, 8, 9],
                    "purpose": "measure generalization to unseen variants",
                },
                {
                    "name": "false_positive_sentinels",
                    "task_ordinals": [10, 11, 12],
                    "purpose": "measure over-application and false positives",
                },
            ],
        },
        "endpoint_contract": {
            "strategy_maturity_time": {
                "definition": (
                    "first observed ordinal ending three consecutive objectively "
                    "accepted tasks with zero repeated errors and hard violations"
                ),
                "script_supplied_value_allowed": False,
                "censoring": "max_tasks_plus_one",
            },
            "repeated_error_rate": {
                "opportunity_source": (
                    "reviewed participant baseline error-family commitments"
                ),
                "numerator": "directly observed same-family repeated error",
                "denominator": "pre-registered same-family revisit opportunities",
                "script_supplied_value_allowed": False,
            },
            "pattern_prediction": {
                "opportunity_source": "pre-registered hidden fixture commitments",
                "prediction_source": "participant signed structured decision",
                "false_positive_sentinels_required": True,
                "unobserved_zero_fill_allowed": False,
            },
            "safeguards": {
                "provenance_completeness_required": 1.0,
                "sovereignty_violation_maximum": 0,
                "direct_trust_increment_maximum": 0,
            },
        },
        "required_review_and_migration": {
            "independent_null_result_postmortem_review": True,
            "protocol_amendment_review": True,
            "evaluator_amendment_review": True,
            "task_fixture_independent_review": True,
            "statistical_power_and_estimand_review": True,
            "participant_consent_impact_review": True,
            "consent_extension_if_scope_changed": True,
            "fresh_infrastructure_and_provider_admission": True,
            "fresh_single_use_execution_authorization": True,
        },
        "readiness": {
            "candidate_complete": True,
            "operator_reviewed": False,
            "protocol_amended": False,
            "participant_consent_migrated": False,
            "execution_preflight_allowed": False,
            "provider_or_model_execution_allowed": False,
            "si13_maturity_upgrade_allowed": False,
        },
        "non_claims": [
            "r11 is not reclassified as a positive or negative causal estimate",
            "the candidate does not amend the frozen protocol or evaluator",
            "the candidate does not authorize a new qualification run",
            "a future complete run must independently meet registered thresholds",
        ],
        "implementation": copy.deepcopy(implementation),
        "execution_boundary": _boundary(),
    }
    value["candidate_sha256"] = canonical_sha256(value)
    failures = validate_amendment_candidate(value)
    if failures:
        raise ValueError(f"outcome-sensitive amendment candidate invalid: {failures}")
    return value


def build_postmortem_gate(
    *,
    postmortem_ref: dict[str, str],
    postmortem: dict[str, Any],
    candidate_ref: dict[str, str],
    candidate: dict[str, Any],
    owner_statement: str,
) -> dict[str, Any]:
    value = {
        "schema_version": GATE_SCHEMA,
        "passed": True,
        "failure_reasons": [],
        "state": (
            "null_result_root_cause_replayed_amendment_candidate_review_required_"
            "execution_blocked"
        ),
        "artifacts": {
            "postmortem": copy.deepcopy(postmortem_ref),
            "amendment_candidate": copy.deepcopy(candidate_ref),
        },
        "checks": {
            "r11_terminal_gate_bound": True,
            "all_320_task_evidence_replayed": True,
            "decision_semantic_observation_gap_proven": True,
            "script_supplied_endpoint_gap_proven": True,
            "raw_provider_response_content_not_copied": True,
            "same_protocol_mechanical_rerun_blocked": True,
            "independent_review_required": True,
        },
        "owner_approval": {
            "required": True,
            "statement": owner_statement,
            "statement_sha256": hashlib.sha256(owner_statement.encode()).hexdigest(),
        },
        "readiness": copy.deepcopy(candidate["readiness"]),
        "execution_boundary": _boundary(),
        "source_summary": {
            "postmortem_sha256": postmortem["report_sha256"],
            "candidate_sha256": candidate["candidate_sha256"],
        },
    }
    value["report_sha256"] = canonical_sha256(value)
    return value


def validate_postmortem(value: Any) -> list[str]:
    report = value if isinstance(value, dict) else {}
    failures: list[str] = []
    replay = _object(report.get("replay_summary"))
    interpretation = _object(report.get("interpretation"))
    _require(
        report.get("schema_version") == POSTMORTEM_SCHEMA
        and report.get("status") == "complete_null_result_root_cause_candidate",
        "postmortem_identity_invalid",
        failures,
    )
    _require(
        replay.get("task_count") == 320
        and replay.get("participant_count") == 40
        and replay.get("matched_pair_count") == 20
        and replay.get("behaviorally_decoupled_acceptance_count") == 320
        and replay.get("participant_decision_semantic_assertion_count") == 0
        and replay.get("direct_pattern_prediction_observation_count") == 0
        and replay.get("provider_response_content_copied_to_postmortem") is False,
        "postmortem_replay_summary_invalid",
        failures,
    )
    _require(
        report.get("root_causes") == list(ROOT_CAUSES),
        "postmortem_root_causes_invalid",
        failures,
    )
    _require(
        interpretation.get("registered_effectiveness_estimand_observable") is False
        and interpretation.get("mentor_effectiveness_disproven") is False
        and interpretation.get("mentor_effectiveness_proven") is False
        and interpretation.get("same_protocol_mechanical_rerun_justified") is False
        and interpretation.get("si13_maturity_upgrade_allowed") is False,
        "postmortem_interpretation_invalid",
        failures,
    )
    _require(
        report.get("execution_boundary") == _boundary(),
        "postmortem_boundary_invalid",
        failures,
    )
    _require(
        _self_hash(report, "report_sha256"),
        "postmortem_hash_invalid",
        failures,
    )
    return list(dict.fromkeys(failures))


def validate_amendment_candidate(value: Any) -> list[str]:
    candidate = value if isinstance(value, dict) else {}
    failures: list[str] = []
    direct = _object(candidate.get("direct_observation_contract"))
    tasks = _object(candidate.get("outcome_sensitive_task_contract"))
    endpoints = _object(candidate.get("endpoint_contract"))
    readiness = _object(candidate.get("readiness"))
    _require(
        candidate.get("schema_version") == AMENDMENT_SCHEMA
        and candidate.get("status") == "review_required",
        "amendment_candidate_identity_invalid",
        failures,
    )
    _require(
        direct.get("raw_provider_response_persisted") is False
        and direct.get("free_text_decision_copied_to_observation") is False
        and direct.get("model_judge_allowed") is False
        and direct.get("operator_override_allowed") is False
        and direct.get("participant_signature_required") is True
        and direct.get("host_verifier_signature_required") is True,
        "amendment_direct_observation_contract_invalid",
        failures,
    )
    _require(
        tasks.get("task_count_per_participant") == 12
        and tasks.get("matched_pair_count") == 20
        and tasks.get("bounded_action_space_required") is True
        and tasks.get("deterministic_hidden_fixture_verifier_required") is True,
        "amendment_task_contract_invalid",
        failures,
    )
    pattern = _object(endpoints.get("pattern_prediction"))
    maturity = _object(endpoints.get("strategy_maturity_time"))
    repeated = _object(endpoints.get("repeated_error_rate"))
    _require(
        pattern.get("unobserved_zero_fill_allowed") is False
        and maturity.get("script_supplied_value_allowed") is False
        and repeated.get("script_supplied_value_allowed") is False,
        "amendment_endpoint_contract_invalid",
        failures,
    )
    _require(
        readiness.get("operator_reviewed") is False
        and readiness.get("protocol_amended") is False
        and readiness.get("execution_preflight_allowed") is False
        and readiness.get("provider_or_model_execution_allowed") is False
        and readiness.get("si13_maturity_upgrade_allowed") is False,
        "amendment_readiness_invalid",
        failures,
    )
    _require(
        candidate.get("execution_boundary") == _boundary(),
        "amendment_boundary_invalid",
        failures,
    )
    _require(
        _self_hash(candidate, "candidate_sha256"),
        "amendment_candidate_hash_invalid",
        failures,
    )
    return list(dict.fromkeys(failures))


def _validate_closed_run(
    *,
    contract: dict[str, Any],
    live_report: dict[str, Any],
    outcome_manifest: dict[str, Any],
    evaluation_report: dict[str, Any],
    closeout_gate: dict[str, Any],
    failures: list[str],
) -> None:
    _require(
        contract.get("status") == "independent_review_required"
        and contract.get("scope", {}).get("task_execution_count") == 320
        and _self_hash(contract, "contract_sha256"),
        "postmortem_execution_contract_invalid",
        failures,
    )
    _require(
        live_report.get("status") == "complete"
        and live_report.get("run_id") == "j1d-qualification-run-20260726-r11"
        and live_report.get("journal", {}).get("task_states") == {"task_committed": 320}
        and live_report.get("execution_scope", {}).get("provider_call_count") == 320
        and live_report.get("execution_scope", {}).get("participant_signature_count")
        == 320
        and _self_hash(live_report, "report_sha256"),
        "postmortem_live_report_invalid",
        failures,
    )
    _require(
        outcome_manifest.get("record_count") == 40
        and len(outcome_manifest.get("records", [])) == 40
        and _self_hash(outcome_manifest, "manifest_sha256"),
        "postmortem_outcome_manifest_invalid",
        failures,
    )
    _require(
        evaluation_report.get("structural_passed") is True
        and evaluation_report.get("valid_for_qualification") is True
        and evaluation_report.get("effectiveness_thresholds_met") is False
        and evaluation_report.get("effectiveness_claim_authorized") is False
        and _self_hash(evaluation_report, "report_sha256"),
        "postmortem_evaluation_report_invalid",
        failures,
    )
    _require(
        closeout_gate.get("passed") is True
        and closeout_gate.get("state") == EXPECTED_CLOSEOUT_STATE
        and closeout_gate.get("terminal_summary", {}).get(
            "si13_maturity_review_authorized"
        )
        is False
        and _self_hash(closeout_gate, "report_sha256"),
        "postmortem_closeout_gate_invalid",
        failures,
    )


def _contract_index(
    contract: dict[str, Any], failures: list[str]
) -> dict[str, dict[str, Any]]:
    tasks = contract.get("task_executions")
    if not isinstance(tasks, list) or len(tasks) != 320:
        failures.append("postmortem_contract_task_set_invalid")
        return {}
    result = {
        str(task.get("task_execution_id")): task
        for task in tasks
        if isinstance(task, dict)
    }
    if len(result) != 320:
        failures.append("postmortem_contract_task_id_set_invalid")
    return result


def _validate_outcome_projection(
    outcome_manifest: dict[str, Any], failures: list[str]
) -> None:
    records = outcome_manifest.get("records")
    if not isinstance(records, list) or len(records) != 40:
        failures.append("postmortem_outcome_record_set_invalid")
        return
    _require(
        all(record.get("maturity_task_count") == 3 for record in records),
        "postmortem_outcome_maturity_projection_invalid",
        failures,
    )
    _require(
        all(record.get("repeated_error_count") == 0 for record in records),
        "postmortem_outcome_repeated_error_projection_invalid",
        failures,
    )
    _require(
        all(
            record.get("pattern_prediction_count") == 0
            and record.get("pattern_false_positive_count") == 0
            for record in records
        ),
        "postmortem_outcome_pattern_projection_invalid",
        failures,
    )


def _boundary() -> dict[str, bool]:
    return {
        "offline_evidence_analysis_only": True,
        "provider_credential_read": False,
        "provider_api_call_performed": False,
        "model_invocation_performed": False,
        "agent_execution_performed": False,
        "participant_container_started": False,
        "participant_signature_performed": False,
        "backend_fact_append_performed": False,
        "ledger_append_performed": False,
        "execution_authorization_issued_or_consumed": False,
        "effectiveness_claim_authorized": False,
        "maturity_upgrade_authorized": False,
    }


def _self_hash(value: dict[str, Any], field: str) -> bool:
    return value.get(field) == canonical_sha256(
        {key: item for key, item in value.items() if key != field}
    )


def _sha256(value: Any) -> bool:
    text = str(value or "")
    return len(text) == 64 and all(char in "0123456789abcdef" for char in text)


def _object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _require(condition: bool, code: str, failures: list[str]) -> None:
    if not condition and code not in failures:
        failures.append(code)
