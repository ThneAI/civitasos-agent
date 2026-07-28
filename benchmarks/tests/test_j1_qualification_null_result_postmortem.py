from __future__ import annotations

import copy

import pytest

from benchmarks.j1.controlled_comparison import canonical_sha256
from benchmarks.j1.qualification_null_result_postmortem import (
    EXPECTED_CASE_COUNTS,
    ROOT_CAUSES,
    build_amendment_candidate,
    build_postmortem,
    validate_amendment_candidate,
    validate_postmortem,
)


CASES = [
    "apprentice-independent-decision",
    "constitution-precedence",
    "restart-provenance-continuity",
    "revocation-fail-closed",
    "scope-and-delivery-contract",
    "scope-and-delivery-contract",
    "stale-advice-rejection",
    "three-consecutive-verified-tasks",
]


def _hashed(value: dict[str, object], field: str) -> dict[str, object]:
    value[field] = canonical_sha256(value)
    return value


def _fixtures() -> tuple[dict[str, object], ...]:
    tasks = []
    records = []
    outcomes = []
    for participant_index in range(40):
        cohort = "mentor" if participant_index % 2 == 0 else "control"
        participant_id = f"participant-{participant_index:02d}"
        pair_id = f"pair-{participant_index // 2:02d}"
        evidence_hashes = []
        for ordinal, case in enumerate(CASES, start=1):
            execution_id = f"task-{participant_index:02d}-{ordinal:02d}"
            task = {
                "task_execution_id": execution_id,
                "participant_id": participant_id,
                "pair_id": pair_id,
                "cohort": cohort,
                "task": {
                    "task_id": f"heldout-{ordinal:02d}",
                    "verifier_case": case,
                },
            }
            tasks.append(task)
            decision = {
                "task_execution_id": execution_id,
                "decision_sha256": f"{participant_index * 8 + ordinal:064x}",
                "verifier_assertions": None,
            }
            receipts = []
            assertions = {}
            if case == "scope-and-delivery-contract":
                event = _hashed(
                    {
                        "event_type": "repeated_error_loaded",
                        "payload": {"observed": False},
                    },
                    "event_sha256",
                )
                receipts.append(event)
                assertions["repeated_error_observed"] = {
                    "value": False,
                    "source_refs": [event["event_sha256"]],
                }
            if case == "three-consecutive-verified-tasks":
                event = _hashed(
                    {
                        "event_type": "three_task_window_evaluated",
                        "payload": {
                            "consecutive_verified_tasks": 3,
                            "repeated_error_count_in_window": 0,
                            "hard_violation_count": 0,
                            "evidence_complete": True,
                        },
                    },
                    "event_sha256",
                )
                receipts.append(event)
                assertions["consecutive_verified_tasks"] = {
                    "value": 3,
                    "source_refs": [event["event_sha256"]],
                }
            evidence = {
                "task_id": task["task"]["task_id"],
                "participant_id": participant_id,
                "pair_id": pair_id,
                "cohort": cohort,
                "verifier_case": case,
                "source_artifacts": [
                    {
                        "kind": "participant_decision",
                        "sha256": canonical_sha256(decision),
                    }
                ],
                "assertions": assertions,
            }
            evidence_hashes.append(canonical_sha256(evidence))
            records.append(
                {
                    "task_execution_id": execution_id,
                    "participant_decision": decision,
                    "task_evidence": evidence,
                    "task_verification": {
                        "passed": True,
                        "model_judge_used": False,
                        "operator_override_used": False,
                        "evidence_sha256": canonical_sha256(evidence),
                    },
                    "event_receipts": receipts,
                }
            )
        outcomes.append(
            {
                "participant_id": participant_id,
                "task_evidence_sha256": evidence_hashes,
                "maturity_task_count": 3,
                "repeated_error_count": 0,
                "pattern_prediction_count": 0,
                "pattern_false_positive_count": 0,
            }
        )
    contract = _hashed(
        {
            "status": "independent_review_required",
            "scope": {"task_execution_count": 320},
            "task_executions": tasks,
        },
        "contract_sha256",
    )
    live_report = _hashed(
        {
            "status": "complete",
            "run_id": "j1d-qualification-run-20260726-r11",
            "journal": {"task_states": {"task_committed": 320}},
            "execution_scope": {
                "provider_call_count": 320,
                "participant_signature_count": 320,
            },
        },
        "report_sha256",
    )
    outcome = _hashed({"record_count": 40, "records": outcomes}, "manifest_sha256")
    evaluation = _hashed(
        {
            "structural_passed": True,
            "valid_for_qualification": True,
            "effectiveness_thresholds_met": False,
            "effectiveness_claim_authorized": False,
        },
        "report_sha256",
    )
    gate = _hashed(
        {
            "passed": True,
            "state": (
                "successful_run_closed_structural_pass_thresholds_not_met_"
                "no_maturity_upgrade"
            ),
            "terminal_summary": {"si13_maturity_review_authorized": False},
        },
        "report_sha256",
    )
    return contract, live_report, outcome, evaluation, gate, records


def _postmortem() -> dict[str, object]:
    contract, live, outcome, evaluation, gate, records = _fixtures()
    return build_postmortem(
        postmortem_id="postmortem-r11",
        created_at="2026-07-28T00:00:00+00:00",
        source_binding={"r11": {"sha256": "a" * 64}},
        implementation={"source_revision": "b" * 40},
        contract=contract,
        live_report=live,
        outcome_manifest=outcome,
        evaluation_report=evaluation,
        closeout_gate=gate,
        task_records=records,
    )


def test_replays_r11_and_classifies_observability_root_causes() -> None:
    report = _postmortem()
    assert report["root_causes"] == list(ROOT_CAUSES)
    assert report["replay_summary"]["case_counts"] == EXPECTED_CASE_COUNTS
    assert report["replay_summary"]["behaviorally_decoupled_acceptance_count"] == 320
    assert report["interpretation"]["mentor_effectiveness_disproven"] is False
    assert validate_postmortem(report) == []


def test_rejects_decision_hash_binding_drift() -> None:
    contract, live, outcome, evaluation, gate, records = _fixtures()
    records[0]["participant_decision"]["decision_sha256"] = "f" * 64
    with pytest.raises(ValueError, match="participant_decision_hash_binding"):
        build_postmortem(
            postmortem_id="postmortem-r11",
            created_at="2026-07-28T00:00:00+00:00",
            source_binding={},
            implementation={},
            contract=contract,
            live_report=live,
            outcome_manifest=outcome,
            evaluation_report=evaluation,
            closeout_gate=gate,
            task_records=records,
        )


def test_builds_review_required_outcome_sensitive_candidate() -> None:
    report = _postmortem()
    candidate = build_amendment_candidate(
        candidate_id="candidate-r12",
        created_at="2026-07-28T00:00:00+00:00",
        postmortem_ref={
            "path": "/private/postmortem.json",
            "sha256": "c" * 64,
            "canonical_sha256": report["report_sha256"],
        },
        implementation={"source_revision": "b" * 40},
    )
    assert candidate["readiness"]["execution_preflight_allowed"] is False
    assert (
        candidate["endpoint_contract"]["pattern_prediction"][
            "unobserved_zero_fill_allowed"
        ]
        is False
    )
    assert validate_amendment_candidate(candidate) == []


def test_validators_reject_self_hash_drift() -> None:
    report = _postmortem()
    changed = copy.deepcopy(report)
    changed["interpretation"]["mentor_effectiveness_proven"] = True
    assert "postmortem_interpretation_invalid" in validate_postmortem(changed)
    assert "postmortem_hash_invalid" in validate_postmortem(changed)
