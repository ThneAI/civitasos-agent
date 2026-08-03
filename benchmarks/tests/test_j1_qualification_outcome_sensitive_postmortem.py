from __future__ import annotations

import copy

from benchmarks.j1.controlled_comparison import canonical_sha256
from benchmarks.j1.qualification_outcome_sensitive_postmortem import (
    ANALYSIS_BOUNDARY,
    build_postmortem,
    build_review_handoff,
    build_review_request,
    owner_review_statement,
    validate_postmortem,
)
from benchmarks.j1.qualification_outcome_sensitive_evaluation import (
    build_participant_outcome,
)


def _identity(
    *,
    pair_index: int,
    cohort: str,
) -> dict[str, str]:
    return {
        "participant_id": f"{cohort}-{pair_index:02d}",
        "participant_did": f"did:civ:{cohort}-{pair_index:02d}",
        "pair_id": f"pair-{pair_index:02d}",
        "cohort": cohort,
    }


def _observations(*, pair_index: int, cohort: str) -> list[dict[str, object]]:
    rows = []
    for ordinal in range(1, 13):
        accepted = ordinal not in {2, 7}
        if cohort == "mentor" and ordinal in {5, 8, 9}:
            accepted = pair_index >= {5: 1, 8: 9, 9: 1}[ordinal]
        rows.append(
            {
                "task_ordinal": ordinal,
                "task_evidence_sha256": f"{pair_index * 100 + ordinal:064x}",
                "structured_decision_sha256": (
                    f"{pair_index * 100 + ordinal + 10000:064x}"
                ),
                "direct_observation_sha256": (
                    f"{pair_index * 100 + ordinal + 20000:064x}"
                ),
                "selected_action_id": "bounded_action",
                "predicted_pattern_ids": ["pattern"] if accepted else [],
                "action_exact": accepted or ordinal in {2, 8},
                "pattern_exact": accepted,
                "accepted": accepted,
                "repeated_error_family": "scope" if ordinal in {1, 4} else None,
                "advice_expected": cohort == "mentor" and ordinal >= 4,
                "advice_provenance_complete": (
                    cohort == "mentor" and ordinal >= 4
                ),
                "hard_violation": False,
                "actual_tokens": 12 if cohort == "mentor" else 10,
                "actual_cost_microunits": 3 if cohort == "mentor" else 2,
            }
        )
    return rows


def _inputs() -> tuple[
    list[dict[str, object]],
    dict[str, list[dict[str, object]]],
    dict[str, object],
    dict[str, object],
]:
    participants = []
    observations = {}
    for index in range(20):
        for cohort in ("mentor", "control"):
            identity = _identity(pair_index=index, cohort=cohort)
            rows = _observations(pair_index=index, cohort=cohort)
            observations[identity["participant_id"]] = rows
            participants.append(
                build_participant_outcome(
                    run_id="run-r4",
                    authorization_sha256="a" * 64,
                    participant=identity,
                    observations=rows,
                )
            )
    evaluation = {
        "run_id": "run-r4",
        "structural_passed": True,
        "valid_for_qualification": True,
        "effectiveness_thresholds_met": False,
        "effectiveness_claim_authorized": False,
        "confirmatory_inference": {"valid": False},
    }
    closeout = {
        "passed": True,
        "state": (
            "successful_run_closed_structural_pass_thresholds_not_met_"
            "no_maturity_upgrade"
        ),
        "terminal_summary": {
            "task_execution_count": 480,
            "effectiveness_claim_authorized": False,
        },
    }
    closeout["report_sha256"] = canonical_sha256(closeout)
    return participants, observations, evaluation, closeout


def test_build_postmortem_preserves_descriptive_nonclaim_boundary() -> None:
    participants, observations, evaluation, closeout = _inputs()
    report = build_postmortem(
        postmortem_id="postmortem-r4",
        created_at="2026-08-03T12:00:00+00:00",
        source_binding={"closeout_gate": {"sha256": "1" * 64}},
        implementation={"source_revision": "2" * 40},
        participant_records=participants,
        observations=observations,
        evaluation_report=evaluation,
        closeout_gate=closeout,
    )

    assert validate_postmortem(report) == []
    assert report["measurement_boundary"]["advice_adherence_observed"] is False
    assert report["execution_boundary"] == ANALYSIS_BOUNDARY
    assert report["phase_summary"][0]["mentor"]["accepted_count"] == 40
    assert report["phase_summary"][0]["control"]["accepted_count"] == 40
    assert report["pair_summary"]["accepted_task_delta_control_minus_mentor"][
        "mentor_better_pair_count"
    ] == 0
    findings = {item["finding_id"]: item for item in report["descriptive_findings"]}
    assert findings["task_discriminability"]["joint_floor_ordinals"] == [2, 7]
    assert findings["advice_measurement"]["advice_adherence_observed"] is False
    assert report["report_sha256"] == canonical_sha256(
        {key: item for key, item in report.items() if key != "report_sha256"}
    )


def test_validate_postmortem_rejects_causal_boundary_drift() -> None:
    participants, observations, evaluation, closeout = _inputs()
    report = build_postmortem(
        postmortem_id="postmortem-r4",
        created_at="2026-08-03T12:00:00+00:00",
        source_binding={},
        implementation={"source_revision": "2" * 40},
        participant_records=participants,
        observations=observations,
        evaluation_report=evaluation,
        closeout_gate=closeout,
    )
    tampered = copy.deepcopy(report)
    tampered["measurement_boundary"]["causal_root_cause_determined"] = True
    tampered["report_sha256"] = canonical_sha256(
        {key: item for key, item in tampered.items() if key != "report_sha256"}
    )

    assert validate_postmortem(tampered) == ["outcome_postmortem_contract_invalid"]

    tampered = copy.deepcopy(report)
    tampered["descriptive_findings"][0]["causal_claim_allowed"] = True
    tampered["report_sha256"] = canonical_sha256(
        {key: item for key, item in tampered.items() if key != "report_sha256"}
    )

    assert validate_postmortem(tampered) == ["outcome_postmortem_contract_invalid"]


def test_review_handoff_requires_exact_bounded_owner_statement() -> None:
    participants, observations, evaluation, closeout = _inputs()
    report = build_postmortem(
        postmortem_id="postmortem-r4",
        created_at="2026-08-03T12:00:00+00:00",
        source_binding={},
        implementation={"source_revision": "2" * 40},
        participant_records=participants,
        observations=observations,
        evaluation_report=evaluation,
        closeout_gate=closeout,
    )
    postmortem_ref = {
        "path": "/private/postmortem.json",
        "sha256": "3" * 64,
        "canonical_sha256": report["report_sha256"],
    }
    request = build_review_request(
        request_id="review-r4",
        created_at="2026-08-03T12:01:00+00:00",
        postmortem_ref=postmortem_ref,
        postmortem=report,
    )
    statement = owner_review_statement(
        postmortem_raw_sha256=postmortem_ref["sha256"],
        postmortem_canonical_sha256=postmortem_ref["canonical_sha256"],
        request_raw_sha256="4" * 64,
        request_canonical_sha256=request["request_sha256"],
        run_id="run-r4",
    )
    handoff = build_review_handoff(
        postmortem_ref=postmortem_ref,
        request_ref={
            "path": "/private/review-request.json",
            "sha256": "4" * 64,
            "canonical_sha256": request["request_sha256"],
        },
        statement=statement,
    )

    assert handoff["status"] == "owner_review_authorization_required"
    assert "does not amend the protocol" in statement
    assert "upgrade SI-13 maturity" in statement
