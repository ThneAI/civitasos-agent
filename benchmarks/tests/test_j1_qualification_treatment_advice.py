from __future__ import annotations

import copy

from benchmarks.j1.controlled_comparison import canonical_sha256
from benchmarks.j1.qualification_treatment_advice import (
    build_advice_candidate,
    validate_advice_candidate,
)
from benchmarks.tests.test_j1_qualification_execution_design import _design
from benchmarks.tests.test_j1_qualification_mentor_identity import (
    _profile as _mentor_profile,
)


NOW = "2026-07-22T14:00:00+00:00"


def _candidate() -> tuple[dict, dict, dict, dict, dict, dict]:
    design, _, _, assignment = _design()
    reviewed_design = {
        "reviewed_design_sha256": "d" * 64,
        "treatment": design["treatment"],
    }
    assigned = assignment["assignments"][0]
    assigned["assignment_commitment_sha256"] = "e" * 64
    mentor, _ = _mentor_profile()
    task = reviewed_design["treatment"]["tasks"][0]
    candidate = build_advice_candidate(
        created_at=NOW,
        reviewed_design=reviewed_design,
        reviewed_assignment=assignment,
        mentor_identity=mentor,
        assignment=assigned,
        task=task,
    )
    return candidate, reviewed_design, assignment, mentor, assigned, task


def test_treatment_advice_is_participant_task_bound_and_unsigned() -> None:
    candidate, design, assignment, mentor, assigned, task = _candidate()

    assert (
        validate_advice_candidate(
            candidate,
            reviewed_design=design,
            reviewed_assignment=assignment,
            mentor_identity=mentor,
            assignment=assigned,
            task=task,
        )
        == []
    )
    assert candidate["recipient"]["cohort"] == "mentor"
    assert candidate["signature"]["performed"] is False
    assert candidate["advice"]["authority"] == "advisory_only"


def test_treatment_advice_rejects_recipient_and_signature_scope_tamper() -> None:
    candidate, design, assignment, mentor, assigned, task = _candidate()
    tampered = copy.deepcopy(candidate)
    tampered["recipient"]["participant_id"] = assigned["control"]["participant_id"]
    tampered["signature"]["performed"] = True
    tampered["candidate_sha256"] = canonical_sha256(
        {key: item for key, item in tampered.items() if key != "candidate_sha256"}
    )

    failures = validate_advice_candidate(
        tampered,
        reviewed_design=design,
        reviewed_assignment=assignment,
        mentor_identity=mentor,
        assignment=assigned,
        task=task,
    )
    assert "treatment_advice_recipient_invalid" in failures
    assert "treatment_advice_signature_boundary_invalid" in failures
