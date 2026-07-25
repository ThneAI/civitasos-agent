from __future__ import annotations

import copy
import hashlib
import json

import pytest

from benchmarks.j1.controlled_comparison import canonical_sha256
from benchmarks.j1.qualification_cohort_assignment import METHOD
from benchmarks.j1.qualification_verifier import (
    CASE_CONTRACTS,
    CASE_IDS,
    EVIDENCE_SCHEMA,
    VERIFIER_ID,
    _assignment_commitment,
    build_verifier_candidate,
    validate_verifier_manifest,
    verify_task,
)


PROVIDER = "a" * 64
EVENT_TRACE = "b" * 64
AUTHORIZATION = "c" * 64


def test_assignment_commitment_supports_rebound_and_legacy_shapes() -> None:
    assert (
        _assignment_commitment({"rebind_commitment_sha256": "a" * 64})
        == "a" * 64
    )
    assert (
        _assignment_commitment({"assignment_commitment_sha256": "b" * 64})
        == "b" * 64
    )


def test_verifier_accepts_self_hashed_rebound_assignment() -> None:
    assignment = _reviewed_assignment()
    assignment["schema_version"] = (
        "j1-qualification-cohort-assignment-rebound:operator-reviewed:v1"
    )
    assignment.pop("reviewed_assignment_sha256")
    for pair in assignment["assignments"]:
        pair["rebind_commitment_sha256"] = pair.pop(
            "assignment_commitment_sha256"
        )
    assignment["reviewed_rebound_assignment_sha256"] = canonical_sha256(assignment)
    evidence = _evidence("scope-and-delivery-contract")
    evidence["assignment_commitment_sha256"] = assignment["assignments"][0][
        "rebind_commitment_sha256"
    ]
    evidence["source_artifacts"][-1]["sha256"] = hashlib.sha256(
        _assignment_bytes(assignment)
    ).hexdigest()

    report = verify_task(
        evidence,
        reviewed_assignment_bytes=_assignment_bytes(assignment),
        expected_reviewed_assignment_sha256=assignment[
            "reviewed_rebound_assignment_sha256"
        ],
    )

    assert report["passed"] is True


def _assertion(value: object) -> dict:
    return {"value": value, "source_refs": [EVENT_TRACE]}


def _assertions(case_id: str, cohort: str) -> dict:
    contract = {
        **CASE_CONTRACTS[case_id]["shared"],
        **CASE_CONTRACTS[case_id][cohort],
    }
    return {name: _assertion(rule["value"]) for name, rule in contract.items()}


def _reviewed_assignment() -> dict:
    assignments = []
    for index in range(1, 21):
        mentor = {
            "participant_id": (
                "participant-alpha" if index == 1 else f"participant-{index:02d}-mentor"
            ),
            "execution_did": (
                "did:civ:qualification:participant-alpha"
                if index == 1
                else f"did:civ:qualification:participant-{index:02d}-mentor"
            ),
        }
        control = {
            "participant_id": (
                "participant-beta" if index == 1 else f"participant-{index:02d}-control"
            ),
            "execution_did": (
                "did:civ:qualification:participant-beta"
                if index == 1
                else f"did:civ:qualification:participant-{index:02d}-control"
            ),
        }
        assignments.append(
            {
                "pair_id": f"pair-{index:02d}",
                "assignment_commitment_sha256": f"{index:064x}",
                "mentor": mentor,
                "control": control,
            }
        )
    value = {
        "schema_version": "j1-qualification-cohort-assignment-reviewed:v1",
        "status": "operator_reviewed",
        "method": METHOD,
        "participant_count": 40,
        "pair_count": 20,
        "source_proposal_sha256": "e" * 64,
        "operator_review": {
            "review_id": "review-r1",
            "reviewer_did": "did:civ:reviewer",
            "reviewed_at": "2026-07-22T00:00:00+00:00",
            "review_receipt_sha256": "f" * 64,
        },
        "assignments": assignments,
    }
    value["reviewed_assignment_sha256"] = canonical_sha256(value)
    return value


def _assignment_bytes(value: dict | None = None) -> bytes:
    return json.dumps(
        value or _reviewed_assignment(), sort_keys=True, separators=(",", ":")
    ).encode()


def _evidence(case_id: str, cohort: str = "mentor") -> dict:
    reviewed_assignment = _reviewed_assignment()
    assignment = reviewed_assignment["assignments"][0]
    member = assignment[cohort]
    return {
        "schema_version": EVIDENCE_SCHEMA,
        "task_id": f"j1q-task-{case_id}",
        "participant_id": member["participant_id"],
        "participant_did": member["execution_did"],
        "pair_id": assignment["pair_id"],
        "cohort": cohort,
        "assignment_commitment_sha256": assignment["assignment_commitment_sha256"],
        "verifier_case": case_id,
        "execution": {
            "profile": "qualification",
            "real_agent_runner": True,
            "real_model_call": True,
            "provider_receipt_sha256": PROVIDER,
            "event_trace_sha256": EVENT_TRACE,
            "execution_authorization_sha256": AUTHORIZATION,
        },
        "source_artifacts": [
            {"kind": "provider_receipt", "sha256": PROVIDER},
            {"kind": "event_trace", "sha256": EVENT_TRACE},
            {"kind": "execution_authorization", "sha256": AUTHORIZATION},
            {
                "kind": "reviewed_assignment",
                "sha256": hashlib.sha256(
                    _assignment_bytes(reviewed_assignment)
                ).hexdigest(),
            },
        ],
        "assertions": _assertions(case_id, cohort),
    }


def _verify(evidence: dict, assignment: dict | None = None) -> dict:
    reviewed_assignment = assignment or _reviewed_assignment()
    return verify_task(
        evidence,
        reviewed_assignment_bytes=_assignment_bytes(reviewed_assignment),
        expected_reviewed_assignment_sha256=reviewed_assignment[
            "reviewed_assignment_sha256"
        ],
    )


@pytest.mark.parametrize("cohort", ["mentor", "control"])
@pytest.mark.parametrize("case_id", sorted(CASE_IDS))
def test_each_case_passes_for_both_bound_cohorts(case_id: str, cohort: str) -> None:
    report = _verify(_evidence(case_id, cohort))

    assert report["passed"] is True
    assert report["cohort"] == cohort
    assert report["verifier_id"] == VERIFIER_ID
    assert report["deterministic"] is True
    assert report["model_judge_used"] is False
    assert report["operator_override_used"] is False


def test_shared_outcome_failure_rejects_both_cohorts() -> None:
    for cohort in ("mentor", "control"):
        evidence = _evidence("constitution-precedence", cohort)
        evidence["assertions"]["unsafe_action_executed"]["value"] = True

        report = _verify(evidence)

        assert report["passed"] is False
        assert (
            "case_assertion_unsafe_action_executed_failed" in report["failure_reasons"]
        )


def test_control_passes_without_advice_and_rejects_contamination() -> None:
    evidence = _evidence("apprentice-independent-decision", "control")
    assert _verify(evidence)["passed"] is True

    evidence["assertions"]["advice_observed"]["value"] = True
    report = _verify(evidence)

    assert report["passed"] is False
    assert "case_assertion_advice_observed_failed" in report["failure_reasons"]


def test_verifier_rejects_self_reported_cohort_drift() -> None:
    evidence = _evidence("scope-and-delivery-contract", "mentor")
    evidence["cohort"] = "control"
    evidence["assertions"] = _assertions("scope-and-delivery-contract", "control")

    report = _verify(evidence)

    assert report["passed"] is False
    assert "evidence_assignment_binding_invalid" in report["failure_reasons"]


def test_verifier_rejects_assignment_commitment_and_artifact_drift() -> None:
    evidence = _evidence("scope-and-delivery-contract")
    evidence["assignment_commitment_sha256"] = "0" * 64
    evidence["source_artifacts"][-1]["sha256"] = "9" * 64

    report = _verify(evidence)

    assert report["passed"] is False
    assert "evidence_assignment_binding_invalid" in report["failure_reasons"]
    assert "reviewed_assignment_source_unbound" in report["failure_reasons"]


def test_verifier_rejects_unbound_assertion_and_secret_field() -> None:
    evidence = _evidence("scope-and-delivery-contract")
    evidence["assertions"]["receipt_count"]["source_refs"] = ["8" * 64]
    evidence["private_key_hex"] = "forbidden"

    report = _verify(evidence)

    assert report["passed"] is False
    assert "evidence_fields_invalid" in report["failure_reasons"]
    assert "assertion_receipt_count_source_refs_unbound" in report["failure_reasons"]
    assert "evidence_contains_secret_field" in report["failure_reasons"]


def test_verifier_rejects_receipt_bound_under_wrong_source_kind() -> None:
    evidence = _evidence("scope-and-delivery-contract")
    evidence["source_artifacts"][0]["kind"] = "unrelated"

    report = _verify(evidence)

    assert report["passed"] is False
    assert "provider_receipt_sha256_source_unbound" in report["failure_reasons"]


def test_verifier_rejects_boolean_encoded_as_integer() -> None:
    evidence = _evidence("constitution-precedence")
    evidence["assertions"]["harmful_advice_refused"]["value"] = 1

    report = _verify(evidence)

    assert report["passed"] is False
    assert "case_assertion_harmful_advice_refused_failed" in report["failure_reasons"]


def test_verifier_rejects_nonqualification_or_fake_execution() -> None:
    evidence = _evidence("restart-provenance-continuity")
    evidence["execution"]["profile"] = "development"
    evidence["execution"]["real_agent_runner"] = False
    evidence["execution"]["real_model_call"] = False

    report = _verify(evidence)

    assert report["passed"] is False
    assert "execution_profile_invalid" in report["failure_reasons"]
    assert "real_agent_runner_required" in report["failure_reasons"]
    assert "real_model_call_required" in report["failure_reasons"]


def test_verifier_candidate_exposes_reviewable_cohort_contract() -> None:
    candidate = build_verifier_candidate(
        source_revision="1" * 40,
        implementation_sha256="2" * 64,
    )

    assert (
        validate_verifier_manifest(
            candidate,
            expected_status="review_required",
            expected_implementation_sha256="2" * 64,
        )
        == []
    )
    assert candidate["status"] == "review_required"
    assert candidate["verifier_id"] == VERIFIER_ID
    assert candidate["cohort_contract"]["evidence_self_report_trusted"] is False
    assert {item["case_id"] for item in candidate["cases"]} == CASE_IDS


def test_verifier_manifest_rejects_control_contract_tamper() -> None:
    candidate = build_verifier_candidate(
        source_revision="1" * 40,
        implementation_sha256="2" * 64,
    )
    candidate["cases"][0]["cohort_assertions"]["control"] = candidate["cases"][0][
        "cohort_assertions"
    ]["mentor"]
    candidate["manifest_sha256"] = canonical_sha256(
        {key: item for key, item in candidate.items() if key != "manifest_sha256"}
    )

    failures = validate_verifier_manifest(
        candidate,
        expected_status="review_required",
        expected_implementation_sha256="2" * 64,
    )

    assert "verifier_manifest_case_contract_invalid" in failures


def test_evidence_hash_changes_on_assertion_drift() -> None:
    evidence = _evidence("three-consecutive-verified-tasks")
    first = _verify(evidence)
    changed = copy.deepcopy(evidence)
    changed["assertions"]["consecutive_verified_tasks"]["value"] = 4

    assert first["evidence_sha256"] != _verify(changed)["evidence_sha256"]
