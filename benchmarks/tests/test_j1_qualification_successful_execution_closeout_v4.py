from __future__ import annotations

import copy
import hashlib
from pathlib import Path

from nacl.signing import SigningKey

from benchmarks.j1.controlled_comparison import (
    REQUIRED_SCENARIOS,
    canonical_sha256,
    write_private_json,
)
from benchmarks.j1.qualification_successful_execution_closeout_v4 import (
    CHECKLIST,
    PROSPECTIVE_CONFIRMATORY_CHECKLIST,
    build_closeout_artifacts,
    build_closeout_gate,
    build_preflight,
    build_review_bundle,
    build_review_gate,
    build_review_receipt,
    build_review_request,
    closeout_authorization_statement,
    reviewer_statement,
    validate_closeout_artifacts,
    validate_preflight,
    validate_review_bundle,
    validate_review_receipt,
)
from benchmarks.j1_qualification_successful_execution_closeout_v4 import (
    _outcome_records,
    _sovereignty_violations,
    _validate_successful_review_gate,
)


class _Signer:
    def __init__(self) -> None:
        self._key = SigningKey.generate()

    @property
    def public_key_hex(self) -> str:
        return self._key.verify_key.encode().hex()

    def sign(self, message: bytes) -> bytes:
        return self._key.sign(message).signature


def _ref(index: int) -> dict[str, str]:
    return {
        "path": f"/private/artifact-{index}.json",
        "sha256": f"{index + 1:064x}",
        "canonical_sha256": f"{index + 101:064x}",
    }


def _evaluation() -> dict[str, object]:
    value: dict[str, object] = {
        "schema_version": "j1-qualification-real-evaluation:v1",
        "run_id": "j1d-run-complete",
        "participant_count": 40,
        "matched_pair_count": 20,
        "structural_passed": True,
        "failure_reasons": [],
        "valid_for_qualification": True,
        "effectiveness_thresholds_met": False,
        "effectiveness_claim_authorized": False,
        "metrics": {},
        "safeguards": {},
    }
    value["report_sha256"] = canonical_sha256(value)
    return value


def _records() -> list[dict[str, object]]:
    return [
        {
            "participant_id": f"participant-{index:02d}",
            "task_evidence_sha256": [
                f"{index * 8 + task + 1:064x}" for task in range(8)
            ],
        }
        for index in range(40)
    ]


def _preflight() -> dict[str, object]:
    records = _records()
    return build_preflight(
        run_id="j1d-run-complete",
        authorization_id="j1d-authorization-consumed",
        execution_summary={
            "status": "complete",
            "task_execution_count": 320,
            "committed_task_count": 320,
            "provider_call_count": 320,
            "participant_signature_count": 320,
            "journal_event_count": 3840,
            "validation_failures": [],
        },
        budget_summary={
            "reservation_count": 320,
            "reconciled_count": 320,
            "non_reconciled_count": 0,
            "actual_tokens": 59416,
            "actual_cost_microunits": 11753,
            "reserved_tokens": 800000,
            "reserved_cost_microunits": 487360,
        },
        terminal_inventory={
            "participant_container_count": 40,
            "created_count": 0,
            "exited_count": 40,
            "running_count": 0,
            "container_set_sha256": "a" * 64,
        },
        outcome_inventory={
            "participant_count": 40,
            "matched_pair_count": 20,
            "task_evidence_count": 320,
            "verified_task_count": 320,
            "participant_outcome_count": 40,
            "task_evidence_set_sha256": "b" * 64,
            "participant_outcome_set_sha256": canonical_sha256(records),
            "pattern_prediction_observation_policy": (
                "no_direct_observation_count_as_zero_no_inference"
            ),
        },
        participant_outcomes=records,
        evaluation_report=_evaluation(),
        source_binding={f"source_{index}": _ref(index) for index in range(13)},
        implementation={
            "source_revision": "c" * 40,
            "source_files": {"domain.py": "d" * 64, "operation.py": "e" * 64},
        },
    )


def _reviewer(public_key_hex: str) -> dict[str, object]:
    return {
        "did": "did:civ:reviewer:test",
        "public_key_hex": public_key_hex,
        "credential_version": 1,
        "signer_kind": "pkcs11",
    }


def _prospective_confirmatory_preflight() -> dict[str, object]:
    records = _records()
    evaluation = {
        "structural_passed": True,
        "participant_count": 40,
        "matched_pair_count": 20,
        "valid_for_qualification": True,
        "effectiveness_thresholds_met": False,
        "effectiveness_claim_authorized": False,
        "report_sha256": "f" * 64,
    }
    return build_preflight(
        run_id="j1d-prospective-confirmatory-run",
        authorization_id="j1d-prospective-confirmatory-authorization",
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
            "actual_tokens": 148869,
            "actual_cost_microunits": 22304,
            "reserved_tokens": 1200000,
            "reserved_cost_microunits": 731040,
        },
        terminal_inventory={
            "participant_container_count": 40,
            "created_count": 0,
            "exited_count": 40,
            "running_count": 0,
            "container_set_sha256": "a" * 64,
        },
        outcome_inventory={
            "participant_count": 40,
            "matched_pair_count": 20,
            "task_evidence_count": 480,
            "verified_task_count": 480,
            "participant_outcome_count": 40,
            "task_evidence_set_sha256": "b" * 64,
            "participant_outcome_set_sha256": canonical_sha256(records),
            "pattern_prediction_observation_policy": (
                "direct_signed_observation_exact_set_scoring"
            ),
        },
        participant_outcomes=records,
        evaluation_report=evaluation,
        source_binding={f"source_{index}": _ref(index) for index in range(13)},
        implementation={
            "source_revision": "c" * 40,
            "source_files": {"domain.py": "d" * 64, "operation.py": "e" * 64},
        },
        profile="prospective_confirmatory",
    )


def test_successful_preflight_accepts_stopped_exited_terminal_inventory() -> None:
    preflight = _preflight()

    assert validate_preflight(preflight) == []
    assert preflight["terminal_inventory"] == {
        "participant_container_count": 40,
        "created_count": 0,
        "exited_count": 40,
        "running_count": 0,
        "container_set_sha256": "a" * 64,
    }


def test_successful_preflight_rejects_running_or_unbalanced_inventory() -> None:
    preflight = _preflight()
    preflight["terminal_inventory"]["running_count"] = 1
    preflight["terminal_inventory"]["exited_count"] = 39
    preflight["preflight_sha256"] = canonical_sha256(
        {key: value for key, value in preflight.items() if key != "preflight_sha256"}
    )

    assert "successful_closeout_terminal_inventory_invalid" in validate_preflight(
        preflight
    )


def test_successful_review_and_closeout_signatures_round_trip() -> None:
    signer = _Signer()
    reviewer = _reviewer(signer.public_key_hex)
    preflight = _preflight()
    preflight_ref = _ref(30)
    bundle = build_review_bundle(
        bundle_id="successful-closeout-review",
        created_at="2026-07-26T12:00:00+00:00",
        preflight_ref=preflight_ref,
        preflight=preflight,
        verification={
            "ruff_all_passed": True,
            "pytest_all_passed": True,
            "pytest_passed_count": 1530,
            "remote_revision_verified": True,
            "external_effect_performed": False,
        },
    )
    bundle_ref = _ref(31)
    request = build_review_request(
        request_id="successful-closeout-request",
        created_at="2026-07-26T12:01:00+00:00",
        bundle_ref=bundle_ref,
        bundle=bundle,
    )
    statement = reviewer_statement(
        request_raw_sha256="1" * 64,
        bundle_raw_sha256="2" * 64,
        bundle=bundle,
    )
    statement_sha256 = hashlib.sha256(statement.encode()).hexdigest()
    receipt = build_review_receipt(
        review_id="successful-closeout-review-receipt",
        reviewed_at="2026-07-26T12:02:00+00:00",
        request_ref=_ref(32),
        bundle_ref=bundle_ref,
        statement_sha256=statement_sha256,
        reviewer=reviewer,
        reviewer_profile_sha256="3" * 64,
        signer=signer,
    )

    assert len(CHECKLIST) == 12
    assert validate_review_bundle(bundle) == []
    assert request["allowed_decision"] == "approve_successful_closeout_implementation"
    assert (
        validate_review_receipt(
            receipt,
            request_ref=_ref(32),
            bundle_ref=bundle_ref,
            reviewer=reviewer,
            reviewer_profile_sha256="3" * 64,
            statement_sha256=statement_sha256,
        )
        == []
    )
    review_gate = build_review_gate(
        bundle_ref=bundle_ref,
        receipt_ref=_ref(33),
        source_revision="c" * 40,
    )
    owner_statement = closeout_authorization_statement(
        preflight_raw_sha256="4" * 64,
        preflight=preflight,
        review_gate_raw_sha256="5" * 64,
        review_gate_canonical_sha256=review_gate["report_sha256"],
    )
    owner_statement_sha256 = hashlib.sha256(owner_statement.encode()).hexdigest()
    artifacts = build_closeout_artifacts(
        closed_at="2026-07-26T12:03:00+00:00",
        preflight_ref=preflight_ref,
        preflight=preflight,
        owner_authorization_id="successful-closeout-owner-authorization",
        owner_statement_sha256=owner_statement_sha256,
        reviewer=reviewer,
        reviewer_profile_sha256="3" * 64,
        signer=signer,
    )

    assert (
        validate_closeout_artifacts(
            artifacts,
            preflight=preflight,
            preflight_ref=preflight_ref,
            reviewer=reviewer,
            reviewer_profile_sha256="3" * 64,
            owner_statement_sha256=owner_statement_sha256,
        )
        == []
    )
    gate = build_closeout_gate(
        artifact_refs={name: _ref(index + 40) for index, name in enumerate(artifacts)},
        artifacts=artifacts,
    )
    assert gate["passed"] is True
    assert (
        gate["state"]
        == "successful_run_closed_structural_pass_thresholds_not_met_no_maturity_upgrade"
    )
    assert gate["terminal_summary"]["effectiveness_claim_authorized"] is False


def test_prospective_confirmatory_review_uses_distinct_frozen_checklist() -> None:
    preflight = _prospective_confirmatory_preflight()
    bundle = build_review_bundle(
        bundle_id="prospective-confirmatory-closeout-review",
        created_at="2026-08-13T08:00:00+00:00",
        preflight_ref=_ref(50),
        preflight=preflight,
        verification={
            "ruff_all_passed": True,
            "pytest_all_passed": True,
            "pytest_passed_count": 1710,
            "remote_revision_verified": True,
            "external_effect_performed": False,
        },
    )
    statement = reviewer_statement(
        request_raw_sha256="1" * 64,
        bundle_raw_sha256="2" * 64,
        bundle=bundle,
    )
    closeout_statement = closeout_authorization_statement(
        preflight_raw_sha256="3" * 64,
        preflight=preflight,
        review_gate_raw_sha256="4" * 64,
        review_gate_canonical_sha256="5" * 64,
    )

    assert validate_preflight(preflight) == []
    assert len(PROSPECTIVE_CONFIRMATORY_CHECKLIST) == 14
    assert bundle["review_checklist"] == PROSPECTIVE_CONFIRMATORY_CHECKLIST
    assert "prospectively frozen one-sided exact sign-flip tests" in statement
    assert "prior runs were not reanalyzed" in statement
    assert "does not authorize an effectiveness claim" in closeout_statement


def test_outcome_mapping_does_not_infer_unobserved_predictions() -> None:
    assignment = {
        "reviewed_rebound_assignment_sha256": "6" * 64,
        "assignments": [],
    }
    participant_data = {}
    all_cases = {
        "scope-and-delivery-contract",
        "constitution-precedence",
        "apprentice-independent-decision",
        "revocation-fail-closed",
        "restart-provenance-continuity",
        "stale-advice-rejection",
        "three-consecutive-verified-tasks",
    }
    for pair_index in range(20):
        pair = {"pair_id": f"pair-{pair_index:02d}"}
        for cohort in ("mentor", "control"):
            participant_id = f"{cohort}-{pair_index:02d}"
            pair[cohort] = {
                "participant_id": participant_id,
                "execution_did": f"did:civ:{participant_id}",
            }
            participant_data[participant_id] = {
                "evidence": [
                    f"{pair_index * 16 + (0 if cohort == 'mentor' else 8) + task + 1:064x}"
                    for task in range(8)
                ],
                "runtime_seconds": 10,
                "tokens": 100,
                "cost": 20,
                "repeated_errors": 0,
                "repeated_opportunities": 2,
                "expected_provenance": 8 if cohort == "mentor" else 0,
                "complete_provenance": 8 if cohort == "mentor" else 0,
                "sovereignty_violations": 0,
                "direct_trust_increments": 0,
                "maturity_task_count": 3,
                "cases": copy.deepcopy(all_cases),
            }
        assignment["assignments"].append(pair)

    records = _outcome_records(
        assignment=assignment,
        evaluator={"manifest_sha256": "7" * 64},
        authorization_sha256="8" * 64,
        run_id="j1d-run-complete",
        participant_data=participant_data,
    )

    assert len(records) == 40
    assert all(record["pattern_prediction_count"] == 0 for record in records)
    assert all(record["pattern_false_positive_count"] == 0 for record in records)
    assert all(
        record["scenario_results"]
        == {scenario: True for scenario in sorted(REQUIRED_SCENARIOS)}
        for record in records
    )


def test_sovereignty_violation_count_uses_only_observed_assertions() -> None:
    assertions = {
        "mentor_direct_execution": {"value": False},
        "unsafe_action_executed": {"value": True},
        "post_revocation_advice_used": {"value": False},
        "unrelated": {"value": True},
    }

    assert _sovereignty_violations(assertions) == 1


def test_successful_closeout_gate_requires_deep_signed_review(
    tmp_path: Path,
) -> None:
    signer = _Signer()
    reviewer = _reviewer(signer.public_key_hex)
    preflight = _preflight()
    preflight_path = tmp_path / "preflight.json"
    write_private_json(preflight_path, preflight)
    preflight_ref = {
        "path": str(preflight_path),
        "sha256": hashlib.sha256(preflight_path.read_bytes()).hexdigest(),
        "canonical_sha256": preflight["preflight_sha256"],
    }
    bundle = build_review_bundle(
        bundle_id="deep-review",
        created_at="2026-07-26T12:00:00+00:00",
        preflight_ref=preflight_ref,
        preflight=preflight,
        verification={
            "ruff_all_passed": True,
            "pytest_all_passed": True,
            "pytest_passed_count": 1531,
            "remote_revision_verified": True,
            "external_effect_performed": False,
        },
    )
    bundle_path = tmp_path / "bundle.json"
    write_private_json(bundle_path, bundle)
    bundle_ref = {
        "path": str(bundle_path),
        "sha256": hashlib.sha256(bundle_path.read_bytes()).hexdigest(),
        "canonical_sha256": bundle["bundle_sha256"],
    }
    receipt = build_review_receipt(
        review_id="deep-review-receipt",
        reviewed_at="2026-07-26T12:01:00+00:00",
        request_ref=_ref(70),
        bundle_ref=bundle_ref,
        statement_sha256="9" * 64,
        reviewer=reviewer,
        reviewer_profile_sha256="8" * 64,
        signer=signer,
    )
    receipt_path = tmp_path / "receipt.json"
    write_private_json(receipt_path, receipt)
    receipt_ref = {
        "path": str(receipt_path),
        "sha256": hashlib.sha256(receipt_path.read_bytes()).hexdigest(),
        "canonical_sha256": receipt["signature"]["signed_payload_sha256"],
    }
    gate = build_review_gate(
        bundle_ref=bundle_ref,
        receipt_ref=receipt_ref,
        source_revision="c" * 40,
    )

    _validate_successful_review_gate(
        gate=gate,
        preflight=preflight,
        reviewer_profile={"reviewer": reviewer},
        reviewer_profile_sha256="8" * 64,
    )

    tampered = copy.deepcopy(receipt)
    tampered["review_statement_sha256"] = "0" * 64
    write_private_json(receipt_path, tampered)
    try:
        _validate_successful_review_gate(
            gate=gate,
            preflight=preflight,
            reviewer_profile={"reviewer": reviewer},
            reviewer_profile_sha256="8" * 64,
        )
    except ValueError as error:
        assert "review" in str(error)
    else:
        raise AssertionError("tampered review receipt was accepted")
