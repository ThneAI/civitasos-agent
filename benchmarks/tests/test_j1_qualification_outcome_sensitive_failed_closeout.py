from __future__ import annotations

import copy

from nacl.signing import SigningKey

from benchmarks.j1.qualification_failed_closeout_review_v4 import (
    OUTCOME_BUNDLE_SCHEMA,
    OUTCOME_GATE_SCHEMA,
    OUTCOME_RECEIPT_SCHEMA,
    build_review_bundle,
    build_review_gate,
    build_review_request,
    build_signed_receipt,
    validate_review_bundle,
    validate_signed_receipt,
)
from benchmarks.j1.qualification_failed_execution_closeout_v4 import (
    OUTCOME_CLOSEOUT_SCHEMA,
    OUTCOME_EVALUATION_SCHEMA,
    OUTCOME_GATE_SCHEMA as OUTCOME_CLOSEOUT_GATE_SCHEMA,
    OUTCOME_POST_RUN_SCHEMA,
    build_closeout_artifacts,
    build_closeout_gate,
    build_preflight,
    validate_closeout_artifacts,
    validate_preflight,
)
from benchmarks.j1_qualification_outcome_sensitive_failed_execution_closeout import (
    _execution_summary,
)


class Signer:
    def __init__(self) -> None:
        self.key = SigningKey.generate()

    @property
    def public_key_hex(self) -> str:
        return self.key.verify_key.encode().hex()

    def sign(self, message: bytes) -> bytes:
        return self.key.sign(message).signature


def _ref(seed: str) -> dict[str, str]:
    return {
        "path": f"/private/{seed}.json",
        "sha256": seed * 64,
        "canonical_sha256": seed * 64,
    }


def _budget() -> dict[str, int]:
    return {
        "reconciled_provider_call_count": 52,
        "overrun_provider_call_count": 0,
        "provider_outcome_unknown_call_count": 1,
        "reserved_tokens": 132500,
        "reserved_cost_microunits": 80719,
        "actual_tokens": 16042,
        "actual_cost_microunits": 4408,
        "unknown_reserved_tokens": 2500,
        "unknown_reserved_cost_microunits": 1523,
        "chargeable_token_upper_bound": 18542,
        "chargeable_cost_upper_bound_microunits": 5931,
    }


def _preflight() -> dict:
    return build_preflight(
        checked_at="2026-07-30T14:30:00+00:00",
        run_id="j1d-outcome-sensitive-qualification-run-20260730-r2",
        authorization_id="j1d-outcome-sensitive-execution-authorization-20260730-r2",
        source_binding={
            "claim": _ref("a"),
            "entry_gate": _ref("b"),
            "live_report": _ref("c"),
        },
        execution_summary={
            "authorized_task_count": 480,
            "committed_task_count": 52,
            "failed_task_count": 1,
            "unattempted_task_count": 427,
            "provider_call_count": 53,
            "participant_signature_count": 52,
            "signed_failed_task_count": 0,
            "container_start_count": 53,
            "container_stop_count": 53,
            "structured_decision_count": 52,
            "direct_behavior_observation_count": 52,
        },
        failure={
            "state": "provider_outcome_unknown",
            "reason": "SanitizedProviderFailure",
            "task_execution_id": "task-53",
            "call_id": "call-53",
            "provider_call_performed": True,
            "provider_retry_performed": False,
            "failure_category": "http",
            "failure_stage": "http_transport",
            "source_exception_type": "URLError",
            "event_sha256": "d" * 64,
        },
        budget_summary=_budget(),
        terminal_inventory={
            "participant_container_count": 40,
            "created_count": 40,
            "running_count": 0,
            "exited_count": 0,
        },
        output_root="/private/outcome-post-run-r2",
        implementation={
            "source_revision": "e" * 40,
            "domain_source_sha256": "f" * 64,
            "operation_source_sha256": "0" * 64,
        },
        profile="outcome_sensitive",
    )


def test_outcome_failed_closeout_uses_480_task_schemas_and_signature() -> None:
    preflight = _preflight()
    signer = Signer()
    reviewer = {
        "reviewer_id": "reviewer-1",
        "public_key_hex": signer.public_key_hex,
    }
    preflight_ref = _ref("1")
    artifacts = build_closeout_artifacts(
        closed_at="2026-07-30T14:31:00+00:00",
        preflight_ref=preflight_ref,
        preflight=preflight,
        owner_authorization_id="owner-r2-closeout",
        owner_statement=preflight["owner_authorization"]["required_exact_statement"],
        reviewer=reviewer,
        reviewer_profile_sha256="2" * 64,
        implementation=preflight["implementation"],
        signer=signer,
    )

    assert validate_preflight(preflight) == []
    assert "J1-D outcome-sensitive partial-failure closeout" in preflight[
        "owner_authorization"
    ]["required_exact_statement"]
    assert artifacts["post_run_receipt"]["schema_version"] == OUTCOME_POST_RUN_SCHEMA
    assert (
        artifacts["evaluation_report"]["schema_version"] == OUTCOME_EVALUATION_SCHEMA
    )
    assert artifacts["operator_closeout"]["schema_version"] == OUTCOME_CLOSEOUT_SCHEMA
    assert (
        validate_closeout_artifacts(
            artifacts,
            preflight_ref=preflight_ref,
            preflight=preflight,
            expected_reviewer=reviewer,
            expected_reviewer_profile_sha256="2" * 64,
            expected_implementation=preflight["implementation"],
        )
        == []
    )
    gate = build_closeout_gate(
        checked_at="2026-07-30T14:32:00+00:00",
        preflight_ref=preflight_ref,
        preflight=preflight,
        artifact_refs={
            "post_run_receipt": _ref("3"),
            "evaluation_report": _ref("4"),
            "operator_closeout": _ref("5"),
        },
        artifacts=artifacts,
    )
    assert gate["schema_version"] == OUTCOME_CLOSEOUT_GATE_SCHEMA


def test_outcome_failed_closeout_rejects_320_task_total() -> None:
    preflight = _preflight()
    preflight["execution_summary"].update(
        {
            "authorized_task_count": 320,
            "unattempted_task_count": 267,
        }
    )

    assert "failed_closeout_execution_summary_invalid" in validate_preflight(preflight)


def test_outcome_execution_summary_binds_direct_observations() -> None:
    report = {
        "execution_scope": {
            "task_execution_count": 480,
            "provider_call_count": 53,
            "participant_signature_count": 52,
            "container_start_count": 53,
            "container_stop_count": 53,
        },
        "outcome_scope": {
            "structured_decision_count": 52,
            "direct_behavior_observation_count": 52,
        },
    }
    journal = {
        "logical": {
            "task_states": {
                "task_committed": 52,
                "provider_outcome_unknown": 1,
                "planned": 427,
            }
        },
        "participant_signature_count": 52,
        "signed_failed_task_count": 0,
    }

    summary = _execution_summary(report, journal, _budget())
    assert summary["authorized_task_count"] == 480
    tampered = copy.deepcopy(report)
    tampered["outcome_scope"]["direct_behavior_observation_count"] = 51
    try:
        _execution_summary(tampered, journal, _budget())
    except ValueError as error:
        assert "execution counts invalid" in str(error)
    else:
        raise AssertionError("direct observation count tamper accepted")


def test_outcome_failed_closeout_review_has_distinct_signed_schema() -> None:
    sources = {
        "benchmarks/j1/qualification_failed_closeout_review_v4.py",
        "benchmarks/j1/qualification_failed_execution_closeout_v4.py",
        "benchmarks/j1/qualification_provider_broker.py",
        "benchmarks/j1_qualification_failed_closeout_review_v4.py",
        "benchmarks/j1_qualification_outcome_sensitive_failed_execution_closeout.py",
    }
    bundle = build_review_bundle(
        bundle_id="outcome-r2-closeout-review",
        created_at="2026-07-30T14:00:00+00:00",
        run_evidence={
            "run_id": "j1d-outcome-sensitive-qualification-run-20260730-r2",
            "execution_profile": "outcome_sensitive",
            "claim": _ref("6"),
            "live_report": _ref("7"),
            "failure_state": "provider_outcome_unknown",
            "failure_diagnostic": {
                "failure_category": "http",
                "failure_stage": "http_transport",
                "reason": "SanitizedProviderFailure",
                "source_exception_type": "URLError",
            },
            "provider_call_count": 53,
            "committed_task_count": 52,
            "failed_task_count": 1,
            "unattempted_task_count": 427,
            "budget_summary": _budget(),
        },
        source_implementation={
            "source_revision": "8" * 40,
            "source_files": {name: "9" * 64 for name in sources},
        },
        verification={
            "ruff_all_passed": True,
            "pytest_all_passed": True,
            "pytest_passed_count": 1598,
            "remote_revision_verified": True,
            "provider_or_model_call_performed": False,
            "participant_container_started": False,
        },
        profile="outcome_sensitive",
    )
    bundle_ref = _ref("a")
    request = build_review_request(
        request_id="outcome-r2-review-request",
        created_at="2026-07-30T14:01:00+00:00",
        bundle_ref=bundle_ref,
        bundle=bundle,
    )
    signer = Signer()
    reviewer = {
        "reviewer_id": "reviewer-1",
        "public_key_hex": signer.public_key_hex,
    }
    receipt = build_signed_receipt(
        review_id="outcome-r2-review",
        reviewed_at="2026-07-30T14:02:00+00:00",
        request_ref=_ref("b"),
        bundle_ref=bundle_ref,
        approval_statement_sha256="c" * 64,
        reviewer=reviewer,
        reviewer_profile_sha256="d" * 64,
        signer=signer,
        profile="outcome_sensitive",
    )

    assert bundle["schema_version"] == OUTCOME_BUNDLE_SCHEMA
    assert validate_review_bundle(bundle) == []
    assert "J1-D outcome-sensitive failed-closeout" in request[
        "required_exact_approval_statement"
    ]
    assert receipt["schema_version"] == OUTCOME_RECEIPT_SCHEMA
    assert (
        validate_signed_receipt(
            receipt,
            request_ref=_ref("b"),
            bundle_ref=bundle_ref,
            expected_reviewer=reviewer,
            expected_reviewer_profile_sha256="d" * 64,
            profile="outcome_sensitive",
        )
        == []
    )
    gate = build_review_gate(
        bundle_ref=bundle_ref,
        receipt_ref=_ref("e"),
        profile="outcome_sensitive",
    )
    assert gate["schema_version"] == OUTCOME_GATE_SCHEMA
