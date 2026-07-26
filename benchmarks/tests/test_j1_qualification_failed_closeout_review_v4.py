from __future__ import annotations

import copy
import hashlib

from nacl.signing import SigningKey

from benchmarks.j1.controlled_comparison import canonical_sha256
from benchmarks.j1.qualification_failed_closeout_review_v4 import (
    BUNDLE_SCHEMA_V1,
    CHECKLIST,
    LEGACY_CHECKLIST,
    build_review_bundle,
    build_review_gate,
    build_review_request,
    build_signed_receipt,
    validate_review_bundle,
    validate_signed_receipt,
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


def _bundle() -> dict:
    sources = {
        "benchmarks/j1/qualification_failed_closeout_review_v4.py",
        "benchmarks/j1/qualification_failed_execution_closeout_v4.py",
        "benchmarks/j1/qualification_provider_broker.py",
        "benchmarks/j1_qualification_failed_closeout_review_v4.py",
        "benchmarks/j1_qualification_failed_execution_closeout_v4.py",
    }
    return build_review_bundle(
        bundle_id="r9-closeout-review",
        created_at="2026-07-26T06:00:00+00:00",
        run_evidence={
            "run_id": "j1d-qualification-run-20260726-r9",
            "claim": _ref("a"),
            "live_report": _ref("b"),
            "failure_state": "provider_outcome_unknown",
            "failure_diagnostic": {
                "failure_category": "schema",
                "failure_stage": "response_decision",
                "reason": "SanitizedProviderFailure",
                "source_exception_type": "ProviderDecisionShapeError",
            },
            "provider_call_count": 8,
            "committed_task_count": 7,
            "failed_task_count": 1,
            "unattempted_task_count": 312,
            "budget_summary": {
                "reconciled_provider_call_count": 7,
                "overrun_provider_call_count": 0,
                "provider_outcome_unknown_call_count": 1,
                "reserved_tokens": 20000,
                "reserved_cost_microunits": 12184,
                "actual_tokens": 3000,
                "actual_cost_microunits": 2000,
                "unknown_reserved_tokens": 2500,
                "unknown_reserved_cost_microunits": 1523,
                "chargeable_token_upper_bound": 5500,
                "chargeable_cost_upper_bound_microunits": 3523,
            },
        },
        source_implementation={
            "source_revision": "c" * 40,
            "source_files": {name: "d" * 64 for name in sources},
        },
        verification={
            "ruff_all_passed": True,
            "pytest_all_passed": True,
            "pytest_passed_count": 1492,
            "remote_revision_verified": True,
            "provider_or_model_call_performed": False,
            "participant_container_started": False,
        },
    )


def test_failed_closeout_review_binds_scope_and_signature() -> None:
    bundle = _bundle()
    bundle_ref = _ref("e")
    request = build_review_request(
        request_id="request-r8",
        created_at="2026-07-26T06:01:00+00:00",
        bundle_ref=bundle_ref,
        bundle=bundle,
    )
    signer = Signer()
    reviewer = {"reviewer_id": "reviewer-1", "public_key_hex": signer.public_key_hex}
    receipt = build_signed_receipt(
        review_id="review-r8",
        reviewed_at="2026-07-26T06:02:00+00:00",
        request_ref=_ref("f"),
        bundle_ref=bundle_ref,
        approval_statement_sha256="0" * 64,
        reviewer=reviewer,
        reviewer_profile_sha256="1" * 64,
        signer=signer,
    )

    assert validate_review_bundle(bundle) == []
    assert request["required_checklist"] == CHECKLIST
    assert request["request_sha256"] == canonical_sha256(
        {key: item for key, item in request.items() if key != "request_sha256"}
    )
    assert (
        validate_signed_receipt(
            receipt,
            request_ref=_ref("f"),
            bundle_ref=bundle_ref,
            expected_reviewer=reviewer,
            expected_reviewer_profile_sha256="1" * 64,
        )
        == []
    )
    gate = build_review_gate(bundle_ref=bundle_ref, receipt_ref=_ref("2"))
    assert gate["readiness"]["execution_preflight_allowed"] is False
    assert gate["readiness"]["failed_closeout_preflight_allowed"] is True


def test_failed_closeout_review_rejects_budget_tamper() -> None:
    bundle = _bundle()
    tampered = copy.deepcopy(bundle)
    tampered["run_evidence"]["budget_summary"][
        "chargeable_cost_upper_bound_microunits"
    ] = 966
    tampered["bundle_sha256"] = canonical_sha256(
        {key: item for key, item in tampered.items() if key != "bundle_sha256"}
    )

    failures = validate_review_bundle(tampered)

    assert "failed_closeout_review_run_evidence_invalid" in failures


def test_failed_closeout_review_rejects_signature_tamper() -> None:
    bundle_ref = _ref("e")
    signer = Signer()
    reviewer = {"reviewer_id": "reviewer-1", "public_key_hex": signer.public_key_hex}
    receipt = build_signed_receipt(
        review_id="review-r8",
        reviewed_at="2026-07-26T06:02:00+00:00",
        request_ref=_ref("f"),
        bundle_ref=bundle_ref,
        approval_statement_sha256=hashlib.sha256(b"statement").hexdigest(),
        reviewer=reviewer,
        reviewer_profile_sha256="1" * 64,
        signer=signer,
    )
    receipt["signature"]["signature_hex"] = "0" * 128

    failures = validate_signed_receipt(
        receipt,
        request_ref=_ref("f"),
        bundle_ref=bundle_ref,
        expected_reviewer=reviewer,
        expected_reviewer_profile_sha256="1" * 64,
    )

    assert "failed_closeout_review_signature_invalid" in failures


def test_failed_closeout_review_keeps_r8_v1_bundle_compatible() -> None:
    bundle = _bundle()
    bundle["schema_version"] = BUNDLE_SCHEMA_V1
    bundle["run_evidence"] = {
        "run_id": "j1d-qualification-run-20260726-r8",
        "claim": _ref("a"),
        "live_report": _ref("b"),
        "failure_state": "provider_outcome_unknown",
        "provider_call_count": 4,
        "committed_task_count": 3,
        "unattempted_task_count": 316,
        "budget_summary": {
            "reconciled_provider_call_count": 3,
            "overrun_provider_call_count": 0,
            "provider_outcome_unknown_call_count": 1,
            "reserved_tokens": 10000,
            "reserved_cost_microunits": 6092,
            "actual_tokens": 1256,
            "actual_cost_microunits": 966,
            "unknown_reserved_tokens": 2500,
            "unknown_reserved_cost_microunits": 1523,
            "chargeable_token_upper_bound": 3756,
            "chargeable_cost_upper_bound_microunits": 2489,
        },
    }
    bundle["review_checklist"] = LEGACY_CHECKLIST
    bundle["bundle_sha256"] = canonical_sha256(
        {key: item for key, item in bundle.items() if key != "bundle_sha256"}
    )

    assert validate_review_bundle(bundle) == []
