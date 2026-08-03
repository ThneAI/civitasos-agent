from __future__ import annotations

import copy
import hashlib

import pytest
from nacl.signing import SigningKey

from benchmarks.j1.controlled_comparison import canonical_sha256
from benchmarks.j1.qualification_outcome_sensitive_confirmatory_amendment import (
    build_preflight,
)
from benchmarks.j1.qualification_outcome_sensitive_confirmatory_review import (
    ALLOWED_DECISION,
    CHECKLIST,
    PROMOTION_BOUNDARY,
    build_frozen_review,
    build_owner_gate,
    build_promotion_gate,
    build_review_handoff,
    build_review_request,
    build_signed_review_receipt,
    reviewer_approval_statement,
    validate_review_request,
    validate_signed_review_receipt,
)
from benchmarks.tests.test_j1_qualification_outcome_sensitive_confirmatory import (
    _chain,
    _sources,
)


class _Signer:
    def __init__(self) -> None:
        self.key = SigningKey.generate()

    @property
    def public_key_hex(self) -> str:
        return self.key.verify_key.encode().hex()

    def sign(self, message: bytes) -> bytes:
        return self.key.sign(message).signature


def _ref(name: str, canonical: str = "a" * 64) -> dict[str, str]:
    return {
        "path": f"/private/{name}.json",
        "sha256": "b" * 64,
        "canonical_sha256": canonical,
    }


def _packet() -> dict[str, object]:
    bundle = _chain()["bundle"]
    bundle_ref = _ref("bundle", bundle["bundle_sha256"])
    preflight = build_preflight(
        bundle_ref=bundle_ref,
        bundle=bundle,
        postmortem_gate_ref=_sources()["postmortem_promotion_gate"],
    )
    preflight_ref = _ref("preflight", preflight["report_sha256"])
    owner_gate = build_owner_gate(
        bundle=bundle,
        bundle_ref=bundle_ref,
        preflight=preflight,
        preflight_ref=preflight_ref,
        owner_statement_sha256=preflight["required_owner_statement_sha256"],
    )
    owner_gate_ref = _ref("owner-gate", owner_gate["report_sha256"])
    implementation = {
        "source_revision": "1" * 40,
        "domain_source_sha256": "2" * 64,
        "handoff_operation_source_sha256": "3" * 64,
        "promotion_operation_source_sha256": "4" * 64,
    }
    request = build_review_request(
        request_id="confirmatory-review-r1",
        created_at="2026-08-03T15:00:00+00:00",
        bundle_ref=bundle_ref,
        bundle=bundle,
        preflight_ref=preflight_ref,
        owner_gate_ref=owner_gate_ref,
        implementation=implementation,
    )
    request_ref = _ref("request", request["request_sha256"])
    handoff = build_review_handoff(request_ref=request_ref, request=request)
    return {
        "bundle": bundle,
        "bundle_ref": bundle_ref,
        "preflight": preflight,
        "preflight_ref": preflight_ref,
        "owner_gate": owner_gate,
        "owner_gate_ref": owner_gate_ref,
        "implementation": implementation,
        "request": request,
        "request_ref": request_ref,
        "handoff": handoff,
    }


def test_owner_gate_binds_exact_preflight_statement() -> None:
    packet = _packet()
    gate = packet["owner_gate"]
    preflight = packet["preflight"]
    assert gate["passed"] is True
    assert (
        gate["owner_authorization"]["statement_sha256"]
        == preflight["required_owner_statement_sha256"]
    )
    assert gate["execution_boundary"]["owner_review_authorization_recorded"] is True


def test_owner_gate_rejects_statement_drift() -> None:
    bundle = _chain()["bundle"]
    bundle_ref = _ref("bundle", bundle["bundle_sha256"])
    preflight = build_preflight(
        bundle_ref=bundle_ref,
        bundle=bundle,
        postmortem_gate_ref=_sources()["postmortem_promotion_gate"],
    )
    with pytest.raises(ValueError, match="owner review authorization invalid"):
        build_owner_gate(
            bundle=bundle,
            bundle_ref=bundle_ref,
            preflight=preflight,
            preflight_ref=_ref("preflight", preflight["report_sha256"]),
            owner_statement_sha256="f" * 64,
        )


def test_review_request_and_handoff_keep_decision_empty() -> None:
    packet = _packet()
    request = packet["request"]
    handoff = packet["handoff"]
    assert (
        validate_review_request(
            request,
            expected_bundle_ref=packet["bundle_ref"],
            expected_preflight_ref=packet["preflight_ref"],
            expected_owner_gate_ref=packet["owner_gate_ref"],
            expected_materials=packet["bundle"]["materials"],
            expected_implementation=packet["implementation"],
        )
        == []
    )
    assert request["decision_template"]["decision"] is None
    assert handoff["decision_template"]["checklist"] == {
        item: None for item in CHECKLIST
    }
    assert ALLOWED_DECISION in handoff["required_exact_approval_statement"]
    assert (
        "40 of 40 new consent extensions"
        in handoff["required_exact_approval_statement"]
    )


def test_signed_receipt_and_promotion_remain_execution_blocked() -> None:
    packet = _packet()
    signer = _Signer()
    reviewer = {
        "did": "did:civ:reviewer",
        "public_key_hex": signer.public_key_hex,
        "credential_version": 1,
        "signer_kind": "pkcs11_ed25519",
    }
    statement = reviewer_approval_statement(
        request_ref=packet["request_ref"],
        request=packet["request"],
    )
    statement_sha256 = hashlib.sha256(statement.encode()).hexdigest()
    receipt = build_signed_review_receipt(
        review_id="review-r1",
        reviewed_at="2026-08-03T16:00:00+00:00",
        request_ref=packet["request_ref"],
        bundle_ref=packet["bundle_ref"],
        preflight_ref=packet["preflight_ref"],
        owner_gate_ref=packet["owner_gate_ref"],
        materials=packet["bundle"]["materials"],
        approval_statement_sha256=statement_sha256,
        reviewer=reviewer,
        reviewer_profile_sha256="5" * 64,
        implementation=packet["implementation"],
        signer=signer,
    )
    assert (
        validate_signed_review_receipt(
            receipt,
            expected_request_ref=packet["request_ref"],
            expected_bundle_ref=packet["bundle_ref"],
            expected_preflight_ref=packet["preflight_ref"],
            expected_owner_gate_ref=packet["owner_gate_ref"],
            expected_materials=packet["bundle"]["materials"],
            expected_approval_statement_sha256=statement_sha256,
            expected_reviewer=reviewer,
            expected_reviewer_profile_sha256="5" * 64,
            expected_implementation=packet["implementation"],
        )
        == []
    )
    frozen = build_frozen_review(
        frozen_id="frozen-r1",
        promoted_at="2026-08-03T16:00:00+00:00",
        source_materials=packet["bundle"]["materials"],
        frozen_materials={
            name: _ref(f"frozen-{name}", ref["canonical_sha256"])
            for name, ref in packet["bundle"]["materials"].items()
        },
        source_bundle_ref=packet["bundle_ref"],
        review_receipt_ref=_ref("receipt", receipt["receipt_sha256"]),
        reviewer_did=reviewer["did"],
        implementation=packet["implementation"],
    )
    gate = build_promotion_gate(
        request_ref=packet["request_ref"],
        handoff_ref=_ref("handoff", packet["handoff"]["handoff_sha256"]),
        owner_gate_ref=packet["owner_gate_ref"],
        receipt_ref=_ref("receipt", receipt["receipt_sha256"]),
        frozen_review_ref=_ref("frozen", frozen["frozen_review_sha256"]),
        frozen_review=frozen,
    )
    assert frozen["execution_boundary"] == PROMOTION_BOUNDARY
    assert frozen["readiness"]["participant_consent_extension_count"] == 0
    assert frozen["readiness"]["execution_preflight_allowed"] is False
    assert gate["state"].endswith("40_of_40_consent_required_execution_blocked")


def test_signed_receipt_rejects_signature_tamper() -> None:
    packet = _packet()
    signer = _Signer()
    reviewer = {
        "did": "did:civ:reviewer",
        "public_key_hex": signer.public_key_hex,
        "credential_version": 1,
        "signer_kind": "pkcs11_ed25519",
    }
    statement = reviewer_approval_statement(
        request_ref=packet["request_ref"],
        request=packet["request"],
    )
    receipt = build_signed_review_receipt(
        review_id="review-r1",
        reviewed_at="2026-08-03T16:00:00+00:00",
        request_ref=packet["request_ref"],
        bundle_ref=packet["bundle_ref"],
        preflight_ref=packet["preflight_ref"],
        owner_gate_ref=packet["owner_gate_ref"],
        materials=packet["bundle"]["materials"],
        approval_statement_sha256=hashlib.sha256(statement.encode()).hexdigest(),
        reviewer=reviewer,
        reviewer_profile_sha256="5" * 64,
        implementation=packet["implementation"],
        signer=signer,
    )
    receipt = copy.deepcopy(receipt)
    receipt["signature"]["signature_hex"] = "00" * 64
    receipt["receipt_sha256"] = canonical_sha256(
        {key: item for key, item in receipt.items() if key != "receipt_sha256"}
    )
    failures = validate_signed_review_receipt(
        receipt,
        expected_request_ref=packet["request_ref"],
        expected_bundle_ref=packet["bundle_ref"],
        expected_preflight_ref=packet["preflight_ref"],
        expected_owner_gate_ref=packet["owner_gate_ref"],
        expected_materials=packet["bundle"]["materials"],
        expected_approval_statement_sha256=hashlib.sha256(
            statement.encode()
        ).hexdigest(),
        expected_reviewer=reviewer,
        expected_reviewer_profile_sha256="5" * 64,
        expected_implementation=packet["implementation"],
    )
    assert "confirmatory_review_receipt_signature_invalid" in failures
