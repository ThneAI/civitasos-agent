from __future__ import annotations

import copy
import hashlib

from nacl.signing import SigningKey

from benchmarks.j1.qualification_review_promotion_v4 import (
    FROZEN_BOUNDARY,
    RECEIPT_BOUNDARY,
    build_frozen_stack,
    build_signed_review_receipt,
    validate_signed_review_receipt,
)


class _Signer:
    def __init__(self) -> None:
        self.key = SigningKey.generate()

    @property
    def public_key_hex(self) -> str:
        return self.key.verify_key.encode().hex()

    def sign(self, message: bytes) -> bytes:
        return self.key.sign(message).signature


def _ref(name: str) -> dict[str, str]:
    return {
        "path": f"/private/{name}.json",
        "sha256": hashlib.sha256(f"raw:{name}".encode()).hexdigest(),
        "canonical_sha256": hashlib.sha256(
            f"canonical:{name}".encode()
        ).hexdigest(),
    }


def test_signed_review_receipt_binds_reviewer_statement_and_checklist() -> None:
    signer = _Signer()
    reviewer = {
        "did": "did:civ:testnet:reviewer",
        "public_key_hex": signer.public_key_hex,
        "credential_version": 1,
        "signer_kind": "pkcs11_ed25519",
    }
    implementation = {
        "source_revision": "a" * 40,
        "domain_source_sha256": "b" * 64,
        "operation_source_sha256": "c" * 64,
    }
    receipt = build_signed_review_receipt(
        review_id="r4-review-r1",
        reviewed_at="2026-07-25T12:00:00+08:00",
        request_ref=_ref("request"),
        bundle_ref=_ref("bundle"),
        contract_sha256="d" * 64,
        approval_statement_sha256="e" * 64,
        reviewer=reviewer,
        reviewer_profile_sha256="f" * 64,
        implementation=implementation,
        signer=signer,
    )

    assert (
        validate_signed_review_receipt(
            receipt,
            expected_request_ref=_ref("request"),
            expected_bundle_ref=_ref("bundle"),
            expected_contract_sha256="d" * 64,
            expected_approval_statement_sha256="e" * 64,
            expected_reviewer=reviewer,
            expected_reviewer_profile_sha256="f" * 64,
            expected_implementation=implementation,
        )
        == []
    )
    assert receipt["execution_boundary"] == RECEIPT_BOUNDARY
    assert len(receipt["checklist"]) == 12


def test_signed_review_receipt_rejects_signature_or_boundary_tamper() -> None:
    signer = _Signer()
    reviewer = {
        "did": "did:civ:testnet:reviewer",
        "public_key_hex": signer.public_key_hex,
        "credential_version": 1,
        "signer_kind": "pkcs11_ed25519",
    }
    implementation = {
        "source_revision": "a" * 40,
        "domain_source_sha256": "b" * 64,
        "operation_source_sha256": "c" * 64,
    }
    receipt = build_signed_review_receipt(
        review_id="r4-review-r1",
        reviewed_at="2026-07-25T12:00:00+08:00",
        request_ref=_ref("request"),
        bundle_ref=_ref("bundle"),
        contract_sha256="d" * 64,
        approval_statement_sha256="e" * 64,
        reviewer=reviewer,
        reviewer_profile_sha256="f" * 64,
        implementation=implementation,
        signer=signer,
    )
    tampered = copy.deepcopy(receipt)
    tampered["execution_boundary"]["provider_api_call_performed"] = True

    failures = validate_signed_review_receipt(
        tampered,
        expected_request_ref=_ref("request"),
        expected_bundle_ref=_ref("bundle"),
        expected_contract_sha256="d" * 64,
        expected_approval_statement_sha256="e" * 64,
        expected_reviewer=reviewer,
        expected_reviewer_profile_sha256="f" * 64,
        expected_implementation=implementation,
    )
    assert "r4_review_receipt_boundary_invalid" in failures
    assert "r4_review_receipt_signature_invalid" in failures
    assert "r4_review_receipt_hash_invalid" in failures


def test_frozen_stack_requires_provider_refresh_after_promotion() -> None:
    frozen = build_frozen_stack(
        frozen_id="r4-frozen-r1",
        promoted_at="2026-07-25T12:00:00+08:00",
        candidate_bundle_sha256="a" * 64,
        review_receipt_ref=_ref("receipt"),
        frozen_artifacts={"execution_contract": _ref("contract")},
        implementation={
            "source_revision": "b" * 40,
            "domain_source_sha256": "c" * 64,
            "operation_source_sha256": "d" * 64,
        },
    )

    assert frozen["status"] == "operator_reviewed_frozen"
    assert frozen["readiness"]["provider_refresh_required"] is True
    assert frozen["readiness"]["execution_preflight_allowed"] is False
    assert frozen["execution_boundary"] == FROZEN_BOUNDARY
