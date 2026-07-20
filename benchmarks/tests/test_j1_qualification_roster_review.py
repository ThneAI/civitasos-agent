from __future__ import annotations

import copy
import hashlib
import json

from nacl.signing import SigningKey

from benchmarks.j1.controlled_comparison import canonical_sha256
from benchmarks.j1.qualification_reviewer_identity import (
    build_reviewer_identity_profile,
)
from benchmarks.j1.qualification_roster_review import (
    build_reviewed_roster,
    build_roster_review_receipt,
    validate_reviewed_roster_binding,
    validate_roster_review_receipt,
)
from benchmarks.tests.test_j1_qualification_roster_gate import (
    CREATED_AT,
    REVIEW_IMPLEMENTATION,
    _Signer,
    _draft,
    _protocol,
)


def _reviewer(key: SigningKey) -> dict:
    challenge = b"q" * 32
    return build_reviewer_identity_profile(
        created_at=CREATED_AT,
        public_key_hex=key.verify_key.encode().hex(),
        credential_version=1,
        module_path="/usr/lib/softhsm/libsofthsm2.so",
        module_bytes=b"module",
        token_label="dev-token",
        token_serial="serial",
        token_model="SoftHSM v2",
        token_manufacturer="SoftHSM project",
        key_label="reviewer-key",
        key_id_hex="4a31",
        key_reference="pkcs11:reviewer-key",
        challenge=challenge,
        signature=key.sign(challenge).signature,
        private_key_sensitive=True,
        private_key_extractable=False,
    )


def _inputs() -> tuple[dict, dict, dict, _Signer]:
    candidate = _draft(_protocol())
    key = SigningKey.generate()
    reviewer = _reviewer(key)
    evidence = {
        "reviewed_pairing_sha256": "1" * 64,
        "baseline_consent_manifest_sha256": "2" * 64,
        "manifest_artifact_sha256": "3" * 64,
        "intake_report_artifact_sha256": "4" * 64,
        "evidence_artifact_count": 220,
        "cognitive_baseline_count": 20,
        "participant_consent_count": 40,
        "participant_packet_count": 40,
    }
    return candidate, reviewer, evidence, _Signer(key)


def _receipt() -> tuple[dict, dict, dict, dict]:
    candidate, reviewer, evidence, signer = _inputs()
    candidate_hash = hashlib.sha256(json.dumps(candidate).encode()).hexdigest()
    reviewer_hash = hashlib.sha256(json.dumps(reviewer).encode()).hexdigest()
    receipt = build_roster_review_receipt(
        review_id="j1q-roster-review-20260721-r1",
        reviewed_at=CREATED_AT,
        authorization_id="j1q-roster-owner-approval-20260721-r1",
        authorization_statement_sha256="d" * 64,
        candidate_roster=candidate,
        candidate_artifact_sha256=candidate_hash,
        source_evidence=evidence,
        reviewer_profile=reviewer,
        reviewer_profile_sha256=reviewer_hash,
        review_implementation=REVIEW_IMPLEMENTATION,
        signer=signer,
    )
    return receipt, candidate, reviewer, evidence


def test_roster_review_signature_binds_candidate_and_execution_boundary() -> None:
    receipt, candidate, reviewer, evidence = _receipt()

    assert (
        validate_roster_review_receipt(
            receipt,
            candidate_roster=candidate,
            candidate_artifact_sha256=receipt["candidate_roster"][
                "roster_artifact_sha256"
            ],
            source_evidence=evidence,
            reviewer_profile=reviewer,
            reviewer_profile_sha256=receipt["reviewer"]["identity_profile_sha256"],
            review_implementation=REVIEW_IMPLEMENTATION,
        )
        == []
    )
    assert receipt["execution_boundary"]["roster_binding_approved"] is True
    assert receipt["execution_boundary"]["single_use_authorization_issued"] is False


def test_roster_review_rejects_signature_and_candidate_tampering() -> None:
    receipt, candidate, reviewer, evidence = _receipt()
    tampered = copy.deepcopy(receipt)
    tampered["candidate_roster"]["roster_sha256"] = "f" * 64

    failures = validate_roster_review_receipt(
        tampered,
        candidate_roster=candidate,
        candidate_artifact_sha256=receipt["candidate_roster"]["roster_artifact_sha256"],
        source_evidence=evidence,
        reviewer_profile=reviewer,
        reviewer_profile_sha256=receipt["reviewer"]["identity_profile_sha256"],
        review_implementation=REVIEW_IMPLEMENTATION,
    )

    assert "roster_review_candidate_binding_invalid" in failures
    assert "roster_review_signature_payload_hash_mismatch" in failures
    assert "roster_review_signature_invalid" in failures


def test_reviewed_roster_is_copy_on_write_and_receipt_bound() -> None:
    receipt, candidate, _, _ = _receipt()
    original = copy.deepcopy(candidate)
    reviewed = build_reviewed_roster(
        candidate_roster=candidate,
        receipt=receipt,
        receipt_sha256="e" * 64,
    )

    assert candidate == original
    assert reviewed["status"] == "operator_reviewed"
    assert reviewed["roster_sha256"] == canonical_sha256(
        {key: value for key, value in reviewed.items() if key != "roster_sha256"}
    )
    assert (
        validate_reviewed_roster_binding(
            reviewed,
            candidate_roster=candidate,
            receipt=receipt,
            receipt_sha256="e" * 64,
        )
        == []
    )
