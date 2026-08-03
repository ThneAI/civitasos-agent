from __future__ import annotations

import copy
import hashlib

from nacl.signing import SigningKey

from benchmarks.j1.controlled_comparison import canonical_sha256
from benchmarks.j1.qualification_outcome_sensitive_postmortem import (
    ANALYSIS_BOUNDARY,
    HANDOFF_SCHEMA,
    REVIEW_CHECKLIST,
    REVIEW_REQUEST_SCHEMA,
)
from benchmarks.j1.qualification_outcome_sensitive_postmortem_review import (
    ALLOWED_DECISION,
    CHECKLIST,
    PROMOTION_BOUNDARY,
    build_frozen_review,
    build_owner_gate,
    build_promotion_gate,
    build_reviewer_handoff,
    build_signed_review_receipt,
    reviewer_approval_statement,
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


def _ref(path: str, raw: str, canonical: str) -> dict[str, str]:
    return {"path": path, "sha256": raw, "canonical_sha256": canonical}


def _packet() -> tuple[dict, dict, dict, dict, dict, dict]:
    from benchmarks.tests.test_j1_qualification_outcome_sensitive_postmortem import (
        _inputs,
    )
    from benchmarks.j1.qualification_outcome_sensitive_postmortem import (
        build_postmortem,
        build_review_handoff,
        build_review_request,
        owner_review_statement,
    )

    participants, observations, evaluation, closeout = _inputs()
    postmortem = build_postmortem(
        postmortem_id="postmortem-r4",
        created_at="2026-08-03T00:00:00+00:00",
        source_binding={},
        implementation={"source_revision": "a" * 40},
        participant_records=participants,
        observations=observations,
        evaluation_report=evaluation,
        closeout_gate=closeout,
    )
    postmortem_ref = _ref(
        "/private/postmortem.json", "1" * 64, postmortem["report_sha256"]
    )
    request = build_review_request(
        request_id="request-r4",
        created_at="2026-08-03T00:01:00+00:00",
        postmortem_ref=postmortem_ref,
        postmortem=postmortem,
    )
    request_ref = _ref(
        "/private/request.json", "2" * 64, request["request_sha256"]
    )
    statement = owner_review_statement(
        postmortem_raw_sha256=postmortem_ref["sha256"],
        postmortem_canonical_sha256=postmortem_ref["canonical_sha256"],
        request_raw_sha256=request_ref["sha256"],
        request_canonical_sha256=request_ref["canonical_sha256"],
        run_id=postmortem["run_id"],
    )
    handoff = build_review_handoff(
        postmortem_ref=postmortem_ref,
        request_ref=request_ref,
        statement=statement,
    )
    handoff_ref = _ref(
        "/private/handoff.json", "3" * 64, handoff["handoff_sha256"]
    )
    return postmortem, postmortem_ref, request, request_ref, handoff, handoff_ref


def test_owner_gate_and_reviewer_handoff_preserve_empty_decision() -> None:
    postmortem, postmortem_ref, request, request_ref, handoff, handoff_ref = _packet()
    statement_sha256 = hashlib.sha256(
        handoff["required_exact_approval_statement"].encode()
    ).hexdigest()
    gate = build_owner_gate(
        postmortem=postmortem,
        postmortem_ref=postmortem_ref,
        request=request,
        request_ref=request_ref,
        handoff=handoff,
        handoff_ref=handoff_ref,
        owner_statement_sha256=statement_sha256,
    )
    gate_ref = _ref("/private/gate.json", "4" * 64, gate["report_sha256"])
    implementation = {
        "source_revision": "a" * 40,
        "domain_source_sha256": "b" * 64,
        "handoff_operation_source_sha256": "c" * 64,
        "promotion_operation_source_sha256": "d" * 64,
    }
    reviewer_handoff = build_reviewer_handoff(
        request=request,
        request_ref=request_ref,
        postmortem_ref=postmortem_ref,
        owner_gate_ref=gate_ref,
        implementation=implementation,
    )

    assert request["schema_version"] == REVIEW_REQUEST_SCHEMA
    assert handoff["schema_version"] == HANDOFF_SCHEMA
    assert request["required_checklist"] == list(REVIEW_CHECKLIST)
    assert reviewer_handoff["decision_template"]["decision"] is None
    assert reviewer_handoff["decision_template"]["checklist"] == {
        item: None for item in CHECKLIST
    }
    assert ALLOWED_DECISION in reviewer_handoff["required_exact_approval_statement"]


def test_owner_gate_rejects_unapproved_statement_hash() -> None:
    postmortem, postmortem_ref, request, request_ref, handoff, handoff_ref = _packet()
    try:
        build_owner_gate(
            postmortem=postmortem,
            postmortem_ref=postmortem_ref,
            request=request,
            request_ref=request_ref,
            handoff=handoff,
            handoff_ref=handoff_ref,
            owner_statement_sha256="f" * 64,
        )
    except ValueError as error:
        assert "postmortem_owner_statement_not_authorized" in str(error)
    else:
        raise AssertionError("owner statement drift must fail closed")

    try:
        build_owner_gate(
            postmortem=postmortem,
            postmortem_ref=postmortem_ref,
            request=request,
            request_ref=request_ref,
            handoff=handoff,
            handoff_ref=handoff_ref,
            owner_statement_sha256="",
        )
    except ValueError as error:
        assert "postmortem_owner_statement_not_authorized" in str(error)
    else:
        raise AssertionError("empty owner statement hash must fail closed")


def test_signed_receipt_and_promotion_preserve_nonclaim_boundary() -> None:
    _, postmortem_ref, request, request_ref, _, _ = _packet()
    signer = _Signer()
    reviewer = {
        "did": "did:civ:reviewer",
        "public_key_hex": signer.public_key_hex,
        "credential_version": 1,
        "signer_kind": "pkcs11_ed25519",
    }
    owner_gate_ref = _ref("/private/gate.json", "4" * 64, "5" * 64)
    implementation = {
        "source_revision": "a" * 40,
        "domain_source_sha256": "b" * 64,
        "handoff_operation_source_sha256": "c" * 64,
        "promotion_operation_source_sha256": "d" * 64,
    }
    statement = reviewer_approval_statement(
        request=request,
        request_ref=request_ref,
        postmortem_ref=postmortem_ref,
        implementation_revision=implementation["source_revision"],
    )
    receipt = build_signed_review_receipt(
        review_id="review-r4",
        reviewed_at="2026-08-03T01:00:00+00:00",
        request_ref=request_ref,
        postmortem_ref=postmortem_ref,
        owner_gate_ref=owner_gate_ref,
        approval_statement_sha256=hashlib.sha256(statement.encode()).hexdigest(),
        reviewer=reviewer,
        reviewer_profile_sha256="6" * 64,
        implementation=implementation,
        signer=signer,
    )
    assert (
        validate_signed_review_receipt(
            receipt,
            expected_request_ref=request_ref,
            expected_postmortem_ref=postmortem_ref,
            expected_owner_gate_ref=owner_gate_ref,
            expected_approval_statement_sha256=hashlib.sha256(
                statement.encode()
            ).hexdigest(),
            expected_reviewer=reviewer,
            expected_reviewer_profile_sha256="6" * 64,
            expected_implementation=implementation,
        )
        == []
    )
    frozen = build_frozen_review(
        frozen_id="frozen-r4",
        promoted_at="2026-08-03T01:00:00+00:00",
        source_postmortem_ref=postmortem_ref,
        frozen_postmortem_ref=_ref(
            "/private/frozen-postmortem.json",
            "7" * 64,
            postmortem_ref["canonical_sha256"],
        ),
        review_receipt_ref=_ref(
            "/private/receipt.json", "8" * 64, receipt["receipt_sha256"]
        ),
        reviewer_did=reviewer["did"],
        implementation=implementation,
    )
    gate = build_promotion_gate(
        request_ref=request_ref,
        reviewer_handoff_ref=_ref("/private/reviewer-handoff.json", "9" * 64, "a" * 64),
        owner_gate_ref=owner_gate_ref,
        receipt_ref=_ref("/private/receipt.json", "8" * 64, receipt["receipt_sha256"]),
        frozen_review_ref=_ref(
            "/private/frozen.json", "b" * 64, frozen["frozen_review_sha256"]
        ),
        frozen_review=frozen,
    )

    assert frozen["execution_boundary"] == PROMOTION_BOUNDARY
    assert frozen["interpretation"]["effectiveness_claim_authorized"] is False
    assert gate["state"] == (
        "descriptive_postmortem_review_promoted_no_effectiveness_claim"
    )


def test_receipt_rejects_signature_tamper() -> None:
    _, postmortem_ref, request, request_ref, _, _ = _packet()
    signer = _Signer()
    reviewer = {
        "did": "did:civ:reviewer",
        "public_key_hex": signer.public_key_hex,
        "credential_version": 1,
        "signer_kind": "pkcs11_ed25519",
    }
    owner_gate_ref = _ref("/private/gate.json", "4" * 64, "5" * 64)
    implementation = {
        "source_revision": "a" * 40,
        "domain_source_sha256": "b" * 64,
        "handoff_operation_source_sha256": "c" * 64,
        "promotion_operation_source_sha256": "d" * 64,
    }
    receipt = build_signed_review_receipt(
        review_id="review-r4",
        reviewed_at="2026-08-03T01:00:00+00:00",
        request_ref=request_ref,
        postmortem_ref=postmortem_ref,
        owner_gate_ref=owner_gate_ref,
        approval_statement_sha256="6" * 64,
        reviewer=reviewer,
        reviewer_profile_sha256="7" * 64,
        implementation=implementation,
        signer=signer,
    )
    changed = copy.deepcopy(receipt)
    changed["signature"]["signature_hex"] = "00" * 64
    changed["receipt_sha256"] = canonical_sha256(
        {key: item for key, item in changed.items() if key != "receipt_sha256"}
    )
    failures = validate_signed_review_receipt(
        changed,
        expected_request_ref=request_ref,
        expected_postmortem_ref=postmortem_ref,
        expected_owner_gate_ref=owner_gate_ref,
        expected_approval_statement_sha256="6" * 64,
        expected_reviewer=reviewer,
        expected_reviewer_profile_sha256="7" * 64,
        expected_implementation=implementation,
    )

    assert "postmortem_review_signature_invalid" in failures
    assert request["execution_boundary"] == ANALYSIS_BOUNDARY
