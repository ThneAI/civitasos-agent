from __future__ import annotations

import copy
import hashlib
import json

from nacl.signing import SigningKey

from benchmarks.j1.controlled_comparison import canonical_sha256
from benchmarks.j1.qualification_roster_assignment_rebind_review import (
    REQUIRED_CHECKS,
    REVIEW_DECISION_SCHEMA,
    approval_review_declaration,
    build_rebind_review_receipt,
    build_rebind_review_decision_template,
    build_rebind_review_request,
    build_reviewed_rebound_assignment,
    build_reviewed_rebound_roster,
    validate_completed_review_decision,
    validate_rebind_review_receipt,
    validate_rebind_review_request,
    validate_reviewed_rebound_assignment,
    validate_reviewed_rebound_roster,
)
from benchmarks.tests.test_j1_qualification_roster_assignment_rebind import (
    _candidates,
)


NOW = "2026-07-23T11:00:00+08:00"
STATEMENT_SHA256 = "a" * 64
IMPLEMENTATION = {"source_revision": "b" * 40, "source_sha256": "c" * 64}


def _bundle() -> tuple[dict, bytes, dict, bytes, dict]:
    _, _, plan = _candidates()
    plan_raw = json.dumps(plan, sort_keys=True).encode()
    preflight = {
        "schema_version": "j1-qualification-roster-assignment-rebind-preflight:v1",
        "passed": True,
        "state": "roster_assignment_rebind_candidates_independent_review_required",
        "report_sha256": "d" * 64,
    }
    preflight_raw = json.dumps(preflight, sort_keys=True).encode()
    request = build_rebind_review_request(
        request_id="j1d-rebind-review-r1",
        created_at=NOW,
        plan_path="/private/rebind-plan.json",
        plan=plan,
        plan_bytes=plan_raw,
        candidate_preflight_path="/private/rebind-preflight.json",
        candidate_preflight=preflight,
        candidate_preflight_bytes=preflight_raw,
        authorization_id="j1d-rebind-owner-approval-r1",
        authorized_at=NOW,
        authorization_statement_sha256=STATEMENT_SHA256,
        implementation=IMPLEMENTATION,
    )
    return plan, plan_raw, preflight, preflight_raw, request


def _validate(bundle: tuple[dict, bytes, dict, bytes, dict]) -> list[str]:
    plan, plan_raw, preflight, preflight_raw, request = bundle
    return validate_rebind_review_request(
        request,
        plan=plan,
        plan_bytes=plan_raw,
        candidate_preflight=preflight,
        candidate_preflight_bytes=preflight_raw,
        expected_authorization_statement_sha256=STATEMENT_SHA256,
        expected_implementation=IMPLEMENTATION,
    )


def test_review_request_binds_owner_authorization_and_both_candidates() -> None:
    bundle = _bundle()
    request = bundle[4]

    assert _validate(bundle) == []
    assert request["owner_authorization"]["scope"] == "independent_review_only"
    assert request["required_checklist"] == sorted(REQUIRED_CHECKS)
    assert request["candidate_artifacts"]["rebound_roster"]
    assert request["candidate_artifacts"]["rebound_assignment"]
    template = build_rebind_review_decision_template(request)
    assert template["review_request_sha256"] == request["request_sha256"]
    assert all(value is False for value in template["checklist"].values())


def test_review_request_rejects_owner_authorization_drift() -> None:
    plan, plan_raw, preflight, preflight_raw, request = _bundle()
    tampered = copy.deepcopy(request)
    tampered["owner_authorization"]["statement_sha256"] = "e" * 64
    tampered["request_sha256"] = canonical_sha256(
        {key: item for key, item in tampered.items() if key != "request_sha256"}
    )

    failures = _validate((plan, plan_raw, preflight, preflight_raw, tampered))

    assert "rebind_review_owner_authorization_invalid" in failures


def test_review_request_rejects_candidate_drift() -> None:
    plan, plan_raw, preflight, preflight_raw, request = _bundle()
    tampered = copy.deepcopy(request)
    tampered["candidate_artifacts"]["rebound_roster"]["canonical_sha256"] = "f" * 64
    tampered["request_sha256"] = canonical_sha256(
        {key: item for key, item in tampered.items() if key != "request_sha256"}
    )

    failures = _validate((plan, plan_raw, preflight, preflight_raw, tampered))

    assert "rebind_review_candidate_binding_invalid" in failures


def test_review_declaration_is_request_bound_and_non_executable() -> None:
    request = _bundle()[4]
    declaration = approval_review_declaration(request)

    assert request["request_sha256"] in declaration
    assert "approve_roster_assignment_rebind" in declaration
    assert "does not reassign or substitute any participant" in declaration
    assert hashlib.sha256(declaration.encode()).hexdigest()


def test_signed_receipt_promotes_both_candidates_copy_on_write() -> None:
    request = _bundle()[4]
    candidate_roster, candidate_assignment, _ = _candidates()
    signer = _Signer()
    decision = _completed_decision(request, signer.public_key_hex)
    declaration_sha256 = hashlib.sha256(
        approval_review_declaration(request).encode()
    ).hexdigest()
    receipt = build_rebind_review_receipt(
        request=request,
        decision=decision,
        review_declaration_sha256=declaration_sha256,
        reviewer_profile_sha256="d" * 64,
        implementation=IMPLEMENTATION,
        signer=signer,
    )

    assert validate_completed_review_decision(decision, request=request) == []
    assert (
        validate_rebind_review_receipt(
            receipt,
            request=request,
            expected_review_declaration_sha256=declaration_sha256,
            expected_reviewer_profile_sha256="d" * 64,
            expected_implementation=IMPLEMENTATION,
        )
        == []
    )
    reviewed_roster = build_reviewed_rebound_roster(
        candidate=candidate_roster,
        receipt=receipt,
        receipt_artifact_sha256="e" * 64,
    )
    reviewed_assignment = build_reviewed_rebound_assignment(
        candidate=candidate_assignment,
        reviewed_roster=reviewed_roster,
        receipt=receipt,
        receipt_artifact_sha256="e" * 64,
    )
    assert (
        validate_reviewed_rebound_roster(
            reviewed_roster,
            candidate=candidate_roster,
            receipt=receipt,
            receipt_artifact_sha256="e" * 64,
        )
        == []
    )
    assert (
        validate_reviewed_rebound_assignment(
            reviewed_assignment,
            candidate=candidate_assignment,
            reviewed_roster=reviewed_roster,
            receipt=receipt,
            receipt_artifact_sha256="e" * 64,
        )
        == []
    )
    assert candidate_roster["status"] == "review_required"
    assert reviewed_roster["status"] == "operator_reviewed"
    assert reviewed_roster["candidate_execution_boundary"]["roster_promoted"] is False
    assert reviewed_roster["execution_boundary"]["roster_promoted"] is True
    assert reviewed_assignment["execution_boundary"]["assignment_promoted"] is True
    assert (
        reviewed_assignment["operator_reviewed_roster_sha256"]
        == reviewed_roster["reviewed_rebound_roster_sha256"]
    )


def test_signed_receipt_rejects_signature_tamper() -> None:
    request = _bundle()[4]
    signer = _Signer()
    declaration_sha256 = hashlib.sha256(
        approval_review_declaration(request).encode()
    ).hexdigest()
    receipt = build_rebind_review_receipt(
        request=request,
        decision=_completed_decision(request, signer.public_key_hex),
        review_declaration_sha256=declaration_sha256,
        reviewer_profile_sha256="d" * 64,
        implementation=IMPLEMENTATION,
        signer=signer,
    )
    receipt["signature"]["signature_hex"] = "00" * 64

    failures = validate_rebind_review_receipt(
        receipt,
        request=request,
        expected_review_declaration_sha256=declaration_sha256,
        expected_reviewer_profile_sha256="d" * 64,
        expected_implementation=IMPLEMENTATION,
    )

    assert "rebind_review_signature_invalid" in failures


class _Signer:
    def __init__(self) -> None:
        self._key = SigningKey.generate()
        self.public_key_hex = self._key.verify_key.encode().hex()

    def sign(self, message: bytes) -> bytes:
        return self._key.sign(message).signature


def _completed_decision(request: dict, public_key_hex: str) -> dict:
    return {
        "schema_version": REVIEW_DECISION_SCHEMA,
        "review_id": "j1d-rebind-review-r1",
        "review_request_sha256": request["request_sha256"],
        "decision": "approve_roster_assignment_rebind",
        "reviewed_at": NOW,
        "reviewer": {
            "did": "did:civ:testnet:z6MkReviewer",
            "public_key_hex": public_key_hex,
            "credential_version": 1,
            "signer_kind": "pkcs11_ed25519",
            "custody_provenance_sha256": "d" * 64,
            "signer_attestation_sha256": "d" * 64,
        },
        "independence": {
            "conflicts_disclosed": True,
            "independent_from_candidate_authoring": True,
            "human_review_completed": True,
        },
        "checklist": {check: True for check in sorted(REQUIRED_CHECKS)},
    }
