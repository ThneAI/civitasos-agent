from __future__ import annotations

import copy
import hashlib

from nacl.signing import SigningKey

from benchmarks.j1.controlled_comparison import canonical_sha256
from benchmarks.j1.qualification_outcome_sensitive_confirmatory_roster_assignment_rebind import (
    PLAN_SCHEMA,
    REQUIRED_REVIEW_CHECKS,
)
from benchmarks.j1.qualification_outcome_sensitive_confirmatory_roster_assignment_rebind_review import (
    APPROVAL_DECISION,
    EXECUTION_BOUNDARY,
    PROMOTION_BOUNDARY,
    approval_review_declaration,
    build_review_decision_template,
    build_review_receipt,
    build_review_request,
    build_reviewed_rebound_assignment,
    build_reviewed_rebound_roster,
    validate_review_receipt,
    validate_review_request,
    validate_reviewed_rebound_assignment,
    validate_reviewed_rebound_roster,
)


IMPLEMENTATION = {
    "source_revision": "a" * 40,
    "source_sha256": "b" * 64,
}
STATEMENT_SHA256 = "c" * 64
PROFILE_SHA256 = "d" * 64
DECLARATION_SHA256 = "e" * 64


class _Signer:
    def __init__(self) -> None:
        self._key = SigningKey.generate()

    @property
    def public_key_hex(self) -> str:
        return self._key.verify_key.encode().hex()

    def sign(self, message: bytes) -> bytes:
        return self._key.sign(message).signature


def _plan() -> tuple[dict, bytes, dict, bytes]:
    plan = {
        "schema_version": PLAN_SCHEMA,
        "status": "review_required",
        "rebind_id": "confirmatory-rebind-r1",
        "created_at": "2026-08-04T08:00:00+08:00",
        "source_binding": {
            "confirmatory_consent_gate": {
                "path": "/private/consent-gate.json",
                "sha256": "1" * 64,
                "canonical_sha256": "2" * 64,
            }
        },
        "candidate_artifacts": {
            "rebound_roster": {
                "path": "/private/roster.json",
                "sha256": "3" * 64,
                "canonical_sha256": "4" * 64,
            },
            "rebound_assignment": {
                "path": "/private/assignment.json",
                "sha256": "5" * 64,
                "canonical_sha256": "6" * 64,
            },
        },
        "inventory": {
            "candidate_artifact_count": 2,
            "participant_count": 40,
            "pair_count": 20,
            "confirmatory_consent_extension_count": 40,
            "total_decision_count": 480,
            "mentor_advice_rebind_required_count": 180,
        },
        "required_review_checks": sorted(REQUIRED_REVIEW_CHECKS),
        "remaining_gate_sequence": [
            "confirmatory_roster_assignment_independent_review",
            "confirmatory_roster_assignment_promotion_gate",
        ],
        "readiness": {
            "roster_rebind_candidate_complete": True,
            "assignment_rebind_candidate_complete": True,
            "roster_rebound": False,
            "assignment_rebound": False,
        },
        "implementation": copy.deepcopy(IMPLEMENTATION),
        "execution_boundary": {
            "candidate_generation_only": True,
            "roster_promoted": False,
        },
    }
    plan["plan_sha256"] = canonical_sha256(plan)
    plan_raw = b"frozen plan bytes"
    preflight = {
        "report_sha256": "7" * 64,
    }
    preflight_raw = b"frozen preflight bytes"
    return plan, plan_raw, preflight, preflight_raw


def _request() -> tuple[dict, dict, bytes, dict, bytes]:
    plan, plan_raw, preflight, preflight_raw = _plan()
    request = build_review_request(
        request_id="confirmatory-rebind-review-r1",
        created_at="2026-08-04T08:05:00+08:00",
        plan_path="/private/plan.json",
        plan=plan,
        plan_bytes=plan_raw,
        candidate_preflight_path="/private/preflight.json",
        candidate_preflight=preflight,
        candidate_preflight_bytes=preflight_raw,
        authorization_id="confirmatory-rebind-owner-approval-r1",
        authorized_at="2026-08-04T08:04:00+08:00",
        authorization_statement_sha256=STATEMENT_SHA256,
        implementation=IMPLEMENTATION,
    )
    return request, plan, plan_raw, preflight, preflight_raw


def _failures(changed: dict) -> list[str]:
    _, plan, plan_raw, preflight, preflight_raw = _request()
    return validate_review_request(
        changed,
        plan=plan,
        plan_bytes=plan_raw,
        candidate_preflight=preflight,
        candidate_preflight_bytes=preflight_raw,
        expected_plan_path="/private/plan.json",
        expected_candidate_preflight_path="/private/preflight.json",
        expected_authorization_statement_sha256=STATEMENT_SHA256,
        expected_implementation=IMPLEMENTATION,
    )


def _receipt() -> tuple[dict, dict]:
    request, *_ = _request()
    signer = _Signer()
    decision = {
        "schema_version": (
            "j1-qualification-outcome-sensitive-confirmatory-"
            "roster-assignment-review-decision:v1"
        ),
        "review_id": "confirmatory-review-r1",
        "review_request_sha256": request["request_sha256"],
        "decision": APPROVAL_DECISION,
        "reviewed_at": "2026-08-04T08:10:00+08:00",
        "reviewer": {
            "did": "did:civ:testnet:reviewer",
            "public_key_hex": signer.public_key_hex,
            "credential_version": 1,
            "signer_kind": "pkcs11_ed25519",
            "custody_provenance_sha256": PROFILE_SHA256,
            "signer_attestation_sha256": PROFILE_SHA256,
        },
        "independence": {
            "conflicts_disclosed": True,
            "independent_from_candidate_authoring": True,
            "human_review_completed": True,
        },
        "checklist": {check: True for check in sorted(REQUIRED_REVIEW_CHECKS)},
    }
    receipt = build_review_receipt(
        request=request,
        decision=decision,
        review_declaration_sha256=DECLARATION_SHA256,
        reviewer_profile_sha256=PROFILE_SHA256,
        implementation=IMPLEMENTATION,
        signer=signer,
    )
    return request, receipt


def _candidates() -> tuple[dict, dict]:
    roster = {
        "schema_version": "confirmatory-roster-candidate:v1",
        "status": "review_required",
        "rebind_id": "confirmatory-rebind-r1",
        "participants": [],
        "execution_boundary": {
            "candidate_generation_only": True,
            "roster_promoted": False,
        },
    }
    roster["rebound_roster_sha256"] = canonical_sha256(roster)
    assignment = {
        "schema_version": "confirmatory-assignment-candidate:v1",
        "status": "review_required",
        "rebind_id": "confirmatory-rebind-r1",
        "assignments": [],
        "rebound_roster_sha256": roster["rebound_roster_sha256"],
        "execution_boundary": {
            "candidate_generation_only": True,
            "assignment_promoted": False,
        },
    }
    assignment["rebound_assignment_sha256"] = canonical_sha256(assignment)
    return roster, assignment


def test_review_request_binds_owner_candidates_and_confirmatory_scope() -> None:
    request, *_ = _request()

    assert request["owner_authorization"]["statement_sha256"] == STATEMENT_SHA256
    assert request["review_scope"]["inventory"]["participant_count"] == 40
    assert request["review_scope"]["inventory"]["pair_count"] == 20
    assert request["review_scope"]["inventory"]["total_decision_count"] == 480
    assert request["required_checklist"] == sorted(REQUIRED_REVIEW_CHECKS)
    assert request["execution_boundary"] == EXECUTION_BOUNDARY
    assert request["execution_boundary"]["r4_reanalysis_performed"] is False
    assert (
        request["execution_boundary"]["effectiveness_or_causal_claim_authorized"]
        is False
    )


def test_review_request_rejects_owner_and_candidate_tamper() -> None:
    request, *_ = _request()
    changed = copy.deepcopy(request)
    changed["owner_authorization"]["statement_sha256"] = "0" * 64
    changed["candidate_artifacts"]["rebound_assignment"]["sha256"] = "9" * 64

    failures = _failures(changed)

    assert "confirmatory_rebind_review_candidate_binding_invalid" in failures
    assert "confirmatory_rebind_review_owner_authorization_invalid" in failures
    assert "confirmatory_rebind_review_request_hash_invalid" in failures


def test_decision_template_is_empty_and_fail_closed() -> None:
    request, *_ = _request()
    decision = build_review_decision_template(request)

    assert decision["review_request_sha256"] == request["request_sha256"]
    assert decision["decision"] == ""
    assert decision["reviewer"]["did"] == ""
    assert all(value is False for value in decision["independence"].values())
    assert len(decision["checklist"]) == 10
    assert all(value is False for value in decision["checklist"].values())


def test_reviewer_declaration_binds_exact_request_and_nonclaims() -> None:
    request, *_ = _request()
    raw_sha256 = hashlib.sha256(b"review request").hexdigest()

    statement = approval_review_declaration(request, raw_sha256)

    assert raw_sha256 in statement
    assert request["request_sha256"] in statement
    assert APPROVAL_DECISION in statement
    assert "all 10 required checklist items" in statement
    assert "It does not reanalyze r4" in statement
    assert "effectiveness or causal claim" in statement


def test_signed_receipt_verifies_exact_scope_and_signature() -> None:
    request, receipt = _receipt()

    assert (
        validate_review_receipt(
            receipt,
            request=request,
            expected_review_declaration_sha256=DECLARATION_SHA256,
            expected_reviewer_profile_sha256=PROFILE_SHA256,
            expected_implementation=IMPLEMENTATION,
        )
        == []
    )


def test_signed_receipt_rejects_scope_tamper() -> None:
    request, receipt = _receipt()
    changed = copy.deepcopy(receipt)
    changed["review_scope"]["inventory"]["total_decision_count"] = 479

    failures = validate_review_receipt(
        changed,
        request=request,
        expected_review_declaration_sha256=DECLARATION_SHA256,
        expected_reviewer_profile_sha256=PROFILE_SHA256,
        expected_implementation=IMPLEMENTATION,
    )

    assert "confirmatory_rebind_review_receipt_scope_invalid" in failures
    assert "confirmatory_rebind_review_signature_invalid" in failures


def test_promotion_is_copy_on_write_and_preserves_confirmatory_blocks() -> None:
    _, receipt = _receipt()
    roster, assignment = _candidates()
    roster_before = copy.deepcopy(roster)
    assignment_before = copy.deepcopy(assignment)
    receipt_sha256 = "f" * 64

    reviewed_roster = build_reviewed_rebound_roster(
        candidate=roster,
        receipt=receipt,
        receipt_artifact_sha256=receipt_sha256,
    )
    reviewed_assignment = build_reviewed_rebound_assignment(
        candidate=assignment,
        reviewed_roster=reviewed_roster,
        receipt=receipt,
        receipt_artifact_sha256=receipt_sha256,
    )

    assert roster == roster_before
    assert assignment == assignment_before
    assert reviewed_roster["execution_boundary"] == PROMOTION_BOUNDARY
    assert reviewed_assignment["execution_boundary"] == PROMOTION_BOUNDARY
    assert reviewed_roster["execution_boundary"]["r4_reanalysis_performed"] is False
    assert (
        reviewed_roster["execution_boundary"]["mentor_advice_rebound_or_signed"]
        is False
    )
    assert (
        validate_reviewed_rebound_roster(
            reviewed_roster,
            candidate=roster,
            receipt=receipt,
            receipt_artifact_sha256=receipt_sha256,
        )
        == []
    )
    assert (
        validate_reviewed_rebound_assignment(
            reviewed_assignment,
            candidate=assignment,
            reviewed_roster=reviewed_roster,
            receipt=receipt,
            receipt_artifact_sha256=receipt_sha256,
        )
        == []
    )
