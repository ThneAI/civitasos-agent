from __future__ import annotations

import copy
import hashlib
import json

from nacl.signing import SigningKey

from benchmarks.j1.controlled_comparison import canonical_sha256
from benchmarks.j1.qualification_outcome_sensitive_roster_assignment_rebind import (
    REQUIRED_REVIEW_CHECKS,
)
from benchmarks.j1.qualification_outcome_sensitive_roster_assignment_rebind_review import (
    APPROVAL_DECISION,
    PROMOTION_BOUNDARY,
    approval_review_declaration,
    build_review_receipt,
    build_review_decision_template,
    build_review_request,
    build_reviewed_rebound_assignment,
    build_reviewed_rebound_roster,
    validate_completed_review_decision,
    validate_review_receipt,
    validate_review_request,
    validate_reviewed_rebound_assignment,
    validate_reviewed_rebound_roster,
)
from benchmarks.tests.test_j1_qualification_outcome_sensitive_roster_assignment_rebind import (
    _candidates,
)


NOW = "2026-07-29T10:00:00+08:00"
STATEMENT_SHA256 = "a" * 64
IMPLEMENTATION = {"source_revision": "b" * 40, "source_sha256": "c" * 64}
PLAN_PATH = "/private/outcome-rebind-plan.json"
PREFLIGHT_PATH = "/private/outcome-rebind-preflight.json"
PROFILE_SHA256 = "9" * 64


class _Signer:
    def __init__(self) -> None:
        self._key = SigningKey.generate()

    @property
    def public_key_hex(self) -> str:
        return self._key.verify_key.encode().hex()

    def sign(self, message: bytes) -> bytes:
        return self._key.sign(message).signature


def _bundle() -> tuple[dict, bytes, dict, bytes, dict]:
    _, _, plan = _candidates()
    plan_raw = json.dumps(plan, sort_keys=True).encode()
    preflight = {
        "schema_version": (
            "j1-qualification-outcome-sensitive-"
            "roster-assignment-rebind-preflight:v1"
        ),
        "passed": True,
        "state": (
            "outcome_sensitive_roster_assignment_candidates_"
            "independent_review_required"
        ),
        "report_sha256": "d" * 64,
    }
    preflight_raw = json.dumps(preflight, sort_keys=True).encode()
    request = build_review_request(
        request_id="j1d-outcome-rebind-review-r1",
        created_at=NOW,
        plan_path=PLAN_PATH,
        plan=plan,
        plan_bytes=plan_raw,
        candidate_preflight_path=PREFLIGHT_PATH,
        candidate_preflight=preflight,
        candidate_preflight_bytes=preflight_raw,
        authorization_id="j1d-outcome-rebind-owner-approval-r1",
        authorized_at=NOW,
        authorization_statement_sha256=STATEMENT_SHA256,
        implementation=IMPLEMENTATION,
    )
    return plan, plan_raw, preflight, preflight_raw, request


def _validate(bundle: tuple[dict, bytes, dict, bytes, dict]) -> list[str]:
    plan, plan_raw, preflight, preflight_raw, request = bundle
    return validate_review_request(
        request,
        plan=plan,
        plan_bytes=plan_raw,
        candidate_preflight=preflight,
        candidate_preflight_bytes=preflight_raw,
        expected_plan_path=PLAN_PATH,
        expected_candidate_preflight_path=PREFLIGHT_PATH,
        expected_authorization_statement_sha256=STATEMENT_SHA256,
        expected_implementation=IMPLEMENTATION,
    )


def test_request_binds_owner_candidates_scope_and_ten_checks() -> None:
    bundle = _bundle()
    request = bundle[4]

    assert _validate(bundle) == []
    assert request["owner_authorization"]["scope"] == "independent_review_only"
    assert request["required_checklist"] == sorted(REQUIRED_REVIEW_CHECKS)
    assert len(request["required_checklist"]) == 10
    assert request["review_scope"]["inventory"]["total_decision_count"] == 480
    assert request["review_scope"]["inventory"]["mentor_advice_required_count"] == 180
    template = build_review_decision_template(request)
    assert template["review_request_sha256"] == request["request_sha256"]
    assert all(value is False for value in template["checklist"].values())


def test_request_rejects_owner_authorization_drift() -> None:
    plan, plan_raw, preflight, preflight_raw, request = _bundle()
    changed = copy.deepcopy(request)
    changed["owner_authorization"]["statement_sha256"] = "e" * 64
    changed["request_sha256"] = canonical_sha256(
        {key: item for key, item in changed.items() if key != "request_sha256"}
    )

    failures = _validate(
        (plan, plan_raw, preflight, preflight_raw, changed)
    )

    assert "outcome_rebind_review_owner_authorization_invalid" in failures


def test_request_rejects_candidate_path_or_hash_drift() -> None:
    plan, plan_raw, preflight, preflight_raw, request = _bundle()
    changed = copy.deepcopy(request)
    changed["candidate_artifacts"]["rebind_plan"]["path"] = "/other/plan.json"
    changed["candidate_artifacts"]["rebound_assignment"][
        "canonical_sha256"
    ] = "f" * 64
    changed["request_sha256"] = canonical_sha256(
        {key: item for key, item in changed.items() if key != "request_sha256"}
    )

    failures = _validate(
        (plan, plan_raw, preflight, preflight_raw, changed)
    )

    assert "outcome_rebind_review_candidate_binding_invalid" in failures


def test_reviewer_declaration_is_exactly_request_bound_and_non_executable() -> None:
    request = _bundle()[4]
    raw_sha256 = "f" * 64
    declaration = approval_review_declaration(request, raw_sha256)

    assert raw_sha256 in declaration
    assert request["request_sha256"] in declaration
    assert APPROVAL_DECISION in declaration
    assert "all 10 required checklist items" in declaration
    assert "does not reassign or substitute any participant" in declaration
    assert "upgrade SI-13 maturity" in declaration
    assert hashlib.sha256(declaration.encode()).hexdigest()


def _approved_decision(request: dict, signer: _Signer) -> dict:
    return {
        "schema_version": (
            "j1-qualification-outcome-sensitive-"
            "roster-assignment-review-decision:v1"
        ),
        "review_id": "j1d-outcome-rebind-independent-review-r1",
        "review_request_sha256": request["request_sha256"],
        "decision": APPROVAL_DECISION,
        "reviewed_at": NOW,
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
        "checklist": {
            check: True for check in sorted(REQUIRED_REVIEW_CHECKS)
        },
    }


def _receipt() -> tuple[dict, dict]:
    request = _bundle()[4]
    signer = _Signer()
    decision = _approved_decision(request, signer)
    declaration_sha256 = hashlib.sha256(
        approval_review_declaration(request, "f" * 64).encode()
    ).hexdigest()
    receipt = build_review_receipt(
        request=request,
        decision=decision,
        review_declaration_sha256=declaration_sha256,
        reviewer_profile_sha256=PROFILE_SHA256,
        implementation=IMPLEMENTATION,
        signer=signer,
    )
    assert validate_completed_review_decision(decision, request=request) == []
    assert (
        validate_review_receipt(
            receipt,
            request=request,
            expected_review_declaration_sha256=declaration_sha256,
            expected_reviewer_profile_sha256=PROFILE_SHA256,
            expected_implementation=IMPLEMENTATION,
        )
        == []
    )
    return request, receipt


def test_signed_receipt_rejects_scope_tamper() -> None:
    request, receipt = _receipt()
    changed = copy.deepcopy(receipt)
    changed["review_scope"]["inventory"]["total_decision_count"] = 479

    failures = validate_review_receipt(
        changed,
        request=request,
        expected_review_declaration_sha256=receipt[
            "review_declaration_sha256"
        ],
        expected_reviewer_profile_sha256=PROFILE_SHA256,
        expected_implementation=IMPLEMENTATION,
    )

    assert "outcome_rebind_review_receipt_scope_invalid" in failures
    assert "outcome_rebind_review_signature_invalid" in failures


def test_promotion_is_copy_on_write_and_preserves_execution_blocks() -> None:
    _, receipt = _receipt()
    candidate_roster, candidate_assignment, _ = _candidates()
    candidate_roster_before = copy.deepcopy(candidate_roster)
    candidate_assignment_before = copy.deepcopy(candidate_assignment)
    receipt_sha256 = "8" * 64

    reviewed_roster = build_reviewed_rebound_roster(
        candidate=candidate_roster,
        receipt=receipt,
        receipt_artifact_sha256=receipt_sha256,
    )
    reviewed_assignment = build_reviewed_rebound_assignment(
        candidate=candidate_assignment,
        reviewed_roster=reviewed_roster,
        receipt=receipt,
        receipt_artifact_sha256=receipt_sha256,
    )

    assert candidate_roster == candidate_roster_before
    assert candidate_assignment == candidate_assignment_before
    assert reviewed_roster["execution_boundary"] == PROMOTION_BOUNDARY
    assert reviewed_assignment["execution_boundary"] == PROMOTION_BOUNDARY
    assert reviewed_roster["execution_boundary"]["mentor_advice_signed"] is False
    assert (
        validate_reviewed_rebound_roster(
            reviewed_roster,
            candidate=candidate_roster,
            receipt=receipt,
            receipt_artifact_sha256=receipt_sha256,
        )
        == []
    )
    assert (
        validate_reviewed_rebound_assignment(
            reviewed_assignment,
            candidate=candidate_assignment,
            reviewed_roster=reviewed_roster,
            receipt=receipt,
            receipt_artifact_sha256=receipt_sha256,
        )
        == []
    )
