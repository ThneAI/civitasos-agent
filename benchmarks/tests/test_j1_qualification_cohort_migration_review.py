from __future__ import annotations

import copy
import hashlib
import json

from nacl.signing import SigningKey

from benchmarks.j1.controlled_comparison import canonical_sha256
from benchmarks.j1.qualification_cohort_migration_review import (
    REQUIRED_CHECKS,
    approval_review_declaration,
    build_migration_review_receipt,
    build_migration_review_decision_template,
    build_migration_review_request,
    build_reviewed_migration_plan,
    validate_completed_review_decision,
    validate_migration_review_receipt,
    validate_migration_review_request,
    validate_reviewed_migration_plan,
)
from benchmarks.tests.test_j1_qualification_cohort_migration import _plan


NOW = "2026-07-22T23:40:00+08:00"
STATEMENT_SHA256 = "a" * 64
IMPLEMENTATION = {"source_revision": "b" * 40, "source_sha256": "c" * 64}


def _bundle() -> tuple[dict, bytes, dict, bytes, dict]:
    plan, _ = _plan()
    plan_raw = json.dumps(plan, sort_keys=True).encode()
    preflight = {
        "schema_version": "j1-qualification-cohort-migration-preflight:v2",
        "passed": True,
        "state": "cohort_migration_plan_prepared_independent_review_required",
        "plan": {
            "path": "/private/migration-plan.json",
            "sha256": hashlib.sha256(plan_raw).hexdigest(),
            "canonical_sha256": plan["plan_sha256"],
        },
        "approval_request": {
            "statement_sha256": STATEMENT_SHA256,
            "protocol_design_amendment_independent_review_required": True,
        },
        "blockers": plan["blockers"],
        "readiness": plan["readiness"],
        "execution_boundary": plan["execution_boundary"],
    }
    preflight_raw = json.dumps(preflight, sort_keys=True).encode()
    request = build_migration_review_request(
        request_id="j1d-cohort-migration-review-20260722-r1",
        created_at=NOW,
        plan_path="/private/migration-plan.json",
        plan=plan,
        plan_bytes=plan_raw,
        candidate_preflight_path="/private/migration-preflight.json",
        candidate_preflight=preflight,
        candidate_preflight_bytes=preflight_raw,
        authorization_id="j1d-cohort-migration-owner-approval-20260722-r1",
        authorized_at=NOW,
        authorization_statement_sha256=STATEMENT_SHA256,
        implementation=IMPLEMENTATION,
    )
    return plan, plan_raw, preflight, preflight_raw, request


def _validate(bundle: tuple[dict, bytes, dict, bytes, dict]) -> list[str]:
    plan, plan_raw, preflight, preflight_raw, request = bundle
    return validate_migration_review_request(
        request,
        plan=plan,
        plan_bytes=plan_raw,
        candidate_preflight=preflight,
        candidate_preflight_bytes=preflight_raw,
        expected_authorization_statement_sha256=STATEMENT_SHA256,
        expected_implementation=IMPLEMENTATION,
    )


def test_review_request_binds_owner_authorization_and_candidate() -> None:
    bundle = _bundle()
    request = bundle[4]

    assert _validate(bundle) == []
    assert request["owner_authorization"]["scope"] == "independent_review_only"
    assert request["required_checklist"] == sorted(REQUIRED_CHECKS)
    template = build_migration_review_decision_template(request)
    assert template["review_request_sha256"] == request["request_sha256"]
    assert all(value is False for value in template["checklist"].values())


def test_review_request_rejects_owner_authorization_drift() -> None:
    plan, plan_raw, preflight, preflight_raw, request = _bundle()
    tampered = copy.deepcopy(request)
    tampered["owner_authorization"]["statement_sha256"] = "d" * 64
    tampered["request_sha256"] = canonical_sha256(
        {key: item for key, item in tampered.items() if key != "request_sha256"}
    )

    failures = _validate((plan, plan_raw, preflight, preflight_raw, tampered))

    assert "migration_review_owner_authorization_invalid" in failures


def test_review_request_rejects_candidate_preflight_drift() -> None:
    plan, plan_raw, preflight, preflight_raw, request = _bundle()
    tampered_preflight = copy.deepcopy(preflight)
    tampered_preflight["plan"]["canonical_sha256"] = "e" * 64

    failures = _validate(
        (plan, plan_raw, tampered_preflight, preflight_raw, request)
    )

    assert "migration_review_candidate_preflight_invalid" in failures


def test_review_request_rejects_execution_boundary_escalation() -> None:
    plan, plan_raw, preflight, preflight_raw, request = _bundle()
    tampered = copy.deepcopy(request)
    tampered["execution_boundary"]["model_invocation_performed"] = True
    tampered["request_sha256"] = canonical_sha256(
        {key: item for key, item in tampered.items() if key != "request_sha256"}
    )

    failures = _validate((plan, plan_raw, preflight, preflight_raw, tampered))

    assert "migration_review_boundary_invalid" in failures


def test_signed_review_receipt_and_reviewed_plan_are_bound() -> None:
    plan, _, _, _, request = _bundle()
    signer = _Signer()
    decision = _completed_decision(request, signer.public_key_hex)
    declaration_sha256 = hashlib.sha256(
        approval_review_declaration(request).encode()
    ).hexdigest()
    receipt = build_migration_review_receipt(
        request=request,
        decision=decision,
        review_declaration_sha256=declaration_sha256,
        reviewer_profile_sha256="d" * 64,
        implementation=IMPLEMENTATION,
        signer=signer,
    )

    assert validate_completed_review_decision(decision, request=request) == []
    assert (
        validate_migration_review_receipt(
            receipt,
            request=request,
            expected_review_declaration_sha256=declaration_sha256,
            expected_reviewer_profile_sha256="d" * 64,
            expected_implementation=IMPLEMENTATION,
        )
        == []
    )
    reviewed = build_reviewed_migration_plan(
        plan=plan,
        receipt=receipt,
        receipt_artifact_sha256="e" * 64,
    )
    assert (
        validate_reviewed_migration_plan(
            reviewed,
            plan=plan,
            receipt=receipt,
            receipt_artifact_sha256="e" * 64,
        )
        == []
    )
    assert reviewed["status"] == "operator_reviewed"
    assert plan["status"] == "review_required"


def test_signed_review_receipt_rejects_signature_tamper() -> None:
    _, _, _, _, request = _bundle()
    signer = _Signer()
    declaration_sha256 = hashlib.sha256(
        approval_review_declaration(request).encode()
    ).hexdigest()
    receipt = build_migration_review_receipt(
        request=request,
        decision=_completed_decision(request, signer.public_key_hex),
        review_declaration_sha256=declaration_sha256,
        reviewer_profile_sha256="d" * 64,
        implementation=IMPLEMENTATION,
        signer=signer,
    )
    receipt["signature"]["signature_hex"] = "00" * 64

    failures = validate_migration_review_receipt(
        receipt,
        request=request,
        expected_review_declaration_sha256=declaration_sha256,
        expected_reviewer_profile_sha256="d" * 64,
        expected_implementation=IMPLEMENTATION,
    )

    assert "migration_review_signature_invalid" in failures


class _Signer:
    def __init__(self) -> None:
        self._key = SigningKey.generate()
        self.public_key_hex = self._key.verify_key.encode().hex()

    def sign(self, message: bytes) -> bytes:
        return self._key.sign(message).signature


def _completed_decision(request: dict, public_key_hex: str) -> dict:
    return {
        "schema_version": "j1-qualification-cohort-migration-review-decision:v1",
        "review_id": "j1d-cohort-migration-review-20260723-r1",
        "review_request_sha256": request["request_sha256"],
        "decision": "approve_protocol_design_amendment_materials",
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
            "independent_from_plan_authoring": True,
            "human_review_completed": True,
        },
        "checklist": {check: True for check in sorted(REQUIRED_CHECKS)},
    }
