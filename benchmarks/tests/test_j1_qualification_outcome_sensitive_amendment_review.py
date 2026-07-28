from __future__ import annotations

import copy
import hashlib

from nacl.signing import SigningKey

from benchmarks.j1.controlled_comparison import canonical_sha256
from benchmarks.j1.qualification_outcome_sensitive_amendment import (
    BOUNDARY,
    BUNDLE_SCHEMA,
    PREFLIGHT_SCHEMA,
)
from benchmarks.j1.qualification_outcome_sensitive_amendment_review import (
    ALLOWED_DECISION,
    CHECKLIST,
    PROMOTION_BOUNDARY,
    build_frozen_review,
    build_promotion_gate,
    build_review_handoff,
    build_review_request,
    build_signed_review_receipt,
    validate_signed_review_receipt,
    validate_review_request,
)

IMPLEMENTATION = {
    "source_revision": "d" * 40,
    "domain_source_sha256": "e" * 64,
    "operation_source_sha256": "f" * 64,
}
REVIEWER_PROFILE_SHA256 = "9" * 64


class _Signer:
    def __init__(self) -> None:
        self._key = SigningKey.generate()

    @property
    def public_key_hex(self) -> str:
        return self._key.verify_key.encode().hex()

    def sign(self, message: bytes) -> bytes:
        return self._key.sign(message).signature


def _ref(label: str, canonical: str | None = None) -> dict[str, str]:
    return {
        "path": f"/private/{label}.json",
        "sha256": canonical_sha256([label, "raw"]),
        "canonical_sha256": canonical or canonical_sha256([label, "canonical"]),
    }


def _bundle() -> dict[str, object]:
    value = {
        "schema_version": BUNDLE_SCHEMA,
        "bundle_id": "bundle-r1",
        "created_at": "2026-07-28T13:00:00+00:00",
        "status": "review_required",
        "materials": {
            name: _ref(name)
            for name in (
                "plan",
                "task_fixture",
                "statistical_plan",
                "protocol",
                "evaluator",
                "consent_impact",
            )
        },
        "inventory": {
            "material_count": 6,
            "task_fixture_count": 12,
            "participant_count": 40,
            "matched_pair_count": 20,
            "participant_decision_count": 480,
            "required_new_consent_signature_count": 40,
        },
        "readiness": {
            "materials_complete": True,
            "owner_review_only_approval_complete": False,
            "independent_human_review_complete": False,
            "copy_on_write_promotion_complete": False,
            "participant_consent_extensions_complete": False,
            "execution_preflight_allowed": False,
            "provider_or_model_execution_allowed": False,
            "si13_maturity_upgrade_allowed": False,
        },
        "implementation": {
            "source_revision": "a" * 40,
            "domain_source_sha256": "b" * 64,
            "operation_source_sha256": "c" * 64,
        },
        "execution_boundary": BOUNDARY,
    }
    value["bundle_sha256"] = canonical_sha256(value)
    return value


def _inputs() -> tuple[dict[str, object], dict[str, str], dict[str, object], dict[str, str]]:
    bundle = _bundle()
    bundle_ref = _ref("bundle", bundle["bundle_sha256"])
    statement = "owner approves independent review only"
    preflight = {
        "schema_version": PREFLIGHT_SCHEMA,
        "passed": True,
        "failure_reasons": [],
        "state": (
            "outcome_sensitive_amendment_materials_owner_review_only_approval_required"
        ),
        "bundle": bundle_ref,
        "source_promotion_gate": _ref("promotion"),
        "checks": {},
        "required_owner_statement": statement,
        "required_owner_statement_sha256": hashlib.sha256(
            statement.encode()
        ).hexdigest(),
        "execution_boundary": BOUNDARY,
    }
    preflight["report_sha256"] = canonical_sha256(preflight)
    return bundle, bundle_ref, preflight, _ref("preflight", preflight["report_sha256"])


def _request() -> tuple[
    dict[str, object],
    dict[str, object],
    dict[str, str],
    dict[str, str],
]:
    bundle, bundle_ref, preflight, preflight_ref = _inputs()
    request = build_review_request(
        request_id="review-r1",
        created_at="2026-07-28T13:10:00+00:00",
        bundle_ref=bundle_ref,
        bundle=bundle,
        preflight_ref=preflight_ref,
        preflight=preflight,
        owner_statement_sha256=preflight["required_owner_statement_sha256"],
        implementation=IMPLEMENTATION,
    )
    return request, bundle, bundle_ref, preflight_ref


def test_builds_empty_fail_closed_review_request() -> None:
    bundle, bundle_ref, preflight, preflight_ref = _inputs()
    request = build_review_request(
        request_id="review-r1",
        created_at="2026-07-28T13:10:00+00:00",
        bundle_ref=bundle_ref,
        bundle=bundle,
        preflight_ref=preflight_ref,
        preflight=preflight,
        owner_statement_sha256=preflight["required_owner_statement_sha256"],
        implementation=IMPLEMENTATION,
    )
    assert request["allowed_decision"] == ALLOWED_DECISION
    assert request["required_checklist"] == sorted(CHECKLIST)
    assert request["decision_template"]["decision"] is None
    assert (
        validate_review_request(
            request,
            expected_bundle_ref=bundle_ref,
            expected_preflight_ref=preflight_ref,
            expected_materials=bundle["materials"],
            expected_implementation=IMPLEMENTATION,
        )
        == []
    )


def test_review_request_rejects_decision_drift() -> None:
    bundle, bundle_ref, preflight, preflight_ref = _inputs()
    request = build_review_request(
        request_id="review-r1",
        created_at="2026-07-28T13:10:00+00:00",
        bundle_ref=bundle_ref,
        bundle=bundle,
        preflight_ref=preflight_ref,
        preflight=preflight,
        owner_statement_sha256=preflight["required_owner_statement_sha256"],
        implementation=IMPLEMENTATION,
    )
    changed = copy.deepcopy(request)
    changed["decision_template"]["decision"] = ALLOWED_DECISION
    failures = validate_review_request(
        changed,
        expected_bundle_ref=bundle_ref,
        expected_preflight_ref=preflight_ref,
        expected_materials=bundle["materials"],
        expected_implementation=IMPLEMENTATION,
    )
    assert "amendment_review_request_identity_invalid" in failures
    assert "amendment_review_decision_contract_invalid" in failures


def test_handoff_requires_exact_twelve_item_review_statement() -> None:
    bundle, bundle_ref, preflight, preflight_ref = _inputs()
    request = build_review_request(
        request_id="review-r1",
        created_at="2026-07-28T13:10:00+00:00",
        bundle_ref=bundle_ref,
        bundle=bundle,
        preflight_ref=preflight_ref,
        preflight=preflight,
        owner_statement_sha256=preflight["required_owner_statement_sha256"],
        implementation=IMPLEMENTATION,
    )
    handoff = build_review_handoff(
        request_ref=_ref("request", request["request_sha256"]),
        request=request,
        request_raw_sha256="1" * 64,
    )
    assert f"all {len(CHECKLIST)} required checklist items" in handoff[
        "required_exact_approval_statement"
    ]
    assert handoff["decision_template"]["decision"] is None
    assert handoff["execution_boundary"] == BOUNDARY


def test_builds_and_verifies_signed_review_receipt() -> None:
    request, bundle, bundle_ref, preflight_ref = _request()
    signer = _Signer()
    reviewer = {
        "did": "did:civ:testnet:reviewer",
        "public_key_hex": signer.public_key_hex,
        "credential_version": 1,
        "signer_kind": "pkcs11_ed25519",
    }
    request_ref = _ref("request", request["request_sha256"])
    receipt = build_signed_review_receipt(
        review_id="review-r1",
        reviewed_at="2026-07-28T13:20:00+00:00",
        request_ref=request_ref,
        bundle_ref=bundle_ref,
        preflight_ref=preflight_ref,
        materials=bundle["materials"],
        approval_statement_sha256="8" * 64,
        reviewer=reviewer,
        reviewer_profile_sha256=REVIEWER_PROFILE_SHA256,
        implementation=IMPLEMENTATION,
        signer=signer,
    )
    assert (
        validate_signed_review_receipt(
            receipt,
            expected_request_ref=request_ref,
            expected_bundle_ref=bundle_ref,
            expected_preflight_ref=preflight_ref,
            expected_materials=bundle["materials"],
            expected_approval_statement_sha256="8" * 64,
            expected_reviewer=reviewer,
            expected_reviewer_profile_sha256=REVIEWER_PROFILE_SHA256,
            expected_implementation=IMPLEMENTATION,
        )
        == []
    )

    changed = copy.deepcopy(receipt)
    changed["checklist"][sorted(CHECKLIST)[0]] = False
    failures = validate_signed_review_receipt(
        changed,
        expected_request_ref=request_ref,
        expected_bundle_ref=bundle_ref,
        expected_preflight_ref=preflight_ref,
        expected_materials=bundle["materials"],
        expected_approval_statement_sha256="8" * 64,
        expected_reviewer=reviewer,
        expected_reviewer_profile_sha256=REVIEWER_PROFILE_SHA256,
        expected_implementation=IMPLEMENTATION,
    )
    assert "amendment_review_receipt_independence_invalid" in failures
    assert "amendment_review_receipt_signature_invalid" in failures


def test_frozen_review_and_promotion_keep_execution_blocked() -> None:
    request, bundle, bundle_ref, _ = _request()
    receipt_ref = _ref("receipt")
    frozen_materials = {
        name: {**ref, "path": f"/frozen/{name}.json"}
        for name, ref in bundle["materials"].items()
    }
    frozen = build_frozen_review(
        frozen_id="frozen-r1",
        promoted_at="2026-07-28T13:20:00+00:00",
        source_materials=bundle["materials"],
        frozen_materials=frozen_materials,
        source_bundle_ref=bundle_ref,
        review_receipt_ref=receipt_ref,
        reviewer_did="did:civ:testnet:reviewer",
        implementation=IMPLEMENTATION,
    )
    frozen_ref = _ref("frozen", frozen["frozen_review_sha256"])
    gate = build_promotion_gate(
        request_ref=_ref("request", request["request_sha256"]),
        handoff_ref=_ref("handoff"),
        receipt_ref=receipt_ref,
        frozen_review_ref=frozen_ref,
        frozen_review=frozen,
    )

    assert frozen["status"] == "operator_reviewed_frozen"
    assert frozen["readiness"]["participant_consent_extension_count"] == 0
    assert frozen["readiness"]["participant_consent_extension_required_count"] == 40
    assert frozen["readiness"]["execution_preflight_allowed"] is False
    assert gate["passed"] is True
    assert gate["pin_recorded"] is False
    assert gate["private_key_exported"] is False
    assert gate["execution_boundary"] == PROMOTION_BOUNDARY
