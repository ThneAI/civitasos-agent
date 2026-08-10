from __future__ import annotations

import copy
import hashlib
import json

from nacl.signing import SigningKey

from benchmarks.j1.controlled_comparison import canonical_sha256
from benchmarks.j1.qualification_outcome_sensitive_confirmatory_infrastructure_rebind import (
    REQUIRED_REVIEW_CHECKS,
)
from benchmarks.j1.qualification_outcome_sensitive_confirmatory_infrastructure_rebind_review import (
    APPROVAL_DECISION,
    DECISION_BOUNDARY,
    EXECUTION_BOUNDARY,
    PROMOTION_BOUNDARY,
    approval_review_declaration,
    build_review_decision_template,
    build_review_receipt,
    build_review_request,
    build_reviewed_infrastructure_rebind,
    validate_review_receipt,
    validate_review_request,
    validate_reviewed_infrastructure_rebind,
)
from benchmarks.tests.test_j1_qualification_outcome_sensitive_confirmatory_infrastructure_rebind import (
    _build,
    _fixtures,
)


NOW = "2026-08-11T08:00:00+08:00"
PLAN_PATH = "/private/confirmatory-infrastructure-plan.json"
PREFLIGHT_PATH = "/private/confirmatory-infrastructure-preflight.json"
STATEMENT_SHA256 = "a" * 64
IMPLEMENTATION = {"source_revision": "b" * 40, "source_sha256": "c" * 64}
PROFILE_SHA256 = "e" * 64
DECLARATION_SHA256 = "f" * 64


class _Signer:
    def __init__(self) -> None:
        self._key = SigningKey.generate()

    @property
    def public_key_hex(self) -> str:
        return self._key.verify_key.encode().hex()

    def sign(self, message: bytes) -> bytes:
        return self._key.sign(message).signature


def _bundle() -> tuple[dict, bytes, dict, bytes, dict]:
    plan = _build(_fixtures())
    plan_raw = json.dumps(plan, sort_keys=True).encode()
    preflight = {
        "report_sha256": "d" * 64,
        "docker_census": {
            "historical_j1_container_count": 240,
            "running_count": 0,
            "cleanup_authorized": False,
        },
        "disk_safety": {
            "historical_container_cleanup_authorized": False,
            "implicit_container_prune_authorized": False,
            "implicit_image_prune_authorized": False,
            "source_container_removal_authorized": False,
        },
    }
    preflight_raw = json.dumps(preflight, sort_keys=True).encode()
    request = build_review_request(
        request_id="confirmatory-infrastructure-review-r1",
        created_at=NOW,
        plan_path=PLAN_PATH,
        plan=plan,
        plan_bytes=plan_raw,
        candidate_preflight_path=PREFLIGHT_PATH,
        candidate_preflight=preflight,
        candidate_preflight_bytes=preflight_raw,
        authorization_id="owner-review-approval-r1",
        authorized_at=NOW,
        authorization_statement_sha256=STATEMENT_SHA256,
        implementation=IMPLEMENTATION,
    )
    return plan, plan_raw, preflight, preflight_raw, request


def _validate(request: dict) -> list[str]:
    plan, plan_raw, preflight, preflight_raw, _ = _bundle()
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


def test_request_binds_confirmatory_scope_and_owner_approval() -> None:
    request = _bundle()[4]

    assert _validate(request) == []
    assert request["owner_authorization"]["scope"] == "independent_review_only"
    assert request["review_scope"]["inventory"]["participant_count"] == 40
    assert request["review_scope"]["inventory"]["total_decision_count"] == 480
    assert (
        request["review_scope"]["inventory"][
            "mentor_confirmatory_signed_advice_count"
        ]
        == 180
    )
    assert request["review_scope"]["r4_reanalysis_allowed"] is False
    assert request["review_scope"]["advice_adherence_observed"] is False
    assert request["required_checklist"] == sorted(REQUIRED_REVIEW_CHECKS)
    assert len(request["required_checklist"]) == 14
    assert request["execution_boundary"] == EXECUTION_BOUNDARY


def test_request_rejects_owner_or_scope_tamper() -> None:
    changed = copy.deepcopy(_bundle()[4])
    changed["owner_authorization"]["statement_sha256"] = "0" * 64
    changed["review_scope"]["r4_reanalysis_allowed"] = True
    changed["request_sha256"] = canonical_sha256(
        {key: item for key, item in changed.items() if key != "request_sha256"}
    )

    failures = _validate(changed)

    assert "confirmatory_infrastructure_review_copy_on_write_binding_invalid" in failures


def test_decision_template_is_empty_and_fail_closed() -> None:
    request = _bundle()[4]
    decision = build_review_decision_template(request)

    assert decision["review_request_sha256"] == request["request_sha256"]
    assert decision["decision"] == ""
    assert decision["reviewer"]["did"] == ""
    assert all(value is False for value in decision["independence"].values())
    assert len(decision["checklist"]) == 14
    assert all(value is False for value in decision["checklist"].values())
    assert decision["execution_boundary"] == EXECUTION_BOUNDARY


def test_reviewer_declaration_binds_request_and_nonclaims() -> None:
    request = _bundle()[4]
    raw_sha256 = hashlib.sha256(b"review request").hexdigest()

    statement = approval_review_declaration(request, raw_sha256)

    assert raw_sha256 in statement
    assert request["request_sha256"] in statement
    assert APPROVAL_DECISION in statement
    assert "all 14 required checklist items" in statement
    assert "It does not create, start, rename, or remove any container" in statement
    assert "reanalyze r4" in statement
    assert "infer advice adherence" in statement


def _receipt() -> tuple[dict, dict]:
    request = _bundle()[4]
    signer = _Signer()
    decision = {
        "schema_version": (
            "j1-qualification-outcome-sensitive-confirmatory-"
            "infrastructure-rebind-review-decision:v1"
        ),
        "review_id": "confirmatory-infrastructure-review-r1",
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
            "independent_from_runner_and_candidate_authoring": True,
            "human_review_completed": True,
        },
        "checklist": {check: True for check in sorted(REQUIRED_REVIEW_CHECKS)},
        "execution_boundary": DECISION_BOUNDARY,
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
    assert receipt["execution_boundary"]["r4_reanalysis_performed"] is False
    assert receipt["execution_boundary"]["advice_adherence_observed"] is False


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

    assert "confirmatory_infrastructure_review_receipt_scope_invalid" in failures
    assert "confirmatory_infrastructure_review_signature_invalid" in failures


def test_promotion_is_copy_on_write_and_preserves_non_effect_boundaries() -> None:
    _, receipt = _receipt()
    candidate = _bundle()[0]
    original = copy.deepcopy(candidate)
    reviewed = build_reviewed_infrastructure_rebind(
        candidate=candidate,
        receipt=receipt,
        receipt_artifact_sha256="1" * 64,
    )

    assert candidate == original
    assert reviewed["execution_boundary"] == PROMOTION_BOUNDARY
    assert reviewed["execution_boundary"]["infrastructure_promoted"] is True
    assert reviewed["execution_boundary"]["participant_container_created"] is False
    assert reviewed["execution_boundary"]["r4_reanalysis_performed"] is False
    assert reviewed["execution_boundary"]["advice_adherence_observed"] is False
    assert (
        validate_reviewed_infrastructure_rebind(
            reviewed,
            candidate=candidate,
            receipt=receipt,
            receipt_artifact_sha256="1" * 64,
        )
        == []
    )

    changed = copy.deepcopy(reviewed)
    changed["isolations"][0]["target_isolation"]["runtime_boundary"][
        "network_mode"
    ] = "bridge"
    failures = validate_reviewed_infrastructure_rebind(
        changed,
        candidate=candidate,
        receipt=receipt,
        receipt_artifact_sha256="1" * 64,
    )
    assert "confirmatory_reviewed_infrastructure_hash_invalid" in failures
    assert "confirmatory_reviewed_infrastructure_copy_on_write_invalid" in failures
