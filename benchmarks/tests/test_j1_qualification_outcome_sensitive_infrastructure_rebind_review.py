from __future__ import annotations

import copy
import hashlib
import json

from nacl.signing import SigningKey

from benchmarks.j1.controlled_comparison import canonical_sha256
from benchmarks.j1.qualification_outcome_sensitive_infrastructure_rebind_review import (
    APPROVAL_DECISION,
    DECISION_SCHEMA,
    PROMOTION_BOUNDARY,
    REQUIRED_REVIEW_CHECKS,
    approval_review_declaration,
    build_review_decision_template,
    build_review_receipt,
    build_review_request,
    build_reviewed_infrastructure_rebind,
    validate_review_receipt,
    validate_review_request,
    validate_reviewed_infrastructure_rebind,
)
from benchmarks.tests.test_j1_qualification_outcome_sensitive_infrastructure_rebind import (
    _build,
    _fixtures,
)


NOW = "2026-07-29T16:00:00+08:00"
PLAN_PATH = "/private/outcome-infrastructure-plan.json"
PREFLIGHT_PATH = "/private/outcome-infrastructure-preflight.json"
STATEMENT_SHA256 = "a" * 64
IMPLEMENTATION = {"source_revision": "b" * 40, "source_sha256": "c" * 64}
PROFILE_SHA256 = "d" * 64


class _Signer:
    def __init__(self) -> None:
        self.key = SigningKey.generate()

    @property
    def public_key_hex(self) -> str:
        return self.key.verify_key.encode().hex()

    def sign(self, message: bytes) -> bytes:
        return self.key.sign(message).signature


def _bundle() -> tuple[dict, bytes, dict, bytes, dict]:
    plan = _build(_fixtures())
    plan_raw = json.dumps(plan, sort_keys=True).encode()
    observed = {
        item["participant_id"]: item["source_isolation"]["observed_state"]
        for item in plan["isolations"]
    }
    preflight = {
        "report_sha256": "e" * 64,
        "observed_sources_sha256": canonical_sha256(observed),
        "docker_census": {
            "historical_j1_container_count": 120,
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
        request_id="outcome-infrastructure-review-r1",
        created_at=NOW,
        plan_path=PLAN_PATH,
        plan=plan,
        plan_raw=plan_raw,
        preflight_path=PREFLIGHT_PATH,
        preflight=preflight,
        preflight_raw=preflight_raw,
        authorization_id="owner-approval-r1",
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
        plan_raw=plan_raw,
        preflight=preflight,
        preflight_raw=preflight_raw,
        expected_plan_path=PLAN_PATH,
        expected_preflight_path=PREFLIGHT_PATH,
        expected_authorization_statement_sha256=STATEMENT_SHA256,
        expected_implementation=IMPLEMENTATION,
    )


def test_request_binds_owner_scope_disk_safety_and_ten_checks() -> None:
    bundle = _bundle()
    request = bundle[4]

    assert _validate(bundle) == []
    assert request["owner_authorization"]["scope"] == "independent_review_only"
    assert request["review_scope"]["inventory"]["participant_count"] == 40
    assert request["review_scope"]["inventory"]["mentor_signed_advice_count"] == 180
    assert (
        request["review_scope"]["docker_census"]["historical_j1_container_count"] == 120
    )
    assert (
        request["review_scope"]["disk_safety"]["implicit_container_prune_authorized"]
        is False
    )
    assert request["required_checklist"] == sorted(REQUIRED_REVIEW_CHECKS)
    assert len(request["required_checklist"]) == 10
    assert all(
        value is False
        for value in build_review_decision_template(request)["checklist"].values()
    )


def test_request_rejects_owner_or_disk_safety_tamper() -> None:
    bundle = list(_bundle())
    changed = copy.deepcopy(bundle[4])
    changed["owner_authorization"]["statement_sha256"] = "f" * 64
    changed["review_scope"]["disk_safety"]["implicit_container_prune_authorized"] = True
    changed["request_sha256"] = canonical_sha256(
        {key: item for key, item in changed.items() if key != "request_sha256"}
    )
    bundle[4] = changed

    failures = _validate(tuple(bundle))

    assert "outcome_infrastructure_review_owner_authorization_invalid" in failures
    assert "outcome_infrastructure_review_scope_invalid" in failures


def test_declaration_is_request_bound_and_non_executable() -> None:
    request = _bundle()[4]
    declaration = approval_review_declaration(request, "1" * 64)

    assert "1" * 64 in declaration
    assert request["request_sha256"] in declaration
    assert APPROVAL_DECISION in declaration
    assert "all 10 required checklist items" in declaration
    assert "prune historical containers or images" in declaration
    assert "upgrade SI-13 maturity" in declaration


def _receipt() -> tuple[dict, dict]:
    request = _bundle()[4]
    signer = _Signer()
    decision = {
        "schema_version": DECISION_SCHEMA,
        "review_id": "outcome-infrastructure-independent-review-r1",
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
    }
    declaration_sha256 = hashlib.sha256(
        approval_review_declaration(request, "1" * 64).encode()
    ).hexdigest()
    receipt = build_review_receipt(
        request=request,
        decision=decision,
        review_declaration_sha256=declaration_sha256,
        reviewer_profile_sha256=PROFILE_SHA256,
        implementation=IMPLEMENTATION,
        signer=signer,
    )
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
    changed["review_scope"]["inventory"]["parent_container_exited_count"] = 39

    failures = validate_review_receipt(
        changed,
        request=request,
        expected_review_declaration_sha256=receipt["review_declaration_sha256"],
        expected_reviewer_profile_sha256=PROFILE_SHA256,
        expected_implementation=IMPLEMENTATION,
    )

    assert "outcome_infrastructure_review_receipt_scope_invalid" in failures
    assert "outcome_infrastructure_review_signature_invalid" in failures


def test_promotion_is_copy_on_write_and_non_executable() -> None:
    _, receipt = _receipt()
    candidate = _bundle()[0]
    original = copy.deepcopy(candidate)
    reviewed = build_reviewed_infrastructure_rebind(
        candidate=candidate,
        receipt=receipt,
        receipt_artifact_sha256="2" * 64,
    )

    assert candidate == original
    assert reviewed["execution_boundary"] == PROMOTION_BOUNDARY
    assert reviewed["execution_boundary"]["infrastructure_promoted"] is True
    assert reviewed["execution_boundary"]["participant_container_created"] is False
    assert reviewed["execution_boundary"]["parent_container_removed"] is False
    assert (
        validate_reviewed_infrastructure_rebind(
            reviewed,
            candidate=candidate,
            receipt=receipt,
            receipt_artifact_sha256="2" * 64,
        )
        == []
    )

    changed = copy.deepcopy(reviewed)
    changed["isolations"][0]["target_isolation"]["runtime_boundary"]["network_mode"] = (
        "bridge"
    )
    failures = validate_reviewed_infrastructure_rebind(
        changed,
        candidate=candidate,
        receipt=receipt,
        receipt_artifact_sha256="2" * 64,
    )
    assert "outcome_reviewed_infrastructure_hash_invalid" in failures
    assert "outcome_reviewed_infrastructure_copy_on_write_invalid" in failures
