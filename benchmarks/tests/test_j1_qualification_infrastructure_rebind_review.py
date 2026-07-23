from __future__ import annotations

import copy
import hashlib
import json

from nacl.signing import SigningKey

from benchmarks.j1.controlled_comparison import canonical_sha256
from benchmarks.j1.qualification_infrastructure_rebind_review import (
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
from benchmarks.tests.test_j1_qualification_infrastructure_rebind import _plan


NOW = "2026-07-23T17:00:00+08:00"
IMPLEMENTATION = {"source_revision": "a" * 40, "source_sha256": "b" * 64}
STATEMENT_SHA256 = "c" * 64
PROFILE_SHA256 = "1" * 64


class _Signer:
    def __init__(self) -> None:
        self.key = SigningKey.generate()

    @property
    def public_key_hex(self) -> str:
        return self.key.verify_key.encode().hex()

    def sign(self, message: bytes) -> bytes:
        return self.key.sign(message).signature


def _bundle() -> tuple:
    plan = _plan()[0]
    plan_raw = json.dumps(plan, sort_keys=True).encode()
    preflight = {
        "report_sha256": "d" * 64,
    }
    preflight_raw = json.dumps(preflight, sort_keys=True).encode()
    runner = {
        "manifest_sha256": "e" * 64,
        "image": {"image_id": f"sha256:{'f' * 64}"},
    }
    runner_raw = json.dumps(runner, sort_keys=True).encode()
    runner_gate = {"report_sha256": "0" * 64}
    runner_gate_raw = json.dumps(runner_gate, sort_keys=True).encode()
    request = build_review_request(
        request_id="review-r1",
        created_at=NOW,
        plan_path="/private/plan.json",
        plan=plan,
        plan_raw=plan_raw,
        preflight_path="/private/preflight.json",
        preflight=preflight,
        preflight_raw=preflight_raw,
        runner_manifest_path="/private/runner.json",
        runner_manifest=runner,
        runner_manifest_raw=runner_raw,
        runner_gate_path="/private/runner-gate.json",
        runner_gate=runner_gate,
        runner_gate_raw=runner_gate_raw,
        authorization_id="owner-approval-r1",
        authorized_at=NOW,
        authorization_statement_sha256=STATEMENT_SHA256,
        implementation=IMPLEMENTATION,
    )
    return (
        plan,
        plan_raw,
        preflight,
        preflight_raw,
        runner,
        runner_raw,
        runner_gate,
        runner_gate_raw,
        request,
    )


def _validate(bundle: tuple) -> list[str]:
    return validate_review_request(
        bundle[8],
        plan=bundle[0],
        plan_raw=bundle[1],
        preflight=bundle[2],
        preflight_raw=bundle[3],
        runner_manifest=bundle[4],
        runner_manifest_raw=bundle[5],
        runner_gate=bundle[6],
        runner_gate_raw=bundle[7],
        expected_authorization_statement_sha256=STATEMENT_SHA256,
        expected_implementation=IMPLEMENTATION,
    )


def test_review_request_binds_plan_image_inventory_and_owner() -> None:
    bundle = _bundle()
    request = bundle[8]

    assert _validate(bundle) == []
    assert request["required_checklist"] == sorted(REQUIRED_REVIEW_CHECKS)
    assert request["review_scope"]["inventory"]["participant_count"] == 40
    assert request["review_scope"]["runner_image_id"].startswith("sha256:")
    assert request["owner_authorization"]["scope"] == "independent_review_only"
    template = build_review_decision_template(request)
    assert all(value is False for value in template["checklist"].values())


def test_review_request_rejects_image_and_owner_tamper() -> None:
    bundle = list(_bundle())
    tampered = copy.deepcopy(bundle[8])
    tampered["review_scope"]["runner_image_id"] = "sha256:" + "1" * 64
    tampered["owner_authorization"]["statement_sha256"] = "2" * 64
    tampered["request_sha256"] = canonical_sha256(
        {key: item for key, item in tampered.items() if key != "request_sha256"}
    )
    bundle[8] = tampered

    failures = _validate(tuple(bundle))

    assert "infrastructure_review_scope_invalid" in failures
    assert "infrastructure_review_owner_authorization_invalid" in failures


def test_review_declaration_is_request_bound_and_non_executable() -> None:
    request = _bundle()[8]
    statement = approval_review_declaration(request)

    assert request["request_sha256"] in statement
    assert "approve_infrastructure_rebind" in statement
    assert "does not create or start any participant container" in statement
    assert hashlib.sha256(statement.encode()).hexdigest()


def _receipt(bundle: tuple) -> dict:
    request = bundle[8]
    signer = _Signer()
    decision = {
        "schema_version": DECISION_SCHEMA,
        "review_id": "infra-review-r1",
        "review_request_sha256": request["request_sha256"],
        "decision": "approve_infrastructure_rebind",
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
    return build_review_receipt(
        request=request,
        decision=decision,
        review_declaration_sha256=hashlib.sha256(
            approval_review_declaration(request).encode()
        ).hexdigest(),
        reviewer_profile_sha256=PROFILE_SHA256,
        implementation=IMPLEMENTATION,
        signer=signer,
    )


def test_review_receipt_signature_and_scope_are_verified() -> None:
    bundle = _bundle()
    receipt = _receipt(bundle)
    declaration_sha256 = hashlib.sha256(
        approval_review_declaration(bundle[8]).encode()
    ).hexdigest()

    assert (
        validate_review_receipt(
            receipt,
            request=bundle[8],
            expected_review_declaration_sha256=declaration_sha256,
            expected_reviewer_profile_sha256=PROFILE_SHA256,
            expected_implementation=IMPLEMENTATION,
        )
        == []
    )

    tampered = copy.deepcopy(receipt)
    tampered["review_scope"]["runner_image_id"] = "sha256:" + "9" * 64
    failures = validate_review_receipt(
        tampered,
        request=bundle[8],
        expected_review_declaration_sha256=declaration_sha256,
        expected_reviewer_profile_sha256=PROFILE_SHA256,
        expected_implementation=IMPLEMENTATION,
    )
    assert "infrastructure_review_receipt_scope_invalid" in failures
    assert "infrastructure_review_signature_invalid" in failures


def test_reviewed_infrastructure_is_copy_on_write_and_non_executable() -> None:
    bundle = _bundle()
    receipt = _receipt(bundle)
    candidate = bundle[0]
    reviewed = build_reviewed_infrastructure_rebind(
        candidate=candidate,
        receipt=receipt,
        receipt_artifact_sha256="2" * 64,
    )

    assert (
        validate_reviewed_infrastructure_rebind(
            reviewed,
            candidate=candidate,
            receipt=receipt,
            receipt_artifact_sha256="2" * 64,
        )
        == []
    )
    assert reviewed["execution_boundary"] == PROMOTION_BOUNDARY
    assert reviewed["execution_boundary"]["infrastructure_artifact_promoted"]
    assert not reviewed["execution_boundary"]["participant_isolation_rebound"]
    assert not reviewed["execution_boundary"]["participant_container_created"]

    tampered = copy.deepcopy(reviewed)
    tampered["isolations"][0]["target_isolation"]["network_mode"] = "bridge"
    failures = validate_reviewed_infrastructure_rebind(
        tampered,
        candidate=candidate,
        receipt=receipt,
        receipt_artifact_sha256="2" * 64,
    )
    assert "reviewed_infrastructure_rebind_hash_invalid" in failures
    assert "reviewed_infrastructure_rebind_copy_on_write_invalid" in failures
