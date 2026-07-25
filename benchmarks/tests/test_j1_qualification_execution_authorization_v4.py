from __future__ import annotations

import copy

from nacl.signing import SigningKey

from benchmarks.j1.qualification_execution_authorization_v4 import (
    AUTH_BOUNDARY,
    build_authorization,
    build_claim_preflight,
    validate_authorization,
)
from benchmarks.tests.test_j1_qualification_execution_preflight_v4 import _plan


class _Signer:
    def __init__(self) -> None:
        self.key = SigningKey.generate()

    @property
    def public_key_hex(self) -> str:
        return self.key.verify_key.encode().hex()

    def sign(self, message: bytes) -> bytes:
        return self.key.sign(message).signature


def _ref(name: str) -> dict[str, str]:
    return {
        "path": f"/private/{name}.json",
        "sha256": "a" * 64,
        "canonical_sha256": "b" * 64,
    }


def test_r4_authorization_is_signed_single_use_and_1800_seconds() -> None:
    plan = _plan()
    signer = _Signer()
    reviewer = {
        "did": "did:civ:testnet:reviewer",
        "public_key_hex": signer.public_key_hex,
        "credential_version": 1,
        "signer_kind": "pkcs11_ed25519",
    }
    implementation = {
        "source_revision": "c" * 40,
        "domain_source_sha256": "d" * 64,
        "operation_source_sha256": "e" * 64,
    }
    authorization = build_authorization(
        authorization_id="r4-auth-r1",
        owner_authorization_id="owner-r1",
        owner_statement_sha256="f" * 64,
        issued_at="2026-07-25T12:00:00+00:00",
        plan_ref=_ref("plan"),
        preflight_ref=_ref("preflight"),
        plan=plan,
        reviewer=reviewer,
        reviewer_profile_sha256="1" * 64,
        implementation=implementation,
        signer=signer,
    )

    assert (
        validate_authorization(
            authorization,
            plan=plan,
            expected_plan_ref=_ref("plan"),
            expected_preflight_ref=_ref("preflight"),
            expected_owner_statement_sha256="f" * 64,
            expected_reviewer=reviewer,
            expected_reviewer_profile_sha256="1" * 64,
            expected_implementation=implementation,
        )
        == []
    )
    assert authorization["ttl_seconds"] == 1800
    assert authorization["execution_boundary"] == AUTH_BOUNDARY


def test_r4_authorization_rejects_scope_or_signature_tamper() -> None:
    plan = _plan()
    signer = _Signer()
    reviewer = {
        "did": "did:civ:testnet:reviewer",
        "public_key_hex": signer.public_key_hex,
        "credential_version": 1,
        "signer_kind": "pkcs11_ed25519",
    }
    implementation = {"source_revision": "c" * 40}
    authorization = build_authorization(
        authorization_id="r4-auth-r1",
        owner_authorization_id="owner-r1",
        owner_statement_sha256="f" * 64,
        issued_at="2026-07-25T12:00:00+00:00",
        plan_ref=_ref("plan"),
        preflight_ref=_ref("preflight"),
        plan=plan,
        reviewer=reviewer,
        reviewer_profile_sha256="1" * 64,
        implementation=implementation,
        signer=signer,
    )
    tampered = copy.deepcopy(authorization)
    tampered["execution_scope"]["authorized_provider_calls"] = 321

    failures = validate_authorization(
        tampered,
        plan=plan,
        expected_plan_ref=_ref("plan"),
        expected_preflight_ref=_ref("preflight"),
        expected_owner_statement_sha256="f" * 64,
        expected_reviewer=reviewer,
        expected_reviewer_profile_sha256="1" * 64,
        expected_implementation=implementation,
    )
    assert "r4_authorization_scope_or_budget_invalid" in failures
    assert "r4_authorization_signature_invalid" in failures


def test_claim_preflight_requires_separate_irreversible_claim_approval() -> None:
    plan = _plan()
    authorization = {
        "authorization_id": "r4-auth-r1",
        "run_id": plan["run_id"],
        "execution_scope": plan["execution_scope"],
        "budget": plan["budget"],
        "controls": plan["controls"],
    }
    preflight = build_claim_preflight(
        checked_at="2026-07-25T12:01:00+00:00",
        authorization_ref=_ref("authorization"),
        authorization=authorization,
        issuance_gate_ref=_ref("gate"),
        plan=plan,
        inventory_snapshot={
            "participant_container_count": 40,
            "created_count": 40,
            "running_count": 0,
        },
        execution_manifest_sha256="2" * 64,
        implementation={"source_revision": "3" * 40},
    )

    statement = preflight["owner_authorization"]["required_exact_statement"]
    assert "create-exclusive atomic claim" in statement
    assert "claim is irreversible" in statement
    assert preflight["readiness"]["atomic_claim_allowed_by_this_preflight"] is False
