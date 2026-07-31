from __future__ import annotations

import copy
import hashlib

from nacl.signing import SigningKey

from benchmarks.j1.controlled_comparison import canonical_sha256
from benchmarks.j1.qualification_transport_reliability import (
    FAULT_SCENARIOS,
    build_fault_matrix_report,
    build_soak_plan,
    build_soak_preflight,
    build_transport_contract,
)
from benchmarks.j1.qualification_transport_review import (
    ALLOWED_DECISION,
    BOUNDARY,
    CHECKLIST,
    PROMOTION_BOUNDARY,
    build_frozen_review,
    build_promotion_gate,
    build_review_handoff,
    build_review_request,
    build_signed_review_receipt,
    validate_review_request,
    validate_review_sources,
    validate_signed_review_receipt,
)


IMPLEMENTATION = {
    "source_revision": "1" * 40,
    "domain_source_sha256": "2" * 64,
    "operation_source_sha256": "3" * 64,
    "transport_source_sha256": "4" * 64,
}
REVIEW_IMPLEMENTATION = {
    "source_revision": "5" * 40,
    "domain_source_sha256": "6" * 64,
    "operation_source_sha256": "7" * 64,
    "promotion_source_sha256": "8" * 64,
}


class _Signer:
    def __init__(self) -> None:
        self._key = SigningKey.generate()

    @property
    def public_key_hex(self) -> str:
        return self._key.verify_key.encode().hex()

    def sign(self, message: bytes) -> bytes:
        return self._key.sign(message).signature


def _ref(name: str, canonical: str = "a" * 64) -> dict[str, str]:
    return {
        "path": f"/private/{name}.json",
        "sha256": canonical_sha256([name, "raw"]),
        "canonical_sha256": canonical,
    }


def _scenarios() -> list[dict]:
    return [
        {
            "scenario": name,
            "expected": "bounded reviewed outcome",
            "observed": "bounded reviewed outcome",
            "observed_connect_attempt_count": 3 if "connect" in name else 1,
            "observed_http_request_count": (
                0 if "before_dispatch" in name else 1
            ),
            "observed_post_dispatch_retry_count": 0,
            "passed": True,
        }
        for name in FAULT_SCENARIOS
    ]


def _sources() -> tuple[
    dict[str, dict[str, str]], dict[str, dict], str
]:
    contract = build_transport_contract(
        contract_id="transport-r1",
        created_at="2026-07-31T13:00:00+00:00",
        source_binding={
            "r2_terminal_gate": _ref("r2"),
            "r3_terminal_gate": _ref("r3"),
        },
        implementation=IMPLEMENTATION,
    )
    contract_ref = _ref("contract", contract["contract_sha256"])
    fault = build_fault_matrix_report(
        checked_at="2026-07-31T13:01:00+00:00",
        contract_ref=contract_ref,
        scenarios=_scenarios(),
        implementation=IMPLEMENTATION,
    )
    fault_ref = _ref("fault", fault["report_sha256"])
    plan = build_soak_plan(
        plan_id="transport-soak-r1",
        created_at="2026-07-31T13:02:00+00:00",
        contract_ref=contract_ref,
        fault_matrix_ref=fault_ref,
        provider_design_ref=_ref("provider"),
        provider={
            "provider_id": "openai_compatible",
            "base_url": "https://api.deepseek.com",
            "endpoint": "/chat/completions",
            "model": "deepseek-v4-pro",
        },
        implementation=IMPLEMENTATION,
    )
    plan_ref = _ref("plan", plan["plan_sha256"])
    preflight = build_soak_preflight(
        checked_at="2026-07-31T13:03:00+00:00",
        plan_ref=plan_ref,
        plan=plan,
        validation_failures=[],
    )
    preflight_ref = _ref("preflight", preflight["preflight_sha256"])
    owner_statement = "owner approves transport materials for review only"
    handoff = {
        "schema_version": "j1-qualification-transport-review-handoff:v1",
        "status": "owner_approval_for_independent_review_required",
        "transport_contract": contract_ref,
        "fault_matrix": fault_ref,
        "soak_plan": plan_ref,
        "soak_preflight": preflight_ref,
        "required_exact_approval_statement": owner_statement,
        "statement_sha256": hashlib.sha256(owner_statement.encode()).hexdigest(),
        "execution_boundary": {},
    }
    handoff["handoff_sha256"] = canonical_sha256(handoff)
    handoff_ref = _ref("handoff", handoff["handoff_sha256"])
    materials = {
        "transport_contract": contract_ref,
        "fault_matrix": fault_ref,
        "soak_plan": plan_ref,
        "soak_preflight": preflight_ref,
        "owner_handoff": handoff_ref,
    }
    values = {
        "transport_contract": contract,
        "fault_matrix": fault,
        "soak_plan": plan,
        "soak_preflight": preflight,
        "owner_handoff": handoff,
    }
    return materials, values, handoff["statement_sha256"]


def _request() -> tuple[dict, dict[str, dict[str, str]], str]:
    materials, values, owner_sha = _sources()
    request = build_review_request(
        request_id="transport-review-r1",
        created_at="2026-07-31T13:05:00+00:00",
        materials=materials,
        values=values,
        owner_statement_sha256=owner_sha,
        review_implementation=REVIEW_IMPLEMENTATION,
    )
    return request, materials, owner_sha


def test_transport_review_sources_and_request_are_fail_closed() -> None:
    materials, values, owner_sha = _sources()
    assert (
        validate_review_sources(
            materials=materials,
            values=values,
            owner_statement_sha256=owner_sha,
        )
        == []
    )
    request = build_review_request(
        request_id="transport-review-r1",
        created_at="2026-07-31T13:05:00+00:00",
        materials=materials,
        values=values,
        owner_statement_sha256=owner_sha,
        review_implementation=REVIEW_IMPLEMENTATION,
    )
    assert request["allowed_decision"] == ALLOWED_DECISION
    assert request["required_checklist"] == sorted(CHECKLIST)
    assert request["decision_template"]["decision"] is None
    assert (
        validate_review_request(
            request,
            expected_materials=materials,
            expected_owner_statement_sha256=owner_sha,
            expected_candidate_implementation=IMPLEMENTATION,
            expected_review_implementation=REVIEW_IMPLEMENTATION,
        )
        == []
    )

    changed = copy.deepcopy(values)
    changed["soak_plan"]["execution_policy"]["http_request_attempts_per_call"] = 2
    failures = validate_review_sources(
        materials=materials,
        values=changed,
        owner_statement_sha256=owner_sha,
    )
    assert "transport_soak_plan_execution_policy_invalid" in failures


def test_transport_review_handoff_requires_exact_ten_item_declaration() -> None:
    request, _, _ = _request()
    handoff = build_review_handoff(
        request_ref=_ref("request", request["request_sha256"]),
        request=request,
        request_raw_sha256="b" * 64,
    )
    statement = handoff["required_exact_approval_statement"]
    assert f"all {len(CHECKLIST)} required checklist items" in statement
    assert "every post-dispatch failure is ambiguous" in statement
    assert handoff["decision_template"]["decision"] is None
    assert handoff["execution_boundary"] == BOUNDARY


def test_transport_review_receipt_signature_detects_tampering() -> None:
    request, materials, owner_sha = _request()
    signer = _Signer()
    reviewer = {
        "did": "did:civ:testnet:reviewer",
        "public_key_hex": signer.public_key_hex,
        "credential_version": 1,
        "signer_kind": "pkcs11_ed25519",
    }
    request_ref = _ref("request", request["request_sha256"])
    receipt = build_signed_review_receipt(
        review_id="transport-review-r1",
        reviewed_at="2026-07-31T13:10:00+00:00",
        request_ref=request_ref,
        materials=materials,
        owner_statement_sha256=owner_sha,
        approval_statement_sha256="c" * 64,
        reviewer=reviewer,
        reviewer_profile_sha256="d" * 64,
        implementation=REVIEW_IMPLEMENTATION,
        signer=signer,
    )
    assert (
        validate_signed_review_receipt(
            receipt,
            expected_request_ref=request_ref,
            expected_materials=materials,
            expected_owner_statement_sha256=owner_sha,
            expected_approval_statement_sha256="c" * 64,
            expected_reviewer=reviewer,
            expected_reviewer_profile_sha256="d" * 64,
            expected_implementation=REVIEW_IMPLEMENTATION,
        )
        == []
    )

    changed = copy.deepcopy(receipt)
    changed["checklist"][sorted(CHECKLIST)[0]] = False
    failures = validate_signed_review_receipt(
        changed,
        expected_request_ref=request_ref,
        expected_materials=materials,
        expected_owner_statement_sha256=owner_sha,
        expected_approval_statement_sha256="c" * 64,
        expected_reviewer=reviewer,
        expected_reviewer_profile_sha256="d" * 64,
        expected_implementation=REVIEW_IMPLEMENTATION,
    )
    assert "transport_review_receipt_reviewer_invalid" in failures
    assert "transport_review_receipt_signature_invalid" in failures


def test_transport_promotion_keeps_live_effects_blocked() -> None:
    request, materials, _ = _request()
    frozen = build_frozen_review(
        frozen_id="transport-frozen-r1",
        promoted_at="2026-07-31T13:10:00+00:00",
        source_materials=materials,
        frozen_materials={
            name: {**ref, "path": f"/frozen/{name}.json"}
            for name, ref in materials.items()
        },
        review_receipt_ref=_ref("receipt"),
        reviewer_did="did:civ:testnet:reviewer",
        implementation=REVIEW_IMPLEMENTATION,
    )
    gate = build_promotion_gate(
        request_ref=_ref("request", request["request_sha256"]),
        handoff_ref=_ref("handoff"),
        receipt_ref=_ref("receipt"),
        frozen_review_ref=_ref("frozen", frozen["frozen_review_sha256"]),
    )
    assert frozen["readiness"]["live_soak_authorization_preflight_allowed"] is True
    assert frozen["readiness"]["provider_or_model_call_allowed"] is False
    assert gate["passed"] is True
    assert gate["pin_recorded"] is False
    assert gate["private_key_exported"] is False
    assert gate["execution_boundary"] == PROMOTION_BOUNDARY
