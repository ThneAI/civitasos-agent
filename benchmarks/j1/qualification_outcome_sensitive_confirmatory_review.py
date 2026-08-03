"""Independent review contracts for the J1-D confirmatory amendment."""

from __future__ import annotations

import copy
import hashlib
import json
from typing import Any, Protocol

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from .controlled_comparison import canonical_sha256
from .qualification_outcome_sensitive_confirmatory_amendment import (
    BOUNDARY,
    BUNDLE_SCHEMA,
    PREFLIGHT_SCHEMA,
    POSTMORTEM_GATE_SHA256,
    validate_bundle,
    validate_preflight,
)


OWNER_GATE_SCHEMA = "j1-confirmatory-amendment-owner-review-gate:v1"
REVIEW_REQUEST_SCHEMA = "j1-confirmatory-amendment-review-request:v1"
REVIEW_HANDOFF_SCHEMA = "j1-confirmatory-amendment-review-handoff:v1"
REVIEW_RECEIPT_SCHEMA = "j1-confirmatory-amendment-review-receipt:v1"
FROZEN_REVIEW_SCHEMA = "j1-confirmatory-amendment-frozen-review:v1"
PROMOTION_GATE_SCHEMA = "j1-confirmatory-amendment-promotion-gate:v1"
ALLOWED_DECISION = "approve_outcome_sensitive_confirmatory_method_amendment"
CHECKLIST = (
    "all_five_copy_on_write_materials_read_and_hash_verified",
    "r4_run_postmortem_and_nonclaim_boundary_remain_immutable",
    "one_sided_exact_20_pair_sign_flip_test_and_statistic_reviewed",
    "all_2_power_20_assignments_exact_rational_p_values_reviewed",
    "zero_effect_tail_tie_and_no_plus_one_rules_reviewed",
    "holm_family_sort_threshold_stop_and_equal_p_tie_order_reviewed",
    "missingness_censoring_and_structural_failure_rules_reviewed",
    "eight_scenario_reference_implementation_verification_reviewed",
    "confirmatory_rejection_does_not_bypass_other_gates",
    "task_treatment_fixture_assignment_and_decision_schema_unchanged",
    "advice_adherence_deferred_and_prior_consent_not_inherited",
    "execution_effectiveness_causal_claim_and_si13_upgrade_remain_blocked",
)
OWNER_BOUNDARY = {
    **BOUNDARY,
    "owner_review_authorization_recorded": True,
    "independent_review_completed": False,
    "copy_on_write_promotion_performed": False,
}
REVIEW_BOUNDARY = {
    **OWNER_BOUNDARY,
    "independent_reviewer_decision_required": True,
}
RECEIPT_BOUNDARY = {
    **OWNER_BOUNDARY,
    "independent_review_completed": True,
    "independent_review_approved": True,
    "copy_on_write_promotion_allowed": True,
}
PROMOTION_BOUNDARY = {
    **RECEIPT_BOUNDARY,
    "offline_material_generation_only": False,
    "protocol_or_evaluator_promoted": True,
    "copy_on_write_promotion_performed": True,
    "review_promotion_only": True,
}


class ReviewSigner(Protocol):
    @property
    def public_key_hex(self) -> str: ...

    def sign(self, message: bytes) -> bytes: ...


def build_owner_gate(
    *,
    bundle: dict[str, Any],
    bundle_ref: dict[str, str],
    preflight: dict[str, Any],
    preflight_ref: dict[str, str],
    owner_statement_sha256: str,
) -> dict[str, Any]:
    failures = validate_bundle(bundle) + validate_preflight(preflight)
    statement = preflight.get("required_owner_statement")
    if not (
        bundle.get("schema_version") == BUNDLE_SCHEMA
        and preflight.get("schema_version") == PREFLIGHT_SCHEMA
        and preflight.get("bundle") == bundle_ref
        and preflight.get("postmortem_promotion_gate", {}).get("canonical_sha256")
        == POSTMORTEM_GATE_SHA256
        and isinstance(statement, str)
        and hashlib.sha256(statement.encode()).hexdigest()
        == preflight.get("required_owner_statement_sha256")
        == owner_statement_sha256
        and _valid_ref(bundle_ref, bundle.get("bundle_sha256"))
        and _valid_ref(preflight_ref, preflight.get("report_sha256"))
    ):
        failures.append("confirmatory_owner_authorization_binding_invalid")
    if failures:
        raise ValueError(
            f"confirmatory owner review authorization invalid: "
            f"{list(dict.fromkeys(failures))}"
        )
    value = {
        "schema_version": OWNER_GATE_SCHEMA,
        "passed": True,
        "failure_reasons": [],
        "state": "owner_authorized_independent_confirmatory_amendment_review_only",
        "bundle": copy.deepcopy(bundle_ref),
        "preflight": copy.deepcopy(preflight_ref),
        "owner_authorization": {
            "statement": statement,
            "statement_sha256": owner_statement_sha256,
        },
        "execution_boundary": copy.deepcopy(OWNER_BOUNDARY),
    }
    return _seal(value, "report_sha256")


def build_review_request(
    *,
    request_id: str,
    created_at: str,
    bundle_ref: dict[str, str],
    bundle: dict[str, Any],
    preflight_ref: dict[str, str],
    owner_gate_ref: dict[str, str],
    implementation: dict[str, str],
) -> dict[str, Any]:
    failures = validate_bundle(bundle)
    if not (
        _valid_ref(bundle_ref, bundle.get("bundle_sha256"))
        and _valid_ref(preflight_ref)
        and _valid_ref(owner_gate_ref)
    ):
        failures.append("confirmatory_review_request_source_ref_invalid")
    if failures:
        raise ValueError(f"confirmatory review request invalid: {failures}")
    value = {
        "schema_version": REVIEW_REQUEST_SCHEMA,
        "request_id": request_id,
        "created_at": created_at,
        "status": "independent_reviewer_decision_required",
        "reviewed_bundle": copy.deepcopy(bundle_ref),
        "owner_approval_preflight": copy.deepcopy(preflight_ref),
        "owner_authorization_gate": copy.deepcopy(owner_gate_ref),
        "reviewed_materials": copy.deepcopy(bundle["materials"]),
        "scope_summary": copy.deepcopy(bundle["inventory"]),
        "required_checklist": list(CHECKLIST),
        "allowed_decision": ALLOWED_DECISION,
        "decision_template": _empty_decision(),
        "implementation": copy.deepcopy(implementation),
        "execution_boundary": copy.deepcopy(REVIEW_BOUNDARY),
    }
    return _seal(value, "request_sha256")


def validate_review_request(
    value: Any,
    *,
    expected_bundle_ref: dict[str, str],
    expected_preflight_ref: dict[str, str],
    expected_owner_gate_ref: dict[str, str],
    expected_materials: dict[str, dict[str, str]],
    expected_implementation: dict[str, str],
) -> list[str]:
    request = value if isinstance(value, dict) else {}
    failures: list[str] = []
    if not (
        request.get("schema_version") == REVIEW_REQUEST_SCHEMA
        and request.get("status") == "independent_reviewer_decision_required"
        and request.get("reviewed_bundle") == expected_bundle_ref
        and request.get("owner_approval_preflight") == expected_preflight_ref
        and request.get("owner_authorization_gate") == expected_owner_gate_ref
        and request.get("reviewed_materials") == expected_materials
        and request.get("required_checklist") == list(CHECKLIST)
        and request.get("allowed_decision") == ALLOWED_DECISION
        and request.get("decision_template") == _empty_decision()
        and request.get("implementation") == expected_implementation
        and request.get("execution_boundary") == REVIEW_BOUNDARY
        and _self_hash(request, "request_sha256")
    ):
        failures.append("confirmatory_review_request_contract_invalid")
    return failures


def reviewer_approval_statement(
    *,
    request_ref: dict[str, str],
    request: dict[str, Any],
) -> str:
    materials = request["reviewed_materials"]
    return (
        "I have independently reviewed J1-D outcome-sensitive confirmatory-method "
        f"amendment review request raw SHA-256 {request_ref['sha256']}, canonical "
        f"SHA-256 {request_ref['canonical_sha256']} and choose {ALLOWED_DECISION}. "
        f"I confirm all {len(CHECKLIST)} required checklist items, disclose all "
        "conflicts, affirm that I am independent from candidate authoring and have "
        "completed human review. I approve only copy-on-write promotion of bundle "
        f"raw SHA-256 {request['reviewed_bundle']['sha256']}, canonical SHA-256 "
        f"{request['reviewed_bundle']['canonical_sha256']}, binding exact paired "
        f"method {materials['confirmatory_method']['canonical_sha256']}, protocol "
        f"addendum {materials['protocol_addendum']['canonical_sha256']}, evaluator "
        f"addendum {materials['evaluator_addendum']['canonical_sha256']}, consent "
        f"impact {materials['consent_impact']['canonical_sha256']}, verification "
        f"{materials['verification']['canonical_sha256']}, and review "
        f"implementation revision {request['implementation']['source_revision']}. "
        "I acknowledge that r4 remains immutable and cannot be reanalyzed for a "
        "confirmatory claim, advice adherence remains unobserved, and prior consent "
        "is not inherited; 40 of 40 new consent extensions remain required after "
        "promotion. This approval permits only review receipt signing and "
        "copy-on-write material promotion. It does not migrate consent, create or "
        "start a container, read a provider credential, call a provider or model, "
        "execute an Agent or task, append Backend Facts or the Ledger, issue or "
        "consume an execution authorization, authorize an effectiveness or causal "
        "claim, or upgrade SI-13 maturity."
    )


def build_review_handoff(
    *,
    request_ref: dict[str, str],
    request: dict[str, Any],
) -> dict[str, Any]:
    statement = reviewer_approval_statement(request_ref=request_ref, request=request)
    value = {
        "schema_version": REVIEW_HANDOFF_SCHEMA,
        "status": "independent_reviewer_decision_required",
        "review_request": copy.deepcopy(request_ref),
        "reviewed_bundle": copy.deepcopy(request["reviewed_bundle"]),
        "owner_authorization_gate": copy.deepcopy(request["owner_authorization_gate"]),
        "decision_template": _empty_decision(),
        "required_exact_approval_statement": statement,
        "required_exact_approval_statement_sha256": hashlib.sha256(
            statement.encode()
        ).hexdigest(),
        "implementation": copy.deepcopy(request["implementation"]),
        "execution_boundary": copy.deepcopy(REVIEW_BOUNDARY),
    }
    return _seal(value, "handoff_sha256")


def build_signed_review_receipt(
    *,
    review_id: str,
    reviewed_at: str,
    request_ref: dict[str, str],
    bundle_ref: dict[str, str],
    preflight_ref: dict[str, str],
    owner_gate_ref: dict[str, str],
    materials: dict[str, dict[str, str]],
    approval_statement_sha256: str,
    reviewer: dict[str, Any],
    reviewer_profile_sha256: str,
    implementation: dict[str, str],
    signer: ReviewSigner,
) -> dict[str, Any]:
    value = {
        "schema_version": REVIEW_RECEIPT_SCHEMA,
        "review_id": review_id,
        "reviewed_at": reviewed_at,
        "decision": ALLOWED_DECISION,
        "request": copy.deepcopy(request_ref),
        "reviewed_bundle": copy.deepcopy(bundle_ref),
        "owner_approval_preflight": copy.deepcopy(preflight_ref),
        "owner_authorization_gate": copy.deepcopy(owner_gate_ref),
        "reviewed_materials": copy.deepcopy(materials),
        "approval_statement_sha256": approval_statement_sha256,
        "reviewer": {
            "did": reviewer["did"],
            "public_key_hex": reviewer["public_key_hex"],
            "credential_version": reviewer["credential_version"],
            "signer_kind": reviewer["signer_kind"],
            "identity_profile_sha256": reviewer_profile_sha256,
        },
        "independence": {
            "conflicts_disclosed": True,
            "independent_from_candidate_authoring": True,
            "human_review_completed": True,
        },
        "checklist": {item: True for item in CHECKLIST},
        "implementation": copy.deepcopy(implementation),
        "execution_boundary": copy.deepcopy(RECEIPT_BOUNDARY),
    }
    payload = _signature_payload(value)
    signature = signer.sign(payload)
    if len(signature) != 64:
        raise ValueError("confirmatory review signature must be 64 bytes")
    value["signature"] = {
        "algorithm": "ed25519",
        "public_key_hex": signer.public_key_hex,
        "signed_payload_sha256": hashlib.sha256(payload).hexdigest(),
        "signature_hex": signature.hex(),
    }
    value["receipt_sha256"] = canonical_sha256(value)
    failures = validate_signed_review_receipt(
        value,
        expected_request_ref=request_ref,
        expected_bundle_ref=bundle_ref,
        expected_preflight_ref=preflight_ref,
        expected_owner_gate_ref=owner_gate_ref,
        expected_materials=materials,
        expected_approval_statement_sha256=approval_statement_sha256,
        expected_reviewer=reviewer,
        expected_reviewer_profile_sha256=reviewer_profile_sha256,
        expected_implementation=implementation,
    )
    if failures:
        raise ValueError(f"confirmatory signed review receipt invalid: {failures}")
    return value


def validate_signed_review_receipt(
    value: Any,
    *,
    expected_request_ref: dict[str, str],
    expected_bundle_ref: dict[str, str],
    expected_preflight_ref: dict[str, str],
    expected_owner_gate_ref: dict[str, str],
    expected_materials: dict[str, dict[str, str]],
    expected_approval_statement_sha256: str,
    expected_reviewer: dict[str, Any],
    expected_reviewer_profile_sha256: str,
    expected_implementation: dict[str, str],
) -> list[str]:
    receipt = value if isinstance(value, dict) else {}
    failures: list[str] = []
    if not (
        receipt.get("schema_version") == REVIEW_RECEIPT_SCHEMA
        and receipt.get("decision") == ALLOWED_DECISION
        and receipt.get("request") == expected_request_ref
        and receipt.get("reviewed_bundle") == expected_bundle_ref
        and receipt.get("owner_approval_preflight") == expected_preflight_ref
        and receipt.get("owner_authorization_gate") == expected_owner_gate_ref
        and receipt.get("reviewed_materials") == expected_materials
        and receipt.get("approval_statement_sha256")
        == expected_approval_statement_sha256
        and receipt.get("reviewer")
        == {
            "did": expected_reviewer.get("did"),
            "public_key_hex": expected_reviewer.get("public_key_hex"),
            "credential_version": expected_reviewer.get("credential_version"),
            "signer_kind": expected_reviewer.get("signer_kind"),
            "identity_profile_sha256": expected_reviewer_profile_sha256,
        }
        and receipt.get("independence")
        == {
            "conflicts_disclosed": True,
            "independent_from_candidate_authoring": True,
            "human_review_completed": True,
        }
        and receipt.get("checklist") == {item: True for item in CHECKLIST}
        and receipt.get("implementation") == expected_implementation
        and receipt.get("execution_boundary") == RECEIPT_BOUNDARY
    ):
        failures.append("confirmatory_review_receipt_contract_invalid")
    signature = receipt.get("signature")
    signature = signature if isinstance(signature, dict) else {}
    unsigned = {
        key: item
        for key, item in receipt.items()
        if key not in {"signature", "receipt_sha256"}
    }
    payload = _signature_payload(unsigned)
    if not (
        signature.get("algorithm") == "ed25519"
        and signature.get("public_key_hex") == expected_reviewer.get("public_key_hex")
        and signature.get("signed_payload_sha256")
        == hashlib.sha256(payload).hexdigest()
    ):
        failures.append("confirmatory_review_receipt_signature_metadata_invalid")
    try:
        VerifyKey(
            bytes.fromhex(str(expected_reviewer.get("public_key_hex", "")))
        ).verify(payload, bytes.fromhex(str(signature.get("signature_hex", ""))))
    except (BadSignatureError, ValueError):
        failures.append("confirmatory_review_receipt_signature_invalid")
    if not _self_hash(receipt, "receipt_sha256"):
        failures.append("confirmatory_review_receipt_hash_invalid")
    return list(dict.fromkeys(failures))


def build_frozen_review(
    *,
    frozen_id: str,
    promoted_at: str,
    source_materials: dict[str, dict[str, str]],
    frozen_materials: dict[str, dict[str, str]],
    source_bundle_ref: dict[str, str],
    review_receipt_ref: dict[str, str],
    reviewer_did: str,
    implementation: dict[str, str],
) -> dict[str, Any]:
    value = {
        "schema_version": FROZEN_REVIEW_SCHEMA,
        "frozen_id": frozen_id,
        "promoted_at": promoted_at,
        "status": "operator_reviewed_frozen",
        "source_bundle": copy.deepcopy(source_bundle_ref),
        "source_materials": copy.deepcopy(source_materials),
        "frozen_source_copies": copy.deepcopy(frozen_materials),
        "operator_review": {
            "reviewer_did": reviewer_did,
            "review_receipt": copy.deepcopy(review_receipt_ref),
            "decision": ALLOWED_DECISION,
        },
        "readiness": {
            "confirmatory_method_frozen": True,
            "protocol_addendum_frozen": True,
            "evaluator_addendum_frozen": True,
            "consent_impact_frozen": True,
            "verification_frozen": True,
            "participant_consent_extensions_complete": False,
            "participant_consent_extension_count": 0,
            "participant_consent_extension_required_count": 40,
            "downstream_bindings_refreshed": False,
            "execution_preflight_allowed": False,
            "effectiveness_or_causal_claim_allowed": False,
            "si13_maturity_upgrade_allowed": False,
        },
        "implementation": copy.deepcopy(implementation),
        "execution_boundary": copy.deepcopy(PROMOTION_BOUNDARY),
    }
    return _seal(value, "frozen_review_sha256")


def build_promotion_gate(
    *,
    request_ref: dict[str, str],
    handoff_ref: dict[str, str],
    owner_gate_ref: dict[str, str],
    receipt_ref: dict[str, str],
    frozen_review_ref: dict[str, str],
    frozen_review: dict[str, Any],
) -> dict[str, Any]:
    value = {
        "schema_version": PROMOTION_GATE_SCHEMA,
        "passed": True,
        "failure_reasons": [],
        "state": (
            "confirmatory_method_amendment_reviewed_frozen_"
            "40_of_40_consent_required_execution_blocked"
        ),
        "review_request": copy.deepcopy(request_ref),
        "review_handoff": copy.deepcopy(handoff_ref),
        "owner_authorization_gate": copy.deepcopy(owner_gate_ref),
        "review_receipt": copy.deepcopy(receipt_ref),
        "frozen_review": copy.deepcopy(frozen_review_ref),
        "signature_valid": True,
        "pin_recorded": False,
        "private_key_exported": False,
        "readiness": copy.deepcopy(frozen_review["readiness"]),
        "execution_boundary": copy.deepcopy(PROMOTION_BOUNDARY),
    }
    return _seal(value, "report_sha256")


def _empty_decision() -> dict[str, Any]:
    return {
        "decision": None,
        "reviewer_did": None,
        "reviewed_at": None,
        "independent_from_candidate_authoring": None,
        "conflicts_disclosed": None,
        "human_review_completed": None,
        "checklist": {name: None for name in CHECKLIST},
    }


def _signature_payload(value: dict[str, Any]) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def _seal(value: dict[str, Any], field: str) -> dict[str, Any]:
    value[field] = canonical_sha256(value)
    return value


def _self_hash(value: Any, field: str) -> bool:
    if not isinstance(value, dict):
        return False
    body = {key: item for key, item in value.items() if key != field}
    return value.get(field) == canonical_sha256(body)


def _valid_ref(value: Any, canonical: Any = None) -> bool:
    ref = value if isinstance(value, dict) else {}
    return (
        isinstance(ref.get("path"), str)
        and _sha256(ref.get("sha256"))
        and _sha256(ref.get("canonical_sha256"))
        and (canonical is None or ref.get("canonical_sha256") == canonical)
    )


def _sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )
