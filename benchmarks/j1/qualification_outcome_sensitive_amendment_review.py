"""Independent-review request contracts for outcome-sensitive amendments."""

from __future__ import annotations

import copy
import hashlib
import json
from typing import Any
from typing import Protocol

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from .controlled_comparison import canonical_sha256
from .qualification_outcome_sensitive_amendment import (
    BOUNDARY,
    PREFLIGHT_SCHEMA,
    validate_bundle,
)


REVIEW_REQUEST_SCHEMA = "j1-qualification-outcome-sensitive-amendment-review-request:v1"
REVIEW_HANDOFF_SCHEMA = "j1-qualification-outcome-sensitive-amendment-review-handoff:v1"
REVIEW_RECEIPT_SCHEMA = "j1-qualification-outcome-sensitive-amendment-review-receipt:v1"
FROZEN_REVIEW_SCHEMA = "j1-qualification-outcome-sensitive-amendment-frozen:v1"
PROMOTION_GATE_SCHEMA = (
    "j1-qualification-outcome-sensitive-amendment-promotion-gate:v1"
)
ALLOWED_DECISION = "approve_outcome_sensitive_amendment_materials"
CHECKLIST = {
    "all_six_copy_on_write_materials_read_and_hash_verified",
    "r11_evidence_and_signed_closeout_remain_immutable",
    "baseline_tasks_are_treatment_free_for_both_cohorts",
    "mentor_treatment_and_empty_control_advice_begin_at_ordinal_four",
    "private_fixture_ground_truth_and_deterministic_verifier_reviewed",
    "participant_decision_semantics_are_directly_observed_and_signed",
    "statistical_estimand_censoring_multiplicity_and_missingness_reviewed",
    "no_prospective_power_claim_invented_from_unobserved_r11_endpoints",
    "prior_consent_not_inherited_and_40_new_extensions_required",
    "participant_pair_substitution_and_outcome_exclusion_forbidden",
    "provider_model_identity_unchanged_but_fresh_admission_required",
    "execution_effectiveness_claim_and_si13_upgrade_remain_blocked",
}
RECEIPT_BOUNDARY = {
    **BOUNDARY,
    "independent_review_approved": True,
    "copy_on_write_promotion_allowed": True,
}
PROMOTION_BOUNDARY = {
    **BOUNDARY,
    "amendment_material_generation_only": False,
    "task_fixture_promoted": True,
    "statistical_plan_promoted": True,
    "protocol_amendment_material_promoted": True,
    "evaluator_amendment_material_promoted": True,
    "consent_impact_promoted": True,
    "copy_on_write_promotion_performed": True,
}


class ReviewSigner(Protocol):
    @property
    def public_key_hex(self) -> str: ...

    def sign(self, message: bytes) -> bytes: ...


def build_review_request(
    *,
    request_id: str,
    created_at: str,
    bundle_ref: dict[str, str],
    bundle: dict[str, Any],
    preflight_ref: dict[str, str],
    preflight: dict[str, Any],
    owner_statement_sha256: str,
    implementation: dict[str, str],
) -> dict[str, Any]:
    failures = validate_review_sources(
        bundle_ref=bundle_ref,
        bundle=bundle,
        preflight_ref=preflight_ref,
        preflight=preflight,
        owner_statement_sha256=owner_statement_sha256,
    )
    if failures:
        raise ValueError(f"amendment review sources invalid: {failures}")
    value = {
        "schema_version": REVIEW_REQUEST_SCHEMA,
        "request_id": request_id,
        "created_at": created_at,
        "status": "independent_reviewer_decision_required",
        "reviewed_bundle": copy.deepcopy(bundle_ref),
        "owner_approval_preflight": copy.deepcopy(preflight_ref),
        "reviewed_materials": copy.deepcopy(bundle["materials"]),
        "scope_summary": copy.deepcopy(bundle["inventory"]),
        "required_checklist": sorted(CHECKLIST),
        "allowed_decision": ALLOWED_DECISION,
        "decision_template": _empty_decision(),
        "implementation": copy.deepcopy(implementation),
        "execution_boundary": copy.deepcopy(BOUNDARY),
    }
    value["request_sha256"] = canonical_sha256(value)
    return value


def validate_review_sources(
    *,
    bundle_ref: dict[str, str],
    bundle: dict[str, Any],
    preflight_ref: dict[str, str],
    preflight: dict[str, Any],
    owner_statement_sha256: str,
) -> list[str]:
    failures = validate_bundle(bundle)
    _require(
        _valid_ref(bundle_ref, bundle.get("bundle_sha256")),
        "review_bundle_ref_invalid",
        failures,
    )
    _require(
        preflight.get("schema_version") == PREFLIGHT_SCHEMA
        and preflight.get("passed") is True
        and preflight.get("failure_reasons") == []
        and preflight.get("state")
        == "outcome_sensitive_amendment_materials_owner_review_only_approval_required"
        and _self_hash(preflight, "report_sha256"),
        "review_preflight_invalid",
        failures,
    )
    _require(
        _valid_ref(preflight_ref, preflight.get("report_sha256")),
        "review_preflight_ref_invalid",
        failures,
    )
    statement = preflight.get("required_owner_statement")
    _require(
        isinstance(statement, str)
        and hashlib.sha256(statement.encode()).hexdigest()
        == owner_statement_sha256
        == preflight.get("required_owner_statement_sha256"),
        "review_owner_statement_invalid",
        failures,
    )
    _require(
        preflight.get("bundle") == bundle_ref
        and preflight.get("execution_boundary") == BOUNDARY,
        "review_preflight_binding_or_boundary_invalid",
        failures,
    )
    return list(dict.fromkeys(failures))


def validate_review_request(
    value: Any,
    *,
    expected_bundle_ref: dict[str, str],
    expected_preflight_ref: dict[str, str],
    expected_materials: dict[str, dict[str, str]],
    expected_implementation: dict[str, str],
) -> list[str]:
    request = value if isinstance(value, dict) else {}
    failures: list[str] = []
    _require(
        request.get("schema_version") == REVIEW_REQUEST_SCHEMA
        and request.get("status") == "independent_reviewer_decision_required"
        and _self_hash(request, "request_sha256"),
        "amendment_review_request_identity_invalid",
        failures,
    )
    _require(
        request.get("reviewed_bundle") == expected_bundle_ref
        and request.get("owner_approval_preflight") == expected_preflight_ref
        and request.get("reviewed_materials") == expected_materials,
        "amendment_review_request_binding_invalid",
        failures,
    )
    _require(
        request.get("required_checklist") == sorted(CHECKLIST)
        and request.get("allowed_decision") == ALLOWED_DECISION
        and request.get("decision_template") == _empty_decision(),
        "amendment_review_decision_contract_invalid",
        failures,
    )
    _require(
        request.get("implementation") == expected_implementation
        and request.get("execution_boundary") == BOUNDARY,
        "amendment_review_implementation_or_boundary_invalid",
        failures,
    )
    return list(dict.fromkeys(failures))


def reviewer_approval_statement(
    *,
    request: dict[str, Any],
    request_raw_sha256: str,
) -> str:
    return (
        "I have independently reviewed J1-D outcome-sensitive amendment review "
        f"request raw SHA-256 {request_raw_sha256}, canonical SHA-256 "
        f"{request['request_sha256']} and choose {ALLOWED_DECISION}. I confirm all "
        f"{len(CHECKLIST)} required checklist items, disclose all conflicts, affirm "
        "that I am independent from candidate authoring and have completed human "
        "review. I approve only copy-on-write promotion of the six amendment "
        "materials bound by the request. I acknowledge that prior participant "
        "consent is not inherited and 40 of 40 new consent extensions remain "
        "required. This approval does not start or create a container, read a "
        "provider credential, call a provider or model, execute an Agent or task, "
        "append Backend Facts, append the Ledger, issue or consume an execution "
        "authorization, authorize an effectiveness claim, or upgrade SI-13 maturity."
    )


def build_review_handoff(
    *,
    request_ref: dict[str, str],
    request: dict[str, Any],
    request_raw_sha256: str,
) -> dict[str, Any]:
    statement = reviewer_approval_statement(
        request=request,
        request_raw_sha256=request_raw_sha256,
    )
    value = {
        "schema_version": REVIEW_HANDOFF_SCHEMA,
        "status": "independent_reviewer_action_required",
        "review_request": copy.deepcopy(request_ref),
        "allowed_decision": ALLOWED_DECISION,
        "required_checklist": sorted(CHECKLIST),
        "decision_template": copy.deepcopy(request["decision_template"]),
        "required_exact_approval_statement": statement,
        "required_exact_approval_statement_sha256": hashlib.sha256(
            statement.encode()
        ).hexdigest(),
        "execution_boundary": copy.deepcopy(BOUNDARY),
    }
    value["handoff_sha256"] = canonical_sha256(value)
    return value


def build_signed_review_receipt(
    *,
    review_id: str,
    reviewed_at: str,
    request_ref: dict[str, str],
    bundle_ref: dict[str, str],
    preflight_ref: dict[str, str],
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
        "checklist": {item: True for item in sorted(CHECKLIST)},
        "implementation": copy.deepcopy(implementation),
        "execution_boundary": copy.deepcopy(RECEIPT_BOUNDARY),
    }
    payload = _signature_payload(value)
    signature = signer.sign(payload)
    if len(signature) != 64:
        raise ValueError("amendment review signature must be 64 bytes")
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
        expected_materials=materials,
        expected_approval_statement_sha256=approval_statement_sha256,
        expected_reviewer=reviewer,
        expected_reviewer_profile_sha256=reviewer_profile_sha256,
        expected_implementation=implementation,
    )
    if failures:
        raise ValueError(f"signed amendment review receipt invalid: {failures}")
    return value


def validate_signed_review_receipt(
    value: Any,
    *,
    expected_request_ref: dict[str, str],
    expected_bundle_ref: dict[str, str],
    expected_preflight_ref: dict[str, str],
    expected_materials: dict[str, dict[str, str]],
    expected_approval_statement_sha256: str,
    expected_reviewer: dict[str, Any],
    expected_reviewer_profile_sha256: str,
    expected_implementation: dict[str, str],
) -> list[str]:
    receipt = value if isinstance(value, dict) else {}
    failures: list[str] = []
    _require(
        receipt.get("schema_version") == REVIEW_RECEIPT_SCHEMA
        and receipt.get("decision") == ALLOWED_DECISION
        and receipt.get("request") == expected_request_ref
        and receipt.get("reviewed_bundle") == expected_bundle_ref
        and receipt.get("owner_approval_preflight") == expected_preflight_ref
        and receipt.get("reviewed_materials") == expected_materials
        and receipt.get("approval_statement_sha256")
        == expected_approval_statement_sha256,
        "amendment_review_receipt_binding_invalid",
        failures,
    )
    _require(
        receipt.get("reviewer")
        == {
            "did": expected_reviewer.get("did"),
            "public_key_hex": expected_reviewer.get("public_key_hex"),
            "credential_version": expected_reviewer.get("credential_version"),
            "signer_kind": expected_reviewer.get("signer_kind"),
            "identity_profile_sha256": expected_reviewer_profile_sha256,
        },
        "amendment_review_receipt_reviewer_invalid",
        failures,
    )
    _require(
        receipt.get("independence")
        == {
            "conflicts_disclosed": True,
            "independent_from_candidate_authoring": True,
            "human_review_completed": True,
        }
        and receipt.get("checklist") == {item: True for item in sorted(CHECKLIST)},
        "amendment_review_receipt_independence_invalid",
        failures,
    )
    _require(
        receipt.get("implementation") == expected_implementation
        and receipt.get("execution_boundary") == RECEIPT_BOUNDARY,
        "amendment_review_receipt_boundary_invalid",
        failures,
    )
    signature = receipt.get("signature")
    signature = signature if isinstance(signature, dict) else {}
    unsigned = {
        key: item
        for key, item in receipt.items()
        if key not in {"signature", "receipt_sha256"}
    }
    payload = _signature_payload(unsigned)
    _require(
        signature.get("algorithm") == "ed25519"
        and signature.get("public_key_hex") == expected_reviewer.get("public_key_hex")
        and signature.get("signed_payload_sha256")
        == hashlib.sha256(payload).hexdigest(),
        "amendment_review_receipt_signature_metadata_invalid",
        failures,
    )
    try:
        VerifyKey(
            bytes.fromhex(str(expected_reviewer.get("public_key_hex", "")))
        ).verify(payload, bytes.fromhex(str(signature.get("signature_hex", ""))))
    except (BadSignatureError, ValueError):
        failures.append("amendment_review_receipt_signature_invalid")
    _require(
        _self_hash(receipt, "receipt_sha256"),
        "amendment_review_receipt_hash_invalid",
        failures,
    )
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
            "protocol_amendment_material_frozen": True,
            "evaluator_amendment_material_frozen": True,
            "task_fixture_frozen": True,
            "statistical_plan_frozen": True,
            "consent_impact_frozen": True,
            "participant_consent_extensions_complete": False,
            "participant_consent_extension_count": 0,
            "participant_consent_extension_required_count": 40,
            "downstream_bindings_refreshed": False,
            "execution_preflight_allowed": False,
            "provider_or_model_execution_allowed": False,
            "si13_maturity_upgrade_allowed": False,
        },
        "implementation": copy.deepcopy(implementation),
        "execution_boundary": copy.deepcopy(PROMOTION_BOUNDARY),
    }
    value["frozen_review_sha256"] = canonical_sha256(value)
    return value


def build_promotion_gate(
    *,
    request_ref: dict[str, str],
    handoff_ref: dict[str, str],
    receipt_ref: dict[str, str],
    frozen_review_ref: dict[str, str],
    frozen_review: dict[str, Any],
) -> dict[str, Any]:
    value = {
        "schema_version": PROMOTION_GATE_SCHEMA,
        "passed": True,
        "failure_reasons": [],
        "state": (
            "outcome_sensitive_amendment_materials_reviewed_frozen_"
            "40_of_40_consent_required_execution_blocked"
        ),
        "review_request": copy.deepcopy(request_ref),
        "review_handoff": copy.deepcopy(handoff_ref),
        "review_receipt": copy.deepcopy(receipt_ref),
        "frozen_review": copy.deepcopy(frozen_review_ref),
        "signature_valid": True,
        "pin_recorded": False,
        "private_key_exported": False,
        "readiness": copy.deepcopy(frozen_review["readiness"]),
        "execution_boundary": copy.deepcopy(PROMOTION_BOUNDARY),
    }
    value["report_sha256"] = canonical_sha256(value)
    return value


def _empty_decision() -> dict[str, Any]:
    return {
        "decision": None,
        "reviewer_did": None,
        "reviewed_at": None,
        "independent_from_candidate_authoring": None,
        "conflicts_disclosed": None,
        "human_review_completed": None,
        "checklist": {name: None for name in sorted(CHECKLIST)},
    }


def _signature_payload(value: dict[str, Any]) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def _self_hash(value: Any, field: str) -> bool:
    if not isinstance(value, dict):
        return False
    body = {key: item for key, item in value.items() if key != field}
    return value.get(field) == canonical_sha256(body)


def _valid_ref(value: Any, canonical: Any) -> bool:
    ref = value if isinstance(value, dict) else {}
    return (
        isinstance(ref.get("path"), str)
        and _sha256(ref.get("sha256"))
        and _sha256(ref.get("canonical_sha256"))
        and ref.get("canonical_sha256") == canonical
    )


def _sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _require(condition: bool, failure: str, failures: list[str]) -> None:
    if not condition:
        failures.append(failure)
