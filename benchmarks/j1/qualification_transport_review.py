"""Independent review and promotion contracts for J1-D transport reliability."""

from __future__ import annotations

import copy
import hashlib
import json
from typing import Any, Protocol

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from .controlled_comparison import canonical_sha256
from .qualification_transport_reliability import (
    SOAK_CALL_COUNT,
    SOAK_PREFLIGHT_SCHEMA,
    validate_fault_matrix_report,
    validate_soak_plan,
    validate_transport_contract,
)


REQUEST_SCHEMA = "j1-qualification-transport-reliability-review-request:v1"
HANDOFF_SCHEMA = "j1-qualification-transport-reliability-review-handoff:v1"
RECEIPT_SCHEMA = "j1-qualification-transport-reliability-review-receipt:v1"
FROZEN_SCHEMA = "j1-qualification-transport-reliability-frozen:v1"
GATE_SCHEMA = "j1-qualification-transport-reliability-promotion-gate:v1"
ALLOWED_DECISION = "approve_transport_reliability_materials"
CHECKLIST = {
    "r2_and_r3_terminal_failure_evidence_reviewed_without_causal_overclaim",
    "dns_tcp_tls_pre_dispatch_boundary_reviewed",
    "pre_dispatch_connection_setup_retries_are_bounded",
    "every_http_request_is_single_use",
    "all_post_dispatch_failures_are_ambiguous_and_never_retried",
    "deterministic_eight_scenario_fault_matrix_passed",
    "sixty_four_soak_requests_are_content_free",
    "soak_budget_duration_sequential_stop_rules_reviewed",
    "credential_response_and_exception_content_non_persistence_reviewed",
    "live_soak_requires_separate_exact_single_use_authorization",
}
BOUNDARY = {
    "independent_review_material_generation_only": True,
    "provider_credential_read": False,
    "provider_or_model_call_performed": False,
    "participant_container_started_or_modified": False,
    "agent_or_experiment_execution_performed": False,
    "backend_fact_append_performed": False,
    "ledger_append_performed": False,
    "live_soak_authorization_issued_or_consumed": False,
    "effectiveness_claim_authorized": False,
    "si13_maturity_upgrade_authorized": False,
}
RECEIPT_BOUNDARY = {
    **BOUNDARY,
    "independent_review_material_generation_only": False,
    "independent_review_completed": True,
    "copy_on_write_promotion_allowed": True,
}
PROMOTION_BOUNDARY = {
    **RECEIPT_BOUNDARY,
    "copy_on_write_promotion_allowed": False,
    "copy_on_write_promotion_performed": True,
    "live_soak_authorization_preflight_allowed": True,
}


class ReviewSigner(Protocol):
    @property
    def public_key_hex(self) -> str: ...

    def sign(self, message: bytes) -> bytes: ...


def build_review_request(
    *,
    request_id: str,
    created_at: str,
    materials: dict[str, dict[str, str]],
    values: dict[str, dict[str, Any]],
    owner_statement_sha256: str,
    review_implementation: dict[str, str],
) -> dict[str, Any]:
    failures = validate_review_sources(
        materials=materials,
        values=values,
        owner_statement_sha256=owner_statement_sha256,
    )
    if failures:
        raise ValueError(f"transport review sources invalid: {failures}")
    candidate_implementation = copy.deepcopy(
        values["transport_contract"]["implementation"]
    )
    value = {
        "schema_version": REQUEST_SCHEMA,
        "request_id": request_id,
        "created_at": created_at,
        "status": "independent_reviewer_decision_required",
        "reviewed_materials": copy.deepcopy(materials),
        "owner_approval": {
            "statement_sha256": owner_statement_sha256,
            "independent_review_only": True,
        },
        "candidate_implementation": candidate_implementation,
        "review_implementation": copy.deepcopy(review_implementation),
        "scope": {
            "fault_scenario_count": 8,
            "live_soak_call_count": SOAK_CALL_COUNT,
            "participant_data_present": False,
            "provider_credential_access_authorized": False,
            "provider_or_model_call_authorized": False,
        },
        "required_checklist": sorted(CHECKLIST),
        "allowed_decision": ALLOWED_DECISION,
        "decision_template": {
            "decision": None,
            "conflicts": [],
            "independent_from_candidate_authoring": None,
            "human_review_completed": None,
            "checklist": {item: None for item in sorted(CHECKLIST)},
        },
        "execution_boundary": copy.deepcopy(BOUNDARY),
    }
    value["request_sha256"] = canonical_sha256(value)
    return value


def validate_review_sources(
    *,
    materials: dict[str, dict[str, str]],
    values: dict[str, dict[str, Any]],
    owner_statement_sha256: str,
) -> list[str]:
    failures: list[str] = []
    required = {
        "transport_contract",
        "fault_matrix",
        "soak_plan",
        "soak_preflight",
        "owner_handoff",
    }
    _require(
        set(materials) == required
        and set(values) == required
        and all(_reference(item) for item in materials.values()),
        "transport_review_material_refs_invalid",
        failures,
    )
    if set(values) != required:
        return list(dict.fromkeys(failures))
    contract = values["transport_contract"]
    fault = values["fault_matrix"]
    plan = values["soak_plan"]
    preflight = values["soak_preflight"]
    handoff = values["owner_handoff"]
    failures.extend(validate_transport_contract(contract))
    failures.extend(validate_fault_matrix_report(fault))
    failures.extend(validate_soak_plan(plan))
    _require(
        materials["transport_contract"]["canonical_sha256"]
        == contract.get("contract_sha256")
        and materials["fault_matrix"]["canonical_sha256"]
        == fault.get("report_sha256")
        and materials["soak_plan"]["canonical_sha256"] == plan.get("plan_sha256")
        and materials["soak_preflight"]["canonical_sha256"]
        == preflight.get("preflight_sha256")
        and materials["owner_handoff"]["canonical_sha256"]
        == handoff.get("handoff_sha256"),
        "transport_review_material_canonical_binding_invalid",
        failures,
    )
    _require(
        fault.get("contract") == materials["transport_contract"]
        and plan.get("source_binding", {}).get("transport_contract")
        == materials["transport_contract"]
        and plan.get("source_binding", {}).get("fault_matrix")
        == materials["fault_matrix"]
        and preflight.get("plan") == materials["soak_plan"],
        "transport_review_cross_binding_invalid",
        failures,
    )
    preflight_body = {
        key: item for key, item in preflight.items() if key != "preflight_sha256"
    }
    _require(
        preflight.get("schema_version") == SOAK_PREFLIGHT_SCHEMA
        and preflight.get("passed") is True
        and preflight.get("validation_failures") == []
        and preflight.get("state")
        == "transport_soak_materials_ready_independent_review_required"
        and preflight.get("readiness", {}).get("independent_review_allowed") is True
        and preflight.get("readiness", {}).get(
            "live_soak_authorization_issuance_allowed"
        )
        is False
        and preflight.get("preflight_sha256") == canonical_sha256(preflight_body),
        "transport_review_soak_preflight_invalid",
        failures,
    )
    handoff_body = {
        key: item for key, item in handoff.items() if key != "handoff_sha256"
    }
    statement = handoff.get("required_exact_approval_statement")
    _require(
        handoff.get("schema_version") == "j1-qualification-transport-review-handoff:v1"
        and handoff.get("status") == "owner_approval_for_independent_review_required"
        and handoff.get("transport_contract") == materials["transport_contract"]
        and handoff.get("fault_matrix") == materials["fault_matrix"]
        and handoff.get("soak_plan") == materials["soak_plan"]
        and handoff.get("soak_preflight") == materials["soak_preflight"]
        and isinstance(statement, str)
        and hashlib.sha256(statement.encode()).hexdigest()
        == handoff.get("statement_sha256")
        == owner_statement_sha256
        and handoff.get("handoff_sha256") == canonical_sha256(handoff_body),
        "transport_review_owner_handoff_invalid",
        failures,
    )
    implementations = {
        canonical_sha256(item.get("implementation"))
        for item in (contract, fault, plan)
        if isinstance(item, dict)
    }
    _require(
        len(implementations) == 1,
        "transport_review_candidate_implementation_drift",
        failures,
    )
    return list(dict.fromkeys(failures))


def validate_review_request(
    value: Any,
    *,
    expected_materials: dict[str, dict[str, str]],
    expected_owner_statement_sha256: str,
    expected_candidate_implementation: dict[str, str],
    expected_review_implementation: dict[str, str],
) -> list[str]:
    request = value if isinstance(value, dict) else {}
    failures: list[str] = []
    body = {key: item for key, item in request.items() if key != "request_sha256"}
    _require(
        request.get("schema_version") == REQUEST_SCHEMA
        and request.get("status") == "independent_reviewer_decision_required"
        and request.get("request_sha256") == canonical_sha256(body),
        "transport_review_request_identity_invalid",
        failures,
    )
    _require(
        request.get("reviewed_materials") == expected_materials
        and request.get("owner_approval")
        == {
            "statement_sha256": expected_owner_statement_sha256,
            "independent_review_only": True,
        }
        and request.get("candidate_implementation")
        == expected_candidate_implementation
        and request.get("review_implementation") == expected_review_implementation,
        "transport_review_request_binding_invalid",
        failures,
    )
    template = request.get("decision_template")
    _require(
        request.get("required_checklist") == sorted(CHECKLIST)
        and request.get("allowed_decision") == ALLOWED_DECISION
        and isinstance(template, dict)
        and template.get("decision") is None
        and template.get("conflicts") == []
        and template.get("independent_from_candidate_authoring") is None
        and template.get("human_review_completed") is None
        and template.get("checklist")
        == {item: None for item in sorted(CHECKLIST)},
        "transport_review_request_decision_contract_invalid",
        failures,
    )
    _require(
        request.get("scope")
        == {
            "fault_scenario_count": 8,
            "live_soak_call_count": SOAK_CALL_COUNT,
            "participant_data_present": False,
            "provider_credential_access_authorized": False,
            "provider_or_model_call_authorized": False,
        }
        and request.get("execution_boundary") == BOUNDARY,
        "transport_review_request_boundary_invalid",
        failures,
    )
    return list(dict.fromkeys(failures))


def reviewer_approval_statement(
    *, request: dict[str, Any], request_raw_sha256: str
) -> str:
    materials = request["reviewed_materials"]
    return (
        "I have independently reviewed J1-D transport reliability review request "
        f"raw SHA-256 {request_raw_sha256}, canonical SHA-256 "
        f"{request['request_sha256']} and choose {ALLOWED_DECISION}. I confirm all "
        f"{len(CHECKLIST)} required checklist items, disclose all conflicts, affirm "
        "that I am independent from candidate authoring and have completed human "
        "review. I approve only copy-on-write promotion of transport contract raw "
        f"SHA-256 {materials['transport_contract']['sha256']}, deterministic fault "
        f"matrix raw SHA-256 {materials['fault_matrix']['sha256']}, and bounded "
        f"64-call admission-soak plan raw SHA-256 {materials['soak_plan']['sha256']}. "
        "I acknowledge that connection setup retries are allowed only before request "
        "dispatch, every HTTP request is single-use, and every post-dispatch failure "
        "is ambiguous and must never be retried. This approval permits only material "
        "promotion and generation of a separate live-soak authorization preflight. "
        "It does not read a provider credential, call a provider or model, start or "
        "modify a participant container, execute an Agent or experiment, append "
        "Backend Facts or the Ledger, issue or consume a live-soak authorization, "
        "authorize an effectiveness claim, or upgrade SI-13 maturity."
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
        "schema_version": HANDOFF_SCHEMA,
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
    materials: dict[str, dict[str, str]],
    owner_statement_sha256: str,
    approval_statement_sha256: str,
    reviewer: dict[str, Any],
    reviewer_profile_sha256: str,
    implementation: dict[str, str],
    signer: ReviewSigner,
) -> dict[str, Any]:
    if signer.public_key_hex != reviewer.get("public_key_hex"):
        raise ValueError("transport reviewer signer mismatch")
    value = {
        "schema_version": RECEIPT_SCHEMA,
        "review_id": review_id,
        "reviewed_at": reviewed_at,
        "decision": ALLOWED_DECISION,
        "request": copy.deepcopy(request_ref),
        "reviewed_materials": copy.deepcopy(materials),
        "owner_statement_sha256": owner_statement_sha256,
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
        raise ValueError("transport review signature must be 64 bytes")
    value["signature"] = {
        "algorithm": "ed25519",
        "public_key_hex": signer.public_key_hex,
        "signed_payload_sha256": hashlib.sha256(payload).hexdigest(),
        "signature_hex": signature.hex(),
    }
    value["receipt_sha256"] = canonical_sha256(value)
    return value


def validate_signed_review_receipt(
    value: Any,
    *,
    expected_request_ref: dict[str, str],
    expected_materials: dict[str, dict[str, str]],
    expected_owner_statement_sha256: str,
    expected_approval_statement_sha256: str,
    expected_reviewer: dict[str, Any],
    expected_reviewer_profile_sha256: str,
    expected_implementation: dict[str, str],
) -> list[str]:
    receipt = value if isinstance(value, dict) else {}
    failures: list[str] = []
    _require(
        receipt.get("schema_version") == RECEIPT_SCHEMA
        and receipt.get("decision") == ALLOWED_DECISION
        and receipt.get("request") == expected_request_ref
        and receipt.get("reviewed_materials") == expected_materials
        and receipt.get("owner_statement_sha256")
        == expected_owner_statement_sha256
        and receipt.get("approval_statement_sha256")
        == expected_approval_statement_sha256,
        "transport_review_receipt_binding_invalid",
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
        }
        and receipt.get("independence")
        == {
            "conflicts_disclosed": True,
            "independent_from_candidate_authoring": True,
            "human_review_completed": True,
        }
        and receipt.get("checklist") == {item: True for item in sorted(CHECKLIST)},
        "transport_review_receipt_reviewer_invalid",
        failures,
    )
    _require(
        receipt.get("implementation") == expected_implementation
        and receipt.get("execution_boundary") == RECEIPT_BOUNDARY,
        "transport_review_receipt_boundary_invalid",
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
        and signature.get("public_key_hex")
        == expected_reviewer.get("public_key_hex")
        and signature.get("signed_payload_sha256")
        == hashlib.sha256(payload).hexdigest(),
        "transport_review_receipt_signature_metadata_invalid",
        failures,
    )
    try:
        VerifyKey(
            bytes.fromhex(str(expected_reviewer.get("public_key_hex", "")))
        ).verify(payload, bytes.fromhex(str(signature.get("signature_hex", ""))))
    except (BadSignatureError, ValueError):
        failures.append("transport_review_receipt_signature_invalid")
    body = {key: item for key, item in receipt.items() if key != "receipt_sha256"}
    _require(
        receipt.get("receipt_sha256") == canonical_sha256(body),
        "transport_review_receipt_hash_invalid",
        failures,
    )
    return list(dict.fromkeys(failures))


def build_frozen_review(
    *,
    frozen_id: str,
    promoted_at: str,
    source_materials: dict[str, dict[str, str]],
    frozen_materials: dict[str, dict[str, str]],
    review_receipt_ref: dict[str, str],
    reviewer_did: str,
    implementation: dict[str, str],
) -> dict[str, Any]:
    value = {
        "schema_version": FROZEN_SCHEMA,
        "frozen_id": frozen_id,
        "promoted_at": promoted_at,
        "status": "operator_reviewed_frozen",
        "source_materials": copy.deepcopy(source_materials),
        "frozen_source_copies": copy.deepcopy(frozen_materials),
        "operator_review": {
            "reviewer_did": reviewer_did,
            "review_receipt": copy.deepcopy(review_receipt_ref),
            "decision": ALLOWED_DECISION,
        },
        "readiness": {
            "transport_materials_frozen": True,
            "live_soak_authorization_preflight_allowed": True,
            "live_soak_authorization_issued": False,
            "provider_credential_access_allowed": False,
            "provider_or_model_call_allowed": False,
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
) -> dict[str, Any]:
    value = {
        "schema_version": GATE_SCHEMA,
        "passed": True,
        "failure_reasons": [],
        "state": (
            "transport_reliability_materials_frozen_"
            "live_soak_authorization_preflight_allowed"
        ),
        "review_request": copy.deepcopy(request_ref),
        "review_handoff": copy.deepcopy(handoff_ref),
        "review_receipt": copy.deepcopy(receipt_ref),
        "frozen_review": copy.deepcopy(frozen_review_ref),
        "signature_valid": True,
        "pin_recorded": False,
        "private_key_exported": False,
        "readiness": {
            "live_soak_authorization_preflight_allowed": True,
            "live_soak_authorization_issued": False,
            "provider_credential_access_allowed": False,
            "provider_or_model_call_allowed": False,
        },
        "execution_boundary": copy.deepcopy(PROMOTION_BOUNDARY),
    }
    value["report_sha256"] = canonical_sha256(value)
    return value


def _signature_payload(value: dict[str, Any]) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode()


def _reference(value: Any) -> bool:
    return (
        isinstance(value, dict)
        and set(value) == {"path", "sha256", "canonical_sha256"}
        and isinstance(value.get("path"), str)
        and str(value["path"]).startswith("/")
        and _sha256(value.get("sha256"))
        and _sha256(value.get("canonical_sha256"))
    )


def _sha256(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        bytes.fromhex(value)
        return True
    except ValueError:
        return False


def _require(condition: bool, failure: str, failures: list[str]) -> None:
    if not condition:
        failures.append(failure)
