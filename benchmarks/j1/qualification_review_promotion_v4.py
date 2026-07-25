"""Signed review receipt and copy-on-write promotion contracts for J1-D r4."""

from __future__ import annotations

import copy
import hashlib
import json
from typing import Any, Protocol

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from .controlled_comparison import canonical_sha256
from .qualification_review_v4 import CHECKLIST


RECEIPT_SCHEMA = "j1-qualification-r4-signed-review-receipt:v1"
FROZEN_SCHEMA = "j1-qualification-r4-frozen-execution-stack:v1"
RECEIPT_BOUNDARY = {
    "independent_review_approved": True,
    "copy_on_write_promotion_allowed": True,
    "participant_container_started": False,
    "provider_credential_read": False,
    "provider_api_call_performed": False,
    "model_invocation_performed": False,
    "agent_execution_performed": False,
    "backend_fact_append_performed": False,
    "ledger_append_performed": False,
    "execution_authorization_issued_or_consumed": False,
    "effectiveness_claim_authorized": False,
}
FROZEN_BOUNDARY = {
    "review_promotion_only": True,
    "r4_execution_stack_frozen": True,
    "provider_refresh_allowed": True,
    "participant_container_started": False,
    "provider_credential_read": False,
    "provider_api_call_performed": False,
    "model_invocation_performed": False,
    "agent_execution_performed": False,
    "backend_fact_append_performed": False,
    "ledger_append_performed": False,
    "execution_authorization_issued_or_consumed": False,
    "effectiveness_claim_authorized": False,
}


class ReviewSigner(Protocol):
    @property
    def public_key_hex(self) -> str: ...

    def sign(self, message: bytes) -> bytes: ...


def build_signed_review_receipt(
    *,
    review_id: str,
    reviewed_at: str,
    request_ref: dict[str, str],
    bundle_ref: dict[str, str],
    contract_sha256: str,
    approval_statement_sha256: str,
    reviewer: dict[str, Any],
    reviewer_profile_sha256: str,
    implementation: dict[str, str],
    signer: ReviewSigner,
) -> dict[str, Any]:
    value = {
        "schema_version": RECEIPT_SCHEMA,
        "review_id": review_id,
        "decision": "approve_r4_execution_stack",
        "reviewed_at": reviewed_at,
        "request": copy.deepcopy(request_ref),
        "bundle": copy.deepcopy(bundle_ref),
        "execution_contract_sha256": contract_sha256,
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
        "checklist": {name: True for name in CHECKLIST},
        "implementation": copy.deepcopy(implementation),
        "execution_boundary": copy.deepcopy(RECEIPT_BOUNDARY),
    }
    payload = _signature_payload(value)
    signature = signer.sign(payload)
    if len(signature) != 64:
        raise ValueError("r4 review signature must be 64 bytes")
    value["signature"] = {
        "algorithm": "ed25519",
        "signed_payload_sha256": hashlib.sha256(payload).hexdigest(),
        "signature_hex": signature.hex(),
    }
    value["receipt_sha256"] = canonical_sha256(value)
    failures = validate_signed_review_receipt(
        value,
        expected_request_ref=request_ref,
        expected_bundle_ref=bundle_ref,
        expected_contract_sha256=contract_sha256,
        expected_approval_statement_sha256=approval_statement_sha256,
        expected_reviewer=reviewer,
        expected_reviewer_profile_sha256=reviewer_profile_sha256,
        expected_implementation=implementation,
    )
    if failures:
        raise ValueError(f"r4 review receipt invalid: {failures}")
    return value


def validate_signed_review_receipt(
    value: Any,
    *,
    expected_request_ref: dict[str, str],
    expected_bundle_ref: dict[str, str],
    expected_contract_sha256: str,
    expected_approval_statement_sha256: str,
    expected_reviewer: dict[str, Any],
    expected_reviewer_profile_sha256: str,
    expected_implementation: dict[str, str],
) -> list[str]:
    receipt = value if isinstance(value, dict) else {}
    failures: list[str] = []
    if not (
        receipt.get("schema_version") == RECEIPT_SCHEMA
        and receipt.get("decision") == "approve_r4_execution_stack"
        and receipt.get("request") == expected_request_ref
        and receipt.get("bundle") == expected_bundle_ref
        and receipt.get("execution_contract_sha256") == expected_contract_sha256
        and receipt.get("approval_statement_sha256")
        == expected_approval_statement_sha256
    ):
        failures.append("r4_review_receipt_binding_invalid")
    reviewer = receipt.get("reviewer")
    expected_bound_reviewer = {
        "did": expected_reviewer.get("did"),
        "public_key_hex": expected_reviewer.get("public_key_hex"),
        "credential_version": expected_reviewer.get("credential_version"),
        "signer_kind": expected_reviewer.get("signer_kind"),
        "identity_profile_sha256": expected_reviewer_profile_sha256,
    }
    if reviewer != expected_bound_reviewer:
        failures.append("r4_review_receipt_reviewer_invalid")
    if receipt.get("independence") != {
        "conflicts_disclosed": True,
        "independent_from_candidate_authoring": True,
        "human_review_completed": True,
    } or receipt.get("checklist") != {name: True for name in CHECKLIST}:
        failures.append("r4_review_receipt_independence_or_checklist_invalid")
    if (
        receipt.get("implementation") != expected_implementation
        or receipt.get("execution_boundary") != RECEIPT_BOUNDARY
    ):
        failures.append("r4_review_receipt_boundary_invalid")
    signature = receipt.get("signature")
    signature = signature if isinstance(signature, dict) else {}
    unsigned = {
        key: item
        for key, item in receipt.items()
        if key not in {"signature", "receipt_sha256"}
    }
    payload = _signature_payload(unsigned)
    try:
        signature_bytes = bytes.fromhex(str(signature.get("signature_hex", "")))
        VerifyKey(bytes.fromhex(expected_reviewer["public_key_hex"])).verify(
            payload, signature_bytes
        )
    except (BadSignatureError, ValueError):
        failures.append("r4_review_receipt_signature_invalid")
    if not (
        signature.get("algorithm") == "ed25519"
        and signature.get("signed_payload_sha256")
        == hashlib.sha256(payload).hexdigest()
    ):
        failures.append("r4_review_receipt_signature_binding_invalid")
    body = {key: item for key, item in receipt.items() if key != "receipt_sha256"}
    if receipt.get("receipt_sha256") != canonical_sha256(body):
        failures.append("r4_review_receipt_hash_invalid")
    return list(dict.fromkeys(failures))


def build_frozen_stack(
    *,
    frozen_id: str,
    promoted_at: str,
    candidate_bundle_sha256: str,
    review_receipt_ref: dict[str, str],
    frozen_artifacts: dict[str, dict[str, str]],
    implementation: dict[str, str],
) -> dict[str, Any]:
    value = {
        "schema_version": FROZEN_SCHEMA,
        "frozen_id": frozen_id,
        "status": "operator_reviewed_frozen",
        "promoted_at": promoted_at,
        "candidate_bundle_sha256": candidate_bundle_sha256,
        "review_receipt": copy.deepcopy(review_receipt_ref),
        "frozen_artifacts": copy.deepcopy(frozen_artifacts),
        "implementation": copy.deepcopy(implementation),
        "readiness": {
            "r4_execution_contract_frozen": True,
            "offline_orchestrator_evidence_frozen": True,
            "fault_matrix_evidence_frozen": True,
            "provider_refresh_required": True,
            "execution_preflight_allowed": False,
            "execution_authorization_issued": False,
            "controlled_experiment_execution_ready": False,
        },
        "execution_boundary": copy.deepcopy(FROZEN_BOUNDARY),
    }
    value["frozen_stack_sha256"] = canonical_sha256(value)
    return value


def _signature_payload(value: dict[str, Any]) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
