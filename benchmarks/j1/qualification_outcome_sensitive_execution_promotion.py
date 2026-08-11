"""Signed review receipt and frozen outcome-sensitive execution stack."""

from __future__ import annotations

import copy
import hashlib
import json
from typing import Any, Protocol

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from .controlled_comparison import canonical_sha256
from .qualification_outcome_sensitive_execution_review import REVIEW_CHECKLIST


RECEIPT_SCHEMA = "j1-qualification-outcome-sensitive-signed-execution-review-receipt:v1"
FROZEN_SCHEMA = "j1-qualification-outcome-sensitive-frozen-execution-stack:v1"
RECEIPT_BOUNDARY = {
    "independent_review_approved": True,
    "copy_on_write_promotion_allowed": True,
    "participant_container_started": False,
    "provider_credential_read": False,
    "provider_api_call_performed": False,
    "model_invocation_performed": False,
    "agent_or_task_execution_performed": False,
    "participant_signature_performed": False,
    "backend_fact_append_performed": False,
    "ledger_append_performed": False,
    "execution_authorization_issued_or_consumed": False,
    "effectiveness_claim_authorized": False,
    "si13_maturity_upgrade_authorized": False,
}
FROZEN_BOUNDARY = {
    "review_promotion_only": True,
    "outcome_sensitive_execution_stack_frozen": True,
    "live_provider_admission_bound": True,
    "participant_container_started": False,
    "provider_credential_read": False,
    "provider_api_call_performed": False,
    "model_invocation_performed": False,
    "agent_or_task_execution_performed": False,
    "participant_signature_performed": False,
    "backend_fact_append_performed": False,
    "ledger_append_performed": False,
    "execution_authorization_issued_or_consumed": False,
    "effectiveness_claim_authorized": False,
    "si13_maturity_upgrade_authorized": False,
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
    receipt_schema: str = RECEIPT_SCHEMA,
    decision: str = "approve_outcome_sensitive_execution_stack",
    review_checklist: list[str] | None = None,
    receipt_boundary: dict[str, bool] | None = None,
) -> dict[str, Any]:
    checklist = REVIEW_CHECKLIST if review_checklist is None else review_checklist
    boundary = RECEIPT_BOUNDARY if receipt_boundary is None else receipt_boundary
    value = {
        "schema_version": receipt_schema,
        "review_id": review_id,
        "decision": decision,
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
        "checklist": {name: True for name in checklist},
        "implementation": copy.deepcopy(implementation),
        "execution_boundary": copy.deepcopy(boundary),
    }
    payload = _signature_payload(value)
    signature = signer.sign(payload)
    if len(signature) != 64:
        raise ValueError("outcome-sensitive review signature must be 64 bytes")
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
        receipt_schema=receipt_schema,
        expected_decision=decision,
        review_checklist=checklist,
        expected_receipt_boundary=boundary,
    )
    if failures:
        raise ValueError(f"outcome-sensitive signed review receipt invalid: {failures}")
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
    receipt_schema: str = RECEIPT_SCHEMA,
    expected_decision: str = "approve_outcome_sensitive_execution_stack",
    review_checklist: list[str] | None = None,
    expected_receipt_boundary: dict[str, bool] | None = None,
) -> list[str]:
    receipt = value if isinstance(value, dict) else {}
    checklist = REVIEW_CHECKLIST if review_checklist is None else review_checklist
    boundary = (
        RECEIPT_BOUNDARY
        if expected_receipt_boundary is None
        else expected_receipt_boundary
    )
    failures: list[str] = []
    if not (
        receipt.get("schema_version") == receipt_schema
        and receipt.get("decision") == expected_decision
        and receipt.get("request") == expected_request_ref
        and receipt.get("bundle") == expected_bundle_ref
        and receipt.get("execution_contract_sha256") == expected_contract_sha256
        and receipt.get("approval_statement_sha256")
        == expected_approval_statement_sha256
    ):
        failures.append("outcome_execution_review_receipt_binding_invalid")
    expected_bound_reviewer = {
        "did": expected_reviewer.get("did"),
        "public_key_hex": expected_reviewer.get("public_key_hex"),
        "credential_version": expected_reviewer.get("credential_version"),
        "signer_kind": expected_reviewer.get("signer_kind"),
        "identity_profile_sha256": expected_reviewer_profile_sha256,
    }
    if receipt.get("reviewer") != expected_bound_reviewer:
        failures.append("outcome_execution_review_receipt_reviewer_invalid")
    if receipt.get("independence") != {
        "conflicts_disclosed": True,
        "independent_from_candidate_authoring": True,
        "human_review_completed": True,
    } or receipt.get("checklist") != {name: True for name in checklist}:
        failures.append(
            "outcome_execution_review_receipt_independence_or_checklist_invalid"
        )
    if (
        receipt.get("implementation") != expected_implementation
        or receipt.get("execution_boundary") != boundary
    ):
        failures.append("outcome_execution_review_receipt_boundary_invalid")
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
        failures.append("outcome_execution_review_receipt_signature_invalid")
    if not (
        signature.get("algorithm") == "ed25519"
        and signature.get("signed_payload_sha256")
        == hashlib.sha256(payload).hexdigest()
    ):
        failures.append("outcome_execution_review_receipt_signature_binding_invalid")
    body = {key: item for key, item in receipt.items() if key != "receipt_sha256"}
    if receipt.get("receipt_sha256") != canonical_sha256(body):
        failures.append("outcome_execution_review_receipt_hash_invalid")
    return list(dict.fromkeys(failures))


def build_frozen_stack(
    *,
    frozen_id: str,
    promoted_at: str,
    candidate_bundle_sha256: str,
    review_receipt_ref: dict[str, str],
    frozen_artifacts: dict[str, dict[str, str]],
    provider_admission: dict[str, Any],
    runtime_inventory: dict[str, int],
    implementation: dict[str, str],
    frozen_schema: str = FROZEN_SCHEMA,
    readiness: dict[str, bool] | None = None,
    next_blocker: str = "new_single_use_execution_preflight_required",
    frozen_boundary: dict[str, bool] | None = None,
) -> dict[str, Any]:
    expected_readiness = (
        _default_readiness() if readiness is None else copy.deepcopy(readiness)
    )
    boundary = FROZEN_BOUNDARY if frozen_boundary is None else frozen_boundary
    value = {
        "schema_version": frozen_schema,
        "frozen_id": frozen_id,
        "status": "operator_reviewed_frozen",
        "promoted_at": promoted_at,
        "candidate_bundle_sha256": candidate_bundle_sha256,
        "review_receipt": copy.deepcopy(review_receipt_ref),
        "frozen_artifacts": copy.deepcopy(frozen_artifacts),
        "provider_admission": copy.deepcopy(provider_admission),
        "runtime_inventory": copy.deepcopy(runtime_inventory),
        "implementation": copy.deepcopy(implementation),
        "readiness": expected_readiness,
        "next_blocker": next_blocker,
        "execution_boundary": copy.deepcopy(boundary),
    }
    value["frozen_stack_sha256"] = canonical_sha256(value)
    failures = validate_frozen_stack(
        value,
        frozen_schema=frozen_schema,
        expected_readiness=expected_readiness,
        expected_next_blocker=next_blocker,
        expected_frozen_boundary=boundary,
    )
    if failures:
        raise ValueError(
            f"outcome-sensitive frozen execution stack invalid: {failures}"
        )
    return value


def validate_frozen_stack(
    value: Any,
    *,
    frozen_schema: str = FROZEN_SCHEMA,
    expected_readiness: dict[str, bool] | None = None,
    expected_next_blocker: str = "new_single_use_execution_preflight_required",
    expected_frozen_boundary: dict[str, bool] | None = None,
) -> list[str]:
    stack = value if isinstance(value, dict) else {}
    readiness_contract = (
        _default_readiness() if expected_readiness is None else expected_readiness
    )
    boundary = (
        FROZEN_BOUNDARY
        if expected_frozen_boundary is None
        else expected_frozen_boundary
    )
    failures: list[str] = []
    if not (
        stack.get("schema_version") == frozen_schema
        and stack.get("status") == "operator_reviewed_frozen"
        and isinstance(stack.get("frozen_id"), str)
        and stack.get("frozen_id")
        and isinstance(stack.get("promoted_at"), str)
        and stack.get("promoted_at")
        and _sha256(stack.get("candidate_bundle_sha256"))
    ):
        failures.append("outcome_execution_frozen_stack_identity_invalid")
    artifacts = stack.get("frozen_artifacts", {})
    if not (
        set(artifacts)
        == {
            "execution_contract",
            "offline_orchestrator_report",
            "offline_execution_journal",
            "fault_matrix_report",
            "review_bundle",
        }
        and all(_artifact_ref(item) for item in artifacts.values())
        and _artifact_ref(stack.get("review_receipt"))
    ):
        failures.append("outcome_execution_frozen_stack_artifacts_invalid")
    admission = stack.get("provider_admission", {})
    if not (
        admission.get("status") == "admitted"
        and admission.get("gate_passed") is True
        and _sha256(admission.get("receipt_sha256"))
        and _sha256(admission.get("gate_sha256"))
    ):
        failures.append("outcome_execution_frozen_provider_admission_invalid")
    if stack.get("runtime_inventory") != {
        "participant_count": 40,
        "created_count": 40,
        "running_count": 0,
    }:
        failures.append("outcome_execution_frozen_runtime_inventory_invalid")
    if stack.get("readiness") != readiness_contract:
        failures.append("outcome_execution_frozen_readiness_invalid")
    if (
        stack.get("next_blocker") != expected_next_blocker
        or stack.get("execution_boundary") != boundary
    ):
        failures.append("outcome_execution_frozen_boundary_invalid")
    body = {key: item for key, item in stack.items() if key != "frozen_stack_sha256"}
    if stack.get("frozen_stack_sha256") != canonical_sha256(body):
        failures.append("outcome_execution_frozen_stack_hash_invalid")
    return list(dict.fromkeys(failures))


def _default_readiness() -> dict[str, bool]:
    return {
        "outcome_sensitive_execution_contract_frozen": True,
        "offline_480_task_recovery_evidence_frozen": True,
        "fault_matrix_evidence_frozen": True,
        "strict_decision_and_observation_contract_frozen": True,
        "live_provider_admission_refreshed": True,
        "runtime_inventory_40_created_0_running": True,
        "execution_preflight_allowed": True,
        "execution_authorization_issued": False,
        "controlled_experiment_execution_ready": False,
    }


def _signature_payload(value: dict[str, Any]) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")


def _artifact_ref(value: Any) -> bool:
    item = value if isinstance(value, dict) else {}
    return (
        set(item) == {"path", "sha256", "canonical_sha256"}
        and str(item.get("path", "")).startswith("/")
        and _sha256(item.get("sha256"))
        and _sha256(item.get("canonical_sha256"))
    )


def _sha256(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True
