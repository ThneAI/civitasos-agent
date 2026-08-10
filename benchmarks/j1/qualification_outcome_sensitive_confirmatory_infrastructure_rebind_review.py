"""Independent-review handoff contracts for confirmatory infrastructure."""

from __future__ import annotations

import copy
import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from .controlled_comparison import canonical_sha256
from .qualification_outcome_sensitive_confirmatory_infrastructure_rebind import (
    PLAN_SCHEMA,
    REQUIRED_REVIEW_CHECKS,
)


REVIEW_REQUEST_SCHEMA = (
    "j1-qualification-outcome-sensitive-confirmatory-"
    "infrastructure-rebind-review-request:v1"
)
REVIEW_DECISION_SCHEMA = (
    "j1-qualification-outcome-sensitive-confirmatory-"
    "infrastructure-rebind-review-decision:v1"
)
REVIEW_RECEIPT_SCHEMA = (
    "j1-qualification-outcome-sensitive-confirmatory-"
    "infrastructure-rebind-review-receipt:v1"
)
REVIEWED_INFRASTRUCTURE_SCHEMA = (
    "j1-qualification-outcome-sensitive-confirmatory-"
    "infrastructure-rebind:operator-reviewed:v1"
)
REQUEST_STATUS = "awaiting_independent_operator_decision"
APPROVAL_DECISION = "approve_outcome_sensitive_confirmatory_infrastructure_rebind"
ALLOWED_DECISIONS = {APPROVAL_DECISION, "request_changes", "reject"}
SIGNER_CONTRACT = {
    "algorithm": "ed25519",
    "allowed_signer_kinds": [
        "non_exportable_ed25519_callback",
        "pkcs11_ed25519",
    ],
    "reviewer_did_networks": ["mainnet", "testnet"],
    "credential_version_required": True,
    "custody_provenance_required": True,
    "signer_attestation_required": True,
}
INDEPENDENCE_REQUIREMENTS = {
    "conflicts_disclosure_required": True,
    "independent_from_runner_and_candidate_authoring_required": True,
    "human_review_required": True,
}
EXECUTION_BOUNDARY = {
    "review_request_preparation_only": True,
    "review_decision_complete": False,
    "review_signature_present": False,
    "infrastructure_promoted": False,
    "parent_container_mutated": False,
    "parent_container_removed": False,
    "participant_container_created": False,
    "participant_container_started": False,
    "target_directory_created": False,
    "provider_credential_read": False,
    "provider_api_call_performed": False,
    "model_invocation_performed": False,
    "agent_execution_performed": False,
    "participant_task_execution_performed": False,
    "backend_fact_append_performed": False,
    "ledger_append_performed": False,
    "execution_authorization_issued_or_consumed": False,
    "r4_reanalysis_performed": False,
    "advice_adherence_observed": False,
    "effectiveness_or_causal_claim_authorized": False,
    "si13_maturity_upgrade_authorized": False,
}
DECISION_BOUNDARY = {
    **EXECUTION_BOUNDARY,
    "review_request_preparation_only": False,
    "review_decision_complete": True,
}
RECEIPT_BOUNDARY = {
    **DECISION_BOUNDARY,
    "review_signature_present": True,
    "review_approved": True,
    "infrastructure_artifact_promotion_allowed": True,
}
PROMOTION_BOUNDARY = {
    **RECEIPT_BOUNDARY,
    "review_promotion_only": True,
    "infrastructure_promoted": True,
}


class ReviewSigner(Protocol):
    @property
    def public_key_hex(self) -> str: ...

    def sign(self, message: bytes) -> bytes: ...


def build_review_request(
    *,
    request_id: str,
    created_at: str,
    plan_path: str,
    plan: dict[str, Any],
    plan_bytes: bytes,
    candidate_preflight_path: str,
    candidate_preflight: dict[str, Any],
    candidate_preflight_bytes: bytes,
    authorization_id: str,
    authorized_at: str,
    authorization_statement_sha256: str,
    implementation: dict[str, str],
) -> dict[str, Any]:
    request = _assemble_request(
        request_id=request_id,
        created_at=created_at,
        plan_path=plan_path,
        plan=plan,
        plan_bytes=plan_bytes,
        candidate_preflight_path=candidate_preflight_path,
        candidate_preflight=candidate_preflight,
        candidate_preflight_bytes=candidate_preflight_bytes,
        authorization_id=authorization_id,
        authorized_at=authorized_at,
        authorization_statement_sha256=authorization_statement_sha256,
        implementation=implementation,
    )
    failures = validate_review_request(
        request,
        plan=plan,
        plan_bytes=plan_bytes,
        candidate_preflight=candidate_preflight,
        candidate_preflight_bytes=candidate_preflight_bytes,
        expected_plan_path=plan_path,
        expected_candidate_preflight_path=candidate_preflight_path,
        expected_authorization_statement_sha256=authorization_statement_sha256,
        expected_implementation=implementation,
    )
    if failures:
        raise ValueError(f"confirmatory infrastructure review request invalid: {failures}")
    return request


def validate_review_request(
    value: Any,
    *,
    plan: dict[str, Any],
    plan_bytes: bytes,
    candidate_preflight: dict[str, Any],
    candidate_preflight_bytes: bytes,
    expected_plan_path: str,
    expected_candidate_preflight_path: str,
    expected_authorization_statement_sha256: str,
    expected_implementation: dict[str, str],
) -> list[str]:
    request = value if isinstance(value, dict) else {}
    failures: list[str] = []
    if request.get("schema_version") != REVIEW_REQUEST_SCHEMA:
        failures.append("confirmatory_infrastructure_review_request_schema_invalid")
    body = {key: item for key, item in request.items() if key != "request_sha256"}
    if request.get("request_sha256") != canonical_sha256(body):
        failures.append("confirmatory_infrastructure_review_request_hash_invalid")
    expected = _assemble_request(
        request_id=str(request.get("request_id", "")),
        created_at=str(request.get("created_at", "")),
        plan_path=expected_plan_path,
        plan=plan,
        plan_bytes=plan_bytes,
        candidate_preflight_path=expected_candidate_preflight_path,
        candidate_preflight=candidate_preflight,
        candidate_preflight_bytes=candidate_preflight_bytes,
        authorization_id=str(
            request.get("owner_authorization", {}).get("authorization_id", "")
        ),
        authorized_at=str(
            request.get("owner_authorization", {}).get("authorized_at", "")
        ),
        authorization_statement_sha256=expected_authorization_statement_sha256,
        implementation=expected_implementation,
    )
    if request != expected:
        failures.append(
            "confirmatory_infrastructure_review_copy_on_write_binding_invalid"
        )
    return list(dict.fromkeys(failures))


def build_review_decision_template(request: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": REVIEW_DECISION_SCHEMA,
        "review_id": "",
        "review_request_sha256": request["request_sha256"],
        "decision": "",
        "reviewed_at": "",
        "reviewer": {
            "did": "",
            "public_key_hex": "",
            "credential_version": 0,
            "signer_kind": "",
            "custody_provenance_sha256": "",
            "signer_attestation_sha256": "",
        },
        "independence": {
            "conflicts_disclosed": False,
            "independent_from_runner_and_candidate_authoring": False,
            "human_review_completed": False,
        },
        "checklist": {
            check: False for check in sorted(REQUIRED_REVIEW_CHECKS)
        },
        "review_notes": "",
        "execution_boundary": copy.deepcopy(EXECUTION_BOUNDARY),
    }


def approval_review_declaration(
    request: dict[str, Any], request_artifact_sha256: str
) -> str:
    return (
        "I have independently reviewed J1-D outcome-sensitive prospective "
        "confirmatory infrastructure rebind review request raw SHA-256 "
        f"{request_artifact_sha256}, canonical SHA-256 "
        f"{request['request_sha256']} and choose {APPROVAL_DECISION}. I confirm "
        f"all {len(REQUIRED_REVIEW_CHECKS)} required checklist items, disclose "
        "all conflicts, affirm that I am independent from runner and candidate "
        "authoring and have completed human review. I acknowledge that this "
        "approval permits only copy-on-write promotion of the reviewed "
        "confirmatory infrastructure artifact. It does not create, start, rename, "
        "or remove any container, create participant directories, prune historical "
        "containers or images, read a provider credential, call a provider or "
        "model, execute an Agent or task, append Backend Facts, append the Ledger, "
        "issue or consume an execution authorization, reanalyze r4, infer advice "
        "adherence, authorize an effectiveness or causal claim, or upgrade SI-13 "
        "maturity."
    )


def validate_completed_review_decision(
    value: Any, *, request: dict[str, Any]
) -> list[str]:
    decision = value if isinstance(value, dict) else {}
    failures: list[str] = []
    _require(
        set(decision)
        == {
            "schema_version",
            "review_id",
            "review_request_sha256",
            "decision",
            "reviewed_at",
            "reviewer",
            "independence",
            "checklist",
            "execution_boundary",
        },
        "confirmatory_infrastructure_review_decision_fields_invalid",
        failures,
    )
    _require(
        decision.get("schema_version") == REVIEW_DECISION_SCHEMA
        and _text(decision.get("review_id"))
        and decision.get("review_request_sha256") == request.get("request_sha256")
        and decision.get("decision") == APPROVAL_DECISION
        and _rfc3339(decision.get("reviewed_at")),
        "confirmatory_infrastructure_review_decision_identity_invalid",
        failures,
    )
    reviewer = decision.get("reviewer", {})
    _require(
        isinstance(reviewer, dict)
        and set(reviewer)
        == {
            "did",
            "public_key_hex",
            "credential_version",
            "signer_kind",
            "custody_provenance_sha256",
            "signer_attestation_sha256",
        }
        and _text(reviewer.get("did"))
        and _hex(reviewer.get("public_key_hex"), 64)
        and isinstance(reviewer.get("credential_version"), int)
        and reviewer.get("credential_version", 0) > 0
        and reviewer.get("signer_kind") in SIGNER_CONTRACT["allowed_signer_kinds"]
        and _sha256(reviewer.get("custody_provenance_sha256"))
        and _sha256(reviewer.get("signer_attestation_sha256")),
        "confirmatory_infrastructure_review_reviewer_invalid",
        failures,
    )
    _require(
        decision.get("independence")
        == {
            "conflicts_disclosed": True,
            "independent_from_runner_and_candidate_authoring": True,
            "human_review_completed": True,
        },
        "confirmatory_infrastructure_review_independence_invalid",
        failures,
    )
    _require(
        decision.get("checklist")
        == {check: True for check in sorted(REQUIRED_REVIEW_CHECKS)},
        "confirmatory_infrastructure_review_checklist_incomplete",
        failures,
    )
    _require(
        decision.get("execution_boundary") == DECISION_BOUNDARY,
        "confirmatory_infrastructure_review_decision_boundary_invalid",
        failures,
    )
    return list(dict.fromkeys(failures))


def build_review_receipt(
    *,
    request: dict[str, Any],
    decision: dict[str, Any],
    review_declaration_sha256: str,
    reviewer_profile_sha256: str,
    implementation: dict[str, str],
    signer: ReviewSigner,
) -> dict[str, Any]:
    failures = validate_completed_review_decision(decision, request=request)
    if failures:
        raise ValueError(
            f"confirmatory infrastructure review decision invalid: {failures}"
        )
    reviewer = decision["reviewer"]
    if not (
        signer.public_key_hex.lower() == reviewer["public_key_hex"].lower()
        and reviewer["custody_provenance_sha256"] == reviewer_profile_sha256
        and reviewer["signer_attestation_sha256"] == reviewer_profile_sha256
    ):
        raise ValueError(
            "confirmatory infrastructure reviewer signer/profile mismatch"
        )
    receipt = {
        "schema_version": REVIEW_RECEIPT_SCHEMA,
        "review_id": decision["review_id"],
        "review_request_sha256": request["request_sha256"],
        "decision": decision["decision"],
        "reviewed_at": decision["reviewed_at"],
        "review_declaration_sha256": review_declaration_sha256,
        "reviewer": copy.deepcopy(reviewer),
        "independence": copy.deepcopy(decision["independence"]),
        "checklist": copy.deepcopy(decision["checklist"]),
        "review_scope": copy.deepcopy(request["review_scope"]),
        "owner_authorization": copy.deepcopy(request["owner_authorization"]),
        "implementation": copy.deepcopy(implementation),
        "execution_boundary": copy.deepcopy(RECEIPT_BOUNDARY),
    }
    payload = review_signature_payload(receipt)
    receipt["signature"] = {
        "algorithm": "ed25519",
        "signed_payload_sha256": hashlib.sha256(payload).hexdigest(),
        "signature_hex": signer.sign(payload).hex(),
    }
    return receipt


def validate_review_receipt(
    value: Any,
    *,
    request: dict[str, Any],
    expected_review_declaration_sha256: str,
    expected_reviewer_profile_sha256: str,
    expected_implementation: dict[str, str],
) -> list[str]:
    receipt = value if isinstance(value, dict) else {}
    failures: list[str] = []
    _require(
        set(receipt)
        == {
            "schema_version",
            "review_id",
            "review_request_sha256",
            "decision",
            "reviewed_at",
            "review_declaration_sha256",
            "reviewer",
            "independence",
            "checklist",
            "review_scope",
            "owner_authorization",
            "implementation",
            "execution_boundary",
            "signature",
        },
        "confirmatory_infrastructure_review_receipt_fields_invalid",
        failures,
    )
    decision = {
        "schema_version": REVIEW_DECISION_SCHEMA,
        "review_id": receipt.get("review_id"),
        "review_request_sha256": receipt.get("review_request_sha256"),
        "decision": receipt.get("decision"),
        "reviewed_at": receipt.get("reviewed_at"),
        "reviewer": receipt.get("reviewer"),
        "independence": receipt.get("independence"),
        "checklist": receipt.get("checklist"),
        "execution_boundary": copy.deepcopy(DECISION_BOUNDARY),
    }
    failures.extend(validate_completed_review_decision(decision, request=request))
    _require(
        receipt.get("schema_version") == REVIEW_RECEIPT_SCHEMA
        and receipt.get("review_declaration_sha256")
        == expected_review_declaration_sha256,
        "confirmatory_infrastructure_review_receipt_identity_invalid",
        failures,
    )
    reviewer = receipt.get("reviewer", {})
    _require(
        isinstance(reviewer, dict)
        and reviewer.get("custody_provenance_sha256")
        == expected_reviewer_profile_sha256
        and reviewer.get("signer_attestation_sha256")
        == expected_reviewer_profile_sha256,
        "confirmatory_infrastructure_review_reviewer_profile_invalid",
        failures,
    )
    _require(
        receipt.get("review_scope") == request.get("review_scope")
        and receipt.get("owner_authorization") == request.get("owner_authorization"),
        "confirmatory_infrastructure_review_receipt_scope_invalid",
        failures,
    )
    _require(
        receipt.get("implementation") == expected_implementation
        and receipt.get("execution_boundary") == RECEIPT_BOUNDARY,
        "confirmatory_infrastructure_review_receipt_boundary_invalid",
        failures,
    )
    signature = receipt.get("signature", {})
    payload = review_signature_payload(receipt)
    _require(
        isinstance(signature, dict)
        and signature.get("algorithm") == "ed25519"
        and signature.get("signed_payload_sha256")
        == hashlib.sha256(payload).hexdigest(),
        "confirmatory_infrastructure_review_signature_metadata_invalid",
        failures,
    )
    try:
        VerifyKey(bytes.fromhex(str(reviewer.get("public_key_hex", "")))).verify(
            payload, bytes.fromhex(str(signature.get("signature_hex", "")))
        )
    except (BadSignatureError, ValueError):
        failures.append("confirmatory_infrastructure_review_signature_invalid")
    return list(dict.fromkeys(failures))


def build_reviewed_infrastructure_rebind(
    *,
    candidate: dict[str, Any],
    receipt: dict[str, Any],
    receipt_artifact_sha256: str,
) -> dict[str, Any]:
    reviewed = {
        **{
            key: item
            for key, item in candidate.items()
            if key
            not in {
                "schema_version",
                "status",
                "plan_sha256",
                "execution_boundary",
            }
        },
        "schema_version": REVIEWED_INFRASTRUCTURE_SCHEMA,
        "status": "operator_reviewed",
        "source_candidate_sha256": candidate["plan_sha256"],
        "candidate_execution_boundary": copy.deepcopy(candidate["execution_boundary"]),
        "operator_review": {
            "review_id": receipt["review_id"],
            "review_request_sha256": receipt["review_request_sha256"],
            "reviewer_did": receipt["reviewer"]["did"],
            "reviewed_at": receipt["reviewed_at"],
            "review_receipt_sha256": receipt_artifact_sha256,
        },
        "execution_boundary": copy.deepcopy(PROMOTION_BOUNDARY),
    }
    reviewed["reviewed_infrastructure_rebind_sha256"] = canonical_sha256(reviewed)
    return reviewed


def validate_reviewed_infrastructure_rebind(
    value: Any,
    *,
    candidate: dict[str, Any],
    receipt: dict[str, Any],
    receipt_artifact_sha256: str,
) -> list[str]:
    reviewed = value if isinstance(value, dict) else {}
    expected = build_reviewed_infrastructure_rebind(
        candidate=candidate,
        receipt=receipt,
        receipt_artifact_sha256=receipt_artifact_sha256,
    )
    failures: list[str] = []
    _require(
        reviewed.get("schema_version") == REVIEWED_INFRASTRUCTURE_SCHEMA
        and reviewed.get("status") == "operator_reviewed"
        and reviewed.get("source_candidate_sha256") == candidate.get("plan_sha256"),
        "confirmatory_reviewed_infrastructure_identity_invalid",
        failures,
    )
    body = {
        key: item
        for key, item in reviewed.items()
        if key != "reviewed_infrastructure_rebind_sha256"
    }
    _require(
        reviewed.get("reviewed_infrastructure_rebind_sha256")
        == canonical_sha256(body),
        "confirmatory_reviewed_infrastructure_hash_invalid",
        failures,
    )
    _require(
        reviewed == expected,
        "confirmatory_reviewed_infrastructure_copy_on_write_invalid",
        failures,
    )
    return list(dict.fromkeys(failures))


def review_signature_payload(receipt: dict[str, Any]) -> bytes:
    body = {key: item for key, item in receipt.items() if key != "signature"}
    return json.dumps(
        body, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode()


def _assemble_request(
    *,
    request_id: str,
    created_at: str,
    plan_path: str,
    plan: dict[str, Any],
    plan_bytes: bytes,
    candidate_preflight_path: str,
    candidate_preflight: dict[str, Any],
    candidate_preflight_bytes: bytes,
    authorization_id: str,
    authorized_at: str,
    authorization_statement_sha256: str,
    implementation: dict[str, str],
) -> dict[str, Any]:
    if plan.get("schema_version") != PLAN_SCHEMA:
        raise ValueError("confirmatory infrastructure plan schema invalid")
    if not (_rfc3339(created_at) and _rfc3339(authorized_at)):
        raise ValueError("confirmatory infrastructure review timestamps invalid")
    target_root = str(
        Path(plan["isolations"][0]["target_isolation"]["input_root"]).parents[1]
    )
    request = {
        "schema_version": REVIEW_REQUEST_SCHEMA,
        "request_id": request_id,
        "status": REQUEST_STATUS,
        "created_at": created_at,
        "candidate_artifacts": {
            "infrastructure_rebind_plan": _artifact(
                plan_path, plan_bytes, plan["plan_sha256"]
            ),
            "candidate_preflight": _artifact(
                candidate_preflight_path,
                candidate_preflight_bytes,
                candidate_preflight["report_sha256"],
            ),
        },
        "owner_authorization": {
            "authorization_id": authorization_id,
            "authorized_at": authorized_at,
            "statement_sha256": authorization_statement_sha256,
            "scope": "independent_review_only",
        },
        "review_scope": {
            "rebind_id": plan["rebind_id"],
            "plan_artifact_sha256": hashlib.sha256(plan_bytes).hexdigest(),
            "plan_canonical_sha256": plan["plan_sha256"],
            "source_binding": copy.deepcopy(plan["source_binding"]),
            "runner_image": copy.deepcopy(plan["runner_image"]),
            "inventory": copy.deepcopy(plan["inventory"]),
            "docker_census": copy.deepcopy(candidate_preflight["docker_census"]),
            "disk_safety": copy.deepcopy(candidate_preflight["disk_safety"]),
            "target_state_root": target_root,
            "candidate_readiness": copy.deepcopy(plan["readiness"]),
            "review_contract": copy.deepcopy(plan["review_contract"]),
            "r4_reanalysis_allowed": False,
            "advice_adherence_observed": False,
            "remaining_gate_sequence": [
                "confirmatory_infrastructure_independent_review",
                "confirmatory_infrastructure_promotion_gate",
                "separate_exact_create_only_authorization",
                "stopped_replacement_container_activation",
            ],
        },
        "required_checklist": sorted(REQUIRED_REVIEW_CHECKS),
        "allowed_decisions": sorted(ALLOWED_DECISIONS),
        "independence_requirements": copy.deepcopy(INDEPENDENCE_REQUIREMENTS),
        "signer_contract": copy.deepcopy(SIGNER_CONTRACT),
        "implementation": copy.deepcopy(implementation),
        "execution_boundary": copy.deepcopy(EXECUTION_BOUNDARY),
    }
    request["request_sha256"] = canonical_sha256(request)
    return request


def _artifact(path: str, raw: bytes, canonical_hash: str) -> dict[str, str]:
    return {
        "path": path,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "canonical_sha256": canonical_hash,
    }


def _rfc3339(value: Any) -> bool:
    if not isinstance(value, str) or not value.strip():
        return False
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).tzinfo is not None
    except ValueError:
        return False


def _require(condition: bool, code: str, failures: list[str]) -> None:
    if not condition:
        failures.append(code)


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _sha256(value: Any) -> bool:
    return _hex(value, 64)


def _hex(value: Any, length: int) -> bool:
    if not isinstance(value, str) or len(value) != length:
        return False
    try:
        bytes.fromhex(value)
    except ValueError:
        return False
    return True
