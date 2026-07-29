"""Independent-review contracts for outcome-sensitive J1-D infrastructure."""

from __future__ import annotations

import copy
import hashlib
import json
from datetime import datetime
from typing import Any, Protocol

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from .controlled_comparison import canonical_sha256
from .qualification_outcome_sensitive_infrastructure_rebind import (
    PLAN_SCHEMA,
    REQUIRED_REVIEW_CHECKS,
)


REQUEST_SCHEMA = (
    "j1-qualification-outcome-sensitive-infrastructure-rebind-review-request:v1"
)
DECISION_SCHEMA = (
    "j1-qualification-outcome-sensitive-infrastructure-rebind-review-decision:v1"
)
RECEIPT_SCHEMA = (
    "j1-qualification-outcome-sensitive-infrastructure-rebind-review-receipt:v1"
)
REVIEWED_SCHEMA = (
    "j1-qualification-outcome-sensitive-infrastructure-rebind:operator-reviewed:v1"
)
REQUEST_STATUS = "awaiting_independent_operator_decision"
APPROVAL_DECISION = "approve_outcome_sensitive_infrastructure_rebind"
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
HANDOFF_BOUNDARY = {
    "review_handoff_only": True,
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
    "effectiveness_claim_authorized": False,
    "si13_maturity_upgrade_authorized": False,
}
RECEIPT_BOUNDARY = {
    **HANDOFF_BOUNDARY,
    "review_handoff_only": False,
    "review_approved": True,
    "infrastructure_artifact_promotion_allowed": True,
}
PROMOTION_BOUNDARY = {
    **HANDOFF_BOUNDARY,
    "review_handoff_only": False,
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
    plan_raw: bytes,
    preflight_path: str,
    preflight: dict[str, Any],
    preflight_raw: bytes,
    authorization_id: str,
    authorized_at: str,
    authorization_statement_sha256: str,
    implementation: dict[str, str],
) -> dict[str, Any]:
    request = {
        "schema_version": REQUEST_SCHEMA,
        "request_id": request_id,
        "status": REQUEST_STATUS,
        "created_at": created_at,
        "candidate_artifacts": {
            "infrastructure_rebind_plan": _artifact(
                plan_path, plan_raw, plan["plan_sha256"]
            ),
            "candidate_preflight": _artifact(
                preflight_path, preflight_raw, preflight["report_sha256"]
            ),
        },
        "owner_authorization": {
            "authorization_id": authorization_id,
            "authorized_at": authorized_at,
            "statement_sha256": authorization_statement_sha256,
            "scope": "independent_review_only",
        },
        "review_scope": _review_scope(plan, plan_raw, preflight),
        "required_checklist": sorted(REQUIRED_REVIEW_CHECKS),
        "allowed_decisions": sorted(ALLOWED_DECISIONS),
        "independence_requirements": copy.deepcopy(INDEPENDENCE_REQUIREMENTS),
        "signer_contract": copy.deepcopy(SIGNER_CONTRACT),
        "implementation": copy.deepcopy(implementation),
        "execution_boundary": copy.deepcopy(HANDOFF_BOUNDARY),
    }
    request["request_sha256"] = canonical_sha256(request)
    failures = validate_review_request(
        request,
        plan=plan,
        plan_raw=plan_raw,
        preflight=preflight,
        preflight_raw=preflight_raw,
        expected_plan_path=plan_path,
        expected_preflight_path=preflight_path,
        expected_authorization_statement_sha256=authorization_statement_sha256,
        expected_implementation=implementation,
    )
    if failures:
        raise ValueError(f"outcome infrastructure review request invalid: {failures}")
    return request


def validate_review_request(
    value: Any,
    *,
    plan: dict[str, Any],
    plan_raw: bytes,
    preflight: dict[str, Any],
    preflight_raw: bytes,
    expected_plan_path: str,
    expected_preflight_path: str,
    expected_authorization_statement_sha256: str,
    expected_implementation: dict[str, str],
) -> list[str]:
    request = value if isinstance(value, dict) else {}
    failures: list[str] = []
    _require(
        set(request)
        == {
            "schema_version",
            "request_id",
            "status",
            "created_at",
            "candidate_artifacts",
            "owner_authorization",
            "review_scope",
            "required_checklist",
            "allowed_decisions",
            "independence_requirements",
            "signer_contract",
            "implementation",
            "execution_boundary",
            "request_sha256",
        },
        "outcome_infrastructure_review_request_fields_invalid",
        failures,
    )
    _require(
        request.get("schema_version") == REQUEST_SCHEMA
        and request.get("status") == REQUEST_STATUS
        and _text(request.get("request_id"))
        and _rfc3339(request.get("created_at")),
        "outcome_infrastructure_review_request_identity_invalid",
        failures,
    )
    plan_body = {key: item for key, item in plan.items() if key != "plan_sha256"}
    _require(
        plan.get("schema_version") == PLAN_SCHEMA
        and plan.get("status") == "review_required"
        and plan.get("plan_sha256") == canonical_sha256(plan_body),
        "outcome_infrastructure_review_plan_invalid",
        failures,
    )
    _require(
        request.get("candidate_artifacts")
        == {
            "infrastructure_rebind_plan": _artifact(
                expected_plan_path, plan_raw, plan["plan_sha256"]
            ),
            "candidate_preflight": _artifact(
                expected_preflight_path,
                preflight_raw,
                preflight["report_sha256"],
            ),
        },
        "outcome_infrastructure_review_candidate_binding_invalid",
        failures,
    )
    authorization = request.get("owner_authorization", {})
    _require(
        isinstance(authorization, dict)
        and set(authorization)
        == {"authorization_id", "authorized_at", "statement_sha256", "scope"}
        and _text(authorization.get("authorization_id"))
        and _rfc3339(authorization.get("authorized_at"))
        and authorization.get("statement_sha256")
        == expected_authorization_statement_sha256
        and authorization.get("scope") == "independent_review_only",
        "outcome_infrastructure_review_owner_authorization_invalid",
        failures,
    )
    _require(
        request.get("review_scope") == _review_scope(plan, plan_raw, preflight),
        "outcome_infrastructure_review_scope_invalid",
        failures,
    )
    _require(
        request.get("required_checklist") == sorted(REQUIRED_REVIEW_CHECKS)
        and len(request.get("required_checklist", [])) == 10,
        "outcome_infrastructure_review_checklist_invalid",
        failures,
    )
    _require(
        request.get("allowed_decisions") == sorted(ALLOWED_DECISIONS)
        and request.get("independence_requirements") == INDEPENDENCE_REQUIREMENTS
        and request.get("signer_contract") == SIGNER_CONTRACT,
        "outcome_infrastructure_review_governance_invalid",
        failures,
    )
    _require(
        request.get("implementation") == expected_implementation
        and request.get("execution_boundary") == HANDOFF_BOUNDARY,
        "outcome_infrastructure_review_implementation_or_boundary_invalid",
        failures,
    )
    body = {key: item for key, item in request.items() if key != "request_sha256"}
    _require(
        request.get("request_sha256") == canonical_sha256(body),
        "outcome_infrastructure_review_request_hash_invalid",
        failures,
    )
    return list(dict.fromkeys(failures))


def build_review_decision_template(request: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": DECISION_SCHEMA,
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
        "checklist": {check: False for check in sorted(REQUIRED_REVIEW_CHECKS)},
    }


def approval_review_declaration(
    request: dict[str, Any], request_artifact_sha256: str
) -> str:
    return (
        "I have independently reviewed J1-D outcome-sensitive infrastructure "
        "rebind review request raw SHA-256 "
        f"{request_artifact_sha256}, canonical SHA-256 "
        f"{request['request_sha256']} and choose {APPROVAL_DECISION}. I confirm "
        "all 10 required checklist items, disclose all conflicts, affirm that I "
        "am independent from runner and candidate authoring and have completed "
        "human review. I acknowledge that this approval permits only copy-on-write "
        "promotion of the reviewed infrastructure artifact. It does not create, "
        "start, rename, or remove any container, create participant directories, "
        "prune historical containers or images, read a provider credential, call "
        "a provider or model, execute an Agent or task, append Backend Facts, "
        "append the Ledger, issue or consume an execution authorization, authorize "
        "an effectiveness claim, or upgrade SI-13 maturity."
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
        },
        "outcome_infrastructure_review_decision_fields_invalid",
        failures,
    )
    _require(
        decision.get("schema_version") == DECISION_SCHEMA
        and _text(decision.get("review_id"))
        and decision.get("review_request_sha256") == request.get("request_sha256")
        and decision.get("decision") == APPROVAL_DECISION
        and _rfc3339(decision.get("reviewed_at")),
        "outcome_infrastructure_review_decision_identity_invalid",
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
        "outcome_infrastructure_review_reviewer_invalid",
        failures,
    )
    _require(
        decision.get("independence")
        == {
            "conflicts_disclosed": True,
            "independent_from_runner_and_candidate_authoring": True,
            "human_review_completed": True,
        },
        "outcome_infrastructure_review_independence_invalid",
        failures,
    )
    _require(
        decision.get("checklist")
        == {check: True for check in sorted(REQUIRED_REVIEW_CHECKS)},
        "outcome_infrastructure_review_checklist_incomplete",
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
        raise ValueError(f"outcome infrastructure review decision invalid: {failures}")
    reviewer = decision["reviewer"]
    if not (
        signer.public_key_hex.lower() == reviewer["public_key_hex"].lower()
        and reviewer["custody_provenance_sha256"] == reviewer_profile_sha256
        and reviewer["signer_attestation_sha256"] == reviewer_profile_sha256
    ):
        raise ValueError("outcome infrastructure reviewer signer/profile mismatch")
    receipt = {
        "schema_version": RECEIPT_SCHEMA,
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
        "outcome_infrastructure_review_receipt_fields_invalid",
        failures,
    )
    decision = {
        "schema_version": DECISION_SCHEMA,
        "review_id": receipt.get("review_id"),
        "review_request_sha256": receipt.get("review_request_sha256"),
        "decision": receipt.get("decision"),
        "reviewed_at": receipt.get("reviewed_at"),
        "reviewer": receipt.get("reviewer"),
        "independence": receipt.get("independence"),
        "checklist": receipt.get("checklist"),
    }
    failures.extend(validate_completed_review_decision(decision, request=request))
    _require(
        receipt.get("schema_version") == RECEIPT_SCHEMA
        and receipt.get("review_declaration_sha256")
        == expected_review_declaration_sha256,
        "outcome_infrastructure_review_receipt_identity_invalid",
        failures,
    )
    reviewer = receipt.get("reviewer", {})
    _require(
        isinstance(reviewer, dict)
        and reviewer.get("custody_provenance_sha256")
        == expected_reviewer_profile_sha256
        and reviewer.get("signer_attestation_sha256")
        == expected_reviewer_profile_sha256,
        "outcome_infrastructure_review_reviewer_profile_invalid",
        failures,
    )
    _require(
        receipt.get("review_scope") == request.get("review_scope")
        and receipt.get("owner_authorization") == request.get("owner_authorization"),
        "outcome_infrastructure_review_receipt_scope_invalid",
        failures,
    )
    _require(
        receipt.get("implementation") == expected_implementation
        and receipt.get("execution_boundary") == RECEIPT_BOUNDARY,
        "outcome_infrastructure_review_receipt_implementation_or_boundary_invalid",
        failures,
    )
    signature = receipt.get("signature", {})
    payload = review_signature_payload(receipt)
    _require(
        isinstance(signature, dict)
        and signature.get("algorithm") == "ed25519"
        and signature.get("signed_payload_sha256")
        == hashlib.sha256(payload).hexdigest(),
        "outcome_infrastructure_review_signature_metadata_invalid",
        failures,
    )
    try:
        VerifyKey(bytes.fromhex(str(reviewer.get("public_key_hex", "")))).verify(
            payload, bytes.fromhex(str(signature.get("signature_hex", "")))
        )
    except (BadSignatureError, ValueError):
        failures.append("outcome_infrastructure_review_signature_invalid")
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
        "schema_version": REVIEWED_SCHEMA,
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
        reviewed.get("schema_version") == REVIEWED_SCHEMA
        and reviewed.get("status") == "operator_reviewed"
        and reviewed.get("source_candidate_sha256") == candidate.get("plan_sha256"),
        "outcome_reviewed_infrastructure_identity_invalid",
        failures,
    )
    body = {
        key: item
        for key, item in reviewed.items()
        if key != "reviewed_infrastructure_rebind_sha256"
    }
    _require(
        reviewed.get("reviewed_infrastructure_rebind_sha256") == canonical_sha256(body),
        "outcome_reviewed_infrastructure_hash_invalid",
        failures,
    )
    _require(
        reviewed == expected,
        "outcome_reviewed_infrastructure_copy_on_write_invalid",
        failures,
    )
    return list(dict.fromkeys(failures))


def review_signature_payload(receipt: dict[str, Any]) -> bytes:
    body = {key: item for key, item in receipt.items() if key != "signature"}
    return json.dumps(
        body, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode()


def _review_scope(
    plan: dict[str, Any], plan_raw: bytes, preflight: dict[str, Any]
) -> dict[str, Any]:
    return {
        "rebind_id": plan["rebind_id"],
        "plan_artifact_sha256": hashlib.sha256(plan_raw).hexdigest(),
        "plan_canonical_sha256": plan["plan_sha256"],
        "source_binding": copy.deepcopy(plan["source_binding"]),
        "runner_image": copy.deepcopy(plan["runner_image"]),
        "inventory": copy.deepcopy(plan["inventory"]),
        "observed_source_set_sha256": preflight["observed_sources_sha256"],
        "target_config_set_sha256": canonical_sha256(
            sorted(
                item["target_isolation"]["container_config_sha256"]
                for item in plan["isolations"]
            )
        ),
        "docker_census": copy.deepcopy(preflight["docker_census"]),
        "disk_safety": copy.deepcopy(preflight["disk_safety"]),
    }


def _artifact(path: str, raw: bytes, canonical_hash: str) -> dict[str, str]:
    return {
        "path": path,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "canonical_sha256": canonical_hash,
    }


def _rfc3339(value: Any) -> bool:
    try:
        parsed = datetime.fromisoformat(str(value or "").replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _hex(value: Any, length: int) -> bool:
    return (
        isinstance(value, str)
        and len(value) == length
        and all(char in "0123456789abcdef" for char in value.lower())
    )


def _sha256(value: Any) -> bool:
    return _hex(value, 64)


def _require(condition: bool, code: str, failures: list[str]) -> None:
    if not condition and code not in failures:
        failures.append(code)
