"""Independent-review handoff contract for J1-D roster/assignment rebind."""

from __future__ import annotations

import copy
import hashlib
import json
from datetime import datetime
from typing import Any, Protocol

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from .controlled_comparison import canonical_sha256
from .qualification_roster_assignment_rebind import PLAN_SCHEMA


REVIEW_REQUEST_SCHEMA = "j1-qualification-roster-assignment-rebind-review-request:v1"
REVIEW_DECISION_SCHEMA = "j1-qualification-roster-assignment-rebind-review-decision:v1"
REVIEW_RECEIPT_SCHEMA = "j1-qualification-roster-assignment-rebind-review-receipt:v1"
REVIEWED_ROSTER_SCHEMA = "j1-qualification-roster-rebound:operator-reviewed:v1"
REVIEWED_ASSIGNMENT_SCHEMA = (
    "j1-qualification-cohort-assignment-rebound:operator-reviewed:v1"
)
REQUEST_STATUS = "awaiting_independent_operator_decision"
ALLOWED_DECISIONS = {
    "approve_roster_assignment_rebind",
    "request_changes",
    "reject",
}
REQUIRED_CHECKS = {
    "amended_protocol_and_design_binding_reviewed",
    "base_roster_and_assignment_immutability_reviewed",
    "control_advice_boundary_reviewed",
    "forty_consent_extension_signatures_reviewed",
    "forty_participant_identity_bindings_reviewed",
    "no_participant_substitution_reviewed",
    "twenty_pair_cohort_assignments_unchanged_reviewed",
    "execution_boundary_reviewed",
}
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
    "independent_from_candidate_authoring_required": True,
    "human_review_required": True,
}
EXECUTION_BOUNDARY = {
    "review_request_preparation_only": True,
    "roster_promoted": False,
    "assignment_promoted": False,
    "infrastructure_rebound": False,
    "container_created": False,
    "container_started": False,
    "provider_api_call_performed": False,
    "model_invocation_performed": False,
    "agent_execution_performed": False,
    "backend_fact_append_performed": False,
    "ledger_append_performed": False,
    "execution_authorization_issued_or_consumed": False,
}
RECEIPT_BOUNDARY = {
    "review_approved": True,
    "roster_assignment_promotion_allowed": True,
    "roster_promoted": False,
    "assignment_promoted": False,
    "infrastructure_rebound": False,
    "container_created": False,
    "container_started": False,
    "provider_api_call_performed": False,
    "model_invocation_performed": False,
    "agent_execution_performed": False,
    "backend_fact_append_performed": False,
    "ledger_append_performed": False,
    "execution_authorization_issued_or_consumed": False,
}
PROMOTION_BOUNDARY = {
    "review_promotion_only": True,
    "roster_promoted": True,
    "assignment_promoted": True,
    "infrastructure_rebound": False,
    "container_created": False,
    "container_started": False,
    "provider_api_call_performed": False,
    "model_invocation_performed": False,
    "agent_execution_performed": False,
    "backend_fact_append_performed": False,
    "ledger_append_performed": False,
    "execution_authorization_issued_or_consumed": False,
}


class ReviewSigner(Protocol):
    @property
    def public_key_hex(self) -> str: ...

    def sign(self, message: bytes) -> bytes: ...


def build_rebind_review_request(
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
    candidates = plan["candidate_artifacts"]
    request = {
        "schema_version": REVIEW_REQUEST_SCHEMA,
        "request_id": request_id,
        "status": REQUEST_STATUS,
        "created_at": created_at,
        "candidate_artifacts": {
            "rebind_plan": _artifact(plan_path, plan_bytes, plan["plan_sha256"]),
            "candidate_preflight": _artifact(
                candidate_preflight_path,
                candidate_preflight_bytes,
                candidate_preflight["report_sha256"],
            ),
            "rebound_roster": copy.deepcopy(candidates["rebound_roster"]),
            "rebound_assignment": copy.deepcopy(candidates["rebound_assignment"]),
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
            "inventory": copy.deepcopy(plan["inventory"]),
            "candidate_readiness": copy.deepcopy(plan["readiness"]),
            "remaining_gate_sequence": copy.deepcopy(plan["remaining_gate_sequence"]),
        },
        "required_checklist": sorted(REQUIRED_CHECKS),
        "allowed_decisions": sorted(ALLOWED_DECISIONS),
        "independence_requirements": copy.deepcopy(INDEPENDENCE_REQUIREMENTS),
        "signer_contract": copy.deepcopy(SIGNER_CONTRACT),
        "implementation": copy.deepcopy(implementation),
        "execution_boundary": copy.deepcopy(EXECUTION_BOUNDARY),
    }
    request["request_sha256"] = canonical_sha256(request)
    failures = validate_rebind_review_request(
        request,
        plan=plan,
        plan_bytes=plan_bytes,
        candidate_preflight=candidate_preflight,
        candidate_preflight_bytes=candidate_preflight_bytes,
        expected_authorization_statement_sha256=authorization_statement_sha256,
        expected_implementation=implementation,
    )
    if failures:
        raise ValueError(f"roster/assignment rebind review request invalid: {failures}")
    return request


def validate_rebind_review_request(
    value: Any,
    *,
    plan: dict[str, Any],
    plan_bytes: bytes,
    candidate_preflight: dict[str, Any],
    candidate_preflight_bytes: bytes,
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
        "rebind_review_request_fields_invalid",
        failures,
    )
    _require(
        request.get("schema_version") == REVIEW_REQUEST_SCHEMA,
        "rebind_review_request_schema_invalid",
        failures,
    )
    _require(
        request.get("status") == REQUEST_STATUS,
        "rebind_review_request_status_invalid",
        failures,
    )
    _require(
        _text(request.get("request_id")), "rebind_review_request_id_invalid", failures
    )
    _require(
        _rfc3339(request.get("created_at")),
        "rebind_review_request_time_invalid",
        failures,
    )
    _require(
        plan.get("schema_version") == PLAN_SCHEMA
        and plan.get("status") == "review_required"
        and plan.get("plan_sha256")
        == canonical_sha256(
            {key: item for key, item in plan.items() if key != "plan_sha256"}
        ),
        "rebind_review_plan_invalid",
        failures,
    )
    _validate_candidate_binding(
        request,
        plan=plan,
        plan_bytes=plan_bytes,
        candidate_preflight=candidate_preflight,
        candidate_preflight_bytes=candidate_preflight_bytes,
        failures=failures,
    )
    authorization = request.get("owner_authorization")
    authorization = authorization if isinstance(authorization, dict) else {}
    _require(
        set(authorization)
        == {"authorization_id", "authorized_at", "statement_sha256", "scope"}
        and _text(authorization.get("authorization_id"))
        and _rfc3339(authorization.get("authorized_at"))
        and authorization.get("statement_sha256")
        == expected_authorization_statement_sha256
        and authorization.get("scope") == "independent_review_only",
        "rebind_review_owner_authorization_invalid",
        failures,
    )
    _require(
        request.get("required_checklist") == sorted(REQUIRED_CHECKS),
        "rebind_review_checklist_invalid",
        failures,
    )
    _require(
        request.get("allowed_decisions") == sorted(ALLOWED_DECISIONS),
        "rebind_review_decisions_invalid",
        failures,
    )
    _require(
        request.get("independence_requirements") == INDEPENDENCE_REQUIREMENTS,
        "rebind_review_independence_invalid",
        failures,
    )
    _require(
        request.get("signer_contract") == SIGNER_CONTRACT,
        "rebind_review_signer_contract_invalid",
        failures,
    )
    _require(
        request.get("implementation") == expected_implementation,
        "rebind_review_implementation_invalid",
        failures,
    )
    _require(
        request.get("execution_boundary") == EXECUTION_BOUNDARY,
        "rebind_review_boundary_invalid",
        failures,
    )
    body = {key: item for key, item in request.items() if key != "request_sha256"}
    _require(
        request.get("request_sha256") == canonical_sha256(body),
        "rebind_review_request_hash_invalid",
        failures,
    )
    return list(dict.fromkeys(failures))


def build_rebind_review_decision_template(
    request: dict[str, Any],
) -> dict[str, Any]:
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
            "independent_from_candidate_authoring": False,
            "human_review_completed": False,
        },
        "checklist": {check: False for check in sorted(REQUIRED_CHECKS)},
    }


def approval_review_declaration(request: dict[str, Any]) -> str:
    return (
        "I have independently reviewed J1-D roster/assignment rebind review "
        f"request {request['request_sha256']} and choose "
        "approve_roster_assignment_rebind. I confirm all 8 required checklist "
        "items, disclose all conflicts, affirm that I am independent from candidate "
        "authoring and have completed human review, and acknowledge that this "
        "approval permits only copy-on-write roster/assignment promotion. It does "
        "not reassign or substitute any participant, rebind infrastructure, "
        "authorize provider or model calls, execute any Agent or container, append "
        "Backend Facts, append the Ledger, or issue or consume an execution "
        "authorization."
    )


def validate_completed_review_decision(
    value: Any,
    *,
    request: dict[str, Any],
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
        "rebind_review_decision_fields_invalid",
        failures,
    )
    _require(
        decision.get("schema_version") == REVIEW_DECISION_SCHEMA,
        "rebind_review_decision_schema_invalid",
        failures,
    )
    _require(_text(decision.get("review_id")), "rebind_review_id_invalid", failures)
    _require(
        decision.get("review_request_sha256") == request.get("request_sha256"),
        "rebind_review_decision_request_invalid",
        failures,
    )
    _require(
        decision.get("decision") == "approve_roster_assignment_rebind",
        "rebind_review_decision_not_approved",
        failures,
    )
    _require(
        _rfc3339(decision.get("reviewed_at")),
        "rebind_review_decision_time_invalid",
        failures,
    )
    reviewer = decision.get("reviewer")
    reviewer = reviewer if isinstance(reviewer, dict) else {}
    _require(
        set(reviewer)
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
        "rebind_review_reviewer_invalid",
        failures,
    )
    _require(
        decision.get("independence")
        == {
            "conflicts_disclosed": True,
            "independent_from_candidate_authoring": True,
            "human_review_completed": True,
        },
        "rebind_review_independence_attestation_invalid",
        failures,
    )
    _require(
        decision.get("checklist") == {check: True for check in sorted(REQUIRED_CHECKS)},
        "rebind_review_checklist_incomplete",
        failures,
    )
    return list(dict.fromkeys(failures))


def build_rebind_review_receipt(
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
            f"roster/assignment rebind review decision invalid: {failures}"
        )
    reviewer = decision["reviewer"]
    if not (
        signer.public_key_hex.lower() == reviewer["public_key_hex"].lower()
        and reviewer["custody_provenance_sha256"] == reviewer_profile_sha256
        and reviewer["signer_attestation_sha256"] == reviewer_profile_sha256
    ):
        raise ValueError("rebind reviewer signer/profile mismatch")
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
    payload = rebind_review_signature_payload(receipt)
    receipt["signature"] = {
        "algorithm": "ed25519",
        "signed_payload_sha256": hashlib.sha256(payload).hexdigest(),
        "signature_hex": signer.sign(payload).hex(),
    }
    return receipt


def validate_rebind_review_receipt(
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
        "rebind_review_receipt_fields_invalid",
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
    }
    failures.extend(validate_completed_review_decision(decision, request=request))
    _require(
        receipt.get("schema_version") == REVIEW_RECEIPT_SCHEMA,
        "rebind_review_receipt_schema_invalid",
        failures,
    )
    _require(
        receipt.get("review_declaration_sha256") == expected_review_declaration_sha256,
        "rebind_review_declaration_invalid",
        failures,
    )
    reviewer = receipt.get("reviewer")
    reviewer = reviewer if isinstance(reviewer, dict) else {}
    _require(
        reviewer.get("custody_provenance_sha256") == expected_reviewer_profile_sha256
        and reviewer.get("signer_attestation_sha256")
        == expected_reviewer_profile_sha256,
        "rebind_review_reviewer_profile_invalid",
        failures,
    )
    _require(
        receipt.get("review_scope") == request.get("review_scope")
        and receipt.get("owner_authorization") == request.get("owner_authorization"),
        "rebind_review_receipt_scope_invalid",
        failures,
    )
    _require(
        receipt.get("implementation") == expected_implementation,
        "rebind_review_receipt_implementation_invalid",
        failures,
    )
    _require(
        receipt.get("execution_boundary") == RECEIPT_BOUNDARY,
        "rebind_review_receipt_boundary_invalid",
        failures,
    )
    signature = receipt.get("signature")
    signature = signature if isinstance(signature, dict) else {}
    payload = rebind_review_signature_payload(receipt)
    _require(
        signature.get("algorithm") == "ed25519"
        and signature.get("signed_payload_sha256")
        == hashlib.sha256(payload).hexdigest(),
        "rebind_review_signature_metadata_invalid",
        failures,
    )
    try:
        VerifyKey(bytes.fromhex(str(reviewer.get("public_key_hex", "")))).verify(
            payload, bytes.fromhex(str(signature.get("signature_hex", "")))
        )
    except (BadSignatureError, ValueError):
        failures.append("rebind_review_signature_invalid")
    return list(dict.fromkeys(failures))


def build_reviewed_rebound_roster(
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
                "rebound_roster_sha256",
                "execution_boundary",
            }
        },
        "schema_version": REVIEWED_ROSTER_SCHEMA,
        "status": "operator_reviewed",
        "source_candidate_sha256": candidate["rebound_roster_sha256"],
        "candidate_execution_boundary": copy.deepcopy(candidate["execution_boundary"]),
        "operator_review": _operator_review(receipt, receipt_artifact_sha256),
        "execution_boundary": copy.deepcopy(PROMOTION_BOUNDARY),
    }
    reviewed["reviewed_rebound_roster_sha256"] = canonical_sha256(reviewed)
    return reviewed


def build_reviewed_rebound_assignment(
    *,
    candidate: dict[str, Any],
    reviewed_roster: dict[str, Any],
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
                "rebound_assignment_sha256",
                "execution_boundary",
            }
        },
        "schema_version": REVIEWED_ASSIGNMENT_SCHEMA,
        "status": "operator_reviewed",
        "source_candidate_sha256": candidate["rebound_assignment_sha256"],
        "operator_reviewed_roster_sha256": reviewed_roster[
            "reviewed_rebound_roster_sha256"
        ],
        "candidate_execution_boundary": copy.deepcopy(candidate["execution_boundary"]),
        "operator_review": _operator_review(receipt, receipt_artifact_sha256),
        "execution_boundary": copy.deepcopy(PROMOTION_BOUNDARY),
    }
    reviewed["reviewed_rebound_assignment_sha256"] = canonical_sha256(reviewed)
    return reviewed


def validate_reviewed_rebound_roster(
    value: Any,
    *,
    candidate: dict[str, Any],
    receipt: dict[str, Any],
    receipt_artifact_sha256: str,
) -> list[str]:
    reviewed = value if isinstance(value, dict) else {}
    expected = build_reviewed_rebound_roster(
        candidate=candidate,
        receipt=receipt,
        receipt_artifact_sha256=receipt_artifact_sha256,
    )
    return _validate_reviewed_artifact(
        reviewed,
        expected=expected,
        schema=REVIEWED_ROSTER_SCHEMA,
        source_hash=candidate.get("rebound_roster_sha256"),
        hash_field="reviewed_rebound_roster_sha256",
        label="reviewed_rebound_roster",
    )


def validate_reviewed_rebound_assignment(
    value: Any,
    *,
    candidate: dict[str, Any],
    reviewed_roster: dict[str, Any],
    receipt: dict[str, Any],
    receipt_artifact_sha256: str,
) -> list[str]:
    reviewed = value if isinstance(value, dict) else {}
    expected = build_reviewed_rebound_assignment(
        candidate=candidate,
        reviewed_roster=reviewed_roster,
        receipt=receipt,
        receipt_artifact_sha256=receipt_artifact_sha256,
    )
    failures = _validate_reviewed_artifact(
        reviewed,
        expected=expected,
        schema=REVIEWED_ASSIGNMENT_SCHEMA,
        source_hash=candidate.get("rebound_assignment_sha256"),
        hash_field="reviewed_rebound_assignment_sha256",
        label="reviewed_rebound_assignment",
    )
    _require(
        reviewed.get("operator_reviewed_roster_sha256")
        == reviewed_roster.get("reviewed_rebound_roster_sha256"),
        "reviewed_rebound_assignment_roster_binding_invalid",
        failures,
    )
    return list(dict.fromkeys(failures))


def rebind_review_signature_payload(receipt: dict[str, Any]) -> bytes:
    body = {key: item for key, item in receipt.items() if key != "signature"}
    return json.dumps(
        body, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode()


def _operator_review(
    receipt: dict[str, Any], receipt_artifact_sha256: str
) -> dict[str, Any]:
    return {
        "review_id": receipt["review_id"],
        "review_request_sha256": receipt["review_request_sha256"],
        "reviewer_did": receipt["reviewer"]["did"],
        "reviewed_at": receipt["reviewed_at"],
        "review_receipt_sha256": receipt_artifact_sha256,
    }


def _validate_reviewed_artifact(
    value: dict[str, Any],
    *,
    expected: dict[str, Any],
    schema: str,
    source_hash: Any,
    hash_field: str,
    label: str,
) -> list[str]:
    failures: list[str] = []
    _require(
        value.get("schema_version") == schema
        and value.get("status") == "operator_reviewed"
        and value.get("source_candidate_sha256") == source_hash,
        f"{label}_identity_invalid",
        failures,
    )
    body = {key: item for key, item in value.items() if key != hash_field}
    _require(
        value.get(hash_field) == canonical_sha256(body),
        f"{label}_hash_invalid",
        failures,
    )
    _require(value == expected, f"{label}_copy_on_write_invalid", failures)
    return failures


def _validate_candidate_binding(
    request: dict[str, Any],
    *,
    plan: dict[str, Any],
    plan_bytes: bytes,
    candidate_preflight: dict[str, Any],
    candidate_preflight_bytes: bytes,
    failures: list[str],
) -> None:
    candidates = request.get("candidate_artifacts")
    candidates = candidates if isinstance(candidates, dict) else {}
    expected = {
        "rebind_plan": _artifact(
            str(plan.get("candidate_artifacts", {}).get("rebind_plan_path", "")),
            plan_bytes,
            str(plan.get("plan_sha256", "")),
        ),
        "candidate_preflight": _artifact(
            str(candidate_preflight.get("_review_path", "")),
            candidate_preflight_bytes,
            str(candidate_preflight.get("report_sha256", "")),
        ),
        "rebound_roster": copy.deepcopy(
            plan.get("candidate_artifacts", {}).get("rebound_roster")
        ),
        "rebound_assignment": copy.deepcopy(
            plan.get("candidate_artifacts", {}).get("rebound_assignment")
        ),
    }
    # Paths are supplied by the request builder and are not canonical plan fields.
    expected["rebind_plan"]["path"] = candidates.get("rebind_plan", {}).get("path")
    expected["candidate_preflight"]["path"] = candidates.get(
        "candidate_preflight", {}
    ).get("path")
    _require(
        candidates == expected,
        "rebind_review_candidate_binding_invalid",
        failures,
    )
    scope = request.get("review_scope")
    scope = scope if isinstance(scope, dict) else {}
    _require(
        scope
        == {
            "rebind_id": plan.get("rebind_id"),
            "plan_artifact_sha256": hashlib.sha256(plan_bytes).hexdigest(),
            "plan_canonical_sha256": plan.get("plan_sha256"),
            "source_binding": plan.get("source_binding"),
            "inventory": plan.get("inventory"),
            "candidate_readiness": plan.get("readiness"),
            "remaining_gate_sequence": plan.get("remaining_gate_sequence"),
        },
        "rebind_review_scope_invalid",
        failures,
    )


def _artifact(path: str, raw: bytes, canonical_sha256: str) -> dict[str, str]:
    return {
        "path": path,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "canonical_sha256": canonical_sha256,
    }


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


def _rfc3339(value: Any) -> bool:
    if not _text(value):
        return False
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).tzinfo is not None
    except ValueError:
        return False


def _require(condition: bool, code: str, failures: list[str]) -> None:
    if not condition and code not in failures:
        failures.append(code)
