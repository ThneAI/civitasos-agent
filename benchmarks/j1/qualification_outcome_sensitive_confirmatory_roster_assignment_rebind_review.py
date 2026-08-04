"""Independent-review handoff contracts for confirmatory J1-D rebind."""

from __future__ import annotations

import copy
import hashlib
from datetime import datetime
from typing import Any

from .controlled_comparison import canonical_sha256
from .qualification_outcome_sensitive_confirmatory_roster_assignment_rebind import (
    PLAN_SCHEMA,
    REQUIRED_REVIEW_CHECKS,
)


REVIEW_REQUEST_SCHEMA = (
    "j1-qualification-outcome-sensitive-confirmatory-"
    "roster-assignment-review-request:v1"
)
REVIEW_DECISION_SCHEMA = (
    "j1-qualification-outcome-sensitive-confirmatory-"
    "roster-assignment-review-decision:v1"
)
REQUEST_STATUS = "awaiting_independent_operator_decision"
APPROVAL_DECISION = "approve_outcome_sensitive_confirmatory_roster_assignment_rebind"
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
    "independent_from_candidate_authoring_required": True,
    "human_review_required": True,
}
EXECUTION_BOUNDARY = {
    "review_request_preparation_only": True,
    "roster_promoted": False,
    "assignment_promoted": False,
    "r4_reanalysis_performed": False,
    "mentor_advice_rebound_or_signed": False,
    "infrastructure_rebound": False,
    "container_created_or_started": False,
    "provider_credential_read": False,
    "provider_api_call_performed": False,
    "model_invocation_performed": False,
    "agent_execution_performed": False,
    "backend_fact_append_performed": False,
    "ledger_append_performed": False,
    "execution_authorization_issued_or_consumed": False,
    "effectiveness_or_causal_claim_authorized": False,
    "si13_maturity_upgrade_authorized": False,
}


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
    """Bind owner approval and immutable candidates into a review request."""
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
        "required_checklist": sorted(REQUIRED_REVIEW_CHECKS),
        "allowed_decisions": sorted(ALLOWED_DECISIONS),
        "independence_requirements": copy.deepcopy(INDEPENDENCE_REQUIREMENTS),
        "signer_contract": copy.deepcopy(SIGNER_CONTRACT),
        "implementation": copy.deepcopy(implementation),
        "execution_boundary": copy.deepcopy(EXECUTION_BOUNDARY),
    }
    request["request_sha256"] = canonical_sha256(request)
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
        raise ValueError(f"confirmatory rebind review request invalid: {failures}")
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
    """Validate the complete no-signature review handoff contract."""
    request = value if isinstance(value, dict) else {}
    failures: list[str] = []
    expected_fields = {
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
    }
    _require(
        set(request) == expected_fields,
        "confirmatory_rebind_review_request_fields_invalid",
        failures,
    )
    _require(
        request.get("schema_version") == REVIEW_REQUEST_SCHEMA
        and request.get("status") == REQUEST_STATUS
        and _text(request.get("request_id"))
        and _rfc3339(request.get("created_at")),
        "confirmatory_rebind_review_request_identity_invalid",
        failures,
    )
    plan_body = {key: item for key, item in plan.items() if key != "plan_sha256"}
    _require(
        plan.get("schema_version") == PLAN_SCHEMA
        and plan.get("status") == "review_required"
        and plan.get("plan_sha256") == canonical_sha256(plan_body),
        "confirmatory_rebind_review_plan_invalid",
        failures,
    )
    expected_candidates = {
        "rebind_plan": _artifact(expected_plan_path, plan_bytes, plan["plan_sha256"]),
        "candidate_preflight": _artifact(
            expected_candidate_preflight_path,
            candidate_preflight_bytes,
            candidate_preflight["report_sha256"],
        ),
        "rebound_roster": plan["candidate_artifacts"]["rebound_roster"],
        "rebound_assignment": plan["candidate_artifacts"]["rebound_assignment"],
    }
    _require(
        request.get("candidate_artifacts") == expected_candidates,
        "confirmatory_rebind_review_candidate_binding_invalid",
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
        "confirmatory_rebind_review_owner_authorization_invalid",
        failures,
    )
    expected_scope = {
        "rebind_id": plan["rebind_id"],
        "plan_artifact_sha256": hashlib.sha256(plan_bytes).hexdigest(),
        "plan_canonical_sha256": plan["plan_sha256"],
        "source_binding": plan["source_binding"],
        "inventory": plan["inventory"],
        "candidate_readiness": plan["readiness"],
        "remaining_gate_sequence": plan["remaining_gate_sequence"],
    }
    _require(
        request.get("review_scope") == expected_scope,
        "confirmatory_rebind_review_scope_invalid",
        failures,
    )
    _require(
        request.get("required_checklist") == sorted(REQUIRED_REVIEW_CHECKS),
        "confirmatory_rebind_review_checklist_invalid",
        failures,
    )
    _require(
        request.get("allowed_decisions") == sorted(ALLOWED_DECISIONS)
        and request.get("independence_requirements") == INDEPENDENCE_REQUIREMENTS
        and request.get("signer_contract") == SIGNER_CONTRACT,
        "confirmatory_rebind_review_governance_invalid",
        failures,
    )
    _require(
        request.get("implementation") == expected_implementation,
        "confirmatory_rebind_review_implementation_invalid",
        failures,
    )
    _require(
        request.get("execution_boundary") == EXECUTION_BOUNDARY,
        "confirmatory_rebind_review_boundary_invalid",
        failures,
    )
    body = {key: item for key, item in request.items() if key != "request_sha256"}
    _require(
        request.get("request_sha256") == canonical_sha256(body),
        "confirmatory_rebind_review_request_hash_invalid",
        failures,
    )
    return list(dict.fromkeys(failures))


def build_review_decision_template(
    request: dict[str, Any],
) -> dict[str, Any]:
    """Return an intentionally incomplete independent-review decision."""
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
        "checklist": {check: False for check in sorted(REQUIRED_REVIEW_CHECKS)},
    }


def approval_review_declaration(
    request: dict[str, Any],
    request_artifact_sha256: str,
) -> str:
    """Return the exact declaration required from an independent reviewer."""
    return (
        "I have independently reviewed J1-D outcome-sensitive confirmatory "
        "roster/assignment rebind review request raw SHA-256 "
        f"{request_artifact_sha256}, canonical SHA-256 "
        f"{request['request_sha256']} and choose {APPROVAL_DECISION}. I confirm "
        "all 10 required checklist items, disclose all conflicts, affirm that I "
        "am independent from candidate authoring and have completed human "
        "review. I acknowledge that this approval permits only copy-on-write "
        "promotion of the prospective confirmatory roster and assignment "
        "candidates. It does not reanalyze r4, reassign or substitute any "
        "participant, sign or rebind confirmatory mentor advice, rebind "
        "infrastructure, create or start a container, read a provider credential, "
        "call a provider or model, execute any Agent or task, append Backend "
        "Facts, append the Ledger, issue or consume an execution authorization, "
        "authorize an effectiveness or causal claim, or upgrade SI-13 maturity."
    )


def _artifact(
    path: str,
    raw: bytes,
    canonical_sha256_value: str,
) -> dict[str, str]:
    return {
        "path": path,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "canonical_sha256": canonical_sha256_value,
    }


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _rfc3339(value: Any) -> bool:
    if not _text(value):
        return False
    try:
        datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return False
    return True


def _require(condition: bool, reason: str, failures: list[str]) -> None:
    if not condition:
        failures.append(reason)
