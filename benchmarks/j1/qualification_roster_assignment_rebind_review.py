"""Independent-review handoff contract for J1-D roster/assignment rebind."""

from __future__ import annotations

import copy
import hashlib
from datetime import datetime
from typing import Any

from .controlled_comparison import canonical_sha256
from .qualification_roster_assignment_rebind import PLAN_SCHEMA


REVIEW_REQUEST_SCHEMA = "j1-qualification-roster-assignment-rebind-review-request:v1"
REVIEW_DECISION_SCHEMA = "j1-qualification-roster-assignment-rebind-review-decision:v1"
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
