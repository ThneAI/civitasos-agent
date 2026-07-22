"""Independent-review handoff contract for a J1-D cohort migration plan."""

from __future__ import annotations

import copy
import hashlib
from datetime import datetime
from typing import Any

from .controlled_comparison import canonical_sha256
from .qualification_cohort_migration import SCHEMA as MIGRATION_SCHEMA


REVIEW_REQUEST_SCHEMA = "j1-qualification-cohort-migration-review-request:v1"
REVIEW_DECISION_SCHEMA = "j1-qualification-cohort-migration-review-decision:v1"
REQUEST_STATUS = "awaiting_independent_operator_decision"
ALLOWED_DECISIONS = {
    "approve_protocol_design_amendment_materials",
    "request_changes",
    "reject",
}
REQUIRED_CHECKS = {
    "reviewed_source_chain_verified",
    "cohort_invariant_semantics_reviewed",
    "mentor_control_event_scripts_reviewed",
    "base_immutability_reviewed",
    "artifact_reuse_and_rebind_matrix_reviewed",
    "participant_consent_extension_requirement_reviewed",
    "required_gate_sequence_reviewed",
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
    "independent_from_plan_authoring_required": True,
    "human_review_required": True,
}
EXECUTION_BOUNDARY = {
    "review_request_preparation_only": True,
    "protocol_design_amendment_performed": False,
    "participant_consent_migrated": False,
    "artifact_promoted": False,
    "container_created": False,
    "container_started": False,
    "provider_api_call_performed": False,
    "model_invocation_performed": False,
    "agent_execution_performed": False,
    "backend_fact_append_performed": False,
    "ledger_append_performed": False,
}


def build_migration_review_request(
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
    request = {
        "schema_version": REVIEW_REQUEST_SCHEMA,
        "request_id": request_id,
        "status": REQUEST_STATUS,
        "created_at": created_at,
        "candidate_artifacts": {
            "migration_plan": _artifact(plan_path, plan_bytes),
            "candidate_preflight": _artifact(
                candidate_preflight_path, candidate_preflight_bytes
            ),
        },
        "owner_authorization": {
            "authorization_id": authorization_id,
            "authorized_at": authorized_at,
            "statement_sha256": authorization_statement_sha256,
            "scope": "independent_review_only",
        },
        "review_scope": {
            "amendment_id": plan.get("amendment_id"),
            "plan_artifact_sha256": hashlib.sha256(plan_bytes).hexdigest(),
            "plan_canonical_sha256": plan.get("plan_sha256"),
            "source_binding": copy.deepcopy(plan.get("source_binding")),
            "completed_prerequisites": copy.deepcopy(
                plan.get("completed_prerequisites")
            ),
            "blockers": copy.deepcopy(plan.get("blockers")),
            "inventory": copy.deepcopy(plan.get("inventory")),
        },
        "required_checklist": sorted(REQUIRED_CHECKS),
        "allowed_decisions": sorted(ALLOWED_DECISIONS),
        "independence_requirements": copy.deepcopy(INDEPENDENCE_REQUIREMENTS),
        "signer_contract": copy.deepcopy(SIGNER_CONTRACT),
        "implementation": implementation,
        "execution_boundary": copy.deepcopy(EXECUTION_BOUNDARY),
    }
    request["request_sha256"] = canonical_sha256(request)
    failures = validate_migration_review_request(
        request,
        plan=plan,
        plan_bytes=plan_bytes,
        candidate_preflight=candidate_preflight,
        candidate_preflight_bytes=candidate_preflight_bytes,
        expected_authorization_statement_sha256=authorization_statement_sha256,
        expected_implementation=implementation,
    )
    if failures:
        raise ValueError(f"cohort migration review request invalid: {failures}")
    return request


def validate_migration_review_request(
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
        "migration_review_request_fields_invalid",
        failures,
    )
    _require(
        request.get("schema_version") == REVIEW_REQUEST_SCHEMA,
        "migration_review_request_schema_invalid",
        failures,
    )
    _require(
        request.get("status") == REQUEST_STATUS,
        "migration_review_request_status_invalid",
        failures,
    )
    _require(_text(request.get("request_id")), "migration_review_request_id_invalid", failures)
    _require(_rfc3339(request.get("created_at")), "migration_review_request_time_invalid", failures)
    _require(
        plan.get("schema_version") == MIGRATION_SCHEMA
        and plan.get("status") == "review_required"
        and plan.get("plan_sha256")
        == canonical_sha256(
            {key: item for key, item in plan.items() if key != "plan_sha256"}
        ),
        "migration_review_plan_invalid",
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
        "migration_review_owner_authorization_invalid",
        failures,
    )
    _require(
        request.get("required_checklist") == sorted(REQUIRED_CHECKS),
        "migration_review_checklist_invalid",
        failures,
    )
    _require(
        request.get("allowed_decisions") == sorted(ALLOWED_DECISIONS),
        "migration_review_decisions_invalid",
        failures,
    )
    _require(
        request.get("independence_requirements") == INDEPENDENCE_REQUIREMENTS,
        "migration_review_independence_invalid",
        failures,
    )
    _require(
        request.get("signer_contract") == SIGNER_CONTRACT,
        "migration_review_signer_contract_invalid",
        failures,
    )
    _require(
        request.get("implementation") == expected_implementation,
        "migration_review_implementation_invalid",
        failures,
    )
    _require(
        request.get("execution_boundary") == EXECUTION_BOUNDARY,
        "migration_review_boundary_invalid",
        failures,
    )
    body = {key: item for key, item in request.items() if key != "request_sha256"}
    _require(
        request.get("request_sha256") == canonical_sha256(body),
        "migration_review_request_hash_invalid",
        failures,
    )
    return list(dict.fromkeys(failures))


def build_migration_review_decision_template(
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
            "independent_from_plan_authoring": False,
            "human_review_completed": False,
        },
        "checklist": {check: False for check in sorted(REQUIRED_CHECKS)},
    }


def _validate_candidate_binding(
    request: dict[str, Any],
    *,
    plan: dict[str, Any],
    plan_bytes: bytes,
    candidate_preflight: dict[str, Any],
    candidate_preflight_bytes: bytes,
    failures: list[str],
) -> None:
    artifacts = request.get("candidate_artifacts")
    artifacts = artifacts if isinstance(artifacts, dict) else {}
    _require(
        set(artifacts) == {"migration_plan", "candidate_preflight"}
        and artifacts.get("migration_plan", {}).get("sha256")
        == hashlib.sha256(plan_bytes).hexdigest()
        and artifacts.get("candidate_preflight", {}).get("sha256")
        == hashlib.sha256(candidate_preflight_bytes).hexdigest(),
        "migration_review_candidate_artifacts_invalid",
        failures,
    )
    expected_scope = {
        "amendment_id": plan.get("amendment_id"),
        "plan_artifact_sha256": hashlib.sha256(plan_bytes).hexdigest(),
        "plan_canonical_sha256": plan.get("plan_sha256"),
        "source_binding": plan.get("source_binding"),
        "completed_prerequisites": plan.get("completed_prerequisites"),
        "blockers": plan.get("blockers"),
        "inventory": plan.get("inventory"),
    }
    _require(
        request.get("review_scope") == expected_scope,
        "migration_review_scope_invalid",
        failures,
    )
    expected_statement_sha256 = request.get("owner_authorization", {}).get(
        "statement_sha256"
    )
    _require(
        candidate_preflight.get("schema_version")
        == "j1-qualification-cohort-migration-preflight:v2"
        and candidate_preflight.get("passed") is True
        and candidate_preflight.get("state")
        == "cohort_migration_plan_prepared_independent_review_required"
        and candidate_preflight.get("plan", {}).get("sha256")
        == hashlib.sha256(plan_bytes).hexdigest()
        and candidate_preflight.get("plan", {}).get("canonical_sha256")
        == plan.get("plan_sha256")
        and candidate_preflight.get("approval_request", {}).get("statement_sha256")
        == expected_statement_sha256
        and candidate_preflight.get("approval_request", {}).get(
            "protocol_design_amendment_independent_review_required"
        )
        is True
        and candidate_preflight.get("blockers") == plan.get("blockers")
        and candidate_preflight.get("readiness") == plan.get("readiness")
        and candidate_preflight.get("execution_boundary")
        == plan.get("execution_boundary"),
        "migration_review_candidate_preflight_invalid",
        failures,
    )


def _artifact(path: str, content: bytes) -> dict[str, str]:
    return {"path": path, "sha256": hashlib.sha256(content).hexdigest()}


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
