"""Independent-review handoff contract for J1-D infrastructure rebind."""

from __future__ import annotations

import copy
import hashlib
from datetime import datetime
from typing import Any

from .controlled_comparison import canonical_sha256
from .qualification_infrastructure_rebind import (
    PLAN_SCHEMA,
    REQUIRED_REVIEW_CHECKS,
)


REQUEST_SCHEMA = "j1-qualification-infrastructure-rebind-review-request:v1"
DECISION_SCHEMA = "j1-qualification-infrastructure-rebind-review-decision:v1"
REQUEST_STATUS = "awaiting_independent_operator_decision"
ALLOWED_DECISIONS = {
    "approve_infrastructure_rebind",
    "request_changes",
    "reject",
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
    "independent_from_runner_and_candidate_authoring_required": True,
    "human_review_required": True,
}
EXECUTION_BOUNDARY = {
    "review_handoff_only": True,
    "runner_image_built": True,
    "infrastructure_promoted": False,
    "participant_container_created": False,
    "participant_container_started": False,
    "provider_admission_refreshed": False,
    "provider_api_call_performed": False,
    "model_invocation_performed": False,
    "agent_execution_performed": False,
    "backend_fact_append_performed": False,
    "ledger_append_performed": False,
    "execution_authorization_issued_or_consumed": False,
}


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
    runner_manifest_path: str,
    runner_manifest: dict[str, Any],
    runner_manifest_raw: bytes,
    runner_gate_path: str,
    runner_gate: dict[str, Any],
    runner_gate_raw: bytes,
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
            "runner_image_manifest": _artifact(
                runner_manifest_path,
                runner_manifest_raw,
                runner_manifest["manifest_sha256"],
            ),
            "runner_image_gate": _artifact(
                runner_gate_path, runner_gate_raw, runner_gate["report_sha256"]
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
            "plan_artifact_sha256": hashlib.sha256(plan_raw).hexdigest(),
            "plan_canonical_sha256": plan["plan_sha256"],
            "runner_image_manifest_sha256": runner_manifest["manifest_sha256"],
            "runner_image_id": runner_manifest["image"]["image_id"],
            "inventory": copy.deepcopy(plan["inventory"]),
            "source_container_state": copy.deepcopy(plan["source_container_state"]),
            "target_config_set_sha256": canonical_sha256(
                sorted(
                    item["target_isolation"]["container_config_sha256"]
                    for item in plan["isolations"]
                )
            ),
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
        plan_raw=plan_raw,
        preflight=preflight,
        preflight_raw=preflight_raw,
        runner_manifest=runner_manifest,
        runner_manifest_raw=runner_manifest_raw,
        runner_gate=runner_gate,
        runner_gate_raw=runner_gate_raw,
        expected_authorization_statement_sha256=authorization_statement_sha256,
        expected_implementation=implementation,
    )
    if failures:
        raise ValueError(f"infrastructure rebind review request invalid: {failures}")
    return request


def validate_review_request(
    value: Any,
    *,
    plan: dict[str, Any],
    plan_raw: bytes,
    preflight: dict[str, Any],
    preflight_raw: bytes,
    runner_manifest: dict[str, Any],
    runner_manifest_raw: bytes,
    runner_gate: dict[str, Any],
    runner_gate_raw: bytes,
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
        "infrastructure_review_request_fields_invalid",
        failures,
    )
    _require(
        request.get("schema_version") == REQUEST_SCHEMA,
        "infrastructure_review_request_schema_invalid",
        failures,
    )
    _require(
        _text(request.get("request_id"))
        and request.get("status") == REQUEST_STATUS
        and _rfc3339(request.get("created_at")),
        "infrastructure_review_request_identity_invalid",
        failures,
    )
    _require(
        plan.get("schema_version") == PLAN_SCHEMA
        and plan.get("status") == "review_required"
        and plan.get("plan_sha256")
        == canonical_sha256(
            {key: item for key, item in plan.items() if key != "plan_sha256"}
        ),
        "infrastructure_review_plan_invalid",
        failures,
    )
    artifacts = request.get("candidate_artifacts")
    artifacts = artifacts if isinstance(artifacts, dict) else {}
    _require(
        artifacts
        == {
            "infrastructure_rebind_plan": _artifact(
                artifacts.get("infrastructure_rebind_plan", {}).get("path", ""),
                plan_raw,
                plan["plan_sha256"],
            ),
            "candidate_preflight": _artifact(
                artifacts.get("candidate_preflight", {}).get("path", ""),
                preflight_raw,
                preflight["report_sha256"],
            ),
            "runner_image_manifest": _artifact(
                artifacts.get("runner_image_manifest", {}).get("path", ""),
                runner_manifest_raw,
                runner_manifest["manifest_sha256"],
            ),
            "runner_image_gate": _artifact(
                artifacts.get("runner_image_gate", {}).get("path", ""),
                runner_gate_raw,
                runner_gate["report_sha256"],
            ),
        },
        "infrastructure_review_candidate_binding_invalid",
        failures,
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
        "infrastructure_review_owner_authorization_invalid",
        failures,
    )
    _require(
        request.get("review_scope")
        == {
            "rebind_id": plan["rebind_id"],
            "plan_artifact_sha256": hashlib.sha256(plan_raw).hexdigest(),
            "plan_canonical_sha256": plan["plan_sha256"],
            "runner_image_manifest_sha256": runner_manifest["manifest_sha256"],
            "runner_image_id": runner_manifest["image"]["image_id"],
            "inventory": plan["inventory"],
            "source_container_state": plan["source_container_state"],
            "target_config_set_sha256": canonical_sha256(
                sorted(
                    item["target_isolation"]["container_config_sha256"]
                    for item in plan["isolations"]
                )
            ),
        },
        "infrastructure_review_scope_invalid",
        failures,
    )
    _require(
        request.get("required_checklist") == sorted(REQUIRED_REVIEW_CHECKS),
        "infrastructure_review_checklist_invalid",
        failures,
    )
    _require(
        request.get("allowed_decisions") == sorted(ALLOWED_DECISIONS),
        "infrastructure_review_decisions_invalid",
        failures,
    )
    _require(
        request.get("independence_requirements") == INDEPENDENCE_REQUIREMENTS,
        "infrastructure_review_independence_invalid",
        failures,
    )
    _require(
        request.get("signer_contract") == SIGNER_CONTRACT,
        "infrastructure_review_signer_contract_invalid",
        failures,
    )
    _require(
        request.get("implementation") == expected_implementation,
        "infrastructure_review_implementation_invalid",
        failures,
    )
    _require(
        request.get("execution_boundary") == EXECUTION_BOUNDARY,
        "infrastructure_review_execution_boundary_invalid",
        failures,
    )
    body = {key: item for key, item in request.items() if key != "request_sha256"}
    _require(
        request.get("request_sha256") == canonical_sha256(body),
        "infrastructure_review_request_hash_invalid",
        failures,
    )
    return list(dict.fromkeys(failures))


def build_review_decision_template(request: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": DECISION_SCHEMA,
        "review_id": None,
        "review_request_sha256": request["request_sha256"],
        "decision": None,
        "reviewed_at": None,
        "reviewer": {
            "did": None,
            "public_key_hex": None,
            "credential_version": None,
            "signer_kind": None,
            "custody_provenance_sha256": None,
            "signer_attestation_sha256": None,
        },
        "independence": {
            "conflicts_disclosed": False,
            "independent_from_runner_and_candidate_authoring": False,
            "human_review_completed": False,
        },
        "checklist": {check: False for check in sorted(REQUIRED_REVIEW_CHECKS)},
    }


def approval_review_declaration(request: dict[str, Any]) -> str:
    return (
        "I have independently reviewed J1-D infrastructure rebind review request "
        f"{request['request_sha256']} and choose approve_infrastructure_rebind. "
        "I confirm all 8 required checklist items, disclose all conflicts, affirm "
        "that I am independent from runner and candidate authoring and have completed "
        "human review, and acknowledge that this approval permits only copy-on-write "
        "infrastructure promotion. It does not create or start any participant "
        "container, refresh provider admission, authorize provider or model calls, "
        "execute any Agent, append Backend Facts, append the Ledger, or issue or "
        "consume an execution authorization."
    )


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


def _require(condition: bool, code: str, failures: list[str]) -> None:
    if not condition and code not in failures:
        failures.append(code)
