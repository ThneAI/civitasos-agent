"""Independent-review handoff contracts for confirmatory infrastructure."""

from __future__ import annotations

import copy
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Any

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
