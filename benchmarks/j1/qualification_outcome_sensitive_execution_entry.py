"""Atomic claim and entry Gate for outcome-sensitive J1-D execution."""

from __future__ import annotations

import copy
from datetime import datetime
from pathlib import Path
from typing import Any

from .controlled_comparison import canonical_sha256
from .qualification_outcome_sensitive_execution_authorization import AUTH_SCHEMA
from .qualification_outcome_sensitive_confirmatory_execution_authorization import (
    AUTH_SCHEMA as CONFIRMATORY_AUTH_SCHEMA,
)


CLAIM_SCHEMA = "j1-qualification-outcome-sensitive-execution-claim:v1"
CONFIRMATORY_CLAIM_SCHEMA = (
    "j1-qualification-outcome-sensitive-prospective-confirmatory-"
    "execution-claim:v1"
)
ENTRY_GATE_SCHEMA = (
    "j1-qualification-outcome-sensitive-execution-entry-gate:v1"
)
CONFIRMATORY_ENTRY_GATE_SCHEMA = (
    "j1-qualification-outcome-sensitive-prospective-confirmatory-"
    "execution-entry-gate:v1"
)
CLAIM_BOUNDARY = {
    "atomic_claim_create_exclusive": True,
    "single_use_authorization_consumed": True,
    "bounded_execution_entry_allowed": False,
    "participant_container_started": False,
    "provider_credential_read": False,
    "provider_api_call_performed": False,
    "model_invocation_performed": False,
    "participant_signature_performed": False,
    "backend_fact_append_performed": False,
    "ledger_append_performed": False,
    "signed_closeout_required": True,
    "effectiveness_claim_authorized": False,
    "si13_maturity_upgrade_authorized": False,
}
ENTRY_BOUNDARY = {
    **CLAIM_BOUNDARY,
    "bounded_execution_entry_allowed": True,
}
CONFIRMATORY_CLAIM_BOUNDARY = {
    **CLAIM_BOUNDARY,
    "prior_run_reanalysis_performed": False,
    "advice_adherence_inferred": False,
    "effectiveness_or_causal_claim_authorized": False,
}
CONFIRMATORY_ENTRY_BOUNDARY = {
    **CONFIRMATORY_CLAIM_BOUNDARY,
    "bounded_execution_entry_allowed": True,
}


def build_claim(
    *,
    claimed_at: str,
    claim_path: str,
    owner_authorization_id: str,
    owner_statement_sha256: str,
    authorization_ref: dict[str, str],
    issuance_gate_ref: dict[str, str],
    claim_preflight_ref: dict[str, str],
    authorization: dict[str, Any],
    claim_preflight: dict[str, Any],
    implementation: dict[str, str],
) -> dict[str, Any]:
    if _timestamp(claimed_at) is None:
        raise ValueError("outcome-sensitive claim timestamp invalid")
    authorization_schema = authorization.get("schema_version")
    if authorization_schema not in {AUTH_SCHEMA, CONFIRMATORY_AUTH_SCHEMA}:
        raise ValueError("outcome-sensitive claim authorization schema invalid")
    confirmatory = authorization_schema == CONFIRMATORY_AUTH_SCHEMA
    value = {
        "schema_version": (
            CONFIRMATORY_CLAIM_SCHEMA if confirmatory else CLAIM_SCHEMA
        ),
        "state": "authorization_claimed_execution_must_close_out",
        "claimed_at": claimed_at,
        "claim_path": str(Path(claim_path).resolve()),
        "authorization_id": authorization["authorization_id"],
        "run_id": authorization["run_id"],
        "owner_authorization": {
            "authorization_id": owner_authorization_id,
            "statement_sha256": owner_statement_sha256,
            "scope": "atomic_claim_and_bounded_execution",
        },
        "source_binding": {
            "authorization": copy.deepcopy(authorization_ref),
            "issuance_gate": copy.deepcopy(issuance_gate_ref),
            "claim_preflight": copy.deepcopy(claim_preflight_ref),
        },
        "execution_manifest_sha256": claim_preflight[
            "execution_manifest_sha256"
        ],
        "material_binding_sha256": authorization["material_bindings"][
            "material_binding_sha256"
        ],
        "execution_scope": copy.deepcopy(authorization["execution_scope"]),
        "budget": copy.deepcopy(authorization["budget"]),
        "controls": copy.deepcopy(authorization["controls"]),
        "single_use": True,
        "reusable": False,
        "implementation": copy.deepcopy(implementation),
        "execution_boundary": copy.deepcopy(
            CONFIRMATORY_CLAIM_BOUNDARY if confirmatory else CLAIM_BOUNDARY
        ),
    }
    if confirmatory:
        value["confirmatory_inference_contract"] = copy.deepcopy(
            authorization["confirmatory_inference_contract"]
        )
    value["claim_sha256"] = canonical_sha256(value)
    return value


def validate_claim(
    value: Any,
    *,
    claim_path: str,
    authorization_ref: dict[str, str],
    issuance_gate_ref: dict[str, str],
    claim_preflight_ref: dict[str, str],
    authorization: dict[str, Any],
    claim_preflight: dict[str, Any],
    owner_statement_sha256: str,
    expected_implementation: dict[str, str],
) -> list[str]:
    claim = value if isinstance(value, dict) else {}
    failures: list[str] = []
    confirmatory = authorization.get("schema_version") == CONFIRMATORY_AUTH_SCHEMA
    expected_schema = CONFIRMATORY_CLAIM_SCHEMA if confirmatory else CLAIM_SCHEMA
    expected_boundary = (
        CONFIRMATORY_CLAIM_BOUNDARY if confirmatory else CLAIM_BOUNDARY
    )
    if not (
        claim.get("schema_version") == expected_schema
        and claim.get("state")
        == "authorization_claimed_execution_must_close_out"
        and _timestamp(claim.get("claimed_at")) is not None
        and claim.get("claim_path") == str(Path(claim_path).resolve())
        and claim.get("authorization_id")
        == authorization.get("authorization_id")
        and claim.get("run_id") == authorization.get("run_id")
    ):
        failures.append("outcome_claim_identity_invalid")
    if claim.get("source_binding") != {
        "authorization": authorization_ref,
        "issuance_gate": issuance_gate_ref,
        "claim_preflight": claim_preflight_ref,
    }:
        failures.append("outcome_claim_source_binding_invalid")
    owner = claim.get("owner_authorization", {})
    if not (
        owner.get("statement_sha256") == owner_statement_sha256
        and owner.get("scope") == "atomic_claim_and_bounded_execution"
        and isinstance(owner.get("authorization_id"), str)
        and owner["authorization_id"]
    ):
        failures.append("outcome_claim_owner_authorization_invalid")
    if not (
        claim.get("execution_manifest_sha256")
        == claim_preflight.get("execution_manifest_sha256")
        and claim.get("material_binding_sha256")
        == authorization.get("material_bindings", {}).get(
            "material_binding_sha256"
        )
        == claim_preflight.get("material_bindings", {}).get(
            "material_binding_sha256"
        )
        and claim.get("execution_scope")
        == authorization.get("execution_scope")
        and claim.get("budget") == authorization.get("budget")
        and claim.get("controls") == authorization.get("controls")
        and claim.get("single_use") is True
        and claim.get("reusable") is False
        and claim.get("implementation") == expected_implementation
        and claim.get("execution_boundary") == expected_boundary
    ):
        failures.append("outcome_claim_scope_or_boundary_invalid")
    if confirmatory and claim.get("confirmatory_inference_contract") != (
        authorization.get("confirmatory_inference_contract")
    ):
        failures.append("confirmatory_claim_inference_contract_invalid")
    body = {
        key: item for key, item in claim.items() if key != "claim_sha256"
    }
    if claim.get("claim_sha256") != canonical_sha256(body):
        failures.append("outcome_claim_hash_invalid")
    return list(dict.fromkeys(failures))


def build_entry_gate(
    *,
    checked_at: str,
    claim_ref: dict[str, str],
    claim: dict[str, Any],
    inventory_snapshot: dict[str, int],
    execution_manifest_sha256: str,
) -> dict[str, Any]:
    if _timestamp(checked_at) is None:
        raise ValueError("outcome-sensitive entry Gate timestamp invalid")
    confirmatory = claim.get("schema_version") == CONFIRMATORY_CLAIM_SCHEMA
    value = {
        "schema_version": (
            CONFIRMATORY_ENTRY_GATE_SCHEMA if confirmatory else ENTRY_GATE_SCHEMA
        ),
        "passed": True,
        "failure_reasons": [],
        "state": "atomic_claim_validated_bounded_execution_entry_allowed",
        "checked_at": checked_at,
        "authorization_id": claim["authorization_id"],
        "run_id": claim["run_id"],
        "claim": copy.deepcopy(claim_ref),
        "inventory_snapshot": copy.deepcopy(inventory_snapshot),
        "execution_manifest_sha256": execution_manifest_sha256,
        "material_binding_sha256": claim["material_binding_sha256"],
        "checks": {
            "atomic_claim_reloaded_and_validated": True,
            "authorization_consumed_exactly_once": True,
            "execution_materials_preclaim_replayed": True,
            "forty_outcome_containers_still_created": True,
            "strict_outcome_runner_image_bound": True,
            "execution_and_post_run_roots_still_absent": True,
            "provider_credential_not_read": True,
            "participant_container_not_started": True,
            "fixture_ground_truth_not_projected": True,
            **(
                {
                    "exact_paired_method_and_holm_order_bound": True,
                    "all_480_terminal_evidence_and_20_pairs_required": True,
                    "prior_run_reanalysis_and_adherence_inference_forbidden": True,
                }
                if confirmatory
                else {}
            ),
        },
        "readiness": {
            "single_use_authorization_consumed": True,
            "bounded_execution_entry_allowed": True,
            "signed_closeout_required": True,
        },
        "execution_boundary": copy.deepcopy(
            CONFIRMATORY_ENTRY_BOUNDARY if confirmatory else ENTRY_BOUNDARY
        ),
    }
    if confirmatory:
        value["confirmatory_inference_contract"] = copy.deepcopy(
            claim["confirmatory_inference_contract"]
        )
    value["report_sha256"] = canonical_sha256(value)
    return value


def _timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else None
