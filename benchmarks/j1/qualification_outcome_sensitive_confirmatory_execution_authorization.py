"""Authorization boundary for prospective confirmatory J1-D execution."""

from __future__ import annotations

import copy
import hashlib
import json
from datetime import datetime, timedelta
from typing import Any, Protocol

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from .controlled_comparison import canonical_sha256
from .qualification_outcome_sensitive_confirmatory_execution_preflight import (
    PLAN_SCHEMA,
    TTL_SECONDS,
    validate_confirmatory_execution_plan,
)


AUTH_SCHEMA = (
    "j1-qualification-outcome-sensitive-prospective-confirmatory-"
    "execution-authorization:v1"
)
GATE_SCHEMA = (
    "j1-qualification-outcome-sensitive-prospective-confirmatory-"
    "execution-authorization-gate:v1"
)
CLAIM_PREFLIGHT_SCHEMA = (
    "j1-qualification-outcome-sensitive-prospective-confirmatory-"
    "claim-preflight:v1"
)
AUTH_BOUNDARY = {
    "prospective_confirmatory_authorization_issuance_only": True,
    "single_use_authorization_issued": True,
    "single_use_authorization_consumed": False,
    "atomic_claim_created": False,
    "participant_container_started": False,
    "provider_credential_read": False,
    "provider_api_call_performed": False,
    "model_invocation_performed": False,
    "agent_or_task_execution_performed": False,
    "participant_signature_performed": False,
    "backend_fact_append_performed": False,
    "ledger_append_performed": False,
    "prior_run_reanalysis_performed": False,
    "advice_adherence_inferred": False,
    "effectiveness_or_causal_claim_authorized": False,
    "si13_maturity_upgrade_authorized": False,
}
CLAIM_PREFLIGHT_BOUNDARY = {
    **AUTH_BOUNDARY,
    "prospective_confirmatory_authorization_issuance_only": False,
    "prospective_confirmatory_claim_preflight_only": True,
}


class AuthorizationSigner(Protocol):
    @property
    def public_key_hex(self) -> str: ...

    def sign(self, message: bytes) -> bytes: ...


def build_confirmatory_authorization(
    *,
    authorization_id: str,
    owner_authorization_id: str,
    owner_statement_sha256: str,
    issued_at: str,
    plan_ref: dict[str, str],
    preflight_ref: dict[str, str],
    plan: dict[str, Any],
    execution_manifest_sha256: str,
    reviewer: dict[str, Any],
    reviewer_profile_sha256: str,
    implementation: dict[str, str],
    signer: AuthorizationSigner,
) -> dict[str, Any]:
    issued = _timestamp(issued_at)
    if issued is None:
        raise ValueError("confirmatory authorization issued_at invalid")
    value = {
        "schema_version": AUTH_SCHEMA,
        "authorization_id": authorization_id,
        "run_id": plan["run_id"],
        "decision": "authorize_once",
        "issued_at": issued.isoformat(),
        "valid_from": issued.isoformat(),
        "valid_until": (issued + timedelta(seconds=TTL_SECONDS)).isoformat(),
        "ttl_seconds": TTL_SECONDS,
        "owner_authorization": {
            "authorization_id": owner_authorization_id,
            "statement_sha256": owner_statement_sha256,
            "source": "interactive_owner_operator_approval",
            "scope": "authorization_issuance_only",
        },
        "source_binding": {
            "plan": copy.deepcopy(plan_ref),
            "preflight": copy.deepcopy(preflight_ref),
            "plan_sha256": plan["plan_sha256"],
            "source_artifact_set_sha256": canonical_sha256(
                plan["source_artifacts"]
            ),
        },
        "binding": copy.deepcopy(plan["binding"]),
        "confirmatory_inference_contract": copy.deepcopy(
            plan["confirmatory_inference_contract"]
        ),
        "material_bindings": copy.deepcopy(plan["material_bindings"]),
        "execution_manifest_sha256": execution_manifest_sha256,
        "execution_scope": copy.deepcopy(plan["execution_scope"]),
        "budget": copy.deepcopy(plan["budget"]),
        "controls": copy.deepcopy(plan["controls"]),
        "reviewer": {
            "did": reviewer["did"],
            "public_key_hex": reviewer["public_key_hex"],
            "credential_version": reviewer["credential_version"],
            "signer_kind": reviewer["signer_kind"],
            "identity_profile_sha256": reviewer_profile_sha256,
        },
        "implementation": copy.deepcopy(implementation),
        "execution_boundary": copy.deepcopy(AUTH_BOUNDARY),
    }
    payload = _payload(value)
    signature = signer.sign(payload)
    if len(signature) != 64:
        raise ValueError("confirmatory authorization signature must be 64 bytes")
    value["signature"] = {
        "algorithm": "ed25519",
        "signed_payload_sha256": hashlib.sha256(payload).hexdigest(),
        "signature_hex": signature.hex(),
    }
    failures = validate_confirmatory_authorization(
        value,
        plan_ref=plan_ref,
        preflight_ref=preflight_ref,
        plan=plan,
        expected_owner_authorization_id=owner_authorization_id,
        expected_owner_statement_sha256=owner_statement_sha256,
        expected_execution_manifest_sha256=execution_manifest_sha256,
        expected_reviewer=reviewer,
        expected_reviewer_profile_sha256=reviewer_profile_sha256,
        expected_implementation=implementation,
        require_current=False,
    )
    if failures:
        raise ValueError(f"confirmatory authorization invalid: {failures}")
    return value


def validate_confirmatory_authorization(
    value: Any,
    *,
    plan_ref: dict[str, str],
    preflight_ref: dict[str, str],
    plan: dict[str, Any],
    expected_owner_authorization_id: str,
    expected_owner_statement_sha256: str,
    expected_execution_manifest_sha256: str,
    expected_reviewer: dict[str, Any],
    expected_reviewer_profile_sha256: str,
    expected_implementation: dict[str, str],
    require_current: bool,
    now: datetime | None = None,
) -> list[str]:
    authorization = value if isinstance(value, dict) else {}
    failures: list[str] = []
    issued = _timestamp(authorization.get("issued_at"))
    valid_from = _timestamp(authorization.get("valid_from"))
    valid_until = _timestamp(authorization.get("valid_until"))
    if not (
        authorization.get("schema_version") == AUTH_SCHEMA
        and authorization.get("run_id") == plan.get("run_id")
        and authorization.get("decision") == "authorize_once"
        and issued is not None
        and valid_from == issued
        and valid_until == issued + timedelta(seconds=TTL_SECONDS)
        and authorization.get("ttl_seconds") == TTL_SECONDS
    ):
        failures.append("confirmatory_authorization_identity_or_validity_invalid")
    if require_current and valid_from is not None and valid_until is not None:
        current = now or datetime.now(valid_from.tzinfo)
        if not valid_from <= current < valid_until:
            failures.append("confirmatory_authorization_not_current")
    if not (
        authorization.get("owner_authorization")
        == {
            "authorization_id": expected_owner_authorization_id,
            "statement_sha256": expected_owner_statement_sha256,
            "source": "interactive_owner_operator_approval",
            "scope": "authorization_issuance_only",
        }
        and authorization.get("source_binding")
        == {
            "plan": plan_ref,
            "preflight": preflight_ref,
            "plan_sha256": plan.get("plan_sha256"),
            "source_artifact_set_sha256": canonical_sha256(
                plan.get("source_artifacts", {})
            ),
        }
        and authorization.get("binding") == plan.get("binding")
        and authorization.get("confirmatory_inference_contract")
        == plan.get("confirmatory_inference_contract")
        and authorization.get("material_bindings")
        == plan.get("material_bindings")
        and authorization.get("execution_manifest_sha256")
        == expected_execution_manifest_sha256
        and authorization.get("execution_scope") == plan.get("execution_scope")
        and authorization.get("budget") == plan.get("budget")
        and authorization.get("controls") == plan.get("controls")
    ):
        failures.append("confirmatory_authorization_scope_or_binding_invalid")
    expected_bound_reviewer = {
        "did": expected_reviewer.get("did"),
        "public_key_hex": expected_reviewer.get("public_key_hex"),
        "credential_version": expected_reviewer.get("credential_version"),
        "signer_kind": expected_reviewer.get("signer_kind"),
        "identity_profile_sha256": expected_reviewer_profile_sha256,
    }
    if not (
        authorization.get("reviewer") == expected_bound_reviewer
        and authorization.get("implementation") == expected_implementation
        and authorization.get("execution_boundary") == AUTH_BOUNDARY
    ):
        failures.append("confirmatory_authorization_reviewer_or_boundary_invalid")
    signature = authorization.get("signature", {})
    unsigned = {
        key: item for key, item in authorization.items() if key != "signature"
    }
    payload = _payload(unsigned)
    try:
        signature_bytes = bytes.fromhex(str(signature.get("signature_hex", "")))
        VerifyKey(bytes.fromhex(expected_reviewer["public_key_hex"])).verify(
            payload,
            signature_bytes,
        )
    except (BadSignatureError, ValueError):
        failures.append("confirmatory_authorization_signature_invalid")
    if not (
        signature.get("algorithm") == "ed25519"
        and signature.get("signed_payload_sha256")
        == hashlib.sha256(payload).hexdigest()
    ):
        failures.append("confirmatory_authorization_signature_binding_invalid")
    return list(dict.fromkeys(failures))


def build_confirmatory_issuance_gate(
    *,
    checked_at: str,
    authorization_ref: dict[str, str],
    authorization: dict[str, Any],
    plan_ref: dict[str, str],
    preflight_ref: dict[str, str],
    inventory_snapshot: dict[str, int],
) -> dict[str, Any]:
    value = {
        "schema_version": GATE_SCHEMA,
        "passed": True,
        "failure_reasons": [],
        "state": (
            "prospective_confirmatory_authorization_issued_"
            "claim_preflight_required"
        ),
        "checked_at": checked_at,
        "run_id": authorization["run_id"],
        "plan": copy.deepcopy(plan_ref),
        "preflight": copy.deepcopy(preflight_ref),
        "authorization": copy.deepcopy(authorization_ref),
        "inventory_snapshot": copy.deepcopy(inventory_snapshot),
        "checks": {
            "authorization_signature_valid": True,
            "authorization_current": True,
            "owner_statement_bound": True,
            "exact_480_task_manifest_bound": True,
            "exact_paired_method_and_holm_order_bound": True,
            "private_material_binding_replayed": True,
            "runtime_inventory_40_created_0_running": True,
            "authorization_unconsumed": True,
            "future_execution_paths_absent": True,
            "prior_run_reanalysis_and_adherence_inference_forbidden": True,
            "no_execution_or_external_write_performed": True,
        },
        "readiness": {
            "single_use_authorization_issued": True,
            "single_use_authorization_current": True,
            "single_use_authorization_consumed": False,
            "controlled_experiment_execution_ready": False,
        },
        "execution_boundary": copy.deepcopy(AUTH_BOUNDARY),
    }
    value["report_sha256"] = canonical_sha256(value)
    return value


def build_confirmatory_claim_preflight(
    *,
    authorization_ref: dict[str, str],
    authorization: dict[str, Any],
    issuance_gate_ref: dict[str, str],
    claim_path: str,
    checked_at: str,
    inventory_snapshot: dict[str, int],
    implementation: dict[str, str],
) -> dict[str, Any]:
    statement = confirmatory_claim_authorization_statement(
        authorization_ref=authorization_ref,
        issuance_gate_ref=issuance_gate_ref,
        authorization=authorization,
    )
    value = {
        "schema_version": CLAIM_PREFLIGHT_SCHEMA,
        "run_id": authorization["run_id"],
        "state": (
            "prospective_confirmatory_claim_preflight_passed_"
            "owner_authorization_required"
        ),
        "checked_at": checked_at,
        "source_binding": {
            "authorization": copy.deepcopy(authorization_ref),
            "issuance_gate": copy.deepcopy(issuance_gate_ref),
        },
        "claim_path": claim_path,
        "inventory_snapshot": copy.deepcopy(inventory_snapshot),
        "binding": copy.deepcopy(authorization["binding"]),
        "confirmatory_inference_contract": copy.deepcopy(
            authorization["confirmatory_inference_contract"]
        ),
        "material_bindings": copy.deepcopy(authorization["material_bindings"]),
        "execution_manifest_sha256": authorization[
            "execution_manifest_sha256"
        ],
        "execution_scope": copy.deepcopy(authorization["execution_scope"]),
        "budget": copy.deepcopy(authorization["budget"]),
        "controls": copy.deepcopy(authorization["controls"]),
        "implementation": copy.deepcopy(implementation),
        "owner_authorization": {
            "required": True,
            "required_exact_statement": statement,
            "statement_sha256": hashlib.sha256(statement.encode()).hexdigest(),
        },
        "checks": {
            "authorization_signature_and_currency_verified": True,
            "authorization_unconsumed": True,
            "claim_path_absent": True,
            "exact_480_task_manifest_bound": True,
            "exact_paired_method_and_holm_order_bound": True,
            "private_material_binding_replayed": True,
            "runtime_inventory_40_created_0_running": True,
            "prior_run_reanalysis_and_adherence_inference_forbidden": True,
            "no_container_or_provider_effect_performed": True,
        },
        "readiness": {
            "owner_claim_authorization_required": True,
            "atomic_claim_created": False,
            "execution_started": False,
        },
        "execution_boundary": copy.deepcopy(CLAIM_PREFLIGHT_BOUNDARY),
    }
    value["preflight_sha256"] = canonical_sha256(value)
    return value


def confirmatory_claim_authorization_statement(
    *,
    authorization_ref: dict[str, str],
    issuance_gate_ref: dict[str, str],
    authorization: dict[str, Any],
) -> str:
    return (
        "I authorize exactly one create-exclusive atomic claim of J1-D "
        "prospective confirmatory authorization "
        f"{authorization['authorization_id']} raw SHA-256 "
        f"{authorization_ref['sha256']}, signed payload SHA-256 "
        f"{authorization_ref['canonical_sha256']}, issuance Gate canonical "
        f"SHA-256 {issuance_gate_ref['canonical_sha256']}, for run "
        f"{authorization['run_id']} and execution manifest "
        f"{authorization['execution_manifest_sha256']} and execution material "
        f"binding {authorization['material_bindings']['material_binding_sha256']}. "
        "After that claim validates, I authorize exactly one bounded execution "
        "covering 40 participants, 20 pairs, 480 task executions, 480 structured "
        "participant decisions, 480 direct behavior observations, and 480 provider "
        "calls using openai_compatible / deepseek-v4-pro at temperature 0. I "
        "acknowledge reservation of 1200000 tokens and 731040 USD microunits, an "
        "absolute protocol ceiling of 4000000 USD microunits, that the claim is "
        "irreversible, provider dispatch ambiguity must never be retried, hidden "
        "fixture ground truth must not be exposed to participants or the provider, "
        "the prospectively frozen one-sided exact 20-pair sign-flip tests over all "
        "1048576 assignments with exact rational p-values and primary-before-"
        "secondary Holm order, and that all 480 terminal task Evidence and all 20 "
        "complete pairs are required for confirmatory inference. I acknowledge that "
        "r4 remains immutable and may not be reanalyzed for a confirmatory claim, "
        "advice adherence remains unobserved and may not be inferred, and any "
        "claimed failure requires a new authorization and signed closeout. Backend "
        "Fact and Ledger append remain prohibited, and no effectiveness or causal "
        "claim or SI-13 maturity upgrade is authorized before signed evaluation and "
        "closeout."
    )


def validate_plan_for_confirmatory_authorization(plan: Any) -> list[str]:
    value = plan if isinstance(plan, dict) else {}
    if value.get("schema_version") != PLAN_SCHEMA:
        return ["confirmatory_authorization_plan_schema_invalid"]
    return validate_confirmatory_execution_plan(value)


def _payload(value: dict[str, Any]) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None
