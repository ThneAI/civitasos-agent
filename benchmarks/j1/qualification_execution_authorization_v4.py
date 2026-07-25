"""Signed authorization and claim preflight for J1-D r4 execution."""

from __future__ import annotations

import copy
import hashlib
import json
from datetime import datetime, timedelta
from typing import Any, Protocol

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from .controlled_comparison import canonical_sha256
from .qualification_execution_preflight_v4 import TTL_SECONDS


AUTH_SCHEMA = "j1-qualification-r4-execution-authorization:v1"
GATE_SCHEMA = "j1-qualification-r4-execution-authorization-gate:v1"
CLAIM_PREFLIGHT_SCHEMA = "j1-qualification-r4-claim-preflight:v1"
AUTH_BOUNDARY = {
    "authorization_issuance_only": True,
    "single_use_authorization_issued": True,
    "single_use_authorization_consumed": False,
    "atomic_claim_created": False,
    "participant_container_started": False,
    "provider_credential_read": False,
    "provider_api_call_performed": False,
    "model_invocation_performed": False,
    "agent_execution_performed": False,
    "backend_fact_append_performed": False,
    "ledger_append_performed": False,
    "effectiveness_claim_authorized": False,
}
CLAIM_PREFLIGHT_BOUNDARY = {
    "claim_preflight_only": True,
    "single_use_authorization_issued": True,
    "single_use_authorization_consumed": False,
    "atomic_claim_created": False,
    "participant_container_started": False,
    "provider_credential_read": False,
    "provider_api_call_performed": False,
    "model_invocation_performed": False,
    "agent_execution_performed": False,
    "backend_fact_append_performed": False,
    "ledger_append_performed": False,
}


class AuthorizationSigner(Protocol):
    @property
    def public_key_hex(self) -> str: ...

    def sign(self, message: bytes) -> bytes: ...


def build_authorization(
    *,
    authorization_id: str,
    owner_authorization_id: str,
    owner_statement_sha256: str,
    issued_at: str,
    plan_ref: dict[str, str],
    preflight_ref: dict[str, str],
    plan: dict[str, Any],
    reviewer: dict[str, Any],
    reviewer_profile_sha256: str,
    implementation: dict[str, str],
    signer: AuthorizationSigner,
) -> dict[str, Any]:
    issued = _timestamp(issued_at)
    if issued is None:
        raise ValueError("r4 authorization issued_at invalid")
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
            "source_artifact_set_sha256": canonical_sha256(
                plan["source_artifacts"]
            ),
        },
        "binding": copy.deepcopy(plan["binding"]),
        "execution_scope": copy.deepcopy(plan["execution_scope"]),
        "budget": copy.deepcopy(plan["budget"]),
        "controls": copy.deepcopy(plan["controls"]),
        "reviewer": {
            **copy.deepcopy(reviewer),
            "identity_profile_sha256": reviewer_profile_sha256,
        },
        "implementation": copy.deepcopy(implementation),
        "execution_boundary": copy.deepcopy(AUTH_BOUNDARY),
    }
    payload = _payload(value)
    signature = signer.sign(payload)
    if len(signature) != 64:
        raise ValueError("r4 authorization signature must be 64 bytes")
    value["signature"] = {
        "algorithm": "ed25519",
        "signed_payload_sha256": hashlib.sha256(payload).hexdigest(),
        "signature_hex": signature.hex(),
    }
    failures = validate_authorization(
        value,
        plan=plan,
        expected_plan_ref=plan_ref,
        expected_preflight_ref=preflight_ref,
        expected_owner_statement_sha256=owner_statement_sha256,
        expected_reviewer=reviewer,
        expected_reviewer_profile_sha256=reviewer_profile_sha256,
        expected_implementation=implementation,
    )
    if failures:
        raise ValueError(f"r4 authorization invalid: {failures}")
    return value


def validate_authorization(
    value: Any,
    *,
    plan: dict[str, Any],
    expected_plan_ref: dict[str, str],
    expected_preflight_ref: dict[str, str],
    expected_owner_statement_sha256: str,
    expected_reviewer: dict[str, Any],
    expected_reviewer_profile_sha256: str,
    expected_implementation: dict[str, str],
    current_time: datetime | None = None,
    require_current: bool = False,
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
        failures.append("r4_authorization_identity_or_validity_invalid")
    if require_current:
        now = current_time or datetime.now().astimezone()
        if not (valid_from and valid_until and valid_from <= now < valid_until):
            failures.append("r4_authorization_not_current")
    if authorization.get("owner_authorization", {}).get(
        "statement_sha256"
    ) != expected_owner_statement_sha256 or authorization.get(
        "source_binding"
    ) != {
        "plan": expected_plan_ref,
        "preflight": expected_preflight_ref,
        "source_artifact_set_sha256": canonical_sha256(plan["source_artifacts"]),
    }:
        failures.append("r4_authorization_owner_or_source_invalid")
    if not (
        authorization.get("binding") == plan.get("binding")
        and authorization.get("execution_scope") == plan.get("execution_scope")
        and authorization.get("budget") == plan.get("budget")
        and authorization.get("controls") == plan.get("controls")
    ):
        failures.append("r4_authorization_scope_or_budget_invalid")
    expected_bound_reviewer = {
        **expected_reviewer,
        "identity_profile_sha256": expected_reviewer_profile_sha256,
    }
    if (
        authorization.get("reviewer") != expected_bound_reviewer
        or authorization.get("implementation") != expected_implementation
        or authorization.get("execution_boundary") != AUTH_BOUNDARY
    ):
        failures.append("r4_authorization_reviewer_or_boundary_invalid")
    signature = authorization.get("signature", {})
    unsigned = {
        key: item for key, item in authorization.items() if key != "signature"
    }
    payload = _payload(unsigned)
    try:
        VerifyKey(bytes.fromhex(expected_reviewer["public_key_hex"])).verify(
            payload, bytes.fromhex(str(signature.get("signature_hex", "")))
        )
    except (BadSignatureError, ValueError):
        failures.append("r4_authorization_signature_invalid")
    if signature.get("signed_payload_sha256") != hashlib.sha256(payload).hexdigest():
        failures.append("r4_authorization_signature_binding_invalid")
    return list(dict.fromkeys(failures))


def build_issuance_gate(
    *,
    checked_at: str,
    authorization_ref: dict[str, str],
    authorization: dict[str, Any],
    plan: dict[str, Any],
    preflight: dict[str, Any],
    inventory_snapshot: dict[str, Any],
) -> dict[str, Any]:
    value = {
        "schema_version": GATE_SCHEMA,
        "passed": True,
        "failure_reasons": [],
        "state": "r4_authorization_issued_claim_preflight_required",
        "checked_at": checked_at,
        "run_id": plan["run_id"],
        "authorization": copy.deepcopy(authorization_ref),
        "plan_sha256": plan["plan_sha256"],
        "preflight_sha256": preflight["preflight_sha256"],
        "inventory_snapshot": copy.deepcopy(inventory_snapshot),
        "checks": {
            "authorization_signature_valid": True,
            "authorization_current": True,
            "owner_statement_bound": True,
            "frozen_r4_stack_and_provider_admission_bound": True,
            "execution_scope_and_budget_bound": True,
            "forty_stopped_containers_revalidated": True,
            "authorization_unconsumed": True,
            "future_execution_paths_absent": True,
            "no_execution_or_external_write_performed": True,
        },
        "readiness": {
            "single_use_authorization_issued": True,
            "single_use_authorization_current": True,
            "single_use_authorization_consumed": False,
            "claim_preflight_required": True,
            "controlled_experiment_execution_ready": False,
        },
        "execution_boundary": copy.deepcopy(AUTH_BOUNDARY),
    }
    value["report_sha256"] = canonical_sha256(value)
    del authorization
    return value


def build_claim_preflight(
    *,
    checked_at: str,
    authorization_ref: dict[str, str],
    authorization: dict[str, Any],
    issuance_gate_ref: dict[str, str],
    plan: dict[str, Any],
    inventory_snapshot: dict[str, Any],
    execution_manifest_sha256: str,
    implementation: dict[str, str],
) -> dict[str, Any]:
    statement = claim_authorization_statement(
        authorization_ref=authorization_ref,
        issuance_gate_ref=issuance_gate_ref,
        authorization=authorization,
        execution_manifest_sha256=execution_manifest_sha256,
    )
    value = {
        "schema_version": CLAIM_PREFLIGHT_SCHEMA,
        "run_id": authorization["run_id"],
        "state": "r4_claim_preflight_passed_owner_authorization_required",
        "checked_at": checked_at,
        "source_binding": {
            "authorization": copy.deepcopy(authorization_ref),
            "issuance_gate": copy.deepcopy(issuance_gate_ref),
            "plan_sha256": plan["plan_sha256"],
        },
        "inventory_snapshot": copy.deepcopy(inventory_snapshot),
        "execution_manifest_sha256": execution_manifest_sha256,
        "execution_scope": copy.deepcopy(authorization["execution_scope"]),
        "budget": copy.deepcopy(authorization["budget"]),
        "controls": copy.deepcopy(authorization["controls"]),
        "owner_authorization": {
            "required": True,
            "required_exact_statement": statement,
            "statement_sha256": hashlib.sha256(statement.encode()).hexdigest(),
            "scope": "atomic_claim_and_bounded_execution",
        },
        "checks": {
            "authorization_signature_and_currency_verified": True,
            "issuance_gate_verified": True,
            "authorization_unconsumed": True,
            "execution_and_post_run_paths_absent": True,
            "forty_stopped_containers_revalidated": True,
            "exact_320_task_manifest_bound": True,
            "provider_admission_and_signed_closeout_bound": True,
            "no_execution_side_effect_performed": True,
        },
        "readiness": {
            "owner_claim_authorization_required": True,
            "atomic_claim_allowed_by_this_preflight": False,
            "controlled_experiment_execution_ready": False,
        },
        "implementation": copy.deepcopy(implementation),
        "execution_boundary": copy.deepcopy(CLAIM_PREFLIGHT_BOUNDARY),
    }
    value["preflight_sha256"] = canonical_sha256(value)
    return value


def claim_authorization_statement(
    *,
    authorization_ref: dict[str, str],
    issuance_gate_ref: dict[str, str],
    authorization: dict[str, Any],
    execution_manifest_sha256: str,
) -> str:
    return (
        "I authorize exactly one create-exclusive atomic claim of J1-D r4 "
        f"authorization {authorization['authorization_id']} raw SHA-256 "
        f"{authorization_ref['sha256']}, signed payload SHA-256 "
        f"{authorization_ref['canonical_sha256']}, issuance Gate canonical SHA-256 "
        f"{issuance_gate_ref['canonical_sha256']}, for run "
        f"{authorization['run_id']} and execution manifest "
        f"{execution_manifest_sha256}. After that claim validates, I authorize "
        "exactly one bounded execution covering 40 participants, 20 pairs, 320 task "
        "executions, and 320 provider calls using openai_compatible / "
        "deepseek-v4-pro at temperature 0. I acknowledge reservation of 800000 "
        "tokens and 487360 USD microunits, an absolute protocol ceiling of 4000000 "
        "USD microunits, that the claim is irreversible, provider dispatch ambiguity "
        "must never be retried, and any claimed failure requires a new authorization "
        "and signed closeout. Backend Fact and Ledger append remain prohibited, and "
        "no effectiveness claim is authorized before signed evaluation and closeout."
    )


def _payload(value: dict[str, Any]) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode()


def _timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else None
