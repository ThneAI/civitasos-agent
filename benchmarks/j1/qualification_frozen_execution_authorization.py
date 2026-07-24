"""Signed authorization contract for a frozen-stack J1-D execution."""

from __future__ import annotations

import copy
import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Any, Protocol

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from .controlled_comparison import canonical_sha256
from .qualification_frozen_execution_preflight import (
    MAX_TTL_SECONDS,
    PLAN_BOUNDARY,
    owner_authorization_statement,
    validate_execution_plan,
    validate_preflight,
)
from .qualification_reviewer_identity import validate_reviewer_identity_profile


AUTHORIZATION_SCHEMA = "j1-qualification-frozen-stack-execution-authorization:v3"
GATE_SCHEMA = "j1-qualification-frozen-stack-execution-authorization-gate:v1"
DECISION = "authorize_once"
AUTHORIZATION_BOUNDARY = {
    "authorization_issuance_only": True,
    "single_use_authorization_issued": True,
    "single_use_authorization_consumed": False,
    "atomic_claim_created": False,
    "participant_container_started": False,
    "provider_api_call_performed": False,
    "model_invocation_performed": False,
    "agent_execution_performed": False,
    "backend_fact_append_performed": False,
    "ledger_append_performed": False,
    "effectiveness_claim_authorized": False,
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
    ttl_seconds: int,
    plan_path: str,
    plan_bytes: bytes,
    plan: dict[str, Any],
    preflight_path: str,
    preflight_bytes: bytes,
    preflight: dict[str, Any],
    reviewer_profile: dict[str, Any],
    reviewer_profile_sha256: str,
    implementation: dict[str, str],
    signer: AuthorizationSigner,
) -> dict[str, Any]:
    issued = _timestamp(issued_at)
    if issued is None:
        raise ValueError("frozen authorization issued_at must be RFC3339")
    if ttl_seconds != MAX_TTL_SECONDS:
        raise ValueError("frozen authorization TTL must be exactly 1800 seconds")
    source_failures = _validate_sources(
        plan_path=plan_path,
        plan_bytes=plan_bytes,
        plan=plan,
        preflight_path=preflight_path,
        preflight_bytes=preflight_bytes,
        preflight=preflight,
    )
    if source_failures:
        raise ValueError(f"frozen authorization source invalid: {source_failures}")
    profile_failures = validate_reviewer_identity_profile(reviewer_profile)
    if profile_failures:
        raise ValueError(f"authorization signer profile invalid: {profile_failures}")
    reviewer = reviewer_profile["reviewer"]
    if signer.public_key_hex.lower() != reviewer["public_key_hex"].lower():
        raise ValueError("authorization signer does not match reviewer profile")
    expected_statement = owner_authorization_statement(
        plan_artifact_sha256=hashlib.sha256(plan_bytes).hexdigest(),
        plan=plan,
    )
    expected_statement_sha256 = hashlib.sha256(expected_statement.encode()).hexdigest()
    if (
        owner_statement_sha256 != expected_statement_sha256
        or owner_statement_sha256
        != preflight["owner_authorization"]["statement_sha256"]
    ):
        raise ValueError("owner authorization statement hash mismatch")
    value = {
        "schema_version": AUTHORIZATION_SCHEMA,
        "authorization_id": authorization_id,
        "run_id": plan["run_id"],
        "decision": DECISION,
        "issued_at": issued.isoformat(),
        "valid_from": issued.isoformat(),
        "valid_until": (issued + timedelta(seconds=ttl_seconds)).isoformat(),
        "ttl_seconds": ttl_seconds,
        "owner_authorization": {
            "authorization_id": owner_authorization_id,
            "statement_sha256": owner_statement_sha256,
            "source": "interactive_owner_operator_approval",
            "scope": "authorization_issuance_only",
        },
        "source_binding": {
            "plan": _artifact(plan_path, plan_bytes, plan["plan_sha256"]),
            "preflight": _artifact(
                preflight_path,
                preflight_bytes,
                preflight["preflight_sha256"],
            ),
            "source_artifact_set_sha256": canonical_sha256(plan["source_artifacts"]),
        },
        "execution_scope": copy.deepcopy(plan["execution_scope"]),
        "cost_acknowledgement": copy.deepcopy(plan["cost_acknowledgement"]),
        "controls": copy.deepcopy(plan["controls"]),
        "reviewer": {
            **copy.deepcopy(reviewer),
            "identity_profile_sha256": reviewer_profile_sha256,
        },
        "implementation": copy.deepcopy(implementation),
        "execution_boundary": copy.deepcopy(AUTHORIZATION_BOUNDARY),
    }
    payload = signature_payload(value)
    signature = signer.sign(payload)
    if len(signature) != 64:
        raise ValueError("frozen authorization signature must be 64 bytes")
    value["signature"] = {
        "algorithm": "ed25519",
        "signed_payload_sha256": hashlib.sha256(payload).hexdigest(),
        "signature_hex": signature.hex(),
    }
    failures = validate_authorization(
        value,
        plan_path=plan_path,
        plan_bytes=plan_bytes,
        plan=plan,
        preflight_path=preflight_path,
        preflight_bytes=preflight_bytes,
        preflight=preflight,
        reviewer_profile=reviewer_profile,
        reviewer_profile_sha256=reviewer_profile_sha256,
        expected_implementation=implementation,
    )
    if failures:
        raise ValueError(f"frozen authorization invalid: {failures}")
    return value


def validate_authorization(
    value: Any,
    *,
    plan_path: str,
    plan_bytes: bytes,
    plan: dict[str, Any],
    preflight_path: str,
    preflight_bytes: bytes,
    preflight: dict[str, Any],
    reviewer_profile: dict[str, Any],
    reviewer_profile_sha256: str,
    expected_implementation: dict[str, str],
    current_time: datetime | None = None,
    require_current: bool = False,
) -> list[str]:
    authorization = value if isinstance(value, dict) else {}
    failures = _validate_sources(
        plan_path=plan_path,
        plan_bytes=plan_bytes,
        plan=plan,
        preflight_path=preflight_path,
        preflight_bytes=preflight_bytes,
        preflight=preflight,
    )
    _require(
        set(authorization)
        == {
            "schema_version",
            "authorization_id",
            "run_id",
            "decision",
            "issued_at",
            "valid_from",
            "valid_until",
            "ttl_seconds",
            "owner_authorization",
            "source_binding",
            "execution_scope",
            "cost_acknowledgement",
            "controls",
            "reviewer",
            "implementation",
            "execution_boundary",
            "signature",
        },
        "frozen_authorization_fields_invalid",
        failures,
    )
    issued = _timestamp(authorization.get("issued_at"))
    valid_from = _timestamp(authorization.get("valid_from"))
    valid_until = _timestamp(authorization.get("valid_until"))
    _require(
        authorization.get("schema_version") == AUTHORIZATION_SCHEMA
        and _text(authorization.get("authorization_id"))
        and authorization.get("run_id") == plan.get("run_id")
        and authorization.get("decision") == DECISION
        and issued is not None
        and valid_from == issued
        and valid_until == issued + timedelta(seconds=MAX_TTL_SECONDS)
        and authorization.get("ttl_seconds") == MAX_TTL_SECONDS,
        "frozen_authorization_identity_or_validity_invalid",
        failures,
    )
    if require_current:
        now = (current_time or datetime.now(timezone.utc)).astimezone(timezone.utc)
        _require(
            bool(valid_from and valid_until and valid_from <= now < valid_until),
            "frozen_authorization_not_current",
            failures,
        )
    expected_statement = owner_authorization_statement(
        plan_artifact_sha256=hashlib.sha256(plan_bytes).hexdigest(),
        plan=plan,
    )
    statement_sha256 = hashlib.sha256(expected_statement.encode()).hexdigest()
    owner = _object(authorization.get("owner_authorization"))
    _require(
        _text(owner.get("authorization_id"))
        and owner.get("statement_sha256") == statement_sha256
        and owner.get("source") == "interactive_owner_operator_approval"
        and owner.get("scope") == "authorization_issuance_only",
        "frozen_authorization_owner_binding_invalid",
        failures,
    )
    _require(
        authorization.get("source_binding")
        == {
            "plan": _artifact(plan_path, plan_bytes, plan.get("plan_sha256")),
            "preflight": _artifact(
                preflight_path,
                preflight_bytes,
                preflight.get("preflight_sha256"),
            ),
            "source_artifact_set_sha256": canonical_sha256(
                plan.get("source_artifacts")
            ),
        },
        "frozen_authorization_source_binding_invalid",
        failures,
    )
    for field in ("execution_scope", "cost_acknowledgement", "controls"):
        _require(
            authorization.get(field) == plan.get(field),
            f"frozen_authorization_{field}_invalid",
            failures,
        )
    expected_reviewer = {
        **_object(reviewer_profile.get("reviewer")),
        "identity_profile_sha256": reviewer_profile_sha256,
    }
    _require(
        not validate_reviewer_identity_profile(reviewer_profile)
        and authorization.get("reviewer") == expected_reviewer,
        "frozen_authorization_reviewer_invalid",
        failures,
    )
    _require(
        authorization.get("implementation") == expected_implementation
        and _valid_implementation(expected_implementation),
        "frozen_authorization_implementation_invalid",
        failures,
    )
    _require(
        authorization.get("execution_boundary") == AUTHORIZATION_BOUNDARY,
        "frozen_authorization_boundary_invalid",
        failures,
    )
    _validate_signature(authorization, failures)
    return list(dict.fromkeys(failures))


def build_gate_report(
    *,
    checked_at: str,
    authorization_path: str,
    authorization_bytes: bytes,
    authorization: dict[str, Any],
    plan: dict[str, Any],
    preflight: dict[str, Any],
    inventory_snapshot: dict[str, Any],
) -> dict[str, Any]:
    checked = _timestamp(checked_at)
    if checked is None:
        raise ValueError("authorization Gate checked_at must be RFC3339")
    value = {
        "schema_version": GATE_SCHEMA,
        "passed": True,
        "failure_reasons": [],
        "state": "frozen_stack_authorization_issued_atomic_claim_preflight_required",
        "checked_at": checked.isoformat(),
        "run_id": plan["run_id"],
        "authorization": {
            "path": authorization_path,
            "sha256": hashlib.sha256(authorization_bytes).hexdigest(),
            "signed_payload_sha256": authorization["signature"][
                "signed_payload_sha256"
            ],
        },
        "plan_sha256": plan["plan_sha256"],
        "preflight_sha256": preflight["preflight_sha256"],
        "inventory_snapshot": copy.deepcopy(inventory_snapshot),
        "checks": {
            "authorization_signature_valid": True,
            "authorization_current": True,
            "owner_statement_bound": True,
            "frozen_plan_and_preflight_bound": True,
            "execution_scope_and_cost_bound": True,
            "forty_stopped_containers_revalidated": True,
            "authorization_unconsumed": True,
            "execution_root_absent": True,
            "post_run_root_absent": True,
            "no_execution_or_external_write_performed": True,
        },
        "readiness": {
            "single_use_authorization_issued": True,
            "single_use_authorization_current": True,
            "single_use_authorization_consumed": False,
            "atomic_claim_preflight_required": True,
            "atomic_claim_allowed_by_this_gate": False,
            "controlled_experiment_execution_ready": False,
        },
        "execution_boundary": copy.deepcopy(AUTHORIZATION_BOUNDARY),
    }
    value["report_sha256"] = canonical_sha256(value)
    failures = validate_gate_report(
        value,
        authorization_path=authorization_path,
        authorization_bytes=authorization_bytes,
        authorization=authorization,
        plan=plan,
        preflight=preflight,
        expected_inventory_snapshot=inventory_snapshot,
    )
    if failures:
        raise ValueError(f"frozen authorization Gate invalid: {failures}")
    return value


def validate_gate_report(
    value: Any,
    *,
    authorization_path: str,
    authorization_bytes: bytes,
    authorization: dict[str, Any],
    plan: dict[str, Any],
    preflight: dict[str, Any],
    expected_inventory_snapshot: dict[str, Any],
) -> list[str]:
    report = value if isinstance(value, dict) else {}
    failures: list[str] = []
    checked = _timestamp(report.get("checked_at"))
    valid_from = _timestamp(authorization.get("valid_from"))
    valid_until = _timestamp(authorization.get("valid_until"))
    _require(
        report.get("schema_version") == GATE_SCHEMA
        and report.get("passed") is True
        and report.get("failure_reasons") == []
        and report.get("state")
        == "frozen_stack_authorization_issued_atomic_claim_preflight_required"
        and checked is not None
        and report.get("run_id") == plan.get("run_id"),
        "frozen_authorization_gate_identity_invalid",
        failures,
    )
    _require(
        bool(
            checked
            and valid_from
            and valid_until
            and valid_from <= checked < valid_until
        ),
        "frozen_authorization_gate_validity_invalid",
        failures,
    )
    _validate_signature(authorization, failures)
    _require(
        report.get("authorization")
        == {
            "path": authorization_path,
            "sha256": hashlib.sha256(authorization_bytes).hexdigest(),
            "signed_payload_sha256": authorization.get("signature", {}).get(
                "signed_payload_sha256"
            ),
        }
        and report.get("plan_sha256") == plan.get("plan_sha256")
        and report.get("preflight_sha256") == preflight.get("preflight_sha256"),
        "frozen_authorization_gate_source_invalid",
        failures,
    )
    _require(
        report.get("inventory_snapshot") == expected_inventory_snapshot,
        "frozen_authorization_gate_inventory_invalid",
        failures,
    )
    _require(
        report.get("checks")
        == {
            "authorization_signature_valid": True,
            "authorization_current": True,
            "owner_statement_bound": True,
            "frozen_plan_and_preflight_bound": True,
            "execution_scope_and_cost_bound": True,
            "forty_stopped_containers_revalidated": True,
            "authorization_unconsumed": True,
            "execution_root_absent": True,
            "post_run_root_absent": True,
            "no_execution_or_external_write_performed": True,
        },
        "frozen_authorization_gate_checks_invalid",
        failures,
    )
    _require(
        report.get("readiness")
        == {
            "single_use_authorization_issued": True,
            "single_use_authorization_current": True,
            "single_use_authorization_consumed": False,
            "atomic_claim_preflight_required": True,
            "atomic_claim_allowed_by_this_gate": False,
            "controlled_experiment_execution_ready": False,
        }
        and report.get("execution_boundary") == AUTHORIZATION_BOUNDARY,
        "frozen_authorization_gate_boundary_invalid",
        failures,
    )
    body = {key: item for key, item in report.items() if key != "report_sha256"}
    _require(
        report.get("report_sha256") == canonical_sha256(body),
        "frozen_authorization_gate_hash_invalid",
        failures,
    )
    return list(dict.fromkeys(failures))


def signature_payload(value: dict[str, Any]) -> bytes:
    body = {key: item for key, item in value.items() if key != "signature"}
    return json.dumps(
        body,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def _validate_sources(
    *,
    plan_path: str,
    plan_bytes: bytes,
    plan: dict[str, Any],
    preflight_path: str,
    preflight_bytes: bytes,
    preflight: dict[str, Any],
) -> list[str]:
    failures = validate_execution_plan(plan)
    failures.extend(
        validate_preflight(
            preflight,
            plan_path=plan_path,
            plan_bytes=plan_bytes,
            plan=plan,
            expected_inventory_snapshot=preflight.get("inventory_snapshot"),
        )
    )
    _require(
        preflight_path.startswith("/") and hashlib.sha256(preflight_bytes).hexdigest(),
        "frozen_authorization_preflight_artifact_invalid",
        failures,
    )
    _require(
        plan.get("execution_boundary") == PLAN_BOUNDARY,
        "frozen_authorization_plan_boundary_invalid",
        failures,
    )
    return list(dict.fromkeys(failures))


def _validate_signature(value: dict[str, Any], failures: list[str]) -> None:
    signature = _object(value.get("signature"))
    payload = signature_payload(value)
    _require(
        set(signature) == {"algorithm", "signed_payload_sha256", "signature_hex"}
        and signature.get("algorithm") == "ed25519"
        and signature.get("signed_payload_sha256")
        == hashlib.sha256(payload).hexdigest(),
        "frozen_authorization_signature_contract_invalid",
        failures,
    )
    try:
        signature_bytes = bytes.fromhex(str(signature.get("signature_hex", "")))
        public_key = bytes.fromhex(
            str(_object(value.get("reviewer")).get("public_key_hex", ""))
        )
        VerifyKey(public_key).verify(payload, signature_bytes)
    except (ValueError, BadSignatureError):
        _require(False, "frozen_authorization_signature_invalid", failures)


def _artifact(
    path: str,
    raw: bytes,
    canonical_sha256_value: str | None,
) -> dict[str, str | None]:
    return {
        "path": path,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "canonical_sha256": canonical_sha256_value,
    }


def _valid_implementation(value: Any) -> bool:
    implementation = _object(value)
    return (
        set(implementation)
        == {
            "source_revision",
            "domain_source_sha256",
            "operation_source_sha256",
        }
        and _hex(implementation.get("source_revision"), 40)
        and _hex(implementation.get("domain_source_sha256"), 64)
        and _hex(implementation.get("operation_source_sha256"), 64)
    )


def _timestamp(value: Any) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(_text(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.astimezone(timezone.utc) if parsed.tzinfo else None


def _hex(value: Any, length: int) -> bool:
    text = _text(value)
    return len(text) == length and all(char in "0123456789abcdef" for char in text)


def _text(value: Any) -> str:
    return str(value or "").strip()


def _object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _require(condition: Any, code: str, failures: list[str]) -> None:
    if not condition and code not in failures:
        failures.append(code)
