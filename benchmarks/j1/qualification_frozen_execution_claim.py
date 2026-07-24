"""Atomic-claim and execution-entry contracts for frozen-stack J1-D runs."""

from __future__ import annotations

import copy
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .controlled_comparison import canonical_sha256
from .qualification_frozen_execution_authorization import (
    validate_authorization,
    validate_gate_report,
)


PREFLIGHT_SCHEMA = "j1-qualification-frozen-stack-claim-preflight:v1"
CLAIM_SCHEMA = "j1-qualification-frozen-stack-authorization-claim:v1"
ENTRY_GATE_SCHEMA = "j1-qualification-frozen-stack-execution-entry-gate:v1"

PREFLIGHT_BOUNDARY = {
    "claim_preparation_only": True,
    "single_use_authorization_consumed": False,
    "atomic_claim_created": False,
    "execution_root_created": False,
    "participant_container_started": False,
    "provider_credential_read": False,
    "provider_api_call_performed": False,
    "model_invocation_performed": False,
    "agent_execution_performed": False,
    "backend_fact_append_performed": False,
    "ledger_append_performed": False,
}
CLAIM_BOUNDARY = {
    "claim_only": True,
    "single_use_authorization_consumed": True,
    "atomic_claim_created": True,
    "execution_root_created": False,
    "participant_container_started": False,
    "provider_credential_read": False,
    "provider_api_call_performed": False,
    "model_invocation_performed": False,
    "agent_execution_performed": False,
    "backend_fact_append_performed": False,
    "ledger_append_performed": False,
    "effectiveness_claim_authorized": False,
}
ENTRY_BOUNDARY = {
    "execution_entry_validation_only": True,
    "single_use_authorization_consumed": True,
    "atomic_claim_validated": True,
    "execution_root_created": False,
    "participant_container_started": False,
    "provider_credential_read": False,
    "provider_api_call_performed": False,
    "model_invocation_performed": False,
    "agent_execution_performed": False,
    "backend_fact_append_performed": False,
    "ledger_append_performed": False,
    "effectiveness_claim_authorized": False,
}


def owner_claim_statement(
    *,
    authorization_artifact_sha256: str,
    issuance_gate_canonical_sha256: str,
    execution_manifest_sha256: str,
    authorization: dict[str, Any],
) -> str:
    scope = authorization["execution_scope"]
    cost = authorization["cost_acknowledgement"]
    return (
        f"I authorize exactly one create-exclusive atomic claim of frozen-stack "
        f"authorization {authorization['authorization_id']} raw SHA-256 "
        f"{authorization_artifact_sha256}, issuance Gate canonical SHA-256 "
        f"{issuance_gate_canonical_sha256}, for run {authorization['run_id']} and "
        f"execution manifest {execution_manifest_sha256}. After that claim validates, "
        f"I authorize exactly one bounded execution covering {scope['participant_count']} "
        f"participants, {scope['matched_pair_count']} pairs, and "
        f"{scope['authorized_task_executions']} provider calls using "
        f"{scope['provider_id']} / {scope['model_id']} at temperature "
        f"{scope['temperature']}. I acknowledge reservation of "
        f"{cost['aggregate_reserved_tokens']} tokens and "
        f"{cost['aggregate_reserved_cost_microunits']} USD microunits, an absolute "
        f"protocol ceiling of {cost['aggregate_protocol_max_cost_microunits']} USD "
        "microunits, that the claim is irreversible, and that any claimed failure "
        "requires a new authorization and signed closeout. Backend Fact and Ledger "
        "append remain prohibited, and no effectiveness claim is authorized before "
        "signed closeout."
    )


def build_claim_preflight(
    *,
    checked_at: str,
    authorization_path: str,
    authorization_bytes: bytes,
    authorization: dict[str, Any],
    issuance_gate_path: str,
    issuance_gate_bytes: bytes,
    issuance_gate: dict[str, Any],
    plan_path: str,
    plan_bytes: bytes,
    plan: dict[str, Any],
    frozen_preflight_path: str,
    frozen_preflight_bytes: bytes,
    frozen_preflight: dict[str, Any],
    reviewer_profile: dict[str, Any],
    reviewer_profile_sha256: str,
    expected_authorization_implementation: dict[str, str],
    inventory_snapshot: dict[str, Any],
    execution_manifest: dict[str, Any],
    implementation: dict[str, str],
) -> dict[str, Any]:
    checked = _timestamp(checked_at)
    if checked is None:
        raise ValueError("claim preflight checked_at must be RFC3339")
    failures = _validate_upstream(
        current_time=checked,
        authorization_path=authorization_path,
        authorization_bytes=authorization_bytes,
        authorization=authorization,
        issuance_gate_path=issuance_gate_path,
        issuance_gate_bytes=issuance_gate_bytes,
        issuance_gate=issuance_gate,
        plan_path=plan_path,
        plan_bytes=plan_bytes,
        plan=plan,
        frozen_preflight_path=frozen_preflight_path,
        frozen_preflight_bytes=frozen_preflight_bytes,
        frozen_preflight=frozen_preflight,
        reviewer_profile=reviewer_profile,
        reviewer_profile_sha256=reviewer_profile_sha256,
        expected_authorization_implementation=expected_authorization_implementation,
        inventory_snapshot=inventory_snapshot,
    )
    failures.extend(
        _validate_execution_manifest(
            execution_manifest,
            authorization=authorization,
            inventory_snapshot=inventory_snapshot,
        )
    )
    if failures:
        raise ValueError(f"claim preflight source invalid: {failures}")
    authorization_sha256 = hashlib.sha256(authorization_bytes).hexdigest()
    statement = owner_claim_statement(
        authorization_artifact_sha256=authorization_sha256,
        issuance_gate_canonical_sha256=issuance_gate["report_sha256"],
        execution_manifest_sha256=canonical_sha256(execution_manifest),
        authorization=authorization,
    )
    value = {
        "schema_version": PREFLIGHT_SCHEMA,
        "state": "frozen_stack_claim_preflight_passed_owner_authorization_required",
        "checked_at": checked.isoformat(),
        "run_id": authorization["run_id"],
        "source_binding": {
            "authorization": _artifact(
                authorization_path,
                authorization_bytes,
                authorization["signature"]["signed_payload_sha256"],
            ),
            "issuance_gate": _artifact(
                issuance_gate_path,
                issuance_gate_bytes,
                issuance_gate["report_sha256"],
            ),
            "plan": _artifact(plan_path, plan_bytes, plan["plan_sha256"]),
            "frozen_preflight": _artifact(
                frozen_preflight_path,
                frozen_preflight_bytes,
                frozen_preflight["preflight_sha256"],
            ),
        },
        "execution_scope": copy.deepcopy(authorization["execution_scope"]),
        "cost_acknowledgement": copy.deepcopy(
            authorization["cost_acknowledgement"]
        ),
        "controls": copy.deepcopy(authorization["controls"]),
        "inventory_snapshot": copy.deepcopy(inventory_snapshot),
        "execution_manifest": copy.deepcopy(execution_manifest),
        "owner_authorization": {
            "required": True,
            "required_exact_statement": statement,
            "statement_sha256": hashlib.sha256(statement.encode()).hexdigest(),
            "scope": "atomic_claim_and_bounded_execution",
        },
        "checks": {
            "v3_authorization_signature_and_currency_verified": True,
            "issuance_gate_verified": True,
            "authorization_unconsumed": True,
            "execution_and_post_run_paths_absent": True,
            "forty_stopped_containers_revalidated": True,
            "execution_workspace_empty_and_isolated": True,
            "provider_admission_and_frozen_closeout_bound": True,
            "no_execution_side_effect_performed": True,
        },
        "readiness": {
            "owner_claim_authorization_required": True,
            "atomic_claim_allowed_by_this_preflight": False,
            "controlled_experiment_execution_ready": False,
        },
        "execution_boundary": copy.deepcopy(PREFLIGHT_BOUNDARY),
        "implementation": copy.deepcopy(implementation),
    }
    value["preflight_sha256"] = canonical_sha256(value)
    validation_failures = validate_claim_preflight(
        value,
        authorization_path=authorization_path,
        authorization_bytes=authorization_bytes,
        authorization=authorization,
        issuance_gate_path=issuance_gate_path,
        issuance_gate_bytes=issuance_gate_bytes,
        issuance_gate=issuance_gate,
        plan_path=plan_path,
        plan_bytes=plan_bytes,
        plan=plan,
        frozen_preflight_path=frozen_preflight_path,
        frozen_preflight_bytes=frozen_preflight_bytes,
        frozen_preflight=frozen_preflight,
        reviewer_profile=reviewer_profile,
        reviewer_profile_sha256=reviewer_profile_sha256,
        expected_authorization_implementation=expected_authorization_implementation,
        expected_inventory_snapshot=inventory_snapshot,
        expected_execution_manifest=execution_manifest,
        expected_implementation=implementation,
        current_time=checked,
        require_current=True,
    )
    if validation_failures:
        raise ValueError(f"claim preflight invalid: {validation_failures}")
    return value


def validate_claim_preflight(
    value: Any,
    *,
    authorization_path: str,
    authorization_bytes: bytes,
    authorization: dict[str, Any],
    issuance_gate_path: str,
    issuance_gate_bytes: bytes,
    issuance_gate: dict[str, Any],
    plan_path: str,
    plan_bytes: bytes,
    plan: dict[str, Any],
    frozen_preflight_path: str,
    frozen_preflight_bytes: bytes,
    frozen_preflight: dict[str, Any],
    reviewer_profile: dict[str, Any],
    reviewer_profile_sha256: str,
    expected_authorization_implementation: dict[str, str],
    expected_inventory_snapshot: dict[str, Any],
    expected_execution_manifest: dict[str, Any],
    expected_implementation: dict[str, str],
    current_time: datetime | None = None,
    require_current: bool = False,
) -> list[str]:
    preflight = value if isinstance(value, dict) else {}
    failures: list[str] = []
    checked = _timestamp(preflight.get("checked_at"))
    _require(
        set(preflight)
        == {
            "schema_version",
            "state",
            "checked_at",
            "run_id",
            "source_binding",
            "execution_scope",
            "cost_acknowledgement",
            "controls",
            "inventory_snapshot",
            "execution_manifest",
            "owner_authorization",
            "checks",
            "readiness",
            "execution_boundary",
            "implementation",
            "preflight_sha256",
        },
        "claim_preflight_fields_invalid",
        failures,
    )
    if require_current:
        failures.extend(
            _validate_upstream(
                current_time=current_time or datetime.now(timezone.utc),
                authorization_path=authorization_path,
                authorization_bytes=authorization_bytes,
                authorization=authorization,
                issuance_gate_path=issuance_gate_path,
                issuance_gate_bytes=issuance_gate_bytes,
                issuance_gate=issuance_gate,
                plan_path=plan_path,
                plan_bytes=plan_bytes,
                plan=plan,
                frozen_preflight_path=frozen_preflight_path,
                frozen_preflight_bytes=frozen_preflight_bytes,
                frozen_preflight=frozen_preflight,
                reviewer_profile=reviewer_profile,
                reviewer_profile_sha256=reviewer_profile_sha256,
                expected_authorization_implementation=expected_authorization_implementation,
                inventory_snapshot=expected_inventory_snapshot,
            )
        )
    _require(
        preflight.get("schema_version") == PREFLIGHT_SCHEMA
        and preflight.get("state")
        == "frozen_stack_claim_preflight_passed_owner_authorization_required"
        and checked is not None
        and preflight.get("run_id") == authorization.get("run_id"),
        "claim_preflight_identity_invalid",
        failures,
    )
    expected_sources = {
        "authorization": _artifact(
            authorization_path,
            authorization_bytes,
            authorization.get("signature", {}).get("signed_payload_sha256"),
        ),
        "issuance_gate": _artifact(
            issuance_gate_path,
            issuance_gate_bytes,
            issuance_gate.get("report_sha256"),
        ),
        "plan": _artifact(plan_path, plan_bytes, plan.get("plan_sha256")),
        "frozen_preflight": _artifact(
            frozen_preflight_path,
            frozen_preflight_bytes,
            frozen_preflight.get("preflight_sha256"),
        ),
    }
    _require(
        preflight.get("source_binding") == expected_sources,
        "claim_preflight_source_binding_invalid",
        failures,
    )
    for field in ("execution_scope", "cost_acknowledgement", "controls"):
        _require(
            preflight.get(field) == authorization.get(field),
            f"claim_preflight_{field}_invalid",
            failures,
        )
    _require(
        preflight.get("inventory_snapshot") == expected_inventory_snapshot,
        "claim_preflight_inventory_invalid",
        failures,
    )
    _require(
        preflight.get("execution_manifest") == expected_execution_manifest
        and not _validate_execution_manifest(
            expected_execution_manifest,
            authorization=authorization,
            inventory_snapshot=expected_inventory_snapshot,
        ),
        "claim_preflight_execution_manifest_invalid",
        failures,
    )
    statement = owner_claim_statement(
        authorization_artifact_sha256=hashlib.sha256(
            authorization_bytes
        ).hexdigest(),
        issuance_gate_canonical_sha256=str(issuance_gate.get("report_sha256", "")),
        execution_manifest_sha256=canonical_sha256(expected_execution_manifest),
        authorization=authorization,
    )
    _require(
        preflight.get("owner_authorization")
        == {
            "required": True,
            "required_exact_statement": statement,
            "statement_sha256": hashlib.sha256(statement.encode()).hexdigest(),
            "scope": "atomic_claim_and_bounded_execution",
        },
        "claim_preflight_owner_authorization_invalid",
        failures,
    )
    _require(
        preflight.get("checks")
        == {
            "v3_authorization_signature_and_currency_verified": True,
            "issuance_gate_verified": True,
            "authorization_unconsumed": True,
            "execution_and_post_run_paths_absent": True,
            "forty_stopped_containers_revalidated": True,
            "execution_workspace_empty_and_isolated": True,
            "provider_admission_and_frozen_closeout_bound": True,
            "no_execution_side_effect_performed": True,
        },
        "claim_preflight_checks_invalid",
        failures,
    )
    _require(
        preflight.get("readiness")
        == {
            "owner_claim_authorization_required": True,
            "atomic_claim_allowed_by_this_preflight": False,
            "controlled_experiment_execution_ready": False,
        }
        and preflight.get("execution_boundary") == PREFLIGHT_BOUNDARY,
        "claim_preflight_boundary_invalid",
        failures,
    )
    _require(
        preflight.get("implementation") == expected_implementation
        and _valid_implementation(expected_implementation),
        "claim_preflight_implementation_invalid",
        failures,
    )
    body = {key: item for key, item in preflight.items() if key != "preflight_sha256"}
    _require(
        preflight.get("preflight_sha256") == canonical_sha256(body),
        "claim_preflight_hash_invalid",
        failures,
    )
    return list(dict.fromkeys(failures))


def build_claim_receipt(
    *,
    claimed_at: str,
    claim_path: str,
    owner_authorization_id: str,
    owner_statement: str,
    owner_statement_sha256: str,
    authorization_path: str,
    authorization_bytes: bytes,
    authorization: dict[str, Any],
    issuance_gate_path: str,
    issuance_gate_bytes: bytes,
    issuance_gate: dict[str, Any],
    claim_preflight_path: str,
    claim_preflight_bytes: bytes,
    claim_preflight: dict[str, Any],
    implementation: dict[str, str],
) -> dict[str, Any]:
    if not all(
        (
            _json_bytes_match(authorization_bytes, authorization),
            _json_bytes_match(issuance_gate_bytes, issuance_gate),
            _json_bytes_match(claim_preflight_bytes, claim_preflight),
        )
    ):
        raise ValueError("claim source object/raw mismatch")
    claimed = _timestamp(claimed_at)
    valid_from = _timestamp(authorization.get("valid_from"))
    valid_until = _timestamp(authorization.get("valid_until"))
    if not claimed or not valid_from or not valid_until or not valid_from <= claimed < valid_until:
        raise ValueError("authorization cannot be claimed outside its validity window")
    expected_path = Path(authorization["controls"]["authorization_consumption_path"])
    if Path(claim_path).resolve() != expected_path.resolve():
        raise ValueError("claim path does not match signed authorization")
    expected_statement = claim_preflight["owner_authorization"][
        "required_exact_statement"
    ]
    if (
        owner_statement != expected_statement
        or hashlib.sha256(owner_statement.encode()).hexdigest()
        != owner_statement_sha256
        or owner_statement_sha256
        != claim_preflight["owner_authorization"]["statement_sha256"]
    ):
        raise ValueError("claim owner statement/hash mismatch")
    if (
        claim_preflight.get("source_binding", {}).get("authorization")
        != _artifact(
            authorization_path,
            authorization_bytes,
            authorization.get("signature", {}).get("signed_payload_sha256"),
        )
        or claim_preflight.get("source_binding", {}).get("issuance_gate")
        != _artifact(
            issuance_gate_path,
            issuance_gate_bytes,
            issuance_gate.get("report_sha256"),
        )
        or claim_preflight.get("controls") != authorization.get("controls")
    ):
        raise ValueError("claim preflight source binding drifted")
    value = {
        "schema_version": CLAIM_SCHEMA,
        "state": "authorization_claimed_execution_must_close_out",
        "authorization_id": authorization["authorization_id"],
        "run_id": authorization["run_id"],
        "claimed_at": claimed.isoformat(),
        "owner_authorization": {
            "authorization_id": owner_authorization_id,
            "statement_sha256": owner_statement_sha256,
            "source": "interactive_owner_operator_approval",
            "scope": "atomic_claim_and_bounded_execution",
        },
        "source_binding": {
            "authorization": _artifact(
                authorization_path,
                authorization_bytes,
                authorization["signature"]["signed_payload_sha256"],
            ),
            "issuance_gate": _artifact(
                issuance_gate_path,
                issuance_gate_bytes,
                issuance_gate["report_sha256"],
            ),
            "claim_preflight": _artifact(
                claim_preflight_path,
                claim_preflight_bytes,
                claim_preflight["preflight_sha256"],
            ),
        },
        "execution_scope": copy.deepcopy(authorization["execution_scope"]),
        "cost_acknowledgement": copy.deepcopy(
            authorization["cost_acknowledgement"]
        ),
        "controls": copy.deepcopy(authorization["controls"]),
        "execution_manifest": copy.deepcopy(claim_preflight["execution_manifest"]),
        "single_use": True,
        "immutable": True,
        "claim_must_survive_execution_failure": True,
        "closeout_required_for_all_terminal_states": True,
        "execution_boundary": copy.deepcopy(CLAIM_BOUNDARY),
        "implementation": copy.deepcopy(implementation),
    }
    value["claim_sha256"] = canonical_sha256(value)
    failures = validate_claim_receipt(
        value,
        claim_path=claim_path,
        authorization_path=authorization_path,
        authorization_bytes=authorization_bytes,
        authorization=authorization,
        issuance_gate_path=issuance_gate_path,
        issuance_gate_bytes=issuance_gate_bytes,
        issuance_gate=issuance_gate,
        claim_preflight_path=claim_preflight_path,
        claim_preflight_bytes=claim_preflight_bytes,
        claim_preflight=claim_preflight,
        expected_implementation=implementation,
    )
    if failures:
        raise ValueError(f"claim receipt invalid: {failures}")
    return value


def validate_claim_receipt(
    value: Any,
    *,
    claim_path: str,
    authorization_path: str,
    authorization_bytes: bytes,
    authorization: dict[str, Any],
    issuance_gate_path: str,
    issuance_gate_bytes: bytes,
    issuance_gate: dict[str, Any],
    claim_preflight_path: str,
    claim_preflight_bytes: bytes,
    claim_preflight: dict[str, Any],
    expected_implementation: dict[str, str],
) -> list[str]:
    claim = value if isinstance(value, dict) else {}
    failures: list[str] = []
    _require(
        set(claim)
        == {
            "schema_version",
            "state",
            "authorization_id",
            "run_id",
            "claimed_at",
            "owner_authorization",
            "source_binding",
            "execution_scope",
            "cost_acknowledgement",
            "controls",
            "execution_manifest",
            "single_use",
            "immutable",
            "claim_must_survive_execution_failure",
            "closeout_required_for_all_terminal_states",
            "execution_boundary",
            "implementation",
            "claim_sha256",
        },
        "claim_fields_invalid",
        failures,
    )
    _require(
        _json_bytes_match(authorization_bytes, authorization)
        and _json_bytes_match(issuance_gate_bytes, issuance_gate)
        and _json_bytes_match(claim_preflight_bytes, claim_preflight),
        "claim_source_object_raw_mismatch",
        failures,
    )
    claimed = _timestamp(claim.get("claimed_at"))
    valid_from = _timestamp(authorization.get("valid_from"))
    valid_until = _timestamp(authorization.get("valid_until"))
    _require(
        claim.get("schema_version") == CLAIM_SCHEMA
        and claim.get("state") == "authorization_claimed_execution_must_close_out"
        and claim.get("authorization_id") == authorization.get("authorization_id")
        and claim.get("run_id") == authorization.get("run_id")
        and bool(
            claimed
            and valid_from
            and valid_until
            and valid_from <= claimed < valid_until
        ),
        "claim_identity_or_validity_invalid",
        failures,
    )
    _require(
        Path(claim_path).resolve()
        == Path(authorization.get("controls", {}).get("authorization_consumption_path", "")).resolve(),
        "claim_path_invalid",
        failures,
    )
    owner = claim.get("owner_authorization")
    _require(
        isinstance(owner, dict)
        and _text(owner.get("authorization_id"))
        and owner.get("statement_sha256")
        == claim_preflight.get("owner_authorization", {}).get("statement_sha256")
        and owner.get("source") == "interactive_owner_operator_approval"
        and owner.get("scope") == "atomic_claim_and_bounded_execution",
        "claim_owner_authorization_invalid",
        failures,
    )
    _require(
        claim.get("source_binding")
        == {
            "authorization": _artifact(
                authorization_path,
                authorization_bytes,
                authorization.get("signature", {}).get("signed_payload_sha256"),
            ),
            "issuance_gate": _artifact(
                issuance_gate_path,
                issuance_gate_bytes,
                issuance_gate.get("report_sha256"),
            ),
            "claim_preflight": _artifact(
                claim_preflight_path,
                claim_preflight_bytes,
                claim_preflight.get("preflight_sha256"),
            ),
        },
        "claim_source_binding_invalid",
        failures,
    )
    for field in ("execution_scope", "cost_acknowledgement", "controls"):
        _require(
            claim.get(field) == authorization.get(field),
            f"claim_{field}_invalid",
            failures,
        )
    _require(
        claim.get("execution_manifest") == claim_preflight.get("execution_manifest"),
        "claim_execution_manifest_invalid",
        failures,
    )
    _require(
        claim.get("single_use") is True
        and claim.get("immutable") is True
        and claim.get("claim_must_survive_execution_failure") is True
        and claim.get("closeout_required_for_all_terminal_states") is True
        and claim.get("execution_boundary") == CLAIM_BOUNDARY,
        "claim_boundary_invalid",
        failures,
    )
    _require(
        claim.get("implementation") == expected_implementation
        and _valid_implementation(expected_implementation),
        "claim_implementation_invalid",
        failures,
    )
    body = {key: item for key, item in claim.items() if key != "claim_sha256"}
    _require(
        claim.get("claim_sha256") == canonical_sha256(body),
        "claim_hash_invalid",
        failures,
    )
    return list(dict.fromkeys(failures))


def write_claim_exclusive(path: Path, claim: dict[str, Any]) -> None:
    expected = Path(claim["controls"]["authorization_consumption_path"]).resolve()
    if path.resolve() != expected:
        raise ValueError("claim path does not match signed authorization")
    parent = path.parent
    if parent.is_symlink():
        raise ValueError("claim parent must not be a symlink")
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    parent.chmod(0o700)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(claim, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    directory = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def build_execution_entry_gate(
    *,
    checked_at: str,
    claim_path: str,
    claim_bytes: bytes,
    claim: dict[str, Any],
    authorization_path: str,
    authorization_bytes: bytes,
    authorization: dict[str, Any],
    issuance_gate_path: str,
    issuance_gate_bytes: bytes,
    issuance_gate: dict[str, Any],
    claim_preflight_path: str,
    claim_preflight_bytes: bytes,
    claim_preflight: dict[str, Any],
    expected_claim_implementation: dict[str, str],
    current_inventory_snapshot: dict[str, Any],
    current_execution_manifest: dict[str, Any],
    execution_root_exists: bool,
    post_run_root_exists: bool,
) -> dict[str, Any]:
    checked = _timestamp(checked_at)
    if checked is None:
        raise ValueError("execution entry checked_at must be RFC3339")
    failures = validate_claim_receipt(
        claim,
        claim_path=claim_path,
        authorization_path=authorization_path,
        authorization_bytes=authorization_bytes,
        authorization=authorization,
        issuance_gate_path=issuance_gate_path,
        issuance_gate_bytes=issuance_gate_bytes,
        issuance_gate=issuance_gate,
        claim_preflight_path=claim_preflight_path,
        claim_preflight_bytes=claim_preflight_bytes,
        claim_preflight=claim_preflight,
        expected_implementation=expected_claim_implementation,
    )
    _require(
        _json_bytes_match(claim_bytes, claim),
        "execution_entry_claim_object_raw_mismatch",
        failures,
    )
    _require(
        current_inventory_snapshot == claim_preflight.get("inventory_snapshot"),
        "execution_entry_inventory_drifted",
        failures,
    )
    _require(
        current_execution_manifest == claim_preflight.get("execution_manifest"),
        "execution_entry_manifest_drifted",
        failures,
    )
    _require(
        execution_root_exists is False,
        "execution_entry_root_already_exists",
        failures,
    )
    _require(
        post_run_root_exists is False,
        "execution_entry_post_run_already_exists",
        failures,
    )
    if failures:
        raise ValueError(f"execution entry invalid: {failures}")
    value = {
        "schema_version": ENTRY_GATE_SCHEMA,
        "passed": True,
        "failure_reasons": [],
        "state": "atomic_claim_validated_bounded_execution_entry_allowed",
        "checked_at": checked.isoformat(),
        "run_id": authorization["run_id"],
        "claim": {
            "path": str(Path(claim_path).resolve()),
            "sha256": hashlib.sha256(claim_bytes).hexdigest(),
            "canonical_sha256": claim["claim_sha256"],
        },
        "authorization_id": authorization["authorization_id"],
        "inventory_snapshot": copy.deepcopy(current_inventory_snapshot),
        "execution_manifest": copy.deepcopy(current_execution_manifest),
        "checks": {
            "atomic_claim_valid": True,
            "claim_matches_signed_authorization_path": True,
            "claim_created_inside_authorization_window": True,
            "claim_and_execution_manifest_bound": True,
            "forty_containers_still_stopped": True,
            "execution_workspace_still_empty": True,
            "post_run_path_absent": True,
            "no_execution_side_effect_performed": True,
        },
        "readiness": {
            "single_use_authorization_consumed": True,
            "bounded_execution_entry_allowed": True,
            "closeout_required": True,
        },
        "execution_boundary": copy.deepcopy(ENTRY_BOUNDARY),
    }
    value["report_sha256"] = canonical_sha256(value)
    failures = validate_execution_entry_gate(
        value,
        claim_path=claim_path,
        claim_bytes=claim_bytes,
        claim=claim,
        expected_inventory_snapshot=current_inventory_snapshot,
        expected_execution_manifest=current_execution_manifest,
    )
    if failures:
        raise ValueError(f"execution entry Gate invalid: {failures}")
    return value


def validate_execution_entry_gate(
    value: Any,
    *,
    claim_path: str,
    claim_bytes: bytes,
    claim: dict[str, Any],
    expected_inventory_snapshot: dict[str, Any],
    expected_execution_manifest: dict[str, Any],
) -> list[str]:
    gate = value if isinstance(value, dict) else {}
    failures: list[str] = []
    _require(
        set(gate)
        == {
            "schema_version",
            "passed",
            "failure_reasons",
            "state",
            "checked_at",
            "run_id",
            "claim",
            "authorization_id",
            "inventory_snapshot",
            "execution_manifest",
            "checks",
            "readiness",
            "execution_boundary",
            "report_sha256",
        },
        "execution_entry_gate_fields_invalid",
        failures,
    )
    _require(
        gate.get("schema_version") == ENTRY_GATE_SCHEMA
        and gate.get("passed") is True
        and gate.get("failure_reasons") == []
        and gate.get("state")
        == "atomic_claim_validated_bounded_execution_entry_allowed"
        and _timestamp(gate.get("checked_at")) is not None
        and gate.get("run_id") == claim.get("run_id")
        and gate.get("authorization_id") == claim.get("authorization_id"),
        "execution_entry_gate_identity_invalid",
        failures,
    )
    _require(
        gate.get("claim")
        == {
            "path": str(Path(claim_path).resolve()),
            "sha256": hashlib.sha256(claim_bytes).hexdigest(),
            "canonical_sha256": claim.get("claim_sha256"),
        },
        "execution_entry_gate_claim_invalid",
        failures,
    )
    _require(
        gate.get("inventory_snapshot") == expected_inventory_snapshot,
        "execution_entry_gate_inventory_invalid",
        failures,
    )
    _require(
        gate.get("execution_manifest") == expected_execution_manifest,
        "execution_entry_gate_manifest_invalid",
        failures,
    )
    _require(
        gate.get("checks")
        == {
            "atomic_claim_valid": True,
            "claim_matches_signed_authorization_path": True,
            "claim_created_inside_authorization_window": True,
            "claim_and_execution_manifest_bound": True,
            "forty_containers_still_stopped": True,
            "execution_workspace_still_empty": True,
            "post_run_path_absent": True,
            "no_execution_side_effect_performed": True,
        },
        "execution_entry_gate_checks_invalid",
        failures,
    )
    _require(
        gate.get("readiness")
        == {
            "single_use_authorization_consumed": True,
            "bounded_execution_entry_allowed": True,
            "closeout_required": True,
        }
        and gate.get("execution_boundary") == ENTRY_BOUNDARY,
        "execution_entry_gate_boundary_invalid",
        failures,
    )
    body = {key: item for key, item in gate.items() if key != "report_sha256"}
    _require(
        gate.get("report_sha256") == canonical_sha256(body),
        "execution_entry_gate_hash_invalid",
        failures,
    )
    return list(dict.fromkeys(failures))


def _validate_upstream(
    *,
    current_time: datetime,
    authorization_path: str,
    authorization_bytes: bytes,
    authorization: dict[str, Any],
    issuance_gate_path: str,
    issuance_gate_bytes: bytes,
    issuance_gate: dict[str, Any],
    plan_path: str,
    plan_bytes: bytes,
    plan: dict[str, Any],
    frozen_preflight_path: str,
    frozen_preflight_bytes: bytes,
    frozen_preflight: dict[str, Any],
    reviewer_profile: dict[str, Any],
    reviewer_profile_sha256: str,
    expected_authorization_implementation: dict[str, str],
    inventory_snapshot: dict[str, Any],
) -> list[str]:
    failures: list[str] = []
    _require(
        _json_bytes_match(authorization_bytes, authorization)
        and _json_bytes_match(issuance_gate_bytes, issuance_gate)
        and _json_bytes_match(plan_bytes, plan)
        and _json_bytes_match(frozen_preflight_bytes, frozen_preflight),
        "claim_upstream_object_raw_mismatch",
        failures,
    )
    failures.extend(
        validate_authorization(
        authorization,
        plan_path=plan_path,
        plan_bytes=plan_bytes,
        plan=plan,
        preflight_path=frozen_preflight_path,
        preflight_bytes=frozen_preflight_bytes,
        preflight=frozen_preflight,
        reviewer_profile=reviewer_profile,
        reviewer_profile_sha256=reviewer_profile_sha256,
        expected_implementation=expected_authorization_implementation,
        current_time=current_time,
        require_current=True,
        )
    )
    failures.extend(
        validate_gate_report(
            issuance_gate,
            authorization_path=authorization_path,
            authorization_bytes=authorization_bytes,
            authorization=authorization,
            plan=plan,
            preflight=frozen_preflight,
            expected_inventory_snapshot=inventory_snapshot,
        )
    )
    _require(
        issuance_gate_path.startswith("/")
        and hashlib.sha256(issuance_gate_bytes).hexdigest(),
        "claim_issuance_gate_artifact_invalid",
        failures,
    )
    return list(dict.fromkeys(failures))


def _validate_execution_manifest(
    value: Any,
    *,
    authorization: dict[str, Any],
    inventory_snapshot: dict[str, Any],
) -> list[str]:
    manifest = value if isinstance(value, dict) else {}
    scope = authorization.get("execution_scope", {})
    failures: list[str] = []
    _require(
        set(manifest)
        == {
            "participant_count",
            "matched_pair_count",
            "task_count_per_participant",
            "task_execution_count",
            "container_count",
            "running_container_count",
            "container_set_sha256",
            "workspace_set_sha256",
            "input_directory_count",
            "output_directory_count",
            "input_file_count",
            "output_file_count",
            "symlink_count",
            "provider_id",
            "model_id",
            "temperature",
        },
        "execution_manifest_fields_invalid",
        failures,
    )
    expected = {
        "participant_count": scope.get("participant_count"),
        "matched_pair_count": scope.get("matched_pair_count"),
        "task_count_per_participant": scope.get("task_count_per_participant"),
        "task_execution_count": scope.get("authorized_task_executions"),
        "container_count": inventory_snapshot.get("container_count"),
        "running_container_count": 0,
        "container_set_sha256": inventory_snapshot.get("container_set_sha256"),
        "input_directory_count": 40,
        "output_directory_count": 40,
        "input_file_count": 0,
        "output_file_count": 0,
        "symlink_count": 0,
        "provider_id": scope.get("provider_id"),
        "model_id": scope.get("model_id"),
        "temperature": scope.get("temperature"),
    }
    for field, expected_value in expected.items():
        _require(
            manifest.get(field) == expected_value,
            f"execution_manifest_{field}_invalid",
            failures,
        )
    _require(
        _sha256(manifest.get("workspace_set_sha256")),
        "execution_manifest_workspace_set_sha256_invalid",
        failures,
    )
    return list(dict.fromkeys(failures))


def _artifact(path: str, raw: bytes, canonical: Any) -> dict[str, str]:
    return {
        "path": str(Path(path).resolve()),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "canonical_sha256": str(canonical or ""),
    }


def _json_bytes_match(raw: bytes, value: Any) -> bool:
    try:
        return json.loads(raw) == value
    except (json.JSONDecodeError, UnicodeDecodeError):
        return False


def _timestamp(value: Any) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(str(value or "").replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.astimezone(timezone.utc) if parsed.tzinfo else None


def _valid_implementation(value: Any) -> bool:
    implementation = value if isinstance(value, dict) else {}
    return (
        set(implementation)
        == {
            "source_revision",
            "domain_source_sha256",
            "operation_source_sha256",
        }
        and 7 <= len(str(implementation.get("source_revision", ""))) <= 64
        and all(
            char in "0123456789abcdef"
            for char in str(implementation.get("source_revision", "")).lower()
        )
        and _sha256(implementation.get("domain_source_sha256"))
        and _sha256(implementation.get("operation_source_sha256"))
    )


def _sha256(value: Any) -> bool:
    text = str(value or "")
    return len(text) == 64 and all(char in "0123456789abcdef" for char in text)


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _require(condition: bool, code: str, failures: list[str]) -> None:
    if not condition and code not in failures:
        failures.append(code)
