"""Contracts for reviewed repair of one stopped J1-D participant container."""

from __future__ import annotations

import copy
import hashlib
from typing import Any, Protocol

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from .controlled_comparison import canonical_sha256


PLAN_SCHEMA = "j1-qualification-infrastructure-repair-plan:v1"
REVIEW_REQUEST_SCHEMA = "j1-qualification-infrastructure-repair-review-request:v1"
REVIEW_RECEIPT_SCHEMA = "j1-qualification-infrastructure-repair-review-receipt:v1"
REVIEWED_SCHEMA = "j1-qualification-infrastructure-repair:operator-reviewed:v1"
ACTIVATION_SCHEMA = "j1-qualification-infrastructure-repair-activation:v1"
CHECKLIST = {
    "immutable_parent_activation_reviewed",
    "exact_single_exited_target_reviewed",
    "target_participant_binding_reviewed",
    "content_addressed_image_reviewed",
    "mount_and_runtime_boundary_reviewed",
    "quarantine_and_rollback_boundary_reviewed",
    "complete_40_container_postcondition_reviewed",
    "no_container_start_or_provider_effect_reviewed",
}
BOUNDARY = {
    "single_exited_container_repair_only": True,
    "participant_container_created": False,
    "participant_container_started": False,
    "provider_credential_read": False,
    "provider_api_call_performed": False,
    "model_invocation_performed": False,
    "agent_execution_performed": False,
    "participant_task_execution_performed": False,
    "backend_fact_append_performed": False,
    "ledger_append_performed": False,
    "execution_authorization_issued_or_consumed": False,
}


class ReviewSigner(Protocol):
    @property
    def public_key_hex(self) -> str: ...

    def sign(self, message: bytes) -> bytes: ...


def build_repair_plan(
    *,
    repair_id: str,
    created_at: str,
    parent_activation_ref: dict[str, str],
    parent_activation: dict[str, Any],
    live_inventory: list[dict[str, Any]],
    target_container_name: str,
    implementation: dict[str, str],
) -> dict[str, Any]:
    parent_records = parent_activation.get("containers", [])
    record_index = {
        item.get("container", {}).get("container_name"): item
        for item in parent_records
        if isinstance(item, dict)
    }
    live_index = {
        item.get("container_name"): item
        for item in live_inventory
        if isinstance(item, dict)
    }
    target_record = record_index.get(target_container_name)
    target_live = live_index.get(target_container_name)
    if not isinstance(target_record, dict) or not isinstance(target_live, dict):
        raise ValueError("infrastructure repair target is outside parent activation")
    plan = {
        "schema_version": PLAN_SCHEMA,
        "repair_id": repair_id,
        "status": "independent_review_required",
        "created_at": created_at,
        "parent_activation": copy.deepcopy(parent_activation_ref),
        "parent_activation_canonical_sha256": parent_activation.get(
            "activation_sha256"
        ),
        "inventory_precondition": {
            "container_count": len(live_inventory),
            "created_count": sum(
                item.get("state", {}).get("status") == "created"
                for item in live_inventory
            ),
            "exited_count": sum(
                item.get("state", {}).get("status") == "exited"
                for item in live_inventory
            ),
            "running_count": sum(
                item.get("state", {}).get("running") is True for item in live_inventory
            ),
            "container_set_sha256": canonical_sha256(live_inventory),
        },
        "target": {
            "participant_id": target_record.get("participant_id"),
            "execution_did": target_record.get("execution_did"),
            "pair_id": target_record.get("pair_id"),
            "cohort": target_record.get("cohort"),
            "assignment_commitment_sha256": target_record.get(
                "assignment_commitment_sha256"
            ),
            "container_name": target_container_name,
            "exited_container_id": target_live.get("container_id"),
            "observed_state": copy.deepcopy(target_live.get("state")),
            "expected_created_projection": copy.deepcopy(
                target_record.get("container")
            ),
        },
        "operation": {
            "quarantine_exact_exited_container": True,
            "create_same_name_from_frozen_projection": True,
            "start_container": False,
            "remove_quarantined_container_after_complete_set_gate": True,
            "rollback_new_container_and_restore_quarantine_on_failure": True,
            "replace_any_other_container": False,
        },
        "postcondition": {
            "container_count": 40,
            "created_count": 40,
            "exited_count": 0,
            "running_count": 0,
            "same_participant_and_container_name_set": True,
            "same_image_mount_and_runtime_boundary": True,
        },
        "required_checklist": sorted(CHECKLIST),
        "implementation": copy.deepcopy(implementation),
        "execution_boundary": copy.deepcopy(BOUNDARY),
    }
    plan["plan_sha256"] = canonical_sha256(plan)
    failures = validate_repair_plan(
        plan,
        parent_activation=parent_activation,
        live_inventory=live_inventory,
        expected_implementation=implementation,
    )
    if failures:
        raise ValueError(f"infrastructure repair plan invalid: {failures}")
    return plan


def validate_repair_plan(
    value: Any,
    *,
    parent_activation: dict[str, Any],
    live_inventory: list[dict[str, Any]],
    expected_implementation: dict[str, str],
) -> list[str]:
    plan = value if isinstance(value, dict) else {}
    failures: list[str] = []
    body = {key: item for key, item in plan.items() if key != "plan_sha256"}
    _require(
        plan.get("schema_version") == PLAN_SCHEMA
        and _text(plan.get("repair_id"))
        and plan.get("status") == "independent_review_required"
        and plan.get("plan_sha256") == canonical_sha256(body),
        "repair_plan_identity_invalid",
        failures,
    )
    parent_records = parent_activation.get("containers", [])
    parent_names = {
        item.get("container", {}).get("container_name")
        for item in parent_records
        if isinstance(item, dict)
    }
    live_names = {item.get("container_name") for item in live_inventory}
    target = plan.get("target", {})
    target_name = target.get("container_name")
    live_target = next(
        (item for item in live_inventory if item.get("container_name") == target_name),
        {},
    )
    parent_target = next(
        (
            item
            for item in parent_records
            if item.get("container", {}).get("container_name") == target_name
        ),
        {},
    )
    _require(
        parent_activation.get("schema_version")
        == "j1-qualification-infrastructure-activation:v1"
        and parent_activation.get("activation_sha256")
        == canonical_sha256(
            {
                key: item
                for key, item in parent_activation.items()
                if key != "activation_sha256"
            }
        )
        and len(parent_records) == 40
        and parent_names == live_names
        and len(parent_names) == 40,
        "repair_parent_activation_invalid",
        failures,
    )
    _require(
        len(live_inventory) == 40
        and sum(
            item.get("state") == {"status": "created", "running": False}
            for item in live_inventory
        )
        == 39
        and sum(
            item.get("state") == {"status": "exited", "running": False}
            for item in live_inventory
        )
        == 1
        and live_target.get("state") == {"status": "exited", "running": False}
        and target.get("exited_container_id") == live_target.get("container_id"),
        "repair_live_inventory_precondition_invalid",
        failures,
    )
    expected_parent_projection = parent_target.get("container", {})
    expected_target = {
        "participant_id": parent_target.get("participant_id"),
        "execution_did": parent_target.get("execution_did"),
        "pair_id": parent_target.get("pair_id"),
        "cohort": parent_target.get("cohort"),
        "assignment_commitment_sha256": parent_target.get(
            "assignment_commitment_sha256"
        ),
        "container_name": target_name,
        "exited_container_id": live_target.get("container_id"),
        "observed_state": live_target.get("state"),
        "expected_created_projection": expected_parent_projection,
    }
    _require(
        target == expected_target
        and live_target.get("image_id") == expected_parent_projection.get("image_id")
        and live_target.get("config_sha256")
        == expected_parent_projection.get("actual_container_config_sha256"),
        "repair_exact_target_binding_invalid",
        failures,
    )
    inventory = plan.get("inventory_precondition", {})
    _require(
        inventory
        == {
            "container_count": 40,
            "created_count": 39,
            "exited_count": 1,
            "running_count": 0,
            "container_set_sha256": canonical_sha256(live_inventory),
        },
        "repair_inventory_commitment_invalid",
        failures,
    )
    _require(
        plan.get("required_checklist") == sorted(CHECKLIST)
        and plan.get("implementation") == expected_implementation
        and plan.get("execution_boundary") == BOUNDARY,
        "repair_review_or_implementation_binding_invalid",
        failures,
    )
    return list(dict.fromkeys(failures))


def owner_review_statement(plan: dict[str, Any], raw_sha256: str) -> str:
    target = plan["target"]
    return (
        "I approve for independent review only the J1-D single-container "
        f"infrastructure repair plan artifact raw SHA-256 {raw_sha256}, canonical "
        f"SHA-256 {plan['plan_sha256']}, targeting exited container "
        f"{target['container_name']} with immutable prior container ID "
        f"{target['exited_container_id']} for participant {target['participant_id']}. "
        "I acknowledge that the plan permits no container mutation before an "
        "independent signed review and promotion Gate, preserves the parent "
        "40-participant activation as immutable Evidence, forbids participant "
        "substitution, and requires a separate exact repair authorization. This "
        "approval does not rename, remove, create, or start any container, read a "
        "provider credential, call a provider or model, execute an Agent or task, "
        "append Backend Facts, append the Ledger, or issue or consume an execution "
        "authorization."
    )


def build_review_request(
    *,
    request_id: str,
    created_at: str,
    plan_ref: dict[str, str],
    plan: dict[str, Any],
    owner_statement_sha256: str,
) -> dict[str, Any]:
    request = {
        "schema_version": REVIEW_REQUEST_SCHEMA,
        "request_id": request_id,
        "status": "awaiting_independent_operator_decision",
        "created_at": created_at,
        "plan": copy.deepcopy(plan_ref),
        "repair_scope": {
            "repair_id": plan["repair_id"],
            "target": copy.deepcopy(plan["target"]),
            "inventory_precondition": copy.deepcopy(plan["inventory_precondition"]),
            "postcondition": copy.deepcopy(plan["postcondition"]),
        },
        "owner_statement_sha256": owner_statement_sha256,
        "required_checklist": sorted(CHECKLIST),
        "allowed_decision": "approve_single_container_repair",
        "execution_boundary": copy.deepcopy(BOUNDARY),
    }
    request["request_sha256"] = canonical_sha256(request)
    return request


def reviewer_statement(request: dict[str, Any], request_raw_sha256: str) -> str:
    scope = request["repair_scope"]
    return (
        "I have independently reviewed J1-D single-container infrastructure repair "
        f"request raw SHA-256 {request_raw_sha256}, canonical SHA-256 "
        f"{request['request_sha256']} and choose approve_single_container_repair "
        f"for exactly {scope['target']['container_name']}. I confirm all "
        f"{len(CHECKLIST)} required checklist items, disclose all conflicts, affirm "
        "that I am independent from candidate authoring and have completed human "
        "review. I acknowledge that this approval permits only copy-on-write "
        "promotion of the bounded repair plan. It does not rename, remove, create, "
        "or start any container, read a provider credential, call a provider or "
        "model, execute an Agent or task, append Backend Facts, append the Ledger, "
        "or issue or consume an execution authorization."
    )


def build_review_receipt(
    *,
    review_id: str,
    reviewed_at: str,
    request: dict[str, Any],
    request_ref: dict[str, str],
    reviewer: dict[str, Any],
    reviewer_profile_sha256: str,
    statement_sha256: str,
    signer: ReviewSigner,
) -> dict[str, Any]:
    payload = {
        "schema_version": REVIEW_RECEIPT_SCHEMA,
        "review_id": review_id,
        "reviewed_at": reviewed_at,
        "decision": "approve_single_container_repair",
        "request": copy.deepcopy(request_ref),
        "repair_scope": copy.deepcopy(request["repair_scope"]),
        "reviewer": {
            "did": reviewer["did"],
            "public_key_hex": reviewer["public_key_hex"],
            "credential_version": reviewer["credential_version"],
            "signer_kind": reviewer["signer_kind"],
            "profile_sha256": reviewer_profile_sha256,
        },
        "independence": {
            "conflicts_disclosed": True,
            "independent_from_candidate_authoring": True,
            "human_review_completed": True,
        },
        "checklist": {key: True for key in sorted(CHECKLIST)},
        "review_statement_sha256": statement_sha256,
        "execution_boundary": copy.deepcopy(BOUNDARY),
    }
    payload_bytes = _canonical_bytes(payload)
    signature = signer.sign(payload_bytes)
    receipt = {
        **payload,
        "signature": {
            "algorithm": "ed25519",
            "public_key_hex": signer.public_key_hex,
            "signed_payload_sha256": hashlib.sha256(payload_bytes).hexdigest(),
            "value_hex": signature.hex(),
        },
    }
    return receipt


def validate_review_receipt(
    value: Any,
    *,
    request: dict[str, Any],
    request_ref: dict[str, str],
    reviewer_profile_sha256: str,
    statement_sha256: str,
) -> list[str]:
    receipt = value if isinstance(value, dict) else {}
    failures: list[str] = []
    signature = receipt.get("signature", {})
    payload = {key: item for key, item in receipt.items() if key != "signature"}
    payload_bytes = _canonical_bytes(payload)
    reviewer = receipt.get("reviewer", {})
    _require(
        receipt.get("schema_version") == REVIEW_RECEIPT_SCHEMA
        and receipt.get("decision") == "approve_single_container_repair"
        and receipt.get("request") == request_ref
        and receipt.get("repair_scope") == request.get("repair_scope")
        and receipt.get("checklist") == {key: True for key in sorted(CHECKLIST)}
        and receipt.get("review_statement_sha256") == statement_sha256
        and reviewer.get("profile_sha256") == reviewer_profile_sha256
        and receipt.get("execution_boundary") == BOUNDARY,
        "repair_review_receipt_binding_invalid",
        failures,
    )
    _require(
        signature.get("algorithm") == "ed25519"
        and signature.get("public_key_hex") == reviewer.get("public_key_hex")
        and signature.get("signed_payload_sha256")
        == hashlib.sha256(payload_bytes).hexdigest(),
        "repair_review_signature_metadata_invalid",
        failures,
    )
    try:
        VerifyKey(bytes.fromhex(str(signature.get("public_key_hex", "")))).verify(
            payload_bytes, bytes.fromhex(str(signature.get("value_hex", "")))
        )
    except (BadSignatureError, ValueError):
        failures.append("repair_review_signature_invalid")
    return list(dict.fromkeys(failures))


def build_reviewed_repair(
    *,
    plan: dict[str, Any],
    plan_ref: dict[str, str],
    receipt_ref: dict[str, str],
    receipt: dict[str, Any],
) -> dict[str, Any]:
    reviewed = {
        "schema_version": REVIEWED_SCHEMA,
        "repair_id": plan["repair_id"],
        "status": "operator_reviewed",
        "plan": copy.deepcopy(plan_ref),
        "review_receipt": copy.deepcopy(receipt_ref),
        "reviewer": copy.deepcopy(receipt["reviewer"]),
        "parent_activation": copy.deepcopy(plan["parent_activation"]),
        "target": copy.deepcopy(plan["target"]),
        "operation": copy.deepcopy(plan["operation"]),
        "postcondition": copy.deepcopy(plan["postcondition"]),
        "implementation": copy.deepcopy(plan["implementation"]),
        "execution_boundary": copy.deepcopy(BOUNDARY),
    }
    reviewed["reviewed_repair_sha256"] = canonical_sha256(reviewed)
    return reviewed


def repair_authorization_statement(
    *,
    reviewed_raw_sha256: str,
    reviewed: dict[str, Any],
    gate_raw_sha256: str,
    gate_canonical_sha256: str,
) -> str:
    target = reviewed["target"]
    projection = target["expected_created_projection"]
    return (
        "I authorize exactly one bounded J1-D single-container repair operation "
        f"from reviewed artifact raw SHA-256 {reviewed_raw_sha256}, canonical "
        f"SHA-256 {reviewed['reviewed_repair_sha256']}, promoted by Gate raw "
        f"SHA-256 {gate_raw_sha256}, canonical SHA-256 {gate_canonical_sha256}. "
        f"The exact target is exited container {target['container_name']} with "
        f"immutable prior container ID {target['exited_container_id']} for "
        f"participant {target['participant_id']}, using image "
        f"{projection['image_id']}. I authorize quarantine rename of only that "
        "exited container, creation of exactly one stopped replacement under the "
        "same participant-scoped name and frozen mount/runtime boundary, removal "
        "of the quarantined prior container only after a complete-set Gate proves "
        "40 created and 0 running, and bounded rollback of only the newly created "
        "container plus restoration of the quarantine name on failure. I "
        "acknowledge that the parent activation and prior container identity remain "
        "immutable Evidence and no other container may be replaced. This "
        "authorization does not permit starting any container, provider admission "
        "refresh, provider or model calls, Agent or participant task execution, "
        "Backend Fact append, Ledger append, or execution authorization issuance "
        "or consumption."
    )


def _canonical_bytes(value: dict[str, Any]) -> bytes:
    import json

    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode()


def _require(condition: bool, reason: str, failures: list[str]) -> None:
    if not condition:
        failures.append(reason)


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())
