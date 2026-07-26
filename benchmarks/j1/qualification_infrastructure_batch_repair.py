"""Contracts for reviewed repair of the complete exited J1-D container set."""

from __future__ import annotations

import copy
import hashlib
import json
from typing import Any, Protocol

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from .controlled_comparison import canonical_sha256


PLAN_SCHEMA = "j1-qualification-infrastructure-batch-repair-plan:v1"
REVIEW_REQUEST_SCHEMA = (
    "j1-qualification-infrastructure-batch-repair-review-request:v1"
)
REVIEW_RECEIPT_SCHEMA = (
    "j1-qualification-infrastructure-batch-repair-review-receipt:v1"
)
REVIEWED_SCHEMA = "j1-qualification-infrastructure-batch-repair:operator-reviewed:v1"
ACTIVATION_SCHEMA = "j1-qualification-infrastructure-batch-repair-activation:v1"
ALLOWED_PARENT_ACTIVATION_SCHEMAS = {
    "j1-qualification-infrastructure-activation:v1",
    "j1-qualification-infrastructure-repair-activation:v1",
    ACTIVATION_SCHEMA,
}
TARGET_COUNT = 2
CHECKLIST = {
    "immutable_parent_activation_reviewed",
    "complete_exited_target_set_reviewed",
    "exact_two_target_participant_bindings_reviewed",
    "content_addressed_images_reviewed",
    "mount_and_runtime_boundaries_reviewed",
    "batch_quarantine_and_rollback_boundary_reviewed",
    "non_target_container_identity_preservation_reviewed",
    "complete_40_container_postcondition_reviewed",
    "no_container_start_or_provider_effect_reviewed",
}
BOUNDARY = {
    "complete_exited_container_set_batch_repair_only": True,
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


def build_batch_repair_plan(
    *,
    repair_id: str,
    created_at: str,
    parent_activation_ref: dict[str, str],
    parent_activation: dict[str, Any],
    live_inventory: list[dict[str, Any]],
    target_container_names: list[str],
    implementation: dict[str, str],
) -> dict[str, Any]:
    record_index = {
        item.get("container", {}).get("container_name"): item
        for item in parent_activation.get("containers", [])
        if isinstance(item, dict)
    }
    live_index = {
        item.get("container_name"): item
        for item in live_inventory
        if isinstance(item, dict)
    }
    names = sorted(set(target_container_names))
    targets = [
        _target_projection(record_index.get(name), live_index.get(name), name)
        for name in names
    ]
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
                item.get("state", {}).get("running") is True
                for item in live_inventory
            ),
            "container_set_sha256": canonical_sha256(live_inventory),
        },
        "targets": targets,
        "operation": {
            "quarantine_complete_exited_set": True,
            "create_same_names_from_frozen_projections": True,
            "start_container": False,
            "remove_quarantined_containers_after_complete_set_gate": True,
            "rollback_new_containers_and_restore_quarantine_on_failure": True,
            "replace_any_other_container": False,
        },
        "postcondition": {
            "container_count": 40,
            "created_count": 40,
            "exited_count": 0,
            "running_count": 0,
            "same_participant_and_container_name_set": True,
            "same_image_mount_and_runtime_boundaries": True,
            "non_target_container_ids_unchanged": True,
        },
        "required_checklist": sorted(CHECKLIST),
        "implementation": copy.deepcopy(implementation),
        "execution_boundary": copy.deepcopy(BOUNDARY),
    }
    plan["plan_sha256"] = canonical_sha256(plan)
    failures = validate_batch_repair_plan(
        plan,
        parent_activation=parent_activation,
        live_inventory=live_inventory,
        expected_implementation=implementation,
    )
    if failures:
        raise ValueError(f"infrastructure batch repair plan invalid: {failures}")
    return plan


def validate_batch_repair_plan(
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
        "batch_repair_plan_identity_invalid",
        failures,
    )
    parent_records = parent_activation.get("containers", [])
    parent_index = {
        item.get("container", {}).get("container_name"): item
        for item in parent_records
        if isinstance(item, dict)
    }
    live_index = {
        item.get("container_name"): item
        for item in live_inventory
        if isinstance(item, dict)
    }
    _require(
        parent_activation.get("schema_version") in ALLOWED_PARENT_ACTIVATION_SCHEMAS
        and parent_activation.get("activation_sha256")
        == canonical_sha256(
            {
                key: item
                for key, item in parent_activation.items()
                if key != "activation_sha256"
            }
        )
        and len(parent_records) == 40
        and len(parent_index) == 40
        and set(parent_index) == set(live_index),
        "batch_repair_parent_activation_invalid",
        failures,
    )
    exited_names = sorted(
        name
        for name, item in live_index.items()
        if item.get("state") == {"status": "exited", "running": False}
    )
    target_values = plan.get("targets", [])
    target_names = [
        item.get("container_name")
        for item in target_values
        if isinstance(item, dict)
    ]
    _require(
        len(live_inventory) == 40
        and sum(
            item.get("state") == {"status": "created", "running": False}
            for item in live_inventory
        )
        == 38
        and len(exited_names) == TARGET_COUNT
        and not any(
            item.get("state", {}).get("running") is True for item in live_inventory
        ),
        "batch_repair_live_inventory_precondition_invalid",
        failures,
    )
    _require(
        len(target_values) == TARGET_COUNT
        and target_names == sorted(set(target_names))
        and target_names == exited_names,
        "batch_repair_complete_exited_target_set_invalid",
        failures,
    )
    expected_targets = [
        _target_projection(parent_index.get(name), live_index.get(name), name)
        for name in exited_names
    ]
    _require(
        target_values == expected_targets
        and all(
            live_index[name].get("image_id")
            == parent_index[name].get("container", {}).get("image_id")
            and live_index[name].get("config_sha256")
            == parent_index[name]
            .get("container", {})
            .get("actual_container_config_sha256")
            for name in exited_names
        ),
        "batch_repair_exact_target_bindings_invalid",
        failures,
    )
    _require(
        plan.get("inventory_precondition")
        == {
            "container_count": 40,
            "created_count": 38,
            "exited_count": TARGET_COUNT,
            "running_count": 0,
            "container_set_sha256": canonical_sha256(live_inventory),
        },
        "batch_repair_inventory_commitment_invalid",
        failures,
    )
    _require(
        plan.get("required_checklist") == sorted(CHECKLIST)
        and plan.get("implementation") == expected_implementation
        and plan.get("execution_boundary") == BOUNDARY,
        "batch_repair_review_or_implementation_binding_invalid",
        failures,
    )
    return list(dict.fromkeys(failures))


def owner_review_statement(plan: dict[str, Any], raw_sha256: str) -> str:
    targets = _target_statement(plan["targets"])
    return (
        "I approve for independent review only the J1-D complete-exited-set "
        f"infrastructure batch repair plan artifact raw SHA-256 {raw_sha256}, "
        f"canonical SHA-256 {plan['plan_sha256']}, targeting exactly 2 exited "
        f"containers: {targets}. I acknowledge that these targets are the complete "
        "exited set in the immutable parent 40-participant activation, the plan "
        "permits no container mutation before an independent signed review and "
        "promotion Gate, forbids participant substitution, and requires a separate "
        "exact batch repair authorization. This approval does not rename, remove, "
        "create, or start any container, read a provider credential, call a provider "
        "or model, execute an Agent or task, append Backend Facts, append the Ledger, "
        "or issue or consume an execution authorization."
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
            "targets": copy.deepcopy(plan["targets"]),
            "inventory_precondition": copy.deepcopy(plan["inventory_precondition"]),
            "postcondition": copy.deepcopy(plan["postcondition"]),
        },
        "owner_statement_sha256": owner_statement_sha256,
        "required_checklist": sorted(CHECKLIST),
        "allowed_decision": "approve_complete_exited_set_batch_repair",
        "execution_boundary": copy.deepcopy(BOUNDARY),
    }
    request["request_sha256"] = canonical_sha256(request)
    return request


def reviewer_statement(request: dict[str, Any], request_raw_sha256: str) -> str:
    targets = _target_statement(request["repair_scope"]["targets"])
    return (
        "I have independently reviewed J1-D complete-exited-set infrastructure "
        f"batch repair request raw SHA-256 {request_raw_sha256}, canonical SHA-256 "
        f"{request['request_sha256']} and choose "
        f"approve_complete_exited_set_batch_repair for exactly: {targets}. I confirm "
        f"all {len(CHECKLIST)} required checklist items, disclose all conflicts, "
        "affirm that I am independent from candidate authoring and have completed "
        "human review. I acknowledge that this approval permits only copy-on-write "
        "promotion of the bounded batch repair plan. It does not rename, remove, "
        "create, or start any container, read a provider credential, call a provider "
        "or model, execute an Agent or task, append Backend Facts, append the Ledger, "
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
        "decision": "approve_complete_exited_set_batch_repair",
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
    receipt = {
        **payload,
        "signature": {
            "algorithm": "ed25519",
            "public_key_hex": signer.public_key_hex,
            "signed_payload_sha256": hashlib.sha256(payload_bytes).hexdigest(),
            "value_hex": signer.sign(payload_bytes).hex(),
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
        and receipt.get("decision") == "approve_complete_exited_set_batch_repair"
        and receipt.get("request") == request_ref
        and receipt.get("repair_scope") == request.get("repair_scope")
        and receipt.get("checklist") == {key: True for key in sorted(CHECKLIST)}
        and receipt.get("review_statement_sha256") == statement_sha256
        and reviewer.get("profile_sha256") == reviewer_profile_sha256
        and receipt.get("execution_boundary") == BOUNDARY,
        "batch_repair_review_receipt_binding_invalid",
        failures,
    )
    _require(
        signature.get("algorithm") == "ed25519"
        and signature.get("public_key_hex") == reviewer.get("public_key_hex")
        and signature.get("signed_payload_sha256")
        == hashlib.sha256(payload_bytes).hexdigest(),
        "batch_repair_review_signature_metadata_invalid",
        failures,
    )
    try:
        VerifyKey(bytes.fromhex(str(signature.get("public_key_hex", "")))).verify(
            payload_bytes, bytes.fromhex(str(signature.get("value_hex", "")))
        )
    except (BadSignatureError, ValueError):
        failures.append("batch_repair_review_signature_invalid")
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
        "targets": copy.deepcopy(plan["targets"]),
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
    targets = _target_statement(reviewed["targets"], include_image=True)
    return (
        "I authorize exactly one bounded J1-D complete-exited-set infrastructure "
        f"batch repair operation from reviewed artifact raw SHA-256 "
        f"{reviewed_raw_sha256}, canonical SHA-256 "
        f"{reviewed['reviewed_repair_sha256']}, promoted by Gate raw SHA-256 "
        f"{gate_raw_sha256}, canonical SHA-256 {gate_canonical_sha256}. The exact "
        f"targets are: {targets}. I authorize quarantine rename of exactly those 2 "
        "exited containers, creation of exactly 2 stopped replacements under the "
        "same participant-scoped names and frozen mount/runtime boundaries, removal "
        "of the quarantined prior containers only after a complete-set Gate proves "
        "40 created and 0 running with all 38 non-target container IDs unchanged, "
        "and bounded rollback of only replacements and quarantine names created by "
        "this operation before the cleanup commit point. I acknowledge that the "
        "parent activation and prior container identities remain immutable Evidence "
        "and no other container may be replaced. This authorization does not permit "
        "starting any container, provider admission refresh, provider or model calls, "
        "Agent or participant task execution, Backend Fact append, Ledger append, or "
        "execution authorization issuance or consumption."
    )


def _target_projection(
    record: Any, live: Any, container_name: str
) -> dict[str, Any]:
    if not isinstance(record, dict) or not isinstance(live, dict):
        raise ValueError("infrastructure batch repair target is outside parent activation")
    return {
        "participant_id": record.get("participant_id"),
        "execution_did": record.get("execution_did"),
        "pair_id": record.get("pair_id"),
        "cohort": record.get("cohort"),
        "assignment_commitment_sha256": record.get(
            "assignment_commitment_sha256"
        ),
        "container_name": container_name,
        "exited_container_id": live.get("container_id"),
        "observed_state": copy.deepcopy(live.get("state")),
        "expected_created_projection": copy.deepcopy(record.get("container")),
    }


def _target_statement(
    targets: list[dict[str, Any]], *, include_image: bool = False
) -> str:
    values = []
    for target in targets:
        value = (
            f"container {target['container_name']} with immutable prior container ID "
            f"{target['exited_container_id']} for participant "
            f"{target['participant_id']}"
        )
        if include_image:
            value += (
                f" using image {target['expected_created_projection']['image_id']}"
            )
        values.append(value)
    return "; ".join(values)


def _canonical_bytes(value: dict[str, Any]) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode()


def _require(condition: bool, reason: str, failures: list[str]) -> None:
    if not condition:
        failures.append(reason)


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())
