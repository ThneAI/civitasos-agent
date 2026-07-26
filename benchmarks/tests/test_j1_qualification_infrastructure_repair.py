from __future__ import annotations

import copy
import hashlib

from nacl.signing import SigningKey

from benchmarks.j1.controlled_comparison import canonical_sha256
from benchmarks.j1.qualification_infrastructure_repair import (
    CHECKLIST,
    build_repair_plan,
    build_review_receipt,
    build_review_request,
    build_reviewed_repair,
    owner_review_statement,
    repair_authorization_statement,
    reviewer_statement,
    validate_repair_plan,
    validate_review_receipt,
)


class Signer:
    def __init__(self) -> None:
        self.key = SigningKey.generate()

    @property
    def public_key_hex(self) -> str:
        return self.key.verify_key.encode().hex()

    def sign(self, message: bytes) -> bytes:
        return self.key.sign(message).signature


def _parent() -> dict:
    records = []
    for ordinal in range(40):
        name = f"container-{ordinal:02d}"
        projection = {
            "container_id": f"{ordinal:064x}",
            "container_name": name,
            "image_id": "sha256:" + "a" * 64,
            "entrypoint": ["python", "-I", "/runner.py"],
            "command": None,
            "runtime_user": "1000:1000",
            "state": {"status": "created", "running": False},
            "labels": {"participant": f"participant-{ordinal:02d}"},
            "runtime_boundary": {"network_mode": "none"},
            "mounts": [],
            "forbidden_environment_present": [],
            "actual_container_config_sha256": f"{ordinal + 1:064x}",
        }
        records.append(
            {
                "participant_id": f"participant-{ordinal:02d}",
                "execution_did": f"did:test:{ordinal}",
                "pair_id": f"pair-{ordinal // 2:02d}",
                "cohort": "mentor" if ordinal % 2 == 0 else "control",
                "assignment_commitment_sha256": "b" * 64,
                "container": projection,
            }
        )
    parent = {
        "schema_version": "j1-qualification-infrastructure-activation:v1",
        "containers": records,
    }
    parent["activation_sha256"] = canonical_sha256(parent)
    return parent


def _inventory(parent: dict) -> list[dict]:
    values = []
    for ordinal, record in enumerate(parent["containers"]):
        projection = record["container"]
        values.append(
            {
                "container_name": projection["container_name"],
                "container_id": projection["container_id"],
                "image_id": projection["image_id"],
                "state": {
                    "status": "exited" if ordinal == 3 else "created",
                    "running": False,
                },
                "config_sha256": projection["actual_container_config_sha256"],
            }
        )
    return values


def test_single_container_repair_contract_and_signed_review() -> None:
    parent = _parent()
    inventory = _inventory(parent)
    implementation = {
        "source_revision": "c" * 40,
        "domain_source_sha256": "d" * 64,
        "operation_source_sha256": "e" * 64,
    }
    parent_ref = {
        "path": "/private/activation.json",
        "sha256": "f" * 64,
        "canonical_sha256": parent["activation_sha256"],
    }
    plan = build_repair_plan(
        repair_id="repair-r1",
        created_at="2026-07-26T10:00:00+00:00",
        parent_activation_ref=parent_ref,
        parent_activation=parent,
        live_inventory=inventory,
        target_container_name="container-03",
        implementation=implementation,
    )
    assert (
        validate_repair_plan(
            plan,
            parent_activation=parent,
            live_inventory=inventory,
            expected_implementation=implementation,
        )
        == []
    )
    owner_statement = owner_review_statement(plan, "1" * 64)
    assert "container-03" in owner_statement
    plan_ref = {
        "path": "/private/plan.json",
        "sha256": "1" * 64,
        "canonical_sha256": plan["plan_sha256"],
    }
    request = build_review_request(
        request_id="request-r1",
        created_at="2026-07-26T10:01:00+00:00",
        plan_ref=plan_ref,
        plan=plan,
        owner_statement_sha256=hashlib.sha256(owner_statement.encode()).hexdigest(),
    )
    declaration = reviewer_statement(request, "2" * 64)
    signer = Signer()
    reviewer = {
        "did": "did:civ:testnet:reviewer",
        "public_key_hex": signer.public_key_hex,
        "credential_version": 1,
        "signer_kind": "pkcs11_ed25519",
    }
    request_ref = {
        "path": "/private/request.json",
        "sha256": "2" * 64,
        "canonical_sha256": request["request_sha256"],
    }
    receipt = build_review_receipt(
        review_id="review-r1",
        reviewed_at="2026-07-26T10:02:00+00:00",
        request=request,
        request_ref=request_ref,
        reviewer=reviewer,
        reviewer_profile_sha256="3" * 64,
        statement_sha256=hashlib.sha256(declaration.encode()).hexdigest(),
        signer=signer,
    )
    assert (
        validate_review_receipt(
            receipt,
            request=request,
            request_ref=request_ref,
            reviewer_profile_sha256="3" * 64,
            statement_sha256=hashlib.sha256(declaration.encode()).hexdigest(),
        )
        == []
    )
    receipt_ref = {
        "path": "/private/receipt.json",
        "sha256": "4" * 64,
        "canonical_sha256": receipt["signature"]["signed_payload_sha256"],
    }
    reviewed = build_reviewed_repair(
        plan=plan,
        plan_ref=plan_ref,
        receipt_ref=receipt_ref,
        receipt=receipt,
    )
    authorization = repair_authorization_statement(
        reviewed_raw_sha256="5" * 64,
        reviewed=reviewed,
        gate_raw_sha256="6" * 64,
        gate_canonical_sha256="7" * 64,
    )
    assert "exactly one bounded" in authorization
    assert "40 created and 0 running" in authorization
    assert len(CHECKLIST) == 8


def test_repair_plan_rejects_second_exited_container() -> None:
    parent = _parent()
    inventory = _inventory(parent)
    inventory[4]["state"]["status"] = "exited"
    implementation = {
        "source_revision": "c" * 40,
        "domain_source_sha256": "d" * 64,
        "operation_source_sha256": "e" * 64,
    }
    plan = build_repair_plan(
        repair_id="repair-r1",
        created_at="2026-07-26T10:00:00+00:00",
        parent_activation_ref={
            "path": "/private/activation.json",
            "sha256": "f" * 64,
            "canonical_sha256": parent["activation_sha256"],
        },
        parent_activation=parent,
        live_inventory=_inventory(parent),
        target_container_name="container-03",
        implementation=implementation,
    )
    failures = validate_repair_plan(
        plan,
        parent_activation=parent,
        live_inventory=inventory,
        expected_implementation=implementation,
    )
    assert "repair_live_inventory_precondition_invalid" in failures


def test_review_signature_tampering_is_rejected() -> None:
    parent = _parent()
    inventory = _inventory(parent)
    implementation = {
        "source_revision": "c" * 40,
        "domain_source_sha256": "d" * 64,
        "operation_source_sha256": "e" * 64,
    }
    plan = build_repair_plan(
        repair_id="repair-r1",
        created_at="2026-07-26T10:00:00+00:00",
        parent_activation_ref={
            "path": "/private/activation.json",
            "sha256": "f" * 64,
            "canonical_sha256": parent["activation_sha256"],
        },
        parent_activation=parent,
        live_inventory=inventory,
        target_container_name="container-03",
        implementation=implementation,
    )
    request = build_review_request(
        request_id="request-r1",
        created_at="2026-07-26T10:01:00+00:00",
        plan_ref={
            "path": "/private/plan.json",
            "sha256": "1" * 64,
            "canonical_sha256": plan["plan_sha256"],
        },
        plan=plan,
        owner_statement_sha256="2" * 64,
    )
    signer = Signer()
    receipt = build_review_receipt(
        review_id="review-r1",
        reviewed_at="2026-07-26T10:02:00+00:00",
        request=request,
        request_ref={
            "path": "/private/request.json",
            "sha256": "3" * 64,
            "canonical_sha256": request["request_sha256"],
        },
        reviewer={
            "did": "did:civ:testnet:reviewer",
            "public_key_hex": signer.public_key_hex,
            "credential_version": 1,
            "signer_kind": "pkcs11_ed25519",
        },
        reviewer_profile_sha256="4" * 64,
        statement_sha256="5" * 64,
        signer=signer,
    )
    tampered = copy.deepcopy(receipt)
    tampered["repair_scope"]["target"]["container_name"] = "container-04"
    failures = validate_review_receipt(
        tampered,
        request=request,
        request_ref=receipt["request"],
        reviewer_profile_sha256="4" * 64,
        statement_sha256="5" * 64,
    )
    assert "repair_review_receipt_binding_invalid" in failures
    assert "repair_review_signature_invalid" in failures
