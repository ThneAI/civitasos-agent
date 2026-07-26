from __future__ import annotations

import copy
import hashlib
import subprocess

import pytest
from nacl.signing import SigningKey

from benchmarks.j1.controlled_comparison import canonical_sha256
from benchmarks.j1.qualification_infrastructure_batch_repair import (
    CHECKLIST,
    build_batch_repair_plan,
    build_review_receipt,
    build_review_request,
    build_reviewed_repair,
    owner_review_statement,
    repair_authorization_statement,
    reviewer_statement,
    validate_batch_repair_plan,
    validate_review_receipt,
)
import benchmarks.j1_qualification_infrastructure_batch_repair as operation
from benchmarks.j1_qualification_infrastructure_batch_repair import (
    _rollback_entries,
    _validate_complete_inventory,
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
        "schema_version": "j1-qualification-infrastructure-repair-activation:v1",
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
                    "status": "exited" if ordinal in {3, 7} else "created",
                    "running": False,
                },
                "config_sha256": projection["actual_container_config_sha256"],
            }
        )
    return values


def _implementation() -> dict[str, str]:
    return {
        "source_revision": "c" * 40,
        "domain_source_sha256": "d" * 64,
        "operation_source_sha256": "e" * 64,
    }


def _plan(parent: dict, inventory: list[dict]) -> dict:
    return build_batch_repair_plan(
        repair_id="batch-repair-r1",
        created_at="2026-07-26T10:00:00+00:00",
        parent_activation_ref={
            "path": "/private/activation.json",
            "sha256": "f" * 64,
            "canonical_sha256": parent["activation_sha256"],
        },
        parent_activation=parent,
        live_inventory=inventory,
        target_container_names=["container-07", "container-03"],
        implementation=_implementation(),
    )


def test_batch_repair_contract_and_signed_review() -> None:
    parent = _parent()
    inventory = _inventory(parent)
    plan = _plan(parent, inventory)
    assert (
        validate_batch_repair_plan(
            plan,
            parent_activation=parent,
            live_inventory=inventory,
            expected_implementation=_implementation(),
        )
        == []
    )
    assert [item["container_name"] for item in plan["targets"]] == [
        "container-03",
        "container-07",
    ]
    owner_statement = owner_review_statement(plan, "1" * 64)
    request = build_review_request(
        request_id="request-r1",
        created_at="2026-07-26T10:01:00+00:00",
        plan_ref={
            "path": "/private/plan.json",
            "sha256": "1" * 64,
            "canonical_sha256": plan["plan_sha256"],
        },
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
    reviewed = build_reviewed_repair(
        plan=plan,
        plan_ref=request["plan"],
        receipt_ref={
            "path": "/private/receipt.json",
            "sha256": "4" * 64,
            "canonical_sha256": receipt["signature"]["signed_payload_sha256"],
        },
        receipt=receipt,
    )
    authorization = repair_authorization_statement(
        reviewed_raw_sha256="5" * 64,
        reviewed=reviewed,
        gate_raw_sha256="6" * 64,
        gate_canonical_sha256="7" * 64,
    )
    assert "exactly 2 stopped replacements" in authorization
    assert "all 38 non-target container IDs unchanged" in authorization
    assert "container-03" in authorization and "container-07" in authorization
    assert len(CHECKLIST) == 9


def test_batch_repair_requires_complete_exited_set() -> None:
    parent = _parent()
    inventory = _inventory(parent)
    plan = _plan(parent, inventory)
    plan["targets"] = plan["targets"][:1]
    plan["plan_sha256"] = canonical_sha256(
        {key: item for key, item in plan.items() if key != "plan_sha256"}
    )
    failures = validate_batch_repair_plan(
        plan,
        parent_activation=parent,
        live_inventory=inventory,
        expected_implementation=_implementation(),
    )
    assert "batch_repair_complete_exited_target_set_invalid" in failures


def test_batch_repair_rejects_third_exited_container() -> None:
    parent = _parent()
    inventory = _inventory(parent)
    plan = _plan(parent, inventory)
    inventory[9]["state"]["status"] = "exited"
    failures = validate_batch_repair_plan(
        plan,
        parent_activation=parent,
        live_inventory=inventory,
        expected_implementation=_implementation(),
    )
    assert "batch_repair_live_inventory_precondition_invalid" in failures
    assert "batch_repair_complete_exited_target_set_invalid" in failures


def test_complete_set_gate_changes_only_two_target_ids() -> None:
    parent = _parent()
    before = _inventory(parent)
    after = copy.deepcopy(before)
    targets = {}
    for ordinal in (3, 7):
        name = f"container-{ordinal:02d}"
        after[ordinal]["container_id"] = f"{ordinal + 100:064x}"
        after[ordinal]["state"] = {"status": "created", "running": False}
        targets[name] = {
            "container_name": name,
            "exited_container_id": before[ordinal]["container_id"],
        }
    _validate_complete_inventory(
        parent,
        live_before=before,
        live_after=after,
        target_index=targets,
    )
    after[9]["container_id"] = "f" * 64
    with pytest.raises(
        ValueError, match="infrastructure batch repair complete-set Gate failed"
    ):
        _validate_complete_inventory(
            parent,
            live_before=before,
            live_after=after,
            target_index=targets,
        )


def test_batch_review_signature_tampering_is_rejected() -> None:
    parent = _parent()
    plan = _plan(parent, _inventory(parent))
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
    request_ref = {
        "path": "/private/request.json",
        "sha256": "3" * 64,
        "canonical_sha256": request["request_sha256"],
    }
    receipt = build_review_receipt(
        review_id="review-r1",
        reviewed_at="2026-07-26T10:02:00+00:00",
        request=request,
        request_ref=request_ref,
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
    tampered["repair_scope"]["targets"][0]["participant_id"] = "substituted"
    failures = validate_review_receipt(
        tampered,
        request=request,
        request_ref=request_ref,
        reviewer_profile_sha256="4" * 64,
        statement_sha256="5" * 64,
    )
    assert "batch_repair_review_receipt_binding_invalid" in failures
    assert "batch_repair_review_signature_invalid" in failures


def test_batch_rollback_reverses_only_created_and_quarantined_targets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[list[str], bool]] = []

    def fake_docker(
        arguments: list[str], *, check: bool = True
    ) -> subprocess.CompletedProcess[str]:
        calls.append((arguments, check))
        return subprocess.CompletedProcess(["docker", *arguments], 0, "", "")

    monkeypatch.setattr(operation, "_docker", fake_docker)
    entries = {
        "container-03": {
            "target_name": "container-03",
            "prior_container_id": "3" * 64,
            "replacement_container_id": "a" * 64,
            "quarantined": True,
        },
        "container-07": {
            "target_name": "container-07",
            "prior_container_id": "7" * 64,
            "replacement_container_id": "b" * 64,
            "quarantined": True,
        },
    }

    assert _rollback_entries(entries) == []
    assert calls == [
        (["container", "rm", "b" * 64], False),
        (["container", "rm", "a" * 64], False),
        (["container", "rename", "7" * 64, "container-07"], False),
        (["container", "rename", "3" * 64, "container-03"], False),
    ]


def test_batch_rollback_records_bounded_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_docker(
        arguments: list[str], *, check: bool = True
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(["docker", *arguments], 1, "", "failed")

    monkeypatch.setattr(operation, "_docker", fake_docker)
    entries = {
        "container-03": {
            "target_name": "container-03",
            "prior_container_id": "3" * 64,
            "replacement_container_id": "a" * 64,
            "quarantined": True,
        }
    }
    assert _rollback_entries(entries) == [
        "replacement_remove_failed:container-03",
        "prior_restore_failed:container-03",
    ]
