from __future__ import annotations

import copy
import json
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path

import pytest

from benchmarks.j1.qualification_frozen_execution_authorization import (
    build_gate_report,
)
from benchmarks.j1.qualification_frozen_execution_claim import (
    CLAIM_BOUNDARY,
    ENTRY_BOUNDARY,
    PREFLIGHT_BOUNDARY,
    build_claim_preflight,
    build_claim_receipt,
    build_execution_entry_gate,
    validate_claim_preflight,
    validate_claim_receipt,
    validate_execution_entry_gate,
    write_claim_exclusive,
)
from benchmarks.tests.test_j1_qualification_frozen_execution_authorization import (
    IMPLEMENTATION,
    NOW,
    _authorization,
)


CLAIM_IMPLEMENTATION = {
    "source_revision": "d" * 40,
    "domain_source_sha256": "e" * 64,
    "operation_source_sha256": "f" * 64,
}
INVENTORY = {
    "container_count": 40,
    "created_count": 40,
    "running_count": 0,
    "participant_count": 40,
    "container_details_persisted": False,
    "container_set_sha256": "1" * 64,
}
MANIFEST = {
    "participant_count": 40,
    "matched_pair_count": 20,
    "task_count_per_participant": 8,
    "task_execution_count": 320,
    "container_count": 40,
    "running_container_count": 0,
    "container_set_sha256": "1" * 64,
    "workspace_set_sha256": "2" * 64,
    "input_directory_count": 40,
    "output_directory_count": 40,
    "input_file_count": 0,
    "output_file_count": 0,
    "symlink_count": 0,
    "provider_id": "openai_compatible",
    "model_id": "deepseek-v4-pro",
    "temperature": 0,
}


def _materials() -> dict:
    authorization, plan, plan_bytes, frozen, frozen_bytes, reviewer = (
        _authorization()
    )
    authorization_bytes = json.dumps(authorization, sort_keys=True).encode()
    gate = build_gate_report(
        checked_at=NOW.isoformat(),
        authorization_path="/private/authorization.json",
        authorization_bytes=authorization_bytes,
        authorization=authorization,
        plan=plan,
        preflight=frozen,
        inventory_snapshot=INVENTORY,
    )
    gate_bytes = json.dumps(gate, sort_keys=True).encode()
    values = {
        "authorization_path": "/private/authorization.json",
        "authorization_bytes": authorization_bytes,
        "authorization": authorization,
        "issuance_gate_path": "/private/authorization-gate.json",
        "issuance_gate_bytes": gate_bytes,
        "issuance_gate": gate,
        "plan_path": "/private/plan.json",
        "plan_bytes": plan_bytes,
        "plan": plan,
        "frozen_preflight_path": "/private/preflight.json",
        "frozen_preflight_bytes": frozen_bytes,
        "frozen_preflight": frozen,
        "reviewer_profile": reviewer,
        "reviewer_profile_sha256": authorization["reviewer"][
            "identity_profile_sha256"
        ],
        "expected_authorization_implementation": IMPLEMENTATION,
        "inventory_snapshot": INVENTORY,
        "execution_manifest": MANIFEST,
        "implementation": CLAIM_IMPLEMENTATION,
    }
    preflight = build_claim_preflight(checked_at=NOW.isoformat(), **values)
    return {**values, "claim_preflight": preflight}


def test_claim_preflight_binds_v3_gate_manifest_and_owner_statement() -> None:
    values = _materials()
    preflight = values.pop("claim_preflight")

    assert validate_claim_preflight(
        preflight,
        **{
            key: value
            for key, value in values.items()
            if key not in {"inventory_snapshot", "execution_manifest", "implementation"}
        },
        expected_inventory_snapshot=INVENTORY,
        expected_execution_manifest=MANIFEST,
        expected_implementation=CLAIM_IMPLEMENTATION,
        current_time=NOW,
        require_current=True,
    ) == []
    assert preflight["execution_boundary"] == PREFLIGHT_BOUNDARY
    assert "create-exclusive atomic claim" in preflight["owner_authorization"][
        "required_exact_statement"
    ]
    assert "320 provider calls" in preflight["owner_authorization"][
        "required_exact_statement"
    ]


def test_claim_preflight_rejects_expiry_inventory_and_manifest_drift() -> None:
    values = _materials()
    preflight = values["claim_preflight"]
    common = {
        key: value
        for key, value in values.items()
        if key
        not in {
            "claim_preflight",
            "inventory_snapshot",
            "execution_manifest",
            "implementation",
        }
    }
    expired = validate_claim_preflight(
        preflight,
        **common,
        expected_inventory_snapshot=INVENTORY,
        expected_execution_manifest=MANIFEST,
        expected_implementation=CLAIM_IMPLEMENTATION,
        current_time=NOW + timedelta(seconds=1800),
        require_current=True,
    )
    assert "frozen_authorization_not_current" in expired

    drifted_inventory = {**INVENTORY, "running_count": 1}
    failures = validate_claim_preflight(
        preflight,
        **common,
        expected_inventory_snapshot=drifted_inventory,
        expected_execution_manifest=MANIFEST,
        expected_implementation=CLAIM_IMPLEMENTATION,
    )
    assert "claim_preflight_inventory_invalid" in failures

    drifted_manifest = {**MANIFEST, "output_file_count": 1}
    failures = validate_claim_preflight(
        preflight,
        **common,
        expected_inventory_snapshot=INVENTORY,
        expected_execution_manifest=drifted_manifest,
        expected_implementation=CLAIM_IMPLEMENTATION,
    )
    assert "claim_preflight_execution_manifest_invalid" in failures


def _claim(values: dict, claim_path: Path) -> tuple[dict, bytes]:
    authorization = values["authorization"]
    preflight = values["claim_preflight"]
    statement = preflight["owner_authorization"]["required_exact_statement"]
    claim = build_claim_receipt(
        claimed_at=(NOW + timedelta(seconds=1)).isoformat(),
        claim_path=str(claim_path),
        owner_authorization_id="owner-claim-r1",
        owner_statement=statement,
        owner_statement_sha256=preflight["owner_authorization"]["statement_sha256"],
        authorization_path=values["authorization_path"],
        authorization_bytes=values["authorization_bytes"],
        authorization=authorization,
        issuance_gate_path=values["issuance_gate_path"],
        issuance_gate_bytes=values["issuance_gate_bytes"],
        issuance_gate=values["issuance_gate"],
        claim_preflight_path="/private/claim-preflight.json",
        claim_preflight_bytes=json.dumps(preflight, sort_keys=True).encode(),
        claim_preflight=preflight,
        implementation=CLAIM_IMPLEMENTATION,
    )
    return claim, json.dumps(preflight, sort_keys=True).encode()


def test_claim_is_create_exclusive_durable_and_replay_safe(tmp_path: Path) -> None:
    values = _materials()
    claim_path = tmp_path / "claims" / "run.claim.json"
    claim, _ = _claim(values, Path("/private/claim.json"))
    claim["controls"]["authorization_consumption_path"] = str(claim_path)
    claim["claim_sha256"] = ""

    def attempt() -> str:
        try:
            write_claim_exclusive(claim_path, claim)
            return "created"
        except FileExistsError:
            return "exists"

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(lambda _: attempt(), range(8)))

    assert results.count("created") == 1
    assert results.count("exists") == 7
    assert claim_path.stat().st_mode & 0o777 == 0o600
    assert json.loads(claim_path.read_text())["claim_sha256"] == claim["claim_sha256"]
    assert claim["execution_boundary"] == CLAIM_BOUNDARY


def test_claim_rejects_wrong_statement_path_and_expired_window(
    tmp_path: Path,
) -> None:
    values = _materials()
    claim_path = Path("/private/claim.json")
    authorization = values["authorization"]
    preflight = values["claim_preflight"]
    common = {
        "claim_path": str(claim_path),
        "owner_authorization_id": "owner-claim-r1",
        "owner_statement_sha256": preflight["owner_authorization"]["statement_sha256"],
        "authorization_path": values["authorization_path"],
        "authorization_bytes": values["authorization_bytes"],
        "authorization": authorization,
        "issuance_gate_path": values["issuance_gate_path"],
        "issuance_gate_bytes": values["issuance_gate_bytes"],
        "issuance_gate": values["issuance_gate"],
        "claim_preflight_path": "/private/claim-preflight.json",
        "claim_preflight_bytes": json.dumps(preflight, sort_keys=True).encode(),
        "claim_preflight": preflight,
        "implementation": CLAIM_IMPLEMENTATION,
    }
    with pytest.raises(ValueError, match="statement/hash mismatch"):
        build_claim_receipt(
            claimed_at=(NOW + timedelta(seconds=1)).isoformat(),
            owner_statement="wrong",
            **common,
        )
    with pytest.raises(ValueError, match="outside its validity window"):
        build_claim_receipt(
            claimed_at=(NOW + timedelta(seconds=1800)).isoformat(),
            owner_statement=preflight["owner_authorization"][
                "required_exact_statement"
            ],
            **common,
        )
    with pytest.raises(ValueError, match="path does not match"):
        build_claim_receipt(
            claimed_at=(NOW + timedelta(seconds=1)).isoformat(),
            claim_path="/private/other.json",
            owner_statement=preflight["owner_authorization"][
                "required_exact_statement"
            ],
            **{key: value for key, value in common.items() if key != "claim_path"},
        )


def test_execution_entry_requires_valid_claim_and_unchanged_live_state(
    tmp_path: Path,
) -> None:
    values = _materials()
    claim_path = Path("/private/claim.json")
    claim, preflight_bytes = _claim(values, claim_path)
    claim_bytes = json.dumps(claim, sort_keys=True).encode()
    preflight = values["claim_preflight"]
    authorization = values["authorization"]
    common = {
        "checked_at": (NOW + timedelta(hours=2)).isoformat(),
        "claim_path": str(claim_path),
        "claim_bytes": claim_bytes,
        "claim": claim,
        "authorization_path": values["authorization_path"],
        "authorization_bytes": values["authorization_bytes"],
        "authorization": authorization,
        "issuance_gate_path": values["issuance_gate_path"],
        "issuance_gate_bytes": values["issuance_gate_bytes"],
        "issuance_gate": values["issuance_gate"],
        "claim_preflight_path": "/private/claim-preflight.json",
        "claim_preflight_bytes": preflight_bytes,
        "claim_preflight": preflight,
        "expected_claim_implementation": CLAIM_IMPLEMENTATION,
        "execution_root_exists": False,
        "post_run_root_exists": False,
    }
    gate = build_execution_entry_gate(
        **common,
        current_inventory_snapshot=INVENTORY,
        current_execution_manifest=MANIFEST,
    )
    assert gate["readiness"]["bounded_execution_entry_allowed"] is True
    assert gate["execution_boundary"] == ENTRY_BOUNDARY
    assert (
        validate_execution_entry_gate(
            gate,
            claim_path=str(claim_path),
            claim_bytes=claim_bytes,
            claim=claim,
            expected_inventory_snapshot=INVENTORY,
            expected_execution_manifest=MANIFEST,
        )
        == []
    )
    tampered_gate = copy.deepcopy(gate)
    tampered_gate["readiness"]["bounded_execution_entry_allowed"] = False
    failures = validate_execution_entry_gate(
        tampered_gate,
        claim_path=str(claim_path),
        claim_bytes=claim_bytes,
        claim=claim,
        expected_inventory_snapshot=INVENTORY,
        expected_execution_manifest=MANIFEST,
    )
    assert "execution_entry_gate_boundary_invalid" in failures
    assert "execution_entry_gate_hash_invalid" in failures

    with pytest.raises(ValueError, match="execution_entry_inventory_drifted"):
        build_execution_entry_gate(
            **common,
            current_inventory_snapshot={**INVENTORY, "running_count": 1},
            current_execution_manifest=MANIFEST,
        )
    with pytest.raises(ValueError, match="execution_entry_manifest_drifted"):
        build_execution_entry_gate(
            **common,
            current_inventory_snapshot=INVENTORY,
            current_execution_manifest={**MANIFEST, "output_file_count": 1},
        )
    with pytest.raises(ValueError, match="execution_entry_root_already_exists"):
        build_execution_entry_gate(
            **{**common, "execution_root_exists": True},
            current_inventory_snapshot=INVENTORY,
            current_execution_manifest=MANIFEST,
        )


def test_claim_receipt_tamper_is_detected(tmp_path: Path) -> None:
    values = _materials()
    claim_path = Path("/private/claim.json")
    claim, preflight_bytes = _claim(values, claim_path)
    preflight = values["claim_preflight"]
    authorization = values["authorization"]
    tampered = copy.deepcopy(claim)
    tampered["execution_scope"]["authorized_task_executions"] = 319

    failures = validate_claim_receipt(
        tampered,
        claim_path=str(claim_path),
        authorization_path=values["authorization_path"],
        authorization_bytes=values["authorization_bytes"],
        authorization=authorization,
        issuance_gate_path=values["issuance_gate_path"],
        issuance_gate_bytes=values["issuance_gate_bytes"],
        issuance_gate=values["issuance_gate"],
        claim_preflight_path="/private/claim-preflight.json",
        claim_preflight_bytes=preflight_bytes,
        claim_preflight=preflight,
        expected_implementation=CLAIM_IMPLEMENTATION,
    )
    assert "claim_execution_scope_invalid" in failures
    assert "claim_hash_invalid" in failures
