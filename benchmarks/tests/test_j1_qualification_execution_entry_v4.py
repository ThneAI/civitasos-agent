from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from benchmarks.j1.qualification_execution_entry_v4 import (
    CLAIM_SCHEMA_V1,
    CLAIM_BOUNDARY,
    ENTRY_BOUNDARY,
    build_claim,
    build_entry_gate,
    validate_claim,
)
from benchmarks.j1.qualification_execution_authorization_v4 import (
    AUTH_SCHEMA,
    AUTH_SCHEMA_V1,
)
from benchmarks.j1_qualification_execution_entry_v4 import _write_exclusive


def _ref(name: str) -> dict[str, str]:
    return {
        "path": f"/private/{name}.json",
        "sha256": hashlib.sha256(f"raw:{name}".encode()).hexdigest(),
        "canonical_sha256": hashlib.sha256(f"canonical:{name}".encode()).hexdigest(),
    }


def _sources() -> tuple[dict, dict]:
    controls = {
        "authorization_claim_path": "/private/run.claim.json",
        "execution_root": "/private/run",
        "post_run_output_root": "/private/post-run",
    }
    authorization = {
        "schema_version": AUTH_SCHEMA,
        "authorization_id": "r4-authorization-r1",
        "run_id": "r4-run-r1",
        "material_bindings": {"material_binding_sha256": "d" * 64},
        "execution_scope": {"authorized_task_executions": 320},
        "budget": {"aggregate_reserved_tokens": 800000},
        "controls": controls,
    }
    preflight = {
        "execution_manifest_sha256": "a" * 64,
        "material_bindings": {"material_binding_sha256": "d" * 64},
    }
    return authorization, preflight


def test_claim_is_single_use_irreversible_and_source_bound() -> None:
    authorization, preflight = _sources()
    implementation = {"source_revision": "b" * 40}
    claim = build_claim(
        claimed_at="2026-07-25T13:00:00+00:00",
        claim_path=authorization["controls"]["authorization_claim_path"],
        owner_authorization_id="owner-r1",
        owner_statement_sha256="c" * 64,
        authorization_ref=_ref("authorization"),
        issuance_gate_ref=_ref("gate"),
        claim_preflight_ref=_ref("preflight"),
        authorization=authorization,
        claim_preflight=preflight,
        implementation=implementation,
    )

    assert (
        validate_claim(
            claim,
            claim_path=authorization["controls"]["authorization_claim_path"],
            authorization_ref=_ref("authorization"),
            issuance_gate_ref=_ref("gate"),
            claim_preflight_ref=_ref("preflight"),
            authorization=authorization,
            claim_preflight=preflight,
            owner_statement_sha256="c" * 64,
            expected_implementation=implementation,
        )
        == []
    )
    assert claim["single_use"] is True
    assert claim["reusable"] is False
    assert claim["material_binding_sha256"] == "d" * 64
    assert claim["execution_boundary"] == CLAIM_BOUNDARY

    tampered = copy.deepcopy(claim)
    tampered["reusable"] = True
    failures = validate_claim(
        tampered,
        claim_path=authorization["controls"]["authorization_claim_path"],
        authorization_ref=_ref("authorization"),
        issuance_gate_ref=_ref("gate"),
        claim_preflight_ref=_ref("preflight"),
        authorization=authorization,
        claim_preflight=preflight,
        owner_statement_sha256="c" * 64,
        expected_implementation=implementation,
    )
    assert "r4_claim_scope_or_boundary_invalid" in failures
    assert "r4_claim_hash_invalid" in failures


def test_entry_gate_keeps_secrets_and_execution_outside_claim_boundary() -> None:
    authorization, preflight = _sources()
    claim = build_claim(
        claimed_at="2026-07-25T13:00:00+00:00",
        claim_path=authorization["controls"]["authorization_claim_path"],
        owner_authorization_id="owner-r1",
        owner_statement_sha256="c" * 64,
        authorization_ref=_ref("authorization"),
        issuance_gate_ref=_ref("gate"),
        claim_preflight_ref=_ref("preflight"),
        authorization=authorization,
        claim_preflight=preflight,
        implementation={"source_revision": "b" * 40},
    )
    gate = build_entry_gate(
        checked_at="2026-07-25T13:00:01+00:00",
        claim_ref=_ref("claim"),
        claim=claim,
        inventory_snapshot={
            "participant_container_count": 40,
            "created_count": 40,
            "running_count": 0,
        },
        execution_manifest_sha256="a" * 64,
    )

    assert gate["execution_boundary"] == ENTRY_BOUNDARY
    assert gate["checks"]["provider_credential_not_read"] is True
    assert gate["checks"]["execution_materials_preclaim_replayed"] is True
    assert gate["checks"]["participant_container_not_started"] is True
    assert gate["readiness"]["signed_closeout_required"] is True


def test_claim_write_is_create_exclusive_and_mode_0600(tmp_path: Path) -> None:
    path = tmp_path / "claims" / "run.claim.json"
    value = {"claim_sha256": "a" * 64}

    _write_exclusive(path, value)

    assert json.loads(path.read_bytes()) == value
    assert path.stat().st_mode & 0o777 == 0o600
    assert path.parent.stat().st_mode & 0o777 == 0o700
    with pytest.raises(FileExistsError):
        _write_exclusive(path, value)


def test_claim_keeps_historical_v1_replayable() -> None:
    authorization, preflight = _sources()
    authorization["schema_version"] = AUTH_SCHEMA_V1
    del authorization["material_bindings"]
    del preflight["material_bindings"]
    implementation = {"source_revision": "b" * 40}
    claim = build_claim(
        claimed_at="2026-07-25T13:00:00+00:00",
        claim_path=authorization["controls"]["authorization_claim_path"],
        owner_authorization_id="owner-r1",
        owner_statement_sha256="c" * 64,
        authorization_ref=_ref("authorization"),
        issuance_gate_ref=_ref("gate"),
        claim_preflight_ref=_ref("preflight"),
        authorization=authorization,
        claim_preflight=preflight,
        implementation=implementation,
    )

    assert claim["schema_version"] == CLAIM_SCHEMA_V1
    assert "material_binding_sha256" not in claim
    assert (
        validate_claim(
            claim,
            claim_path=authorization["controls"]["authorization_claim_path"],
            authorization_ref=_ref("authorization"),
            issuance_gate_ref=_ref("gate"),
            claim_preflight_ref=_ref("preflight"),
            authorization=authorization,
            claim_preflight=preflight,
            owner_statement_sha256="c" * 64,
            expected_implementation=implementation,
        )
        == []
    )
