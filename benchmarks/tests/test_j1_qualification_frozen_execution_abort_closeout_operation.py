from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from nacl.signing import SigningKey

from benchmarks.j1.controlled_comparison import write_private_json
from benchmarks.j1.qualification_frozen_execution_abort_closeout import (
    build_abort_artifacts,
    build_closeout_preflight,
)
from benchmarks.j1_qualification_frozen_execution_abort_closeout import (
    _persist_closeout,
)


class _Signer:
    def __init__(self) -> None:
        self.key = SigningKey.generate()

    @property
    def public_key_hex(self) -> str:
        return self.key.verify_key.encode().hex()

    def sign(self, message: bytes) -> bytes:
        return self.key.sign(message).signature


def _ref(path: str) -> dict[str, str]:
    return {
        "path": path,
        "sha256": hashlib.sha256(path.encode()).hexdigest(),
        "canonical_sha256": hashlib.sha256(f"canonical:{path}".encode()).hexdigest(),
    }


def _preflight(tmp_path: Path, implementation: dict[str, str]) -> dict:
    claim = {
        "state": "authorization_claimed_execution_must_close_out",
        "run_id": "run-r3",
        "authorization_id": "authorization-r3",
        "claim_sha256": "a" * 64,
        "single_use": True,
        "execution_scope": {
            "participant_count": 40,
            "matched_pair_count": 20,
            "authorized_task_executions": 320,
        },
    }
    return build_closeout_preflight(
        checked_at="2026-07-25T00:00:00+00:00",
        claim_ref=_ref("/private/claim.json"),
        claim=claim,
        entry_gate_ref=_ref("/private/entry.json"),
        entry_gate={
            "passed": True,
            "state": "atomic_claim_validated_bounded_execution_entry_allowed",
            "report_sha256": "b" * 64,
            "claim": {"canonical_sha256": claim["claim_sha256"]},
        },
        frozen_bundle_ref=_ref("/private/bundle.json"),
        frozen_bundle={
            "status": "operator_reviewed_frozen",
            "frozen_bundle_sha256": "c" * 64,
        },
        post_run_contract_ref=_ref("/private/post-run-contract.json"),
        post_run_contract={
            "status": "operator_reviewed_frozen",
            "terminal_states": {
                "aborted": "post_run_aborted_operator_closeout_required"
            },
        },
        closeout_contract_ref=_ref("/private/closeout-contract.json"),
        closeout_contract={
            "status": "operator_reviewed_frozen",
            "operator_decision": {"allowed": ["record_aborted_run"]},
            "failure_policy": {"claimed_authorization_reusable": False},
        },
        inventory_snapshot={
            "container_count": 40,
            "running_count": 0,
            "container_set_sha256": "d" * 64,
        },
        execution_manifest={
            "workspace_set_sha256": "e" * 64,
            "input_file_count": 0,
            "output_file_count": 0,
            "symlink_count": 0,
        },
        output_root=str(tmp_path / "post-run-r3"),
        implementation=implementation,
    )


def test_persist_closeout_publishes_one_complete_private_terminal_root(
    tmp_path: Path,
) -> None:
    implementation = {
        "source_revision": "f" * 40,
        "domain_source_sha256": "1" * 64,
        "operation_source_sha256": "2" * 64,
    }
    preflight = _preflight(tmp_path, implementation)
    preflight_path = tmp_path / "abort-preflight.json"
    write_private_json(preflight_path, preflight)
    signer = _Signer()
    reviewer = {
        "did": "did:civ:testnet:reviewer",
        "public_key_hex": signer.public_key_hex,
        "credential_version": 1,
        "signer_kind": "pkcs11_ed25519",
    }
    artifacts = build_abort_artifacts(
        closed_at="2026-07-25T00:01:00+00:00",
        preflight_ref={
            "path": str(preflight_path.resolve()),
            "sha256": hashlib.sha256(preflight_path.read_bytes()).hexdigest(),
            "canonical_sha256": preflight["preflight_sha256"],
        },
        preflight=preflight,
        owner_authorization_id="owner-closeout-r3",
        owner_statement=preflight["owner_authorization"]["required_exact_statement"],
        reviewer=reviewer,
        reviewer_profile_sha256="3" * 64,
        implementation=implementation,
        signer=signer,
    )
    target = tmp_path / "post-run-r3"
    result = _persist_closeout(
        target=target,
        preflight_path=preflight_path,
        preflight=preflight,
        artifacts=artifacts,
        context={
            "reviewer_profile": {"reviewer": reviewer},
            "reviewer_profile_sha256": "3" * 64,
            "implementation": implementation,
        },
    )

    assert result["state"] == (
        "claimed_before_execution_run_aborted_and_signed_closed_out"
    )
    assert target.stat().st_mode & 0o777 == 0o700
    assert len(list(target.iterdir())) == 5
    for path in target.iterdir():
        assert path.stat().st_mode & 0o777 == 0o600
    gate = json.loads((target / "claimed-abort-closeout-gate-report.json").read_text())
    assert all(
        Path(ref["path"]).parent == target.resolve()
        for ref in gate["artifacts"].values()
    )
    assert gate["terminal_summary"]["attempted_task_executions"] == 0
    assert gate["readiness"]["authorization_reusable"] is False

    with pytest.raises(FileExistsError, match="output already exists"):
        _persist_closeout(
            target=target,
            preflight_path=preflight_path,
            preflight=preflight,
            artifacts=artifacts,
            context={
                "reviewer_profile": {"reviewer": reviewer},
                "reviewer_profile_sha256": "3" * 64,
                "implementation": implementation,
            },
        )
    assert not list(tmp_path.glob(".post-run-r3.*"))
