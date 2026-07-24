from __future__ import annotations

import copy
import hashlib

import pytest
from nacl.signing import SigningKey

from benchmarks.j1.qualification_frozen_execution_abort_closeout import (
    ABORT_REASON,
    build_abort_artifacts,
    build_closeout_gate,
    build_closeout_preflight,
    validate_abort_artifacts,
    validate_closeout_gate,
    validate_closeout_preflight,
)


class _Signer:
    def __init__(self) -> None:
        self.key = SigningKey.generate()

    @property
    def public_key_hex(self) -> str:
        return self.key.verify_key.encode().hex()

    def sign(self, message: bytes) -> bytes:
        return self.key.sign(message).signature


def _ref(name: str) -> dict[str, str]:
    return {
        "path": f"/private/{name}.json",
        "sha256": hashlib.sha256(name.encode()).hexdigest(),
        "canonical_sha256": hashlib.sha256(f"canonical:{name}".encode()).hexdigest(),
    }


def _sources() -> dict:
    claim = {
        "state": "authorization_claimed_execution_must_close_out",
        "run_id": "j1d-run-r3",
        "authorization_id": "authorization-r3",
        "claim_sha256": "a" * 64,
        "single_use": True,
        "execution_scope": {
            "participant_count": 40,
            "matched_pair_count": 20,
            "authorized_task_executions": 320,
        },
    }
    entry = {
        "passed": True,
        "state": "atomic_claim_validated_bounded_execution_entry_allowed",
        "report_sha256": "b" * 64,
        "claim": {"canonical_sha256": claim["claim_sha256"]},
    }
    bundle = {
        "status": "operator_reviewed_frozen",
        "frozen_bundle_sha256": "c" * 64,
    }
    post_run = {
        "status": "operator_reviewed_frozen",
        "terminal_states": {"aborted": "post_run_aborted_operator_closeout_required"},
    }
    closeout = {
        "status": "operator_reviewed_frozen",
        "operator_decision": {"allowed": ["record_aborted_run"]},
        "failure_policy": {"claimed_authorization_reusable": False},
    }
    inventory = {
        "container_count": 40,
        "running_count": 0,
        "container_set_sha256": "d" * 64,
    }
    manifest = {
        "workspace_set_sha256": "e" * 64,
        "input_file_count": 0,
        "output_file_count": 0,
        "symlink_count": 0,
    }
    implementation = {
        "source_revision": "f" * 40,
        "domain_source_sha256": "1" * 64,
        "operation_source_sha256": "2" * 64,
    }
    return {
        "claim_ref": _ref("claim"),
        "claim": claim,
        "entry_gate_ref": _ref("entry"),
        "entry_gate": entry,
        "frozen_bundle_ref": _ref("bundle"),
        "frozen_bundle": bundle,
        "post_run_contract_ref": _ref("post-run"),
        "post_run_contract": post_run,
        "closeout_contract_ref": _ref("closeout"),
        "closeout_contract": closeout,
        "inventory_snapshot": inventory,
        "execution_manifest": manifest,
        "output_root": "/private/post-run-r3",
        "implementation": implementation,
    }


def _preflight(sources: dict | None = None) -> tuple[dict, dict]:
    source = sources or _sources()
    return (
        build_closeout_preflight(
            checked_at="2026-07-25T00:00:00+00:00",
            **source,
        ),
        source,
    )


def _validate_preflight(preflight: dict, sources: dict) -> list[str]:
    return validate_closeout_preflight(
        preflight,
        claim_ref=sources["claim_ref"],
        claim=sources["claim"],
        entry_gate_ref=sources["entry_gate_ref"],
        entry_gate=sources["entry_gate"],
        frozen_bundle_ref=sources["frozen_bundle_ref"],
        frozen_bundle=sources["frozen_bundle"],
        post_run_contract_ref=sources["post_run_contract_ref"],
        post_run_contract=sources["post_run_contract"],
        closeout_contract_ref=sources["closeout_contract_ref"],
        closeout_contract=sources["closeout_contract"],
        inventory_snapshot=sources["inventory_snapshot"],
        execution_manifest=sources["execution_manifest"],
        output_root=sources["output_root"],
        expected_implementation=sources["implementation"],
    )


def test_preflight_binds_zero_execution_abort_and_exact_owner_statement() -> None:
    preflight, sources = _preflight()

    assert _validate_preflight(preflight, sources) == []
    observation = preflight["terminal_observation"]
    assert observation["attempted_task_executions"] == 0
    assert observation["unattempted_task_executions"] == 320
    assert observation["missing_task_reason"] == ABORT_REASON
    statement = preflight["owner_authorization"]["required_exact_statement"]
    assert "record_aborted_run with 0 attempted and 320 unattempted" in statement
    assert "0 tokens, and 0 USD microunits" in statement


def test_preflight_rejects_tamper_and_live_execution_evidence() -> None:
    preflight, sources = _preflight()
    tampered = copy.deepcopy(preflight)
    tampered["terminal_observation"]["provider_call_count"] = 1
    assert "abort_closeout_preflight_invalid" in _validate_preflight(tampered, sources)

    running = copy.deepcopy(sources)
    running["inventory_snapshot"]["running_count"] = 1
    with pytest.raises(ValueError, match="terminal source invalid"):
        _preflight(running)

    nonempty = copy.deepcopy(sources)
    nonempty["execution_manifest"]["output_file_count"] = 1
    with pytest.raises(ValueError, match="terminal source invalid"):
        _preflight(nonempty)


def test_signed_abort_artifacts_account_for_zero_execution() -> None:
    preflight, sources = _preflight()
    signer = _Signer()
    reviewer = {
        "did": "did:civ:testnet:reviewer",
        "public_key_hex": signer.public_key_hex,
        "credential_version": 1,
        "signer_kind": "pkcs11_ed25519",
    }
    preflight_ref = _ref("abort-preflight")
    artifacts = build_abort_artifacts(
        closed_at="2026-07-25T00:01:00+00:00",
        preflight_ref=preflight_ref,
        preflight=preflight,
        owner_authorization_id="owner-closeout-r3",
        owner_statement=preflight["owner_authorization"]["required_exact_statement"],
        reviewer=reviewer,
        reviewer_profile_sha256="3" * 64,
        implementation=sources["implementation"],
        signer=signer,
    )

    assert (
        validate_abort_artifacts(
            **artifacts,
            preflight_ref=preflight_ref,
            preflight=preflight,
            expected_reviewer=reviewer,
            expected_reviewer_profile_sha256="3" * 64,
            expected_implementation=sources["implementation"],
        )
        == []
    )
    assert artifacts["execution_journal"]["execution_events"] == []
    assert artifacts["post_run_receipt"]["budget_reconciliation"]["actual_tokens"] == 0
    assert artifacts["evaluation_report"]["effectiveness_evaluated"] is False
    assert artifacts["operator_closeout_receipt"]["decision"] == "record_aborted_run"


def test_signed_abort_artifacts_reject_statement_signature_and_metric_tamper() -> None:
    preflight, sources = _preflight()
    signer = _Signer()
    reviewer = {
        "did": "did:civ:testnet:reviewer",
        "public_key_hex": signer.public_key_hex,
        "credential_version": 1,
        "signer_kind": "pkcs11_ed25519",
    }
    with pytest.raises(ValueError, match="owner statement mismatch"):
        build_abort_artifacts(
            closed_at="2026-07-25T00:01:00+00:00",
            preflight_ref=_ref("abort-preflight"),
            preflight=preflight,
            owner_authorization_id="owner-closeout-r3",
            owner_statement="wrong",
            reviewer=reviewer,
            reviewer_profile_sha256="3" * 64,
            implementation=sources["implementation"],
            signer=signer,
        )
    artifacts = build_abort_artifacts(
        closed_at="2026-07-25T00:01:00+00:00",
        preflight_ref=_ref("abort-preflight"),
        preflight=preflight,
        owner_authorization_id="owner-closeout-r3",
        owner_statement=preflight["owner_authorization"]["required_exact_statement"],
        reviewer=reviewer,
        reviewer_profile_sha256="3" * 64,
        implementation=sources["implementation"],
        signer=signer,
    )
    tampered = copy.deepcopy(artifacts)
    tampered["evaluation_report"]["effectiveness_verified"] = True
    failures = validate_abort_artifacts(
        **tampered,
        preflight_ref=_ref("abort-preflight"),
        preflight=preflight,
        expected_reviewer=reviewer,
        expected_reviewer_profile_sha256="3" * 64,
        expected_implementation=sources["implementation"],
    )
    assert "evaluation_report_invalid" in failures

    bad_signature = copy.deepcopy(artifacts)
    bad_signature["operator_closeout_receipt"]["signature"]["signature_hex"] = "00" * 64
    failures = validate_abort_artifacts(
        **bad_signature,
        preflight_ref=_ref("abort-preflight"),
        preflight=preflight,
        expected_reviewer=reviewer,
        expected_reviewer_profile_sha256="3" * 64,
        expected_implementation=sources["implementation"],
    )
    assert "abort_closeout_signature_invalid" in failures


def test_closeout_gate_is_terminal_non_promotable_and_tamper_evident() -> None:
    preflight, sources = _preflight()
    signer = _Signer()
    reviewer = {
        "did": "did:civ:testnet:reviewer",
        "public_key_hex": signer.public_key_hex,
        "credential_version": 1,
        "signer_kind": "pkcs11_ed25519",
    }
    preflight_ref = _ref("abort-preflight")
    artifacts = build_abort_artifacts(
        closed_at="2026-07-25T00:01:00+00:00",
        preflight_ref=preflight_ref,
        preflight=preflight,
        owner_authorization_id="owner-closeout-r3",
        owner_statement=preflight["owner_authorization"]["required_exact_statement"],
        reviewer=reviewer,
        reviewer_profile_sha256="3" * 64,
        implementation=sources["implementation"],
        signer=signer,
    )
    refs = {name: _ref(name) for name in artifacts}
    gate = build_closeout_gate(
        checked_at="2026-07-25T00:02:00+00:00",
        preflight_ref=preflight_ref,
        preflight=preflight,
        artifact_refs=refs,
        artifacts=artifacts,
    )

    assert (
        validate_closeout_gate(
            gate,
            preflight_ref=preflight_ref,
            preflight=preflight,
            artifact_refs=refs,
            artifacts=artifacts,
        )
        == []
    )
    assert gate["readiness"]["authorization_reusable"] is False
    assert gate["terminal_summary"]["effectiveness_evaluated"] is False

    tampered = copy.deepcopy(gate)
    tampered["readiness"]["authorization_reusable"] = True
    assert "abort_closeout_gate_invalid" in validate_closeout_gate(
        tampered,
        preflight_ref=preflight_ref,
        preflight=preflight,
        artifact_refs=refs,
        artifacts=artifacts,
    )
