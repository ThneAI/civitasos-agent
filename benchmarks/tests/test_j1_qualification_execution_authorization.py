from __future__ import annotations

import copy
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from nacl.signing import SigningKey

from benchmarks.j1.qualification_execution_authorization import (
    build_authorization_context,
    build_execution_authorization,
    claim_execution_authorization,
    validate_execution_authorization,
)
from benchmarks.j1.qualification_reviewer_identity import (
    build_reviewer_identity_profile,
)
from benchmarks.j1_qualification_execution_authorization import (
    authorization_statement,
)


NOW = datetime(2026, 7, 22, 0, 0, tzinfo=timezone.utc)
IMPLEMENTATION = {
    "agent_revision": "a" * 40,
    "contract_source_sha256": "b" * 64,
    "operation_source_sha256": "c" * 64,
    "gate_source_sha256": "d" * 64,
}


class _Signer:
    def __init__(self, key: SigningKey) -> None:
        self.key = key

    @property
    def public_key_hex(self) -> str:
        return self.key.verify_key.encode().hex()

    def sign(self, message: bytes) -> bytes:
        return self.key.sign(message).signature


def _reviewer(key: SigningKey) -> dict:
    challenge = b"e" * 32
    return build_reviewer_identity_profile(
        created_at=NOW.isoformat(),
        public_key_hex=key.verify_key.encode().hex(),
        credential_version=1,
        module_path="/usr/lib/softhsm/libsofthsm2.so",
        module_bytes=b"module",
        token_label="dev-token",
        token_serial="serial",
        token_model="SoftHSM v2",
        token_manufacturer="SoftHSM project",
        key_label="reviewer-key",
        key_id_hex="4a31",
        key_reference="pkcs11:reviewer-key",
        challenge=challenge,
        signature=key.sign(challenge).signature,
        private_key_sensitive=True,
        private_key_extractable=False,
    )


def _context(tmp_path: Path) -> dict[str, dict]:
    protocol = {
        "protocol_sha256": "1" * 64,
        "minimum_completed_pairs": 20,
        "task_corpus": {
            "corpus_id": "j1q-heldout-corpus-v1",
            "tasks_sha256": "2" * 64,
            "task_count": 8,
        },
        "frozen_stack": {
            "provider_id": "openai_compatible",
            "model_id": "deepseek-v4-pro",
            "temperature": 0,
            "same_stack_for_both_cohorts": True,
            "budget": {
                "max_tasks": 12,
                "max_tokens": 20000,
                "max_cost_microunits": 100000,
            },
        },
    }
    roster = {
        "roster_sha256": "3" * 64,
        "participants": [
            {"participant_id": f"participant-{index}", "pair_id": f"pair-{index // 2}"}
            for index in range(40)
        ],
    }
    assignment = {"reviewed_assignment_sha256": "a" * 64}
    request = {
        "provider": {
            "kind": "openai_compatible",
            "base_url": "https://api.deepseek.com",
            "model": "deepseek-v4-pro",
        }
    }
    admission = {
        "admission": {
            "request_sha256": "4" * 64,
            "provider_admission": {"host": "api.deepseek.com"},
        }
    }
    return build_authorization_context(
        run_id="j1d-qualification-run-20260722-r1",
        protocol=protocol,
        protocol_artifact_sha256="5" * 64,
        roster=roster,
        roster_artifact_sha256="6" * 64,
        roster_gate_artifact_sha256="7" * 64,
        reviewed_assignment=assignment,
        reviewed_assignment_artifact_sha256="b" * 64,
        assignment_gate_artifact_sha256="c" * 64,
        admission_request=request,
        admission_request_artifact_sha256="8" * 64,
        provider_admission_report=admission,
        provider_admission_artifact_sha256="9" * 64,
        execution_root=tmp_path / "execution",
        consumption_path=tmp_path / "authorization-consumption.json",
    )


def _receipt(tmp_path: Path) -> tuple[dict, dict, dict]:
    key = SigningKey.generate()
    reviewer = _reviewer(key)
    context = _context(tmp_path)
    receipt = build_execution_authorization(
        authorization_id="j1d-execution-authorization-20260722-r1",
        issued_at=NOW.isoformat(),
        ttl_seconds=1800,
        owner_authorization_id="j1d-owner-execution-approval-20260722-r1",
        owner_statement_sha256="a" * 64,
        context=context,
        reviewer_profile=reviewer,
        reviewer_profile_sha256=hashlib.sha256(
            json.dumps(reviewer, sort_keys=True).encode()
        ).hexdigest(),
        implementation=IMPLEMENTATION,
        signer=_Signer(key),
    )
    return receipt, context, reviewer


def _validate(
    receipt: dict,
    context: dict,
    reviewer: dict,
    *,
    current_time: datetime = NOW,
) -> list[str]:
    return validate_execution_authorization(
        receipt,
        expected_context=context,
        reviewer_profile=reviewer,
        reviewer_profile_sha256=receipt["reviewer"]["identity_profile_sha256"],
        expected_implementation=IMPLEMENTATION,
        current_time=current_time,
        require_current=True,
    )


def test_signed_authorization_binds_exact_scope_cost_and_ttl(tmp_path: Path) -> None:
    receipt, context, reviewer = _receipt(tmp_path)

    assert _validate(receipt, context, reviewer) == []
    assert receipt["source_binding"]["qualification_protocol_sha256"] != "1" * 64
    assert receipt["execution_scope"]["participant_count"] == 40
    assert receipt["execution_scope"]["pair_count"] == 20
    assert receipt["source_binding"]["reviewed_assignment_sha256"] == "a" * 64
    assert receipt["cost_acknowledgement"]["aggregate_ceiling"] == {
        "authorized_task_executions": 320,
        "max_tokens": 800000,
        "max_cost_microunits": 4000000,
    }
    assert (
        receipt["execution_boundary"]["controlled_experiment_execution_ready"] is False
    )


def test_authorization_rejects_cost_tamper_and_expiry(tmp_path: Path) -> None:
    receipt, context, reviewer = _receipt(tmp_path)
    tampered = copy.deepcopy(receipt)
    tampered["cost_acknowledgement"]["aggregate_ceiling"]["max_cost_microunits"] += 1

    failures = _validate(tampered, context, reviewer)
    assert "authorization_cost_acknowledgement_binding_invalid" in failures
    assert "authorization_aggregate_budget_invalid" in failures
    assert "authorization_signature_payload_hash_mismatch" in failures
    assert "authorization_signature_invalid" in failures
    assert "authorization_not_current" in _validate(
        receipt, context, reviewer, current_time=NOW + timedelta(seconds=1800)
    )


def test_atomic_claim_rejects_path_drift_and_replay(tmp_path: Path) -> None:
    receipt, _, _ = _receipt(tmp_path)
    path = tmp_path / "authorization-consumption.json"

    with pytest.raises(ValueError, match="path does not match"):
        claim_execution_authorization(
            path=tmp_path / "different.json",
            receipt=receipt,
            receipt_artifact_sha256="1" * 64,
            gate_artifact_sha256="2" * 64,
            claimed_at=NOW.isoformat(),
        )

    claimed = claim_execution_authorization(
        path=path,
        receipt=receipt,
        receipt_artifact_sha256="1" * 64,
        gate_artifact_sha256="2" * 64,
        claimed_at=NOW.isoformat(),
    )
    assert claimed["claim_must_survive_execution_failure"] is True
    assert path.stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        claim_execution_authorization(
            path=path,
            receipt=receipt,
            receipt_artifact_sha256="1" * 64,
            gate_artifact_sha256="2" * 64,
            claimed_at=NOW.isoformat(),
        )


def test_exact_statement_includes_cost_and_failure_boundary(tmp_path: Path) -> None:
    context = _context(tmp_path)
    statement = authorization_statement(
        run_id="j1d-qualification-run-20260722-r1",
        ttl_seconds=1800,
        context=context,
    )

    assert "320 task executions" in statement
    assert "800000 tokens and 4000000 microunits" in statement
    assert "any claimed failure requires new authorization" in statement
    assert "Backend/Ledger writes remain prohibited" in statement
    assert "cohort assignment" in statement
