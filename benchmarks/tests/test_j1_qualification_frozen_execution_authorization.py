from __future__ import annotations

import copy
import hashlib
import json
from datetime import datetime, timezone

import pytest
from nacl.signing import SigningKey

from benchmarks.j1.qualification_frozen_execution_authorization import (
    AUTHORIZATION_BOUNDARY,
    build_authorization,
    build_gate_report,
    validate_authorization,
    validate_gate_report,
)
from benchmarks.j1.qualification_frozen_execution_preflight import (
    SOURCE_NAMES,
    build_execution_plan,
    build_preflight,
)
from benchmarks.j1.qualification_reviewer_identity import (
    build_reviewer_identity_profile,
)


NOW = datetime(2026, 7, 24, 12, 0, tzinfo=timezone.utc)
IMPLEMENTATION = {
    "source_revision": "a" * 40,
    "domain_source_sha256": "b" * 64,
    "operation_source_sha256": "c" * 64,
}


class _Signer:
    def __init__(self, key: SigningKey) -> None:
        self.key = key

    @property
    def public_key_hex(self) -> str:
        return self.key.verify_key.encode().hex()

    def sign(self, message: bytes) -> bytes:
        return self.key.sign(message).signature


def _source() -> tuple[dict, bytes, dict, bytes]:
    sources = {
        name: {
            "path": f"/private/{name}.json",
            "sha256": hashlib.sha256(f"raw:{name}".encode()).hexdigest(),
            "canonical_sha256": hashlib.sha256(
                f"canonical:{name}".encode()
            ).hexdigest(),
        }
        for name in SOURCE_NAMES
    }
    plan = build_execution_plan(
        run_id="j1d-qualification-run-r1",
        created_at=NOW.isoformat(),
        ttl_seconds=1800,
        source_artifacts=sources,
        execution_scope={
            "provider_id": "openai_compatible",
            "provider_host": "api.deepseek.com",
            "model_id": "deepseek-v4-pro",
            "temperature": 0,
            "participant_count": 40,
            "mentor_participant_count": 20,
            "control_participant_count": 20,
            "matched_pair_count": 20,
            "task_count_per_participant": 8,
            "authorized_task_executions": 320,
            "same_stack_for_both_cohorts": True,
            "cohort_source": "reviewed_rebound_assignment",
            "outcome_evaluator_status": "operator_reviewed_frozen",
            "post_run_contract_status": "operator_reviewed_frozen",
            "operator_closeout_contract_status": "operator_reviewed_frozen",
        },
        cost_acknowledgement={
            "currency": "usd_microunit",
            "authorized_provider_calls": 320,
            "aggregate_reserved_tokens": 800000,
            "aggregate_reserved_cost_microunits": 487360,
            "aggregate_protocol_max_cost_microunits": 4000000,
            "reservation_required_before_each_call": True,
            "actual_usage_reconciliation_required": True,
            "budget_overrun_fail_stop_required": True,
        },
        controls={
            "single_use": True,
            "atomic_claim_create_exclusive": True,
            "claimed_failure_requires_new_authorization": True,
            "unclaimed_expiry_requires_new_authorization": True,
            "container_state_recheck_before_claim": True,
            "provider_admission_recheck_before_claim": True,
            "post_run_receipt_required": True,
            "operator_closeout_required": True,
            "backend_fact_append_allowed": False,
            "ledger_append_allowed": False,
            "effectiveness_claim_before_closeout_allowed": False,
            "execution_root": "/private/run",
            "authorization_output_root": "/private/authorization",
            "authorization_consumption_path": "/private/claim.json",
            "post_run_output_root": "/private/post-run",
        },
        implementation=IMPLEMENTATION,
    )
    plan_bytes = json.dumps(plan, sort_keys=True).encode()
    preflight = build_preflight(
        plan_path="/private/plan.json",
        plan_bytes=plan_bytes,
        plan=plan,
        created_at=NOW.isoformat(),
        inventory_snapshot={"running_count": 0},
    )
    preflight_bytes = json.dumps(preflight, sort_keys=True).encode()
    return plan, plan_bytes, preflight, preflight_bytes


def _reviewer(key: SigningKey) -> dict:
    challenge = b"d" * 32
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


def _authorization() -> tuple[dict, dict, bytes, dict, bytes, dict]:
    plan, plan_bytes, preflight, preflight_bytes = _source()
    key = SigningKey.generate()
    reviewer = _reviewer(key)
    profile_hash = hashlib.sha256(
        json.dumps(reviewer, sort_keys=True).encode()
    ).hexdigest()
    authorization = build_authorization(
        authorization_id="authorization-r1",
        owner_authorization_id="owner-r1",
        owner_statement_sha256=preflight["owner_authorization"]["statement_sha256"],
        issued_at=NOW.isoformat(),
        ttl_seconds=1800,
        plan_path="/private/plan.json",
        plan_bytes=plan_bytes,
        plan=plan,
        preflight_path="/private/preflight.json",
        preflight_bytes=preflight_bytes,
        preflight=preflight,
        reviewer_profile=reviewer,
        reviewer_profile_sha256=profile_hash,
        implementation=IMPLEMENTATION,
        signer=_Signer(key),
    )
    return authorization, plan, plan_bytes, preflight, preflight_bytes, reviewer


def test_signed_frozen_authorization_validates_and_is_not_consumed() -> None:
    authorization, plan, plan_bytes, preflight, preflight_bytes, reviewer = (
        _authorization()
    )

    assert (
        validate_authorization(
            authorization,
            plan_path="/private/plan.json",
            plan_bytes=plan_bytes,
            plan=plan,
            preflight_path="/private/preflight.json",
            preflight_bytes=preflight_bytes,
            preflight=preflight,
            reviewer_profile=reviewer,
            reviewer_profile_sha256=authorization["reviewer"][
                "identity_profile_sha256"
            ],
            expected_implementation=IMPLEMENTATION,
            current_time=NOW,
            require_current=True,
        )
        == []
    )
    assert authorization["execution_boundary"] == AUTHORIZATION_BOUNDARY


@pytest.mark.parametrize(
    ("field", "value", "failure"),
    [
        ("execution_scope", {}, "frozen_authorization_execution_scope_invalid"),
        (
            "cost_acknowledgement",
            {},
            "frozen_authorization_cost_acknowledgement_invalid",
        ),
        ("controls", {}, "frozen_authorization_controls_invalid"),
        (
            "execution_boundary",
            {},
            "frozen_authorization_boundary_invalid",
        ),
    ],
)
def test_authorization_rejects_scope_cost_control_or_boundary_tamper(
    field: str, value: object, failure: str
) -> None:
    authorization, plan, plan_bytes, preflight, preflight_bytes, reviewer = (
        _authorization()
    )
    authorization[field] = value

    failures = validate_authorization(
        authorization,
        plan_path="/private/plan.json",
        plan_bytes=plan_bytes,
        plan=plan,
        preflight_path="/private/preflight.json",
        preflight_bytes=preflight_bytes,
        preflight=preflight,
        reviewer_profile=reviewer,
        reviewer_profile_sha256=authorization["reviewer"]["identity_profile_sha256"],
        expected_implementation=IMPLEMENTATION,
    )
    assert failure in failures
    assert "frozen_authorization_signature_contract_invalid" in failures


def test_authorization_rejects_expired_or_signature_tamper() -> None:
    authorization, plan, plan_bytes, preflight, preflight_bytes, reviewer = (
        _authorization()
    )
    expired = validate_authorization(
        authorization,
        plan_path="/private/plan.json",
        plan_bytes=plan_bytes,
        plan=plan,
        preflight_path="/private/preflight.json",
        preflight_bytes=preflight_bytes,
        preflight=preflight,
        reviewer_profile=reviewer,
        reviewer_profile_sha256=authorization["reviewer"]["identity_profile_sha256"],
        expected_implementation=IMPLEMENTATION,
        current_time=datetime(2026, 7, 24, 13, 0, tzinfo=timezone.utc),
        require_current=True,
    )
    assert "frozen_authorization_not_current" in expired

    tampered = copy.deepcopy(authorization)
    tampered["signature"]["signature_hex"] = "00" * 64
    failures = validate_authorization(
        tampered,
        plan_path="/private/plan.json",
        plan_bytes=plan_bytes,
        plan=plan,
        preflight_path="/private/preflight.json",
        preflight_bytes=preflight_bytes,
        preflight=preflight,
        reviewer_profile=reviewer,
        reviewer_profile_sha256=authorization["reviewer"]["identity_profile_sha256"],
        expected_implementation=IMPLEMENTATION,
    )
    assert "frozen_authorization_signature_invalid" in failures


def test_issuance_gate_requires_atomic_claim_preflight() -> None:
    authorization, plan, _, preflight, _, _ = _authorization()
    authorization_bytes = json.dumps(authorization, sort_keys=True).encode()
    gate = build_gate_report(
        checked_at=NOW.isoformat(),
        authorization_path="/private/authorization.json",
        authorization_bytes=authorization_bytes,
        authorization=authorization,
        plan=plan,
        preflight=preflight,
        inventory_snapshot={"running_count": 0},
    )

    assert (
        validate_gate_report(
            gate,
            authorization_path="/private/authorization.json",
            authorization_bytes=authorization_bytes,
            authorization=authorization,
            plan=plan,
            preflight=preflight,
            expected_inventory_snapshot={"running_count": 0},
        )
        == []
    )
    assert gate["readiness"]["atomic_claim_preflight_required"] is True
    assert gate["readiness"]["atomic_claim_allowed_by_this_gate"] is False
    assert gate["readiness"]["controlled_experiment_execution_ready"] is False


def test_issuance_gate_rejects_readiness_tamper() -> None:
    authorization, plan, _, preflight, _, _ = _authorization()
    authorization_bytes = json.dumps(authorization, sort_keys=True).encode()
    gate = build_gate_report(
        checked_at=NOW.isoformat(),
        authorization_path="/private/authorization.json",
        authorization_bytes=authorization_bytes,
        authorization=authorization,
        plan=plan,
        preflight=preflight,
        inventory_snapshot={"running_count": 0},
    )
    gate["readiness"]["controlled_experiment_execution_ready"] = True

    failures = validate_gate_report(
        gate,
        authorization_path="/private/authorization.json",
        authorization_bytes=authorization_bytes,
        authorization=authorization,
        plan=plan,
        preflight=preflight,
        expected_inventory_snapshot={"running_count": 0},
    )
    assert "frozen_authorization_gate_boundary_invalid" in failures
    assert "frozen_authorization_gate_hash_invalid" in failures


def test_issuance_gate_rejects_expired_authorization() -> None:
    authorization, plan, _, preflight, _, _ = _authorization()
    authorization_bytes = json.dumps(authorization, sort_keys=True).encode()

    with pytest.raises(ValueError, match="gate_validity_invalid"):
        build_gate_report(
            checked_at="2026-07-24T13:00:00+00:00",
            authorization_path="/private/authorization.json",
            authorization_bytes=authorization_bytes,
            authorization=authorization,
            plan=plan,
            preflight=preflight,
            inventory_snapshot={"running_count": 0},
        )
