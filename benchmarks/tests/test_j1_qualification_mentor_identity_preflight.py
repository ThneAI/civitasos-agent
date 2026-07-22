from __future__ import annotations

import copy

from benchmarks.j1.controlled_comparison import canonical_sha256
from benchmarks.j1_qualification_mentor_identity_preflight import (
    PLAN_SCHEMA,
    validate_mentor_identity_plan,
)


def _plan() -> dict:
    identities = [
        {
            "participant_id": f"participant-{index}",
            "execution_did": f"did:civ:qualification:{index}",
            "public_key_sha256": f"{index + 1:064x}",
            "key_label": f"participant-key-{index}",
            "key_id_hex": f"{index + 100:04x}",
            "profile_sha256": f"{index + 200:064x}",
        }
        for index in range(40)
    ]
    value = {
        "schema_version": PLAN_SCHEMA,
        "plan_id": "j1d-mentor-identity-plan-20260722-r1",
        "status": "explicit_owner_authorization_required",
        "created_at": "2026-07-22T12:00:00+00:00",
        "source_binding": {
            "reviewed_design_sha256": "a" * 64,
            "reviewed_design_artifact_sha256": "b" * 64,
            "design_gate_artifact_sha256": "c" * 64,
            "reviewer_identity_artifact_sha256": "d" * 64,
            "participant_provisioning_report_sha256": "e" * 64,
            "participant_identity_set_sha256": canonical_sha256(identities),
            "participant_count": 40,
        },
        "mentor_role": {
            "role": "qualification_treatment_advice_signer",
            "must_not_be_participant": True,
            "must_not_be_reviewer_key": True,
            "participant_identity_set": identities,
        },
        "proposed_identity": {
            "credential_version": 1,
            "signer_kind": "pkcs11_ed25519",
            "module_path": "/usr/lib/softhsm/libsofthsm2.so",
            "module_sha256": "f" * 64,
            "token_label": "dev-token",
            "token_serial": "serial",
            "token_model": "SoftHSM v2",
            "key_label": "civitas-j1-mentor-beta",
            "key_id_hex": "4a32",
            "private_key_sensitive": True,
            "private_key_extractable": False,
            "physical_hsm_claimed": False,
            "production_custody_claimed": False,
            "soft_token_limitations_acknowledgement_required": True,
        },
        "authorized_operation_if_approved": {
            "generate_exactly_one_keypair": True,
            "create_possession_proof": True,
            "write_private_identity_profile": True,
            "rollback_new_key_on_failure": True,
            "sign_treatment_advice": False,
            "provider_api_call": False,
            "model_invocation": False,
            "agent_execution": False,
            "backend_fact_append": False,
            "ledger_append": False,
        },
        "current_execution_boundary": {
            "pin_read": False,
            "token_login_attempted": False,
            "key_generation_performed": False,
            "possession_signature_performed": False,
            "treatment_advice_signed": False,
            "provider_api_call_performed": False,
            "model_invocation_performed": False,
            "agent_execution_performed": False,
            "backend_fact_append_performed": False,
            "ledger_append_performed": False,
        },
    }
    value["plan_sha256"] = canonical_sha256(value)
    return value


def test_mentor_identity_plan_is_review_required_and_non_executing() -> None:
    plan = _plan()

    assert validate_mentor_identity_plan(plan) == []
    assert all(item is False for item in plan["current_execution_boundary"].values())


def test_mentor_identity_plan_rejects_advice_signing_scope_expansion() -> None:
    plan = copy.deepcopy(_plan())
    plan["authorized_operation_if_approved"]["sign_treatment_advice"] = True
    plan["plan_sha256"] = canonical_sha256(
        {key: item for key, item in plan.items() if key != "plan_sha256"}
    )

    assert "mentor_identity_plan_authorized_operation_invalid" in (
        validate_mentor_identity_plan(plan)
    )
