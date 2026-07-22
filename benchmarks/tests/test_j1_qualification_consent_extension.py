from __future__ import annotations

import copy
import hashlib

from benchmarks.j1.qualification_consent_extension import (
    authorization_statement,
    build_consent_extension_plan,
    validate_consent_extension_plan,
)


def _plan() -> dict:
    identities = [
        {
            "participant_id": f"participant-{index:02d}",
            "execution_did": f"did:civ:qualification:{index:02d}",
            "public_key_sha256": hashlib.sha256(f"key-{index}".encode()).hexdigest(),
            "key_label": f"participant-key-{index:02d}",
            "key_id_hex": f"{index + 1:032x}",
            "profile_sha256": hashlib.sha256(f"profile-{index}".encode()).hexdigest(),
        }
        for index in range(40)
    ]
    targets = [
        {
            "participant_id": identity["participant_id"],
            "execution_did": identity["execution_did"],
            "pair_id": f"pair-{index // 2:02d}",
            "cohort": "mentor" if index % 2 == 0 else "control",
            "assignment_commitment_sha256": hashlib.sha256(
                f"assignment-{index // 2}".encode()
            ).hexdigest(),
            "participant_profile_sha256": identity["profile_sha256"],
            "prior_consent_artifact_sha256": hashlib.sha256(
                f"prior-raw-{index}".encode()
            ).hexdigest(),
            "prior_consent_sha256": hashlib.sha256(
                f"prior-{index}".encode()
            ).hexdigest(),
        }
        for index, identity in enumerate(identities)
    ]
    source = {
        field: hashlib.sha256(field.encode()).hexdigest()
        for field in (
            "amendment_bundle_artifact_sha256",
            "amendment_bundle_sha256",
            "protocol_amendment_artifact_sha256",
            "protocol_amendment_sha256",
            "design_amendment_artifact_sha256",
            "design_amendment_sha256",
            "reviewed_assignment_artifact_sha256",
            "reviewed_assignment_sha256",
            "assignment_gate_artifact_sha256",
            "participant_provisioning_report_artifact_sha256",
            "prior_consent_manifest_artifact_sha256",
            "prior_consent_manifest_sha256",
        )
    }
    source["token_label"] = "dev-token"
    return build_consent_extension_plan(
        plan_id="j1d-consent-extension-plan-r1",
        created_at="2026-07-23T08:30:00+08:00",
        source_binding=source,
        participant_identity_set=identities,
        consent_targets=targets,
        implementation={"source_revision": "a" * 40, "source_sha256": "b" * 64},
    )


def test_plan_requires_40_distinct_non_executable_extensions() -> None:
    plan = _plan()

    assert validate_consent_extension_plan(plan) == []
    assert plan["inventory"] == {
        "participant_count": 40,
        "mentor_participant_count": 20,
        "control_participant_count": 20,
        "prior_consent_count": 40,
        "planned_signature_count": 40,
    }
    assert plan["consent_extension_contract"]["prior_consent_inherited"] is False
    assert plan["authorized_operation_if_approved"]["agent_execution"] is False


def test_plan_rejects_participant_substitution_and_implicit_consent() -> None:
    plan = _plan()
    tampered = copy.deepcopy(plan)
    tampered["consent_targets"][0]["participant_id"] = "substitute"
    tampered["consent_extension_contract"]["prior_consent_inherited"] = True

    failures = validate_consent_extension_plan(tampered)

    assert "consent_extension_targets_invalid" in failures
    assert "consent_extension_contract_invalid" in failures
    assert "consent_extension_plan_hash_invalid" in failures


def test_authorization_statement_is_exactly_plan_bound() -> None:
    plan = _plan()
    statement = authorization_statement(plan, "c" * 64)

    assert plan["plan_sha256"] in statement
    assert plan["participant_identity_set_sha256"] in statement
    assert "exactly 40 participant Ed25519 signatures" in statement
    assert "does not authorize participant substitution" in statement
