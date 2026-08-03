from __future__ import annotations

import copy
import hashlib

import pytest

from benchmarks.j1.controlled_comparison import canonical_sha256
from benchmarks.j1.qualification_outcome_sensitive_confirmatory_consent import (
    MATERIAL_NAMES,
    authorization_statement,
    build_plan,
    validate_plan,
)


def _ref(seed: str) -> dict[str, str]:
    return {
        "path": f"/private/{seed}.json",
        "sha256": hashlib.sha256(f"raw:{seed}".encode()).hexdigest(),
        "canonical_sha256": hashlib.sha256(f"canonical:{seed}".encode()).hexdigest(),
    }


def _plan() -> dict:
    identities = []
    targets = []
    for index in range(40):
        participant_id = f"j1q-agent-{index:020d}"
        execution_did = f"did:civ:qualification:{index:040d}"
        cohort = "mentor" if index % 2 == 0 else "control"
        identities.append(
            {
                "participant_id": participant_id,
                "execution_did": execution_did,
                "public_key_sha256": hashlib.sha256(
                    f"public:{index}".encode()
                ).hexdigest(),
                "key_label": f"participant-{index}",
                "key_id_hex": f"{index + 1:04x}",
                "profile_artifact_sha256": hashlib.sha256(
                    f"profile-raw:{index}".encode()
                ).hexdigest(),
                "profile_sha256": hashlib.sha256(
                    f"profile:{index}".encode()
                ).hexdigest(),
            }
        )
        targets.append(
            {
                "participant_id": participant_id,
                "execution_did": execution_did,
                "pair_id": f"j1q-pair-{index // 2 + 1:02d}",
                "cohort": cohort,
                "assignment_commitment_sha256": hashlib.sha256(
                    f"assignment:{index // 2}".encode()
                ).hexdigest(),
                "participant_profile_artifact_sha256": hashlib.sha256(
                    f"profile-raw:{index}".encode()
                ).hexdigest(),
                "participant_profile_sha256": hashlib.sha256(
                    f"profile:{index}".encode()
                ).hexdigest(),
                "prior_outcome_consent_artifact_sha256": hashlib.sha256(
                    f"prior-raw:{index}".encode()
                ).hexdigest(),
                "prior_outcome_consent_sha256": hashlib.sha256(
                    f"prior:{index}".encode()
                ).hexdigest(),
            }
        )
    source = {
        "promotion_gate": _ref("promotion"),
        "frozen_review": _ref("frozen"),
        "review_receipt": _ref("receipt"),
        "frozen_materials": {name: _ref(name) for name in sorted(MATERIAL_NAMES)},
        "reviewed_assignment": _ref("assignment"),
        "assignment_gate": _ref("assignment-gate"),
        "participant_provisioning_report": {
            "path": "/private/provisioning.json",
            "sha256": hashlib.sha256(b"provisioning").hexdigest(),
        },
        "prior_outcome_consent_manifest": _ref("prior-manifest"),
        "prior_outcome_consent_gate": _ref("prior-gate"),
        "token_label": "dev-token",
    }
    return build_plan(
        plan_id="j1d-confirmatory-consent-20260804-r1",
        created_at="2026-08-04T01:00:00+00:00",
        source_binding=source,
        participant_identity_set=identities,
        consent_targets=targets,
        implementation={
            "source_revision": "a" * 40,
            "domain_source_sha256": "b" * 64,
            "preflight_source_sha256": "c" * 64,
        },
    )


def test_plan_freezes_exact_40_participant_scope() -> None:
    plan = _plan()
    assert validate_plan(plan) == []
    assert plan["inventory"] == {
        "participant_count": 40,
        "mentor_participant_count": 20,
        "control_participant_count": 20,
        "prior_outcome_consent_count": 40,
        "planned_signature_count": 40,
    }
    assert plan["current_execution_boundary"]["token_login_attempted"] is False
    assert (
        plan["current_execution_boundary"]["execution_authorization_issued_or_consumed"]
        is False
    )


def test_authorization_statement_binds_every_promoted_material() -> None:
    plan = _plan()
    statement = authorization_statement(plan, "d" * 64)
    assert plan["source_binding"]["promotion_gate"]["canonical_sha256"] in statement
    assert (
        plan["source_binding"]["prior_outcome_consent_gate"]["canonical_sha256"]
        in statement
    )
    for ref in plan["source_binding"]["frozen_materials"].values():
        assert ref["canonical_sha256"] in statement
    assert "exactly 40 participant Ed25519 signatures" in statement
    assert "does not authorize participant substitution" in statement


def test_plan_rejects_missing_participant() -> None:
    plan = _plan()
    plan["participant_identity_set"].pop()
    plan["plan_sha256"] = canonical_sha256(
        {key: item for key, item in plan.items() if key != "plan_sha256"}
    )
    assert "confirmatory_consent_identity_set_invalid" in validate_plan(plan)


def test_plan_rejects_prior_consent_inheritance() -> None:
    plan = _plan()
    plan["extension_contract"]["prior_consent_inherited"] = True
    plan["plan_sha256"] = canonical_sha256(
        {key: item for key, item in plan.items() if key != "plan_sha256"}
    )
    assert "confirmatory_consent_extension_contract_invalid" in validate_plan(plan)


def test_plan_rejects_material_inventory_drift() -> None:
    plan = _plan()
    del plan["source_binding"]["frozen_materials"]["verification"]
    plan["plan_sha256"] = canonical_sha256(
        {key: item for key, item in plan.items() if key != "plan_sha256"}
    )
    assert "confirmatory_consent_source_binding_invalid" in validate_plan(plan)


def test_builder_rejects_duplicate_prior_consent() -> None:
    plan = _plan()
    targets = copy.deepcopy(plan["consent_targets"])
    targets[1]["prior_outcome_consent_sha256"] = targets[0][
        "prior_outcome_consent_sha256"
    ]
    with pytest.raises(ValueError, match="inventory"):
        build_plan(
            plan_id=plan["plan_id"],
            created_at=plan["created_at"],
            source_binding=plan["source_binding"],
            participant_identity_set=plan["participant_identity_set"],
            consent_targets=targets,
            implementation=plan["implementation"],
        )
