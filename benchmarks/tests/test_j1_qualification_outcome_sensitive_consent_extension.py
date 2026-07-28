from __future__ import annotations

import copy
import hashlib

from benchmarks.j1.controlled_comparison import canonical_sha256
from benchmarks.j1.qualification_outcome_sensitive_consent_extension import (
    AUTHORIZED_OPERATION,
    CONSENT_SCOPE,
    CURRENT_BOUNDARY,
    REQUIRED_MATERIALS,
    authorization_statement,
    build_consent_extension_plan,
    validate_consent_extension_plan,
)


def _hash(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def _ref(label: str, canonical: bool = True) -> dict[str, str]:
    value = {"path": f"/private/{label}.json", "sha256": _hash(f"{label}:raw")}
    if canonical:
        value["canonical_sha256"] = _hash(f"{label}:canonical")
    return value


def _plan() -> dict:
    identities = [
        {
            "participant_id": f"participant-{index:02d}",
            "execution_did": f"did:civ:participant:{index:02d}",
            "public_key_sha256": _hash(f"public-key-{index}"),
            "key_label": f"participant-key-{index:02d}",
            "key_id_hex": f"{index + 1:04x}",
            "profile_artifact_sha256": _hash(f"profile-raw-{index}"),
            "profile_sha256": _hash(f"profile-{index}"),
        }
        for index in range(40)
    ]
    targets = [
        {
            "participant_id": identity["participant_id"],
            "execution_did": identity["execution_did"],
            "pair_id": f"pair-{index // 2:02d}",
            "cohort": "mentor" if index % 2 == 0 else "control",
            "assignment_commitment_sha256": _hash(f"assignment-{index // 2}"),
            "participant_profile_artifact_sha256": identity[
                "profile_artifact_sha256"
            ],
            "participant_profile_sha256": identity["profile_sha256"],
            "prior_consent_artifact_sha256": _hash(f"prior-raw-{index}"),
            "prior_consent_sha256": _hash(f"prior-{index}"),
        }
        for index, identity in enumerate(identities)
    ]
    source = {
        "promotion_gate": _ref("promotion-gate"),
        "frozen_review": _ref("frozen-review"),
        "review_receipt": _ref("review-receipt"),
        "frozen_materials": {
            name: _ref(name) for name in sorted(REQUIRED_MATERIALS)
        },
        "reviewed_assignment": _ref("reviewed-assignment"),
        "assignment_gate": _ref("assignment-gate"),
        "participant_provisioning_report": _ref(
            "participant-provisioning",
            canonical=False,
        ),
        "prior_consent_manifest": _ref("prior-consent-manifest"),
        "prior_consent_gate": _ref("prior-consent-gate"),
        "token_label": "dev-token",
    }
    return build_consent_extension_plan(
        plan_id="outcome-consent-r1",
        created_at="2026-07-28T14:00:00+00:00",
        source_binding=source,
        participant_identity_set=identities,
        consent_targets=targets,
        implementation={
            "source_revision": "a" * 40,
            "source_sha256": "b" * 64,
        },
    )


def test_plan_binds_exact_outcome_sensitive_scope_and_40_identities() -> None:
    plan = _plan()

    assert validate_consent_extension_plan(plan) == []
    assert plan["consent_scope"] == CONSENT_SCOPE
    assert plan["inventory"]["participant_count"] == 40
    assert plan["inventory"]["planned_signature_count"] == 40
    assert plan["consent_extension_contract"]["prior_consent_inherited"] is False
    assert plan["authorized_operation_if_approved"] == AUTHORIZED_OPERATION
    assert plan["current_execution_boundary"] == CURRENT_BOUNDARY


def test_plan_rejects_substitution_implicit_consent_and_execution() -> None:
    plan = _plan()
    changed = copy.deepcopy(plan)
    changed["consent_targets"][0]["participant_id"] = "substitute"
    changed["consent_extension_contract"]["prior_consent_inherited"] = True
    changed["authorized_operation_if_approved"]["model_invocation"] = True

    failures = validate_consent_extension_plan(changed)

    assert "outcome_consent_targets_invalid" in failures
    assert "outcome_consent_contract_invalid" in failures
    assert "outcome_consent_boundary_invalid" in failures
    assert "outcome_consent_plan_hash_invalid" in failures


def test_plan_rejects_material_or_scope_drift() -> None:
    plan = _plan()
    changed = copy.deepcopy(plan)
    changed["source_binding"]["frozen_materials"].pop("evaluator")
    changed["consent_scope"]["tasks_per_participant"] = 8

    failures = validate_consent_extension_plan(changed)

    assert "outcome_consent_source_binding_invalid" in failures
    assert "outcome_consent_scope_invalid" in failures
    assert "outcome_consent_plan_hash_invalid" in failures


def test_authorization_statement_binds_all_materials_and_prohibitions() -> None:
    plan = _plan()
    statement = authorization_statement(plan, "c" * 64)

    assert plan["plan_sha256"] in statement
    assert plan["participant_identity_set_sha256"] in statement
    assert plan["source_binding"]["promotion_gate"]["canonical_sha256"] in statement
    assert all(
        material["canonical_sha256"] in statement
        for name, material in plan["source_binding"]["frozen_materials"].items()
        if name != "plan"
    )
    assert "12 tasks per participant" in statement
    assert "decline without penalty" in statement
    assert "exactly 40 participant Ed25519 signatures" in statement
    assert "does not authorize participant substitution" in statement
    assert canonical_sha256(plan) != plan["plan_sha256"]
