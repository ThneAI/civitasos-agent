from __future__ import annotations

import copy
import hashlib
import json

import pytest
from nacl.signing import SigningKey

from benchmarks.j1.controlled_comparison import canonical_sha256, write_private_json
from benchmarks.j1.qualification_outcome_sensitive_confirmatory_consent import (
    MATERIAL_NAMES,
    authorization_statement,
    build_extension,
    build_plan,
    validate_extension,
    validate_plan,
)
from benchmarks.j1.qualification_participant_provisioning import (
    participant_did,
    participant_id,
)
from benchmarks.j1_qualification_outcome_sensitive_confirmatory_consent_sign import (
    SIGNING_BOUNDARY,
    _build_manifest,
    validate_manifest,
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
        public_key = SigningKey(bytes([index + 1]) * 32).verify_key.encode()
        public_key_hex = public_key.hex()
        current_participant_id = participant_id(public_key_hex)
        execution_did = participant_did(public_key_hex)
        cohort = "mentor" if index % 2 == 0 else "control"
        identities.append(
            {
                "participant_id": current_participant_id,
                "execution_did": execution_did,
                "public_key_sha256": hashlib.sha256(public_key).hexdigest(),
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
                "participant_id": current_participant_id,
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


class _Signer:
    def __init__(self, key: SigningKey) -> None:
        self._key = key

    @property
    def public_key_hex(self) -> str:
        return self._key.verify_key.encode().hex()

    def sign(self, message: bytes) -> bytes:
        return self._key.sign(message).signature


def _extension(
    plan: dict,
    index: int,
    *,
    plan_artifact_sha256: str = "d" * 64,
    preflight_artifact_sha256: str = "e" * 64,
) -> dict:
    key = SigningKey(bytes([index + 1]) * 32)
    return build_extension(
        extension_id=f"extension-{index}",
        signed_at="2026-08-04T03:00:00+00:00",
        target=plan["consent_targets"][index],
        identity=plan["participant_identity_set"][index],
        public_key_hex=key.verify_key.encode().hex(),
        plan=plan,
        plan_artifact_sha256=plan_artifact_sha256,
        preflight_artifact_sha256=preflight_artifact_sha256,
        authorization_id="confirmatory-consent-authorization",
        authorization_statement_sha256="f" * 64,
        nonce=bytes([index + 41]) * 32,
        signer=_Signer(key),
    )


def test_extension_signature_and_parent_binding_validate() -> None:
    extension = _extension(_plan(), 0)
    assert validate_extension(extension) == []
    assert extension["prior_outcome_consent"]["inherited"] is False
    assert extension["provider_or_model_execution_authorized"] is False


def test_extension_rejects_signature_tamper() -> None:
    extension = _extension(_plan(), 0)
    extension["signature"]["signature_hex"] = "00" * 64
    extension["extension_sha256"] = canonical_sha256(
        {key: item for key, item in extension.items() if key != "extension_sha256"}
    )
    assert "confirmatory_consent_extension_signature_invalid" in validate_extension(
        extension
    )


def test_extension_rejects_non_object_frozen_material() -> None:
    extension = _extension(_plan(), 0)
    extension["confirmatory_material_binding"]["frozen_materials"][
        "exact_paired_method"
    ] = None
    extension["extension_sha256"] = canonical_sha256(
        {key: item for key, item in extension.items() if key != "extension_sha256"}
    )
    assert "confirmatory_consent_extension_material_invalid" in validate_extension(
        extension
    )


def test_manifest_replays_exactly_40_signatures(tmp_path) -> None:
    plan = _plan()
    plan_raw = json.dumps(plan, sort_keys=True).encode()
    preflight_raw = b"{}"
    descriptors = []
    for index in range(40):
        extension = _extension(
            plan,
            index,
            plan_artifact_sha256=hashlib.sha256(plan_raw).hexdigest(),
            preflight_artifact_sha256=hashlib.sha256(preflight_raw).hexdigest(),
        )
        path = tmp_path / f"{index}.json"
        write_private_json(path, extension)
        descriptors.append(
            {
                "path": str(path.resolve()),
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "canonical_sha256": extension["extension_sha256"],
                "participant_id": extension["participant"]["participant_id"],
                "cohort": extension["cohort_binding"]["cohort"],
            }
        )
    implementation = {
        "source_revision": "1" * 40,
        "source_sha256": "2" * 64,
    }
    manifest = _build_manifest(
        signing_id="confirmatory-consent-signing",
        signed_at="2026-08-04T03:00:00+00:00",
        plan=plan,
        plan_raw=plan_raw,
        preflight_raw=preflight_raw,
        authorization_id="confirmatory-consent-authorization",
        authorization_statement_sha256="f" * 64,
        descriptors=descriptors,
        implementation=implementation,
    )
    assert manifest["execution_boundary"] == SIGNING_BOUNDARY
    assert (
        validate_manifest(
            manifest,
            plan=plan,
            plan_raw=plan_raw,
            preflight_raw=preflight_raw,
            authorization_id="confirmatory-consent-authorization",
            authorization_statement_sha256="f" * 64,
            implementation=implementation,
        )
        == []
    )
