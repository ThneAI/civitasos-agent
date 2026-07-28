from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

from nacl.signing import SigningKey

from benchmarks.j1.controlled_comparison import canonical_sha256, write_private_json
from benchmarks.j1.qualification_outcome_sensitive_consent_extension import (
    AUTHORIZED_OPERATION,
    CONSENT_SCOPE,
    CURRENT_BOUNDARY,
    REQUIRED_MATERIALS,
    authorization_statement,
    build_consent_extension,
    build_consent_extension_plan,
    validate_consent_extension,
    validate_consent_extension_plan,
)
from benchmarks.j1.qualification_participant_provisioning import (
    participant_did,
    participant_id,
)
from benchmarks.j1_qualification_outcome_sensitive_consent_extension_sign import (
    _manifest,
    validate_signed_manifest,
)


class _Signer:
    def __init__(self, key: SigningKey) -> None:
        self.key = key

    @property
    def public_key_hex(self) -> str:
        return self.key.verify_key.encode().hex()

    def sign(self, message: bytes) -> bytes:
        return self.key.sign(message).signature


def _hash(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def _ref(label: str, canonical: bool = True) -> dict[str, str]:
    value = {"path": f"/private/{label}.json", "sha256": _hash(f"{label}:raw")}
    if canonical:
        value["canonical_sha256"] = _hash(f"{label}:canonical")
    return value


def _plan() -> dict:
    public_keys = [
        SigningKey(bytes([index + 1]) * 32).verify_key.encode().hex()
        for index in range(40)
    ]
    identities = [
        {
            "participant_id": participant_id(public_keys[index]),
            "execution_did": participant_did(public_keys[index]),
            "public_key_sha256": hashlib.sha256(
                bytes.fromhex(public_keys[index])
            ).hexdigest(),
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


def test_extension_binds_outcome_material_scope_and_authorization() -> None:
    plan = _plan()
    key = SigningKey(bytes([1]) * 32)
    identity = plan["participant_identity_set"][0]
    target = plan["consent_targets"][0]
    extension = build_consent_extension(
        extension_id="outcome-extension-01",
        signed_at="2026-07-28T15:00:00+00:00",
        target=target,
        identity=identity,
        public_key_hex=key.verify_key.encode().hex(),
        plan=plan,
        plan_artifact_sha256="c" * 64,
        preflight_artifact_sha256="d" * 64,
        authorization_id="outcome-owner-authorization-r1",
        authorization_statement_sha256="e" * 64,
        nonce=b"n" * 32,
        signer=_Signer(key),
    )

    assert validate_consent_extension(extension) == []
    assert extension["scope_binding"]["consent_scope"] == CONSENT_SCOPE
    assert extension["prior_consent"]["inherited"] is False
    assert extension["effectiveness_claim_authorized"] is False

    changed = copy.deepcopy(extension)
    changed["material_binding"]["promotion_gate_sha256"] = "f" * 64
    failures = validate_consent_extension(changed)
    assert "outcome_consent_extension_signature_invalid" in failures
    assert "outcome_consent_extension_hash_invalid" in failures


def test_manifest_replays_exactly_40_participant_signatures(tmp_path: Path) -> None:
    plan = _plan()
    plan_path = tmp_path / "plan.json"
    write_private_json(plan_path, plan)
    plan_raw = plan_path.read_bytes()
    preflight_raw = b'{"passed":true}'
    statement_sha = "e" * 64
    implementation = {"source_revision": "a" * 40, "source_sha256": "b" * 64}
    descriptors = []
    for index, (identity, target) in enumerate(
        zip(
            plan["participant_identity_set"],
            plan["consent_targets"],
            strict=True,
        )
    ):
        key = SigningKey(bytes([index + 1]) * 32)
        extension = build_consent_extension(
            extension_id=f"outcome-extension-{index:02d}",
            signed_at="2026-07-28T15:00:00+00:00",
            target=target,
            identity=identity,
            public_key_hex=key.verify_key.encode().hex(),
            plan=plan,
            plan_artifact_sha256=hashlib.sha256(plan_raw).hexdigest(),
            preflight_artifact_sha256=hashlib.sha256(preflight_raw).hexdigest(),
            authorization_id="outcome-owner-authorization-r1",
            authorization_statement_sha256=statement_sha,
            nonce=index.to_bytes(32),
            signer=_Signer(key),
        )
        path = tmp_path / f"{identity['participant_id']}.json"
        write_private_json(path, extension)
        descriptors.append(
            {
                "path": str(path.resolve()),
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "participant_id": identity["participant_id"],
                "cohort": target["cohort"],
                "canonical_sha256": extension["extension_sha256"],
            }
        )
    manifest = _manifest(
        signing_id="outcome-signing-r1",
        signed_at="2026-07-28T15:00:00+00:00",
        plan=plan,
        plan_raw=plan_raw,
        preflight_raw=preflight_raw,
        authorization_id="outcome-owner-authorization-r1",
        authorization_statement_sha256=statement_sha,
        descriptors=descriptors,
        implementation=implementation,
    )

    assert (
        validate_signed_manifest(
            manifest,
            plan=plan,
            plan_raw=plan_raw,
            preflight_raw=preflight_raw,
            authorization_id="outcome-owner-authorization-r1",
            authorization_statement_sha256=statement_sha,
            implementation=implementation,
        )
        == []
    )

    first_path = Path(descriptors[0]["path"])
    changed = json.loads(first_path.read_text())
    changed["scope_binding"]["consent_scope"]["tasks_per_participant"] = 8
    changed["material_binding"]["promotion_gate_sha256"] = "f" * 64
    write_private_json(first_path, changed)
    failures = validate_signed_manifest(
        manifest,
        plan=plan,
        plan_raw=plan_raw,
        preflight_raw=preflight_raw,
        authorization_id="outcome-owner-authorization-r1",
        authorization_statement_sha256=statement_sha,
        implementation=implementation,
    )
    assert "outcome_consent_extension_scope_invalid" in failures
    assert any(
        item.startswith("outcome_consent_extension_binding_invalid:")
        for item in failures
    )
    assert "outcome_consent_extension_signature_invalid" in failures
