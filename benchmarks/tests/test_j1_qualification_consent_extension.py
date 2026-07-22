from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

from nacl.signing import SigningKey

from benchmarks.j1.controlled_comparison import canonical_sha256, write_private_json
from benchmarks.j1.qualification_consent_extension import (
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
from benchmarks.j1_qualification_consent_extension_sign import (
    MANIFEST_SCHEMA,
    _execution_boundary,
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


def test_extension_binds_participant_amendment_assignment_and_prior_consent() -> None:
    key = SigningKey(b"p" * 32)
    public_key_hex = key.verify_key.encode().hex()
    plan = _plan()
    identity = {
        **plan["participant_identity_set"][0],
        "participant_id": participant_id(public_key_hex),
        "execution_did": participant_did(public_key_hex),
        "public_key_sha256": hashlib.sha256(bytes.fromhex(public_key_hex)).hexdigest(),
    }
    target = {
        **plan["consent_targets"][0],
        "participant_id": identity["participant_id"],
        "execution_did": identity["execution_did"],
    }
    extension = build_consent_extension(
        extension_id="extension-01",
        signed_at="2026-07-23T09:00:00+08:00",
        target=target,
        identity=identity,
        public_key_hex=public_key_hex,
        plan=plan,
        plan_artifact_sha256="c" * 64,
        preflight_artifact_sha256="d" * 64,
        authorization_id="owner-authorization-r1",
        authorization_statement_sha256="e" * 64,
        nonce=b"n" * 32,
        signer=_Signer(key),
    )

    assert validate_consent_extension(extension) == []
    assert extension["prior_consent"]["inherited"] is False
    assert extension["model_execution_authorized"] is False
    assert extension["downstream_rebind_authorized"] is False

    tampered = copy.deepcopy(extension)
    tampered["prior_consent"]["inherited"] = True
    failures = validate_consent_extension(tampered)
    assert "consent_extension_prior_consent_invalid" in failures
    assert "consent_extension_signature_invalid" in failures
    assert "consent_extension_hash_invalid" in failures


def test_signed_manifest_verifies_exactly_40_extensions(tmp_path: Path) -> None:
    plan = _plan()
    plan_path = tmp_path / "plan.json"
    write_private_json(plan_path, plan)
    plan_raw = plan_path.read_bytes()
    preflight_raw = b'{"passed":true}'
    statement_sha256 = "e" * 64
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
        public_key_hex = key.verify_key.encode().hex()
        extension = build_consent_extension(
            extension_id=f"extension-{index:02d}",
            signed_at="2026-07-23T09:00:00+08:00",
            target=target,
            identity=identity,
            public_key_hex=public_key_hex,
            plan=plan,
            plan_artifact_sha256=hashlib.sha256(plan_raw).hexdigest(),
            preflight_artifact_sha256=hashlib.sha256(preflight_raw).hexdigest(),
            authorization_id="owner-authorization-r1",
            authorization_statement_sha256=statement_sha256,
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
    manifest = {
        "schema_version": MANIFEST_SCHEMA,
        "signing_id": "signing-r1",
        "status": "signed_gate_required",
        "signed_at": "2026-07-23T09:00:00+08:00",
        "source_binding": {
            "plan_artifact_sha256": hashlib.sha256(plan_raw).hexdigest(),
            "plan_sha256": plan["plan_sha256"],
            "preflight_artifact_sha256": hashlib.sha256(preflight_raw).hexdigest(),
            "participant_identity_set_sha256": plan["participant_identity_set_sha256"],
            "amendment_bundle_sha256": plan["source_binding"][
                "amendment_bundle_sha256"
            ],
            "reviewed_assignment_sha256": plan["source_binding"][
                "reviewed_assignment_sha256"
            ],
        },
        "authorization": {
            "authorization_id": "owner-authorization-r1",
            "statement_sha256": statement_sha256,
        },
        "inventory": {
            "participant_count": 40,
            "mentor_participant_count": 20,
            "control_participant_count": 20,
            "signed_extension_count": 40,
            "unique_extension_count": 40,
            "all_signatures_verified": True,
            "prior_consent_inherited": False,
        },
        "extensions": descriptors,
        "implementation": implementation,
        "execution_boundary": _execution_boundary(),
    }
    manifest["manifest_sha256"] = canonical_sha256(manifest)

    assert (
        validate_signed_manifest(
            manifest,
            plan=plan,
            plan_raw=plan_raw,
            preflight_raw=preflight_raw,
            authorization_id="owner-authorization-r1",
            authorization_statement_sha256=statement_sha256,
            implementation=implementation,
        )
        == []
    )

    first_path = Path(descriptors[0]["path"])
    tampered = json.loads(first_path.read_text())
    tampered["cohort_binding"]["cohort"] = "control"
    write_private_json(first_path, tampered)
    failures = validate_signed_manifest(
        manifest,
        plan=plan,
        plan_raw=plan_raw,
        preflight_raw=preflight_raw,
        authorization_id="owner-authorization-r1",
        authorization_statement_sha256=statement_sha256,
        implementation=implementation,
    )
    assert any("consent_extension_binding_invalid" in item for item in failures)
    assert "consent_extension_signature_invalid" in failures
