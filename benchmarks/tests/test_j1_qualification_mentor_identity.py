from __future__ import annotations

import copy
import hashlib
from pathlib import Path

from nacl.signing import SigningKey

from benchmarks.j1.controlled_comparison import canonical_sha256, write_private_json
from benchmarks.j1.qualification_mentor_identity import (
    build_mentor_identity_profile,
    validate_mentor_identity_profile,
)
from benchmarks.tests.test_j1_qualification_mentor_identity_preflight import _plan
from benchmarks.j1_qualification_mentor_identity_gate import run_gate
from benchmarks.j1_qualification_mentor_identity_gate import (
    CONTRACT_SOURCE,
    GATE_SOURCE,
    OPERATION_SOURCE,
)


NOW = "2026-07-22T13:00:00+00:00"


def _profile() -> tuple[dict, dict]:
    plan = _plan()
    key = SigningKey.generate()
    challenge = b"m" * 32
    implementation = {
        "agent_revision": "a" * 40,
        "contract_source_sha256": hashlib.sha256(
            CONTRACT_SOURCE.read_bytes()
        ).hexdigest(),
        "operation_source_sha256": hashlib.sha256(
            OPERATION_SOURCE.read_bytes()
        ).hexdigest(),
        "gate_source_sha256": hashlib.sha256(GATE_SOURCE.read_bytes()).hexdigest(),
    }
    profile = build_mentor_identity_profile(
        created_at=NOW,
        plan=plan,
        plan_artifact_sha256="1" * 64,
        owner_authorization_id="j1d-owner-mentor-identity-20260722-r1",
        owner_statement_sha256="2" * 64,
        public_key_hex=key.verify_key.encode().hex(),
        module_path=plan["proposed_identity"]["module_path"],
        module_sha256=plan["proposed_identity"]["module_sha256"],
        token_label=plan["proposed_identity"]["token_label"],
        token_serial=plan["proposed_identity"]["token_serial"],
        token_model=plan["proposed_identity"]["token_model"],
        token_manufacturer="SoftHSM project",
        key_label=plan["proposed_identity"]["key_label"],
        key_id_hex=plan["proposed_identity"]["key_id_hex"],
        key_reference_sha256="3" * 64,
        challenge=challenge,
        signature=key.sign(challenge).signature,
        private_key_sensitive=True,
        private_key_extractable=False,
        implementation=implementation,
    )
    return profile, plan


def test_mentor_identity_binds_possession_and_non_execution_boundary() -> None:
    profile, plan = _profile()

    assert validate_mentor_identity_profile(profile, plan=plan) == []
    assert profile["mentor"]["did"].startswith("did:civ:mentor:z")
    assert (
        profile["authorization_boundary"]["treatment_advice_signing_allowed"] is False
    )


def test_mentor_identity_rejects_scope_and_possession_tamper() -> None:
    profile, plan = _profile()
    tampered = copy.deepcopy(profile)
    tampered["authorization_boundary"]["treatment_advice_signing_allowed"] = True
    tampered["possession_proof"]["signature_hex"] = "0" * 128

    failures = validate_mentor_identity_profile(tampered, plan=plan)
    assert "mentor_identity_authorization_boundary_invalid" in failures
    assert "mentor_identity_possession_signature_invalid" in failures
    assert "mentor_identity_hash_mismatch" in failures


def test_mentor_identity_gate_binds_operation_and_sources(tmp_path: Path) -> None:
    profile, plan = _profile()
    paths = {
        "plan": tmp_path / "plan.json",
        "preflight": tmp_path / "preflight.json",
        "mentor_identity": tmp_path / "mentor-identity.json",
        "operation_report": tmp_path / "operation.json",
        "reviewed_design": tmp_path / "reviewed-design.json",
        "design_gate": tmp_path / "design-gate.json",
        "reviewer_identity": tmp_path / "reviewer.json",
        "participant_provisioning_report": tmp_path / "participants.json",
    }
    sources = {
        "reviewed_design": {"reviewed_design_sha256": "a" * 64},
        "design_gate": {"passed": True},
        "reviewer_identity": {"reviewer": "identity"},
        "participant_provisioning_report": {"participant_count": 40},
    }
    for name, value in sources.items():
        write_private_json(paths[name], value)
    source_artifacts = {
        name: {
            "path": str(paths[name].resolve()),
            "sha256": hashlib.sha256(paths[name].read_bytes()).hexdigest(),
        }
        for name in sources
    }
    write_private_json(paths["plan"], plan)
    profile["source_binding"]["provisioning_plan_artifact_sha256"] = hashlib.sha256(
        paths["plan"].read_bytes()
    ).hexdigest()
    profile["profile_sha256"] = canonical_sha256(
        {key: item for key, item in profile.items() if key != "profile_sha256"}
    )
    write_private_json(paths["mentor_identity"], profile)
    write_private_json(paths["preflight"], {"source_artifacts": source_artifacts})
    write_private_json(
        paths["operation_report"],
        {
            "passed": True,
            "state": "mentor_identity_provisioned_advice_authorization_required",
            "mentor_identity": {
                "path": str(paths["mentor_identity"].resolve()),
                "sha256": hashlib.sha256(
                    paths["mentor_identity"].read_bytes()
                ).hexdigest(),
                "canonical_sha256": profile["profile_sha256"],
            },
            "source_artifacts": source_artifacts,
            "authorization": {
                "statement_sha256": profile["source_binding"]["owner_statement_sha256"]
            },
        },
    )

    report = run_gate(
        plan_path=paths["plan"],
        preflight_path=paths["preflight"],
        mentor_identity_path=paths["mentor_identity"],
        operation_report_path=paths["operation_report"],
        reviewed_design_path=paths["reviewed_design"],
        design_gate_path=paths["design_gate"],
        reviewer_profile_path=paths["reviewer_identity"],
        participant_provisioning_report_path=paths["participant_provisioning_report"],
        output_path=tmp_path / "gate.json",
    )

    assert report["passed"] is True, report
    assert report["readiness"]["mentor_identity_bound"] is True
    assert report["readiness"]["treatment_advice_signed"] is False
