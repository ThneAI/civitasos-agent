from __future__ import annotations

import json
from pathlib import Path

from benchmarks.j1.controlled_comparison import canonical_sha256, write_private_json
from benchmarks.j1.qualification_participant_evidence import PACKET_SCHEMA
from benchmarks.j1.qualification_roster import QUALIFICATION_PROTOCOL_SCHEMA
from benchmarks.j1_qualification_admission_gate import DEFAULT_REQUEST
from benchmarks.j1_qualification_protocol_freeze_gate import GATE_SCHEMA
from benchmarks.j1_qualification_roster_intake import prepare_roster_draft


def _request_hash() -> str:
    return canonical_sha256(json.loads(DEFAULT_REQUEST.read_text(encoding="utf-8")))


def _protocol() -> dict:
    return {
        "schema_version": QUALIFICATION_PROTOCOL_SCHEMA,
        "status": "frozen",
        "frozen_at": "2026-07-20T22:00:00+08:00",
        "admission_request_sha256": _request_hash(),
        "task_corpus": {
            "corpus_id": "j1q-heldout-corpus-20260720-r1",
            "tasks_sha256": "1" * 64,
            "task_count": 8,
            "synthetic": False,
        },
        "frozen_stack": {
            "provider_id": "openai_compatible",
            "model_id": "deepseek-v4-pro",
            "budget_id": "j1q-budget-20260720-r1",
            "verifier_id": "j1q-deterministic-verifier:v1",
            "temperature": 0,
            "same_stack_for_both_cohorts": True,
        },
        "minimum_completed_pairs": 20,
        "execution_boundary": {
            "single_use_authorization_required": True,
            "execution_authorized": False,
        },
    }


def _write(path: Path, value: dict) -> Path:
    write_private_json(path, value)
    return path


def _artifact_ref(path: Path) -> dict[str, str]:
    import hashlib

    return {
        "path": path.name,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }


def _common(protocol_hash: str, attestation: str) -> dict:
    return {
        "qualification_protocol_sha256": protocol_hash,
        "attested_at": "2026-07-20T22:10:00+08:00",
        "public_only": True,
        "secret_material_included": False,
        "operator_attestation_sha256": canonical_sha256([attestation]),
    }


def _prepare_evidence(root: Path, protocol: dict) -> None:
    root.mkdir()
    root.chmod(0o700)
    protocol_hash = canonical_sha256(protocol)
    stack = protocol["frozen_stack"]
    packet_stack = {
        "provider_id": stack["provider_id"],
        "model_id": stack["model_id"],
        "budget_id": stack["budget_id"],
        "corpus_id": protocol["task_corpus"]["corpus_id"],
        "verifier_id": stack["verifier_id"],
    }
    for pair_index in range(20):
        pair_id = f"j1q-pair-{pair_index:02d}"
        baseline_path = _write(
            root / f"{pair_id}.baseline.json",
            {
                "schema_version": "j1-qualification-cognitive-baseline:v1",
                **_common(protocol_hash, f"baseline-{pair_index}"),
                "pair_id": pair_id,
                "baseline_commitment_sha256": canonical_sha256(
                    ["cognitive-baseline", pair_index]
                ),
                "assessment_method": "operator-reviewed-cognitive-baseline:v1",
            },
        )
        for member in ("a", "b"):
            participant_id = f"j1q-participant-{pair_index:02d}-{member}"
            execution_did = f"did:civ:qualification:{pair_index:02d}:{member}"
            identity_path = _write(
                root / f"{participant_id}.identity.json",
                {
                    "schema_version": "j1-qualification-identity-snapshot:v1",
                    **_common(protocol_hash, f"identity-{participant_id}"),
                    "participant_id": participant_id,
                    "execution_did": execution_did,
                    "credential_version": 1,
                    "signer_kind": "pkcs11",
                    "public_key_sha256": canonical_sha256(
                        ["public-key", participant_id]
                    ),
                    "identity_state_sha256": canonical_sha256(
                        ["identity-state", participant_id]
                    ),
                },
            )
            custody_path = _write(
                root / f"{participant_id}.custody.json",
                {
                    "schema_version": "j1-qualification-custody-provenance:v1",
                    **_common(protocol_hash, f"custody-{participant_id}"),
                    "participant_id": participant_id,
                    "execution_did": execution_did,
                    "signer_kind": "pkcs11",
                    "non_exportable": True,
                    "key_reference_sha256": canonical_sha256(
                        ["key-reference", participant_id]
                    ),
                },
            )
            isolation_path = _write(
                root / f"{participant_id}.isolation.json",
                {
                    "schema_version": "j1-qualification-isolation-root:v1",
                    **_common(protocol_hash, f"isolation-{participant_id}"),
                    "participant_id": participant_id,
                    "execution_did": execution_did,
                    "isolation_id": f"j1q-isolation-{pair_index:02d}-{member}",
                    "isolation_commitment_sha256": canonical_sha256(
                        ["isolation", participant_id]
                    ),
                    "exclusive_assignment": True,
                },
            )
            consent_path = _write(
                root / f"{participant_id}.consent.json",
                {
                    "schema_version": "j1-qualification-consent-receipt:v1",
                    **_common(protocol_hash, f"consent-{participant_id}"),
                    "participant_id": participant_id,
                    "execution_did": execution_did,
                    "random_assignment_consented": True,
                    "model_execution_authorized": False,
                    "consent_statement_sha256": canonical_sha256(
                        ["random-assignment-consent", participant_id]
                    ),
                },
            )
            packet = {
                "schema_version": PACKET_SCHEMA,
                "participant_id": participant_id,
                "pair_id": pair_id,
                "execution_did": execution_did,
                "credential_version": 1,
                "signer_kind": "pkcs11",
                "prior_mentorship_exposure": False,
                "random_assignment_consented": True,
                "model_execution_authorized": False,
                "stack": packet_stack,
                "evidence": {
                    "cognitive_baseline": _artifact_ref(baseline_path),
                    "identity_snapshot": _artifact_ref(identity_path),
                    "custody_provenance": _artifact_ref(custody_path),
                    "isolation_root": _artifact_ref(isolation_path),
                    "consent_receipt": _artifact_ref(consent_path),
                },
            }
            packet["packet_sha256"] = canonical_sha256(packet)
            _write(root / f"{participant_id}.participant.json", packet)


def _run(tmp_path: Path, *, prepare_evidence: bool = True) -> tuple[dict, Path, Path]:
    protocol = _protocol()
    protocol_hash = canonical_sha256(protocol)
    protocol_path = _write(tmp_path / "qualification-protocol.json", protocol)
    freeze_report_path = _write(
        tmp_path / "qualification-protocol-freeze-report.json",
        {
            "schema_version": GATE_SCHEMA,
            "passed": True,
            "qualification_protocol_sha256": protocol_hash,
            "readiness": {"qualification_protocol_frozen": True},
        },
    )
    evidence_root = tmp_path / "participant-evidence"
    if prepare_evidence:
        _prepare_evidence(evidence_root, protocol)
    else:
        evidence_root.mkdir()
        evidence_root.chmod(0o700)
    output_path = tmp_path / "private" / "qualification-roster.review-required.json"
    report_path = tmp_path / "private" / "qualification-roster-intake-report.json"
    report = prepare_roster_draft(
        roster_id="j1q-roster-20260720-r1",
        qualification_protocol_path=protocol_path,
        protocol_freeze_report_path=freeze_report_path,
        evidence_root=evidence_root,
        output_path=output_path,
        report_path=report_path,
    )
    return report, output_path, report_path


def test_prepares_review_required_roster_from_40_bound_participants(
    tmp_path: Path,
) -> None:
    report, output_path, report_path = _run(tmp_path)
    roster = json.loads(output_path.read_text(encoding="utf-8"))

    assert report["passed"] is True
    assert report["counts"] == {
        "required_participants": 40,
        "valid_participants": 40,
        "missing_participants": 0,
        "required_pairs": 20,
        "complete_pairs": 20,
    }
    assert roster["status"] == "review_required"
    assert "operator_review" not in roster
    assert len(roster["participants"]) == 40
    assert output_path.stat().st_mode & 0o777 == 0o600
    assert report_path.stat().st_mode & 0o777 == 0o600
    assert report["readiness"]["real_participant_roster_bound"] is False
    assert report["execution_boundary"]["identity_generation_performed"] is False


def test_rejects_tampered_participant_evidence(tmp_path: Path) -> None:
    protocol = _protocol()
    evidence_root = tmp_path / "participant-evidence"
    _prepare_evidence(evidence_root, protocol)
    identity_path = evidence_root / "j1q-participant-00-a.identity.json"
    identity = json.loads(identity_path.read_text(encoding="utf-8"))
    identity["identity_state_sha256"] = "0" * 64
    _write(identity_path, identity)
    protocol_path = _write(tmp_path / "qualification-protocol.json", protocol)
    protocol_hash = canonical_sha256(protocol)
    freeze_path = _write(
        tmp_path / "freeze-report.json",
        {
            "schema_version": GATE_SCHEMA,
            "passed": True,
            "qualification_protocol_sha256": protocol_hash,
            "readiness": {"qualification_protocol_frozen": True},
        },
    )
    output_path = tmp_path / "private" / "roster.json"

    report = prepare_roster_draft(
        roster_id="j1q-roster-20260720-r1",
        qualification_protocol_path=protocol_path,
        protocol_freeze_report_path=freeze_path,
        evidence_root=evidence_root,
        output_path=output_path,
        report_path=tmp_path / "private" / "report.json",
    )

    assert report["passed"] is False
    assert any(
        "participant_identity_snapshot_artifact_hash_mismatch" in failure
        for failure in report["failure_reasons"]
    )
    assert not output_path.exists()


def test_rejects_symlinked_participant_evidence(tmp_path: Path) -> None:
    protocol = _protocol()
    evidence_root = tmp_path / "participant-evidence"
    _prepare_evidence(evidence_root, protocol)
    identity_path = evidence_root / "j1q-participant-00-a.identity.json"
    target_path = evidence_root / "j1q-participant-00-a.identity.target.json"
    identity_path.rename(target_path)
    identity_path.symlink_to(target_path.name)
    protocol_path = _write(tmp_path / "qualification-protocol.json", protocol)
    protocol_hash = canonical_sha256(protocol)
    freeze_path = _write(
        tmp_path / "freeze-report.json",
        {
            "schema_version": GATE_SCHEMA,
            "passed": True,
            "qualification_protocol_sha256": protocol_hash,
            "readiness": {"qualification_protocol_frozen": True},
        },
    )
    output_path = tmp_path / "private" / "roster.json"

    report = prepare_roster_draft(
        roster_id="j1q-roster-20260720-r1",
        qualification_protocol_path=protocol_path,
        protocol_freeze_report_path=freeze_path,
        evidence_root=evidence_root,
        output_path=output_path,
        report_path=tmp_path / "private" / "report.json",
    )

    assert report["passed"] is False
    assert any(
        "participant_identity_snapshot_path_uses_symlink" in failure
        for failure in report["failure_reasons"]
    )
    assert not output_path.exists()


def test_empty_evidence_root_reports_exact_collection_gap(tmp_path: Path) -> None:
    report, output_path, _ = _run(tmp_path, prepare_evidence=False)

    assert report["passed"] is False
    assert "qualification_participant_evidence_missing" in report["failure_reasons"]
    assert report["counts"]["valid_participants"] == 0
    assert report["counts"]["missing_participants"] == 40
    assert report["readiness"]["qualification_protocol_frozen"] is True
    assert not output_path.exists()


def test_freeze_hash_mismatch_clears_protocol_readiness(tmp_path: Path) -> None:
    protocol = _protocol()
    protocol_path = _write(tmp_path / "qualification-protocol.json", protocol)
    freeze_path = _write(
        tmp_path / "freeze-report.json",
        {
            "schema_version": GATE_SCHEMA,
            "passed": True,
            "qualification_protocol_sha256": "0" * 64,
            "readiness": {"qualification_protocol_frozen": True},
        },
    )
    evidence_root = tmp_path / "participant-evidence"
    evidence_root.mkdir()
    evidence_root.chmod(0o700)
    output_path = tmp_path / "private" / "roster.json"

    report = prepare_roster_draft(
        roster_id="j1q-roster-20260720-r1",
        qualification_protocol_path=protocol_path,
        protocol_freeze_report_path=freeze_path,
        evidence_root=evidence_root,
        output_path=output_path,
        report_path=tmp_path / "private" / "report.json",
    )

    assert "qualification_protocol_freeze_hash_mismatch" in report["failure_reasons"]
    assert report["qualification_protocol"]["freeze_validated"] is False
    assert report["readiness"]["qualification_protocol_frozen"] is False
    assert not output_path.exists()
