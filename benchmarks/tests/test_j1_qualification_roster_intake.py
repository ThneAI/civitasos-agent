from __future__ import annotations

import json
import hashlib
from pathlib import Path

from nacl.signing import SigningKey

from benchmarks.j1.controlled_comparison import canonical_sha256, write_private_json
from benchmarks.j1.qualification_baseline_consent import (
    build_cognitive_baseline,
    build_participant_consent,
    reviewer_did,
)
from benchmarks.j1.qualification_participant_provisioning import (
    participant_did,
    participant_id,
)
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


class _Signer:
    def __init__(self, key: SigningKey) -> None:
        self.key = key

    @property
    def public_key_hex(self) -> str:
        return self.key.verify_key.encode().hex()

    def sign(self, message: bytes) -> bytes:
        return self.key.sign(message).signature


def _participants() -> list[dict]:
    records = []
    for pair_index in range(1, 21):
        for member_index, member in enumerate(("a", "b")):
            key = SigningKey(hashlib.sha256(f"{pair_index}:{member}".encode()).digest())
            public_key = key.verify_key.encode().hex()
            records.append(
                {
                    "pair_id": f"j1q-pair-{pair_index:02d}",
                    "member": member,
                    "key": key,
                    "participant_id": participant_id(public_key),
                    "execution_did": participant_did(public_key),
                    "public_key_hex": public_key,
                    "profile_sha256": canonical_sha256(["profile", pair_index, member_index]),
                }
            )
    return records


def _reviewed_pairing(protocol_hash: str, records: list[dict] | None = None) -> dict:
    records = records or _participants()
    pairs = []
    for pair_index in range(1, 21):
        members = [item for item in records if item["pair_id"] == f"j1q-pair-{pair_index:02d}"]
        pairs.append(
            {
                "pair_id": f"j1q-pair-{pair_index:02d}",
                "participant_ids": [item["participant_id"] for item in members],
                "execution_dids": [item["execution_did"] for item in members],
                "status": "operator_reviewed",
                "cognitive_baseline_evidence_created": False,
                "random_assignment_consent_created": False,
            }
        )
    reviewed = {
        "schema_version": "j1-qualification-pairing-reviewed:v1",
        "proposal_id": "j1q-pairing-20260720-r1",
        "status": "operator_reviewed",
        "created_at": "2026-07-20T22:00:00+08:00",
        "reviewed_at": "2026-07-20T22:05:00+08:00",
        "qualification_protocol_sha256": protocol_hash,
        "source_proposal_sha256": "1" * 64,
        "assignment_method": "nonce_randomized_fresh_baseline_pairing_proposal:v1",
        "assignment_nonce_hex": "2" * 64,
        "participant_profile_sha256": sorted(item["profile_sha256"] for item in records),
        "pairs": pairs,
        "operator_review": {
            "review_id": "j1q-pairing-review-test-r1",
            "reviewer_did": reviewer_did(SigningKey(b"r" * 32).verify_key.encode().hex()),
            "decision": "approve_exact_pairing",
            "reviewed_at": "2026-07-20T22:05:00+08:00",
            "review_receipt_sha256": "3" * 64,
        },
        "readiness": {
            "all_participant_identities_provisioned": True,
            "pairing_operator_reviewed": True,
            "participant_evidence_complete": False,
            "real_participant_roster_bound": False,
            "single_use_authorization_issued": False,
            "controlled_experiment_execution_ready": False,
        },
    }
    reviewed["reviewed_pairing_sha256"] = canonical_sha256(reviewed)
    return reviewed


def _prepare_evidence(root: Path, protocol: dict) -> dict:
    root.mkdir()
    root.chmod(0o700)
    protocol_hash = canonical_sha256(protocol)
    records = _participants()
    reviewed = _reviewed_pairing(protocol_hash, records)
    pairing_hash = reviewed["reviewed_pairing_sha256"]
    reviewer_key = SigningKey(b"r" * 32)
    reviewer = {
        "did": reviewer_did(reviewer_key.verify_key.encode().hex()),
        "public_key_hex": reviewer_key.verify_key.encode().hex(),
        "signer_kind": "pkcs11_ed25519",
        "credential_version": 1,
    }
    stack = protocol["frozen_stack"]
    packet_stack = {
        "provider_id": stack["provider_id"],
        "model_id": stack["model_id"],
        "budget_id": stack["budget_id"],
        "corpus_id": protocol["task_corpus"]["corpus_id"],
        "verifier_id": stack["verifier_id"],
    }
    for pair_index in range(1, 21):
        pair_id = f"j1q-pair-{pair_index:02d}"
        members = [item for item in records if item["pair_id"] == pair_id]
        baseline_records = []
        for item in members:
            state = {
                "schema_version": "j1-qualification-initial-state:v1",
                "participant_id": item["participant_id"],
                "qualification_protocol_sha256": protocol_hash,
                "agent_revision": "a" * 40,
                "runtime_revision": "b" * 40,
                "prior_mentorship_exposure": False,
                "memory_entry_count": 0,
                "relation_count": 0,
                "model_invocation_count": 0,
                "tick_count": 0,
                "execution_authorized": False,
            }
            state["initial_state_sha256"] = canonical_sha256(state)
            baseline_records.append(
                {
                    "participant_id": item["participant_id"],
                    "participant_profile_sha256": item["profile_sha256"],
                    "initial_state_artifact_sha256": canonical_sha256(["state", item["participant_id"]]),
                    "initial_state": state,
                }
            )
        baseline_path = _write(
            root / f"{pair_id}.baseline.json",
            build_cognitive_baseline(
                pair_id=pair_id,
                reviewed_pairing_sha256=pairing_hash,
                qualification_protocol_sha256=protocol_hash,
                owner_authorization_id="test-authorization",
                owner_authorization_statement_sha256="4" * 64,
                attested_at="2026-07-20T22:10:00+08:00",
                participants=baseline_records,
                reviewer=reviewer,
                signer=_Signer(reviewer_key),
            ),
        )
        for item in members:
            current_participant_id = item["participant_id"]
            execution_did = item["execution_did"]
            identity_path = _write(
                root / f"{current_participant_id}.identity.json",
                {
                    "schema_version": "j1-qualification-identity-snapshot:v1",
                    **_common(protocol_hash, f"identity-{current_participant_id}"),
                    "participant_id": current_participant_id,
                    "execution_did": execution_did,
                    "credential_version": 1,
                    "signer_kind": "pkcs11",
                    "public_key_sha256": hashlib.sha256(bytes.fromhex(item["public_key_hex"])).hexdigest(),
                    "identity_state_sha256": canonical_sha256(
                        ["identity-state", current_participant_id]
                    ),
                },
            )
            custody_path = _write(
                root / f"{current_participant_id}.custody.json",
                {
                    "schema_version": "j1-qualification-custody-provenance:v1",
                    **_common(protocol_hash, f"custody-{current_participant_id}"),
                    "participant_id": current_participant_id,
                    "execution_did": execution_did,
                    "signer_kind": "pkcs11",
                    "non_exportable": True,
                    "key_reference_sha256": canonical_sha256(
                        ["key-reference", current_participant_id]
                    ),
                },
            )
            isolation_path = _write(
                root / f"{current_participant_id}.isolation.json",
                {
                    "schema_version": "j1-qualification-isolation-root:v1",
                    **_common(protocol_hash, f"isolation-{current_participant_id}"),
                    "participant_id": current_participant_id,
                    "execution_did": execution_did,
                    "isolation_id": f"j1q-isolation-{pair_index:02d}-{item['member']}",
                    "isolation_commitment_sha256": canonical_sha256(
                        ["isolation", current_participant_id]
                    ),
                    "exclusive_assignment": True,
                },
            )
            consent_path = _write(
                root / f"{current_participant_id}.consent.json",
                build_participant_consent(
                    participant={
                        "participant_id": current_participant_id,
                        "execution_did": execution_did,
                        "public_key_hex": item["public_key_hex"],
                    },
                    pair_id=pair_id,
                    participant_profile_sha256=item["profile_sha256"],
                    reviewed_pairing_sha256=pairing_hash,
                    qualification_protocol_sha256=protocol_hash,
                    owner_authorization_id="test-authorization",
                    owner_authorization_statement_sha256="4" * 64,
                    attested_at="2026-07-20T22:10:00+08:00",
                    consent_nonce=hashlib.sha256(current_participant_id.encode()).digest(),
                    signer=_Signer(item["key"]),
                ),
            )
            packet = {
                "schema_version": PACKET_SCHEMA,
                "participant_id": current_participant_id,
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
            _write(root / f"{current_participant_id}.participant.json", packet)
    return reviewed


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
        reviewed = _prepare_evidence(evidence_root, protocol)
    else:
        evidence_root.mkdir()
        evidence_root.chmod(0o700)
        reviewed = _reviewed_pairing(protocol_hash)
    reviewed_path = _write(tmp_path / "reviewed-pairing.json", reviewed)
    output_path = tmp_path / "private" / "qualification-roster.review-required.json"
    report_path = tmp_path / "private" / "qualification-roster-intake-report.json"
    report = prepare_roster_draft(
        roster_id="j1q-roster-20260720-r1",
        qualification_protocol_path=protocol_path,
        protocol_freeze_report_path=freeze_report_path,
        reviewed_pairing_path=reviewed_path,
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
    reviewed = _prepare_evidence(evidence_root, protocol)
    identity_path = sorted(evidence_root.glob("*.identity.json"))[0]
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
    reviewed_path = _write(tmp_path / "reviewed-pairing.json", reviewed)
    output_path = tmp_path / "private" / "roster.json"

    report = prepare_roster_draft(
        roster_id="j1q-roster-20260720-r1",
        qualification_protocol_path=protocol_path,
        protocol_freeze_report_path=freeze_path,
        reviewed_pairing_path=reviewed_path,
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
    reviewed = _prepare_evidence(evidence_root, protocol)
    identity_path = sorted(evidence_root.glob("*.identity.json"))[0]
    target_path = identity_path.with_suffix(".target.json")
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
    reviewed_path = _write(tmp_path / "reviewed-pairing.json", reviewed)
    output_path = tmp_path / "private" / "roster.json"

    report = prepare_roster_draft(
        roster_id="j1q-roster-20260720-r1",
        qualification_protocol_path=protocol_path,
        protocol_freeze_report_path=freeze_path,
        reviewed_pairing_path=reviewed_path,
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
    reviewed_path = _write(
        tmp_path / "reviewed-pairing.json",
        _reviewed_pairing(canonical_sha256(protocol)),
    )

    report = prepare_roster_draft(
        roster_id="j1q-roster-20260720-r1",
        qualification_protocol_path=protocol_path,
        protocol_freeze_report_path=freeze_path,
        reviewed_pairing_path=reviewed_path,
        evidence_root=evidence_root,
        output_path=output_path,
        report_path=tmp_path / "private" / "report.json",
    )

    assert "qualification_protocol_freeze_hash_mismatch" in report["failure_reasons"]
    assert report["qualification_protocol"]["freeze_validated"] is False
    assert report["readiness"]["qualification_protocol_frozen"] is False
    assert not output_path.exists()
