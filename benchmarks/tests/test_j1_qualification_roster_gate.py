from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

from nacl.signing import SigningKey

from benchmarks.j1.controlled_comparison import canonical_sha256
from benchmarks.j1.qualification_roster import (
    QUALIFICATION_PROTOCOL_SCHEMA,
    ROSTER_SCHEMA,
    validate_qualification_protocol,
    validate_roster,
)
from benchmarks.j1.qualification_reviewer_identity import (
    build_reviewer_identity_profile,
)
from benchmarks.j1.qualification_roster_review import (
    build_reviewed_roster,
    build_roster_review_receipt,
)
from benchmarks.j1_qualification_admission_gate import DEFAULT_REQUEST
from benchmarks.j1_qualification_roster_gate import GATE_SCHEMA, run_gate


CREATED_AT = "2026-07-19T20:05:00+08:00"
REVIEW_IMPLEMENTATION = {
    "agent_revision": "a" * 40,
    "contract_source_sha256": "b" * 64,
    "operation_source_sha256": "c" * 64,
}


class _Signer:
    def __init__(self, key: SigningKey) -> None:
        self.key = key

    @property
    def public_key_hex(self) -> str:
        return self.key.verify_key.encode().hex()

    def sign(self, message: bytes) -> bytes:
        return self.key.sign(message).signature


def _request_hash() -> str:
    return canonical_sha256(json.loads(DEFAULT_REQUEST.read_text(encoding="utf-8")))


def _protocol() -> dict:
    return {
        "schema_version": QUALIFICATION_PROTOCOL_SCHEMA,
        "status": "frozen",
        "frozen_at": "2026-07-19T20:00:00+08:00",
        "admission_request_sha256": _request_hash(),
        "task_corpus": {
            "corpus_id": "j1q-corpus:v1",
            "tasks_sha256": "1" * 64,
            "task_count": 8,
            "synthetic": False,
        },
        "frozen_stack": {
            "provider_id": "openai_compatible",
            "model_id": "deepseek-v4-pro",
            "budget_id": "j1q-budget:v1",
            "verifier_id": "j1q-verifier:v1",
            "temperature": 0,
            "same_stack_for_both_cohorts": True,
        },
        "minimum_completed_pairs": 20,
        "execution_boundary": {
            "single_use_authorization_required": True,
            "execution_authorized": False,
        },
    }


def _roster(protocol: dict) -> dict:
    stack = protocol["frozen_stack"]
    participants = []
    for pair_index in range(20):
        baseline = canonical_sha256(["reviewed-cognitive-baseline", pair_index])
        for member in ("a", "b"):
            identity = f"qualification-{pair_index:02d}-{member}"
            participants.append(
                {
                    "participant_id": f"j1q-participant-{pair_index:02d}-{member}",
                    "pair_id": f"j1q-pair-{pair_index:02d}",
                    "execution_did": f"did:civ:qualification:{identity}",
                    "cognitive_baseline_sha256": baseline,
                    "identity_snapshot_sha256": canonical_sha256(
                        ["public-identity-snapshot", identity]
                    ),
                    "credential_version": 1,
                    "signer_kind": "pkcs11",
                    "custody_provenance_sha256": canonical_sha256(
                        ["custody-provenance", identity]
                    ),
                    "isolation_root_sha256": canonical_sha256(
                        ["isolation-root", identity]
                    ),
                    "consent_receipt_sha256": canonical_sha256(
                        ["consent-receipt", identity]
                    ),
                    "prior_mentorship_exposure": False,
                    "random_assignment_consented": True,
                    "model_execution_authorized": False,
                    "provider_id": stack["provider_id"],
                    "model_id": stack["model_id"],
                    "budget_id": stack["budget_id"],
                    "corpus_id": protocol["task_corpus"]["corpus_id"],
                    "verifier_id": stack["verifier_id"],
                }
            )
    roster = {
        "schema_version": ROSTER_SCHEMA,
        "roster_id": "j1q-roster-20260719-v1",
        "status": "operator_reviewed",
        "admission_request_sha256": _request_hash(),
        "qualification_protocol_sha256": canonical_sha256(protocol),
        "operator_review": {
            "reviewer_did": "did:civ:operator:cc",
            "decision": "approve_roster_binding",
            "conflicts_disclosed": True,
            "reviewed_at": "2026-07-19T20:05:00+08:00",
            "review_receipt_sha256": "2" * 64,
        },
        "participants": participants,
    }
    roster["roster_sha256"] = canonical_sha256(roster)
    return roster


def _write(path: Path, value: dict) -> Path:
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def _reviewer(key: SigningKey) -> dict:
    challenge = b"r" * 32
    return build_reviewer_identity_profile(
        created_at=CREATED_AT,
        public_key_hex=key.verify_key.encode().hex(),
        credential_version=1,
        module_path="/usr/lib/softhsm/libsofthsm2.so",
        module_bytes=b"module",
        token_label="dev-token",
        token_serial="serial",
        token_model="SoftHSM v2",
        token_manufacturer="SoftHSM project",
        key_label="reviewer-key",
        key_id_hex="4a31",
        key_reference="pkcs11:reviewer-key",
        challenge=challenge,
        signature=key.sign(challenge).signature,
        private_key_sensitive=True,
        private_key_extractable=False,
    )


def _draft(protocol: dict) -> dict:
    draft = _roster(protocol)
    draft.pop("operator_review")
    draft["status"] = "review_required"
    draft["roster_sha256"] = canonical_sha256(
        {key: value for key, value in draft.items() if key != "roster_sha256"}
    )
    return draft


def _review_bundle(tmp_path: Path, protocol: dict) -> dict[str, Path]:
    source = _draft(protocol)
    source_path = _write(tmp_path / "source-roster.json", source)
    reviewer_key = SigningKey.generate()
    reviewer = _reviewer(reviewer_key)
    reviewer_path = _write(tmp_path / "reviewer.json", reviewer)
    receipt = build_roster_review_receipt(
        review_id="j1q-roster-review-20260721-r1",
        reviewed_at=CREATED_AT,
        authorization_id="j1q-roster-owner-approval-20260721-r1",
        authorization_statement_sha256="d" * 64,
        candidate_roster=source,
        candidate_artifact_sha256=hashlib.sha256(source_path.read_bytes()).hexdigest(),
        source_evidence={
            "reviewed_pairing_sha256": "1" * 64,
            "baseline_consent_manifest_sha256": "2" * 64,
            "manifest_artifact_sha256": "3" * 64,
            "intake_report_artifact_sha256": "4" * 64,
            "evidence_artifact_count": 220,
            "cognitive_baseline_count": 20,
            "participant_consent_count": 40,
            "participant_packet_count": 40,
        },
        reviewer_profile=reviewer,
        reviewer_profile_sha256=hashlib.sha256(reviewer_path.read_bytes()).hexdigest(),
        review_implementation=REVIEW_IMPLEMENTATION,
        signer=_Signer(reviewer_key),
    )
    receipt_path = _write(tmp_path / "review-receipt.json", receipt)
    reviewed = build_reviewed_roster(
        candidate_roster=source,
        receipt=receipt,
        receipt_sha256=hashlib.sha256(receipt_path.read_bytes()).hexdigest(),
    )
    return {
        "roster_path": _write(tmp_path / "roster.json", reviewed),
        "source_roster_path": source_path,
        "review_receipt_path": receipt_path,
        "reviewer_profile_path": reviewer_path,
        "qualification_protocol_path": _write(tmp_path / "protocol.json", protocol),
    }


def test_qualification_protocol_and_reviewed_roster_are_valid() -> None:
    protocol = _protocol()
    roster = _roster(protocol)
    stack = protocol["frozen_stack"]

    assert (
        validate_qualification_protocol(
            protocol, admission_request_sha256=_request_hash()
        )
        == []
    )
    assert (
        validate_roster(
            roster,
            admission_request_sha256=_request_hash(),
            qualification_protocol_sha256=canonical_sha256(protocol),
            expected_stack={
                "provider_id": stack["provider_id"],
                "model_id": stack["model_id"],
                "budget_id": stack["budget_id"],
                "corpus_id": protocol["task_corpus"]["corpus_id"],
                "verifier_id": stack["verifier_id"],
            },
        )
        == []
    )


def test_roster_gate_binds_reviewed_public_only_roster(tmp_path: Path) -> None:
    protocol = _protocol()
    output = tmp_path / "report.json"

    report = run_gate(
        **_review_bundle(tmp_path, protocol),
        output_path=output,
    )

    assert report["schema_version"] == GATE_SCHEMA
    assert report["passed"] is True
    assert report["participant_count"] == 40
    assert report["readiness"]["real_participant_roster_bound"] is True
    assert report["readiness"]["signed_roster_review_verified"] is True
    assert report["readiness"]["qualification_protocol_frozen"] is True
    assert report["readiness"]["controlled_experiment_execution_ready"] is False
    assert report["execution_boundary"]["identity_generation_allowed"] is False
    assert output.stat().st_mode & 0o777 == 0o600


def test_roster_rejects_pair_drift_secret_and_software_seed() -> None:
    protocol = _protocol()
    roster = _roster(protocol)
    roster["participants"][0]["cognitive_baseline_sha256"] = "3" * 64
    roster["participants"][0]["signer_kind"] = "software_seed"
    roster["participants"][0]["seed_hex"] = "do-not-record"
    roster["roster_sha256"] = canonical_sha256(
        {key: value for key, value in roster.items() if key != "roster_sha256"}
    )

    failures = validate_roster(
        roster,
        admission_request_sha256=_request_hash(),
        qualification_protocol_sha256=canonical_sha256(protocol),
        expected_stack={
            "provider_id": "openai_compatible",
            "model_id": "deepseek-v4-pro",
            "budget_id": "j1q-budget:v1",
            "corpus_id": "j1q-corpus:v1",
            "verifier_id": "j1q-verifier:v1",
        },
    )

    assert "pair_cognitive_baseline_mismatch" in failures
    assert "participant_0_signer_kind_invalid" in failures
    assert "roster_contains_secret_field" in failures


def test_roster_rejects_duplicate_identity_isolation_and_consent() -> None:
    protocol = _protocol()
    roster = _roster(protocol)
    first, second = roster["participants"][:2]
    second["execution_did"] = first["execution_did"]
    second["isolation_root_sha256"] = first["isolation_root_sha256"]
    second["consent_receipt_sha256"] = first["consent_receipt_sha256"]
    roster["roster_sha256"] = canonical_sha256(
        {key: value for key, value in roster.items() if key != "roster_sha256"}
    )

    failures = validate_roster(
        roster,
        admission_request_sha256=_request_hash(),
        qualification_protocol_sha256=canonical_sha256(protocol),
        expected_stack={
            "provider_id": "openai_compatible",
            "model_id": "deepseek-v4-pro",
            "budget_id": "j1q-budget:v1",
            "corpus_id": "j1q-corpus:v1",
            "verifier_id": "j1q-verifier:v1",
        },
    )

    assert "execution_did_duplicate" in failures
    assert "isolation_root_duplicate" in failures
    assert "consent_receipt_duplicate" in failures


def test_gate_fails_closed_when_real_roster_and_protocol_are_absent(
    tmp_path: Path,
) -> None:
    report = run_gate(
        roster_path=tmp_path / "real-roster-required.json",
        source_roster_path=tmp_path / "source-roster-required.json",
        review_receipt_path=tmp_path / "review-receipt-required.json",
        reviewer_profile_path=tmp_path / "reviewer-profile-required.json",
        qualification_protocol_path=tmp_path / "qualification-protocol-required.json",
        output_path=tmp_path / "report.json",
    )

    assert report["passed"] is False
    assert "qualification_roster_unreadable" in report["failure_reasons"]
    assert "source_roster_unreadable" in report["failure_reasons"]
    assert "roster_review_receipt_unreadable" in report["failure_reasons"]
    assert "reviewer_identity_profile_unreadable" in report["failure_reasons"]
    assert "qualification_protocol_unreadable" in report["failure_reasons"]
    assert report["readiness"]["controlled_experiment_execution_ready"] is False


def test_gate_preserves_valid_protocol_readiness_when_roster_is_absent(
    tmp_path: Path,
) -> None:
    report = run_gate(
        roster_path=tmp_path / "real-roster-required.json",
        source_roster_path=tmp_path / "source-roster-required.json",
        review_receipt_path=tmp_path / "review-receipt-required.json",
        reviewer_profile_path=tmp_path / "reviewer-profile-required.json",
        qualification_protocol_path=_write(
            tmp_path / "qualification-protocol.json", _protocol()
        ),
        output_path=tmp_path / "report.json",
    )

    assert report["passed"] is False
    assert "qualification_roster_unreadable" in report["failure_reasons"]
    assert "source_roster_unreadable" in report["failure_reasons"]
    assert report["readiness"]["qualification_protocol_frozen"] is True
    assert report["readiness"]["real_participant_roster_bound"] is False
    assert report["readiness"]["controlled_experiment_execution_ready"] is False


def test_gate_rejects_tampered_signed_review(tmp_path: Path) -> None:
    paths = _review_bundle(tmp_path, _protocol())
    receipt = json.loads(paths["review_receipt_path"].read_text(encoding="utf-8"))
    receipt["execution_boundary"]["model_invocation_allowed"] = True
    _write(paths["review_receipt_path"], receipt)

    report = run_gate(**paths, output_path=tmp_path / "report.json")

    assert report["passed"] is False
    assert (
        "roster_review_model_invocation_allowed_must_be_false"
        in report["failure_reasons"]
    )
    assert "roster_review_signature_payload_hash_mismatch" in report["failure_reasons"]
    assert report["readiness"]["real_participant_roster_bound"] is False


def test_protocol_rejects_synthetic_corpus_and_preauthorization() -> None:
    protocol = copy.deepcopy(_protocol())
    protocol["task_corpus"]["synthetic"] = True
    protocol["execution_boundary"]["execution_authorized"] = True

    failures = validate_qualification_protocol(
        protocol, admission_request_sha256=_request_hash()
    )

    assert "qualification_corpus_must_be_real" in failures
    assert "qualification_execution_must_be_false" in failures
