from __future__ import annotations

import copy
import json
from pathlib import Path

from benchmarks.j1.controlled_comparison import canonical_sha256
from benchmarks.j1.qualification_roster import (
    QUALIFICATION_PROTOCOL_SCHEMA,
    ROSTER_SCHEMA,
    validate_qualification_protocol,
    validate_roster,
)
from benchmarks.j1_qualification_admission_gate import DEFAULT_REQUEST
from benchmarks.j1_qualification_roster_gate import GATE_SCHEMA, run_gate


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
        roster_path=_write(tmp_path / "roster.json", _roster(protocol)),
        qualification_protocol_path=_write(tmp_path / "protocol.json", protocol),
        output_path=output,
    )

    assert report["schema_version"] == GATE_SCHEMA
    assert report["passed"] is True
    assert report["participant_count"] == 40
    assert report["readiness"]["real_participant_roster_bound"] is True
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
        qualification_protocol_path=tmp_path / "qualification-protocol-required.json",
        output_path=tmp_path / "report.json",
    )

    assert report["passed"] is False
    assert "qualification_roster_unreadable" in report["failure_reasons"]
    assert "qualification_protocol_unreadable" in report["failure_reasons"]
    assert report["readiness"]["controlled_experiment_execution_ready"] is False


def test_protocol_rejects_synthetic_corpus_and_preauthorization() -> None:
    protocol = copy.deepcopy(_protocol())
    protocol["task_corpus"]["synthetic"] = True
    protocol["execution_boundary"]["execution_authorized"] = True

    failures = validate_qualification_protocol(
        protocol, admission_request_sha256=_request_hash()
    )

    assert "qualification_corpus_must_be_real" in failures
    assert "qualification_execution_must_be_false" in failures
