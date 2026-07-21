from __future__ import annotations

import copy
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from nacl.signing import SigningKey

from benchmarks.j1.controlled_comparison import canonical_sha256, write_private_json
from benchmarks.j1.qualification_cohort_assignment import (
    build_assignment_proposal,
    build_assignment_review_receipt,
    build_reviewed_assignment,
    validate_assignment_proposal,
    validate_assignment_review_receipt,
    validate_reviewed_assignment,
)
from benchmarks.tests.test_j1_qualification_execution_authorization import (
    _Signer,
    _reviewer,
)
from benchmarks.j1_qualification_cohort_assignment_gate import run_gate
from benchmarks.j1_qualification_cohort_assignment_gate import (
    CONTRACT_SOURCE as ASSIGNMENT_CONTRACT_SOURCE,
)
from benchmarks.j1_qualification_cohort_assignment_gate import (
    OPERATION_SOURCE as ASSIGNMENT_OPERATION_SOURCE,
)


NOW = datetime(2026, 7, 22, tzinfo=timezone.utc).isoformat()
IMPLEMENTATION = {
    "agent_revision": "a" * 40,
    "contract_source_sha256": "b" * 64,
    "operation_source_sha256": "c" * 64,
}


def _sources() -> tuple[dict, dict, dict]:
    protocol = {"schema_version": "j1-qualification-protocol:v1", "frozen": True}
    protocol_hash = canonical_sha256(protocol)
    pairs = []
    participants = []
    profile_hashes = []
    for pair_index in range(1, 21):
        pair_ids = []
        pair_dids = []
        for member_index in range(2):
            index = (pair_index - 1) * 2 + member_index
            participant_id = f"j1q-agent-{index:020d}"
            execution_did = f"did:civ:qualification:{index:040d}"
            pair_ids.append(participant_id)
            pair_dids.append(execution_did)
            profile_hashes.append(f"{index + 1:064x}")
            participants.append(
                {
                    "participant_id": participant_id,
                    "execution_did": execution_did,
                    "pair_id": f"j1q-pair-{pair_index:02d}",
                }
            )
        pairs.append(
            {
                "pair_id": f"j1q-pair-{pair_index:02d}",
                "participant_ids": pair_ids,
                "execution_dids": pair_dids,
                "status": "operator_reviewed",
                "cognitive_baseline_evidence_created": False,
                "random_assignment_consent_created": False,
            }
        )
    pairing = {
        "schema_version": "j1-qualification-pairing-reviewed:v1",
        "proposal_id": "j1q-pairing-proposal-r1",
        "status": "operator_reviewed",
        "created_at": NOW,
        "reviewed_at": NOW,
        "qualification_protocol_sha256": protocol_hash,
        "source_proposal_sha256": "1" * 64,
        "assignment_method": "nonce_randomized_fresh_baseline_pairing_proposal:v1",
        "assignment_nonce_hex": "2" * 64,
        "participant_profile_sha256": profile_hashes,
        "pairs": pairs,
        "operator_review": {
            "review_id": "pairing-review-r1",
            "reviewer_did": "did:civ:testnet:reviewer",
            "decision": "approve_exact_pairing",
            "reviewed_at": NOW,
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
    pairing["reviewed_pairing_sha256"] = canonical_sha256(pairing)
    roster = {
        "qualification_protocol_sha256": protocol_hash,
        "participants": participants,
    }
    roster["roster_sha256"] = canonical_sha256(roster)
    return protocol, pairing, roster


def test_assignment_is_deterministic_balanced_and_bound() -> None:
    protocol, pairing, roster = _sources()
    first = build_assignment_proposal(
        assignment_id="j1d-cohort-assignment-20260722-r1",
        created_at=NOW,
        protocol=protocol,
        reviewed_pairing=pairing,
        reviewed_roster=roster,
    )
    second = build_assignment_proposal(
        assignment_id="j1d-cohort-assignment-20260722-r1",
        created_at=NOW,
        protocol=protocol,
        reviewed_pairing=pairing,
        reviewed_roster=roster,
    )

    assert first == second
    assert (
        validate_assignment_proposal(
            first,
            protocol=protocol,
            reviewed_pairing=pairing,
            reviewed_roster=roster,
        )
        == []
    )
    assert (
        len({item["mentor"]["participant_id"] for item in first["assignments"]}) == 20
    )
    assert (
        len({item["control"]["participant_id"] for item in first["assignments"]}) == 20
    )


def test_assignment_rejects_cohort_swap_and_source_drift() -> None:
    protocol, pairing, roster = _sources()
    proposal = build_assignment_proposal(
        assignment_id="j1d-cohort-assignment-20260722-r1",
        created_at=NOW,
        protocol=protocol,
        reviewed_pairing=pairing,
        reviewed_roster=roster,
    )
    swapped = copy.deepcopy(proposal)
    swapped["assignments"][0]["mentor"], swapped["assignments"][0]["control"] = (
        swapped["assignments"][0]["control"],
        swapped["assignments"][0]["mentor"],
    )
    failures = validate_assignment_proposal(
        swapped,
        protocol=protocol,
        reviewed_pairing=pairing,
        reviewed_roster=roster,
    )
    assert "assignment_cohort_derivation_invalid" in failures
    assert "assignment_hash_mismatch" in failures

    drifted_roster = copy.deepcopy(roster)
    drifted_roster["roster_sha256"] = "f" * 64
    assert "assignment_roster_hash_mismatch" in validate_assignment_proposal(
        proposal,
        protocol=protocol,
        reviewed_pairing=pairing,
        reviewed_roster=drifted_roster,
    )


def test_signed_review_binds_exact_assignment() -> None:
    protocol, pairing, roster = _sources()
    proposal = build_assignment_proposal(
        assignment_id="j1d-cohort-assignment-20260722-r1",
        created_at=NOW,
        protocol=protocol,
        reviewed_pairing=pairing,
        reviewed_roster=roster,
    )
    key = SigningKey.generate()
    reviewer = _reviewer(key)
    reviewer_hash = hashlib.sha256(
        json.dumps(reviewer, sort_keys=True).encode()
    ).hexdigest()
    receipt = build_assignment_review_receipt(
        review_id="j1d-cohort-assignment-review-20260722-r1",
        reviewed_at=NOW,
        authorization_id="j1d-owner-cohort-assignment-approval-20260722-r1",
        authorization_statement_sha256="d" * 64,
        proposal=proposal,
        proposal_artifact_sha256="e" * 64,
        reviewer_profile=reviewer,
        reviewer_profile_sha256=reviewer_hash,
        implementation=IMPLEMENTATION,
        signer=_Signer(key),
    )

    assert (
        validate_assignment_review_receipt(
            receipt,
            proposal=proposal,
            proposal_artifact_sha256="e" * 64,
            reviewer_profile=reviewer,
            reviewer_profile_sha256=reviewer_hash,
            implementation=IMPLEMENTATION,
        )
        == []
    )
    reviewed = build_reviewed_assignment(
        proposal=proposal,
        receipt=receipt,
        receipt_artifact_sha256="f" * 64,
    )
    assert validate_reviewed_assignment(reviewed) == []

    tampered = copy.deepcopy(receipt)
    tampered["proposal"]["assignment_sha256"] = "0" * 64
    failures = validate_assignment_review_receipt(
        tampered,
        proposal=proposal,
        proposal_artifact_sha256="e" * 64,
        reviewer_profile=reviewer,
        reviewer_profile_sha256=reviewer_hash,
        implementation=IMPLEMENTATION,
    )
    assert "assignment_review_proposal_binding_invalid" in failures
    assert "assignment_review_signature_invalid" in failures


def test_gate_validates_complete_review_chain(tmp_path: Path) -> None:
    protocol, pairing, roster = _sources()
    proposal = build_assignment_proposal(
        assignment_id="j1d-cohort-assignment-20260722-r1",
        created_at=NOW,
        protocol=protocol,
        reviewed_pairing=pairing,
        reviewed_roster=roster,
    )
    key = SigningKey.generate()
    reviewer = _reviewer(key)
    reviewer_hash = hashlib.sha256(
        (json.dumps(reviewer, indent=2, sort_keys=True) + "\n").encode()
    ).hexdigest()
    paths = {
        "proposal": tmp_path / "proposal.json",
        "protocol": tmp_path / "protocol.json",
        "pairing": tmp_path / "pairing.json",
        "roster": tmp_path / "roster.json",
        "reviewer": tmp_path / "reviewer.json",
    }
    for key_name, value in (
        ("proposal", proposal),
        ("protocol", protocol),
        ("pairing", pairing),
        ("roster", roster),
        ("reviewer", reviewer),
    ):
        write_private_json(paths[key_name], value)
    assert hashlib.sha256(paths["reviewer"].read_bytes()).hexdigest() == reviewer_hash
    gate_implementation = {
        "agent_revision": "a" * 40,
        "contract_source_sha256": hashlib.sha256(
            ASSIGNMENT_CONTRACT_SOURCE.read_bytes()
        ).hexdigest(),
        "operation_source_sha256": hashlib.sha256(
            ASSIGNMENT_OPERATION_SOURCE.read_bytes()
        ).hexdigest(),
    }
    receipt = build_assignment_review_receipt(
        review_id="j1d-cohort-assignment-review-20260722-r1",
        reviewed_at=NOW,
        authorization_id="j1d-owner-cohort-assignment-approval-20260722-r1",
        authorization_statement_sha256="d" * 64,
        proposal=proposal,
        proposal_artifact_sha256=hashlib.sha256(
            paths["proposal"].read_bytes()
        ).hexdigest(),
        reviewer_profile=reviewer,
        reviewer_profile_sha256=reviewer_hash,
        implementation=gate_implementation,
        signer=_Signer(key),
    )
    receipt_path = tmp_path / "receipt.json"
    write_private_json(receipt_path, receipt)
    reviewed = build_reviewed_assignment(
        proposal=proposal,
        receipt=receipt,
        receipt_artifact_sha256=hashlib.sha256(receipt_path.read_bytes()).hexdigest(),
    )
    reviewed_path = tmp_path / "reviewed.json"
    write_private_json(reviewed_path, reviewed)

    report = run_gate(
        proposal_path=paths["proposal"],
        review_receipt_path=receipt_path,
        reviewed_assignment_path=reviewed_path,
        qualification_protocol_path=paths["protocol"],
        reviewed_pairing_path=paths["pairing"],
        reviewed_roster_path=paths["roster"],
        reviewer_profile_path=paths["reviewer"],
        output_path=tmp_path / "gate.json",
    )

    assert report["passed"] is True
    assert report["readiness"]["cohort_assignment_bound"] is True

    tampered = copy.deepcopy(reviewed)
    tampered["assignments"][0]["mentor"], tampered["assignments"][0]["control"] = (
        tampered["assignments"][0]["control"],
        tampered["assignments"][0]["mentor"],
    )
    write_private_json(reviewed_path, tampered)
    rejected = run_gate(
        proposal_path=paths["proposal"],
        review_receipt_path=receipt_path,
        reviewed_assignment_path=reviewed_path,
        qualification_protocol_path=paths["protocol"],
        reviewed_pairing_path=paths["pairing"],
        reviewed_roster_path=paths["roster"],
        reviewer_profile_path=paths["reviewer"],
        output_path=tmp_path / "rejected-gate.json",
    )
    assert rejected["passed"] is False
    assert (
        "reviewed_assignment_copy_on_write_binding_invalid"
        in rejected["failure_reasons"]
    )
