from __future__ import annotations

import copy
import hashlib

from nacl.signing import SigningKey

from benchmarks.j1.controlled_comparison import canonical_sha256
from benchmarks.j1.qualification_treatment_advice import (
    build_advice_candidate,
    build_signed_advice,
    validate_advice_candidate,
    validate_signed_advice,
)
from benchmarks.tests.test_j1_qualification_execution_design import _design
from benchmarks.tests.test_j1_qualification_mentor_identity import (
    _profile as _mentor_profile,
)


NOW = "2026-07-22T14:00:00+00:00"


class _Signer:
    def __init__(self, signing_key: SigningKey) -> None:
        self._signing_key = signing_key
        self.public_key_hex = signing_key.verify_key.encode().hex()

    def sign(self, payload: bytes) -> bytes:
        return self._signing_key.sign(payload).signature


def _candidate() -> tuple[dict, dict, dict, dict, dict, dict]:
    design, _, _, assignment = _design()
    reviewed_design = {
        "reviewed_design_sha256": "d" * 64,
        "treatment": design["treatment"],
    }
    assigned = assignment["assignments"][0]
    assigned["assignment_commitment_sha256"] = "e" * 64
    mentor, _ = _mentor_profile()
    task = reviewed_design["treatment"]["tasks"][0]
    candidate = build_advice_candidate(
        created_at=NOW,
        reviewed_design=reviewed_design,
        reviewed_assignment=assignment,
        mentor_identity=mentor,
        assignment=assigned,
        task=task,
    )
    return candidate, reviewed_design, assignment, mentor, assigned, task


def test_treatment_advice_is_participant_task_bound_and_unsigned() -> None:
    candidate, design, assignment, mentor, assigned, task = _candidate()

    assert (
        validate_advice_candidate(
            candidate,
            reviewed_design=design,
            reviewed_assignment=assignment,
            mentor_identity=mentor,
            assignment=assigned,
            task=task,
        )
        == []
    )
    assert candidate["recipient"]["cohort"] == "mentor"
    assert candidate["signature"]["performed"] is False
    assert candidate["advice"]["authority"] == "advisory_only"


def test_treatment_advice_rejects_recipient_and_signature_scope_tamper() -> None:
    candidate, design, assignment, mentor, assigned, task = _candidate()
    tampered = copy.deepcopy(candidate)
    tampered["recipient"]["participant_id"] = assigned["control"]["participant_id"]
    tampered["signature"]["performed"] = True
    tampered["candidate_sha256"] = canonical_sha256(
        {key: item for key, item in tampered.items() if key != "candidate_sha256"}
    )

    failures = validate_advice_candidate(
        tampered,
        reviewed_design=design,
        reviewed_assignment=assignment,
        mentor_identity=mentor,
        assignment=assigned,
        task=task,
    )
    assert "treatment_advice_recipient_invalid" in failures
    assert "treatment_advice_signature_boundary_invalid" in failures


def _signed_advice() -> tuple[dict, dict, dict]:
    _, design, assignment, mentor, assigned, task = _candidate()
    signing_key = SigningKey(bytes(range(32)))
    public_key = signing_key.verify_key.encode()
    mentor["mentor"]["public_key_hex"] = public_key.hex()
    mentor["mentor"]["public_key_sha256"] = hashlib.sha256(public_key).hexdigest()
    candidate = build_advice_candidate(
        created_at=NOW,
        reviewed_design=design,
        reviewed_assignment=assignment,
        mentor_identity=mentor,
        assignment=assigned,
        task=task,
    )
    signed = build_signed_advice(
        candidate=candidate,
        candidate_artifact_sha256="a" * 64,
        source_manifest_artifact_sha256="b" * 64,
        source_manifest_sha256="c" * 64,
        authorization_id="owner-advice-signing-r1",
        authorization_statement_sha256="d" * 64,
        signed_at=NOW,
        mentor_identity=mentor,
        signer=_Signer(signing_key),
    )
    return signed, candidate, mentor


def test_signed_treatment_advice_is_bound_verified_and_non_executable() -> None:
    signed, candidate, mentor = _signed_advice()

    assert (
        validate_signed_advice(
            signed,
            candidate=candidate,
            candidate_artifact_sha256="a" * 64,
            source_manifest_artifact_sha256="b" * 64,
            source_manifest_sha256="c" * 64,
            authorization_id="owner-advice-signing-r1",
            authorization_statement_sha256="d" * 64,
            mentor_identity=mentor,
        )
        == []
    )
    assert signed["status"] == "signed_non_executable"
    assert signed["execution_boundary"]["runtime_projection_allowed"] is False


def test_signed_treatment_advice_rejects_scope_and_signature_tamper() -> None:
    signed, candidate, mentor = _signed_advice()
    tampered = copy.deepcopy(signed)
    tampered["recipient"]["participant_id"] = "substituted-participant"
    tampered["signed_advice_sha256"] = canonical_sha256(
        {key: item for key, item in tampered.items() if key != "signed_advice_sha256"}
    )

    failures = validate_signed_advice(
        tampered,
        candidate=candidate,
        candidate_artifact_sha256="a" * 64,
        source_manifest_artifact_sha256="b" * 64,
        source_manifest_sha256="c" * 64,
        authorization_id="owner-advice-signing-r1",
        authorization_statement_sha256="d" * 64,
        mentor_identity=mentor,
    )

    assert "signed_treatment_advice_recipient_invalid" in failures
    assert "signed_treatment_advice_signature_unverified" in failures
