"""Deterministic, reviewed cohort assignment for J1-D qualification."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any, Protocol

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from .controlled_comparison import canonical_sha256
from .qualification_pairing_review import validate_reviewed_pairing
from .qualification_reviewer_identity import validate_reviewer_identity_profile


PROPOSAL_SCHEMA = "j1-qualification-cohort-assignment-proposal:v1"
RECEIPT_SCHEMA = "j1-qualification-cohort-assignment-review-receipt:v1"
REVIEWED_SCHEMA = "j1-qualification-cohort-assignment-reviewed:v1"
METHOD = "reviewed-pairing-hash-parity:v1"
DECISION = "approve_exact_cohort_assignment"


class AssignmentReviewSigner(Protocol):
    @property
    def public_key_hex(self) -> str: ...

    def sign(self, message: bytes) -> bytes: ...


def build_assignment_proposal(
    *,
    assignment_id: str,
    created_at: str,
    protocol: dict[str, Any],
    reviewed_pairing: dict[str, Any],
    reviewed_roster: dict[str, Any],
) -> dict[str, Any]:
    failures = validate_reviewed_pairing(reviewed_pairing)
    protocol_hash = canonical_sha256(protocol)
    if reviewed_pairing.get("qualification_protocol_sha256") != protocol_hash:
        failures.append("assignment_pairing_protocol_hash_mismatch")
    roster_participants = _roster_participants(reviewed_roster, failures)
    if reviewed_roster.get("qualification_protocol_sha256") != protocol_hash:
        failures.append("assignment_roster_protocol_hash_mismatch")
    pairing_hash = reviewed_pairing.get("reviewed_pairing_sha256")
    if not _text(assignment_id):
        failures.append("assignment_id_invalid")
    if not _rfc3339(created_at):
        failures.append("assignment_created_at_invalid")
    if failures:
        raise ValueError(
            f"cohort assignment source invalid: {list(dict.fromkeys(failures))}"
        )

    assignments = []
    for pair in sorted(reviewed_pairing["pairs"], key=lambda item: item["pair_id"]):
        pair_id = pair["pair_id"]
        participant_ids = sorted(pair["participant_ids"])
        if any(
            roster_participants[item]["pair_id"] != pair_id for item in participant_ids
        ):
            raise ValueError(f"cohort assignment roster pair mismatch: {pair_id}")
        commitment = canonical_sha256(
            {
                "method": METHOD,
                "reviewed_pairing_sha256": pairing_hash,
                "pair_id": pair_id,
                "participant_ids": participant_ids,
            }
        )
        mentor_index = int(commitment, 16) & 1
        mentor_id = participant_ids[mentor_index]
        control_id = participant_ids[1 - mentor_index]
        assignments.append(
            {
                "pair_id": pair_id,
                "assignment_commitment_sha256": commitment,
                "mentor": _assignment_member(roster_participants[mentor_id]),
                "control": _assignment_member(roster_participants[control_id]),
            }
        )

    proposal = {
        "schema_version": PROPOSAL_SCHEMA,
        "assignment_id": assignment_id,
        "status": "review_required",
        "created_at": created_at,
        "method": METHOD,
        "qualification_protocol_sha256": protocol_hash,
        "reviewed_pairing_sha256": pairing_hash,
        "reviewed_roster_sha256": reviewed_roster.get("roster_sha256"),
        "participant_count": 40,
        "pair_count": 20,
        "assignments": assignments,
    }
    proposal["assignment_sha256"] = canonical_sha256(proposal)
    proposal_failures = validate_assignment_proposal(
        proposal,
        protocol=protocol,
        reviewed_pairing=reviewed_pairing,
        reviewed_roster=reviewed_roster,
    )
    if proposal_failures:
        raise ValueError(f"cohort assignment proposal invalid: {proposal_failures}")
    return proposal


def validate_assignment_proposal(
    value: Any,
    *,
    protocol: dict[str, Any],
    reviewed_pairing: dict[str, Any],
    reviewed_roster: dict[str, Any],
) -> list[str]:
    proposal = value if isinstance(value, dict) else {}
    failures = validate_reviewed_pairing(reviewed_pairing)
    expected_fields = {
        "schema_version",
        "assignment_id",
        "status",
        "created_at",
        "method",
        "qualification_protocol_sha256",
        "reviewed_pairing_sha256",
        "reviewed_roster_sha256",
        "participant_count",
        "pair_count",
        "assignments",
        "assignment_sha256",
    }
    _require(set(proposal) == expected_fields, "assignment_fields_invalid", failures)
    _require(
        proposal.get("schema_version") == PROPOSAL_SCHEMA,
        "assignment_schema_invalid",
        failures,
    )
    _require(_text(proposal.get("assignment_id")), "assignment_id_invalid", failures)
    _require(
        proposal.get("status") == "review_required",
        "assignment_status_invalid",
        failures,
    )
    _require(
        _rfc3339(proposal.get("created_at")), "assignment_created_at_invalid", failures
    )
    _require(proposal.get("method") == METHOD, "assignment_method_invalid", failures)
    protocol_hash = canonical_sha256(protocol)
    pairing_hash = reviewed_pairing.get("reviewed_pairing_sha256")
    _require(
        proposal.get("qualification_protocol_sha256") == protocol_hash,
        "assignment_protocol_hash_mismatch",
        failures,
    )
    _require(
        proposal.get("reviewed_pairing_sha256") == pairing_hash,
        "assignment_pairing_hash_mismatch",
        failures,
    )
    _require(
        proposal.get("reviewed_roster_sha256") == reviewed_roster.get("roster_sha256"),
        "assignment_roster_hash_mismatch",
        failures,
    )
    _require(
        proposal.get("participant_count") == 40,
        "assignment_participant_count_invalid",
        failures,
    )
    _require(
        proposal.get("pair_count") == 20, "assignment_pair_count_invalid", failures
    )

    roster_participants = _roster_participants(reviewed_roster, failures)
    expected_pairs = {
        item["pair_id"]: sorted(item["participant_ids"])
        for item in reviewed_pairing.get("pairs", [])
        if isinstance(item, dict) and isinstance(item.get("participant_ids"), list)
    }
    assignments = proposal.get("assignments")
    items = assignments if isinstance(assignments, list) else []
    _require(len(items) == 20, "assignment_pair_count_invalid", failures)
    seen_pairs: set[str] = set()
    seen_participants: set[str] = set()
    for item in items:
        assignment = item if isinstance(item, dict) else {}
        pair_id = assignment.get("pair_id")
        _require(
            set(assignment)
            == {"pair_id", "assignment_commitment_sha256", "mentor", "control"},
            "assignment_pair_fields_invalid",
            failures,
        )
        _require(
            isinstance(pair_id, str) and pair_id not in seen_pairs,
            "assignment_pair_duplicate",
            failures,
        )
        seen_pairs.add(str(pair_id))
        members = [
            _object(assignment.get("mentor")),
            _object(assignment.get("control")),
        ]
        member_ids = sorted(
            str(member.get("participant_id") or "") for member in members
        )
        _require(
            member_ids == expected_pairs.get(pair_id),
            "assignment_pair_members_invalid",
            failures,
        )
        for member in members:
            participant_id = str(member.get("participant_id") or "")
            _require(
                set(member) == {"participant_id", "execution_did"},
                "assignment_member_fields_invalid",
                failures,
            )
            _require(
                participant_id not in seen_participants,
                "assignment_participant_duplicate",
                failures,
            )
            seen_participants.add(participant_id)
            roster_item = roster_participants.get(participant_id, {})
            _require(
                member.get("execution_did") == roster_item.get("execution_did"),
                "assignment_execution_did_invalid",
                failures,
            )
        commitment = canonical_sha256(
            {
                "method": METHOD,
                "reviewed_pairing_sha256": pairing_hash,
                "pair_id": pair_id,
                "participant_ids": member_ids,
            }
        )
        _require(
            assignment.get("assignment_commitment_sha256") == commitment,
            "assignment_commitment_invalid",
            failures,
        )
        mentor_index = int(commitment, 16) & 1
        _require(
            _object(assignment.get("mentor")).get("participant_id")
            == member_ids[mentor_index],
            "assignment_cohort_derivation_invalid",
            failures,
        )
    _require(
        seen_pairs == set(expected_pairs), "assignment_pair_inventory_invalid", failures
    )
    _require(
        seen_participants == set(roster_participants),
        "assignment_participant_inventory_invalid",
        failures,
    )
    body = {key: item for key, item in proposal.items() if key != "assignment_sha256"}
    _require(
        proposal.get("assignment_sha256") == canonical_sha256(body),
        "assignment_hash_mismatch",
        failures,
    )
    return list(dict.fromkeys(failures))


def build_assignment_review_receipt(
    *,
    review_id: str,
    reviewed_at: str,
    authorization_id: str,
    authorization_statement_sha256: str,
    proposal: dict[str, Any],
    proposal_artifact_sha256: str,
    reviewer_profile: dict[str, Any],
    reviewer_profile_sha256: str,
    implementation: dict[str, str],
    signer: AssignmentReviewSigner,
) -> dict[str, Any]:
    reviewer_failures = validate_reviewer_identity_profile(reviewer_profile)
    if reviewer_failures:
        raise ValueError(f"reviewer identity profile invalid: {reviewer_failures}")
    reviewer = reviewer_profile["reviewer"]
    if signer.public_key_hex.lower() != reviewer["public_key_hex"].lower():
        raise ValueError("assignment reviewer signer does not match reviewer identity")
    receipt = {
        "schema_version": RECEIPT_SCHEMA,
        "review_id": review_id,
        "decision": DECISION,
        "reviewed_at": reviewed_at,
        "authorization": {
            "authorization_id": authorization_id,
            "authorization_statement_sha256": authorization_statement_sha256,
            "source": "interactive_owner_operator_approval",
        },
        "proposal": {
            "assignment_id": proposal.get("assignment_id"),
            "assignment_sha256": proposal.get("assignment_sha256"),
            "artifact_sha256": proposal_artifact_sha256,
            "participant_count": 40,
            "pair_count": 20,
        },
        "reviewer": {**reviewer, "identity_profile_sha256": reviewer_profile_sha256},
        "implementation": implementation,
        "review_checks": {
            "exact_assignment_hash_reviewed": True,
            "deterministic_derivation_verified": True,
            "twenty_balanced_pairs_verified": True,
            "forty_unique_participants_verified": True,
            "post_assignment_substitution_prohibited": True,
        },
        "execution_boundary": {
            "cohort_assignment_approved": True,
            "single_use_authorization_issued": False,
            "provider_api_call_allowed": False,
            "model_invocation_allowed": False,
            "agent_execution_allowed": False,
            "backend_fact_append_allowed": False,
            "ledger_append_allowed": False,
        },
    }
    payload = signature_payload(receipt)
    signature = signer.sign(payload)
    if len(signature) != 64:
        raise ValueError("assignment review signature must be 64 bytes")
    receipt["signature"] = {
        "algorithm": "ed25519",
        "signed_payload_sha256": hashlib.sha256(payload).hexdigest(),
        "signature_hex": signature.hex(),
    }
    failures = validate_assignment_review_receipt(
        receipt,
        proposal=proposal,
        proposal_artifact_sha256=proposal_artifact_sha256,
        reviewer_profile=reviewer_profile,
        reviewer_profile_sha256=reviewer_profile_sha256,
        implementation=implementation,
    )
    if failures:
        raise ValueError(f"assignment review receipt invalid: {failures}")
    return receipt


def validate_assignment_review_receipt(
    value: Any,
    *,
    proposal: dict[str, Any],
    proposal_artifact_sha256: str,
    reviewer_profile: dict[str, Any],
    reviewer_profile_sha256: str,
    implementation: dict[str, str],
) -> list[str]:
    receipt = value if isinstance(value, dict) else {}
    failures = validate_reviewer_identity_profile(reviewer_profile)
    expected_fields = {
        "schema_version",
        "review_id",
        "decision",
        "reviewed_at",
        "authorization",
        "proposal",
        "reviewer",
        "implementation",
        "review_checks",
        "execution_boundary",
        "signature",
    }
    _require(
        set(receipt) == expected_fields, "assignment_review_fields_invalid", failures
    )
    _require(
        receipt.get("schema_version") == RECEIPT_SCHEMA,
        "assignment_review_schema_invalid",
        failures,
    )
    _require(_text(receipt.get("review_id")), "assignment_review_id_invalid", failures)
    _require(
        receipt.get("decision") == DECISION,
        "assignment_review_decision_invalid",
        failures,
    )
    _require(
        _rfc3339(receipt.get("reviewed_at")), "assignment_review_time_invalid", failures
    )
    authorization = _object(receipt.get("authorization"))
    _require(
        set(authorization)
        == {"authorization_id", "authorization_statement_sha256", "source"},
        "assignment_review_authorization_fields_invalid",
        failures,
    )
    _require(
        _text(authorization.get("authorization_id")),
        "assignment_review_authorization_id_invalid",
        failures,
    )
    _require(
        _sha256(authorization.get("authorization_statement_sha256")),
        "assignment_review_authorization_hash_invalid",
        failures,
    )
    _require(
        authorization.get("source") == "interactive_owner_operator_approval",
        "assignment_review_authorization_source_invalid",
        failures,
    )
    expected_proposal = {
        "assignment_id": proposal.get("assignment_id"),
        "assignment_sha256": proposal.get("assignment_sha256"),
        "artifact_sha256": proposal_artifact_sha256,
        "participant_count": 40,
        "pair_count": 20,
    }
    _require(
        receipt.get("proposal") == expected_proposal,
        "assignment_review_proposal_binding_invalid",
        failures,
    )
    expected_reviewer = {
        **_object(reviewer_profile.get("reviewer")),
        "identity_profile_sha256": reviewer_profile_sha256,
    }
    _require(
        receipt.get("reviewer") == expected_reviewer,
        "assignment_review_reviewer_binding_invalid",
        failures,
    )
    _require(
        receipt.get("implementation") == implementation,
        "assignment_review_implementation_binding_invalid",
        failures,
    )
    _validate_implementation(_object(receipt.get("implementation")), failures)
    checks = _object(receipt.get("review_checks"))
    _require(
        len(checks) == 5 and all(item is True for item in checks.values()),
        "assignment_review_checks_incomplete",
        failures,
    )
    boundary = _object(receipt.get("execution_boundary"))
    _require(
        boundary.get("cohort_assignment_approved") is True,
        "assignment_review_not_approved",
        failures,
    )
    _require(
        len(boundary) == 7
        and all(
            value is False
            for key, value in boundary.items()
            if key != "cohort_assignment_approved"
        ),
        "assignment_review_boundary_invalid",
        failures,
    )
    signature = _object(receipt.get("signature"))
    payload = signature_payload(receipt)
    _require(
        signature.get("algorithm") == "ed25519",
        "assignment_review_signature_algorithm_invalid",
        failures,
    )
    _require(
        signature.get("signed_payload_sha256") == hashlib.sha256(payload).hexdigest(),
        "assignment_review_signature_payload_hash_mismatch",
        failures,
    )
    try:
        VerifyKey(
            bytes.fromhex(str(receipt.get("reviewer", {}).get("public_key_hex", "")))
        ).verify(payload, bytes.fromhex(str(signature.get("signature_hex", ""))))
    except (BadSignatureError, ValueError):
        failures.append("assignment_review_signature_invalid")
    return list(dict.fromkeys(failures))


def build_reviewed_assignment(
    *, proposal: dict[str, Any], receipt: dict[str, Any], receipt_artifact_sha256: str
) -> dict[str, Any]:
    reviewed = {
        **{
            key: item
            for key, item in proposal.items()
            if key not in {"status", "assignment_sha256"}
        },
        "schema_version": REVIEWED_SCHEMA,
        "status": "operator_reviewed",
        "source_proposal_sha256": proposal["assignment_sha256"],
        "operator_review": {
            "review_id": receipt["review_id"],
            "reviewer_did": receipt["reviewer"]["did"],
            "reviewed_at": receipt["reviewed_at"],
            "review_receipt_sha256": receipt_artifact_sha256,
        },
    }
    reviewed["reviewed_assignment_sha256"] = canonical_sha256(reviewed)
    return reviewed


def validate_reviewed_assignment(value: Any) -> list[str]:
    reviewed = value if isinstance(value, dict) else {}
    failures: list[str] = []
    _require(
        reviewed.get("schema_version") == REVIEWED_SCHEMA,
        "reviewed_assignment_schema_invalid",
        failures,
    )
    _require(
        reviewed.get("status") == "operator_reviewed",
        "reviewed_assignment_status_invalid",
        failures,
    )
    _require(
        reviewed.get("method") == METHOD, "reviewed_assignment_method_invalid", failures
    )
    _require(
        reviewed.get("participant_count") == 40,
        "reviewed_assignment_participant_count_invalid",
        failures,
    )
    _require(
        reviewed.get("pair_count") == 20,
        "reviewed_assignment_pair_count_invalid",
        failures,
    )
    _require(
        _sha256(reviewed.get("source_proposal_sha256")),
        "reviewed_assignment_source_hash_invalid",
        failures,
    )
    review = _object(reviewed.get("operator_review"))
    _require(
        _text(review.get("review_id"))
        and _text(review.get("reviewer_did"))
        and _rfc3339(review.get("reviewed_at"))
        and _sha256(review.get("review_receipt_sha256")),
        "reviewed_assignment_review_invalid",
        failures,
    )
    assignments = reviewed.get("assignments")
    items = assignments if isinstance(assignments, list) else []
    _require(len(items) == 20, "reviewed_assignment_pairs_invalid", failures)
    _require(
        sum(2 for _ in items) == 40,
        "reviewed_assignment_participants_invalid",
        failures,
    )
    body = {
        key: item
        for key, item in reviewed.items()
        if key != "reviewed_assignment_sha256"
    }
    _require(
        reviewed.get("reviewed_assignment_sha256") == canonical_sha256(body),
        "reviewed_assignment_hash_mismatch",
        failures,
    )
    return list(dict.fromkeys(failures))


def validate_reviewed_assignment_binding(
    reviewed: Any,
    *,
    proposal: dict[str, Any],
    receipt: dict[str, Any],
    receipt_artifact_sha256: str,
) -> list[str]:
    expected = build_reviewed_assignment(
        proposal=proposal,
        receipt=receipt,
        receipt_artifact_sha256=receipt_artifact_sha256,
    )
    failures = validate_reviewed_assignment(reviewed)
    if reviewed != expected:
        failures.append("reviewed_assignment_copy_on_write_binding_invalid")
    return list(dict.fromkeys(failures))


def signature_payload(receipt: dict[str, Any]) -> bytes:
    body = {key: item for key, item in receipt.items() if key != "signature"}
    return json.dumps(
        body, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")


def _roster_participants(
    roster: dict[str, Any], failures: list[str]
) -> dict[str, dict[str, Any]]:
    participants = roster.get("participants")
    items = participants if isinstance(participants, list) else []
    by_id = {
        str(item.get("participant_id")): item
        for item in items
        if isinstance(item, dict) and _text(item.get("participant_id"))
    }
    _require(
        len(items) == 40 and len(by_id) == 40,
        "assignment_roster_participants_invalid",
        failures,
    )
    return by_id


def _assignment_member(roster_item: dict[str, Any]) -> dict[str, str]:
    return {
        "participant_id": str(roster_item["participant_id"]),
        "execution_did": str(roster_item["execution_did"]),
    }


def _validate_implementation(value: dict[str, Any], failures: list[str]) -> None:
    _require(
        set(value)
        == {"agent_revision", "contract_source_sha256", "operation_source_sha256"},
        "assignment_review_implementation_fields_invalid",
        failures,
    )
    _require(
        _text(value.get("agent_revision"))
        and 7 <= len(str(value.get("agent_revision"))) <= 64,
        "assignment_review_revision_invalid",
        failures,
    )
    _require(
        _sha256(value.get("contract_source_sha256"))
        and _sha256(value.get("operation_source_sha256")),
        "assignment_review_source_hash_invalid",
        failures,
    )


def _object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(char in "0123456789abcdef" for char in value.lower())
    )


def _rfc3339(value: Any) -> bool:
    if not _text(value):
        return False
    try:
        return (
            datetime.fromisoformat(str(value).replace("Z", "+00:00")).tzinfo is not None
        )
    except ValueError:
        return False


def _require(condition: bool, failure: str, failures: list[str]) -> None:
    if not condition:
        failures.append(failure)
