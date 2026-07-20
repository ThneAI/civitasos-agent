"""Signed independent review contract for a J1-D qualification roster."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any, Protocol

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from .controlled_comparison import canonical_sha256
from .qualification_reviewer_identity import validate_reviewer_identity_profile


RECEIPT_SCHEMA = "j1-qualification-roster-review-receipt:v1"
DECISION = "approve_roster_binding"
REQUIRED_CHECKS = {
    "exact_roster_artifact_hash_reviewed",
    "frozen_protocol_binding_verified",
    "reviewed_pairing_binding_verified",
    "forty_unique_participants_verified",
    "twenty_complete_pairs_verified",
    "participant_signatures_verified",
    "baseline_signatures_verified",
    "zero_prior_mentorship_verified",
    "same_frozen_stack_verified",
    "soft_token_limitations_acknowledged",
}
FALSE_BOUNDARIES = {
    "agent_execution_allowed",
    "backend_fact_append_allowed",
    "ledger_append_allowed",
    "model_invocation_allowed",
    "provider_api_call_allowed",
    "single_use_authorization_issued",
    "controlled_experiment_execution_ready",
}
RECEIPT_FIELDS = {
    "schema_version",
    "review_id",
    "decision",
    "reviewed_at",
    "authorization",
    "candidate_roster",
    "source_evidence",
    "reviewer",
    "reviewer_declarations",
    "review_implementation",
    "review_checks",
    "execution_boundary",
    "signature",
}
SIGNATURE_FIELDS = {"algorithm", "signed_payload_sha256", "signature_hex"}


class RosterReviewSigner(Protocol):
    @property
    def public_key_hex(self) -> str: ...

    def sign(self, message: bytes) -> bytes: ...


def signature_payload(receipt: dict[str, Any]) -> bytes:
    body = {key: item for key, item in receipt.items() if key != "signature"}
    return json.dumps(
        body, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")


def build_roster_review_receipt(
    *,
    review_id: str,
    reviewed_at: str,
    authorization_id: str,
    authorization_statement_sha256: str,
    candidate_roster: dict[str, Any],
    candidate_artifact_sha256: str,
    source_evidence: dict[str, Any],
    reviewer_profile: dict[str, Any],
    reviewer_profile_sha256: str,
    review_implementation: dict[str, str],
    signer: RosterReviewSigner,
) -> dict[str, Any]:
    profile_failures = validate_reviewer_identity_profile(reviewer_profile)
    if profile_failures:
        raise ValueError(f"reviewer identity profile invalid: {profile_failures}")
    reviewer = reviewer_profile["reviewer"]
    if signer.public_key_hex.lower() != reviewer["public_key_hex"].lower():
        raise ValueError("roster review signer does not match reviewer identity")
    receipt = {
        "schema_version": RECEIPT_SCHEMA,
        "review_id": review_id,
        "decision": DECISION,
        "reviewed_at": reviewed_at,
        "authorization": {
            "authorization_id": authorization_id,
            "authorization_statement_sha256": authorization_statement_sha256,
            "source": "interactive_owner_operator_approval",
            "cryptographically_signed_by_reviewer": True,
        },
        "candidate_roster": {
            "roster_id": candidate_roster["roster_id"],
            "roster_sha256": candidate_roster["roster_sha256"],
            "roster_artifact_sha256": candidate_artifact_sha256,
            "admission_request_sha256": candidate_roster["admission_request_sha256"],
            "qualification_protocol_sha256": candidate_roster[
                "qualification_protocol_sha256"
            ],
            "participant_count": len(candidate_roster["participants"]),
            "pair_count": len(
                {item["pair_id"] for item in candidate_roster["participants"]}
            ),
        },
        "source_evidence": source_evidence,
        "reviewer": {**reviewer, "identity_profile_sha256": reviewer_profile_sha256},
        "reviewer_declarations": {
            "conflicts_disclosed": True,
            "independent_judgment_exercised": True,
            "participant_consent_not_execution_authorization": True,
            "baseline_not_performance_measurement": True,
        },
        "review_implementation": review_implementation,
        "review_checks": {field: True for field in sorted(REQUIRED_CHECKS)},
        "execution_boundary": {
            "roster_binding_approved": True,
            **{field: False for field in sorted(FALSE_BOUNDARIES)},
        },
    }
    payload = signature_payload(receipt)
    signature = signer.sign(payload)
    if len(signature) != 64:
        raise ValueError("roster review signature must be 64 bytes")
    receipt["signature"] = {
        "algorithm": "ed25519",
        "signed_payload_sha256": hashlib.sha256(payload).hexdigest(),
        "signature_hex": signature.hex(),
    }
    failures = validate_roster_review_receipt(
        receipt,
        candidate_roster=candidate_roster,
        candidate_artifact_sha256=candidate_artifact_sha256,
        source_evidence=source_evidence,
        reviewer_profile=reviewer_profile,
        reviewer_profile_sha256=reviewer_profile_sha256,
        review_implementation=review_implementation,
    )
    if failures:
        raise ValueError(f"roster review receipt invalid: {failures}")
    return receipt


def validate_roster_review_receipt(
    value: Any,
    *,
    candidate_roster: dict[str, Any],
    candidate_artifact_sha256: str,
    source_evidence: dict[str, Any],
    reviewer_profile: dict[str, Any],
    reviewer_profile_sha256: str,
    review_implementation: dict[str, str],
) -> list[str]:
    receipt = value if isinstance(value, dict) else {}
    failures: list[str] = []
    _require(set(receipt) == RECEIPT_FIELDS, "roster_review_fields_invalid", failures)
    _require(
        receipt.get("schema_version") == RECEIPT_SCHEMA,
        "roster_review_schema_invalid",
        failures,
    )
    _require(_real_text(receipt.get("review_id")), "roster_review_id_invalid", failures)
    _require(
        receipt.get("decision") == DECISION, "roster_review_decision_invalid", failures
    )
    _require(
        _rfc3339(receipt.get("reviewed_at")), "roster_review_time_invalid", failures
    )
    authorization = _object(receipt.get("authorization"))
    _require(
        set(authorization)
        == {
            "authorization_id",
            "authorization_statement_sha256",
            "source",
            "cryptographically_signed_by_reviewer",
        },
        "roster_review_authorization_fields_invalid",
        failures,
    )
    _require(
        _real_text(authorization.get("authorization_id")),
        "roster_review_authorization_id_invalid",
        failures,
    )
    _require(
        _sha256(authorization.get("authorization_statement_sha256")),
        "roster_review_authorization_hash_invalid",
        failures,
    )
    _require(
        authorization.get("source") == "interactive_owner_operator_approval",
        "roster_review_authorization_source_invalid",
        failures,
    )
    _require(
        authorization.get("cryptographically_signed_by_reviewer") is True,
        "roster_review_authorization_unsigned",
        failures,
    )
    expected_candidate = {
        "roster_id": candidate_roster.get("roster_id"),
        "roster_sha256": candidate_roster.get("roster_sha256"),
        "roster_artifact_sha256": candidate_artifact_sha256,
        "admission_request_sha256": candidate_roster.get("admission_request_sha256"),
        "qualification_protocol_sha256": candidate_roster.get(
            "qualification_protocol_sha256"
        ),
        "participant_count": len(candidate_roster.get("participants", [])),
        "pair_count": len(
            {
                item.get("pair_id")
                for item in candidate_roster.get("participants", [])
                if isinstance(item, dict)
            }
        ),
    }
    _require(
        receipt.get("candidate_roster") == expected_candidate,
        "roster_review_candidate_binding_invalid",
        failures,
    )
    _require(
        receipt.get("source_evidence") == source_evidence,
        "roster_review_evidence_binding_invalid",
        failures,
    )
    _validate_source_evidence(_object(receipt.get("source_evidence")), failures)
    expected_reviewer = {
        **_object(reviewer_profile.get("reviewer")),
        "identity_profile_sha256": reviewer_profile_sha256,
    }
    _require(
        receipt.get("reviewer") == expected_reviewer,
        "roster_review_reviewer_binding_invalid",
        failures,
    )
    _require(
        not validate_reviewer_identity_profile(reviewer_profile),
        "roster_review_reviewer_profile_invalid",
        failures,
    )
    declarations = _object(receipt.get("reviewer_declarations"))
    _require(
        set(declarations)
        == {
            "conflicts_disclosed",
            "independent_judgment_exercised",
            "participant_consent_not_execution_authorization",
            "baseline_not_performance_measurement",
        }
        and all(item is True for item in declarations.values()),
        "roster_review_declarations_incomplete",
        failures,
    )
    _require(
        receipt.get("review_implementation") == review_implementation,
        "roster_review_implementation_binding_invalid",
        failures,
    )
    _validate_implementation(_object(receipt.get("review_implementation")), failures)
    checks = _object(receipt.get("review_checks"))
    _require(
        set(checks) == REQUIRED_CHECKS
        and all(item is True for item in checks.values()),
        "roster_review_checks_incomplete",
        failures,
    )
    boundary = _object(receipt.get("execution_boundary"))
    _require(
        set(boundary) == FALSE_BOUNDARIES | {"roster_binding_approved"},
        "roster_review_boundary_fields_invalid",
        failures,
    )
    _require(
        boundary.get("roster_binding_approved") is True,
        "roster_review_not_approved",
        failures,
    )
    for field in FALSE_BOUNDARIES:
        _require(
            boundary.get(field) is False,
            f"roster_review_{field}_must_be_false",
            failures,
        )
    _validate_signature(receipt, failures)
    return list(dict.fromkeys(failures))


def build_reviewed_roster(
    *, candidate_roster: dict[str, Any], receipt: dict[str, Any], receipt_sha256: str
) -> dict[str, Any]:
    reviewed = {
        key: item
        for key, item in candidate_roster.items()
        if key not in {"status", "roster_sha256"}
    }
    reviewed["status"] = "operator_reviewed"
    reviewed["operator_review"] = {
        "reviewer_did": receipt["reviewer"]["did"],
        "decision": receipt["decision"],
        "conflicts_disclosed": receipt["reviewer_declarations"]["conflicts_disclosed"],
        "reviewed_at": receipt["reviewed_at"],
        "review_receipt_sha256": receipt_sha256,
    }
    reviewed["roster_sha256"] = canonical_sha256(reviewed)
    return reviewed


def validate_reviewed_roster_binding(
    reviewed_roster: Any,
    *,
    candidate_roster: dict[str, Any],
    receipt: dict[str, Any],
    receipt_sha256: str,
) -> list[str]:
    expected = build_reviewed_roster(
        candidate_roster=candidate_roster,
        receipt=receipt,
        receipt_sha256=receipt_sha256,
    )
    return (
        []
        if reviewed_roster == expected
        else ["reviewed_roster_copy_on_write_binding_invalid"]
    )


def _validate_source_evidence(evidence: dict[str, Any], failures: list[str]) -> None:
    expected_fields = {
        "reviewed_pairing_sha256",
        "baseline_consent_manifest_sha256",
        "manifest_artifact_sha256",
        "intake_report_artifact_sha256",
        "evidence_artifact_count",
        "cognitive_baseline_count",
        "participant_consent_count",
        "participant_packet_count",
    }
    _require(
        set(evidence) == expected_fields,
        "roster_review_evidence_fields_invalid",
        failures,
    )
    for field in (
        "reviewed_pairing_sha256",
        "baseline_consent_manifest_sha256",
        "manifest_artifact_sha256",
        "intake_report_artifact_sha256",
    ):
        _require(
            _sha256(evidence.get(field)), f"roster_review_{field}_invalid", failures
        )
    expected_counts = {
        "evidence_artifact_count": 220,
        "cognitive_baseline_count": 20,
        "participant_consent_count": 40,
        "participant_packet_count": 40,
    }
    for field, expected in expected_counts.items():
        _require(
            evidence.get(field) == expected, f"roster_review_{field}_invalid", failures
        )


def _validate_implementation(value: dict[str, Any], failures: list[str]) -> None:
    _require(
        set(value)
        == {"agent_revision", "contract_source_sha256", "operation_source_sha256"},
        "roster_review_implementation_fields_invalid",
        failures,
    )
    revision = str(value.get("agent_revision", "")).lower()
    _require(
        7 <= len(revision) <= 64
        and all(char in "0123456789abcdef" for char in revision),
        "roster_review_agent_revision_invalid",
        failures,
    )
    for field in ("contract_source_sha256", "operation_source_sha256"):
        _require(_sha256(value.get(field)), f"roster_review_{field}_invalid", failures)


def _validate_signature(receipt: dict[str, Any], failures: list[str]) -> None:
    signature = _object(receipt.get("signature"))
    _require(
        set(signature) == SIGNATURE_FIELDS,
        "roster_review_signature_fields_invalid",
        failures,
    )
    payload = signature_payload(receipt)
    _require(
        signature.get("algorithm") == "ed25519",
        "roster_review_signature_algorithm_invalid",
        failures,
    )
    _require(
        signature.get("signed_payload_sha256") == hashlib.sha256(payload).hexdigest(),
        "roster_review_signature_payload_hash_mismatch",
        failures,
    )
    try:
        VerifyKey(
            bytes.fromhex(
                str(_object(receipt.get("reviewer")).get("public_key_hex", ""))
            )
        ).verify(payload, bytes.fromhex(str(signature.get("signature_hex", ""))))
    except (BadSignatureError, ValueError):
        failures.append("roster_review_signature_invalid")


def _rfc3339(value: Any) -> bool:
    try:
        parsed = datetime.fromisoformat(str(value or "").replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None


def _sha256(value: Any) -> bool:
    text = str(value or "")
    return len(text) == 64 and all(char in "0123456789abcdef" for char in text)


def _real_text(value: Any) -> bool:
    text = str(value or "").strip().lower()
    return bool(text) and not any(
        token in text for token in ("synthetic", "fixture", "test", "demo")
    )


def _object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _require(condition: bool, code: str, failures: list[str]) -> None:
    if not condition and code not in failures:
        failures.append(code)
