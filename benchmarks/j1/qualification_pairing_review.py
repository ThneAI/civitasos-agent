"""Signed exact-pairing review contracts for J1-D qualification."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any, Protocol

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from .controlled_comparison import canonical_sha256
from .qualification_participant_evidence import validate_evidence_artifact
from .qualification_participant_provisioning import validate_pairing_proposal
from .qualification_reviewer_identity import validate_reviewer_identity_profile


RECEIPT_SCHEMA = "j1-qualification-pairing-review-receipt:v1"
REVIEWED_PAIRING_SCHEMA = "j1-qualification-pairing-reviewed:v1"
DECISION = "approve_exact_pairing"
REQUIRED_CHECKS = {
    "exact_proposal_hash_reviewed",
    "forty_unique_identities_verified",
    "twenty_unique_pairs_verified",
    "zero_prior_mentorship_verified",
    "exclusive_isolation_verified",
    "soft_token_limitations_acknowledged",
}
FALSE_BOUNDARIES = {
    "agent_execution_allowed",
    "backend_fact_append_allowed",
    "cognitive_baseline_created",
    "ledger_append_allowed",
    "model_invocation_allowed",
    "participant_consent_created",
    "participant_packet_created",
    "roster_approved",
    "single_use_authorization_issued",
}
RECEIPT_FIELDS = {
    "schema_version",
    "review_id",
    "decision",
    "reviewed_at",
    "authorization",
    "proposal",
    "reviewer",
    "review_implementation",
    "review_checks",
    "execution_boundary",
    "signature",
}
REVIEWED_PAIRING_FIELDS = {
    "schema_version",
    "proposal_id",
    "status",
    "created_at",
    "reviewed_at",
    "qualification_protocol_sha256",
    "source_proposal_sha256",
    "assignment_method",
    "assignment_nonce_hex",
    "participant_profile_sha256",
    "pairs",
    "operator_review",
    "readiness",
    "reviewed_pairing_sha256",
}


class PairingReviewSigner(Protocol):
    @property
    def public_key_hex(self) -> str: ...

    def sign(self, message: bytes) -> bytes: ...


def pairing_review_signature_payload(receipt: dict[str, Any]) -> bytes:
    body = {key: value for key, value in receipt.items() if key != "signature"}
    return json.dumps(
        body, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")


def build_pairing_review_receipt(
    *,
    review_id: str,
    reviewed_at: str,
    authorization_id: str,
    authorization_statement_sha256: str,
    proposal: dict[str, Any],
    proposal_artifact_sha256: str,
    reviewer_profile: dict[str, Any],
    reviewer_profile_sha256: str,
    review_implementation: dict[str, str],
    signer: PairingReviewSigner,
) -> dict[str, Any]:
    proposal_failures = validate_pairing_proposal(proposal)
    if proposal_failures:
        raise ValueError(f"pairing proposal invalid: {proposal_failures}")
    profile_failures = validate_reviewer_identity_profile(reviewer_profile)
    if profile_failures:
        raise ValueError(f"reviewer identity profile invalid: {profile_failures}")
    reviewer = reviewer_profile["reviewer"]
    if signer.public_key_hex.lower() != reviewer["public_key_hex"].lower():
        raise ValueError("pairing review signer does not match reviewer identity")
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
        "proposal": {
            "proposal_id": proposal["proposal_id"],
            "proposal_sha256": proposal["proposal_sha256"],
            "proposal_artifact_sha256": proposal_artifact_sha256,
            "qualification_protocol_sha256": proposal["qualification_protocol_sha256"],
            "participant_profile_sha256": proposal["participant_profile_sha256"],
            "pair_count": len(proposal["pairs"]),
            "participant_count": sum(
                len(pair["participant_ids"]) for pair in proposal["pairs"]
            ),
        },
        "reviewer": {
            **reviewer,
            "identity_profile_sha256": reviewer_profile_sha256,
        },
        "review_implementation": review_implementation,
        "review_checks": {field: True for field in sorted(REQUIRED_CHECKS)},
        "execution_boundary": {
            "pairing_approved": True,
            "public_identity_custody_isolation_evidence_export_allowed": True,
            **{field: False for field in sorted(FALSE_BOUNDARIES)},
        },
    }
    payload = pairing_review_signature_payload(receipt)
    signature = signer.sign(payload)
    receipt["signature"] = {
        "algorithm": "ed25519",
        "signed_payload_sha256": hashlib.sha256(payload).hexdigest(),
        "signature_hex": signature.hex(),
    }
    failures = validate_pairing_review_receipt(
        receipt,
        proposal=proposal,
        proposal_artifact_sha256=proposal_artifact_sha256,
        reviewer_profile=reviewer_profile,
        reviewer_profile_sha256=reviewer_profile_sha256,
        review_implementation=review_implementation,
    )
    if failures:
        raise ValueError(f"pairing review receipt invalid: {failures}")
    return receipt


def validate_pairing_review_receipt(
    value: Any,
    *,
    proposal: dict[str, Any],
    proposal_artifact_sha256: str,
    reviewer_profile: dict[str, Any],
    reviewer_profile_sha256: str,
    review_implementation: dict[str, str],
) -> list[str]:
    receipt = value if isinstance(value, dict) else {}
    failures = validate_pairing_proposal(proposal)
    failures.extend(validate_reviewer_identity_profile(reviewer_profile))
    _require(set(receipt) == RECEIPT_FIELDS, "pairing_review_fields_invalid", failures)
    _require(
        receipt.get("schema_version") == RECEIPT_SCHEMA,
        "pairing_review_schema_invalid",
        failures,
    )
    _require(
        _real_text(receipt.get("review_id")), "pairing_review_id_invalid", failures
    )
    _require(
        receipt.get("decision") == DECISION, "pairing_review_decision_invalid", failures
    )
    _require(
        _rfc3339(receipt.get("reviewed_at")), "pairing_review_time_invalid", failures
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
        "pairing_review_authorization_fields_invalid",
        failures,
    )
    _require(
        _real_text(authorization.get("authorization_id")),
        "pairing_review_authorization_id_invalid",
        failures,
    )
    _require(
        _sha256(authorization.get("authorization_statement_sha256")),
        "pairing_review_authorization_hash_invalid",
        failures,
    )
    _require(
        authorization.get("source") == "interactive_owner_operator_approval",
        "pairing_review_authorization_source_invalid",
        failures,
    )
    _require(
        authorization.get("cryptographically_signed_by_reviewer") is True,
        "pairing_review_authorization_unsigned",
        failures,
    )
    expected_proposal = {
        "proposal_id": proposal.get("proposal_id"),
        "proposal_sha256": proposal.get("proposal_sha256"),
        "proposal_artifact_sha256": proposal_artifact_sha256,
        "qualification_protocol_sha256": proposal.get("qualification_protocol_sha256"),
        "participant_profile_sha256": proposal.get("participant_profile_sha256"),
        "pair_count": 20,
        "participant_count": 40,
    }
    _require(
        receipt.get("proposal") == expected_proposal,
        "pairing_review_proposal_binding_invalid",
        failures,
    )
    expected_reviewer = {
        **_object(reviewer_profile.get("reviewer")),
        "identity_profile_sha256": reviewer_profile_sha256,
    }
    _require(
        receipt.get("reviewer") == expected_reviewer,
        "pairing_review_reviewer_binding_invalid",
        failures,
    )
    _require(
        receipt.get("review_implementation") == review_implementation,
        "pairing_review_implementation_binding_invalid",
        failures,
    )
    implementation = _object(receipt.get("review_implementation"))
    _require(
        set(implementation)
        == {
            "agent_revision",
            "contract_source_sha256",
            "operation_source_sha256",
        },
        "pairing_review_implementation_fields_invalid",
        failures,
    )
    _require(
        _git_revision(implementation.get("agent_revision")),
        "pairing_review_agent_revision_invalid",
        failures,
    )
    for field in ("contract_source_sha256", "operation_source_sha256"):
        _require(
            _sha256(implementation.get(field)),
            f"pairing_review_{field}_invalid",
            failures,
        )
    checks = _object(receipt.get("review_checks"))
    _require(
        set(checks) == REQUIRED_CHECKS
        and all(value is True for value in checks.values()),
        "pairing_review_checks_incomplete",
        failures,
    )
    boundary = _object(receipt.get("execution_boundary"))
    _require(
        set(boundary)
        == FALSE_BOUNDARIES
        | {
            "pairing_approved",
            "public_identity_custody_isolation_evidence_export_allowed",
        },
        "pairing_review_boundary_fields_invalid",
        failures,
    )
    _require(
        boundary.get("pairing_approved") is True,
        "pairing_review_not_approved",
        failures,
    )
    _require(
        boundary.get("public_identity_custody_isolation_evidence_export_allowed")
        is True,
        "pairing_public_evidence_export_not_allowed",
        failures,
    )
    for field in FALSE_BOUNDARIES:
        _require(
            boundary.get(field) is False,
            f"pairing_review_{field}_must_be_false",
            failures,
        )
    _validate_signature(receipt, failures)
    return list(dict.fromkeys(failures))


def build_reviewed_pairing(
    *, proposal: dict[str, Any], receipt: dict[str, Any], receipt_sha256: str
) -> dict[str, Any]:
    reviewed = {
        "schema_version": REVIEWED_PAIRING_SCHEMA,
        "proposal_id": proposal["proposal_id"],
        "status": "operator_reviewed",
        "created_at": proposal["created_at"],
        "reviewed_at": receipt["reviewed_at"],
        "qualification_protocol_sha256": proposal["qualification_protocol_sha256"],
        "source_proposal_sha256": proposal["proposal_sha256"],
        "assignment_method": proposal["assignment_method"],
        "assignment_nonce_hex": proposal["assignment_nonce_hex"],
        "participant_profile_sha256": proposal["participant_profile_sha256"],
        "pairs": [
            {
                **pair,
                "status": "operator_reviewed",
            }
            for pair in proposal["pairs"]
        ],
        "operator_review": {
            "review_id": receipt["review_id"],
            "reviewer_did": receipt["reviewer"]["did"],
            "decision": receipt["decision"],
            "reviewed_at": receipt["reviewed_at"],
            "review_receipt_sha256": receipt_sha256,
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
    failures = validate_reviewed_pairing(reviewed)
    if failures:
        raise ValueError(f"reviewed pairing invalid: {failures}")
    return reviewed


def validate_reviewed_pairing(value: Any) -> list[str]:
    reviewed = value if isinstance(value, dict) else {}
    failures: list[str] = []
    _require(
        set(reviewed) == REVIEWED_PAIRING_FIELDS,
        "reviewed_pairing_fields_invalid",
        failures,
    )
    _require(
        reviewed.get("schema_version") == REVIEWED_PAIRING_SCHEMA,
        "reviewed_pairing_schema_invalid",
        failures,
    )
    _require(
        reviewed.get("status") == "operator_reviewed",
        "reviewed_pairing_status_invalid",
        failures,
    )
    _require(
        _real_text(reviewed.get("proposal_id")), "reviewed_pairing_id_invalid", failures
    )
    for field in ("created_at", "reviewed_at"):
        _require(
            _rfc3339(reviewed.get(field)), f"reviewed_pairing_{field}_invalid", failures
        )
    for field in ("qualification_protocol_sha256", "source_proposal_sha256"):
        _require(
            _sha256(reviewed.get(field)), f"reviewed_pairing_{field}_invalid", failures
        )
    _require(
        reviewed.get("assignment_method")
        == "nonce_randomized_fresh_baseline_pairing_proposal:v1",
        "reviewed_pairing_assignment_method_invalid",
        failures,
    )
    _require(
        _hex_bytes(reviewed.get("assignment_nonce_hex"), 32),
        "reviewed_pairing_nonce_invalid",
        failures,
    )
    profiles = reviewed.get("participant_profile_sha256")
    _require(
        isinstance(profiles, list)
        and len(profiles) == 40
        and len({_text(item) for item in profiles}) == 40
        and all(_sha256(item) for item in profiles),
        "reviewed_pairing_profiles_invalid",
        failures,
    )
    pairs = reviewed.get("pairs")
    ids: list[str] = []
    dids: list[str] = []
    _require(
        isinstance(pairs, list) and len(pairs) == 20,
        "reviewed_pairing_pair_count_invalid",
        failures,
    )
    if isinstance(pairs, list):
        for index, pair in enumerate(pairs, start=1):
            item = _object(pair)
            _require(
                set(item)
                == {
                    "pair_id",
                    "participant_ids",
                    "execution_dids",
                    "status",
                    "cognitive_baseline_evidence_created",
                    "random_assignment_consent_created",
                },
                "reviewed_pair_fields_invalid",
                failures,
            )
            _require(
                item.get("pair_id") == f"j1q-pair-{index:02d}",
                "reviewed_pair_id_invalid",
                failures,
            )
            pair_ids = item.get("participant_ids")
            pair_dids = item.get("execution_dids")
            _require(
                item.get("status") == "operator_reviewed",
                "reviewed_pair_status_invalid",
                failures,
            )
            _require(
                isinstance(pair_ids, list) and len(pair_ids) == 2,
                "reviewed_pair_participants_invalid",
                failures,
            )
            _require(
                isinstance(pair_dids, list) and len(pair_dids) == 2,
                "reviewed_pair_dids_invalid",
                failures,
            )
            if isinstance(pair_ids, list):
                ids.extend(_text(value) for value in pair_ids)
            if isinstance(pair_dids, list):
                dids.extend(_text(value) for value in pair_dids)
            for field in (
                "cognitive_baseline_evidence_created",
                "random_assignment_consent_created",
            ):
                _require(
                    item.get(field) is False,
                    f"reviewed_pairing_{field}_must_be_false",
                    failures,
                )
    _require(
        len(ids) == 40 and len(set(ids)) == 40,
        "reviewed_pairing_participant_uniqueness_invalid",
        failures,
    )
    _require(
        len(dids) == 40 and len(set(dids)) == 40,
        "reviewed_pairing_did_uniqueness_invalid",
        failures,
    )
    review = _object(reviewed.get("operator_review"))
    _require(
        set(review)
        == {
            "review_id",
            "reviewer_did",
            "decision",
            "reviewed_at",
            "review_receipt_sha256",
        },
        "reviewed_pairing_review_fields_invalid",
        failures,
    )
    for field in ("review_id", "reviewer_did"):
        _require(
            bool(_text(review.get(field))),
            f"reviewed_pairing_{field}_invalid",
            failures,
        )
    _require(
        _rfc3339(review.get("reviewed_at")),
        "reviewed_pairing_reviewed_at_invalid",
        failures,
    )
    _require(
        review.get("decision") == DECISION, "reviewed_pairing_review_invalid", failures
    )
    _require(
        _sha256(review.get("review_receipt_sha256")),
        "reviewed_pairing_receipt_hash_invalid",
        failures,
    )
    readiness = _object(reviewed.get("readiness"))
    for field in (
        "all_participant_identities_provisioned",
        "pairing_operator_reviewed",
    ):
        _require(
            readiness.get(field) is True, f"reviewed_pairing_{field}_required", failures
        )
    for field in (
        "participant_evidence_complete",
        "real_participant_roster_bound",
        "single_use_authorization_issued",
        "controlled_experiment_execution_ready",
    ):
        _require(
            readiness.get(field) is False,
            f"reviewed_pairing_{field}_must_be_false",
            failures,
        )
    declared = reviewed.get("reviewed_pairing_sha256")
    body = {
        key: item for key, item in reviewed.items() if key != "reviewed_pairing_sha256"
    }
    _require(
        declared == canonical_sha256(body), "reviewed_pairing_hash_mismatch", failures
    )
    return list(dict.fromkeys(failures))


def build_public_state_evidence(
    *,
    profile: dict[str, Any],
    pair_id: str,
    attested_at: str,
    operator_attestation_sha256: str,
) -> dict[str, dict[str, Any]]:
    participant = profile["participant"]
    common = {
        "qualification_protocol_sha256": profile["qualification_protocol_sha256"],
        "attested_at": attested_at,
        "public_only": True,
        "secret_material_included": False,
        "operator_attestation_sha256": operator_attestation_sha256,
    }
    binding = {
        "participant_id": participant["participant_id"],
        "execution_did": participant["execution_did"],
    }
    artifacts = {
        "identity_snapshot": {
            "schema_version": "j1-qualification-identity-snapshot:v1",
            **common,
            **binding,
            "credential_version": participant["credential_version"],
            "signer_kind": participant["signer_kind"],
            "public_key_sha256": participant["public_key_sha256"],
            "identity_state_sha256": profile["profile_sha256"],
        },
        "custody_provenance": {
            "schema_version": "j1-qualification-custody-provenance:v1",
            **common,
            **binding,
            "signer_kind": participant["signer_kind"],
            "non_exportable": profile["custody_boundary"]["private_key_extractable"]
            is False,
            "key_reference_sha256": profile["pkcs11_key"]["key_reference_sha256"],
        },
        "isolation_root": {
            "schema_version": "j1-qualification-isolation-root:v1",
            **common,
            **binding,
            "isolation_id": profile["isolation"]["isolation_id"],
            "isolation_commitment_sha256": profile["isolation"][
                "container_config_sha256"
            ],
            "exclusive_assignment": profile["isolation"]["exclusive_assignment"],
        },
    }
    packet = {
        **binding,
        "pair_id": pair_id,
        "credential_version": participant["credential_version"],
        "signer_kind": participant["signer_kind"],
    }
    for kind, artifact in artifacts.items():
        failures = validate_evidence_artifact(
            kind,
            artifact,
            packet=packet,
            qualification_protocol_sha256=profile["qualification_protocol_sha256"],
        )
        if failures:
            raise ValueError(f"public {kind} Evidence invalid: {failures}")
    return artifacts


def _validate_signature(receipt: dict[str, Any], failures: list[str]) -> None:
    signature = _object(receipt.get("signature"))
    _require(
        set(signature) == {"algorithm", "signed_payload_sha256", "signature_hex"},
        "pairing_review_signature_fields_invalid",
        failures,
    )
    payload = pairing_review_signature_payload(receipt)
    _require(
        signature.get("algorithm") == "ed25519",
        "pairing_review_signature_algorithm_invalid",
        failures,
    )
    _require(
        signature.get("signed_payload_sha256") == hashlib.sha256(payload).hexdigest(),
        "pairing_review_signature_payload_hash_mismatch",
        failures,
    )
    try:
        VerifyKey(
            bytes.fromhex(_text(_object(receipt.get("reviewer")).get("public_key_hex")))
        ).verify(payload, bytes.fromhex(_text(signature.get("signature_hex"))))
    except (BadSignatureError, ValueError):
        failures.append("pairing_review_signature_invalid")


def _rfc3339(value: Any) -> bool:
    try:
        parsed = datetime.fromisoformat(_text(value).replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None


def _sha256(value: Any) -> bool:
    return _hex_bytes(value, 32)


def _hex_bytes(value: Any, size: int) -> bool:
    text = _text(value)
    return len(text) == size * 2 and all(char in "0123456789abcdef" for char in text)


def _real_text(value: Any) -> bool:
    text = _text(value).lower()
    return bool(text) and not any(
        token in text for token in ("synthetic", "fixture", "test", "demo")
    )


def _git_revision(value: Any) -> bool:
    text = _text(value).lower()
    return 7 <= len(text) <= 64 and all(char in "0123456789abcdef" for char in text)


def _text(value: Any) -> str:
    return str(value or "").strip()


def _object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _require(condition: bool, code: str, failures: list[str]) -> None:
    if not condition and code not in failures:
        failures.append(code)
