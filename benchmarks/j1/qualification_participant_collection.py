"""Protocol-bound collection templates for real J1-D participant Evidence."""

from __future__ import annotations

from typing import Any

from .qualification_participant_evidence import (
    EVIDENCE_SCHEMAS,
    PACKET_SCHEMA,
)
from .qualification_roster import ALLOWED_SIGNERS


COLLECTION_SCHEMA = "j1-qualification-participant-collection:v1"
TEMPLATE_MARKER = {
    "template_only": True,
    "valid_participant_evidence": False,
    "required_action": "replace_placeholders_and_remove_template_marker",
}
TEMPLATE_FILENAMES = {
    "participant_packet": "participant-packet.template.json",
    "cognitive_baseline": "cognitive-baseline.template.json",
    "identity_snapshot": "identity-snapshot.template.json",
    "custody_provenance": "custody-provenance.template.json",
    "isolation_root": "isolation-root.template.json",
    "consent_receipt": "consent-receipt.template.json",
}


def build_collection_templates(
    *, qualification_protocol_sha256: str, stack: dict[str, str]
) -> dict[str, dict[str, Any]]:
    common = {
        "_template": TEMPLATE_MARKER,
        "qualification_protocol_sha256": qualification_protocol_sha256,
        "attested_at": "TODO_REPLACE_RFC3339_TIMESTAMP",
        "public_only": False,
        "secret_material_included": False,
        "operator_attestation_sha256": "",
    }
    templates = {
        "cognitive_baseline": {
            "schema_version": EVIDENCE_SCHEMAS["cognitive_baseline"],
            **common,
            "pair_id": "TODO_REPLACE_REAL_PAIR_ID",
            "baseline_commitment_sha256": "",
            "assessment_method": "TODO_REPLACE_REAL_ASSESSMENT_METHOD",
        },
        "identity_snapshot": {
            "schema_version": EVIDENCE_SCHEMAS["identity_snapshot"],
            **common,
            "participant_id": "TODO_REPLACE_REAL_PARTICIPANT_ID",
            "execution_did": "TODO_REPLACE_REAL_DID_CIV",
            "credential_version": 0,
            "signer_kind": "TODO_REPLACE_ALLOWED_SIGNER_KIND",
            "public_key_sha256": "",
            "identity_state_sha256": "",
        },
        "custody_provenance": {
            "schema_version": EVIDENCE_SCHEMAS["custody_provenance"],
            **common,
            "participant_id": "TODO_REPLACE_REAL_PARTICIPANT_ID",
            "execution_did": "TODO_REPLACE_REAL_DID_CIV",
            "signer_kind": "TODO_REPLACE_ALLOWED_SIGNER_KIND",
            "non_exportable": False,
            "key_reference_sha256": "",
        },
        "isolation_root": {
            "schema_version": EVIDENCE_SCHEMAS["isolation_root"],
            **common,
            "participant_id": "TODO_REPLACE_REAL_PARTICIPANT_ID",
            "execution_did": "TODO_REPLACE_REAL_DID_CIV",
            "isolation_id": "TODO_REPLACE_REAL_ISOLATION_ID",
            "isolation_commitment_sha256": "",
            "exclusive_assignment": False,
        },
        "consent_receipt": {
            "schema_version": EVIDENCE_SCHEMAS["consent_receipt"],
            **common,
            "participant_id": "TODO_REPLACE_REAL_PARTICIPANT_ID",
            "execution_did": "TODO_REPLACE_REAL_DID_CIV",
            "random_assignment_consented": False,
            "model_execution_authorized": False,
            "consent_statement_sha256": "",
        },
    }
    templates["participant_packet"] = {
        "_template": TEMPLATE_MARKER,
        "schema_version": PACKET_SCHEMA,
        "participant_id": "TODO_REPLACE_REAL_PARTICIPANT_ID",
        "pair_id": "TODO_REPLACE_REAL_PAIR_ID",
        "execution_did": "TODO_REPLACE_REAL_DID_CIV",
        "credential_version": 0,
        "signer_kind": "TODO_REPLACE_ALLOWED_SIGNER_KIND",
        "prior_mentorship_exposure": None,
        "random_assignment_consented": False,
        "model_execution_authorized": False,
        "stack": stack,
        "evidence": {
            kind: {
                "path": f"TODO_REPLACE_RELATIVE_{kind.upper()}_PATH.json",
                "sha256": "",
            }
            for kind in EVIDENCE_SCHEMAS
        },
        "packet_sha256": "",
    }
    return templates


def collection_slots() -> list[dict[str, Any]]:
    return [
        {
            "pair_slot": index,
            "status": "awaiting_two_real_participants_and_shared_baseline",
            "participant_slots": [
                {"member_slot": member, "status": "awaiting_real_participant_evidence"}
                for member in ("a", "b")
            ],
        }
        for index in range(1, 21)
    ]


def collection_policy() -> dict[str, Any]:
    return {
        "required_participants": 40,
        "required_pairs": 20,
        "required_evidence_kinds": list(EVIDENCE_SCHEMAS),
        "allowed_signer_kinds": sorted(ALLOWED_SIGNERS),
        "templates_are_evidence": False,
        "identity_generation_allowed": False,
        "automatic_matching_allowed": False,
        "secret_material_allowed": False,
        "independent_operator_review_required": True,
    }
