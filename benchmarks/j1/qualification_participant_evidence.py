"""Public-only participant Evidence contracts for J1-D qualification."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from .controlled_comparison import canonical_sha256
from .qualification_roster import contains_secret_field, validate_roster_entry


PACKET_SCHEMA = "j1-qualification-participant-evidence:v1"
EVIDENCE_SCHEMAS = {
    "cognitive_baseline": "j1-qualification-cognitive-baseline:v1",
    "identity_snapshot": "j1-qualification-identity-snapshot:v1",
    "custody_provenance": "j1-qualification-custody-provenance:v1",
    "isolation_root": "j1-qualification-isolation-root:v1",
    "consent_receipt": "j1-qualification-consent-receipt:v1",
}
PACKET_FIELDS = {
    "schema_version",
    "participant_id",
    "pair_id",
    "execution_did",
    "credential_version",
    "signer_kind",
    "prior_mentorship_exposure",
    "random_assignment_consented",
    "model_execution_authorized",
    "stack",
    "evidence",
    "packet_sha256",
}
STACK_FIELDS = {"provider_id", "model_id", "budget_id", "corpus_id", "verifier_id"}
REF_FIELDS = {"path", "sha256"}
COMMON_ARTIFACT_FIELDS = {
    "schema_version",
    "qualification_protocol_sha256",
    "attested_at",
    "public_only",
    "secret_material_included",
}
ARTIFACT_FIELDS = {
    "cognitive_baseline": COMMON_ARTIFACT_FIELDS
    | {
        "pair_id",
        "baseline_commitment_sha256",
        "assessment_method",
        "operator_attestation_sha256",
    },
    "identity_snapshot": COMMON_ARTIFACT_FIELDS
    | {
        "participant_id",
        "execution_did",
        "credential_version",
        "signer_kind",
        "public_key_sha256",
        "identity_state_sha256",
        "operator_attestation_sha256",
    },
    "custody_provenance": COMMON_ARTIFACT_FIELDS
    | {
        "participant_id",
        "execution_did",
        "signer_kind",
        "non_exportable",
        "key_reference_sha256",
        "operator_attestation_sha256",
    },
    "isolation_root": COMMON_ARTIFACT_FIELDS
    | {
        "participant_id",
        "execution_did",
        "isolation_id",
        "isolation_commitment_sha256",
        "exclusive_assignment",
        "operator_attestation_sha256",
    },
    "consent_receipt": COMMON_ARTIFACT_FIELDS
    | {
        "participant_id",
        "execution_did",
        "random_assignment_consented",
        "model_execution_authorized",
        "consent_statement_sha256",
        "operator_attestation_sha256",
    },
}


def validate_participant_packet(
    value: Any,
    *,
    expected_stack: dict[str, str],
    qualification_protocol_sha256: str,
) -> list[str]:
    packet = value if isinstance(value, dict) else {}
    failures: list[str] = []
    _require(
        set(packet) == PACKET_FIELDS, "participant_packet_fields_invalid", failures
    )
    _require(
        packet.get("schema_version") == PACKET_SCHEMA,
        "participant_packet_schema_invalid",
        failures,
    )
    stack = _object(packet.get("stack"))
    _require(
        set(stack) == STACK_FIELDS, "participant_packet_stack_fields_invalid", failures
    )
    for field, expected in expected_stack.items():
        _require(
            stack.get(field) == expected,
            f"participant_packet_{field}_mismatch",
            failures,
        )
    evidence = _object(packet.get("evidence"))
    _require(
        set(evidence) == set(EVIDENCE_SCHEMAS),
        "participant_packet_evidence_fields_invalid",
        failures,
    )
    for kind in EVIDENCE_SCHEMAS:
        reference = _object(evidence.get(kind))
        _require(
            set(reference) == REF_FIELDS,
            f"participant_{kind}_reference_fields_invalid",
            failures,
        )
        _require(
            _relative_json_path(reference.get("path")),
            f"participant_{kind}_path_invalid",
            failures,
        )
        _require(
            _sha256(reference.get("sha256")),
            f"participant_{kind}_hash_invalid",
            failures,
        )
    entry = roster_entry_from_packet(packet, evidence_hashes={})
    failures.extend(validate_roster_entry(entry, expected_stack))
    _require(
        packet.get("packet_sha256")
        == canonical_sha256(
            {key: item for key, item in packet.items() if key != "packet_sha256"}
        ),
        "participant_packet_hash_mismatch",
        failures,
    )
    _require(
        not contains_secret_field(packet),
        "participant_packet_contains_secret_field",
        failures,
    )
    _require(
        _sha256(qualification_protocol_sha256),
        "qualification_protocol_hash_invalid",
        failures,
    )
    return list(dict.fromkeys(failures))


def validate_evidence_artifact(
    kind: str,
    value: Any,
    *,
    packet: dict[str, Any],
    qualification_protocol_sha256: str,
) -> list[str]:
    artifact = value if isinstance(value, dict) else {}
    failures: list[str] = []
    expected_schema = EVIDENCE_SCHEMAS.get(kind)
    _require(expected_schema is not None, "participant_evidence_kind_invalid", failures)
    _require(
        set(artifact) == ARTIFACT_FIELDS.get(kind, set()),
        f"participant_{kind}_artifact_fields_invalid",
        failures,
    )
    _require(
        artifact.get("schema_version") == expected_schema,
        f"participant_{kind}_artifact_schema_invalid",
        failures,
    )
    _require(
        artifact.get("qualification_protocol_sha256") == qualification_protocol_sha256,
        f"participant_{kind}_protocol_hash_mismatch",
        failures,
    )
    _require(
        _rfc3339(artifact.get("attested_at")),
        f"participant_{kind}_attested_at_invalid",
        failures,
    )
    _require(
        artifact.get("public_only") is True,
        f"participant_{kind}_must_be_public_only",
        failures,
    )
    _require(
        artifact.get("secret_material_included") is False,
        f"participant_{kind}_secret_material_forbidden",
        failures,
    )
    _require(
        not contains_secret_field(artifact),
        f"participant_{kind}_contains_secret_field",
        failures,
    )
    if kind == "cognitive_baseline":
        _validate_baseline(artifact, packet, failures)
    elif kind == "identity_snapshot":
        _validate_identity(artifact, packet, failures)
    elif kind == "custody_provenance":
        _validate_custody(artifact, packet, failures)
    elif kind == "isolation_root":
        _validate_isolation(artifact, packet, failures)
    elif kind == "consent_receipt":
        _validate_consent(artifact, packet, failures)
    return list(dict.fromkeys(failures))


def roster_entry_from_packet(
    packet: dict[str, Any], *, evidence_hashes: dict[str, str]
) -> dict[str, Any]:
    stack = _object(packet.get("stack"))
    evidence = _object(packet.get("evidence"))

    def evidence_hash(kind: str) -> Any:
        return evidence_hashes.get(kind) or _object(evidence.get(kind)).get("sha256")

    return {
        "participant_id": packet.get("participant_id"),
        "pair_id": packet.get("pair_id"),
        "execution_did": packet.get("execution_did"),
        "cognitive_baseline_sha256": evidence_hash("cognitive_baseline"),
        "identity_snapshot_sha256": evidence_hash("identity_snapshot"),
        "credential_version": packet.get("credential_version"),
        "signer_kind": packet.get("signer_kind"),
        "custody_provenance_sha256": evidence_hash("custody_provenance"),
        "isolation_root_sha256": evidence_hash("isolation_root"),
        "consent_receipt_sha256": evidence_hash("consent_receipt"),
        "prior_mentorship_exposure": packet.get("prior_mentorship_exposure"),
        "random_assignment_consented": packet.get("random_assignment_consented"),
        "model_execution_authorized": packet.get("model_execution_authorized"),
        **{field: stack.get(field) for field in sorted(STACK_FIELDS)},
    }


def _validate_baseline(
    artifact: dict[str, Any], packet: dict[str, Any], failures: list[str]
) -> None:
    _require(
        artifact.get("pair_id") == packet.get("pair_id"),
        "participant_baseline_pair_mismatch",
        failures,
    )
    _require_hash_fields(
        artifact,
        ("baseline_commitment_sha256", "operator_attestation_sha256"),
        "participant_baseline",
        failures,
    )
    _require(
        _real_text(artifact.get("assessment_method")),
        "participant_baseline_assessment_method_invalid",
        failures,
    )


def _validate_identity(
    artifact: dict[str, Any], packet: dict[str, Any], failures: list[str]
) -> None:
    _require_participant_binding(artifact, packet, "identity", failures)
    _require(
        artifact.get("credential_version") == packet.get("credential_version"),
        "participant_identity_credential_version_mismatch",
        failures,
    )
    _require(
        artifact.get("signer_kind") == packet.get("signer_kind"),
        "participant_identity_signer_kind_mismatch",
        failures,
    )
    _require_hash_fields(
        artifact,
        (
            "public_key_sha256",
            "identity_state_sha256",
            "operator_attestation_sha256",
        ),
        "participant_identity",
        failures,
    )


def _validate_custody(
    artifact: dict[str, Any], packet: dict[str, Any], failures: list[str]
) -> None:
    _require_participant_binding(artifact, packet, "custody", failures)
    _require(
        artifact.get("signer_kind") == packet.get("signer_kind"),
        "participant_custody_signer_kind_mismatch",
        failures,
    )
    _require(
        artifact.get("non_exportable") is True,
        "participant_custody_must_be_non_exportable",
        failures,
    )
    _require_hash_fields(
        artifact,
        ("key_reference_sha256", "operator_attestation_sha256"),
        "participant_custody",
        failures,
    )


def _validate_isolation(
    artifact: dict[str, Any], packet: dict[str, Any], failures: list[str]
) -> None:
    _require_participant_binding(artifact, packet, "isolation", failures)
    _require(
        _real_text(artifact.get("isolation_id")),
        "participant_isolation_id_invalid",
        failures,
    )
    _require(
        artifact.get("exclusive_assignment") is True,
        "participant_isolation_must_be_exclusive",
        failures,
    )
    _require_hash_fields(
        artifact,
        ("isolation_commitment_sha256", "operator_attestation_sha256"),
        "participant_isolation",
        failures,
    )


def _validate_consent(
    artifact: dict[str, Any], packet: dict[str, Any], failures: list[str]
) -> None:
    _require_participant_binding(artifact, packet, "consent", failures)
    _require(
        artifact.get("random_assignment_consented") is True,
        "participant_random_assignment_consent_missing",
        failures,
    )
    _require(
        artifact.get("model_execution_authorized") is False,
        "participant_model_execution_must_be_false",
        failures,
    )
    _require_hash_fields(
        artifact,
        ("consent_statement_sha256", "operator_attestation_sha256"),
        "participant_consent",
        failures,
    )


def _require_participant_binding(
    artifact: dict[str, Any],
    packet: dict[str, Any],
    label: str,
    failures: list[str],
) -> None:
    for field in ("participant_id", "execution_did"):
        _require(
            artifact.get(field) == packet.get(field),
            f"participant_{label}_{field}_mismatch",
            failures,
        )


def _require_hash_fields(
    value: dict[str, Any],
    fields: tuple[str, ...],
    label: str,
    failures: list[str],
) -> None:
    for field in fields:
        _require(_sha256(value.get(field)), f"{label}_{field}_invalid", failures)


def _relative_json_path(value: Any) -> bool:
    text = str(value or "").strip()
    if not text:
        return False
    path = Path(text)
    return not path.is_absolute() and ".." not in path.parts and path.suffix == ".json"


def _rfc3339(value: Any) -> bool:
    try:
        parsed = datetime.fromisoformat(str(value or "").replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None


def _real_text(value: Any) -> bool:
    text = str(value or "").strip().lower()
    return bool(text) and not any(
        token in text for token in ("synthetic", "fixture", "test", "demo")
    )


def _sha256(value: Any) -> bool:
    text = str(value or "")
    return len(text) == 64 and all(char in "0123456789abcdef" for char in text)


def _object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _require(condition: bool, code: str, failures: list[str]) -> None:
    if not condition and code not in failures:
        failures.append(code)
