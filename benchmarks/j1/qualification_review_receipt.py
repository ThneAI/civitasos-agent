"""Validate externally signed J1-D material review receipts."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey


REVIEW_RECEIPT_SCHEMA = "j1-qualification-material-review-receipt:v1"
ALLOWED_DECISIONS = {
    "approve_qualification_materials",
    "reject_qualification_materials",
    "defer_qualification_materials",
}
ALLOWED_SIGNERS = {"pkcs11_ed25519", "non_exportable_ed25519_callback"}
REQUIRED_CHECKS = {
    "answer_leakage_absent",
    "confidentiality_controls_reviewed",
    "prompt_quality_reviewed",
    "scenario_coverage_reviewed",
    "task_independence_reviewed",
    "verifier_logic_reviewed",
    "verifier_source_revision_verified",
}
FALSE_BOUNDARIES = {
    "agent_execution_allowed",
    "backend_fact_append_allowed",
    "ledger_append_allowed",
    "model_invocation_allowed",
    "protocol_freeze_automatic",
}
SECRET_TOKENS = {"seed", "private_key", "api_key", "passphrase", "pin"}
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
RECEIPT_FIELDS = {
    "schema_version",
    "review_id",
    "review_request_sha256",
    "reviewer",
    "decision",
    "reviewed_at",
    "independence",
    "review_scope",
    "checklist",
    "execution_boundary",
    "signature",
}
REVIEWER_FIELDS = {
    "did",
    "public_key_hex",
    "credential_version",
    "signer_kind",
    "custody_provenance_sha256",
    "signer_attestation_sha256",
}
REVIEW_SCOPE_FIELDS = {
    "corpus_artifact_sha256",
    "corpus_id",
    "corpus_tasks_sha256",
    "verifier_artifact_sha256",
    "verifier_id",
    "verifier_implementation_sha256",
    "verifier_manifest_sha256",
    "verifier_source_revision",
}
SIGNATURE_FIELDS = {"algorithm", "signed_payload_sha256", "signature_hex"}


def review_signature_payload(receipt: dict[str, Any]) -> bytes:
    body = {key: value for key, value in receipt.items() if key != "signature"}
    return json.dumps(
        body,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def build_review_scope(
    *,
    corpus: dict[str, Any],
    verifier: dict[str, Any],
    corpus_bytes: bytes,
    verifier_bytes: bytes,
    verifier_source_bytes: bytes,
) -> dict[str, Any]:
    return {
        "corpus_artifact_sha256": hashlib.sha256(corpus_bytes).hexdigest(),
        "corpus_id": corpus.get("corpus_id"),
        "corpus_tasks_sha256": corpus.get("tasks_sha256"),
        "verifier_artifact_sha256": hashlib.sha256(verifier_bytes).hexdigest(),
        "verifier_id": verifier.get("verifier_id"),
        "verifier_implementation_sha256": hashlib.sha256(
            verifier_source_bytes
        ).hexdigest(),
        "verifier_manifest_sha256": verifier.get("manifest_sha256"),
        "verifier_source_revision": verifier.get("source_revision"),
    }


def validate_review_receipt(
    receipt: Any,
    *,
    corpus: dict[str, Any],
    verifier: dict[str, Any],
    corpus_bytes: bytes,
    verifier_bytes: bytes,
    verifier_source_bytes: bytes,
) -> list[str]:
    failures = validate_signed_review_receipt(receipt)
    value = receipt if isinstance(receipt, dict) else {}
    _validate_scope_binding(
        _object(value.get("review_scope")),
        corpus=corpus,
        verifier=verifier,
        corpus_bytes=corpus_bytes,
        verifier_bytes=verifier_bytes,
        verifier_source_bytes=verifier_source_bytes,
        failures=failures,
    )
    return list(dict.fromkeys(failures))


def validate_signed_review_receipt(receipt: Any) -> list[str]:
    value = receipt if isinstance(receipt, dict) else {}
    failures: list[str] = []
    _require(set(value) == RECEIPT_FIELDS, "review_receipt_fields_invalid", failures)
    body = {key: item for key, item in value.items() if key != "signature"}
    failures.extend(validate_review_receipt_body(body))
    _validate_signature(value, failures)
    return list(dict.fromkeys(failures))


def validate_review_receipt_body(receipt: Any) -> list[str]:
    """Validate every receipt field except the detached signature."""
    failures: list[str] = []
    value = receipt if isinstance(receipt, dict) else {}
    _require(
        set(value) == RECEIPT_FIELDS - {"signature"},
        "review_receipt_body_fields_invalid",
        failures,
    )
    _require(
        value.get("schema_version") == REVIEW_RECEIPT_SCHEMA,
        "review_receipt_schema_invalid",
        failures,
    )
    _require(_real_text(value.get("review_id")), "review_id_invalid", failures)
    _require(
        _sha256(value.get("review_request_sha256")),
        "review_request_hash_invalid",
        failures,
    )
    _require(
        value.get("decision") in ALLOWED_DECISIONS, "review_decision_invalid", failures
    )
    _require(_rfc3339(value.get("reviewed_at")), "reviewed_at_invalid", failures)
    _require(
        not _contains_secret_key(value),
        "review_receipt_contains_secret_field",
        failures,
    )
    _validate_reviewer(_object(value.get("reviewer")), failures)
    _validate_independence(_object(value.get("independence")), failures)
    _validate_scope_shape(_object(value.get("review_scope")), failures)
    checklist = _object(value.get("checklist"))
    _require(
        set(checklist) == REQUIRED_CHECKS, "review_checklist_fields_invalid", failures
    )
    _require(
        bool(checklist) and all(item is True for item in checklist.values()),
        "review_checklist_incomplete",
        failures,
    )
    boundary = _object(value.get("execution_boundary"))
    _require(
        set(boundary) == FALSE_BOUNDARIES, "review_boundary_fields_invalid", failures
    )
    for field in FALSE_BOUNDARIES:
        _require(boundary.get(field) is False, f"{field}_must_be_false", failures)
    return list(dict.fromkeys(failures))


def _validate_reviewer(reviewer: dict[str, Any], failures: list[str]) -> None:
    _require(set(reviewer) == REVIEWER_FIELDS, "reviewer_fields_invalid", failures)
    did = _text(reviewer.get("did"))
    public_key = _text(reviewer.get("public_key_hex"))
    _require(
        _reviewer_did_matches_key(did, public_key),
        "reviewer_did_key_mismatch",
        failures,
    )
    _require(
        type(reviewer.get("credential_version")) is int
        and reviewer.get("credential_version") > 0,
        "reviewer_credential_version_invalid",
        failures,
    )
    _require(
        reviewer.get("signer_kind") in ALLOWED_SIGNERS,
        "reviewer_signer_kind_invalid",
        failures,
    )
    _require(
        _sha256(reviewer.get("custody_provenance_sha256")),
        "reviewer_custody_provenance_invalid",
        failures,
    )
    _require(
        _sha256(reviewer.get("signer_attestation_sha256")),
        "reviewer_signer_attestation_invalid",
        failures,
    )


def _validate_independence(value: dict[str, Any], failures: list[str]) -> None:
    _require(
        value.get("independent_from_authoring") is True,
        "independent_review_required",
        failures,
    )
    _require(
        value.get("conflicts_disclosed") is True,
        "review_conflict_disclosure_required",
        failures,
    )
    _require(
        value.get("ai_assisted_authoring_disclosed") is True,
        "ai_authoring_disclosure_required",
        failures,
    )


def _validate_scope_shape(scope: dict[str, Any], failures: list[str]) -> None:
    _require(set(scope) == REVIEW_SCOPE_FIELDS, "review_scope_fields_invalid", failures)
    for field in (
        "corpus_artifact_sha256",
        "corpus_tasks_sha256",
        "verifier_artifact_sha256",
        "verifier_implementation_sha256",
        "verifier_manifest_sha256",
    ):
        _require(_sha256(scope.get(field)), f"review_scope_{field}_invalid", failures)
    for field in ("corpus_id", "verifier_id"):
        _require(
            _real_text(scope.get(field)), f"review_scope_{field}_invalid", failures
        )
    _require(
        _git_revision(scope.get("verifier_source_revision")),
        "review_scope_verifier_source_revision_invalid",
        failures,
    )


def _validate_scope_binding(
    scope: dict[str, Any],
    *,
    corpus: dict[str, Any],
    verifier: dict[str, Any],
    corpus_bytes: bytes,
    verifier_bytes: bytes,
    verifier_source_bytes: bytes,
    failures: list[str],
) -> None:
    expected = build_review_scope(
        corpus=corpus,
        verifier=verifier,
        corpus_bytes=corpus_bytes,
        verifier_bytes=verifier_bytes,
        verifier_source_bytes=verifier_source_bytes,
    )
    _require(scope == expected, "review_scope_mismatch", failures)


def _validate_signature(receipt: dict[str, Any], failures: list[str]) -> None:
    signature = _object(receipt.get("signature"))
    _require(
        set(signature) == SIGNATURE_FIELDS, "review_signature_fields_invalid", failures
    )
    payload = review_signature_payload(receipt)
    _require(
        signature.get("algorithm") == "ed25519",
        "review_signature_algorithm_invalid",
        failures,
    )
    _require(
        signature.get("signed_payload_sha256") == hashlib.sha256(payload).hexdigest(),
        "review_signed_payload_hash_mismatch",
        failures,
    )
    public_key = _text(_object(receipt.get("reviewer")).get("public_key_hex"))
    signature_hex = _text(signature.get("signature_hex"))
    try:
        VerifyKey(bytes.fromhex(public_key)).verify(
            payload, bytes.fromhex(signature_hex)
        )
    except (BadSignatureError, ValueError):
        failures.append("review_signature_invalid")


def _reviewer_did_matches_key(did: str, public_key_hex: str) -> bool:
    parts = did.split(":")
    if len(parts) != 4 or parts[:2] != ["did", "civ"]:
        return False
    if parts[2] not in {"mainnet", "testnet"} or not parts[3].startswith("z"):
        return False
    try:
        public_key = bytes.fromhex(public_key_hex)
        payload = _base58_decode(parts[3][1:])
    except ValueError:
        return False
    return len(public_key) == 32 and payload == b"\xed\x01" + public_key


def _base58_decode(value: str) -> bytes:
    if not value or any(char not in BASE58_ALPHABET for char in value):
        raise ValueError("invalid base58")
    number = 0
    for char in value:
        number = number * 58 + BASE58_ALPHABET.index(char)
    decoded = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    return b"\x00" * (len(value) - len(value.lstrip("1"))) + decoded


def _contains_secret_key(value: Any) -> bool:
    if isinstance(value, dict):
        return any(
            any(token in str(key).lower() for token in SECRET_TOKENS)
            or _contains_secret_key(item)
            for key, item in value.items()
        )
    if isinstance(value, list):
        return any(_contains_secret_key(item) for item in value)
    return False


def _rfc3339(value: Any) -> bool:
    try:
        parsed = datetime.fromisoformat(_text(value).replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None


def _sha256(value: Any) -> bool:
    text = _text(value)
    return len(text) == 64 and all(char in "0123456789abcdef" for char in text)


def _git_revision(value: Any) -> bool:
    text = _text(value)
    return len(text) == 40 and all(char in "0123456789abcdef" for char in text)


def _real_text(value: Any) -> bool:
    text = _text(value).lower()
    return bool(text) and not any(
        token in text
        for token in (
            "synthetic",
            "fixture",
            "test",
            "demo",
            "devnet",
            "required",
            "placeholder",
        )
    )


def _text(value: Any) -> str:
    return str(value or "").strip()


def _object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _require(condition: bool, code: str, failures: list[str]) -> None:
    if not condition and code not in failures:
        failures.append(code)
