"""Prepare J1-D review requests and sign explicit operator decisions."""

from __future__ import annotations

import copy
import hashlib
from datetime import datetime
from typing import Any, Protocol

from .controlled_comparison import canonical_sha256
from .qualification_material_review import validate_candidate_materials
from .qualification_review_receipt import (
    ALLOWED_DECISIONS,
    FALSE_BOUNDARIES,
    REQUIRED_CHECKS,
    REVIEW_RECEIPT_SCHEMA,
    build_review_scope,
    review_signature_payload,
    validate_review_receipt_body,
    validate_review_receipt,
)


REVIEW_REQUEST_SCHEMA = "j1-qualification-material-review-request:v1"
REVIEW_DECISION_SCHEMA = "j1-qualification-material-review-decision:v1"
REQUEST_FIELDS = {
    "schema_version",
    "request_id",
    "status",
    "created_at",
    "candidate_artifacts",
    "review_scope",
    "required_checklist",
    "allowed_decisions",
    "signer_contract",
    "confidentiality",
    "execution_boundary",
    "request_sha256",
}
DECISION_FIELDS = {
    "schema_version",
    "review_id",
    "review_request_sha256",
    "decision",
    "reviewed_at",
    "reviewer",
    "independence",
    "checklist",
}
REQUEST_STATUS = "awaiting_independent_operator_decision"
SIGNER_CONTRACT = {
    "algorithm": "ed25519",
    "allowed_signer_kinds": [
        "non_exportable_ed25519_callback",
        "pkcs11_ed25519",
    ],
    "reviewer_did_networks": ["mainnet", "testnet"],
    "credential_version_required": True,
    "custody_provenance_required": True,
    "signer_attestation_required": True,
}
CONFIDENTIALITY_CONTRACT = {
    "source_content_recorded": False,
    "candidate_files_must_remain_private": True,
    "request_file_must_be_private": True,
}
EXECUTION_BOUNDARY = {field: False for field in sorted(FALSE_BOUNDARIES)}


class ReviewSigner(Protocol):
    @property
    def public_key_hex(self) -> str: ...

    def sign(self, message: bytes) -> bytes: ...


def build_review_request(
    *,
    request_id: str,
    created_at: str,
    corpus_path: str,
    verifier_path: str,
    verifier_source_path: str,
    corpus: dict[str, Any],
    verifier: dict[str, Any],
    corpus_bytes: bytes,
    verifier_bytes: bytes,
    verifier_source_bytes: bytes,
) -> dict[str, Any]:
    failures = validate_candidate_materials(
        corpus,
        verifier,
        verifier_source_bytes=verifier_source_bytes,
    )
    if failures:
        raise ValueError(f"review candidate invalid: {failures}")
    request = {
        "schema_version": REVIEW_REQUEST_SCHEMA,
        "request_id": request_id,
        "status": REQUEST_STATUS,
        "created_at": created_at,
        "candidate_artifacts": {
            "corpus": _artifact(corpus_path, corpus_bytes),
            "verifier": _artifact(verifier_path, verifier_bytes),
            "verifier_source": _artifact(verifier_source_path, verifier_source_bytes),
        },
        "review_scope": build_review_scope(
            corpus=corpus,
            verifier=verifier,
            corpus_bytes=corpus_bytes,
            verifier_bytes=verifier_bytes,
            verifier_source_bytes=verifier_source_bytes,
        ),
        "required_checklist": sorted(REQUIRED_CHECKS),
        "allowed_decisions": sorted(ALLOWED_DECISIONS),
        "signer_contract": copy.deepcopy(SIGNER_CONTRACT),
        "confidentiality": copy.deepcopy(CONFIDENTIALITY_CONTRACT),
        "execution_boundary": copy.deepcopy(EXECUTION_BOUNDARY),
    }
    request["request_sha256"] = canonical_sha256(request)
    failures = validate_review_request(
        request,
        corpus=corpus,
        verifier=verifier,
        corpus_bytes=corpus_bytes,
        verifier_bytes=verifier_bytes,
        verifier_source_bytes=verifier_source_bytes,
    )
    if failures:
        raise ValueError(f"review request invalid: {failures}")
    return request


def validate_review_request(
    request: Any,
    *,
    corpus: dict[str, Any],
    verifier: dict[str, Any],
    corpus_bytes: bytes,
    verifier_bytes: bytes,
    verifier_source_bytes: bytes,
) -> list[str]:
    failures: list[str] = []
    value = request if isinstance(request, dict) else {}
    _require(set(value) == REQUEST_FIELDS, "review_request_fields_invalid", failures)
    _require(
        value.get("schema_version") == REVIEW_REQUEST_SCHEMA,
        "review_request_schema_invalid",
        failures,
    )
    _require(
        value.get("status") == REQUEST_STATUS,
        "review_request_status_invalid",
        failures,
    )
    _require(_real_text(value.get("request_id")), "review_request_id_invalid", failures)
    _require(
        _rfc3339(value.get("created_at")), "review_request_created_at_invalid", failures
    )
    _require(
        value.get("required_checklist") == sorted(REQUIRED_CHECKS),
        "review_request_checklist_invalid",
        failures,
    )
    _require(
        value.get("allowed_decisions") == sorted(ALLOWED_DECISIONS),
        "review_request_decisions_invalid",
        failures,
    )
    _require(
        value.get("signer_contract") == SIGNER_CONTRACT,
        "review_request_signer_contract_invalid",
        failures,
    )
    _require(
        value.get("confidentiality") == CONFIDENTIALITY_CONTRACT,
        "review_request_confidentiality_invalid",
        failures,
    )
    _require(
        value.get("execution_boundary") == EXECUTION_BOUNDARY,
        "review_request_boundary_invalid",
        failures,
    )
    candidate_failures = validate_candidate_materials(
        corpus,
        verifier,
        verifier_source_bytes=verifier_source_bytes,
    )
    failures.extend(candidate_failures)
    expected_scope = build_review_scope(
        corpus=corpus,
        verifier=verifier,
        corpus_bytes=corpus_bytes,
        verifier_bytes=verifier_bytes,
        verifier_source_bytes=verifier_source_bytes,
    )
    _require(
        value.get("review_scope") == expected_scope,
        "review_request_scope_mismatch",
        failures,
    )
    artifacts = value.get("candidate_artifacts")
    artifact_values = artifacts if isinstance(artifacts, dict) else {}
    _require(
        set(artifact_values) == {"corpus", "verifier", "verifier_source"},
        "review_request_artifacts_invalid",
        failures,
    )
    expected_hashes = {
        "corpus": hashlib.sha256(corpus_bytes).hexdigest(),
        "verifier": hashlib.sha256(verifier_bytes).hexdigest(),
        "verifier_source": hashlib.sha256(verifier_source_bytes).hexdigest(),
    }
    for name, digest in expected_hashes.items():
        artifact = artifact_values.get(name)
        artifact_value = artifact if isinstance(artifact, dict) else {}
        _require(
            set(artifact_value) == {"path", "sha256"},
            f"review_request_{name}_fields_invalid",
            failures,
        )
        _require(
            bool(str(artifact_value.get("path") or "").strip()),
            f"review_request_{name}_path_invalid",
            failures,
        )
        _require(
            artifact_value.get("sha256") == digest,
            f"review_request_{name}_hash_mismatch",
            failures,
        )
    body = {key: item for key, item in value.items() if key != "request_sha256"}
    _require(
        value.get("request_sha256") == canonical_sha256(body),
        "review_request_hash_mismatch",
        failures,
    )
    return list(dict.fromkeys(failures))


def sign_review_decision(
    *,
    request: dict[str, Any],
    decision: dict[str, Any],
    signer: ReviewSigner,
    corpus: dict[str, Any],
    verifier: dict[str, Any],
    corpus_bytes: bytes,
    verifier_bytes: bytes,
    verifier_source_bytes: bytes,
) -> dict[str, Any]:
    request_failures = validate_review_request(
        request,
        corpus=corpus,
        verifier=verifier,
        corpus_bytes=corpus_bytes,
        verifier_bytes=verifier_bytes,
        verifier_source_bytes=verifier_source_bytes,
    )
    if request_failures:
        raise ValueError(f"review request invalid: {request_failures}")
    decision_failures = validate_review_decision(decision, request=request)
    if decision_failures:
        raise ValueError(f"review decision invalid: {decision_failures}")
    receipt_body = build_review_receipt_body(request, decision)
    reviewer = receipt_body["reviewer"]
    if signer.public_key_hex.lower() != str(reviewer["public_key_hex"]).lower():
        raise ValueError("review signer public key does not match decision reviewer")
    payload = review_signature_payload(receipt_body)
    signature = signer.sign(payload)
    return assemble_review_receipt(
        request=request,
        decision=decision,
        signature=signature,
        corpus=corpus,
        verifier=verifier,
        corpus_bytes=corpus_bytes,
        verifier_bytes=verifier_bytes,
        verifier_source_bytes=verifier_source_bytes,
    )


def assemble_review_receipt(
    *,
    request: dict[str, Any],
    decision: dict[str, Any],
    signature: bytes,
    corpus: dict[str, Any],
    verifier: dict[str, Any],
    corpus_bytes: bytes,
    verifier_bytes: bytes,
    verifier_source_bytes: bytes,
) -> dict[str, Any]:
    request_failures = validate_review_request(
        request,
        corpus=corpus,
        verifier=verifier,
        corpus_bytes=corpus_bytes,
        verifier_bytes=verifier_bytes,
        verifier_source_bytes=verifier_source_bytes,
    )
    if request_failures:
        raise ValueError(f"review request invalid: {request_failures}")
    decision_failures = validate_review_decision(decision, request=request)
    if decision_failures:
        raise ValueError(f"review decision invalid: {decision_failures}")
    if not isinstance(signature, bytes) or len(signature) != 64:
        raise ValueError("review signature must be 64-byte Ed25519 signature")
    receipt = build_review_receipt_body(request, decision)
    payload = review_signature_payload(receipt)
    receipt["signature"] = {
        "algorithm": "ed25519",
        "signed_payload_sha256": hashlib.sha256(payload).hexdigest(),
        "signature_hex": signature.hex(),
    }
    failures = validate_review_receipt(
        receipt,
        corpus=corpus,
        verifier=verifier,
        corpus_bytes=corpus_bytes,
        verifier_bytes=verifier_bytes,
        verifier_source_bytes=verifier_source_bytes,
    )
    if failures:
        raise ValueError(f"signed review receipt invalid: {failures}")
    return receipt


def validate_review_decision(decision: Any, *, request: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    value = decision if isinstance(decision, dict) else {}
    _require(set(value) == DECISION_FIELDS, "review_decision_fields_invalid", failures)
    _require(
        value.get("schema_version") == REVIEW_DECISION_SCHEMA,
        "review_decision_schema_invalid",
        failures,
    )
    _require(
        value.get("review_request_sha256") == request.get("request_sha256"),
        "review_decision_request_hash_mismatch",
        failures,
    )
    _require(
        value.get("decision") in ALLOWED_DECISIONS,
        "review_decision_value_invalid",
        failures,
    )
    if not failures:
        failures.extend(
            validate_review_receipt_body(build_review_receipt_body(request, value))
        )
    return list(dict.fromkeys(failures))


def build_review_receipt_body(
    request: dict[str, Any], decision: dict[str, Any]
) -> dict[str, Any]:
    return {
        "schema_version": REVIEW_RECEIPT_SCHEMA,
        "review_id": decision.get("review_id"),
        "review_request_sha256": request.get("request_sha256"),
        "reviewer": copy.deepcopy(decision.get("reviewer")),
        "decision": decision.get("decision"),
        "reviewed_at": decision.get("reviewed_at"),
        "independence": copy.deepcopy(decision.get("independence")),
        "review_scope": copy.deepcopy(request.get("review_scope")),
        "checklist": copy.deepcopy(decision.get("checklist")),
        "execution_boundary": copy.deepcopy(EXECUTION_BOUNDARY),
    }


def _artifact(path: str, content: bytes) -> dict[str, str]:
    return {
        "path": path,
        "sha256": hashlib.sha256(content).hexdigest(),
    }


def _rfc3339(value: Any) -> bool:
    try:
        parsed = datetime.fromisoformat(str(value or "").strip().replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None


def _real_text(value: Any) -> bool:
    text = str(value or "").strip().lower()
    return bool(text) and not any(
        token in text for token in ("synthetic", "fixture", "test", "demo", "devnet")
    )


def _require(condition: bool, code: str, failures: list[str]) -> None:
    if not condition and code not in failures:
        failures.append(code)
