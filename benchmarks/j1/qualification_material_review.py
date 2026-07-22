"""Validate J1-D material candidates and create reviewed immutable copies."""

from __future__ import annotations

import copy
import hashlib
import json
from typing import Any

from .controlled_comparison import canonical_sha256
from .qualification_materials import TASK_SOURCE_SCHEMA, validate_task_source
from .qualification_protocol_freeze import CORPUS_SCHEMA, VERIFIER_SCHEMA
from .qualification_verifier import (
    CASE_IDS,
    validate_verifier_manifest,
)


REVIEW_GATE_SCHEMA = "j1-qualification-material-review-gate:v1"


def validate_candidate_materials(
    corpus: Any,
    verifier: Any,
    *,
    verifier_source_bytes: bytes,
) -> list[str]:
    failures: list[str] = []
    corpus_value = corpus if isinstance(corpus, dict) else {}
    verifier_value = verifier if isinstance(verifier, dict) else {}
    _validate_corpus(corpus_value, failures)
    _validate_verifier(
        verifier_value,
        verifier_source_bytes=verifier_source_bytes,
        failures=failures,
    )
    return list(dict.fromkeys(failures))


def promote_reviewed_materials(
    *,
    corpus: dict[str, Any],
    verifier: dict[str, Any],
    review_receipt_bytes: bytes,
) -> tuple[dict[str, Any], dict[str, Any]]:
    receipt = json.loads(review_receipt_bytes)
    review = {
        "review_id": receipt["review_id"],
        "review_request_sha256": receipt["review_request_sha256"],
        "reviewer_did": receipt["reviewer"]["did"],
        "reviewer_credential_version": receipt["reviewer"]["credential_version"],
        "signer_kind": receipt["reviewer"]["signer_kind"],
        "custody_provenance_sha256": receipt["reviewer"]["custody_provenance_sha256"],
        "signer_attestation_sha256": receipt["reviewer"]["signer_attestation_sha256"],
        "decision": receipt["decision"],
        "reviewed_at": receipt["reviewed_at"],
        "conflicts_disclosed": receipt["independence"]["conflicts_disclosed"],
        "independent_from_authoring": receipt["independence"][
            "independent_from_authoring"
        ],
        "review_receipt_sha256": hashlib.sha256(review_receipt_bytes).hexdigest(),
        "review_scope": copy.deepcopy(receipt["review_scope"]),
    }
    reviewed_corpus = copy.deepcopy(corpus)
    reviewed_corpus["status"] = "operator_reviewed"
    reviewed_corpus["operator_review"] = review
    reviewed_verifier = copy.deepcopy(verifier)
    reviewed_verifier["status"] = "operator_reviewed"
    reviewed_verifier["operator_review"] = review
    reviewed_verifier.pop("manifest_sha256", None)
    reviewed_verifier["manifest_sha256"] = canonical_sha256(reviewed_verifier)
    return reviewed_corpus, reviewed_verifier


def _validate_corpus(corpus: dict[str, Any], failures: list[str]) -> None:
    _require(
        corpus.get("schema_version") == CORPUS_SCHEMA,
        "review_candidate_corpus_schema_invalid",
        failures,
    )
    _require(
        corpus.get("status") == "review_required",
        "review_candidate_corpus_status_invalid",
        failures,
    )
    _require(
        corpus.get("synthetic") is False,
        "review_candidate_corpus_synthetic",
        failures,
    )
    _require(
        corpus.get("confidential") is True,
        "review_candidate_corpus_not_confidential",
        failures,
    )
    tasks = corpus.get("tasks")
    task_values = tasks if isinstance(tasks, list) else []
    failures.extend(
        validate_task_source(
            {
                "schema_version": TASK_SOURCE_SCHEMA,
                "corpus_id": corpus.get("corpus_id"),
                "tasks": task_values,
            }
        )
    )
    _require(
        corpus.get("tasks_sha256") == canonical_sha256(task_values),
        "review_candidate_tasks_hash_mismatch",
        failures,
    )


def _validate_verifier(
    verifier: dict[str, Any],
    *,
    verifier_source_bytes: bytes,
    failures: list[str],
) -> None:
    failures.extend(
        validate_verifier_manifest(
            verifier,
            expected_status="review_required",
            expected_implementation_sha256=hashlib.sha256(
                verifier_source_bytes
            ).hexdigest(),
        )
    )
    _require(
        verifier.get("schema_version") == VERIFIER_SCHEMA,
        "review_candidate_verifier_schema_invalid",
        failures,
    )
    _require(
        verifier.get("status") == "review_required",
        "review_candidate_verifier_status_invalid",
        failures,
    )
    _require(
        _real_text(verifier.get("verifier_id")),
        "review_candidate_verifier_id_invalid",
        failures,
    )
    _require(
        _git_revision(verifier.get("source_revision")),
        "review_candidate_source_revision_invalid",
        failures,
    )
    _require(
        verifier.get("deterministic") is True,
        "review_candidate_verifier_not_deterministic",
        failures,
    )
    _require(
        verifier.get("model_judge_allowed") is False,
        "review_candidate_model_judge_allowed",
        failures,
    )
    _require(
        verifier.get("operator_override_allowed") is False,
        "review_candidate_override_allowed",
        failures,
    )
    implementation_sha256 = hashlib.sha256(verifier_source_bytes).hexdigest()
    cases = verifier.get("cases")
    case_values = cases if isinstance(cases, list) else []
    case_ids = {
        _text(item.get("case_id")) for item in case_values if isinstance(item, dict)
    }
    _require(case_ids == CASE_IDS, "review_candidate_verifier_cases_invalid", failures)
    _require(
        bool(case_values)
        and all(
            isinstance(item, dict)
            and item.get("implementation_sha256") == implementation_sha256
            for item in case_values
        ),
        "review_candidate_verifier_source_hash_mismatch",
        failures,
    )
    body = {key: value for key, value in verifier.items() if key != "manifest_sha256"}
    _require(
        verifier.get("manifest_sha256") == canonical_sha256(body),
        "review_candidate_verifier_manifest_hash_mismatch",
        failures,
    )


def _git_revision(value: Any) -> bool:
    text = _text(value)
    return len(text) == 40 and all(char in "0123456789abcdef" for char in text)


def _real_text(value: Any) -> bool:
    text = _text(value).lower()
    return bool(text) and not any(
        token in text for token in ("synthetic", "fixture", "test", "demo", "devnet")
    )


def _text(value: Any) -> str:
    return str(value or "").strip()


def _require(condition: bool, code: str, failures: list[str]) -> None:
    if not condition and code not in failures:
        failures.append(code)
