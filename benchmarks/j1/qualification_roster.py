"""Public-only qualification roster validation for J1-D."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from typing import Any

from .controlled_comparison import canonical_sha256


ROSTER_SCHEMA = "j1-qualification-roster:v1"
QUALIFICATION_PROTOCOL_SCHEMA = "j1-qualification-protocol:v1"
ALLOWED_SIGNERS = {"pkcs11", "webauthn", "non_exportable_callback"}
FORBIDDEN_ID_TOKENS = {"synthetic", "fixture", "test", "demo", "devnet"}
SECRET_KEY_TOKENS = {"seed", "private_key", "api_key", "token", "passphrase", "pin"}


def validate_roster(
    value: Any,
    *,
    admission_request_sha256: str,
    qualification_protocol_sha256: str,
    expected_stack: dict[str, str],
) -> list[str]:
    failures: list[str] = []
    roster = value if isinstance(value, dict) else {}
    _require(
        roster.get("schema_version") == ROSTER_SCHEMA, "roster_schema_invalid", failures
    )
    _require(_text(roster.get("roster_id")), "roster_id_missing", failures)
    _require(
        roster.get("status") == "operator_reviewed", "roster_status_invalid", failures
    )
    _require(
        roster.get("admission_request_sha256") == admission_request_sha256,
        "roster_admission_request_hash_mismatch",
        failures,
    )
    _require(
        roster.get("qualification_protocol_sha256") == qualification_protocol_sha256,
        "roster_qualification_protocol_hash_mismatch",
        failures,
    )
    _validate_review(_object(roster.get("operator_review")), failures)
    if _contains_secret_key(roster):
        failures.append("roster_contains_secret_field")

    entries = roster.get("participants")
    if not isinstance(entries, list) or len(entries) != 40:
        failures.append("roster_must_contain_40_participants")
        entries = entries if isinstance(entries, list) else []
    participant_ids: set[str] = set()
    execution_dids: set[str] = set()
    isolation_hashes: set[str] = set()
    consent_hashes: set[str] = set()
    pairs: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for index, entry_value in enumerate(entries):
        entry = entry_value if isinstance(entry_value, dict) else {}
        _validate_entry(entry, index, expected_stack, failures)
        participant_id = _text(entry.get("participant_id"))
        execution_did = _text(entry.get("execution_did"))
        pair_id = _text(entry.get("pair_id"))
        isolation_hash = _text(entry.get("isolation_root_sha256"))
        consent_hash = _text(entry.get("consent_receipt_sha256"))
        _unique(participant_id, participant_ids, "participant_id_duplicate", failures)
        _unique(execution_did, execution_dids, "execution_did_duplicate", failures)
        _unique(isolation_hash, isolation_hashes, "isolation_root_duplicate", failures)
        _unique(consent_hash, consent_hashes, "consent_receipt_duplicate", failures)
        if pair_id:
            pairs[pair_id].append(entry)
    _require(len(pairs) == 20, "roster_must_contain_20_pairs", failures)
    for pair_id, pair in pairs.items():
        if len(pair) != 2:
            failures.append(f"pair_{pair_id}_must_contain_two_participants")
            continue
        baselines = {item.get("cognitive_baseline_sha256") for item in pair}
        _require(len(baselines) == 1, "pair_cognitive_baseline_mismatch", failures)
    declared_hash = roster.get("roster_sha256")
    body = {key: item for key, item in roster.items() if key != "roster_sha256"}
    _require(declared_hash == canonical_sha256(body), "roster_hash_mismatch", failures)
    return list(dict.fromkeys(failures))


def validate_qualification_protocol(
    value: Any, *, admission_request_sha256: str
) -> list[str]:
    failures: list[str] = []
    protocol = value if isinstance(value, dict) else {}
    _require(
        protocol.get("schema_version") == QUALIFICATION_PROTOCOL_SCHEMA,
        "qualification_protocol_schema_invalid",
        failures,
    )
    _require(
        protocol.get("status") == "frozen",
        "qualification_protocol_not_frozen",
        failures,
    )
    _require(
        _rfc3339(protocol.get("frozen_at")),
        "qualification_protocol_frozen_at_invalid",
        failures,
    )
    _require(
        protocol.get("admission_request_sha256") == admission_request_sha256,
        "qualification_protocol_admission_hash_mismatch",
        failures,
    )
    corpus = _object(protocol.get("task_corpus"))
    corpus_id = _text(corpus.get("corpus_id"))
    _require(_real_identifier(corpus_id), "qualification_corpus_id_invalid", failures)
    _require(
        _sha256(corpus.get("tasks_sha256")),
        "qualification_corpus_hash_invalid",
        failures,
    )
    _require(
        type(corpus.get("task_count")) is int and corpus.get("task_count") >= 8,
        "qualification_corpus_too_small",
        failures,
    )
    _require(
        corpus.get("synthetic") is False, "qualification_corpus_must_be_real", failures
    )
    stack = _object(protocol.get("frozen_stack"))
    for field in ("provider_id", "model_id", "budget_id", "verifier_id"):
        _require(
            _real_identifier(_text(stack.get(field))),
            f"qualification_{field}_invalid",
            failures,
        )
    _require(
        stack.get("temperature") == 0, "qualification_temperature_invalid", failures
    )
    _require(
        stack.get("same_stack_for_both_cohorts") is True,
        "qualification_stack_must_match",
        failures,
    )
    _require(
        protocol.get("minimum_completed_pairs") == 20,
        "qualification_pair_count_invalid",
        failures,
    )
    boundary = _object(protocol.get("execution_boundary"))
    _require(
        boundary.get("single_use_authorization_required") is True,
        "qualification_authorization_required",
        failures,
    )
    _require(
        boundary.get("execution_authorized") is False,
        "qualification_execution_must_be_false",
        failures,
    )
    return list(dict.fromkeys(failures))


def _validate_review(review: dict[str, Any], failures: list[str]) -> None:
    reviewer = _text(review.get("reviewer_did"))
    _require(_real_did(reviewer), "operator_reviewer_did_invalid", failures)
    _require(
        review.get("decision") == "approve_roster_binding",
        "operator_review_decision_invalid",
        failures,
    )
    _require(
        review.get("conflicts_disclosed") is True,
        "operator_conflict_disclosure_required",
        failures,
    )
    _require(
        _rfc3339(review.get("reviewed_at")), "operator_reviewed_at_invalid", failures
    )
    _require(
        _sha256(review.get("review_receipt_sha256")),
        "operator_review_receipt_invalid",
        failures,
    )


def _validate_entry(
    entry: dict[str, Any],
    index: int,
    expected_stack: dict[str, str],
    failures: list[str],
) -> None:
    prefix = f"participant_{index}"
    participant_id = _text(entry.get("participant_id"))
    _require(_real_identifier(participant_id), f"{prefix}_id_invalid", failures)
    _require(
        _real_identifier(_text(entry.get("pair_id"))),
        f"{prefix}_pair_id_invalid",
        failures,
    )
    _require(
        _real_did(_text(entry.get("execution_did"))),
        f"{prefix}_execution_did_invalid",
        failures,
    )
    for field in (
        "cognitive_baseline_sha256",
        "identity_snapshot_sha256",
        "custody_provenance_sha256",
        "isolation_root_sha256",
        "consent_receipt_sha256",
    ):
        _require(_sha256(entry.get(field)), f"{prefix}_{field}_invalid", failures)
    _require(
        type(entry.get("credential_version")) is int
        and entry.get("credential_version") > 0,
        f"{prefix}_credential_version_invalid",
        failures,
    )
    _require(
        entry.get("signer_kind") in ALLOWED_SIGNERS,
        f"{prefix}_signer_kind_invalid",
        failures,
    )
    _require(
        entry.get("prior_mentorship_exposure") is False,
        f"{prefix}_prior_mentorship_exposure_invalid",
        failures,
    )
    _require(
        entry.get("random_assignment_consented") is True,
        f"{prefix}_random_assignment_consent_missing",
        failures,
    )
    _require(
        entry.get("model_execution_authorized") is False,
        f"{prefix}_model_execution_must_be_false",
        failures,
    )
    for field, expected in expected_stack.items():
        _require(entry.get(field) == expected, f"{prefix}_{field}_mismatch", failures)


def _contains_secret_key(value: Any) -> bool:
    if isinstance(value, dict):
        for key, item in value.items():
            normalized = str(key).lower()
            if any(token in normalized for token in SECRET_KEY_TOKENS):
                return True
            if _contains_secret_key(item):
                return True
    elif isinstance(value, list):
        return any(_contains_secret_key(item) for item in value)
    return False


def _real_identifier(value: str) -> bool:
    lowered = value.lower()
    return bool(value) and not any(token in lowered for token in FORBIDDEN_ID_TOKENS)


def _real_did(value: str) -> bool:
    return value.startswith("did:civ:") and _real_identifier(value)


def _rfc3339(value: Any) -> bool:
    try:
        parsed = datetime.fromisoformat(_text(value).replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None


def _sha256(value: Any) -> bool:
    text = _text(value)
    return len(text) == 64 and all(char in "0123456789abcdef" for char in text)


def _text(value: Any) -> str:
    return str(value or "").strip()


def _object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _unique(value: str, seen: set[str], code: str, failures: list[str]) -> None:
    if value and value in seen:
        failures.append(code)
    seen.add(value)


def _require(condition: bool, code: str, failures: list[str]) -> None:
    if not condition and code not in failures:
        failures.append(code)
