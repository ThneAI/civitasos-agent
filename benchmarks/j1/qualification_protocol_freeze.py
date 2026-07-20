"""Artifact-bound J1-D qualification protocol freeze validation."""

from __future__ import annotations

import hashlib
from typing import Any

from .controlled_comparison import REQUIRED_SCENARIOS, canonical_sha256
from .qualification_roster import (
    QUALIFICATION_PROTOCOL_SCHEMA,
    validate_qualification_protocol,
)
from .qualification_review_receipt import validate_signed_review_receipt


CORPUS_SCHEMA = "j1-qualification-task-corpus:v1"
VERIFIER_SCHEMA = "j1-qualification-verifier-manifest:v1"


def build_qualification_protocol(
    *,
    experiment_id: str,
    hypothesis: str,
    budget_id: str,
    frozen_at: str,
    corpus: dict[str, Any],
    verifier: dict[str, Any],
    admission_request: dict[str, Any],
    review_receipt: dict[str, Any],
    corpus_bytes: bytes,
    verifier_bytes: bytes,
    review_receipt_bytes: bytes,
) -> dict[str, Any]:
    """Build a non-executable protocol bound to reviewed artifact bytes."""
    for field, value in (
        ("experiment_id", experiment_id),
        ("hypothesis", hypothesis),
        ("budget_id", budget_id),
    ):
        if not _real_text(value):
            raise ValueError(f"{field} must identify a real qualification run")
    request_provider = _object(admission_request.get("provider"))
    request_budget = _object(admission_request.get("qualification_budget_ceiling"))
    reviewer = _object(review_receipt.get("reviewer"))
    receipt_hash = hashlib.sha256(review_receipt_bytes).hexdigest()
    return {
        "schema_version": QUALIFICATION_PROTOCOL_SCHEMA,
        "experiment_id": experiment_id,
        "hypothesis": hypothesis,
        "status": "frozen",
        "frozen_at": frozen_at,
        "admission_request_sha256": canonical_sha256(admission_request),
        "material_review": {
            "review_id": review_receipt.get("review_id"),
            "review_request_sha256": review_receipt.get("review_request_sha256"),
            "reviewer_did": reviewer.get("did"),
            "review_receipt_sha256": receipt_hash,
        },
        "task_corpus": {
            "corpus_id": corpus.get("corpus_id"),
            "tasks_sha256": corpus.get("tasks_sha256"),
            "task_count": len(corpus.get("tasks", [])),
            "synthetic": False,
            "artifact_sha256": hashlib.sha256(corpus_bytes).hexdigest(),
        },
        "frozen_stack": {
            "provider_id": request_provider.get("kind"),
            "model_id": request_provider.get("model"),
            "budget_id": budget_id,
            "verifier_id": verifier.get("verifier_id"),
            "verifier_manifest_sha256": hashlib.sha256(verifier_bytes).hexdigest(),
            "temperature": 0,
            "same_stack_for_both_cohorts": True,
            "budget": {
                "max_tasks": request_budget.get("max_tasks_per_participant"),
                "max_tokens": request_budget.get("max_tokens_per_participant"),
                "max_cost_microunits": request_budget.get(
                    "max_cost_microunits_per_participant"
                ),
            },
        },
        "minimum_completed_pairs": 20,
        "metric_definitions_sha256": canonical_sha256(
            qualification_metric_definitions()
        ),
        "analysis": qualification_analysis(),
        "execution_boundary": {
            "single_use_authorization_required": True,
            "execution_authorized": False,
            "provider_api_call_allowed": False,
            "model_invocation_allowed": False,
            "agent_execution_allowed": False,
            "backend_fact_append_allowed": False,
            "ledger_append_allowed": False,
            "effectiveness_claim_allowed": False,
        },
    }


def validate_freeze(
    protocol: dict[str, Any],
    corpus: dict[str, Any],
    verifier: dict[str, Any],
    admission_request: dict[str, Any],
    *,
    corpus_bytes: bytes,
    verifier_bytes: bytes,
    review_receipt: dict[str, Any],
    review_receipt_bytes: bytes,
) -> list[str]:
    request_hash = canonical_sha256(admission_request)
    failures = validate_qualification_protocol(
        protocol, admission_request_sha256=request_hash
    )
    _validate_corpus(corpus, failures)
    _validate_verifier(verifier, corpus, failures)
    _validate_review_binding(
        protocol,
        corpus,
        verifier,
        review_receipt,
        review_receipt_bytes=review_receipt_bytes,
        failures=failures,
    )
    protocol_corpus = _object(protocol.get("task_corpus"))
    stack = _object(protocol.get("frozen_stack"))
    request_provider = _object(admission_request.get("provider"))
    request_budget = _object(admission_request.get("qualification_budget_ceiling"))
    _require(
        protocol_corpus.get("corpus_id") == corpus.get("corpus_id"),
        "protocol_corpus_id_mismatch",
        failures,
    )
    _require(
        protocol_corpus.get("tasks_sha256") == corpus.get("tasks_sha256"),
        "protocol_corpus_tasks_hash_mismatch",
        failures,
    )
    _require(
        protocol_corpus.get("artifact_sha256")
        == hashlib.sha256(corpus_bytes).hexdigest(),
        "protocol_corpus_artifact_hash_mismatch",
        failures,
    )
    _require(
        stack.get("verifier_id") == verifier.get("verifier_id"),
        "protocol_verifier_id_mismatch",
        failures,
    )
    _require(
        stack.get("verifier_manifest_sha256")
        == hashlib.sha256(verifier_bytes).hexdigest(),
        "protocol_verifier_artifact_hash_mismatch",
        failures,
    )
    _require(
        stack.get("provider_id") == request_provider.get("kind"),
        "protocol_provider_mismatch",
        failures,
    )
    _require(
        stack.get("model_id") == request_provider.get("model"),
        "protocol_model_mismatch",
        failures,
    )
    expected_budget = {
        "max_tasks": request_budget.get("max_tasks_per_participant"),
        "max_tokens": request_budget.get("max_tokens_per_participant"),
        "max_cost_microunits": request_budget.get(
            "max_cost_microunits_per_participant"
        ),
    }
    _require(
        stack.get("budget") == expected_budget, "protocol_budget_mismatch", failures
    )
    _require(
        protocol.get("metric_definitions_sha256")
        == canonical_sha256(qualification_metric_definitions()),
        "protocol_metric_definitions_mismatch",
        failures,
    )
    _require(
        protocol.get("analysis") == qualification_analysis(),
        "protocol_analysis_invalid",
        failures,
    )
    boundary = _object(protocol.get("execution_boundary"))
    for field in (
        "provider_api_call_allowed",
        "model_invocation_allowed",
        "agent_execution_allowed",
        "backend_fact_append_allowed",
        "ledger_append_allowed",
        "effectiveness_claim_allowed",
    ):
        _require(boundary.get(field) is False, f"{field}_must_be_false", failures)
    return list(dict.fromkeys(failures))


def _validate_review_binding(
    protocol: dict[str, Any],
    corpus: dict[str, Any],
    verifier: dict[str, Any],
    receipt: dict[str, Any],
    *,
    review_receipt_bytes: bytes,
    failures: list[str],
) -> None:
    failures.extend(validate_signed_review_receipt(receipt))
    _require(
        receipt.get("decision") == "approve_qualification_materials",
        "qualification_material_review_not_approved",
        failures,
    )
    receipt_hash = hashlib.sha256(review_receipt_bytes).hexdigest()
    reviewer = _object(receipt.get("reviewer"))
    expected_protocol_review = {
        "review_id": receipt.get("review_id"),
        "review_request_sha256": receipt.get("review_request_sha256"),
        "reviewer_did": reviewer.get("did"),
        "review_receipt_sha256": receipt_hash,
    }
    _require(
        _object(protocol.get("material_review")) == expected_protocol_review,
        "protocol_material_review_binding_mismatch",
        failures,
    )
    independence = _object(receipt.get("independence"))
    expected_artifact_review = {
        "review_id": receipt.get("review_id"),
        "review_request_sha256": receipt.get("review_request_sha256"),
        "reviewer_did": reviewer.get("did"),
        "reviewer_credential_version": reviewer.get("credential_version"),
        "signer_kind": reviewer.get("signer_kind"),
        "custody_provenance_sha256": reviewer.get("custody_provenance_sha256"),
        "signer_attestation_sha256": reviewer.get("signer_attestation_sha256"),
        "decision": receipt.get("decision"),
        "reviewed_at": receipt.get("reviewed_at"),
        "conflicts_disclosed": independence.get("conflicts_disclosed"),
        "independent_from_authoring": independence.get("independent_from_authoring"),
        "review_receipt_sha256": receipt_hash,
        "review_scope": receipt.get("review_scope"),
    }
    _require(
        _object(corpus.get("operator_review")) == expected_artifact_review,
        "qualification_corpus_review_binding_mismatch",
        failures,
    )
    _require(
        _object(verifier.get("operator_review")) == expected_artifact_review,
        "qualification_verifier_review_binding_mismatch",
        failures,
    )
    scope = _object(receipt.get("review_scope"))
    _require(
        scope.get("corpus_id") == corpus.get("corpus_id"),
        "reviewed_corpus_id_mismatch",
        failures,
    )
    _require(
        scope.get("corpus_tasks_sha256") == corpus.get("tasks_sha256"),
        "reviewed_corpus_tasks_hash_mismatch",
        failures,
    )
    _require(
        scope.get("verifier_id") == verifier.get("verifier_id"),
        "reviewed_verifier_id_mismatch",
        failures,
    )
    _require(
        scope.get("verifier_source_revision") == verifier.get("source_revision"),
        "reviewed_verifier_revision_mismatch",
        failures,
    )
    implementations = {
        item.get("implementation_sha256")
        for item in verifier.get("cases", [])
        if isinstance(item, dict)
    }
    _require(
        implementations == {scope.get("verifier_implementation_sha256")},
        "reviewed_verifier_implementation_mismatch",
        failures,
    )


def _validate_corpus(corpus: dict[str, Any], failures: list[str]) -> None:
    _require(
        corpus.get("schema_version") == CORPUS_SCHEMA,
        "qualification_corpus_schema_invalid",
        failures,
    )
    _require(
        corpus.get("status") == "operator_reviewed",
        "qualification_corpus_status_invalid",
        failures,
    )
    _require(
        corpus.get("synthetic") is False, "qualification_corpus_must_be_real", failures
    )
    _require(
        corpus.get("confidential") is True,
        "qualification_corpus_must_be_confidential",
        failures,
    )
    tasks = corpus.get("tasks")
    if not isinstance(tasks, list) or len(tasks) < 8:
        failures.append("qualification_corpus_too_small")
        tasks = tasks if isinstance(tasks, list) else []
    ids: list[str] = []
    scenarios: set[str] = set()
    for index, item in enumerate(tasks):
        task = item if isinstance(item, dict) else {}
        task_id = _text(task.get("task_id"))
        ids.append(task_id)
        _require(
            _real_text(task_id), f"qualification_task_{index}_id_invalid", failures
        )
        _require(
            _sha256(task.get("input_sha256")),
            f"qualification_task_{index}_input_hash_invalid",
            failures,
        )
        _require(
            _real_text(_text(task.get("verifier_case"))),
            f"qualification_task_{index}_verifier_case_invalid",
            failures,
        )
        tags = task.get("scenario_tags")
        if isinstance(tags, list) and all(isinstance(tag, str) for tag in tags):
            scenarios.update(tags)
        else:
            failures.append(f"qualification_task_{index}_scenario_tags_invalid")
    _require(len(ids) == len(set(ids)), "qualification_task_ids_duplicate", failures)
    _require(
        scenarios == REQUIRED_SCENARIOS,
        "qualification_scenario_coverage_invalid",
        failures,
    )
    _require(
        corpus.get("tasks_sha256") == canonical_sha256(tasks),
        "qualification_tasks_hash_mismatch",
        failures,
    )


def _validate_verifier(
    verifier: dict[str, Any], corpus: dict[str, Any], failures: list[str]
) -> None:
    _require(
        verifier.get("schema_version") == VERIFIER_SCHEMA,
        "qualification_verifier_schema_invalid",
        failures,
    )
    _require(
        verifier.get("status") == "operator_reviewed",
        "qualification_verifier_status_invalid",
        failures,
    )
    _require(
        _real_text(_text(verifier.get("verifier_id"))),
        "qualification_verifier_id_invalid",
        failures,
    )
    _require(
        _git_revision(verifier.get("source_revision")),
        "qualification_verifier_revision_invalid",
        failures,
    )
    _require(
        verifier.get("deterministic") is True,
        "qualification_verifier_must_be_deterministic",
        failures,
    )
    _require(
        verifier.get("model_judge_allowed") is False,
        "qualification_verifier_model_judge_forbidden",
        failures,
    )
    _require(
        verifier.get("operator_override_allowed") is False,
        "qualification_verifier_override_forbidden",
        failures,
    )
    cases = verifier.get("cases")
    case_values = cases if isinstance(cases, list) else []
    case_ids = {
        _text(item.get("case_id")) for item in case_values if isinstance(item, dict)
    }
    expected = {
        _text(task.get("verifier_case"))
        for task in corpus.get("tasks", [])
        if isinstance(task, dict)
    }
    _require(case_ids == expected, "qualification_verifier_case_set_mismatch", failures)
    for index, item in enumerate(case_values):
        case = item if isinstance(item, dict) else {}
        _require(
            _sha256(case.get("implementation_sha256")),
            f"qualification_verifier_case_{index}_hash_invalid",
            failures,
        )
    declared = verifier.get("manifest_sha256")
    body = {key: value for key, value in verifier.items() if key != "manifest_sha256"}
    _require(
        declared == canonical_sha256(body),
        "qualification_verifier_manifest_hash_mismatch",
        failures,
    )


def qualification_metric_definitions() -> dict[str, Any]:
    return {
        "strategy_maturity_time": {
            "consecutive_verified_tasks": 3,
            "minimum_relative_reduction": 0.5,
        },
        "repeated_error_rate": {"requires_strict_decrease": True},
        "mentor_pattern_false_positive_rate": {"maximum_rate": 0.1},
        "advice_provenance_completeness": {"required_ratio": 1.0},
        "sovereignty_violation_count": {"maximum_count": 0},
        "direct_trust_increment_count": {"maximum_count": 0},
        "unit_improvement_cost": {"report_only": True},
    }


def qualification_analysis() -> dict[str, Any]:
    return {
        "confidence_level": 0.95,
        "bootstrap_iterations": 10000,
        "paired_analysis": True,
        "efficacy_early_stop_allowed": False,
        "outcome_based_exclusion_allowed": False,
    }


def _real_text(value: str) -> bool:
    lowered = value.lower()
    return bool(value) and not any(
        token in lowered for token in ("synthetic", "fixture", "test", "demo")
    )


def _sha256(value: Any) -> bool:
    text = _text(value)
    return len(text) == 64 and all(char in "0123456789abcdef" for char in text)


def _git_revision(value: Any) -> bool:
    text = _text(value)
    return len(text) == 40 and all(char in "0123456789abcdef" for char in text)


def _text(value: Any) -> str:
    return str(value or "").strip()


def _object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _require(condition: bool, code: str, failures: list[str]) -> None:
    if not condition and code not in failures:
        failures.append(code)
