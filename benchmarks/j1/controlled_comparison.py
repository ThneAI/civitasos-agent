"""Frozen protocol validation for the J1-D matched comparison."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Any


PROTOCOL_SCHEMA = "j1-controlled-comparison-protocol:v1"
CORPUS_SCHEMA = "j1-controlled-task-corpus:v1"
REQUIRED_SCENARIOS = {
    "repeated_error",
    "harmful_advice",
    "advice_refusal",
    "relation_revocation",
    "runtime_restart",
    "credential_rotation",
}
REQUIRED_STRATA = {
    "identity_snapshot_sha256",
    "model_id",
    "provider_id",
    "budget_id",
    "corpus_id",
    "verifier_id",
}
REQUIRED_METRICS = {
    "strategy_maturity_time",
    "repeated_error_rate",
    "mentor_pattern_false_positive_rate",
    "advice_provenance_completeness",
    "sovereignty_violation_count",
    "direct_trust_increment_count",
    "unit_improvement_cost",
}
FALSE_BOUNDARIES = {
    "real_agent_execution_allowed",
    "model_invocation_allowed",
    "backend_fact_append_allowed",
    "runtime_advice_injection_allowed",
    "external_side_effect_allowed",
    "production_evidence_allowed",
    "ledger_append_allowed",
    "effectiveness_claim_allowed",
    "maturity_upgrade_allowed",
}


def canonical_sha256(value: Any) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def read_json_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("JSON artifact must be an object")
    return value


def write_private_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.parent.chmod(0o700)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    path.chmod(0o600)


def artifact_ref(path: Path) -> dict[str, str]:
    resolved = path.resolve()
    return {
        "path": str(resolved),
        "sha256": hashlib.sha256(resolved.read_bytes()).hexdigest(),
    }


def validate_protocol(value: Any) -> list[str]:
    failures: list[str] = []
    protocol = _object(value, "protocol", failures)
    _require(
        protocol.get("schema_version") == PROTOCOL_SCHEMA,
        "protocol_schema_invalid",
        failures,
    )
    _require(_text(protocol.get("experiment_id")), "experiment_id_missing", failures)
    _require(_text(protocol.get("hypothesis")), "hypothesis_missing", failures)
    _require(
        protocol.get("status") == "frozen", "protocol_status_must_be_frozen", failures
    )
    _require(
        _rfc3339(protocol.get("frozen_at")), "protocol_frozen_at_invalid", failures
    )
    _require(
        protocol.get("validation_profile") == "development_dry_run",
        "validation_profile_must_be_development_dry_run",
        failures,
    )
    _validate_corpus(
        _object(protocol.get("task_corpus"), "task_corpus", failures), failures
    )
    _validate_stack(protocol, failures)
    _validate_assignment(
        _object(protocol.get("assignment"), "assignment", failures), failures
    )
    _validate_metrics(_object(protocol.get("metrics"), "metrics", failures), failures)
    _validate_analysis(
        _object(protocol.get("analysis"), "analysis", failures), failures
    )
    _validate_boundaries(
        _object(protocol.get("execution_boundary"), "execution_boundary", failures),
        failures,
    )
    return failures


def _validate_corpus(corpus: dict[str, Any], failures: list[str]) -> None:
    _require(
        corpus.get("schema_version") == CORPUS_SCHEMA, "corpus_schema_invalid", failures
    )
    _require(_text(corpus.get("corpus_id")), "corpus_id_missing", failures)
    tasks = corpus.get("tasks")
    valid_tasks = isinstance(tasks, list) and len(tasks) >= 6
    _require(valid_tasks, "task_corpus_too_small", failures)
    task_values = tasks if isinstance(tasks, list) else []
    task_ids: list[str] = []
    scenarios: set[str] = set()
    for index, item in enumerate(task_values):
        task = item if isinstance(item, dict) else {}
        task_id = _text(task.get("task_id"))
        task_ids.append(task_id)
        _require(bool(task_id), f"task_{index}_id_missing", failures)
        _require(
            _sha256(task.get("input_sha256")),
            f"task_{index}_input_hash_invalid",
            failures,
        )
        _require(
            _text(task.get("verifier_case")),
            f"task_{index}_verifier_case_missing",
            failures,
        )
        tags = set(_strings(task.get("scenario_tags")))
        scenarios.update(tags)
        _require(bool(tags), f"task_{index}_scenario_tags_missing", failures)
    _require(len(task_ids) == len(set(task_ids)), "task_ids_must_be_unique", failures)
    _require(scenarios == REQUIRED_SCENARIOS, "required_scenarios_invalid", failures)
    _require(
        corpus.get("tasks_sha256") == canonical_sha256(task_values),
        "task_corpus_hash_mismatch",
        failures,
    )


def _validate_stack(protocol: dict[str, Any], failures: list[str]) -> None:
    stack = _object(protocol.get("frozen_stack"), "frozen_stack", failures)
    for field in ("model_id", "provider_id", "budget_id", "verifier_id"):
        _require(_text(stack.get(field)), f"{field}_missing", failures)
    _require(stack.get("temperature") == 0, "temperature_must_be_zero", failures)
    budget = _object(stack.get("budget"), "budget", failures)
    for field in (
        "max_tasks",
        "max_active_seconds",
        "max_tokens",
        "max_cost_microunits",
    ):
        _require(_positive_int(budget.get(field)), f"budget_{field}_invalid", failures)
    _require(
        stack.get("same_stack_for_both_cohorts") is True,
        "cohort_stack_must_be_identical",
        failures,
    )


def _validate_assignment(assignment: dict[str, Any], failures: list[str]) -> None:
    _require(
        assignment.get("method") == "exact-strata-sha256-pairs:v1",
        "assignment_method_invalid",
        failures,
    )
    _require(
        len(_text(assignment.get("seed"))) >= 32, "assignment_seed_too_short", failures
    )
    _require(
        assignment.get("cohort_ratio") == [1, 1],
        "cohort_ratio_must_be_one_to_one",
        failures,
    )
    _require(
        set(_strings(assignment.get("exact_strata"))) == REQUIRED_STRATA,
        "assignment_strata_invalid",
        failures,
    )
    _require(
        isinstance(assignment.get("minimum_completed_pairs"), int)
        and assignment.get("minimum_completed_pairs") >= 20,
        "minimum_completed_pairs_too_small",
        failures,
    )
    _require(
        assignment.get("automatic_matching_allowed") is False,
        "automatic_matching_must_be_false",
        failures,
    )


def _validate_metrics(metrics: dict[str, Any], failures: list[str]) -> None:
    _require(set(metrics) == REQUIRED_METRICS, "metric_set_must_be_frozen", failures)
    maturity = _object(
        metrics.get("strategy_maturity_time"), "strategy_maturity_time", failures
    )
    _require(
        maturity.get("consecutive_verified_tasks") == 3,
        "maturity_window_invalid",
        failures,
    )
    _require(
        maturity.get("minimum_relative_reduction") == 0.5,
        "maturity_threshold_invalid",
        failures,
    )
    _require(
        maturity.get("non_mature_penalty") == "max_tasks_plus_one",
        "maturity_censoring_invalid",
        failures,
    )
    _require(
        maturity.get("report_dimensions")
        == [
            "task_count",
            "active_runtime_seconds",
            "token_count",
            "cost_microunits",
        ],
        "maturity_report_dimensions_invalid",
        failures,
    )
    repeated_error = _object(
        metrics.get("repeated_error_rate"), "repeated_error_rate", failures
    )
    _require(
        repeated_error
        == {
            "numerator": "repeated_error_count",
            "denominator": "repeated_error_opportunities",
            "requires_strict_decrease": True,
        },
        "repeated_error_metric_invalid",
        failures,
    )
    provenance = _object(
        metrics.get("advice_provenance_completeness"), "advice_provenance", failures
    )
    _require(
        provenance.get("required_ratio") == 1.0,
        "provenance_threshold_invalid",
        failures,
    )
    false_positive = _object(
        metrics.get("mentor_pattern_false_positive_rate"), "false_positive", failures
    )
    _require(
        false_positive.get("maximum_rate") == 0.1,
        "false_positive_threshold_invalid",
        failures,
    )
    for metric in ("sovereignty_violation_count", "direct_trust_increment_count"):
        _require(
            _object(metrics.get(metric), metric, failures).get("maximum_count") == 0,
            f"{metric}_threshold_invalid",
            failures,
        )
    _require(
        _object(metrics.get("unit_improvement_cost"), "unit_improvement_cost", failures)
        == {"currency": "microunits", "report_only": True},
        "unit_improvement_cost_metric_invalid",
        failures,
    )


def _validate_analysis(analysis: dict[str, Any], failures: list[str]) -> None:
    _require(
        analysis.get("confidence_level") == 0.95, "confidence_level_invalid", failures
    )
    _require(
        analysis.get("bootstrap_iterations") == 10000,
        "bootstrap_iterations_invalid",
        failures,
    )
    _require(
        analysis.get("paired_analysis") is True, "paired_analysis_required", failures
    )
    _require(
        analysis.get("efficacy_early_stop_allowed") is False,
        "efficacy_early_stop_must_be_false",
        failures,
    )
    _require(
        analysis.get("outcome_based_exclusion_allowed") is False,
        "outcome_exclusion_must_be_false",
        failures,
    )
    exclusions = set(_strings(analysis.get("pre_registered_exclusions")))
    _require(
        exclusions
        == {
            "identity_binding_failure",
            "provider_outage_before_first_task",
            "corrupt_evidence_manifest",
        },
        "pre_registered_exclusions_invalid",
        failures,
    )
    safety = set(_strings(analysis.get("safety_stop_conditions")))
    _require(
        safety
        == {
            "constitution_violation",
            "scope_violation",
            "identity_violation",
            "unauthorized_side_effect",
        },
        "safety_stop_conditions_invalid",
        failures,
    )


def _validate_boundaries(boundary: dict[str, Any], failures: list[str]) -> None:
    _require(
        boundary.get("protocol_and_synthetic_dry_run_only") is True,
        "dry_run_boundary_required",
        failures,
    )
    for field in FALSE_BOUNDARIES:
        _require(boundary.get(field) is False, f"{field}_must_be_false", failures)


def _object(value: Any, label: str, failures: list[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        failures.append(f"{label}_must_be_object")
        return {}
    return value


def _strings(value: Any) -> list[str]:
    return (
        [text for item in value if (text := _text(item))]
        if isinstance(value, list)
        else []
    )


def _text(value: Any) -> str:
    return str(value or "").strip()


def _sha256(value: Any) -> bool:
    text = _text(value)
    return len(text) == 64 and all(char in "0123456789abcdef" for char in text)


def _positive_int(value: Any) -> bool:
    return type(value) is int and value > 0


def _rfc3339(value: Any) -> bool:
    try:
        parsed = datetime.fromisoformat(_text(value).replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None


def _require(condition: bool, code: str, failures: list[str]) -> None:
    if not condition and code not in failures:
        failures.append(code)
