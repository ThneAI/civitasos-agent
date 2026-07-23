"""Post-run receipt and operator closeout contracts for J1-D qualification."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from .controlled_comparison import canonical_sha256


POST_RUN_SCHEMA = "j1-qualification-post-run-contract:v1"
CLOSEOUT_SCHEMA = "j1-qualification-operator-closeout-contract:v1"
STATUS = "review_required"


def build_post_run_contract(
    *,
    contract_id: str,
    created_at: str,
    evaluator_manifest_sha256: str,
    source_binding: dict[str, str],
    implementation: dict[str, str],
) -> dict[str, Any]:
    value = _post_run_value(
        contract_id=contract_id,
        created_at=created_at,
        evaluator_manifest_sha256=evaluator_manifest_sha256,
        source_binding=source_binding,
        implementation=implementation,
    )
    failures = validate_post_run_contract(
        value,
        evaluator_manifest_sha256=evaluator_manifest_sha256,
        source_binding=source_binding,
        implementation=implementation,
    )
    if failures:
        raise ValueError(f"post-run contract invalid: {failures}")
    return value


def _post_run_value(
    *,
    contract_id: str,
    created_at: str,
    evaluator_manifest_sha256: str,
    source_binding: dict[str, str],
    implementation: dict[str, str],
) -> dict[str, Any]:
    value = {
        "schema_version": POST_RUN_SCHEMA,
        "contract_id": contract_id,
        "status": STATUS,
        "created_at": created_at,
        "source_binding": {
            **source_binding,
            "evaluator_manifest_sha256": evaluator_manifest_sha256,
        },
        "planned_inventory": {
            "participant_count": 40,
            "matched_pair_count": 20,
            "task_count_per_participant": 8,
            "task_evidence_count": 320,
            "provider_receipt_count": 320,
            "participant_decision_receipt_count": 320,
            "event_trace_count": 320,
            "participant_outcome_count": 40,
        },
        "terminal_completeness": {
            "complete_requires_exact_planned_inventory": True,
            "failed_or_aborted_allows_partial_inventory": True,
            "every_attempted_task_must_be_accounted": True,
            "every_missing_task_requires_reason": True,
            "attempted_completed_failed_aborted_counts_must_balance": True,
            "partial_inventory_effectiveness_claim_allowed": False,
        },
        "integrity": {
            "all_artifacts_content_addressed": True,
            "task_evidence_verified_by_frozen_verifier": True,
            "cohort_derived_from_reviewed_assignment": True,
            "execution_authorization_bound_to_every_task": True,
            "duplicate_task_or_call_id_rejected": True,
            "missing_or_extra_artifact_rejected": True,
            "raw_provider_response_persisted": False,
            "credential_value_or_hash_persisted": False,
        },
        "budget_reconciliation": {
            "all_provider_reservations_terminal": True,
            "aggregate_actual_tokens_required": True,
            "aggregate_actual_cost_microunits_required": True,
            "participant_and_aggregate_ceiling_rechecked": True,
            "overrun_forces_failed_closeout": True,
        },
        "terminal_states": {
            "complete": "post_run_complete_evaluation_required",
            "failed": "post_run_failed_operator_closeout_required",
            "aborted": "post_run_aborted_operator_closeout_required",
            "closeout_always_required": True,
        },
        "execution_boundary": _boundary(),
        "implementation": dict(implementation),
    }
    value["contract_sha256"] = canonical_sha256(value)
    return value


def build_closeout_contract(
    *,
    contract_id: str,
    created_at: str,
    evaluator_manifest_sha256: str,
    post_run_contract_sha256: str,
    source_binding: dict[str, str],
    implementation: dict[str, str],
) -> dict[str, Any]:
    value = _closeout_value(
        contract_id=contract_id,
        created_at=created_at,
        evaluator_manifest_sha256=evaluator_manifest_sha256,
        post_run_contract_sha256=post_run_contract_sha256,
        source_binding=source_binding,
        implementation=implementation,
    )
    failures = validate_closeout_contract(
        value,
        evaluator_manifest_sha256=evaluator_manifest_sha256,
        post_run_contract_sha256=post_run_contract_sha256,
        source_binding=source_binding,
        implementation=implementation,
    )
    if failures:
        raise ValueError(f"closeout contract invalid: {failures}")
    return value


def _closeout_value(
    *,
    contract_id: str,
    created_at: str,
    evaluator_manifest_sha256: str,
    post_run_contract_sha256: str,
    source_binding: dict[str, str],
    implementation: dict[str, str],
) -> dict[str, Any]:
    value = {
        "schema_version": CLOSEOUT_SCHEMA,
        "contract_id": contract_id,
        "status": STATUS,
        "created_at": created_at,
        "source_binding": {
            **source_binding,
            "evaluator_manifest_sha256": evaluator_manifest_sha256,
            "post_run_contract_sha256": post_run_contract_sha256,
        },
        "required_inputs": {
            "post_run_receipt_required": True,
            "evaluation_report_required": True,
            "authorization_consumption_receipt_required": True,
            "execution_journal_required": True,
            "container_terminal_inventory_required": True,
            "budget_reconciliation_required": True,
        },
        "operator_decision": {
            "required": True,
            "allowed": [
                "accept_qualification_result",
                "reject_qualification_result",
                "record_failed_run",
                "record_aborted_run",
            ],
            "independence_and_conflict_disclosure_required": True,
            "signed_receipt_required": True,
            "operator_override_of_metrics_allowed": False,
        },
        "claim_policy": {
            "effectiveness_claim_requires_structural_pass": True,
            "effectiveness_claim_requires_thresholds_met": True,
            "effectiveness_claim_requires_all_20_pairs": True,
            "effectiveness_claim_requires_zero_safety_violations": True,
            "confidence_interval_must_be_reported": True,
            "automatic_maturity_upgrade_allowed": False,
            "single_run_proves_long_term_sustainability": False,
            "provider_admission_proves_effectiveness": False,
        },
        "failure_policy": {
            "claimed_authorization_reusable": False,
            "partial_result_promotable": False,
            "failed_or_aborted_run_requires_closeout": True,
            "new_run_requires_new_preflight_and_authorization": True,
        },
        "execution_boundary": _boundary(),
        "implementation": dict(implementation),
    }
    value["contract_sha256"] = canonical_sha256(value)
    return value


def validate_post_run_contract(
    value: Any,
    *,
    evaluator_manifest_sha256: str,
    source_binding: dict[str, str],
    implementation: dict[str, str],
) -> list[str]:
    actual = value if isinstance(value, dict) else {}
    expected = _post_run_value(
        contract_id=actual.get("contract_id", ""),
        created_at=actual.get("created_at", ""),
        evaluator_manifest_sha256=evaluator_manifest_sha256,
        source_binding=source_binding,
        implementation=implementation,
    )
    failures = _exact(value, expected, "post_run")
    source = actual.get("source_binding")
    _require(
        actual.get("schema_version") == POST_RUN_SCHEMA
        and actual.get("status") == STATUS
        and _text(actual.get("contract_id"))
        and _rfc3339(actual.get("created_at")),
        "post_run_contract_identity_invalid",
        failures,
    )
    _require(
        isinstance(source, dict)
        and source
        == {**source_binding, "evaluator_manifest_sha256": evaluator_manifest_sha256}
        and all(_sha256(item) for item in source.values()),
        "post_run_contract_source_invalid",
        failures,
    )
    _require(
        actual.get("execution_boundary") == _boundary(),
        "post_run_contract_boundary_invalid",
        failures,
    )
    _require(
        _valid_implementation(actual.get("implementation")),
        "post_run_contract_implementation_invalid",
        failures,
    )
    return list(dict.fromkeys(failures))


def validate_closeout_contract(
    value: Any,
    *,
    evaluator_manifest_sha256: str,
    post_run_contract_sha256: str,
    source_binding: dict[str, str],
    implementation: dict[str, str],
) -> list[str]:
    actual = value if isinstance(value, dict) else {}
    expected = _closeout_value(
        contract_id=actual.get("contract_id", ""),
        created_at=actual.get("created_at", ""),
        evaluator_manifest_sha256=evaluator_manifest_sha256,
        post_run_contract_sha256=post_run_contract_sha256,
        source_binding=source_binding,
        implementation=implementation,
    )
    failures = _exact(value, expected, "closeout")
    source = actual.get("source_binding")
    _require(
        actual.get("schema_version") == CLOSEOUT_SCHEMA
        and actual.get("status") == STATUS
        and _text(actual.get("contract_id"))
        and _rfc3339(actual.get("created_at")),
        "closeout_contract_identity_invalid",
        failures,
    )
    _require(
        isinstance(source, dict)
        and source
        == {
            **source_binding,
            "evaluator_manifest_sha256": evaluator_manifest_sha256,
            "post_run_contract_sha256": post_run_contract_sha256,
        }
        and all(_sha256(item) for item in source.values()),
        "closeout_contract_source_invalid",
        failures,
    )
    _require(
        actual.get("execution_boundary") == _boundary(),
        "closeout_contract_boundary_invalid",
        failures,
    )
    _require(
        _valid_implementation(actual.get("implementation")),
        "closeout_contract_implementation_invalid",
        failures,
    )
    return list(dict.fromkeys(failures))


def _exact(value: Any, expected: dict[str, Any], label: str) -> list[str]:
    actual = value if isinstance(value, dict) else {}
    failures = []
    if actual != expected:
        failures.append(f"{label}_contract_binding_invalid")
    body = {key: item for key, item in actual.items() if key != "contract_sha256"}
    if actual.get("contract_sha256") != canonical_sha256(body):
        failures.append(f"{label}_contract_hash_invalid")
    return failures


def _boundary() -> dict[str, bool]:
    return {
        "contract_only": True,
        "provider_api_call_performed": False,
        "model_invocation_performed": False,
        "agent_execution_performed": False,
        "participant_container_started": False,
        "backend_fact_append_performed": False,
        "ledger_append_performed": False,
        "effectiveness_claim_authorized": False,
    }


def _text(value: Any) -> str:
    return str(value or "").strip()


def _sha256(value: Any) -> bool:
    text = _text(value)
    return len(text) == 64 and all(char in "0123456789abcdef" for char in text)


def _rfc3339(value: Any) -> bool:
    try:
        parsed = datetime.fromisoformat(_text(value).replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None


def _valid_implementation(value: Any) -> bool:
    implementation = value if isinstance(value, dict) else {}
    revision = _text(implementation.get("source_revision"))
    return (
        set(implementation) == {"source_revision", "source_sha256"}
        and len(revision) == 40
        and all(char in "0123456789abcdef" for char in revision)
        and _sha256(implementation.get("source_sha256"))
    )


def _require(condition: bool, code: str, failures: list[str]) -> None:
    if not condition and code not in failures:
        failures.append(code)
