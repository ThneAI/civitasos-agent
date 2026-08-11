"""Independent-review contracts for the prospective confirmatory stack."""

from __future__ import annotations

import copy
from typing import Any

from .controlled_comparison import canonical_sha256
from .qualification_outcome_sensitive_confirmatory_execution_contract import (
    CONTRACT_SCHEMA,
)
from .qualification_outcome_sensitive_confirmatory_fault_matrix import (
    REPORT_SCHEMA as FAULT_REPORT_SCHEMA,
)
from .qualification_outcome_sensitive_confirmatory_orchestrator import (
    REPORT_SCHEMA as OFFLINE_REPORT_SCHEMA,
)
from .qualification_outcome_sensitive_execution_review import (
    BUNDLE_SCHEMA as BASE_BUNDLE_SCHEMA,
    REVIEW_BOUNDARY as BASE_REVIEW_BOUNDARY,
    REVIEW_CHECKLIST as BASE_REVIEW_CHECKLIST,
    build_review_bundle,
    build_review_request,
    validate_review_bundle,
)


BUNDLE_SCHEMA = (
    "j1-qualification-outcome-sensitive-confirmatory-execution-review-bundle:v1"
)
REQUEST_SCHEMA = (
    "j1-qualification-outcome-sensitive-confirmatory-execution-review-request:v1"
)
REVIEW_CHECKLIST = [
    "all_31_source_artifact_hashes_replayed",
    "prospective_exact_paired_method_and_holm_order_bound",
    "40_of_40_confirmatory_consent_gate_bound",
    "40_participants_20_pairs_480_decisions_bound",
    "180_fresh_mentor_advice_and_empty_control_projection_bound",
    "40_created_0_running_confirmatory_infrastructure_bound",
    "single_use_confirmatory_live_provider_admission_bound",
    "strict_live_runner_decision_and_ground_truth_non_disclosure_verified",
    "480_unique_task_and_provider_call_ids_verified",
    "full_480_task_offline_recovery_evidence_verified",
    "all_8_fault_scenarios_verified",
    "live_adapter_atomic_claim_and_sanitized_failure_boundary_reviewed",
    "r4_reanalysis_for_confirmatory_claim_forbidden",
    "advice_adherence_unobserved_and_not_inferred",
]
REVIEW_BOUNDARY = {
    **BASE_REVIEW_BOUNDARY,
    "prior_run_reanalysis_performed": False,
    "advice_adherence_inferred": False,
}


def build_confirmatory_review_bundle(
    *,
    bundle_id: str,
    created_at: str,
    artifacts: dict[str, dict[str, str]],
    contract: dict[str, Any],
    offline_report: dict[str, Any],
    fault_report: dict[str, Any],
    source_implementation: dict[str, Any],
    verification: dict[str, Any],
    inventory_snapshot: dict[str, int],
) -> dict[str, Any]:
    bundle = build_review_bundle(
        bundle_id=bundle_id,
        created_at=created_at,
        artifacts=artifacts,
        contract=contract,
        offline_report=offline_report,
        fault_report=fault_report,
        source_implementation=source_implementation,
        verification=verification,
        inventory_snapshot=inventory_snapshot,
    )
    bundle["schema_version"] = BUNDLE_SCHEMA
    bundle["frozen_stack"]["confirmatory_method_binding"] = copy.deepcopy(
        contract.get("confirmatory_method_binding")
    )
    bundle["review_checklist"] = copy.deepcopy(REVIEW_CHECKLIST)
    bundle["review_boundary"] = copy.deepcopy(REVIEW_BOUNDARY)
    bundle["bundle_sha256"] = canonical_sha256(
        {key: value for key, value in bundle.items() if key != "bundle_sha256"}
    )
    failures = validate_confirmatory_review_bundle(bundle)
    if failures:
        raise ValueError(f"confirmatory review bundle invalid: {failures}")
    return bundle


def validate_confirmatory_review_bundle(value: Any) -> list[str]:
    bundle = value if isinstance(value, dict) else {}
    normalized = copy.deepcopy(bundle)
    normalized["schema_version"] = BASE_BUNDLE_SCHEMA
    normalized.get("frozen_stack", {}).pop("confirmatory_method_binding", None)
    normalized["review_checklist"] = copy.deepcopy(BASE_REVIEW_CHECKLIST)
    normalized["review_boundary"] = copy.deepcopy(BASE_REVIEW_BOUNDARY)
    normalized["bundle_sha256"] = canonical_sha256(
        {key: item for key, item in normalized.items() if key != "bundle_sha256"}
    )
    failures = validate_review_bundle(normalized)
    method = bundle.get("frozen_stack", {}).get("confirmatory_method_binding", {})
    _require(
        bundle.get("schema_version") == BUNDLE_SCHEMA
        and bundle.get("review_checklist") == REVIEW_CHECKLIST
        and bundle.get("review_boundary") == REVIEW_BOUNDARY,
        "confirmatory_review_contract_invalid",
        failures,
    )
    _require(
        _sha256(method.get("method_sha256"))
        and _sha256(method.get("promotion_gate_sha256"))
        and _sha256(method.get("consent_gate_sha256"))
        and method.get("prior_run_reanalysis_allowed") is False
        and method.get("advice_adherence_inference_allowed") is False
        and method.get("test", {}).get("assignment_count") == 1_048_576
        and method.get("multiplicity", {}).get("method") == "holm_step_down",
        "confirmatory_review_method_binding_invalid",
        failures,
    )
    body = {key: item for key, item in bundle.items() if key != "bundle_sha256"}
    _require(
        bundle.get("bundle_sha256") == canonical_sha256(body),
        "confirmatory_review_hash_invalid",
        failures,
    )
    return list(dict.fromkeys(failures))


def build_confirmatory_review_request(
    *,
    request_id: str,
    created_at: str,
    bundle_path: str,
    bundle_raw_sha256: str,
    bundle: dict[str, Any],
) -> dict[str, Any]:
    request = build_review_request(
        request_id=request_id,
        created_at=created_at,
        bundle_path=bundle_path,
        bundle_raw_sha256=bundle_raw_sha256,
        bundle=bundle,
    )
    request["schema_version"] = REQUEST_SCHEMA
    request["required_checklist"] = copy.deepcopy(REVIEW_CHECKLIST)
    request["allowed_decision"] = (
        "approve_outcome_sensitive_prospective_confirmatory_execution_stack"
    )
    request["review_boundary"] = copy.deepcopy(REVIEW_BOUNDARY)
    request["request_sha256"] = canonical_sha256(
        {key: value for key, value in request.items() if key != "request_sha256"}
    )
    return request


def reviewer_approval_statement(
    *,
    request_raw_sha256: str,
    bundle_raw_sha256: str,
    bundle: dict[str, Any],
) -> str:
    frozen = bundle["frozen_stack"]
    method = frozen["confirmatory_method_binding"]
    return (
        "I have independently reviewed J1-D outcome-sensitive prospective "
        f"confirmatory execution review request raw SHA-256 {request_raw_sha256} "
        "and choose approve_outcome_sensitive_prospective_confirmatory_execution_"
        "stack. I confirm all 14 required checklist items, disclose all conflicts, "
        "affirm that I am independent from candidate authoring and have completed "
        "human review. I approve only copy-on-write promotion of review bundle raw "
        f"SHA-256 {bundle_raw_sha256}, canonical SHA-256 {bundle['bundle_sha256']}, "
        f"binding execution contract {frozen['execution_contract_sha256']}, exact "
        f"paired method {method['method_sha256']}, full 480-task offline recovery "
        "evidence, the outcome-specific sealed runner, live adapter, atomic claim "
        "entry, sanitized failure boundary, strict structured participant decisions "
        "and direct behavior observations, and the 8-scenario fault matrix. I "
        "acknowledge that r4 remains immutable and cannot be reanalyzed for a "
        "confirmatory claim, advice adherence remains unobserved and may not be "
        "inferred, and a new single-use execution preflight and authorization remain "
        "required before any real execution. This approval does not start a "
        "participant container, read a provider credential, call a provider or "
        "model, execute an Agent or task, append Backend Facts, append the Ledger, "
        "issue or consume an execution authorization, authorize an effectiveness or "
        "causal claim, or upgrade SI-13 maturity."
    )


def validate_evidence_schemas(
    *,
    contract: dict[str, Any],
    offline_report: dict[str, Any],
    fault_report: dict[str, Any],
) -> bool:
    return (
        contract.get("schema_version") == CONTRACT_SCHEMA
        and offline_report.get("schema_version") == OFFLINE_REPORT_SCHEMA
        and fault_report.get("schema_version") == FAULT_REPORT_SCHEMA
    )


def _sha256(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


def _require(condition: bool, reason: str, failures: list[str]) -> None:
    if not condition and reason not in failures:
        failures.append(reason)
