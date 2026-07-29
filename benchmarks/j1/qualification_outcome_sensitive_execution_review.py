"""Independent-review contracts for the outcome-sensitive execution stack."""

from __future__ import annotations

import copy
from datetime import datetime
from typing import Any

from .controlled_comparison import canonical_sha256
from .qualification_outcome_sensitive_execution_contract import (
    CONTRACT_SCHEMA,
    TASK_EXECUTION_COUNT,
)
from .qualification_outcome_sensitive_fault_matrix import (
    REPORT_SCHEMA as FAULT_REPORT_SCHEMA,
)
from .qualification_outcome_sensitive_orchestrator import (
    REPORT_SCHEMA as OFFLINE_REPORT_SCHEMA,
)


BUNDLE_SCHEMA = "j1-qualification-outcome-sensitive-execution-review-bundle:v1"
REQUEST_SCHEMA = "j1-qualification-outcome-sensitive-execution-review-request:v1"
REVIEW_CHECKLIST = [
    "all_21_source_artifact_hashes_replayed",
    "outcome_protocol_evaluator_fixture_and_statistical_plan_bound",
    "40_of_40_outcome_sensitive_consent_gate_bound",
    "40_participants_20_pairs_480_decisions_bound",
    "180_mentor_advice_and_empty_control_projection_bound",
    "40_created_0_running_infrastructure_bound",
    "single_use_live_provider_admission_receipt_bound",
    "strict_decision_and_ground_truth_non_disclosure_verified",
    "480_unique_task_and_provider_call_ids_verified",
    "full_480_task_offline_recovery_evidence_verified",
    "all_8_fault_scenarios_verified",
    "no_external_execution_effect_boundary_verified",
]
REVIEW_BOUNDARY = {
    "independent_review_only": True,
    "execution_stack_promoted": False,
    "execution_authorization_issued_or_consumed": False,
    "participant_container_started": False,
    "provider_credential_read": False,
    "provider_api_call_performed": False,
    "model_invocation_performed": False,
    "agent_or_task_execution_performed": False,
    "participant_signature_performed": False,
    "backend_fact_append_performed": False,
    "ledger_append_performed": False,
    "effectiveness_claim_authorized": False,
    "si13_maturity_upgrade_authorized": False,
}


def build_review_bundle(
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
    value = {
        "schema_version": BUNDLE_SCHEMA,
        "bundle_id": bundle_id,
        "status": "independent_human_review_required",
        "created_at": created_at,
        "artifacts": copy.deepcopy(artifacts),
        "frozen_stack": {
            "execution_contract_sha256": contract.get("contract_sha256"),
            "provider_admission_receipt_sha256": contract.get(
                "provider_admission", {}
            ).get("receipt_sha256"),
            "provider_admission_gate_sha256": contract.get(
                "provider_admission", {}
            ).get("gate_sha256"),
            "scope": copy.deepcopy(contract.get("scope")),
            "structured_decision_contract": copy.deepcopy(
                contract.get("structured_decision_contract")
            ),
            "direct_observation_contract": copy.deepcopy(
                contract.get("direct_observation_contract")
            ),
            "treatment_contract": copy.deepcopy(contract.get("treatment_contract")),
            "recovery_contract": copy.deepcopy(contract.get("recovery_contract")),
        },
        "offline_recovery_evidence": {
            "status": offline_report.get("status"),
            "task_states": copy.deepcopy(
                offline_report.get("journal", {}).get("task_states")
            ),
            "budget_states": copy.deepcopy(
                offline_report.get("journal", {}).get("budget_states")
            ),
            "event_count": offline_report.get("journal", {}).get("event_count"),
            "provider_call_count": offline_report.get("offline_scope", {}).get(
                "provider_call_count"
            ),
            "participant_signature_count": offline_report.get(
                "offline_scope", {}
            ).get("participant_signature_count"),
            "validation_failures": copy.deepcopy(
                offline_report.get("validation_failures")
            ),
        },
        "fault_matrix": {
            "passed": fault_report.get("passed"),
            "scenario_count": fault_report.get("scenario_count"),
            "scenarios": [
                item.get("scenario")
                for item in fault_report.get("results", [])
                if isinstance(item, dict)
            ],
        },
        "inventory_snapshot": copy.deepcopy(inventory_snapshot),
        "review_checklist": copy.deepcopy(REVIEW_CHECKLIST),
        "source_implementation": copy.deepcopy(source_implementation),
        "verification": copy.deepcopy(verification),
        "review_boundary": copy.deepcopy(REVIEW_BOUNDARY),
    }
    value["bundle_sha256"] = canonical_sha256(value)
    failures = validate_review_bundle(value)
    if failures:
        raise ValueError(
            f"outcome-sensitive execution review bundle invalid: {failures}"
        )
    return value


def validate_review_bundle(value: Any) -> list[str]:
    bundle = value if isinstance(value, dict) else {}
    failures: list[str] = []
    _require(
        bundle.get("schema_version") == BUNDLE_SCHEMA
        and bundle.get("status") == "independent_human_review_required"
        and _text(bundle.get("bundle_id"))
        and _rfc3339(bundle.get("created_at")),
        "outcome_execution_review_identity_invalid",
        failures,
    )
    artifacts = bundle.get("artifacts", {})
    _require(
        set(artifacts)
        == {
            "execution_contract",
            "offline_orchestrator_report",
            "offline_execution_journal",
            "fault_matrix_report",
        }
        and all(_artifact_ref(item) for item in artifacts.values()),
        "outcome_execution_review_artifacts_invalid",
        failures,
    )
    frozen = bundle.get("frozen_stack", {})
    scope = frozen.get("scope", {})
    _require(
        _sha256(frozen.get("execution_contract_sha256"))
        and _sha256(frozen.get("provider_admission_receipt_sha256"))
        and _sha256(frozen.get("provider_admission_gate_sha256"))
        and scope.get("participant_count") == 40
        and scope.get("matched_pair_count") == 20
        and scope.get("task_execution_count") == TASK_EXECUTION_COUNT
        and scope.get("provider_call_count") == TASK_EXECUTION_COUNT
        and scope.get("aggregate_reserved_tokens") == 1_200_000
        and scope.get("aggregate_reserved_cost_microunits") == 731_040,
        "outcome_execution_review_frozen_scope_invalid",
        failures,
    )
    offline = bundle.get("offline_recovery_evidence", {})
    _require(
        offline
        == {
            "status": "complete",
            "task_states": {"task_committed": TASK_EXECUTION_COUNT},
            "budget_states": {"reconciled": TASK_EXECUTION_COUNT},
            "event_count": TASK_EXECUTION_COUNT * 12,
            "provider_call_count": TASK_EXECUTION_COUNT,
            "participant_signature_count": TASK_EXECUTION_COUNT,
            "validation_failures": [],
        },
        "outcome_execution_review_offline_recovery_invalid",
        failures,
    )
    matrix = bundle.get("fault_matrix", {})
    _require(
        matrix.get("passed") is True
        and matrix.get("scenario_count") == 8
        and len(set(matrix.get("scenarios", []))) == 8,
        "outcome_execution_review_fault_matrix_invalid",
        failures,
    )
    inventory = bundle.get("inventory_snapshot", {})
    _require(
        inventory
        == {
            "participant_count": 40,
            "created_count": 40,
            "running_count": 0,
        },
        "outcome_execution_review_inventory_invalid",
        failures,
    )
    _require(
        bundle.get("review_checklist") == REVIEW_CHECKLIST,
        "outcome_execution_review_checklist_invalid",
        failures,
    )
    verification = bundle.get("verification", {})
    _require(
        verification.get("ruff_all_passed") is True
        and verification.get("pytest_all_passed") is True
        and isinstance(verification.get("pytest_passed_count"), int)
        and verification.get("pytest_passed_count") > 0
        and verification.get("journal_artifact_hash_recomputed") is True
        and verification.get("remote_revision_verified") is True
        and verification.get("all_source_hashes_replayed") is True,
        "outcome_execution_review_verification_invalid",
        failures,
    )
    _require(
        bundle.get("review_boundary") == REVIEW_BOUNDARY,
        "outcome_execution_review_boundary_invalid",
        failures,
    )
    body = {key: item for key, item in bundle.items() if key != "bundle_sha256"}
    _require(
        bundle.get("bundle_sha256") == canonical_sha256(body),
        "outcome_execution_review_hash_invalid",
        failures,
    )
    return list(dict.fromkeys(failures))


def build_review_request(
    *,
    request_id: str,
    created_at: str,
    bundle_path: str,
    bundle_raw_sha256: str,
    bundle: dict[str, Any],
) -> dict[str, Any]:
    value = {
        "schema_version": REQUEST_SCHEMA,
        "request_id": request_id,
        "status": "independent_reviewer_decision_required",
        "created_at": created_at,
        "review_bundle": {
            "path": bundle_path,
            "sha256": bundle_raw_sha256,
            "canonical_sha256": bundle.get("bundle_sha256"),
        },
        "required_checklist": copy.deepcopy(REVIEW_CHECKLIST),
        "allowed_decision": "approve_outcome_sensitive_execution_stack",
        "reviewer_requirements": {
            "independent_from_candidate_authoring": True,
            "human_review_completed": True,
            "conflicts_disclosed": True,
            "all_checklist_items_confirmed": True,
        },
        "review_boundary": copy.deepcopy(REVIEW_BOUNDARY),
    }
    value["request_sha256"] = canonical_sha256(value)
    return value


def reviewer_approval_statement(
    *,
    request_raw_sha256: str,
    bundle_raw_sha256: str,
    bundle: dict[str, Any],
) -> str:
    frozen = bundle["frozen_stack"]
    return (
        "I have independently reviewed J1-D outcome-sensitive execution review "
        f"request raw SHA-256 {request_raw_sha256} and choose "
        "approve_outcome_sensitive_execution_stack. I confirm all 12 required "
        "checklist items, disclose all conflicts, affirm that I am independent "
        "from candidate authoring and have completed human review. I approve only "
        f"copy-on-write promotion of review bundle raw SHA-256 {bundle_raw_sha256}, "
        f"canonical SHA-256 {bundle['bundle_sha256']}, binding execution contract "
        f"{frozen['execution_contract_sha256']}, full 480-task offline recovery "
        "evidence, strict structured participant decisions and direct behavior "
        "observations, and the 8-scenario fault matrix. I acknowledge that a new "
        "single-use execution preflight and authorization remain required before "
        "any real execution. This approval does not start a participant container, "
        "read a provider credential, call a provider or model, execute an Agent or "
        "task, append Backend Facts, append the Ledger, issue or consume an "
        "execution authorization, authorize an effectiveness claim, or upgrade "
        "SI-13 maturity."
    )


def _artifact_ref(value: Any) -> bool:
    item = value if isinstance(value, dict) else {}
    return (
        set(item) == {"path", "sha256", "canonical_sha256"}
        and str(item.get("path", "")).startswith("/")
        and _sha256(item.get("sha256"))
        and _sha256(item.get("canonical_sha256"))
    )


def _rfc3339(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return True


def _sha256(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _require(condition: bool, reason: str, failures: list[str]) -> None:
    if not condition:
        failures.append(reason)


def validate_evidence_schemas(
    *,
    contract: dict[str, Any],
    offline_report: dict[str, Any],
    fault_report: dict[str, Any],
) -> bool:
    """Expose the schema tuple used by generation and focused tests."""
    return (
        contract.get("schema_version") == CONTRACT_SCHEMA
        and offline_report.get("schema_version") == OFFLINE_REPORT_SCHEMA
        and fault_report.get("schema_version") == FAULT_REPORT_SCHEMA
    )
