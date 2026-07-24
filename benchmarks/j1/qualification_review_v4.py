"""Independent-review packet contracts for the J1-D r4 execution stack."""

from __future__ import annotations

import copy
from datetime import datetime
from typing import Any

from .controlled_comparison import canonical_sha256


BUNDLE_SCHEMA = "j1-qualification-r4-review-bundle:v1"
REQUEST_SCHEMA = "j1-qualification-r4-review-request:v1"
CHECKLIST = [
    "frozen_sources_and_320_task_manifest_verified",
    "deterministic_unique_task_and_call_ids_verified",
    "state_machine_and_terminal_transitions_verified",
    "provider_dispatch_ambiguity_fail_stop_verified",
    "journal_hash_chain_and_fsync_boundary_verified",
    "budget_reservation_reconciliation_and_overrun_verified",
    "participant_pkcs11_signature_boundary_verified",
    "container_and_private_workspace_isolation_verified",
    "all_run_terminal_states_require_signed_closeout",
    "full_320_task_offline_orchestrator_evidence_verified",
    "all_8_fault_matrix_scenarios_verified",
    "no_real_execution_or_effectiveness_claim_authorized",
]
BOUNDARY = {
    "review_material_generation_only": True,
    "execution_contract_promoted": False,
    "participant_container_started": False,
    "provider_credential_read": False,
    "provider_api_call_performed": False,
    "model_invocation_performed": False,
    "pkcs11_signature_performed": False,
    "backend_fact_append_performed": False,
    "ledger_append_performed": False,
    "execution_authorization_issued_or_consumed": False,
    "effectiveness_claim_authorized": False,
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
    inventory_snapshot: dict[str, Any],
) -> dict[str, Any]:
    value = {
        "schema_version": BUNDLE_SCHEMA,
        "bundle_id": bundle_id,
        "status": "independent_review_required",
        "created_at": created_at,
        "artifacts": copy.deepcopy(artifacts),
        "contract_summary": {
            "contract_sha256": contract.get("contract_sha256"),
            "source_revision": contract.get("implementation", {}).get(
                "source_revision"
            ),
            "task_execution_count": contract.get("scope", {}).get(
                "task_execution_count"
            ),
            "provider_call_count": contract.get("scope", {}).get(
                "provider_call_count"
            ),
            "unknown_provider_outcome_is_terminal": contract.get(
                "state_machine", {}
            ).get("unknown_provider_outcome_is_terminal"),
            "automatic_provider_retry": contract.get("recovery_contract", {}).get(
                "automatic_provider_retry"
            ),
            "signed_closeout_required": contract.get(
                "run_terminal_contract", {}
            ).get("operator_closeout_signature_required"),
        },
        "offline_evidence_summary": {
            "status": offline_report.get("status"),
            "task_states": copy.deepcopy(
                offline_report.get("journal", {}).get("task_states")
            ),
            "budget_states": copy.deepcopy(
                offline_report.get("journal", {}).get("budget_states")
            ),
            "event_count": offline_report.get("journal", {}).get("event_count"),
            "fault_matrix_passed": fault_report.get("passed"),
            "fault_scenario_count": fault_report.get("scenario_count"),
        },
        "known_limitations": [
            (
                "provider_exactly_once_cannot_be_proven_after_dispatch_without_"
                "provider_idempotency_or_a_committed_response"
            ),
            "offline_adapter_results_are_not_model_or_agent_effectiveness_evidence",
            "softhsm_is_not_physical_hsm_or_production_custody",
            "real_provider_container_and_pkcs11_paths_remain_unexecuted_in_r4_d",
        ],
        "review_checklist": CHECKLIST,
        "source_implementation": copy.deepcopy(source_implementation),
        "verification": copy.deepcopy(verification),
        "inventory_snapshot": copy.deepcopy(inventory_snapshot),
        "promotion_contract": {
            "copy_on_write_only": True,
            "independent_human_review_required": True,
            "all_checklist_items_required": True,
            "conflicts_disclosed": True,
            "reviewer_signature_required": True,
            "promotion_gate_required": True,
            "candidate_artifacts_immutable": True,
            "provider_refresh_required_after_promotion": True,
            "new_single_use_execution_authorization_required": True,
        },
        "execution_boundary": copy.deepcopy(BOUNDARY),
    }
    value["bundle_sha256"] = canonical_sha256(value)
    failures = validate_review_bundle(value)
    if failures:
        raise ValueError(f"r4 review bundle invalid: {failures}")
    return value


def validate_review_bundle(value: Any) -> list[str]:
    bundle = value if isinstance(value, dict) else {}
    failures: list[str] = []
    _require(
        bundle.get("schema_version") == BUNDLE_SCHEMA
        and bundle.get("status") == "independent_review_required"
        and _text(bundle.get("bundle_id"))
        and _rfc3339(bundle.get("created_at")),
        "r4_review_bundle_identity_invalid",
        failures,
    )
    artifacts = bundle.get("artifacts")
    artifacts = artifacts if isinstance(artifacts, dict) else {}
    _require(
        set(artifacts)
        == {
            "execution_contract",
            "offline_orchestrator_report",
            "offline_execution_journal",
            "fault_matrix_report",
        }
        and all(_artifact_ref(item) for item in artifacts.values()),
        "r4_review_bundle_artifacts_invalid",
        failures,
    )
    summary = bundle.get("contract_summary")
    _require(
        isinstance(summary, dict)
        and summary.get("task_execution_count") == 320
        and summary.get("provider_call_count") == 320
        and summary.get("unknown_provider_outcome_is_terminal") is True
        and summary.get("automatic_provider_retry") is False
        and summary.get("signed_closeout_required") is True,
        "r4_review_bundle_contract_summary_invalid",
        failures,
    )
    offline = bundle.get("offline_evidence_summary")
    _require(
        offline
        == {
            "status": "complete",
            "task_states": {"task_committed": 320},
            "budget_states": {"reconciled": 320},
            "event_count": 3840,
            "fault_matrix_passed": True,
            "fault_scenario_count": 8,
        },
        "r4_review_bundle_offline_evidence_invalid",
        failures,
    )
    _require(
        bundle.get("review_checklist") == CHECKLIST,
        "r4_review_bundle_checklist_invalid",
        failures,
    )
    verification = bundle.get("verification")
    _require(
        isinstance(verification, dict)
        and verification.get("ruff_all_passed") is True
        and verification.get("pytest_all_passed") is True
        and verification.get("pytest_passed_count") >= 1447
        and verification.get("journal_artifact_hash_recomputed") is True
        and verification.get("remote_revision_verified") is True,
        "r4_review_bundle_verification_invalid",
        failures,
    )
    inventory = bundle.get("inventory_snapshot")
    _require(
        inventory
        == {
            "participant_container_count": 40,
            "created_count": 40,
            "running_count": 0,
        },
        "r4_review_bundle_inventory_invalid",
        failures,
    )
    promotion = bundle.get("promotion_contract")
    _require(
        isinstance(promotion, dict)
        and promotion
        == {
            "copy_on_write_only": True,
            "independent_human_review_required": True,
            "all_checklist_items_required": True,
            "conflicts_disclosed": True,
            "reviewer_signature_required": True,
            "promotion_gate_required": True,
            "candidate_artifacts_immutable": True,
            "provider_refresh_required_after_promotion": True,
            "new_single_use_execution_authorization_required": True,
        },
        "r4_review_bundle_promotion_invalid",
        failures,
    )
    _require(
        bundle.get("execution_boundary") == BOUNDARY,
        "r4_review_bundle_boundary_invalid",
        failures,
    )
    body = {key: item for key, item in bundle.items() if key != "bundle_sha256"}
    _require(
        bundle.get("bundle_sha256") == canonical_sha256(body),
        "r4_review_bundle_hash_invalid",
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
    statement = reviewer_approval_statement(
        request_raw_sha256="{REQUEST_RAW_SHA256}",
        bundle_raw_sha256=bundle_raw_sha256,
        bundle=bundle,
    )
    value = {
        "schema_version": REQUEST_SCHEMA,
        "request_id": request_id,
        "status": "independent_reviewer_decision_required",
        "created_at": created_at,
        "bundle": {
            "path": bundle_path,
            "sha256": bundle_raw_sha256,
            "canonical_sha256": bundle["bundle_sha256"],
        },
        "required_checklist": CHECKLIST,
        "allowed_decisions": ["approve_r4_execution_stack", "reject_r4_execution_stack"],
        "reviewer_requirements": {
            "independent_from_candidate_authoring": True,
            "human_review_completed": True,
            "all_conflicts_disclosed": True,
            "all_checklist_items_explicitly_confirmed_for_approval": True,
        },
        "approval_statement_template": statement,
        "execution_boundary": copy.deepcopy(BOUNDARY),
    }
    value["request_sha256"] = canonical_sha256(value)
    return value


def reviewer_approval_statement(
    *,
    request_raw_sha256: str,
    bundle_raw_sha256: str,
    bundle: dict[str, Any],
) -> str:
    return (
        "I have independently reviewed J1-D r4 execution review request raw SHA-256 "
        f"{request_raw_sha256} and choose approve_r4_execution_stack. I confirm all "
        f"{len(CHECKLIST)} required checklist items, disclose all conflicts, affirm "
        "that I am independent from candidate authoring and have completed human "
        "review. I approve only copy-on-write promotion of review bundle raw SHA-256 "
        f"{bundle_raw_sha256}, canonical SHA-256 {bundle['bundle_sha256']}, binding "
        f"execution contract {bundle['contract_summary']['contract_sha256']}, full "
        "320-task offline recovery evidence, and the 8-scenario fault matrix. I "
        "acknowledge that provider refresh, real container/provider/PKCS#11 execution, "
        "and a new single-use execution authorization remain required. This approval "
        "does not start a participant container, read a provider credential, call a "
        "provider or model, execute an Agent or experiment, append Backend Facts, "
        "append the Ledger, issue or consume an execution authorization, or authorize "
        "an effectiveness claim."
    )


def _artifact_ref(value: Any) -> bool:
    item = value if isinstance(value, dict) else {}
    return (
        set(item) == {"path", "sha256", "canonical_sha256"}
        and str(item.get("path", "")).startswith("/")
        and all(_sha256(item.get(field)) for field in ("sha256", "canonical_sha256"))
    )


def _rfc3339(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None


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
