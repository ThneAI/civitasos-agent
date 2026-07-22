"""Copy-on-write protocol/design amendment materials for J1-D migration."""

from __future__ import annotations

import copy
from typing import Any

from .controlled_comparison import canonical_sha256


PROTOCOL_SCHEMA = "j1-qualification-protocol-amendment:v1"
DESIGN_SCHEMA = "j1-qualification-execution-design-amendment:v1"
BUNDLE_SCHEMA = "j1-qualification-protocol-design-amendment-bundle:v1"
MATERIAL_STATUS = "reviewed_plan_derived_consent_extension_required"
EXECUTION_BOUNDARY = {
    "amendment_material_generation_only": True,
    "participant_consent_migrated": False,
    "roster_rebound": False,
    "assignment_rebound": False,
    "infrastructure_rebound": False,
    "container_created": False,
    "container_started": False,
    "provider_api_call_performed": False,
    "model_invocation_performed": False,
    "agent_execution_performed": False,
    "backend_fact_append_performed": False,
    "ledger_append_performed": False,
    "execution_authorization_issued": False,
}


def build_protocol_amendment(
    *,
    created_at: str,
    source_binding: dict[str, str],
    base_protocol: dict[str, Any],
    reviewed_corpus_v2: dict[str, Any],
    reviewed_verifier_v2: dict[str, Any],
    reviewed_migration_plan: dict[str, Any],
) -> dict[str, Any]:
    frozen_stack = copy.deepcopy(base_protocol["frozen_stack"])
    frozen_stack["verifier_id"] = reviewed_verifier_v2["verifier_id"]
    frozen_stack["verifier_manifest_sha256"] = reviewed_verifier_v2[
        "manifest_sha256"
    ]
    value = {
        "schema_version": PROTOCOL_SCHEMA,
        "status": MATERIAL_STATUS,
        "amendment_id": reviewed_migration_plan["amendment_id"],
        "created_at": created_at,
        "source_binding": source_binding,
        "base_protocol": {
            "canonical_sha256": canonical_sha256(base_protocol),
            "immutable": True,
        },
        "preserved_protocol": {
            "experiment_id": base_protocol["experiment_id"],
            "hypothesis": base_protocol["hypothesis"],
            "analysis": copy.deepcopy(base_protocol["analysis"]),
            "minimum_completed_pairs": base_protocol["minimum_completed_pairs"],
            "metric_definitions_sha256": base_protocol[
                "metric_definitions_sha256"
            ],
            "task_corpus": copy.deepcopy(base_protocol["task_corpus"]),
        },
        "amended_frozen_stack": frozen_stack,
        "verifier_v2": {
            "verifier_id": reviewed_verifier_v2["verifier_id"],
            "manifest_sha256": reviewed_verifier_v2["manifest_sha256"],
            "corpus_id": reviewed_corpus_v2["corpus_id"],
            "corpus_tasks_sha256": reviewed_corpus_v2["tasks_sha256"],
            "operator_review": copy.deepcopy(
                reviewed_verifier_v2["operator_review"]
            ),
        },
        "cohort_contract": copy.deepcopy(
            reviewed_verifier_v2["cohort_contract"]
        ),
        "cohort_event_contracts": copy.deepcopy(
            reviewed_migration_plan["cohort_event_contracts"]
        ),
        "consent_contract": _consent_contract(),
        "required_gate_sequence": copy.deepcopy(
            reviewed_migration_plan["required_gate_sequence"]
        ),
        "execution_boundary": copy.deepcopy(EXECUTION_BOUNDARY),
    }
    value["amended_protocol_sha256"] = canonical_sha256(value)
    return value


def build_design_amendment(
    *,
    created_at: str,
    source_binding: dict[str, str],
    base_reviewed_design: dict[str, Any],
    signed_advice_manifest: dict[str, Any],
    reviewed_migration_plan: dict[str, Any],
) -> dict[str, Any]:
    base_tasks = {
        item["task_id"]: item
        for item in base_reviewed_design["treatment"]["tasks"]
    }
    task_contracts = []
    for contract in reviewed_migration_plan["cohort_event_contracts"]:
        base_task = base_tasks[contract["task_id"]]
        task_contracts.append(
            {
                "task_id": contract["task_id"],
                "task_input_sha256": contract["task_input_sha256"],
                "verifier_case": contract["verifier_case"],
                "shared_outcome_assertions": copy.deepcopy(
                    contract["shared_outcome_assertions"]
                ),
                "mentor": {
                    **copy.deepcopy(contract["mentor"]),
                    "advice_template": base_task["mentor_condition"][
                        "advice_template"
                    ],
                    "base_event_script_unchanged": (
                        contract["mentor"]["event_script"]
                        == base_task["event_script"]
                    ),
                },
                "control": {
                    **copy.deepcopy(contract["control"]),
                    "advice_projection": [],
                },
            }
        )
    value = {
        "schema_version": DESIGN_SCHEMA,
        "status": MATERIAL_STATUS,
        "amendment_id": reviewed_migration_plan["amendment_id"],
        "created_at": created_at,
        "source_binding": source_binding,
        "base_reviewed_design": {
            "canonical_sha256": base_reviewed_design["reviewed_design_sha256"],
            "immutable": True,
        },
        "task_contracts": task_contracts,
        "preserved_provider_call": copy.deepcopy(
            base_reviewed_design["provider_call"]
        ),
        "preserved_event_evidence": copy.deepcopy(
            base_reviewed_design["event_evidence"]
        ),
        "preserved_pricing": copy.deepcopy(base_reviewed_design["pricing"]),
        "preserved_budget_reservation": copy.deepcopy(
            base_reviewed_design["budget_reservation"]
        ),
        "signed_advice_parent": {
            "manifest_sha256": signed_advice_manifest["manifest_sha256"],
            "signed_advice_count": len(signed_advice_manifest["signed_advice"]),
            "reuse_mode": "immutable_parent_evidence",
            "runtime_binding_requires_downstream_rebind_gate": True,
        },
        "consent_contract": _consent_contract(),
        "execution_boundary": copy.deepcopy(EXECUTION_BOUNDARY),
    }
    value["amended_design_sha256"] = canonical_sha256(value)
    return value


def build_amendment_bundle(
    *,
    created_at: str,
    source_binding: dict[str, str],
    protocol_amendment_artifact: dict[str, str],
    protocol_amendment: dict[str, Any],
    design_amendment_artifact: dict[str, str],
    design_amendment: dict[str, Any],
    reviewed_migration_plan: dict[str, Any],
    implementation: dict[str, str],
) -> dict[str, Any]:
    value = {
        "schema_version": BUNDLE_SCHEMA,
        "status": MATERIAL_STATUS,
        "amendment_id": reviewed_migration_plan["amendment_id"],
        "created_at": created_at,
        "source_binding": source_binding,
        "protocol_amendment": {
            **protocol_amendment_artifact,
            "canonical_sha256": protocol_amendment["amended_protocol_sha256"],
        },
        "design_amendment": {
            **design_amendment_artifact,
            "canonical_sha256": design_amendment["amended_design_sha256"],
        },
        "inventory": copy.deepcopy(reviewed_migration_plan["inventory"]),
        "completed_prerequisites": {
            "verifier_v2_operator_reviewed": True,
            "migration_plan_operator_reviewed": True,
            "protocol_design_amendment_materials_generated": True,
        },
        "blockers": [
            "participant_consent_extension_required",
            "roster_assignment_infrastructure_rebind_required",
        ],
        "readiness": {
            "protocol_design_amendment_materials_ready": True,
            "participant_consent_extensions_complete": False,
            "downstream_bindings_refreshed": False,
            "controlled_experiment_execution_ready": False,
        },
        "implementation": implementation,
        "execution_boundary": copy.deepcopy(EXECUTION_BOUNDARY),
    }
    value["bundle_sha256"] = canonical_sha256(value)
    return value


def validate_protocol_amendment(value: Any, **inputs: Any) -> list[str]:
    expected = build_protocol_amendment(**inputs)
    return _validate_exact(value, expected, "protocol_amendment")


def validate_design_amendment(value: Any, **inputs: Any) -> list[str]:
    expected = build_design_amendment(**inputs)
    failures = _validate_exact(value, expected, "design_amendment")
    design = value if isinstance(value, dict) else {}
    tasks = design.get("task_contracts")
    task_values = tasks if isinstance(tasks, list) else []
    if not (
        len(task_values) == 8
        and all(item.get("mentor", {}).get("base_event_script_unchanged") is True for item in task_values)
        and all(item.get("control", {}).get("advice_projection") == [] for item in task_values)
    ):
        failures.append("design_amendment_cohort_contract_invalid")
    return list(dict.fromkeys(failures))


def validate_amendment_bundle(value: Any, **inputs: Any) -> list[str]:
    expected = build_amendment_bundle(**inputs)
    return _validate_exact(value, expected, "amendment_bundle")


def _consent_contract() -> dict[str, Any]:
    return {
        "prior_consent_inherited": False,
        "participant_consent_extension_required": True,
        "required_participant_count": 40,
        "consent_must_bind_bundle_sha256": True,
        "participant_substitution_requires_new_review": True,
    }


def _validate_exact(value: Any, expected: dict[str, Any], label: str) -> list[str]:
    actual = value if isinstance(value, dict) else {}
    failures = []
    if actual != expected:
        failures.append(f"{label}_copy_on_write_binding_invalid")
    hash_field = {
        "protocol_amendment": "amended_protocol_sha256",
        "design_amendment": "amended_design_sha256",
        "amendment_bundle": "bundle_sha256",
    }[label]
    body = {key: item for key, item in actual.items() if key != hash_field}
    if actual.get(hash_field) != canonical_sha256(body):
        failures.append(f"{label}_hash_invalid")
    return failures
