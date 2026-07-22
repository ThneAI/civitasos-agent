"""J1-D participant harness and host provider-broker plan contracts."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from .controlled_comparison import canonical_sha256


PLAN_SCHEMA = "j1-qualification-execution-infrastructure-plan:v1"
REQUIRED_BLOCKERS = {
    "cohort_invariant_verifier_contract_required",
    "live_provider_admission_refresh_required",
    "participant_isolation_runner_replacement_required",
}
COHORT_SENSITIVE_VERIFIER_EXPECTATIONS = {
    "constitution-precedence": {"harmful_advice_observed": True},
    "apprentice-independent-decision": {"advice_observed": True},
}


def build_execution_infrastructure_plan(
    *,
    plan_id: str,
    created_at: str,
    source_binding: dict[str, str],
    reviewed_design: dict[str, Any],
    reviewed_assignment: dict[str, Any],
    signed_advice_manifest: dict[str, Any],
    participant_profiles: list[dict[str, Any]],
    blockers: list[str],
    implementation: dict[str, str],
    offline_readiness: dict[str, bool] | None = None,
) -> dict[str, Any]:
    profiles = {
        item["participant"]["participant_id"]: item for item in participant_profiles
    }
    advice = _advice_index(signed_advice_manifest)
    tasks = sorted(
        reviewed_design["treatment"]["tasks"], key=lambda item: item["task_id"]
    )
    participants = []
    for pair in sorted(
        reviewed_assignment["assignments"], key=lambda item: item["pair_id"]
    ):
        for cohort in ("mentor", "control"):
            assigned = pair[cohort]
            profile = profiles[assigned["participant_id"]]
            participant_advice = advice.get(assigned["participant_id"], {})
            participants.append(
                {
                    "participant_id": assigned["participant_id"],
                    "execution_did": assigned["execution_did"],
                    "pair_id": pair["pair_id"],
                    "cohort": cohort,
                    "participant_profile_sha256": profile["profile_sha256"],
                    "source_isolation": {
                        "isolation_id": profile["isolation"]["isolation_id"],
                        "container_name": profile["isolation"]["container_name"],
                        "container_config_sha256": profile["isolation"][
                            "container_config_sha256"
                        ],
                        "initial_state_artifact_sha256": profile["isolation"][
                            "initial_state_artifact_sha256"
                        ],
                    },
                    "tasks": [
                        {
                            "task_id": task["task_id"],
                            "task_input_sha256": task["task_input_sha256"],
                            "verifier_case": task["verifier_case"],
                            "event_script": task["event_script"],
                            "signed_advice": (
                                participant_advice[task["task_id"]]
                                if cohort == "mentor"
                                else None
                            ),
                        }
                        for task in tasks
                    ],
                    "target_isolation": _target_isolation(),
                }
            )
    normalized_blockers = sorted(set(blockers))
    value = {
        "schema_version": PLAN_SCHEMA,
        "plan_id": plan_id,
        "status": "blocked_review_required",
        "created_at": created_at,
        "source_binding": source_binding,
        "inventory": {
            "participant_count": 40,
            "pair_count": 20,
            "mentor_participant_count": 20,
            "control_participant_count": 20,
            "task_count_per_participant": 8,
            "planned_task_execution_count": 320,
            "signed_advice_count": 160,
            "control_advice_count": 0,
        },
        "participants": participants,
        "event_harness": _event_harness(),
        "provider_broker": _provider_broker(reviewed_design),
        "blockers": normalized_blockers,
        "readiness": _readiness(offline_readiness),
        "implementation": implementation,
        "execution_boundary": {
            "plan_only": True,
            "container_created": False,
            "container_started": False,
            "provider_api_call_performed": False,
            "model_invocation_performed": False,
            "agent_execution_performed": False,
            "backend_fact_append_performed": False,
            "ledger_append_performed": False,
        },
    }
    value["plan_sha256"] = canonical_sha256(value)
    failures = validate_execution_infrastructure_plan(
        value,
        reviewed_design=reviewed_design,
        reviewed_assignment=reviewed_assignment,
        signed_advice_manifest=signed_advice_manifest,
        participant_profiles=participant_profiles,
        expected_source_binding=source_binding,
        expected_implementation=implementation,
        expected_offline_readiness=offline_readiness,
    )
    if failures:
        raise ValueError(f"execution infrastructure plan invalid: {failures}")
    return value


def validate_execution_infrastructure_plan(
    value: Any,
    *,
    reviewed_design: dict[str, Any],
    reviewed_assignment: dict[str, Any],
    signed_advice_manifest: dict[str, Any],
    participant_profiles: list[dict[str, Any]],
    expected_source_binding: dict[str, str],
    expected_implementation: dict[str, str],
    expected_offline_readiness: dict[str, bool] | None = None,
) -> list[str]:
    plan = value if isinstance(value, dict) else {}
    failures: list[str] = []
    _require(
        set(plan)
        == {
            "schema_version",
            "plan_id",
            "status",
            "created_at",
            "source_binding",
            "inventory",
            "participants",
            "event_harness",
            "provider_broker",
            "blockers",
            "readiness",
            "implementation",
            "execution_boundary",
            "plan_sha256",
        },
        "infrastructure_plan_fields_invalid",
        failures,
    )
    _require(
        plan.get("schema_version") == PLAN_SCHEMA,
        "infrastructure_plan_schema_invalid",
        failures,
    )
    _require(_text(plan.get("plan_id")), "infrastructure_plan_id_invalid", failures)
    _require(
        plan.get("status") == "blocked_review_required",
        "infrastructure_plan_status_invalid",
        failures,
    )
    _require(
        _rfc3339(plan.get("created_at")), "infrastructure_plan_time_invalid", failures
    )
    _require(
        plan.get("source_binding") == expected_source_binding,
        "infrastructure_plan_source_invalid",
        failures,
    )
    profiles = {
        item.get("participant", {}).get("participant_id"): item
        for item in participant_profiles
        if isinstance(item, dict)
    }
    assignments = {
        item[cohort]["participant_id"]: (item, cohort)
        for item in reviewed_assignment.get("assignments", [])
        if isinstance(item, dict)
        for cohort in ("mentor", "control")
    }
    advice = _advice_index(signed_advice_manifest)
    tasks = {
        item["task_id"]: item
        for item in reviewed_design.get("treatment", {}).get("tasks", [])
    }
    participants = (
        plan.get("participants") if isinstance(plan.get("participants"), list) else []
    )
    signed_items = signed_advice_manifest.get("signed_advice")
    signed_items = signed_items if isinstance(signed_items, list) else []
    signed_keys = [
        (item.get("participant_id"), item.get("task_id"))
        for item in signed_items
        if isinstance(item, dict)
    ]
    mentor_ids = {
        pair["mentor"]["participant_id"]
        for pair in reviewed_assignment.get("assignments", [])
        if isinstance(pair, dict)
    }
    _require(
        len(signed_items) == 160
        and len(set(signed_keys)) == 160
        and {participant_id for participant_id, _ in signed_keys} == mentor_ids
        and {task_id for _, task_id in signed_keys} == set(tasks),
        "infrastructure_signed_advice_inventory_invalid",
        failures,
    )
    ids: set[str] = set()
    isolation_ids: set[str] = set()
    mentor_count = 0
    control_count = 0
    for item in participants:
        participant = item if isinstance(item, dict) else {}
        participant_id = participant.get("participant_id")
        assigned = assignments.get(participant_id)
        profile = profiles.get(participant_id)
        if assigned is None or profile is None:
            failures.append("infrastructure_participant_source_missing")
            continue
        pair, cohort = assigned
        ids.add(participant_id)
        mentor_count += int(cohort == "mentor")
        control_count += int(cohort == "control")
        _require(
            participant.get("execution_did") == pair[cohort]["execution_did"]
            and participant.get("pair_id") == pair["pair_id"]
            and participant.get("cohort") == cohort
            and participant.get("participant_profile_sha256")
            == profile.get("profile_sha256"),
            "infrastructure_participant_binding_invalid",
            failures,
        )
        source_isolation = participant.get("source_isolation", {})
        isolation_ids.add(str(source_isolation.get("isolation_id") or ""))
        _require(
            source_isolation
            == {
                "isolation_id": profile["isolation"]["isolation_id"],
                "container_name": profile["isolation"]["container_name"],
                "container_config_sha256": profile["isolation"][
                    "container_config_sha256"
                ],
                "initial_state_artifact_sha256": profile["isolation"][
                    "initial_state_artifact_sha256"
                ],
            },
            "infrastructure_source_isolation_invalid",
            failures,
        )
        participant_tasks = (
            participant.get("tasks")
            if isinstance(participant.get("tasks"), list)
            else []
        )
        _require(
            len(participant_tasks) == 8,
            "infrastructure_participant_tasks_invalid",
            failures,
        )
        for task_plan in participant_tasks:
            task = (
                tasks.get(task_plan.get("task_id"))
                if isinstance(task_plan, dict)
                else None
            )
            if task is None:
                failures.append("infrastructure_task_source_missing")
                continue
            expected_advice = (
                advice.get(participant_id, {}).get(task["task_id"])
                if cohort == "mentor"
                else None
            )
            _require(
                (cohort == "mentor" and expected_advice is not None)
                or (cohort == "control" and expected_advice is None),
                "infrastructure_advice_cohort_boundary_invalid",
                failures,
            )
            _require(
                task_plan
                == {
                    "task_id": task["task_id"],
                    "task_input_sha256": task["task_input_sha256"],
                    "verifier_case": task["verifier_case"],
                    "event_script": task["event_script"],
                    "signed_advice": expected_advice,
                },
                "infrastructure_task_binding_invalid",
                failures,
            )
        _require(
            participant.get("target_isolation") == _target_isolation(),
            "infrastructure_target_isolation_invalid",
            failures,
        )
    _require(
        len(participants) == 40 and len(ids) == 40 and len(isolation_ids) == 40,
        "infrastructure_inventory_invalid",
        failures,
    )
    _require(
        mentor_count == 20 and control_count == 20,
        "infrastructure_cohort_inventory_invalid",
        failures,
    )
    _require(
        plan.get("inventory") == _inventory(),
        "infrastructure_declared_inventory_invalid",
        failures,
    )
    _require(
        plan.get("event_harness") == _event_harness(),
        "infrastructure_event_harness_invalid",
        failures,
    )
    _require(
        plan.get("provider_broker") == _provider_broker(reviewed_design),
        "infrastructure_provider_broker_invalid",
        failures,
    )
    blockers = plan.get("blockers")
    _require(
        isinstance(blockers, list) and set(blockers) == REQUIRED_BLOCKERS,
        "infrastructure_blockers_invalid",
        failures,
    )
    _require(
        plan.get("readiness") == _readiness(expected_offline_readiness),
        "infrastructure_readiness_invalid",
        failures,
    )
    _require(
        plan.get("implementation") == expected_implementation,
        "infrastructure_implementation_invalid",
        failures,
    )
    _require(
        plan.get("execution_boundary") == _execution_boundary(),
        "infrastructure_execution_boundary_invalid",
        failures,
    )
    body = {key: item for key, item in plan.items() if key != "plan_sha256"}
    _require(
        plan.get("plan_sha256") == canonical_sha256(body),
        "infrastructure_plan_hash_invalid",
        failures,
    )
    return list(dict.fromkeys(failures))


def verifier_contract_conflicts(
    reviewed_design: dict[str, Any],
) -> list[dict[str, Any]]:
    conflicts: list[dict[str, Any]] = []
    tasks = reviewed_design.get("treatment", {}).get("tasks", [])
    for task in tasks if isinstance(tasks, list) else []:
        if not isinstance(task, dict):
            continue
        case_id = task.get("verifier_case")
        expected = COHORT_SENSITIVE_VERIFIER_EXPECTATIONS.get(str(case_id))
        control = task.get("control_condition", {})
        if (
            expected
            and isinstance(control, dict)
            and control.get("advice_projection") == []
            and control.get("mentor_event_visibility") == "none"
        ):
            conflicts.append(
                {
                    "task_id": task.get("task_id"),
                    "verifier_case": case_id,
                    "affected_cohort": "control",
                    "control_advice_projection": [],
                    "verifier_requires": expected,
                    "impact": "control_task_fails_due_to_cohort_assignment",
                }
            )
    return conflicts


def _advice_index(manifest: dict[str, Any]) -> dict[str, dict[str, dict[str, str]]]:
    result: dict[str, dict[str, dict[str, str]]] = {}
    for item in manifest.get("signed_advice", []):
        participant_id = item["participant_id"]
        result.setdefault(participant_id, {})[item["task_id"]] = {
            "advice_id": item["advice_id"],
            "artifact_sha256": item["sha256"],
            "canonical_sha256": item["canonical_sha256"],
        }
    return result


def _target_isolation() -> dict[str, Any]:
    return {
        "replacement_required": True,
        "runner_image_digest_required": True,
        "runner_entrypoint": [
            "python",
            "-I",
            "-m",
            "benchmarks.j1_qualification_event_runner",
        ],
        "network_mode": "none",
        "read_only_rootfs": True,
        "cap_drop_all": True,
        "no_new_privileges": True,
        "pids_limit": 64,
        "memory_limit_bytes": 268_435_456,
        "nano_cpus": 250_000_000,
        "input_mount_read_only": True,
        "output_mount_read_write": True,
        "docker_socket_mounted": False,
        "provider_secret_available": False,
        "pkcs11_device_available": False,
    }


def _event_harness() -> dict[str, Any]:
    return {
        "event_receipt_schema": "j1-qualification-harness-event:v1",
        "hash_chain_required": True,
        "monotonic_sequence_required": True,
        "model_output_is_decision_only": True,
        "model_assertions_ignored": True,
        "assertions_derived_from_events": True,
        "participant_decision_signature_required": True,
        "restart_process_replacement_required": True,
        "revocation_fail_closed": True,
        "credential_rotation_fail_closed": True,
        "provider_network_inside_container": False,
    }


def _provider_broker(design: dict[str, Any]) -> dict[str, Any]:
    return {
        "location": "host_only",
        "provider": design["provider_call"],
        "pricing": design["pricing"],
        "budget": design["budget_reservation"],
        "secret_source": "process_environment_only",
        "secret_persisted": False,
        "secret_forwarded_to_container": False,
        "reservation_store": "sqlite_begin_immediate",
        "reservation_required_before_network_call": True,
        "usage_reconciliation_required": True,
        "provider_receipt_required": True,
        "raw_prompt_persisted": False,
        "raw_response_persisted": False,
        "request_and_response_hashes_required": True,
    }


def _inventory() -> dict[str, int]:
    return {
        "participant_count": 40,
        "pair_count": 20,
        "mentor_participant_count": 20,
        "control_participant_count": 20,
        "task_count_per_participant": 8,
        "planned_task_execution_count": 320,
        "signed_advice_count": 160,
        "control_advice_count": 0,
    }


def _readiness(offline: dict[str, bool] | None = None) -> dict[str, bool]:
    offline = offline or {}
    return {
        "offline_contract_complete": True,
        "runner_image_built": False,
        "participant_isolation_replaced": False,
        "event_harness_dry_run_passed": offline.get(
            "event_harness_dry_run_passed", False
        )
        is True,
        "provider_broker_dry_run_passed": offline.get(
            "provider_broker_dry_run_passed", False
        )
        is True,
        "live_provider_admission_bound": False,
        "controlled_experiment_execution_ready": False,
    }


def _execution_boundary() -> dict[str, bool]:
    return {
        "plan_only": True,
        "container_created": False,
        "container_started": False,
        "provider_api_call_performed": False,
        "model_invocation_performed": False,
        "agent_execution_performed": False,
        "backend_fact_append_performed": False,
        "ledger_append_performed": False,
    }


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _rfc3339(value: Any) -> bool:
    if not _text(value):
        return False
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).tzinfo is not None
    except ValueError:
        return False


def _require(condition: bool, code: str, failures: list[str]) -> None:
    if not condition and code not in failures:
        failures.append(code)
