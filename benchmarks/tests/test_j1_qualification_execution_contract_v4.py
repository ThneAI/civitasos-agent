from __future__ import annotations

import copy
import hashlib

from benchmarks.j1.qualification_execution_contract_v4 import (
    EXECUTION_BOUNDARY,
    SOURCE_NAMES,
    build_execution_contract,
    validate_execution_contract,
)


NOW = "2026-07-25T08:00:00+00:00"
IMPLEMENTATION = {
    "source_revision": "a" * 40,
    "domain_source_sha256": "b" * 64,
    "operation_source_sha256": "c" * 64,
}


def _sources() -> tuple[dict, dict, dict, dict, dict]:
    tasks = []
    for index in range(8):
        task_id = f"task-{index:02d}"
        tasks.append(
            {
                "task_id": task_id,
                "task_input_sha256": hashlib.sha256(task_id.encode()).hexdigest(),
                "verifier_case": f"case-{index:02d}",
                "mentor": {"event_script": ["advice_loaded", "decision"]},
                "control": {"event_script": ["advice_absent", "decision"]},
            }
        )
    design = {
        "task_contracts": tasks,
        "preserved_provider_call": {
            "provider_id": "openai_compatible",
            "model_id": "deepseek-v4-pro",
            "temperature": 0,
            "max_input_utf8_bytes": 1500,
            "max_output_tokens": 1000,
            "reserved_total_tokens_per_call": 2500,
        },
        "preserved_budget_reservation": {
            "per_call_max_microunits": 1523,
            "aggregate_reserved_tokens": 800000,
            "aggregate_reserved_microunits": 487360,
        },
    }
    assignments = []
    participants = []
    containers = []
    advice = []
    for pair_index in range(20):
        pair_id = f"pair-{pair_index:02d}"
        pair = {"pair_id": pair_id}
        for cohort in ("mentor", "control"):
            participant_id = f"{cohort}-{pair_index:02d}"
            did = f"did:civ:test:{participant_id}"
            pair[cohort] = {"participant_id": participant_id, "execution_did": did}
            participants.append(
                {
                    "participant_id": participant_id,
                    "execution_did": did,
                    "credential_version": 1,
                }
            )
            containers.append(
                {
                    "participant_id": participant_id,
                    "container": {
                        "container_id": hashlib.sha256(
                            participant_id.encode()
                        ).hexdigest(),
                        "container_name": f"container-{participant_id}",
                        "image_id": "sha256:" + "d" * 64,
                        "runtime_boundary": {"network_mode": "none"},
                    },
                }
            )
            if cohort == "mentor":
                for task in tasks:
                    key = f"{participant_id}:{task['task_id']}"
                    advice.append(
                        {
                            "participant_id": participant_id,
                            "task_id": task["task_id"],
                            "advice_id": f"advice-{key}",
                            "sha256": hashlib.sha256(f"raw:{key}".encode()).hexdigest(),
                            "canonical_sha256": hashlib.sha256(
                                f"canonical:{key}".encode()
                            ).hexdigest(),
                        }
                    )
        assignments.append(pair)
    return (
        design,
        {"participants": participants},
        {"assignments": assignments},
        {"signed_advice": advice},
        {"containers": containers},
    )


def _refs() -> dict[str, dict[str, str]]:
    return {
        name: {
            "path": f"/private/{name}.json",
            "sha256": hashlib.sha256(f"raw:{name}".encode()).hexdigest(),
            "canonical_sha256": hashlib.sha256(
                f"canonical:{name}".encode()
            ).hexdigest(),
        }
        for name in SOURCE_NAMES
    }


def _contract() -> tuple[dict, tuple[dict, dict, dict, dict, dict]]:
    sources = _sources()
    contract = build_execution_contract(
        contract_id="j1d-r4-execution-contract-r1",
        created_at=NOW,
        source_artifacts=_refs(),
        amended_design=sources[0],
        rebound_roster=sources[1],
        rebound_assignment=sources[2],
        signed_advice_manifest=sources[3],
        infrastructure_activation=sources[4],
        implementation=IMPLEMENTATION,
    )
    return contract, sources


def _validate(contract: dict, sources: tuple[dict, dict, dict, dict, dict]) -> list[str]:
    return validate_execution_contract(
        contract,
        amended_design=sources[0],
        rebound_roster=sources[1],
        rebound_assignment=sources[2],
        signed_advice_manifest=sources[3],
        infrastructure_activation=sources[4],
        expected_source_artifacts=_refs(),
        expected_implementation=IMPLEMENTATION,
    )


def test_contract_freezes_exact_320_unique_task_and_call_ids() -> None:
    contract, sources = _contract()

    assert _validate(contract, sources) == []
    assert len(contract["task_executions"]) == 320
    assert len({item["task_execution_id"] for item in contract["task_executions"]}) == 320
    assert len({item["call_id"] for item in contract["task_executions"]}) == 320
    assert contract["execution_boundary"] == EXECUTION_BOUNDARY
    assert sum(
        item["advice"]["mode"] == "mentor_signed"
        for item in contract["task_executions"]
    ) == 160
    assert sum(
        item["advice"]["mode"] == "control_empty"
        for item in contract["task_executions"]
    ) == 160


def test_dispatch_ambiguity_is_terminal_and_never_retried() -> None:
    contract, _ = _contract()

    state = contract["state_machine"]
    recovery = contract["recovery_contract"]
    assert state["unknown_provider_outcome_is_terminal"] is True
    assert state["automatic_retry_allowed"] is False
    assert recovery["dispatch_intent_committed_without_provider_response"] == (
        "mark_provider_outcome_unknown_do_not_retry"
    )
    assert contract["budget_contract"]["provider_outcome_unknown_policy"] == (
        "retain_full_reservation_and_signed_closeout"
    )


def test_contract_rejects_task_manifest_or_boundary_tamper() -> None:
    contract, sources = _contract()
    tampered = copy.deepcopy(contract)
    tampered["task_executions"][0]["call_id"] = "duplicate"
    tampered["execution_boundary"]["provider_api_call_performed"] = True

    failures = _validate(tampered, sources)
    assert "r4_contract_task_manifest_invalid" in failures
    assert "r4_contract_boundary_invalid" in failures
    assert "r4_contract_hash_invalid" in failures


def test_contract_requires_signed_closeout_for_every_terminal_run() -> None:
    contract, _ = _contract()

    terminal = contract["run_terminal_contract"]
    assert terminal["allowed_states"] == ["complete", "failed", "aborted"]
    assert terminal["operator_closeout_signature_required"] is True
    assert terminal["claimed_authorization_reusable"] is False
    assert terminal["failed_or_aborted"]["all_320_task_executions_accounted"] is True
