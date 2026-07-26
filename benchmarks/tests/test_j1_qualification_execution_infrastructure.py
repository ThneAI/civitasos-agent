from __future__ import annotations

import copy
from pathlib import Path

import pytest

from benchmarks.j1.controlled_comparison import canonical_sha256
from benchmarks.j1.qualification_event_harness import (
    build_event_receipt,
    build_event_trace,
    validate_built_event_trace,
    validate_event_trace,
)
from benchmarks.j1.qualification_execution_infrastructure import (
    REQUIRED_BLOCKERS,
    build_execution_infrastructure_plan,
    validate_execution_infrastructure_plan,
    verifier_contract_conflicts,
)
from benchmarks.j1.qualification_provider_broker import (
    QualificationBudgetStore,
    execute_provider_call,
)
from benchmarks.tests.test_j1_qualification_execution_design import _design


NOW = "2026-07-22T16:00:00+00:00"
SOURCE_BINDING = {
    "reviewed_design_artifact_sha256": "1" * 64,
    "reviewed_assignment_artifact_sha256": "2" * 64,
    "signed_advice_manifest_artifact_sha256": "3" * 64,
    "participant_provisioning_report_artifact_sha256": "4" * 64,
}
IMPLEMENTATION = {"source_revision": "a" * 40, "source_sha256": "5" * 64}


def _infrastructure_sources() -> tuple[dict, dict, dict, list[dict]]:
    design, _, _, assignment = _design()
    profiles = []
    signed_advice = []
    for pair in assignment["assignments"]:
        for cohort in ("mentor", "control"):
            participant = pair[cohort]
            participant_id = participant["participant_id"]
            profiles.append(
                {
                    "participant": participant,
                    "profile_sha256": canonical_sha256(participant),
                    "isolation": {
                        "isolation_id": f"isolation-{participant_id}",
                        "container_name": f"container-{participant_id}",
                        "container_config_sha256": canonical_sha256(
                            {"participant_id": participant_id}
                        ),
                        "initial_state_artifact_sha256": canonical_sha256(
                            {"initial_state": participant_id}
                        ),
                    },
                }
            )
        mentor_id = pair["mentor"]["participant_id"]
        for task in design["treatment"]["tasks"]:
            key = f"{mentor_id}:{task['task_id']}"
            signed_advice.append(
                {
                    "participant_id": mentor_id,
                    "task_id": task["task_id"],
                    "advice_id": key,
                    "sha256": canonical_sha256({"raw": key}),
                    "canonical_sha256": canonical_sha256({"canonical": key}),
                }
            )
    return design, assignment, {"signed_advice": signed_advice}, profiles


def _plan() -> tuple[dict, dict, dict, dict, list[dict]]:
    design, assignment, advice, profiles = _infrastructure_sources()
    plan = build_execution_infrastructure_plan(
        plan_id="j1d-execution-infrastructure-20260722-r1",
        created_at=NOW,
        source_binding=SOURCE_BINDING,
        reviewed_design=design,
        reviewed_assignment=assignment,
        signed_advice_manifest=advice,
        participant_profiles=profiles,
        blockers=sorted(REQUIRED_BLOCKERS),
        implementation=IMPLEMENTATION,
    )
    return plan, design, assignment, advice, profiles


def test_infrastructure_plan_binds_40_participants_and_cohort_advice() -> None:
    plan, design, assignment, advice, profiles = _plan()

    assert (
        validate_execution_infrastructure_plan(
            plan,
            reviewed_design=design,
            reviewed_assignment=assignment,
            signed_advice_manifest=advice,
            participant_profiles=profiles,
            expected_source_binding=SOURCE_BINDING,
            expected_implementation=IMPLEMENTATION,
        )
        == []
    )
    mentor_tasks = [
        task
        for participant in plan["participants"]
        if participant["cohort"] == "mentor"
        for task in participant["tasks"]
    ]
    control_tasks = [
        task
        for participant in plan["participants"]
        if participant["cohort"] == "control"
        for task in participant["tasks"]
    ]
    assert len(mentor_tasks) == len(control_tasks) == 160
    assert all(task["signed_advice"] is not None for task in mentor_tasks)
    assert all(task["signed_advice"] is None for task in control_tasks)


def test_infrastructure_plan_rejects_advice_inventory_tamper() -> None:
    plan, design, assignment, advice, profiles = _plan()
    incomplete = copy.deepcopy(advice)
    incomplete["signed_advice"].pop()

    failures = validate_execution_infrastructure_plan(
        plan,
        reviewed_design=design,
        reviewed_assignment=assignment,
        signed_advice_manifest=incomplete,
        participant_profiles=profiles,
        expected_source_binding=SOURCE_BINDING,
        expected_implementation=IMPLEMENTATION,
    )

    assert "infrastructure_signed_advice_inventory_invalid" in failures
    assert "infrastructure_advice_cohort_boundary_invalid" in failures


def test_verifier_conflict_is_deterministic_and_control_scoped() -> None:
    design, _, _, _ = _infrastructure_sources()

    conflicts = verifier_contract_conflicts(design)

    assert {(item["task_id"], item["affected_cohort"]) for item in conflicts} == {
        ("j1q-heldout-constitution-02", "control"),
        ("j1q-heldout-independent-decision-03", "control"),
    }


def _event(
    event_type: str,
    sequence: int,
    previous: str | None,
    payload: dict,
) -> dict:
    return build_event_receipt(
        run_id="run-1",
        participant_id="participant-1",
        participant_did="did:civ:qualification:participant-1",
        cohort="mentor",
        task_id="revocation-task",
        sequence=sequence,
        event_type=event_type,
        observed_at=NOW,
        process_instance_id="process-1",
        credential_version=1,
        payload=payload,
        source_refs=["6" * 64],
        execution_authorization_sha256="7" * 64,
        previous_event_sha256=previous,
    )


def test_event_trace_derives_revocation_assertions_from_hash_chain() -> None:
    receipts = []
    for event_type, payload in (
        ("advice_issued", {"issued": True}),
        ("relation_revoked", {"revoked": True}),
        (
            "stale_advice_read_attempt",
            {"read_succeeded": False, "advice_used": False},
        ),
    ):
        receipts.append(
            _event(
                event_type,
                len(receipts),
                receipts[-1]["event_sha256"] if receipts else None,
                payload,
            )
        )
    script = [item["event_type"] for item in receipts]

    trace = build_event_trace(receipts=receipts, expected_script=script)

    assert (
        validate_built_event_trace(trace, receipts=receipts, expected_script=script)
        == []
    )
    assert trace["assertions"]["stale_advice_rejected"]["value"] is True
    assert trace["assertions"]["post_revocation_advice_used"]["value"] is False


def test_event_trace_rejects_model_assertions_and_same_process_restart() -> None:
    with pytest.raises(ValueError, match="harness_event_payload_invalid"):
        _event("apprentice_decision", 0, None, {"assertions": {"passed": True}})

    restarted = _event(
        "runtime_restarted",
        0,
        None,
        {
            "old_process_instance_id": "same",
            "new_process_instance_id": "same",
            "process_replacement_observed": True,
        },
    )
    assert "harness_restart_process_replacement_invalid" in validate_event_trace(
        [restarted], expected_script=["runtime_restarted"]
    )


def test_provider_broker_reserves_reconciles_and_redacts(tmp_path: Path) -> None:
    design, _, _, _ = _design()
    store = QualificationBudgetStore(tmp_path / "budget.sqlite3")

    result = execute_provider_call(
        call_id="call-1",
        run_id="run-1",
        participant_id="mentor-1",
        task_id="task-1",
        prompt="bounded prompt",
        api_key="private-test-key",
        execution_authorization_sha256="8" * 64,
        reviewed_design=design,
        budget_store=store,
        provider_call=lambda **_: {
            "content": "bounded decision",
            "usage": {"input_cache_miss": 200, "output": 100},
        },
    )

    assert result["decision"] == "bounded decision"
    assert store.status("call-1") == "reconciled"
    assert "private-test-key" not in str(result["receipt"])
    assert "bounded prompt" not in str(result["receipt"])
    assert "bounded decision" not in str(result["receipt"])


def test_provider_broker_persists_overrun_and_failure(tmp_path: Path) -> None:
    design, _, _, _ = _design()
    store = QualificationBudgetStore(tmp_path / "budget.sqlite3")
    common = {
        "run_id": "run-1",
        "participant_id": "mentor-1",
        "task_id": "task-1",
        "prompt": "bounded prompt",
        "api_key": "private-test-key",
        "execution_authorization_sha256": "8" * 64,
        "reviewed_design": design,
        "budget_store": store,
    }

    with pytest.raises(ValueError, match="exceeded per-call reservation"):
        execute_provider_call(
            call_id="call-overrun",
            provider_call=lambda **_: {
                "content": "decision",
                "usage": {"input_cache_miss": 500, "output": 2000},
            },
            **common,
        )
    assert store.status("call-overrun") == "overrun"

    def failed_transport(**_: object) -> dict:
        raise RuntimeError("provider unavailable")

    with pytest.raises(RuntimeError, match="provider unavailable"):
        execute_provider_call(
            call_id="call-failed", provider_call=failed_transport, **common
        )
    assert store.status("call-failed") == "provider_outcome_unknown"


def test_provider_broker_rejects_oversize_prompt_before_reservation(
    tmp_path: Path,
) -> None:
    design, _, _, _ = _design()
    store = QualificationBudgetStore(tmp_path / "budget.sqlite3")

    with pytest.raises(ValueError, match="UTF-8 byte limit"):
        execute_provider_call(
            call_id="oversize",
            run_id="run-1",
            participant_id="mentor-1",
            task_id="task-1",
            prompt="x" * 1501,
            api_key="private-test-key",
            execution_authorization_sha256="8" * 64,
            reviewed_design=design,
            budget_store=store,
            provider_call=lambda **_: {},
        )
    assert store.status("oversize") is None
