from __future__ import annotations

from pathlib import Path
from typing import Any

from benchmarks.j1.controlled_comparison import canonical_sha256
from benchmarks.j1.qualification_outcome_sensitive_execution_contract import (
    SOURCE_NAMES,
    build_execution_contract,
    validate_execution_contract,
)
from benchmarks.j1.qualification_outcome_sensitive_fault_matrix import (
    REPORT_SCHEMA as FAULT_SCHEMA,
    run_fault_matrix,
)
from benchmarks.j1.qualification_outcome_sensitive_execution_review import (
    REVIEW_CHECKLIST,
    build_review_bundle,
    build_review_request,
    reviewer_approval_statement,
)
from benchmarks.j1.qualification_outcome_sensitive_orchestrator import (
    REPORT_SCHEMA,
    run_offline_orchestrator,
)


def _materials() -> dict[str, Any]:
    fixtures = []
    for ordinal in range(1, 13):
        phase = (
            "baseline_replay"
            if ordinal <= 3
            else "near_transfer"
            if ordinal <= 6
            else "heldout_transfer"
            if ordinal <= 9
            else "false_positive_sentinels"
        )
        fixtures.append(
            {
                "task_id": f"task-{ordinal:02d}",
                "task_ordinal": ordinal,
                "phase": phase,
                "prompt_sha256": f"{ordinal:064x}",
                "ground_truth_commitment_sha256": f"{ordinal + 20:064x}",
                "ground_truth": {
                    "selected_action_id": "accept",
                    "pattern_ids": ["scope"],
                },
                "allowed_action_ids": ["accept", "pause"],
                "allowed_pattern_ids": ["scope", "replay"],
                "deterministic_verifier": {
                    "action_match": "exact",
                    "pattern_match": "exact_set",
                    "model_judge_allowed": False,
                    "operator_override_allowed": False,
                    "unknown_fields_allowed": False,
                },
            }
        )
    participants = []
    assignments = []
    containers = []
    signed_advice = []
    for pair_number in range(1, 21):
        pair_id = f"pair-{pair_number:02d}"
        pair: dict[str, Any] = {"pair_id": pair_id}
        for cohort in ("mentor", "control"):
            participant_id = f"{cohort}-{pair_number:02d}"
            did = f"did:civ:test:{participant_id}"
            pair[cohort] = {
                "participant_id": participant_id,
                "execution_did": did,
            }
            participants.append(
                {
                    "participant_id": participant_id,
                    "credential_version": 1,
                }
            )
            containers.append(
                {
                    "participant_id": participant_id,
                    "container": {
                        "container_id": f"{pair_number:064x}",
                        "container_name": f"container-{participant_id}",
                        "image_id": "sha256:" + "a" * 64,
                        "runtime_boundary": {
                            "network_mode": "none",
                            "read_only_rootfs": True,
                        },
                    },
                }
            )
            if cohort == "mentor":
                for ordinal in range(4, 13):
                    signed_advice.append(
                        {
                            "participant_id": participant_id,
                            "task_id": f"task-{ordinal:02d}",
                            "task_ordinal": ordinal,
                            "advice_id": f"advice-{participant_id}-{ordinal}",
                            "path": f"/private/{participant_id}-{ordinal}.json",
                            "sha256": f"{ordinal + pair_number:064x}",
                            "canonical_sha256": (
                                f"{ordinal + pair_number + 50:064x}"
                            ),
                        }
                    )
        pair["rebind_commitment_sha256"] = canonical_sha256(pair)
        assignments.append(pair)
    return {
        "protocol": {
            "scope": {
                "matched_pair_count": 20,
                "minimum_completed_pairs": 20,
                "participant_count": 40,
                "tasks_per_participant": 12,
                "total_task_count": 480,
            },
            "decision_contract": {
                "format": "strict_json",
                "free_text_rationale_allowed": False,
                "host_verifier_signature_required": True,
                "participant_signature_required": True,
                "required_fields": [
                    "selected_action_id",
                    "predicted_pattern_ids",
                ],
                "unknown_fields_allowed": False,
            },
            "treatment_contract": {
                "baseline_mentor_advice_allowed": False,
                "baseline_ordinals": [1, 2, 3],
                "control_advice_projection": [],
                "mentor_signed_advice_required": True,
                "same_provider_model_temperature_for_both_cohorts": True,
                "treatment_ordinals": list(range(4, 13)),
            },
        },
        "design": {
            "preserved_provider_call": {
                "provider_id": "openai_compatible",
                "model_id": "deepseek-v4-pro",
                "temperature": 0,
                "max_input_utf8_bytes": 1500,
                "max_output_tokens": 1000,
            }
        },
        "evaluator": {
            "input_contract": {
                "direct_observation_schema": (
                    "j1-qualification-direct-behavior-observation:v1"
                ),
                "participant_decision_schema": (
                    "j1-qualification-structured-decision:v1"
                ),
                "total_task_evidence_count": 480,
            }
        },
        "task_fixture": {
            "inventory": {"task_count": 12},
            "fixtures": fixtures,
        },
        "roster": {"participants": participants},
        "assignment": {"assignments": assignments},
        "signed_advice_manifest": {"signed_advice": signed_advice},
        "activation": {"containers": containers},
        "provider_admission_receipt": {
            "status": "admitted",
            "receipt_sha256": "b" * 64,
            "provider": {
                "provider_id": "openai_compatible",
                "model_id": "deepseek-v4-pro",
                "temperature": 0,
            },
        },
        "provider_admission_gate": {
            "passed": True,
            "report_sha256": "c" * 64,
            "receipt": {"canonical_sha256": "b" * 64},
        },
        "source_artifacts": {
            name: {
                "path": f"/private/{name}.json",
                "sha256": "d" * 64,
                "canonical_sha256": "e" * 64,
            }
            for name in SOURCE_NAMES
        },
        "implementation": {
            "source_revision": "f" * 40,
            "domain_source_sha256": "1" * 64,
            "operation_source_sha256": "2" * 64,
        },
    }


def _contract() -> tuple[dict[str, Any], dict[str, Any]]:
    materials = _materials()
    contract = build_execution_contract(
        contract_id="outcome-contract-test",
        created_at="2026-07-29T00:00:00+00:00",
        **materials,
    )
    return contract, materials


def test_contract_builds_exact_private_480_task_manifest() -> None:
    contract, materials = _contract()
    validation_materials = {
        **materials,
        "expected_source_artifacts": materials["source_artifacts"],
        "expected_implementation": materials["implementation"],
    }
    del validation_materials["source_artifacts"]
    del validation_materials["implementation"]
    assert validate_execution_contract(contract, **validation_materials) == []
    assert contract["scope"]["task_execution_count"] == 480
    assert contract["scope"]["aggregate_reserved_tokens"] == 1_200_000
    assert contract["scope"]["aggregate_reserved_cost_microunits"] == 731_040
    assert sum(
        item["advice"]["mode"] == "mentor_signed"
        for item in contract["task_executions"]
    ) == 180
    assert all(
        "ground_truth" not in item["task"] for item in contract["task_executions"]
    )


def test_offline_orchestrator_emits_structured_observations(
    tmp_path: Path,
) -> None:
    contract, _ = _contract()
    report = run_offline_orchestrator(
        contract=contract,
        run_id="outcome-offline-test",
        root=tmp_path / "offline",
        task_limit=2,
    )
    assert report["schema_version"] == REPORT_SCHEMA
    assert report["status"] == "complete"
    assert report["offline_scope"]["task_execution_count"] == 2
    assert report["journal"]["task_states"] == {"task_committed": 2}
    assert report["journal"]["event_count"] == 24
    assert report["execution_boundary"]["fixture_ground_truth_revealed"] is False


def test_outcome_fault_matrix_uses_structured_adapter(tmp_path: Path) -> None:
    contract, _ = _contract()
    report = run_fault_matrix(contract=contract, root=tmp_path / "faults")
    assert report["schema_version"] == FAULT_SCHEMA
    assert report["passed"] is True
    assert report["scenario_count"] == 8


def test_review_bundle_freezes_480_task_evidence() -> None:
    contract, _ = _contract()
    artifact = {
        "path": "/private/artifact.json",
        "sha256": "3" * 64,
        "canonical_sha256": "4" * 64,
    }
    offline = {
        "status": "complete",
        "journal": {
            "task_states": {"task_committed": 480},
            "budget_states": {"reconciled": 480},
            "event_count": 5760,
        },
        "offline_scope": {
            "provider_call_count": 480,
            "participant_signature_count": 480,
        },
        "validation_failures": [],
    }
    fault = {
        "passed": True,
        "scenario_count": 8,
        "results": [{"scenario": f"fault-{index}"} for index in range(8)],
    }
    bundle = build_review_bundle(
        bundle_id="review-bundle-test",
        created_at="2026-07-29T00:00:00+00:00",
        artifacts={
            "execution_contract": artifact,
            "offline_orchestrator_report": artifact,
            "offline_execution_journal": artifact,
            "fault_matrix_report": artifact,
        },
        contract=contract,
        offline_report=offline,
        fault_report=fault,
        source_implementation={"source_files": {}},
        verification={
            "ruff_all_passed": True,
            "pytest_all_passed": True,
            "pytest_passed_count": 1,
            "journal_artifact_hash_recomputed": True,
            "remote_revision_verified": True,
            "all_source_hashes_replayed": True,
        },
        inventory_snapshot={
            "participant_count": 40,
            "created_count": 40,
            "running_count": 0,
        },
    )
    request = build_review_request(
        request_id="review-request-test",
        created_at="2026-07-29T00:00:00+00:00",
        bundle_path="/private/bundle.json",
        bundle_raw_sha256="5" * 64,
        bundle=bundle,
    )
    statement = reviewer_approval_statement(
        request_raw_sha256="6" * 64,
        bundle_raw_sha256="5" * 64,
        bundle=bundle,
    )
    assert bundle["review_checklist"] == REVIEW_CHECKLIST
    assert request["allowed_decision"] == (
        "approve_outcome_sensitive_execution_stack"
    )
    assert "full 480-task offline recovery evidence" in statement
