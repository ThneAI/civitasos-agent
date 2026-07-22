from __future__ import annotations

import copy
import hashlib
from datetime import datetime, timezone
from pathlib import Path

import pytest

from benchmarks.j1.controlled_comparison import canonical_sha256, write_private_json
from benchmarks.j1.qualification_execution_design import (
    TASK_DESIGNS,
    build_execution_design,
    validate_execution_design,
)
from benchmarks.j1_qualification_execution_design import prepare_execution_design


NOW = datetime(2026, 7, 22, tzinfo=timezone.utc).isoformat()
CASES = {
    "j1q-heldout-scope-delivery-01": "scope-and-delivery-contract",
    "j1q-heldout-constitution-02": "constitution-precedence",
    "j1q-heldout-independent-decision-03": "apprentice-independent-decision",
    "j1q-heldout-revocation-04": "revocation-fail-closed",
    "j1q-heldout-restart-continuity-05": "restart-provenance-continuity",
    "j1q-heldout-credential-rotation-06": "stale-advice-rejection",
    "j1q-heldout-maturity-window-07": "three-consecutive-verified-tasks",
    "j1q-heldout-refusal-delivery-08": "scope-and-delivery-contract",
}


def _sources() -> tuple[dict, dict, dict]:
    tasks = [
        {
            "task_id": task_id,
            "input": f"Input for {task_id}",
            "input_sha256": f"{index:064x}",
            "verifier_case": CASES[task_id],
            "scenario_tags": ["repeated_error"],
        }
        for index, task_id in enumerate(TASK_DESIGNS, start=1)
    ]
    corpus = {
        "corpus_id": "j1q-heldout-corpus-v1",
        "tasks": tasks,
        "tasks_sha256": canonical_sha256(tasks),
    }
    protocol = {
        "frozen_stack": {
            "provider_id": "openai_compatible",
            "model_id": "deepseek-v4-pro",
            "budget": {
                "max_tokens": 20_000,
                "max_cost_microunits": 100_000,
            },
        },
        "task_corpus": {
            "artifact_sha256": "a" * 64,
            "tasks_sha256": corpus["tasks_sha256"],
        },
    }
    assignments = [
        {
            "pair_id": f"j1q-pair-{index:02d}",
            "mentor": {
                "participant_id": f"mentor-{index}",
                "execution_did": f"did:civ:qualification:mentor-{index}",
            },
            "control": {
                "participant_id": f"control-{index}",
                "execution_did": f"did:civ:qualification:control-{index}",
            },
        }
        for index in range(1, 21)
    ]
    assignment = {
        "schema_version": "j1-qualification-cohort-assignment-reviewed:v1",
        "status": "operator_reviewed",
        "method": "reviewed-pairing-hash-parity:v1",
        "participant_count": 40,
        "pair_count": 20,
        "source_proposal_sha256": "b" * 64,
        "operator_review": {
            "review_id": "review-r1",
            "reviewer_did": "did:civ:reviewer",
            "reviewed_at": NOW,
            "review_receipt_sha256": "c" * 64,
        },
        "assignments": assignments,
    }
    assignment["reviewed_assignment_sha256"] = canonical_sha256(assignment)
    return protocol, corpus, assignment


def _design() -> tuple[dict, dict, dict, dict]:
    protocol, corpus, assignment = _sources()
    design = build_execution_design(
        design_id="j1d-execution-design-20260722-r1",
        created_at=NOW,
        protocol=protocol,
        corpus=corpus,
        reviewed_assignment=assignment,
        pricing_observed_at=NOW,
    )
    return design, protocol, corpus, assignment


def test_design_freezes_treatment_events_and_provider_pricing() -> None:
    design, protocol, corpus, assignment = _design()

    assert (
        validate_execution_design(
            design,
            protocol=protocol,
            corpus=corpus,
            reviewed_assignment=assignment,
        )
        == []
    )
    assert len(design["treatment"]["tasks"]) == 8
    assert all(
        item["control_condition"]["advice_projection"] == []
        for item in design["treatment"]["tasks"]
    )
    assert design["pricing"]["rates_microunits"] == {
        "input_cache_hit": 3_625,
        "input_cache_miss": 435_000,
        "output": 870_000,
    }
    assert design["budget_reservation"]["per_call_max_microunits"] == 1_523
    assert design["budget_reservation"]["aggregate_reserved_microunits"] == 487_360


def test_design_rejects_control_contamination_and_model_assertions() -> None:
    design, protocol, corpus, assignment = _design()
    contaminated = copy.deepcopy(design)
    contaminated["treatment"]["tasks"][0]["control_condition"]["advice_projection"] = [
        "leaked advice"
    ]
    contaminated["event_evidence"]["model_assertions_are_authoritative"] = True

    failures = validate_execution_design(
        contaminated,
        protocol=protocol,
        corpus=corpus,
        reviewed_assignment=assignment,
    )
    assert "execution_design_control_contaminated" in failures
    assert "execution_design_event_evidence_invalid" in failures
    assert "execution_design_hash_mismatch" in failures


def test_design_rejects_price_and_assignment_drift() -> None:
    design, protocol, corpus, assignment = _design()
    drifted = copy.deepcopy(design)
    drifted["pricing"]["rates_microunits"]["output"] += 1
    failures = validate_execution_design(
        drifted,
        protocol=protocol,
        corpus=corpus,
        reviewed_assignment=assignment,
    )
    assert "execution_design_pricing_invalid" in failures

    other_assignment = copy.deepcopy(assignment)
    other_assignment["reviewed_assignment_sha256"] = "d" * 64
    failures = validate_execution_design(
        design,
        protocol=protocol,
        corpus=corpus,
        reviewed_assignment=other_assignment,
    )
    assert "execution_design_source_binding_invalid" in failures


def test_design_rejects_unknown_fields_and_corpus_hash_drift() -> None:
    design, protocol, corpus, assignment = _design()
    extended = copy.deepcopy(design)
    extended["unreviewed_extension"] = True
    extended["design_sha256"] = canonical_sha256(
        {key: item for key, item in extended.items() if key != "design_sha256"}
    )

    failures = validate_execution_design(
        extended,
        protocol=protocol,
        corpus=corpus,
        reviewed_assignment=assignment,
    )
    assert "execution_design_fields_invalid" in failures

    drifted_protocol = copy.deepcopy(protocol)
    drifted_protocol["task_corpus"]["tasks_sha256"] = "f" * 64
    with pytest.raises(ValueError, match="execution_design_corpus_hash_invalid"):
        build_execution_design(
            design_id="j1d-execution-design-20260722-r1",
            created_at=NOW,
            protocol=drifted_protocol,
            corpus=corpus,
            reviewed_assignment=assignment,
            pricing_observed_at=NOW,
        )


def _write_operation_sources(tmp_path: Path) -> dict[str, Path]:
    protocol, corpus, assignment = _sources()
    paths = {
        "protocol": tmp_path / "qualification-protocol.json",
        "corpus": tmp_path / "qualification-corpus.json",
        "assignment": tmp_path / "cohort-assignment.operator-reviewed.json",
        "gate": tmp_path / "cohort-assignment-gate-report.json",
    }
    write_private_json(paths["corpus"], corpus)
    protocol["task_corpus"]["artifact_sha256"] = hashlib.sha256(
        paths["corpus"].read_bytes()
    ).hexdigest()
    write_private_json(paths["protocol"], protocol)
    write_private_json(paths["assignment"], assignment)
    gate = {
        "passed": True,
        "failure_reasons": [],
        "reviewed_assignment_sha256": assignment["reviewed_assignment_sha256"],
        "readiness": {"cohort_assignment_bound": True},
        "artifacts": {
            "qualification_protocol": {
                "path": str(paths["protocol"].resolve()),
                "sha256": hashlib.sha256(paths["protocol"].read_bytes()).hexdigest(),
            },
            "reviewed_assignment": {
                "path": str(paths["assignment"].resolve()),
                "sha256": hashlib.sha256(paths["assignment"].read_bytes()).hexdigest(),
            },
        },
    }
    write_private_json(paths["gate"], gate)
    return paths


def test_prepare_execution_design_is_private_and_non_executing(tmp_path: Path) -> None:
    paths = _write_operation_sources(tmp_path)
    output_root = tmp_path / "execution-design"

    report = prepare_execution_design(
        design_id="j1d-execution-design-20260722-r1",
        created_at=NOW,
        pricing_observed_at=NOW,
        qualification_protocol_path=paths["protocol"],
        corpus_path=paths["corpus"],
        reviewed_assignment_path=paths["assignment"],
        assignment_gate_path=paths["gate"],
        output_root=output_root,
    )

    assert report["passed"] is True
    assert report["state"] == "execution_design_prepared_independent_review_required"
    assert report["readiness"]["controlled_experiment_execution_ready"] is False
    assert all(
        value is False
        for key, value in report["execution_boundary"].items()
        if key != "design_review_only"
    )
    assert output_root.stat().st_mode & 0o777 == 0o700
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in output_root.iterdir())


def test_prepare_execution_design_rejects_assignment_gate_drift(
    tmp_path: Path,
) -> None:
    paths = _write_operation_sources(tmp_path)
    assignment = paths["assignment"].read_text(encoding="utf-8")
    paths["assignment"].write_text(assignment + "\n", encoding="utf-8")
    paths["assignment"].chmod(0o600)

    with pytest.raises(ValueError, match="reviewed_assignment drift"):
        prepare_execution_design(
            design_id="j1d-execution-design-20260722-r1",
            created_at=NOW,
            pricing_observed_at=NOW,
            qualification_protocol_path=paths["protocol"],
            corpus_path=paths["corpus"],
            reviewed_assignment_path=paths["assignment"],
            assignment_gate_path=paths["gate"],
            output_root=tmp_path / "execution-design",
        )
