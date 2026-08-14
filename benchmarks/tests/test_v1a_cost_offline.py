from __future__ import annotations

import json
import stat
from copy import deepcopy
from pathlib import Path

import pytest
from civitasos_runtime import EvidenceReference, unknown_cost_request

from benchmarks.v1a_cost.contracts import (
    OFFLINE_BOUNDARY,
    build_cohort_plan,
    finalize_artifact,
    validate_source_manifest,
    write_private_json,
)
from benchmarks.v1a_cost.offline import (
    _project_batch,
    build_entry_set,
    build_fact_batch,
    build_preflight,
    build_reconciliation_gate,
    generate_dry_run_fixture,
)


def _read(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _fixture(tmp_path: Path, name: str = "fixture") -> Path:
    root = tmp_path / name
    generate_dry_run_fixture(root)
    return root


def _write_pipeline(
    *,
    root: Path,
    source: dict,
    plan: dict,
    entries: list[dict],
    suffix: str,
) -> dict:
    source_path = root / "source-manifest.json"
    plan_path = root / f"cohort-plan-{suffix}.json"
    entry_path = root / f"entry-set-{suffix}.json"
    preflight_path = root / f"preflight-{suffix}.json"
    batch_path = root / f"offline-fact-batch-{suffix}.json"
    write_private_json(plan_path, plan)
    entry_set = build_entry_set(
        entry_set_id=f"v1a-entry-set:{suffix}",
        created_at=201,
        source_manifest=source,
        cohort_plan=plan,
        entries=entries,
    )
    write_private_json(entry_path, entry_set)
    preflight = build_preflight(
        source_manifest_path=source_path,
        cohort_plan_path=plan_path,
    )
    write_private_json(preflight_path, preflight)
    batch = build_fact_batch(
        source_manifest_path=source_path,
        cohort_plan_path=plan_path,
        preflight_path=preflight_path,
        entry_set_path=entry_path,
    )
    write_private_json(batch_path, batch)
    return build_reconciliation_gate(
        source_manifest_path=source_path,
        cohort_plan_path=plan_path,
        preflight_path=preflight_path,
        entry_set_path=entry_path,
        fact_batch_path=batch_path,
    )


def test_dry_run_is_private_structural_and_non_promotable(tmp_path: Path) -> None:
    root = _fixture(tmp_path)
    batch = _read(root / "offline-fact-batch.json")
    gate = _read(root / "offline-reconciliation-gate.json")

    assert stat.S_IMODE(root.stat().st_mode) == 0o700
    assert all(
        stat.S_IMODE(path.stat().st_mode) == 0o600
        for path in root.rglob("*.json")
    )
    assert batch["request_count"] == 18
    assert len(batch["entry_source_bindings"]) == 5
    assert gate["offline_structural_passed"] is True
    assert gate["real_source_review_ready"] is False
    assert gate["real_cohort_gate_passed"] is False
    assert gate["decision"] == "offline_dry_run_passed_real_source_review_required"
    assert gate["reservation_count"] == gate["terminal_count"] == 5
    assert gate["unknown_count"] == 0
    assert gate["totals_by_currency"] == {
        "CNY": {
            "actual_microunits": 1669,
            "reserved_microunits": 30000,
            "unknown_upper_bound_microunits": 0,
        },
        "USD": {
            "actual_microunits": 2,
            "reserved_microunits": 20000,
            "unknown_upper_bound_microunits": 0,
        },
    }
    assert gate["backend_fact_append_allowed"] is False
    assert gate["offline_boundary"] == OFFLINE_BOUNDARY


def test_dry_run_canonical_artifacts_are_deterministic(tmp_path: Path) -> None:
    first = generate_dry_run_fixture(tmp_path / "first")
    second = generate_dry_run_fixture(tmp_path / "second")

    for key in ("source_manifest", "cohort_plan", "entry_set", "preflight", "fact_batch", "gate"):
        assert first[key]["canonical_sha256"] == second[key]["canonical_sha256"]


def test_preflight_fails_closed_on_tampered_source_manifest(tmp_path: Path) -> None:
    root = _fixture(tmp_path)
    source_path = root / "source-manifest.json"
    source = _read(source_path)
    source["sources"][0]["measurement_scope"] = "tampered"
    write_private_json(source_path, source)

    preflight = build_preflight(
        source_manifest_path=source_path,
        cohort_plan_path=root / "cohort-plan.json",
    )

    assert preflight["structural_passed"] is False
    assert "source_manifest_self_hash_invalid" in preflight["structural_failures"]
    assert preflight["fact_batch_generation_allowed"] is False


def test_fixture_evidence_cannot_be_relabelled_as_real(tmp_path: Path) -> None:
    root = _fixture(tmp_path)
    source = _read(root / "source-manifest.json")
    source["sources"][0].update(
        {
            "provenance_class": "external_invoice",
            "real_external_source": True,
            "independently_reviewed": True,
        }
    )
    source = finalize_artifact(source)

    assert "source_0_non_fixture_uses_fixture_evidence" in validate_source_manifest(
        source
    )


def test_entry_set_requires_every_task_terminal_state(tmp_path: Path) -> None:
    root = _fixture(tmp_path)
    source = _read(root / "source-manifest.json")
    plan = _read(root / "cohort-plan.json")
    entries = _read(root / "entry-set.json")["entries"]
    entries[0].pop("terminal")

    with pytest.raises(ValueError, match="terminal_kind_invalid"):
        build_entry_set(
            entry_set_id="v1a-entry-set:missing-terminal",
            created_at=201,
            source_manifest=source,
            cohort_plan=plan,
            entries=entries,
        )


def test_unknown_cost_is_bounded_and_blocks_real_gate(tmp_path: Path) -> None:
    root = _fixture(tmp_path)
    source = _read(root / "source-manifest.json")
    plan = _read(root / "cohort-plan.json")
    entries = _read(root / "entry-set.json")["entries"]
    reservation = entries[0]["reservation"]
    reservation_data = reservation["event"]["data"]
    source_ref = EvidenceReference(
        uri="evidence:v1a:unknown-accounting",
        sha256="e" * 64,
    )
    entries[0]["measurement"] = None
    entries[0]["terminal"] = unknown_cost_request(
        operation_id="v1a:dry-task-01:storage:unknown",
        task_id=reservation["task_id"],
        actor=reservation["actor"],
        entry_id=reservation_data["entry_id"],
        category=reservation_data["category"],
        currency=reservation_data["currency"],
        upper_bound_microunits=10_000,
        reason_code="source_measurement_unavailable",
        source_refs=[source_ref],
    )

    gate = _write_pipeline(
        root=root,
        source=source,
        plan=plan,
        entries=entries,
        suffix="unknown",
    )

    assert gate["offline_structural_passed"] is True
    assert gate["unknown_count"] == 1
    assert gate["unknown_cost_free"] is False
    assert gate["totals_by_currency"]["CNY"]["unknown_upper_bound_microunits"] == 10_000
    assert gate["real_cohort_gate_passed"] is False


def test_zero_accepted_outcomes_have_null_unit_cost(tmp_path: Path) -> None:
    root = _fixture(tmp_path)
    source = _read(root / "source-manifest.json")
    parent_plan = _read(root / "cohort-plan.json")
    entries = _read(root / "entry-set.json")["entries"]
    plan = build_cohort_plan(
        cohort_id="v1a-cohort:zero-accepted",
        created_at=10,
        observation_started_at=10,
        observation_ended_at=200,
        actor=parent_plan["actor"],
        task_ids=parent_plan["task_ids"],
        accepted_task_ids=[],
        expected_categories=parent_plan["expected_categories"],
        source_manifest=source,
    )

    gate = _write_pipeline(
        root=root,
        source=source,
        plan=plan,
        entries=entries,
        suffix="zero-accepted",
    )

    assert gate["accepted_outcome_count"] == 0
    assert gate["cost_per_accepted_outcome_by_currency"] == {
        "CNY": None,
        "USD": None,
    }


def test_conflicting_rate_remains_invalid_after_matching_republication(
    tmp_path: Path,
) -> None:
    root = _fixture(tmp_path)
    plan = _read(root / "cohort-plan.json")
    batch = _read(root / "offline-fact-batch.json")
    original = next(
        request
        for request in batch["requests"]
        if request["event"]["kind"] == "rate_published"
        and request["event"]["data"]["category"] == "storage"
    )
    conflict = deepcopy(original)
    conflict["operation_id"] = "v1a:fixture:rate:storage:conflict"
    conflict["event"]["data"]["price_microunits"] = 2
    repeat = deepcopy(original)
    repeat["operation_id"] = "v1a:fixture:rate:storage:repeat"
    nonrates = [
        request
        for request in batch["requests"]
        if request["event"]["kind"] != "rate_published"
    ]
    projection = _project_batch(
        {"requests": [original, conflict, repeat, *nonrates]},
        plan,
    )

    assert "conflicting_rate:rate:v1a:fixture:storage" in projection["failures"]
    assert any(
        failure.startswith("rate_missing:") for failure in projection["failures"]
    )


def test_gate_fails_closed_on_malformed_measurement_quantity(tmp_path: Path) -> None:
    root = _fixture(tmp_path)
    source = _read(root / "source-manifest.json")
    plan = _read(root / "cohort-plan.json")
    entries = _read(root / "entry-set.json")["entries"]
    entries[0]["measurement"]["event"]["data"]["quantity"] = "not-an-integer"

    gate = _write_pipeline(
        root=root,
        source=source,
        plan=plan,
        entries=entries,
        suffix="malformed-quantity",
    )

    assert gate["offline_structural_passed"] is False
    assert any(
        failure.startswith("measurement_quantity_invalid:")
        for failure in gate["failure_reasons"]
    )


def test_gate_revalidates_entry_set_lineage(tmp_path: Path) -> None:
    root = _fixture(tmp_path)
    batch_path = root / "offline-fact-batch.json"
    batch = _read(batch_path)
    batch["entry_set"]["canonical_sha256"] = "0" * 64
    write_private_json(batch_path, finalize_artifact(batch))

    gate = build_reconciliation_gate(
        source_manifest_path=root / "source-manifest.json",
        cohort_plan_path=root / "cohort-plan.json",
        preflight_path=root / "preflight.json",
        entry_set_path=root / "entry-set.json",
        fact_batch_path=batch_path,
    )

    assert gate["offline_structural_passed"] is False
    assert "fact_batch_entry_set_binding_invalid" in gate["failure_reasons"]
