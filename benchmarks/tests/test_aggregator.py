"""Aggregator smoke + fail-fast tests."""
from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest
import yaml

from benchmarks.aggregator import (
    AggregatorError, FINAL_METRIC_COLUMNS, aggregate_run, write_final_metrics,
)
from benchmarks.task_loader import load_manifest
from observability.metrics.schema import RAW_COLUMNS

REAL_MANIFEST = Path(__file__).resolve().parents[1] / "v1" / "manifest.yaml"


def _build_minimal_run(tmp_path: Path) -> Path:
    run_dir = tmp_path / "runs" / "rid"
    raw = run_dir / "raw_ticks"
    raw.mkdir(parents=True)
    csv_path = raw / "R01_happy_01.csv"
    with csv_path.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=RAW_COLUMNS)
        w.writeheader()
        for seq in range(1, 4):
            row = {col: "" for col in RAW_COLUMNS}
            row.update({
                "run_id": "rid",
                "agent_id": "fake-agent",
                "task_id": "R01_happy_01",
                "tick_seq": seq,
                "tick_id": f"t{seq}",
                "timestamp": f"2026-04-18T00:00:0{seq}+00:00",
                "phase_reached": "reflect",
                "decision_action": "wait" if seq == 2 else "noop",
                "decision_source": "rules",
                "conscience_allowed": "true",
                "conscience_reason": "ok",
                "eval_success": "true" if seq == 3 else "",
                "eval_cost": "0.001",
                "eval_duration_ms": "10",
                "aspect_gap": "0.1",
                "peer_trust_avg": "0.5",
                "balance": "100.0",
                "mode": "active",
                "is_wait": "true" if seq == 2 else "false",
                "lessons_count": "0",
                "wait_references_telos": "false",
                "subjective_lifecycle_stage": "mature",
                "subjective_recommended_mode": "deep_think",
                "llm_mode_request": "deep_think" if seq == 2 else "",
                "llm_mode_selected": "true" if seq == 2 else "false",
            })
            w.writerow(row)
    summary = {
        "run_id": "rid",
        "tasks": [{
            "task_id": "R01_happy_01",
            "agent_self_reported_success": True,
        }],
    }
    (run_dir / "summary.json").write_text(json.dumps(summary), encoding="utf-8")
    return run_dir


def test_aggregate_real_manifest(tmp_path: Path) -> None:
    run_dir = _build_minimal_run(tmp_path)
    rows = aggregate_run(run_dir, load_manifest(REAL_MANIFEST))
    assert len(rows) == 1
    r = rows[0]
    assert r.category_id == "R01"
    assert r.targets_disease == "R"
    assert r.task_count == 1
    # M4 needs fail->success + lessons_count signal; minimal fixture has none.
    assert r.metrics["m4_lessons_impact_rate"] is None
    assert "insufficient M4 signal" in r.notes
    assert r.metrics["g2_mode_choice_observable_ratio"] == 1.0
    assert r.metrics["g2_llm_deep_think_ratio"] == 1.0


def test_write_final_metrics_columns(tmp_path: Path) -> None:
    run_dir = _build_minimal_run(tmp_path)
    rows = aggregate_run(run_dir, load_manifest(REAL_MANIFEST))
    out = write_final_metrics(rows, tmp_path / "final_metrics.csv")
    header = out.open(encoding="utf-8").readline().rstrip("\n").split(",")
    assert tuple(header) == FINAL_METRIC_COLUMNS


def test_unknown_task_id_in_run_fails(tmp_path: Path) -> None:
    run_dir = _build_minimal_run(tmp_path)
    bogus = run_dir / "raw_ticks" / "ZZ99_unknown.csv"
    bogus.write_text(",".join(RAW_COLUMNS) + "\n", encoding="utf-8")
    with pytest.raises(AggregatorError, match="unknown task_id"):
        aggregate_run(run_dir, load_manifest(REAL_MANIFEST))


def test_metric_code_drift_fails_fast(tmp_path: Path) -> None:
    """Schema YAML missing one final_metrics column the manifest declares -> fail."""
    fake_schema = tmp_path / "schema.yaml"
    fake_schema.write_text(yaml.safe_dump({
        "schema_version": "1.1",
        "columns": [],
        "final_metrics": {
            "schema_version": "1.1",
            "columns": [{"name": "totally_unrelated"}],
        },
    }), encoding="utf-8")
    run_dir = _build_minimal_run(tmp_path)
    with pytest.raises(AggregatorError, match="does not match"):
        aggregate_run(run_dir, load_manifest(REAL_MANIFEST), schema_yaml=fake_schema)
