"""Aggregator — read runs/{run_id}/raw_ticks/*.csv + summary.json,
emit final_metrics.csv with one row per (agent_id, category_id).

Fail-fast on metric-code drift between manifest.allowed_metric_codes and the
final_metrics CSV column names declared in observability/metrics/schema.yaml.
"""
from __future__ import annotations

import csv
import json
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import yaml

from observability.metrics.computers import (
    _loader as loader,
    m1_result_deviation,
    m2_verification_miss,
    m3_aspect_gap_response,
    m4_lessons_impact,
    m5_reaction_latency,
    m6_wait_ratio,
    g2_subjective_mode,
    g3_relation_time,
    h0_expectation_trace,
)
from observability.metrics.computers._loader import TaskRun

from .task_loader import Manifest

FINAL_METRIC_COLUMNS: tuple[str, ...] = (
    "run_id",
    "agent_id",
    "category_id",
    "targets_disease",
    "task_count",
    "m1_result_deviation_rate",
    "m2_verification_miss_rate",
    "m3_aspect_gap_response_rate",
    "m4_lessons_impact_rate",
    "m5_tick_latency_p50_ms",
    "m5_tick_latency_p95_ms",
    "m5_tick_latency_p99_ms",
    "m5_task_latency_p50_ms",
    "m5_task_latency_p95_ms",
    "m6_wait_ratio",
    "g2_mode_choice_observable_ratio",
    "g2_llm_waiting_ratio",
    "g2_llm_deep_think_ratio",
    "g3_relation_memory_hit_ratio",
    "g3_relation_aware_decision_ratio",
    "g3_cross_agent_time_consistency_ratio",
    "g3_r2r_relation_id_ratio",
    "g3_relation_pair_context_ratio",
    "g3_relation_pair_failure_ref_ratio",
    "h0_expectation_trace_ratio",
    "h0_hard_domain_trace_ratio",
    "h0_drive_constitution_verdict_ratio",
    "h0_iem_update_log_ratio",
    "h0_relation_action_bias_ratio",
    "h0_normative_guard_ratio",
    "h0_identity_domain_trace_ratio",
    "h0_identity_action_bias_ratio",
    "h0_constitutional_surprise_ratio",
    "h0_normative_governance_trigger_ratio",
    "h0_predicted_update_ratio",
    "h0_desired_slow_drift_ratio",
    "notes",
)


class AggregatorError(RuntimeError):
    pass


@dataclass
class AggregateRow:
    run_id: str
    agent_id: str
    category_id: str
    targets_disease: str
    task_count: int
    metrics: dict[str, float | None]
    notes: str = ""


def aggregate_run(run_dir: str | Path, manifest: Manifest, *, schema_yaml: str | Path | None = None) -> list[AggregateRow]:
    run_dir = Path(run_dir)
    if not run_dir.is_dir():
        raise AggregatorError(f"run_dir not found: {run_dir}")

    _validate_metric_code_alignment(manifest, schema_yaml)

    summary_path = run_dir / "summary.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8")) if summary_path.exists() else {"tasks": []}
    self_reported = {t["task_id"]: t.get("agent_self_reported_success") for t in summary.get("tasks", [])}

    raw_dir = run_dir / "raw_ticks"
    task_runs = loader.load_task_runs(raw_dir)

    # Annotate task_runs with manifest fields and self-reported flag.
    for tid, tr in task_runs.items():
        try:
            spec = manifest.task_by_id(tid)
        except KeyError:
            raise AggregatorError(f"runs contain unknown task_id: {tid}") from None
        tr.category_id = spec.category_id
        tr.targets_disease = spec.targets_disease
        tr.variant = spec.variant
        tr.verifier_tools = list(spec.verifier_tools)
        tr.success_criteria = list(spec.success_criteria)
        tr.agent_self_reported_success = self_reported.get(tid)

    by_cat: dict[tuple[str, str], list[TaskRun]] = defaultdict(list)
    for tr in task_runs.values():
        if not tr.ticks:
            continue
        agent_id = tr.ticks[0].agent_id
        by_cat[(agent_id, tr.category_id)].append(tr)

    out: list[AggregateRow] = []
    run_id = summary.get("run_id", "")
    for (agent_id, cat_id), tasks in sorted(by_cat.items()):
        targets_disease = tasks[0].targets_disease
        m4_val, m4_notes = m4_lessons_impact.compute(tasks)
        m5 = m5_reaction_latency.compute(tasks)
        g2 = g2_subjective_mode.compute(tasks)
        g3 = g3_relation_time.compute(tasks)
        h0 = h0_expectation_trace.compute(tasks)
        metrics: dict[str, float | None] = {
            "m1_result_deviation_rate": m1_result_deviation.compute(tasks),
            "m2_verification_miss_rate": m2_verification_miss.compute(tasks),
            "m3_aspect_gap_response_rate": m3_aspect_gap_response.compute(tasks),
            "m4_lessons_impact_rate": m4_val,
            **m5,
            "m6_wait_ratio": m6_wait_ratio.compute(tasks),
            **g2,
            **g3,
            **h0,
        }
        out.append(AggregateRow(
            run_id=run_id,
            agent_id=agent_id,
            category_id=cat_id,
            targets_disease=targets_disease,
            task_count=len(tasks),
            metrics=metrics,
            notes=m4_notes,
        ))
    return out


def write_final_metrics(rows: Iterable[AggregateRow], out_path: str | Path) -> Path:
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh, quoting=csv.QUOTE_MINIMAL)
        w.writerow(FINAL_METRIC_COLUMNS)
        for r in rows:
            w.writerow([
                r.run_id, r.agent_id, r.category_id, r.targets_disease, r.task_count,
                _fmt(r.metrics.get("m1_result_deviation_rate")),
                _fmt(r.metrics.get("m2_verification_miss_rate")),
                _fmt(r.metrics.get("m3_aspect_gap_response_rate")),
                _fmt(r.metrics.get("m4_lessons_impact_rate")),
                _fmt(r.metrics.get("m5_tick_latency_p50_ms")),
                _fmt(r.metrics.get("m5_tick_latency_p95_ms")),
                _fmt(r.metrics.get("m5_tick_latency_p99_ms")),
                _fmt(r.metrics.get("m5_task_latency_p50_ms")),
                _fmt(r.metrics.get("m5_task_latency_p95_ms")),
                _fmt(r.metrics.get("m6_wait_ratio")),
                _fmt(r.metrics.get("g2_mode_choice_observable_ratio")),
                _fmt(r.metrics.get("g2_llm_waiting_ratio")),
                _fmt(r.metrics.get("g2_llm_deep_think_ratio")),
                _fmt(r.metrics.get("g3_relation_memory_hit_ratio")),
                _fmt(r.metrics.get("g3_relation_aware_decision_ratio")),
                _fmt(r.metrics.get("g3_cross_agent_time_consistency_ratio")),
                _fmt(r.metrics.get("g3_r2r_relation_id_ratio")),
                _fmt(r.metrics.get("g3_relation_pair_context_ratio")),
                _fmt(r.metrics.get("g3_relation_pair_failure_ref_ratio")),
                _fmt(r.metrics.get("h0_expectation_trace_ratio")),
                _fmt(r.metrics.get("h0_hard_domain_trace_ratio")),
                _fmt(r.metrics.get("h0_drive_constitution_verdict_ratio")),
                _fmt(r.metrics.get("h0_iem_update_log_ratio")),
                _fmt(r.metrics.get("h0_relation_action_bias_ratio")),
                _fmt(r.metrics.get("h0_normative_guard_ratio")),
                _fmt(r.metrics.get("h0_identity_domain_trace_ratio")),
                _fmt(r.metrics.get("h0_identity_action_bias_ratio")),
                _fmt(r.metrics.get("h0_constitutional_surprise_ratio")),
                _fmt(r.metrics.get("h0_normative_governance_trigger_ratio")),
                _fmt(r.metrics.get("h0_predicted_update_ratio")),
                _fmt(r.metrics.get("h0_desired_slow_drift_ratio")),
                r.notes,
            ])
    return out


def _fmt(value: float | None) -> str:
    if value is None:
        return ""
    if isinstance(value, float):
        return f"{value:.6f}".rstrip("0").rstrip(".")
    return str(value)


def _validate_metric_code_alignment(manifest: Manifest, schema_yaml: str | Path | None) -> None:
    """Manifest.allowed_metric_codes must each appear as a final_metrics column
    *family* (prefix-match)."""
    if schema_yaml is None:
        schema_yaml = Path(__file__).resolve().parents[1] / "observability" / "metrics" / "schema.yaml"
    data = yaml.safe_load(Path(schema_yaml).read_text(encoding="utf-8"))
    final_cols = {c["name"] for c in data["final_metrics"]["columns"]}
    for code in manifest.allowed_metric_codes:
        if code in final_cols:
            continue
        if any(col.startswith(code) for col in final_cols):
            continue
        raise AggregatorError(
            f"manifest.allowed_metric_codes entry {code!r} does not match any "
            f"final_metrics column in schema.yaml"
        )
