"""H.1-D cost attribution report.

Compares an H1-D candidate run against a baseline and attributes the observed
cost to raw tick volume, raw tick categories, latency aggregates, and live judge
workload. This script is diagnostic: it does not rerun agents or judges.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any


_H1_REQUIRED_BRIDGE_CATEGORIES = ("h1_verifier_bridge",)
_H1_OPTIMIZABLE_BRIDGE_CATEGORIES = ("g3_llm_relation_trace",)
_H1_RUNTIME_OVERHEAD_CATEGORIES = (
    *_H1_REQUIRED_BRIDGE_CATEGORIES,
    *_H1_OPTIMIZABLE_BRIDGE_CATEGORIES,
)


def build_h1_cost_report(
    *,
    baseline_run_root: Path,
    candidate_run_root: Path,
    judge_report_path: Path,
    agent_root: Path,
    max_raw_tick_volume_increase: float,
    max_per_tick_p95_regression: float,
    task_p95_warning_threshold: float,
) -> dict[str, Any]:
    baseline_run_root = _resolve_path(baseline_run_root, agent_root)
    candidate_run_root = _resolve_path(candidate_run_root, agent_root)
    judge_report_path = _resolve_path(judge_report_path, agent_root)

    baseline_cost = _cost_metrics(baseline_run_root)
    candidate_cost = _cost_metrics(candidate_run_root)
    raw_attribution = _raw_tick_attribution(candidate_run_root)
    judge_workload = _judge_workload(judge_report_path)
    relative_change = _cost_relative_change(baseline_cost, candidate_cost)
    checks = {
        "raw_tick_volume_within_budget": _is_within(
            relative_change.get("raw_tick_rows"),
            max_raw_tick_volume_increase,
        ),
        "per_tick_p95_within_budget": _is_within(
            relative_change.get("tick_p95_ms_mean"),
            max_per_tick_p95_regression,
        ),
    }
    task_p95_change = relative_change.get("task_p95_ms_mean")
    findings = _findings(
        relative_change=relative_change,
        raw_attribution=raw_attribution,
        judge_workload=judge_workload,
        task_p95_warning_threshold=task_p95_warning_threshold,
    )
    if task_p95_change is not None and task_p95_change > task_p95_warning_threshold:
        checks["task_p95_recorded_as_optimization_target"] = True

    return {
        "schema_version": "h1-cost-report:v1",
        "passed": all(checks.values()),
        "baseline_run_root": str(baseline_run_root),
        "candidate_run_root": str(candidate_run_root),
        "judge_report_path": str(judge_report_path),
        "thresholds": {
            "max_raw_tick_volume_increase": max_raw_tick_volume_increase,
            "max_per_tick_p95_regression": max_per_tick_p95_regression,
            "task_p95_warning_threshold": task_p95_warning_threshold,
        },
        "checks": checks,
        "latency_and_volume": {
            "baseline": baseline_cost,
            "candidate": candidate_cost,
            "relative_change": relative_change,
        },
        "raw_tick_attribution": raw_attribution,
        "judge_workload": judge_workload,
        "findings": findings,
    }


def _cost_metrics(run_root: Path) -> dict[str, float | int | None]:
    metrics = _final_metrics_means(run_root / "final_metrics.csv")
    raw_tick_rows = _raw_tick_rows(run_root)
    metrics["raw_tick_rows"] = raw_tick_rows
    final_rows = metrics.get("final_metrics_rows")
    metrics["raw_ticks_per_metrics_row"] = raw_tick_rows / final_rows if final_rows else None
    return metrics


def _final_metrics_means(path: Path) -> dict[str, float | int | None]:
    fields = {
        "m5_tick_latency_p50_ms": "tick_p50_ms_mean",
        "m5_tick_latency_p95_ms": "tick_p95_ms_mean",
        "m5_tick_latency_p99_ms": "tick_p99_ms_mean",
        "m5_task_latency_p50_ms": "task_p50_ms_mean",
        "m5_task_latency_p95_ms": "task_p95_ms_mean",
    }
    buckets: dict[str, list[float]] = {name: [] for name in fields.values()}
    if not path.exists():
        return {"final_metrics_rows": 0, **{name: None for name in fields.values()}}
    row_count = 0
    with path.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            row_count += 1
            for csv_key, out_key in fields.items():
                value = _float(row.get(csv_key))
                if value is not None:
                    buckets[out_key].append(value)
    return {
        "final_metrics_rows": row_count,
        **{key: _mean(values) for key, values in buckets.items()},
    }


def _raw_tick_attribution(run_root: Path) -> dict[str, Any]:
    source_counts: Counter[str] = Counter()
    action_counts: Counter[str] = Counter()
    agent_counts: Counter[str] = Counter()
    task_counts: Counter[str] = Counter()
    category_counts: Counter[str] = Counter()
    category_task_counts: dict[str, Counter[str]] = {}
    category_agent_counts: dict[str, Counter[str]] = {}
    total_rows = 0
    for csv_path in run_root.glob("baseline-*/raw_ticks/*.csv"):
        agent_alias = _agent_alias_from_run_dir(csv_path)
        with csv_path.open(newline="", encoding="utf-8") as handle:
            for row in csv.DictReader(handle):
                total_rows += 1
                action = str(row.get("decision_action") or "unknown")
                source = str(row.get("decision_source") or "unknown")
                task_id = str(row.get("task_id") or csv_path.stem)
                reasoning = str(row.get("decision_reasoning") or "")
                source_counts[source] += 1
                action_counts[action] += 1
                agent_counts[agent_alias] += 1
                task_counts[task_id] += 1
                for category in _tick_categories(row, reasoning):
                    category_counts[category] += 1
                    category_task_counts.setdefault(category, Counter())[task_id] += 1
                    category_agent_counts.setdefault(category, Counter())[agent_alias] += 1
    return {
        "total_rows": total_rows,
        "decision_source_counts": dict(sorted(source_counts.items())),
        "top_decision_actions": _top(action_counts),
        "rows_by_agent": dict(sorted(agent_counts.items())),
        "top_tasks_by_rows": _top(task_counts, limit=12),
        "category_counts": dict(sorted(category_counts.items())),
        "h1_runtime_overhead": _h1_runtime_overhead(
            total_rows=total_rows,
            category_counts=category_counts,
            category_task_counts=category_task_counts,
            category_agent_counts=category_agent_counts,
        ),
    }


def _h1_runtime_overhead(
    *,
    total_rows: int,
    category_counts: Counter[str],
    category_task_counts: dict[str, Counter[str]],
    category_agent_counts: dict[str, Counter[str]],
) -> dict[str, Any]:
    bridge_task_counts: Counter[str] = Counter()
    bridge_agent_counts: Counter[str] = Counter()
    bridge_category_counts: dict[str, int] = {}
    for category in _H1_RUNTIME_OVERHEAD_CATEGORIES:
        count = int(category_counts.get(category, 0))
        bridge_category_counts[category] = count
        bridge_task_counts.update(category_task_counts.get(category, Counter()))
        bridge_agent_counts.update(category_agent_counts.get(category, Counter()))

    bridge_rows = sum(bridge_category_counts.values())
    required_bridge = _bridge_breakdown(
        categories=_H1_REQUIRED_BRIDGE_CATEGORIES,
        total_rows=total_rows,
        category_counts=category_counts,
        category_task_counts=category_task_counts,
        category_agent_counts=category_agent_counts,
    )
    optimizable_bridge = _bridge_breakdown(
        categories=_H1_OPTIMIZABLE_BRIDGE_CATEGORIES,
        total_rows=total_rows,
        category_counts=category_counts,
        category_task_counts=category_task_counts,
        category_agent_counts=category_agent_counts,
    )
    final_delivery_rows = int(category_counts.get("h1_criteria_evidence", 0))
    return {
        "bridge_categories": list(_H1_RUNTIME_OVERHEAD_CATEGORIES),
        "bridge_category_counts": bridge_category_counts,
        "bridge_rows": bridge_rows,
        "bridge_row_ratio": bridge_rows / total_rows if total_rows else 0.0,
        "bridge_rows_by_agent": dict(sorted(bridge_agent_counts.items())),
        "top_bridge_tasks": _top(bridge_task_counts, limit=12),
        "required_bridge_categories": list(_H1_REQUIRED_BRIDGE_CATEGORIES),
        "required_bridge_category_counts": required_bridge["category_counts"],
        "required_bridge_rows": required_bridge["rows"],
        "required_bridge_row_ratio": required_bridge["row_ratio"],
        "required_bridge_rows_by_agent": required_bridge["rows_by_agent"],
        "top_required_bridge_tasks": required_bridge["top_tasks"],
        "optimizable_bridge_categories": list(_H1_OPTIMIZABLE_BRIDGE_CATEGORIES),
        "optimizable_bridge_category_counts": optimizable_bridge["category_counts"],
        "optimizable_bridge_rows": optimizable_bridge["rows"],
        "optimizable_bridge_row_ratio": optimizable_bridge["row_ratio"],
        "optimizable_bridge_rows_by_agent": optimizable_bridge["rows_by_agent"],
        "top_optimizable_bridge_tasks": optimizable_bridge["top_tasks"],
        "bridge_optimization_note": (
            "h1_verifier_bridge is mandatory verifier-before-delivery evidence; "
            "treat g3_llm_relation_trace as the sequencing-optimizable bridge "
            "unless a future design preserves verifier-before-delivery evidence by another explicit action."
        ),
        "h1_final_delivery_rows": final_delivery_rows,
        "h1_final_delivery_note": (
            "h1_criteria_evidence rows are the final task_execute delivery surface; "
            "treat them as payload/validation cost, not removable bridge overhead."
        ),
    }


def _bridge_breakdown(
    *,
    categories: tuple[str, ...],
    total_rows: int,
    category_counts: Counter[str],
    category_task_counts: dict[str, Counter[str]],
    category_agent_counts: dict[str, Counter[str]],
) -> dict[str, Any]:
    task_counts: Counter[str] = Counter()
    agent_counts: Counter[str] = Counter()
    counts: dict[str, int] = {}
    for category in categories:
        counts[category] = int(category_counts.get(category, 0))
        task_counts.update(category_task_counts.get(category, Counter()))
        agent_counts.update(category_agent_counts.get(category, Counter()))
    rows = sum(counts.values())
    return {
        "category_counts": counts,
        "rows": rows,
        "row_ratio": rows / total_rows if total_rows else 0.0,
        "rows_by_agent": dict(sorted(agent_counts.items())),
        "top_tasks": _top(task_counts, limit=12),
    }


def _tick_categories(row: dict[str, str], reasoning: str) -> list[str]:
    categories: list[str] = []
    action = str(row.get("decision_action") or "")
    source = str(row.get("decision_source") or "")
    if source == "llm":
        categories.append("llm_decision")
    if source == "rules":
        categories.append("rules_decision")
    if action == "wait" or _bool(row.get("is_wait")):
        categories.append("wait")
    if action == "task_execute":
        categories.append("task_execute")
    if "H1 verifier-before-delivery bridge" in reasoning:
        categories.append("h1_verifier_bridge")
    if "H1 llm_judge criteria evidence" in reasoning:
        categories.append("h1_criteria_evidence")
    if row.get("relation_context_id") or row.get("relation_memory_refs"):
        categories.append("relation_context")
        if source == "llm":
            categories.append("g3_llm_relation_trace")
    if "benchmark mode: sampled adversarial verification probe" in reasoning:
        categories.append("adversarial_verification_probe")
    if "capability identity probe" in reasoning:
        categories.append("identity_probe")
    return categories or ["uncategorized"]


def _judge_workload(path: Path) -> dict[str, Any]:
    payload = _read_json(path)
    rows = payload.get("rows") if isinstance(payload.get("rows"), list) else []
    task_counts: Counter[str] = Counter()
    agent_counts: Counter[str] = Counter()
    prompt_hashes: set[str] = set()
    row_durations: list[float] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        task_counts[str(row.get("task_id") or "unknown")] += 1
        agent_counts[str(row.get("agent_alias") or "unknown")] += 1
        prompt_hash = str(row.get("prompt_hash") or "")
        if prompt_hash:
            prompt_hashes.add(prompt_hash)
        duration = _float(row.get("judge_duration_ms"))
        if duration is not None:
            row_durations.append(duration)
    report_timing = payload.get("timing") if isinstance(payload.get("timing"), dict) else {}
    total_criteria = _int(payload.get("total_criteria"))
    judged_criteria = _int(payload.get("judged_criteria"))
    duration_count = _int(report_timing.get("duration_count")) or len(row_durations)
    total_duration_ms = _float(report_timing.get("total_judge_duration_ms"))
    if total_duration_ms is None and row_durations:
        total_duration_ms = sum(row_durations)
    mean_duration_ms = _float(report_timing.get("judge_duration_ms_mean"))
    if mean_duration_ms is None and row_durations:
        mean_duration_ms = sum(row_durations) / len(row_durations)
    p50_duration_ms = _float(report_timing.get("judge_duration_ms_p50"))
    if p50_duration_ms is None:
        p50_duration_ms = _pct(row_durations, 0.50)
    p95_duration_ms = _float(report_timing.get("judge_duration_ms_p95"))
    if p95_duration_ms is None:
        p95_duration_ms = _pct(row_durations, 0.95)
    max_duration_ms = _float(report_timing.get("judge_duration_ms_max"))
    if max_duration_ms is None and row_durations:
        max_duration_ms = max(row_durations)
    duration_available = bool(report_timing.get("duration_available")) or duration_count > 0
    coverage_denominator = judged_criteria or total_criteria or 0
    return {
        "duration_available": duration_available,
        "duration_note": _judge_duration_note(duration_available),
        "duration_count": duration_count,
        "duration_coverage": duration_count / coverage_denominator if coverage_denominator else 0.0,
        "total_judge_duration_ms": total_duration_ms,
        "judge_duration_ms_mean": mean_duration_ms,
        "judge_duration_ms_p50": p50_duration_ms,
        "judge_duration_ms_p95": p95_duration_ms,
        "judge_duration_ms_max": max_duration_ms,
        "criteria_per_second": (
            duration_count / (total_duration_ms / 1000.0)
            if total_duration_ms is not None and total_duration_ms > 0
            else None
        ),
        "total_criteria": total_criteria,
        "judged_criteria": judged_criteria,
        "passed_criteria": _int(payload.get("passed_criteria")),
        "failed_criteria": _int(payload.get("failed_criteria")),
        "skipped_criteria": _int(payload.get("skipped_criteria")),
        "missing_final_output_criteria": _int(payload.get("missing_final_output_criteria")),
        "pass_rate": _float(payload.get("pass_rate")),
        "models": payload.get("models"),
        "prompt_versions": payload.get("prompt_versions"),
        "unique_prompt_hash_count": len(prompt_hashes),
        "criteria_by_agent": dict(sorted(agent_counts.items())),
        "top_tasks_by_criteria": _top(task_counts, limit=12),
    }


def _findings(
    *,
    relative_change: dict[str, float | None],
    raw_attribution: dict[str, Any],
    judge_workload: dict[str, Any],
    task_p95_warning_threshold: float,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    task_p95 = relative_change.get("task_p95_ms_mean")
    if task_p95 is not None and task_p95 > task_p95_warning_threshold:
        findings.append({
            "kind": "optimization_target",
            "metric": "task_p95_ms_mean",
            "relative_change": task_p95,
            "message": "End-to-end task p95 increased; optimize verifier/evidence/witness sequencing before treating H1-D as cheap.",
        })
    tick_volume = relative_change.get("raw_tick_rows")
    if tick_volume is not None:
        findings.append({
            "kind": "tick_volume_delta",
            "metric": "raw_tick_rows",
            "relative_change": tick_volume,
            "message": "Raw tick volume is the best current proxy for H1 runtime overhead.",
        })
    findings.append({
        "kind": "judge_workload",
        "metric": "total_criteria",
        "value": judge_workload.get("total_criteria"),
        "message": _judge_workload_message(judge_workload),
    })
    category_counts = raw_attribution.get("category_counts") if isinstance(raw_attribution, dict) else {}
    if isinstance(category_counts, dict):
        findings.append({
            "kind": "raw_tick_attribution",
            "metric": "category_counts",
            "value": category_counts,
            "message": "Use category counts to locate H1 verifier, criteria evidence, and G3 relation witness overhead.",
        })
    h1_overhead = raw_attribution.get("h1_runtime_overhead") if isinstance(raw_attribution, dict) else {}
    if isinstance(h1_overhead, dict):
        findings.append({
            "kind": "h1_runtime_overhead",
            "metric": "bridge_rows",
            "value": h1_overhead.get("bridge_rows"),
            "message": (
                "Split mandatory H1 verifier bridge from sequencing-optimizable G3 relation witness rows; "
                "H1 criteria evidence is final delivery and should not be removed."
            ),
        })
    return findings


def _cost_relative_change(
    baseline: dict[str, float | int | None],
    candidate: dict[str, float | int | None],
) -> dict[str, float | None]:
    keys = (
        "tick_p50_ms_mean",
        "tick_p95_ms_mean",
        "tick_p99_ms_mean",
        "task_p50_ms_mean",
        "task_p95_ms_mean",
        "raw_tick_rows",
        "raw_ticks_per_metrics_row",
    )
    return {key: _relative_change(baseline.get(key), candidate.get(key)) for key in keys}


def _raw_tick_rows(run_root: Path) -> int:
    rows = 0
    for path in run_root.glob("baseline-*/raw_ticks/*.csv"):
        try:
            with path.open(newline="", encoding="utf-8") as handle:
                rows += max(sum(1 for _ in handle) - 1, 0)
        except OSError:
            continue
    return rows


def _agent_alias_from_run_dir(csv_path: Path) -> str:
    run_dir = csv_path.parents[1].name
    parts = run_dir.split("-")
    return parts[1] if len(parts) >= 3 and parts[0] == "baseline" else "unknown"


def _top(counter: Counter[str], *, limit: int = 10) -> list[dict[str, int | str]]:
    return [{"key": key, "count": count} for key, count in counter.most_common(limit)]


def _read_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"expected JSON object in {path}")
    return payload


def _judge_duration_note(duration_available: bool) -> str:
    if duration_available:
        return "h1_llm_judge_report.json contains wall-clock judge duration fields."
    return "h1_llm_judge_report.json records criteria workload, not wall-clock judge duration."


def _judge_workload_message(judge_workload: dict[str, Any]) -> str:
    if judge_workload.get("duration_available"):
        return "Judge report contains wall-clock timing; use total/p95 judge duration to separate live judge cost from agent runtime cost."
    return "Judge report does not contain wall-clock duration; rerun H1 judge with timing-enabled report for direct judge cost attribution."


def _is_within(value: float | None, maximum: float) -> bool:
    return value is not None and value <= maximum


def _relative_change(baseline: float | int | None, candidate: float | int | None) -> float | None:
    if baseline is None or candidate is None or baseline <= 0:
        return None
    return (float(candidate) - float(baseline)) / float(baseline)


def _float(value: Any) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _bool(value: Any) -> bool:
    return str(value).strip().lower() in {"true", "1", "yes"}


def _mean(values: list[float]) -> float | None:
    return sum(values) / len(values) if values else None


def _pct(values: list[float], q: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = int(round((len(ordered) - 1) * q))
    return ordered[index]


def _resolve_path(path: Path, agent_root: Path) -> Path:
    return path if path.is_absolute() else agent_root / path


def main() -> int:
    agent_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-run-root", required=True)
    parser.add_argument("--candidate-run-root", required=True)
    parser.add_argument("--judge-report", required=True)
    parser.add_argument("--output", default=None)
    parser.add_argument("--max-raw-tick-volume-increase", type=float, default=0.30)
    parser.add_argument("--max-per-tick-p95-regression", type=float, default=0.30)
    parser.add_argument("--task-p95-warning-threshold", type=float, default=0.30)
    args = parser.parse_args()

    report = build_h1_cost_report(
        baseline_run_root=Path(args.baseline_run_root),
        candidate_run_root=Path(args.candidate_run_root),
        judge_report_path=Path(args.judge_report),
        agent_root=agent_root,
        max_raw_tick_volume_increase=args.max_raw_tick_volume_increase,
        max_per_tick_p95_regression=args.max_per_tick_p95_regression,
        task_p95_warning_threshold=args.task_p95_warning_threshold,
    )
    text = json.dumps(report, indent=2, sort_keys=True)
    if args.output:
        output = _resolve_path(Path(args.output), agent_root)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0 if report["passed"] else 2


if __name__ == "__main__":
    sys.exit(main())
