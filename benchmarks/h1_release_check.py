"""H.1-D release evidence checker.

Validates already-produced H1-D artifacts without rerunning agents or judge
models. This is the low-cost release check layer: it fails closed when core
evidence is missing, thresholds are relaxed, or carry-through gates regress.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Any


def check_h1d_release(
    *,
    main_run_root: Path,
    h0g_run_root: Path,
    compare_report: Path | None,
    agent_root: Path,
    min_llm_pass_rate: float,
    min_llm_total_criteria: int,
    min_g3_llm_relation_trace_rows: int,
    min_h1_served_ratio: float,
    min_h1_verifier_ratio: float,
    min_h0g_relation_ratio: float,
    max_raw_tick_volume_increase: float,
    max_per_tick_p95_regression: float,
    require_compare: bool,
) -> dict[str, Any]:
    main_run_root = _resolve_path(main_run_root, agent_root)
    h0g_run_root = _resolve_path(h0g_run_root, agent_root)
    compare_report = _default_compare_report(main_run_root) if compare_report is None else compare_report
    compare_report = _resolve_path(compare_report, agent_root)

    checks: dict[str, bool] = {}
    failures: list[str] = []
    evidence: dict[str, Any] = {
        "main_run_root": str(main_run_root),
        "h0g_run_root": str(h0g_run_root),
        "compare_report": str(compare_report),
    }

    main_summary = _read_json(main_run_root / "merge_summary.json", failures)
    judge_report = _read_json(main_run_root / "h1_llm_judge_report.json", failures)
    h0g_summary = _read_json(h0g_run_root / "merge_summary.json", failures)
    compare_payload = _read_json(compare_report, failures) if compare_report.exists() else None
    if compare_payload is None and require_compare:
        failures.append(f"missing required compare report: {compare_report}")

    _check_main_gate_summary(
        main_summary,
        checks=checks,
        failures=failures,
        evidence=evidence,
        min_g3_llm_relation_trace_rows=min_g3_llm_relation_trace_rows,
        min_h1_served_ratio=min_h1_served_ratio,
        min_h1_verifier_ratio=min_h1_verifier_ratio,
    )
    _check_judge_report(
        judge_report,
        checks=checks,
        failures=failures,
        evidence=evidence,
        min_llm_pass_rate=min_llm_pass_rate,
        min_llm_total_criteria=min_llm_total_criteria,
    )
    _check_h0g_supplement(
        h0g_summary,
        checks=checks,
        failures=failures,
        evidence=evidence,
        min_h0g_relation_ratio=min_h0g_relation_ratio,
    )
    _check_compare_report(
        compare_payload,
        checks=checks,
        failures=failures,
        evidence=evidence,
        require_compare=require_compare,
    )
    _check_cost_budget(
        compare_payload,
        main_run_root=main_run_root,
        agent_root=agent_root,
        checks=checks,
        failures=failures,
        evidence=evidence,
        max_raw_tick_volume_increase=max_raw_tick_volume_increase,
        max_per_tick_p95_regression=max_per_tick_p95_regression,
    )

    return {
        "schema_version": "h1d-release-check:v1",
        "passed": not failures and all(checks.values()),
        "checks": checks,
        "failure_reasons": failures,
        "thresholds": {
            "min_llm_pass_rate": min_llm_pass_rate,
            "min_llm_total_criteria": min_llm_total_criteria,
            "min_g3_llm_relation_trace_rows": min_g3_llm_relation_trace_rows,
            "min_h1_served_ratio": min_h1_served_ratio,
            "min_h1_verifier_ratio": min_h1_verifier_ratio,
            "min_h0g_relation_ratio": min_h0g_relation_ratio,
            "max_raw_tick_volume_increase": max_raw_tick_volume_increase,
            "max_per_tick_p95_regression": max_per_tick_p95_regression,
            "require_compare": require_compare,
        },
        "evidence": evidence,
    }


def _check_main_gate_summary(
    summary: dict[str, Any] | None,
    *,
    checks: dict[str, bool],
    failures: list[str],
    evidence: dict[str, Any],
    min_g3_llm_relation_trace_rows: int,
    min_h1_served_ratio: float,
    min_h1_verifier_ratio: float,
) -> None:
    if summary is None:
        _fail(checks, failures, "main_summary_present", "missing main merge_summary.json")
        return
    checks["main_summary_present"] = True
    for key in ("integrity_gate", "sentinel_gate", "g2_gate", "g3_gate", "h0_gate", "h1_gate", "ii2_gate"):
        _require_gate(summary, key, checks=checks, failures=failures)

    g3 = _object(summary.get("g3_gate"))
    h1 = _object(summary.get("h1_gate"))
    relation_trace_rows = _int(g3.get("raw_llm_relation_trace_rows"))
    relation_ref_rows = _int(g3.get("raw_llm_relation_ref_rows"))
    served_ratio = _float(h1.get("raw_h1_served_intent_layer_coverage_ratio"))
    verifier_ratio = _float(h1.get("raw_h1_verifier_before_delivery_ratio"))
    evidence["main_gate_metrics"] = {
        "final_metrics_rows": _int(summary.get("final_metrics_rows")),
        "jaccard_common_task_count": _int(summary.get("jaccard_common_task_count")),
        "raw_llm_relation_trace_rows": relation_trace_rows,
        "raw_llm_relation_ref_rows": relation_ref_rows,
        "raw_h1_served_intent_layer_coverage_ratio": served_ratio,
        "raw_h1_verifier_before_delivery_ratio": verifier_ratio,
    }
    _require_min(
        "g3_llm_relation_trace_rows",
        relation_trace_rows,
        min_g3_llm_relation_trace_rows,
        checks=checks,
        failures=failures,
    )
    _require_min(
        "g3_llm_relation_ref_rows",
        relation_ref_rows,
        relation_trace_rows,
        checks=checks,
        failures=failures,
    )
    _require_min("h1_served_intent_ratio", served_ratio, min_h1_served_ratio, checks=checks, failures=failures)
    _require_min("h1_verifier_ratio", verifier_ratio, min_h1_verifier_ratio, checks=checks, failures=failures)


def _check_judge_report(
    report: dict[str, Any] | None,
    *,
    checks: dict[str, bool],
    failures: list[str],
    evidence: dict[str, Any],
    min_llm_pass_rate: float,
    min_llm_total_criteria: int,
) -> None:
    if report is None:
        _fail(checks, failures, "judge_report_present", "missing h1_llm_judge_report.json")
        return
    checks["judge_report_present"] = True
    total = _int(report.get("total_criteria"))
    judged = _int(report.get("judged_criteria"))
    passed = _int(report.get("passed_criteria"))
    failed = _int(report.get("failed_criteria"))
    skipped = _int(report.get("skipped_criteria"))
    missing = _int(report.get("missing_final_output_criteria"))
    pass_rate = _float(report.get("pass_rate"))
    evidence["judge_report"] = {
        "passed": bool(report.get("passed")),
        "total_criteria": total,
        "judged_criteria": judged,
        "passed_criteria": passed,
        "failed_criteria": failed,
        "skipped_criteria": skipped,
        "missing_final_output_criteria": missing,
        "pass_rate": pass_rate,
        "min_pass_rate": _float(report.get("min_pass_rate")),
        "models": report.get("models"),
        "prompt_versions": report.get("prompt_versions"),
    }
    _require_bool("judge_report_passed", bool(report.get("passed")), checks=checks, failures=failures)
    _require_min("judge_total_criteria", total, min_llm_total_criteria, checks=checks, failures=failures)
    _require_equal("judge_all_criteria_judged", judged, total, checks=checks, failures=failures)
    _require_equal("judge_all_criteria_passed", passed, total, checks=checks, failures=failures)
    _require_equal("judge_failed_criteria_zero", failed, 0, checks=checks, failures=failures)
    _require_equal("judge_skipped_criteria_zero", skipped, 0, checks=checks, failures=failures)
    _require_equal("judge_missing_final_output_zero", missing, 0, checks=checks, failures=failures)
    _require_min("judge_pass_rate", pass_rate, min_llm_pass_rate, checks=checks, failures=failures)


def _check_h0g_supplement(
    summary: dict[str, Any] | None,
    *,
    checks: dict[str, bool],
    failures: list[str],
    evidence: dict[str, Any],
    min_h0g_relation_ratio: float,
) -> None:
    if summary is None:
        _fail(checks, failures, "h0g_summary_present", "missing H0G supplement merge_summary.json")
        return
    checks["h0g_summary_present"] = True
    _require_gate(summary, "g3_gate", checks=checks, failures=failures, prefix="h0g_")
    _require_gate(summary, "h0_gate", checks=checks, failures=failures, prefix="h0g_")
    h0 = _object(summary.get("h0_gate"))
    evidence["h0g_supplement"] = {
        "require_active": bool(h0.get("require_active")),
        "skipped": bool(h0.get("skipped")),
        "raw_h0_relation_training_sample_ratio": _float(h0.get("raw_h0_relation_training_sample_ratio")),
        "raw_h0_relation_negative_fast_learning_ratio": _float(h0.get("raw_h0_relation_negative_fast_learning_ratio")),
        "raw_h0_relation_repair_slow_recovery_ratio": _float(h0.get("raw_h0_relation_repair_slow_recovery_ratio")),
        "raw_h0_relation_history_preserved_ratio": _float(h0.get("raw_h0_relation_history_preserved_ratio")),
        "raw_h0_relation_repair_sample_rows": _int(h0.get("raw_h0_relation_repair_sample_rows")),
    }
    _require_bool("h0g_require_active", bool(h0.get("require_active")), checks=checks, failures=failures)
    _require_bool("h0g_not_skipped", not bool(h0.get("skipped")), checks=checks, failures=failures)
    for field in (
        "raw_h0_relation_training_sample_ratio",
        "raw_h0_relation_negative_fast_learning_ratio",
        "raw_h0_relation_repair_slow_recovery_ratio",
        "raw_h0_relation_history_preserved_ratio",
    ):
        _require_min(f"h0g_{field}", _float(h0.get(field)), min_h0g_relation_ratio, checks=checks, failures=failures)
    _require_min("h0g_repair_sample_rows", _int(h0.get("raw_h0_relation_repair_sample_rows")), 1, checks=checks, failures=failures)


def _check_compare_report(
    report: dict[str, Any] | None,
    *,
    checks: dict[str, bool],
    failures: list[str],
    evidence: dict[str, Any],
    require_compare: bool,
) -> None:
    if report is None:
        if not require_compare:
            checks["compare_report_optional"] = True
        return
    checks["compare_report_present"] = True
    evidence["compare_report_summary"] = {
        "passed": bool(report.get("passed")),
        "baseline_runs_root": report.get("baseline_runs_root"),
        "candidate_runs_root": report.get("candidate_runs_root"),
        "relative_reduction": report.get("relative_reduction"),
        "delta": report.get("delta"),
    }
    _require_bool("compare_report_passed", bool(report.get("passed")), checks=checks, failures=failures)


def _check_cost_budget(
    compare_report: dict[str, Any] | None,
    *,
    main_run_root: Path,
    agent_root: Path,
    checks: dict[str, bool],
    failures: list[str],
    evidence: dict[str, Any],
    max_raw_tick_volume_increase: float,
    max_per_tick_p95_regression: float,
) -> None:
    if compare_report is None:
        checks["cost_budget_skipped_without_compare"] = True
        return
    baseline_raw = compare_report.get("baseline_runs_root")
    baseline_root = _resolve_path(Path(str(baseline_raw)), agent_root) if baseline_raw else None
    if baseline_root is None:
        _fail(checks, failures, "cost_budget_baseline_present", "compare report has no baseline_runs_root")
        return
    baseline_cost = _cost_metrics(baseline_root)
    candidate_cost = _cost_metrics(main_run_root)
    evidence["cost"] = {"baseline": baseline_cost, "candidate": candidate_cost}
    raw_increase = _relative_change(baseline_cost.get("raw_tick_rows"), candidate_cost.get("raw_tick_rows"))
    tick_p95_regression = _relative_change(
        baseline_cost.get("tick_p95_ms_mean"),
        candidate_cost.get("tick_p95_ms_mean"),
    )
    evidence["cost_delta"] = {
        "raw_tick_volume_relative_change": raw_increase,
        "tick_p95_ms_mean_relative_change": tick_p95_regression,
        "task_p95_ms_mean_relative_change": _relative_change(
            baseline_cost.get("task_p95_ms_mean"),
            candidate_cost.get("task_p95_ms_mean"),
        ),
    }
    _require_max("raw_tick_volume_increase", raw_increase, max_raw_tick_volume_increase, checks=checks, failures=failures)
    _require_max("per_tick_p95_regression", tick_p95_regression, max_per_tick_p95_regression, checks=checks, failures=failures)


def _cost_metrics(run_root: Path) -> dict[str, float | int | None]:
    metrics = _final_metrics_means(run_root / "final_metrics.csv")
    raw_tick_rows = _raw_tick_rows(run_root)
    metrics["raw_tick_rows"] = raw_tick_rows
    metrics["raw_ticks_per_metrics_row"] = (
        raw_tick_rows / metrics["final_metrics_rows"]
        if metrics.get("final_metrics_rows")
        else None
    )
    return metrics


def _final_metrics_means(path: Path) -> dict[str, float | int | None]:
    fields = (
        "m5_tick_latency_p50_ms",
        "m5_tick_latency_p95_ms",
        "m5_tick_latency_p99_ms",
        "m5_task_latency_p50_ms",
        "m5_task_latency_p95_ms",
    )
    buckets: dict[str, list[float]] = {field: [] for field in fields}
    if not path.exists():
        return {"final_metrics_rows": 0, **{_mean_key(field): None for field in fields}}
    with path.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            for field in fields:
                value = _float(row.get(field))
                if value is not None:
                    buckets[field].append(value)
    row_count = max((len(values) for values in buckets.values()), default=0)
    return {
        "final_metrics_rows": row_count,
        **{_mean_key(field): _mean(values) for field, values in buckets.items()},
    }


def _raw_tick_rows(run_root: Path) -> int:
    rows = 0
    for path in run_root.glob("baseline-*/raw_ticks/*.csv"):
        try:
            with path.open(newline="", encoding="utf-8") as handle:
                rows += max(sum(1 for _ in handle) - 1, 0)
        except OSError:
            continue
    return rows


def _read_json(path: Path, failures: list[str]) -> dict[str, Any] | None:
    if not path.exists():
        failures.append(f"missing JSON artifact: {path}")
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        failures.append(f"invalid JSON artifact {path}: {exc}")
        return None
    if not isinstance(payload, dict):
        failures.append(f"expected JSON object in {path}")
        return None
    return payload


def _require_gate(
    summary: dict[str, Any],
    key: str,
    *,
    checks: dict[str, bool],
    failures: list[str],
    prefix: str = "",
) -> None:
    gate = _object(summary.get(key))
    _require_bool(f"{prefix}{key}_passed", bool(gate.get("passed")), checks=checks, failures=failures)


def _require_bool(name: str, value: bool, *, checks: dict[str, bool], failures: list[str]) -> None:
    checks[name] = value
    if not value:
        failures.append(f"{name} is false")


def _require_equal(
    name: str,
    value: int | None,
    expected: int | None,
    *,
    checks: dict[str, bool],
    failures: list[str],
) -> None:
    passed = value is not None and expected is not None and value == expected
    checks[name] = passed
    if not passed:
        failures.append(f"{name} {value} != {expected}")


def _require_min(
    name: str,
    value: float | int | None,
    minimum: float | int | None,
    *,
    checks: dict[str, bool],
    failures: list[str],
) -> None:
    passed = value is not None and minimum is not None and value >= minimum
    checks[name] = passed
    if not passed:
        failures.append(f"{name} {value} < {minimum}")


def _require_max(
    name: str,
    value: float | int | None,
    maximum: float | int,
    *,
    checks: dict[str, bool],
    failures: list[str],
) -> None:
    passed = value is not None and value <= maximum
    checks[name] = passed
    if not passed:
        failures.append(f"{name} {value} > {maximum}")


def _fail(checks: dict[str, bool], failures: list[str], name: str, reason: str) -> None:
    checks[name] = False
    failures.append(reason)


def _object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _float(value: Any) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _mean(values: list[float]) -> float | None:
    return sum(values) / len(values) if values else None


def _mean_key(field: str) -> str:
    return {
        "m5_tick_latency_p50_ms": "tick_p50_ms_mean",
        "m5_tick_latency_p95_ms": "tick_p95_ms_mean",
        "m5_tick_latency_p99_ms": "tick_p99_ms_mean",
        "m5_task_latency_p50_ms": "task_p50_ms_mean",
        "m5_task_latency_p95_ms": "task_p95_ms_mean",
    }[field]


def _relative_change(baseline: float | int | None, candidate: float | int | None) -> float | None:
    if baseline is None or candidate is None or baseline <= 0:
        return None
    return (float(candidate) - float(baseline)) / float(baseline)


def _resolve_path(path: Path, agent_root: Path) -> Path:
    return path if path.is_absolute() else agent_root / path


def _default_compare_report(main_run_root: Path) -> Path:
    return main_run_root / "h1_compare_f1c_identity_probe_r2.json"


def main() -> int:
    agent_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--main-run-root", required=True)
    parser.add_argument("--h0g-run-root", required=True)
    parser.add_argument("--compare-report", default=None)
    parser.add_argument("--output", default=None)
    parser.add_argument("--min-llm-pass-rate", type=float, default=1.0)
    parser.add_argument("--min-llm-total-criteria", type=int, default=1)
    parser.add_argument("--min-g3-llm-relation-trace-rows", type=int, default=1)
    parser.add_argument("--min-h1-served-ratio", type=float, default=1.0)
    parser.add_argument("--min-h1-verifier-ratio", type=float, default=1.0)
    parser.add_argument("--min-h0g-relation-ratio", type=float, default=1.0)
    parser.add_argument("--max-raw-tick-volume-increase", type=float, default=0.30)
    parser.add_argument("--max-per-tick-p95-regression", type=float, default=0.30)
    parser.add_argument("--allow-missing-compare", action="store_true")
    args = parser.parse_args()

    report = check_h1d_release(
        main_run_root=Path(args.main_run_root),
        h0g_run_root=Path(args.h0g_run_root),
        compare_report=Path(args.compare_report) if args.compare_report else None,
        agent_root=agent_root,
        min_llm_pass_rate=args.min_llm_pass_rate,
        min_llm_total_criteria=args.min_llm_total_criteria,
        min_g3_llm_relation_trace_rows=args.min_g3_llm_relation_trace_rows,
        min_h1_served_ratio=args.min_h1_served_ratio,
        min_h1_verifier_ratio=args.min_h1_verifier_ratio,
        min_h0g_relation_ratio=args.min_h0g_relation_ratio,
        max_raw_tick_volume_increase=args.max_raw_tick_volume_increase,
        max_per_tick_p95_regression=args.max_per_tick_p95_regression,
        require_compare=not args.allow_missing_compare,
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