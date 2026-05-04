from __future__ import annotations

import json
from pathlib import Path

from benchmarks.h1_cost_report import build_h1_cost_report


def _write_final_metrics(path: Path, *, tick_p95: float, task_p95: float) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "agent_alias,run_id,agent_id,category_id,targets_disease,task_count,"
        "m5_tick_latency_p50_ms,m5_tick_latency_p95_ms,m5_tick_latency_p99_ms,"
        "m5_task_latency_p50_ms,m5_task_latency_p95_ms\n"
        f"alpha,r,did,R01,R,1,1.0,{tick_p95},2.0,100.0,{task_p95}\n"
        f"beta,r,did,R01,R,1,1.0,{tick_p95},2.0,100.0,{task_p95}\n",
        encoding="utf-8",
    )


def _write_raw_ticks(run_root: Path, rows: list[dict[str, str]]) -> None:
    path = run_root / "baseline-alpha-1" / "raw_ticks" / "G05_adversarial_01.csv"
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = [
        "run_id",
        "agent_id",
        "task_id",
        "tick_seq",
        "decision_action",
        "decision_source",
        "decision_reasoning",
        "is_wait",
        "relation_context_id",
        "relation_memory_refs",
    ]
    lines = [",".join(fields)]
    for idx, row in enumerate(rows, start=1):
        values = {"run_id": "r", "agent_id": "did", "task_id": "G05_adversarial_01", "tick_seq": str(idx)}
        values.update(row)
        lines.append(",".join(values.get(field, "") for field in fields))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _write_judge_report(path: Path, *, include_duration: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    rows = [
        {
            "agent_alias": "alpha",
            "task_id": "G05_adversarial_01",
            "prompt_hash": "sha256:a",
        },
        {
            "agent_alias": "alpha",
            "task_id": "V05_happy_01",
            "prompt_hash": "sha256:b",
        },
    ]
    timing = None
    if include_duration:
        rows[0]["judge_duration_ms"] = 100.0
        rows[1]["judge_duration_ms"] = 300.0
        timing = {
            "duration_available": True,
            "duration_count": 2,
            "duration_coverage": 1.0,
            "total_judge_duration_ms": 400.0,
            "judge_duration_ms_mean": 200.0,
            "judge_duration_ms_p50": 100.0,
            "judge_duration_ms_p95": 300.0,
            "judge_duration_ms_max": 300.0,
            "criteria_per_second": 5.0,
        }
    payload = {
        "total_criteria": 2,
        "judged_criteria": 2,
        "passed_criteria": 2,
        "failed_criteria": 0,
        "skipped_criteria": 0,
        "missing_final_output_criteria": 0,
        "pass_rate": 1.0,
        "models": ["gemma4:26b"],
        "prompt_versions": ["h1-judge-v1"],
        "rows": rows,
    }
    if timing is not None:
        payload["timing"] = timing
    path.write_text(
        json.dumps(payload),
        encoding="utf-8",
    )


def _write_cost_inputs(tmp_path: Path) -> tuple[Path, Path, Path]:
    baseline = tmp_path / "baseline"
    candidate = tmp_path / "candidate"
    judge = candidate / "h1_llm_judge_report.json"
    _write_final_metrics(baseline / "final_metrics.csv", tick_p95=10.0, task_p95=1000.0)
    _write_final_metrics(candidate / "final_metrics.csv", tick_p95=8.0, task_p95=1500.0)
    _write_raw_ticks(
        baseline,
        [
            {"decision_action": "task_execute", "decision_source": "rules"},
            {"decision_action": "wait", "decision_source": "llm", "is_wait": "true"},
        ],
    )
    _write_raw_ticks(
        candidate,
        [
            {
                "decision_action": "wait",
                "decision_source": "llm",
                "is_wait": "true",
                "relation_context_id": "rel:1",
                "relation_memory_refs": "task:1",
            },
            {
                "decision_action": "address_diff",
                "decision_source": "rules",
                "decision_reasoning": "benchmark mode: H1 verifier-before-delivery bridge",
            },
            {
                "decision_action": "task_execute",
                "decision_source": "rules",
                "decision_reasoning": "benchmark mode: deliver structured H1 llm_judge criteria evidence",
            },
        ],
    )
    _write_judge_report(judge)
    return baseline, candidate, judge


def test_h1_cost_report_attributes_h1_and_g3_ticks(tmp_path: Path) -> None:
    baseline, candidate, judge = _write_cost_inputs(tmp_path)

    report = build_h1_cost_report(
        baseline_run_root=baseline,
        candidate_run_root=candidate,
        judge_report_path=judge,
        agent_root=tmp_path,
        max_raw_tick_volume_increase=0.60,
        max_per_tick_p95_regression=0.30,
        task_p95_warning_threshold=0.30,
    )

    assert report["passed"] is True
    categories = report["raw_tick_attribution"]["category_counts"]
    assert categories["g3_llm_relation_trace"] == 1
    assert categories["h1_verifier_bridge"] == 1
    assert categories["h1_criteria_evidence"] == 1
    h1_overhead = report["raw_tick_attribution"]["h1_runtime_overhead"]
    assert h1_overhead["bridge_category_counts"] == {
        "g3_llm_relation_trace": 1,
        "h1_verifier_bridge": 1,
    }
    assert h1_overhead["bridge_rows"] == 2
    assert h1_overhead["bridge_row_ratio"] == 2 / 3
    assert h1_overhead["bridge_rows_by_agent"] == {"alpha": 2}
    assert h1_overhead["top_bridge_tasks"] == [
        {"key": "G05_adversarial_01", "count": 2},
    ]
    assert h1_overhead["required_bridge_category_counts"] == {"h1_verifier_bridge": 1}
    assert h1_overhead["required_bridge_rows"] == 1
    assert h1_overhead["required_bridge_row_ratio"] == 1 / 3
    assert h1_overhead["required_bridge_rows_by_agent"] == {"alpha": 1}
    assert h1_overhead["top_required_bridge_tasks"] == [
        {"key": "G05_adversarial_01", "count": 1},
    ]
    assert h1_overhead["optimizable_bridge_category_counts"] == {"g3_llm_relation_trace": 1}
    assert h1_overhead["optimizable_bridge_rows"] == 1
    assert h1_overhead["optimizable_bridge_row_ratio"] == 1 / 3
    assert h1_overhead["optimizable_bridge_rows_by_agent"] == {"alpha": 1}
    assert h1_overhead["top_optimizable_bridge_tasks"] == [
        {"key": "G05_adversarial_01", "count": 1},
    ]
    assert "mandatory verifier-before-delivery" in h1_overhead["bridge_optimization_note"]
    assert h1_overhead["h1_final_delivery_rows"] == 1
    assert "not removable bridge overhead" in h1_overhead["h1_final_delivery_note"]
    assert report["judge_workload"]["total_criteria"] == 2
    assert report["judge_workload"]["duration_available"] is False
    assert any(item["kind"] == "optimization_target" for item in report["findings"])
    assert any(item["kind"] == "h1_runtime_overhead" for item in report["findings"])


def test_h1_cost_report_reads_judge_duration_when_available(tmp_path: Path) -> None:
    baseline, candidate, judge = _write_cost_inputs(tmp_path)
    _write_judge_report(judge, include_duration=True)

    report = build_h1_cost_report(
        baseline_run_root=baseline,
        candidate_run_root=candidate,
        judge_report_path=judge,
        agent_root=tmp_path,
        max_raw_tick_volume_increase=0.60,
        max_per_tick_p95_regression=0.30,
        task_p95_warning_threshold=0.30,
    )

    workload = report["judge_workload"]
    assert workload["duration_available"] is True
    assert workload["total_judge_duration_ms"] == 400.0
    assert workload["judge_duration_ms_p95"] == 300.0
    assert workload["criteria_per_second"] == 5.0
    assert any("wall-clock timing" in item["message"] for item in report["findings"])


def test_h1_cost_report_fails_when_raw_tick_budget_is_exceeded(tmp_path: Path) -> None:
    baseline, candidate, judge = _write_cost_inputs(tmp_path)

    report = build_h1_cost_report(
        baseline_run_root=baseline,
        candidate_run_root=candidate,
        judge_report_path=judge,
        agent_root=tmp_path,
        max_raw_tick_volume_increase=0.10,
        max_per_tick_p95_regression=0.30,
        task_p95_warning_threshold=0.30,
    )

    assert report["passed"] is False
    assert report["checks"]["raw_tick_volume_within_budget"] is False


def test_h1_cost_report_fails_when_per_tick_p95_regresses(tmp_path: Path) -> None:
    baseline, candidate, judge = _write_cost_inputs(tmp_path)
    _write_final_metrics(candidate / "final_metrics.csv", tick_p95=15.0, task_p95=1500.0)

    report = build_h1_cost_report(
        baseline_run_root=baseline,
        candidate_run_root=candidate,
        judge_report_path=judge,
        agent_root=tmp_path,
        max_raw_tick_volume_increase=0.60,
        max_per_tick_p95_regression=0.30,
        task_p95_warning_threshold=0.30,
    )

    assert report["passed"] is False
    assert report["checks"]["per_tick_p95_within_budget"] is False
