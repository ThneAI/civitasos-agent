from __future__ import annotations

import json
from pathlib import Path

from benchmarks.h1_release_check import check_h1d_release


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


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


def _write_raw_ticks(run_root: Path, *, rows: int) -> None:
    raw = run_root / "baseline-alpha-1" / "raw_ticks" / "R01.csv"
    raw.parent.mkdir(parents=True, exist_ok=True)
    raw.write_text("run_id,task_id,tick_seq\n" + "\n".join(f"r,t,{i}" for i in range(rows)) + "\n", encoding="utf-8")


def _write_release_payloads(tmp_path: Path) -> tuple[Path, Path, Path]:
    main = tmp_path / "runs" / "h1d"
    h0g = tmp_path / "runs" / "h0g"
    baseline = tmp_path / "runs" / "baseline"
    compare = main / "h1_compare_f1c_identity_probe_r2.json"
    _write_json(
        main / "merge_summary.json",
        {
            "integrity_gate": {"passed": True},
            "sentinel_gate": {"passed": True},
            "g2_gate": {"passed": True},
            "g3_gate": {
                "passed": True,
                "raw_llm_relation_trace_rows": 2,
                "raw_llm_relation_ref_rows": 2,
            },
            "h0_gate": {"passed": True},
            "h1_gate": {
                "passed": True,
                "raw_h1_served_intent_layer_coverage_ratio": 1.0,
                "raw_h1_verifier_before_delivery_ratio": 1.0,
            },
            "ii2_gate": {"passed": True},
            "final_metrics_rows": 2,
            "jaccard_common_task_count": 2,
        },
    )
    _write_json(
        main / "h1_llm_judge_report.json",
        {
            "passed": True,
            "total_criteria": 3,
            "judged_criteria": 3,
            "passed_criteria": 3,
            "failed_criteria": 0,
            "skipped_criteria": 0,
            "missing_final_output_criteria": 0,
            "pass_rate": 1.0,
            "min_pass_rate": 1.0,
            "models": ["gemma4:26b"],
            "prompt_versions": ["h1-judge-v1"],
        },
    )
    _write_json(
        h0g / "merge_summary.json",
        {
            "g3_gate": {"passed": True},
            "h0_gate": {
                "passed": True,
                "skipped": False,
                "require_active": True,
                "raw_h0_relation_training_sample_ratio": 1.0,
                "raw_h0_relation_negative_fast_learning_ratio": 1.0,
                "raw_h0_relation_repair_slow_recovery_ratio": 1.0,
                "raw_h0_relation_history_preserved_ratio": 1.0,
                "raw_h0_relation_repair_sample_rows": 4,
            },
        },
    )
    _write_json(compare, {"passed": True, "baseline_runs_root": str(baseline), "relative_reduction": {"m2": 1.0}})
    _write_final_metrics(baseline / "final_metrics.csv", tick_p95=10.0, task_p95=1000.0)
    _write_final_metrics(main / "final_metrics.csv", tick_p95=8.0, task_p95=1400.0)
    _write_raw_ticks(baseline, rows=10)
    _write_raw_ticks(main, rows=12)
    return main, h0g, compare


def _run_check(main: Path, h0g: Path, compare: Path, agent_root: Path) -> dict:
    return check_h1d_release(
        main_run_root=main,
        h0g_run_root=h0g,
        compare_report=compare,
        agent_root=agent_root,
        min_llm_pass_rate=1.0,
        min_llm_total_criteria=1,
        min_g3_llm_relation_trace_rows=1,
        min_h1_served_ratio=1.0,
        min_h1_verifier_ratio=1.0,
        min_h0g_relation_ratio=1.0,
        max_raw_tick_volume_increase=0.30,
        max_per_tick_p95_regression=0.30,
        require_compare=True,
    )


def test_h1d_release_check_passes_for_complete_evidence(tmp_path: Path) -> None:
    main, h0g, compare = _write_release_payloads(tmp_path)

    report = _run_check(main, h0g, compare, tmp_path)

    assert report["passed"] is True
    assert report["checks"]["judge_all_criteria_passed"] is True
    assert report["checks"]["h0g_require_active"] is True
    assert report["checks"]["raw_tick_volume_increase"] is True


def test_h1d_release_check_fails_closed_on_judge_regression(tmp_path: Path) -> None:
    main, h0g, compare = _write_release_payloads(tmp_path)
    payload = json.loads((main / "h1_llm_judge_report.json").read_text(encoding="utf-8"))
    payload["passed"] = False
    payload["passed_criteria"] = 2
    payload["failed_criteria"] = 1
    payload["pass_rate"] = 2 / 3
    _write_json(main / "h1_llm_judge_report.json", payload)

    report = _run_check(main, h0g, compare, tmp_path)

    assert report["passed"] is False
    assert report["checks"]["judge_report_passed"] is False
    assert report["checks"]["judge_pass_rate"] is False


def test_h1d_release_check_fails_when_h0g_repair_is_not_active(tmp_path: Path) -> None:
    main, h0g, compare = _write_release_payloads(tmp_path)
    payload = json.loads((h0g / "merge_summary.json").read_text(encoding="utf-8"))
    payload["h0_gate"]["require_active"] = False
    payload["h0_gate"]["raw_h0_relation_repair_slow_recovery_ratio"] = 0.0
    _write_json(h0g / "merge_summary.json", payload)

    report = _run_check(main, h0g, compare, tmp_path)

    assert report["passed"] is False
    assert report["checks"]["h0g_require_active"] is False
    assert report["checks"]["h0g_raw_h0_relation_repair_slow_recovery_ratio"] is False


def test_h1d_release_check_fails_when_tick_volume_budget_is_exceeded(tmp_path: Path) -> None:
    main, h0g, compare = _write_release_payloads(tmp_path)
    _write_raw_ticks(main, rows=20)

    report = _run_check(main, h0g, compare, tmp_path)

    assert report["passed"] is False
    assert report["checks"]["raw_tick_volume_increase"] is False