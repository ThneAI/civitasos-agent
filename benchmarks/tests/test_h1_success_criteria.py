from __future__ import annotations

import csv
import json
from pathlib import Path

import benchmarks.h1.success_criteria as success_criteria
from benchmarks.h1.llm_judge import JudgeRequest, JudgeResult
from benchmarks.h1.success_criteria import (
    evaluate_llm_judge_success_criteria,
    validate_calibration_report,
)
from benchmarks.task_loader import Manifest, TaskSpec


class PassingJudge:
    def __init__(self) -> None:
        self.requests: list[JudgeRequest] = []

    def evaluate(self, req: JudgeRequest) -> JudgeResult:
        self.requests.append(req)
        return JudgeResult(
            passed=True,
            score=0.91,
            rationale="criterion satisfied",
            model="judge-test-model",
            prompt_version="h1-judge-v1",
            prompt_hash="sha256:test-prompt",
        )


def test_validate_calibration_report_accepts_passed_report(tmp_path: Path) -> None:
    path = _write_calibration_report(tmp_path / "calibration.json")

    gate = validate_calibration_report(path)

    assert gate["passed"] is True
    assert gate["agreement"] == 0.9
    assert gate["adversarial_boundary_accuracy"] == 0.8


def test_validate_calibration_report_fails_closed(tmp_path: Path) -> None:
    path = _write_calibration_report(tmp_path / "calibration.json", passed=False, skipped=1)

    gate = validate_calibration_report(path)

    assert gate["passed"] is False
    assert any("did not pass" in reason for reason in gate["failure_reasons"])
    assert any("skipped" in reason for reason in gate["failure_reasons"])


def test_evaluate_llm_judge_success_criteria_reads_final_output(tmp_path: Path, monkeypatch) -> None:
    run_dir = tmp_path / "baseline-alpha-20260101T000000Z"
    _write_run(run_dir, final_output={"answer": "安全公理保持为 10 条"})
    manifest = _manifest(tmp_path)
    judge = PassingJudge()
    ticks = iter([10.0, 10.123])
    monkeypatch.setattr(success_criteria.time, "perf_counter", lambda: next(ticks))

    report = evaluate_llm_judge_success_criteria(
        runs=[("alpha", run_dir)],
        manifest=manifest,
        judge=judge,
        calibration_report_path=_write_calibration_report(tmp_path / "calibration.json"),
    )

    assert report["passed"] is True
    assert report["total_criteria"] == 1
    assert report["passed_criteria"] == 1
    assert report["pass_rate"] == 1.0
    assert judge.requests[0].sample_id == "alpha:R01_happy_01:criterion:0"
    assert judge.requests[0].final_output == '{"answer": "安全公理保持为 10 条"}'
    assert judge.requests[0].action_trace == ["pool_claim", "task_execute"]
    assert report["timing"]["duration_available"] is True
    assert report["timing"]["duration_count"] == 1
    assert abs(report["timing"]["total_judge_duration_ms"] - 123.0) < 0.001
    assert abs(report["rows"][0]["judge_duration_ms"] - 123.0) < 0.001


def test_evaluate_llm_judge_success_criteria_fails_missing_output(tmp_path: Path) -> None:
    run_dir = tmp_path / "baseline-alpha-20260101T000000Z"
    _write_run(run_dir, final_output=None)

    report = evaluate_llm_judge_success_criteria(
        runs=[("alpha", run_dir)],
        manifest=_manifest(tmp_path),
        judge=PassingJudge(),
        calibration_report_path=_write_calibration_report(tmp_path / "calibration.json"),
    )

    assert report["passed"] is False
    assert report["missing_final_output_criteria"] == 1
    assert any("missing final output" in reason for reason in report["failure_reasons"])


def test_evaluate_llm_judge_success_criteria_can_scope_subset(tmp_path: Path, monkeypatch) -> None:
    run_dir = tmp_path / "baseline-alpha-20260101T000000Z"
    _write_run(run_dir, final_output={"answer": "安全公理保持为 10 条"})
    _write_run_task(
        run_dir,
        task_id="V04_h1_verifier_before_delivery_01",
        final_output={"answer": "address_diff before delivery"},
    )
    judge = PassingJudge()
    ticks = iter([20.0, 20.050])
    monkeypatch.setattr(success_criteria.time, "perf_counter", lambda: next(ticks))

    report = evaluate_llm_judge_success_criteria(
        runs=[("alpha", run_dir)],
        manifest=_two_task_manifest(tmp_path),
        judge=judge,
        calibration_report_path=_write_calibration_report(tmp_path / "calibration.json"),
        task_ids={"V04_h1_verifier_before_delivery_01"},
        max_criteria=1,
    )

    assert report["passed"] is True
    assert report["total_criteria"] == 1
    assert report["subset"] == {
        "enabled": True,
        "task_ids": ["V04_h1_verifier_before_delivery_01"],
        "max_criteria": 1,
        "available_criteria": 1,
        "selected_criteria": 1,
    }
    assert judge.requests[0].task_id == "V04_h1_verifier_before_delivery_01"
    assert abs(report["timing"]["total_judge_duration_ms"] - 50.0) < 0.001


def _manifest(tmp_path: Path) -> Manifest:
    task = TaskSpec(
        id="R01_happy_01",
        category_id="R01",
        category_name="translation",
        targets_disease="R",
        variant="happy_path",
        description="d",
        briefing="translate accurately",
        telos="accurate translation",
        success_criteria=[
            {"kind": "llm_judge", "body": "译文质量评分 >= 7/10", "required_in_phase": ["H.1+"]},
        ],
        max_ticks=20,
        metrics_targeted=["m1_result_deviation_rate"],
    )
    return Manifest(
        schema_version="2.0",
        allowed_metric_codes=["m1_result_deviation_rate"],
        taxonomy=[{"id": "R01"}],
        tasks=[task],
        path=tmp_path / "manifest.yaml",
    )


def _two_task_manifest(tmp_path: Path) -> Manifest:
    first = _manifest(tmp_path).tasks[0]
    second = TaskSpec(
        id="V04_h1_verifier_before_delivery_01",
        category_id="V04",
        category_name="payment_verification",
        targets_disease="V",
        variant="h1_verifier",
        description="d",
        briefing="verify before delivery",
        telos="verified transfer",
        success_criteria=[
            {"kind": "llm_judge", "body": "验证动作必须在交付前", "required_in_phase": ["H.1+"]},
        ],
        max_ticks=20,
        metrics_targeted=["m2_verification_miss_rate"],
    )
    return Manifest(
        schema_version="2.0",
        allowed_metric_codes=["m1_result_deviation_rate", "m2_verification_miss_rate"],
        taxonomy=[{"id": "R01"}, {"id": "V04"}],
        tasks=[first, second],
        path=tmp_path / "manifest.yaml",
    )


def _write_run(run_dir: Path, *, final_output: object | None) -> None:
    raw_dir = run_dir / "raw_ticks"
    raw_dir.mkdir(parents=True)
    with (raw_dir / "R01_happy_01.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["decision_action"])
        writer.writeheader()
        writer.writerow({"decision_action": "pool_claim"})
        writer.writerow({"decision_action": "task_execute"})
    summary_task = {
        "task_id": "R01_happy_01",
        "agent_self_reported_success": True,
    }
    if final_output is not None:
        summary_task["final_output"] = final_output
    (run_dir / "summary.json").write_text(
        json.dumps({"run_id": "rid-alpha", "tasks": [summary_task]}, ensure_ascii=False),
        encoding="utf-8",
    )


def _write_run_task(run_dir: Path, *, task_id: str, final_output: object | None) -> None:
    raw_dir = run_dir / "raw_ticks"
    with (raw_dir / f"{task_id}.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["decision_action"])
        writer.writeheader()
        writer.writerow({"decision_action": "address_diff"})
        writer.writerow({"decision_action": "task_execute"})
    summary_path = run_dir / "summary.json"
    payload = json.loads(summary_path.read_text(encoding="utf-8"))
    summary_task = {
        "task_id": task_id,
        "agent_self_reported_success": True,
    }
    if final_output is not None:
        summary_task["final_output"] = final_output
    payload["tasks"].append(summary_task)
    summary_path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")


def _write_calibration_report(
    path: Path,
    *,
    passed: bool = True,
    skipped: int = 0,
) -> Path:
    path.write_text(
        json.dumps({
            "schema_version": "h1c-calibration-report:v1",
            "total_samples": 60,
            "regular_samples": 50,
            "judged_samples": 60 - skipped,
            "skipped_samples": skipped,
            "agreement": 0.9,
            "adversarial_boundary_samples": 10,
            "adversarial_boundary_accuracy": 0.8,
            "models": ["judge-test-model"],
            "prompt_versions": ["h1-judge-v1"],
            "prompt_hashes": ["sha256:test"],
            "passed": passed,
            "rows": [],
        }),
        encoding="utf-8",
    )
    return path
