"""H.1 llm_judge success-criteria evaluation for benchmark runs."""
from __future__ import annotations

import csv
import json
import time
from pathlib import Path
from typing import Any

from benchmarks.task_loader import Manifest, TaskSpec

from .calibration import (
    DEFAULT_MIN_ADVERSARIAL_ACCURACY,
    DEFAULT_MIN_AGREEMENT,
    MIN_ADVERSARIAL_BOUNDARY_SAMPLES,
    MIN_CALIBRATION_SAMPLES,
)
from .llm_judge import JudgeRequest, LLMJudge, PROMPT_VERSION

CALIBRATION_REPORT_SCHEMA = "h1c-calibration-report:v1"
LLM_CRITERIA_REPORT_SCHEMA = "h1-llm-criteria-report:v1"
DEFAULT_MIN_LLM_JUDGE_PASS_RATE = 1.0


def validate_calibration_report(
    report_path: str | Path | None,
    *,
    min_agreement: float = DEFAULT_MIN_AGREEMENT,
    min_adversarial_accuracy: float = DEFAULT_MIN_ADVERSARIAL_ACCURACY,
) -> dict[str, Any]:
    failure_reasons: list[str] = []
    if report_path is None:
        return _calibration_gate(
            path=None,
            payload={},
            failure_reasons=["missing H1-C calibration report path"],
        )

    path = Path(report_path)
    if not path.is_file():
        return _calibration_gate(
            path=path,
            payload={},
            failure_reasons=[f"H1-C calibration report not found: {path}"],
        )

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return _calibration_gate(
            path=path,
            payload={},
            failure_reasons=[f"invalid H1-C calibration report JSON: {exc}"],
        )
    if not isinstance(payload, dict):
        return _calibration_gate(
            path=path,
            payload={},
            failure_reasons=["H1-C calibration report must be a JSON object"],
        )

    if payload.get("schema_version") != CALIBRATION_REPORT_SCHEMA:
        failure_reasons.append("H1-C calibration report schema_version mismatch")
    if payload.get("passed") is not True:
        failure_reasons.append("H1-C calibration report did not pass")
    if _int(payload.get("regular_samples")) < MIN_CALIBRATION_SAMPLES:
        failure_reasons.append("H1-C calibration report has too few regular samples")
    if _int(payload.get("adversarial_boundary_samples")) < MIN_ADVERSARIAL_BOUNDARY_SAMPLES:
        failure_reasons.append("H1-C calibration report has too few adversarial boundary samples")
    total = _int(payload.get("total_samples"))
    judged = _int(payload.get("judged_samples"))
    skipped = _int(payload.get("skipped_samples"))
    if total <= 0 or judged != total:
        failure_reasons.append("H1-C calibration report did not judge every sample")
    if skipped != 0:
        failure_reasons.append("H1-C calibration report contains skipped samples")
    if _float(payload.get("agreement")) < min_agreement:
        failure_reasons.append("H1-C calibration agreement below threshold")
    if _float(payload.get("adversarial_boundary_accuracy")) < min_adversarial_accuracy:
        failure_reasons.append("H1-C adversarial boundary accuracy below threshold")
    if not _non_empty_strings(payload.get("models")):
        failure_reasons.append("H1-C calibration report missing judge model evidence")
    if PROMPT_VERSION not in _non_empty_strings(payload.get("prompt_versions")):
        failure_reasons.append("H1-C calibration report missing expected prompt version")
    prompt_hashes = _non_empty_strings(payload.get("prompt_hashes"))
    if not prompt_hashes or any(not item.startswith("sha256:") for item in prompt_hashes):
        failure_reasons.append("H1-C calibration report missing prompt hash evidence")

    return _calibration_gate(path=path, payload=payload, failure_reasons=failure_reasons)


def evaluate_llm_judge_success_criteria(
    *,
    runs: list[tuple[str, Path]],
    manifest: Manifest,
    judge: LLMJudge,
    calibration_report_path: str | Path | None,
    min_pass_rate: float = DEFAULT_MIN_LLM_JUDGE_PASS_RATE,
    task_ids: set[str] | None = None,
    max_criteria: int | None = None,
) -> dict[str, Any]:
    calibration_gate = validate_calibration_report(calibration_report_path)
    if not calibration_gate.get("passed"):
        return _calibration_failed_llm_judge_report(
            calibration_gate,
            min_pass_rate=min_pass_rate,
        )

    task_by_id = {task.id: task for task in manifest.tasks}
    candidates = _llm_judge_candidates(
        runs=runs,
        task_by_id=task_by_id,
        task_ids=task_ids,
    )
    selected_candidates = candidates[:max_criteria] if max_criteria is not None else candidates
    rows: list[dict[str, Any]] = []

    for candidate in selected_candidates:
        alias = candidate["alias"]
        run_dir = candidate["run_dir"]
        task = candidate["task"]
        criterion_index = candidate["criterion_index"]
        criterion = candidate["criterion"]
        final_output = candidate["final_output"]
        action_trace = candidate["action_trace"]
        if final_output is None:
            rows.append(_missing_output_row(alias, run_dir, task, criterion_index, criterion))
            continue
        started = time.perf_counter()
        result = judge.evaluate(
            JudgeRequest(
                task_id=task.id,
                criterion_body=str(criterion.get("body") or ""),
                criterion_desc=str(criterion.get("desc") or ""),
                briefing=task.briefing,
                telos=task.telos,
                final_output=final_output,
                action_trace=action_trace,
                sample_id=f"{alias}:{task.id}:criterion:{criterion_index}",
            )
        )
        judge_duration_ms = (time.perf_counter() - started) * 1000.0
        rows.append({
            "agent_alias": alias,
            "run_dir": str(run_dir),
            "task_id": task.id,
            "criterion_index": criterion_index,
            "criterion_body": str(criterion.get("body") or ""),
            "criterion_desc": str(criterion.get("desc") or ""),
            "passed": result.passed,
            "score": result.score,
            "skipped": result.skipped,
            "rationale": result.rationale,
            "model": result.model,
            "prompt_version": result.prompt_version,
            "prompt_hash": result.prompt_hash,
            "judge_duration_ms": judge_duration_ms,
        })

    subset = {
        "enabled": task_ids is not None or max_criteria is not None,
        "task_ids": sorted(task_ids) if task_ids is not None else None,
        "max_criteria": max_criteria,
        "available_criteria": len(candidates),
        "selected_criteria": len(selected_candidates),
    }

    return summarize_llm_judge_rows(
        rows,
        calibration_gate=calibration_gate,
        min_pass_rate=min_pass_rate,
        subset=subset,
    )


def _llm_judge_candidates(
    *,
    runs: list[tuple[str, Path]],
    task_by_id: dict[str, TaskSpec],
    task_ids: set[str] | None,
) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for alias, run_dir in runs:
        present_task_ids = _run_task_ids(run_dir)
        for task_id in sorted(present_task_ids):
            if task_ids is not None and task_id not in task_ids:
                continue
            task = task_by_id.get(task_id)
            if task is None:
                continue
            criteria = _llm_judge_criteria(task)
            if not criteria:
                continue
            final_output = _load_final_output(run_dir, task_id)
            action_trace = _load_action_trace(run_dir, task_id)
            for criterion_index, criterion in criteria:
                candidates.append({
                    "alias": alias,
                    "run_dir": run_dir,
                    "task": task,
                    "criterion_index": criterion_index,
                    "criterion": criterion,
                    "final_output": final_output,
                    "action_trace": action_trace,
                })
    return candidates


def summarize_llm_judge_rows(
    rows: list[dict[str, Any]],
    *,
    calibration_gate: dict[str, Any],
    min_pass_rate: float = DEFAULT_MIN_LLM_JUDGE_PASS_RATE,
    subset: dict[str, Any] | None = None,
) -> dict[str, Any]:
    total = len(rows)
    skipped = sum(1 for row in rows if row.get("skipped") is True or row.get("passed") is None)
    judged = total - skipped
    passed = sum(1 for row in rows if row.get("passed") is True and row.get("skipped") is not True)
    failed = sum(1 for row in rows if row.get("passed") is False and row.get("skipped") is not True)
    missing_output = sum(1 for row in rows if row.get("failure_kind") == "missing_final_output")
    pass_rate = passed / total if total else 0.0
    failure_reasons: list[str] = []

    if not calibration_gate.get("passed"):
        failure_reasons.append(
            "H1 llm_judge calibration gate failed: "
            + "; ".join(str(reason) for reason in calibration_gate.get("failure_reasons", []))
        )
    if total == 0:
        failure_reasons.append("H1 llm_judge enabled but no llm_judge criteria were found in run tasks")
    if skipped:
        failure_reasons.append(f"H1 llm_judge skipped or missing {skipped}/{total} criteria")
    if missing_output:
        failure_reasons.append(f"H1 llm_judge missing final output for {missing_output} criteria")
    if pass_rate < min_pass_rate:
        failure_reasons.append(
            f"H1 llm_judge pass rate {pass_rate:.4f} < {min_pass_rate:.4f}"
        )

    models = sorted({str(row.get("model")) for row in rows if row.get("model")})
    prompt_versions = sorted(
        {str(row.get("prompt_version")) for row in rows if row.get("prompt_version")}
    )
    prompt_hashes = sorted(
        {str(row.get("prompt_hash")) for row in rows if row.get("prompt_hash")}
    )
    timing = _judge_timing_summary(rows, judged)
    return {
        "schema_version": LLM_CRITERIA_REPORT_SCHEMA,
        "enabled": True,
        "skipped": False,
        "passed": not failure_reasons,
        "failure_reasons": failure_reasons,
        "total_criteria": total,
        "judged_criteria": judged,
        "passed_criteria": passed,
        "failed_criteria": failed,
        "skipped_criteria": skipped,
        "missing_final_output_criteria": missing_output,
        "pass_rate": pass_rate,
        "min_pass_rate": min_pass_rate,
        "models": models,
        "prompt_versions": prompt_versions,
        "prompt_hashes": prompt_hashes,
        "timing": timing,
        "subset": subset or {
            "enabled": False,
            "task_ids": None,
            "max_criteria": None,
            "available_criteria": total,
            "selected_criteria": total,
        },
        "calibration_gate": calibration_gate,
        "rows": rows,
    }


def disabled_llm_judge_report() -> dict[str, Any]:
    return {
        "schema_version": LLM_CRITERIA_REPORT_SCHEMA,
        "enabled": False,
        "skipped": True,
        "passed": True,
        "failure_reasons": [],
        "total_criteria": 0,
        "rows": [],
    }


def failure_llm_judge_report(reason: str) -> dict[str, Any]:
    return {
        "schema_version": LLM_CRITERIA_REPORT_SCHEMA,
        "enabled": True,
        "skipped": False,
        "passed": False,
        "failure_reasons": [reason],
        "total_criteria": 0,
        "rows": [],
    }


def _calibration_failed_llm_judge_report(
    calibration_gate: dict[str, Any],
    *,
    min_pass_rate: float,
) -> dict[str, Any]:
    reasons = calibration_gate.get("failure_reasons")
    if isinstance(reasons, list) and reasons:
        detail = "; ".join(str(reason) for reason in reasons)
    else:
        detail = "unknown calibration failure"
    return {
        "schema_version": LLM_CRITERIA_REPORT_SCHEMA,
        "enabled": True,
        "skipped": False,
        "passed": False,
        "failure_reasons": [f"H1 llm_judge calibration gate failed: {detail}"],
        "total_criteria": 0,
        "judged_criteria": 0,
        "passed_criteria": 0,
        "failed_criteria": 0,
        "skipped_criteria": 0,
        "missing_final_output_criteria": 0,
        "pass_rate": 0.0,
        "min_pass_rate": min_pass_rate,
        "models": [],
        "prompt_versions": [],
        "prompt_hashes": [],
        "calibration_gate": calibration_gate,
        "rows": [],
    }


def write_llm_judge_report(report: dict[str, Any], path: str | Path) -> Path:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    return out


def _calibration_gate(
    *,
    path: Path | None,
    payload: dict[str, Any],
    failure_reasons: list[str],
) -> dict[str, Any]:
    return {
        "path": None if path is None else str(path),
        "passed": not failure_reasons,
        "failure_reasons": failure_reasons,
        "schema_version": payload.get("schema_version"),
        "total_samples": payload.get("total_samples"),
        "regular_samples": payload.get("regular_samples"),
        "adversarial_boundary_samples": payload.get("adversarial_boundary_samples"),
        "judged_samples": payload.get("judged_samples"),
        "skipped_samples": payload.get("skipped_samples"),
        "agreement": payload.get("agreement"),
        "adversarial_boundary_accuracy": payload.get("adversarial_boundary_accuracy"),
        "models": payload.get("models", []),
        "prompt_versions": payload.get("prompt_versions", []),
        "prompt_hashes": payload.get("prompt_hashes", []),
    }


def _llm_judge_criteria(task: TaskSpec) -> list[tuple[int, dict[str, Any]]]:
    out: list[tuple[int, dict[str, Any]]] = []
    for index, criterion in enumerate(task.success_criteria):
        if criterion.get("kind") != "llm_judge":
            continue
        phases = criterion.get("required_in_phase")
        if isinstance(phases, list) and "H.1+" not in {str(phase) for phase in phases}:
            continue
        out.append((index, criterion))
    return out


def _run_task_ids(run_dir: Path) -> set[str]:
    summary_path = run_dir / "summary.json"
    task_ids: set[str] = set()
    if summary_path.is_file():
        try:
            payload = json.loads(summary_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            payload = {}
        if isinstance(payload, dict):
            tasks = payload.get("tasks")
            if isinstance(tasks, list):
                for item in tasks:
                    if isinstance(item, dict) and isinstance(item.get("task_id"), str):
                        task_ids.add(item["task_id"])
    raw_dir = run_dir / "raw_ticks"
    if raw_dir.is_dir():
        task_ids.update(path.stem for path in raw_dir.glob("*.csv") if not path.name.startswith("_"))
    return task_ids


def _load_final_output(run_dir: Path, task_id: str) -> str | None:
    output = _load_summary_final_output(run_dir, task_id)
    if output is not None:
        return output
    task_dir = run_dir / "tasks" / task_id
    for path in (task_dir / "result.json", task_dir / "backend_terminal_state.json"):
        output = _load_output_from_json(path)
        if output is not None:
            return output
    return _load_sentinel_final_artifact(task_dir / "sentinel")


def _load_summary_final_output(run_dir: Path, task_id: str) -> str | None:
    path = run_dir / "summary.json"
    if not path.is_file():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict) or not isinstance(payload.get("tasks"), list):
        return None
    for item in payload["tasks"]:
        if not isinstance(item, dict) or item.get("task_id") != task_id:
            continue
        return _output_to_text(item.get("final_output"))
    return None


def _load_output_from_json(path: Path) -> str | None:
    if not path.is_file():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    if "final_output" in payload:
        return _output_to_text(payload.get("final_output"))
    if "output" in payload:
        return _output_to_text(payload.get("output"))
    return None


def _load_sentinel_final_artifact(sentinel_dir: Path) -> str | None:
    if not sentinel_dir.is_dir():
        return None
    for path in sorted(sentinel_dir.iterdir()):
        if not path.is_file():
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(payload, dict) and "final_artifact" in payload:
            return _output_to_text(payload.get("final_artifact"))
    return None


def _load_action_trace(run_dir: Path, task_id: str) -> list[str]:
    path = run_dir / "raw_ticks" / f"{task_id}.csv"
    if not path.is_file():
        return []
    try:
        with path.open(encoding="utf-8", newline="") as handle:
            return [
                str(row.get("decision_action") or "")
                for row in csv.DictReader(handle)
                if row.get("decision_action")
            ]
    except OSError:
        return []


def _missing_output_row(
    alias: str,
    run_dir: Path,
    task: TaskSpec,
    criterion_index: int,
    criterion: dict[str, Any],
) -> dict[str, Any]:
    return {
        "agent_alias": alias,
        "run_dir": str(run_dir),
        "task_id": task.id,
        "criterion_index": criterion_index,
        "criterion_body": str(criterion.get("body") or ""),
        "criterion_desc": str(criterion.get("desc") or ""),
        "passed": None,
        "score": None,
        "skipped": True,
        "failure_kind": "missing_final_output",
        "rationale": "missing final output evidence for llm_judge criterion",
        "model": "",
        "prompt_version": "",
        "prompt_hash": "",
        "judge_duration_ms": None,
    }


def _judge_timing_summary(rows: list[dict[str, Any]], judged: int) -> dict[str, Any]:
    durations = [
        float(duration)
        for row in rows
        for duration in [_float_or_none(row.get("judge_duration_ms"))]
        if duration is not None
    ]
    total_ms = sum(durations)
    count = len(durations)
    return {
        "duration_available": count > 0 and count == judged,
        "duration_count": count,
        "duration_coverage": count / judged if judged else 0.0,
        "total_judge_duration_ms": total_ms if durations else None,
        "judge_duration_ms_mean": total_ms / count if durations else None,
        "judge_duration_ms_p50": _pct(durations, 0.50),
        "judge_duration_ms_p95": _pct(durations, 0.95),
        "judge_duration_ms_max": max(durations) if durations else None,
        "criteria_per_second": (count / (total_ms / 1000.0)) if total_ms > 0 else None,
    }


def _output_to_text(output: object) -> str | None:
    if output is None or output == "":
        return None
    if isinstance(output, str):
        return output
    return json.dumps(output, ensure_ascii=False, sort_keys=True, default=str)


def _int(value: object) -> int:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return 0


def _float(value: object) -> float:
    try:
        return float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return 0.0


def _float_or_none(value: object) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def _pct(values: list[float], q: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = int(round((len(ordered) - 1) * q))
    return ordered[index]


def _non_empty_strings(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if str(item).strip()]
