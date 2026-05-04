"""H.1-C LLM-as-judge calibration dataset and report logic."""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .llm_judge import JudgeRequest, JudgeResult, LLMJudge


MIN_CALIBRATION_SAMPLES = 50
MIN_ADVERSARIAL_BOUNDARY_SAMPLES = 10
DEFAULT_MIN_AGREEMENT = 0.80
DEFAULT_MIN_ADVERSARIAL_ACCURACY = 0.70


@dataclass(frozen=True)
class CalibrationSample:
    sample_id: str
    task_id: str
    briefing: str
    telos: str
    criterion_body: str
    final_output: str
    action_trace: list[str]
    gold_passed: bool
    gold_score: float
    gold_rationale: str
    adversarial_boundary: bool = False
    criterion_desc: str = ""
    category: str = ""

    def to_request(self) -> JudgeRequest:
        return JudgeRequest(
            task_id=self.task_id,
            criterion_body=self.criterion_body,
            briefing=self.briefing,
            final_output=self.final_output,
            action_trace=list(self.action_trace),
            sample_id=self.sample_id,
            telos=self.telos,
            criterion_desc=self.criterion_desc,
        )


def default_samples_path() -> Path:
    return Path(__file__).with_name("calibration_samples.jsonl")


def load_calibration_samples(path: Path | str | None = None) -> list[CalibrationSample]:
    source = Path(path) if path is not None else default_samples_path()
    samples: list[CalibrationSample] = []
    with source.open(encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, start=1):
            raw = line.strip()
            if not raw:
                continue
            try:
                payload = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSONL at {source}:{line_no}") from exc
            samples.append(_sample_from_payload(payload, source=source, line_no=line_no))
    validate_calibration_samples(samples)
    return samples


def validate_calibration_samples(samples: list[CalibrationSample]) -> None:
    if len(samples) < MIN_CALIBRATION_SAMPLES + MIN_ADVERSARIAL_BOUNDARY_SAMPLES:
        raise ValueError(
            "H1-C calibration requires at least "
            f"{MIN_CALIBRATION_SAMPLES} regular + "
            f"{MIN_ADVERSARIAL_BOUNDARY_SAMPLES} adversarial samples"
        )
    sample_ids = [sample.sample_id for sample in samples]
    if len(set(sample_ids)) != len(sample_ids):
        raise ValueError("H1-C calibration sample ids must be unique")
    adversarial = [sample for sample in samples if sample.adversarial_boundary]
    if len(adversarial) < MIN_ADVERSARIAL_BOUNDARY_SAMPLES:
        raise ValueError("H1-C calibration requires at least 10 adversarial boundary samples")
    labels = {sample.gold_passed for sample in samples}
    if labels != {False, True}:
        raise ValueError("H1-C calibration samples must contain pass and fail labels")


def evaluate_calibration(
    samples: Iterable[CalibrationSample],
    judge: LLMJudge,
    *,
    min_agreement: float = DEFAULT_MIN_AGREEMENT,
    min_adversarial_accuracy: float = DEFAULT_MIN_ADVERSARIAL_ACCURACY,
) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []

    for sample in samples:
        result = judge.evaluate(sample.to_request())
        rows.append(calibration_row(sample, result))

    return summarize_calibration_rows(
        rows,
        min_agreement=min_agreement,
        min_adversarial_accuracy=min_adversarial_accuracy,
    )


def calibration_row(sample: CalibrationSample, result: JudgeResult) -> dict[str, Any]:
    if result.skipped or result.passed is None:
        agreed = False
    else:
        agreed = result.passed == sample.gold_passed
    return {
        "sample_id": sample.sample_id,
        "task_id": sample.task_id,
        "gold_passed": sample.gold_passed,
        "judge_passed": result.passed,
        "judge_score": result.score,
        "agreed": agreed,
        "skipped": result.skipped,
        "adversarial_boundary": sample.adversarial_boundary,
        "rationale": result.rationale,
        "model": result.model,
        "prompt_version": result.prompt_version,
        "prompt_hash": result.prompt_hash,
    }


def summarize_calibration_rows(
    rows: Iterable[dict[str, Any]],
    *,
    min_agreement: float = DEFAULT_MIN_AGREEMENT,
    min_adversarial_accuracy: float = DEFAULT_MIN_ADVERSARIAL_ACCURACY,
) -> dict[str, Any]:
    materialized = list(rows)
    total = len(materialized)
    skipped = sum(1 for row in materialized if row.get("skipped") is True)
    judged = sum(
        1
        for row in materialized
        if row.get("skipped") is not True and row.get("judge_passed") is not None
    )
    matching = sum(1 for row in materialized if row.get("agreed") is True)
    adversarial_total = sum(
        1 for row in materialized if row.get("adversarial_boundary") is True
    )
    adversarial_matching = sum(
        1
        for row in materialized
        if row.get("adversarial_boundary") is True and row.get("agreed") is True
    )
    regular_total = total - adversarial_total
    models = sorted({str(row.get("model")) for row in materialized if row.get("model")})
    prompt_versions = sorted(
        {str(row.get("prompt_version")) for row in materialized if row.get("prompt_version")}
    )
    prompt_hashes = sorted(
        {str(row.get("prompt_hash")) for row in materialized if row.get("prompt_hash")}
    )

    agreement = matching / judged if judged else 0.0
    adversarial_accuracy = (
        adversarial_matching / adversarial_total if adversarial_total else 0.0
    )
    passed = (
        skipped == 0
        and judged == total
        and regular_total >= MIN_CALIBRATION_SAMPLES
        and adversarial_total >= MIN_ADVERSARIAL_BOUNDARY_SAMPLES
        and agreement >= min_agreement
        and adversarial_accuracy >= min_adversarial_accuracy
    )
    return {
        "schema_version": "h1c-calibration-report:v1",
        "total_samples": total,
        "regular_samples": regular_total,
        "judged_samples": judged,
        "skipped_samples": skipped,
        "agreement": agreement,
        "adversarial_boundary_samples": adversarial_total,
        "adversarial_boundary_accuracy": adversarial_accuracy,
        "thresholds": {
            "min_agreement": min_agreement,
            "min_adversarial_accuracy": min_adversarial_accuracy,
        },
        "models": models,
        "prompt_versions": prompt_versions,
        "prompt_hashes": prompt_hashes,
        "passed": passed,
        "rows": materialized,
    }


def _sample_from_payload(payload: Any, *, source: Path, line_no: int) -> CalibrationSample:
    if not isinstance(payload, dict):
        raise ValueError(f"sample must be an object at {source}:{line_no}")
    required = (
        "sample_id",
        "task_id",
        "briefing",
        "telos",
        "criterion_body",
        "final_output",
        "action_trace",
        "gold_passed",
        "gold_score",
        "gold_rationale",
    )
    for key in required:
        if key not in payload:
            raise ValueError(f"missing {key!r} at {source}:{line_no}")
    action_trace = payload["action_trace"]
    if not isinstance(action_trace, list) or not all(isinstance(x, str) for x in action_trace):
        raise ValueError(f"action_trace must be list[str] at {source}:{line_no}")
    gold_passed = payload["gold_passed"]
    if not isinstance(gold_passed, bool):
        raise ValueError(f"gold_passed must be bool at {source}:{line_no}")
    try:
        gold_score = float(payload["gold_score"])
    except (TypeError, ValueError) as exc:
        raise ValueError(f"gold_score must be numeric at {source}:{line_no}") from exc
    if gold_score < 0.0 or gold_score > 1.0:
        raise ValueError(f"gold_score must be in [0, 1] at {source}:{line_no}")
    return CalibrationSample(
        sample_id=_required_str(payload, "sample_id", source, line_no),
        task_id=_required_str(payload, "task_id", source, line_no),
        briefing=_required_str(payload, "briefing", source, line_no),
        telos=_required_str(payload, "telos", source, line_no),
        criterion_body=_required_str(payload, "criterion_body", source, line_no),
        final_output=_required_str(payload, "final_output", source, line_no),
        action_trace=list(action_trace),
        gold_passed=gold_passed,
        gold_score=gold_score,
        gold_rationale=_required_str(payload, "gold_rationale", source, line_no),
        adversarial_boundary=bool(payload.get("adversarial_boundary", False)),
        criterion_desc=str(payload.get("criterion_desc") or ""),
        category=str(payload.get("category") or ""),
    )


def _required_str(payload: dict[str, Any], key: str, source: Path, line_no: int) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{key} must be a non-empty string at {source}:{line_no}")
    return value
