"""Run H.1-C LLM-as-judge calibration against a labeled dataset."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from benchmarks.h1.calibration import (
    DEFAULT_MIN_ADVERSARIAL_ACCURACY,
    DEFAULT_MIN_AGREEMENT,
    calibration_row,
    evaluate_calibration,
    load_calibration_samples,
    summarize_calibration_rows,
)
from benchmarks.h1.llm_judge import (
    JudgeBackendUnavailable,
    JudgeResponseInvalid,
    build_judge_from_env,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--samples", default="")
    parser.add_argument("--output", default="")
    parser.add_argument("--checkpoint", default="")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--min-agreement", type=float, default=DEFAULT_MIN_AGREEMENT)
    parser.add_argument(
        "--min-adversarial-accuracy",
        type=float,
        default=DEFAULT_MIN_ADVERSARIAL_ACCURACY,
    )
    args = parser.parse_args()

    checkpoint = _checkpoint_path(args.output, args.checkpoint)
    rows: list[dict] = []
    try:
        samples = load_calibration_samples(Path(args.samples) if args.samples else None)
        if args.limit > 0:
            samples = samples[: args.limit]
        if checkpoint is not None:
            rows = _load_checkpoint_rows(checkpoint) if args.resume else []
            if not args.resume and checkpoint.exists():
                checkpoint.unlink()
        judge = build_judge_from_env()
        if checkpoint is None:
            report = evaluate_calibration(
                samples,
                judge,
                min_agreement=args.min_agreement,
                min_adversarial_accuracy=args.min_adversarial_accuracy,
            )
        else:
            rows = _evaluate_with_checkpoint(samples, judge, checkpoint, rows)
            report = summarize_calibration_rows(
                rows,
                min_agreement=args.min_agreement,
                min_adversarial_accuracy=args.min_adversarial_accuracy,
            )
    except KeyboardInterrupt:
        report = summarize_calibration_rows(
            rows,
            min_agreement=args.min_agreement,
            min_adversarial_accuracy=args.min_adversarial_accuracy,
        )
        report["passed"] = False
        report["interrupted"] = True
        _emit(report, args.output)
        return 130
    except (JudgeBackendUnavailable, JudgeResponseInvalid) as exc:
        report = {
            "schema_version": "h1c-calibration-report:v1",
            "passed": False,
            "error": str(exc),
            "rows": rows,
        }
        _emit(report, args.output)
        return 3

    _emit(report, args.output)
    return 0 if report["passed"] else 2


def _emit(report: dict, output: str) -> None:
    text = json.dumps(report, indent=2, ensure_ascii=False)
    print(text)
    if output:
        path = Path(output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text + "\n", encoding="utf-8")


def _checkpoint_path(output: str, checkpoint: str) -> Path | None:
    if checkpoint:
        return Path(checkpoint)
    if output:
        return Path(f"{output}.checkpoint.jsonl")
    return None


def _load_checkpoint_rows(path: Path) -> list[dict]:
    if not path.exists():
        return []
    rows: list[dict] = []
    seen: set[str] = set()
    with path.open(encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, start=1):
            raw = line.strip()
            if not raw:
                continue
            try:
                row = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid checkpoint JSON at {path}:{line_no}") from exc
            sample_id = str(row.get("sample_id") or "")
            if not sample_id or sample_id in seen:
                continue
            seen.add(sample_id)
            rows.append(row)
    return rows


def _evaluate_with_checkpoint(samples: list, judge, checkpoint: Path, rows: list[dict]) -> list[dict]:
    done = {str(row.get("sample_id")) for row in rows if row.get("sample_id")}
    checkpoint.parent.mkdir(parents=True, exist_ok=True)
    with checkpoint.open("a", encoding="utf-8") as handle:
        for index, sample in enumerate(samples, start=1):
            if sample.sample_id in done:
                continue
            print(
                f"[h1c] judging {index}/{len(samples)} {sample.sample_id}",
                file=sys.stderr,
                flush=True,
            )
            result = judge.evaluate(sample.to_request())
            row = calibration_row(sample, result)
            rows.append(row)
            done.add(sample.sample_id)
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
            handle.flush()
    return rows


if __name__ == "__main__":
    sys.exit(main())
