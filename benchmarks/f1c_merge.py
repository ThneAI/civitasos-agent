"""benchmarks/f1c_merge.py — Combine N per-agent runs into one final_metrics.csv.

Discovers ``runs/F1c/baseline-<alias>-<ts>/`` directories, runs the F.0
``aggregator.aggregate_run`` over each, then concatenates with an
``agent_alias`` discriminator column prepended to support per-disease
break-downs in the F.1.d REPORT (§4.3 / §5.2).

Also writes:
  - ``inter_agent_jaccard.csv`` — pseudo-sample detection (§3.5):
    Jaccard similarity of action sequences per common task; flags any
    pair >= 0.95 as a basleine integrity issue.
"""
from __future__ import annotations

import argparse
import csv
import json
import logging
import re
import sys
from dataclasses import asdict
from pathlib import Path

from .aggregator import (
    FINAL_METRIC_COLUMNS,
    AggregatorError,
    aggregate_run,
)
from .task_loader import load_manifest

logger = logging.getLogger("f1c_merge")

_RUN_DIR_RE = re.compile(r"^baseline-(?P<alias>[a-z]+)-(?P<ts>\d{8}T\d{6}Z)$")


def _discover_runs(runs_root: Path) -> list[tuple[str, Path]]:
    """Return [(alias, run_dir), ...] for the latest run per alias."""
    candidates: dict[str, tuple[str, Path]] = {}  # alias -> (ts, dir)
    for d in runs_root.iterdir():
        if not d.is_dir():
            continue
        m = _RUN_DIR_RE.match(d.name)
        if not m:
            continue
        alias, ts = m["alias"], m["ts"]
        cur = candidates.get(alias)
        if cur is None or ts > cur[0]:
            candidates[alias] = (ts, d)
    return sorted([(alias, d) for alias, (_ts, d) in candidates.items()])


def _row_with_alias(alias: str, agg) -> dict[str, str]:
    """Flatten an AggregateRow to a CSV-ready dict, prepending agent_alias."""
    out: dict[str, str] = {"agent_alias": alias}
    for col in FINAL_METRIC_COLUMNS:
        if col in ("m1_result_deviation_rate", "m2_verification_miss_rate",
                   "m3_aspect_gap_response_rate", "m4_lessons_impact_rate",
                   "m5_tick_latency_p50_ms", "m5_tick_latency_p95_ms",
                   "m5_tick_latency_p99_ms", "m5_task_latency_p50_ms",
                   "m5_task_latency_p95_ms", "m6_wait_ratio"):
            v = agg.metrics.get(col)
            out[col] = "" if v is None else f"{v:.6f}" if isinstance(v, float) else str(v)
        else:
            out[col] = str(getattr(agg, col, ""))
    return out


def _action_seq(run_dir: Path, task_id: str) -> tuple[str, ...]:
    """Read raw_ticks/<task_id>.csv and return the decision.action sequence."""
    csv_path = run_dir / "raw_ticks" / f"{task_id}.csv"
    if not csv_path.exists():
        return ()
    actions: list[str] = []
    with csv_path.open(newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            a = row.get("decision_action") or row.get("action") or ""
            if a:
                actions.append(a)
    return tuple(actions)


def _jaccard(a: tuple[str, ...], b: tuple[str, ...]) -> float:
    sa, sb = set(a), set(b)
    if not sa and not sb:
        return 1.0
    return len(sa & sb) / len(sa | sb) if (sa | sb) else 0.0


def _inter_agent_jaccard(runs: list[tuple[str, Path]]) -> list[dict[str, str]]:
    """For each task common to ≥2 runs, compute pairwise Jaccard."""
    per_alias_tasks: dict[str, set[str]] = {}
    for alias, d in runs:
        raw_dir = d / "raw_ticks"
        if raw_dir.exists():
            per_alias_tasks[alias] = {p.stem for p in raw_dir.glob("*.csv")}
        else:
            per_alias_tasks[alias] = set()
    common = set.intersection(*per_alias_tasks.values()) if per_alias_tasks else set()
    rows: list[dict[str, str]] = []
    aliases = [a for a, _ in runs]
    for task_id in sorted(common):
        seqs = {a: _action_seq(d, task_id) for a, d in runs}
        for i, a in enumerate(aliases):
            for b in aliases[i + 1:]:
                j = _jaccard(seqs[a], seqs[b])
                rows.append({
                    "task_id": task_id,
                    "agent_a": a,
                    "agent_b": b,
                    "jaccard": f"{j:.4f}",
                    "len_a": str(len(seqs[a])),
                    "len_b": str(len(seqs[b])),
                    "flagged": "1" if j >= 0.95 else "0",
                })
    return rows


def merge(*, runs_root: Path, manifest_path: Path, schema_yaml: Path | None) -> dict:
    runs = _discover_runs(runs_root)
    if not runs:
        raise AggregatorError(f"no baseline-* run dirs found under {runs_root}")
    logger.info("discovered %d runs: %s", len(runs), [a for a, _ in runs])

    manifest = load_manifest(manifest_path)
    out_csv = runs_root / "final_metrics.csv"
    fieldnames = ["agent_alias", *FINAL_METRIC_COLUMNS]
    n_rows = 0
    with out_csv.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fieldnames)
        w.writeheader()
        for alias, run_dir in runs:
            aggs = aggregate_run(run_dir, manifest, schema_yaml=schema_yaml)
            for agg in aggs:
                w.writerow(_row_with_alias(alias, agg))
                n_rows += 1
    logger.info("wrote %s (%d rows)", out_csv, n_rows)

    jaccard_rows = _inter_agent_jaccard(runs)
    jaccard_csv = runs_root / "inter_agent_jaccard.csv"
    if jaccard_rows:
        with jaccard_csv.open("w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=list(jaccard_rows[0].keys()))
            w.writeheader()
            w.writerows(jaccard_rows)
        flagged = sum(1 for r in jaccard_rows if r["flagged"] == "1")
        logger.info("wrote %s (%d pairs, %d flagged ≥0.95)", jaccard_csv, len(jaccard_rows), flagged)
    else:
        flagged = 0
        logger.warning("no common tasks across runs — Jaccard skipped")

    summary = {
        "runs_root": str(runs_root),
        "agents": [a for a, _ in runs],
        "final_metrics_csv": str(out_csv),
        "final_metrics_rows": n_rows,
        "jaccard_csv": str(jaccard_csv) if jaccard_rows else None,
        "jaccard_pairs": len(jaccard_rows),
        "jaccard_flagged_ge_0_95": flagged,
    }
    (runs_root / "merge_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--runs-root", default="runs/F1c")
    p.add_argument("--manifest", default="benchmarks/v1/manifest.yaml")
    p.add_argument("--schema-yaml", default=None)
    p.add_argument("--log-level", default="INFO")
    args = p.parse_args()
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )
    summary = merge(
        runs_root=Path(args.runs_root),
        manifest_path=Path(args.manifest),
        schema_yaml=Path(args.schema_yaml) if args.schema_yaml else None,
    )
    print(json.dumps(summary, indent=2))
    if summary["jaccard_flagged_ge_0_95"]:
        logger.error(
            "F.1.c integrity gate FAILED: %d task(s) have inter-agent Jaccard ≥0.95 "
            "(pseudo-sample). Re-design capability matrix.",
            summary["jaccard_flagged_ge_0_95"],
        )
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
