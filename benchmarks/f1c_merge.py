"""benchmarks/f1c_merge.py — Combine N per-agent runs into one final_metrics.csv.

Discovers ``runs/F1c/baseline-<alias>-<ts>/`` directories, runs the F.0
``aggregator.aggregate_run`` over each, then concatenates with an
``agent_alias`` discriminator column prepended to support per-disease
break-downs in the F.1.d REPORT (§4.3 / §5.2).

Also writes:
  - ``inter_agent_jaccard.csv`` — pseudo-sample detection (§3.5):
    Primary score is weighted Jaccard over action bigram multisets
    (order-aware, count-aware), with legacy set-Jaccard of action tokens
    retained for compatibility/audit columns.

Integrity gate (default):
  - flag pairs where score >= 0.95
  - pass if flagged_pair_ratio <= 0.25 AND flagged_task_ratio <= 0.50
    with at least 30 common tasks.

G.2 gate (default):
  - every final_metrics row must have g2_mode_choice_observable_ratio
  - each agent must emit raw llm_mode_selected at least once per task.

G.3 gate (auto):
  - skipped when no relation-aware rows are present
  - enforced once g3_* final_metrics values are emitted.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import logging
import re
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from .aggregator import (
    FINAL_METRIC_COLUMNS,
    AggregatorError,
    aggregate_run,
)
from observability.metrics.computers.m2_verification_miss import (
    is_verification_observed,
)
from .task_loader import Manifest, load_manifest

logger = logging.getLogger("f1c_merge")

_RUN_DIR_RE = re.compile(r"^baseline-(?P<alias>[a-z]+)-(?P<ts>\d{8}T\d{6}Z)$")

_DEFAULT_SURVIVAL_THRESHOLD = 0.55
_DEFAULT_COMPLETION_FLOOR = 0.95
_DEFAULT_LATENCY_TARGET_MS = 20000.0
_DEFAULT_G2_OBSERVABLE_ROW_RATIO = 1.0
_DEFAULT_G2_SELECTED_PER_TASK_RATIO = 1.0
_DEFAULT_G3_RELATION_MEMORY_HIT_FLOOR = 0.80
_DEFAULT_G3_RELATION_AWARE_DECISION_FLOOR = 0.80
_DEFAULT_G3_TIME_CONSISTENCY_FLOOR = 0.95
_DEFAULT_G3_LLM_RELATION_REF_FLOOR = 1.0
_DEFAULT_G3_R2R_RELATION_ID_FLOOR = 1.0
_DEFAULT_G3_RELATION_PAIR_CONTEXT_FLOOR = 1.0
_DEFAULT_H0_RELATION_FAILURE_TRACE_FLOOR = 1.0
_DEFAULT_H0_IEM_UPDATE_LOG_FLOOR = 1.0
_DEFAULT_H0_RELATION_ACTION_BIAS_FLOOR = 1.0
_DEFAULT_H0_NORMATIVE_GUARD_FLOOR = 1.0
_DEFAULT_H0_RELATION_TRAINING_SAMPLE_FLOOR = 0.0
_DEFAULT_H0_RELATION_NEGATIVE_FAST_LEARNING_FLOOR = 0.0
_DEFAULT_H0_RELATION_REPAIR_SLOW_RECOVERY_FLOOR = 0.0
_DEFAULT_H0_RELATION_HISTORY_PRESERVED_FLOOR = 0.0
_DEFAULT_H0_IDENTITY_DOMAIN_TRACE_FLOOR = 1.0
_DEFAULT_H0_EXPANDED_DOMAIN_TRACE_FLOOR = 1.0
_DEFAULT_H0_IDENTITY_ACTION_BIAS_FLOOR = 1.0
_DEFAULT_H0_PREDICTED_UPDATE_FLOOR = 1.0
_DEFAULT_H0_DESIRED_SLOW_DRIFT_FLOOR = 0.0
_DEFAULT_H0_NORMATIVE_GOVERNANCE_TRIGGER_FLOOR = 1.0
_DEFAULT_H0_GOVERNED_REVISION_FLOOR = 1.0
_DEFAULT_H0_DECISION_PROOF_HASH_FLOOR = 1.0
_DEFAULT_H0_IEM_ANCHOR_REPLAY_FLOOR = 1.0
_DEFAULT_H0_IEM_ANCHOR_REPLAY_EMBEDDED_FLOOR = 0.0
_DEFAULT_H0_IEM_ANCHOR_REPLAY_LEGACY_SIDECAR_MAX = 1.0
_DEFAULT_H0_RUNTIME_IEM_AUDIT_FLOOR = 0.0
_DEFAULT_H0_VOTE_REFS_FLOOR = 1.0
_DEFAULT_H0_AUTHORITY_KIND_FLOOR = 1
_H0_RELATION_NEGATIVE_FAST_LEARNING_METRIC = "h0_relation_negative_fast_learning_ratio"
_H0_GOVERNED_REVISION_METRIC = "h0_governed_revision_ratio"
_DIM_WEIGHTS = {
    "completion_rate": 0.30,
    "latency_score": 0.20,
    "collaboration_score": 0.20,
    "trust_score": 0.30,
}
_SENTINEL_HARD_FAIL = frozenset({"failed", "give_up"})


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


def _safe_float(raw: str | None) -> float | None:
    if raw is None:
        return None
    s = str(raw).strip()
    if not s:
        return None
    try:
        return float(s)
    except ValueError:
        return None


def _mean(xs: list[float]) -> float | None:
    if not xs:
        return None
    return sum(xs) / len(xs)


def _env_float(name: str, default: float) -> float:
    try:
        import os

        val = os.getenv(name)
        if not val:
            return default
        parsed = float(val)
        if parsed <= 0:
            return default
        return parsed
    except Exception:
        return default


def _env_flag(name: str, default: bool = False) -> bool:
    try:
        import os

        val = os.getenv(name)
        if val is None:
            return default
        return val.strip().lower() in {"1", "true", "yes", "on"}
    except Exception:
        return default


def _raw_bool(raw: str | None) -> bool:
    return str(raw or "").strip().lower() == "true"


def _load_completion_from_summary(run_dir: Path) -> tuple[int, int]:
    payload = _load_summary_payload(run_dir)
    return (
        int(payload.get("tasks_completed", 0)),
        int(payload.get("tasks_total", 0)),
    )


def _load_summary_payload(run_dir: Path) -> dict[str, object]:
    summary_path = run_dir / "summary.json"
    if not summary_path.exists():
        return {}
    try:
        payload = json.loads(summary_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    return payload if isinstance(payload, dict) else {}


def _evaluate_sentinel_gate(
    runs: list[tuple[str, Path]],
    *,
    disallowed_sentinels: frozenset[str] = _SENTINEL_HARD_FAIL,
    max_examples: int = 30,
) -> dict[str, object]:
    """Hard gate: any failed/give_up sentinel in task summary fails the batch."""
    violations: list[dict[str, str]] = []
    by_agent: list[dict[str, object]] = []

    for alias, run_dir in runs:
        payload = _load_summary_payload(run_dir)
        tasks = payload.get("tasks")
        if not isinstance(tasks, list):
            tasks = []
        counts: Counter[str] = Counter()
        bad = 0
        for row in tasks:
            if not isinstance(row, dict):
                continue
            kind_raw = row.get("sentinel_kind")
            kind = str(kind_raw).strip().lower() if kind_raw is not None else ""
            if not kind:
                kind = "none"
            counts[kind] += 1
            if kind in disallowed_sentinels:
                bad += 1
                if len(violations) < max_examples:
                    violations.append(
                        {
                            "agent_alias": alias,
                            "task_id": str(row.get("task_id", "")),
                            "sentinel_kind": kind,
                            "reason": str(row.get("sentinel_reason", "")),
                        }
                    )
        by_agent.append(
            {
                "agent_alias": alias,
                "run_dir": str(run_dir),
                "tasks_total": sum(counts.values()),
                "disallowed_count": bad,
                "sentinel_counts": dict(sorted(counts.items())),
            }
        )

    by_agent = sorted(by_agent, key=lambda row: str(row["agent_alias"]))
    violation_count = sum(int(row["disallowed_count"]) for row in by_agent)
    reasons = [
        (
            f"{row['agent_alias']}: disallowed sentinel count "
            f"{row['disallowed_count']} in {row['tasks_total']} tasks"
        )
        for row in by_agent
        if int(row["disallowed_count"]) > 0
    ]
    return {
        "passed": violation_count == 0,
        "disallowed_sentinels": sorted(disallowed_sentinels),
        "violation_count": violation_count,
        "failure_reasons": reasons,
        "per_agent": by_agent,
        "violations_sample": violations,
    }


def _agent_alias_metrics(final_metrics_csv: Path) -> dict[str, dict[str, float | None]]:
    by_alias: dict[str, dict[str, list[float]]] = {}
    with final_metrics_csv.open(newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            alias = row.get("agent_alias", "")
            if not alias:
                continue
            slot = by_alias.setdefault(
                alias,
                {
                    "m1": [],
                    "m2": [],
                    "m3": [],
                    "m4": [],
                    "m5_task_p95": [],
                },
            )
            for src, dst in (
                ("m1_result_deviation_rate", "m1"),
                ("m2_verification_miss_rate", "m2"),
                ("m3_aspect_gap_response_rate", "m3"),
                ("m4_lessons_impact_rate", "m4"),
                ("m5_task_latency_p95_ms", "m5_task_p95"),
            ):
                v = _safe_float(row.get(src))
                if v is not None:
                    slot[dst].append(v)

    out: dict[str, dict[str, float | None]] = {}
    for alias, raw in by_alias.items():
        out[alias] = {
            "m1_result_deviation_rate": _mean(raw["m1"]),
            "m2_verification_miss_rate": _mean(raw["m2"]),
            "m3_aspect_gap_response_rate": _mean(raw["m3"]),
            "m4_lessons_impact_rate": _mean(raw["m4"]),
            "m5_task_latency_p95_ms": _mean(raw["m5_task_p95"]),
            "m3_coverage": (len(raw["m3"]) / 30.0) if raw["m3"] else 0.0,
            "m4_coverage": (len(raw["m4"]) / 30.0) if raw["m4"] else 0.0,
        }
    return out


def _m2_observable_ratio(run_dir: Path, manifest: Manifest | None) -> float:
    if manifest is None:
        return 1.0
    eligible = [
        t for t in manifest.tasks
        if t.variant == "adversarial" and t.verifier_tools
    ]
    if not eligible:
        return 1.0
    observed = 0
    total = 0
    for t in eligible:
        seq = _action_seq(run_dir, t.id)
        if not seq:
            continue
        total += 1
        if is_verification_observed(
            verifier_tools=t.verifier_tools,
            decision_actions=seq,
        ):
            observed += 1
    if total == 0:
        return 0.0
    return observed / total


def _parse_csv_bool(raw: str | None) -> bool | None:
    if raw is None:
        return None
    s = str(raw).strip().lower()
    if not s:
        return None
    if s == "true":
        return True
    if s == "false":
        return False
    return None


def _count_g2_llm_mode_selected(run_dir: Path) -> dict[str, int]:
    raw_dir = run_dir / "raw_ticks"
    counts = {
        "raw_tick_rows": 0,
        "llm_mode_selected": 0,
        "llm_waiting_selected": 0,
        "llm_deep_think_selected": 0,
    }
    if not raw_dir.exists():
        return counts

    for csv_path in sorted(raw_dir.glob("*.csv")):
        with csv_path.open(newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                counts["raw_tick_rows"] += 1
                if _parse_csv_bool(row.get("llm_mode_selected")) is not True:
                    continue
                counts["llm_mode_selected"] += 1
                mode_request = str(row.get("llm_mode_request") or "").strip()
                if mode_request == "waiting":
                    counts["llm_waiting_selected"] += 1
                elif mode_request == "deep_think":
                    counts["llm_deep_think_selected"] += 1
    return counts


def _load_g2_final_metric_rows(final_metrics_csv: Path) -> list[dict[str, str]]:
    with final_metrics_csv.open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def _g3_time_windows_by_task(run_dir: Path) -> dict[str, set[str]]:
    raw_dir = run_dir / "raw_ticks"
    if not raw_dir.exists():
        return {}
    out: dict[str, set[str]] = {}
    for csv_path in sorted(raw_dir.glob("*.csv")):
        windows: set[str] = set()
        with csv_path.open(newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                value = str(row.get("time_window_id") or "").strip()
                if value:
                    windows.add(value)
        if windows:
            out[csv_path.stem] = windows
    return out


def _evaluate_g3_raw_time_consistency(
    runs: list[tuple[str, Path]],
    *,
    max_examples: int = 20,
) -> dict[str, object]:
    per_alias = {
        alias: _g3_time_windows_by_task(run_dir)
        for alias, run_dir in runs
    }
    task_ids = set().union(*(set(mapping.keys()) for mapping in per_alias.values()))
    comparable = 0
    consistent = 0
    inconsistent_sample: list[dict[str, object]] = []

    for task_id in sorted(task_ids):
        windows_by_alias = {
            alias: windows.get(task_id, set())
            for alias, windows in per_alias.items()
        }
        if sum(1 for values in windows_by_alias.values() if values) < 2:
            continue
        comparable += 1
        all_present = all(bool(values) for values in windows_by_alias.values())
        shared = set.intersection(*windows_by_alias.values()) if all_present else set()
        if shared:
            consistent += 1
            continue
        if len(inconsistent_sample) < max_examples:
            inconsistent_sample.append(
                {
                    "task_id": task_id,
                    "windows_by_agent": {
                        alias: sorted(values)
                        for alias, values in windows_by_alias.items()
                    },
                },
            )

    ratio = (consistent / comparable) if comparable else None
    return {
        "raw_time_window_task_count": comparable,
        "raw_time_window_consistent_task_count": consistent,
        "raw_cross_agent_time_consistency_ratio": ratio,
        "raw_time_window_inconsistent_sample": inconsistent_sample,
    }


def _evaluate_g3_raw_relation_trace(
    runs: list[tuple[str, Path]],
    *,
    max_examples: int = 20,
) -> dict[str, object]:
    """Check that relation-aware LLM ticks carry structured memory refs."""
    total = 0
    with_refs = 0
    missing_sample: list[dict[str, str]] = []

    for alias, run_dir in runs:
        raw_dir = run_dir / "raw_ticks"
        if not raw_dir.exists():
            continue
        for csv_path in sorted(raw_dir.glob("*.csv")):
            with csv_path.open(newline="", encoding="utf-8") as fh:
                reader = csv.DictReader(fh)
                for row in reader:
                    if str(row.get("decision_source") or "").strip() != "llm":
                        continue
                    relation_context_id = str(row.get("relation_context_id") or "").strip()
                    relation_memory_refs = str(row.get("relation_memory_refs") or "").strip()
                    time_window_id = str(row.get("time_window_id") or "").strip()
                    challenge_bucket = str(row.get("challenge_deadline_bucket") or "").strip()
                    if not any((
                        relation_context_id,
                        relation_memory_refs,
                        time_window_id,
                        challenge_bucket,
                    )):
                        continue
                    total += 1
                    if relation_memory_refs:
                        with_refs += 1
                        continue
                    if len(missing_sample) < max_examples:
                        missing_sample.append(
                            {
                                "agent_alias": alias,
                                "task_id": csv_path.stem,
                                "decision_action": str(row.get("decision_action") or ""),
                                "tick_seq": str(row.get("tick_seq") or ""),
                                "relation_context_id": relation_context_id,
                                "time_window_id": time_window_id,
                            },
                        )

    ratio = (with_refs / total) if total else None
    return {
        "raw_llm_relation_trace_rows": total,
        "raw_llm_relation_ref_rows": with_refs,
        "raw_llm_relation_ref_ratio": ratio,
        "raw_llm_relation_ref_missing_sample": missing_sample,
    }


def _evaluate_g3_backend_relation_context_source(
    runs: list[tuple[str, Path]],
    *,
    max_examples: int = 20,
) -> dict[str, object]:
    """Check relation-aware raw rows are backed by backend read-model context."""
    total = 0
    backend = 0
    non_backend_sample: list[dict[str, str]] = []

    for alias, run_dir in runs:
        raw_dir = run_dir / "raw_ticks"
        if not raw_dir.exists():
            continue
        for csv_path in sorted(raw_dir.glob("*.csv")):
            with csv_path.open(newline="", encoding="utf-8") as fh:
                reader = csv.DictReader(fh)
                for row in reader:
                    relation_context_id = str(row.get("relation_context_id") or "").strip()
                    relation_memory_refs = str(row.get("relation_memory_refs") or "").strip()
                    time_window_id = str(row.get("time_window_id") or "").strip()
                    challenge_bucket = str(row.get("challenge_deadline_bucket") or "").strip()
                    if not any((
                        relation_context_id,
                        relation_memory_refs,
                        time_window_id,
                        challenge_bucket,
                    )):
                        continue
                    total += 1
                    source = str(row.get("relation_context_source") or "").strip()
                    if source == "backend_read_model":
                        backend += 1
                        continue
                    if len(non_backend_sample) < max_examples:
                        non_backend_sample.append(
                            {
                                "agent_alias": alias,
                                "task_id": csv_path.stem,
                                "tick_seq": str(row.get("tick_seq") or ""),
                                "relation_context_id": relation_context_id,
                                "time_window_id": time_window_id,
                                "relation_context_source": source,
                            },
                        )

    ratio = (backend / total) if total else None
    return {
        "raw_relation_context_source_rows": total,
        "raw_backend_relation_context_source_rows": backend,
        "raw_backend_relation_context_source_ratio": ratio,
        "raw_relation_context_non_backend_sample": non_backend_sample,
    }


def _evaluate_g3_relation_provenance(
    runs: list[tuple[str, Path]],
    *,
    max_examples: int = 20,
) -> dict[str, object]:
    """Check relation-aware raw rows carry R2R id and relation-pair provenance."""
    total = 0
    r2r = 0
    pair = 0
    failure_events = 0
    failure_refs = 0
    missing_r2r_sample: list[dict[str, str]] = []
    missing_pair_sample: list[dict[str, str]] = []
    missing_failure_ref_sample: list[dict[str, str]] = []

    for alias, run_dir in runs:
        raw_dir = run_dir / "raw_ticks"
        if not raw_dir.exists():
            continue
        for csv_path in sorted(raw_dir.glob("*.csv")):
            with csv_path.open(newline="", encoding="utf-8") as fh:
                reader = csv.DictReader(fh)
                for row in reader:
                    relation_context_id = str(row.get("relation_context_id") or "").strip()
                    relation_memory_refs = str(row.get("relation_memory_refs") or "").strip()
                    time_window_id = str(row.get("time_window_id") or "").strip()
                    challenge_bucket = str(row.get("challenge_deadline_bucket") or "").strip()
                    if not any((
                        relation_context_id,
                        relation_memory_refs,
                        time_window_id,
                        challenge_bucket,
                    )):
                        continue
                    total += 1
                    relation_id_source = str(row.get("relation_id_source") or "").strip()
                    pair_present = _raw_bool(row.get("relation_pair_present"))
                    has_failure_events = _raw_bool(
                        row.get("relation_pair_failure_events_present"),
                    )
                    has_failure_ref = _raw_bool(
                        row.get("relation_pair_failure_ref_present"),
                    )

                    if relation_id_source == "r2r_registry":
                        r2r += 1
                    elif len(missing_r2r_sample) < max_examples:
                        missing_r2r_sample.append({
                            "agent_alias": alias,
                            "task_id": csv_path.stem,
                            "tick_seq": str(row.get("tick_seq") or ""),
                            "relation_context_id": relation_context_id,
                            "relation_id_source": relation_id_source,
                        })

                    if pair_present:
                        pair += 1
                    elif len(missing_pair_sample) < max_examples:
                        missing_pair_sample.append({
                            "agent_alias": alias,
                            "task_id": csv_path.stem,
                            "tick_seq": str(row.get("tick_seq") or ""),
                            "relation_context_id": relation_context_id,
                        })

                    if has_failure_events:
                        failure_events += 1
                        if has_failure_ref:
                            failure_refs += 1
                        elif len(missing_failure_ref_sample) < max_examples:
                            missing_failure_ref_sample.append({
                                "agent_alias": alias,
                                "task_id": csv_path.stem,
                                "tick_seq": str(row.get("tick_seq") or ""),
                                "relation_context_id": relation_context_id,
                                "relation_memory_refs": relation_memory_refs,
                            })

    return {
        "raw_g3_relation_provenance_rows": total,
        "raw_g3_r2r_relation_id_rows": r2r,
        "raw_g3_r2r_relation_id_ratio": (r2r / total) if total else None,
        "raw_g3_relation_pair_rows": pair,
        "raw_g3_relation_pair_context_ratio": (pair / total) if total else None,
        "raw_g3_relation_pair_failure_event_rows": failure_events,
        "raw_g3_relation_pair_failure_ref_rows": failure_refs,
        "raw_g3_relation_pair_failure_ref_ratio": (
            failure_refs / failure_events if failure_events else None
        ),
        "raw_g3_relation_id_non_r2r_sample": missing_r2r_sample,
        "raw_g3_relation_pair_missing_sample": missing_pair_sample,
        "raw_g3_relation_pair_failure_ref_missing_sample": missing_failure_ref_sample,
    }


def _evaluate_g2_gate(
    *,
    runs: list[tuple[str, Path]],
    final_metrics_csv: Path,
    min_observable_row_ratio: float = _DEFAULT_G2_OBSERVABLE_ROW_RATIO,
    min_selected_per_task_ratio: float = _DEFAULT_G2_SELECTED_PER_TASK_RATIO,
) -> dict[str, object]:
    rows = _load_g2_final_metric_rows(final_metrics_csv)
    total_rows = len(rows)
    observable_rows = 0
    expected_tasks_by_alias: Counter[str] = Counter()
    missing_rows: list[dict[str, str]] = []

    for row in rows:
        alias = row.get("agent_alias", "")
        task_count = int(_safe_float(row.get("task_count")) or 0)
        if alias:
            expected_tasks_by_alias[alias] += task_count
        if _safe_float(row.get("g2_mode_choice_observable_ratio")) is not None:
            observable_rows += 1
            continue
        if len(missing_rows) < 20:
            missing_rows.append(
                {
                    "agent_alias": alias,
                    "category_id": row.get("category_id", ""),
                    "task_count": row.get("task_count", ""),
                },
            )

    observable_row_ratio = (observable_rows / total_rows) if total_rows else 0.0
    failure_reasons: list[str] = []
    if total_rows == 0:
        failure_reasons.append("final_metrics has no rows")
    if observable_row_ratio < min_observable_row_ratio:
        failure_reasons.append(
            "g2 observable final_metrics row ratio "
            f"{observable_row_ratio:.4f} < {min_observable_row_ratio:.4f}",
        )

    per_agent: list[dict[str, object]] = []
    for alias, run_dir in runs:
        expected_tasks = int(expected_tasks_by_alias.get(alias, 0))
        counts = _count_g2_llm_mode_selected(run_dir)
        selected = counts["llm_mode_selected"]
        selected_per_task_ratio = (selected / expected_tasks) if expected_tasks else 0.0
        if expected_tasks == 0:
            failure_reasons.append(f"{alias}: expected task count is 0")
        elif selected_per_task_ratio < min_selected_per_task_ratio:
            failure_reasons.append(
                f"{alias}: raw llm_mode_selected/task_count "
                f"{selected_per_task_ratio:.4f} < {min_selected_per_task_ratio:.4f} "
                f"({selected}/{expected_tasks})",
            )
        per_agent.append(
            {
                "agent_alias": alias,
                "run_dir": str(run_dir),
                "expected_task_count": expected_tasks,
                **counts,
                "selected_per_task_ratio": selected_per_task_ratio,
            },
        )

    return {
        "passed": not failure_reasons,
        "min_observable_row_ratio": min_observable_row_ratio,
        "min_selected_per_task_ratio": min_selected_per_task_ratio,
        "final_metrics_rows": total_rows,
        "observable_rows": observable_rows,
        "observable_row_ratio": observable_row_ratio,
        "missing_rows_sample": missing_rows,
        "per_agent": sorted(per_agent, key=lambda row: str(row["agent_alias"])),
        "failure_reasons": failure_reasons,
    }


def _evaluate_g3_gate(
    *,
    final_metrics_csv: Path,
    runs: list[tuple[str, Path]] | None = None,
    min_relation_memory_hit_ratio: float = _DEFAULT_G3_RELATION_MEMORY_HIT_FLOOR,
    min_relation_aware_decision_ratio: float = _DEFAULT_G3_RELATION_AWARE_DECISION_FLOOR,
    min_cross_agent_time_consistency_ratio: float = _DEFAULT_G3_TIME_CONSISTENCY_FLOOR,
    min_llm_relation_ref_ratio: float = _DEFAULT_G3_LLM_RELATION_REF_FLOOR,
    min_backend_relation_context_source_ratio: float | None = None,
    min_r2r_relation_id_ratio: float | None = None,
    min_relation_pair_context_ratio: float | None = None,
    min_relation_pair_failure_ref_ratio: float | None = None,
) -> dict[str, object]:
    rows = _load_g2_final_metric_rows(final_metrics_csv)
    relation_rows: list[dict[str, str]] = []
    failure_reasons: list[str] = []
    for row in rows:
        values = {
            "g3_relation_memory_hit_ratio": _safe_float(
                row.get("g3_relation_memory_hit_ratio"),
            ),
            "g3_relation_aware_decision_ratio": _safe_float(
                row.get("g3_relation_aware_decision_ratio"),
            ),
            "g3_cross_agent_time_consistency_ratio": _safe_float(
                row.get("g3_cross_agent_time_consistency_ratio"),
            ),
            "g3_r2r_relation_id_ratio": _safe_float(
                row.get("g3_r2r_relation_id_ratio"),
            ),
            "g3_relation_pair_context_ratio": _safe_float(
                row.get("g3_relation_pair_context_ratio"),
            ),
            "g3_relation_pair_failure_ref_ratio": _safe_float(
                row.get("g3_relation_pair_failure_ref_ratio"),
            ),
        }
        if all(value is None for value in values.values()):
            continue
        relation_rows.append(row)
        checks: list[tuple[str, float | None, float]] = [
            (
                "g3_relation_memory_hit_ratio",
                values["g3_relation_memory_hit_ratio"],
                min_relation_memory_hit_ratio,
            ),
            (
                "g3_relation_aware_decision_ratio",
                values["g3_relation_aware_decision_ratio"],
                min_relation_aware_decision_ratio,
            ),
            (
                "g3_cross_agent_time_consistency_ratio",
                values["g3_cross_agent_time_consistency_ratio"],
                min_cross_agent_time_consistency_ratio,
            ),
        ]
        if min_r2r_relation_id_ratio is not None:
            checks.append((
                "g3_r2r_relation_id_ratio",
                values["g3_r2r_relation_id_ratio"],
                min_r2r_relation_id_ratio,
            ))
        if min_relation_pair_context_ratio is not None:
            checks.append((
                "g3_relation_pair_context_ratio",
                values["g3_relation_pair_context_ratio"],
                min_relation_pair_context_ratio,
            ))
        if (
            min_relation_pair_failure_ref_ratio is not None
            and values["g3_relation_pair_failure_ref_ratio"] is not None
        ):
            checks.append((
                "g3_relation_pair_failure_ref_ratio",
                values["g3_relation_pair_failure_ref_ratio"],
                min_relation_pair_failure_ref_ratio,
            ))
        for field, value, floor in checks:
            if value is not None and value >= floor:
                continue
            failure_reasons.append(
                f"{row.get('agent_alias', '')}/{row.get('category_id', '')}: "
                f"{field} {0.0 if value is None else value:.4f} < {floor:.4f}",
            )

    raw_consistency = (
        _evaluate_g3_raw_time_consistency(runs)
        if runs is not None
        else {
            "raw_time_window_task_count": 0,
            "raw_time_window_consistent_task_count": 0,
            "raw_cross_agent_time_consistency_ratio": None,
            "raw_time_window_inconsistent_sample": [],
        }
    )
    raw_relation_trace = (
        _evaluate_g3_raw_relation_trace(runs)
        if runs is not None
        else {
            "raw_llm_relation_trace_rows": 0,
            "raw_llm_relation_ref_rows": 0,
            "raw_llm_relation_ref_ratio": None,
            "raw_llm_relation_ref_missing_sample": [],
        }
    )
    raw_backend_source = (
        _evaluate_g3_backend_relation_context_source(runs)
        if runs is not None
        else {
            "raw_relation_context_source_rows": 0,
            "raw_backend_relation_context_source_rows": 0,
            "raw_backend_relation_context_source_ratio": None,
            "raw_relation_context_non_backend_sample": [],
        }
    )
    raw_provenance = (
        _evaluate_g3_relation_provenance(runs)
        if runs is not None
        else {
            "raw_g3_relation_provenance_rows": 0,
            "raw_g3_r2r_relation_id_rows": 0,
            "raw_g3_r2r_relation_id_ratio": None,
            "raw_g3_relation_pair_rows": 0,
            "raw_g3_relation_pair_context_ratio": None,
            "raw_g3_relation_pair_failure_event_rows": 0,
            "raw_g3_relation_pair_failure_ref_rows": 0,
            "raw_g3_relation_pair_failure_ref_ratio": None,
            "raw_g3_relation_id_non_r2r_sample": [],
            "raw_g3_relation_pair_missing_sample": [],
            "raw_g3_relation_pair_failure_ref_missing_sample": [],
        }
    )
    raw_ratio = raw_consistency["raw_cross_agent_time_consistency_ratio"]
    if raw_ratio is not None and raw_ratio < min_cross_agent_time_consistency_ratio:
        failure_reasons.append(
            "raw cross-agent time consistency ratio "
            f"{raw_ratio:.4f} < {min_cross_agent_time_consistency_ratio:.4f}",
        )
    raw_ref_ratio = raw_relation_trace["raw_llm_relation_ref_ratio"]
    if relation_rows and raw_ref_ratio is None and runs is not None:
        failure_reasons.append("raw LLM relation trace rows are missing")
    elif raw_ref_ratio is not None and raw_ref_ratio < min_llm_relation_ref_ratio:
        failure_reasons.append(
            "raw LLM relation ref ratio "
            f"{raw_ref_ratio:.4f} < {min_llm_relation_ref_ratio:.4f}",
        )
    raw_backend_ratio = raw_backend_source["raw_backend_relation_context_source_ratio"]
    if min_backend_relation_context_source_ratio is not None:
        if relation_rows and raw_backend_ratio is None and runs is not None:
            failure_reasons.append("raw backend relation context source rows are missing")
        elif raw_backend_ratio is not None and raw_backend_ratio < min_backend_relation_context_source_ratio:
            failure_reasons.append(
                "raw backend relation context source ratio "
                f"{raw_backend_ratio:.4f} < {min_backend_relation_context_source_ratio:.4f}",
            )

    raw_r2r_ratio = raw_provenance["raw_g3_r2r_relation_id_ratio"]
    if min_r2r_relation_id_ratio is not None:
        if relation_rows and raw_r2r_ratio is None and runs is not None:
            failure_reasons.append("raw G.3 R2R relation id rows are missing")
        elif raw_r2r_ratio is not None and raw_r2r_ratio < min_r2r_relation_id_ratio:
            failure_reasons.append(
                "raw G.3 R2R relation id ratio "
                f"{raw_r2r_ratio:.4f} < {min_r2r_relation_id_ratio:.4f}",
            )

    raw_pair_ratio = raw_provenance["raw_g3_relation_pair_context_ratio"]
    if min_relation_pair_context_ratio is not None:
        if relation_rows and raw_pair_ratio is None and runs is not None:
            failure_reasons.append("raw G.3 relation pair context rows are missing")
        elif raw_pair_ratio is not None and raw_pair_ratio < min_relation_pair_context_ratio:
            failure_reasons.append(
                "raw G.3 relation pair context ratio "
                f"{raw_pair_ratio:.4f} < {min_relation_pair_context_ratio:.4f}",
            )

    raw_failure_ref_ratio = raw_provenance["raw_g3_relation_pair_failure_ref_ratio"]
    if min_relation_pair_failure_ref_ratio is not None:
        if relation_rows and raw_failure_ref_ratio is None and runs is not None:
            failure_reasons.append("raw G.3 relation-pair failure ref sample is missing")
        elif raw_failure_ref_ratio is not None and raw_failure_ref_ratio < min_relation_pair_failure_ref_ratio:
            failure_reasons.append(
                "raw G.3 relation-pair failure ref ratio "
                f"{raw_failure_ref_ratio:.4f} < {min_relation_pair_failure_ref_ratio:.4f}",
            )

    if (
        not relation_rows
        and raw_consistency["raw_time_window_task_count"] == 0
        and raw_relation_trace["raw_llm_relation_trace_rows"] == 0
        and raw_backend_source["raw_relation_context_source_rows"] == 0
        and raw_provenance["raw_g3_relation_provenance_rows"] == 0
    ):
        return {
            "passed": True,
            "skipped": True,
            "reason": "no relation-aware G.3 rows in final_metrics",
            "relation_rows": 0,
            **raw_consistency,
            **raw_relation_trace,
            **raw_backend_source,
            **raw_provenance,
            "failure_reasons": [],
        }

    return {
        "passed": not failure_reasons,
        "skipped": False,
        "relation_rows": len(relation_rows),
        "min_relation_memory_hit_ratio": min_relation_memory_hit_ratio,
        "min_relation_aware_decision_ratio": min_relation_aware_decision_ratio,
        "min_cross_agent_time_consistency_ratio": min_cross_agent_time_consistency_ratio,
        "min_llm_relation_ref_ratio": min_llm_relation_ref_ratio,
        "min_backend_relation_context_source_ratio": min_backend_relation_context_source_ratio,
        "min_r2r_relation_id_ratio": min_r2r_relation_id_ratio,
        "min_relation_pair_context_ratio": min_relation_pair_context_ratio,
        "min_relation_pair_failure_ref_ratio": min_relation_pair_failure_ref_ratio,
        **raw_consistency,
        **raw_relation_trace,
        **raw_backend_source,
        **raw_provenance,
        "failure_reasons": failure_reasons,
    }


def _evaluate_h0_raw_relation_expectation(
    runs: list[tuple[str, Path]],
    *,
    manifest: Manifest | None = None,
    max_examples: int = 20,
) -> dict[str, object]:
    relation_negative_training_task_ids = _h0_relation_negative_training_task_ids(manifest)
    governed_revision_expected_task_ids = _h0_governed_revision_expected_task_ids(manifest)
    failure_rows = 0
    trace_rows = 0
    update_rows = 0
    action_bias_rows = 0
    normative_guard_rows = 0
    relation_training_sample_rows = 0
    relation_negative_fast_learning_rows = 0
    relation_repair_sample_rows = 0
    relation_repair_slow_recovery_rows = 0
    relation_history_preserved_rows = 0
    relation_failure_task_keys: set[str] = set()
    relation_negative_fast_learning_required_task_keys: set[str] = set()
    relation_negative_fast_learning_observed_task_keys: set[str] = set()
    relation_negative_fast_learning_task_keys: set[str] = set()
    relation_repair_sample_task_keys: set[str] = set()
    relation_repair_slow_recovery_task_keys: set[str] = set()
    h0_trace_rows = 0
    identity_rows = 0
    identity_domain_rows = 0
    reputation_rows = 0
    task_rows = 0
    governance_rows = 0
    expanded_domain_rows = 0
    expanded_domain_trace_rows = 0
    identity_action_bias_rows = 0
    predicted_update_rows = 0
    desired_slow_drift_rows = 0
    constitutional_rows = 0
    governance_trigger_rows = 0
    governed_revision_event_rows = 0
    governed_revision_rows = 0
    governed_revision_expected_task_keys: set[str] = set()
    governed_revision_task_keys: set[str] = set()
    missing_sample: list[dict[str, str]] = []
    identity_missing_sample: list[dict[str, str]] = []
    governance_missing_sample: list[dict[str, str]] = []

    for alias, run_dir in runs:
        raw_dir = run_dir / "raw_ticks"
        if not raw_dir.exists():
            continue
        for csv_path in sorted(raw_dir.glob("*.csv")):
            with csv_path.open(newline="", encoding="utf-8") as fh:
                reader = csv.DictReader(fh)
                for row in reader:
                    relation_surprise = _raw_bool(row.get("h0_relation_surprise_present"))
                    survival_surprise = _raw_bool(row.get("h0_survival_surprise_present"))
                    economic_surprise = _raw_bool(row.get("h0_economic_surprise_present"))
                    reputation_surprise = _raw_bool(row.get("h0_reputation_surprise_present"))
                    task_surprise = _raw_bool(row.get("h0_task_surprise_present"))
                    governance_surprise = _raw_bool(row.get("h0_governance_surprise_present"))
                    update_log = _raw_bool(row.get("h0_iem_update_log_present"))
                    action_bias = _raw_bool(row.get("h0_relation_action_bias_present"))
                    normative_guard = _raw_bool(row.get("h0_normative_local_update_blocked"))
                    relation_training_sample = _raw_bool(row.get("h0_relation_training_sample_present"))
                    relation_negative_fast_learning = _raw_bool(
                        row.get("h0_relation_negative_fast_learning_present")
                    )
                    relation_repair_sample = _raw_bool(row.get("h0_relation_repair_sample_present"))
                    relation_repair_slow_recovery = _raw_bool(
                        row.get("h0_relation_repair_slow_recovery_present")
                    )
                    relation_history_preserved = _raw_bool(
                        row.get("h0_relation_history_preserved_present")
                    )
                    identity_action_bias = _raw_bool(row.get("h0_identity_action_bias_present"))
                    constitutional_surprise = _raw_bool(row.get("h0_constitutional_surprise_present"))
                    governance_trigger = _raw_bool(row.get("h0_normative_governance_trigger_present"))
                    governed_revision = _raw_bool(row.get("h0_governed_revision_present"))
                    predicted_update = _raw_bool(row.get("h0_predicted_update_present"))
                    desired_slow_drift = _raw_bool(row.get("h0_desired_slow_drift_present"))
                    if any((
                        _raw_bool(row.get("h0_expectation_trace_present")),
                        survival_surprise,
                        economic_surprise,
                        reputation_surprise,
                        task_surprise,
                        governance_surprise,
                        relation_surprise,
                        update_log,
                        action_bias,
                        normative_guard,
                        relation_training_sample,
                        relation_negative_fast_learning,
                        relation_repair_sample,
                        relation_repair_slow_recovery,
                        relation_history_preserved,
                        identity_action_bias,
                        constitutional_surprise,
                        governance_trigger,
                        governed_revision,
                        predicted_update,
                        desired_slow_drift,
                    )):
                        h0_trace_rows += 1

                    if any((
                        survival_surprise,
                        economic_surprise,
                        reputation_surprise,
                        task_surprise,
                        governance_surprise,
                        identity_action_bias,
                        predicted_update,
                        desired_slow_drift,
                    )):
                        identity_rows += 1
                        if survival_surprise and economic_surprise:
                            identity_domain_rows += 1
                        if reputation_surprise:
                            reputation_rows += 1
                        if task_surprise:
                            task_rows += 1
                        if governance_surprise:
                            governance_rows += 1
                        if reputation_surprise or task_surprise or governance_surprise:
                            expanded_domain_rows += 1
                        if reputation_surprise and task_surprise and governance_surprise:
                            expanded_domain_trace_rows += 1
                        if identity_action_bias:
                            identity_action_bias_rows += 1
                        if predicted_update:
                            predicted_update_rows += 1
                        if desired_slow_drift:
                            desired_slow_drift_rows += 1
                        if (
                            survival_surprise
                            and economic_surprise
                            and identity_action_bias
                            and predicted_update
                        ):
                            pass
                        elif len(identity_missing_sample) < max_examples:
                            identity_missing_sample.append({
                                "agent_alias": alias,
                                "task_id": csv_path.stem,
                                "tick_seq": str(row.get("tick_seq") or ""),
                                "h0_survival_surprise_present": str(row.get("h0_survival_surprise_present") or ""),
                                "h0_economic_surprise_present": str(row.get("h0_economic_surprise_present") or ""),
                                "h0_reputation_surprise_present": str(row.get("h0_reputation_surprise_present") or ""),
                                "h0_task_surprise_present": str(row.get("h0_task_surprise_present") or ""),
                                "h0_governance_surprise_present": str(row.get("h0_governance_surprise_present") or ""),
                                "h0_identity_action_bias_present": str(row.get("h0_identity_action_bias_present") or ""),
                                "h0_predicted_update_present": str(row.get("h0_predicted_update_present") or ""),
                            })

                    if constitutional_surprise:
                        constitutional_rows += 1
                        if governance_trigger:
                            governance_trigger_rows += 1
                        elif len(governance_missing_sample) < max_examples:
                            governance_missing_sample.append({
                                "agent_alias": alias,
                                "task_id": csv_path.stem,
                                "tick_seq": str(row.get("tick_seq") or ""),
                                "h0_constitutional_surprise_present": str(row.get("h0_constitutional_surprise_present") or ""),
                                "h0_normative_governance_trigger_present": str(row.get("h0_normative_governance_trigger_present") or ""),
                                "h0_normative_local_update_blocked": str(row.get("h0_normative_local_update_blocked") or ""),
                            })

                    governed_revision_expected = _h0_governed_revision_expected_task(
                        csv_path.stem,
                        governed_revision_expected_task_ids,
                    )
                    if governed_revision_expected or governed_revision:
                        task_key = f"{alias}:{csv_path.stem}"
                        governed_revision_event_rows += 1
                        if governed_revision_expected:
                            governed_revision_expected_task_keys.add(task_key)
                        if governed_revision:
                            governed_revision_rows += 1
                            if governed_revision_expected:
                                governed_revision_task_keys.add(task_key)

                    if not _raw_bool(row.get("relation_pair_failure_events_present")):
                        continue
                    task_key = f"{alias}:{csv_path.stem}"
                    relation_failure_task_keys.add(task_key)
                    negative_training_required = _h0_relation_negative_training_task(
                        csv_path.stem,
                        relation_negative_training_task_ids,
                    )
                    if negative_training_required:
                        relation_negative_fast_learning_required_task_keys.add(task_key)
                    failure_rows += 1
                    if relation_surprise:
                        trace_rows += 1
                    if update_log:
                        update_rows += 1
                    if action_bias:
                        action_bias_rows += 1
                    if normative_guard:
                        normative_guard_rows += 1
                    if relation_training_sample:
                        relation_training_sample_rows += 1
                    if relation_negative_fast_learning:
                        relation_negative_fast_learning_rows += 1
                        relation_negative_fast_learning_observed_task_keys.add(task_key)
                        if negative_training_required:
                            relation_negative_fast_learning_task_keys.add(task_key)
                    if relation_repair_sample:
                        relation_repair_sample_rows += 1
                        relation_repair_sample_task_keys.add(task_key)
                    if relation_repair_slow_recovery:
                        relation_repair_slow_recovery_rows += 1
                        relation_repair_slow_recovery_task_keys.add(task_key)
                    if relation_history_preserved:
                        relation_history_preserved_rows += 1
                    if (
                        relation_surprise
                        and update_log
                        and action_bias
                        and normative_guard
                        and relation_training_sample
                    ):
                        continue
                    if len(missing_sample) < max_examples:
                        missing_sample.append({
                            "agent_alias": alias,
                            "task_id": csv_path.stem,
                            "tick_seq": str(row.get("tick_seq") or ""),
                            "relation_context_id": str(row.get("relation_context_id") or ""),
                            "h0_relation_surprise_present": str(row.get("h0_relation_surprise_present") or ""),
                            "h0_iem_update_log_present": str(row.get("h0_iem_update_log_present") or ""),
                            "h0_relation_action_bias_present": str(row.get("h0_relation_action_bias_present") or ""),
                            "h0_normative_local_update_blocked": str(row.get("h0_normative_local_update_blocked") or ""),
                            "h0_relation_training_sample_present": str(row.get("h0_relation_training_sample_present") or ""),
                            "h0_relation_negative_fast_learning_present": str(row.get("h0_relation_negative_fast_learning_present") or ""),
                            "h0_relation_history_preserved_present": str(row.get("h0_relation_history_preserved_present") or ""),
                        })

    def _relation_ratio(num: int) -> float | None:
        return (num / failure_rows) if failure_rows else None

    def _relation_training_ratio(num: int) -> float | None:
        return (num / relation_training_sample_rows) if relation_training_sample_rows else None

    def _relation_negative_training_task_ratio(num: int) -> float | None:
        denom = len(relation_negative_fast_learning_required_task_keys)
        return (num / denom) if denom else None

    def _relation_repair_task_ratio(num: int) -> float | None:
        denom = len(relation_repair_sample_task_keys)
        return (num / denom) if denom else None

    def _relation_repair_ratio(num: int) -> float | None:
        return (num / relation_repair_sample_rows) if relation_repair_sample_rows else None

    def _identity_ratio(num: int) -> float | None:
        return (num / identity_rows) if identity_rows else None

    def _expanded_ratio(num: int) -> float | None:
        return (num / expanded_domain_rows) if expanded_domain_rows else None

    def _constitutional_ratio(num: int) -> float | None:
        return (num / constitutional_rows) if constitutional_rows else None

    def _governed_revision_ratio(num: int) -> float | None:
        return (num / governed_revision_event_rows) if governed_revision_event_rows else None

    def _governed_revision_task_ratio(num: int) -> float | None:
        denom = len(governed_revision_expected_task_keys)
        return (num / denom) if denom else None

    return {
        "raw_h0_trace_rows": h0_trace_rows,
        "raw_h0_relation_failure_event_rows": failure_rows,
        "raw_h0_relation_failure_trace_rows": trace_rows,
        "raw_h0_relation_failure_trace_ratio": _relation_ratio(trace_rows),
        "raw_h0_iem_update_log_rows": update_rows,
        "raw_h0_iem_update_log_ratio": _relation_ratio(update_rows),
        "raw_h0_relation_action_bias_rows": action_bias_rows,
        "raw_h0_relation_action_bias_ratio": _relation_ratio(action_bias_rows),
        "raw_h0_normative_guard_rows": normative_guard_rows,
        "raw_h0_normative_guard_ratio": _relation_ratio(normative_guard_rows),
        "raw_h0_relation_training_sample_rows": relation_training_sample_rows,
        "raw_h0_relation_training_sample_ratio": _relation_ratio(relation_training_sample_rows),
        "raw_h0_relation_negative_fast_learning_rows": relation_negative_fast_learning_rows,
        "raw_h0_relation_negative_fast_learning_tick_ratio": _relation_ratio(
            relation_negative_fast_learning_rows
        ),
        "raw_h0_relation_failure_task_count": len(relation_failure_task_keys),
        "raw_h0_relation_negative_fast_learning_required_task_count": len(
            relation_negative_fast_learning_required_task_keys
        ),
        "raw_h0_relation_negative_fast_learning_observed_task_count": len(
            relation_negative_fast_learning_observed_task_keys
        ),
        "raw_h0_relation_negative_fast_learning_task_count": len(
            relation_negative_fast_learning_task_keys
        ),
        "raw_h0_relation_negative_fast_learning_ratio": _relation_negative_training_task_ratio(
            len(relation_negative_fast_learning_task_keys)
        ),
        "raw_h0_relation_repair_sample_rows": relation_repair_sample_rows,
        "raw_h0_relation_repair_slow_recovery_rows": relation_repair_slow_recovery_rows,
        "raw_h0_relation_repair_slow_recovery_tick_ratio": _relation_repair_ratio(
            relation_repair_slow_recovery_rows
        ),
        "raw_h0_relation_repair_sample_task_count": len(relation_repair_sample_task_keys),
        "raw_h0_relation_repair_slow_recovery_task_count": len(
            relation_repair_slow_recovery_task_keys
        ),
        "raw_h0_relation_repair_slow_recovery_ratio": _relation_repair_task_ratio(
            len(relation_repair_slow_recovery_task_keys)
        ),
        "raw_h0_relation_history_preserved_rows": relation_history_preserved_rows,
        "raw_h0_relation_history_preserved_ratio": _relation_training_ratio(relation_history_preserved_rows),
        "raw_h0_identity_event_rows": identity_rows,
        "raw_h0_identity_domain_trace_rows": identity_domain_rows,
        "raw_h0_identity_domain_trace_ratio": _identity_ratio(identity_domain_rows),
        "raw_h0_reputation_surprise_rows": reputation_rows,
        "raw_h0_task_surprise_rows": task_rows,
        "raw_h0_governance_surprise_rows": governance_rows,
        "raw_h0_expanded_domain_event_rows": expanded_domain_rows,
        "raw_h0_expanded_domain_trace_rows": expanded_domain_trace_rows,
        "raw_h0_expanded_domain_trace_ratio": _expanded_ratio(expanded_domain_trace_rows),
        "raw_h0_identity_action_bias_rows": identity_action_bias_rows,
        "raw_h0_identity_action_bias_ratio": _identity_ratio(identity_action_bias_rows),
        "raw_h0_predicted_update_rows": predicted_update_rows,
        "raw_h0_predicted_update_ratio": _identity_ratio(predicted_update_rows),
        "raw_h0_desired_slow_drift_rows": desired_slow_drift_rows,
        "raw_h0_desired_slow_drift_ratio": _identity_ratio(desired_slow_drift_rows),
        "raw_h0_constitutional_surprise_rows": constitutional_rows,
        "raw_h0_normative_governance_trigger_rows": governance_trigger_rows,
        "raw_h0_normative_governance_trigger_ratio": _constitutional_ratio(governance_trigger_rows),
        "raw_h0_governed_revision_event_rows": governed_revision_event_rows,
        "raw_h0_governed_revision_rows": governed_revision_rows,
        "raw_h0_governed_revision_tick_ratio": _governed_revision_ratio(governed_revision_rows),
        "raw_h0_governed_revision_expected_task_count": len(
            governed_revision_expected_task_keys
        ),
        "raw_h0_governed_revision_task_count": len(governed_revision_task_keys),
        "raw_h0_governed_revision_ratio": _governed_revision_task_ratio(
            len(governed_revision_task_keys)
        ),
        "raw_h0_missing_trace_sample": missing_sample,
        "raw_h0_identity_missing_trace_sample": identity_missing_sample,
        "raw_h0_governance_missing_trigger_sample": governance_missing_sample,
    }


def _evaluate_h0_governed_revision_evidence(
    runs: list[tuple[str, Path]],
    *,
    max_examples: int = 20,
) -> dict[str, object]:
    evidence_files = 0
    proof_hash_valid = 0
    anchor_replay_valid = 0
    anchor_replay_embedded = 0
    anchor_replay_legacy_sidecar = 0
    runtime_iem_audit_valid = 0
    vote_refs_present = 0
    authority_kinds: set[str] = set()
    failure_sample: list[dict[str, str]] = []

    for alias, run_dir in runs:
        tasks_dir = run_dir / "tasks"
        if not tasks_dir.exists():
            continue
        for evidence_path in sorted(tasks_dir.glob("*/h0e_governed_revision.json")):
            evidence_files += 1
            try:
                evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                _append_h0e_evidence_failure(
                    failure_sample,
                    max_examples=max_examples,
                    alias=alias,
                    evidence_path=evidence_path,
                    reason=f"unreadable evidence: {exc}",
                )
                continue
            if not isinstance(evidence, dict):
                _append_h0e_evidence_failure(
                    failure_sample,
                    max_examples=max_examples,
                    alias=alias,
                    evidence_path=evidence_path,
                    reason="evidence is not an object",
                )
                continue

            authority = str(evidence.get("authority") or "")
            proof = evidence.get("decision_proof")
            if isinstance(proof, dict):
                authority = authority or str(proof.get("authority") or "")
                vote_refs = proof.get("vote_refs")
                if isinstance(vote_refs, list) and len(vote_refs) >= 2:
                    vote_refs_present += 1
                elif len(failure_sample) < max_examples:
                    _append_h0e_evidence_failure(
                        failure_sample,
                        max_examples=max_examples,
                        alias=alias,
                        evidence_path=evidence_path,
                        reason="decision_proof.vote_refs has fewer than 2 entries",
                    )
                if _decision_proof_hashes_valid(proof):
                    proof_hash_valid += 1
                else:
                    _append_h0e_evidence_failure(
                        failure_sample,
                        max_examples=max_examples,
                        alias=alias,
                        evidence_path=evidence_path,
                        reason="decision_proof hash replay failed",
                    )
            else:
                _append_h0e_evidence_failure(
                    failure_sample,
                    max_examples=max_examples,
                    alias=alias,
                    evidence_path=evidence_path,
                    reason="decision_proof missing",
                )

            kind = _governed_authority_kind(authority)
            if kind:
                authority_kinds.add(kind)
            replay_source = _iem_anchor_replay_valid_source(evidence, evidence_path)
            if replay_source:
                anchor_replay_valid += 1
                if replay_source == "embedded":
                    anchor_replay_embedded += 1
                elif replay_source == "legacy_sidecar":
                    anchor_replay_legacy_sidecar += 1
            else:
                _append_h0e_evidence_failure(
                    failure_sample,
                    max_examples=max_examples,
                    alias=alias,
                    evidence_path=evidence_path,
                    reason="iem_anchor replay/hash check failed",
                )
            if _runtime_iem_audit_valid(evidence, evidence_path):
                runtime_iem_audit_valid += 1
            else:
                _append_h0e_evidence_failure(
                    failure_sample,
                    max_examples=max_examples,
                    alias=alias,
                    evidence_path=evidence_path,
                    reason="runtime Identity IEM audit replay check failed",
                )

    def _evidence_ratio(num: int) -> float | None:
        return (num / evidence_files) if evidence_files else None

    return {
        "raw_h0_governed_revision_evidence_files": evidence_files,
        "raw_h0_decision_proof_hash_valid_files": proof_hash_valid,
        "raw_h0_decision_proof_hash_valid_ratio": _evidence_ratio(proof_hash_valid),
        "raw_h0_iem_anchor_replay_valid_files": anchor_replay_valid,
        "raw_h0_iem_anchor_replay_valid_ratio": _evidence_ratio(anchor_replay_valid),
        "raw_h0_iem_anchor_replay_embedded_files": anchor_replay_embedded,
        "raw_h0_iem_anchor_replay_embedded_ratio": _evidence_ratio(anchor_replay_embedded),
        "raw_h0_iem_anchor_replay_legacy_sidecar_files": anchor_replay_legacy_sidecar,
        "raw_h0_iem_anchor_replay_legacy_sidecar_ratio": _evidence_ratio(anchor_replay_legacy_sidecar),
        "raw_h0_runtime_iem_audit_valid_files": runtime_iem_audit_valid,
        "raw_h0_runtime_iem_audit_valid_ratio": _evidence_ratio(runtime_iem_audit_valid),
        "raw_h0_vote_refs_present_files": vote_refs_present,
        "raw_h0_vote_refs_present_ratio": _evidence_ratio(vote_refs_present),
        "raw_h0_governed_revision_authority_kinds": sorted(authority_kinds),
        "raw_h0_governed_revision_authority_kind_count": len(authority_kinds),
        "raw_h0_governed_revision_evidence_failure_sample": failure_sample,
    }


def _append_h0e_evidence_failure(
    sample: list[dict[str, str]],
    *,
    max_examples: int,
    alias: str,
    evidence_path: Path,
    reason: str,
) -> None:
    if len(sample) >= max_examples:
        return
    sample.append({
        "agent_alias": alias,
        "task_id": evidence_path.parent.name,
        "evidence_path": str(evidence_path),
        "reason": reason,
    })


def _decision_proof_hashes_valid(proof: dict[str, object]) -> bool:
    vote_refs = proof.get("vote_refs")
    if not isinstance(vote_refs, list):
        return False
    if proof.get("votes_hash") != _hash_json_payload(vote_refs):
        return False
    proof_hash = proof.get("proof_hash")
    if not isinstance(proof_hash, str) or not proof_hash.startswith("sha256:"):
        return False
    proof_without_hash = dict(proof)
    proof_without_hash.pop("proof_hash", None)
    return proof_hash == _hash_json_payload(proof_without_hash)


def _iem_anchor_replay_valid(evidence: dict[str, object], evidence_path: Path) -> bool:
    return _iem_anchor_replay_valid_source(evidence, evidence_path) is not None


def _iem_anchor_replay_valid_source(
    evidence: dict[str, object],
    evidence_path: Path,
) -> str | None:
    anchor = evidence.get("iem_anchor")
    if not isinstance(anchor, dict):
        return None
    anchor_hash = _hash_json_payload(anchor)
    if evidence.get("iem_anchor_hash") != anchor_hash:
        return None
    proof = evidence.get("decision_proof")
    if isinstance(proof, dict) and proof.get("iem_anchor_hash") != anchor_hash:
        return None
    replay, source = _h0e_iem_anchor_replay_source(evidence, evidence_path)
    if not isinstance(replay, dict):
        return None
    if replay.get("anchor") != anchor:
        return None
    if anchor.get("state_hash") != _hash_json_payload(replay.get("state")):
        return None
    if anchor.get("latest_update_log_hash") != _hash_json_payload(replay.get("update_log")):
        return None
    return source


def _h0e_iem_anchor_replay_source(
    evidence: dict[str, object],
    evidence_path: Path,
) -> tuple[dict[str, object] | None, str | None]:
    embedded = evidence.get("iem_anchor_replay")
    if isinstance(embedded, dict):
        return embedded, "embedded"
    replay_path = evidence_path.with_name("h0e_iem_anchor_replay.json")
    try:
        replay = json.loads(replay_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None, None
    if isinstance(replay, dict):
        return replay, "legacy_sidecar"
    return None, None


def _runtime_iem_audit_valid(evidence: dict[str, object], evidence_path: Path) -> bool:
    audit_path = evidence_path.with_name("h0f_runtime_iem_audit.json")
    try:
        audit = json.loads(audit_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    if not isinstance(audit, dict):
        return False
    if audit.get("source") != "runtime_identity_iem_audit_log":
        return False
    state = audit.get("identity_iem_state")
    update_log = audit.get("expectation_update_log")
    anchor = audit.get("identity_iem_anchor")
    if not isinstance(state, dict) or not isinstance(update_log, list) or not isinstance(anchor, dict):
        return False
    identity_id = str(audit.get("identity_id") or state.get("identity_id") or "")
    did_anchor = str(audit.get("did_anchor") or "")
    if not identity_id or not did_anchor or state.get("identity_id") != identity_id:
        return False
    if anchor.get("state_hash") != _hash_json_payload(state):
        return False
    if anchor.get("latest_update_log_hash") != _hash_json_payload(update_log):
        return False
    if anchor.get("storage_hint") != f"civitasos://identity/{identity_id}/iem/latest":
        return False
    governed_updates = audit.get("governed_revision_updates")
    if not isinstance(governed_updates, list) or not governed_updates:
        return False
    return any(_runtime_governed_update_matches_evidence(update, evidence) for update in governed_updates)


def _runtime_governed_update_matches_evidence(
    update: object,
    evidence: dict[str, object],
) -> bool:
    if not isinstance(update, dict):
        return False
    if update.get("target") != "normative_state":
        return False
    if update.get("rule") != "governed_revision":
        return False
    if update.get("local_update_blocked"):
        return False
    rule_id = str(evidence.get("rule_id") or "")
    if rule_id and update.get("parameter_name") != rule_id:
        return False
    revision_id = str(evidence.get("revision_id") or "")
    if revision_id and update.get("reason_event") != revision_id:
        return False
    update_params = update.get("update_params")
    if isinstance(update_params, dict):
        status = str(update_params.get("status") or "").lower()
        if status and status not in {"approved", "ratified", "enacted"}:
            return False
    return True


def _governed_authority_kind(authority: str) -> str | None:
    value = authority.strip().lower()
    if "arbitration" in value:
        return "arbitration"
    if "constitution" in value or "steward" in value:
        return "constitution"
    if "governance" in value or "council" in value:
        return "governance"
    return None


def _h0_relation_negative_training_task_ids(manifest: Manifest | None) -> set[str] | None:
    if manifest is None:
        return None
    return {
        task.id
        for task in manifest.tasks
        if task.backend_seed_failures > 0
        or _H0_RELATION_NEGATIVE_FAST_LEARNING_METRIC in task.metrics_targeted
    }


def _h0_relation_negative_training_task(
    task_id: str,
    relation_negative_training_task_ids: set[str] | None,
) -> bool:
    if relation_negative_training_task_ids is None:
        return True
    return task_id in relation_negative_training_task_ids


def _h0_unapproved_local_revision_task(task_id: str) -> bool:
    value = task_id.lower()
    return "h0e" in value and "unapproved" in value and "local_revision" in value


def _h0_governed_revision_expected_task_ids(manifest: Manifest | None) -> set[str] | None:
    if manifest is None:
        return None
    return {
        task.id
        for task in manifest.tasks
        if _H0_GOVERNED_REVISION_METRIC in task.metrics_targeted
        and not _h0_unapproved_local_revision_task(task.id)
    }


def _h0_governed_revision_expected_task(
    task_id: str,
    governed_revision_expected_task_ids: set[str] | None,
) -> bool:
    if _h0_unapproved_local_revision_task(task_id):
        return False
    if governed_revision_expected_task_ids is None:
        return "h0e" in task_id.lower()
    return task_id in governed_revision_expected_task_ids


def _hash_json_payload(payload: object) -> str:
    blob = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return f"sha256:{hashlib.sha256(blob).hexdigest()}"


def _h0_final_metric_counts(rows: list[dict[str, str]]) -> dict[str, object]:
    fields = (
        "h0_expectation_trace_ratio",
        "h0_hard_domain_trace_ratio",
        "h0_drive_constitution_verdict_ratio",
        "h0_iem_update_log_ratio",
        "h0_relation_action_bias_ratio",
        "h0_normative_guard_ratio",
        "h0_relation_training_sample_ratio",
        "h0_relation_negative_fast_learning_ratio",
        "h0_relation_repair_slow_recovery_ratio",
        "h0_relation_history_preserved_ratio",
        "h0_identity_domain_trace_ratio",
        "h0_reputation_surprise_ratio",
        "h0_task_surprise_ratio",
        "h0_governance_surprise_ratio",
        "h0_expanded_domain_trace_ratio",
        "h0_identity_action_bias_ratio",
        "h0_constitutional_surprise_ratio",
        "h0_normative_governance_trigger_ratio",
        "h0_governed_revision_ratio",
        "h0_predicted_update_ratio",
        "h0_desired_slow_drift_ratio",
    )
    counts = {field: 0 for field in fields}
    h0_rows = 0
    for row in rows:
        row_has_h0 = False
        for field in fields:
            if _safe_float(row.get(field)) is None:
                continue
            counts[field] += 1
            row_has_h0 = True
        if row_has_h0:
            h0_rows += 1
    counts["final_h0_rows"] = h0_rows
    return counts


def _evaluate_h0_gate(
    *,
    final_metrics_csv: Path,
    runs: list[tuple[str, Path]] | None = None,
    manifest: Manifest | None = None,
    require_active: bool = False,
    min_relation_failure_trace_ratio: float = _DEFAULT_H0_RELATION_FAILURE_TRACE_FLOOR,
    min_iem_update_log_ratio: float = _DEFAULT_H0_IEM_UPDATE_LOG_FLOOR,
    min_relation_action_bias_ratio: float = _DEFAULT_H0_RELATION_ACTION_BIAS_FLOOR,
    min_normative_guard_ratio: float = _DEFAULT_H0_NORMATIVE_GUARD_FLOOR,
    min_relation_training_sample_ratio: float = _DEFAULT_H0_RELATION_TRAINING_SAMPLE_FLOOR,
    min_relation_negative_fast_learning_ratio: float = _DEFAULT_H0_RELATION_NEGATIVE_FAST_LEARNING_FLOOR,
    min_relation_repair_slow_recovery_ratio: float = _DEFAULT_H0_RELATION_REPAIR_SLOW_RECOVERY_FLOOR,
    min_relation_history_preserved_ratio: float = _DEFAULT_H0_RELATION_HISTORY_PRESERVED_FLOOR,
    min_identity_domain_trace_ratio: float = _DEFAULT_H0_IDENTITY_DOMAIN_TRACE_FLOOR,
    min_expanded_domain_trace_ratio: float = _DEFAULT_H0_EXPANDED_DOMAIN_TRACE_FLOOR,
    min_identity_action_bias_ratio: float = _DEFAULT_H0_IDENTITY_ACTION_BIAS_FLOOR,
    min_predicted_update_ratio: float = _DEFAULT_H0_PREDICTED_UPDATE_FLOOR,
    min_desired_slow_drift_ratio: float = _DEFAULT_H0_DESIRED_SLOW_DRIFT_FLOOR,
    min_normative_governance_trigger_ratio: float = _DEFAULT_H0_NORMATIVE_GOVERNANCE_TRIGGER_FLOOR,
    min_governed_revision_ratio: float = _DEFAULT_H0_GOVERNED_REVISION_FLOOR,
    min_decision_proof_hash_ratio: float = _DEFAULT_H0_DECISION_PROOF_HASH_FLOOR,
    min_iem_anchor_replay_ratio: float = _DEFAULT_H0_IEM_ANCHOR_REPLAY_FLOOR,
    min_iem_anchor_replay_embedded_ratio: float = _DEFAULT_H0_IEM_ANCHOR_REPLAY_EMBEDDED_FLOOR,
    max_iem_anchor_replay_legacy_sidecar_ratio: float = _DEFAULT_H0_IEM_ANCHOR_REPLAY_LEGACY_SIDECAR_MAX,
    min_runtime_iem_audit_ratio: float = _DEFAULT_H0_RUNTIME_IEM_AUDIT_FLOOR,
    min_vote_refs_ratio: float = _DEFAULT_H0_VOTE_REFS_FLOOR,
    min_authority_kind_count: int = _DEFAULT_H0_AUTHORITY_KIND_FLOOR,
) -> dict[str, object]:
    rows = _load_g2_final_metric_rows(final_metrics_csv)
    final_counts = _h0_final_metric_counts(rows)
    raw = (
        {
            **_evaluate_h0_raw_relation_expectation(runs, manifest=manifest),
            **_evaluate_h0_governed_revision_evidence(runs),
        }
        if runs is not None
        else {
            "raw_h0_trace_rows": 0,
            "raw_h0_relation_failure_event_rows": 0,
            "raw_h0_relation_failure_trace_rows": 0,
            "raw_h0_relation_failure_trace_ratio": None,
            "raw_h0_iem_update_log_rows": 0,
            "raw_h0_iem_update_log_ratio": None,
            "raw_h0_relation_action_bias_rows": 0,
            "raw_h0_relation_action_bias_ratio": None,
            "raw_h0_normative_guard_rows": 0,
            "raw_h0_normative_guard_ratio": None,
            "raw_h0_relation_training_sample_rows": 0,
            "raw_h0_relation_training_sample_ratio": None,
            "raw_h0_relation_negative_fast_learning_rows": 0,
            "raw_h0_relation_negative_fast_learning_tick_ratio": None,
            "raw_h0_relation_failure_task_count": 0,
            "raw_h0_relation_negative_fast_learning_required_task_count": 0,
            "raw_h0_relation_negative_fast_learning_observed_task_count": 0,
            "raw_h0_relation_negative_fast_learning_task_count": 0,
            "raw_h0_relation_negative_fast_learning_ratio": None,
            "raw_h0_relation_repair_sample_rows": 0,
            "raw_h0_relation_repair_slow_recovery_rows": 0,
            "raw_h0_relation_repair_slow_recovery_tick_ratio": None,
            "raw_h0_relation_repair_sample_task_count": 0,
            "raw_h0_relation_repair_slow_recovery_task_count": 0,
            "raw_h0_relation_repair_slow_recovery_ratio": None,
            "raw_h0_relation_history_preserved_rows": 0,
            "raw_h0_relation_history_preserved_ratio": None,
            "raw_h0_identity_event_rows": 0,
            "raw_h0_identity_domain_trace_rows": 0,
            "raw_h0_identity_domain_trace_ratio": None,
            "raw_h0_reputation_surprise_rows": 0,
            "raw_h0_task_surprise_rows": 0,
            "raw_h0_governance_surprise_rows": 0,
            "raw_h0_expanded_domain_event_rows": 0,
            "raw_h0_expanded_domain_trace_rows": 0,
            "raw_h0_expanded_domain_trace_ratio": None,
            "raw_h0_identity_action_bias_rows": 0,
            "raw_h0_identity_action_bias_ratio": None,
            "raw_h0_predicted_update_rows": 0,
            "raw_h0_predicted_update_ratio": None,
            "raw_h0_desired_slow_drift_rows": 0,
            "raw_h0_desired_slow_drift_ratio": None,
            "raw_h0_constitutional_surprise_rows": 0,
            "raw_h0_normative_governance_trigger_rows": 0,
            "raw_h0_normative_governance_trigger_ratio": None,
            "raw_h0_governed_revision_event_rows": 0,
            "raw_h0_governed_revision_rows": 0,
            "raw_h0_governed_revision_tick_ratio": None,
            "raw_h0_governed_revision_expected_task_count": 0,
            "raw_h0_governed_revision_task_count": 0,
            "raw_h0_governed_revision_ratio": None,
            "raw_h0_governed_revision_evidence_files": 0,
            "raw_h0_decision_proof_hash_valid_files": 0,
            "raw_h0_decision_proof_hash_valid_ratio": None,
            "raw_h0_iem_anchor_replay_valid_files": 0,
            "raw_h0_iem_anchor_replay_valid_ratio": None,
            "raw_h0_iem_anchor_replay_embedded_files": 0,
            "raw_h0_iem_anchor_replay_embedded_ratio": None,
            "raw_h0_iem_anchor_replay_legacy_sidecar_files": 0,
            "raw_h0_iem_anchor_replay_legacy_sidecar_ratio": None,
            "raw_h0_runtime_iem_audit_valid_files": 0,
            "raw_h0_runtime_iem_audit_valid_ratio": None,
            "raw_h0_vote_refs_present_files": 0,
            "raw_h0_vote_refs_present_ratio": None,
            "raw_h0_governed_revision_authority_kinds": [],
            "raw_h0_governed_revision_authority_kind_count": 0,
            "raw_h0_missing_trace_sample": [],
            "raw_h0_identity_missing_trace_sample": [],
            "raw_h0_governance_missing_trigger_sample": [],
            "raw_h0_governed_revision_evidence_failure_sample": [],
        }
    )

    final_h0_rows = int(final_counts["final_h0_rows"])
    raw_h0_rows = int(raw["raw_h0_trace_rows"])
    raw_failure_rows = int(raw["raw_h0_relation_failure_event_rows"])
    raw_identity_rows = int(raw["raw_h0_identity_event_rows"])
    raw_expanded_rows = int(raw["raw_h0_expanded_domain_event_rows"])
    raw_constitutional_rows = int(raw["raw_h0_constitutional_surprise_rows"])
    raw_governed_revision_rows = int(raw["raw_h0_governed_revision_event_rows"])
    raw_governed_revision_evidence_files = int(raw["raw_h0_governed_revision_evidence_files"])
    if not require_active and final_h0_rows == 0 and raw_h0_rows == 0 and raw_failure_rows == 0:
        return {
            "passed": True,
            "skipped": True,
            "reason": "no H.0 expectation rows in final_metrics or raw ticks",
            "require_active": require_active,
            **final_counts,
            **raw,
            "failure_reasons": [],
        }

    failure_reasons: list[str] = []
    if require_active:
        if final_h0_rows == 0:
            failure_reasons.append("H.0 active required but final_metrics has no h0 rows")
        if raw_h0_rows == 0:
            failure_reasons.append("H.0 active required but raw ticks have no h0 trace rows")
        for field in (
            "h0_expectation_trace_ratio",
            "h0_iem_update_log_ratio",
        ):
            if int(final_counts[field]) == 0:
                failure_reasons.append(f"H.0 active required but {field} is absent")
        if raw_failure_rows > 0:
            for field in (
                "h0_relation_action_bias_ratio",
                "h0_normative_guard_ratio",
            ):
                if int(final_counts[field]) == 0:
                    failure_reasons.append(f"H.0 active required but {field} is absent")
            for field, floor in (
                ("h0_relation_training_sample_ratio", min_relation_training_sample_ratio),
                ("h0_relation_negative_fast_learning_ratio", min_relation_negative_fast_learning_ratio),
                ("h0_relation_history_preserved_ratio", min_relation_history_preserved_ratio),
            ):
                if floor > 0 and int(final_counts[field]) == 0:
                    failure_reasons.append(f"H.0 active required but {field} is absent")
        if raw_identity_rows > 0:
            for field in (
                "h0_identity_domain_trace_ratio",
                "h0_identity_action_bias_ratio",
                "h0_predicted_update_ratio",
            ):
                if int(final_counts[field]) == 0:
                    failure_reasons.append(f"H.0 active required but {field} is absent")
        if raw_expanded_rows > 0:
            for field in (
                "h0_reputation_surprise_ratio",
                "h0_task_surprise_ratio",
                "h0_governance_surprise_ratio",
                "h0_expanded_domain_trace_ratio",
            ):
                if int(final_counts[field]) == 0:
                    failure_reasons.append(f"H.0 active required but {field} is absent")
        if raw_governed_revision_rows > 0:
            if int(final_counts["h0_governed_revision_ratio"]) == 0:
                failure_reasons.append("H.0 active required but h0_governed_revision_ratio is absent")
        if raw_failure_rows == 0 and raw_identity_rows == 0 and raw_governed_revision_rows == 0:
            failure_reasons.append(
                "H.0 active required but raw relation-pair failure, identity, and governed revision rows are missing",
            )

    relation_checks = [
        (
            "raw_h0_relation_failure_trace_ratio",
            raw["raw_h0_relation_failure_trace_ratio"],
            min_relation_failure_trace_ratio,
        ),
        (
            "raw_h0_iem_update_log_ratio",
            raw["raw_h0_iem_update_log_ratio"],
            min_iem_update_log_ratio,
        ),
        (
            "raw_h0_relation_action_bias_ratio",
            raw["raw_h0_relation_action_bias_ratio"],
            min_relation_action_bias_ratio,
        ),
        (
            "raw_h0_normative_guard_ratio",
            raw["raw_h0_normative_guard_ratio"],
            min_normative_guard_ratio,
        ),
        (
            "raw_h0_relation_training_sample_ratio",
            raw["raw_h0_relation_training_sample_ratio"],
            min_relation_training_sample_ratio,
        ),
        (
            "raw_h0_relation_negative_fast_learning_ratio",
            raw["raw_h0_relation_negative_fast_learning_ratio"],
            min_relation_negative_fast_learning_ratio,
        ),
    ]
    if raw_failure_rows > 0:
        for field, value, floor in relation_checks:
            if floor <= 0 and value is None:
                continue
            if value is not None and value >= floor:
                continue
            failure_reasons.append(
                f"{field} {0.0 if value is None else value:.4f} < {floor:.4f}",
            )
        value = raw["raw_h0_relation_history_preserved_ratio"]
        if min_relation_history_preserved_ratio > 0 and (
            value is None or value < min_relation_history_preserved_ratio
        ):
            failure_reasons.append(
                "raw_h0_relation_history_preserved_ratio "
                f"{0.0 if value is None else value:.4f} < "
                f"{min_relation_history_preserved_ratio:.4f}",
            )
    repair_sample_rows = int(raw["raw_h0_relation_repair_sample_rows"])
    if min_relation_repair_slow_recovery_ratio > 0 and repair_sample_rows == 0:
        failure_reasons.append(
            "raw_h0_relation_repair_slow_recovery_ratio 0.0000 < "
            f"{min_relation_repair_slow_recovery_ratio:.4f} (no repair sample rows)",
        )
    elif repair_sample_rows > 0:
        value = raw["raw_h0_relation_repair_slow_recovery_ratio"]
        if value is None or value < min_relation_repair_slow_recovery_ratio:
            failure_reasons.append(
                "raw_h0_relation_repair_slow_recovery_ratio "
                f"{0.0 if value is None else value:.4f} < "
                f"{min_relation_repair_slow_recovery_ratio:.4f}",
            )
    identity_checks = [
        (
            "raw_h0_identity_domain_trace_ratio",
            raw["raw_h0_identity_domain_trace_ratio"],
            min_identity_domain_trace_ratio,
        ),
        (
            "raw_h0_identity_action_bias_ratio",
            raw["raw_h0_identity_action_bias_ratio"],
            min_identity_action_bias_ratio,
        ),
        (
            "raw_h0_predicted_update_ratio",
            raw["raw_h0_predicted_update_ratio"],
            min_predicted_update_ratio,
        ),
    ]
    if min_desired_slow_drift_ratio > 0:
        identity_checks.append((
            "raw_h0_desired_slow_drift_ratio",
            raw["raw_h0_desired_slow_drift_ratio"],
            min_desired_slow_drift_ratio,
        ))
    if raw_identity_rows > 0:
        for field, value, floor in identity_checks:
            if value is not None and value >= floor:
                continue
            failure_reasons.append(
                f"{field} {0.0 if value is None else value:.4f} < {floor:.4f}",
            )
    if raw_expanded_rows > 0:
        value = raw["raw_h0_expanded_domain_trace_ratio"]
        if value is None or value < min_expanded_domain_trace_ratio:
            failure_reasons.append(
                "raw_h0_expanded_domain_trace_ratio "
                f"{0.0 if value is None else value:.4f} < "
                f"{min_expanded_domain_trace_ratio:.4f}",
            )
    if raw_constitutional_rows > 0:
        value = raw["raw_h0_normative_governance_trigger_ratio"]
        if value is None or value < min_normative_governance_trigger_ratio:
            failure_reasons.append(
                "raw_h0_normative_governance_trigger_ratio "
                f"{0.0 if value is None else value:.4f} < "
                f"{min_normative_governance_trigger_ratio:.4f}",
            )
    if raw_governed_revision_rows > 0:
        value = raw["raw_h0_governed_revision_ratio"]
        if value is None or value < min_governed_revision_ratio:
            failure_reasons.append(
                "raw_h0_governed_revision_ratio "
                f"{0.0 if value is None else value:.4f} < "
                f"{min_governed_revision_ratio:.4f}",
            )
    if raw_governed_revision_evidence_files > 0:
        evidence_checks = [
            (
                "raw_h0_decision_proof_hash_valid_ratio",
                raw["raw_h0_decision_proof_hash_valid_ratio"],
                min_decision_proof_hash_ratio,
            ),
            (
                "raw_h0_iem_anchor_replay_valid_ratio",
                raw["raw_h0_iem_anchor_replay_valid_ratio"],
                min_iem_anchor_replay_ratio,
            ),
            (
                "raw_h0_iem_anchor_replay_embedded_ratio",
                raw["raw_h0_iem_anchor_replay_embedded_ratio"],
                min_iem_anchor_replay_embedded_ratio,
            ),
            (
                "raw_h0_runtime_iem_audit_valid_ratio",
                raw["raw_h0_runtime_iem_audit_valid_ratio"],
                min_runtime_iem_audit_ratio,
            ),
            (
                "raw_h0_vote_refs_present_ratio",
                raw["raw_h0_vote_refs_present_ratio"],
                min_vote_refs_ratio,
            ),
        ]
        for field, value, floor in evidence_checks:
            if value is not None and value >= floor:
                continue
            failure_reasons.append(
                f"{field} {0.0 if value is None else value:.4f} < {floor:.4f}",
            )
        legacy_sidecar_ratio = raw["raw_h0_iem_anchor_replay_legacy_sidecar_ratio"]
        if (
            legacy_sidecar_ratio is not None
            and legacy_sidecar_ratio > max_iem_anchor_replay_legacy_sidecar_ratio
        ):
            failure_reasons.append(
                "raw_h0_iem_anchor_replay_legacy_sidecar_ratio "
                f"{legacy_sidecar_ratio:.4f} > "
                f"{max_iem_anchor_replay_legacy_sidecar_ratio:.4f}",
            )
        authority_kind_count = int(raw["raw_h0_governed_revision_authority_kind_count"])
        if authority_kind_count < min_authority_kind_count:
            failure_reasons.append(
                "raw_h0_governed_revision_authority_kind_count "
                f"{authority_kind_count} < {min_authority_kind_count}",
            )

    return {
        "passed": not failure_reasons,
        "skipped": False,
        "require_active": require_active,
        "min_relation_failure_trace_ratio": min_relation_failure_trace_ratio,
        "min_iem_update_log_ratio": min_iem_update_log_ratio,
        "min_relation_action_bias_ratio": min_relation_action_bias_ratio,
        "min_normative_guard_ratio": min_normative_guard_ratio,
        "min_relation_training_sample_ratio": min_relation_training_sample_ratio,
        "min_relation_negative_fast_learning_ratio": min_relation_negative_fast_learning_ratio,
        "min_relation_repair_slow_recovery_ratio": min_relation_repair_slow_recovery_ratio,
        "min_relation_history_preserved_ratio": min_relation_history_preserved_ratio,
        "min_identity_domain_trace_ratio": min_identity_domain_trace_ratio,
        "min_expanded_domain_trace_ratio": min_expanded_domain_trace_ratio,
        "min_identity_action_bias_ratio": min_identity_action_bias_ratio,
        "min_predicted_update_ratio": min_predicted_update_ratio,
        "min_desired_slow_drift_ratio": min_desired_slow_drift_ratio,
        "min_normative_governance_trigger_ratio": min_normative_governance_trigger_ratio,
        "min_governed_revision_ratio": min_governed_revision_ratio,
        "min_decision_proof_hash_ratio": min_decision_proof_hash_ratio,
        "min_iem_anchor_replay_ratio": min_iem_anchor_replay_ratio,
        "min_iem_anchor_replay_embedded_ratio": min_iem_anchor_replay_embedded_ratio,
        "max_iem_anchor_replay_legacy_sidecar_ratio": max_iem_anchor_replay_legacy_sidecar_ratio,
        "min_runtime_iem_audit_ratio": min_runtime_iem_audit_ratio,
        "min_vote_refs_ratio": min_vote_refs_ratio,
        "min_authority_kind_count": min_authority_kind_count,
        **final_counts,
        **raw,
        "failure_reasons": failure_reasons,
    }


def _identity_prompt_observability(run_dir: Path) -> dict[str, object]:
    raw_dir = run_dir / "raw_ticks"
    if not raw_dir.exists():
        return {
            "tasks_with_ticks": 0,
            "observable_schema_tasks": 0,
            "identity_state_tasks": 0,
            "identity_prompt_tasks": 0,
            "tick_rows": 0,
            "identity_prompt_ticks": 0,
            "llm_tasks": 0,
            "llm_identity_prompt_tasks": 0,
            "llm_tick_rows": 0,
            "llm_identity_prompt_ticks": 0,
            "observable_schema_task_ratio": None,
            "identity_state_task_ratio": None,
            "identity_prompt_task_ratio": None,
            "identity_prompt_tick_ratio": None,
            "identity_prompt_llm_task_ratio": None,
            "identity_prompt_llm_tick_ratio": None,
        }

    tasks_with_ticks = 0
    observable_schema_tasks = 0
    identity_state_tasks = 0
    identity_prompt_tasks = 0
    tick_rows = 0
    identity_prompt_ticks = 0
    llm_tasks = 0
    llm_identity_prompt_tasks = 0
    llm_tick_rows = 0
    llm_identity_prompt_ticks = 0

    for csv_path in sorted(raw_dir.glob("*.csv")):
        with csv_path.open(newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            fieldnames = set(reader.fieldnames or [])
            task_ticks = 0
            task_has_identity_state = False
            task_has_prompt = False
            task_has_llm = False
            task_llm_has_prompt = False
            if fieldnames & {
                "identity_state",
                "identity_remaining_epochs",
                "identity_prompt_injected",
            }:
                observable_schema_tasks += 1
            for row in reader:
                task_ticks += 1
                tick_rows += 1
                state = str(row.get("identity_state", "") or "").strip().upper()
                if state and state != "UNKNOWN":
                    task_has_identity_state = True
                prompt = _parse_csv_bool(row.get("identity_prompt_injected"))
                if prompt is True:
                    identity_prompt_ticks += 1
                    task_has_prompt = True
                if str(row.get("decision_source", "")).strip().lower() == "llm":
                    task_has_llm = True
                    llm_tick_rows += 1
                    if prompt is True:
                        llm_identity_prompt_ticks += 1
                        task_llm_has_prompt = True
            if task_ticks > 0:
                tasks_with_ticks += 1
                if task_has_identity_state:
                    identity_state_tasks += 1
                if task_has_prompt:
                    identity_prompt_tasks += 1
                if task_has_llm:
                    llm_tasks += 1
                    if task_llm_has_prompt:
                        llm_identity_prompt_tasks += 1

    def _ratio(num: int, den: int) -> float | None:
        return (num / den) if den else None

    return {
        "tasks_with_ticks": tasks_with_ticks,
        "observable_schema_tasks": observable_schema_tasks,
        "identity_state_tasks": identity_state_tasks,
        "identity_prompt_tasks": identity_prompt_tasks,
        "tick_rows": tick_rows,
        "identity_prompt_ticks": identity_prompt_ticks,
        "llm_tasks": llm_tasks,
        "llm_identity_prompt_tasks": llm_identity_prompt_tasks,
        "llm_tick_rows": llm_tick_rows,
        "llm_identity_prompt_ticks": llm_identity_prompt_ticks,
        "observable_schema_task_ratio": _ratio(observable_schema_tasks, tasks_with_ticks),
        "identity_state_task_ratio": _ratio(identity_state_tasks, tasks_with_ticks),
        "identity_prompt_task_ratio": _ratio(identity_prompt_tasks, tasks_with_ticks),
        "identity_prompt_tick_ratio": _ratio(identity_prompt_ticks, tick_rows),
        "identity_prompt_llm_task_ratio": _ratio(llm_identity_prompt_tasks, llm_tasks),
        "identity_prompt_llm_tick_ratio": _ratio(llm_identity_prompt_ticks, llm_tick_rows),
    }


def _aggregate_identity_prompt_observability(
    runs: list[tuple[str, Path]],
) -> dict[str, object]:
    per_agent: list[dict[str, object]] = []
    total_tasks = 0
    total_schema_tasks = 0
    total_identity_state_tasks = 0
    total_identity_prompt_tasks = 0
    total_ticks = 0
    total_prompt_ticks = 0
    total_llm_tasks = 0
    total_llm_prompt_tasks = 0
    total_llm_ticks = 0
    total_llm_prompt_ticks = 0
    for alias, run_dir in runs:
        obs = _identity_prompt_observability(run_dir)
        total_tasks += int(obs["tasks_with_ticks"])
        total_schema_tasks += int(obs["observable_schema_tasks"])
        total_identity_state_tasks += int(obs["identity_state_tasks"])
        total_identity_prompt_tasks += int(obs["identity_prompt_tasks"])
        total_ticks += int(obs["tick_rows"])
        total_prompt_ticks += int(obs["identity_prompt_ticks"])
        total_llm_tasks += int(obs["llm_tasks"])
        total_llm_prompt_tasks += int(obs["llm_identity_prompt_tasks"])
        total_llm_ticks += int(obs["llm_tick_rows"])
        total_llm_prompt_ticks += int(obs["llm_identity_prompt_ticks"])
        per_agent.append({"agent_alias": alias, **obs})

    def _ratio(num: int, den: int) -> float | None:
        return (num / den) if den else None

    return {
        "per_agent": sorted(per_agent, key=lambda row: str(row["agent_alias"])),
        "tasks_with_ticks": total_tasks,
        "observable_schema_task_ratio": _ratio(total_schema_tasks, total_tasks),
        "identity_state_task_ratio": _ratio(total_identity_state_tasks, total_tasks),
        "identity_prompt_task_ratio": _ratio(total_identity_prompt_tasks, total_tasks),
        "identity_prompt_tick_ratio": _ratio(total_prompt_ticks, total_ticks),
        "identity_prompt_llm_task_ratio": _ratio(total_llm_prompt_tasks, total_llm_tasks),
        "identity_prompt_llm_tick_ratio": _ratio(total_llm_prompt_ticks, total_llm_ticks),
    }


def _alias_collaboration_score(
    alias: str,
    rows: list[dict[str, str]],
) -> float:
    mine = [
        r for r in rows
        if r.get("agent_a") == alias or r.get("agent_b") == alias
    ]
    if not mine:
        return 1.0
    flagged = sum(1 for r in mine if r.get("flagged") == "1")
    ratio = flagged / len(mine)
    return max(0.0, min(1.0, 1.0 - ratio))


def _score_from_metric(value: float | None, *, invert: bool, unknown: float = 0.5) -> float:
    if value is None:
        return unknown
    clamped = max(0.0, min(1.0, value))
    return 1.0 - clamped if invert else clamped


def _latency_score(task_p95_ms: float | None, target_ms: float) -> float:
    if task_p95_ms is None:
        return 0.5
    if task_p95_ms <= 0:
        return 1.0
    ratio = min(task_p95_ms / target_ms, 1.0)
    return max(0.0, 1.0 - ratio)


def _build_ii2_scorecard(
    *,
    runs: list[tuple[str, Path]],
    final_metrics_csv: Path,
    jaccard_rows: list[dict[str, str]],
    manifest: Manifest | None = None,
) -> dict[str, object]:
    survival_threshold = _env_float(
        "CIVITASOS_IDENTITY_SURVIVAL_THRESHOLD",
        _DEFAULT_SURVIVAL_THRESHOLD,
    )
    completion_floor = _env_float(
        "CIVITASOS_II2_COMPLETION_FLOOR",
        _DEFAULT_COMPLETION_FLOOR,
    )
    latency_target_ms = _env_float(
        "CIVITASOS_II2_LATENCY_TARGET_MS",
        _DEFAULT_LATENCY_TARGET_MS,
    )
    identity_prompt_floor = _env_float(
        "CIVITASOS_IDENTITY_PROMPT_TASK_FLOOR",
        0.95,
    )
    institutional_on = _env_flag("CIVITASOS_INSTITUTIONAL_IDENTITY_ENABLED")

    metrics = _agent_alias_metrics(final_metrics_csv)
    by_agent: list[dict[str, object]] = []
    failure_reasons: list[str] = []
    observability_warnings: list[str] = []
    pass_count = 0
    for alias, run_dir in runs:
        completed, total = _load_completion_from_summary(run_dir)
        completion_rate = (completed / total) if total else 0.0
        m = metrics.get(alias, {})
        m2_obs_ratio = _m2_observable_ratio(run_dir, manifest)
        identity_obs = _identity_prompt_observability(run_dir)

        trust_components = {
            "m1_score": _score_from_metric(
                m.get("m1_result_deviation_rate"), invert=True,
            ),
            "m2_score": _score_from_metric(
                m.get("m2_verification_miss_rate"), invert=True,
            ),
            "m3_score": _score_from_metric(
                m.get("m3_aspect_gap_response_rate"), invert=False,
            ),
            "m4_score": _score_from_metric(
                m.get("m4_lessons_impact_rate"), invert=False,
            ),
        }
        if m2_obs_ratio < 0.05:
            trust_components["m2_score"] = 0.5
            observability_warnings.append(
                f"{alias}: m2 observable ratio {m2_obs_ratio:.4f} is low; m2_score neutralized",
        )
        if institutional_on:
            prompt_task_ratio = identity_obs["identity_prompt_llm_task_ratio"]
            state_task_ratio = identity_obs["identity_state_task_ratio"]
            schema_task_ratio = identity_obs["observable_schema_task_ratio"]
            llm_tasks = int(identity_obs["llm_tasks"])
            if schema_task_ratio is None or schema_task_ratio < identity_prompt_floor:
                observability_warnings.append(
                    f"{alias}: identity observability schema ratio {0.0 if schema_task_ratio is None else schema_task_ratio:.4f} < {identity_prompt_floor:.4f}",
                )
            if llm_tasks > 0 and (
                prompt_task_ratio is None or prompt_task_ratio < identity_prompt_floor
            ):
                observability_warnings.append(
                    f"{alias}: identity prompt llm task ratio {0.0 if prompt_task_ratio is None else prompt_task_ratio:.4f} < {identity_prompt_floor:.4f}",
                )
            if state_task_ratio is None or state_task_ratio < identity_prompt_floor:
                observability_warnings.append(
                    f"{alias}: identity state task ratio {0.0 if state_task_ratio is None else state_task_ratio:.4f} < {identity_prompt_floor:.4f}",
                )
        trust_score = (
            0.35 * trust_components["m1_score"]
            + 0.35 * trust_components["m2_score"]
            + 0.15 * trust_components["m3_score"]
            + 0.15 * trust_components["m4_score"]
        )
        latency_score = _latency_score(m.get("m5_task_latency_p95_ms"), latency_target_ms)
        collaboration_score = _alias_collaboration_score(alias, jaccard_rows)
        identity_score = (
            _DIM_WEIGHTS["completion_rate"] * completion_rate
            + _DIM_WEIGHTS["latency_score"] * latency_score
            + _DIM_WEIGHTS["collaboration_score"] * collaboration_score
            + _DIM_WEIGHTS["trust_score"] * trust_score
        )
        passed = completion_rate >= completion_floor and identity_score >= survival_threshold
        if passed:
            pass_count += 1
        else:
            if completion_rate < completion_floor:
                failure_reasons.append(
                    f"{alias}: completion_rate {completion_rate:.4f} < {completion_floor:.4f}",
                )
            if identity_score < survival_threshold:
                failure_reasons.append(
                    f"{alias}: identity_score {identity_score:.4f} < {survival_threshold:.4f}",
                )

        by_agent.append(
            {
                "agent_alias": alias,
                "run_dir": str(run_dir),
                "completion_rate": round(completion_rate, 6),
                "latency_score": round(latency_score, 6),
                "collaboration_score": round(collaboration_score, 6),
                "trust_score": round(trust_score, 6),
                "identity_score": round(identity_score, 6),
                "metrics_observed": {
                    "m1_result_deviation_rate": m.get("m1_result_deviation_rate"),
                    "m2_verification_miss_rate": m.get("m2_verification_miss_rate"),
                    "m3_aspect_gap_response_rate": m.get("m3_aspect_gap_response_rate"),
                    "m4_lessons_impact_rate": m.get("m4_lessons_impact_rate"),
                    "m5_task_latency_p95_ms": m.get("m5_task_latency_p95_ms"),
                    "m2_observable_ratio": round(m2_obs_ratio, 6),
                    "m3_coverage_ratio": m.get("m3_coverage", 0.0),
                    "m4_coverage_ratio": m.get("m4_coverage", 0.0),
                    "identity_observable_schema_task_ratio": identity_obs["observable_schema_task_ratio"],
                    "identity_state_task_ratio": identity_obs["identity_state_task_ratio"],
                    "identity_prompt_task_ratio": identity_obs["identity_prompt_task_ratio"],
                    "identity_prompt_tick_ratio": identity_obs["identity_prompt_tick_ratio"],
                    "identity_prompt_llm_task_ratio": identity_obs["identity_prompt_llm_task_ratio"],
                    "identity_prompt_llm_tick_ratio": identity_obs["identity_prompt_llm_tick_ratio"],
                },
                "passed": passed,
            }
        )

    by_agent_sorted = sorted(by_agent, key=lambda r: str(r["agent_alias"]))
    overall_identity_score = _mean(
        [float(r["identity_score"]) for r in by_agent_sorted],
    ) or 0.0
    return {
        "schema_version": "ii2_scorecard.v1",
        "generated_at": datetime.now(UTC).isoformat(),
        "runs_root": str(final_metrics_csv.parent),
        "weights": _DIM_WEIGHTS,
        "gate": {
            "passed": pass_count == len(by_agent_sorted),
            "survival_threshold": survival_threshold,
            "completion_floor": completion_floor,
            "failure_reasons": failure_reasons,
            "observability_warnings": observability_warnings,
        },
        "overall_identity_score": round(overall_identity_score, 6),
        "agents": by_agent_sorted,
    }


def _row_with_alias(alias: str, agg) -> dict[str, str]:
    """Flatten an AggregateRow to a CSV-ready dict, prepending agent_alias."""
    out: dict[str, str] = {"agent_alias": alias}
    for col in FINAL_METRIC_COLUMNS:
        if col in agg.metrics:
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


def _action_bigrams(seq: tuple[str, ...]) -> tuple[str, ...]:
    if len(seq) < 2:
        return ()
    return tuple(f"{seq[i]}>{seq[i + 1]}" for i in range(len(seq) - 1))


def _jaccard_set(a: tuple[str, ...], b: tuple[str, ...]) -> float:
    sa, sb = set(a), set(b)
    if not sa and not sb:
        return 1.0
    return len(sa & sb) / len(sa | sb) if (sa | sb) else 0.0


def _jaccard_weighted_multiset(a: tuple[str, ...], b: tuple[str, ...]) -> float:
    """Weighted Jaccard over multisets (counts matter)."""
    ca, cb = Counter(a), Counter(b)
    keys = set(ca) | set(cb)
    if not keys:
        return 1.0
    num = sum(min(ca[k], cb[k]) for k in keys)
    den = sum(max(ca[k], cb[k]) for k in keys)
    return num / den if den else 0.0


def _inter_agent_jaccard(
    runs: list[tuple[str, Path]],
    *,
    jaccard_threshold: float = 0.95,
) -> list[dict[str, str]]:
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
        bigrams = {a: _action_bigrams(seqs[a]) for a in aliases}
        for i, a in enumerate(aliases):
            for b in aliases[i + 1:]:
                j_legacy = _jaccard_set(seqs[a], seqs[b])
                j_weighted_action = _jaccard_weighted_multiset(seqs[a], seqs[b])
                # Primary score for gate: order-aware + count-aware.
                j = _jaccard_weighted_multiset(bigrams[a], bigrams[b])
                rows.append({
                    "task_id": task_id,
                    "agent_a": a,
                    "agent_b": b,
                    "jaccard": f"{j:.4f}",
                    "len_a": str(len(seqs[a])),
                    "len_b": str(len(seqs[b])),
                    "jaccard_legacy_set": f"{j_legacy:.4f}",
                    "jaccard_weighted_action": f"{j_weighted_action:.4f}",
                    "jaccard_weighted_bigram": f"{j:.4f}",
                    "flagged": "1" if j >= jaccard_threshold else "0",
                    "flagged_legacy_set": "1" if j_legacy >= jaccard_threshold else "0",
                })
    return rows


def _evaluate_integrity_gate(
    rows: list[dict[str, str]],
    *,
    max_flagged_pair_ratio: float,
    max_flagged_task_ratio: float,
    min_common_tasks: int,
) -> dict[str, object]:
    pair_count = len(rows)
    flagged_pairs = sum(1 for r in rows if r["flagged"] == "1")
    all_tasks = {r["task_id"] for r in rows}
    flagged_tasks = {r["task_id"] for r in rows if r["flagged"] == "1"}
    common_task_count = len(all_tasks)
    flagged_task_count = len(flagged_tasks)

    flagged_pair_ratio = (flagged_pairs / pair_count) if pair_count else 0.0
    flagged_task_ratio = (flagged_task_count / common_task_count) if common_task_count else 0.0

    reasons: list[str] = []
    if common_task_count < min_common_tasks:
        reasons.append(
            f"insufficient common tasks: {common_task_count} < {min_common_tasks}",
        )
    if flagged_pair_ratio > max_flagged_pair_ratio:
        reasons.append(
            f"flagged pair ratio {flagged_pair_ratio:.4f} > {max_flagged_pair_ratio:.4f}",
        )
    if flagged_task_ratio > max_flagged_task_ratio:
        reasons.append(
            f"flagged task ratio {flagged_task_ratio:.4f} > {max_flagged_task_ratio:.4f}",
        )

    return {
        "passed": not reasons,
        "failure_reasons": reasons,
        "pair_count": pair_count,
        "flagged_pair_count": flagged_pairs,
        "flagged_pair_ratio": flagged_pair_ratio,
        "common_task_count": common_task_count,
        "flagged_task_count": flagged_task_count,
        "flagged_task_ratio": flagged_task_ratio,
    }


def merge(
    *,
    runs_root: Path,
    manifest_path: Path,
    schema_yaml: Path | None,
    jaccard_threshold: float = 0.95,
    gate_max_flagged_pair_ratio: float = 0.25,
    gate_max_flagged_task_ratio: float = 0.50,
    gate_min_common_tasks: int = 30,
    enable_g2_gate: bool = True,
    g3_min_backend_source_ratio: float | None = None,
    g3_min_r2r_relation_id_ratio: float | None = None,
    g3_min_relation_pair_context_ratio: float | None = None,
    g3_min_relation_pair_failure_ref_ratio: float | None = None,
    require_h0_active: bool = False,
    h0_min_relation_failure_trace_ratio: float = _DEFAULT_H0_RELATION_FAILURE_TRACE_FLOOR,
    h0_min_iem_update_log_ratio: float = _DEFAULT_H0_IEM_UPDATE_LOG_FLOOR,
    h0_min_relation_action_bias_ratio: float = _DEFAULT_H0_RELATION_ACTION_BIAS_FLOOR,
    h0_min_normative_guard_ratio: float = _DEFAULT_H0_NORMATIVE_GUARD_FLOOR,
    h0_min_relation_training_sample_ratio: float = _DEFAULT_H0_RELATION_TRAINING_SAMPLE_FLOOR,
    h0_min_relation_negative_fast_learning_ratio: float = _DEFAULT_H0_RELATION_NEGATIVE_FAST_LEARNING_FLOOR,
    h0_min_relation_repair_slow_recovery_ratio: float = _DEFAULT_H0_RELATION_REPAIR_SLOW_RECOVERY_FLOOR,
    h0_min_relation_history_preserved_ratio: float = _DEFAULT_H0_RELATION_HISTORY_PRESERVED_FLOOR,
    h0_min_identity_domain_trace_ratio: float = _DEFAULT_H0_IDENTITY_DOMAIN_TRACE_FLOOR,
    h0_min_expanded_domain_trace_ratio: float = _DEFAULT_H0_EXPANDED_DOMAIN_TRACE_FLOOR,
    h0_min_identity_action_bias_ratio: float = _DEFAULT_H0_IDENTITY_ACTION_BIAS_FLOOR,
    h0_min_predicted_update_ratio: float = _DEFAULT_H0_PREDICTED_UPDATE_FLOOR,
    h0_min_desired_slow_drift_ratio: float = _DEFAULT_H0_DESIRED_SLOW_DRIFT_FLOOR,
    h0_min_normative_governance_trigger_ratio: float = _DEFAULT_H0_NORMATIVE_GOVERNANCE_TRIGGER_FLOOR,
    h0_min_governed_revision_ratio: float = _DEFAULT_H0_GOVERNED_REVISION_FLOOR,
    h0_min_decision_proof_hash_ratio: float = _DEFAULT_H0_DECISION_PROOF_HASH_FLOOR,
    h0_min_iem_anchor_replay_ratio: float = _DEFAULT_H0_IEM_ANCHOR_REPLAY_FLOOR,
    h0_min_iem_anchor_replay_embedded_ratio: float = _DEFAULT_H0_IEM_ANCHOR_REPLAY_EMBEDDED_FLOOR,
    h0_max_iem_anchor_replay_legacy_sidecar_ratio: float = _DEFAULT_H0_IEM_ANCHOR_REPLAY_LEGACY_SIDECAR_MAX,
    h0_min_runtime_iem_audit_ratio: float = _DEFAULT_H0_RUNTIME_IEM_AUDIT_FLOOR,
    h0_min_vote_refs_ratio: float = _DEFAULT_H0_VOTE_REFS_FLOOR,
    h0_min_authority_kind_count: int = _DEFAULT_H0_AUTHORITY_KIND_FLOOR,
) -> dict:
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

    jaccard_rows = _inter_agent_jaccard(
        runs,
        jaccard_threshold=jaccard_threshold,
    )
    jaccard_csv = runs_root / "inter_agent_jaccard.csv"
    if jaccard_rows:
        with jaccard_csv.open("w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=list(jaccard_rows[0].keys()))
            w.writeheader()
            w.writerows(jaccard_rows)
        flagged = sum(1 for r in jaccard_rows if r["flagged"] == "1")
        logger.info(
            "wrote %s (%d pairs, %d flagged ≥%.2f)",
            jaccard_csv, len(jaccard_rows), flagged, jaccard_threshold,
        )
    else:
        flagged = 0
        logger.warning("no common tasks across runs — Jaccard skipped")

    gate = _evaluate_integrity_gate(
        jaccard_rows,
        max_flagged_pair_ratio=gate_max_flagged_pair_ratio,
        max_flagged_task_ratio=gate_max_flagged_task_ratio,
        min_common_tasks=gate_min_common_tasks,
    )
    sentinel_gate = _evaluate_sentinel_gate(runs)
    identity_prompt_observability = _aggregate_identity_prompt_observability(runs)
    if enable_g2_gate:
        g2_gate = _evaluate_g2_gate(
            runs=runs,
            final_metrics_csv=out_csv,
        )
    else:
        g2_gate = {
            "passed": True,
            "skipped": True,
            "failure_reasons": [],
        }
    g3_gate = _evaluate_g3_gate(
        final_metrics_csv=out_csv,
        runs=runs,
        min_backend_relation_context_source_ratio=g3_min_backend_source_ratio,
        min_r2r_relation_id_ratio=g3_min_r2r_relation_id_ratio,
        min_relation_pair_context_ratio=g3_min_relation_pair_context_ratio,
        min_relation_pair_failure_ref_ratio=g3_min_relation_pair_failure_ref_ratio,
    )
    h0_gate = _evaluate_h0_gate(
        final_metrics_csv=out_csv,
        runs=runs,
        manifest=manifest,
        require_active=require_h0_active,
        min_relation_failure_trace_ratio=h0_min_relation_failure_trace_ratio,
        min_iem_update_log_ratio=h0_min_iem_update_log_ratio,
        min_relation_action_bias_ratio=h0_min_relation_action_bias_ratio,
        min_normative_guard_ratio=h0_min_normative_guard_ratio,
        min_relation_training_sample_ratio=h0_min_relation_training_sample_ratio,
        min_relation_negative_fast_learning_ratio=h0_min_relation_negative_fast_learning_ratio,
        min_relation_repair_slow_recovery_ratio=h0_min_relation_repair_slow_recovery_ratio,
        min_relation_history_preserved_ratio=h0_min_relation_history_preserved_ratio,
        min_identity_domain_trace_ratio=h0_min_identity_domain_trace_ratio,
        min_expanded_domain_trace_ratio=h0_min_expanded_domain_trace_ratio,
        min_identity_action_bias_ratio=h0_min_identity_action_bias_ratio,
        min_predicted_update_ratio=h0_min_predicted_update_ratio,
        min_desired_slow_drift_ratio=h0_min_desired_slow_drift_ratio,
        min_normative_governance_trigger_ratio=h0_min_normative_governance_trigger_ratio,
        min_governed_revision_ratio=h0_min_governed_revision_ratio,
        min_decision_proof_hash_ratio=h0_min_decision_proof_hash_ratio,
        min_iem_anchor_replay_ratio=h0_min_iem_anchor_replay_ratio,
        min_iem_anchor_replay_embedded_ratio=h0_min_iem_anchor_replay_embedded_ratio,
        max_iem_anchor_replay_legacy_sidecar_ratio=h0_max_iem_anchor_replay_legacy_sidecar_ratio,
        min_runtime_iem_audit_ratio=h0_min_runtime_iem_audit_ratio,
        min_vote_refs_ratio=h0_min_vote_refs_ratio,
        min_authority_kind_count=h0_min_authority_kind_count,
    )

    summary = {
        "runs_root": str(runs_root),
        "agents": [a for a, _ in runs],
        "final_metrics_csv": str(out_csv),
        "final_metrics_rows": n_rows,
        "jaccard_method": "weighted_multiset_action_bigram",
        "jaccard_threshold": jaccard_threshold,
        "jaccard_csv": str(jaccard_csv) if jaccard_rows else None,
        "jaccard_pairs": len(jaccard_rows),
        "jaccard_flagged_ge_0_95": flagged,
        "jaccard_flagged_ratio": gate["flagged_pair_ratio"],
        "jaccard_flagged_task_count": gate["flagged_task_count"],
        "jaccard_common_task_count": gate["common_task_count"],
        "jaccard_flagged_task_ratio": gate["flagged_task_ratio"],
        "jaccard_legacy_flagged_ge_0_95": (
            sum(1 for r in jaccard_rows if r["flagged_legacy_set"] == "1")
            if jaccard_rows
            else 0
        ),
        "integrity_gate": {
            "passed": gate["passed"],
            "max_flagged_pair_ratio": gate_max_flagged_pair_ratio,
            "max_flagged_task_ratio": gate_max_flagged_task_ratio,
            "min_common_tasks": gate_min_common_tasks,
            "failure_reasons": gate["failure_reasons"],
        },
        "sentinel_gate": sentinel_gate,
        "identity_prompt_observability": identity_prompt_observability,
        "g2_gate": g2_gate,
        "g3_gate": g3_gate,
        "h0_gate": h0_gate,
    }
    ii2_scorecard = _build_ii2_scorecard(
        runs=runs,
        final_metrics_csv=out_csv,
        jaccard_rows=jaccard_rows,
        manifest=manifest,
    )
    ii2_path = runs_root / "ii2_scorecard.json"
    ii2_path.write_text(json.dumps(ii2_scorecard, indent=2), encoding="utf-8")
    summary["ii2_scorecard_json"] = str(ii2_path)
    summary["ii2_gate"] = ii2_scorecard["gate"]
    (runs_root / "merge_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--runs-root", default="runs/F1c")
    p.add_argument("--manifest", default="benchmarks/v1/manifest.yaml")
    p.add_argument("--schema-yaml", default=None)
    p.add_argument("--jaccard-threshold", type=float, default=0.95)
    p.add_argument("--gate-max-flagged-pair-ratio", type=float, default=0.25)
    p.add_argument("--gate-max-flagged-task-ratio", type=float, default=0.50)
    p.add_argument("--gate-min-common-tasks", type=int, default=30)
    p.add_argument(
        "--skip-g2-gate",
        action="store_true",
        help="Skip G.2 subjective-time hard gate; use only for historical run replay.",
    )
    p.add_argument(
        "--g3-min-backend-source-ratio",
        type=float,
        default=None,
        help="Require relation-aware raw rows to come from backend_read_model at this minimum ratio.",
    )
    p.add_argument(
        "--g3-min-r2r-relation-id-ratio",
        type=float,
        default=None,
        help="Require relation-aware raw rows to use R2R registry relation ids at this minimum ratio.",
    )
    p.add_argument(
        "--g3-min-relation-pair-context-ratio",
        type=float,
        default=None,
        help="Require relation-aware raw rows to carry relation_pair context at this minimum ratio.",
    )
    p.add_argument(
        "--g3-min-relation-pair-failure-ref-ratio",
        type=float,
        default=None,
        help="Require rows with relation-pair failure events to emit relation-pair failure refs.",
    )
    p.add_argument(
        "--require-h0-active",
        action="store_true",
        help="Require H.0 expectation traces to be present and non-skipped.",
    )
    p.add_argument(
        "--h0-min-relation-failure-trace-ratio",
        type=float,
        default=_DEFAULT_H0_RELATION_FAILURE_TRACE_FLOOR,
        help="Require relation-pair failure rows to emit H.0 relation surprise traces.",
    )
    p.add_argument(
        "--h0-min-iem-update-log-ratio",
        type=float,
        default=_DEFAULT_H0_IEM_UPDATE_LOG_FLOOR,
        help="Require relation-pair failure rows to emit H.0 IEM update logs.",
    )
    p.add_argument(
        "--h0-min-relation-action-bias-ratio",
        type=float,
        default=_DEFAULT_H0_RELATION_ACTION_BIAS_FLOOR,
        help="Require relation-pair failure rows to emit H.0 relation action bias.",
    )
    p.add_argument(
        "--h0-min-normative-guard-ratio",
        type=float,
        default=_DEFAULT_H0_NORMATIVE_GUARD_FLOOR,
        help="Require relation-pair failure rows to prove normative local update guard.",
    )
    p.add_argument(
        "--h0-min-relation-training-sample-ratio",
        type=float,
        default=_DEFAULT_H0_RELATION_TRAINING_SAMPLE_FLOOR,
        help="Require relation-pair failure rows to expose H0-G training samples.",
    )
    p.add_argument(
        "--h0-min-relation-negative-fast-learning-ratio",
        type=float,
        default=_DEFAULT_H0_RELATION_NEGATIVE_FAST_LEARNING_FLOOR,
        help="Require seeded/targeted relation-training tasks to prove negative fast-learning updates.",
    )
    p.add_argument(
        "--h0-min-relation-repair-slow-recovery-ratio",
        type=float,
        default=_DEFAULT_H0_RELATION_REPAIR_SLOW_RECOVERY_FLOOR,
        help="Require repair rows to prove bounded slow recovery.",
    )
    p.add_argument(
        "--h0-min-relation-history-preserved-ratio",
        type=float,
        default=_DEFAULT_H0_RELATION_HISTORY_PRESERVED_FLOOR,
        help="Require H0-G training samples to preserve failure/repair source refs.",
    )
    p.add_argument(
        "--h0-min-identity-domain-trace-ratio",
        type=float,
        default=_DEFAULT_H0_IDENTITY_DOMAIN_TRACE_FLOOR,
        help="Require H0-C identity rows to emit survival and economic surprise traces.",
    )
    p.add_argument(
        "--h0-min-expanded-domain-trace-ratio",
        type=float,
        default=_DEFAULT_H0_EXPANDED_DOMAIN_TRACE_FLOOR,
        help="Require H0-D expanded rows to emit reputation, task, and governance surprise traces.",
    )
    p.add_argument(
        "--h0-min-identity-action-bias-ratio",
        type=float,
        default=_DEFAULT_H0_IDENTITY_ACTION_BIAS_FLOOR,
        help="Require H0-C identity rows to emit identity action bias.",
    )
    p.add_argument(
        "--h0-min-predicted-update-ratio",
        type=float,
        default=_DEFAULT_H0_PREDICTED_UPDATE_FLOOR,
        help="Require H0-C identity rows to emit predicted-state update candidates.",
    )
    p.add_argument(
        "--h0-min-desired-slow-drift-ratio",
        type=float,
        default=_DEFAULT_H0_DESIRED_SLOW_DRIFT_FLOOR,
        help="Require H0-C identity rows to emit desired-state slow drift updates.",
    )
    p.add_argument(
        "--h0-min-normative-governance-trigger-ratio",
        type=float,
        default=_DEFAULT_H0_NORMATIVE_GOVERNANCE_TRIGGER_FLOOR,
        help="Require constitutional surprise rows to emit normative governance triggers.",
    )
    p.add_argument(
        "--h0-min-governed-revision-ratio",
        type=float,
        default=_DEFAULT_H0_GOVERNED_REVISION_FLOOR,
        help="Require H0-E governed revision rows to emit approved governed revision evidence.",
    )
    p.add_argument(
        "--h0-min-decision-proof-hash-ratio",
        type=float,
        default=_DEFAULT_H0_DECISION_PROOF_HASH_FLOOR,
        help="Require H0-E governed revision evidence files to have recomputable decision proof hashes.",
    )
    p.add_argument(
        "--h0-min-iem-anchor-replay-ratio",
        type=float,
        default=_DEFAULT_H0_IEM_ANCHOR_REPLAY_FLOOR,
        help="Require H0-E governed revision evidence files to have replayable IEM anchors.",
    )
    p.add_argument(
        "--h0-min-iem-anchor-replay-embedded-ratio",
        type=float,
        default=_DEFAULT_H0_IEM_ANCHOR_REPLAY_EMBEDDED_FLOOR,
        help="Require H0-F governed revision evidence replay to come from embedded backend read-model evidence.",
    )
    p.add_argument(
        "--h0-max-iem-anchor-replay-legacy-sidecar-ratio",
        type=float,
        default=_DEFAULT_H0_IEM_ANCHOR_REPLAY_LEGACY_SIDECAR_MAX,
        help="Reject H0-F governed revision replay that falls back to legacy sidecar above this ratio.",
    )
    p.add_argument(
        "--h0-min-runtime-iem-audit-ratio",
        type=float,
        default=_DEFAULT_H0_RUNTIME_IEM_AUDIT_FLOOR,
        help="Require H0-F governed revision evidence to have a replayable Runtime Identity IEM audit artifact.",
    )
    p.add_argument(
        "--h0-min-vote-refs-ratio",
        type=float,
        default=_DEFAULT_H0_VOTE_REFS_FLOOR,
        help="Require H0-E governed revision evidence files to carry at least two vote_refs.",
    )
    p.add_argument(
        "--h0-min-authority-kind-count",
        type=int,
        default=_DEFAULT_H0_AUTHORITY_KIND_FLOOR,
        help="Require at least this many governed authority kinds across H0-E evidence files.",
    )
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
        jaccard_threshold=args.jaccard_threshold,
        gate_max_flagged_pair_ratio=args.gate_max_flagged_pair_ratio,
        gate_max_flagged_task_ratio=args.gate_max_flagged_task_ratio,
        gate_min_common_tasks=args.gate_min_common_tasks,
        enable_g2_gate=not args.skip_g2_gate,
        g3_min_backend_source_ratio=args.g3_min_backend_source_ratio,
        g3_min_r2r_relation_id_ratio=args.g3_min_r2r_relation_id_ratio,
        g3_min_relation_pair_context_ratio=args.g3_min_relation_pair_context_ratio,
        g3_min_relation_pair_failure_ref_ratio=args.g3_min_relation_pair_failure_ref_ratio,
        require_h0_active=args.require_h0_active,
        h0_min_relation_failure_trace_ratio=args.h0_min_relation_failure_trace_ratio,
        h0_min_iem_update_log_ratio=args.h0_min_iem_update_log_ratio,
        h0_min_relation_action_bias_ratio=args.h0_min_relation_action_bias_ratio,
        h0_min_normative_guard_ratio=args.h0_min_normative_guard_ratio,
        h0_min_relation_training_sample_ratio=args.h0_min_relation_training_sample_ratio,
        h0_min_relation_negative_fast_learning_ratio=args.h0_min_relation_negative_fast_learning_ratio,
        h0_min_relation_repair_slow_recovery_ratio=args.h0_min_relation_repair_slow_recovery_ratio,
        h0_min_relation_history_preserved_ratio=args.h0_min_relation_history_preserved_ratio,
        h0_min_identity_domain_trace_ratio=args.h0_min_identity_domain_trace_ratio,
        h0_min_expanded_domain_trace_ratio=args.h0_min_expanded_domain_trace_ratio,
        h0_min_identity_action_bias_ratio=args.h0_min_identity_action_bias_ratio,
        h0_min_predicted_update_ratio=args.h0_min_predicted_update_ratio,
        h0_min_desired_slow_drift_ratio=args.h0_min_desired_slow_drift_ratio,
        h0_min_normative_governance_trigger_ratio=args.h0_min_normative_governance_trigger_ratio,
        h0_min_governed_revision_ratio=args.h0_min_governed_revision_ratio,
        h0_min_decision_proof_hash_ratio=args.h0_min_decision_proof_hash_ratio,
        h0_min_iem_anchor_replay_ratio=args.h0_min_iem_anchor_replay_ratio,
        h0_min_iem_anchor_replay_embedded_ratio=args.h0_min_iem_anchor_replay_embedded_ratio,
        h0_max_iem_anchor_replay_legacy_sidecar_ratio=args.h0_max_iem_anchor_replay_legacy_sidecar_ratio,
        h0_min_runtime_iem_audit_ratio=args.h0_min_runtime_iem_audit_ratio,
        h0_min_vote_refs_ratio=args.h0_min_vote_refs_ratio,
        h0_min_authority_kind_count=args.h0_min_authority_kind_count,
    )
    print(json.dumps(summary, indent=2))
    if not summary["integrity_gate"]["passed"]:
        logger.error(
            "F.1.c integrity gate FAILED: pair_ratio=%.4f task_ratio=%.4f "
            "(thresholds pair<=%.4f task<=%.4f, min_common_tasks=%d).",
            summary["jaccard_flagged_ratio"],
            summary["jaccard_flagged_task_ratio"],
            summary["integrity_gate"]["max_flagged_pair_ratio"],
            summary["integrity_gate"]["max_flagged_task_ratio"],
            summary["integrity_gate"]["min_common_tasks"],
        )
        return 3
    if not summary["sentinel_gate"]["passed"]:
        logger.error(
            "F.1.c sentinel gate FAILED: %d disallowed task sentinel(s): %s",
            summary["sentinel_gate"]["violation_count"],
            "; ".join(summary["sentinel_gate"]["failure_reasons"]),
        )
        return 4
    if not summary["g2_gate"]["passed"]:
        logger.error(
            "G.2 subjective-time gate FAILED: %s",
            "; ".join(summary["g2_gate"]["failure_reasons"]),
        )
        return 6
    if not summary["g3_gate"]["passed"]:
        logger.error(
            "G.3 relation-time gate FAILED: %s",
            "; ".join(summary["g3_gate"]["failure_reasons"]),
        )
        return 7
    if not summary["h0_gate"]["passed"]:
        logger.error(
            "H.0 expectation gate FAILED: %s",
            "; ".join(summary["h0_gate"]["failure_reasons"]),
        )
        return 8
    logger.info(
        "F.1.c integrity+sentinel, G.2, G.3, and H.0 gates PASSED: pair_ratio=%.4f task_ratio=%.4f",
        summary["jaccard_flagged_ratio"],
        summary["jaccard_flagged_task_ratio"],
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
