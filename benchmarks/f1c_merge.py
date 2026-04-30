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
        }
        if all(value is None for value in values.values()):
            continue
        relation_rows.append(row)
        checks = (
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
        )
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

    if (
        not relation_rows
        and raw_consistency["raw_time_window_task_count"] == 0
        and raw_relation_trace["raw_llm_relation_trace_rows"] == 0
    ):
        return {
            "passed": True,
            "skipped": True,
            "reason": "no relation-aware G.3 rows in final_metrics",
            "relation_rows": 0,
            **raw_consistency,
            **raw_relation_trace,
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
        **raw_consistency,
        **raw_relation_trace,
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
        if col in ("m1_result_deviation_rate", "m2_verification_miss_rate",
                   "m3_aspect_gap_response_rate", "m4_lessons_impact_rate",
                   "m5_tick_latency_p50_ms", "m5_tick_latency_p95_ms",
                   "m5_tick_latency_p99_ms", "m5_task_latency_p50_ms",
                   "m5_task_latency_p95_ms", "m6_wait_ratio",
                   "g2_mode_choice_observable_ratio", "g2_llm_waiting_ratio",
                   "g2_llm_deep_think_ratio",
                   "g3_relation_memory_hit_ratio",
                   "g3_relation_aware_decision_ratio",
                   "g3_cross_agent_time_consistency_ratio"):
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
    g3_gate = _evaluate_g3_gate(final_metrics_csv=out_csv, runs=runs)

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
    logger.info(
        "F.1.c integrity+sentinel, G.2, and G.3 gates PASSED: pair_ratio=%.4f task_ratio=%.4f",
        summary["jaccard_flagged_ratio"],
        summary["jaccard_flagged_task_ratio"],
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
