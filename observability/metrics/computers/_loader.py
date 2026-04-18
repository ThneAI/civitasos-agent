"""Shared structures + CSV loader for computers/."""
from __future__ import annotations

import csv
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable


@dataclass
class TickRow:
    """Parsed raw_tick row with the fields F.0 computers actually need."""
    run_id: str
    agent_id: str
    task_id: str
    tick_seq: int
    timestamp: str
    phase_reached: str
    decision_action: str
    eval_success: bool | None
    eval_duration_ms: int | None
    aspect_gap: float
    is_wait: bool


@dataclass
class TaskRun:
    task_id: str
    ticks: list[TickRow] = field(default_factory=list)
    # Resolved later from manifest:
    category_id: str = ""
    targets_disease: str = ""
    variant: str = ""
    verifier_tools: list[str] = field(default_factory=list)
    success_criteria: list[dict] = field(default_factory=list)
    # Filled by orchestrator into summary.json:
    agent_self_reported_success: bool | None = None


def load_task_runs(runs_dir: str | Path) -> dict[str, TaskRun]:
    """Load every {task_id}.csv under runs_dir into TaskRun objects."""
    runs_dir = Path(runs_dir)
    out: dict[str, TaskRun] = {}
    for csv_path in sorted(runs_dir.glob("*.csv")):
        task_id = csv_path.stem
        if task_id.startswith("_"):
            continue
        out[task_id] = TaskRun(task_id=task_id, ticks=list(_iter_rows(csv_path)))
    return out


def _iter_rows(path: Path) -> Iterable[TickRow]:
    with path.open("r", encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        for raw in reader:
            yield TickRow(
                run_id=raw.get("run_id", ""),
                agent_id=raw.get("agent_id", ""),
                task_id=raw.get("task_id", ""),
                tick_seq=_int(raw.get("tick_seq"), 0),
                timestamp=raw.get("timestamp", ""),
                phase_reached=raw.get("phase_reached", ""),
                decision_action=raw.get("decision_action", ""),
                eval_success=_optbool(raw.get("eval_success")),
                eval_duration_ms=_optint(raw.get("eval_duration_ms")),
                aspect_gap=_float(raw.get("aspect_gap"), 0.0),
                is_wait=_optbool(raw.get("is_wait")) or False,
            )


def _int(s: str | None, default: int) -> int:
    if s is None or s == "":
        return default
    return int(s)


def _optint(s: str | None) -> int | None:
    if s is None or s == "":
        return None
    try:
        return int(s)
    except ValueError:
        return None


def _float(s: str | None, default: float) -> float:
    if s is None or s == "":
        return default
    return float(s)


def _optbool(s: str | None) -> bool | None:
    if s is None or s == "":
        return None
    return s.lower() == "true"
