"""Briefing renderer — produces the JSON injected to agent via env var.

F.0.c contract: orchestrator writes briefing.json to tasks/{id}/briefing.json,
then sets BENCHMARK_BRIEFING_FILE=<path>; the agent's perceive step reads it.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .task_loader import TaskSpec

BRIEFING_SCHEMA_VERSION = "1.0"


def render(task: TaskSpec, *, run_id: str) -> dict[str, Any]:
    return {
        "schema_version": BRIEFING_SCHEMA_VERSION,
        "run_id": run_id,
        "task_id": task.id,
        "category_id": task.category_id,
        "variant": task.variant,
        "max_ticks": task.max_ticks,
        "tools_allowed": list(task.tools_allowed),
        "fixtures": list(task.fixtures),
        # The actual instruction text the agent sees:
        "briefing": task.briefing,
        "metadata": {
            "active_tasks": [task.id],   # consumed by CognitiveLoop conscience
        },
    }


def write_briefing(task: TaskSpec, *, run_id: str, out_path: str | Path) -> Path:
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    payload = render(task, run_id=run_id)
    out.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return out
