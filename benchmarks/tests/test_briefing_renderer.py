"""briefing_renderer tests — schema integrity."""
from __future__ import annotations

import json
from pathlib import Path

from benchmarks.briefing_renderer import (
    BRIEFING_SCHEMA_VERSION, render, write_briefing,
)
from benchmarks.task_loader import TaskSpec


def _spec() -> TaskSpec:
    return TaskSpec(
        id="R01_happy_01",
        category_id="R01",
        category_name="x",
        targets_disease="R",
        variant="happy_path",
        description="x",
        briefing="please translate",
        telos="t",
        success_criteria=[{"kind": "regex", "body": "x"}],
        max_ticks=20,
        metrics_targeted=["m1_result_deviation_rate"],
        tools_allowed=["llm"],
    )


def test_render_payload_shape() -> None:
    p = render(_spec(), run_id="R")
    assert p["schema_version"] == BRIEFING_SCHEMA_VERSION
    assert p["task_id"] == "R01_happy_01"
    assert p["max_ticks"] == 20
    assert p["briefing"] == "please translate"
    assert p["metadata"]["active_tasks"] == ["R01_happy_01"]


def test_write_briefing_round_trip(tmp_path: Path) -> None:
    out = write_briefing(_spec(), run_id="R", out_path=tmp_path / "b.json")
    loaded = json.loads(out.read_text(encoding="utf-8"))
    assert loaded["task_id"] == "R01_happy_01"
    assert loaded["tools_allowed"] == ["llm"]
