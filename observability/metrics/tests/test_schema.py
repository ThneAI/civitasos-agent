"""Verify schema.py constants stay in lockstep with schema.yaml."""
from __future__ import annotations

from pathlib import Path

import yaml

from observability.metrics.schema import (
    RAW_COLUMNS,
    REQUIRED_COLUMNS,
    SCHEMA_VERSION,
)

SCHEMA_YAML = Path(__file__).resolve().parents[1] / "schema.yaml"


def _load_yaml() -> dict:
    return yaml.safe_load(SCHEMA_YAML.read_text(encoding="utf-8"))


def test_schema_version_matches_yaml() -> None:
    data = _load_yaml()
    assert data["schema_version"] == SCHEMA_VERSION


def test_columns_match_yaml_order() -> None:
    data = _load_yaml()
    yaml_cols = tuple(c["name"] for c in data["columns"])
    assert yaml_cols == RAW_COLUMNS


def test_required_columns_match_yaml() -> None:
    data = _load_yaml()
    yaml_required = {c["name"] for c in data["columns"] if c.get("required") is True}
    assert yaml_required == set(REQUIRED_COLUMNS)


def test_final_metrics_has_six_metric_families() -> None:
    data = _load_yaml()
    cols = [c["name"] for c in data["final_metrics"]["columns"]]
    # M1, M2, M3, M4, M5(tick + task), M6 — at least one column per family.
    families = {"m1_", "m2_", "m3_", "m4_", "m5_", "m6_"}
    for f in families:
        assert any(c.startswith(f) for c in cols), f"missing metric family {f}"
