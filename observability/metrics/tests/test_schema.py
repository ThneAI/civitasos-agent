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
    assert data["final_metrics"]["schema_version"] == SCHEMA_VERSION


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
    # M1..M6 plus G/H stage families — at least one column per family.
    families = {"m1_", "m2_", "m3_", "m4_", "m5_", "m6_", "g2_", "g3_", "h0_"}
    for f in families:
        assert any(c.startswith(f) for c in cols), f"missing metric family {f}"


def test_h0_raw_columns_are_optional() -> None:
    data = _load_yaml()
    columns = {c["name"]: c for c in data["columns"]}
    for name in RAW_COLUMNS:
        if name.startswith("h0_"):
            assert columns[name]["required"] is False
