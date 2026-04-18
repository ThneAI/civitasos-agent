"""task_loader tests — including failure paths required by F.0.c design."""
from __future__ import annotations

from pathlib import Path

import pytest

from benchmarks.task_loader import (
    Manifest, ManifestError, load_manifest,
)

REAL_MANIFEST = Path(__file__).resolve().parents[1] / "v1" / "manifest.yaml"


def test_real_manifest_loads() -> None:
    m = load_manifest(REAL_MANIFEST)
    assert isinstance(m, Manifest)
    assert m.schema_version == "1.1"
    assert len(m.tasks) >= 3
    assert "m1_result_deviation_rate" in m.allowed_metric_codes


def test_lookup_by_id() -> None:
    m = load_manifest(REAL_MANIFEST)
    t = m.task_by_id("R01_happy_01")
    assert t.targets_disease == "R"
    assert t.variant == "happy_path"


def _write(tmp_path: Path, body: str) -> Path:
    p = tmp_path / "manifest.yaml"
    p.write_text(body, encoding="utf-8")
    return p


def _base_yaml() -> str:
    return """
schema:
  version: "1.1"
allowed_metric_codes: [m1_result_deviation_rate]
taxonomy:
  - {id: R01, name: x, targets: R}
tasks:
  - id: R01_happy_01
    category_id: R01
    category_name: x
    targets_disease: R
    variant: happy_path
    description: x
    briefing: x
    telos: x
    success_criteria: [{kind: regex, body: "x"}]
    max_ticks: 5
    metrics_targeted: [m1_result_deviation_rate]
"""


def test_unknown_field_value_rejected(tmp_path: Path) -> None:
    body = _base_yaml().replace("targets_disease: R", "targets_disease: Q")
    with pytest.raises(ManifestError, match="targets_disease"):
        load_manifest(_write(tmp_path, body))


def test_missing_required_field_rejected(tmp_path: Path) -> None:
    body = _base_yaml().replace("    telos: x\n", "")
    with pytest.raises(ManifestError, match="missing required field"):
        load_manifest(_write(tmp_path, body))


def test_invalid_metric_code_rejected(tmp_path: Path) -> None:
    body = _base_yaml().replace(
        "metrics_targeted: [m1_result_deviation_rate]",
        "metrics_targeted: [m99_unknown]",
    )
    with pytest.raises(ManifestError, match="not in allowed_metric_codes"):
        load_manifest(_write(tmp_path, body))


def test_unknown_category_rejected(tmp_path: Path) -> None:
    body = _base_yaml().replace("category_id: R01", "category_id: ZZZ")
    with pytest.raises(ManifestError, match="not in taxonomy"):
        load_manifest(_write(tmp_path, body))


def test_missing_fixture_rejected(tmp_path: Path) -> None:
    body = _base_yaml() + '    fixtures: ["nonexistent.txt"]\n'
    with pytest.raises(ManifestError, match="fixture file does not exist"):
        load_manifest(_write(tmp_path, body))


def test_invalid_kind_rejected(tmp_path: Path) -> None:
    body = _base_yaml().replace("kind: regex", "kind: bogus")
    with pytest.raises(ManifestError, match="kind"):
        load_manifest(_write(tmp_path, body))


def test_duplicate_task_id_rejected(tmp_path: Path) -> None:
    body = _base_yaml() + """
  - id: R01_happy_01
    category_id: R01
    category_name: x
    targets_disease: R
    variant: happy_path
    description: x
    briefing: x
    telos: x
    success_criteria: [{kind: regex, body: "x"}]
    max_ticks: 5
    metrics_targeted: [m1_result_deviation_rate]
"""
    with pytest.raises(ManifestError, match="duplicate task id"):
        load_manifest(_write(tmp_path, body))
