"""task_loader tests — including failure paths required by F.0.c design."""
from __future__ import annotations

from pathlib import Path

import pytest

from benchmarks.task_loader import (
    Manifest, ManifestError, load_manifest,
)

REAL_MANIFEST = Path(__file__).resolve().parents[1] / "v1" / "manifest.yaml"
V2_RELATION_MANIFEST = Path(__file__).resolve().parents[1] / "v2" / "relation_memory_manifest.yaml"


def test_real_manifest_loads() -> None:
    m = load_manifest(REAL_MANIFEST)
    assert isinstance(m, Manifest)
    assert m.schema_version == "1.1"
    assert len(m.tasks) >= 3
    assert "m1_result_deviation_rate" in m.allowed_metric_codes


def test_v2_relation_manifest_loads_and_has_expanded_g3_coverage() -> None:
    m = load_manifest(V2_RELATION_MANIFEST)
    assert m.schema_version == "2.0"
    assert len(m.tasks) >= 10

    variants_by_category: dict[str, set[str]] = {}
    for task in m.tasks:
        assert task.targets_disease == "G"
        assert any(code.startswith("g3_") for code in task.metrics_targeted)
        variants_by_category.setdefault(task.category_id, set()).add(task.variant)

    taxonomy_ids = {entry["id"] for entry in m.taxonomy}
    assert taxonomy_ids <= set(variants_by_category)
    for category_id, variants in variants_by_category.items():
        assert variants == {"happy_path", "adversarial"}, category_id

    seeded = {task.id: task.backend_seed_failures for task in m.tasks}
    assert seeded["G03_happy_01"] == 1
    assert seeded["G03_adversarial_01"] == 1
    repair_seeded = {task.id: task.backend_seed_repairs for task in m.tasks}
    assert repair_seeded["G03_happy_01"] == 1
    assert repair_seeded["G03_adversarial_01"] == 0


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


# ─── F.1.a: $ref support tests ────────────────────────────────────────

REF_TASK_BODY = """\
id: R01_happy_42
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


def _ref_manifest(ref_target: str) -> str:
    return f"""
schema:
  version: "1.1"
allowed_metric_codes: [m1_result_deviation_rate]
taxonomy:
  - {{id: R01, name: x, targets: R}}
tasks:
  - {{$ref: {ref_target}}}
"""


def test_ref_loads_external_file(tmp_path: Path) -> None:
    sub = tmp_path / "tasks" / "R01"
    sub.mkdir(parents=True)
    (sub / "happy_42.yaml").write_text(REF_TASK_BODY, encoding="utf-8")
    p = _write(tmp_path, _ref_manifest("tasks/R01/happy_42.yaml"))
    m = load_manifest(p)
    assert len(m.tasks) == 1
    assert m.tasks[0].id == "R01_happy_42"


def test_ref_missing_file_rejected(tmp_path: Path) -> None:
    p = _write(tmp_path, _ref_manifest("tasks/does_not_exist.yaml"))
    with pytest.raises(ManifestError, match="does not exist"):
        load_manifest(p)


def test_ref_duplicate_rejected(tmp_path: Path) -> None:
    sub = tmp_path / "tasks" / "R01"
    sub.mkdir(parents=True)
    (sub / "happy_42.yaml").write_text(REF_TASK_BODY, encoding="utf-8")
    body = f"""
schema:
  version: "1.1"
allowed_metric_codes: [m1_result_deviation_rate]
taxonomy:
  - {{id: R01, name: x, targets: R}}
tasks:
  - {{$ref: tasks/R01/happy_42.yaml}}
  - {{$ref: tasks/R01/happy_42.yaml}}
"""
    with pytest.raises(ManifestError, match="cycle / duplicate"):
        load_manifest(_write(tmp_path, body))


def test_ref_with_extra_keys_treated_as_inline(tmp_path: Path) -> None:
    """$ref + other keys (len != 1) is NOT a $ref — falls through to inline parse,
    which fails because the dict isn't a valid task."""
    body = """
schema:
  version: "1.1"
allowed_metric_codes: [m1_result_deviation_rate]
taxonomy:
  - {id: R01, name: x, targets: R}
tasks:
  - {$ref: tasks/foo.yaml, id: extra_key}
"""
    with pytest.raises(ManifestError):
        load_manifest(_write(tmp_path, body))


def test_ref_target_must_be_mapping(tmp_path: Path) -> None:
    sub = tmp_path / "tasks"
    sub.mkdir()
    (sub / "scalar.yaml").write_text("just a string\n", encoding="utf-8")
    p = _write(tmp_path, _ref_manifest("tasks/scalar.yaml"))
    with pytest.raises(ManifestError, match="single task mapping"):
        load_manifest(p)
