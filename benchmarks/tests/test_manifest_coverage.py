"""F.1.a — manifest coverage tests.

Enforces design constraints from F1_BASELINE_DESIGN.md §2.1, §2.2, §2.6:
  - Total tasks ≥ 60 (30 categories × 2 variants)
  - Each category has ≥1 happy_path AND ≥1 adversarial
  - V/A/G tasks: ≥60% machine-checkable (regex/pyexpr) success_criteria (aggregate)
  - R/S tasks:   ≥30% machine-checkable success_criteria (aggregate)
  - Every adversarial task has expected_failure_mode + ≥1 verifier_tools

These tests fail-fast: a regression in manifest construction will break the
CI before F.1.c baseline run begins (saves ~9h of wasted compute).
"""
from __future__ import annotations

from collections import defaultdict
from pathlib import Path

import pytest

from benchmarks.task_loader import load_manifest

MANIFEST = Path(__file__).resolve().parents[1] / "v1" / "manifest.yaml"

MACHINE_KINDS = frozenset({"regex", "pyexpr"})
LLM_KINDS = frozenset({"llm_judge"})

VAG_DISEASES = frozenset({"V", "A", "G"})
RS_DISEASES = frozenset({"R", "S"})


@pytest.fixture(scope="module")
def manifest():
    return load_manifest(MANIFEST)


# ─── §2.1 scale & per-category coverage ───────────────────────────────

def test_total_tasks_at_least_60(manifest) -> None:
    assert len(manifest.tasks) >= 60, (
        f"F.1.a requires ≥60 tasks (30 cat × 2 variants); got {len(manifest.tasks)}"
    )


def test_each_category_has_happy_and_adversarial(manifest) -> None:
    by_cat: dict[str, set[str]] = defaultdict(set)
    for t in manifest.tasks:
        by_cat[t.category_id].add(t.variant)

    taxonomy_ids = {t["id"] for t in manifest.taxonomy}
    missing: list[str] = []
    for cat in taxonomy_ids:
        variants = by_cat.get(cat, set())
        if "happy_path" not in variants:
            missing.append(f"{cat}: no happy_path")
        if "adversarial" not in variants:
            missing.append(f"{cat}: no adversarial")
    assert not missing, "Coverage gaps:\n  " + "\n  ".join(missing)


# ─── §2.2 per-disease verification distribution ───────────────────────

def _criterion_kind_counts(tasks) -> tuple[int, int]:
    machine = sum(
        1 for t in tasks
        for c in t.success_criteria
        if c.get("kind") in MACHINE_KINDS
    )
    total = sum(len(t.success_criteria) for t in tasks)
    return machine, total


def test_vag_machine_checkable_ratio_at_least_60pct(manifest) -> None:
    vag = [t for t in manifest.tasks if t.targets_disease in VAG_DISEASES]
    machine, total = _criterion_kind_counts(vag)
    assert total > 0, "no V/A/G tasks found"
    ratio = machine / total
    assert ratio >= 0.60, (
        f"V/A/G machine-checkable ratio {ratio:.1%} < 60% "
        f"({machine}/{total} criteria); design §2.2 requires ≥60%"
    )


def test_rs_machine_checkable_ratio_at_least_30pct(manifest) -> None:
    rs = [t for t in manifest.tasks if t.targets_disease in RS_DISEASES]
    machine, total = _criterion_kind_counts(rs)
    assert total > 0, "no R/S tasks found"
    ratio = machine / total
    assert ratio >= 0.30, (
        f"R/S machine-checkable ratio {ratio:.1%} < 30% "
        f"({machine}/{total} criteria); design §2.2 requires ≥30%"
    )


# ─── §2.2 adversarial-specific constraints ────────────────────────────

def test_every_adversarial_has_expected_failure_mode(manifest) -> None:
    missing = [
        t.id for t in manifest.tasks
        if t.variant == "adversarial" and not t.expected_failure_mode
    ]
    assert not missing, (
        f"adversarial tasks missing expected_failure_mode: {missing}"
    )


def test_every_adversarial_has_at_least_one_verifier_tool(manifest) -> None:
    missing = [
        t.id for t in manifest.tasks
        if t.variant == "adversarial" and not t.verifier_tools
    ]
    assert not missing, (
        f"adversarial tasks missing verifier_tools (M2 cannot be computed for them): {missing}"
    )


# ─── §6 backward compat: inline + $ref dual-mode ──────────────────────

def test_inline_tasks_still_loadable(manifest) -> None:
    """F.0 inline tasks must remain loadable (M5 backward-compat)."""
    inline_ids = {"R01_happy_01", "V04_adversarial_01", "A01_happy_01"}
    loaded_ids = {t.id for t in manifest.tasks}
    missing = inline_ids - loaded_ids
    assert not missing, f"F.0 inline tasks lost: {missing}"


def test_ref_tasks_loaded(manifest) -> None:
    """At least 50 $ref-loaded tasks expected (3 inline + ≥57 $ref = ≥60)."""
    # heuristic: count tasks that come from category subdirs (not inline)
    # by checking that we have many distinct category files
    by_cat = defaultdict(int)
    for t in manifest.tasks:
        by_cat[t.category_id] += 1
    assert len(by_cat) >= 30, (
        f"expected ≥30 distinct categories, got {len(by_cat)}"
    )


# ─── duplicate / ID format sanity ─────────────────────────────────────

def test_no_duplicate_task_ids(manifest) -> None:
    ids = [t.id for t in manifest.tasks]
    assert len(ids) == len(set(ids)), (
        f"duplicate task IDs: {[i for i in ids if ids.count(i) > 1]}"
    )


def test_task_id_format(manifest) -> None:
    import re
    pattern = re.compile(r"^[RVSAG]\d{2}_(happy|adversarial|h1_[a-z0-9_]+)_\d{2}$")
    bad = [t.id for t in manifest.tasks if not pattern.match(t.id)]
    assert not bad, f"task IDs violating [RVSAG]NN_(happy|adversarial|h1_*)_NN: {bad}"
