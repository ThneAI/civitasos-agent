"""Manifest loader + validator for benchmarks/v1/manifest.yaml.

Enforces v1.1 schema:
  * Every task has a category_id present in taxonomy[].id.
  * Every metrics_targeted code is in allowed_metric_codes.
  * Every fixture path resolves to an existing file (relative to manifest dir).
  * Every success_criterion has kind ∈ {regex, pyexpr, llm_judge}.
  * Variant ∈ {happy_path, adversarial}; targets_disease ∈ {R,V,S,A,G}.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

VALID_KINDS = frozenset({"regex", "pyexpr", "llm_judge"})
VALID_VARIANTS = frozenset({"happy_path", "adversarial"})
VALID_DISEASES = frozenset({"R", "V", "S", "A", "G"})
REQUIRED_TASK_FIELDS = (
    "id", "category_id", "category_name", "targets_disease",
    "variant", "description", "briefing", "telos",
    "success_criteria", "max_ticks", "metrics_targeted",
)


class ManifestError(ValueError):
    """Raised when the manifest fails validation; aggregator must fail-fast."""


@dataclass
class TaskSpec:
    id: str
    category_id: str
    category_name: str
    targets_disease: str
    variant: str
    description: str
    briefing: str
    telos: str
    success_criteria: list[dict[str, Any]]
    max_ticks: int
    metrics_targeted: list[str]
    expected_failure_mode: str | None = None
    tools_allowed: list[str] = field(default_factory=lambda: ["*"])
    verifier_tools: list[str] = field(default_factory=list)
    fixtures: list[str] = field(default_factory=list)


@dataclass
class Manifest:
    schema_version: str
    allowed_metric_codes: list[str]
    taxonomy: list[dict[str, Any]]
    tasks: list[TaskSpec]
    path: Path

    def task_by_id(self, task_id: str) -> TaskSpec:
        for t in self.tasks:
            if t.id == task_id:
                return t
        raise KeyError(task_id)


def load_manifest(path: str | Path) -> Manifest:
    p = Path(path)
    if not p.is_file():
        raise ManifestError(f"manifest not found: {p}")
    raw = yaml.safe_load(p.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ManifestError("manifest must be a top-level mapping")

    schema = raw.get("schema") or {}
    schema_version = str(schema.get("version", ""))
    if not schema_version:
        raise ManifestError("manifest.schema.version is required")

    allowed_codes = raw.get("allowed_metric_codes")
    if not isinstance(allowed_codes, list) or not allowed_codes:
        raise ManifestError("manifest.allowed_metric_codes must be a non-empty list")

    taxonomy = raw.get("taxonomy") or []
    if not isinstance(taxonomy, list) or not taxonomy:
        raise ManifestError("manifest.taxonomy must be a non-empty list")
    taxonomy_ids = {t["id"] for t in taxonomy if isinstance(t, dict) and "id" in t}

    raw_tasks = raw.get("tasks") or []
    if not isinstance(raw_tasks, list) or not raw_tasks:
        raise ManifestError("manifest.tasks must be a non-empty list")

    seen_ids: set[str] = set()
    seen_refs: set[Path] = set()
    tasks: list[TaskSpec] = []
    for i, raw_task in enumerate(raw_tasks):
        # v1.1.1: $ref support — referenced file must contain a single task mapping.
        # Inline mappings still supported (backward compat with F.0 manifest).
        if isinstance(raw_task, dict) and "$ref" in raw_task and len(raw_task) == 1:
            ref_str = str(raw_task["$ref"])
            ref_path = (p.parent / ref_str).resolve()
            if ref_path in seen_refs:
                raise ManifestError(f"task[{i}]: $ref cycle / duplicate reference: {ref_str}")
            seen_refs.add(ref_path)
            if not ref_path.is_file():
                raise ManifestError(f"task[{i}]: $ref target does not exist: {ref_str}")
            try:
                ref_raw = yaml.safe_load(ref_path.read_text(encoding="utf-8"))
            except yaml.YAMLError as e:
                raise ManifestError(f"task[{i}]: $ref {ref_str} yaml parse error: {e}") from e
            if not isinstance(ref_raw, dict):
                raise ManifestError(f"task[{i}]: $ref {ref_str} must contain a single task mapping")
            # Fixture paths inside referenced file are resolved relative to the referenced
            # file's directory, NOT the manifest dir — keeps task files self-contained.
            try:
                t = _parse_task(ref_raw, taxonomy_ids, set(allowed_codes), ref_path.parent)
            except ManifestError as e:
                raise ManifestError(f"task[{i}] ($ref={ref_str}): {e}") from e
        else:
            try:
                t = _parse_task(raw_task, taxonomy_ids, set(allowed_codes), p.parent)
            except ManifestError as e:
                raise ManifestError(f"task[{i}] ({raw_task.get('id', '?')}): {e}") from e
        if t.id in seen_ids:
            raise ManifestError(f"duplicate task id: {t.id}")
        seen_ids.add(t.id)
        tasks.append(t)

    return Manifest(
        schema_version=schema_version,
        allowed_metric_codes=list(allowed_codes),
        taxonomy=taxonomy,
        tasks=tasks,
        path=p,
    )


def _parse_task(
    raw: Any, taxonomy_ids: set[str], allowed_codes: set[str], manifest_dir: Path,
) -> TaskSpec:
    if not isinstance(raw, dict):
        raise ManifestError("task must be a mapping")
    for f in REQUIRED_TASK_FIELDS:
        if f not in raw:
            raise ManifestError(f"missing required field: {f}")
    if raw["category_id"] not in taxonomy_ids:
        raise ManifestError(
            f"category_id {raw['category_id']!r} not in taxonomy"
        )
    if raw["targets_disease"] not in VALID_DISEASES:
        raise ManifestError(f"targets_disease must be one of {sorted(VALID_DISEASES)}")
    if raw["variant"] not in VALID_VARIANTS:
        raise ManifestError(f"variant must be one of {sorted(VALID_VARIANTS)}")

    criteria = raw["success_criteria"]
    if not isinstance(criteria, list) or not criteria:
        raise ManifestError("success_criteria must be a non-empty list")
    for j, c in enumerate(criteria):
        if not isinstance(c, dict):
            raise ManifestError(f"success_criteria[{j}] must be a mapping")
        if c.get("kind") not in VALID_KINDS:
            raise ManifestError(
                f"success_criteria[{j}].kind must be one of {sorted(VALID_KINDS)}"
            )
        if "body" not in c or not isinstance(c["body"], str):
            raise ManifestError(f"success_criteria[{j}].body must be a string")

    metrics = raw["metrics_targeted"]
    if not isinstance(metrics, list) or not metrics:
        raise ManifestError("metrics_targeted must be a non-empty list")
    for code in metrics:
        if code not in allowed_codes:
            raise ManifestError(
                f"metrics_targeted contains {code!r} not in allowed_metric_codes"
            )

    fixtures = raw.get("fixtures") or []
    for fp in fixtures:
        full = manifest_dir / fp
        if not full.is_file():
            raise ManifestError(f"fixture file does not exist: {fp}")

    return TaskSpec(
        id=str(raw["id"]),
        category_id=str(raw["category_id"]),
        category_name=str(raw["category_name"]),
        targets_disease=str(raw["targets_disease"]),
        variant=str(raw["variant"]),
        description=str(raw["description"]),
        briefing=str(raw["briefing"]),
        telos=str(raw["telos"]),
        success_criteria=list(criteria),
        max_ticks=int(raw["max_ticks"]),
        metrics_targeted=list(metrics),
        expected_failure_mode=raw.get("expected_failure_mode"),
        tools_allowed=list(raw.get("tools_allowed", ["*"])),
        verifier_tools=list(raw.get("verifier_tools", [])),
        fixtures=list(fixtures),
    )
