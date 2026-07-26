from __future__ import annotations

import hashlib
import json
from pathlib import Path

from benchmarks.j1.controlled_comparison import canonical_sha256
from benchmarks.j1.qualification_execution_contract_v4 import SOURCE_NAMES
from benchmarks.j1_qualification_execution_contract_v4 import CANONICAL_FIELDS
from benchmarks.j1_qualification_source_inventory_v4 import (
    build_source_inventory,
    validate_source_inventory,
)


def _artifact(root: Path, name: str) -> dict[str, str]:
    canonical_field = CANONICAL_FIELDS.get(name)
    value = (
        {canonical_field: hashlib.sha256(name.encode()).hexdigest()}
        if canonical_field
        else {"name": name}
    )
    path = root / f"{name}.json"
    path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")
    canonical = value[canonical_field] if canonical_field else canonical_sha256(value)
    return {
        "path": str(path),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "canonical_sha256": canonical,
    }


def test_build_source_inventory_replaces_only_activation_pair(tmp_path: Path) -> None:
    sources = {name: _artifact(tmp_path, name) for name in SOURCE_NAMES}
    base_path = tmp_path / "base.json"
    base = {"schema_version": "v1", "source_artifacts": sources}
    base_path.write_text(json.dumps(base, sort_keys=True), encoding="utf-8")
    activation = _artifact(tmp_path, "infrastructure_activation")
    gate = _artifact(tmp_path, "infrastructure_activation_gate")
    inventory = build_source_inventory(
        created_at="2026-07-26T12:00:00+00:00",
        base_inventory_path=base_path,
        infrastructure_activation_path=Path(activation["path"]),
        infrastructure_activation_gate_path=Path(gate["path"]),
    )
    assert validate_source_inventory(inventory, base_inventory=base) == []
    assert set(inventory["source_artifacts"]) == SOURCE_NAMES
    assert set(inventory["replacements"]) == {
        "infrastructure_activation",
        "infrastructure_activation_gate",
    }
    for name in SOURCE_NAMES - set(inventory["replacements"]):
        assert inventory["source_artifacts"][name] == sources[name]


def test_source_inventory_rejects_immutable_source_drift(tmp_path: Path) -> None:
    sources = {name: _artifact(tmp_path, name) for name in SOURCE_NAMES}
    base_path = tmp_path / "base.json"
    base = {"schema_version": "v1", "source_artifacts": sources}
    base_path.write_text(json.dumps(base, sort_keys=True), encoding="utf-8")
    inventory = build_source_inventory(
        created_at="2026-07-26T12:00:00+00:00",
        base_inventory_path=base_path,
        infrastructure_activation_path=Path(
            sources["infrastructure_activation"]["path"]
        ),
        infrastructure_activation_gate_path=Path(
            sources["infrastructure_activation_gate"]["path"]
        ),
    )
    inventory["source_artifacts"]["amended_design"]["sha256"] = "0" * 64
    failures = validate_source_inventory(inventory, base_inventory=base)
    assert "source_inventory_identity_invalid" in failures
    assert "source_inventory_immutable_source_drifted" in failures
