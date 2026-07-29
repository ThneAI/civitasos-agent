"""Private material bindings for an outcome-sensitive J1-D live run."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .controlled_comparison import canonical_sha256


MATERIAL_BINDING_SCHEMA = (
    "j1-qualification-outcome-sensitive-execution-material-bindings:v1"
)


def build_material_bindings(
    *,
    task_fixture_path: Path,
    signed_advice_root: Path,
    participant_profiles_root: Path,
) -> dict[str, Any]:
    value = {
        "schema_version": MATERIAL_BINDING_SCHEMA,
        "task_fixture": _file_binding(task_fixture_path),
        "signed_advice": _directory_binding(
            signed_advice_root,
            pattern="*.json",
            expected_count=180,
        ),
        "participant_profiles": _directory_binding(
            participant_profiles_root,
            pattern="*.json",
            expected_count=40,
        ),
    }
    value["material_binding_sha256"] = canonical_sha256(value)
    failures = validate_material_bindings(value)
    if failures:
        raise ValueError(
            f"outcome-sensitive material bindings invalid: {failures}"
        )
    return value


def validate_material_bindings(value: Any) -> list[str]:
    bindings = value if isinstance(value, dict) else {}
    failures: list[str] = []
    if bindings.get("schema_version") != MATERIAL_BINDING_SCHEMA:
        failures.append("outcome_material_binding_schema_invalid")
    fixture = bindings.get("task_fixture", {})
    if not (
        _absolute_path(fixture.get("path"))
        and _digest(fixture.get("sha256"))
        and _digest(fixture.get("canonical_sha256"))
    ):
        failures.append("outcome_task_fixture_binding_invalid")
    for name, expected_count in (
        ("signed_advice", 180),
        ("participant_profiles", 40),
    ):
        item = bindings.get(name, {})
        if not (
            _absolute_path(item.get("path"))
            and item.get("file_count") == expected_count
            and _digest(item.get("manifest_sha256"))
        ):
            failures.append(f"outcome_{name}_binding_invalid")
    body = {
        key: item
        for key, item in bindings.items()
        if key != "material_binding_sha256"
    }
    if bindings.get("material_binding_sha256") != canonical_sha256(body):
        failures.append("outcome_material_binding_hash_invalid")
    return list(dict.fromkeys(failures))


def replay_material_bindings(bindings: dict[str, Any]) -> None:
    failures = validate_material_bindings(bindings)
    if not failures:
        actual = {
            "task_fixture": _file_binding(
                Path(bindings["task_fixture"]["path"])
            ),
            "signed_advice": _directory_binding(
                Path(bindings["signed_advice"]["path"]),
                pattern="*.json",
                expected_count=180,
            ),
            "participant_profiles": _directory_binding(
                Path(bindings["participant_profiles"]["path"]),
                pattern="*.json",
                expected_count=40,
            ),
        }
        for name, item in actual.items():
            if item != bindings[name]:
                failures.append(f"outcome_{name}_content_drift")
    if failures:
        raise ValueError(
            f"outcome-sensitive material replay invalid: {failures}"
        )


def _file_binding(path: Path) -> dict[str, Any]:
    resolved, raw, value = _read_private_json(path)
    return {
        "path": str(resolved),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "canonical_sha256": canonical_sha256(value),
    }


def _directory_binding(
    root: Path,
    *,
    pattern: str,
    expected_count: int,
) -> dict[str, Any]:
    resolved = root.resolve()
    if (
        root.is_symlink()
        or not resolved.is_dir()
        or resolved.stat().st_mode & 0o077
    ):
        raise ValueError(
            f"outcome execution material directory is not private: {resolved}"
        )
    entries = []
    for path in sorted(resolved.glob(pattern)):
        child, raw, value = _read_private_json(path)
        entries.append(
            {
                "name": child.name,
                "sha256": hashlib.sha256(raw).hexdigest(),
                "canonical_sha256": canonical_sha256(value),
            }
        )
    if len(entries) != expected_count:
        raise ValueError(
            "outcome execution material directory requires "
            f"{expected_count} files: {resolved}"
        )
    return {
        "path": str(resolved),
        "file_count": len(entries),
        "manifest_sha256": canonical_sha256(entries),
    }


def _read_private_json(path: Path) -> tuple[Path, bytes, dict[str, Any]]:
    resolved = path.resolve()
    if (
        path.is_symlink()
        or not resolved.is_file()
        or resolved.stat().st_mode & 0o077
    ):
        raise ValueError(
            f"outcome execution material is not private: {resolved}"
        )
    raw = resolved.read_bytes()
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError(
            f"outcome execution material is not an object: {resolved}"
        )
    return resolved, raw, value


def _absolute_path(value: Any) -> bool:
    return isinstance(value, str) and Path(value).is_absolute()


def _digest(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(char in "0123456789abcdef" for char in value)
    )
