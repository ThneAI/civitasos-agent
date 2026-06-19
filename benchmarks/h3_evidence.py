"""Shared evidence primitives for H.3 gates."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


def object_value(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def objects_value(value: Any) -> list[dict[str, Any]]:
    return [item for item in value] if isinstance(value, list) and all(isinstance(item, dict) for item in value) else []


def read_json_object(path: Path, failures: list[str], label: str) -> dict[str, Any] | None:
    if not path.is_file():
        failures.append(f"{label} missing: {path}")
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        failures.append(f"{label} invalid: {exc}")
        return None
    if not isinstance(value, dict):
        failures.append(f"{label} must be an object")
        return None
    return value


def read_required_json_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def write_json_object(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def artifact_ref(path: Path) -> dict[str, str]:
    return {"path": str(path.resolve()), "sha256": sha256_file(path)}


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def resolve_under_root(path: Path, root: Path) -> Path:
    return path.resolve() if path.is_absolute() else (root / path).resolve()
