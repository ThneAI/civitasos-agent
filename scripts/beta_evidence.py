"""Shared artifact evidence primitives for Beta and Beta-FE scripts."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


def read_json_or_empty(path: Path | None, failures: list[str], label: str) -> dict[str, Any]:
    if path is None or not path.is_file():
        failures.append(f"missing {label}: {path}")
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        failures.append(f"invalid {label}: {exc}")
        return {}
    if not isinstance(value, dict):
        failures.append(f"{label} must be a JSON object")
        return {}
    return value


def read_json_any_or_empty(path: Path, failures: list[str], label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        failures.append(f"{label} not found: {path}")
    except json.JSONDecodeError as exc:
        failures.append(f"{label} is not valid JSON: {exc}")
    return {}


def read_json_object(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"JSON object required: {path}")
    return payload


def safe_read_json_object(path: Path | None, failures: list[str], label: str) -> dict[str, Any] | None:
    if path is None:
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 - validation needs artifact reason.
        failures.append(f"{label} could not be read: {exc}")
        return None
    if not isinstance(payload, dict):
        failures.append(f"{label} must be a JSON object")
        return None
    return payload


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def artifact_ref(path: Path) -> dict[str, str]:
    if not path.is_file():
        raise FileNotFoundError(f"artifact path is not a file: {path}")
    return {"path": str(path.resolve()), "sha256": sha256_file(path)}


def artifact_ref_or_path(path: Path) -> dict[str, str | None]:
    return {
        "path": str(path.resolve()),
        "sha256": sha256_file(path) if path.is_file() else None,
    }


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_ref(value: Any, failures: list[str], label: str) -> Path | None:
    if not isinstance(value, dict):
        failures.append(f"{label} must be an object ref")
        return None
    path = Path(str(value.get("path") or ""))
    expected = str(value.get("sha256") or "")
    if not path.is_file():
        failures.append(f"{label}.path does not exist: {path}")
        return None
    if expected and sha256_file(path) != expected:
        failures.append(f"{label}.sha256 does not match file content")
    return path


def validate_ref_bytes(value: Any, failures: list[str], label: str) -> Path | None:
    if not isinstance(value, dict):
        failures.append(f"{label} must be an object")
        return None
    path_text = str(value.get("path") or "").strip()
    if not path_text:
        failures.append(f"{label}.path must be a non-empty string")
        return None
    path = Path(path_text)
    if not path.is_file():
        failures.append(f"{label}.path is not a file: {path}")
        return None
    if value.get("sha256") != sha256_file(path):
        failures.append(f"{label}.sha256 does not match file bytes")
    return path
