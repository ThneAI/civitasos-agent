"""Typed JSON helpers for I.1 preparation assets."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def read_json(path: Path, failures: list[str], label: str) -> dict[str, Any]:
    if not path.is_file():
        failures.append(f"{label}_missing")
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        failures.append(f"{label}_invalid_json")
        return {}
    if not isinstance(value, dict):
        failures.append(f"{label}_must_be_object")
        return {}
    return value


def check(
    checks: dict[str, bool],
    failures: list[str],
    name: str,
    passed: bool,
) -> None:
    checks[name] = bool(passed)
    if not passed:
        failures.append(name)


def as_object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def objects(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def strings(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if str(item)]
