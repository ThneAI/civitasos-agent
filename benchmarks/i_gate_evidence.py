"""Shared evidence primitives for I-series gates."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


def read_json_object(path: Path) -> dict[str, Any]:
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


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def sha256_json(value: Any) -> str:
    return sha256_text(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")))


def object_value(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def objects_value(value: Any) -> list[dict[str, Any]]:
    return [item for item in value] if isinstance(value, list) and all(isinstance(item, dict) for item in value) else []


def check(checks: dict[str, bool], failures: list[str], name: str, passed: bool) -> None:
    checks[name] = bool(passed)
    if not passed:
        failures.append(name)


def all_checks_passed(checks: dict[str, bool], failures: list[str]) -> bool:
    return bool(checks) and all(checks.values()) and not failures


def write_boundaries_closed(boundary: dict[str, Any]) -> bool:
    return (
        boundary.get("real_task_command_allowed") is False
        and boundary.get("source_tree_write_allowed") is False
        and boundary.get("git_write_allowed") is False
        and boundary.get("runtime_state_mutation_allowed") is False
        and boundary.get("deploy_allowed") is False
    )
