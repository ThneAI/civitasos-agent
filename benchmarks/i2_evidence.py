"""Shared I.2 evidence helpers.

I.2 gates should keep orchestration, provider calls, and evidence formatting
separate. This module intentionally contains only deterministic local helpers:
JSON object IO, artifact references, and boundary predicates.
"""

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
    return {"path": str(path.resolve()), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


def object_value(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def write_boundaries_closed(boundary: dict[str, Any]) -> bool:
    return (
        boundary.get("real_task_command_allowed") is False
        and boundary.get("source_tree_write_allowed") is False
        and boundary.get("git_write_allowed") is False
        and boundary.get("runtime_state_mutation_allowed") is False
        and boundary.get("deploy_allowed") is False
    )
