"""Shared Beta preview evidence boundaries and artifact helpers."""

from __future__ import annotations

from pathlib import Path
from typing import Any

try:
    from beta_evidence import artifact_ref_or_path, sha256_file, write_json as write_json
except ModuleNotFoundError:
    from scripts.beta_evidence import artifact_ref_or_path, sha256_file, write_json as write_json


def boundary() -> dict[str, bool]:
    return {
        "l1_beta_controlled_preview_only": True,
        "merge_allowed": False,
        "deploy_allowed": False,
        "production_deploy_allowed": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
        "h3_production_readiness_claimed": False,
    }


def h3_boundary() -> dict[str, bool]:
    return {"h3_remains_blocked": True, "h3_production_readiness_claimed": False}


def validate_boundary(value: Any, failures: list[str], label: str) -> None:
    if not isinstance(value, dict):
        failures.append(f"{label} must be an object")
        return
    expected = boundary()
    for key, expected_value in expected.items():
        if value.get(key) is not expected_value:
            failures.append(f"{label}.{key} must be {str(expected_value).lower()}")


def validate_h3(value: Any, failures: list[str], label: str) -> None:
    if not isinstance(value, dict):
        failures.append(f"{label} must be an object")
        return
    if value.get("h3_remains_blocked") is not True:
        failures.append(f"{label}.h3_remains_blocked must be true")
    if value.get("h3_production_readiness_claimed") is not False:
        failures.append(f"{label}.h3_production_readiness_claimed must be false")


def expect_h3_blocked(payload: dict[str, Any], failures: list[str], label: str) -> None:
    boundary_value = payload.get("h3_boundary") if isinstance(payload.get("h3_boundary"), dict) else {}
    if boundary_value.get("h3_remains_blocked") is not True:
        failures.append(f"{label}.h3_boundary.h3_remains_blocked must be true")
    if boundary_value.get("h3_production_readiness_claimed") is not False:
        failures.append(f"{label}.h3_boundary.h3_production_readiness_claimed must be false")


def artifact_ref(path: Path) -> dict[str, str | None]:
    return artifact_ref_or_path(path)


def sha256(path: Path) -> str:
    return sha256_file(path)
