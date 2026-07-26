"""Build a self-hashed J1-D execution source inventory from reviewed artifacts."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from benchmarks.j1.controlled_comparison import canonical_sha256, write_private_json
from benchmarks.j1.qualification_execution_contract_v4 import SOURCE_NAMES
from benchmarks.j1_qualification_execution_contract_v4 import CANONICAL_FIELDS


SCHEMA = "j1-qualification-r4-source-inventory:v2"
REPLACEABLE = {"infrastructure_activation", "infrastructure_activation_gate"}


def build_source_inventory(
    *,
    created_at: str,
    base_inventory_path: Path,
    infrastructure_activation_path: Path,
    infrastructure_activation_gate_path: Path,
) -> dict[str, Any]:
    base, base_raw = _read_object(base_inventory_path)
    sources = base.get("source_artifacts")
    if not isinstance(sources, dict) or set(sources) != SOURCE_NAMES:
        raise ValueError("base source inventory artifact set is invalid")
    replacements = {
        "infrastructure_activation": infrastructure_activation_path,
        "infrastructure_activation_gate": infrastructure_activation_gate_path,
    }
    refs: dict[str, dict[str, str]] = {}
    for name in sorted(SOURCE_NAMES):
        path = replacements.get(name, Path(str(sources[name]["path"]))).resolve()
        value, raw = _read_object(path)
        canonical_field = CANONICAL_FIELDS.get(name)
        canonical = (
            value.get(canonical_field) if canonical_field else canonical_sha256(value)
        )
        if not _sha256(canonical):
            raise ValueError(f"{name} canonical hash is invalid")
        ref = {
            "path": str(path),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "canonical_sha256": str(canonical),
        }
        if name not in REPLACEABLE and ref != sources[name]:
            raise ValueError(f"immutable source artifact drifted: {name}")
        refs[name] = ref
    value = {
        "schema_version": SCHEMA,
        "created_at": created_at,
        "base_inventory": {
            "path": str(base_inventory_path.resolve()),
            "sha256": hashlib.sha256(base_raw).hexdigest(),
            "source_artifact_set_sha256": canonical_sha256(sources),
        },
        "replacements": {
            name: {
                "prior": copy.deepcopy(sources[name]),
                "current": copy.deepcopy(refs[name]),
            }
            for name in sorted(REPLACEABLE)
        },
        "source_artifacts": refs,
        "execution_boundary": {
            "source_inventory_generation_only": True,
            "container_mutation_performed": False,
            "participant_container_started": False,
            "provider_credential_read": False,
            "provider_api_call_performed": False,
            "model_invocation_performed": False,
            "agent_execution_performed": False,
            "backend_fact_append_performed": False,
            "ledger_append_performed": False,
            "execution_authorization_issued_or_consumed": False,
        },
    }
    value["source_inventory_sha256"] = canonical_sha256(value)
    return value


def validate_source_inventory(
    value: Any,
    *,
    base_inventory: dict[str, Any],
) -> list[str]:
    inventory = value if isinstance(value, dict) else {}
    failures: list[str] = []
    body = {
        key: item for key, item in inventory.items() if key != "source_inventory_sha256"
    }
    sources = inventory.get("source_artifacts", {})
    base_sources = base_inventory.get("source_artifacts", {})
    if not (
        inventory.get("schema_version") == SCHEMA
        and set(sources) == SOURCE_NAMES
        and inventory.get("source_inventory_sha256") == canonical_sha256(body)
    ):
        failures.append("source_inventory_identity_invalid")
    if any(
        sources.get(name) != base_sources.get(name)
        for name in SOURCE_NAMES - REPLACEABLE
    ):
        failures.append("source_inventory_immutable_source_drifted")
    replacements = inventory.get("replacements", {})
    if not (
        set(replacements) == REPLACEABLE
        and all(
            replacements[name].get("prior") == base_sources.get(name)
            and replacements[name].get("current") == sources.get(name)
            for name in REPLACEABLE
        )
    ):
        failures.append("source_inventory_replacement_binding_invalid")
    return failures


def _read_object(path: Path) -> tuple[dict[str, Any], bytes]:
    resolved = path.resolve()
    if not resolved.is_file():
        raise ValueError(f"source inventory artifact is not a file: {resolved}")
    raw = resolved.read_bytes()
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError(f"source inventory artifact must be an object: {resolved}")
    return value, raw


def _sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(char in "0123456789abcdef" for char in value.lower())
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--created-at")
    parser.add_argument("--base-inventory", type=Path, required=True)
    parser.add_argument("--infrastructure-activation", type=Path, required=True)
    parser.add_argument("--infrastructure-activation-gate", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError(f"source inventory output exists: {args.output}")
    base, _ = _read_object(args.base_inventory)
    inventory = build_source_inventory(
        created_at=args.created_at or datetime.now(UTC).isoformat(),
        base_inventory_path=args.base_inventory,
        infrastructure_activation_path=args.infrastructure_activation,
        infrastructure_activation_gate_path=args.infrastructure_activation_gate,
    )
    failures = validate_source_inventory(inventory, base_inventory=base)
    if failures:
        raise ValueError(f"source inventory invalid: {failures}")
    args.output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    args.output.parent.chmod(0o700)
    write_private_json(args.output, inventory)
    print(
        json.dumps(
            {
                "output": str(args.output.resolve()),
                "source_inventory_sha256": inventory["source_inventory_sha256"],
                "source_count": len(inventory["source_artifacts"]),
                "replacements": sorted(inventory["replacements"]),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
