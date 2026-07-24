"""Generate the offline J1-D r4 execution contract candidate."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any

from benchmarks.j1.controlled_comparison import canonical_sha256, write_private_json
from benchmarks.j1.qualification_execution_contract_v4 import (
    SOURCE_NAMES,
    build_execution_contract,
)


DOMAIN_SOURCE = Path(__file__).parent / "j1" / "qualification_execution_contract_v4.py"
OPERATION_SOURCE = Path(__file__)
CANONICAL_FIELDS = {
    "amended_protocol": "amended_protocol_sha256",
    "amended_design": "amended_design_sha256",
    "reviewed_verifier": "manifest_sha256",
    "rebound_roster": "reviewed_rebound_roster_sha256",
    "rebound_assignment": "reviewed_rebound_assignment_sha256",
    "signed_advice_manifest": "manifest_sha256",
    "reviewed_infrastructure": "reviewed_infrastructure_rebind_sha256",
    "infrastructure_promotion_gate": "report_sha256",
    "infrastructure_activation": "activation_sha256",
    "infrastructure_activation_gate": "report_sha256",
    "frozen_real_evaluator": "manifest_sha256",
    "frozen_post_run_contract": "contract_sha256",
    "frozen_operator_closeout_contract": "contract_sha256",
    "frozen_evaluation_closeout_bundle": "frozen_bundle_sha256",
    "evaluation_closeout_promotion_gate": "report_sha256",
}


def generate_execution_contract(
    *,
    contract_id: str,
    created_at: str,
    source_inventory_path: Path,
    repository_root: Path,
    output_path: Path,
) -> dict[str, Any]:
    if output_path.exists():
        raise FileExistsError(f"r4 execution contract output exists: {output_path}")
    inventory = _read_object(source_inventory_path)
    raw_sources = inventory.get("source_artifacts")
    if not isinstance(raw_sources, dict) or not SOURCE_NAMES <= set(raw_sources):
        raise ValueError("source inventory does not contain the frozen r4 source set")
    loaded: dict[str, dict[str, Any]] = {}
    refs: dict[str, dict[str, str]] = {}
    for name in sorted(SOURCE_NAMES):
        source = raw_sources[name]
        path = Path(str(source["path"])).resolve()
        value = _read_object(path)
        raw_sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
        canonical_field = CANONICAL_FIELDS.get(name)
        canonical_digest = (
            value.get(canonical_field) if canonical_field else canonical_sha256(value)
        )
        if raw_sha256 != source.get("sha256"):
            raise ValueError(f"{name} raw artifact hash mismatch")
        if canonical_digest != source.get("canonical_sha256"):
            raise ValueError(f"{name} canonical artifact hash mismatch")
        loaded[name] = value
        refs[name] = {
            "path": str(path),
            "sha256": raw_sha256,
            "canonical_sha256": str(canonical_digest),
        }
    contract = build_execution_contract(
        contract_id=contract_id,
        created_at=created_at,
        source_artifacts=refs,
        amended_design=loaded["amended_design"],
        rebound_roster=loaded["rebound_roster"],
        rebound_assignment=loaded["rebound_assignment"],
        signed_advice_manifest=loaded["signed_advice_manifest"],
        infrastructure_activation=loaded["infrastructure_activation"],
        implementation=_implementation(repository_root),
    )
    write_private_json(output_path, contract)
    return contract


def _implementation(repository_root: Path) -> dict[str, str]:
    status = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=repository_root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    if status.strip():
        raise ValueError("repository must be clean before r4 contract generation")
    revision = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repository_root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    return {
        "source_revision": revision,
        "domain_source_sha256": hashlib.sha256(DOMAIN_SOURCE.read_bytes()).hexdigest(),
        "operation_source_sha256": hashlib.sha256(
            OPERATION_SOURCE.read_bytes()
        ).hexdigest(),
    }


def _read_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"JSON artifact must be an object: {path}")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract-id", required=True)
    parser.add_argument("--created-at", required=True)
    parser.add_argument("--source-inventory", type=Path, required=True)
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    datetime.fromisoformat(args.created_at.replace("Z", "+00:00"))
    contract = generate_execution_contract(
        contract_id=args.contract_id,
        created_at=args.created_at,
        source_inventory_path=args.source_inventory,
        repository_root=args.repository_root,
        output_path=args.output,
    )
    print(
        json.dumps(
            {
                "output": str(args.output.resolve()),
                "contract_sha256": contract["contract_sha256"],
                "status": contract["status"],
                "task_execution_count": len(contract["task_executions"]),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
