"""Generate the offline J1-D r4 provider-admission authorization preflight."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any

from benchmarks.j1.controlled_comparison import canonical_sha256, write_private_json
from benchmarks.j1.qualification_provider_admission_v4 import (
    build_admission_plan,
    build_preflight,
)
from benchmarks.j1_qualification_runtime_inventory_v4 import activation_inventory


DOMAIN_SOURCE = Path(__file__).parent / "j1" / "qualification_provider_admission_v4.py"
OPERATION_SOURCE = Path(__file__)


def generate_preflight(
    *,
    admission_id: str,
    created_at: str,
    frozen_stack_path: Path,
    promotion_gate_path: Path,
    repository_root: Path,
    output_root: Path,
) -> dict[str, Any]:
    if output_root.exists():
        raise FileExistsError(f"r4 provider preflight output exists: {output_root}")
    frozen = _read_object(frozen_stack_path)
    gate = _read_object(promotion_gate_path)
    _self_hash(frozen, "frozen_stack_sha256")
    _self_hash(gate, "report_sha256")
    if not (
        frozen.get("status") == "operator_reviewed_frozen"
        and gate.get("passed") is True
        and gate.get("frozen_stack", {}).get("canonical_sha256")
        == frozen.get("frozen_stack_sha256")
    ):
        raise ValueError("r4 frozen stack promotion binding invalid")
    contract_ref = frozen["frozen_artifacts"]["execution_contract"]
    contract_path = Path(contract_ref["path"])
    contract = _read_object(contract_path)
    _self_hash(contract, "contract_sha256")
    if (
        hashlib.sha256(contract_path.read_bytes()).hexdigest() != contract_ref["sha256"]
        or contract["contract_sha256"] != contract_ref["canonical_sha256"]
    ):
        raise ValueError("r4 frozen execution contract binding invalid")
    source_refs = contract["source_artifacts"]
    protocol_path = Path(source_refs["amended_protocol"]["path"])
    design_path = Path(source_refs["amended_design"]["path"])
    activation_path = Path(source_refs["infrastructure_activation"]["path"])
    protocol = _read_object(protocol_path)
    design = _read_object(design_path)
    activation = _read_object(activation_path)
    _validate_source(protocol_path, protocol, source_refs["amended_protocol"])
    _validate_source(design_path, design, source_refs["amended_design"])
    _validate_source(activation_path, activation, source_refs["infrastructure_activation"])
    inventory = activation_inventory(activation)
    implementation = _implementation(repository_root)
    refs = {
        "frozen_r4_stack": _ref(frozen_stack_path, frozen["frozen_stack_sha256"]),
        "r4_promotion_gate": _ref(promotion_gate_path, gate["report_sha256"]),
        "execution_contract": _ref(contract_path, contract["contract_sha256"]),
        "amended_protocol": source_refs["amended_protocol"],
        "amended_design": source_refs["amended_design"],
        "infrastructure_activation": source_refs["infrastructure_activation"],
    }
    plan = build_admission_plan(
        admission_id=admission_id,
        created_at=created_at,
        source_artifacts=refs,
        frozen_stack=frozen,
        design=design,
        inventory_snapshot=inventory,
        implementation=implementation,
    )
    output_root.mkdir(parents=True, mode=0o700)
    output_root.chmod(0o700)
    plan_path = output_root / "r4-provider-admission-plan.review-required.json"
    write_private_json(plan_path, plan)
    preflight = build_preflight(
        plan_path=str(plan_path.resolve()),
        plan_raw_sha256=hashlib.sha256(plan_path.read_bytes()).hexdigest(),
        plan=plan,
        created_at=created_at,
    )
    write_private_json(output_root / "r4-provider-admission-preflight.json", preflight)
    return preflight


def _validate_source(
    path: Path, value: dict[str, Any], reference: dict[str, str]
) -> None:
    if hashlib.sha256(path.read_bytes()).hexdigest() != reference["sha256"]:
        raise ValueError(f"r4 provider source raw hash mismatch: {path}")
    canonical_fields = [
        name for name in value if name.endswith("_sha256") and name != "source_sha256"
    ]
    if reference["canonical_sha256"] not in {
        str(value.get(name)) for name in canonical_fields
    }:
        raise ValueError(f"r4 provider source canonical hash mismatch: {path}")


def _implementation(root: Path) -> dict[str, str]:
    if _git(root, "status", "--porcelain"):
        raise ValueError("repository must be clean before r4 provider preflight")
    return {
        "source_revision": _git(root, "rev-parse", "HEAD"),
        "domain_source_sha256": hashlib.sha256(DOMAIN_SOURCE.read_bytes()).hexdigest(),
        "operation_source_sha256": hashlib.sha256(
            OPERATION_SOURCE.read_bytes()
        ).hexdigest(),
    }


def _ref(path: Path, canonical_digest: str) -> dict[str, str]:
    return {
        "path": str(path.resolve()),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "canonical_sha256": canonical_digest,
    }


def _self_hash(value: dict[str, Any], field: str) -> None:
    body = {key: item for key, item in value.items() if key != field}
    if value.get(field) != canonical_sha256(body):
        raise ValueError(f"r4 provider source self-hash invalid: {field}")


def _read_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"JSON artifact must contain an object: {path}")
    return value


def _git(root: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", *arguments],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--admission-id", required=True)
    parser.add_argument("--created-at", required=True)
    parser.add_argument("--frozen-stack", type=Path, required=True)
    parser.add_argument("--promotion-gate", type=Path, required=True)
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    datetime.fromisoformat(args.created_at.replace("Z", "+00:00"))
    preflight = generate_preflight(
        admission_id=args.admission_id,
        created_at=args.created_at,
        frozen_stack_path=args.frozen_stack,
        promotion_gate_path=args.promotion_gate,
        repository_root=args.repository_root,
        output_root=args.output_root,
    )
    print(json.dumps(preflight, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
