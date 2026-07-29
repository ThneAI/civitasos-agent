"""Generate the offline J1-D outcome-sensitive execution contract."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any

from benchmarks.j1.controlled_comparison import write_private_json
from benchmarks.j1.qualification_outcome_sensitive_execution_contract import (
    SOURCE_NAMES,
    build_execution_contract,
)
from benchmarks.j1.qualification_outcome_sensitive_provider_admission import (
    SOURCE_CANONICAL_FIELDS,
)


DOMAIN_SOURCE = (
    Path(__file__).parent
    / "j1"
    / "qualification_outcome_sensitive_execution_contract.py"
)
OPERATION_SOURCE = Path(__file__)
EXTRA_CANONICAL_FIELDS = {
    "consent_gate": "report_sha256",
    "provider_admission_plan": "plan_sha256",
    "provider_admission_preflight": "preflight_sha256",
    "provider_admission_receipt": "receipt_sha256",
    "provider_admission_gate": "report_sha256",
}


def generate_execution_contract(
    *,
    contract_id: str,
    created_at: str,
    provider_plan_path: Path,
    consent_gate_path: Path,
    provider_preflight_path: Path,
    provider_receipt_path: Path,
    provider_gate_path: Path,
    repository_root: Path,
    output_path: Path,
) -> dict[str, Any]:
    if output_path.exists():
        raise FileExistsError(
            f"outcome-sensitive execution contract output exists: {output_path}"
        )
    provider_plan = _read_object(provider_plan_path)
    source_binding = provider_plan.get("source_binding")
    if (
        not isinstance(source_binding, dict)
        or set(source_binding) != set(SOURCE_CANONICAL_FIELDS)
    ):
        raise ValueError("provider plan source binding is incomplete")
    paths = {
        name: Path(str(reference["path"]))
        for name, reference in source_binding.items()
    }
    paths.update(
        {
            "consent_gate": consent_gate_path,
            "provider_admission_plan": provider_plan_path,
            "provider_admission_preflight": provider_preflight_path,
            "provider_admission_receipt": provider_receipt_path,
            "provider_admission_gate": provider_gate_path,
        }
    )
    if set(paths) != SOURCE_NAMES:
        raise ValueError("outcome-sensitive execution source set is incomplete")
    canonical_fields = {
        **SOURCE_CANONICAL_FIELDS,
        **EXTRA_CANONICAL_FIELDS,
    }
    loaded: dict[str, dict[str, Any]] = {}
    refs: dict[str, dict[str, str]] = {}
    for name in sorted(paths):
        path = paths[name].resolve()
        value = _read_object(path)
        raw_sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
        canonical_sha256 = value.get(canonical_fields[name])
        if not isinstance(canonical_sha256, str):
            raise ValueError(f"{name} canonical digest missing")
        planned_ref = source_binding.get(name)
        if planned_ref is not None and (
            raw_sha256 != planned_ref.get("sha256")
            or canonical_sha256 != planned_ref.get("canonical_sha256")
        ):
            raise ValueError(f"{name} drifted from provider admission plan")
        loaded[name] = value
        refs[name] = {
            "path": str(path),
            "sha256": raw_sha256,
            "canonical_sha256": canonical_sha256,
        }
    contract = build_execution_contract(
        contract_id=contract_id,
        created_at=created_at,
        source_artifacts=refs,
        protocol=loaded["protocol"],
        design=loaded["design"],
        evaluator=loaded["evaluator"],
        task_fixture=loaded["task_fixture"],
        roster=loaded["roster"],
        assignment=loaded["assignment"],
        signed_advice_manifest=loaded["signed_advice_manifest"],
        activation=loaded["activation"],
        provider_admission_receipt=loaded["provider_admission_receipt"],
        provider_admission_gate=loaded["provider_admission_gate"],
        implementation=_implementation(repository_root),
    )
    write_private_json(output_path, contract)
    return contract


def _implementation(repository_root: Path) -> dict[str, str]:
    status = _git(repository_root, "status", "--porcelain")
    if status:
        raise ValueError(
            "repository must be clean before outcome-sensitive contract generation"
        )
    return {
        "source_revision": _git(repository_root, "rev-parse", "HEAD"),
        "domain_source_sha256": hashlib.sha256(DOMAIN_SOURCE.read_bytes()).hexdigest(),
        "operation_source_sha256": hashlib.sha256(
            OPERATION_SOURCE.read_bytes()
        ).hexdigest(),
    }


def _git(root: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", *arguments],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _read_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"JSON artifact must be an object: {path}")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract-id", required=True)
    parser.add_argument("--created-at", required=True)
    parser.add_argument("--provider-plan", type=Path, required=True)
    parser.add_argument("--consent-gate", type=Path, required=True)
    parser.add_argument("--provider-preflight", type=Path, required=True)
    parser.add_argument("--provider-receipt", type=Path, required=True)
    parser.add_argument("--provider-gate", type=Path, required=True)
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    datetime.fromisoformat(args.created_at.replace("Z", "+00:00"))
    contract = generate_execution_contract(
        contract_id=args.contract_id,
        created_at=args.created_at,
        provider_plan_path=args.provider_plan,
        consent_gate_path=args.consent_gate,
        provider_preflight_path=args.provider_preflight,
        provider_receipt_path=args.provider_receipt,
        provider_gate_path=args.provider_gate,
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
