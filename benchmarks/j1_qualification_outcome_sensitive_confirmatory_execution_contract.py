"""Generate the offline J1-D prospective confirmatory execution contract."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any

from benchmarks.j1.controlled_comparison import canonical_sha256, write_private_json
from benchmarks.j1.qualification_outcome_sensitive_confirmatory_execution_contract import (
    SOURCE_NAMES,
    build_confirmatory_execution_contract,
)
from benchmarks.j1.qualification_outcome_sensitive_confirmatory_provider_admission import (
    validate_plan,
    validate_probe_sources,
)
from benchmarks.j1.qualification_provider_admission_probe import (
    validate_probe_receipt,
)
from benchmarks.j1_qualification_outcome_sensitive_confirmatory_provider_admission import (
    replay_source_binding,
)


DOMAIN_SOURCE = (
    Path(__file__).parent
    / "j1"
    / "qualification_outcome_sensitive_confirmatory_execution_contract.py"
)
OPERATION_SOURCE = Path(__file__)
PROVIDER_CANONICAL_FIELDS = {
    "provider_admission_plan": "plan_sha256",
    "provider_admission_preflight": "preflight_sha256",
    "provider_admission_receipt": "receipt_sha256",
    "provider_admission_gate": "report_sha256",
}


def generate_confirmatory_execution_contract(
    *,
    contract_id: str,
    created_at: str,
    provider_plan_path: Path,
    provider_preflight_path: Path,
    provider_receipt_path: Path,
    provider_gate_path: Path,
    repository_root: Path,
    output_path: Path,
) -> dict[str, Any]:
    if output_path.exists():
        raise FileExistsError(f"confirmatory execution output exists: {output_path}")
    provider_plan = _read_object(provider_plan_path)
    provider_preflight = _read_object(provider_preflight_path)
    provider_receipt = _read_object(provider_receipt_path)
    provider_gate = _read_object(provider_gate_path)
    _validate_provider_admission(
        plan_path=provider_plan_path,
        preflight_path=provider_preflight_path,
        receipt_path=provider_receipt_path,
        gate_path=provider_gate_path,
        plan=provider_plan,
        preflight=provider_preflight,
        receipt=provider_receipt,
        gate=provider_gate,
    )
    values = replay_source_binding(provider_plan)
    source_binding = provider_plan["source_binding"]
    references = {
        name: {
            "path": str(Path(str(reference["path"])).resolve()),
            "sha256": reference["sha256"],
            "canonical_sha256": reference["canonical_sha256"],
        }
        for name, reference in source_binding.items()
    }
    provider_values = {
        "provider_admission_plan": (provider_plan_path, provider_plan),
        "provider_admission_preflight": (
            provider_preflight_path,
            provider_preflight,
        ),
        "provider_admission_receipt": (provider_receipt_path, provider_receipt),
        "provider_admission_gate": (provider_gate_path, provider_gate),
    }
    for name, (path, value) in provider_values.items():
        references[name] = _ref(
            path,
            str(value[PROVIDER_CANONICAL_FIELDS[name]]),
        )
    if set(references) != SOURCE_NAMES:
        raise ValueError("confirmatory execution source set is incomplete")
    contract = build_confirmatory_execution_contract(
        contract_id=contract_id,
        created_at=created_at,
        source_artifacts=references,
        protocol=values["protocol"],
        design=values["design"],
        evaluator=values["evaluator"],
        task_fixture=values["task_fixture"],
        roster=values["roster"],
        assignment=values["assignment"],
        signed_advice_manifest=values["signed_advice_manifest"],
        activation=values["activation"],
        provider_admission_receipt=provider_receipt,
        provider_admission_gate=provider_gate,
        confirmatory_method=values["confirmatory_method"],
        confirmatory_promotion_gate=values["confirmatory_promotion_gate"],
        consent_gate=values["consent_gate"],
        roster_assignment_gate=values["roster_assignment_gate"],
        mentor_advice_gate=values["mentor_advice_gate"],
        activation_gate=values["activation_gate"],
        implementation=_implementation(repository_root),
    )
    write_private_json(output_path, contract)
    return contract


def _validate_provider_admission(
    *,
    plan_path: Path,
    preflight_path: Path,
    receipt_path: Path,
    gate_path: Path,
    plan: dict[str, Any],
    preflight: dict[str, Any],
    receipt: dict[str, Any],
    gate: dict[str, Any],
) -> None:
    authorization = preflight.get("owner_authorization", {})
    statement = authorization.get("statement")
    statement_sha256 = authorization.get("statement_sha256")
    failures = validate_plan(plan)
    failures.extend(
        validate_probe_sources(
            plan=plan,
            plan_raw_sha256=_raw_sha256(plan_path),
            preflight=preflight,
            authorization_statement=statement,
        )
    )
    failures.extend(
        validate_probe_receipt(
            receipt,
            plan=plan,
            expected_authorization_sha256=statement_sha256,
        )
    )
    gate_body = {key: value for key, value in gate.items() if key != "report_sha256"}
    if (
        gate.get("passed") is not True
        or gate.get("state")
        != "live_provider_admission_refreshed_execution_still_blocked"
        or gate.get("report_sha256") != canonical_sha256(gate_body)
        or gate.get("authorization", {}).get("statement_sha256") != statement_sha256
        or gate.get("authorization", {}).get("consumed") is not True
        or gate.get("authorization", {}).get("reusable") is not False
        or gate.get("receipt", {}).get("sha256") != _raw_sha256(receipt_path)
        or gate.get("receipt", {}).get("canonical_sha256")
        != receipt.get("receipt_sha256")
        or gate.get("source_binding", {}).get("plan_artifact_sha256")
        != _raw_sha256(plan_path)
        or gate.get("source_binding", {}).get("preflight_artifact_sha256")
        != _raw_sha256(preflight_path)
        or gate.get("report_sha256") != _read_object(gate_path).get("report_sha256")
    ):
        failures.append("confirmatory_execution_provider_gate_invalid")
    if failures:
        raise ValueError(f"confirmatory provider admission invalid: {failures}")


def _implementation(repository_root: Path) -> dict[str, str]:
    if _git(repository_root, "status", "--porcelain"):
        raise ValueError("repository must be clean before contract generation")
    revision = _git(repository_root, "rev-parse", "HEAD")
    if revision != _git(repository_root, "rev-parse", "@{upstream}"):
        raise ValueError("contract generation revision must be pushed")
    return {
        "source_revision": revision,
        "domain_source_sha256": hashlib.sha256(DOMAIN_SOURCE.read_bytes()).hexdigest(),
        "operation_source_sha256": hashlib.sha256(
            OPERATION_SOURCE.read_bytes()
        ).hexdigest(),
    }


def _ref(path: Path, canonical_digest: str) -> dict[str, str]:
    resolved = path.resolve()
    return {
        "path": str(resolved),
        "sha256": _raw_sha256(resolved),
        "canonical_sha256": canonical_digest,
    }


def _raw_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


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
    parser.add_argument("--provider-preflight", type=Path, required=True)
    parser.add_argument("--provider-receipt", type=Path, required=True)
    parser.add_argument("--provider-gate", type=Path, required=True)
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    datetime.fromisoformat(args.created_at.replace("Z", "+00:00"))
    contract = generate_confirmatory_execution_contract(
        contract_id=args.contract_id,
        created_at=args.created_at,
        provider_plan_path=args.provider_plan,
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
