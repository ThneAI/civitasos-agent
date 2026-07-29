"""Generate the outcome-sensitive J1-D execution authorization preflight."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any

from benchmarks.j1.controlled_comparison import canonical_sha256, write_private_json
from benchmarks.j1.qualification_outcome_sensitive_execution_materials import (
    build_material_bindings,
)
from benchmarks.j1.qualification_outcome_sensitive_execution_preflight import (
    build_execution_plan,
    build_preflight,
)
from benchmarks.j1_qualification_runtime_inventory_v4 import activation_inventory


DOMAIN_SOURCE = (
    Path(__file__).parent
    / "j1"
    / "qualification_outcome_sensitive_execution_preflight.py"
)
OPERATION_SOURCE = Path(__file__)
CONTRACT_SOURCE_NAMES = {
    "activation",
    "activation_gate",
    "assignment",
    "consent_gate",
    "evaluator",
    "mentor_advice_gate",
    "protocol",
    "provider_admission_gate",
    "provider_admission_receipt",
    "roster",
    "signed_advice_manifest",
    "statistical_plan",
    "task_fixture",
}


def generate_preflight(
    *,
    run_id: str,
    created_at: str,
    frozen_stack_path: Path,
    promotion_gate_path: Path,
    task_fixture_path: Path,
    signed_advice_root: Path,
    participant_profiles_root: Path,
    repository_root: Path,
    output_root: Path,
    execution_root: Path,
    authorization_output_root: Path,
    authorization_claim_path: Path,
    post_run_output_root: Path,
) -> dict[str, Any]:
    if output_root.exists():
        raise FileExistsError(
            f"outcome-sensitive execution preflight output exists: {output_root}"
        )
    frozen = _read(frozen_stack_path)
    promotion_gate = _read(promotion_gate_path)
    _self_hash(frozen, "frozen_stack_sha256")
    _self_hash(promotion_gate, "report_sha256")
    if not (
        frozen.get("status") == "operator_reviewed_frozen"
        and promotion_gate.get("passed") is True
        and promotion_gate.get("frozen_stack", {}).get("canonical_sha256")
        == frozen["frozen_stack_sha256"]
        and frozen.get("readiness", {}).get("execution_preflight_allowed") is True
        and frozen.get("readiness", {}).get("execution_authorization_issued")
        is False
    ):
        raise ValueError(
            "outcome-sensitive promoted stack is not preflight eligible"
        )
    contract_ref = frozen["frozen_artifacts"]["execution_contract"]
    contract_path = Path(contract_ref["path"])
    contract = _read(contract_path)
    _self_hash(contract, "contract_sha256")
    if (
        contract.get("contract_sha256")
        != frozen["frozen_artifacts"]["execution_contract"][
            "canonical_sha256"
        ]
        or contract.get("scope", {}).get("task_execution_count") != 480
    ):
        raise ValueError("outcome-sensitive frozen execution contract invalid")
    source = contract["source_artifacts"]
    refs = {
        "frozen_execution_stack": _ref(
            frozen_stack_path,
            frozen["frozen_stack_sha256"],
        ),
        "promotion_gate": _ref(
            promotion_gate_path,
            promotion_gate["report_sha256"],
        ),
        "execution_contract": _ref(
            contract_path,
            contract["contract_sha256"],
        ),
        **{name: source[name] for name in CONTRACT_SOURCE_NAMES},
    }
    for name, reference in refs.items():
        _validate_ref(name, reference)
    if task_fixture_path.resolve() != Path(source["task_fixture"]["path"]).resolve():
        raise ValueError("outcome-sensitive task fixture path differs from contract")
    activation = _read(Path(source["activation"]["path"]))
    inventory = activation_inventory(activation)
    expected_inventory = {
        "participant_container_count": 40,
        "created_count": 40,
        "running_count": 0,
    }
    if inventory != expected_inventory:
        raise ValueError(
            "outcome-sensitive execution inventory is not 40 created / 0 running"
        )
    material_bindings = build_material_bindings(
        task_fixture_path=task_fixture_path,
        signed_advice_root=signed_advice_root,
        participant_profiles_root=participant_profiles_root,
    )
    paths = {
        "execution_root": str(execution_root.resolve()),
        "authorization_output_root": str(authorization_output_root.resolve()),
        "authorization_claim_path": str(authorization_claim_path.resolve()),
        "post_run_output_root": str(post_run_output_root.resolve()),
    }
    if len(set(paths.values())) != 4 or any(
        Path(path).exists() for path in paths.values()
    ):
        raise ValueError(
            "outcome-sensitive future execution paths must be distinct and absent"
        )
    plan = build_execution_plan(
        run_id=run_id,
        created_at=created_at,
        source_artifacts=refs,
        frozen_stack_sha256=frozen["frozen_stack_sha256"],
        contract_sha256=contract["contract_sha256"],
        provider_receipt_sha256=source["provider_admission_receipt"][
            "canonical_sha256"
        ],
        evaluator_sha256=source["evaluator"]["canonical_sha256"],
        statistical_plan_sha256=source["statistical_plan"]["canonical_sha256"],
        material_bindings=material_bindings,
        paths=paths,
        implementation=_implementation(repository_root),
    )
    output_root.mkdir(parents=True, mode=0o700)
    output_root.chmod(0o700)
    plan_path = (
        output_root / "outcome-sensitive-execution-plan.review-required.json"
    )
    write_private_json(plan_path, plan)
    preflight = build_preflight(
        plan_path=str(plan_path.resolve()),
        plan_raw_sha256=hashlib.sha256(plan_path.read_bytes()).hexdigest(),
        plan=plan,
        created_at=created_at,
        inventory_snapshot=inventory,
    )
    write_private_json(
        output_root / "outcome-sensitive-execution-preflight.json",
        preflight,
    )
    return preflight


def _validate_ref(name: str, reference: dict[str, str]) -> None:
    path = Path(reference["path"])
    if hashlib.sha256(path.read_bytes()).hexdigest() != reference["sha256"]:
        raise ValueError(
            f"outcome-sensitive preflight source drift: {name}"
        )


def _implementation(root: Path) -> dict[str, str]:
    if _git(root, "status", "--porcelain"):
        raise ValueError(
            "repository must be clean before outcome-sensitive execution preflight"
        )
    revision = _git(root, "rev-parse", "HEAD")
    if subprocess.run(
        ["git", "merge-base", "--is-ancestor", revision, "@{upstream}"],
        cwd=root,
        check=False,
    ).returncode:
        raise ValueError(
            "outcome-sensitive preflight revision is not present upstream"
        )
    return {
        "source_revision": revision,
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
        raise ValueError(
            f"outcome-sensitive preflight source self-hash invalid: {field}"
        )


def _read(path: Path) -> dict[str, Any]:
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
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--created-at", required=True)
    parser.add_argument("--frozen-stack", type=Path, required=True)
    parser.add_argument("--promotion-gate", type=Path, required=True)
    parser.add_argument("--task-fixture", type=Path, required=True)
    parser.add_argument("--signed-advice-root", type=Path, required=True)
    parser.add_argument("--participant-profiles-root", type=Path, required=True)
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--execution-root", type=Path, required=True)
    parser.add_argument("--authorization-output-root", type=Path, required=True)
    parser.add_argument("--authorization-claim-path", type=Path, required=True)
    parser.add_argument("--post-run-output-root", type=Path, required=True)
    args = parser.parse_args()
    datetime.fromisoformat(args.created_at.replace("Z", "+00:00"))
    preflight = generate_preflight(
        run_id=args.run_id,
        created_at=args.created_at,
        frozen_stack_path=args.frozen_stack,
        promotion_gate_path=args.promotion_gate,
        task_fixture_path=args.task_fixture,
        signed_advice_root=args.signed_advice_root,
        participant_profiles_root=args.participant_profiles_root,
        repository_root=args.repository_root,
        output_root=args.output_root,
        execution_root=args.execution_root,
        authorization_output_root=args.authorization_output_root,
        authorization_claim_path=args.authorization_claim_path,
        post_run_output_root=args.post_run_output_root,
    )
    print(json.dumps(preflight, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
