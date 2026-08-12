"""Generate a prospective confirmatory J1-D execution preflight."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

from benchmarks.j1.controlled_comparison import canonical_sha256, write_private_json
from benchmarks.j1.qualification_outcome_sensitive_confirmatory_execution_contract import (
    CONTRACT_SCHEMA,
    SOURCE_NAMES as CONTRACT_SOURCE_NAMES,
)
from benchmarks.j1.qualification_outcome_sensitive_confirmatory_execution_preflight import (
    build_confirmatory_execution_plan,
    build_confirmatory_preflight,
    validate_confirmatory_preflight,
)
from benchmarks.j1.qualification_outcome_sensitive_confirmatory_execution_promotion import (
    FROZEN_SCHEMA,
    validate_confirmatory_frozen_stack,
)
from benchmarks.j1.qualification_outcome_sensitive_execution_materials import (
    build_material_bindings,
    replay_material_bindings,
)
from benchmarks.j1_qualification_runtime_inventory_v4 import activation_inventory


DOMAIN_SOURCE = (
    Path(__file__).parent
    / "j1"
    / "qualification_outcome_sensitive_confirmatory_execution_preflight.py"
)
OPERATION_SOURCE = Path(__file__)


def generate_confirmatory_preflight(
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
        raise FileExistsError(f"confirmatory preflight output exists: {output_root}")
    frozen = _read_private(frozen_stack_path)
    promotion_gate = _read_private(promotion_gate_path)
    frozen_failures = validate_confirmatory_frozen_stack(frozen)
    _self_hash(promotion_gate, "report_sha256")
    if frozen_failures:
        raise ValueError(f"confirmatory frozen stack invalid: {frozen_failures}")
    if not (
        frozen.get("schema_version") == FROZEN_SCHEMA
        and promotion_gate.get("passed") is True
        and promotion_gate.get("state")
        == "confirmatory_execution_stack_frozen_new_execution_preflight_required"
        and promotion_gate.get("frozen_stack", {}).get("canonical_sha256")
        == frozen["frozen_stack_sha256"]
        and promotion_gate.get("next_blocker")
        == "new_confirmatory_single_use_execution_preflight_required"
        and frozen.get("readiness", {}).get("execution_preflight_allowed") is True
        and frozen.get("readiness", {}).get("execution_authorization_issued") is False
    ):
        raise ValueError("confirmatory promoted stack is not preflight eligible")

    contract_ref = frozen["frozen_artifacts"]["execution_contract"]
    contract_path = Path(contract_ref["path"])
    contract = _read_private(contract_path)
    _self_hash(contract, "contract_sha256")
    if not (
        contract.get("schema_version") == CONTRACT_SCHEMA
        and contract.get("contract_sha256") == contract_ref["canonical_sha256"]
        and contract.get("scope", {}).get("task_execution_count") == 480
        and contract.get("confirmatory_method_binding")
        == frozen.get("confirmatory_method_binding")
    ):
        raise ValueError("confirmatory frozen execution contract invalid")
    source = contract.get("source_artifacts", {})
    if set(source) != CONTRACT_SOURCE_NAMES:
        raise ValueError("confirmatory contract source inventory invalid")
    refs = {
        "frozen_execution_stack": _ref(
            frozen_stack_path, frozen["frozen_stack_sha256"]
        ),
        "execution_promotion_gate": _ref(
            promotion_gate_path, promotion_gate["report_sha256"]
        ),
        "execution_contract": _ref(contract_path, contract["contract_sha256"]),
        **source,
    }
    for name, reference in refs.items():
        _validate_ref(name, reference)
    if task_fixture_path.resolve() != Path(source["task_fixture"]["path"]).resolve():
        raise ValueError("confirmatory task fixture path differs from contract")

    activation = _read_private(Path(source["activation"]["path"]))
    inventory = activation_inventory(activation)
    if inventory != {
        "participant_container_count": 40,
        "created_count": 40,
        "running_count": 0,
    }:
        raise ValueError(
            "confirmatory execution inventory is not 40 created / 0 running"
        )
    material_bindings = build_material_bindings(
        task_fixture_path=task_fixture_path,
        signed_advice_root=signed_advice_root,
        participant_profiles_root=participant_profiles_root,
    )
    replay_material_bindings(material_bindings)
    if not (
        material_bindings["signed_advice"]["file_count"] == 180
        and material_bindings["participant_profiles"]["file_count"] == 40
        and signed_advice_root.resolve()
        == Path(source["signed_advice_manifest"]["path"]).resolve().parent / "signed"
    ):
        raise ValueError("confirmatory private execution materials invalid")

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
            "confirmatory future execution paths must be distinct and absent"
        )
    implementation = _implementation(repository_root)
    method = contract["confirmatory_method_binding"]
    plan = build_confirmatory_execution_plan(
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
        confirmatory_method_binding=method,
        execution_promotion_gate_sha256=promotion_gate["report_sha256"],
        material_bindings=material_bindings,
        paths=paths,
        implementation=implementation,
    )

    output_root.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    output_root.parent.chmod(0o700)
    temporary = output_root.with_name(
        f".{output_root.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp"
    )
    temporary.mkdir(mode=0o700)
    try:
        plan_path = temporary / "confirmatory-execution-plan.review-required.json"
        write_private_json(plan_path, plan)
        published_plan_path = output_root / plan_path.name
        preflight = build_confirmatory_preflight(
            plan_path=str(published_plan_path.resolve()),
            plan_raw_sha256=hashlib.sha256(plan_path.read_bytes()).hexdigest(),
            plan=plan,
            created_at=created_at,
            inventory_snapshot=inventory,
        )
        failures = validate_confirmatory_preflight(
            preflight,
            expected_plan=plan,
            expected_plan_raw_sha256=hashlib.sha256(plan_path.read_bytes()).hexdigest(),
        )
        if failures:
            raise ValueError(f"confirmatory execution preflight invalid: {failures}")
        write_private_json(
            temporary / "confirmatory-execution-preflight.json", preflight
        )
        os.replace(temporary, output_root)
        _fsync_directory(output_root.parent)
        return preflight
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


def _validate_ref(name: str, reference: dict[str, str]) -> None:
    path = Path(reference["path"])
    if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o077:
        raise ValueError(f"confirmatory preflight source is not private: {name}")
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != reference["sha256"]:
        raise ValueError(f"confirmatory preflight source drift: {name}")
    if path.suffix == ".json":
        value = json.loads(raw)
        canonical_field = next(
            (
                field
                for field in (
                    "report_sha256",
                    "receipt_sha256",
                    "activation_sha256",
                    "assignment_sha256",
                    "roster_sha256",
                    "manifest_sha256",
                    "method_sha256",
                    "protocol_sha256",
                    "design_sha256",
                    "evaluator_sha256",
                    "plan_sha256",
                    "preflight_sha256",
                    "frozen_review_sha256",
                )
                if field in value
            ),
            None,
        )
        if canonical_field and value[canonical_field] != reference["canonical_sha256"]:
            raise ValueError(f"confirmatory preflight canonical drift: {name}")


def _implementation(root: Path) -> dict[str, str]:
    if _git(root, "status", "--porcelain"):
        raise ValueError("repository must be clean before confirmatory preflight")
    revision = _git(root, "rev-parse", "HEAD")
    if subprocess.run(
        ["git", "merge-base", "--is-ancestor", revision, "@{upstream}"],
        cwd=root,
        check=False,
    ).returncode:
        raise ValueError("confirmatory preflight revision is not present upstream")
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
        raise ValueError(f"confirmatory preflight source self-hash invalid: {field}")


def _read_private(path: Path) -> dict[str, Any]:
    resolved = path.resolve()
    if path.is_symlink() or not resolved.is_file() or resolved.stat().st_mode & 0o077:
        raise ValueError(f"confirmatory source is not private: {resolved}")
    value = json.loads(resolved.read_bytes())
    if not isinstance(value, dict):
        raise ValueError(f"JSON artifact must contain an object: {resolved}")
    return value


def _git(root: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", *arguments],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


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
    preflight = generate_confirmatory_preflight(
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
