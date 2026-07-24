"""Preflight and atomically claim one frozen-stack v3 J1-D authorization."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from benchmarks.j1.controlled_comparison import canonical_sha256, write_private_json
from benchmarks.j1.qualification_frozen_execution_claim import (
    build_claim_preflight,
    build_claim_receipt,
    build_execution_entry_gate,
    validate_claim_preflight,
    validate_claim_receipt,
    write_claim_exclusive,
)
from benchmarks.j1_qualification_frozen_execution_preflight import (
    _canonical,
    _inspect_current_inventory,
    _read_private,
    _validate_frozen_stack,
)


DOMAIN_SOURCE = (
    Path(__file__).parent / "j1" / "qualification_frozen_execution_claim.py"
)
OPERATION_SOURCE = Path(__file__)


class AtomicClaimPersistedError(RuntimeError):
    """Raised when a claim exists but post-claim entry validation failed."""

    def __init__(self, claim_path: Path, reason: Exception) -> None:
        self.claim_path = claim_path
        self.reason = reason
        super().__init__(
            f"atomic claim persisted at {claim_path}; execution remains blocked and "
            f"signed closeout is required: {reason}"
        )


def generate_claim_preflight(
    *,
    authorization_path: Path,
    issuance_gate_path: Path,
    reviewer_profile_path: Path,
    output_root: Path,
    repository_root: Path,
) -> dict[str, Any]:
    if output_root.exists():
        raise ValueError(f"claim preflight output exists: {output_root}")
    context = _load_context(
        authorization_path=authorization_path,
        issuance_gate_path=issuance_gate_path,
        reviewer_profile_path=reviewer_profile_path,
        repository_root=repository_root,
        require_clean_repository=True,
    )
    _require_future_paths_absent(context["authorization"])
    output_root.mkdir(parents=True, mode=0o700)
    output_root.chmod(0o700)
    try:
        preflight = build_claim_preflight(
            checked_at=datetime.now(timezone.utc).isoformat(),
            **context["contract_values"],
            inventory_snapshot=context["inventory_snapshot"],
            execution_manifest=context["execution_manifest"],
            implementation=context["claim_implementation"],
        )
        path = output_root / "frozen-stack-claim-preflight.json"
        write_private_json(path, preflight)
        return preflight
    except Exception:
        shutil.rmtree(output_root, ignore_errors=True)
        raise


def claim_and_build_entry_gate(
    *,
    authorization_path: Path,
    issuance_gate_path: Path,
    reviewer_profile_path: Path,
    claim_preflight_path: Path,
    owner_authorization_id: str,
    owner_statement: str,
    owner_statement_sha256: str,
    repository_root: Path,
) -> dict[str, Any]:
    context = _load_context(
        authorization_path=authorization_path,
        issuance_gate_path=issuance_gate_path,
        reviewer_profile_path=reviewer_profile_path,
        repository_root=repository_root,
        require_clean_repository=True,
    )
    _require_future_paths_absent(context["authorization"])
    preflight_artifact = _read_private(claim_preflight_path, "claim_preflight")
    preflight = preflight_artifact["value"]
    failures = validate_claim_preflight(
        preflight,
        **context["contract_values"],
        expected_inventory_snapshot=context["inventory_snapshot"],
        expected_execution_manifest=context["execution_manifest"],
        expected_implementation=context["claim_implementation"],
        current_time=datetime.now(timezone.utc),
        require_current=True,
    )
    if failures:
        raise ValueError(f"claim preflight invalid: {failures}")
    statement = preflight["owner_authorization"]["required_exact_statement"]
    if (
        owner_statement != statement
        or hashlib.sha256(owner_statement.encode()).hexdigest()
        != owner_statement_sha256
        or owner_statement_sha256
        != preflight["owner_authorization"]["statement_sha256"]
    ):
        raise ValueError("claim owner statement/hash mismatch")
    authorization = context["authorization"]
    claim_path = Path(authorization["controls"]["authorization_consumption_path"])
    claim = build_claim_receipt(
        claimed_at=datetime.now(timezone.utc).isoformat(),
        claim_path=str(claim_path),
        owner_authorization_id=owner_authorization_id,
        owner_statement=owner_statement,
        owner_statement_sha256=owner_statement_sha256,
        authorization_path=str(context["authorization_artifact"]["path"]),
        authorization_bytes=context["authorization_artifact"]["raw"],
        authorization=authorization,
        issuance_gate_path=str(context["issuance_gate_artifact"]["path"]),
        issuance_gate_bytes=context["issuance_gate_artifact"]["raw"],
        issuance_gate=context["issuance_gate"],
        claim_preflight_path=str(preflight_artifact["path"]),
        claim_preflight_bytes=preflight_artifact["raw"],
        claim_preflight=preflight,
        implementation=context["claim_implementation"],
    )
    try:
        write_claim_exclusive(claim_path, claim)
        claim_bytes = claim_path.read_bytes()
        claim_failures = validate_claim_receipt(
            claim,
            claim_path=str(claim_path),
            authorization_path=str(context["authorization_artifact"]["path"]),
            authorization_bytes=context["authorization_artifact"]["raw"],
            authorization=authorization,
            issuance_gate_path=str(context["issuance_gate_artifact"]["path"]),
            issuance_gate_bytes=context["issuance_gate_artifact"]["raw"],
            issuance_gate=context["issuance_gate"],
            claim_preflight_path=str(preflight_artifact["path"]),
            claim_preflight_bytes=preflight_artifact["raw"],
            claim_preflight=preflight,
            expected_implementation=context["claim_implementation"],
        )
        if claim_failures:
            raise ValueError(f"post-write claim validation failed: {claim_failures}")
        entry_gate = build_execution_entry_gate(
            checked_at=datetime.now(timezone.utc).isoformat(),
            claim_path=str(claim_path),
            claim_bytes=claim_bytes,
            claim=claim,
            authorization_path=str(context["authorization_artifact"]["path"]),
            authorization_bytes=context["authorization_artifact"]["raw"],
            authorization=authorization,
            issuance_gate_path=str(context["issuance_gate_artifact"]["path"]),
            issuance_gate_bytes=context["issuance_gate_artifact"]["raw"],
            issuance_gate=context["issuance_gate"],
            claim_preflight_path=str(preflight_artifact["path"]),
            claim_preflight_bytes=preflight_artifact["raw"],
            claim_preflight=preflight,
            expected_claim_implementation=context["claim_implementation"],
            current_inventory_snapshot=context["inventory_snapshot"],
            current_execution_manifest=context["execution_manifest"],
            execution_root_exists=Path(
                authorization["controls"]["execution_root"]
            ).exists(),
            post_run_root_exists=Path(
                authorization["controls"]["post_run_output_root"]
            ).exists(),
        )
        gate_path = (
            claim_preflight_path.parent / "frozen-stack-execution-entry-gate.json"
        )
        write_private_json(gate_path, entry_gate)
    except Exception as error:
        if claim_path.exists():
            raise AtomicClaimPersistedError(claim_path, error) from error
        raise
    return {
        "claim": {
            "path": str(claim_path.resolve()),
            "sha256": hashlib.sha256(claim_bytes).hexdigest(),
            "canonical_sha256": claim["claim_sha256"],
        },
        "execution_entry_gate": {
            "path": str(gate_path.resolve()),
            "sha256": hashlib.sha256(gate_path.read_bytes()).hexdigest(),
            "canonical_sha256": entry_gate["report_sha256"],
        },
        "state": entry_gate["state"],
        "execution_started": False,
    }


def _load_context(
    *,
    authorization_path: Path,
    issuance_gate_path: Path,
    reviewer_profile_path: Path,
    repository_root: Path,
    require_clean_repository: bool,
) -> dict[str, Any]:
    authorization_artifact = _read_private(authorization_path, "authorization")
    issuance_gate_artifact = _read_private(issuance_gate_path, "issuance_gate")
    reviewer_artifact = _read_private(reviewer_profile_path, "reviewer_profile")
    authorization = authorization_artifact["value"]
    issuance_gate = issuance_gate_artifact["value"]
    plan_ref = authorization["source_binding"]["plan"]
    frozen_ref = authorization["source_binding"]["preflight"]
    plan_artifact = _read_private(Path(plan_ref["path"]), "plan")
    frozen_artifact = _read_private(Path(frozen_ref["path"]), "frozen_preflight")
    plan = plan_artifact["value"]
    frozen = frozen_artifact["value"]
    if not _json_matches(authorization_artifact["raw"], authorization):
        raise ValueError("authorization object/raw mismatch")
    if not _json_matches(issuance_gate_artifact["raw"], issuance_gate):
        raise ValueError("issuance Gate object/raw mismatch")
    source_artifacts = {
        name: _read_private(Path(ref["path"]), name)
        for name, ref in plan["source_artifacts"].items()
    }
    for name, artifact in source_artifacts.items():
        ref = plan["source_artifacts"][name]
        if (
            artifact["sha256"] != ref["sha256"]
            or _canonical(name, artifact["value"]) != ref["canonical_sha256"]
        ):
            raise ValueError(f"claim source drifted: {name}")
    _validate_frozen_stack(source_artifacts)
    inventory, inventory_failures = _inspect_current_inventory(
        infrastructure=source_artifacts["reviewed_infrastructure"]["value"],
        activation=source_artifacts["infrastructure_activation"]["value"],
    )
    if inventory_failures:
        raise ValueError(f"claim inventory invalid: {inventory_failures}")
    execution_manifest = _inspect_execution_workspace(
        activation=source_artifacts["infrastructure_activation"]["value"],
        authorization=authorization,
        inventory_snapshot=inventory,
    )
    claim_implementation = _implementation(
        repository_root,
        require_clean=require_clean_repository,
    )
    contract_values = {
        "authorization_path": str(authorization_artifact["path"]),
        "authorization_bytes": authorization_artifact["raw"],
        "authorization": authorization,
        "issuance_gate_path": str(issuance_gate_artifact["path"]),
        "issuance_gate_bytes": issuance_gate_artifact["raw"],
        "issuance_gate": issuance_gate,
        "plan_path": str(plan_artifact["path"]),
        "plan_bytes": plan_artifact["raw"],
        "plan": plan,
        "frozen_preflight_path": str(frozen_artifact["path"]),
        "frozen_preflight_bytes": frozen_artifact["raw"],
        "frozen_preflight": frozen,
        "reviewer_profile": reviewer_artifact["value"],
        "reviewer_profile_sha256": reviewer_artifact["sha256"],
        "expected_authorization_implementation": _authorization_implementation(
            authorization
        ),
    }
    return {
        "authorization_artifact": authorization_artifact,
        "issuance_gate_artifact": issuance_gate_artifact,
        "authorization": authorization,
        "issuance_gate": issuance_gate,
        "contract_values": contract_values,
        "inventory_snapshot": inventory,
        "execution_manifest": execution_manifest,
        "claim_implementation": claim_implementation,
    }


def _inspect_execution_workspace(
    *,
    activation: dict[str, Any],
    authorization: dict[str, Any],
    inventory_snapshot: dict[str, Any],
) -> dict[str, Any]:
    workspaces: list[dict[str, str]] = []
    input_file_count = 0
    output_file_count = 0
    symlink_count = 0
    for item in activation["containers"]:
        mounts = {
            mount["destination"]: Path(mount["source"])
            for mount in item["container"]["mounts"]
        }
        if set(mounts) != {"/input", "/output"}:
            raise ValueError("participant workspace mount set invalid")
        for destination, path in mounts.items():
            if path.is_symlink() or not path.is_dir():
                raise ValueError("participant workspace must be a non-symlink directory")
            entries = list(path.iterdir())
            symlink_count += sum(entry.is_symlink() for entry in entries)
            if destination == "/input":
                input_file_count += len(entries)
            else:
                output_file_count += len(entries)
        workspaces.append(
            {
                "participant_id": item["participant_id"],
                "container_name": item["container"]["container_name"],
                "input_path": str(mounts["/input"].resolve()),
                "output_path": str(mounts["/output"].resolve()),
            }
        )
    scope = authorization["execution_scope"]
    return {
        "participant_count": scope["participant_count"],
        "matched_pair_count": scope["matched_pair_count"],
        "task_count_per_participant": scope["task_count_per_participant"],
        "task_execution_count": scope["authorized_task_executions"],
        "container_count": inventory_snapshot["container_count"],
        "running_container_count": inventory_snapshot["running_count"],
        "container_set_sha256": inventory_snapshot["container_set_sha256"],
        "workspace_set_sha256": canonical_sha256(
            sorted(workspaces, key=lambda value: value["participant_id"])
        ),
        "input_directory_count": len(workspaces),
        "output_directory_count": len(workspaces),
        "input_file_count": input_file_count,
        "output_file_count": output_file_count,
        "symlink_count": symlink_count,
        "provider_id": scope["provider_id"],
        "model_id": scope["model_id"],
        "temperature": scope["temperature"],
    }


def _require_future_paths_absent(authorization: dict[str, Any]) -> None:
    controls = authorization["controls"]
    for field in (
        "authorization_consumption_path",
        "execution_root",
        "post_run_output_root",
    ):
        if Path(controls[field]).exists():
            raise ValueError(f"claim future path already exists: {field}")


def _authorization_implementation(
    authorization: dict[str, Any],
) -> dict[str, str]:
    expected = authorization["implementation"]
    domain = (
        Path(__file__).parent / "j1" / "qualification_frozen_execution_authorization.py"
    )
    operation = Path(__file__).parent / "j1_qualification_frozen_execution_authorization.py"
    actual = {
        "source_revision": expected["source_revision"],
        "domain_source_sha256": hashlib.sha256(domain.read_bytes()).hexdigest(),
        "operation_source_sha256": hashlib.sha256(operation.read_bytes()).hexdigest(),
    }
    if actual != expected:
        raise ValueError("signed authorization implementation source drifted")
    return actual


def _implementation(root: Path, *, require_clean: bool) -> dict[str, str]:
    repository = root.resolve()
    if require_clean and _git(repository, "status", "--porcelain").strip():
        raise ValueError("repository must be clean before claim preflight or claim")
    return {
        "source_revision": _git(repository, "rev-parse", "HEAD").strip(),
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
    ).stdout


def _json_matches(raw: bytes, value: Any) -> bool:
    try:
        return json.loads(raw) == value
    except (json.JSONDecodeError, UnicodeDecodeError):
        return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="operation", required=True)
    for name in ("preflight", "claim"):
        command = subparsers.add_parser(name)
        command.add_argument("--authorization", type=Path, required=True)
        command.add_argument("--issuance-gate", type=Path, required=True)
        command.add_argument("--reviewer-profile", type=Path, required=True)
        command.add_argument(
            "--repository-root", type=Path, default=Path(__file__).parents[1]
        )
        if name == "preflight":
            command.add_argument("--output-root", type=Path, required=True)
        else:
            command.add_argument("--claim-preflight", type=Path, required=True)
            command.add_argument("--owner-authorization-id", required=True)
            command.add_argument("--owner-statement", required=True)
            command.add_argument("--owner-statement-sha256", required=True)
    args = parser.parse_args()
    try:
        if args.operation == "preflight":
            report = generate_claim_preflight(
                authorization_path=args.authorization,
                issuance_gate_path=args.issuance_gate,
                reviewer_profile_path=args.reviewer_profile,
                output_root=args.output_root,
                repository_root=args.repository_root,
            )
        else:
            report = claim_and_build_entry_gate(
                authorization_path=args.authorization,
                issuance_gate_path=args.issuance_gate,
                reviewer_profile_path=args.reviewer_profile,
                claim_preflight_path=args.claim_preflight,
                owner_authorization_id=args.owner_authorization_id,
                owner_statement=args.owner_statement,
                owner_statement_sha256=args.owner_statement_sha256,
                repository_root=args.repository_root,
            )
    except AtomicClaimPersistedError as error:
        print(
            json.dumps(
                {
                    "passed": False,
                    "state": "atomic_claim_persisted_execution_blocked_closeout_required",
                    "error_class": type(error.reason).__name__,
                    "error": str(error),
                    "claim_path": str(error.claim_path.resolve()),
                    "atomic_claim_created": True,
                    "single_use_authorization_consumed": True,
                    "execution_started": False,
                    "provider_credential_read": False,
                    "provider_api_call_performed": False,
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 2
    except (OSError, ValueError, RuntimeError, KeyError, json.JSONDecodeError) as error:
        print(
            json.dumps(
                {
                    "passed": False,
                    "state": "blocked_frozen_stack_claim_operation",
                    "error_class": type(error).__name__,
                    "error": str(error),
                    "atomic_claim_created": False,
                    "execution_started": False,
                    "provider_credential_read": False,
                    "provider_api_call_performed": False,
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
