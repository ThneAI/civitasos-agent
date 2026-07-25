"""Atomically claim one J1-D r4 authorization and open its execution Gate."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from benchmarks.j1.controlled_comparison import canonical_sha256
from benchmarks.j1.qualification_execution_authorization_v4 import (
    AUTH_BOUNDARY,
    claim_authorization_statement,
    validate_authorization,
)
from benchmarks.j1.qualification_execution_entry_v4 import (
    build_claim,
    build_entry_gate,
    validate_claim,
)
from benchmarks.j1.qualification_execution_preflight_v4 import (
    validate_execution_plan,
)
from benchmarks.j1.qualification_reviewer_identity import (
    validate_reviewer_identity_profile,
)
from benchmarks.j1_qualification_runtime_inventory_v4 import activation_inventory


DOMAIN_SOURCE = Path(__file__).parent / "j1" / "qualification_execution_entry_v4.py"
OPERATION_SOURCE = Path(__file__)


def claim_and_build_entry_gate(
    *,
    owner_authorization_id: str,
    owner_statement: str,
    authorization_path: Path,
    issuance_gate_path: Path,
    claim_preflight_path: Path,
    reviewer_profile_path: Path,
    repository_root: Path,
) -> dict[str, Any]:
    authorization, authorization_raw = _read_private(authorization_path)
    gate, gate_raw = _read_private(issuance_gate_path)
    preflight, preflight_raw = _read_private(claim_preflight_path)
    profile, profile_raw = _read_private(reviewer_profile_path)
    plan_ref = authorization["source_binding"]["plan"]
    plan_path = Path(plan_ref["path"])
    plan, plan_raw = _read_private(plan_path)
    execution_preflight_ref = authorization["source_binding"]["preflight"]
    execution_preflight_path = Path(execution_preflight_ref["path"])
    execution_preflight, execution_preflight_raw = _read_private(
        execution_preflight_path
    )
    contract_ref = plan["source_artifacts"]["execution_contract"]
    contract, contract_raw = _read_private(Path(contract_ref["path"]))
    activation_ref = contract["source_artifacts"]["infrastructure_activation"]
    activation, activation_raw = _read_private(Path(activation_ref["path"]))
    _validate_upstream(
        authorization=authorization,
        authorization_raw=authorization_raw,
        authorization_path=authorization_path,
        gate=gate,
        gate_raw=gate_raw,
        gate_path=issuance_gate_path,
        preflight=preflight,
        preflight_raw=preflight_raw,
        preflight_path=claim_preflight_path,
        profile=profile,
        profile_raw=profile_raw,
        plan=plan,
        plan_raw=plan_raw,
        plan_path=plan_path,
        execution_preflight=execution_preflight,
        execution_preflight_raw=execution_preflight_raw,
        execution_preflight_path=execution_preflight_path,
        contract=contract,
        contract_raw=contract_raw,
        contract_ref=contract_ref,
        activation_raw=activation_raw,
        activation_ref=activation_ref,
        activation=activation,
        repository_root=repository_root,
    )
    authorization_ref = _ref(
        authorization_path, authorization["signature"]["signed_payload_sha256"]
    )
    gate_ref = _ref(issuance_gate_path, gate["report_sha256"])
    preflight_ref = _ref(claim_preflight_path, preflight["preflight_sha256"])
    execution_manifest_sha256 = canonical_sha256(contract["task_executions"])
    if not (
        gate.get("authorization") == authorization_ref
        and preflight.get("state")
        == "r4_claim_preflight_passed_owner_authorization_required"
        and preflight.get("source_binding")
        == {
            "authorization": authorization_ref,
            "issuance_gate": gate_ref,
            "plan_sha256": plan["plan_sha256"],
        }
        and preflight.get("execution_manifest_sha256")
        == execution_manifest_sha256
        and preflight.get("execution_scope") == authorization["execution_scope"]
        and preflight.get("budget") == authorization["budget"]
        and preflight.get("controls") == authorization["controls"]
    ):
        raise ValueError("r4 claim preflight scope or source binding invalid")
    expected_statement = claim_authorization_statement(
        authorization_ref=authorization_ref,
        issuance_gate_ref=gate_ref,
        authorization=authorization,
        execution_manifest_sha256=execution_manifest_sha256,
    )
    statement_sha256 = hashlib.sha256(owner_statement.encode()).hexdigest()
    if not (
        owner_statement == expected_statement
        and preflight["owner_authorization"]["required_exact_statement"]
        == expected_statement
        and preflight["owner_authorization"]["statement_sha256"]
        == statement_sha256
    ):
        raise ValueError("r4 claim owner authorization mismatch")
    claim_path = Path(authorization["controls"]["authorization_claim_path"])
    execution_root = Path(authorization["controls"]["execution_root"])
    post_run_root = Path(authorization["controls"]["post_run_output_root"])
    if claim_path.exists() or execution_root.exists() or post_run_root.exists():
        raise ValueError("r4 claim or future execution path already exists")
    inventory = activation_inventory(activation)
    if inventory != preflight["inventory_snapshot"]:
        raise ValueError("r4 claim activation inventory drift")
    implementation = _implementation(repository_root)
    claim = build_claim(
        claimed_at=datetime.now(UTC).isoformat(),
        claim_path=str(claim_path),
        owner_authorization_id=owner_authorization_id,
        owner_statement_sha256=statement_sha256,
        authorization_ref=authorization_ref,
        issuance_gate_ref=gate_ref,
        claim_preflight_ref=preflight_ref,
        authorization=authorization,
        claim_preflight=preflight,
        implementation=implementation,
    )
    failures = validate_claim(
        claim,
        claim_path=str(claim_path),
        authorization_ref=authorization_ref,
        issuance_gate_ref=gate_ref,
        claim_preflight_ref=preflight_ref,
        authorization=authorization,
        claim_preflight=preflight,
        owner_statement_sha256=statement_sha256,
        expected_implementation=implementation,
    )
    if failures:
        raise ValueError(f"r4 claim invalid before write: {failures}")
    _write_exclusive(claim_path, claim)
    try:
        persisted, persisted_raw = _read_private(claim_path)
        failures = validate_claim(
            persisted,
            claim_path=str(claim_path),
            authorization_ref=authorization_ref,
            issuance_gate_ref=gate_ref,
            claim_preflight_ref=preflight_ref,
            authorization=authorization,
            claim_preflight=preflight,
            owner_statement_sha256=statement_sha256,
            expected_implementation=implementation,
        )
        if failures:
            raise ValueError(f"persisted r4 claim invalid: {failures}")
        if (
            activation_inventory(activation) != inventory
            or execution_root.exists()
            or post_run_root.exists()
        ):
            raise ValueError("r4 execution entry state drifted after claim")
        claim_ref = _ref(claim_path, persisted["claim_sha256"])
        entry_gate = build_entry_gate(
            checked_at=datetime.now(UTC).isoformat(),
            claim_ref=claim_ref,
            claim=persisted,
            inventory_snapshot=inventory,
            execution_manifest_sha256=execution_manifest_sha256,
        )
        entry_path = authorization_path.parent / "r4-execution-entry-gate.json"
        if entry_path.exists():
            raise ValueError("r4 execution entry Gate already exists")
        _write_exclusive(entry_path, entry_gate)
    except Exception as error:
        raise AtomicClaimPersistedError(claim_path, error) from error
    return {
        "claim": _ref(claim_path, persisted["claim_sha256"]),
        "entry_gate": _ref(entry_path, entry_gate["report_sha256"]),
        "authorization": authorization,
        "plan": plan,
        "contract": contract,
        "activation": activation,
        "state": entry_gate["state"],
    }


class AtomicClaimPersistedError(RuntimeError):
    def __init__(self, claim_path: Path, reason: Exception) -> None:
        self.claim_path = claim_path
        self.reason = reason
        super().__init__(
            "atomic claim persisted; execution is blocked and signed closeout is required"
        )


def _validate_upstream(
    *,
    authorization: dict[str, Any],
    authorization_raw: bytes,
    authorization_path: Path,
    gate: dict[str, Any],
    gate_raw: bytes,
    gate_path: Path,
    preflight: dict[str, Any],
    preflight_raw: bytes,
    preflight_path: Path,
    profile: dict[str, Any],
    profile_raw: bytes,
    plan: dict[str, Any],
    plan_raw: bytes,
    plan_path: Path,
    execution_preflight: dict[str, Any],
    execution_preflight_raw: bytes,
    execution_preflight_path: Path,
    contract: dict[str, Any],
    contract_raw: bytes,
    contract_ref: dict[str, str],
    activation_raw: bytes,
    activation_ref: dict[str, str],
    activation: dict[str, Any],
    repository_root: Path,
) -> None:
    del authorization_raw, gate_raw, preflight_raw
    if validate_execution_plan(plan):
        raise ValueError("r4 claim execution plan invalid")
    plan_expected = _ref(plan_path, plan["plan_sha256"])
    execution_preflight_expected = _ref(
        execution_preflight_path, execution_preflight["preflight_sha256"]
    )
    profile_failures = validate_reviewer_identity_profile(profile)
    implementation = authorization["implementation"]
    authorization_failures = validate_authorization(
        authorization,
        plan=plan,
        expected_plan_ref=plan_expected,
        expected_preflight_ref=execution_preflight_expected,
        expected_owner_statement_sha256=authorization["owner_authorization"][
            "statement_sha256"
        ],
        expected_reviewer=profile["reviewer"],
        expected_reviewer_profile_sha256=hashlib.sha256(profile_raw).hexdigest(),
        expected_implementation=implementation,
        current_time=datetime.now(UTC),
        require_current=True,
    )
    gate_body = {key: item for key, item in gate.items() if key != "report_sha256"}
    preflight_body = {
        key: item for key, item in preflight.items() if key != "preflight_sha256"
    }
    if profile_failures or authorization_failures or not (
        authorization_path.resolve()
        == Path(gate["authorization"]["path"]).resolve()
        and gate.get("report_sha256") == canonical_sha256(gate_body)
        and gate.get("passed") is True
        and gate.get("execution_boundary") == AUTH_BOUNDARY
        and preflight.get("preflight_sha256") == canonical_sha256(preflight_body)
        and preflight.get("source_binding", {}).get("authorization", {}).get("sha256")
        == hashlib.sha256(authorization_path.read_bytes()).hexdigest()
        and preflight.get("source_binding", {}).get("issuance_gate", {}).get("sha256")
        == hashlib.sha256(gate_path.read_bytes()).hexdigest()
    ):
        raise ValueError("r4 authorization, issuance Gate, or claim preflight invalid")
    if not (
        hashlib.sha256(plan_raw).hexdigest() == plan_expected["sha256"]
        and hashlib.sha256(execution_preflight_raw).hexdigest()
        == execution_preflight_expected["sha256"]
        and hashlib.sha256(contract_raw).hexdigest() == contract_ref["sha256"]
        and contract.get("contract_sha256") == contract_ref["canonical_sha256"]
        and hashlib.sha256(activation_raw).hexdigest() == activation_ref["sha256"]
        and activation.get("activation_sha256") == activation_ref["canonical_sha256"]
        and len(contract.get("task_executions", [])) == 320
        and _implementation(repository_root)["source_revision"]
        == _git(repository_root, "rev-parse", "HEAD")
    ):
        raise ValueError("r4 claim source artifact drift")


def _implementation(root: Path) -> dict[str, str]:
    if _git(root, "status", "--porcelain"):
        raise ValueError("repository must be clean before r4 claim")
    return {
        "source_revision": _git(root, "rev-parse", "HEAD"),
        "domain_source_sha256": hashlib.sha256(DOMAIN_SOURCE.read_bytes()).hexdigest(),
        "operation_source_sha256": hashlib.sha256(OPERATION_SOURCE.read_bytes()).hexdigest(),
    }


def _git(root: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", *arguments],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _read_private(path: Path) -> tuple[dict[str, Any], bytes]:
    resolved = path.resolve()
    if path.is_symlink() or not resolved.is_file() or resolved.stat().st_mode & 0o077:
        raise ValueError(f"private r4 artifact invalid: {resolved}")
    raw = resolved.read_bytes()
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError(f"r4 artifact must contain an object: {resolved}")
    return value, raw


def _ref(path: Path, canonical_digest: str) -> dict[str, str]:
    return {
        "path": str(path.resolve()),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "canonical_sha256": canonical_digest,
    }


def _write_exclusive(path: Path, value: dict[str, Any]) -> None:
    parent = path.parent.resolve()
    if path.parent.is_symlink():
        raise ValueError("r4 claim parent must not be a symlink")
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    parent.chmod(0o700)
    payload = json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    directory = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--owner-authorization-id", required=True)
    parser.add_argument("--owner-statement", required=True)
    parser.add_argument("--authorization", type=Path, required=True)
    parser.add_argument("--issuance-gate", type=Path, required=True)
    parser.add_argument("--claim-preflight", type=Path, required=True)
    parser.add_argument("--reviewer-profile", type=Path, required=True)
    parser.add_argument("--repository-root", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = claim_and_build_entry_gate(
            owner_authorization_id=args.owner_authorization_id,
            owner_statement=args.owner_statement,
            authorization_path=args.authorization,
            issuance_gate_path=args.issuance_gate,
            claim_preflight_path=args.claim_preflight,
            reviewer_profile_path=args.reviewer_profile,
            repository_root=args.repository_root,
        )
    except AtomicClaimPersistedError as error:
        print(
            json.dumps(
                {
                    "passed": False,
                    "state": "atomic_claim_persisted_closeout_required",
                    "claim_path": str(error.claim_path.resolve()),
                    "execution_started": False,
                },
                sort_keys=True,
            )
        )
        return 2
    print(
        json.dumps(
            {
                "passed": True,
                "state": result["state"],
                "claim": result["claim"],
                "entry_gate": result["entry_gate"],
                "execution_started": False,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
