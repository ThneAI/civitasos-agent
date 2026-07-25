"""Issue J1-D r4 authorization and generate its claim preflight."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from civitasos import Pkcs11Ed25519Signer

from benchmarks.j1.controlled_comparison import canonical_sha256, write_private_json
from benchmarks.j1.qualification_execution_authorization_v4 import (
    build_authorization,
    build_claim_preflight,
    build_issuance_gate,
)
from benchmarks.j1.qualification_execution_preflight_v4 import (
    issuance_authorization_statement,
    validate_execution_plan,
)
from benchmarks.j1.qualification_reviewer_identity import (
    validate_reviewer_identity_profile,
)
from scripts.pkcs11_identity_probe import DEFAULT_MODULE, read_pin


DOMAIN_SOURCE = (
    Path(__file__).parent / "j1" / "qualification_execution_authorization_v4.py"
)
OPERATION_SOURCE = Path(__file__)


def issue_authorization(
    *,
    authorization_id: str,
    owner_authorization_id: str,
    owner_statement_sha256: str,
    plan_path: Path,
    preflight_path: Path,
    reviewer_profile_path: Path,
    module_path: str,
    token_label: str,
    key_label: str,
    key_id_hex: str,
    repository_root: Path,
    output_root: Path,
    pin: str,
) -> dict[str, Any]:
    if not pin:
        raise ValueError("SoftHSM user PIN is empty")
    if output_root.exists():
        raise FileExistsError(f"r4 authorization output exists: {output_root}")
    plan, plan_raw = _read(plan_path)
    preflight, preflight_raw = _read(preflight_path)
    profile, profile_raw = _read(reviewer_profile_path)
    failures = validate_execution_plan(plan)
    statement = issuance_authorization_statement(
        plan_raw_sha256=hashlib.sha256(plan_raw).hexdigest(), plan=plan
    )
    if failures or not (
        preflight.get("plan", {}).get("sha256")
        == hashlib.sha256(plan_raw).hexdigest()
        and preflight.get("plan", {}).get("canonical_sha256")
        == plan["plan_sha256"]
        and preflight.get("owner_authorization", {}).get(
            "required_exact_statement"
        )
        == statement
        and hashlib.sha256(statement.encode()).hexdigest()
        == owner_statement_sha256
    ):
        raise ValueError("r4 authorization plan, preflight, or owner statement invalid")
    profile_failures = validate_reviewer_identity_profile(profile)
    if profile_failures:
        raise ValueError(f"r4 authorization signer profile invalid: {profile_failures}")
    _validate_pkcs11(
        profile,
        module_path=module_path,
        token_label=token_label,
        key_label=key_label,
        key_id_hex=key_id_hex,
    )
    expected_output = Path(plan["controls"]["authorization_output_root"]).resolve()
    if output_root.resolve() != expected_output:
        raise ValueError("r4 authorization output path differs from plan")
    for name in (
        "execution_root",
        "authorization_claim_path",
        "post_run_output_root",
    ):
        if Path(plan["controls"][name]).exists():
            raise ValueError(f"r4 authorization future path exists: {name}")
    _replay_sources(plan)
    inventory = _inventory()
    if inventory != preflight["inventory_snapshot"]:
        raise ValueError("r4 authorization container inventory drift")
    implementation = _implementation(repository_root)
    reviewer = profile["reviewer"]
    profile_sha256 = hashlib.sha256(profile_raw).hexdigest()
    plan_ref = _ref(plan_path, plan["plan_sha256"])
    preflight_ref = _ref(preflight_path, preflight["preflight_sha256"])
    output_root.mkdir(parents=True, mode=0o700)
    output_root.chmod(0o700)
    try:
        issued_at = datetime.now(UTC).isoformat()
        with Pkcs11Ed25519Signer(
            str(Path(module_path).resolve()),
            token_label,
            key_label,
            reviewer["public_key_hex"],
            pin,
            key_id=key_id_hex,
        ) as signer:
            authorization = build_authorization(
                authorization_id=authorization_id,
                owner_authorization_id=owner_authorization_id,
                owner_statement_sha256=owner_statement_sha256,
                issued_at=issued_at,
                plan_ref=plan_ref,
                preflight_ref=preflight_ref,
                plan=plan,
                reviewer=reviewer,
                reviewer_profile_sha256=profile_sha256,
                implementation=implementation,
                signer=signer,
            )
        authorization_path = output_root / "r4-execution-authorization.json"
        write_private_json(authorization_path, authorization)
        authorization_ref = _ref(
            authorization_path, authorization["signature"]["signed_payload_sha256"]
        )
        gate = build_issuance_gate(
            checked_at=datetime.now(UTC).isoformat(),
            authorization_ref=authorization_ref,
            authorization=authorization,
            plan=plan,
            preflight=preflight,
            inventory_snapshot=inventory,
        )
        gate_path = output_root / "r4-execution-authorization-gate.json"
        write_private_json(gate_path, gate)
        gate_ref = _ref(gate_path, gate["report_sha256"])
        contract_ref = plan["source_artifacts"]["execution_contract"]
        contract = json.loads(Path(contract_ref["path"]).read_text())
        execution_manifest_sha256 = canonical_sha256(contract["task_executions"])
        claim_preflight = build_claim_preflight(
            checked_at=datetime.now(UTC).isoformat(),
            authorization_ref=authorization_ref,
            authorization=authorization,
            issuance_gate_ref=gate_ref,
            plan=plan,
            inventory_snapshot=inventory,
            execution_manifest_sha256=execution_manifest_sha256,
            implementation=implementation,
        )
        claim_path = output_root / "r4-claim-preflight.json"
        write_private_json(claim_path, claim_preflight)
        return {
            "authorization": authorization_ref,
            "issuance_gate": gate_ref,
            "claim_preflight": _ref(
                claim_path, claim_preflight["preflight_sha256"]
            ),
            "valid_from": authorization["valid_from"],
            "valid_until": authorization["valid_until"],
            "owner_claim_authorization": claim_preflight["owner_authorization"],
            "state": claim_preflight["state"],
        }
    except Exception:
        shutil.rmtree(output_root, ignore_errors=True)
        raise


def _validate_pkcs11(
    profile: dict[str, Any],
    *,
    module_path: str,
    token_label: str,
    key_label: str,
    key_id_hex: str,
) -> None:
    module = Path(module_path).resolve()
    key = profile["pkcs11_key"]
    if not (
        key["module_path"] == str(module)
        and key["module_sha256"] == hashlib.sha256(module.read_bytes()).hexdigest()
        and key["token_label"] == token_label
        and key["key_label"] == key_label
        and key["key_id_hex"] == key_id_hex.lower()
    ):
        raise ValueError("r4 authorization PKCS#11 configuration mismatch")


def _replay_sources(plan: dict[str, Any]) -> None:
    for name, reference in plan["source_artifacts"].items():
        if (
            hashlib.sha256(Path(reference["path"]).read_bytes()).hexdigest()
            != reference["sha256"]
        ):
            raise ValueError(f"r4 authorization source drift: {name}")


def _inventory() -> dict[str, int]:
    statuses = subprocess.run(
        [
            "docker",
            "ps",
            "-a",
            "--filter",
            "name=civitas-j1q-runner",
            "--format",
            "{{.Status}}",
        ],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()
    return {
        "participant_container_count": len(statuses),
        "created_count": sum(item.startswith("Created") for item in statuses),
        "running_count": sum(item.startswith("Up ") for item in statuses),
    }


def _implementation(root: Path) -> dict[str, str]:
    if _git(root, "status", "--porcelain"):
        raise ValueError("repository must be clean before r4 authorization issuance")
    return {
        "source_revision": _git(root, "rev-parse", "HEAD"),
        "domain_source_sha256": hashlib.sha256(DOMAIN_SOURCE.read_bytes()).hexdigest(),
        "operation_source_sha256": hashlib.sha256(
            OPERATION_SOURCE.read_bytes()
        ).hexdigest(),
    }


def _read(path: Path) -> tuple[dict[str, Any], bytes]:
    raw = path.read_bytes()
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError(f"JSON artifact must contain an object: {path}")
    return value, raw


def _ref(path: Path, canonical_digest: str) -> dict[str, str]:
    return {
        "path": str(path.resolve()),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "canonical_sha256": canonical_digest,
    }


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
    parser.add_argument("--authorization-id", required=True)
    parser.add_argument("--owner-authorization-id", required=True)
    parser.add_argument("--owner-statement-sha256", required=True)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--preflight", type=Path, required=True)
    parser.add_argument("--reviewer-profile", type=Path, required=True)
    parser.add_argument("--module", default=DEFAULT_MODULE)
    parser.add_argument("--token-label", required=True)
    parser.add_argument("--key-label", required=True)
    parser.add_argument("--key-id", required=True)
    parser.add_argument("--pin-file", type=Path)
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    pin = read_pin(args.pin_file)
    result = issue_authorization(
        authorization_id=args.authorization_id,
        owner_authorization_id=args.owner_authorization_id,
        owner_statement_sha256=args.owner_statement_sha256,
        plan_path=args.plan,
        preflight_path=args.preflight,
        reviewer_profile_path=args.reviewer_profile,
        module_path=args.module,
        token_label=args.token_label,
        key_label=args.key_label,
        key_id_hex=args.key_id,
        repository_root=args.repository_root,
        output_root=args.output_root,
        pin=pin,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
