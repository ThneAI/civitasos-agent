"""Issue an outcome-sensitive J1-D authorization and claim preflight."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any

from civitasos import Pkcs11Ed25519Signer

from benchmarks.j1.controlled_comparison import canonical_sha256, write_private_json
from benchmarks.j1.qualification_outcome_sensitive_execution_authorization import (
    AUTH_BOUNDARY,
    build_authorization,
    build_claim_preflight,
    build_issuance_gate,
    validate_authorization,
    validate_plan_for_authorization,
)
from benchmarks.j1.qualification_outcome_sensitive_execution_materials import (
    replay_material_bindings,
)
from benchmarks.j1.qualification_outcome_sensitive_execution_preflight import (
    issuance_authorization_statement,
)
from benchmarks.j1.qualification_reviewer_identity import (
    validate_reviewer_identity_profile,
)
from benchmarks.j1_qualification_runtime_inventory_v4 import activation_inventory
from scripts.pkcs11_identity_probe import DEFAULT_MODULE, read_pin


DOMAIN_SOURCE = (
    Path(__file__).parent
    / "j1"
    / "qualification_outcome_sensitive_execution_authorization.py"
)
OPERATION_SOURCE = Path(__file__)
EXPECTED_INVENTORY = {
    "participant_container_count": 40,
    "created_count": 40,
    "running_count": 0,
}


def issue_authorization(
    *,
    authorization_id: str,
    owner_authorization_id: str,
    owner_statement_sha256: str,
    issued_at: str,
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
        raise FileExistsError(
            f"outcome-sensitive authorization output exists: {output_root}"
        )
    plan, plan_raw = _read(plan_path)
    preflight, _ = _read(preflight_path)
    profile, profile_raw = _read(reviewer_profile_path)
    plan_raw_sha256 = hashlib.sha256(plan_raw).hexdigest()
    statement = issuance_authorization_statement(
        plan_raw_sha256=plan_raw_sha256,
        plan=plan,
    )
    failures = validate_plan_for_authorization(plan)
    if failures or not (
        preflight.get("passed") is True
        and preflight.get("plan")
        == {
            "path": str(plan_path.resolve()),
            "sha256": plan_raw_sha256,
            "canonical_sha256": plan["plan_sha256"],
        }
        and preflight.get("owner_authorization", {}).get(
            "required_exact_statement"
        )
        == statement
        and preflight.get("owner_authorization", {}).get("statement_sha256")
        == owner_statement_sha256
        == hashlib.sha256(statement.encode()).hexdigest()
        and preflight.get("readiness", {}).get(
            "single_use_authorization_issued"
        )
        is False
        and preflight.get("readiness", {}).get(
            "single_use_authorization_consumed"
        )
        is False
    ):
        raise ValueError(
            "outcome-sensitive plan, preflight, or owner statement invalid"
        )
    _self_hash(preflight, "preflight_sha256")
    profile_failures = validate_reviewer_identity_profile(profile)
    if profile_failures:
        raise ValueError(
            "outcome-sensitive authorization signer profile invalid: "
            f"{profile_failures}"
        )
    _validate_pkcs11(
        profile,
        module_path=module_path,
        token_label=token_label,
        key_label=key_label,
        key_id_hex=key_id_hex,
    )
    expected_output = Path(plan["controls"]["authorization_output_root"]).resolve()
    if output_root.resolve() != expected_output:
        raise ValueError(
            "outcome-sensitive authorization output path differs from plan"
        )
    for name in (
        "execution_root",
        "authorization_claim_path",
        "post_run_output_root",
    ):
        if Path(plan["controls"][name]).exists():
            raise ValueError(
                f"outcome-sensitive authorization future path exists: {name}"
            )
    _replay_sources(plan)
    replay_material_bindings(plan["material_bindings"])
    contract_ref = plan["source_artifacts"]["execution_contract"]
    contract, _ = _read(Path(contract_ref["path"]))
    _self_hash(contract, "contract_sha256")
    execution_manifest_sha256 = canonical_sha256(contract["task_executions"])
    if not (
        contract["contract_sha256"]
        == contract_ref["canonical_sha256"]
        == plan["binding"]["execution_contract_sha256"]
        and contract.get("scope", {}).get("task_execution_count") == 480
        and len(contract.get("task_executions", [])) == 480
    ):
        raise ValueError(
            "outcome-sensitive authorization execution contract invalid"
        )
    activation_ref = plan["source_artifacts"]["activation"]
    activation, _ = _read(Path(activation_ref["path"]))
    inventory = activation_inventory(activation)
    if (
        inventory != EXPECTED_INVENTORY
        or inventory != preflight.get("inventory_snapshot")
    ):
        raise ValueError(
            "outcome-sensitive authorization container inventory drift"
        )
    implementation = _implementation(repository_root)
    reviewer = profile["reviewer"]
    profile_sha256 = hashlib.sha256(profile_raw).hexdigest()
    plan_ref = _ref(plan_path, plan["plan_sha256"])
    preflight_ref = _ref(preflight_path, preflight["preflight_sha256"])
    claim_path = str(
        Path(plan["controls"]["authorization_claim_path"]).resolve()
    )
    output_root.mkdir(parents=True, mode=0o700)
    output_root.chmod(0o700)
    try:
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
                execution_manifest_sha256=execution_manifest_sha256,
                reviewer=reviewer,
                reviewer_profile_sha256=profile_sha256,
                implementation=implementation,
                signer=signer,
            )
        validation_failures = validate_authorization(
            authorization,
            plan_ref=plan_ref,
            preflight_ref=preflight_ref,
            plan=plan,
            expected_owner_authorization_id=owner_authorization_id,
            expected_owner_statement_sha256=owner_statement_sha256,
            expected_execution_manifest_sha256=execution_manifest_sha256,
            expected_reviewer=reviewer,
            expected_reviewer_profile_sha256=profile_sha256,
            expected_implementation=implementation,
            require_current=True,
        )
        if validation_failures:
            raise ValueError(
                "outcome-sensitive authorization post-sign validation failed: "
                f"{validation_failures}"
            )
        authorization_path = (
            output_root / "outcome-sensitive-execution-authorization.json"
        )
        write_private_json(authorization_path, authorization)
        authorization_ref = _ref(
            authorization_path,
            authorization["signature"]["signed_payload_sha256"],
        )
        gate = build_issuance_gate(
            checked_at=issued_at,
            authorization_ref=authorization_ref,
            authorization=authorization,
            plan_ref=plan_ref,
            preflight_ref=preflight_ref,
            inventory_snapshot=inventory,
        )
        gate_path = (
            output_root / "outcome-sensitive-execution-authorization-gate.json"
        )
        write_private_json(gate_path, gate)
        gate_ref = _ref(gate_path, gate["report_sha256"])
        claim_preflight = build_claim_preflight(
            authorization_ref=authorization_ref,
            authorization=authorization,
            issuance_gate_ref=gate_ref,
            claim_path=claim_path,
            checked_at=issued_at,
            inventory_snapshot=inventory,
            implementation=implementation,
        )
        claim_preflight_path = (
            output_root / "outcome-sensitive-claim-preflight.json"
        )
        write_private_json(claim_preflight_path, claim_preflight)
        report = {
            "schema_version": (
                "j1-qualification-outcome-sensitive-"
                "authorization-issuance-report:v1"
            ),
            "run_id": authorization["run_id"],
            "state": claim_preflight["state"],
            "authorization": authorization_ref,
            "issuance_gate": gate_ref,
            "claim_preflight": _ref(
                claim_preflight_path,
                claim_preflight["preflight_sha256"],
            ),
            "inventory_snapshot": inventory,
            "valid_from": authorization["valid_from"],
            "valid_until": authorization["valid_until"],
            "owner_claim_authorization": claim_preflight[
                "owner_authorization"
            ],
            "execution_boundary": AUTH_BOUNDARY,
            "pin_recorded": False,
            "private_key_exported": False,
        }
        report_path = (
            output_root / "outcome-sensitive-authorization-issuance-report.json"
        )
        write_private_json(report_path, report)
        return report
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
        and key["module_sha256"]
        == hashlib.sha256(module.read_bytes()).hexdigest()
        and key["token_label"] == token_label
        and key["key_label"] == key_label
        and key["key_id_hex"] == key_id_hex.lower()
    ):
        raise ValueError(
            "outcome-sensitive authorization PKCS#11 configuration mismatch"
        )


def _replay_sources(plan: dict[str, Any]) -> None:
    for name, reference in plan["source_artifacts"].items():
        path = Path(reference["path"])
        if hashlib.sha256(path.read_bytes()).hexdigest() != reference["sha256"]:
            raise ValueError(
                f"outcome-sensitive authorization source drift: {name}"
            )


def _implementation(root: Path) -> dict[str, str]:
    if _git(root, "status", "--porcelain"):
        raise ValueError(
            "repository must be clean before outcome-sensitive authorization issuance"
        )
    revision = _git(root, "rev-parse", "HEAD")
    if subprocess.run(
        ["git", "merge-base", "--is-ancestor", revision, "@{upstream}"],
        cwd=root,
        check=False,
    ).returncode:
        raise ValueError(
            "outcome-sensitive authorization revision is not present upstream"
        )
    return {
        "source_revision": revision,
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


def _self_hash(value: dict[str, Any], field: str) -> None:
    body = {key: item for key, item in value.items() if key != field}
    if value.get(field) != canonical_sha256(body):
        raise ValueError(
            f"outcome-sensitive authorization source self-hash invalid: {field}"
        )


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
    parser.add_argument("--issued-at", required=True)
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
    datetime.fromisoformat(args.issued_at.replace("Z", "+00:00"))
    pin = read_pin(args.pin_file)
    report = issue_authorization(
        authorization_id=args.authorization_id,
        owner_authorization_id=args.owner_authorization_id,
        owner_statement_sha256=args.owner_statement_sha256,
        issued_at=args.issued_at,
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
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
