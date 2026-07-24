"""Issue and Gate one frozen-stack J1-D execution authorization."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pkcs11
from civitasos import Pkcs11Ed25519Signer

from benchmarks.j1.controlled_comparison import write_private_json
from benchmarks.j1.qualification_frozen_execution_authorization import (
    build_authorization,
    build_gate_report,
    validate_authorization,
)
from benchmarks.j1.qualification_frozen_execution_preflight import (
    MAX_TTL_SECONDS,
    owner_authorization_statement,
    validate_execution_plan,
    validate_preflight,
)
from benchmarks.j1.qualification_reviewer_identity import (
    validate_reviewer_identity_profile,
)
from benchmarks.j1_qualification_frozen_execution_preflight import (
    _canonical,
    _inspect_current_inventory,
    _read_private,
    _validate_frozen_stack,
)
from benchmarks.j1_qualification_reviewer_identity import inspect_token_pin_state
from scripts.pkcs11_identity_probe import DEFAULT_MODULE, read_pin


DOMAIN_SOURCE = (
    Path(__file__).parent / "j1" / "qualification_frozen_execution_authorization.py"
)
OPERATION_SOURCE = Path(__file__)


def issue_frozen_execution_authorization(
    *,
    authorization_id: str,
    owner_authorization_id: str,
    owner_statement: str,
    owner_statement_sha256: str,
    plan_path: Path,
    preflight_path: Path,
    reviewer_profile_path: Path,
    output_root: Path,
    repository_root: Path,
    module_path: str,
    token_label: str,
    key_label: str,
    key_id_hex: str,
    pin: str,
) -> dict[str, Any]:
    if not pin:
        raise ValueError("SoftHSM user PIN is empty")
    if output_root.exists():
        raise ValueError(f"frozen authorization output exists: {output_root}")
    plan_artifact = _read_private(plan_path, "frozen_execution_plan")
    preflight_artifact = _read_private(preflight_path, "frozen_execution_preflight")
    profile_artifact = _read_private(reviewer_profile_path, "reviewer_profile")
    plan = plan_artifact["value"]
    preflight = preflight_artifact["value"]
    plan_bytes = plan_artifact["raw"]
    preflight_bytes = preflight_artifact["raw"]
    failures = validate_execution_plan(plan)
    failures.extend(
        validate_preflight(
            preflight,
            plan_path=str(plan_artifact["path"]),
            plan_bytes=plan_bytes,
            plan=plan,
            expected_inventory_snapshot=preflight["inventory_snapshot"],
        )
    )
    if failures:
        raise ValueError(f"frozen authorization plan/preflight invalid: {failures}")
    expected_statement = owner_authorization_statement(
        plan_artifact_sha256=plan_artifact["sha256"],
        plan=plan,
    )
    if (
        owner_statement != expected_statement
        or hashlib.sha256(owner_statement.encode()).hexdigest()
        != owner_statement_sha256
        or owner_statement_sha256
        != preflight["owner_authorization"]["statement_sha256"]
    ):
        raise ValueError("frozen authorization owner statement/hash mismatch")
    expected_output = Path(plan["controls"]["authorization_output_root"]).resolve()
    if output_root.resolve() != expected_output:
        raise ValueError("authorization output root does not match frozen plan")
    for field in (
        "execution_root",
        "authorization_consumption_path",
        "post_run_output_root",
    ):
        if Path(plan["controls"][field]).exists():
            raise ValueError(
                f"frozen authorization future path already exists: {field}"
            )
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
            raise ValueError(f"frozen authorization source drifted: {name}")
    _validate_frozen_stack(source_artifacts)
    inventory_snapshot, inventory_failures = _inspect_current_inventory(
        infrastructure=source_artifacts["reviewed_infrastructure"]["value"],
        activation=source_artifacts["infrastructure_activation"]["value"],
    )
    if inventory_failures or inventory_snapshot != preflight["inventory_snapshot"]:
        raise ValueError(
            f"frozen authorization inventory invalid: {inventory_failures}"
        )
    profile = profile_artifact["value"]
    profile_failures = validate_reviewer_identity_profile(profile)
    if profile_failures:
        raise ValueError(f"authorization signer profile invalid: {profile_failures}")
    _validate_pkcs11_configuration(
        profile=profile,
        module_path=module_path,
        token_label=token_label,
        key_label=key_label,
        key_id_hex=key_id_hex,
    )
    pin_state = inspect_token_pin_state(
        module_path=module_path,
        token_label=token_label,
    )
    if not (
        pin_state["token_initialized"]
        and pin_state["user_pin_initialized"]
        and pin_state["safe_to_attempt_user_login"]
    ):
        raise ValueError(f"authorization signer token not ready: {pin_state}")
    implementation = _implementation(repository_root)
    issued_at = datetime.now(timezone.utc).isoformat()
    output_root.mkdir(parents=True, mode=0o700)
    output_root.chmod(0o700)
    try:
        with Pkcs11Ed25519Signer(
            str(Path(module_path).resolve()),
            token_label,
            key_label,
            profile["reviewer"]["public_key_hex"],
            pin,
            key_id=key_id_hex,
        ) as signer:
            authorization = build_authorization(
                authorization_id=authorization_id,
                owner_authorization_id=owner_authorization_id,
                owner_statement_sha256=owner_statement_sha256,
                issued_at=issued_at,
                ttl_seconds=MAX_TTL_SECONDS,
                plan_path=str(plan_artifact["path"]),
                plan_bytes=plan_bytes,
                plan=plan,
                preflight_path=str(preflight_artifact["path"]),
                preflight_bytes=preflight_bytes,
                preflight=preflight,
                reviewer_profile=profile,
                reviewer_profile_sha256=profile_artifact["sha256"],
                implementation=implementation,
                signer=signer,
            )
        authorization_path = output_root / "execution-authorization.json"
        write_private_json(authorization_path, authorization)
        authorization_bytes = authorization_path.read_bytes()
        validation_failures = validate_authorization(
            authorization,
            plan_path=str(plan_artifact["path"]),
            plan_bytes=plan_bytes,
            plan=plan,
            preflight_path=str(preflight_artifact["path"]),
            preflight_bytes=preflight_bytes,
            preflight=preflight,
            reviewer_profile=profile,
            reviewer_profile_sha256=profile_artifact["sha256"],
            expected_implementation=implementation,
            current_time=datetime.now(timezone.utc),
            require_current=True,
        )
        if validation_failures:
            raise ValueError(
                f"frozen authorization validation failed: {validation_failures}"
            )
        gate = build_gate_report(
            checked_at=datetime.now(timezone.utc).isoformat(),
            authorization_path=str(authorization_path.resolve()),
            authorization_bytes=authorization_bytes,
            authorization=authorization,
            plan=plan,
            preflight=preflight,
            inventory_snapshot=inventory_snapshot,
        )
        write_private_json(
            output_root / "execution-authorization-gate-report.json",
            gate,
        )
        return gate
    except Exception:
        shutil.rmtree(output_root, ignore_errors=True)
        raise


def _validate_pkcs11_configuration(
    *,
    profile: dict[str, Any],
    module_path: str,
    token_label: str,
    key_label: str,
    key_id_hex: str,
) -> None:
    module = Path(module_path).resolve()
    key = profile["pkcs11_key"]
    expected = {
        "module_path": str(module),
        "token_label": token_label,
        "key_label": key_label,
        "key_id_hex": key_id_hex.lower(),
    }
    drift = [
        field
        for field, expected_value in expected.items()
        if key.get(field) != expected_value
    ]
    if drift:
        raise ValueError(f"authorization PKCS#11 configuration mismatch: {drift}")
    if key.get("module_sha256") != hashlib.sha256(module.read_bytes()).hexdigest():
        raise ValueError("authorization PKCS#11 module hash mismatch")


def _implementation(repository_root: Path) -> dict[str, str]:
    root = repository_root.resolve()
    if _git(root, "status", "--porcelain").strip():
        raise ValueError("repository must be clean before authorization issuance")
    return {
        "source_revision": _git(root, "rev-parse", "HEAD").strip(),
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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--authorization-id", required=True)
    parser.add_argument("--owner-authorization-id", required=True)
    parser.add_argument("--owner-statement", required=True)
    parser.add_argument("--owner-statement-sha256", required=True)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--preflight", type=Path, required=True)
    parser.add_argument("--reviewer-profile", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument(
        "--repository-root",
        type=Path,
        default=Path(__file__).parents[1],
    )
    parser.add_argument("--module", default=DEFAULT_MODULE)
    parser.add_argument("--token-label", required=True)
    parser.add_argument("--key-label", required=True)
    parser.add_argument("--key-id", required=True)
    parser.add_argument("--pin-file", type=Path)
    args = parser.parse_args()
    pin = read_pin(args.pin_file)
    try:
        report = issue_frozen_execution_authorization(
            authorization_id=args.authorization_id,
            owner_authorization_id=args.owner_authorization_id,
            owner_statement=args.owner_statement,
            owner_statement_sha256=args.owner_statement_sha256,
            plan_path=args.plan,
            preflight_path=args.preflight,
            reviewer_profile_path=args.reviewer_profile,
            output_root=args.output_root,
            repository_root=args.repository_root,
            module_path=args.module,
            token_label=args.token_label,
            key_label=args.key_label,
            key_id_hex=args.key_id,
            pin=pin,
        )
    except (
        OSError,
        ValueError,
        RuntimeError,
        KeyError,
        json.JSONDecodeError,
        pkcs11.PKCS11Error,
    ) as error:
        print(
            json.dumps(
                {
                    "passed": False,
                    "state": "blocked_frozen_execution_authorization_issuance",
                    "error_class": type(error).__name__,
                    "error": str(error),
                    "pin_recorded": False,
                    "private_key_exported": False,
                    "authorization_consumed": False,
                    "provider_api_call_performed": False,
                    "model_invocation_performed": False,
                    "agent_execution_performed": False,
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 1
    finally:
        pin = ""
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
