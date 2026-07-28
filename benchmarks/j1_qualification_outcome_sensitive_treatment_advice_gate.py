"""Independently validate all 180 signed outcome-sensitive J1-D advice items."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from benchmarks.j1.controlled_comparison import (
    canonical_sha256,
    write_private_json,
)
from benchmarks.j1.qualification_outcome_sensitive_treatment_advice import (
    authorization_statement,
)
from benchmarks.j1_qualification_outcome_sensitive_treatment_advice_sign import (
    _implementation,
    _load_context,
    validate_signed_manifest,
)


GATE_SCHEMA = "j1-qualification-outcome-sensitive-treatment-advice-gate:v1"


def run_gate(
    *,
    candidate_manifest_path: Path,
    candidate_preflight_path: Path,
    signed_manifest_path: Path,
    signing_operation_path: Path,
    protocol_path: Path,
    task_fixture_path: Path,
    reviewed_assignment_path: Path,
    assignment_gate_path: Path,
    mentor_plan_path: Path,
    mentor_identity_path: Path,
    mentor_identity_gate_path: Path,
    repository_root: Path,
    output_root: Path,
) -> dict[str, Any]:
    if output_root.exists():
        raise FileExistsError(f"outcome advice Gate output exists: {output_root}")
    context = _load_context(
        candidate_manifest_path=candidate_manifest_path,
        candidate_preflight_path=candidate_preflight_path,
        protocol_path=protocol_path,
        task_fixture_path=task_fixture_path,
        reviewed_assignment_path=reviewed_assignment_path,
        assignment_gate_path=assignment_gate_path,
        mentor_plan_path=mentor_plan_path,
        mentor_identity_path=mentor_identity_path,
        mentor_identity_gate_path=mentor_identity_gate_path,
    )
    signed, signed_raw = _read_private(signed_manifest_path)
    operation, operation_raw = _read_private(signing_operation_path)
    manifest = context["manifest"]
    manifest_raw = context["manifest_raw"]
    statement = authorization_statement(
        manifest, hashlib.sha256(manifest_raw).hexdigest()
    )
    statement_sha256 = hashlib.sha256(statement.encode()).hexdigest()
    authorization = signed.get("authorization", {})
    implementation = _implementation(repository_root)
    failures = validate_signed_manifest(
        signed,
        source_manifest=manifest,
        source_manifest_raw=manifest_raw,
        source_preflight_raw=context["preflight_raw"],
        mentor_identity=context["mentor"],
        authorization_id=str(authorization.get("authorization_id", "")),
        authorization_statement_sha256=statement_sha256,
        implementation=implementation,
    )
    failures.extend(
        _validate_operation(
            operation,
            operation_raw=operation_raw,
            signed_manifest=signed,
            signed_manifest_path=signed_manifest_path,
            signed_manifest_raw=signed_raw,
            implementation=implementation,
        )
    )
    passed = not failures
    report = {
        "schema_version": GATE_SCHEMA,
        "passed": passed,
        "failure_reasons": list(dict.fromkeys(failures)),
        "state": (
            "outcome_sensitive_mentor_advice_verified_infrastructure_rebind_required"
            if passed
            else "blocked_outcome_sensitive_mentor_advice_verification"
        ),
        "checked_at": datetime.now(timezone.utc).astimezone().isoformat(),
        "source_binding": {
            "candidate_manifest": _artifact(candidate_manifest_path),
            "candidate_preflight": _artifact(candidate_preflight_path),
            "signed_manifest": {
                **_artifact(signed_manifest_path),
                "canonical_sha256": signed.get("manifest_sha256"),
            },
            "signing_operation": _artifact(signing_operation_path),
        },
        "authorization": {
            "authorization_id": authorization.get("authorization_id"),
            "statement_sha256": statement_sha256,
            "exact_statement_replayed": True,
        },
        "inventory": {
            "expected_signature_count": 180,
            "verified_signature_count": 180 if passed else 0,
            "participant_count": 20,
            "treatment_task_count": 9,
            "baseline_advice_count": 0,
            "control_advice_count": 0,
            "prompt_copy_count": 0,
            "ground_truth_copy_count": 0,
            "action_or_pattern_identifier_copy_count": 0,
        },
        "implementation": implementation,
        "readiness": {
            "candidate_manifest_frozen": True,
            "owner_signing_authorization_bound": passed,
            "mentor_signatures_complete": passed,
            "all_signatures_independently_verified": passed,
            "infrastructure_rebound": False,
            "controlled_experiment_execution_ready": False,
        },
        "execution_boundary": {
            "verification_only": True,
            "token_login_performed": False,
            "pkcs11_session_opened": False,
            "runtime_projection_performed": False,
            "provider_credential_read": False,
            "provider_api_call_performed": False,
            "model_invocation_performed": False,
            "agent_execution_performed": False,
            "backend_fact_append_performed": False,
            "ledger_append_performed": False,
            "execution_authorization_issued_or_consumed": False,
            "effectiveness_claim_authorized": False,
            "si13_maturity_upgrade_authorized": False,
        },
    }
    report["report_sha256"] = canonical_sha256(report)
    parent = output_root.resolve().parent
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    parent.chmod(0o700)
    staging = Path(tempfile.mkdtemp(prefix=f".{output_root.name}.", dir=parent))
    staging.chmod(0o700)
    try:
        write_private_json(
            staging / "outcome-sensitive-treatment-advice-gate-report.json",
            report,
        )
        os.rename(staging, output_root)
        _fsync_directory(parent)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return report


def _validate_operation(
    operation: dict[str, Any],
    *,
    operation_raw: bytes,
    signed_manifest: dict[str, Any],
    signed_manifest_path: Path,
    signed_manifest_raw: bytes,
    implementation: dict[str, str],
) -> list[str]:
    del operation_raw
    failures: list[str] = []
    body = {key: item for key, item in operation.items() if key != "report_sha256"}
    expected_manifest = {
        "path": str(signed_manifest_path.resolve()),
        "sha256": hashlib.sha256(signed_manifest_raw).hexdigest(),
        "canonical_sha256": signed_manifest.get("manifest_sha256"),
    }
    if not (
        operation.get("schema_version")
        == ("j1-qualification-outcome-sensitive-treatment-advice-signing-operation:v1")
        and operation.get("passed") is True
        and operation.get("failure_reasons") == []
        and operation.get("state")
        == "outcome_sensitive_mentor_advice_signed_gate_required"
        and operation.get("signed_manifest") == expected_manifest
        and operation.get("authorization") == signed_manifest.get("authorization")
        and operation.get("inventory") == signed_manifest.get("inventory")
        and operation.get("implementation") == implementation
        and operation.get("pkcs11_session_count") == 1
        and operation.get("pin_recorded") is False
        and operation.get("private_key_exported") is False
        and operation.get("report_sha256") == canonical_sha256(body)
    ):
        failures.append("outcome_advice_signing_operation_invalid")
    return failures


def _read_private(path: Path) -> tuple[dict[str, Any], bytes]:
    if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o077:
        raise ValueError(f"private JSON artifact invalid: {path}")
    raw = path.read_bytes()
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError(f"JSON artifact must be object: {path}")
    return value, raw


def _artifact(path: Path) -> dict[str, str]:
    return {
        "path": str(path.resolve()),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-manifest", type=Path, required=True)
    parser.add_argument("--candidate-preflight", type=Path, required=True)
    parser.add_argument("--signed-manifest", type=Path, required=True)
    parser.add_argument("--signing-operation", type=Path, required=True)
    parser.add_argument("--protocol", type=Path, required=True)
    parser.add_argument("--task-fixture", type=Path, required=True)
    parser.add_argument("--reviewed-assignment", type=Path, required=True)
    parser.add_argument("--assignment-gate", type=Path, required=True)
    parser.add_argument("--mentor-plan", type=Path, required=True)
    parser.add_argument("--mentor-identity", type=Path, required=True)
    parser.add_argument("--mentor-identity-gate", type=Path, required=True)
    parser.add_argument(
        "--repository-root", type=Path, default=Path(__file__).parents[1]
    )
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    report = run_gate(
        candidate_manifest_path=args.candidate_manifest,
        candidate_preflight_path=args.candidate_preflight,
        signed_manifest_path=args.signed_manifest,
        signing_operation_path=args.signing_operation,
        protocol_path=args.protocol,
        task_fixture_path=args.task_fixture,
        reviewed_assignment_path=args.reviewed_assignment,
        assignment_gate_path=args.assignment_gate,
        mentor_plan_path=args.mentor_plan,
        mentor_identity_path=args.mentor_identity,
        mentor_identity_gate_path=args.mentor_identity_gate,
        repository_root=args.repository_root,
        output_root=args.output_root,
    )
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
