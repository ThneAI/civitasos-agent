"""Validate all 160 signed J1-D treatment advice artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from benchmarks.j1.controlled_comparison import canonical_sha256, write_private_json
from benchmarks.j1.qualification_mentor_identity import (
    validate_mentor_identity_profile,
)
from benchmarks.j1_qualification_mentor_identity_preflight import (
    validate_mentor_identity_plan,
)
from benchmarks.j1_qualification_treatment_advice import (
    _validate_batch_members,
    _validate_manifest,
    _validate_sources,
    approval_statement,
)
from benchmarks.j1_qualification_treatment_advice_sign import (
    CONTRACT_SOURCE,
    OPERATION_SOURCE,
    validate_signed_manifest,
)


GATE_SCHEMA = "j1-qualification-treatment-advice-gate:v1"
GATE_SOURCE = Path(__file__)


def run_gate(
    *,
    candidate_manifest_path: Path,
    candidate_preflight_path: Path,
    signed_manifest_path: Path,
    signing_operation_path: Path,
    reviewed_design_path: Path,
    design_gate_path: Path,
    reviewed_assignment_path: Path,
    assignment_gate_path: Path,
    mentor_plan_path: Path,
    mentor_identity_path: Path,
    mentor_identity_gate_path: Path,
    output_path: Path,
) -> dict[str, Any]:
    failures: list[str] = []
    paths = {
        "candidate_manifest": candidate_manifest_path,
        "candidate_preflight": candidate_preflight_path,
        "signed_manifest": signed_manifest_path,
        "signing_operation": signing_operation_path,
        "reviewed_design": reviewed_design_path,
        "design_gate": design_gate_path,
        "reviewed_assignment": reviewed_assignment_path,
        "assignment_gate": assignment_gate_path,
        "mentor_plan": mentor_plan_path,
        "mentor_identity": mentor_identity_path,
        "mentor_identity_gate": mentor_identity_gate_path,
    }
    loaded = {
        name: _read_private(path, f"{name}_unreadable", failures)
        for name, path in paths.items()
    }
    signature_failures: list[str] = []
    if not failures:
        source, source_raw = loaded["candidate_manifest"]
        preflight, preflight_raw = loaded["candidate_preflight"]
        signed, signed_raw = loaded["signed_manifest"]
        operation, _ = loaded["signing_operation"]
        design, design_raw = loaded["reviewed_design"]
        design_gate, design_gate_raw = loaded["design_gate"]
        assignment, assignment_raw = loaded["reviewed_assignment"]
        assignment_gate, assignment_gate_raw = loaded["assignment_gate"]
        mentor_plan, _ = loaded["mentor_plan"]
        mentor, mentor_raw = loaded["mentor_identity"]
        mentor_gate, mentor_gate_raw = loaded["mentor_identity_gate"]
        failures.extend(validate_mentor_identity_plan(mentor_plan))
        failures.extend(validate_mentor_identity_profile(mentor, plan=mentor_plan))
        try:
            _validate_sources(
                design=design,
                design_path=reviewed_design_path,
                design_raw=design_raw,
                design_gate=design_gate,
                assignment=assignment,
                assignment_path=reviewed_assignment_path,
                assignment_raw=assignment_raw,
                assignment_gate=assignment_gate,
                mentor=mentor,
                mentor_path=mentor_identity_path,
                mentor_raw=mentor_raw,
                mentor_gate=mentor_gate,
            )
            assignments = sorted(
                assignment["assignments"], key=lambda item: item["pair_id"]
            )
            tasks = sorted(
                design["treatment"]["tasks"], key=lambda item: item["task_id"]
            )
            _validate_batch_members(assignments, tasks)
            _validate_manifest(
                source,
                batch_id=source["batch_id"],
                created_at=source["created_at"],
                design=design,
                design_raw=design_raw,
                design_gate_raw=design_gate_raw,
                assignment=assignment,
                assignment_raw=assignment_raw,
                assignment_gate_raw=assignment_gate_raw,
                mentor=mentor,
                mentor_raw=mentor_raw,
                mentor_gate_raw=mentor_gate_raw,
                implementation=source["implementation"],
                assignments=assignments,
                tasks=tasks,
            )
        except (OSError, ValueError, KeyError, json.JSONDecodeError) as error:
            failures.append(f"treatment_advice_source_chain_invalid:{error}")
        source_body = {
            key: item for key, item in source.items() if key != "manifest_sha256"
        }
        if source.get("manifest_sha256") != canonical_sha256(source_body):
            failures.append("candidate_manifest_hash_invalid")
        expected_source_artifact = {
            "path": str(candidate_manifest_path.resolve()),
            "sha256": hashlib.sha256(source_raw).hexdigest(),
            "canonical_sha256": source.get("manifest_sha256"),
        }
        expected_statement = approval_statement(
            source, hashlib.sha256(source_raw).hexdigest()
        )
        expected_statement_sha256 = hashlib.sha256(
            expected_statement.encode()
        ).hexdigest()
        if not (
            preflight.get("passed") is True
            and preflight.get("state")
            == "treatment_advice_prepared_explicit_owner_signing_authorization_required"
            and preflight.get("manifest") == expected_source_artifact
            and preflight.get("inventory") == source.get("inventory")
            and preflight.get("approval_request", {}).get("required_exact_statement")
            == expected_statement
            and preflight.get("approval_request", {}).get("statement_sha256")
            == expected_statement_sha256
        ):
            failures.append("candidate_preflight_binding_invalid")
        implementation = {
            "agent_revision": signed.get("implementation", {}).get("agent_revision"),
            "contract_source_sha256": hashlib.sha256(
                CONTRACT_SOURCE.read_bytes()
            ).hexdigest(),
            "operation_source_sha256": hashlib.sha256(
                OPERATION_SOURCE.read_bytes()
            ).hexdigest(),
            "gate_source_sha256": hashlib.sha256(GATE_SOURCE.read_bytes()).hexdigest(),
        }
        authorization = signed.get("authorization", {})
        if authorization.get("statement_sha256") != preflight.get(
            "approval_request", {}
        ).get("statement_sha256"):
            failures.append("treatment_advice_authorization_binding_invalid")
        try:
            signature_failures = validate_signed_manifest(
                signed,
                source_manifest=source,
                source_manifest_raw=source_raw,
                source_preflight_raw=preflight_raw,
                mentor_identity=mentor,
                authorization_id=str(authorization.get("authorization_id") or ""),
                authorization_statement_sha256=str(
                    authorization.get("statement_sha256") or ""
                ),
                implementation=implementation,
            )
        except (
            OSError,
            ValueError,
            KeyError,
            TypeError,
            json.JSONDecodeError,
        ) as error:
            signature_failures = [
                f"signed_treatment_advice_validation_error:{type(error).__name__}"
            ]
        failures.extend(signature_failures)
        expected_boundary = signed.get("execution_boundary")
        if not (
            operation.get("passed") is True
            and operation.get("state") == "treatment_advice_signed_gate_required"
            and operation.get("source_manifest")
            == {
                "path": str(candidate_manifest_path.resolve()),
                "sha256": hashlib.sha256(source_raw).hexdigest(),
            }
            and operation.get("signed_manifest")
            == {
                "path": str(signed_manifest_path.resolve()),
                "sha256": hashlib.sha256(signed_raw).hexdigest(),
                "canonical_sha256": signed.get("manifest_sha256"),
            }
            and operation.get("authorization") == authorization
            and operation.get("inventory") == signed.get("inventory")
            and operation.get("pin_recorded") is False
            and operation.get("execution_boundary") == expected_boundary
        ):
            failures.append("treatment_advice_signing_operation_binding_invalid")
    failures = list(dict.fromkeys(failures))
    passed = not failures
    signed = loaded["signed_manifest"][0]
    report = {
        "schema_version": GATE_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "signed_manifest_sha256": signed.get("manifest_sha256"),
        "signing_id": signed.get("signing_id"),
        "inventory": signed.get("inventory", {}),
        "signature_verification": {
            "expected": 160,
            "verified": 160 if passed else 0,
            "failure_count": len(signature_failures),
        },
        "artifacts": {
            name: _artifact(path, loaded[name][1]) for name, path in paths.items()
        },
        "readiness": {
            "mentor_identity_provisioned": passed,
            "treatment_advice_signed": passed,
            "treatment_advice_bound": passed,
            "executable_harness_ready": False,
            "provider_broker_ready": False,
            "single_use_authorization_issued": False,
            "controlled_experiment_execution_ready": False,
        },
        "execution_boundary": {
            "treatment_advice_validation_only": True,
            "runtime_projection_allowed": False,
            "provider_api_call_allowed": False,
            "model_invocation_allowed": False,
            "agent_execution_allowed": False,
            "backend_fact_append_allowed": False,
            "ledger_append_allowed": False,
        },
    }
    write_private_json(output_path, report)
    return report


def _read_private(
    path: Path, failure: str, failures: list[str]
) -> tuple[dict[str, Any], bytes]:
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o077:
            raise ValueError("private artifact invalid")
        raw = path.read_bytes()
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ValueError("artifact must be JSON object")
        return value, raw
    except (OSError, ValueError, json.JSONDecodeError):
        failures.append(failure)
        return {}, b""


def _artifact(path: Path, raw: bytes) -> dict[str, str | None]:
    return {
        "path": str(path.resolve()),
        "sha256": hashlib.sha256(raw).hexdigest() if raw else None,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-manifest", type=Path, required=True)
    parser.add_argument("--candidate-preflight", type=Path, required=True)
    parser.add_argument("--signed-manifest", type=Path, required=True)
    parser.add_argument("--signing-operation", type=Path, required=True)
    parser.add_argument("--reviewed-design", type=Path, required=True)
    parser.add_argument("--design-gate", type=Path, required=True)
    parser.add_argument("--reviewed-assignment", type=Path, required=True)
    parser.add_argument("--assignment-gate", type=Path, required=True)
    parser.add_argument("--mentor-plan", type=Path, required=True)
    parser.add_argument("--mentor-identity", type=Path, required=True)
    parser.add_argument("--mentor-identity-gate", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = run_gate(
        candidate_manifest_path=args.candidate_manifest,
        candidate_preflight_path=args.candidate_preflight,
        signed_manifest_path=args.signed_manifest,
        signing_operation_path=args.signing_operation,
        reviewed_design_path=args.reviewed_design,
        design_gate_path=args.design_gate,
        reviewed_assignment_path=args.reviewed_assignment,
        assignment_gate_path=args.assignment_gate,
        mentor_plan_path=args.mentor_plan,
        mentor_identity_path=args.mentor_identity,
        mentor_identity_gate_path=args.mentor_identity_gate,
        output_path=args.output,
    )
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
