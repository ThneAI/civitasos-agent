"""Validate the authorized J1-D mentor identity provisioning chain."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from benchmarks.j1.controlled_comparison import write_private_json
from benchmarks.j1.qualification_mentor_identity import (
    validate_mentor_identity_profile,
)
from benchmarks.j1_qualification_mentor_identity_preflight import (
    validate_mentor_identity_plan,
)


GATE_SCHEMA = "j1-qualification-mentor-identity-gate:v1"
CONTRACT_SOURCE = Path(__file__).parent / "j1" / "qualification_mentor_identity.py"
OPERATION_SOURCE = Path(__file__).parent / "j1_qualification_mentor_identity.py"
GATE_SOURCE = Path(__file__)


def run_gate(
    *,
    plan_path: Path,
    preflight_path: Path,
    mentor_identity_path: Path,
    operation_report_path: Path,
    reviewed_design_path: Path,
    design_gate_path: Path,
    reviewer_profile_path: Path,
    participant_provisioning_report_path: Path,
    output_path: Path,
) -> dict[str, Any]:
    failures: list[str] = []
    paths = {
        "plan": plan_path,
        "preflight": preflight_path,
        "mentor_identity": mentor_identity_path,
        "operation_report": operation_report_path,
        "reviewed_design": reviewed_design_path,
        "design_gate": design_gate_path,
        "reviewer_identity": reviewer_profile_path,
        "participant_provisioning_report": participant_provisioning_report_path,
    }
    loaded = {
        name: _read_private(path, f"{name}_unreadable", failures)
        for name, path in paths.items()
    }
    if not failures:
        plan, plan_raw = loaded["plan"]
        profile, profile_raw = loaded["mentor_identity"]
        operation, _ = loaded["operation_report"]
        preflight, _ = loaded["preflight"]
        failures.extend(validate_mentor_identity_plan(plan))
        failures.extend(validate_mentor_identity_profile(profile, plan=plan))
        expected_implementation = {
            "agent_revision": profile.get("implementation", {}).get("agent_revision"),
            "contract_source_sha256": hashlib.sha256(
                CONTRACT_SOURCE.read_bytes()
            ).hexdigest(),
            "operation_source_sha256": hashlib.sha256(
                OPERATION_SOURCE.read_bytes()
            ).hexdigest(),
            "gate_source_sha256": hashlib.sha256(GATE_SOURCE.read_bytes()).hexdigest(),
        }
        if profile.get("implementation") != expected_implementation:
            failures.append("mentor_identity_implementation_binding_invalid")
        expected_sources = {
            "reviewed_design": _artifact(
                reviewed_design_path, loaded["reviewed_design"][1]
            ),
            "design_gate": _artifact(design_gate_path, loaded["design_gate"][1]),
            "reviewer_identity": _artifact(
                reviewer_profile_path, loaded["reviewer_identity"][1]
            ),
            "participant_provisioning_report": _artifact(
                participant_provisioning_report_path,
                loaded["participant_provisioning_report"][1],
            ),
        }
        if preflight.get("source_artifacts") != expected_sources:
            failures.append("mentor_identity_preflight_source_binding_invalid")
        if not (
            operation.get("passed") is True
            and operation.get("state")
            == "mentor_identity_provisioned_advice_authorization_required"
            and operation.get("mentor_identity", {}).get("path")
            == str(mentor_identity_path.resolve())
            and operation.get("mentor_identity", {}).get("sha256")
            == hashlib.sha256(profile_raw).hexdigest()
            and operation.get("mentor_identity", {}).get("canonical_sha256")
            == profile.get("profile_sha256")
            and operation.get("source_artifacts") == expected_sources
            and operation.get("authorization", {}).get("statement_sha256")
            == profile.get("source_binding", {}).get("owner_statement_sha256")
            and profile.get("source_binding", {}).get(
                "provisioning_plan_artifact_sha256"
            )
            == hashlib.sha256(plan_raw).hexdigest()
        ):
            failures.append("mentor_identity_operation_binding_invalid")
    failures = list(dict.fromkeys(failures))
    passed = not failures
    profile = loaded["mentor_identity"][0]
    report = {
        "schema_version": GATE_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "mentor_identity_sha256": profile.get("profile_sha256"),
        "mentor_id": profile.get("mentor", {}).get("mentor_id"),
        "mentor_did": profile.get("mentor", {}).get("did"),
        "artifacts": {
            name: _artifact(path, loaded[name][1]) for name, path in paths.items()
        },
        "readiness": {
            "mentor_identity_provisioned": passed,
            "mentor_identity_bound": passed,
            "treatment_advice_signed": False,
            "executable_harness_ready": False,
            "provider_broker_ready": False,
            "controlled_experiment_execution_ready": False,
        },
        "execution_boundary": {
            "identity_validation_only": True,
            "treatment_advice_signing_allowed": False,
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
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--preflight", type=Path, required=True)
    parser.add_argument("--mentor-identity", type=Path, required=True)
    parser.add_argument("--operation-report", type=Path, required=True)
    parser.add_argument("--reviewed-design", type=Path, required=True)
    parser.add_argument("--design-gate", type=Path, required=True)
    parser.add_argument("--reviewer-profile", type=Path, required=True)
    parser.add_argument("--participant-provisioning-report", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = run_gate(
        plan_path=args.plan,
        preflight_path=args.preflight,
        mentor_identity_path=args.mentor_identity,
        operation_report_path=args.operation_report,
        reviewed_design_path=args.reviewed_design,
        design_gate_path=args.design_gate,
        reviewer_profile_path=args.reviewer_profile,
        participant_provisioning_report_path=args.participant_provisioning_report,
        output_path=args.output,
    )
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
