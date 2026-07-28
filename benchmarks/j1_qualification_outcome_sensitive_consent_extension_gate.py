"""Validate all 40 signed outcome-sensitive J1-D participant consents."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from benchmarks.j1.controlled_comparison import canonical_sha256, write_private_json
from benchmarks.j1.qualification_outcome_sensitive_consent_extension import (
    authorization_statement,
    validate_consent_extension_plan,
)
from benchmarks.j1_qualification_outcome_sensitive_consent_extension_sign import (
    _artifact,
    _implementation,
    _read_private,
    _validate_frozen_sources,
    _validate_preflight,
    validate_signed_manifest,
)


GATE_SCHEMA = "j1-qualification-outcome-sensitive-consent-gate:v1"


def run_gate(
    *,
    plan_path: Path,
    preflight_path: Path,
    signed_manifest_path: Path,
    signing_operation_path: Path,
    repository_root: Path,
    output_path: Path,
) -> dict[str, Any]:
    """Replay the complete signed set without opening a token session."""
    if output_path.exists():
        raise FileExistsError(f"outcome consent Gate output exists: {output_path}")
    plan, plan_raw = _read_private(plan_path)
    preflight, preflight_raw = _read_private(preflight_path)
    manifest, manifest_raw = _read_private(signed_manifest_path)
    operation, operation_raw = _read_private(signing_operation_path)
    failures = validate_consent_extension_plan(plan)
    signature_failures: list[str] = []
    plan_raw_sha = hashlib.sha256(plan_raw).hexdigest()
    statement = authorization_statement(plan, plan_raw_sha)
    statement_sha = hashlib.sha256(statement.encode()).hexdigest()
    try:
        _validate_preflight(
            plan=plan,
            plan_path=plan_path,
            plan_raw=plan_raw,
            preflight=preflight,
            expected_statement=statement,
            expected_statement_sha=statement_sha,
        )
        _validate_frozen_sources(plan=plan, preflight=preflight)
    except (KeyError, OSError, ValueError, TypeError, json.JSONDecodeError) as error:
        failures.append(
            f"outcome_consent_source_chain_invalid:{type(error).__name__}"
        )
    authorization = manifest.get("authorization", {})
    if authorization.get("statement_sha256") != statement_sha:
        failures.append("outcome_consent_authorization_binding_invalid")
    implementation = _implementation(repository_root)
    try:
        signature_failures = validate_signed_manifest(
            manifest,
            plan=plan,
            plan_raw=plan_raw,
            preflight_raw=preflight_raw,
            authorization_id=str(authorization.get("authorization_id", "")),
            authorization_statement_sha256=str(
                authorization.get("statement_sha256", "")
            ),
            implementation=implementation,
        )
    except (KeyError, OSError, ValueError, TypeError, json.JSONDecodeError) as error:
        signature_failures = [
            f"outcome_consent_validation_error:{type(error).__name__}"
        ]
    failures.extend(signature_failures)
    expected_manifest = {
        **_artifact(signed_manifest_path),
        "canonical_sha256": manifest.get("manifest_sha256"),
    }
    operation_body = {
        key: item for key, item in operation.items() if key != "report_sha256"
    }
    if not (
        operation.get("passed") is True
        and operation.get("failure_reasons") == []
        and operation.get("state")
        == "outcome_sensitive_participant_consents_signed_gate_required"
        and operation.get("plan") == _artifact(plan_path)
        and operation.get("preflight") == _artifact(preflight_path)
        and operation.get("signed_manifest") == expected_manifest
        and operation.get("authorization") == authorization
        and operation.get("inventory") == manifest.get("inventory")
        and operation.get("pkcs11_boundary", {}).get("single_session_login") is True
        and operation.get("pkcs11_boundary", {}).get(
            "distinct_participant_signatures"
        )
        == 40
        and operation.get("pkcs11_boundary", {}).get("pin_recorded") is False
        and operation.get("pkcs11_boundary", {}).get("private_key_exported") is False
        and operation.get("execution_boundary") == manifest.get("execution_boundary")
        and operation.get("implementation") == implementation
        and operation.get("report_sha256") == canonical_sha256(operation_body)
    ):
        failures.append("outcome_consent_signing_operation_binding_invalid")
    failures = list(dict.fromkeys(failures))
    passed = not failures
    report = {
        "schema_version": GATE_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "state": (
            "outcome_sensitive_participant_consents_complete_"
            "downstream_rebind_required"
            if passed
            else "outcome_sensitive_participant_consent_gate_failed"
        ),
        "signed_manifest_sha256": manifest.get("manifest_sha256"),
        "signing_id": manifest.get("signing_id"),
        "inventory": manifest.get("inventory", {}),
        "signature_verification": {
            "expected": 40,
            "verified": 40 if passed else 0,
            "failure_count": len(signature_failures),
        },
        "artifacts": {
            "plan": _artifact(plan_path),
            "preflight": _artifact(preflight_path),
            "signed_manifest": {
                "path": str(signed_manifest_path.resolve()),
                "sha256": hashlib.sha256(manifest_raw).hexdigest(),
            },
            "signing_operation": {
                "path": str(signing_operation_path.resolve()),
                "sha256": hashlib.sha256(operation_raw).hexdigest(),
            },
        },
        "readiness": {
            "outcome_sensitive_materials_reviewed_frozen": passed,
            "participant_consent_extensions_complete": passed,
            "operative_protocol_evaluator_ready": False,
            "roster_rebound": False,
            "assignment_rebound": False,
            "mentor_advice_signed": False,
            "infrastructure_rebound": False,
            "provider_admission_ready": False,
            "controlled_experiment_execution_ready": False,
        },
        "next_blocker": (
            "outcome_sensitive_roster_assignment_advice_"
            "infrastructure_rebind_required"
        ),
        "execution_boundary": {
            "consent_extension_validation_only": True,
            "provider_api_call_allowed": False,
            "model_invocation_allowed": False,
            "agent_execution_allowed": False,
            "container_execution_allowed": False,
            "backend_fact_append_allowed": False,
            "ledger_append_allowed": False,
            "execution_authorization_issue_or_consume_allowed": False,
            "effectiveness_claim_allowed": False,
            "si13_maturity_upgrade_allowed": False,
        },
        "implementation": implementation,
    }
    report["report_sha256"] = canonical_sha256(report)
    write_private_json(output_path, report)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--preflight", type=Path, required=True)
    parser.add_argument("--signed-manifest", type=Path, required=True)
    parser.add_argument("--signing-operation", type=Path, required=True)
    parser.add_argument(
        "--repository-root",
        type=Path,
        default=Path(__file__).parents[1],
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = run_gate(
        plan_path=args.plan,
        preflight_path=args.preflight,
        signed_manifest_path=args.signed_manifest,
        signing_operation_path=args.signing_operation,
        repository_root=args.repository_root,
        output_path=args.output,
    )
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
