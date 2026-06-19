"""Create a non-executable I.2 external Agent command/isolation gate request."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from benchmarks.i_gate_evidence import artifact_ref, check, object_value, read_json_object, write_json_object

SCHEMA_VERSION = "i2-external-command-gate-request:v1"


def run_gate(*, i1_reconciliation_path: Path, output: Path) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    i1 = read_json_object(i1_reconciliation_path)
    readiness = object_value(i1.get("readiness"))
    check(
        checks,
        failures,
        "i1_reconciliation_passed",
        i1.get("schema_version") == "i1-operator-reconciliation-gate:v1"
        and i1.get("passed") is True,
    )
    check(
        checks,
        failures,
        "i1_allows_i2_request_only",
        readiness.get("i1_complete") is True
        and readiness.get("i2_gate_request_ready") is True
        and readiness.get("i2_execution_allowed") is False,
    )
    source = artifact_ref(i1_reconciliation_path)
    request_id = "i2-request:" + source["sha256"][:20]
    passed = bool(checks) and all(checks.values()) and not failures
    report = {
        "schema_version": SCHEMA_VERSION,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "request": {
            "request_id": request_id,
            "requested_gate": "I.2 external Agent command, acceptance, and isolation",
            "source_i1_reconciliation": source,
            "requested_scope": "non_executable_gate_opening_request",
            "required_future_evidence": [
                "external_agent_registration_receipt",
                "scoped_command_authorization_request",
                "external_agent_acceptance_receipt",
                "isolation_policy_preflight",
                "command_execution_receipt",
                "rollback_or_abort_receipt",
                "operator_reconciliation",
            ],
        },
        "readiness": {
            "state": "i2_gate_request_ready_for_operator_review" if passed else "blocked_i2_gate_request",
            "i2_gate_requested": passed,
            "i2_execution_allowed": False,
            "operator_authorization_required": True,
        },
        "boundary": {
            "request_recording_allowed": True,
            "external_agent_command_allowed": False,
            "external_side_effect_allowed": False,
            "state_mutation_allowed": False,
            "production_transition_allowed": False,
        },
        "non_claims": [
            "i2_request_is_not_i2_authorization",
            "i2_request_does_not_command_external_agents",
            "i2_request_does_not_mutate_runtime_state",
            "i2_request_does_not_unlock_production",
        ],
    }
    write_json_object(output, report)
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--i1-reconciliation", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    report = run_gate(
        i1_reconciliation_path=Path(args.i1_reconciliation).resolve(),
        output=Path(args.output).resolve(),
    )
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    raise SystemExit(0 if report["passed"] else 2)


if __name__ == "__main__":
    main()
