"""Create a non-executable I.2 external Agent command/isolation gate request."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "i2-external-command-gate-request:v1"


def run_gate(*, i1_reconciliation_path: Path, output: Path) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    i1 = _read_json(i1_reconciliation_path)
    readiness = _object(i1.get("readiness"))
    _check(
        checks,
        failures,
        "i1_reconciliation_passed",
        i1.get("schema_version") == "i1-operator-reconciliation-gate:v1"
        and i1.get("passed") is True,
    )
    _check(
        checks,
        failures,
        "i1_allows_i2_request_only",
        readiness.get("i1_complete") is True
        and readiness.get("i2_gate_request_ready") is True
        and readiness.get("i2_execution_allowed") is False,
    )
    source = _artifact_ref(i1_reconciliation_path)
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
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return report


def _check(
    checks: dict[str, bool],
    failures: list[str],
    name: str,
    passed: bool,
) -> None:
    checks[name] = bool(passed)
    if not passed:
        failures.append(name)


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def _object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _artifact_ref(path: Path) -> dict[str, str]:
    return {"path": str(path.resolve()), "sha256": _sha256(path)}


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
