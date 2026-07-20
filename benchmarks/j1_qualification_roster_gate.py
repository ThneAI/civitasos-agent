"""Validate a reviewed J1-D qualification roster without executing it."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from benchmarks.j1.controlled_comparison import (
    canonical_sha256,
    read_json_object,
    write_private_json,
)
from benchmarks.j1.qualification_roster import (
    validate_qualification_protocol,
    validate_roster,
)
from benchmarks.j1_qualification_admission_gate import DEFAULT_REQUEST


GATE_SCHEMA = "j1-qualification-roster-gate:v1"


def run_gate(
    *, roster_path: Path, qualification_protocol_path: Path, output_path: Path
) -> dict[str, Any]:
    failures: list[str] = []
    try:
        roster = read_json_object(roster_path)
    except (OSError, ValueError, json.JSONDecodeError):
        roster = {}
        failures.append("qualification_roster_unreadable")
    request = read_json_object(DEFAULT_REQUEST)
    try:
        protocol = read_json_object(qualification_protocol_path)
    except (OSError, ValueError, json.JSONDecodeError):
        protocol = {}
        failures.append("qualification_protocol_unreadable")
    request_hash = canonical_sha256(request)
    protocol_failures: list[str] = []
    if protocol:
        protocol_failures = validate_qualification_protocol(
            protocol, admission_request_sha256=request_hash
        )
        failures.extend(protocol_failures)
    protocol_frozen = bool(protocol) and not protocol_failures
    stack = protocol.get("frozen_stack", {})
    corpus = protocol.get("task_corpus", {})
    expected_stack = {
        "provider_id": stack.get("provider_id", ""),
        "model_id": stack.get("model_id", ""),
        "budget_id": stack.get("budget_id", ""),
        "corpus_id": corpus.get("corpus_id", ""),
        "verifier_id": stack.get("verifier_id", ""),
    }
    if roster:
        failures.extend(
            validate_roster(
                roster,
                admission_request_sha256=request_hash,
                qualification_protocol_sha256=canonical_sha256(protocol),
                expected_stack=expected_stack,
            )
        )
    passed = not failures
    report = {
        "schema_version": GATE_SCHEMA,
        "passed": passed,
        "failure_reasons": list(dict.fromkeys(failures)),
        "roster_path": str(roster_path.resolve()),
        "qualification_protocol_path": str(qualification_protocol_path.resolve()),
        "admission_request_sha256": request_hash,
        "qualification_protocol_sha256": (
            canonical_sha256(protocol) if protocol else None
        ),
        "roster_content_recorded": False,
        "roster_sha256": roster.get("roster_sha256") if roster else None,
        "participant_count": len(roster.get("participants", [])) if roster else 0,
        "readiness": {
            "state": (
                "j1d_qualification_roster_bound_authorization_required"
                if passed
                else "blocked_j1d_qualification_roster_binding"
            ),
            "real_participant_roster_bound": passed,
            "qualification_protocol_frozen": protocol_frozen,
            "single_use_authorization_issued": False,
            "controlled_experiment_execution_ready": False,
        },
        "execution_boundary": {
            "roster_validation_only": True,
            "identity_generation_allowed": False,
            "model_invocation_allowed": False,
            "agent_execution_allowed": False,
            "backend_fact_append_allowed": False,
            "ledger_append_allowed": False,
        },
    }
    write_private_json(output_path, report)
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--roster", type=Path, required=True)
    parser.add_argument("--qualification-protocol", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = run_gate(
        roster_path=args.roster,
        qualification_protocol_path=args.qualification_protocol,
        output_path=args.output,
    )
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
