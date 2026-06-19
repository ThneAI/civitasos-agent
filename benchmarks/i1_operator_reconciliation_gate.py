"""Reconcile I.1 read-only verifier matrix results into a bounded I.1 decision."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from benchmarks.i_gate_evidence import artifact_ref, check, object_value, read_json_object, write_json_object

SCHEMA_VERSION = "i1-operator-reconciliation-gate:v1"


def run_gate(*, matrix_report_path: Path, output: Path) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    matrix = read_json_object(matrix_report_path)
    matrix_checks = object_value(matrix.get("checks"))
    metrics = object_value(matrix.get("metrics"))
    readiness = object_value(matrix.get("readiness"))

    check(
        checks,
        failures,
        "matrix_report_passed",
        matrix.get("schema_version") == "i1-read-only-verifier-matrix-gate:v1"
        and matrix.get("passed") is True,
    )
    for name in (
        "all_verdict_signatures_verified",
        "all_positive_cases_accepted_by_quorum",
        "all_negative_controls_rejected_by_quorum",
        "quorum_provider_independence_sufficient",
        "proposer_excluded_from_all_quorums",
        "hash_drift_negative_control_rejected",
        "replay_negative_control_rejected",
        "provider_homogeneity_negative_control_rejected",
        "identity_conflict_negative_control_rejected",
    ):
        check(checks, failures, name, matrix_checks.get(name) is True)
    check(
        checks,
        failures,
        "matrix_ready_for_reconciliation",
        readiness.get("i1_b_c_reconciliation_input_ready") is True,
    )
    check(
        checks,
        failures,
        "quorum_metrics_complete",
        metrics.get("positive_cases_accepted") == 4
        and metrics.get("negative_controls_rejected") == 7
        and metrics.get("signature_verified_count") == 55,
    )

    passed = bool(checks) and all(checks.values()) and not failures
    report = {
        "schema_version": SCHEMA_VERSION,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "source_artifacts": {"matrix_report": artifact_ref(matrix_report_path)},
        "operator_reconciliation": {
            "decision": "i1_read_only_verifier_consensus_passed" if passed else "blocked_i1_reconciliation",
            "reason": (
                "Five registered identities produced signed read-only verdicts; "
                "default quorum excluded the proposer; all positive fixtures were "
                "accepted and all negative controls were rejected."
                if passed
                else "I.1 verifier matrix did not satisfy quorum or control requirements."
            ),
            "positive_cases_accepted": metrics.get("positive_cases_accepted", 0),
            "negative_controls_rejected": metrics.get("negative_controls_rejected", 0),
            "signature_verified_count": metrics.get("signature_verified_count", 0),
        },
        "readiness": {
            "state": "i1_passed_i2_request_ready" if passed else "blocked_i1_operator_reconciliation",
            "i1_complete": passed,
            "i2_gate_request_ready": passed,
            "i2_execution_allowed": False,
        },
        "boundary": {
            "operator_reconciliation_recording_allowed": True,
            "state_mutation_allowed": False,
            "external_side_effect_allowed": False,
            "i2_command_allowed": False,
            "production_transition_allowed": False,
        },
        "non_claims": [
            "i1_reconciliation_does_not_execute_i2",
            "i1_reconciliation_does_not_command_external_agents",
            "i1_reconciliation_does_not_unlock_production",
        ],
    }
    write_json_object(output, report)
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--matrix-report", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    report = run_gate(
        matrix_report_path=Path(args.matrix_report).resolve(),
        output=Path(args.output).resolve(),
    )
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    raise SystemExit(0 if report["passed"] else 2)


if __name__ == "__main__":
    main()
