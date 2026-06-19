from __future__ import annotations

import json
from pathlib import Path

from benchmarks.i1_operator_reconciliation_gate import run_gate as run_i1_reconciliation
from benchmarks.i2_external_command_request_gate import run_gate as run_i2_request


def test_i1_reconciliation_and_i2_request_pass_without_execution(tmp_path: Path) -> None:
    matrix = _write_matrix(tmp_path, passed=True)
    i1 = run_i1_reconciliation(
        matrix_report_path=matrix,
        output=tmp_path / "i1_reconciliation.json",
    )

    assert i1["passed"] is True
    assert i1["readiness"]["i1_complete"] is True
    assert i1["readiness"]["i2_gate_request_ready"] is True
    assert i1["readiness"]["i2_execution_allowed"] is False

    i2 = run_i2_request(
        i1_reconciliation_path=tmp_path / "i1_reconciliation.json",
        output=tmp_path / "i2_request.json",
    )

    assert i2["passed"] is True
    assert i2["readiness"]["i2_gate_requested"] is True
    assert i2["readiness"]["i2_execution_allowed"] is False
    assert i2["boundary"]["external_agent_command_allowed"] is False


def test_i1_reconciliation_blocks_failed_matrix(tmp_path: Path) -> None:
    matrix = _write_matrix(tmp_path, passed=False)

    report = run_i1_reconciliation(
        matrix_report_path=matrix,
        output=tmp_path / "i1_reconciliation.json",
    )

    assert report["passed"] is False
    assert report["checks"]["matrix_report_passed"] is False


def _write_matrix(tmp_path: Path, *, passed: bool) -> Path:
    checks = {
        "all_verdict_signatures_verified": True,
        "all_positive_cases_accepted_by_quorum": True,
        "all_negative_controls_rejected_by_quorum": True,
        "quorum_provider_independence_sufficient": True,
        "proposer_excluded_from_all_quorums": True,
        "hash_drift_negative_control_rejected": True,
        "replay_negative_control_rejected": True,
        "provider_homogeneity_negative_control_rejected": True,
        "identity_conflict_negative_control_rejected": True,
    }
    path = tmp_path / "matrix.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": "i1-read-only-verifier-matrix-gate:v1",
                "passed": passed,
                "checks": checks,
                "metrics": {
                    "positive_cases_accepted": 4,
                    "negative_controls_rejected": 7,
                    "signature_verified_count": 55,
                },
                "readiness": {"i1_b_c_reconciliation_input_ready": True},
            }
        ),
        encoding="utf-8",
    )
    return path
