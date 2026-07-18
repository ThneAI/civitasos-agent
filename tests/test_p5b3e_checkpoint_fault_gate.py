import json
import sys
from pathlib import Path

import pytest

from scripts.p5b3e_checkpoint_fault_gate import (
    KILL_POINTS,
    REJECTION_CASES,
    SUMMARY_SCHEMA,
    execute_local_matrix,
    validate_local_run_root,
)


WORKER = Path(__file__).parent / "fixtures" / "p5b3e_synthetic_worker.py"


def test_local_matrix_sigkills_and_recovers_every_durable_boundary(tmp_path: Path) -> None:
    run_root = tmp_path / "p5b3e-local"

    summary = execute_local_matrix(
        [sys.executable, str(WORKER)],
        run_root,
        timeout=5,
    )

    assert summary["schema_version"] == SUMMARY_SCHEMA
    assert summary["passed"] is True
    assert summary["kill_points"] == list(KILL_POINTS)
    assert len(summary["cases"]) == len(KILL_POINTS)
    assert all(case["first_exit_code"] == -9 for case in summary["cases"])
    assert all(case["restart_exit_code"] == 0 for case in summary["cases"])
    assert len({case["activation_fact_id"] for case in summary["cases"]}) == 1
    assert summary["network_used"] is False
    assert summary["real_tls_executed"] is False
    assert summary["p4_soak_resources_used"] is False
    assert [case["rejection_case"] for case in summary["rejection_cases"]] == list(
        REJECTION_CASES
    )
    assert all(case["passed"] is True for case in summary["rejection_cases"])
    assert json.loads((run_root / "summary.json").read_text()) == summary


def test_local_matrix_fails_when_worker_exits_before_target(tmp_path: Path) -> None:
    with pytest.raises(RuntimeError, match="before runtime_intent_durable"):
        execute_local_matrix(
            [sys.executable, "-c", "pass"],
            tmp_path / "failed-local",
            fault_points=("runtime_intent_durable",),
            timeout=2,
        )


def test_local_gate_refuses_p4_soak_paths(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="must not overlap"):
        validate_local_run_root(tmp_path / "p4eg-active" / "stage-24h")


def test_local_gate_refuses_nonempty_output(tmp_path: Path) -> None:
    run_root = tmp_path / "existing"
    run_root.mkdir()
    (run_root / "evidence.json").write_text("{}")

    with pytest.raises(ValueError, match="must be empty"):
        validate_local_run_root(run_root)


def test_local_gate_refuses_file_output_and_nonpositive_timeout(tmp_path: Path) -> None:
    output = tmp_path / "output"
    output.write_text("not a directory")
    with pytest.raises(ValueError, match="must be a directory"):
        validate_local_run_root(output)

    with pytest.raises(ValueError, match="must be positive"):
        execute_local_matrix(
            [sys.executable, str(WORKER)],
            tmp_path / "timeout",
            fault_points=("runtime_intent_durable",),
            timeout=0,
        )
