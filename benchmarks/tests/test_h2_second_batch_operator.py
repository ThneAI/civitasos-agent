from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path


AGENT_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = AGENT_ROOT / "benchmarks" / "h2_second_batch_operator.sh"


def test_h2_second_batch_operator_shell_is_valid() -> None:
    subprocess.run(["bash", "-n", str(SCRIPT)], check=True)


def test_h2_second_batch_operator_status_reports_time_guard(tmp_path: Path) -> None:
    first_report = tmp_path / "first.json"
    first_report.write_text(
        json.dumps(
            {
                "schema_version": "h2-multi-agent-backend-continuity-gate:v1",
                "owner_id": "owner-a",
                "evidence_class": "controlled_pilot_backend",
                "passed": True,
                "worker_summaries": {
                    "alpha": {
                        "task_id": "task-a",
                        "observed_at": "2099-06-07T14:18:32.717657558+00:00",
                    },
                    "beta": {
                        "task_id": "task-b",
                        "observed_at": "2099-06-07T14:18:32.733993090+00:00",
                    },
                    "gamma": {
                        "task_id": "task-c",
                        "observed_at": "2099-06-07T14:18:32.741061762+00:00",
                    },
                },
            }
        ),
        encoding="utf-8",
    )
    env = os.environ.copy()
    env.update(
        {
            "H2_FIRST_SOURCE_REPORT": str(first_report),
            "H2_SECOND_OWNER_ID": "owner-b",
            "H2_SECOND_RUN_ROOT": str(tmp_path / "second"),
            "H2_AGGREGATE_ROOT": str(tmp_path / "aggregate"),
        }
    )

    completed = subprocess.run(
        [str(SCRIPT), "status"],
        check=True,
        capture_output=True,
        env=env,
        text=True,
    )

    assert "time_state=WAITING" in completed.stdout
    assert "first_owner=owner-a" in completed.stdout
    assert "second_owner=owner-b" in completed.stdout
    assert "second_source=missing" in completed.stdout


def test_h2_second_batch_operator_status_reads_h3_proposal_surface(
    tmp_path: Path,
) -> None:
    first_report = tmp_path / "first.json"
    first_report.write_text(
        json.dumps(
            {
                "owner_id": "owner-a",
                "worker_summaries": {
                    "alpha": {
                        "observed_at": "2020-06-07T14:18:32.717657558+00:00",
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    aggregate = tmp_path / "aggregate"
    aggregate.mkdir()
    (aggregate / "h3_read_only_goal_proposal_gate.json").write_text(
        json.dumps({"passed": True, "proposal_surface": {"proposal_count": 2}}),
        encoding="utf-8",
    )
    env = os.environ.copy()
    env.update(
        {
            "H2_FIRST_SOURCE_REPORT": str(first_report),
            "H2_SECOND_OWNER_ID": "owner-b",
            "H2_SECOND_RUN_ROOT": str(tmp_path / "second"),
            "H2_AGGREGATE_ROOT": str(aggregate),
        }
    )

    completed = subprocess.run(
        [str(SCRIPT), "status"],
        check=True,
        capture_output=True,
        env=env,
        text=True,
    )

    assert "h3_proposals=present passed=True proposal_count=2" in completed.stdout
