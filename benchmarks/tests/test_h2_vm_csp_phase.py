from __future__ import annotations

from pathlib import Path

from benchmarks.h2_multi_agent_backend_continuity_gate import (
    PRIOR_EXPECTATION,
    WORKER_CASES,
)
from benchmarks.h2_restart_continuity_gate import _write_json
from benchmarks.h2_vm_csp_phase import evaluate_cycle


def test_evaluate_cycle_accepts_remote_recovery_reports(tmp_path: Path) -> None:
    identities = {
        "requester": {"agent_id": "did:civ:requester"},
        **{
            worker: {"agent_id": f"did:civ:{worker}"}
            for worker in WORKER_CASES
        },
    }
    tasks = {worker: f"task-{worker}" for worker in WORKER_CASES}
    _write_json(
        tmp_path / "bootstrap.json",
        {"identities": identities, "tasks": tasks},
    )

    for index, (worker, event_kind) in enumerate(WORKER_CASES.items()):
        shutdown_at = f"2026-06-06T00:00:0{index}+00:00"
        _write_json(
            tmp_path / worker / "seed.json",
            {
                "pid": index + 10,
                "runtime_instance_id": f"seed-{worker}",
                "agent_id": identities[worker]["agent_id"],
                "public_key_hex": f"pk-{worker}",
                "identity_file_sha256": f"hash-{worker}",
                "identity_file_mode": 0o600,
                "shutdown_state": {"shutdown_at": shutdown_at},
            },
        )
        after = dict(PRIOR_EXPECTATION)
        after["expected_trust"] += 0.1 if worker == "alpha" else -0.1
        _write_json(
            tmp_path / worker / "recover.json",
            {
                "pid": index + 20,
                "runtime_instance_id": f"recover-{worker}",
                "agent_id": identities[worker]["agent_id"],
                "public_key_hex": f"pk-{worker}",
                "identity_file_sha256": f"hash-{worker}",
                "identity_file_mode": 0o600,
                "continuity": {"identity_continuous": True},
                "recalled": {
                    "seed": {"task_id": tasks[worker]},
                    "identity_iem_state": {"identity_id": identities[worker]["agent_id"]},
                    "relation_expectation": {"expectation": PRIOR_EXPECTATION},
                },
                "backend_outcome": {
                    "event_kind": event_kind,
                    "observed_at": f"2026-06-06T00:01:0{index}+00:00",
                },
                "consequence_applied": True,
                "relation_update": {
                    "before": PRIOR_EXPECTATION,
                    "after": after,
                },
            },
        )

    report = evaluate_cycle(tmp_path, report_name="recover")

    assert report["passed"] is True
    assert report["failure_reasons"] == []
    assert all(report["checks"].values())
