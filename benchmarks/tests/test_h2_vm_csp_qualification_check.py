from __future__ import annotations

import json
from pathlib import Path

from benchmarks.h2_multi_agent_backend_continuity_gate import WORKER_CASES
from benchmarks.h2_vm_csp_qualification_check import check_qualification


def test_qualification_checker_recomputes_cycle_evidence(tmp_path: Path) -> None:
    run_root = tmp_path / "qualification"
    for name in ("preflight.json", "deployment.json", "services.json"):
        _write(run_root / name, {"passed": True})
    _write(run_root / "h2_vm_csp_smoke.json", {"passed": True})
    _write(
        run_root / "h2_vm_csp_soak.json",
        {
            "passed": True,
            "last_cycle": 2,
            "duration_seconds": 100.0,
            "restart_csp_cycles": [1],
            "restart_backend_cycles": [2],
        },
    )
    _write(run_root / "h2_vm_csp_soak_checkpoint.json", {"passed": True})
    for cycle in (1, 2):
        _write(
            run_root / "remote_agent" / f"soak_{cycle:04d}.evaluation.json",
            {
                "schema_version": "h2-vm-csp-cycle-evaluation:v1",
                "passed": True,
                "checks": {f"check_{index}": True for index in range(6)},
                "worker_summaries": {
                    worker: {
                        "agent_id": f"did:civ:{worker}",
                        "event_kind": event_kind,
                        "local_db_existed_before": False,
                    }
                    for worker, event_kind in WORKER_CASES.items()
                },
            },
        )

    report = check_qualification(
        run_root=run_root,
        agent_root=tmp_path,
        min_cycles=2,
        min_checks_per_cycle=6,
        min_duration_seconds=90,
    )

    assert report["passed"] is True
    assert report["metrics"]["evaluation_file_count"] == 2
    assert report["metrics"]["total_check_count"] == 12
    assert report["metrics"]["failed_check_count"] == 0
    assert report["metrics"]["worker_recovery_counts"] == {
        "alpha": 2,
        "beta": 2,
        "gamma": 2,
    }
    assert sorted(report["evaluation_sha256"]) == [
        "remote_agent/soak_0001.evaluation.json",
        "remote_agent/soak_0002.evaluation.json",
    ]


def test_qualification_checker_rejects_short_or_failed_evidence(tmp_path: Path) -> None:
    run_root = tmp_path / "qualification"
    for name in (
        "preflight.json",
        "deployment.json",
        "services.json",
        "h2_vm_csp_smoke.json",
        "h2_vm_csp_soak_checkpoint.json",
    ):
        _write(run_root / name, {"passed": True})
    _write(
        run_root / "h2_vm_csp_soak.json",
        {
            "passed": True,
            "last_cycle": 1,
            "duration_seconds": 5,
            "restart_csp_cycles": [],
            "restart_backend_cycles": [],
        },
    )
    _write(
        run_root / "remote_agent" / "soak_0001.evaluation.json",
        {
            "schema_version": "h2-vm-csp-cycle-evaluation:v1",
            "passed": False,
            "checks": {"identity_continuous": False},
            "worker_summaries": {},
        },
    )

    report = check_qualification(
        run_root=run_root,
        agent_root=tmp_path,
        min_cycles=2,
        min_checks_per_cycle=1,
        min_duration_seconds=10,
    )

    assert report["passed"] is False
    assert report["checks"]["minimum_cycle_count"] is False
    assert report["checks"]["all_cycle_evaluations_passed"] is False
    assert report["checks"]["minimum_duration_seconds"] is False
    assert report["checks"]["csp_restart_scheduled"] is False


def _write(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")
