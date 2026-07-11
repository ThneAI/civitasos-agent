#!/usr/bin/env python3
"""Run repeated single-node Private Beta recovery and identity drills."""

from __future__ import annotations

import argparse
import json
import math
import os
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PYTHON = ROOT / ".venv" / "bin" / "python"
DRILL = ROOT / "scripts" / "beta_runtime_identity_task_smoke.py"
RECOVERY_DRILLS = [
    ROOT / "scripts" / "p1_fact_outbox_recovery_smoke.py",
    ROOT / "scripts" / "p1_settlement_outbox_recovery_smoke.py",
]
RESTART_POINTS = ("posted", "claimed", "delivered")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rounds", type=int, default=10)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--recovery-every", type=int, default=10)
    args = parser.parse_args()
    if args.rounds < 1:
        parser.error("--rounds must be at least 1")
    if args.recovery_every < 0:
        parser.error("--recovery-every must be non-negative")

    started = time.monotonic()
    records = []
    recovery_records = []
    for round_number in range(1, args.rounds + 1):
        round_started = time.monotonic()
        restart_point = RESTART_POINTS[(round_number - 1) % len(RESTART_POINTS)]
        completed = subprocess.run(
            [str(PYTHON), str(DRILL)],
            cwd=ROOT,
            capture_output=True,
            text=True,
            env=os.environ | {"CIVITASOS_SOAK_RESTART_POINT": restart_point},
        )
        if completed.returncode != 0:
            result = {
                "schema_version": "private-beta-soak:v1",
                "passed": False,
                "completed_rounds": len(records),
                "failed_round": round_number,
                "stderr": completed.stderr[-4000:],
            }
            _emit(result, args.output)
            return 1
        record = json.loads(completed.stdout)
        required = (
            "restart_recovery",
            "failed_delivery_retry",
            "challenge_window",
            "audit_continuity",
            "old_token_invalidated_after_rotation",
            "token_invalidated_after_revocation",
            "emergency_revocation",
        )
        if record.get("passed") is not True or not all(record.get(key) is True for key in required):
            raise RuntimeError(f"round {round_number} omitted required soak assertions")
        records.append(
            {
                "round": round_number,
                "task_id": record["task_id"],
                "receipt_hash": record["final_receipt_hash"],
                "restart_point": record["restart_point"],
                "backend_rss_kib": record["backend_rss_kib"],
                "backend_fd_count": record["backend_fd_count"],
                "state_bytes": record["state_bytes"],
                "duration_seconds": round(time.monotonic() - round_started, 3),
            }
        )
        if args.recovery_every and round_number % args.recovery_every == 0:
            for drill in RECOVERY_DRILLS:
                recovery = subprocess.run(
                    [str(PYTHON), str(drill)],
                    cwd=ROOT,
                    capture_output=True,
                    text=True,
                )
                if recovery.returncode != 0:
                    _emit({
                        "schema_version": "private-beta-soak:v1",
                        "passed": False,
                        "completed_rounds": len(records),
                        "failed_recovery_drill": drill.name,
                        "stderr": recovery.stderr[-4000:],
                    }, args.output)
                    return 1
                recovery_records.append({"after_round": round_number, "drill": drill.name, "passed": True})

    durations = [record["duration_seconds"] for record in records]
    result = {
        "schema_version": "private-beta-soak:v1",
        "passed": True,
        "requested_rounds": args.rounds,
        "completed_rounds": len(records),
        "duration_seconds": round(time.monotonic() - started, 3),
        "latency_seconds": {
            "p50": percentile(durations, 0.50),
            "p95": percentile(durations, 0.95),
            "p99": percentile(durations, 0.99),
        },
        "resource_maxima": {
            "backend_rss_kib": max(record["backend_rss_kib"] for record in records),
            "backend_fd_count": max(record["backend_fd_count"] for record in records),
            "state_bytes": max(record["state_bytes"] for record in records),
        },
        "coverage": [
            "restart_recovery",
            "challenge_window",
            "failed_delivery_retry",
            "audit_continuity",
            "credential_rotation",
            "signed_revocation",
            "emergency_revocation",
            "receipt_and_evidence_projection",
            "restart_point_matrix",
            "resource_observation",
        ],
        "rounds": records,
        "recovery_drills": recovery_records,
        "production_claimed": False,
    }
    _emit(result, args.output)
    return 0


def percentile(values: list[float], quantile: float) -> float:
    ordered = sorted(values)
    index = max(0, math.ceil(len(ordered) * quantile) - 1)
    return ordered[index]


def _emit(result: dict, output: Path | None) -> None:
    rendered = json.dumps(result, indent=2) + "\n"
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered)
    print(rendered, end="")


if __name__ == "__main__":
    raise SystemExit(main())
