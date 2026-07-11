#!/usr/bin/env python3
"""Run repeated single-node Private Beta recovery and identity drills."""

from __future__ import annotations

import argparse
import json
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PYTHON = ROOT / ".venv" / "bin" / "python"
DRILL = ROOT / "scripts" / "beta_runtime_identity_task_smoke.py"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rounds", type=int, default=10)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.rounds < 1:
        parser.error("--rounds must be at least 1")

    started = time.monotonic()
    records = []
    for round_number in range(1, args.rounds + 1):
        round_started = time.monotonic()
        completed = subprocess.run(
            [str(PYTHON), str(DRILL)],
            cwd=ROOT,
            capture_output=True,
            text=True,
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
                "duration_seconds": round(time.monotonic() - round_started, 3),
            }
        )

    result = {
        "schema_version": "private-beta-soak:v1",
        "passed": True,
        "requested_rounds": args.rounds,
        "completed_rounds": len(records),
        "duration_seconds": round(time.monotonic() - started, 3),
        "coverage": [
            "restart_recovery",
            "challenge_window",
            "failed_delivery_retry",
            "audit_continuity",
            "credential_rotation",
            "signed_revocation",
            "emergency_revocation",
            "receipt_and_evidence_projection",
        ],
        "rounds": records,
        "production_claimed": False,
    }
    _emit(result, args.output)
    return 0


def _emit(result: dict, output: Path | None) -> None:
    rendered = json.dumps(result, indent=2) + "\n"
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered)
    print(rendered, end="")


if __name__ == "__main__":
    raise SystemExit(main())
