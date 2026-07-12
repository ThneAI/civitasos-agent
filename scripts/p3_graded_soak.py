#!/usr/bin/env python3
"""Run repeated P3 fault matrices for a 1h, 8h, or 24h soak tier."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

AGENT = Path(__file__).resolve().parents[1]


def write_report(path: Path, report: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    os.replace(temporary, path)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    tier = parser.add_mutually_exclusive_group(required=True)
    tier.add_argument("--hours", type=int, choices=(1, 8, 24))
    tier.add_argument("--duration-seconds", type=int, help="runner validation only")
    parser.add_argument("--partition-tasks", type=int, default=4)
    parser.add_argument("--output", type=Path, default=Path("/tmp/civitasos-p3-graded-soak.json"))
    args = parser.parse_args()
    if os.environ.get("CIVITASOS_P3_MULTIVM_EXECUTION_ACK") != "1":
        parser.error("set CIVITASOS_P3_MULTIVM_EXECUTION_ACK=1 to authorize the graded soak")
    duration_seconds = args.hours * 3600 if args.hours else args.duration_seconds
    if duration_seconds is None or duration_seconds < 1 or args.partition_tasks < 1:
        parser.error("duration and partition task count must be positive")

    started_wall = int(time.time())
    started = time.monotonic()
    deadline = started + duration_seconds
    rounds = []
    passed = True
    while time.monotonic() < deadline or not rounds:
        round_number = len(rounds) + 1
        round_output = args.output.with_name(f"{args.output.stem}-round-{round_number}.json")
        round_started = time.monotonic()
        process = subprocess.run(
            [
                sys.executable,
                "scripts/p3_fault_matrix.py",
                "--partition-tasks",
                str(args.partition_tasks),
                "--output",
                str(round_output),
            ],
            cwd=AGENT,
            env=os.environ | {"CIVITASOS_P3_MULTIVM_EXECUTION_ACK": "1"},
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        result = {
            "round": round_number,
            "passed": process.returncode == 0,
            "return_code": process.returncode,
            "duration_seconds": round(time.monotonic() - round_started, 3),
            "evidence": str(round_output),
            "output_tail": process.stdout.splitlines()[-30:],
        }
        rounds.append(result)
        print(f"[round {round_number}] {'PASS' if result['passed'] else 'FAIL'} ({result['duration_seconds']}s)")
        if not result["passed"]:
            passed = False
        report = {
            "schema_version": "civitasos-p3-graded-soak:v1",
            "passed": passed,
            "status": "failed" if not passed else "running",
            "tier_hours": args.hours,
            "requested_duration_seconds": duration_seconds,
            "started_at": started_wall,
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "round_count": len(rounds),
            "rounds": rounds,
            "boundaries": {
                "physical_hsm_evidence_claimed": False,
                "public_ingress_authorized": False,
                "production_runtime_authorized": False,
            },
        }
        write_report(args.output, report)
        if not passed:
            break

    report["status"] = "passed" if passed else "failed"
    report["elapsed_seconds"] = round(time.monotonic() - started, 3)
    write_report(args.output, report)
    print(f"P3 graded soak: {report['status']}; rounds={len(rounds)}; report={args.output}")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
