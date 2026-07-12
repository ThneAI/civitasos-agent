#!/usr/bin/env python3
"""Run the P3 replay, recovery, rotation, and partition fault matrix."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

AGENT = Path(__file__).resolve().parents[1]
BACKEND = AGENT.parent / "civitasos-backend"


def run_case(name: str, command: list[str], cwd: Path, env: dict[str, str] | None = None) -> dict:
    started = time.monotonic()
    process = subprocess.run(
        command,
        cwd=cwd,
        env=os.environ | (env or {}),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    parsed = None
    try:
        start = process.stdout.find("{")
        if start >= 0:
            parsed = json.loads(process.stdout[start:])
    except json.JSONDecodeError:
        pass
    return {
        "name": name,
        "passed": process.returncode == 0,
        "return_code": process.returncode,
        "duration_seconds": round(time.monotonic() - started, 3),
        "result": parsed,
        "output_tail": process.stdout.splitlines()[-40:],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--partition-tasks", type=int, default=4)
    parser.add_argument("--output", type=Path, default=Path("/tmp/civitasos-p3-fault-matrix.json"))
    args = parser.parse_args()
    if args.partition_tasks < 1:
        parser.error("--partition-tasks must be positive")
    if os.environ.get("CIVITASOS_P3_MULTIVM_EXECUTION_ACK") != "1":
        parser.error("set CIVITASOS_P3_MULTIVM_EXECUTION_ACK=1 to authorize the fault matrix")

    python = sys.executable
    definitions = [
        (
            "durable_nonce_replay",
            ["cargo", "test", "test_put_if_absent_rejects_duplicate_claim", "--lib"],
            BACKEND,
            None,
        ),
        (
            "webauthn_challenge_and_counter_replay",
            [python, "scripts/p3_webauthn_e2e_smoke.py"],
            AGENT,
            None,
        ),
        (
            "settlement_uncertainty_and_operator_resolution",
            [python, "scripts/p3_settlement_effect_uncertainty_smoke.py"],
            AGENT,
            None,
        ),
        (
            "peer_rotation_restart",
            [python, "scripts/p3_peer_key_rotation_smoke.py"],
            AGENT,
            None,
        ),
        (
            "authenticated_multivm_combined_faults",
            [
                python,
                "scripts/p3_multivm_authenticated_deploy.py",
                "--kernel-partition",
                "--rotate-vm2",
                "--partition-tasks",
                str(args.partition_tasks),
                "--output",
                "/tmp/civitasos-p3-combined-multivm.json",
            ],
            AGENT,
            {"CIVITASOS_P3_MULTIVM_EXECUTION_ACK": "1"},
        ),
    ]
    started = time.monotonic()
    cases = []
    for definition in definitions:
        result = run_case(*definition)
        cases.append(result)
        print(f"[{result['name']}] {'PASS' if result['passed'] else 'FAIL'} ({result['duration_seconds']}s)")
        if not result["passed"]:
            break
    passed = len(cases) == len(definitions) and all(case["passed"] for case in cases)
    report = {
        "schema_version": "civitasos-p3-fault-matrix:v1",
        "passed": passed,
        "decision": "go_p3_soak_candidate" if passed else "no_go",
        "duration_seconds": round(time.monotonic() - started, 3),
        "cases": cases,
        "boundaries": {
            "single_run_only": True,
            "one_hour_soak_completed": False,
            "eight_hour_soak_completed": False,
            "twenty_four_hour_soak_completed": False,
            "production_evidence_claimed": False,
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_suffix(args.output.suffix + ".tmp")
    temporary.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    os.replace(temporary, args.output)
    print(f"P3 fault matrix: {report['decision']}; report: {args.output}")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
