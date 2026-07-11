#!/usr/bin/env python3
"""Run P2 concurrency, multi-node, settlement, signer, and VM soak gates."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

AGENT = Path(__file__).resolve().parents[1]
WORKSPACE = AGENT.parent
BACKEND = WORKSPACE / "civitasos-backend"
SDK = WORKSPACE / "civitasos-sdk"


def run_gate(name: str, command: list[str], cwd: Path, env: dict[str, str] | None = None) -> dict:
    started = time.monotonic()
    process = subprocess.run(
        command,
        cwd=cwd,
        env=os.environ | (env or {}),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    return {
        "name": name,
        "passed": process.returncode == 0,
        "return_code": process.returncode,
        "duration_seconds": round(time.monotonic() - started, 3),
        "command": command,
        "output_tail": process.stdout.splitlines()[-30:],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--multivm-tasks", type=int, default=12)
    parser.add_argument("--p1-soak-rounds", type=int, default=3)
    parser.add_argument("--output", type=Path, default=Path("/tmp/civitasos-p2-release-gate.json"))
    args = parser.parse_args()
    if os.environ.get("CIVITASOS_P2_MULTIVM_EXECUTION_ACK") != "1":
        parser.error("set CIVITASOS_P2_MULTIVM_EXECUTION_ACK=1 to authorize the bounded vm1/vm2/vm3 soak")

    python = sys.executable
    definitions = [
        ("fact_concurrency", ["cargo", "test", "fact::tests"], BACKEND, None),
        (
            "multinode_fact_convergence",
            ["cargo", "test", "--test", "g1_multinode_task_state_e2e_test", "--", "--test-threads=1"],
            BACKEND,
            None,
        ),
        ("settlement_saga", [python, "scripts/p2_settlement_saga_recovery_smoke.py"], AGENT, None),
        (
            "sdk_signers",
            [python, "-m", "pytest", "-q", "python/tests"],
            SDK,
            {"PYTHONPATH": str(SDK / "python")},
        ),
        ("external_signer_auth", [python, "scripts/p2_external_signer_auth_smoke.py"], AGENT, None),
        (
            "p1_regression",
            [python, "scripts/p1_release_gate.py", "--soak-rounds", str(args.p1_soak_rounds)],
            AGENT,
            None,
        ),
        (
            "multivm_fact_soak",
            [python, "scripts/p2_multivm_fact_soak.py", "--concurrent-tasks", str(args.multivm_tasks)],
            AGENT,
            None,
        ),
    ]
    started = time.monotonic()
    results = []
    for definition in definitions:
        result = run_gate(*definition)
        results.append(result)
        print(f"[{result['name']}] {'PASS' if result['passed'] else 'FAIL'} ({result['duration_seconds']}s)")
        if not result["passed"]:
            break

    passed = len(results) == len(definitions) and all(result["passed"] for result in results)
    report = {
        "schema_version": "civitasos-p2-release-gate:v1",
        "passed": passed,
        "decision": "go_p2_private_beta" if passed else "no_go",
        "duration_seconds": round(time.monotonic() - started, 3),
        "gates": results,
        "multivm_execution_acknowledged": True,
        "boundaries": {
            "public_ingress_authorized": False,
            "production_runtime_authorized": False,
            "production_evidence_claimed": False,
            "specific_hardware_integrated": False,
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_suffix(args.output.suffix + ".tmp")
    temporary.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    os.replace(temporary, args.output)
    print(f"P2 decision: {report['decision']}; report: {args.output}")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
