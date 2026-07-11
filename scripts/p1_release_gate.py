#!/usr/bin/env python3
"""Run the P1 Fact, identity, recovery, Evidence, and soak release gates."""

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
LEDGER = WORKSPACE / "civitasos-evidence-ledger"


def run_gate(name: str, command: list[str], cwd: Path, env: dict[str, str] | None = None) -> dict:
    started = time.monotonic()
    process = subprocess.run(
        command,
        cwd=cwd,
        env=(os.environ | (env or {})),
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


def write_report(path: Path, report: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    os.replace(temporary, path)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--soak-rounds", type=int, default=3)
    parser.add_argument("--output", type=Path, default=Path("/tmp/civitasos-p1-release-gate.json"))
    args = parser.parse_args()
    if args.soak_rounds < 1:
        parser.error("--soak-rounds must be at least 1")

    python = sys.executable
    definitions = [
        ("backend_fact_unit", ["cargo", "test", "fact::tests"], BACKEND, None),
        (
            "identity_operator_unit",
            [python, "-m", "pytest", "-q", "tests/test_identity_ops.py", "tests/test_credential_ops.py"],
            AGENT,
            None,
        ),
        (
            "evidence_manifest_unit",
            [python, "-m", "pytest", "-q", "tests/test_task_manifest.py", "tests/test_ledger_verifier.py"],
            LEDGER,
            {"PYTHONPATH": str(LEDGER / "src")},
        ),
        ("fact_outbox_recovery", [python, "scripts/p1_fact_outbox_recovery_smoke.py"], AGENT, None),
        ("settlement_outbox_recovery", [python, "scripts/p1_settlement_outbox_recovery_smoke.py"], AGENT, None),
        ("identity_runtime", [python, "scripts/beta_runtime_identity_task_smoke.py"], AGENT, None),
        (
            "private_beta_soak",
            [python, "scripts/private_beta_soak.py", "--rounds", str(args.soak_rounds)],
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
        "schema_version": "civitasos-p1-release-gate:v1",
        "passed": passed,
        "decision": "go_private_beta" if passed else "no_go",
        "soak_rounds": args.soak_rounds,
        "duration_seconds": round(time.monotonic() - started, 3),
        "gates": results,
        "boundaries": {
            "public_ingress_authorized": False,
            "production_runtime_authorized": False,
            "production_evidence_claimed": False,
        },
    }
    write_report(args.output, report)
    print(f"P1 decision: {report['decision']}; report: {args.output}")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
