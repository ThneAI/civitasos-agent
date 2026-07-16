#!/usr/bin/env python3
"""Run P4 PKCS#11 operability and durable Evidence export gates."""

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
SDK = WORKSPACE / "civitasos-sdk" / "python"
LEDGER = WORKSPACE / "civitasos-evidence-ledger"


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
    parser.add_argument("--output", type=Path, default=Path("/tmp/civitasos-p4-release-gate.json"))
    args = parser.parse_args()
    python = sys.executable
    ledger_python = LEDGER / ".venv" / "bin" / "python"
    definitions = [
        (
            "sdk_pkcs11_provider",
            [python, "-m", "pytest", "-q", "tests/test_signers.py", "tests/test_auth_challenge.py"],
            SDK,
            {"PYTHONPATH": str(SDK)},
        ),
        (
            "softhsm_operability",
            [python, "scripts/p3_softhsm_pkcs11_smoke.py"],
            AGENT,
            None,
        ),
        (
            "backend_evidence_outbox",
            ["cargo", "test", "evidence_export", "--lib"],
            BACKEND,
            None,
        ),
        (
            "ledger_import_receipt",
            [str(ledger_python), "-m", "pytest", "-q", "tests/test_task_manifest.py"],
            LEDGER,
            None,
        ),
        (
            "backend_api_binary",
            ["cargo", "build", "--bin", "api_only"],
            BACKEND,
            None,
        ),
        (
            "evidence_export_end_to_end",
            [python, "scripts/p4_evidence_export_smoke.py"],
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
        "schema_version": "civitasos-p4-release-gate:v1",
        "passed": passed,
        "decision": "go_p4ab_private_beta_operations" if passed else "no_go",
        "duration_seconds": round(time.monotonic() - started, 3),
        "gates": results,
        "boundaries": {
            "physical_hsm_evidence_claimed": False,
            "automatic_ledger_append_enabled": False,
            "external_truth_verified": False,
            "production_evidence_claimed": False,
            "public_ingress_authorized": False,
            "production_runtime_authorized": False,
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_suffix(args.output.suffix + ".tmp")
    temporary.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    os.replace(temporary, args.output)
    print(f"P4 decision: {report['decision']}; report: {args.output}")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
