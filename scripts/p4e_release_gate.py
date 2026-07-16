#!/usr/bin/env python3
"""Run the P4-E local identity, Evidence operations, and hardware-boundary gates."""

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
FRONTEND = WORKSPACE / "civitasos-frontend"
SDK = WORKSPACE / "civitasos-sdk" / "python"


def run_gate(
    name: str,
    command: list[str],
    cwd: Path,
    env: dict[str, str] | None = None,
) -> dict[str, object]:
    started = time.monotonic()
    completed = subprocess.run(
        command,
        cwd=cwd,
        env=os.environ | (env or {}),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    return {
        "name": name,
        "passed": completed.returncode == 0,
        "return_code": completed.returncode,
        "duration_seconds": round(time.monotonic() - started, 3),
        "command": command,
        "output_tail": completed.stdout.splitlines()[-40:],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("/tmp/civitasos-p4e-local-release-gate.json"),
    )
    args = parser.parse_args()
    python = sys.executable
    definitions = [
        (
            "production_security_preflight",
            [python, "scripts/p4e_production_security_smoke.py"],
            AGENT,
            None,
        ),
        (
            "tls_browser_webauthn_lifecycle",
            ["npm", "run", "test:p4e-webauthn"],
            FRONTEND,
            None,
        ),
        (
            "evidence_alert_retry_recovery",
            [python, "scripts/p4_evidence_export_smoke.py"],
            AGENT,
            None,
        ),
        (
            "operator_file_and_alert_rules",
            [
                python,
                "-m",
                "pytest",
                "-q",
                "tests/test_pkcs11_identity_probe.py",
                "tests/test_p4e_evidence_alert_rules.py",
            ],
            AGENT,
            None,
        ),
        (
            "sdk_hardware_signer_boundary",
            [python, "-m", "pytest", "-q", "tests/test_signers.py"],
            SDK,
            {"PYTHONPATH": str(SDK)},
        ),
        (
            "softhsm_pkcs11_failure_matrix",
            [python, "scripts/p4e_pkcs11_failure_matrix.py"],
            AGENT,
            None,
        ),
    ]

    started = time.monotonic()
    results = []
    for definition in definitions:
        result = run_gate(*definition)
        results.append(result)
        print(
            f"[{result['name']}] {'PASS' if result['passed'] else 'FAIL'} "
            f"({result['duration_seconds']}s)"
        )
        if not result["passed"]:
            break

    passed = len(results) == len(definitions) and all(result["passed"] for result in results)
    report = {
        "schema_version": "civitasos-p4e-local-release-gate:v1",
        "passed": passed,
        "decision": "go_p4e_private_tls_multivm_candidate" if passed else "no_go",
        "duration_seconds": round(time.monotonic() - started, 3),
        "gates": results,
        "boundaries": {
            "public_ingress_authorized": False,
            "production_data_used": False,
            "automatic_ledger_append_enabled": False,
            "physical_authenticator_provenance_verified": False,
            "physical_hsm_provenance_verified": False,
            "software_identity_fallback_allowed": False,
            "multivm_tls_execution_authorized": False,
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_suffix(args.output.suffix + ".tmp")
    temporary.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    os.chmod(temporary, 0o600)
    os.replace(temporary, args.output)
    print(f"P4-E decision: {report['decision']}; report: {args.output}")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
