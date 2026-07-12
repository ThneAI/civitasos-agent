#!/usr/bin/env python3
"""Run local P3 settlement, peer-auth, mTLS, PKCS#11, and WebAuthn gates."""

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
CORE = WORKSPACE / "civitasos"
SDK_PYTHON = WORKSPACE / "civitasos-sdk" / "python"


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
    parser.add_argument("--output", type=Path, default=Path("/tmp/civitasos-p3-release-gate.json"))
    args = parser.parse_args()
    python = sys.executable
    definitions = [
        (
            "peer_envelope_crypto",
            ["cargo", "test", "e1_metadata_tamper_and_rotation_window", "--lib"],
            CORE,
            None,
        ),
        (
            "durable_replay_claim",
            ["cargo", "test", "test_put_if_absent_rejects_duplicate_claim", "--lib"],
            BACKEND,
            None,
        ),
        (
            "webauthn_crypto",
            ["cargo", "test", "verifies_es256_assertion_and_rejects_stale_counter", "--lib"],
            BACKEND,
            None,
        ),
        (
            "sdk_signers",
            [python, "-m", "pytest", "-q", "tests/test_signers.py"],
            SDK_PYTHON,
            {"PYTHONPATH": str(SDK_PYTHON)},
        ),
        (
            "settlement_effect_uncertainty",
            [python, "scripts/p3_settlement_effect_uncertainty_smoke.py"],
            AGENT,
            None,
        ),
        ("peer_key_rotation", [python, "scripts/p3_peer_key_rotation_smoke.py"], AGENT, None),
        ("mtls_handshake", [python, "scripts/p3_mtls_handshake_smoke.py"], AGENT, None),
        ("softhsm_pkcs11", [python, "scripts/p3_softhsm_pkcs11_smoke.py"], AGENT, None),
        ("webauthn_e2e", [python, "scripts/p3_webauthn_e2e_smoke.py"], AGENT, None),
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
        "schema_version": "civitasos-p3-release-gate:v1",
        "passed": passed,
        "decision": "go_p3_authenticated_multivm_candidate" if passed else "no_go",
        "duration_seconds": round(time.monotonic() - started, 3),
        "gates": results,
        "boundaries": {
            "multivm_authenticated_soak_completed": False,
            "physical_hsm_evidence_claimed": False,
            "public_ingress_authorized": False,
            "production_runtime_authorized": False,
            "production_evidence_claimed": False,
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_suffix(args.output.suffix + ".tmp")
    temporary.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    os.replace(temporary, args.output)
    print(f"P3 decision: {report['decision']}; report: {args.output}")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
