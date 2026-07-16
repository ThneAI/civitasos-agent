#!/usr/bin/env python3
"""Run P4 identity, Evidence export, browser workflow, and receipt gates."""

from __future__ import annotations

import argparse
import hashlib
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
FRONTEND = WORKSPACE / "civitasos-frontend"


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
    parser.add_argument("--p4d-multivm-summary", type=Path)
    parser.add_argument("--p4d-candidate-bin", type=Path)
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
        (
            "backend_webauthn_lifecycle",
            ["cargo", "test", "webauthn", "--lib"],
            BACKEND,
            None,
        ),
        (
            "webauthn_registration_revocation_end_to_end",
            [python, "scripts/p3_webauthn_e2e_smoke.py"],
            AGENT,
            None,
        ),
        (
            "p4d_operational_receipt_runner",
            [python, "-m", "pytest", "-q", "tests/test_p4d_multivm_upgrade_drill.py"],
            AGENT,
            None,
        ),
        (
            "frontend_identity_receipt_suite",
            ["npm", "test", "--", "--runInBand", "--watchAll=false"],
            FRONTEND,
            {"CI": "true"},
        ),
        (
            "frontend_production_build",
            ["npm", "run", "build"],
            FRONTEND,
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

    if all(result["passed"] for result in results) and args.p4d_multivm_summary:
        started_summary = time.monotonic()
        try:
            summary = json.loads(args.p4d_multivm_summary.read_text())
            boundaries = summary.get("boundaries", {})
            candidate_hash = (
                hashlib.sha256(args.p4d_candidate_bin.read_bytes()).hexdigest()
                if args.p4d_candidate_bin and args.p4d_candidate_bin.is_file()
                else None
            )
            valid = (
                summary.get("schema_version") == "civitasos-p4d-multivm-upgrade-summary:v1"
                and summary.get("passed") is True
                and summary.get("authorization_consumed") is True
                and candidate_hash is not None
                and summary.get("candidate_sha256") == candidate_hash
                and boundaries.get("public_ingress_opened") is False
                and boundaries.get("production_runtime_executed") is False
                and boundaries.get("production_receipt_written") is False
            )
            error = None if valid else "P4-D multi-VM summary failed schema, pass, candidate hash, authorization, or boundary checks"
        except Exception as exc:  # noqa: BLE001
            valid, error = False, str(exc)
        result = {
            "name": "p4d_multivm_upgrade_rollback",
            "passed": valid,
            "return_code": 0 if valid else 1,
            "duration_seconds": round(time.monotonic() - started_summary, 3),
            "command": ["validate", str(args.p4d_multivm_summary)],
            "output_tail": [] if valid else [error],
        }
        results.append(result)
        print(f"[{result['name']}] {'PASS' if result['passed'] else 'FAIL'} ({result['duration_seconds']}s)")

    expected_gate_count = len(definitions) + (1 if args.p4d_multivm_summary else 0)
    passed = len(results) == expected_gate_count and all(result["passed"] for result in results)
    p4d_validated = args.p4d_multivm_summary is not None and results[-1]["name"] == "p4d_multivm_upgrade_rollback" and results[-1]["passed"]
    report = {
        "schema_version": "civitasos-p4-release-gate:v3",
        "passed": passed,
        "decision": ("go_p4d_private_beta_operations" if passed and p4d_validated else "go_p4abc_private_beta_operations" if passed else "no_go"),
        "duration_seconds": round(time.monotonic() - started, 3),
        "gates": results,
        "boundaries": {
            "physical_hsm_evidence_claimed": False,
            "automatic_ledger_append_enabled": False,
            "external_truth_verified": False,
            "production_evidence_claimed": False,
            "public_ingress_authorized": False,
            "production_runtime_authorized": False,
            "webauthn_registration_challenge_verified": True,
            "webauthn_cose_key_binding_verified": True,
            "webauthn_device_attestation_provenance_verified": False,
            "webauthn_existing_jwt_immediately_revoked": True,
            "private_multivm_upgrade_rollback_validated": p4d_validated,
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
