#!/usr/bin/env python3
"""Run the P4-E local identity, Evidence operations, and hardware-boundary gates."""

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
    parser.add_argument("--p4ef-summary", type=Path)
    parser.add_argument("--p4ef-candidate-bin", type=Path)
    parser.add_argument("--p4ef-frontend-build-dir", type=Path)
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

    if all(result["passed"] for result in results) and args.p4ef_summary:
        validation_started = time.monotonic()
        error = None
        try:
            summary = json.loads(args.p4ef_summary.read_text())
            candidate_hash = (
                hashlib.sha256(args.p4ef_candidate_bin.read_bytes()).hexdigest()
                if args.p4ef_candidate_bin and args.p4ef_candidate_bin.is_file()
                else None
            )
            frontend_hash = None
            if args.p4ef_frontend_build_dir and args.p4ef_frontend_build_dir.is_dir():
                digest = hashlib.sha256()
                for path in sorted(
                    item for item in args.p4ef_frontend_build_dir.rglob("*") if item.is_file()
                ):
                    digest.update(str(path.relative_to(args.p4ef_frontend_build_dir)).encode())
                    digest.update(b"\0")
                    digest.update(path.read_bytes())
                    digest.update(b"\0")
                frontend_hash = digest.hexdigest()
            boundaries = summary.get("boundaries", {})
            task = summary.get("candidate_task_receipt") or {}
            browser = summary.get("candidate_browser_webauthn") or {}
            valid = (
                summary.get("schema_version") == "civitasos-p4ef-multivm-tls-summary:v1"
                and summary.get("passed") is True
                and summary.get("authorization_consumed") is True
                and candidate_hash is not None
                and summary.get("candidate_sha256") == candidate_hash
                and frontend_hash is not None
                and summary.get("frontend_sha256") == frontend_hash
                and task.get("passed") is True
                and task.get("node_count") == 3
                and all(item.get("fact_count") == 5 for item in task.get("observations", []))
                and browser.get("passed") is True
                and browser.get("node_count") == 3
                and summary.get("cleanup", {}).get("passed") is True
                and boundaries.get("public_ingress_opened") is False
                and boundaries.get("production_data_used") is False
                and boundaries.get("production_evidence_claimed") is False
            )
            if not valid:
                error = "P4-EF summary failed schema, artifact hash, identity, Receipt, cleanup, or boundary validation"
        except Exception as exception:  # noqa: BLE001
            valid = False
            error = str(exception)
        result = {
            "name": "p4ef_multivm_tls_identity_receipt_rollback",
            "passed": valid,
            "return_code": 0 if valid else 1,
            "duration_seconds": round(time.monotonic() - validation_started, 3),
            "command": ["validate", str(args.p4ef_summary)],
            "output_tail": [] if valid else [error],
        }
        results.append(result)
        print(
            f"[{result['name']}] {'PASS' if result['passed'] else 'FAIL'} "
            f"({result['duration_seconds']}s)"
        )

    expected_count = len(definitions) + (1 if args.p4ef_summary else 0)
    passed = len(results) == expected_count and all(result["passed"] for result in results)
    p4ef_validated = bool(
        args.p4ef_summary
        and results
        and results[-1]["name"] == "p4ef_multivm_tls_identity_receipt_rollback"
        and results[-1]["passed"]
    )
    report = {
        "schema_version": "civitasos-p4e-local-release-gate:v1",
        "passed": passed,
        "decision": (
            "go_p4ef_private_tls_soak_candidate"
            if passed and p4ef_validated
            else "go_p4e_private_tls_multivm_candidate"
            if passed
            else "no_go"
        ),
        "duration_seconds": round(time.monotonic() - started, 3),
        "gates": results,
        "boundaries": {
            "public_ingress_authorized": False,
            "production_data_used": False,
            "automatic_ledger_append_enabled": False,
            "physical_authenticator_provenance_verified": False,
            "physical_hsm_provenance_verified": False,
            "software_identity_fallback_allowed": False,
            "multivm_tls_execution_validated": p4ef_validated,
            "soak_execution_authorized": False,
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
