#!/usr/bin/env python3
"""Verify production auth configuration fails closed and serves TLS when complete."""

from __future__ import annotations

import argparse
import json
import os
import socket
import ssl
import subprocess
import tempfile
import time
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKSPACE = ROOT.parent
BACKEND = WORKSPACE / "civitasos-backend"


def free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def fail_closed(binary: Path) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="civitasos-p4e-fail-closed-") as temp:
        data_dir = Path(temp) / "data"
        env = {
            "PATH": os.environ.get("PATH", ""),
            "HOME": os.environ.get("HOME", ""),
            "CIVITASOS_AUTH_MODE": "production",
            "CIVITASOS_DATA_DIR": str(data_dir),
        }
        completed = subprocess.run(
            [str(binary), "--api-port", str(free_port())],
            cwd=BACKEND,
            env=env,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        output = completed.stdout + completed.stderr
        passed = (
            completed.returncode != 0
            and "CIVITASOS_WEBAUTHN_RP_ID is required" in output
            and not data_dir.exists()
        )
        if not passed:
            raise RuntimeError(
                f"{binary.name} did not fail before persistence: "
                f"rc={completed.returncode} output={output[-1000:]}"
            )
        return {
            "binary": binary.name,
            "return_code": completed.returncode,
            "persistence_created": data_dir.exists(),
            "passed": True,
        }


def generate_certificate(root: Path) -> tuple[Path, Path]:
    certificate = root / "tls.crt"
    private_key = root / "tls.key"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=identity.civitas.internal",
            "-addext",
            "subjectAltName=DNS:identity.civitas.internal",
            "-keyout",
            str(private_key),
            "-out",
            str(certificate),
        ],
        capture_output=True,
        check=True,
    )
    return certificate, private_key


def insecure_key_permissions_fail_closed(binary: Path) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="civitasos-p4e-key-mode-") as temp:
        root = Path(temp)
        certificate, private_key = generate_certificate(root)
        private_key.chmod(0o644)
        port = free_port()
        origin = f"https://identity.civitas.internal:{port}"
        data_dir = root / "data"
        env = os.environ.copy()
        env.update(
            {
                "CIVITASOS_AUTH_MODE": "production",
                "CIVITASOS_WEBAUTHN_RP_ID": "identity.civitas.internal",
                "CIVITASOS_WEBAUTHN_ORIGIN": origin,
                "CIVITASOS_TLS_CERT": str(certificate),
                "CIVITASOS_TLS_KEY": str(private_key),
                "CIVITASOS_JWT_SECRET": "0123456789abcdef0123456789abcdef",
                "CIVITASOS_CORS_ORIGINS": origin,
                "CIVITASOS_TRUST_PROXY_HEADERS": "false",
                "CIVITASOS_DATA_DIR": str(data_dir),
            }
        )
        completed = subprocess.run(
            [str(binary), "--api-port", str(port)],
            cwd=BACKEND,
            env=env,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        output = completed.stdout + completed.stderr
        passed = (
            completed.returncode != 0
            and "must not grant group or other permissions" in output
            and not data_dir.exists()
        )
        if not passed:
            raise RuntimeError(
                "backend accepted an insecure TLS private-key mode: "
                f"rc={completed.returncode} output={output[-1000:]}"
            )
        return {
            "private_key_mode": "0644",
            "return_code": completed.returncode,
            "persistence_created": data_dir.exists(),
            "passed": True,
        }


def tls_startup(binary: Path) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="civitasos-p4e-tls-") as temp:
        root = Path(temp)
        certificate, private_key = generate_certificate(root)
        port = free_port()
        origin = f"https://identity.civitas.internal:{port}"
        env = os.environ.copy()
        env.update(
            {
                "CIVITASOS_AUTH_MODE": "production",
                "CIVITASOS_WEBAUTHN_RP_ID": "identity.civitas.internal",
                "CIVITASOS_WEBAUTHN_ORIGIN": origin,
                "CIVITASOS_TLS_CERT": str(certificate),
                "CIVITASOS_TLS_KEY": str(private_key),
                "CIVITASOS_JWT_SECRET": "0123456789abcdef0123456789abcdef",
                "CIVITASOS_CORS_ORIGINS": origin,
                "CIVITASOS_TRUST_PROXY_HEADERS": "false",
                "CIVITASOS_DATA_DIR": str(root / "data"),
            }
        )
        log_path = root / "server.log"
        with log_path.open("w", encoding="utf-8") as log:
            process = subprocess.Popen(
                [str(binary), "--api-port", str(port)],
                cwd=BACKEND,
                env=env,
                stdout=log,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            try:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                deadline = time.monotonic() + 15
                last_error = "not attempted"
                while time.monotonic() < deadline:
                    if process.poll() is not None:
                        raise RuntimeError(
                            f"production TLS backend exited with {process.returncode}: "
                            f"{log_path.read_text(encoding='utf-8')[-2000:]}"
                        )
                    try:
                        with urllib.request.urlopen(
                            f"https://127.0.0.1:{port}/healthz",
                            context=context,
                            timeout=1,
                        ) as response:
                            if response.status == 200:
                                break
                    except Exception as error:  # readiness retries retain the final error
                        last_error = str(error)
                        time.sleep(0.1)
                else:
                    raise RuntimeError(f"production TLS backend did not become ready: {last_error}")
                return {
                    "binary": binary.name,
                    "https_health_status": 200,
                    "rp_id": "identity.civitas.internal",
                    "origin": origin,
                    "passed": True,
                }
            finally:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--backend-bin",
        type=Path,
        default=BACKEND / "target" / "debug" / "api_only",
    )
    parser.add_argument(
        "--full-backend-bin",
        type=Path,
        default=BACKEND / "target" / "debug" / "civitasos-backend",
    )
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    for binary in (args.backend_bin, args.full_backend_bin):
        if not binary.is_file():
            raise SystemExit(f"backend binary not found: {binary}")

    started = time.monotonic()
    report = {
        "schema_version": "civitasos-p4e-production-security-smoke:v1",
        "fail_closed": [fail_closed(args.backend_bin), fail_closed(args.full_backend_bin)],
        "insecure_key_permissions": insecure_key_permissions_fail_closed(args.backend_bin),
        "tls_startup": tls_startup(args.backend_bin),
        "boundaries": {
            "public_ingress_opened": False,
            "production_data_used": False,
            "certificate_is_test_only": True,
        },
        "passed": True,
    }
    report["duration_seconds"] = round(time.monotonic() - started, 3)
    encoded = json.dumps(report, indent=2, sort_keys=True)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded + "\n", encoding="utf-8")
    print(encoded)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
