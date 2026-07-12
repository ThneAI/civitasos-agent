#!/usr/bin/env python3
"""Verify the API rejects anonymous TLS clients when cluster mTLS is enabled."""

from __future__ import annotations

import json
import os
import ssl
import subprocess
import tempfile
import time
from pathlib import Path
from urllib.request import urlopen

from beta_runtime_identity_task_smoke import BACKEND


def openssl(directory: Path, *args: str) -> None:
    subprocess.run(
        ["openssl", *args], cwd=directory, check=True, capture_output=True, text=True
    )


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="civitasos-mtls-") as temporary:
        root = Path(temporary)
        openssl(root, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                "-subj", "/CN=CivitasOS Test CA", "-addext", "basicConstraints=critical,CA:TRUE",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-keyout", "ca.key", "-out", "ca.crt")
        openssl(root, "req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=localhost",
                "-keyout", "server.key", "-out", "server.csr")
        (root / "server.ext").write_text(
            "subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n"
        )
        openssl(root, "x509", "-req", "-days", "1", "-in", "server.csr",
                "-CA", "ca.crt", "-CAkey", "ca.key", "-CAcreateserial",
                "-extfile", "server.ext", "-out", "server.crt")
        openssl(root, "req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=peer-node",
                "-keyout", "client.key", "-out", "client.csr")
        (root / "client.ext").write_text("extendedKeyUsage=clientAuth\n")
        openssl(root, "x509", "-req", "-days", "1", "-in", "client.csr",
                "-CA", "ca.crt", "-CAkey", "ca.key", "-CAcreateserial",
                "-extfile", "client.ext", "-out", "client.crt")

        port = 18443
        env = os.environ | {
            "CIVITASOS_DATA_DIR": str(root / "data"),
            "CIVITASOS_STORAGE_DATA_DIR": str(root / "storage"),
            "CIVITASOS_TLS_CERT": str(root / "server.crt"),
            "CIVITASOS_TLS_KEY": str(root / "server.key"),
            "CIVITASOS_MTLS_CA_CERT": str(root / "ca.crt"),
            "CIVITASOS_MTLS_CLIENT_CERT": str(root / "client.crt"),
            "CIVITASOS_MTLS_CLIENT_KEY": str(root / "client.key"),
            "CIVITASOS_A2A_SEED_TASKS": "false",
        }
        server_log = (root / "server.log").open("w+")
        process = subprocess.Popen(
            [str(BACKEND), "--api-port", str(port)],
            cwd=BACKEND.parents[2],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=server_log,
        )
        try:
            authenticated = ssl.create_default_context(cafile=str(root / "ca.crt"))
            authenticated.load_cert_chain(root / "client.crt", root / "client.key")
            url = f"https://localhost:{port}/healthz"
            last_error: OSError | None = None
            for _ in range(200):
                if process.poll() is not None:
                    raise RuntimeError(f"mTLS backend exited with {process.returncode}")
                try:
                    with urlopen(url, context=authenticated, timeout=1) as response:
                        if response.status == 200:
                            break
                except OSError as error:
                    last_error = error
                    time.sleep(0.05)
            else:
                server_log.flush()
                server_log.seek(0)
                raise RuntimeError(
                    f"mTLS backend did not become ready: {last_error}; "
                    f"server={server_log.read()[-4000:]}"
                )

            anonymous = ssl.create_default_context(cafile=str(root / "ca.crt"))
            anonymous_rejected = False
            try:
                urlopen(url, context=anonymous, timeout=2)
            except OSError:
                anonymous_rejected = True
            if not anonymous_rejected:
                raise RuntimeError("anonymous TLS client was accepted while mTLS was enabled")

            print(json.dumps({
                "schema_version": "p3-mtls-handshake-smoke:v1",
                "passed": True,
                "anonymous_client_rejected": True,
                "authenticated_client_status": 200,
                "production_claimed": False,
            }, indent=2))
            return 0
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


if __name__ == "__main__":
    raise SystemExit(main())
