#!/usr/bin/env python3
"""Generate isolated, hash-bound mTLS and peer materials for P5-B4."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import subprocess
import time
from pathlib import Path
from typing import Any

from nacl.signing import SigningKey


MATERIALS_SCHEMA = "civitasos-p5b4-multivm-materials:v1"
EXPECTED_NODES = {"vm1": "192.168.56.4", "vm2": "192.168.56.5", "vm3": "192.168.56.6"}
PRIVATE_SUFFIXES = (".key", ".seed", ".secret")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_private(path: Path, value: str) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        stream.write(value + "\n")
        stream.flush()
        os.fsync(stream.fileno())


def _openssl(root: Path, *arguments: str) -> None:
    subprocess.run(
        ["openssl", *arguments],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )


def _certificate(root: Path, name: str, common_name: str, extensions: str) -> None:
    _openssl(
        root,
        "req",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-subj",
        f"/CN={common_name}",
        "-keyout",
        f"{name}.key",
        "-out",
        f"{name}.csr",
    )
    (root / f"{name}.ext").write_text(extensions)
    _openssl(
        root,
        "x509",
        "-req",
        "-days",
        "2",
        "-in",
        f"{name}.csr",
        "-CA",
        "ca.crt",
        "-CAkey",
        "ca.key",
        "-CAcreateserial",
        "-extfile",
        f"{name}.ext",
        "-out",
        f"{name}.crt",
    )
    (root / f"{name}.csr").unlink()
    (root / f"{name}.ext").unlink()


def generate_materials(output: Path, *, created_at: int | None = None) -> dict[str, Any]:
    root = output.expanduser().resolve()
    if root.exists() and any(root.iterdir()):
        raise ValueError(f"refusing to overwrite P5-B4 materials: {root}")
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(root, 0o700)
    _openssl(
        root,
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-days",
        "2",
        "-subj",
        "/CN=CivitasOS P5-B4 Gate CA",
        "-addext",
        "basicConstraints=critical,CA:TRUE",
        "-addext",
        "keyUsage=critical,keyCertSign,cRLSign",
        "-keyout",
        "ca.key",
        "-out",
        "ca.crt",
    )
    trusted_peer_keys: dict[str, list[str]] = {}
    for node_id, address in EXPECTED_NODES.items():
        _certificate(
            root,
            node_id,
            f"p5b4-{node_id}",
            f"subjectAltName=DNS:{node_id},IP:{address}\nextendedKeyUsage=serverAuth,clientAuth\n",
        )
        key = SigningKey.generate()
        _write_private(root / f"{node_id}.seed", key.encode().hex())
        trusted_peer_keys[f"p5b4-{node_id}"] = [key.verify_key.encode().hex()]
    _certificate(
        root,
        "controller",
        "p5b4-controller",
        "extendedKeyUsage=clientAuth\n",
    )
    for name in ("jwt.secret", "service.secret", "cluster.secret"):
        _write_private(root / name, secrets.token_urlsafe(48))
    _write_private(root / "identity.seed", SigningKey.generate().encode().hex())
    for path in root.iterdir():
        os.chmod(path, 0o600)
    files = {
        path.name: {"sha256": _sha256(path), "mode": "0600"}
        for path in sorted(root.iterdir())
        if path.name not in {"manifest.json", "ca.srl"}
    }
    (root / "ca.srl").unlink(missing_ok=True)
    payload: dict[str, Any] = {
        "schema_version": MATERIALS_SCHEMA,
        "created_at": int(time.time()) if created_at is None else created_at,
        "expires_after_seconds": 172800,
        "nodes": EXPECTED_NODES,
        "trusted_peer_keys": trusted_peer_keys,
        "files": files,
        "private_material_exported_to_vm": True,
        "isolated_gate_only": True,
        "production_identity": False,
        "production_evidence": False,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    payload["materials_id"] = f"p5b4-materials:{hashlib.sha256(encoded).hexdigest()[:24]}"
    manifest = root / "manifest.json"
    _write_private(manifest, json.dumps(payload, indent=2, sort_keys=True))
    return payload


def validate_materials(manifest_path: Path) -> dict[str, Any]:
    path = manifest_path.expanduser().resolve()
    manifest = json.loads(path.read_text())
    failures: list[str] = []
    if manifest.get("schema_version") != MATERIALS_SCHEMA:
        failures.append("schema_version")
    material = {key: value for key, value in manifest.items() if key != "materials_id"}
    expected_id = f"p5b4-materials:{hashlib.sha256(json.dumps(material, sort_keys=True, separators=(',', ':')).encode()).hexdigest()[:24]}"
    if manifest.get("materials_id") != expected_id:
        failures.append("materials_id")
    if manifest.get("nodes") != EXPECTED_NODES:
        failures.append("nodes")
    expected_files = {
        "ca.crt",
        "ca.key",
        "controller.crt",
        "controller.key",
        "jwt.secret",
        "service.secret",
        "cluster.secret",
        "identity.seed",
        *(f"{node}.{suffix}" for node in EXPECTED_NODES for suffix in ("crt", "key", "seed")),
    }
    files = manifest.get("files")
    if not isinstance(files, dict) or set(files) != expected_files:
        failures.append("file_set")
        files = {}
    for name, record in files.items():
        candidate = path.parent / name
        if not candidate.is_file() or record.get("sha256") != _sha256(candidate):
            failures.append(f"sha256:{name}")
        if candidate.is_file() and candidate.stat().st_mode & 0o777 != 0o600:
            failures.append(f"mode:{name}")
    if failures:
        raise ValueError(f"P5-B4 materials validation failed: {failures}")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--ack-isolated-nonproduction-materials", action="store_true")
    args = parser.parse_args()
    if not args.ack_isolated_nonproduction_materials:
        parser.error("explicit isolated non-production materials acknowledgement is required")
    result = generate_materials(args.output)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
