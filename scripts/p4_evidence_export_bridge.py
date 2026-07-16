#!/usr/bin/env python3
"""Import pending backend Evidence Manifests and acknowledge durable receipts."""

from __future__ import annotations

import argparse
import json
import os
import stat
import subprocess
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


AGENT = Path(__file__).resolve().parents[1]
DEFAULT_LEDGER_CLI = AGENT.parent / "civitasos-evidence-ledger" / ".venv" / "bin" / "civitasos-evidence-ledger"


def read_service_token(path: Path) -> str:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("service token path must be a regular file")
        if metadata.st_uid != os.geteuid():
            raise ValueError("service token file must be owned by the current user")
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            raise ValueError("service token file must not grant group/other access")
        encoded = os.read(descriptor, 65537)
        if len(encoded) > 65536:
            raise ValueError("service token file is unexpectedly large")
    finally:
        os.close(descriptor)
    token = encoded.decode("utf-8").strip()
    if not token:
        raise ValueError("service token file is empty")
    return token


def request_json(
    url: str,
    token: str,
    body: dict | None = None,
) -> dict:
    payload = json.dumps(body, separators=(",", ":")).encode() if body is not None else None
    request = Request(
        url,
        data=payload,
        method="POST" if body is not None else "GET",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
    )
    try:
        with urlopen(request, timeout=15) as response:
            result = json.loads(response.read())
    except HTTPError as error:
        detail = error.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"backend request failed with HTTP {error.code}: {detail}") from error
    if not isinstance(result, dict) or result.get("success") is not True:
        raise RuntimeError(f"backend returned an invalid response for {url}")
    return result


def write_private_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def import_manifest(
    ledger_cli: Path,
    run_root: Path,
    actor_id: str,
    source_system: str,
    manifest_path: Path,
    receipt_path: Path,
) -> dict:
    subprocess.run(
        [
            str(ledger_cli),
            "import-task-manifest",
            "--run-root",
            str(run_root),
            "--input",
            str(manifest_path),
            "--actor-id",
            actor_id,
            "--source-system",
            source_system,
            "--receipt-output",
            str(receipt_path),
        ],
        check=True,
        text=True,
        capture_output=True,
    )
    receipt = json.loads(receipt_path.read_text())
    if receipt.get("schema_version") != "civitasos-task-manifest-import-receipt:v1":
        raise RuntimeError("ledger returned an unsupported import receipt")
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend-url", required=True)
    parser.add_argument("--service-token-file", type=Path, required=True)
    parser.add_argument("--ledger-cli", type=Path, default=DEFAULT_LEDGER_CLI)
    parser.add_argument("--ledger-run-root", type=Path, required=True)
    parser.add_argument("--actor-id", required=True)
    parser.add_argument("--source-system", default="civitasos_backend")
    parser.add_argument("--staging-root", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    token = read_service_token(args.service_token_file)
    base_url = args.backend_url.rstrip("/")
    query = urlencode({"pending_only": "true"})
    response = request_json(
        f"{base_url}/api/v1/a2a/operator/evidence-exports?{query}", token
    )
    records = response.get("data", {}).get("records", [])
    if not isinstance(records, list):
        raise RuntimeError("backend evidence outbox records must be a list")

    processed = []
    for record in records:
        manifest = record.get("manifest") or {}
        manifest_hash = record.get("manifest_hash")
        task_id = record.get("task_id")
        if not isinstance(manifest_hash, str) or not isinstance(task_id, str):
            raise RuntimeError("backend evidence export record is incomplete")
        if manifest.get("manifest_hash") != manifest_hash:
            raise RuntimeError(f"outbox manifest hash mismatch for task {task_id}")
        manifest_path = args.staging_root / "manifests" / f"{manifest_hash}.json"
        receipt_path = args.staging_root / "receipts" / f"{manifest_hash}.json"
        write_private_json(manifest_path, manifest)
        receipt = import_manifest(
            args.ledger_cli,
            args.ledger_run_root,
            args.actor_id,
            args.source_system,
            manifest_path,
            receipt_path,
        )
        if receipt.get("manifest_hash") != manifest_hash:
            raise RuntimeError(f"ledger receipt manifest hash mismatch for task {task_id}")
        acknowledgement = request_json(
            f"{base_url}/api/v1/a2a/operator/evidence-exports/{task_id}/acknowledge",
            token,
            {
                "manifest_hash": manifest_hash,
                "ledger_event_id": receipt["ledger_event_id"],
                "ledger_event_sha256": receipt["ledger_event_sha256"],
                "source_manifest_ref": receipt["source_manifest_ref"],
            },
        )
        processed.append(
            {
                "task_id": task_id,
                "manifest_hash": manifest_hash,
                "ledger_event_id": receipt["ledger_event_id"],
                "acknowledged": acknowledgement.get("data", {}).get("status") == "acknowledged",
            }
        )

    report = {
        "schema_version": "civitasos-p4-evidence-export-bridge:v1",
        "passed": all(item["acknowledged"] for item in processed),
        "pending_record_count": len(records),
        "processed_count": len(processed),
        "processed": processed,
        "automatic_ledger_append": False,
        "externally_verified": False,
        "production_evidence": False,
    }
    if args.output is not None:
        write_private_json(args.output, report)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
