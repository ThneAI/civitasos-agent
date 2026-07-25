"""Qualify the reusable participant runner service with synthetic file IPC."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from benchmarks.j1.controlled_comparison import canonical_sha256, write_private_json
from benchmarks.j1.qualification_participant_runner_image import (
    validate_runner_image_manifest,
)
from benchmarks.j1_qualification_participant_runner import (
    validate_output_envelope,
)
from benchmarks.j1_qualification_participant_runner_image import _synthetic_input


REPORT_SCHEMA = "j1-qualification-participant-runner-service-smoke:v1"


def run_service_smoke(
    *,
    smoke_id: str,
    created_at: str,
    runner_manifest_path: Path,
    output_root: Path,
) -> dict[str, Any]:
    if output_root.exists():
        raise FileExistsError(f"runner service smoke output exists: {output_root}")
    manifest_raw = runner_manifest_path.read_bytes()
    manifest = json.loads(manifest_raw)
    failures = validate_runner_image_manifest(
        manifest, expected_implementation=manifest["implementation"]
    )
    if failures:
        raise ValueError(f"runner manifest invalid: {failures}")
    with tempfile.TemporaryDirectory(prefix="j1d-service-smoke-") as temporary:
        root = Path(temporary)
        input_root = root / "input"
        output_root_mount = root / "output"
        input_root.mkdir(mode=0o700)
        output_root_mount.mkdir(mode=0o700)
        source = _synthetic_input()
        request_path = input_root / "request.json"
        response_path = output_root_mount / "response.json"
        _atomic_write(request_path, source)
        container_id = _start_container(
            image_id=manifest["image"]["image_id"],
            input_root=input_root,
            output_root=output_root_mount,
            smoke_id=smoke_id,
        )
        try:
            first = _wait_response(response_path, container_id)
            _validate_output(first, source)
            response_path.unlink()
            source = _finalize_source(source, first)
            _atomic_write(request_path, source)
            second = _wait_response(response_path, container_id)
            _validate_output(second, source)
            if first["process_instance_id"] != second["process_instance_id"]:
                raise ValueError("runner service replaced process between exchanges")
        finally:
            subprocess.run(
                ["docker", "stop", "--time", "1", container_id],
                check=False,
                capture_output=True,
                text=True,
            )
        _wait_removed(container_id)
    report = {
        "schema_version": REPORT_SCHEMA,
        "smoke_id": smoke_id,
        "created_at": created_at,
        "passed": True,
        "failure_reasons": [],
        "runner_manifest": {
            "sha256": hashlib.sha256(manifest_raw).hexdigest(),
            "canonical_sha256": manifest["manifest_sha256"],
        },
        "image_id": manifest["image"]["image_id"],
        "checks": {
            "default_entrypoint_service_started": True,
            "prepare_and_finalize_exchanges_completed": True,
            "same_process_instance_observed": True,
            "input_mount_read_only": True,
            "output_mount_read_write": True,
            "network_mode_none": True,
            "container_removed_after_smoke": True,
        },
        "outputs": {
            "prepare_output_sha256": first["output_sha256"],
            "finalize_output_sha256": second["output_sha256"],
            "process_instance_sha256": hashlib.sha256(
                first["process_instance_id"].encode()
            ).hexdigest(),
        },
        "execution_boundary": {
            "synthetic_runner_service_smoke_only": True,
            "participant_data_used": False,
            "participant_container_started": False,
            "provider_credential_read": False,
            "provider_api_call_performed": False,
            "model_invocation_performed": False,
            "pkcs11_signature_performed": False,
            "backend_fact_append_performed": False,
            "ledger_append_performed": False,
        },
    }
    report["report_sha256"] = canonical_sha256(report)
    output_root.mkdir(parents=True, mode=0o700)
    output_root.chmod(0o700)
    write_private_json(output_root / "runner-service-smoke.json", report)
    return report


def _start_container(
    *, image_id: str, input_root: Path, output_root: Path, smoke_id: str
) -> str:
    result = subprocess.run(
        [
            "docker",
            "run",
            "--detach",
            "--rm",
            "--label",
            f"civitasos.j1d.synthetic-service-smoke={smoke_id}",
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--pids-limit",
            "64",
            "--memory",
            "256m",
            "--cpus",
            "0.25",
            "--user",
            f"{os.getuid()}:{os.getgid()}",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=16777216",
            "--mount",
            f"type=bind,src={input_root},dst=/input,readonly",
            "--mount",
            f"type=bind,src={output_root},dst=/output",
            image_id,
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _wait_response(path: Path, container_id: str) -> dict[str, Any]:
    for _ in range(600):
        if path.is_file():
            value = json.loads(path.read_bytes())
            if isinstance(value, dict):
                return value
            raise ValueError("runner service output is not an object")
        state = subprocess.run(
            ["docker", "inspect", "--format", "{{.State.Running}}", container_id],
            check=False,
            capture_output=True,
            text=True,
        )
        if state.returncode != 0 or state.stdout.strip() != "true":
            raise RuntimeError("runner service exited before output")
        time.sleep(0.05)
    raise TimeoutError("runner service output timed out")


def _wait_removed(container_id: str) -> None:
    for _ in range(100):
        result = subprocess.run(
            ["docker", "inspect", container_id],
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            return
        time.sleep(0.05)
    raise RuntimeError("synthetic runner service container was not removed")


def _finalize_source(
    source: dict[str, Any], first: dict[str, Any]
) -> dict[str, Any]:
    decision = "Synthetic bounded participant decision."
    value = json.loads(json.dumps(source))
    value["operation"] = "finalize_provider_response"
    value["ipc"]["request_id"] = "synthetic-service-finalize"
    value["ipc"]["nonce"] = "f" * 64
    value["provider_response"] = {
        "provider_request_sha256": canonical_sha256(first["provider_request"]),
        "provider_receipt_sha256": "0" * 64,
        "decision": decision,
        "decision_sha256": hashlib.sha256(decision.encode()).hexdigest(),
    }
    return value


def _atomic_write(path: Path, value: dict[str, Any]) -> None:
    payload = json.dumps(value, ensure_ascii=False, sort_keys=True).encode()
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_bytes(payload)
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def _validate_output(output: dict[str, Any], source: dict[str, Any]) -> None:
    failures = validate_output_envelope(output, source=source)
    if failures:
        raise ValueError(f"runner service output invalid: {failures}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--smoke-id", required=True)
    parser.add_argument(
        "--created-at", default=datetime.now(UTC).isoformat()
    )
    parser.add_argument("--runner-manifest", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    report = run_service_smoke(
        smoke_id=args.smoke_id,
        created_at=args.created_at,
        runner_manifest_path=args.runner_manifest,
        output_root=args.output_root,
    )
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
