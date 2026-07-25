"""Build and offline-qualify the content-addressed J1-D runner image."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from benchmarks.j1.controlled_comparison import canonical_sha256, write_private_json
from benchmarks.j1.qualification_participant_runner_image import (
    BASE_IMAGE_DIGEST,
    ENTRYPOINT,
    build_runner_image_manifest,
)
from benchmarks.j1_qualification_participant_runner import INPUT_SCHEMA


REPORT_SCHEMA = "j1-qualification-participant-runner-image-gate:v1"
DOCKERFILE = Path(__file__).parent / "j1" / "participant_runner.Dockerfile"
RUNNER_SOURCE = Path(__file__).parent / "j1_qualification_participant_runner.py"
CONTRACT_SOURCE = (
    Path(__file__).parent / "j1" / "qualification_participant_runner_image.py"
)


def qualify_runner_image(
    *,
    build_id: str,
    created_at: str,
    image_tag: str,
    repository_root: Path,
    output_root: Path,
) -> dict[str, Any]:
    if output_root.exists():
        raise ValueError(f"runner image output already exists: {output_root}")
    dockerfile_raw = DOCKERFILE.read_bytes()
    runner_raw = RUNNER_SOURCE.read_bytes()
    _validate_dockerfile(dockerfile_raw.decode("utf-8"))
    _require_base_image()
    implementation = _implementation(repository_root)
    source_hashes = {
        "dockerfile_sha256": hashlib.sha256(dockerfile_raw).hexdigest(),
        "runner_source_sha256": hashlib.sha256(runner_raw).hexdigest(),
    }
    context_sha256 = canonical_sha256(source_hashes)
    output_root.mkdir(parents=True, mode=0o700)
    output_root.chmod(0o700)
    try:
        with tempfile.TemporaryDirectory(prefix="civitas-j1d-runner-build-") as temp:
            context = Path(temp)
            shutil.copy2(DOCKERFILE, context / "Dockerfile")
            shutil.copy2(RUNNER_SOURCE, context / "participant_runner.py")
            _run(
                [
                    "docker",
                    "build",
                    "--pull=false",
                    "--no-cache",
                    "--network=none",
                    "--label",
                    f"civitasos.j1d.runner.build={build_id}",
                    "--tag",
                    image_tag,
                    ".",
                ],
                cwd=context,
            )
        image = _inspect_image(image_tag)
        smoke = _run_smoke(image["Id"])
        manifest = build_runner_image_manifest(
            build_id=build_id,
            created_at=created_at,
            dockerfile_sha256=source_hashes["dockerfile_sha256"],
            runner_source_sha256=source_hashes["runner_source_sha256"],
            build_context_sha256=context_sha256,
            image_id=image["Id"],
            image_tag=image_tag,
            architecture=image["Architecture"],
            os_name=image["Os"],
            implementation=implementation,
            smoke=smoke,
        )
        manifest_path = output_root / "participant-runner-image-manifest.json"
        write_private_json(manifest_path, manifest)
        report = {
            "schema_version": REPORT_SCHEMA,
            "passed": True,
            "failure_reasons": [],
            "state": "runner_image_qualified_infrastructure_rebind_review_required",
            "manifest": {
                "path": str(manifest_path.resolve()),
                "sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
                "canonical_sha256": manifest["manifest_sha256"],
            },
            "image": manifest["image"],
            "runtime_boundary": manifest["runtime_boundary"],
            "smoke": smoke,
            "implementation": implementation,
            "readiness": manifest["readiness"],
            "execution_boundary": manifest["execution_boundary"],
        }
        report["report_sha256"] = canonical_sha256(report)
        write_private_json(
            output_root / "participant-runner-image-gate-report.json", report
        )
        return report
    except Exception:
        shutil.rmtree(output_root, ignore_errors=True)
        raise


def _run_smoke(image_id: str) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="civitas-j1d-runner-smoke-") as temp:
        root = Path(temp)
        input_root = root / "input"
        output_root = root / "output"
        input_root.mkdir(mode=0o700)
        output_root.mkdir(mode=0o700)
        positive = _synthetic_input()
        positive_path = input_root / "positive.json"
        positive_path.write_text(json.dumps(positive, sort_keys=True), encoding="utf-8")
        hashes = []
        for index in range(2):
            output_path = output_root / f"positive-{index}.json"
            result = _docker_run(
                image_id=image_id,
                input_root=input_root,
                output_root=output_root,
                input_name=positive_path.name,
                output_name=output_path.name,
            )
            if result.returncode != 0 or not output_path.is_file():
                raise ValueError(f"runner positive smoke failed: {result.stderr}")
            hashes.append(hashlib.sha256(output_path.read_bytes()).hexdigest())
        negative = json.loads(json.dumps(positive))
        negative["participant"]["cohort"] = "control"
        negative_path = input_root / "negative.json"
        negative_path.write_text(json.dumps(negative, sort_keys=True), encoding="utf-8")
        negative_output = output_root / "negative.json"
        negative_result = _docker_run(
            image_id=image_id,
            input_root=input_root,
            output_root=output_root,
            input_name=negative_path.name,
            output_name=negative_output.name,
        )
        if negative_result.returncode == 0 or negative_output.exists():
            raise ValueError("runner negative smoke did not fail closed")
        return {
            "positive_exit_code": 0,
            "positive_output_sha256": hashes[0],
            "positive_repeat_output_sha256": hashes[1],
            "deterministic_output": hashes[0] == hashes[1],
            "negative_exit_code": negative_result.returncode,
            "negative_output_created": negative_output.exists(),
            "synthetic_only": True,
        }


def _docker_run(
    *,
    image_id: str,
    input_root: Path,
    output_root: Path,
    input_name: str,
    output_name: str,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "docker",
            "run",
            "--rm",
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
            f"type=bind,src={input_root.resolve()},dst=/input,readonly",
            "--mount",
            f"type=bind,src={output_root.resolve()},dst=/output",
            image_id,
            "--input",
            f"/input/{input_name}",
            "--output",
            f"/output/{output_name}",
        ],
        check=False,
        capture_output=True,
        text=True,
    )


def _synthetic_input() -> dict[str, Any]:
    task_input = "Synthetic runner image smoke input."
    return {
        "schema_version": INPUT_SCHEMA,
        "operation": "prepare_provider_request",
        "run_id": "runner-image-smoke",
        "participant": {
            "participant_id": "synthetic-runner-participant",
            "execution_did": "did:civ:qualification:synthetic-runner-participant",
            "credential_version": 1,
            "pair_id": "synthetic-pair",
            "cohort": "mentor",
            "assignment_commitment_sha256": "a" * 64,
        },
        "task": {
            "task_id": "synthetic-task",
            "input": task_input,
            "input_sha256": hashlib.sha256(task_input.encode()).hexdigest(),
            "verifier_case": "synthetic-case",
            "event_script": ["synthetic_event"],
        },
        "advice_projection": {
            "advice_id": "synthetic-advice",
            "artifact_sha256": "b" * 64,
            "canonical_sha256": "c" * 64,
            "template": "Synthetic advisory context.",
            "visibility": "visible",
            "authority": "advisory_only",
            "may_execute_for_participant": False,
            "may_override_constitution": False,
        },
        "authorization": {
            "authorization_id": "synthetic-authorization",
            "artifact_sha256": "d" * 64,
        },
        "ipc": {
            "request_id": "synthetic-request",
            "nonce": "e" * 64,
            "created_at": "2026-07-23T00:00:00+00:00",
        },
        "provider_response": None,
    }


def _validate_dockerfile(value: str) -> None:
    expected = (
        f"FROM python@{BASE_IMAGE_DIGEST}\n\n"
        "WORKDIR /opt/civitas\n"
        "COPY --chown=65532:65532 participant_runner.py "
        "/opt/civitas/participant_runner.py\n"
        "USER 65532:65532\n\n"
        f"ENTRYPOINT {json.dumps(ENTRYPOINT)}\n"
    )
    if value != expected:
        raise ValueError("participant runner Dockerfile contract drifted")


def _require_base_image() -> None:
    result = subprocess.run(
        ["docker", "image", "inspect", f"python@{BASE_IMAGE_DIGEST}"],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise ValueError(
            "pinned participant runner base image is not available locally"
        )


def _inspect_image(reference: str) -> dict[str, Any]:
    result = _run(["docker", "image", "inspect", reference])
    values = json.loads(result.stdout)
    if not isinstance(values, list) or len(values) != 1:
        raise ValueError("unexpected participant runner image inspect response")
    image = values[0]
    config = image.get("Config", {})
    if not (
        str(image.get("Id", "")).startswith("sha256:")
        and image.get("Architecture") == "amd64"
        and image.get("Os") == "linux"
        and config.get("Entrypoint") == ENTRYPOINT
        and config.get("User") == "65532:65532"
        and config.get("WorkingDir") == "/opt/civitas"
    ):
        raise ValueError("participant runner image configuration invalid")
    return image


def _implementation(repository_root: Path) -> dict[str, str]:
    revision = _run(["git", "rev-parse", "HEAD"], cwd=repository_root).stdout.strip()
    source_hashes = {
        str(path.relative_to(repository_root)): hashlib.sha256(
            path.read_bytes()
        ).hexdigest()
        for path in (DOCKERFILE, RUNNER_SOURCE, CONTRACT_SOURCE, Path(__file__))
    }
    return {
        "source_revision": revision,
        "source_sha256": canonical_sha256(source_hashes),
    }


def _run(
    command: list[str], *, cwd: Path | None = None
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=cwd, check=True, capture_output=True, text=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-id", required=True)
    parser.add_argument(
        "--created-at",
        default=datetime.now(timezone.utc).isoformat(),
    )
    parser.add_argument(
        "--image-tag", default="civitasos/j1d-participant-runner:qualified"
    )
    parser.add_argument(
        "--repository-root", type=Path, default=Path(__file__).parents[1]
    )
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    report = qualify_runner_image(
        build_id=args.build_id,
        created_at=args.created_at,
        image_tag=args.image_tag,
        repository_root=args.repository_root,
        output_root=args.output_root,
    )
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
