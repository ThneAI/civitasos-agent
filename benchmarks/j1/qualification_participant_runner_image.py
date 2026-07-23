"""Contracts for the content-addressed J1-D participant runner image."""

from __future__ import annotations

from typing import Any

from .controlled_comparison import canonical_sha256


MANIFEST_SCHEMA = "j1-qualification-participant-runner-image:v1"
BASE_IMAGE_DIGEST = (
    "sha256:86adf8dbadc3d6e82ee5dd2c74bec2e1c2467cdad47886280501df722372d2e1"
)
ENTRYPOINT = ["python", "-I", "/opt/civitas/participant_runner.py"]
RUNTIME_BOUNDARY = {
    "network_mode": "none",
    "read_only_rootfs": True,
    "cap_drop_all": True,
    "no_new_privileges": True,
    "pids_limit": 64,
    "memory_limit_bytes": 268_435_456,
    "nano_cpus": 250_000_000,
    "input_mount_read_only": True,
    "output_mount_read_write": True,
    "docker_socket_mounted": False,
    "provider_secret_available": False,
    "pkcs11_device_available": False,
}


def build_runner_image_manifest(
    *,
    build_id: str,
    created_at: str,
    dockerfile_sha256: str,
    runner_source_sha256: str,
    build_context_sha256: str,
    image_id: str,
    image_tag: str,
    architecture: str,
    os_name: str,
    implementation: dict[str, str],
    smoke: dict[str, Any],
) -> dict[str, Any]:
    value = {
        "schema_version": MANIFEST_SCHEMA,
        "build_id": build_id,
        "status": "offline_qualified_review_required",
        "created_at": created_at,
        "source": {
            "dockerfile_sha256": dockerfile_sha256,
            "runner_source_sha256": runner_source_sha256,
            "build_context_sha256": build_context_sha256,
            "base_image_digest": BASE_IMAGE_DIGEST,
        },
        "image": {
            "image_id": image_id,
            "content_addressed_reference": image_id,
            "local_tag": image_tag,
            "architecture": architecture,
            "os": os_name,
            "entrypoint": ENTRYPOINT,
            "configured_user": "65532:65532",
            "working_dir": "/opt/civitas",
        },
        "runtime_boundary": RUNTIME_BOUNDARY,
        "smoke": smoke,
        "implementation": implementation,
        "readiness": {
            "image_built": True,
            "image_content_addressed": True,
            "positive_smoke_passed": True,
            "negative_smoke_passed": True,
            "participant_execution_allowed": False,
            "infrastructure_rebind_allowed": False,
        },
        "execution_boundary": {
            "synthetic_image_smoke_only": True,
            "participant_container_created": False,
            "participant_container_started": False,
            "provider_api_call_performed": False,
            "model_invocation_performed": False,
            "agent_execution_performed": False,
            "backend_fact_append_performed": False,
            "ledger_append_performed": False,
        },
    }
    value["manifest_sha256"] = canonical_sha256(value)
    failures = validate_runner_image_manifest(
        value, expected_implementation=implementation
    )
    if failures:
        raise ValueError(f"participant runner image manifest invalid: {failures}")
    return value


def validate_runner_image_manifest(
    value: Any, *, expected_implementation: dict[str, str]
) -> list[str]:
    manifest = value if isinstance(value, dict) else {}
    failures: list[str] = []
    _require(
        set(manifest)
        == {
            "schema_version",
            "build_id",
            "status",
            "created_at",
            "source",
            "image",
            "runtime_boundary",
            "smoke",
            "implementation",
            "readiness",
            "execution_boundary",
            "manifest_sha256",
        },
        "runner_image_manifest_fields_invalid",
        failures,
    )
    _require(
        manifest.get("schema_version") == MANIFEST_SCHEMA,
        "runner_image_manifest_schema_invalid",
        failures,
    )
    _require(
        _text(manifest.get("build_id"))
        and manifest.get("status") == "offline_qualified_review_required"
        and _text(manifest.get("created_at")),
        "runner_image_manifest_identity_invalid",
        failures,
    )
    source = _object(manifest.get("source"))
    _require(
        set(source)
        == {
            "dockerfile_sha256",
            "runner_source_sha256",
            "build_context_sha256",
            "base_image_digest",
        }
        and all(
            _sha256(source.get(field))
            for field in (
                "dockerfile_sha256",
                "runner_source_sha256",
                "build_context_sha256",
            )
        )
        and source.get("base_image_digest") == BASE_IMAGE_DIGEST,
        "runner_image_source_invalid",
        failures,
    )
    image = _object(manifest.get("image"))
    image_id = str(image.get("image_id", ""))
    _require(
        set(image)
        == {
            "image_id",
            "content_addressed_reference",
            "local_tag",
            "architecture",
            "os",
            "entrypoint",
            "configured_user",
            "working_dir",
        }
        and image_id.startswith("sha256:")
        and _sha256(image_id.removeprefix("sha256:"))
        and image.get("content_addressed_reference") == image_id
        and _text(image.get("local_tag"))
        and image.get("architecture") == "amd64"
        and image.get("os") == "linux"
        and image.get("entrypoint") == ENTRYPOINT
        and image.get("configured_user") == "65532:65532"
        and image.get("working_dir") == "/opt/civitas",
        "runner_image_identity_invalid",
        failures,
    )
    _require(
        manifest.get("runtime_boundary") == RUNTIME_BOUNDARY,
        "runner_image_runtime_boundary_invalid",
        failures,
    )
    smoke = _object(manifest.get("smoke"))
    _require(
        set(smoke)
        == {
            "positive_exit_code",
            "positive_output_sha256",
            "positive_repeat_output_sha256",
            "deterministic_output",
            "negative_exit_code",
            "negative_output_created",
            "synthetic_only",
        }
        and smoke.get("positive_exit_code") == 0
        and _sha256(smoke.get("positive_output_sha256"))
        and smoke.get("positive_repeat_output_sha256")
        == smoke.get("positive_output_sha256")
        and smoke.get("deterministic_output") is True
        and type(smoke.get("negative_exit_code")) is int
        and smoke["negative_exit_code"] != 0
        and smoke.get("negative_output_created") is False
        and smoke.get("synthetic_only") is True,
        "runner_image_smoke_invalid",
        failures,
    )
    _require(
        manifest.get("implementation") == expected_implementation,
        "runner_image_implementation_invalid",
        failures,
    )
    _require(
        manifest.get("readiness")
        == {
            "image_built": True,
            "image_content_addressed": True,
            "positive_smoke_passed": True,
            "negative_smoke_passed": True,
            "participant_execution_allowed": False,
            "infrastructure_rebind_allowed": False,
        },
        "runner_image_readiness_invalid",
        failures,
    )
    _require(
        manifest.get("execution_boundary")
        == {
            "synthetic_image_smoke_only": True,
            "participant_container_created": False,
            "participant_container_started": False,
            "provider_api_call_performed": False,
            "model_invocation_performed": False,
            "agent_execution_performed": False,
            "backend_fact_append_performed": False,
            "ledger_append_performed": False,
        },
        "runner_image_execution_boundary_invalid",
        failures,
    )
    body = {key: item for key, item in manifest.items() if key != "manifest_sha256"}
    _require(
        manifest.get("manifest_sha256") == canonical_sha256(body),
        "runner_image_manifest_hash_invalid",
        failures,
    )
    return list(dict.fromkeys(failures))


def _sha256(value: Any) -> bool:
    text = str(value or "")
    return len(text) == 64 and all(char in "0123456789abcdef" for char in text)


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _require(condition: bool, code: str, failures: list[str]) -> None:
    if not condition and code not in failures:
        failures.append(code)
