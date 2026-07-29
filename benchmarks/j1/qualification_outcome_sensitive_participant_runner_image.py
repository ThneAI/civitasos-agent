"""Contracts for the content-addressed outcome-sensitive runner image."""

from __future__ import annotations

from typing import Any

from .controlled_comparison import canonical_sha256
from .qualification_participant_runner_image import (
    BASE_IMAGE_DIGEST,
    ENTRYPOINT,
    RUNTIME_BOUNDARY,
)


MANIFEST_SCHEMA = "j1-qualification-outcome-sensitive-runner-image:v1"
RUNNER_PROTOCOL = {
    "input_schema": "j1-qualification-outcome-sensitive-runner-input:v1",
    "structured_decision_schema": "j1-qualification-structured-decision:v1",
    "strict_structured_decision": True,
    "mentor_baseline_empty_advice": True,
    "fixture_ground_truth_available": False,
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
        "runner_protocol": RUNNER_PROTOCOL,
        "smoke": smoke,
        "implementation": implementation,
        "readiness": {
            "image_built": True,
            "image_content_addressed": True,
            "baseline_empty_advice_smoke_passed": True,
            "treatment_advice_smoke_passed": True,
            "strict_decision_smoke_passed": True,
            "ground_truth_rejection_smoke_passed": True,
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
        value,
        expected_implementation=implementation,
    )
    if failures:
        raise ValueError(
            f"outcome-sensitive runner image manifest invalid: {failures}"
        )
    return value


def validate_runner_image_manifest(
    value: Any,
    *,
    expected_implementation: dict[str, str],
) -> list[str]:
    manifest = value if isinstance(value, dict) else {}
    failures: list[str] = []
    _require(
        manifest.get("schema_version") == MANIFEST_SCHEMA
        and manifest.get("status") == "offline_qualified_review_required"
        and _text(manifest.get("build_id"))
        and _text(manifest.get("created_at")),
        "outcome_runner_image_identity_invalid",
        failures,
    )
    source = manifest.get("source", {})
    _require(
        source.get("base_image_digest") == BASE_IMAGE_DIGEST
        and all(
            _sha256(source.get(field))
            for field in (
                "dockerfile_sha256",
                "runner_source_sha256",
                "build_context_sha256",
            )
        ),
        "outcome_runner_image_source_invalid",
        failures,
    )
    image = manifest.get("image", {})
    image_id = str(image.get("image_id", ""))
    _require(
        image_id.startswith("sha256:")
        and _sha256(image_id.removeprefix("sha256:"))
        and image.get("content_addressed_reference") == image_id
        and image.get("architecture") == "amd64"
        and image.get("os") == "linux"
        and image.get("entrypoint") == ENTRYPOINT
        and image.get("configured_user") == "65532:65532"
        and image.get("working_dir") == "/opt/civitas",
        "outcome_runner_image_content_address_invalid",
        failures,
    )
    smoke = manifest.get("smoke", {})
    _require(
        smoke.get("baseline_empty_advice_exit_code") == 0
        and smoke.get("treatment_advice_exit_code") == 0
        and _sha256(smoke.get("baseline_output_sha256"))
        and _sha256(smoke.get("treatment_output_sha256"))
        and type(smoke.get("ground_truth_negative_exit_code")) is int
        and smoke["ground_truth_negative_exit_code"] != 0
        and smoke.get("ground_truth_negative_output_created") is False
        and smoke.get("strict_structured_decision_tested_in_process") is True
        and smoke.get("synthetic_only") is True,
        "outcome_runner_image_smoke_invalid",
        failures,
    )
    _require(
        manifest.get("runtime_boundary") == RUNTIME_BOUNDARY
        and manifest.get("runner_protocol") == RUNNER_PROTOCOL
        and manifest.get("implementation") == expected_implementation,
        "outcome_runner_image_boundary_or_implementation_invalid",
        failures,
    )
    readiness = manifest.get("readiness", {})
    _require(
        all(
            readiness.get(field) is True
            for field in (
                "image_built",
                "image_content_addressed",
                "baseline_empty_advice_smoke_passed",
                "treatment_advice_smoke_passed",
                "strict_decision_smoke_passed",
                "ground_truth_rejection_smoke_passed",
            )
        )
        and readiness.get("participant_execution_allowed") is False
        and readiness.get("infrastructure_rebind_allowed") is False,
        "outcome_runner_image_readiness_invalid",
        failures,
    )
    body = {
        key: item
        for key, item in manifest.items()
        if key != "manifest_sha256"
    }
    _require(
        manifest.get("manifest_sha256") == canonical_sha256(body),
        "outcome_runner_image_hash_invalid",
        failures,
    )
    return list(dict.fromkeys(failures))


def _sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(char in "0123456789abcdef" for char in value)
    )


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _require(condition: bool, reason: str, failures: list[str]) -> None:
    if not condition:
        failures.append(reason)
