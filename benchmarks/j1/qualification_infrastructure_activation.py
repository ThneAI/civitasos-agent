"""Contracts for bounded J1-D replacement-container creation."""

from __future__ import annotations

import hashlib
from typing import Any

from .controlled_comparison import canonical_sha256


ACTIVATION_SCHEMA = "j1-qualification-infrastructure-activation:v1"
GATE_SCHEMA = "j1-qualification-infrastructure-activation-gate:v1"
OUTCOME_SENSITIVE_REVIEWED_SCHEMAS = {
    "j1-qualification-outcome-sensitive-infrastructure-rebind:operator-reviewed:v1",
    (
        "j1-qualification-outcome-sensitive-confirmatory-"
        "infrastructure-rebind:operator-reviewed:v1"
    ),
}
FORBIDDEN_ENVIRONMENT_NAMES = {
    "ANTHROPIC_API_KEY",
    "DEEPSEEK_API_KEY",
    "OPENAI_API_KEY",
    "PKCS11_PIN",
    "SOFTHSM2_CONF",
}
ACTIVATION_BOUNDARY = {
    "replacement_container_creation_only": True,
    "infrastructure_artifact_promoted": True,
    "participant_isolation_rebound": True,
    "participant_container_created": True,
    "participant_container_started": False,
    "provider_admission_refreshed": False,
    "provider_api_call_performed": False,
    "model_invocation_performed": False,
    "agent_execution_performed": False,
    "participant_task_execution_performed": False,
    "backend_fact_append_performed": False,
    "ledger_append_performed": False,
    "execution_authorization_issued_or_consumed": False,
}


def creation_authorization_statement(
    *,
    reviewed_raw_sha256: str,
    reviewed_canonical_sha256: str,
    gate_raw_sha256: str,
    gate_canonical_sha256: str,
    image_id: str,
) -> str:
    return (
        "I authorize exactly one bounded J1-D replacement-container creation "
        "operation covering the 40 participant isolation definitions in reviewed "
        f"infrastructure artifact raw SHA-256 {reviewed_raw_sha256}, canonical "
        f"SHA-256 {reviewed_canonical_sha256}, as promoted by Gate raw SHA-256 "
        f"{gate_raw_sha256}, canonical SHA-256 {gate_canonical_sha256}. I authorize "
        "creation of exactly 40 stopped replacement containers using "
        f"content-addressed image {image_id} and the participant-scoped names, "
        "mounts, resource limits, network isolation, runtime users, and security "
        "boundaries frozen in that reviewed artifact. I also authorize creation of "
        "the required participant-scoped local input/output directories and bounded "
        "rollback removal of only containers and empty directories created by this "
        "operation if the Gate fails. I acknowledge that historical isolation "
        "Evidence remains immutable, all reviewed source containers remain untouched, "
        "participant substitution is forbidden, and no historical container or image "
        "pruning is authorized. This authorization does not permit starting any "
        "container, provider admission refresh, provider or model calls, Agent "
        "execution, participant task execution, Backend Fact append, Ledger append, "
        "or execution authorization issuance or consumption."
    )


def docker_create_command(
    *,
    rebind_id: str,
    reviewed_canonical_sha256: str,
    authorization_sha256: str,
    isolation: dict[str, Any],
    uid: int,
    gid: int,
) -> list[str]:
    target = isolation["target_isolation"]
    return [
        "docker",
        "create",
        "--name",
        target["container_name"],
        "--label",
        f"civitasos.j1d.rebind={rebind_id}",
        "--label",
        f"civitasos.j1d.participant={isolation['participant_id']}",
        "--label",
        f"civitasos.j1d.pair={isolation['pair_id']}",
        "--label",
        f"civitasos.j1d.cohort={isolation['cohort']}",
        "--label",
        f"civitasos.j1d.reviewed-artifact={reviewed_canonical_sha256}",
        "--label",
        f"civitasos.j1d.creation-authorization={authorization_sha256}",
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--pids-limit",
        str(target["runtime_boundary"]["pids_limit"]),
        "--memory",
        str(target["runtime_boundary"]["memory_limit_bytes"]),
        "--cpus",
        _cpus(target["runtime_boundary"]["nano_cpus"]),
        "--user",
        f"{uid}:{gid}",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=16777216",
        "--mount",
        f"type=bind,src={target['input_root']},dst=/input,readonly",
        "--mount",
        f"type=bind,src={target['output_root']},dst=/output",
        target["content_addressed_image"],
    ]


def inspect_projection(
    value: dict[str, Any],
    *,
    isolation: dict[str, Any],
    rebind_id: str,
    reviewed_canonical_sha256: str,
    authorization_sha256: str,
    uid: int,
    gid: int,
) -> tuple[dict[str, Any], list[str]]:
    target = isolation["target_isolation"]
    config = _object(value.get("Config"))
    host = _object(value.get("HostConfig"))
    state = _object(value.get("State"))
    mounts = value.get("Mounts")
    mounts = mounts if isinstance(mounts, list) else []
    labels = _object(config.get("Labels"))
    environment = _environment(config.get("Env"))
    expected_labels = {
        "civitasos.j1d.rebind": rebind_id,
        "civitasos.j1d.participant": isolation["participant_id"],
        "civitasos.j1d.pair": isolation["pair_id"],
        "civitasos.j1d.cohort": isolation["cohort"],
        "civitasos.j1d.reviewed-artifact": reviewed_canonical_sha256,
        "civitasos.j1d.creation-authorization": authorization_sha256,
    }
    projection = {
        "container_id": value.get("Id"),
        "container_name": str(value.get("Name", "")).removeprefix("/"),
        "image_id": value.get("Image"),
        "entrypoint": config.get("Entrypoint"),
        "command": config.get("Cmd"),
        "runtime_user": config.get("User"),
        "state": {
            "status": state.get("Status"),
            "running": state.get("Running"),
        },
        "labels": {key: labels.get(key) for key in sorted(expected_labels)},
        "runtime_boundary": {
            "network_mode": host.get("NetworkMode"),
            "read_only_rootfs": host.get("ReadonlyRootfs"),
            "cap_drop": host.get("CapDrop"),
            "no_new_privileges": "no-new-privileges:true"
            in (host.get("SecurityOpt") or []),
            "pids_limit": host.get("PidsLimit"),
            "memory_limit_bytes": host.get("Memory"),
            "nano_cpus": host.get("NanoCpus"),
            "privileged": host.get("Privileged"),
            "devices": host.get("Devices") or [],
            "tmpfs": _object(host.get("Tmpfs")),
        },
        "mounts": sorted(
            [
                {
                    "type": item.get("Type"),
                    "source": item.get("Source"),
                    "destination": item.get("Destination"),
                    "rw": item.get("RW"),
                }
                for item in mounts
            ],
            key=lambda item: str(item["destination"]),
        ),
        "forbidden_environment_present": sorted(
            FORBIDDEN_ENVIRONMENT_NAMES.intersection(environment)
        ),
    }
    expected_mounts = [
        {
            "type": "bind",
            "source": target["input_root"],
            "destination": "/input",
            "rw": False,
        },
        {
            "type": "bind",
            "source": target["output_root"],
            "destination": "/output",
            "rw": True,
        },
    ]
    failures: list[str] = []
    _require(
        projection["container_name"] == target["container_name"]
        and projection["image_id"] == target["image_id"]
        and projection["entrypoint"] == target["entrypoint"]
        and projection["command"] in (None, [])
        and projection["runtime_user"] == f"{uid}:{gid}",
        "activation_container_identity_invalid",
        failures,
    )
    _require(
        projection["state"] == {"status": "created", "running": False},
        "activation_container_started_or_state_invalid",
        failures,
    )
    _require(
        projection["labels"] == expected_labels,
        "activation_container_labels_invalid",
        failures,
    )
    boundary = projection["runtime_boundary"]
    expected = target["runtime_boundary"]
    _require(
        boundary["network_mode"] == expected["network_mode"]
        and boundary["read_only_rootfs"] is expected["read_only_rootfs"]
        and boundary["cap_drop"] == ["ALL"]
        and boundary["no_new_privileges"] is expected["no_new_privileges"]
        and boundary["pids_limit"] == expected["pids_limit"]
        and boundary["memory_limit_bytes"] == expected["memory_limit_bytes"]
        and boundary["nano_cpus"] == expected["nano_cpus"]
        and boundary["privileged"] is False
        and boundary["devices"] == []
        and boundary["tmpfs"].get("/tmp") == "rw,noexec,nosuid,size=16777216",
        "activation_runtime_boundary_invalid",
        failures,
    )
    _require(
        projection["mounts"] == expected_mounts,
        "activation_mount_boundary_invalid",
        failures,
    )
    _require(
        projection["forbidden_environment_present"] == [],
        "activation_forbidden_environment_present",
        failures,
    )
    projection["actual_container_config_sha256"] = canonical_sha256(projection)
    return projection, failures


def validate_reviewed_activation_source(
    *,
    reviewed: dict[str, Any],
    reviewed_raw: bytes,
    gate: dict[str, Any],
) -> list[str]:
    failures: list[str] = []
    reviewed_body = {
        key: item
        for key, item in reviewed.items()
        if key != "reviewed_infrastructure_rebind_sha256"
    }
    gate_body = {key: item for key, item in gate.items() if key != "report_sha256"}
    schema = reviewed.get("schema_version")
    outcome_sensitive = schema in OUTCOME_SENSITIVE_REVIEWED_SCHEMAS
    confirmatory = schema == (
        "j1-qualification-outcome-sensitive-confirmatory-"
        "infrastructure-rebind:operator-reviewed:v1"
    )
    _require(
        schema
        in {
            "j1-qualification-infrastructure-rebind:operator-reviewed:v1",
            (
                "j1-qualification-outcome-sensitive-"
                "infrastructure-rebind:operator-reviewed:v1"
            ),
            (
                "j1-qualification-outcome-sensitive-confirmatory-"
                "infrastructure-rebind:operator-reviewed:v1"
            ),
        }
        and reviewed.get("status") == "operator_reviewed"
        and reviewed.get("reviewed_infrastructure_rebind_sha256")
        == canonical_sha256(reviewed_body)
        and len(reviewed.get("isolations", [])) == 40,
        "activation_reviewed_artifact_invalid",
        failures,
    )
    if confirmatory:
        expected_gate_state = (
            "confirmatory_infrastructure_artifact_promoted_"
            "replacement_container_authorization_required"
        )
    elif outcome_sensitive:
        expected_gate_state = (
            "outcome_sensitive_infrastructure_artifact_promoted_"
            "replacement_container_authorization_required"
        )
    else:
        expected_gate_state = (
            "infrastructure_artifact_promoted_"
            "replacement_container_authorization_required"
        )
    _require(
        gate.get("passed") is True
        and gate.get("failure_reasons") == []
        and gate.get("state") == expected_gate_state
        and gate.get("report_sha256") == canonical_sha256(gate_body)
        and gate.get("reviewed_artifact", {}).get("sha256")
        == hashlib.sha256(reviewed_raw).hexdigest()
        and gate.get("reviewed_artifact", {}).get("canonical_sha256")
        == reviewed.get("reviewed_infrastructure_rebind_sha256")
        and gate.get("readiness", {}).get("participant_containers_created") == 0
        and gate.get("readiness", {}).get("participant_containers_started") == 0
        and (
            not outcome_sensitive
            or gate.get("disk_safety")
            == {
                "historical_container_cleanup_authorized": False,
                "implicit_container_prune_authorized": False,
                "implicit_image_prune_authorized": False,
                "source_container_removal_authorized": False,
            }
        ),
        "activation_promotion_gate_invalid",
        failures,
    )
    return list(dict.fromkeys(failures))


def _cpus(nano_cpus: int) -> str:
    return f"{nano_cpus / 1_000_000_000:g}"


def _environment(value: Any) -> set[str]:
    if not isinstance(value, list):
        return set()
    return {str(item).partition("=")[0] for item in value}


def _object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _require(condition: bool, code: str, failures: list[str]) -> None:
    if not condition and code not in failures:
        failures.append(code)
