from __future__ import annotations

import copy
import hashlib
import json
import subprocess
from pathlib import Path

import benchmarks.j1_qualification_infrastructure_activate as activation_operation
from benchmarks.j1.controlled_comparison import canonical_sha256
from benchmarks.j1.qualification_infrastructure_activation import (
    creation_authorization_statement,
    docker_create_command,
    inspect_projection,
    validate_reviewed_activation_source,
)
from benchmarks.tests.test_j1_qualification_infrastructure_rebind import _plan


REVIEWED_SHA256 = "a" * 64
AUTHORIZATION_SHA256 = "b" * 64


def _isolation() -> dict:
    return _plan()[0]["isolations"][0]


def _inspect(isolation: dict) -> dict:
    target = isolation["target_isolation"]
    labels = {
        "civitasos.j1d.rebind": "rebind-r1",
        "civitasos.j1d.participant": isolation["participant_id"],
        "civitasos.j1d.pair": isolation["pair_id"],
        "civitasos.j1d.cohort": isolation["cohort"],
        "civitasos.j1d.reviewed-artifact": REVIEWED_SHA256,
        "civitasos.j1d.creation-authorization": AUTHORIZATION_SHA256,
    }
    return {
        "Id": "c" * 64,
        "Name": f"/{target['container_name']}",
        "Image": target["image_id"],
        "State": {"Status": "created", "Running": False},
        "Config": {
            "Entrypoint": target["entrypoint"],
            "Cmd": None,
            "User": "1000:1000",
            "Labels": labels,
            "Env": ["PATH=/usr/bin", "LANG=C.UTF-8"],
        },
        "HostConfig": {
            "NetworkMode": "none",
            "ReadonlyRootfs": True,
            "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges:true"],
            "PidsLimit": 64,
            "Memory": 268_435_456,
            "NanoCpus": 250_000_000,
            "Privileged": False,
            "Devices": [],
            "Tmpfs": {"/tmp": "rw,noexec,nosuid,size=16777216"},
        },
        "Mounts": [
            {
                "Type": "bind",
                "Source": target["input_root"],
                "Destination": "/input",
                "RW": False,
            },
            {
                "Type": "bind",
                "Source": target["output_root"],
                "Destination": "/output",
                "RW": True,
            },
        ],
    }


def test_authorization_statement_binds_artifacts_image_and_create_only_scope() -> None:
    statement = creation_authorization_statement(
        reviewed_raw_sha256="1" * 64,
        reviewed_canonical_sha256="2" * 64,
        gate_raw_sha256="3" * 64,
        gate_canonical_sha256="4" * 64,
        image_id=f"sha256:{'5' * 64}",
    )

    assert "exactly 40 stopped replacement containers" in statement
    assert f"sha256:{'5' * 64}" in statement
    assert "does not permit starting any container" in statement
    assert "bounded rollback removal of only containers" in statement
    assert "all reviewed source containers remain untouched" in statement
    assert "no historical container or image pruning is authorized" in statement


def test_docker_create_command_has_frozen_hardening_and_no_start() -> None:
    isolation = _isolation()
    command = docker_create_command(
        rebind_id="rebind-r1",
        reviewed_canonical_sha256=REVIEWED_SHA256,
        authorization_sha256=AUTHORIZATION_SHA256,
        isolation=isolation,
        uid=1000,
        gid=1000,
    )

    assert command[:2] == ["docker", "create"]
    assert "start" not in command
    assert "run" not in command
    assert command[-1] == isolation["target_isolation"]["content_addressed_image"]
    assert ["--network", "none"] == command[
        command.index("--network") : command.index("--network") + 2
    ]
    assert "type=bind" in " ".join(command)
    assert any("dst=/input,readonly" in item for item in command)
    assert any("dst=/output" in item for item in command)


def test_inspect_projection_accepts_stopped_container_and_rejects_drift() -> None:
    isolation = _isolation()
    value = _inspect(isolation)
    projection, failures = inspect_projection(
        value,
        isolation=isolation,
        rebind_id="rebind-r1",
        reviewed_canonical_sha256=REVIEWED_SHA256,
        authorization_sha256=AUTHORIZATION_SHA256,
        uid=1000,
        gid=1000,
    )

    assert failures == []
    assert projection["state"] == {"status": "created", "running": False}
    assert projection["runtime_boundary"]["network_mode"] == "none"

    tampered = copy.deepcopy(value)
    tampered["State"] = {"Status": "running", "Running": True}
    tampered["HostConfig"]["NetworkMode"] = "bridge"
    tampered["Config"]["Env"].append("DEEPSEEK_API_KEY=secret")
    _, failures = inspect_projection(
        tampered,
        isolation=isolation,
        rebind_id="rebind-r1",
        reviewed_canonical_sha256=REVIEWED_SHA256,
        authorization_sha256=AUTHORIZATION_SHA256,
        uid=1000,
        gid=1000,
    )
    assert "activation_container_started_or_state_invalid" in failures
    assert "activation_runtime_boundary_invalid" in failures
    assert "activation_forbidden_environment_present" in failures


def test_activation_source_requires_promoted_zero_container_gate() -> None:
    reviewed = {
        "schema_version": (
            "j1-qualification-infrastructure-rebind:operator-reviewed:v1"
        ),
        "status": "operator_reviewed",
        "isolations": [
            {"participant_id": f"participant-{index}"} for index in range(40)
        ],
    }
    reviewed["reviewed_infrastructure_rebind_sha256"] = canonical_sha256(reviewed)
    reviewed_raw = json.dumps(reviewed, sort_keys=True).encode()
    gate = {
        "passed": True,
        "failure_reasons": [],
        "state": (
            "infrastructure_artifact_promoted_"
            "replacement_container_authorization_required"
        ),
        "reviewed_artifact": {
            "sha256": hashlib.sha256(reviewed_raw).hexdigest(),
            "canonical_sha256": reviewed["reviewed_infrastructure_rebind_sha256"],
        },
        "readiness": {
            "participant_containers_created": 0,
            "participant_containers_started": 0,
        },
    }
    gate["report_sha256"] = canonical_sha256(gate)

    assert (
        validate_reviewed_activation_source(
            reviewed=reviewed,
            reviewed_raw=reviewed_raw,
            gate=gate,
        )
        == []
    )

    tampered = copy.deepcopy(gate)
    tampered["readiness"]["participant_containers_created"] = 1
    tampered["report_sha256"] = canonical_sha256(
        {key: item for key, item in tampered.items() if key != "report_sha256"}
    )
    failures = validate_reviewed_activation_source(
        reviewed=reviewed,
        reviewed_raw=reviewed_raw,
        gate=tampered,
    )
    assert "activation_promotion_gate_invalid" in failures


def test_activation_source_accepts_outcome_sensitive_promoted_gate() -> None:
    reviewed = {
        "schema_version": (
            "j1-qualification-outcome-sensitive-"
            "infrastructure-rebind:operator-reviewed:v1"
        ),
        "status": "operator_reviewed",
        "isolations": [
            {"participant_id": f"participant-{index}"} for index in range(40)
        ],
    }
    reviewed["reviewed_infrastructure_rebind_sha256"] = canonical_sha256(reviewed)
    reviewed_raw = json.dumps(reviewed, sort_keys=True).encode()
    gate = {
        "passed": True,
        "failure_reasons": [],
        "state": (
            "outcome_sensitive_infrastructure_artifact_promoted_"
            "replacement_container_authorization_required"
        ),
        "reviewed_artifact": {
            "sha256": hashlib.sha256(reviewed_raw).hexdigest(),
            "canonical_sha256": reviewed["reviewed_infrastructure_rebind_sha256"],
        },
        "readiness": {
            "participant_containers_created": 0,
            "participant_containers_started": 0,
        },
        "disk_safety": {
            "historical_container_cleanup_authorized": False,
            "implicit_container_prune_authorized": False,
            "implicit_image_prune_authorized": False,
            "source_container_removal_authorized": False,
        },
    }
    gate["report_sha256"] = canonical_sha256(gate)

    assert (
        validate_reviewed_activation_source(
            reviewed=reviewed,
            reviewed_raw=reviewed_raw,
            gate=gate,
        )
        == []
    )


def test_rollback_removes_only_recorded_ids_and_empty_created_directories(
    monkeypatch, tmp_path: Path
) -> None:
    parent = tmp_path / "states"
    child = parent / "participant"
    child.mkdir(parents=True)
    commands = []

    def fake_run(command, **_kwargs):
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(activation_operation.subprocess, "run", fake_run)

    failures = activation_operation._rollback(
        ["container-a", "container-b"],
        [parent, child],
    )

    assert failures == []
    assert commands == [
        ["docker", "container", "rm", "container-b"],
        ["docker", "container", "rm", "container-a"],
    ]
    assert not parent.exists()
