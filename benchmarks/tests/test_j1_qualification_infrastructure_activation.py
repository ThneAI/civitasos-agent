from __future__ import annotations

import copy
import hashlib
import json
import subprocess
from pathlib import Path

import benchmarks.j1_qualification_infrastructure_activate as activation_operation
import benchmarks.j1_qualification_infrastructure_activation_preflight as activation_preflight
from benchmarks.j1.controlled_comparison import canonical_sha256
from benchmarks.j1.qualification_infrastructure_activation import (
    creation_authorization_statement,
    docker_create_command,
    inspect_projection,
    validate_reviewed_activation_source,
)
from benchmarks.j1.qualification_outcome_sensitive_participant_runner_image import (
    build_runner_image_manifest as build_outcome_runner_image_manifest,
)
from benchmarks.j1.qualification_participant_runner_image import (
    build_runner_image_manifest as build_participant_runner_image_manifest,
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


def test_activation_source_accepts_confirmatory_promoted_gate() -> None:
    reviewed = {
        "schema_version": (
            "j1-qualification-outcome-sensitive-confirmatory-"
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
            "confirmatory_infrastructure_artifact_promoted_"
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


def test_activation_selects_runner_validator_from_reviewed_schema() -> None:
    implementation = {
        "source_revision": "a" * 40,
        "source_sha256": "b" * 64,
    }
    common = {
        "build_id": "runner-r1",
        "created_at": "2026-07-30T00:00:00+00:00",
        "dockerfile_sha256": "1" * 64,
        "runner_source_sha256": "2" * 64,
        "build_context_sha256": "3" * 64,
        "image_id": f"sha256:{'4' * 64}",
        "image_tag": "civitasos/test:runner-r1",
        "architecture": "amd64",
        "os_name": "linux",
        "implementation": implementation,
    }
    outcome_manifest = build_outcome_runner_image_manifest(
        **common,
        smoke={
            "baseline_empty_advice_exit_code": 0,
            "baseline_output_sha256": "5" * 64,
            "treatment_advice_exit_code": 0,
            "treatment_output_sha256": "6" * 64,
            "ground_truth_negative_exit_code": 1,
            "ground_truth_negative_output_created": False,
            "strict_structured_decision_tested_in_process": True,
            "synthetic_only": True,
        },
    )
    participant_manifest = build_participant_runner_image_manifest(
        **common,
        smoke={
            "positive_exit_code": 0,
            "positive_output_sha256": "7" * 64,
            "positive_repeat_output_sha256": "7" * 64,
            "deterministic_output": True,
            "negative_exit_code": 1,
            "negative_output_created": False,
            "synthetic_only": True,
        },
    )
    outcome_reviewed = {
        "schema_version": (
            "j1-qualification-outcome-sensitive-"
            "infrastructure-rebind:operator-reviewed:v1"
        )
    }
    confirmatory_reviewed = {
        "schema_version": (
            "j1-qualification-outcome-sensitive-confirmatory-"
            "infrastructure-rebind:operator-reviewed:v1"
        )
    }
    participant_reviewed = {
        "schema_version": (
            "j1-qualification-infrastructure-rebind:operator-reviewed:v1"
        )
    }

    assert (
        activation_operation._validate_runner_manifest_for_activation(
            runner_manifest=outcome_manifest,
            reviewed=outcome_reviewed,
        )
        == []
    )
    assert (
        activation_operation._validate_runner_manifest_for_activation(
            runner_manifest=outcome_manifest,
            reviewed=confirmatory_reviewed,
        )
        == []
    )
    assert (
        activation_operation._validate_runner_manifest_for_activation(
            runner_manifest=participant_manifest,
            reviewed=participant_reviewed,
        )
        == []
    )
    assert (
        activation_operation._validate_runner_manifest_for_activation(
            runner_manifest=participant_manifest,
            reviewed=outcome_reviewed,
        )
        == ["activation_outcome_runner_manifest_schema_invalid"]
    )
    assert (
        activation_operation._validate_runner_manifest_for_activation(
            runner_manifest=outcome_manifest,
            reviewed=participant_reviewed,
        )
        == ["activation_participant_runner_manifest_schema_invalid"]
    )


def test_activation_preflight_freezes_statement_without_container_effects(
    tmp_path: Path, monkeypatch
) -> None:
    target_root = tmp_path / "target-state"
    isolations = [
        {
            "participant_id": f"participant-{index:02d}",
            "cohort": "mentor" if index < 20 else "control",
            "target_isolation": {
                "container_name": f"target-{index:02d}",
                "input_root": str(target_root / f"participant-{index:02d}" / "input"),
                "output_root": str(
                    target_root / f"participant-{index:02d}" / "output"
                ),
            },
        }
        for index in range(40)
    ]
    runner = {"manifest_sha256": "f" * 64, "image": {"image_id": "sha256:image"}}
    runner_path = tmp_path / "runner.json"
    _write_private(runner_path, runner)
    reviewed = {
        "schema_version": (
            "j1-qualification-outcome-sensitive-confirmatory-"
            "infrastructure-rebind:operator-reviewed:v1"
        ),
        "status": "operator_reviewed",
        "source_binding": {
            "runner_manifest": {
                "sha256": hashlib.sha256(runner_path.read_bytes()).hexdigest()
            }
        },
        "runner_image": {
            "manifest_sha256": runner["manifest_sha256"],
            "image_id": "sha256:image",
        },
        "isolations": isolations,
    }
    reviewed["reviewed_infrastructure_rebind_sha256"] = canonical_sha256(reviewed)
    reviewed_path = tmp_path / "reviewed.json"
    _write_private(reviewed_path, reviewed)
    gate = {
        "passed": True,
        "failure_reasons": [],
        "state": (
            "confirmatory_infrastructure_artifact_promoted_"
            "replacement_container_authorization_required"
        ),
        "reviewed_artifact": {
            "sha256": hashlib.sha256(reviewed_path.read_bytes()).hexdigest(),
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
    gate_path = tmp_path / "gate.json"
    _write_private(gate_path, gate)
    monkeypatch.setattr(activation_preflight, "_validate_runner_binding", lambda **_: None)
    monkeypatch.setattr(activation_preflight, "_validate_runner_image_local", lambda _: None)
    monkeypatch.setattr(
        activation_preflight, "_validate_outcome_source_containers", lambda _: None
    )
    monkeypatch.setattr(activation_preflight, "_require_targets_absent", lambda **_: None)
    monkeypatch.setattr(activation_preflight, "_validate_target_paths", lambda _: None)
    monkeypatch.setattr(
        activation_preflight,
        "_docker_census",
        lambda: {
            "historical_j1_container_count": 240,
            "running_count": 0,
            "cleanup_authorized": False,
        },
    )
    monkeypatch.setattr(
        activation_preflight,
        "_implementation",
        lambda _: {"source_revision": "a" * 40, "source_sha256": "b" * 64},
    )
    output_root = tmp_path / "preflight"

    report = activation_preflight.prepare_activation_preflight(
        preflight_id="confirmatory-create-preflight-r1",
        created_at="2026-08-11T12:00:00+08:00",
        reviewed_artifact_path=reviewed_path,
        promotion_gate_path=gate_path,
        runner_manifest_path=runner_path,
        repository_root=tmp_path,
        output_root=output_root,
    )

    assert report["passed"] is True
    assert report["inventory"]["participant_count"] == 40
    assert report["readiness"]["replacement_container_creation_authorized"] is False
    assert report["execution_boundary"]["participant_container_created"] is False
    assert "exactly 40 stopped replacement containers" in report[
        "approval_request"
    ]["required_exact_statement"]
    assert not target_root.exists()
    artifact = output_root / "infrastructure-activation-authorization-preflight.json"
    assert artifact.is_file()
    assert artifact.stat().st_mode & 0o077 == 0


def _write_private(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")
    path.chmod(0o600)


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
