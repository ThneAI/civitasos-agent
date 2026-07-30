"""Create and verify exactly 40 stopped J1-D replacement containers."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any

from benchmarks.j1.controlled_comparison import canonical_sha256, write_private_json
from benchmarks.j1.qualification_infrastructure_activation import (
    ACTIVATION_BOUNDARY,
    ACTIVATION_SCHEMA,
    GATE_SCHEMA,
    creation_authorization_statement,
    docker_create_command,
    inspect_projection,
    validate_reviewed_activation_source,
)
from benchmarks.j1.qualification_participant_runner_image import (
    MANIFEST_SCHEMA as PARTICIPANT_RUNNER_MANIFEST_SCHEMA,
    validate_runner_image_manifest as validate_participant_runner_image_manifest,
)
from benchmarks.j1.qualification_outcome_sensitive_participant_runner_image import (
    MANIFEST_SCHEMA as OUTCOME_SENSITIVE_RUNNER_MANIFEST_SCHEMA,
    validate_runner_image_manifest as validate_outcome_sensitive_runner_image_manifest,
)
from benchmarks.j1_qualification_infrastructure_rebind import (
    _read_private,
    _require_target_names_absent,
    _validate_runner_image_local,
)
from benchmarks.j1_qualification_outcome_sensitive_infrastructure_rebind import (
    _inspect_parent_containers,
)


DOMAIN_SOURCE = (
    Path(__file__).parent / "j1" / "qualification_infrastructure_activation.py"
)
OPERATION_SOURCE = Path(__file__)


def activate_infrastructure(
    *,
    operation_id: str,
    created_at: str,
    authorization_statement: str,
    reviewed_artifact_path: Path,
    promotion_gate_path: Path,
    runner_manifest_path: Path,
    repository_root: Path,
    output_root: Path,
) -> dict[str, Any]:
    _require_rfc3339(created_at)
    if output_root.exists():
        raise ValueError(f"infrastructure activation output exists: {output_root}")
    reviewed, reviewed_raw = _read_private(reviewed_artifact_path)
    gate, gate_raw = _read_private(promotion_gate_path)
    runner_manifest, runner_manifest_raw = _read_private(runner_manifest_path)
    failures = validate_reviewed_activation_source(
        reviewed=reviewed,
        reviewed_raw=reviewed_raw,
        gate=gate,
    )
    if failures:
        raise ValueError(f"infrastructure activation source invalid: {failures}")
    reviewed_raw_sha256 = hashlib.sha256(reviewed_raw).hexdigest()
    gate_raw_sha256 = hashlib.sha256(gate_raw).hexdigest()
    reviewed_canonical_sha256 = reviewed["reviewed_infrastructure_rebind_sha256"]
    gate_canonical_sha256 = gate["report_sha256"]
    image_id = reviewed["runner_image"]["image_id"]
    expected_statement = creation_authorization_statement(
        reviewed_raw_sha256=reviewed_raw_sha256,
        reviewed_canonical_sha256=reviewed_canonical_sha256,
        gate_raw_sha256=gate_raw_sha256,
        gate_canonical_sha256=gate_canonical_sha256,
        image_id=image_id,
    )
    if authorization_statement != expected_statement:
        raise ValueError("replacement-container creation authorization mismatch")
    authorization_sha256 = hashlib.sha256(authorization_statement.encode()).hexdigest()
    manifest_failures = _validate_runner_manifest_for_activation(
        runner_manifest=runner_manifest,
        reviewed=reviewed,
    )
    runner_source = reviewed.get("source_binding", {}).get("runner_manifest")
    runner_raw_binding = (
        runner_source.get("sha256")
        if isinstance(runner_source, dict)
        else reviewed.get("source_binding", {}).get("runner_manifest_artifact_sha256")
    )
    if not (
        not manifest_failures
        and hashlib.sha256(runner_manifest_raw).hexdigest() == runner_raw_binding
        and runner_manifest.get("image", {}).get("image_id") == image_id
        and runner_manifest.get("manifest_sha256")
        == reviewed.get("runner_image", {}).get("manifest_sha256")
    ):
        raise ValueError("activation runner manifest binding invalid")
    _validate_runner_image_local(runner_manifest)
    _validate_outcome_source_containers(reviewed)
    isolations = reviewed["isolations"]
    names = [item["target_isolation"]["container_name"] for item in isolations]
    _require_target_names_absent(names)
    _validate_target_paths(isolations)
    implementation = _implementation(repository_root)
    output_root.mkdir(mode=0o700)
    output_root.chmod(0o700)
    journal_path = output_root / "replacement-container-creation-journal.json"
    created_containers: list[str] = []
    created_directories: list[Path] = []
    journal = {
        "schema_version": "j1-qualification-container-creation-journal:v1",
        "operation_id": operation_id,
        "created_at": created_at,
        "authorization_statement_sha256": authorization_sha256,
        "reviewed_infrastructure_sha256": reviewed_canonical_sha256,
        "state": "creating",
        "created_container_ids": [],
        "created_directories": [],
    }
    write_private_json(journal_path, journal)
    try:
        uid = os.getuid()
        gid = os.getgid()
        records = []
        for isolation in isolations:
            target = isolation["target_isolation"]
            _create_private_directories(
                [Path(target["input_root"]), Path(target["output_root"])],
                created_directories,
            )
            container_id = _create_container(
                docker_create_command(
                    rebind_id=reviewed["rebind_id"],
                    reviewed_canonical_sha256=reviewed_canonical_sha256,
                    authorization_sha256=authorization_sha256,
                    isolation=isolation,
                    uid=uid,
                    gid=gid,
                )
            )
            created_containers.append(container_id)
            _update_journal(
                journal_path,
                journal,
                containers=created_containers,
                directories=created_directories,
            )
            inspect = _docker_inspect(container_id)
            projection, inspect_failures = inspect_projection(
                inspect,
                isolation=isolation,
                rebind_id=reviewed["rebind_id"],
                reviewed_canonical_sha256=reviewed_canonical_sha256,
                authorization_sha256=authorization_sha256,
                uid=uid,
                gid=gid,
            )
            if inspect_failures:
                raise ValueError(
                    f"replacement container inspect invalid: {inspect_failures}"
                )
            records.append(
                {
                    "participant_id": isolation["participant_id"],
                    "execution_did": isolation["execution_did"],
                    "pair_id": isolation["pair_id"],
                    "cohort": isolation["cohort"],
                    "assignment_commitment_sha256": _assignment_commitment(isolation),
                    "expected_container_config_sha256": target[
                        "container_config_sha256"
                    ],
                    "container": projection,
                }
            )
        _revalidate_created_containers(
            records,
            reviewed=reviewed,
            reviewed_canonical_sha256=reviewed_canonical_sha256,
            authorization_sha256=authorization_sha256,
            uid=uid,
            gid=gid,
        )
        _validate_complete_set(records, reviewed)
        activation = {
            "schema_version": ACTIVATION_SCHEMA,
            "operation_id": operation_id,
            "created_at": created_at,
            "authorization": {
                "statement_sha256": authorization_sha256,
                "scope": "exactly_40_stopped_replacement_containers",
            },
            "source_binding": {
                "reviewed_artifact_sha256": reviewed_raw_sha256,
                "reviewed_infrastructure_sha256": reviewed_canonical_sha256,
                "promotion_gate_sha256": gate_raw_sha256,
                "promotion_gate_canonical_sha256": gate_canonical_sha256,
                "runner_manifest_sha256": runner_manifest["manifest_sha256"],
                "image_id": image_id,
            },
            "inventory": {
                "participant_count": 40,
                "mentor_count": 20,
                "control_count": 20,
                "container_created_count": 40,
                "container_started_count": 0,
            },
            "containers": sorted(records, key=lambda item: str(item["participant_id"])),
            "implementation": implementation,
            "execution_boundary": ACTIVATION_BOUNDARY,
        }
        activation["activation_sha256"] = canonical_sha256(activation)
        activation_path = output_root / "infrastructure-activation.json"
        write_private_json(activation_path, activation)
        journal["state"] = "completed"
        _update_journal(
            journal_path,
            journal,
            containers=created_containers,
            directories=created_directories,
        )
        report = {
            "schema_version": GATE_SCHEMA,
            "passed": True,
            "failure_reasons": [],
            "state": "replacement_containers_created_provider_admission_required",
            "operation_id": operation_id,
            "authorization_statement_sha256": authorization_sha256,
            "activation": {
                "path": str(activation_path.resolve()),
                "sha256": hashlib.sha256(activation_path.read_bytes()).hexdigest(),
                "canonical_sha256": activation["activation_sha256"],
            },
            "journal": _artifact(journal_path),
            "inventory": activation["inventory"],
            "rollback_performed": False,
            "readiness": {
                "runner_image_qualified": True,
                "roster_assignment_rebound": True,
                "infrastructure_artifact_promoted": True,
                "participant_isolation_rebound": True,
                "participant_containers_created": 40,
                "participant_containers_started": 0,
                "live_provider_admission_refreshed": False,
                "controlled_experiment_execution_ready": False,
            },
            "next_blocker": "live_provider_admission_refresh_required",
            "implementation": implementation,
            "execution_boundary": ACTIVATION_BOUNDARY,
        }
        report["report_sha256"] = canonical_sha256(report)
        write_private_json(
            output_root / "infrastructure-activation-gate-report.json", report
        )
        return report
    except Exception as error:
        rollback_failures = _rollback(created_containers, created_directories)
        journal["state"] = "rolled_back" if not rollback_failures else "rollback_failed"
        _update_journal(
            journal_path,
            journal,
            containers=created_containers,
            directories=created_directories,
        )
        failure = {
            "schema_version": GATE_SCHEMA,
            "passed": False,
            "failure_reasons": [type(error).__name__, *rollback_failures],
            "state": journal["state"],
            "operation_id": operation_id,
            "authorization_statement_sha256": authorization_sha256,
            "created_before_rollback": len(created_containers),
            "rollback_performed": True,
            "execution_boundary": {
                **ACTIVATION_BOUNDARY,
                "participant_isolation_rebound": False,
                "participant_container_created": False,
            },
        }
        failure["report_sha256"] = canonical_sha256(failure)
        write_private_json(
            output_root / "infrastructure-activation-gate-report.json", failure
        )
        raise RuntimeError(
            f"infrastructure activation failed and rollback state is "
            f"{journal['state']}: {error}"
        ) from error


def _validate_target_paths(isolations: list[dict[str, Any]]) -> None:
    roots = []
    for isolation in isolations:
        participant_id = isolation["participant_id"]
        target = isolation["target_isolation"]
        input_root = Path(target["input_root"])
        output_root = Path(target["output_root"])
        if not (
            input_root.is_absolute()
            and output_root.is_absolute()
            and input_root.name == "input"
            and output_root.name == "output"
            and input_root.parent == output_root.parent
            and input_root.parent.name == participant_id
            and not input_root.exists()
            and not output_root.exists()
            and not input_root.parent.exists()
        ):
            raise ValueError("activation target path invalid or already exists")
        roots.extend([input_root, output_root])
    if len(roots) != len(set(roots)) or len(roots) != 80:
        raise ValueError("activation target paths must be 80 unique paths")


def _validate_outcome_source_containers(reviewed: dict[str, Any]) -> None:
    if reviewed.get("schema_version") != (
        "j1-qualification-outcome-sensitive-infrastructure-rebind:operator-reviewed:v1"
    ):
        return
    source_binding = reviewed["source_binding"]
    parent_activation, _ = _read_private(
        Path(source_binding["parent_activation"]["path"])
    )
    reviewed_roster, _ = _read_private(Path(source_binding["reviewed_roster"]["path"]))
    current = _inspect_parent_containers(
        parent_activation=parent_activation,
        reviewed_roster=reviewed_roster,
    )
    expected = {
        item["participant_id"]: item["source_isolation"]["observed_state"]
        for item in reviewed["isolations"]
    }
    if current != expected:
        raise ValueError(
            "outcome activation source container state changed after promotion"
        )


def _validate_runner_manifest_for_activation(
    *,
    runner_manifest: dict[str, Any],
    reviewed: dict[str, Any],
) -> list[str]:
    expected_implementation = runner_manifest.get("implementation", {})
    if reviewed.get("schema_version") == (
        "j1-qualification-outcome-sensitive-infrastructure-rebind:"
        "operator-reviewed:v1"
    ):
        if (
            runner_manifest.get("schema_version")
            != OUTCOME_SENSITIVE_RUNNER_MANIFEST_SCHEMA
        ):
            return ["activation_outcome_runner_manifest_schema_invalid"]
        return validate_outcome_sensitive_runner_image_manifest(
            runner_manifest,
            expected_implementation=expected_implementation,
        )
    if runner_manifest.get("schema_version") != PARTICIPANT_RUNNER_MANIFEST_SCHEMA:
        return ["activation_participant_runner_manifest_schema_invalid"]
    return validate_participant_runner_image_manifest(
        runner_manifest,
        expected_implementation=expected_implementation,
    )


def _assignment_commitment(isolation: dict[str, Any]) -> str:
    value = isolation.get(
        "assignment_commitment_sha256",
        isolation.get("assignment_rebind_commitment_sha256"),
    )
    if not isinstance(value, str) or not value:
        raise ValueError("activation assignment commitment missing")
    return value


def _create_private_directories(
    paths: list[Path], created_directories: list[Path]
) -> None:
    for path in paths:
        missing = []
        cursor = path
        while not cursor.exists():
            missing.append(cursor)
            cursor = cursor.parent
        if cursor.is_symlink() or not cursor.is_dir():
            raise ValueError(f"activation directory ancestor invalid: {cursor}")
        path.mkdir(parents=True, mode=0o700)
        for created in reversed(missing):
            created.chmod(0o700)
            if created not in created_directories:
                created_directories.append(created)


def _create_container(command: list[str]) -> str:
    result = subprocess.run(command, check=False, capture_output=True, text=True)
    container_id = result.stdout.strip()
    if result.returncode != 0:
        raise ValueError(f"docker create failed: {result.stderr.strip()}")
    if not (
        len(container_id) == 64
        and all(char in "0123456789abcdef" for char in container_id.lower())
    ):
        raise ValueError("docker create returned an invalid container ID")
    return container_id


def _docker_inspect(container_id: str) -> dict[str, Any]:
    result = subprocess.run(
        ["docker", "container", "inspect", container_id],
        check=True,
        capture_output=True,
        text=True,
    )
    values = json.loads(result.stdout)
    if not (isinstance(values, list) and len(values) == 1):
        raise ValueError("docker inspect returned an invalid result")
    return values[0]


def _validate_complete_set(
    records: list[dict[str, Any]], reviewed: dict[str, Any]
) -> None:
    if not (
        len(records) == 40
        and len({item["participant_id"] for item in records}) == 40
        and len({item["container"]["container_id"] for item in records}) == 40
        and len({item["container"]["container_name"] for item in records}) == 40
        and sum(item["cohort"] == "mentor" for item in records) == 20
        and sum(item["cohort"] == "control" for item in records) == 20
        and {item["participant_id"] for item in records}
        == {
            item["participant_id"]
            for item in reviewed.get("isolations", [])
            if isinstance(item, dict)
        }
        and all(
            item["container"]["state"] == {"status": "created", "running": False}
            for item in records
        )
    ):
        raise ValueError("replacement container complete-set Gate failed")


def _revalidate_created_containers(
    records: list[dict[str, Any]],
    *,
    reviewed: dict[str, Any],
    reviewed_canonical_sha256: str,
    authorization_sha256: str,
    uid: int,
    gid: int,
) -> None:
    isolation_index = {item["participant_id"]: item for item in reviewed["isolations"]}
    for record in records:
        isolation = isolation_index[record["participant_id"]]
        projection, failures = inspect_projection(
            _docker_inspect(record["container"]["container_id"]),
            isolation=isolation,
            rebind_id=reviewed["rebind_id"],
            reviewed_canonical_sha256=reviewed_canonical_sha256,
            authorization_sha256=authorization_sha256,
            uid=uid,
            gid=gid,
        )
        if failures:
            raise ValueError(f"replacement container final inspect invalid: {failures}")
        record["container"] = projection


def _rollback(containers: list[str], directories: list[Path]) -> list[str]:
    failures = []
    for container_id in reversed(containers):
        result = subprocess.run(
            ["docker", "container", "rm", container_id],
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            failures.append("activation_container_rollback_failed")
    for path in sorted(directories, key=lambda item: len(item.parts), reverse=True):
        try:
            path.rmdir()
        except FileNotFoundError:
            continue
        except OSError:
            failures.append("activation_directory_rollback_failed")
    return list(dict.fromkeys(failures))


def _update_journal(
    path: Path,
    journal: dict[str, Any],
    *,
    containers: list[str],
    directories: list[Path],
) -> None:
    journal["created_container_ids"] = list(containers)
    journal["created_directories"] = [str(item.resolve()) for item in directories]
    write_private_json(path, journal)


def _implementation(repository_root: Path) -> dict[str, str]:
    root = repository_root.resolve()
    if _git(root, "status", "--porcelain").strip():
        raise ValueError("repository must be clean before infrastructure activation")
    revision = _git(root, "rev-parse", "HEAD").strip()
    if subprocess.run(
        ["git", "merge-base", "--is-ancestor", revision, "@{upstream}"],
        cwd=root,
        check=False,
    ).returncode:
        raise ValueError("infrastructure activation revision is not pushed")
    return {
        "source_revision": revision,
        "domain_source_sha256": hashlib.sha256(DOMAIN_SOURCE.read_bytes()).hexdigest(),
        "operation_source_sha256": hashlib.sha256(
            OPERATION_SOURCE.read_bytes()
        ).hexdigest(),
    }


def _git(root: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", *arguments], cwd=root, check=True, capture_output=True, text=True
    ).stdout


def _artifact(path: Path) -> dict[str, str]:
    return {
        "path": str(path.resolve()),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }


def _require_rfc3339(value: str) -> None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("activation timestamp invalid") from error
    if parsed.tzinfo is None:
        raise ValueError("activation timestamp must include timezone")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--operation-id", required=True)
    parser.add_argument("--created-at", required=True)
    parser.add_argument("--authorization-statement", required=True)
    parser.add_argument("--reviewed-artifact", type=Path, required=True)
    parser.add_argument("--promotion-gate", type=Path, required=True)
    parser.add_argument("--runner-manifest", type=Path, required=True)
    parser.add_argument(
        "--repository-root", type=Path, default=Path(__file__).parents[1]
    )
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    report = activate_infrastructure(
        operation_id=args.operation_id,
        created_at=args.created_at,
        authorization_statement=args.authorization_statement,
        reviewed_artifact_path=args.reviewed_artifact,
        promotion_gate_path=args.promotion_gate,
        runner_manifest_path=args.runner_manifest,
        repository_root=args.repository_root,
        output_root=args.output_root,
    )
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
