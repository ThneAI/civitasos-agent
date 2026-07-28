"""Prepare 180 unsigned outcome-sensitive J1-D treatment advice candidates."""

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
from benchmarks.j1.qualification_outcome_sensitive_treatment_advice import (
    ADVICE_TEMPLATES,
    MANIFEST_BOUNDARY,
    MANIFEST_SCHEMA,
    TREATMENT_ORDINALS,
    authorization_statement,
    build_advice_candidate,
    validate_advice_candidate,
)


REPORT_SCHEMA = (
    "j1-qualification-outcome-sensitive-treatment-advice-preflight:v1"
)
DOMAIN_SOURCE = (
    Path(__file__).parent
    / "j1"
    / "qualification_outcome_sensitive_treatment_advice.py"
)
OPERATION_SOURCE = Path(__file__)


def prepare_treatment_advice(
    *,
    batch_id: str,
    created_at: str,
    protocol_path: Path,
    task_fixture_path: Path,
    reviewed_assignment_path: Path,
    assignment_gate_path: Path,
    mentor_identity_path: Path,
    mentor_identity_gate_path: Path,
    repository_root: Path,
    output_root: Path,
) -> dict[str, Any]:
    if output_root.exists():
        raise FileExistsError(f"outcome advice output exists: {output_root}")
    if not batch_id.strip():
        raise ValueError("outcome advice batch ID is required")
    paths = {
        "protocol": protocol_path,
        "task_fixture": task_fixture_path,
        "reviewed_assignment": reviewed_assignment_path,
        "assignment_gate": assignment_gate_path,
        "mentor_identity": mentor_identity_path,
        "mentor_identity_gate": mentor_identity_gate_path,
    }
    sources = {name: _read_private(path) for name, path in paths.items()}
    values = {name: value for name, (value, _) in sources.items()}
    _validate_sources(paths=paths, sources=sources)
    implementation = _implementation(repository_root)
    protocol = values["protocol"]
    fixture = values["task_fixture"]
    assignment = values["reviewed_assignment"]
    mentor = values["mentor_identity"]
    tasks = sorted(
        (
            task
            for task in fixture["fixtures"]
            if task["task_ordinal"] in TREATMENT_ORDINALS
        ),
        key=lambda item: item["task_ordinal"],
    )
    assignments = sorted(
        assignment["assignments"], key=lambda item: item["pair_id"]
    )
    _validate_batch_members(assignments, tasks)
    source_binding = {
        name: _source_ref(
            paths[name],
            sources[name][1],
            _canonical_source_hash(
                name, values[name], sources[name][1]
            ),
        )
        for name in sorted(paths)
    }
    parent = output_root.resolve().parent
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    parent.chmod(0o700)
    staging = Path(tempfile.mkdtemp(prefix=f".{output_root.name}.", dir=parent))
    staging.chmod(0o700)
    candidates_root = staging / "candidates"
    candidates_root.mkdir(mode=0o700)
    try:
        artifacts: list[dict[str, Any]] = []
        for assigned in assignments:
            for task in tasks:
                candidate = build_advice_candidate(
                    created_at=created_at,
                    protocol=protocol,
                    task_fixture=fixture,
                    reviewed_assignment=assignment,
                    mentor_identity=mentor,
                    assignment=assigned,
                    task=task,
                )
                path = candidates_root / f"{candidate['advice_id']}.json"
                write_private_json(path, candidate)
                artifacts.append(
                    {
                        **_published_artifact(
                            path,
                            output_root / "candidates" / path.name,
                        ),
                        "advice_id": candidate["advice_id"],
                        "pair_id": candidate["recipient"]["pair_id"],
                        "participant_id": candidate["recipient"][
                            "participant_id"
                        ],
                        "task_id": candidate["task"]["task_id"],
                        "task_ordinal": candidate["task"]["task_ordinal"],
                        "phase": candidate["task"]["phase"],
                        "canonical_sha256": candidate["candidate_sha256"],
                    }
                )
        manifest = {
            "schema_version": MANIFEST_SCHEMA,
            "batch_id": batch_id,
            "status": "explicit_owner_signing_authorization_required",
            "created_at": created_at,
            "source_binding": source_binding,
            "mentor": {
                "mentor_id": mentor["mentor"]["mentor_id"],
                "mentor_did": mentor["mentor"]["did"],
                "credential_version": mentor["mentor"]["credential_version"],
                "public_key_sha256": mentor["mentor"]["public_key_sha256"],
                "signer_kind": mentor["mentor"]["signer_kind"],
            },
            "templates": {
                name: dict(template)
                for name, template in sorted(ADVICE_TEMPLATES.items())
            },
            "inventory": {
                "cohort": "mentor",
                "participant_count": 20,
                "treatment_task_count": 9,
                "candidate_count": 180,
                "unique_candidate_count": 180,
                "baseline_advice_count": 0,
                "control_advice_count": 0,
                "phase_template_count": 3,
                "prompt_copy_count": 0,
                "ground_truth_copy_count": 0,
                "action_or_pattern_identifier_copy_count": 0,
            },
            "candidates": artifacts,
            "implementation": implementation,
            "execution_boundary": dict(MANIFEST_BOUNDARY),
        }
        manifest["manifest_sha256"] = canonical_sha256(manifest)
        _validate_manifest(
            manifest,
            batch_id=batch_id,
            created_at=created_at,
            source_binding=source_binding,
            mentor=mentor,
            assignments=assignments,
            tasks=tasks,
            implementation=implementation,
            candidate_root=candidates_root,
        )
        manifest_path = (
            staging
            / "outcome-sensitive-treatment-advice-manifest.review-required.json"
        )
        write_private_json(manifest_path, manifest)
        manifest_raw_sha256 = hashlib.sha256(
            manifest_path.read_bytes()
        ).hexdigest()
        statement = authorization_statement(manifest, manifest_raw_sha256)
        report = {
            "schema_version": REPORT_SCHEMA,
            "passed": True,
            "failure_reasons": [],
            "state": (
                "outcome_sensitive_mentor_advice_candidates_"
                "owner_signing_authorization_required"
            ),
            "created_at": created_at,
            "manifest": {
                **_published_artifact(
                    manifest_path, output_root / manifest_path.name
                ),
                "canonical_sha256": manifest["manifest_sha256"],
            },
            "source_binding": source_binding,
            "inventory": manifest["inventory"],
            "authorization_request": {
                "required_exact_statement": statement,
                "statement_sha256": hashlib.sha256(
                    statement.encode()
                ).hexdigest(),
                "single_pkcs11_session_required": True,
                "signature_count": 180,
            },
            "implementation": implementation,
            "readiness": {
                "candidate_manifest_frozen": True,
                "owner_signing_authorization_present": False,
                "mentor_signatures_complete": False,
                "infrastructure_rebound": False,
                "controlled_experiment_execution_ready": False,
            },
            "execution_boundary": manifest["execution_boundary"],
        }
        report["report_sha256"] = canonical_sha256(report)
        write_private_json(
            staging / "outcome-sensitive-treatment-advice-preflight.json",
            report,
        )
        os.rename(staging, output_root)
        _fsync_directory(parent)
        return report
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def _validate_sources(
    *,
    paths: dict[str, Path],
    sources: dict[str, tuple[dict[str, Any], bytes]],
) -> None:
    values = {name: value for name, (value, _) in sources.items()}
    raws = {name: raw for name, (_, raw) in sources.items()}
    protocol = values["protocol"]
    fixture = values["task_fixture"]
    assignment = values["reviewed_assignment"]
    assignment_gate = values["assignment_gate"]
    mentor = values["mentor_identity"]
    mentor_gate = values["mentor_identity_gate"]
    failures: list[str] = []
    _require(
        protocol.get("schema_version")
        == "j1-qualification-outcome-sensitive-protocol-amendment:v1"
        and protocol.get("protocol_sha256")
        == canonical_sha256(
            {
                key: item
                for key, item in protocol.items()
                if key != "protocol_sha256"
            }
        )
        and protocol.get("treatment_contract", {}).get(
            "baseline_ordinals"
        )
        == [1, 2, 3]
        and protocol.get("treatment_contract", {}).get(
            "treatment_ordinals"
        )
        == list(TREATMENT_ORDINALS)
        and protocol.get("fresh_bindings_required", {}).get(
            "mentor_advice_candidates_and_signatures"
        )
        == 180,
        "outcome_advice_protocol_invalid",
        failures,
    )
    _require(
        fixture.get("schema_version")
        == "j1-qualification-outcome-sensitive-task-fixture-manifest:v1"
        and fixture.get("fixture_sha256")
        == canonical_sha256(
            {
                key: item
                for key, item in fixture.items()
                if key != "fixture_sha256"
            }
        )
        and fixture.get("inventory", {}).get("task_count") == 12
        and len(fixture.get("fixtures", [])) == 12,
        "outcome_advice_fixture_invalid",
        failures,
    )
    _require(
        assignment.get("schema_version")
        == (
            "j1-qualification-outcome-sensitive-"
            "assignment-rebound:operator-reviewed:v1"
        )
        and assignment.get("status") == "operator_reviewed"
        and assignment.get("reviewed_rebound_assignment_sha256")
        == canonical_sha256(
            {
                key: item
                for key, item in assignment.items()
                if key != "reviewed_rebound_assignment_sha256"
            }
        )
        and assignment.get("inventory", {}).get(
            "mentor_advice_required_count"
        )
        == 180
        and len(assignment.get("assignments", [])) == 20,
        "outcome_advice_assignment_invalid",
        failures,
    )
    assignment_gate_body = {
        key: item
        for key, item in assignment_gate.items()
        if key != "report_sha256"
    }
    _require(
        assignment_gate.get("passed") is True
        and assignment_gate.get("report_sha256")
        == canonical_sha256(assignment_gate_body)
        and assignment_gate.get("reviewed_artifacts", {}).get(
            "rebound_assignment"
        )
        == _source_ref(
            paths["reviewed_assignment"],
            raws["reviewed_assignment"],
            assignment["reviewed_rebound_assignment_sha256"],
        ),
        "outcome_advice_assignment_gate_invalid",
        failures,
    )
    mentor_body = {
        key: item for key, item in mentor.items() if key != "profile_sha256"
    }
    _require(
        mentor.get("profile_sha256") == canonical_sha256(mentor_body)
        and mentor.get("mentor", {}).get("signer_kind") == "pkcs11_ed25519"
        and mentor.get("pkcs11_key", {}).get("key_id_hex") == "4a32",
        "outcome_advice_mentor_identity_invalid",
        failures,
    )
    _require(
        mentor_gate.get("passed") is True
        and mentor_gate.get("mentor_identity_sha256")
        == mentor.get("profile_sha256")
        and mentor_gate.get("artifacts", {}).get("mentor_identity")
        == _raw_ref(paths["mentor_identity"], raws["mentor_identity"])
        and mentor_gate.get("execution_boundary", {}).get(
            "treatment_advice_signing_allowed"
        )
        is False,
        "outcome_advice_mentor_gate_invalid",
        failures,
    )
    _require(
        assignment.get("outcome_sensitive_material_binding", {})
        .get("frozen_materials", {})
        .get("protocol", {})
        .get("canonical_sha256")
        == protocol.get("protocol_sha256")
        and assignment.get("outcome_sensitive_material_binding", {})
        .get("frozen_materials", {})
        .get("task_fixture", {})
        .get("canonical_sha256")
        == fixture.get("fixture_sha256"),
        "outcome_advice_material_binding_invalid",
        failures,
    )
    if failures:
        raise ValueError(f"outcome advice source chain invalid: {failures}")


def _validate_batch_members(
    assignments: list[dict[str, Any]],
    tasks: list[dict[str, Any]],
) -> None:
    combinations = {
        (item["mentor"]["participant_id"], task["task_id"])
        for item in assignments
        for task in tasks
    }
    if not (
        len(assignments) == 20
        and len(
            {item["mentor"]["participant_id"] for item in assignments}
        )
        == 20
        and len(tasks) == 9
        and [task["task_ordinal"] for task in tasks]
        == list(TREATMENT_ORDINALS)
        and all(task["phase"] in ADVICE_TEMPLATES for task in tasks)
        and len(combinations) == 180
        and all(item.get("control_advice_projection") == [] for item in assignments)
    ):
        raise ValueError("outcome advice batch members invalid")


def _validate_manifest(
    manifest: dict[str, Any],
    *,
    batch_id: str,
    created_at: str,
    source_binding: dict[str, Any],
    mentor: dict[str, Any],
    assignments: list[dict[str, Any]],
    tasks: list[dict[str, Any]],
    implementation: dict[str, str],
    candidate_root: Path,
) -> None:
    artifacts = manifest.get("candidates", [])
    combinations = {
        (item.get("participant_id"), item.get("task_id"))
        for item in artifacts
    }
    expected = {
        (item["mentor"]["participant_id"], task["task_id"])
        for item in assignments
        for task in tasks
    }
    body = {
        key: item
        for key, item in manifest.items()
        if key != "manifest_sha256"
    }
    inventory = manifest.get("inventory", {})
    if not (
        manifest.get("schema_version") == MANIFEST_SCHEMA
        and manifest.get("batch_id") == batch_id
        and manifest.get("status")
        == "explicit_owner_signing_authorization_required"
        and manifest.get("created_at") == created_at
        and manifest.get("source_binding") == source_binding
        and manifest.get("mentor", {}).get("mentor_did")
        == mentor.get("mentor", {}).get("did")
        and manifest.get("templates")
        == {
            name: dict(template)
            for name, template in sorted(ADVICE_TEMPLATES.items())
        }
        and inventory.get("candidate_count") == 180
        and inventory.get("unique_candidate_count") == 180
        and inventory.get("baseline_advice_count") == 0
        and inventory.get("control_advice_count") == 0
        and len(artifacts) == 180
        and combinations == expected
        and len({item.get("advice_id") for item in artifacts}) == 180
        and len({item.get("canonical_sha256") for item in artifacts}) == 180
        and manifest.get("implementation") == implementation
        and manifest.get("execution_boundary") == MANIFEST_BOUNDARY
        and manifest.get("manifest_sha256") == canonical_sha256(body)
    ):
        raise ValueError("outcome advice manifest invalid")
    assignment_index = {
        item["mentor"]["participant_id"]: item for item in assignments
    }
    task_index = {task["task_id"]: task for task in tasks}
    for artifact in artifacts:
        path = candidate_root / f"{artifact['advice_id']}.json"
        candidate, raw = _read_private(path)
        if not (
            hashlib.sha256(raw).hexdigest() == artifact["sha256"]
            and candidate.get("candidate_sha256")
            == artifact["canonical_sha256"]
            and validate_advice_candidate(
                candidate,
                protocol=_read_private(
                    Path(source_binding["protocol"]["path"])
                )[0],
                task_fixture=_read_private(
                    Path(source_binding["task_fixture"]["path"])
                )[0],
                reviewed_assignment=_read_private(
                    Path(source_binding["reviewed_assignment"]["path"])
                )[0],
                mentor_identity=mentor,
                assignment=assignment_index[artifact["participant_id"]],
                task=task_index[artifact["task_id"]],
            )
            == []
        ):
            raise ValueError("outcome advice candidate artifact invalid")


def _canonical_source_hash(
    name: str, value: dict[str, Any], raw: bytes
) -> str:
    fields = {
        "protocol": "protocol_sha256",
        "task_fixture": "fixture_sha256",
        "reviewed_assignment": "reviewed_rebound_assignment_sha256",
        "assignment_gate": "report_sha256",
        "mentor_identity": "profile_sha256",
    }
    if name == "mentor_identity_gate":
        return hashlib.sha256(raw).hexdigest()
    return str(value[fields[name]])


def _implementation(repository_root: Path) -> dict[str, str]:
    root = repository_root.resolve()
    if _git(root, "status", "--porcelain"):
        raise ValueError("repository must be clean before freezing outcome advice")
    revision = _git(root, "rev-parse", "HEAD")
    upstream = subprocess.run(
        ["git", "merge-base", "--is-ancestor", revision, "@{upstream}"],
        cwd=root,
        check=False,
    )
    if upstream.returncode != 0:
        raise ValueError("outcome advice revision is not pushed")
    hashes = {
        str(source.relative_to(root)): hashlib.sha256(
            source.read_bytes()
        ).hexdigest()
        for source in (DOMAIN_SOURCE, OPERATION_SOURCE)
    }
    return {
        "source_revision": revision,
        "source_sha256": canonical_sha256(hashes),
    }


def _read_private(path: Path) -> tuple[dict[str, Any], bytes]:
    if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o077:
        raise ValueError(f"private JSON artifact invalid: {path}")
    raw = path.read_bytes()
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError(f"JSON artifact must be object: {path}")
    return value, raw


def _source_ref(
    path: Path, raw: bytes, canonical_sha256_value: str
) -> dict[str, str]:
    return {
        "path": str(path.resolve()),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "canonical_sha256": canonical_sha256_value,
    }


def _raw_ref(path: Path, raw: bytes) -> dict[str, str]:
    return {
        "path": str(path.resolve()),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def _published_artifact(path: Path, published_path: Path) -> dict[str, str]:
    return {
        "path": str(published_path.resolve()),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }


def _git(root: Path, *arguments: str) -> str:
    return subprocess.check_output(
        ["git", *arguments], cwd=root, text=True
    ).strip()


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _require(condition: bool, reason: str, failures: list[str]) -> None:
    if not condition and reason not in failures:
        failures.append(reason)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--batch-id", required=True)
    parser.add_argument("--protocol", type=Path, required=True)
    parser.add_argument("--task-fixture", type=Path, required=True)
    parser.add_argument("--reviewed-assignment", type=Path, required=True)
    parser.add_argument("--assignment-gate", type=Path, required=True)
    parser.add_argument("--mentor-identity", type=Path, required=True)
    parser.add_argument("--mentor-identity-gate", type=Path, required=True)
    parser.add_argument(
        "--repository-root", type=Path, default=Path(__file__).parents[1]
    )
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    report = prepare_treatment_advice(
        batch_id=args.batch_id,
        created_at=datetime.now(timezone.utc).astimezone().isoformat(),
        protocol_path=args.protocol,
        task_fixture_path=args.task_fixture,
        reviewed_assignment_path=args.reviewed_assignment,
        assignment_gate_path=args.assignment_gate,
        mentor_identity_path=args.mentor_identity,
        mentor_identity_gate_path=args.mentor_identity_gate,
        repository_root=args.repository_root,
        output_root=args.output_root,
    )
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
