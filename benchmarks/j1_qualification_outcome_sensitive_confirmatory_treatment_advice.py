"""Prepare 180 unsigned prospective confirmatory J1-D advice candidates."""

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
from benchmarks.j1.qualification_outcome_sensitive_confirmatory_treatment_advice import (
    MANIFEST_BOUNDARY,
    MANIFEST_SCHEMA,
    authorization_statement,
    build_advice_candidate,
    validate_advice_candidate,
)
from benchmarks.j1.qualification_outcome_sensitive_treatment_advice import (
    ADVICE_TEMPLATES,
    TREATMENT_ORDINALS,
)


REPORT_SCHEMA = (
    "j1-qualification-outcome-sensitive-confirmatory-treatment-advice-preflight:v1"
)
DOMAIN_SOURCE = (
    Path(__file__).parent
    / "j1"
    / "qualification_outcome_sensitive_confirmatory_treatment_advice.py"
)
OPERATION_SOURCE = Path(__file__)


def prepare_confirmatory_treatment_advice(
    *,
    batch_id: str,
    created_at: str,
    protocol_path: Path,
    task_fixture_path: Path,
    confirmatory_method_path: Path,
    material_gate_path: Path,
    reviewed_assignment_path: Path,
    assignment_gate_path: Path,
    mentor_identity_path: Path,
    mentor_identity_gate_path: Path,
    repository_root: Path,
    output_root: Path,
) -> dict[str, Any]:
    if output_root.exists():
        raise FileExistsError(f"confirmatory advice output exists: {output_root}")
    if not batch_id.strip():
        raise ValueError("confirmatory advice batch ID is required")
    paths = {
        "protocol": protocol_path,
        "task_fixture": task_fixture_path,
        "confirmatory_method": confirmatory_method_path,
        "material_gate": material_gate_path,
        "reviewed_assignment": reviewed_assignment_path,
        "assignment_gate": assignment_gate_path,
        "mentor_identity": mentor_identity_path,
        "mentor_identity_gate": mentor_identity_gate_path,
    }
    sources = {name: _read_private(path) for name, path in paths.items()}
    values = {name: value for name, (value, _) in sources.items()}
    _validate_sources(paths=paths, sources=sources)
    implementation = _implementation(repository_root)
    fixture = values["task_fixture"]
    reviewed_assignment = values["reviewed_assignment"]
    assignments = sorted(
        reviewed_assignment["assignments"], key=lambda item: item["pair_id"]
    )
    tasks = sorted(
        (
            task
            for task in fixture["fixtures"]
            if task["task_ordinal"] in TREATMENT_ORDINALS
        ),
        key=lambda item: item["task_ordinal"],
    )
    _validate_batch_members(assignments, tasks)
    source_binding = {
        name: _source_ref(
            paths[name],
            sources[name][1],
            _canonical_source_hash(name, values[name], sources[name][1]),
        )
        for name in sorted(paths)
    }
    parent = output_root.resolve().parent
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    parent.chmod(0o700)
    staging = Path(tempfile.mkdtemp(prefix=f".{output_root.name}.", dir=parent))
    staging.chmod(0o700)
    candidate_root = staging / "candidates"
    candidate_root.mkdir(mode=0o700)
    try:
        artifacts = _write_candidates(
            candidate_root=candidate_root,
            output_root=output_root,
            created_at=created_at,
            values=values,
            assignments=assignments,
            tasks=tasks,
        )
        manifest = _build_manifest(
            batch_id=batch_id,
            created_at=created_at,
            source_binding=source_binding,
            mentor=values["mentor_identity"],
            artifacts=artifacts,
            implementation=implementation,
        )
        _validate_manifest(
            manifest,
            assignments=assignments,
            tasks=tasks,
            values=values,
            candidate_root=candidate_root,
        )
        manifest_name = "confirmatory-treatment-advice-manifest.review-required.json"
        manifest_path = staging / manifest_name
        write_private_json(manifest_path, manifest)
        raw_sha256 = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
        statement = authorization_statement(manifest, raw_sha256)
        report = {
            "schema_version": REPORT_SCHEMA,
            "passed": True,
            "failure_reasons": [],
            "state": (
                "confirmatory_mentor_advice_candidates_"
                "exact_owner_signing_authorization_required"
            ),
            "created_at": created_at,
            "manifest": {
                **_published_artifact(manifest_path, output_root / manifest_name),
                "canonical_sha256": manifest["manifest_sha256"],
            },
            "source_binding": source_binding,
            "inventory": manifest["inventory"],
            "authorization_request": {
                "required_exact_statement": statement,
                "statement_sha256": hashlib.sha256(statement.encode()).hexdigest(),
                "single_pkcs11_session_required": True,
                "signature_count": 180,
            },
            "implementation": implementation,
            "readiness": {
                "confirmatory_roster_assignment_promoted": True,
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
            staging / "confirmatory-treatment-advice-preflight.json",
            report,
        )
        os.rename(staging, output_root)
        _fsync_directory(parent)
        return report
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def _write_candidates(
    *,
    candidate_root: Path,
    output_root: Path,
    created_at: str,
    values: dict[str, dict[str, Any]],
    assignments: list[dict[str, Any]],
    tasks: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    artifacts: list[dict[str, Any]] = []
    for assignment in assignments:
        for task in tasks:
            candidate = build_advice_candidate(
                created_at=created_at,
                protocol=values["protocol"],
                task_fixture=values["task_fixture"],
                confirmatory_method=values["confirmatory_method"],
                reviewed_assignment=values["reviewed_assignment"],
                assignment_gate=values["assignment_gate"],
                mentor_identity=values["mentor_identity"],
                assignment=assignment,
                task=task,
            )
            path = candidate_root / f"{candidate['advice_id']}.json"
            write_private_json(path, candidate)
            artifacts.append(
                {
                    **_published_artifact(path, output_root / "candidates" / path.name),
                    "advice_id": candidate["advice_id"],
                    "pair_id": candidate["recipient"]["pair_id"],
                    "participant_id": candidate["recipient"]["participant_id"],
                    "confirmatory_consent_sha256": candidate["recipient"][
                        "confirmatory_consent_sha256"
                    ],
                    "task_id": candidate["task"]["task_id"],
                    "task_ordinal": candidate["task"]["task_ordinal"],
                    "phase": candidate["task"]["phase"],
                    "canonical_sha256": candidate["candidate_sha256"],
                }
            )
    return artifacts


def _build_manifest(
    *,
    batch_id: str,
    created_at: str,
    source_binding: dict[str, Any],
    mentor: dict[str, Any],
    artifacts: list[dict[str, Any]],
    implementation: dict[str, Any],
) -> dict[str, Any]:
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
            name: dict(template) for name, template in sorted(ADVICE_TEMPLATES.items())
        },
        "inventory": {
            "cohort": "mentor",
            "participant_count": 20,
            "treatment_task_count": 9,
            "candidate_count": 180,
            "unique_candidate_count": 180,
            "confirmatory_consent_binding_count": 180,
            "baseline_advice_count": 0,
            "control_advice_count": 0,
            "prior_advice_reuse_count": 0,
            "phase_template_count": 3,
            "prompt_copy_count": 0,
            "ground_truth_copy_count": 0,
            "action_or_pattern_identifier_copy_count": 0,
            "advice_adherence_observation_count": 0,
        },
        "candidates": artifacts,
        "implementation": implementation,
        "execution_boundary": dict(MANIFEST_BOUNDARY),
    }
    manifest["manifest_sha256"] = canonical_sha256(manifest)
    return manifest


def _validate_sources(
    *,
    paths: dict[str, Path],
    sources: dict[str, tuple[dict[str, Any], bytes]],
) -> None:
    values = {name: value for name, (value, _) in sources.items()}
    raws = {name: raw for name, (_, raw) in sources.items()}
    protocol = values["protocol"]
    fixture = values["task_fixture"]
    method = values["confirmatory_method"]
    material_gate = values["material_gate"]
    assignment = values["reviewed_assignment"]
    assignment_gate = values["assignment_gate"]
    mentor = values["mentor_identity"]
    mentor_gate = values["mentor_identity_gate"]
    failures: list[str] = []
    _require(
        protocol.get("schema_version")
        == "j1-qualification-outcome-sensitive-protocol-amendment:v1"
        and protocol.get("protocol_sha256") == _body_hash(protocol, "protocol_sha256")
        and protocol.get("treatment_contract", {}).get("baseline_ordinals") == [1, 2, 3]
        and protocol.get("treatment_contract", {}).get("treatment_ordinals")
        == list(TREATMENT_ORDINALS),
        "confirmatory_advice_protocol_invalid",
        failures,
    )
    _require(
        fixture.get("schema_version")
        == "j1-qualification-outcome-sensitive-task-fixture-manifest:v1"
        and fixture.get("fixture_sha256") == _body_hash(fixture, "fixture_sha256")
        and fixture.get("inventory", {}).get("task_count") == 12
        and len(fixture.get("fixtures", [])) == 12,
        "confirmatory_advice_fixture_invalid",
        failures,
    )
    _require(
        method.get("schema_version") == "j1-outcome-sensitive-confirmatory-method:v1"
        and method.get("method_sha256") == _body_hash(method, "method_sha256"),
        "confirmatory_advice_method_invalid",
        failures,
    )
    _require(
        material_gate.get("schema_version")
        == "j1-confirmatory-amendment-promotion-gate:v1"
        and material_gate.get("passed") is True
        and material_gate.get("report_sha256")
        == _body_hash(material_gate, "report_sha256")
        and material_gate.get("state")
        == (
            "confirmatory_method_amendment_reviewed_frozen_"
            "40_of_40_consent_required_execution_blocked"
        ),
        "confirmatory_advice_material_gate_invalid",
        failures,
    )
    _require(
        assignment.get("schema_version")
        == (
            "j1-qualification-outcome-sensitive-confirmatory-"
            "assignment-rebound:operator-reviewed:v1"
        )
        and assignment.get("status") == "operator_reviewed"
        and assignment.get("reviewed_rebound_assignment_sha256")
        == _body_hash(assignment, "reviewed_rebound_assignment_sha256")
        and assignment.get("inventory", {}).get("mentor_advice_rebind_required_count")
        == 180
        and len(assignment.get("assignments", [])) == 20,
        "confirmatory_advice_assignment_invalid",
        failures,
    )
    assignment_ref = _source_ref(
        paths["reviewed_assignment"],
        raws["reviewed_assignment"],
        assignment.get("reviewed_rebound_assignment_sha256", ""),
    )
    _require(
        assignment_gate.get("schema_version")
        == (
            "j1-qualification-outcome-sensitive-confirmatory-"
            "roster-assignment-review-gate:v1"
        )
        and assignment_gate.get("passed") is True
        and assignment_gate.get("report_sha256")
        == _body_hash(assignment_gate, "report_sha256")
        and assignment_gate.get("reviewed_artifacts", {}).get("rebound_assignment")
        == assignment_ref
        and assignment_gate.get("readiness", {}).get("assignment_rebound") is True
        and assignment_gate.get("readiness", {}).get("mentor_advice_rebound_or_signed")
        is False,
        "confirmatory_advice_assignment_gate_invalid",
        failures,
    )
    frozen = assignment.get("confirmatory_material_binding", {}).get(
        "frozen_materials", {}
    )
    _require(
        frozen.get("confirmatory_method")
        == _source_ref(
            paths["confirmatory_method"],
            raws["confirmatory_method"],
            method.get("method_sha256", ""),
        )
        and assignment.get("confirmatory_material_binding", {}).get(
            "material_promotion_gate"
        )
        == _source_ref(
            paths["material_gate"],
            raws["material_gate"],
            material_gate.get("report_sha256", ""),
        )
        and all(
            item.get("protocol_sha256") == protocol.get("protocol_sha256")
            and item.get("task_fixture_sha256") == fixture.get("fixture_sha256")
            and item.get("confirmatory_method_sha256") == method.get("method_sha256")
            and item.get("mentor_confirmatory_advice_rebound") is False
            and item.get("advice_adherence_observed") is False
            for item in assignment.get("assignments", [])
        ),
        "confirmatory_advice_material_binding_invalid",
        failures,
    )
    mentor_body = {key: item for key, item in mentor.items() if key != "profile_sha256"}
    _require(
        mentor.get("profile_sha256") == canonical_sha256(mentor_body)
        and mentor.get("mentor", {}).get("signer_kind") == "pkcs11_ed25519"
        and mentor.get("pkcs11_key", {}).get("key_id_hex") == "4a32",
        "confirmatory_advice_mentor_identity_invalid",
        failures,
    )
    _require(
        mentor_gate.get("passed") is True
        and mentor_gate.get("mentor_identity_sha256") == mentor.get("profile_sha256")
        and mentor_gate.get("artifacts", {}).get("mentor_identity")
        == _raw_ref(paths["mentor_identity"], raws["mentor_identity"])
        and mentor_gate.get("execution_boundary", {}).get(
            "treatment_advice_signing_allowed"
        )
        is False,
        "confirmatory_advice_mentor_gate_invalid",
        failures,
    )
    if failures:
        raise ValueError(f"confirmatory advice source chain invalid: {failures}")


def _validate_batch_members(
    assignments: list[dict[str, Any]], tasks: list[dict[str, Any]]
) -> None:
    combinations = {
        (item["mentor"]["participant_id"], task["task_id"])
        for item in assignments
        for task in tasks
    }
    if not (
        len(assignments) == 20
        and len({item["mentor"]["participant_id"] for item in assignments}) == 20
        and len(tasks) == 9
        and [task["task_ordinal"] for task in tasks] == list(TREATMENT_ORDINALS)
        and all(task["phase"] in ADVICE_TEMPLATES for task in tasks)
        and len(combinations) == 180
        and all(item.get("control_advice_projection") == [] for item in assignments)
        and all(
            item.get("mentor_advice_required_ordinals") == list(TREATMENT_ORDINALS)
            for item in assignments
        )
    ):
        raise ValueError("confirmatory advice batch members invalid")


def _validate_manifest(
    manifest: dict[str, Any],
    *,
    assignments: list[dict[str, Any]],
    tasks: list[dict[str, Any]],
    values: dict[str, dict[str, Any]],
    candidate_root: Path,
) -> None:
    artifacts = manifest.get("candidates", [])
    expected = {
        (item["mentor"]["participant_id"], task["task_id"])
        for item in assignments
        for task in tasks
    }
    actual = {(item.get("participant_id"), item.get("task_id")) for item in artifacts}
    inventory = manifest.get("inventory", {})
    body = {key: item for key, item in manifest.items() if key != "manifest_sha256"}
    if not (
        manifest.get("schema_version") == MANIFEST_SCHEMA
        and manifest.get("status") == "explicit_owner_signing_authorization_required"
        and inventory.get("candidate_count") == 180
        and inventory.get("unique_candidate_count") == 180
        and inventory.get("confirmatory_consent_binding_count") == 180
        and inventory.get("baseline_advice_count") == 0
        and inventory.get("control_advice_count") == 0
        and inventory.get("prior_advice_reuse_count") == 0
        and inventory.get("advice_adherence_observation_count") == 0
        and len(artifacts) == 180
        and actual == expected
        and len({item.get("advice_id") for item in artifacts}) == 180
        and len({item.get("canonical_sha256") for item in artifacts}) == 180
        and manifest.get("execution_boundary") == MANIFEST_BOUNDARY
        and manifest.get("manifest_sha256") == canonical_sha256(body)
    ):
        raise ValueError("confirmatory advice manifest invalid")
    assignment_index = {item["mentor"]["participant_id"]: item for item in assignments}
    task_index = {task["task_id"]: task for task in tasks}
    for artifact in artifacts:
        path = candidate_root / f"{artifact['advice_id']}.json"
        candidate, raw = _read_private(path)
        if not (
            hashlib.sha256(raw).hexdigest() == artifact["sha256"]
            and candidate.get("candidate_sha256") == artifact["canonical_sha256"]
            and validate_advice_candidate(
                candidate,
                protocol=values["protocol"],
                task_fixture=values["task_fixture"],
                confirmatory_method=values["confirmatory_method"],
                reviewed_assignment=values["reviewed_assignment"],
                assignment_gate=values["assignment_gate"],
                mentor_identity=values["mentor_identity"],
                assignment=assignment_index[artifact["participant_id"]],
                task=task_index[artifact["task_id"]],
            )
            == []
        ):
            raise ValueError("confirmatory advice candidate artifact invalid")


def _canonical_source_hash(name: str, value: dict[str, Any], raw: bytes) -> str:
    fields = {
        "protocol": "protocol_sha256",
        "task_fixture": "fixture_sha256",
        "confirmatory_method": "method_sha256",
        "material_gate": "report_sha256",
        "reviewed_assignment": "reviewed_rebound_assignment_sha256",
        "assignment_gate": "report_sha256",
        "mentor_identity": "profile_sha256",
    }
    if name == "mentor_identity_gate":
        return hashlib.sha256(raw).hexdigest()
    return str(value[fields[name]])


def _implementation(repository_root: Path) -> dict[str, Any]:
    root = repository_root.resolve()
    if _git(root, "status", "--porcelain"):
        raise ValueError("repository must be clean before freezing confirmatory advice")
    revision = _git(root, "rev-parse", "HEAD")
    if (
        subprocess.run(
            ["git", "merge-base", "--is-ancestor", revision, "@{upstream}"],
            cwd=root,
            check=False,
        ).returncode
        != 0
    ):
        raise ValueError("confirmatory advice revision is not pushed")
    return {
        "source_revision": revision,
        "source_files": {
            str(source.relative_to(root)): hashlib.sha256(
                source.read_bytes()
            ).hexdigest()
            for source in (DOMAIN_SOURCE, OPERATION_SOURCE)
        },
    }


def _body_hash(value: dict[str, Any], field: str) -> str:
    return canonical_sha256({key: item for key, item in value.items() if key != field})


def _read_private(path: Path) -> tuple[dict[str, Any], bytes]:
    if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o077:
        raise ValueError(f"private JSON artifact invalid: {path}")
    raw = path.read_bytes()
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError(f"JSON artifact must be object: {path}")
    return value, raw


def _source_ref(path: Path, raw: bytes, canonical: str) -> dict[str, str]:
    return {
        **_raw_ref(path, raw),
        "canonical_sha256": canonical,
    }


def _raw_ref(path: Path, raw: bytes) -> dict[str, str]:
    return {
        "path": str(path.resolve()),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def _published_artifact(source: Path, target: Path) -> dict[str, str]:
    return {
        "path": str(target.resolve()),
        "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
    }


def _git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args],
        cwd=root,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    ).stdout.strip()


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _require(condition: bool, failure: str, failures: list[str]) -> None:
    if not condition:
        failures.append(failure)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--batch-id", required=True)
    parser.add_argument("--created-at")
    parser.add_argument("--protocol", type=Path, required=True)
    parser.add_argument("--task-fixture", type=Path, required=True)
    parser.add_argument("--confirmatory-method", type=Path, required=True)
    parser.add_argument("--material-gate", type=Path, required=True)
    parser.add_argument("--reviewed-assignment", type=Path, required=True)
    parser.add_argument("--assignment-gate", type=Path, required=True)
    parser.add_argument("--mentor-identity", type=Path, required=True)
    parser.add_argument("--mentor-identity-gate", type=Path, required=True)
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    report = prepare_confirmatory_treatment_advice(
        batch_id=args.batch_id,
        created_at=args.created_at
        or datetime.now(timezone.utc).astimezone().isoformat(),
        protocol_path=args.protocol,
        task_fixture_path=args.task_fixture,
        confirmatory_method_path=args.confirmatory_method,
        material_gate_path=args.material_gate,
        reviewed_assignment_path=args.reviewed_assignment,
        assignment_gate_path=args.assignment_gate,
        mentor_identity_path=args.mentor_identity,
        mentor_identity_gate_path=args.mentor_identity_gate,
        repository_root=args.repository_root,
        output_root=args.output_root,
    )
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
