"""Prepare 160 unsigned J1-D participant/task-bound treatment advice candidates."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from benchmarks.j1.controlled_comparison import canonical_sha256, write_private_json
from benchmarks.j1.qualification_treatment_advice import (
    MANIFEST_SCHEMA,
    build_advice_candidate,
    validate_advice_candidate,
)


REPORT_SCHEMA = "j1-qualification-treatment-advice-preflight:v1"
CONTRACT_SOURCE = Path(__file__).parent / "j1" / "qualification_treatment_advice.py"
OPERATION_SOURCE = Path(__file__)


def prepare_treatment_advice(
    *,
    batch_id: str,
    created_at: str,
    reviewed_design_path: Path,
    design_gate_path: Path,
    reviewed_assignment_path: Path,
    assignment_gate_path: Path,
    mentor_identity_path: Path,
    mentor_identity_gate_path: Path,
    agent_revision: str,
    output_root: Path,
) -> dict[str, Any]:
    if output_root.exists():
        raise ValueError(f"treatment advice output already exists: {output_root}")
    if not batch_id.strip():
        raise ValueError("treatment advice batch ID is required")
    design, design_raw = _read_private(reviewed_design_path)
    design_gate, design_gate_raw = _read_private(design_gate_path)
    assignment, assignment_raw = _read_private(reviewed_assignment_path)
    assignment_gate, assignment_gate_raw = _read_private(assignment_gate_path)
    mentor, mentor_raw = _read_private(mentor_identity_path)
    mentor_gate, mentor_gate_raw = _read_private(mentor_identity_gate_path)
    _validate_sources(
        design=design,
        design_path=reviewed_design_path,
        design_raw=design_raw,
        design_gate=design_gate,
        assignment=assignment,
        assignment_path=reviewed_assignment_path,
        assignment_raw=assignment_raw,
        assignment_gate=assignment_gate,
        mentor=mentor,
        mentor_path=mentor_identity_path,
        mentor_raw=mentor_raw,
        mentor_gate=mentor_gate,
    )
    implementation = _implementation(agent_revision)
    tasks = sorted(design["treatment"]["tasks"], key=lambda item: item["task_id"])
    assignments = sorted(assignment["assignments"], key=lambda item: item["pair_id"])
    _validate_batch_members(assignments, tasks)
    output_root.mkdir(parents=True, mode=0o700)
    output_root.chmod(0o700)
    candidates_root = output_root / "candidates"
    candidates_root.mkdir(mode=0o700)
    try:
        artifacts = []
        canonical_hashes = []
        for assigned in assignments:
            for task in tasks:
                candidate = build_advice_candidate(
                    created_at=created_at,
                    reviewed_design=design,
                    reviewed_assignment=assignment,
                    mentor_identity=mentor,
                    assignment=assigned,
                    task=task,
                )
                path = candidates_root / f"{candidate['advice_id']}.json"
                write_private_json(path, candidate)
                artifacts.append(
                    {
                        **_artifact(path),
                        "advice_id": candidate["advice_id"],
                        "participant_id": candidate["recipient"]["participant_id"],
                        "task_id": candidate["task"]["task_id"],
                        "canonical_sha256": candidate["candidate_sha256"],
                    }
                )
                canonical_hashes.append(candidate["candidate_sha256"])
        manifest = {
            "schema_version": MANIFEST_SCHEMA,
            "batch_id": batch_id,
            "status": "explicit_owner_signing_authorization_required",
            "created_at": created_at,
            "source_binding": {
                "reviewed_design_sha256": design["reviewed_design_sha256"],
                "reviewed_design_artifact_sha256": hashlib.sha256(
                    design_raw
                ).hexdigest(),
                "design_gate_artifact_sha256": hashlib.sha256(
                    design_gate_raw
                ).hexdigest(),
                "reviewed_assignment_sha256": assignment["reviewed_assignment_sha256"],
                "reviewed_assignment_artifact_sha256": hashlib.sha256(
                    assignment_raw
                ).hexdigest(),
                "assignment_gate_artifact_sha256": hashlib.sha256(
                    assignment_gate_raw
                ).hexdigest(),
                "mentor_identity_sha256": mentor["profile_sha256"],
                "mentor_identity_artifact_sha256": hashlib.sha256(
                    mentor_raw
                ).hexdigest(),
                "mentor_identity_gate_artifact_sha256": hashlib.sha256(
                    mentor_gate_raw
                ).hexdigest(),
            },
            "inventory": {
                "cohort": "mentor",
                "participant_count": 20,
                "task_count": 8,
                "candidate_count": 160,
                "unique_candidate_count": len(set(canonical_hashes)),
                "all_candidates_unsigned": True,
                "control_advice_candidate_count": 0,
            },
            "mentor": {
                "mentor_id": mentor["mentor"]["mentor_id"],
                "mentor_did": mentor["mentor"]["did"],
                "credential_version": mentor["mentor"]["credential_version"],
                "public_key_sha256": mentor["mentor"]["public_key_sha256"],
            },
            "implementation": implementation,
            "candidates": artifacts,
            "execution_boundary": {
                "candidate_preparation_only": True,
                "pin_read": False,
                "token_login_attempted": False,
                "treatment_advice_signed": False,
                "runtime_projection_allowed": False,
                "provider_api_call_allowed": False,
                "model_invocation_allowed": False,
                "agent_execution_allowed": False,
                "backend_fact_append_allowed": False,
                "ledger_append_allowed": False,
            },
        }
        manifest["manifest_sha256"] = canonical_sha256(manifest)
        _validate_manifest(
            manifest,
            batch_id=batch_id,
            created_at=created_at,
            design=design,
            design_raw=design_raw,
            design_gate_raw=design_gate_raw,
            assignment=assignment,
            assignment_raw=assignment_raw,
            assignment_gate_raw=assignment_gate_raw,
            mentor=mentor,
            mentor_raw=mentor_raw,
            mentor_gate_raw=mentor_gate_raw,
            implementation=implementation,
            assignments=assignments,
            tasks=tasks,
        )
        manifest_path = output_root / "treatment-advice-manifest.review-required.json"
        write_private_json(manifest_path, manifest)
        persisted_manifest, _ = _read_private(manifest_path)
        _validate_manifest(
            persisted_manifest,
            batch_id=batch_id,
            created_at=created_at,
            design=design,
            design_raw=design_raw,
            design_gate_raw=design_gate_raw,
            assignment=assignment,
            assignment_raw=assignment_raw,
            assignment_gate_raw=assignment_gate_raw,
            mentor=mentor,
            mentor_raw=mentor_raw,
            mentor_gate_raw=mentor_gate_raw,
            implementation=implementation,
            assignments=assignments,
            tasks=tasks,
        )
        raw_sha256 = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
        statement = approval_statement(manifest, raw_sha256)
        report = {
            "schema_version": REPORT_SCHEMA,
            "passed": True,
            "state": "treatment_advice_prepared_explicit_owner_signing_authorization_required",
            "manifest": {
                **_artifact(manifest_path),
                "canonical_sha256": manifest["manifest_sha256"],
            },
            "inventory": manifest["inventory"],
            "approval_request": {
                "required_exact_statement": statement,
                "statement_sha256": hashlib.sha256(statement.encode()).hexdigest(),
                "treatment_advice_signing_authorization_required": True,
            },
            "execution_boundary": manifest["execution_boundary"],
        }
        write_private_json(output_root / "treatment-advice-preflight.json", report)
        return report
    except Exception:
        shutil.rmtree(output_root, ignore_errors=True)
        raise


def approval_statement(manifest: dict[str, Any], raw_sha256: str) -> str:
    source = manifest["source_binding"]
    mentor = manifest["mentor"]
    return (
        "I authorize the J1-D mentor identity "
        f"{mentor['mentor_did']} to sign exactly 160 treatment advice candidates from "
        f"manifest artifact {raw_sha256}, canonical manifest {manifest['manifest_sha256']}, "
        f"bound to reviewed execution design {source['reviewed_design_sha256']}, reviewed "
        f"assignment {source['reviewed_assignment_sha256']}, and mentor identity "
        f"{source['mentor_identity_sha256']}. I acknowledge that all 160 signatures are "
        "participant/task scoped, control advice remains empty, and signed advice remains "
        "non-executable advisory data. This authorization does not permit runtime projection, "
        "provider or model calls, Agent execution, Backend Fact append, or Ledger append."
    )


def _validate_sources(**values: Any) -> None:
    design = values["design"]
    assignment = values["assignment"]
    mentor = values["mentor"]
    design_gate = values["design_gate"]
    assignment_gate = values["assignment_gate"]
    mentor_gate = values["mentor_gate"]
    if not (
        design_gate.get("passed") is True
        and design_gate.get("failure_reasons") == []
        and design_gate.get("reviewed_design_sha256")
        == design.get("reviewed_design_sha256")
        and design_gate.get("artifacts", {}).get("reviewed_design")
        == _artifact_bytes(values["design_path"], values["design_raw"])
        and assignment_gate.get("passed") is True
        and assignment_gate.get("failure_reasons") == []
        and assignment_gate.get("reviewed_assignment_sha256")
        == assignment.get("reviewed_assignment_sha256")
        and assignment_gate.get("artifacts", {}).get("reviewed_assignment")
        == _artifact_bytes(values["assignment_path"], values["assignment_raw"])
        and mentor_gate.get("passed") is True
        and mentor_gate.get("failure_reasons") == []
        and mentor_gate.get("mentor_identity_sha256") == mentor.get("profile_sha256")
        and mentor_gate.get("artifacts", {}).get("mentor_identity")
        == _artifact_bytes(values["mentor_path"], values["mentor_raw"])
        and design.get("source_binding", {}).get("reviewed_assignment_sha256")
        == assignment.get("reviewed_assignment_sha256")
        and mentor.get("source_binding", {}).get("reviewed_design_sha256")
        == design.get("reviewed_design_sha256")
        and mentor.get("authorization_boundary", {}).get(
            "treatment_advice_signing_allowed"
        )
        is False
        and len(assignment.get("assignments", [])) == 20
        and len(design.get("treatment", {}).get("tasks", [])) == 8
    ):
        raise ValueError("treatment advice source chain invalid")


def _validate_batch_members(
    assignments: list[dict[str, Any]], tasks: list[dict[str, Any]]
) -> None:
    pair_ids = [item.get("pair_id") for item in assignments]
    participant_ids = [
        item.get("mentor", {}).get("participant_id") for item in assignments
    ]
    execution_dids = [
        item.get("mentor", {}).get("execution_did") for item in assignments
    ]
    task_ids = [item.get("task_id") for item in tasks]
    task_hashes = [item.get("task_input_sha256") for item in tasks]
    if not (
        len(assignments) == 20
        and len(set(pair_ids)) == 20
        and None not in pair_ids
        and len(set(participant_ids)) == 20
        and None not in participant_ids
        and len(set(execution_dids)) == 20
        and None not in execution_dids
        and len(tasks) == 8
        and len(set(task_ids)) == 8
        and None not in task_ids
        and len(set(task_hashes)) == 8
        and None not in task_hashes
    ):
        raise ValueError("treatment advice batch members are not unique and complete")


def _validate_manifest(
    manifest: dict[str, Any],
    *,
    batch_id: str,
    created_at: str,
    design: dict[str, Any],
    design_raw: bytes,
    design_gate_raw: bytes,
    assignment: dict[str, Any],
    assignment_raw: bytes,
    assignment_gate_raw: bytes,
    mentor: dict[str, Any],
    mentor_raw: bytes,
    mentor_gate_raw: bytes,
    implementation: dict[str, str],
    assignments: list[dict[str, Any]],
    tasks: list[dict[str, Any]],
) -> None:
    expected_fields = {
        "schema_version",
        "batch_id",
        "status",
        "created_at",
        "source_binding",
        "inventory",
        "mentor",
        "implementation",
        "candidates",
        "execution_boundary",
        "manifest_sha256",
    }
    expected_sources = {
        "reviewed_design_sha256": design["reviewed_design_sha256"],
        "reviewed_design_artifact_sha256": hashlib.sha256(design_raw).hexdigest(),
        "design_gate_artifact_sha256": hashlib.sha256(design_gate_raw).hexdigest(),
        "reviewed_assignment_sha256": assignment["reviewed_assignment_sha256"],
        "reviewed_assignment_artifact_sha256": hashlib.sha256(
            assignment_raw
        ).hexdigest(),
        "assignment_gate_artifact_sha256": hashlib.sha256(
            assignment_gate_raw
        ).hexdigest(),
        "mentor_identity_sha256": mentor["profile_sha256"],
        "mentor_identity_artifact_sha256": hashlib.sha256(mentor_raw).hexdigest(),
        "mentor_identity_gate_artifact_sha256": hashlib.sha256(
            mentor_gate_raw
        ).hexdigest(),
    }
    expected_mentor = {
        "mentor_id": mentor["mentor"]["mentor_id"],
        "mentor_did": mentor["mentor"]["did"],
        "credential_version": mentor["mentor"]["credential_version"],
        "public_key_sha256": mentor["mentor"]["public_key_sha256"],
    }
    expected_boundary = {
        "candidate_preparation_only": True,
        "pin_read": False,
        "token_login_attempted": False,
        "treatment_advice_signed": False,
        "runtime_projection_allowed": False,
        "provider_api_call_allowed": False,
        "model_invocation_allowed": False,
        "agent_execution_allowed": False,
        "backend_fact_append_allowed": False,
        "ledger_append_allowed": False,
    }
    artifacts = manifest.get("candidates")
    if not isinstance(artifacts, list):
        raise ValueError("treatment advice manifest candidates invalid")
    expected_combinations = {
        (assigned["mentor"]["participant_id"], task["task_id"])
        for assigned in assignments
        for task in tasks
    }
    actual_combinations: set[tuple[str, str]] = set()
    advice_ids: set[str] = set()
    canonical_hashes: set[str] = set()
    assignment_by_participant = {
        item["mentor"]["participant_id"]: item for item in assignments
    }
    task_by_id = {item["task_id"]: item for item in tasks}
    for artifact in artifacts:
        if not isinstance(artifact, dict) or set(artifact) != {
            "path",
            "sha256",
            "advice_id",
            "participant_id",
            "task_id",
            "canonical_sha256",
        }:
            raise ValueError("treatment advice artifact descriptor invalid")
        path = Path(artifact["path"])
        candidate, raw = _read_private(path)
        participant_id = artifact["participant_id"]
        task_id = artifact["task_id"]
        failures = validate_advice_candidate(
            candidate,
            reviewed_design=design,
            reviewed_assignment=assignment,
            mentor_identity=mentor,
            assignment=assignment_by_participant[participant_id],
            task=task_by_id[task_id],
        )
        if failures:
            raise ValueError(
                f"treatment advice candidate failed validation: {failures}"
            )
        if not (
            artifact["sha256"] == hashlib.sha256(raw).hexdigest()
            and artifact["advice_id"] == candidate["advice_id"]
            and artifact["canonical_sha256"] == candidate["candidate_sha256"]
            and path.name == f"{candidate['advice_id']}.json"
        ):
            raise ValueError("treatment advice artifact binding invalid")
        actual_combinations.add((participant_id, task_id))
        advice_ids.add(artifact["advice_id"])
        canonical_hashes.add(artifact["canonical_sha256"])
    expected_inventory = {
        "cohort": "mentor",
        "participant_count": 20,
        "task_count": 8,
        "candidate_count": 160,
        "unique_candidate_count": 160,
        "all_candidates_unsigned": True,
        "control_advice_candidate_count": 0,
    }
    body = {key: item for key, item in manifest.items() if key != "manifest_sha256"}
    if not (
        set(manifest) == expected_fields
        and manifest.get("schema_version") == MANIFEST_SCHEMA
        and manifest.get("batch_id") == batch_id
        and manifest.get("status") == "explicit_owner_signing_authorization_required"
        and manifest.get("created_at") == created_at
        and manifest.get("source_binding") == expected_sources
        and manifest.get("inventory") == expected_inventory
        and manifest.get("mentor") == expected_mentor
        and manifest.get("implementation") == implementation
        and manifest.get("execution_boundary") == expected_boundary
        and len(artifacts) == 160
        and actual_combinations == expected_combinations
        and len(advice_ids) == 160
        and len(canonical_hashes) == 160
        and manifest.get("manifest_sha256") == canonical_sha256(body)
    ):
        raise ValueError("treatment advice manifest invalid")


def _implementation(agent_revision: str) -> dict[str, str]:
    repository = OPERATION_SOURCE.parent.parent
    revision = agent_revision.lower()
    head = subprocess.run(
        ["git", "-C", str(repository), "rev-parse", "HEAD"],
        check=False,
        capture_output=True,
        text=True,
    )
    status = subprocess.run(
        ["git", "-C", str(repository), "status", "--porcelain"],
        check=False,
        capture_output=True,
        text=True,
    )
    if head.returncode or head.stdout.strip().lower() != revision:
        raise ValueError("treatment advice revision is not checked out")
    if status.returncode or status.stdout.strip():
        raise ValueError("treatment advice worktree must be clean")
    return {
        "agent_revision": revision,
        "contract_source_sha256": hashlib.sha256(
            CONTRACT_SOURCE.read_bytes()
        ).hexdigest(),
        "operation_source_sha256": hashlib.sha256(
            OPERATION_SOURCE.read_bytes()
        ).hexdigest(),
    }


def _read_private(path: Path) -> tuple[dict[str, Any], bytes]:
    if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o077:
        raise ValueError(f"private JSON artifact invalid: {path}")
    raw = path.read_bytes()
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError(f"JSON artifact must be object: {path}")
    return value, raw


def _artifact(path: Path) -> dict[str, str]:
    return _artifact_bytes(path, path.read_bytes())


def _artifact_bytes(path: Path, raw: bytes) -> dict[str, str]:
    return {"path": str(path.resolve()), "sha256": hashlib.sha256(raw).hexdigest()}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--batch-id", required=True)
    parser.add_argument("--reviewed-design", type=Path, required=True)
    parser.add_argument("--design-gate", type=Path, required=True)
    parser.add_argument("--reviewed-assignment", type=Path, required=True)
    parser.add_argument("--assignment-gate", type=Path, required=True)
    parser.add_argument("--mentor-identity", type=Path, required=True)
    parser.add_argument("--mentor-identity-gate", type=Path, required=True)
    parser.add_argument("--agent-revision", required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = prepare_treatment_advice(
            batch_id=args.batch_id,
            created_at=datetime.now(timezone.utc).isoformat(),
            reviewed_design_path=args.reviewed_design,
            design_gate_path=args.design_gate,
            reviewed_assignment_path=args.reviewed_assignment,
            assignment_gate_path=args.assignment_gate,
            mentor_identity_path=args.mentor_identity,
            mentor_identity_gate_path=args.mentor_identity_gate,
            agent_revision=args.agent_revision,
            output_root=args.output_root,
        )
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as error:
        report = {
            "schema_version": REPORT_SCHEMA,
            "passed": False,
            "state": "blocked_treatment_advice_preparation",
            "error_class": type(error).__name__,
            "error": str(error),
            "pin_read": False,
            "token_login_attempted": False,
            "treatment_advice_signed": False,
            "provider_api_call_performed": False,
            "model_invocation_performed": False,
        }
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
        return 1
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
