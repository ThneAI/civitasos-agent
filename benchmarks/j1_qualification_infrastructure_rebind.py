"""Prepare the offline J1-D participant infrastructure rebind candidate."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from benchmarks.j1.controlled_comparison import canonical_sha256, write_private_json
from benchmarks.j1.qualification_infrastructure_rebind import (
    approval_statement,
    build_infrastructure_rebind_plan,
)
from benchmarks.j1.qualification_participant_provisioning import (
    validate_participant_profile,
)
from benchmarks.j1.qualification_participant_runner_image import (
    validate_runner_image_manifest,
)


REPORT_SCHEMA = "j1-qualification-infrastructure-rebind-preflight:v1"
CONTRACT_SOURCE = (
    Path(__file__).parent / "j1" / "qualification_infrastructure_rebind.py"
)
OPERATION_SOURCE = Path(__file__)


def prepare_infrastructure_rebind(
    *,
    rebind_id: str,
    created_at: str,
    reviewed_roster_path: Path,
    reviewed_assignment_path: Path,
    roster_assignment_gate_path: Path,
    base_roster_path: Path,
    provisioning_report_path: Path,
    profiles_root: Path,
    participant_evidence_root: Path,
    runner_manifest_path: Path,
    runner_gate_path: Path,
    target_state_root: Path,
    repository_root: Path,
    output_root: Path,
) -> dict[str, Any]:
    if output_root.exists():
        raise ValueError(f"infrastructure rebind output already exists: {output_root}")
    paths = {
        "reviewed_roster": reviewed_roster_path,
        "reviewed_assignment": reviewed_assignment_path,
        "roster_assignment_gate": roster_assignment_gate_path,
        "base_roster": base_roster_path,
        "provisioning_report": provisioning_report_path,
        "runner_manifest": runner_manifest_path,
        "runner_gate": runner_gate_path,
    }
    sources = {name: _read_private(path) for name, path in paths.items()}
    profiles = _load_profiles(profiles_root)
    isolations = _load_isolation_artifacts(participant_evidence_root)
    _validate_sources(sources, paths, profiles, isolations)
    runner_manifest = sources["runner_manifest"][0]
    _validate_runner_image_local(runner_manifest)
    source_state = _inspect_source_containers(profiles)
    target_names = [
        _target_name(rebind_id, profile["participant"]["participant_id"])
        for profile in profiles
    ]
    _require_target_names_absent(target_names)
    source_binding = {
        f"{name}_artifact_sha256": hashlib.sha256(raw).hexdigest()
        for name, (_, raw) in sources.items()
    }
    source_binding["participant_profile_set_sha256"] = canonical_sha256(
        sorted(profile["profile_sha256"] for profile in profiles)
    )
    source_binding["historical_isolation_artifact_set_sha256"] = canonical_sha256(
        sorted(item["sha256"] for item in isolations.values())
    )
    implementation = _implementation(repository_root)
    output_root.mkdir(parents=True, mode=0o700)
    output_root.chmod(0o700)
    try:
        plan = build_infrastructure_rebind_plan(
            rebind_id=rebind_id,
            created_at=created_at,
            source_binding=source_binding,
            reviewed_roster=sources["reviewed_roster"][0],
            reviewed_assignment=sources["reviewed_assignment"][0],
            base_roster=sources["base_roster"][0],
            profiles=profiles,
            isolation_artifacts=isolations,
            runner_manifest=runner_manifest,
            source_container_state=source_state,
            target_state_root=str(target_state_root.resolve()),
            implementation=implementation,
        )
        plan_path = output_root / "infrastructure-rebind-plan.review-required.json"
        write_private_json(plan_path, plan)
        plan_raw_sha256 = hashlib.sha256(plan_path.read_bytes()).hexdigest()
        runner_raw_sha256 = hashlib.sha256(sources["runner_manifest"][1]).hexdigest()
        statement = approval_statement(
            plan=plan,
            plan_artifact_sha256=plan_raw_sha256,
            runner_manifest_artifact_sha256=runner_raw_sha256,
        )
        report = {
            "schema_version": REPORT_SCHEMA,
            "passed": True,
            "failure_reasons": [],
            "state": "infrastructure_rebind_candidate_ready_owner_review_required",
            "plan": {
                "path": str(plan_path.resolve()),
                "sha256": plan_raw_sha256,
                "canonical_sha256": plan["plan_sha256"],
            },
            "runner_image": plan["runner_image"],
            "inventory": plan["inventory"],
            "source_container_state": source_state,
            "target_name_conflicts": 0,
            "owner_approval_statement": statement,
            "owner_approval_statement_sha256": hashlib.sha256(
                statement.encode()
            ).hexdigest(),
            "readiness": plan["readiness"],
            "implementation": implementation,
            "execution_boundary": plan["execution_boundary"],
        }
        report["report_sha256"] = canonical_sha256(report)
        write_private_json(output_root / "infrastructure-rebind-preflight.json", report)
        return report
    except Exception:
        shutil.rmtree(output_root, ignore_errors=True)
        raise


def _validate_sources(
    sources: dict[str, tuple[dict[str, Any], bytes]],
    paths: dict[str, Path],
    profiles: list[dict[str, Any]],
    isolations: dict[str, dict[str, Any]],
) -> None:
    roster = sources["reviewed_roster"][0]
    assignment = sources["reviewed_assignment"][0]
    gate = sources["roster_assignment_gate"][0]
    base_roster = sources["base_roster"][0]
    provisioning = sources["provisioning_report"][0]
    runner = sources["runner_manifest"][0]
    runner_gate = sources["runner_gate"][0]
    failures = []
    if not (
        roster.get("status") == "operator_reviewed"
        and roster.get("reviewed_rebound_roster_sha256")
        == canonical_sha256(
            {
                key: item
                for key, item in roster.items()
                if key != "reviewed_rebound_roster_sha256"
            }
        )
        and len(roster.get("participants", [])) == 40
    ):
        failures.append("infrastructure_rebind_reviewed_roster_invalid")
    if not (
        assignment.get("status") == "operator_reviewed"
        and assignment.get("reviewed_rebound_assignment_sha256")
        == canonical_sha256(
            {
                key: item
                for key, item in assignment.items()
                if key != "reviewed_rebound_assignment_sha256"
            }
        )
        and len(assignment.get("assignments", [])) == 20
        and assignment.get("operator_reviewed_roster_sha256")
        == roster.get("reviewed_rebound_roster_sha256")
    ):
        failures.append("infrastructure_rebind_reviewed_assignment_invalid")
    if not (
        gate.get("passed") is True
        and gate.get("failure_reasons") == []
        and gate.get("state")
        == "roster_assignment_rebind_passed_infrastructure_rebind_required"
        and gate.get("reviewed_artifacts", {}).get("rebound_roster", {}).get("sha256")
        == hashlib.sha256(sources["reviewed_roster"][1]).hexdigest()
        and gate.get("reviewed_artifacts", {})
        .get("rebound_assignment", {})
        .get("sha256")
        == hashlib.sha256(sources["reviewed_assignment"][1]).hexdigest()
        and gate.get("readiness", {}).get("roster_rebound") is True
        and gate.get("readiness", {}).get("assignment_rebound") is True
        and gate.get("readiness", {}).get("infrastructure_rebound") is False
    ):
        failures.append("infrastructure_rebind_roster_assignment_gate_invalid")
    base_index = {
        item["participant_id"]: item
        for item in base_roster.get("participants", [])
        if isinstance(item, dict)
    }
    if not (base_roster.get("status") == "operator_reviewed" and len(base_index) == 40):
        failures.append("infrastructure_rebind_base_roster_invalid")
    if (
        len(profiles) != 40
        or any(validate_participant_profile(profile) for profile in profiles)
        or sorted(provisioning.get("participant_profile_sha256", []))
        != sorted(profile["profile_sha256"] for profile in profiles)
    ):
        failures.append("infrastructure_rebind_profiles_invalid")
    roster_index = {
        item["participant_id"]: item for item in roster.get("participants", [])
    }
    for participant_id, participant in roster_index.items():
        base = base_index.get(participant_id)
        isolation = isolations.get(participant_id)
        profile = next(
            (
                item
                for item in profiles
                if item["participant"]["participant_id"] == participant_id
            ),
            None,
        )
        if not (
            base
            and profile
            and isolation
            and participant.get("base_roster_entry_sha256") == canonical_sha256(base)
            and base.get("isolation_root_sha256") == isolation["sha256"]
            and isolation["value"].get("isolation_commitment_sha256")
            == profile["isolation"]["container_config_sha256"]
        ):
            failures.append("infrastructure_rebind_identity_isolation_binding_invalid")
            break
    implementation = runner.get("implementation", {})
    runner_failures = validate_runner_image_manifest(
        runner, expected_implementation=implementation
    )
    if runner_failures:
        failures.append("infrastructure_rebind_runner_manifest_invalid")
    if not (
        runner_gate.get("passed") is True
        and runner_gate.get("failure_reasons") == []
        and runner_gate.get("manifest", {}).get("sha256")
        == hashlib.sha256(sources["runner_manifest"][1]).hexdigest()
        and runner_gate.get("manifest", {}).get("canonical_sha256")
        == runner.get("manifest_sha256")
        and runner_gate.get("readiness", {}).get("participant_execution_allowed")
        is False
    ):
        failures.append("infrastructure_rebind_runner_gate_invalid")
    if failures:
        raise ValueError(f"infrastructure rebind sources invalid: {failures}")


def _inspect_source_containers(profiles: list[dict[str, Any]]) -> dict[str, Any]:
    ids = [profile["isolation"]["isolation_id"] for profile in profiles]
    present = 0
    missing = 0
    running = 0
    for container_id in ids:
        result = subprocess.run(
            ["docker", "inspect", container_id],
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            missing += 1
            continue
        present += 1
        values = json.loads(result.stdout)
        if values[0].get("State", {}).get("Running") is True:
            running += 1
    if running or present not in {0, 40}:
        raise ValueError(
            "source isolation inventory must be all absent or all present and stopped"
        )
    return {
        "historical_count": 40,
        "present_count": present,
        "missing_count": missing,
        "running_count": running,
        "inventory_mode": (
            "all_historical_containers_absent"
            if present == 0
            else "all_historical_containers_present_stopped"
        ),
        "absence_does_not_rewrite_historical_evidence": True,
    }


def _validate_runner_image_local(manifest: dict[str, Any]) -> None:
    image_id = manifest["image"]["image_id"]
    result = subprocess.run(
        ["docker", "image", "inspect", image_id],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise ValueError("qualified runner image is not available locally")
    values = json.loads(result.stdout)
    if len(values) != 1 or values[0].get("Id") != image_id:
        raise ValueError("qualified runner image identity drifted")


def _require_target_names_absent(names: list[str]) -> None:
    conflicts = []
    for name in names:
        result = subprocess.run(
            ["docker", "container", "inspect", name],
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            conflicts.append(name)
    if conflicts:
        raise ValueError(f"infrastructure rebind target names exist: {conflicts}")


def _load_profiles(root: Path) -> list[dict[str, Any]]:
    if root.is_symlink() or not root.is_dir() or root.stat().st_mode & 0o077:
        raise ValueError("participant profile root invalid")
    profiles = [_read_private(path)[0] for path in sorted(root.glob("*.json"))]
    if len(profiles) != 40:
        raise ValueError("expected exactly 40 participant profiles")
    return profiles


def _load_isolation_artifacts(root: Path) -> dict[str, dict[str, Any]]:
    if root.is_symlink() or not root.is_dir() or root.stat().st_mode & 0o077:
        raise ValueError("participant evidence root invalid")
    result = {}
    for path in sorted(root.glob("*.isolation.json")):
        value, raw = _read_private(path)
        participant_id = value.get("participant_id")
        result[participant_id] = {
            "path": str(path.resolve()),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "value": value,
        }
    if len(result) != 40:
        raise ValueError("expected exactly 40 historical isolation artifacts")
    return result


def _read_private(path: Path) -> tuple[dict[str, Any], bytes]:
    if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o077:
        raise ValueError(f"private artifact invalid: {path}")
    raw = path.read_bytes()
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError(f"private artifact must be a JSON object: {path}")
    return value, raw


def _implementation(repository_root: Path) -> dict[str, str]:
    revision = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repository_root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    sources = (CONTRACT_SOURCE, OPERATION_SOURCE)
    return {
        "source_revision": revision,
        "source_sha256": canonical_sha256(
            {
                str(path.relative_to(repository_root)): hashlib.sha256(
                    path.read_bytes()
                ).hexdigest()
                for path in sources
            }
        ),
    }


def _target_name(rebind_id: str, participant_id: str) -> str:
    digest = hashlib.sha256(f"{rebind_id}:{participant_id}".encode()).hexdigest()[:16]
    return f"civitas-j1q-runner-{digest}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rebind-id", required=True)
    parser.add_argument("--created-at", required=True)
    parser.add_argument("--reviewed-roster", type=Path, required=True)
    parser.add_argument("--reviewed-assignment", type=Path, required=True)
    parser.add_argument("--roster-assignment-gate", type=Path, required=True)
    parser.add_argument("--base-roster", type=Path, required=True)
    parser.add_argument("--provisioning-report", type=Path, required=True)
    parser.add_argument("--profiles-root", type=Path, required=True)
    parser.add_argument("--participant-evidence-root", type=Path, required=True)
    parser.add_argument("--runner-manifest", type=Path, required=True)
    parser.add_argument("--runner-gate", type=Path, required=True)
    parser.add_argument("--target-state-root", type=Path, required=True)
    parser.add_argument(
        "--repository-root", type=Path, default=Path(__file__).parents[1]
    )
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    report = prepare_infrastructure_rebind(
        rebind_id=args.rebind_id,
        created_at=args.created_at,
        reviewed_roster_path=args.reviewed_roster,
        reviewed_assignment_path=args.reviewed_assignment,
        roster_assignment_gate_path=args.roster_assignment_gate,
        base_roster_path=args.base_roster,
        provisioning_report_path=args.provisioning_report,
        profiles_root=args.profiles_root,
        participant_evidence_root=args.participant_evidence_root,
        runner_manifest_path=args.runner_manifest,
        runner_gate_path=args.runner_gate,
        target_state_root=args.target_state_root,
        repository_root=args.repository_root,
        output_root=args.output_root,
    )
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
