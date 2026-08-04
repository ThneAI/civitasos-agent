"""Prepare the offline prospective confirmatory infrastructure rebind candidate."""

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
from benchmarks.j1.qualification_outcome_sensitive_confirmatory_infrastructure_rebind import (
    approval_statement,
    build_rebind_plan,
    target_container_name,
)
from benchmarks.j1.qualification_outcome_sensitive_participant_runner_image import (
    validate_runner_image_manifest,
)
from benchmarks.j1_qualification_outcome_sensitive_infrastructure_rebind import (
    _docker_census,
    _fsync_directory,
    _inspect_parent_containers,
    _published_artifact,
    _read_private,
    _require_targets_absent,
    _source_ref,
    _validate_runner_image_local,
)


REPORT_SCHEMA = (
    "j1-qualification-outcome-sensitive-confirmatory-"
    "infrastructure-rebind-preflight:v1"
)
DOMAIN_SOURCE = (
    Path(__file__).parent
    / "j1"
    / "qualification_outcome_sensitive_confirmatory_infrastructure_rebind.py"
)
OPERATION_SOURCE = Path(__file__)


def prepare_confirmatory_infrastructure_rebind(
    *,
    rebind_id: str,
    created_at: str,
    reviewed_roster_path: Path,
    reviewed_assignment_path: Path,
    roster_assignment_gate_path: Path,
    signed_advice_manifest_path: Path,
    mentor_advice_gate_path: Path,
    parent_activation_path: Path,
    parent_activation_gate_path: Path,
    runner_manifest_path: Path,
    runner_gate_path: Path,
    target_state_root: Path,
    repository_root: Path,
    output_root: Path,
) -> dict[str, Any]:
    if output_root.exists():
        raise FileExistsError(
            f"confirmatory infrastructure output exists: {output_root}"
        )
    if not rebind_id.strip():
        raise ValueError("confirmatory infrastructure rebind ID is required")
    paths = {
        "reviewed_roster": reviewed_roster_path,
        "reviewed_assignment": reviewed_assignment_path,
        "roster_assignment_gate": roster_assignment_gate_path,
        "signed_advice_manifest": signed_advice_manifest_path,
        "mentor_advice_gate": mentor_advice_gate_path,
        "parent_activation": parent_activation_path,
        "parent_activation_gate": parent_activation_gate_path,
        "runner_manifest": runner_manifest_path,
        "runner_gate": runner_gate_path,
    }
    sources = {name: _read_private(path) for name, path in paths.items()}
    values = {name: value for name, (value, _) in sources.items()}
    _validate_sources(paths=paths, sources=sources)
    _validate_runner_image_local(values["runner_manifest"])
    observed_sources = _inspect_parent_containers(
        parent_activation=values["parent_activation"],
        reviewed_roster=values["reviewed_roster"],
    )
    target_names = [
        target_container_name(rebind_id, participant["participant_id"])
        for participant in values["reviewed_roster"]["participants"]
    ]
    _require_targets_absent(
        target_names=target_names,
        target_state_root=target_state_root,
    )
    source_binding = {
        name: _source_ref(
            paths[name],
            sources[name][1],
            _canonical_source_hash(name, values[name]),
        )
        for name in sorted(paths)
    }
    implementation = _implementation(repository_root)
    parent = output_root.resolve().parent
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    parent.chmod(0o700)
    staging = Path(tempfile.mkdtemp(prefix=f".{output_root.name}.", dir=parent))
    staging.chmod(0o700)
    try:
        plan = build_rebind_plan(
            rebind_id=rebind_id,
            created_at=created_at,
            source_binding=source_binding,
            reviewed_roster=values["reviewed_roster"],
            reviewed_assignment=values["reviewed_assignment"],
            signed_advice_manifest=values["signed_advice_manifest"],
            parent_activation=values["parent_activation"],
            observed_sources=observed_sources,
            runner_manifest=values["runner_manifest"],
            target_state_root=str(target_state_root.resolve()),
            implementation=implementation,
        )
        plan_path = (
            staging
            / "confirmatory-infrastructure-rebind-plan.review-required.json"
        )
        write_private_json(plan_path, plan)
        plan_raw_sha256 = hashlib.sha256(plan_path.read_bytes()).hexdigest()
        statement = approval_statement(
            plan=plan,
            plan_artifact_sha256=plan_raw_sha256,
        )
        report = {
            "schema_version": REPORT_SCHEMA,
            "passed": True,
            "failure_reasons": [],
            "state": (
                "confirmatory_infrastructure_rebind_candidate_owner_review_required"
            ),
            "created_at": created_at,
            "plan": {
                **_published_artifact(plan_path, output_root / plan_path.name),
                "canonical_sha256": plan["plan_sha256"],
            },
            "source_binding": source_binding,
            "inventory": plan["inventory"],
            "observed_sources_sha256": canonical_sha256(observed_sources),
            "docker_census": _docker_census(),
            "disk_safety": {
                "historical_container_cleanup_authorized": False,
                "implicit_container_prune_authorized": False,
                "implicit_image_prune_authorized": False,
                "source_container_removal_authorized": False,
            },
            "review_request": {
                "required_exact_statement": statement,
                "statement_sha256": hashlib.sha256(statement.encode()).hexdigest(),
                "independent_human_review_required": True,
                "copy_on_write_promotion_required": True,
            },
            "implementation": implementation,
            "readiness": plan["readiness"],
            "execution_boundary": plan["execution_boundary"],
        }
        report["report_sha256"] = canonical_sha256(report)
        write_private_json(
            staging / "confirmatory-infrastructure-rebind-preflight.json",
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
    roster = values["reviewed_roster"]
    assignment = values["reviewed_assignment"]
    roster_gate = values["roster_assignment_gate"]
    advice = values["signed_advice_manifest"]
    advice_gate = values["mentor_advice_gate"]
    activation = values["parent_activation"]
    activation_gate = values["parent_activation_gate"]
    runner = values["runner_manifest"]
    runner_gate = values["runner_gate"]
    failures: list[str] = []
    _require(
        roster.get("schema_version")
        == (
            "j1-qualification-outcome-sensitive-confirmatory-"
            "roster-rebound:operator-reviewed:v1"
        )
        and roster.get("status") == "operator_reviewed"
        and roster.get("reviewed_rebound_roster_sha256")
        == _self_hash(roster, "reviewed_rebound_roster_sha256")
        and len(roster.get("participants", [])) == 40,
        "confirmatory_infrastructure_roster_invalid",
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
        == _self_hash(assignment, "reviewed_rebound_assignment_sha256")
        and assignment.get("operator_reviewed_roster_sha256")
        == roster.get("reviewed_rebound_roster_sha256")
        and len(assignment.get("assignments", [])) == 20,
        "confirmatory_infrastructure_assignment_invalid",
        failures,
    )
    reviewed = roster_gate.get("reviewed_artifacts", {})
    _require(
        roster_gate.get("schema_version")
        == (
            "j1-qualification-outcome-sensitive-confirmatory-"
            "roster-assignment-review-gate:v1"
        )
        and roster_gate.get("passed") is True
        and roster_gate.get("failure_reasons") == []
        and roster_gate.get("state")
        == (
            "confirmatory_roster_assignment_rebind_passed_"
            "mentor_advice_and_infrastructure_rebind_required"
        )
        and roster_gate.get("report_sha256")
        == _self_hash(roster_gate, "report_sha256")
        and reviewed.get("rebound_roster")
        == _source_ref(
            paths["reviewed_roster"],
            raws["reviewed_roster"],
            roster["reviewed_rebound_roster_sha256"],
        )
        and reviewed.get("rebound_assignment")
        == _source_ref(
            paths["reviewed_assignment"],
            raws["reviewed_assignment"],
            assignment["reviewed_rebound_assignment_sha256"],
        ),
        "confirmatory_infrastructure_roster_gate_invalid",
        failures,
    )
    advice_inventory = advice.get("inventory", {})
    _require(
        advice.get("schema_version")
        == (
            "j1-qualification-outcome-sensitive-confirmatory-"
            "treatment-advice-signed-manifest:v1"
        )
        and advice.get("status") == "signed_non_executable_gate_required"
        and advice.get("manifest_sha256") == _self_hash(advice, "manifest_sha256")
        and advice.get("source_binding", {}).get("reviewed_assignment_sha256")
        == assignment.get("reviewed_rebound_assignment_sha256")
        and advice.get("source_binding", {}).get("assignment_promotion_gate_sha256")
        == roster_gate.get("report_sha256")
        and advice_inventory.get("signed_advice_count") == 180
        and advice_inventory.get("unique_signed_advice_count") == 180
        and advice_inventory.get("confirmatory_consent_binding_count") == 180
        and advice_inventory.get("participant_count") == 20
        and advice_inventory.get("all_signatures_verified") is True
        and advice_inventory.get("prior_advice_reuse_count") == 0
        and advice_inventory.get("advice_adherence_observation_count") == 0
        and len(advice.get("signed_advice", [])) == 180,
        "confirmatory_infrastructure_advice_manifest_invalid",
        failures,
    )
    _require(
        advice_gate.get("schema_version")
        == (
            "j1-qualification-outcome-sensitive-confirmatory-"
            "treatment-advice-gate:v1"
        )
        and advice_gate.get("passed") is True
        and advice_gate.get("failure_reasons") == []
        and advice_gate.get("state")
        == "confirmatory_mentor_advice_verified_infrastructure_rebind_required"
        and advice_gate.get("report_sha256")
        == _self_hash(advice_gate, "report_sha256")
        and advice_gate.get("source_binding", {}).get("signed_manifest")
        == _source_ref(
            paths["signed_advice_manifest"],
            raws["signed_advice_manifest"],
            advice["manifest_sha256"],
        )
        and advice_gate.get("inventory", {}).get("verified_signature_count") == 180
        and advice_gate.get("execution_boundary", {}).get("pkcs11_session_opened")
        is False,
        "confirmatory_infrastructure_advice_gate_invalid",
        failures,
    )
    activation_schema = activation.get("schema_version")
    activation_gate_contracts = {
        "j1-qualification-infrastructure-activation:v1": (
            "j1-qualification-infrastructure-activation-gate:v1",
            "replacement_containers_created_provider_admission_required",
        ),
        "j1-qualification-infrastructure-repair-activation:v1": (
            "j1-qualification-infrastructure-repair-gate:v1",
            "single_container_repaired_40_created_0_running",
        ),
        "j1-qualification-infrastructure-batch-repair-activation:v1": (
            "j1-qualification-infrastructure-batch-repair-gate:v1",
            "complete_exited_set_repaired_40_created_0_running",
        ),
    }
    gate_contract = activation_gate_contracts.get(activation_schema)
    _require(
        gate_contract is not None
        and activation.get("activation_sha256")
        == _self_hash(activation, "activation_sha256")
        and activation.get("inventory", {}).get("participant_count") == 40
        and activation.get("inventory", {}).get("container_created_count") == 40
        and activation.get("inventory", {}).get("container_started_count") == 0
        and len(activation.get("containers", [])) == 40,
        "confirmatory_infrastructure_parent_activation_invalid",
        failures,
    )
    _require(
        gate_contract is not None
        and activation_gate.get("schema_version") == gate_contract[0]
        and activation_gate.get("state") == gate_contract[1]
        and activation_gate.get("passed") is True
        and activation_gate.get("failure_reasons") == []
        and activation_gate.get("report_sha256")
        == _self_hash(activation_gate, "report_sha256")
        and activation_gate.get("activation")
        == _source_ref(
            paths["parent_activation"],
            raws["parent_activation"],
            activation["activation_sha256"],
        ),
        "confirmatory_infrastructure_parent_gate_invalid",
        failures,
    )
    runner_failures = validate_runner_image_manifest(
        runner,
        expected_implementation=runner.get("implementation", {}),
    )
    _require(
        not runner_failures,
        "confirmatory_infrastructure_runner_manifest_invalid",
        failures,
    )
    _require(
        runner_gate.get("schema_version")
        == "j1-qualification-outcome-sensitive-runner-image-gate:v1"
        and runner_gate.get("passed") is True
        and runner_gate.get("failure_reasons") == []
        and runner_gate.get("report_sha256")
        == _self_hash(runner_gate, "report_sha256")
        and runner_gate.get("manifest")
        == _source_ref(
            paths["runner_manifest"],
            raws["runner_manifest"],
            runner["manifest_sha256"],
        )
        and runner_gate.get("readiness", {}).get("participant_execution_allowed")
        is False,
        "confirmatory_infrastructure_runner_gate_invalid",
        failures,
    )
    roster_index = {
        item.get("participant_id"): item for item in roster.get("participants", [])
    }
    assigned = {
        member.get("participant_id"): (pair, cohort)
        for pair in assignment.get("assignments", [])
        for cohort in ("mentor", "control")
        for member in [pair.get(cohort, {})]
    }
    parent_index = {
        item.get("participant_id"): item for item in activation.get("containers", [])
    }
    advice_counts: dict[str, int] = {}
    advice_consents: dict[str, set[str]] = {}
    for item in advice.get("signed_advice", []):
        participant_id = item.get("participant_id")
        advice_counts[participant_id] = advice_counts.get(participant_id, 0) + 1
        advice_consents.setdefault(participant_id, set()).add(
            str(item.get("confirmatory_consent_sha256"))
        )
    _require(
        len(roster_index) == len(assigned) == len(parent_index) == 40
        and set(roster_index) == set(assigned) == set(parent_index),
        "confirmatory_infrastructure_participant_sets_invalid",
        failures,
    )
    method_hashes = {
        pair.get("confirmatory_method_sha256")
        for pair in assignment.get("assignments", [])
    }
    _require(
        len(method_hashes) == 1
        and next(iter(method_hashes), None)
        == advice.get("source_binding", {}).get("confirmatory_method_sha256"),
        "confirmatory_infrastructure_method_binding_invalid",
        failures,
    )
    for participant_id, participant in roster_index.items():
        pair, cohort = assigned.get(participant_id, ({}, ""))
        member = pair.get(cohort, {})
        parent = parent_index.get(participant_id, {})
        consent = participant.get("confirmatory_consent", {}).get("canonical_sha256")
        _require(
            participant.get("pair_id") == pair.get("pair_id")
            and participant.get("cohort") == cohort
            and participant.get("execution_did") == member.get("execution_did")
            and participant.get("advice_adherence_observed") is False
            and member.get("confirmatory_consent_sha256") == consent
            and parent.get("pair_id") == pair.get("pair_id")
            and parent.get("cohort") == cohort
            and parent.get("execution_did") == participant.get("execution_did")
            and str(parent.get("container", {}).get("image_id", "")).startswith(
                "sha256:"
            )
            and advice_counts.get(participant_id, 0)
            == (9 if cohort == "mentor" else 0)
            and (
                advice_consents.get(participant_id, set()) == {consent}
                if cohort == "mentor"
                else participant_id not in advice_consents
            ),
            "confirmatory_infrastructure_cross_binding_invalid",
            failures,
        )
    if failures:
        raise ValueError(
            "confirmatory infrastructure sources invalid: "
            f"{list(dict.fromkeys(failures))}"
        )


def _canonical_source_hash(name: str, value: dict[str, Any]) -> str:
    fields = {
        "reviewed_roster": "reviewed_rebound_roster_sha256",
        "reviewed_assignment": "reviewed_rebound_assignment_sha256",
        "roster_assignment_gate": "report_sha256",
        "signed_advice_manifest": "manifest_sha256",
        "mentor_advice_gate": "report_sha256",
        "parent_activation": "activation_sha256",
        "parent_activation_gate": "report_sha256",
        "runner_manifest": "manifest_sha256",
        "runner_gate": "report_sha256",
    }
    return str(value[fields[name]])


def _implementation(repository_root: Path) -> dict[str, str]:
    root = repository_root.resolve()
    if _git(root, "status", "--porcelain"):
        raise ValueError(
            "repository must be clean before freezing confirmatory infrastructure"
        )
    revision = _git(root, "rev-parse", "HEAD")
    if subprocess.run(
        ["git", "merge-base", "--is-ancestor", revision, "@{upstream}"],
        cwd=root,
        check=False,
    ).returncode:
        raise ValueError("confirmatory infrastructure revision is not pushed")
    hashes = {
        str(source.relative_to(root)): hashlib.sha256(source.read_bytes()).hexdigest()
        for source in (DOMAIN_SOURCE, OPERATION_SOURCE)
    }
    return {
        "source_revision": revision,
        "source_sha256": canonical_sha256(hashes),
    }


def _self_hash(value: dict[str, Any], field: str) -> str:
    return canonical_sha256({key: item for key, item in value.items() if key != field})


def _git(root: Path, *arguments: str) -> str:
    return subprocess.check_output(["git", *arguments], cwd=root, text=True).strip()


def _require(condition: bool, reason: str, failures: list[str]) -> None:
    if not condition and reason not in failures:
        failures.append(reason)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rebind-id", required=True)
    parser.add_argument("--reviewed-roster", type=Path, required=True)
    parser.add_argument("--reviewed-assignment", type=Path, required=True)
    parser.add_argument("--roster-assignment-gate", type=Path, required=True)
    parser.add_argument("--signed-advice-manifest", type=Path, required=True)
    parser.add_argument("--mentor-advice-gate", type=Path, required=True)
    parser.add_argument("--parent-activation", type=Path, required=True)
    parser.add_argument("--parent-activation-gate", type=Path, required=True)
    parser.add_argument("--runner-manifest", type=Path, required=True)
    parser.add_argument("--runner-gate", type=Path, required=True)
    parser.add_argument("--target-state-root", type=Path, required=True)
    parser.add_argument(
        "--repository-root", type=Path, default=Path(__file__).parents[1]
    )
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    report = prepare_confirmatory_infrastructure_rebind(
        rebind_id=args.rebind_id,
        created_at=datetime.now(timezone.utc).astimezone().isoformat(),
        reviewed_roster_path=args.reviewed_roster,
        reviewed_assignment_path=args.reviewed_assignment,
        roster_assignment_gate_path=args.roster_assignment_gate,
        signed_advice_manifest_path=args.signed_advice_manifest,
        mentor_advice_gate_path=args.mentor_advice_gate,
        parent_activation_path=args.parent_activation,
        parent_activation_gate_path=args.parent_activation_gate,
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
