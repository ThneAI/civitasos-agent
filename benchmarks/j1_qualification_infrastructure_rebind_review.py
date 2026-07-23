"""Prepare the owner-authorized J1-D infrastructure rebind review handoff."""

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
from benchmarks.j1.qualification_infrastructure_rebind import (
    approval_statement,
    validate_infrastructure_rebind_plan,
)
from benchmarks.j1.qualification_infrastructure_rebind_review import (
    approval_review_declaration,
    build_review_decision_template,
    build_review_request,
)
from benchmarks.j1_qualification_infrastructure_rebind import (
    _implementation as candidate_implementation,
)
from benchmarks.j1_qualification_infrastructure_rebind import (
    _inspect_source_containers,
    _load_isolation_artifacts,
    _load_profiles,
    _read_private,
    _require_target_names_absent,
    _target_name,
    _validate_runner_image_local,
    _validate_sources,
)


REPORT_SCHEMA = "j1-qualification-infrastructure-rebind-review-handoff:v1"
DOMAIN_SOURCE = (
    Path(__file__).parent / "j1" / "qualification_infrastructure_rebind_review.py"
)
PLAN_SOURCE = Path(__file__).parent / "j1" / "qualification_infrastructure_rebind.py"
CANDIDATE_SOURCE = Path(__file__).parent / "j1_qualification_infrastructure_rebind.py"
OPERATION_SOURCE = Path(__file__)


def prepare_review_handoff(
    *,
    request_id: str,
    authorization_id: str,
    authorized_at: str,
    authorization_statement: str,
    plan_path: Path,
    candidate_preflight_path: Path,
    reviewed_roster_path: Path,
    reviewed_assignment_path: Path,
    roster_assignment_gate_path: Path,
    base_roster_path: Path,
    provisioning_report_path: Path,
    profiles_root: Path,
    participant_evidence_root: Path,
    runner_manifest_path: Path,
    runner_gate_path: Path,
    repository_root: Path,
    output_root: Path,
) -> dict[str, Any]:
    if output_root.exists():
        raise ValueError(f"infrastructure review output already exists: {output_root}")
    plan, plan_raw = _read_private(plan_path)
    preflight, preflight_raw = _read_private(candidate_preflight_path)
    runner_manifest, runner_manifest_raw = _read_private(runner_manifest_path)
    runner_gate, runner_gate_raw = _read_private(runner_gate_path)
    profiles = _load_profiles(profiles_root)
    isolations = _load_isolation_artifacts(participant_evidence_root)
    source_paths = {
        "reviewed_roster": reviewed_roster_path,
        "reviewed_assignment": reviewed_assignment_path,
        "roster_assignment_gate": roster_assignment_gate_path,
        "base_roster": base_roster_path,
        "provisioning_report": provisioning_report_path,
        "runner_manifest": runner_manifest_path,
        "runner_gate": runner_gate_path,
    }
    sources = {name: _read_private(path) for name, path in source_paths.items()}
    _validate_sources(sources, source_paths, profiles, isolations)
    _validate_runner_image_local(runner_manifest)
    source_state = _inspect_source_containers(profiles)
    if source_state != plan.get("source_container_state"):
        raise ValueError("infrastructure rebind source container state drifted")
    target_names = [
        _target_name(plan["rebind_id"], profile["participant"]["participant_id"])
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
    candidate_impl = candidate_implementation(repository_root)
    frozen_candidate_impl = plan.get("implementation", {})
    if (
        not isinstance(frozen_candidate_impl, dict)
        or candidate_impl.get("source_sha256")
        != frozen_candidate_impl.get("source_sha256")
        or not _is_ancestor(
            repository_root,
            str(frozen_candidate_impl.get("source_revision", "")),
        )
    ):
        raise ValueError("infrastructure rebind candidate implementation drifted")
    target_root = str(
        Path(plan["isolations"][0]["target_isolation"]["input_root"]).parents[1]
    )
    plan_failures = validate_infrastructure_rebind_plan(
        plan,
        expected_source_binding=source_binding,
        reviewed_roster=sources["reviewed_roster"][0],
        reviewed_assignment=sources["reviewed_assignment"][0],
        base_roster=sources["base_roster"][0],
        profiles=profiles,
        isolation_artifacts=isolations,
        runner_manifest=runner_manifest,
        expected_source_container_state=source_state,
        expected_target_state_root=target_root,
        expected_implementation=frozen_candidate_impl,
    )
    if plan_failures:
        raise ValueError(f"infrastructure rebind plan invalid: {plan_failures}")
    _validate_preflight(
        preflight=preflight,
        preflight_raw=preflight_raw,
        plan=plan,
        plan_raw=plan_raw,
        plan_path=plan_path,
    )
    expected_statement = approval_statement(
        plan=plan,
        plan_artifact_sha256=hashlib.sha256(plan_raw).hexdigest(),
        runner_manifest_artifact_sha256=hashlib.sha256(runner_manifest_raw).hexdigest(),
    )
    if authorization_statement != expected_statement:
        raise ValueError("infrastructure rebind owner approval statement mismatch")
    statement_sha256 = hashlib.sha256(authorization_statement.encode()).hexdigest()
    if statement_sha256 != preflight["owner_approval_statement_sha256"]:
        raise ValueError("infrastructure rebind owner approval hash mismatch")
    implementation = _implementation(repository_root)
    now = datetime.now(timezone.utc).isoformat()
    request = build_review_request(
        request_id=request_id,
        created_at=now,
        plan_path=str(plan_path.resolve()),
        plan=plan,
        plan_raw=plan_raw,
        preflight_path=str(candidate_preflight_path.resolve()),
        preflight=preflight,
        preflight_raw=preflight_raw,
        runner_manifest_path=str(runner_manifest_path.resolve()),
        runner_manifest=runner_manifest,
        runner_manifest_raw=runner_manifest_raw,
        runner_gate_path=str(runner_gate_path.resolve()),
        runner_gate=runner_gate,
        runner_gate_raw=runner_gate_raw,
        authorization_id=authorization_id,
        authorized_at=authorized_at,
        authorization_statement_sha256=statement_sha256,
        implementation=implementation,
    )
    output_root.mkdir(parents=True, mode=0o700)
    output_root.chmod(0o700)
    try:
        request_path = output_root / "infrastructure-rebind-review-request.json"
        decision_path = (
            output_root / "infrastructure-rebind-review-decision.template.json"
        )
        write_private_json(request_path, request)
        write_private_json(decision_path, build_review_decision_template(request))
        declaration = approval_review_declaration(request)
        report = {
            "schema_version": REPORT_SCHEMA,
            "passed": True,
            "failure_reasons": [],
            "state": "infrastructure_rebind_owner_approved_independent_review_required",
            "created_at": now,
            "owner_authorization": request["owner_authorization"],
            "review_request": {
                **_artifact(request_path),
                "canonical_sha256": request["request_sha256"],
            },
            "decision_template": _artifact(decision_path),
            "review_scope": request["review_scope"],
            "required_checklist": request["required_checklist"],
            "allowed_decisions": request["allowed_decisions"],
            "review_declaration_request": {
                "required_exact_statement": declaration,
                "statement_sha256": hashlib.sha256(declaration.encode()).hexdigest(),
            },
            "implementation": implementation,
            "readiness": {
                "owner_authorization_bound": True,
                "independent_reviewer_bound": False,
                "independent_review_decision_complete": False,
                "review_signature_present": False,
                "infrastructure_promoted": False,
                "participant_containers_created": 0,
                "controlled_experiment_execution_ready": False,
            },
            "execution_boundary": request["execution_boundary"],
        }
        report["report_sha256"] = canonical_sha256(report)
        write_private_json(
            output_root / "infrastructure-rebind-review-handoff.json", report
        )
        return report
    except Exception:
        shutil.rmtree(output_root, ignore_errors=True)
        raise


def _validate_preflight(
    *,
    preflight: dict[str, Any],
    preflight_raw: bytes,
    plan: dict[str, Any],
    plan_raw: bytes,
    plan_path: Path,
) -> None:
    body = {key: item for key, item in preflight.items() if key != "report_sha256"}
    expected_plan = {
        "path": str(plan_path.resolve()),
        "sha256": hashlib.sha256(plan_raw).hexdigest(),
        "canonical_sha256": plan["plan_sha256"],
    }
    if not (
        preflight.get("passed") is True
        and preflight.get("failure_reasons") == []
        and preflight.get("state")
        == "infrastructure_rebind_candidate_ready_owner_review_required"
        and preflight.get("report_sha256") == canonical_sha256(body)
        and preflight.get("plan") == expected_plan
        and preflight.get("inventory") == plan["inventory"]
        and preflight.get("source_container_state") == plan["source_container_state"]
        and preflight.get("target_name_conflicts") == 0
        and hashlib.sha256(preflight_raw).hexdigest()
        == hashlib.sha256(
            Path(preflight["plan"]["path"])
            .parent.joinpath("infrastructure-rebind-preflight.json")
            .read_bytes()
        ).hexdigest()
    ):
        raise ValueError("infrastructure rebind candidate preflight invalid")


def _implementation(repository_root: Path) -> dict[str, str]:
    root = repository_root.resolve()
    if _git(root, "status", "--porcelain").strip():
        raise ValueError(
            "repository must be clean before freezing infrastructure review handoff"
        )
    sources = (DOMAIN_SOURCE, PLAN_SOURCE, CANDIDATE_SOURCE, OPERATION_SOURCE)
    return {
        "source_revision": _git(root, "rev-parse", "HEAD").strip(),
        "source_sha256": canonical_sha256(
            {
                str(path.relative_to(root)): hashlib.sha256(
                    path.read_bytes()
                ).hexdigest()
                for path in sources
            }
        ),
    }


def _git(root: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", *arguments],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout


def _is_ancestor(repository_root: Path, revision: str) -> bool:
    if not (
        7 <= len(revision) <= 64
        and all(char in "0123456789abcdef" for char in revision.lower())
    ):
        return False
    result = subprocess.run(
        ["git", "merge-base", "--is-ancestor", revision, "HEAD"],
        cwd=repository_root.resolve(),
        check=False,
        capture_output=True,
        text=True,
    )
    return result.returncode == 0


def _artifact(path: Path) -> dict[str, str]:
    return {
        "path": str(path.resolve()),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request-id", required=True)
    parser.add_argument("--authorization-id", required=True)
    parser.add_argument("--authorized-at", required=True)
    parser.add_argument("--authorization-statement", required=True)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--candidate-preflight", type=Path, required=True)
    parser.add_argument("--reviewed-roster", type=Path, required=True)
    parser.add_argument("--reviewed-assignment", type=Path, required=True)
    parser.add_argument("--roster-assignment-gate", type=Path, required=True)
    parser.add_argument("--base-roster", type=Path, required=True)
    parser.add_argument("--provisioning-report", type=Path, required=True)
    parser.add_argument("--profiles-root", type=Path, required=True)
    parser.add_argument("--participant-evidence-root", type=Path, required=True)
    parser.add_argument("--runner-manifest", type=Path, required=True)
    parser.add_argument("--runner-gate", type=Path, required=True)
    parser.add_argument(
        "--repository-root", type=Path, default=Path(__file__).parents[1]
    )
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    report = prepare_review_handoff(
        request_id=args.request_id,
        authorization_id=args.authorization_id,
        authorized_at=args.authorized_at,
        authorization_statement=args.authorization_statement,
        plan_path=args.plan,
        candidate_preflight_path=args.candidate_preflight,
        reviewed_roster_path=args.reviewed_roster,
        reviewed_assignment_path=args.reviewed_assignment,
        roster_assignment_gate_path=args.roster_assignment_gate,
        base_roster_path=args.base_roster,
        provisioning_report_path=args.provisioning_report,
        profiles_root=args.profiles_root,
        participant_evidence_root=args.participant_evidence_root,
        runner_manifest_path=args.runner_manifest,
        runner_gate_path=args.runner_gate,
        repository_root=args.repository_root,
        output_root=args.output_root,
    )
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
