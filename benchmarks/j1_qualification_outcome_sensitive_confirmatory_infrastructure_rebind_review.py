"""Prepare the owner-authorized confirmatory infrastructure review handoff."""

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
    validate_rebind_plan,
)
from benchmarks.j1.qualification_outcome_sensitive_confirmatory_infrastructure_rebind_review import (
    approval_review_declaration,
    build_review_decision_template,
    build_review_request,
)
from benchmarks.j1_qualification_outcome_sensitive_infrastructure_rebind import (
    _docker_census,
    _inspect_parent_containers,
    _read_private,
    _require_targets_absent,
)


REPORT_SCHEMA = (
    "j1-qualification-outcome-sensitive-confirmatory-"
    "infrastructure-review-handoff:v1"
)
DOMAIN_SOURCE = (
    Path(__file__).parent
    / "j1"
    / "qualification_outcome_sensitive_confirmatory_infrastructure_rebind_review.py"
)
REBIND_SOURCE = (
    Path(__file__).parent
    / "j1"
    / "qualification_outcome_sensitive_confirmatory_infrastructure_rebind.py"
)
PREFLIGHT_SOURCE = (
    Path(__file__).parent
    / "j1_qualification_outcome_sensitive_confirmatory_infrastructure_rebind.py"
)
OPERATION_SOURCE = Path(__file__)


def prepare_review_handoff(
    *,
    request_id: str,
    authorization_id: str,
    authorized_at: str,
    authorization_statement: str,
    plan_path: Path,
    candidate_preflight_path: Path,
    repository_root: Path,
    output_root: Path,
) -> dict[str, Any]:
    if output_root.exists():
        raise FileExistsError(
            f"confirmatory infrastructure review output exists: {output_root}"
        )
    plan, plan_raw = _read_private(plan_path)
    preflight, preflight_raw = _read_private(candidate_preflight_path)
    validate_candidate_bundle(
        plan=plan,
        plan_raw=plan_raw,
        plan_path=plan_path,
        preflight=preflight,
        preflight_raw=preflight_raw,
    )
    expected_statement = approval_statement(
        plan=plan,
        plan_artifact_sha256=hashlib.sha256(plan_raw).hexdigest(),
    )
    if authorization_statement != expected_statement:
        raise ValueError(
            "confirmatory infrastructure owner approval statement mismatch"
        )
    statement_sha256 = hashlib.sha256(authorization_statement.encode()).hexdigest()
    if statement_sha256 != preflight["review_request"]["statement_sha256"]:
        raise ValueError(
            "confirmatory infrastructure owner approval statement hash mismatch"
        )
    implementation = _implementation(repository_root)
    created_at = datetime.now(timezone.utc).astimezone().isoformat()
    request = build_review_request(
        request_id=request_id,
        created_at=created_at,
        plan_path=str(plan_path.resolve()),
        plan=plan,
        plan_bytes=plan_raw,
        candidate_preflight_path=str(candidate_preflight_path.resolve()),
        candidate_preflight=preflight,
        candidate_preflight_bytes=preflight_raw,
        authorization_id=authorization_id,
        authorized_at=authorized_at,
        authorization_statement_sha256=statement_sha256,
        implementation=implementation,
    )
    parent = output_root.resolve().parent
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    parent.chmod(0o700)
    staging = Path(tempfile.mkdtemp(prefix=f".{output_root.name}.", dir=parent))
    staging.chmod(0o700)
    try:
        request_path = staging / "confirmatory-infrastructure-review-request.json"
        decision_path = (
            staging / "confirmatory-infrastructure-review-decision.template.json"
        )
        write_private_json(request_path, request)
        write_private_json(decision_path, build_review_decision_template(request))
        request_raw_sha256 = hashlib.sha256(request_path.read_bytes()).hexdigest()
        declaration = approval_review_declaration(request, request_raw_sha256)
        report = {
            "schema_version": REPORT_SCHEMA,
            "passed": True,
            "failure_reasons": [],
            "state": (
                "confirmatory_infrastructure_owner_approved_"
                "independent_review_required"
            ),
            "created_at": created_at,
            "owner_authorization": request["owner_authorization"],
            "review_request": {
                **_published_artifact(request_path, output_root / request_path.name),
                "canonical_sha256": request["request_sha256"],
            },
            "decision_template": _published_artifact(
                decision_path, output_root / decision_path.name
            ),
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
                "independent_review_decision_complete": False,
                "review_signature_present": False,
                "infrastructure_promoted": False,
                "participant_container_created": False,
                "controlled_experiment_execution_ready": False,
            },
            "execution_boundary": request["execution_boundary"],
        }
        report["report_sha256"] = canonical_sha256(report)
        write_private_json(
            staging / "confirmatory-infrastructure-review-handoff.json",
            report,
        )
        os.rename(staging, output_root)
        _fsync_directory(parent)
        return report
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def validate_candidate_bundle(
    *,
    plan: dict[str, Any],
    plan_raw: bytes,
    plan_path: Path,
    preflight: dict[str, Any],
    preflight_raw: bytes,
) -> None:
    report_body = {
        key: item for key, item in preflight.items() if key != "report_sha256"
    }
    expected_plan = {
        "path": str(plan_path.resolve()),
        "sha256": hashlib.sha256(plan_raw).hexdigest(),
        "canonical_sha256": plan.get("plan_sha256"),
    }
    if not (
        preflight.get("passed") is True
        and preflight.get("failure_reasons") == []
        and preflight.get("state")
        == "confirmatory_infrastructure_rebind_candidate_owner_review_required"
        and preflight.get("report_sha256") == canonical_sha256(report_body)
        and preflight.get("plan") == expected_plan
        and preflight.get("source_binding") == plan.get("source_binding")
        and preflight.get("inventory") == plan.get("inventory")
        and preflight.get("execution_boundary") == plan.get("execution_boundary")
        and preflight.get("disk_safety")
        == {
            "historical_container_cleanup_authorized": False,
            "implicit_container_prune_authorized": False,
            "implicit_image_prune_authorized": False,
            "source_container_removal_authorized": False,
        }
    ):
        raise ValueError("confirmatory infrastructure candidate preflight invalid")
    sources: dict[str, tuple[dict[str, Any], bytes]] = {}
    for name, reference in plan["source_binding"].items():
        if not isinstance(reference, dict) or set(reference) != {
            "path",
            "sha256",
            "canonical_sha256",
        }:
            raise ValueError(
                f"confirmatory infrastructure source reference invalid: {name}"
            )
        source_path = Path(reference["path"])
        source_value, source_raw = _read_private(source_path)
        if (
            hashlib.sha256(source_raw).hexdigest() != reference["sha256"]
            or _canonical_source_hash(name, source_value)
            != reference["canonical_sha256"]
        ):
            raise ValueError(
                f"confirmatory infrastructure source artifact drift: {name}"
            )
        sources[name] = (source_value, source_raw)
    values = {name: value for name, (value, _) in sources.items()}
    observed = _inspect_parent_containers(
        parent_activation=values["parent_activation"],
        reviewed_roster=values["reviewed_roster"],
    )
    frozen_observed = {
        item["participant_id"]: item["source_isolation"]["observed_state"]
        for item in plan["isolations"]
    }
    if observed != frozen_observed:
        raise ValueError("confirmatory infrastructure parent inventory drifted")
    target_root = Path(
        plan["isolations"][0]["target_isolation"]["input_root"]
    ).parents[1]
    _require_targets_absent(
        target_names=[
            item["target_isolation"]["container_name"]
            for item in plan["isolations"]
        ],
        target_state_root=target_root,
    )
    if _docker_census() != preflight.get("docker_census"):
        raise ValueError("confirmatory infrastructure Docker census drifted")
    failures = validate_rebind_plan(
        plan,
        expected_source_binding=plan["source_binding"],
        reviewed_roster=values["reviewed_roster"],
        reviewed_assignment=values["reviewed_assignment"],
        signed_advice_manifest=values["signed_advice_manifest"],
        parent_activation=values["parent_activation"],
        observed_sources=observed,
        runner_manifest=values["runner_manifest"],
        expected_target_state_root=str(target_root),
        expected_implementation=plan["implementation"],
    )
    if failures:
        raise ValueError(
            f"confirmatory infrastructure plan replay invalid: {failures}"
        )
    if preflight.get("observed_sources_sha256") != canonical_sha256(observed):
        raise ValueError("confirmatory infrastructure observed source hash invalid")


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
            "repository must be clean before freezing confirmatory review handoff"
        )
    revision = _git(root, "rev-parse", "HEAD")
    if subprocess.run(
        ["git", "merge-base", "--is-ancestor", revision, "@{upstream}"],
        cwd=root,
        check=False,
    ).returncode:
        raise ValueError("confirmatory review handoff revision is not pushed")
    hashes = {
        str(source.relative_to(root)): hashlib.sha256(source.read_bytes()).hexdigest()
        for source in (
            DOMAIN_SOURCE,
            REBIND_SOURCE,
            PREFLIGHT_SOURCE,
            OPERATION_SOURCE,
        )
    }
    return {
        "source_revision": revision,
        "source_sha256": canonical_sha256(hashes),
    }


def _published_artifact(path: Path, published_path: Path) -> dict[str, str]:
    return {
        "path": str(published_path.resolve()),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }


def _git(root: Path, *arguments: str) -> str:
    return subprocess.check_output(["git", *arguments], cwd=root, text=True).strip()


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request-id", required=True)
    parser.add_argument("--authorization-id", required=True)
    parser.add_argument("--authorized-at", required=True)
    parser.add_argument("--authorization-statement", required=True)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--candidate-preflight", type=Path, required=True)
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
        repository_root=args.repository_root,
        output_root=args.output_root,
    )
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
