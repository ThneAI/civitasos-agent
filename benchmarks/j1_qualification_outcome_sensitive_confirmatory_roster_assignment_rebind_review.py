"""Prepare the owner-authorized confirmatory rebind review handoff."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from benchmarks.j1.controlled_comparison import canonical_sha256, write_private_json
from benchmarks.j1.qualification_outcome_sensitive_confirmatory_roster_assignment_rebind import (
    approval_statement,
    validate_rebind_plan,
    validate_rebound_assignment,
    validate_rebound_roster,
)
from benchmarks.j1.qualification_outcome_sensitive_confirmatory_roster_assignment_rebind_review import (
    approval_review_declaration,
    build_review_decision_template,
    build_review_request,
)
from benchmarks.j1_qualification_outcome_sensitive_confirmatory_roster_assignment_rebind import (
    _load_extensions,
    _read_private,
    _validate_sources,
)


REPORT_SCHEMA = (
    "j1-qualification-outcome-sensitive-confirmatory-"
    "roster-assignment-review-handoff:v1"
)
DOMAIN_SOURCE = (
    Path(__file__).parent
    / "j1"
    / "qualification_outcome_sensitive_confirmatory_roster_assignment_rebind_review.py"
)
REBIND_SOURCE = (
    Path(__file__).parent
    / "j1"
    / "qualification_outcome_sensitive_confirmatory_roster_assignment_rebind.py"
)
PREFLIGHT_SOURCE = (
    Path(__file__).parent
    / "j1_qualification_outcome_sensitive_confirmatory_roster_assignment_rebind.py"
)
OPERATION_SOURCE = Path(__file__)
SOURCE_NAMES = {
    "confirmatory_consent_plan",
    "confirmatory_consent_preflight",
    "signed_confirmatory_consent_manifest",
    "confirmatory_consent_signing_operation",
    "confirmatory_consent_gate",
    "parent_reviewed_roster",
    "parent_reviewed_assignment",
    "parent_assignment_gate",
}


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
    """Replay all candidate sources and publish a no-signature handoff."""
    if output_root.exists():
        raise FileExistsError(
            f"confirmatory rebind review output exists: {output_root}"
        )
    plan, plan_raw = _read_private(plan_path)
    preflight, preflight_raw = _read_private(candidate_preflight_path)
    validate_candidate_bundle(
        plan=plan,
        plan_raw=plan_raw,
        plan_path=plan_path,
        preflight=preflight,
        preflight_raw=preflight_raw,
        preflight_path=candidate_preflight_path,
    )
    expected_statement = approval_statement(
        plan=plan,
        plan_artifact_sha256=hashlib.sha256(plan_raw).hexdigest(),
    )
    if authorization_statement != expected_statement:
        raise ValueError("confirmatory rebind owner approval statement mismatch")
    statement_sha256 = hashlib.sha256(authorization_statement.encode()).hexdigest()
    if statement_sha256 != preflight["approval_request"]["statement_sha256"]:
        raise ValueError("confirmatory rebind owner approval statement hash mismatch")
    implementation = _implementation(repository_root)
    created_at = datetime.now(UTC).astimezone().isoformat()
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
        request_path = staging / "confirmatory-roster-assignment-review-request.json"
        decision_path = (
            staging / "confirmatory-roster-assignment-review-decision.template.json"
        )
        write_private_json(request_path, request)
        write_private_json(decision_path, build_review_decision_template(request))
        request_artifact_sha256 = hashlib.sha256(request_path.read_bytes()).hexdigest()
        declaration = approval_review_declaration(request, request_artifact_sha256)
        report = {
            "schema_version": REPORT_SCHEMA,
            "passed": True,
            "failure_reasons": [],
            "state": ("confirmatory_rebind_owner_approved_independent_review_required"),
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
                "independent_reviewer_bound": False,
                "independent_review_decision_complete": False,
                "review_signature_present": False,
                "roster_promoted": False,
                "assignment_promoted": False,
                "mentor_advice_rebound_or_signed": False,
                "controlled_experiment_execution_ready": False,
            },
            "execution_boundary": request["execution_boundary"],
        }
        report["report_sha256"] = canonical_sha256(report)
        write_private_json(
            staging / "confirmatory-roster-assignment-review-handoff.json",
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
    preflight_path: Path,
) -> None:
    """Rebuild every source and candidate binding before handoff."""
    report_body = {
        key: item for key, item in preflight.items() if key != "report_sha256"
    }
    expected_plan_ref = {
        "path": str(plan_path.resolve()),
        "sha256": hashlib.sha256(plan_raw).hexdigest(),
        "canonical_sha256": plan.get("plan_sha256"),
    }
    if not (
        preflight.get("passed") is True
        and preflight.get("failure_reasons") == []
        and preflight.get("state")
        == ("confirmatory_roster_assignment_candidates_independent_review_required")
        and preflight.get("report_sha256") == canonical_sha256(report_body)
        and preflight.get("plan") == expected_plan_ref
        and preflight.get("candidate_artifacts") == plan.get("candidate_artifacts")
    ):
        raise ValueError("confirmatory rebind candidate preflight invalid")
    source_artifacts = preflight.get("source_artifacts")
    if not isinstance(source_artifacts, dict) or set(source_artifacts) != SOURCE_NAMES:
        raise ValueError("confirmatory rebind source artifact inventory invalid")
    paths: dict[str, Path] = {}
    sources: dict[str, tuple[dict[str, Any], bytes]] = {}
    for name in sorted(SOURCE_NAMES):
        reference = source_artifacts.get(name)
        if not isinstance(reference, dict) or set(reference) != {"path", "sha256"}:
            raise ValueError(f"confirmatory rebind source reference invalid: {name}")
        source_path = Path(str(reference["path"]))
        value, raw = _read_private(source_path)
        if hashlib.sha256(raw).hexdigest() != reference["sha256"]:
            raise ValueError(f"confirmatory rebind source artifact drift: {name}")
        paths[name] = source_path
        sources[name] = (value, raw)
    extensions = _load_extensions(sources["signed_confirmatory_consent_manifest"][0])
    _validate_sources(paths=paths, sources=sources, extensions=extensions)
    _validate_bound_source_refs(plan["source_binding"])
    roster_path = Path(plan["candidate_artifacts"]["rebound_roster"]["path"])
    assignment_path = Path(plan["candidate_artifacts"]["rebound_assignment"]["path"])
    roster, roster_raw = _read_private(roster_path)
    assignment, assignment_raw = _read_private(assignment_path)
    expected_candidates = {
        "rebound_roster": {
            **_raw_ref(roster_path, roster_raw),
            "canonical_sha256": roster.get("rebound_roster_sha256"),
        },
        "rebound_assignment": {
            **_raw_ref(assignment_path, assignment_raw),
            "canonical_sha256": assignment.get("rebound_assignment_sha256"),
        },
    }
    if plan.get("candidate_artifacts") != expected_candidates:
        raise ValueError("confirmatory rebind candidate artifact drift")
    source_values = {name: value for name, (value, _) in sources.items()}
    roster_inputs = {
        "rebind_id": plan["rebind_id"],
        "created_at": plan["created_at"],
        "source_binding": plan["source_binding"],
        "reviewed_roster": source_values["parent_reviewed_roster"],
        "reviewed_assignment": source_values["parent_reviewed_assignment"],
        "extensions": extensions,
    }
    failures = validate_rebound_roster(roster, **roster_inputs)
    assignment_inputs = {
        "rebind_id": plan["rebind_id"],
        "created_at": plan["created_at"],
        "source_binding": plan["source_binding"],
        "reviewed_assignment": source_values["parent_reviewed_assignment"],
        "rebound_roster": roster,
    }
    failures.extend(validate_rebound_assignment(assignment, **assignment_inputs))
    plan_inputs = {
        "rebind_id": plan["rebind_id"],
        "created_at": plan["created_at"],
        "source_binding": plan["source_binding"],
        "rebound_roster_artifact": _raw_ref(roster_path, roster_raw),
        "rebound_roster": roster,
        "rebound_assignment_artifact": _raw_ref(assignment_path, assignment_raw),
        "rebound_assignment": assignment,
        "implementation": preflight.get("implementation", {}),
    }
    failures.extend(validate_rebind_plan(plan, **plan_inputs))
    if failures:
        raise ValueError(
            f"confirmatory rebind candidate invalid: {list(dict.fromkeys(failures))}"
        )
    if (
        hashlib.sha256(preflight_path.read_bytes()).hexdigest()
        != hashlib.sha256(preflight_raw).hexdigest()
    ):
        raise ValueError("confirmatory rebind preflight changed during validation")


def _validate_bound_source_refs(source_binding: dict[str, Any]) -> None:
    references = [
        source_binding["confirmatory_material_promotion_gate"],
        source_binding["frozen_confirmatory_review"],
        *source_binding["frozen_confirmatory_materials"].values(),
        source_binding["confirmatory_consent_plan"],
        source_binding["confirmatory_consent_preflight"],
        source_binding["signed_confirmatory_consent_manifest"],
        source_binding["confirmatory_consent_signing_operation"],
        source_binding["confirmatory_consent_gate"],
        source_binding["parent_reviewed_roster"],
        source_binding["parent_reviewed_assignment"],
        source_binding["parent_assignment_gate"],
    ]
    for reference in references:
        path = Path(reference["path"])
        _, raw = _read_private(path)
        if hashlib.sha256(raw).hexdigest() != reference["sha256"]:
            raise ValueError(f"confirmatory rebind bound source drift: {path}")


def _implementation(repository_root: Path) -> dict[str, str]:
    root = repository_root.resolve()
    if _git(root, "status", "--porcelain"):
        raise ValueError(
            "repository must be clean before freezing confirmatory review handoff"
        )
    revision = _git(root, "rev-parse", "HEAD")
    if revision != _git(root, "rev-parse", "@{upstream}"):
        raise ValueError("confirmatory review handoff revision must be pushed")
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


def _raw_ref(path: Path, raw: bytes) -> dict[str, str]:
    return {
        "path": str(path.resolve()),
        "sha256": hashlib.sha256(raw).hexdigest(),
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
        "--repository-root",
        type=Path,
        default=Path(__file__).parents[1],
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
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
