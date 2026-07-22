"""Prepare an owner-authorized J1-D rebind independent-review handoff."""

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
from benchmarks.j1.qualification_roster_assignment_rebind import (
    approval_statement,
    validate_rebind_plan,
    validate_rebound_assignment,
    validate_rebound_roster,
)
from benchmarks.j1.qualification_roster_assignment_rebind_review import (
    approval_review_declaration,
    build_rebind_review_decision_template,
    build_rebind_review_request,
)
from benchmarks.j1_qualification_roster_assignment_rebind import (
    _artifact_bytes,
    _load_extensions,
    _read_private,
    _validate_sources,
)


REPORT_SCHEMA = "j1-qualification-roster-assignment-rebind-review-handoff:v1"
DOMAIN_SOURCE = (
    Path(__file__).parent / "j1" / "qualification_roster_assignment_rebind_review.py"
)
REBIND_SOURCE = (
    Path(__file__).parent / "j1" / "qualification_roster_assignment_rebind.py"
)
PREFLIGHT_SOURCE = (
    Path(__file__).parent / "j1_qualification_roster_assignment_rebind.py"
)
OPERATION_SOURCE = Path(__file__)
SOURCE_NAMES = {
    "amendment_bundle",
    "protocol_amendment",
    "design_amendment",
    "signed_consent_manifest",
    "consent_extension_gate",
    "reviewed_roster",
    "roster_gate",
    "reviewed_assignment",
    "assignment_gate",
    "reviewed_migration_plan",
    "migration_review_gate",
}


def prepare_rebind_review_handoff(
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
        raise ValueError(f"rebind review output already exists: {output_root}")
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
        raise ValueError("rebind owner approval statement mismatch")
    statement_sha256 = hashlib.sha256(authorization_statement.encode()).hexdigest()
    if statement_sha256 != preflight["approval_request"]["statement_sha256"]:
        raise ValueError("rebind owner approval statement hash mismatch")
    implementation = _implementation(repository_root)
    now = datetime.now(timezone.utc).isoformat()
    request = build_rebind_review_request(
        request_id=request_id,
        created_at=now,
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
    output_root.mkdir(parents=True, mode=0o700)
    output_root.chmod(0o700)
    try:
        request_path = output_root / "roster-assignment-rebind-review-request.json"
        decision_path = (
            output_root / "roster-assignment-rebind-review-decision.template.json"
        )
        write_private_json(request_path, request)
        write_private_json(
            decision_path, build_rebind_review_decision_template(request)
        )
        declaration = approval_review_declaration(request)
        report = {
            "schema_version": REPORT_SCHEMA,
            "passed": True,
            "state": "rebind_owner_approved_independent_review_required",
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
                "roster_promoted": False,
                "assignment_promoted": False,
                "controlled_experiment_execution_ready": False,
            },
            "execution_boundary": request["execution_boundary"],
        }
        report["report_sha256"] = canonical_sha256(report)
        write_private_json(
            output_root / "roster-assignment-rebind-review-handoff.json", report
        )
        return report
    except Exception:
        shutil.rmtree(output_root, ignore_errors=True)
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
    report_body = {
        key: item for key, item in preflight.items() if key != "report_sha256"
    }
    plan_artifact = {
        "path": str(plan_path.resolve()),
        "sha256": hashlib.sha256(plan_raw).hexdigest(),
        "canonical_sha256": plan.get("plan_sha256"),
    }
    if not (
        preflight.get("passed") is True
        and preflight.get("state")
        == "roster_assignment_rebind_candidates_independent_review_required"
        and preflight.get("report_sha256") == canonical_sha256(report_body)
        and preflight.get("plan") == plan_artifact
        and preflight.get("candidate_artifacts") == plan.get("candidate_artifacts")
    ):
        raise ValueError("rebind candidate preflight invalid")
    source_artifacts = preflight.get("source_artifacts")
    if not isinstance(source_artifacts, dict) or set(source_artifacts) != SOURCE_NAMES:
        raise ValueError("rebind source artifact inventory invalid")
    paths: dict[str, Path] = {}
    sources: dict[str, tuple[dict[str, Any], bytes]] = {}
    for name in sorted(SOURCE_NAMES):
        reference = source_artifacts.get(name)
        if not isinstance(reference, dict) or set(reference) != {"path", "sha256"}:
            raise ValueError(f"rebind source reference invalid: {name}")
        source_path = Path(str(reference["path"]))
        value, raw = _read_private(source_path)
        if hashlib.sha256(raw).hexdigest() != reference["sha256"]:
            raise ValueError(f"rebind source artifact drift: {name}")
        paths[name] = source_path
        sources[name] = (value, raw)
    values = {name: value for name, (value, _) in sources.items()}
    extensions = _load_extensions(values["signed_consent_manifest"])
    _validate_sources(paths=paths, sources=sources, extensions=extensions)
    source_binding = {
        f"{name}_artifact_sha256": hashlib.sha256(raw).hexdigest()
        for name, (_, raw) in sources.items()
    }
    source_binding.update(
        {
            "amendment_bundle_sha256": values["amendment_bundle"]["bundle_sha256"],
            "protocol_amendment_sha256": values["protocol_amendment"][
                "amended_protocol_sha256"
            ],
            "design_amendment_sha256": values["design_amendment"][
                "amended_design_sha256"
            ],
            "signed_consent_manifest_sha256": values["signed_consent_manifest"][
                "manifest_sha256"
            ],
            "reviewed_roster_sha256": values["reviewed_roster"]["roster_sha256"],
            "reviewed_assignment_sha256": values["reviewed_assignment"][
                "reviewed_assignment_sha256"
            ],
        }
    )
    if source_binding != plan.get("source_binding"):
        raise ValueError("rebind plan source binding drift")
    roster_path = Path(plan["candidate_artifacts"]["rebound_roster"]["path"])
    assignment_path = Path(plan["candidate_artifacts"]["rebound_assignment"]["path"])
    roster, roster_raw = _read_private(roster_path)
    assignment, assignment_raw = _read_private(assignment_path)
    if plan["candidate_artifacts"] != {
        "rebound_roster": {
            **_artifact_bytes(roster_path, roster_raw),
            "canonical_sha256": roster.get("rebound_roster_sha256"),
        },
        "rebound_assignment": {
            **_artifact_bytes(assignment_path, assignment_raw),
            "canonical_sha256": assignment.get("rebound_assignment_sha256"),
        },
    }:
        raise ValueError("rebind candidate artifact drift")
    roster_inputs = {
        "rebind_id": plan["rebind_id"],
        "created_at": plan["created_at"],
        "source_binding": source_binding,
        "reviewed_roster": values["reviewed_roster"],
        "reviewed_assignment": values["reviewed_assignment"],
        "amendment_bundle": values["amendment_bundle"],
        "protocol_amendment": values["protocol_amendment"],
        "design_amendment": values["design_amendment"],
        "extensions": extensions,
    }
    failures = validate_rebound_roster(roster, **roster_inputs)
    assignment_inputs = {
        "rebind_id": plan["rebind_id"],
        "created_at": plan["created_at"],
        "source_binding": source_binding,
        "reviewed_assignment": values["reviewed_assignment"],
        "rebound_roster": roster,
        "amendment_bundle": values["amendment_bundle"],
        "protocol_amendment": values["protocol_amendment"],
        "design_amendment": values["design_amendment"],
    }
    failures.extend(validate_rebound_assignment(assignment, **assignment_inputs))
    plan_inputs = {
        "rebind_id": plan["rebind_id"],
        "created_at": plan["created_at"],
        "source_binding": source_binding,
        "rebound_roster_artifact": _artifact_bytes(roster_path, roster_raw),
        "rebound_roster": roster,
        "rebound_assignment_artifact": _artifact_bytes(assignment_path, assignment_raw),
        "rebound_assignment": assignment,
        "implementation": preflight.get("implementation", {}),
    }
    failures.extend(validate_rebind_plan(plan, **plan_inputs))
    if failures:
        raise ValueError(f"rebind candidate invalid: {list(dict.fromkeys(failures))}")
    if (
        hashlib.sha256(preflight_path.read_bytes()).hexdigest()
        != hashlib.sha256(preflight_raw).hexdigest()
    ):
        raise ValueError("rebind candidate preflight changed during validation")


def _implementation(repository_root: Path) -> dict[str, str]:
    root = repository_root.resolve()
    if _git(root, "status", "--porcelain").strip():
        raise ValueError(
            "repository must be clean before freezing rebind review handoff"
        )
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
        "source_revision": _git(root, "rev-parse", "HEAD").strip(),
        "source_sha256": canonical_sha256(hashes),
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
    report = prepare_rebind_review_handoff(
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
