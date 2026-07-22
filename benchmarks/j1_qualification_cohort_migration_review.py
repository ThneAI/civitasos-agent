"""Prepare an owner-authorized J1-D cohort migration review handoff."""

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
from benchmarks.j1.qualification_cohort_migration import (
    validate_cohort_migration_plan,
)
from benchmarks.j1.qualification_cohort_migration_review import (
    build_migration_review_decision_template,
    build_migration_review_request,
)
from benchmarks.j1_qualification_cohort_migration import (
    approval_statement,
    validate_migration_source_states,
)


REPORT_SCHEMA = "j1-qualification-cohort-migration-review-handoff:v1"
DOMAIN_SOURCE = (
    Path(__file__).parent / "j1" / "qualification_cohort_migration_review.py"
)
MIGRATION_SOURCE = Path(__file__).parent / "j1" / "qualification_cohort_migration.py"
OPERATION_SOURCE = Path(__file__)
SOURCE_NAMES = {
    "base_protocol",
    "base_reviewed_design",
    "reviewed_assignment",
    "signed_advice_manifest",
    "signed_advice_gate",
    "reviewed_corpus_v2",
    "reviewed_verifier_v2",
    "verifier_v2_material_review_gate",
}


def prepare_migration_review_handoff(
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
        raise ValueError(f"migration review output already exists: {output_root}")
    plan, plan_raw = _read_private(plan_path)
    preflight, preflight_raw = _read_private(candidate_preflight_path)
    _validate_candidate_bundle(
        plan=plan,
        plan_raw=plan_raw,
        plan_path=plan_path,
        preflight=preflight,
        preflight_raw=preflight_raw,
    )
    expected_statement = approval_statement(
        plan,
        hashlib.sha256(plan_raw).hexdigest(),
    )
    if authorization_statement != expected_statement:
        raise ValueError("cohort migration owner approval statement mismatch")
    statement_sha256 = hashlib.sha256(authorization_statement.encode()).hexdigest()
    if statement_sha256 != preflight["approval_request"]["statement_sha256"]:
        raise ValueError("cohort migration owner approval statement hash mismatch")
    implementation = _implementation(repository_root)
    now = datetime.now(timezone.utc).isoformat()
    request = build_migration_review_request(
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
        request_path = output_root / "cohort-migration-review-request.json"
        decision_path = output_root / "cohort-migration-review-decision.template.json"
        write_private_json(request_path, request)
        write_private_json(
            decision_path,
            build_migration_review_decision_template(request),
        )
        report = {
            "schema_version": REPORT_SCHEMA,
            "passed": True,
            "state": "cohort_migration_owner_approved_independent_review_required",
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
            "implementation": implementation,
            "readiness": {
                "owner_authorization_bound": True,
                "independent_reviewer_bound": False,
                "independent_review_decision_complete": False,
                "review_signature_present": False,
                "protocol_design_amendment_promoted": False,
                "controlled_experiment_execution_ready": False,
            },
            "execution_boundary": request["execution_boundary"],
        }
        report["report_sha256"] = canonical_sha256(report)
        write_private_json(
            output_root / "cohort-migration-review-handoff.json",
            report,
        )
        return report
    except Exception:
        shutil.rmtree(output_root, ignore_errors=True)
        raise


def _validate_candidate_bundle(
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
    plan_artifact = {
        "path": str(plan_path.resolve()),
        "sha256": hashlib.sha256(plan_raw).hexdigest(),
        "canonical_sha256": plan.get("plan_sha256"),
    }
    if not (
        preflight.get("passed") is True
        and preflight.get("state")
        == "cohort_migration_plan_prepared_independent_review_required"
        and preflight.get("report_sha256") == canonical_sha256(report_body)
        and preflight.get("plan") == plan_artifact
    ):
        raise ValueError("cohort migration candidate preflight invalid")
    source_artifacts = preflight.get("source_artifacts")
    if not isinstance(source_artifacts, dict) or set(source_artifacts) != SOURCE_NAMES:
        raise ValueError("cohort migration source artifact inventory invalid")
    paths: dict[str, Path] = {}
    sources: dict[str, tuple[dict[str, Any], bytes]] = {}
    for name in sorted(SOURCE_NAMES):
        reference = source_artifacts.get(name)
        if not isinstance(reference, dict) or set(reference) != {"path", "sha256"}:
            raise ValueError(f"cohort migration source reference invalid: {name}")
        source_path = Path(str(reference["path"]))
        value, raw = _read_private(source_path)
        if hashlib.sha256(raw).hexdigest() != reference["sha256"]:
            raise ValueError(f"cohort migration source artifact drift: {name}")
        paths[name] = source_path
        sources[name] = (value, raw)
    validate_migration_source_states(
        {name: value for name, (value, _) in sources.items()},
        paths=paths,
        raw_sources={name: raw for name, (_, raw) in sources.items()},
    )
    source_binding = {
        f"{name}_artifact_sha256": hashlib.sha256(raw).hexdigest()
        for name, (_, raw) in sources.items()
    }
    failures = validate_cohort_migration_plan(
        plan,
        expected_source_binding=source_binding,
        base_protocol=sources["base_protocol"][0],
        base_reviewed_design=sources["base_reviewed_design"][0],
        reviewed_assignment=sources["reviewed_assignment"][0],
        signed_advice_manifest=sources["signed_advice_manifest"][0],
        reviewed_verifier_v2=sources["reviewed_verifier_v2"][0],
        expected_implementation=preflight.get("implementation", {}),
    )
    if failures:
        raise ValueError(f"cohort migration candidate invalid: {failures}")


def _implementation(repository_root: Path) -> dict[str, str]:
    root = repository_root.resolve()
    if _git(root, "status", "--porcelain").strip():
        raise ValueError("repository must be clean before freezing review handoff")
    hashes = {
        str(source.relative_to(root)): hashlib.sha256(source.read_bytes()).hexdigest()
        for source in (DOMAIN_SOURCE, MIGRATION_SOURCE, OPERATION_SOURCE)
    }
    return {
        "source_revision": _git(root, "rev-parse", "HEAD").strip(),
        "source_sha256": canonical_sha256(hashes),
    }


def _git(root: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", *arguments],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout


def _read_private(path: Path) -> tuple[dict[str, Any], bytes]:
    resolved = path.resolve()
    if path.is_symlink() or not resolved.is_file() or resolved.stat().st_mode & 0o077:
        raise ValueError(f"private JSON artifact invalid: {resolved}")
    raw = resolved.read_bytes()
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError(f"JSON artifact must contain an object: {resolved}")
    return value, raw


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
    report = prepare_migration_review_handoff(
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
