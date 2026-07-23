"""Prepare an owner-authorized J1-D evaluator/closeout review handoff."""

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
from benchmarks.j1.qualification_evaluation_closeout_review import (
    approval_review_declaration,
    build_review_decision_template,
    build_review_request,
    validate_candidate_set,
)
from benchmarks.j1_qualification_evaluation_closeout_candidate import (
    _source_binding,
    _validate_sources,
    approval_statement,
)


REPORT_SCHEMA = "j1-qualification-evaluation-closeout-review-handoff:v1"
DOMAIN_SOURCE = (
    Path(__file__).parent / "j1" / "qualification_evaluation_closeout_review.py"
)
CANDIDATE_SOURCE = (
    Path(__file__).parent / "j1_qualification_evaluation_closeout_candidate.py"
)
CONTRACT_SOURCE = Path(__file__).parent / "j1" / "qualification_closeout_contracts.py"
EVALUATOR_SOURCE = Path(__file__).parent / "j1" / "qualification_real_evaluator.py"
OPERATION_SOURCE = Path(__file__)
SOURCE_NAMES = {
    "amended_protocol",
    "amended_design",
    "reviewed_verifier",
    "rebound_roster",
    "rebound_assignment",
    "provider_admission_gate",
    "provider_admission_receipt",
}


def prepare_review_handoff(
    *,
    request_id: str,
    authorization_id: str,
    authorized_at: str,
    authorization_statement: str,
    candidate_bundle_path: Path,
    candidate_preflight_path: Path,
    repository_root: Path,
    output_root: Path,
) -> dict[str, Any]:
    if output_root.exists():
        raise ValueError(
            f"evaluation/closeout review output already exists: {output_root}"
        )
    candidate = load_candidate_set(
        candidate_bundle_path=candidate_bundle_path,
        candidate_preflight_path=candidate_preflight_path,
    )
    expected_statement = approval_statement(
        bundle_artifact_sha256=hashlib.sha256(candidate["bundle_bytes"]).hexdigest(),
        bundle=candidate["bundle"],
    )
    if authorization_statement != expected_statement:
        raise ValueError("evaluation/closeout owner approval statement mismatch")
    statement_sha256 = hashlib.sha256(authorization_statement.encode()).hexdigest()
    if statement_sha256 != candidate["preflight"]["owner_approval"]["statement_sha256"]:
        raise ValueError("evaluation/closeout owner approval statement hash mismatch")
    implementation = review_request_implementation(repository_root)
    created_at = datetime.now(timezone.utc).isoformat()
    request = build_review_request(
        request_id=request_id,
        created_at=created_at,
        candidate_paths=candidate["paths"],
        bundle=candidate["bundle"],
        bundle_bytes=candidate["bundle_bytes"],
        preflight=candidate["preflight"],
        preflight_bytes=candidate["preflight_bytes"],
        evaluator=candidate["evaluator"],
        evaluator_bytes=candidate["evaluator_bytes"],
        post_run=candidate["post_run"],
        post_run_bytes=candidate["post_run_bytes"],
        closeout=candidate["closeout"],
        closeout_bytes=candidate["closeout_bytes"],
        authorization_id=authorization_id,
        authorized_at=authorized_at,
        authorization_statement_sha256=statement_sha256,
        implementation=implementation,
    )
    output_root.mkdir(parents=True, mode=0o700)
    output_root.chmod(0o700)
    try:
        request_path = output_root / "evaluation-closeout-review-request.json"
        decision_path = (
            output_root / "evaluation-closeout-review-decision.template.json"
        )
        write_private_json(request_path, request)
        write_private_json(decision_path, build_review_decision_template(request))
        declaration = approval_review_declaration(request)
        report = {
            "schema_version": REPORT_SCHEMA,
            "passed": True,
            "state": ("evaluation_closeout_owner_approved_independent_review_required"),
            "created_at": created_at,
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
                "evaluation_closeout_frozen": False,
                "execution_preflight_allowed": False,
                "controlled_experiment_execution_ready": False,
            },
            "execution_boundary": request["execution_boundary"],
        }
        report["report_sha256"] = canonical_sha256(report)
        write_private_json(
            output_root / "evaluation-closeout-review-handoff.json", report
        )
        return report
    except Exception:
        shutil.rmtree(output_root, ignore_errors=True)
        raise


def load_candidate_set(
    *, candidate_bundle_path: Path, candidate_preflight_path: Path
) -> dict[str, Any]:
    bundle, bundle_bytes = _read_private(candidate_bundle_path)
    preflight, preflight_bytes = _read_private(candidate_preflight_path)
    candidates = bundle.get("candidate_artifacts")
    if not isinstance(candidates, dict):
        raise ValueError("evaluation/closeout candidate artifact inventory invalid")
    paths = {
        "candidate_bundle": str(candidate_bundle_path.resolve()),
        "candidate_preflight": str(candidate_preflight_path.resolve()),
        "real_evaluator": str(Path(candidates["real_evaluator"]["path"]).resolve()),
        "post_run_contract": str(
            Path(candidates["post_run_contract"]["path"]).resolve()
        ),
        "operator_closeout_contract": str(
            Path(candidates["operator_closeout_contract"]["path"]).resolve()
        ),
    }
    evaluator, evaluator_bytes = _read_private(Path(paths["real_evaluator"]))
    post_run, post_run_bytes = _read_private(Path(paths["post_run_contract"]))
    closeout, closeout_bytes = _read_private(Path(paths["operator_closeout_contract"]))
    failures = validate_candidate_set(
        bundle=bundle,
        bundle_bytes=bundle_bytes,
        preflight=preflight,
        preflight_bytes=preflight_bytes,
        evaluator=evaluator,
        evaluator_bytes=evaluator_bytes,
        post_run=post_run,
        post_run_bytes=post_run_bytes,
        closeout=closeout,
        closeout_bytes=closeout_bytes,
    )
    if failures:
        raise ValueError(f"evaluation/closeout candidate set invalid: {failures}")
    source_refs = preflight.get("source_artifacts")
    if not isinstance(source_refs, dict) or set(source_refs) != SOURCE_NAMES:
        raise ValueError("evaluation/closeout source artifact inventory invalid")
    source_artifacts: dict[str, dict[str, Any]] = {}
    for name in sorted(SOURCE_NAMES):
        reference = source_refs[name]
        if not isinstance(reference, dict) or set(reference) != {"path", "sha256"}:
            raise ValueError(f"evaluation/closeout source reference invalid: {name}")
        source_path = Path(reference["path"])
        value, raw = _read_private(source_path)
        if hashlib.sha256(raw).hexdigest() != reference["sha256"]:
            raise ValueError(f"evaluation/closeout source artifact drift: {name}")
        source_artifacts[name] = {"value": value, "ref": reference}
    _validate_sources(source_artifacts)
    if _source_binding(source_artifacts) != bundle.get("source_binding"):
        raise ValueError("evaluation/closeout source binding drift")
    if (
        hashlib.sha256(candidate_bundle_path.read_bytes()).hexdigest()
        != hashlib.sha256(bundle_bytes).hexdigest()
        or hashlib.sha256(candidate_preflight_path.read_bytes()).hexdigest()
        != hashlib.sha256(preflight_bytes).hexdigest()
    ):
        raise ValueError("evaluation/closeout candidate changed during validation")
    return {
        "paths": paths,
        "bundle": bundle,
        "bundle_bytes": bundle_bytes,
        "preflight": preflight,
        "preflight_bytes": preflight_bytes,
        "evaluator": evaluator,
        "evaluator_bytes": evaluator_bytes,
        "post_run": post_run,
        "post_run_bytes": post_run_bytes,
        "closeout": closeout,
        "closeout_bytes": closeout_bytes,
    }


def review_request_implementation(repository_root: Path) -> dict[str, str]:
    root = repository_root.resolve()
    if _git(root, "status", "--porcelain").strip():
        raise ValueError(
            "repository must be clean before freezing evaluation/closeout handoff"
        )
    hashes = {
        str(source.relative_to(root)): hashlib.sha256(source.read_bytes()).hexdigest()
        for source in (
            DOMAIN_SOURCE,
            CANDIDATE_SOURCE,
            CONTRACT_SOURCE,
            EVALUATOR_SOURCE,
            OPERATION_SOURCE,
        )
    }
    return {
        "source_revision": _git(root, "rev-parse", "HEAD").strip(),
        "source_sha256": canonical_sha256(hashes),
    }


def _read_private(path: Path) -> tuple[dict[str, Any], bytes]:
    resolved = path.resolve()
    if path.is_symlink() or not resolved.is_file() or resolved.stat().st_mode & 0o077:
        raise ValueError(f"private JSON artifact invalid: {resolved}")
    raw = resolved.read_bytes()
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError(f"JSON artifact must contain an object: {resolved}")
    return value, raw


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
    parser.add_argument("--candidate-bundle", type=Path, required=True)
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
        candidate_bundle_path=args.candidate_bundle,
        candidate_preflight_path=args.candidate_preflight,
        repository_root=args.repository_root,
        output_root=args.output_root,
    )
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
