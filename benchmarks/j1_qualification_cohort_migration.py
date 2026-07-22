"""Generate a private, non-executable J1-D cohort migration plan."""

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
from benchmarks.j1.qualification_cohort_migration import build_cohort_migration_plan


REPORT_SCHEMA = "j1-qualification-cohort-migration-preflight:v1"


def prepare_migration(
    *,
    amendment_id: str,
    created_at: str,
    base_protocol_path: Path,
    base_reviewed_design_path: Path,
    reviewed_assignment_path: Path,
    signed_advice_manifest_path: Path,
    signed_advice_gate_path: Path,
    verifier_v2_candidate_path: Path,
    verifier_v2_review_request_path: Path,
    repository_root: Path,
    output_root: Path,
) -> dict[str, Any]:
    if output_root.exists():
        raise ValueError(f"migration output already exists: {output_root}")
    paths = {
        "base_protocol": base_protocol_path,
        "base_reviewed_design": base_reviewed_design_path,
        "reviewed_assignment": reviewed_assignment_path,
        "signed_advice_manifest": signed_advice_manifest_path,
        "signed_advice_gate": signed_advice_gate_path,
        "verifier_v2_candidate": verifier_v2_candidate_path,
        "verifier_v2_review_request": verifier_v2_review_request_path,
    }
    sources = {name: _read_private(path) for name, path in paths.items()}
    _validate_source_states({name: value for name, (value, _) in sources.items()})
    implementation = _implementation(repository_root)
    source_binding = {
        f"{name}_artifact_sha256": hashlib.sha256(raw).hexdigest()
        for name, (_, raw) in sources.items()
    }
    plan = build_cohort_migration_plan(
        amendment_id=amendment_id,
        created_at=created_at,
        source_binding=source_binding,
        base_protocol=sources["base_protocol"][0],
        base_reviewed_design=sources["base_reviewed_design"][0],
        reviewed_assignment=sources["reviewed_assignment"][0],
        signed_advice_manifest=sources["signed_advice_manifest"][0],
        verifier_v2_candidate=sources["verifier_v2_candidate"][0],
        implementation=implementation,
    )
    output_root.mkdir(parents=True, mode=0o700)
    output_root.chmod(0o700)
    try:
        plan_path = output_root / "cohort-migration-plan.review-required.json"
        write_private_json(plan_path, plan)
        report = {
            "schema_version": REPORT_SCHEMA,
            "passed": True,
            "state": "cohort_migration_plan_prepared_independent_review_required",
            "created_at": created_at,
            "plan": {
                **_artifact(plan_path),
                "canonical_sha256": plan["plan_sha256"],
            },
            "source_artifacts": {
                name: _artifact_bytes(path, sources[name][1])
                for name, path in paths.items()
            },
            "inventory": plan["inventory"],
            "blockers": plan["blockers"],
            "readiness": plan["readiness"],
            "implementation": implementation,
            "execution_boundary": plan["execution_boundary"],
        }
        report["report_sha256"] = canonical_sha256(report)
        write_private_json(output_root / "cohort-migration-preflight.json", report)
        return report
    except Exception:
        shutil.rmtree(output_root, ignore_errors=True)
        raise


def _validate_source_states(sources: dict[str, dict[str, Any]]) -> None:
    failures = []
    if sources["base_protocol"].get("status") != "frozen":
        failures.append("base_protocol_not_frozen")
    if sources["base_reviewed_design"].get("status") != "operator_reviewed":
        failures.append("base_design_not_reviewed")
    if sources["reviewed_assignment"].get("status") != "operator_reviewed":
        failures.append("assignment_not_reviewed")
    if sources["signed_advice_manifest"].get("status") != (
        "signed_non_executable_gate_required"
    ):
        failures.append("signed_advice_manifest_invalid")
    if not (
        sources["signed_advice_gate"].get("passed") is True
        and sources["signed_advice_gate"].get("failure_reasons") == []
        and sources["signed_advice_gate"].get("signed_manifest_sha256")
        == sources["signed_advice_manifest"].get("manifest_sha256")
    ):
        failures.append("signed_advice_gate_invalid")
    if sources["verifier_v2_candidate"].get("status") != "review_required":
        failures.append("verifier_v2_candidate_status_invalid")
    if sources["verifier_v2_review_request"].get("status") != (
        "awaiting_independent_operator_decision"
    ):
        failures.append("verifier_v2_review_request_status_invalid")
    if failures:
        raise ValueError(f"cohort migration source state invalid: {failures}")


def _implementation(repository_root: Path) -> dict[str, str]:
    root = repository_root.resolve()
    if _git(root, "status", "--porcelain").strip():
        raise ValueError("repository must be clean before freezing migration evidence")
    revision = _git(root, "rev-parse", "HEAD").strip()
    paths = [
        "benchmarks/j1/qualification_cohort_migration.py",
        "benchmarks/j1/qualification_verifier.py",
        "benchmarks/j1_qualification_cohort_migration.py",
    ]
    hashes = {
        path: hashlib.sha256((root / path).read_bytes()).hexdigest() for path in paths
    }
    return {"source_revision": revision, "source_sha256": canonical_sha256(hashes)}


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
    if path.is_symlink() or not resolved.is_file():
        raise ValueError(f"artifact must be a regular non-symlink file: {path}")
    if resolved.stat().st_mode & 0o077:
        raise PermissionError(f"artifact permissions must be private: {resolved}")
    raw = resolved.read_bytes()
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError(f"artifact must contain a JSON object: {resolved}")
    return value, raw


def _artifact(path: Path) -> dict[str, str]:
    return {
        "path": str(path.resolve()),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }


def _artifact_bytes(path: Path, raw: bytes) -> dict[str, str]:
    return {"path": str(path.resolve()), "sha256": hashlib.sha256(raw).hexdigest()}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-protocol", type=Path, required=True)
    parser.add_argument("--base-reviewed-design", type=Path, required=True)
    parser.add_argument("--reviewed-assignment", type=Path, required=True)
    parser.add_argument("--signed-advice-manifest", type=Path, required=True)
    parser.add_argument("--signed-advice-gate", type=Path, required=True)
    parser.add_argument("--verifier-v2-candidate", type=Path, required=True)
    parser.add_argument("--verifier-v2-review-request", type=Path, required=True)
    parser.add_argument(
        "--repository-root", type=Path, default=Path(__file__).parents[1]
    )
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--amendment-id", default="j1d-cohort-migration-20260722-r1")
    args = parser.parse_args()
    report = prepare_migration(
        amendment_id=args.amendment_id,
        created_at=datetime.now(timezone.utc).isoformat(),
        base_protocol_path=args.base_protocol,
        base_reviewed_design_path=args.base_reviewed_design,
        reviewed_assignment_path=args.reviewed_assignment,
        signed_advice_manifest_path=args.signed_advice_manifest,
        signed_advice_gate_path=args.signed_advice_gate,
        verifier_v2_candidate_path=args.verifier_v2_candidate,
        verifier_v2_review_request_path=args.verifier_v2_review_request,
        repository_root=args.repository_root,
        output_root=args.output_root,
    )
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
