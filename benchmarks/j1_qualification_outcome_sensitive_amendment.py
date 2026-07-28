"""Generate review-required J1-D outcome-sensitive amendment materials."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from benchmarks.j1.controlled_comparison import write_private_json
from benchmarks.j1.qualification_outcome_sensitive_amendment import (
    BUNDLE_SCHEMA,
    PREFLIGHT_SCHEMA,
    build_amendment_plan,
    build_bundle,
    build_consent_impact,
    build_evaluator_amendment,
    build_preflight,
    build_protocol_amendment,
    build_statistical_plan,
    build_task_fixture_manifest,
    validate_bundle,
    validate_material,
    validate_preflight,
)


OPERATION_SOURCE = Path(__file__)
DOMAIN_SOURCE = (
    Path(__file__).parent / "j1" / "qualification_outcome_sensitive_amendment.py"
)


def generate_materials(
    *,
    amendment_id: str,
    reviewed_candidate_path: Path,
    promotion_gate_path: Path,
    current_protocol_path: Path,
    current_evaluator_path: Path,
    current_consent_manifest_path: Path,
    reviewed_assignment_path: Path,
    output_root: Path,
    repository_root: Path,
    created_at: str | None = None,
) -> dict[str, Any]:
    if output_root.exists():
        raise ValueError(f"amendment output already exists: {output_root}")
    created = created_at or datetime.now(UTC).isoformat()
    sources = {
        "reviewed_candidate": _read_artifact(
            reviewed_candidate_path, "candidate_sha256"
        ),
        "promotion_gate": _read_artifact(promotion_gate_path, "report_sha256"),
        "current_protocol": _read_artifact(
            current_protocol_path, "amended_protocol_sha256"
        ),
        "current_evaluator": _read_artifact(
            current_evaluator_path, "manifest_sha256"
        ),
        "current_consent_manifest": _read_artifact(
            current_consent_manifest_path, "manifest_sha256"
        ),
        "reviewed_assignment": _read_artifact(
            reviewed_assignment_path, "reviewed_rebound_assignment_sha256"
        ),
    }
    implementation = _implementation(repository_root)
    plan = build_amendment_plan(
        amendment_id=amendment_id,
        created_at=created,
        source_binding={name: item["ref"] for name, item in sources.items()},
        reviewed_candidate=sources["reviewed_candidate"]["value"],
        promotion_gate=sources["promotion_gate"]["value"],
        current_protocol=sources["current_protocol"]["value"],
        current_evaluator=sources["current_evaluator"]["value"],
        current_consent_manifest=sources["current_consent_manifest"]["value"],
        reviewed_assignment=sources["reviewed_assignment"]["value"],
        implementation=implementation,
    )
    output_root.mkdir(parents=True, mode=0o700)
    output_root.chmod(0o700)
    plan_ref = _write(
        output_root / "outcome-sensitive-amendment-plan.review-required.json",
        plan,
        "plan_sha256",
    )
    fixture = build_task_fixture_manifest(
        fixture_id=f"{amendment_id}:task-fixtures",
        created_at=created,
        plan_ref=plan_ref,
        reviewed_candidate_ref=sources["reviewed_candidate"]["ref"],
    )
    fixture_ref = _write(
        output_root / "task-fixture-manifest.review-required.json",
        fixture,
        "fixture_sha256",
    )
    statistical = build_statistical_plan(
        statistical_plan_id=f"{amendment_id}:statistical-plan",
        created_at=created,
        plan_ref=plan_ref,
        fixture_ref=fixture_ref,
    )
    statistical_ref = _write(
        output_root / "statistical-analysis-plan.review-required.json",
        statistical,
        "statistical_plan_sha256",
    )
    protocol = build_protocol_amendment(
        protocol_id=f"{amendment_id}:protocol",
        created_at=created,
        plan_ref=plan_ref,
        current_protocol_ref=sources["current_protocol"]["ref"],
        fixture_ref=fixture_ref,
        statistical_plan_ref=statistical_ref,
        current_protocol=sources["current_protocol"]["value"],
    )
    protocol_ref = _write(
        output_root / "qualification-protocol.amendment-candidate.json",
        protocol,
        "protocol_sha256",
    )
    evaluator = build_evaluator_amendment(
        evaluator_id=f"{amendment_id}:evaluator",
        created_at=created,
        plan_ref=plan_ref,
        current_evaluator_ref=sources["current_evaluator"]["ref"],
        protocol_ref=protocol_ref,
        fixture_ref=fixture_ref,
        statistical_plan_ref=statistical_ref,
    )
    evaluator_ref = _write(
        output_root / "real-evaluator.amendment-candidate.json",
        evaluator,
        "evaluator_sha256",
    )
    consent = build_consent_impact(
        assessment_id=f"{amendment_id}:consent-impact",
        created_at=created,
        plan_ref=plan_ref,
        current_consent_ref=sources["current_consent_manifest"]["ref"],
        protocol_ref=protocol_ref,
        evaluator_ref=evaluator_ref,
        fixture_ref=fixture_ref,
        statistical_plan_ref=statistical_ref,
    )
    consent_ref = _write(
        output_root / "participant-consent-impact.review-required.json",
        consent,
        "assessment_sha256",
    )
    bundle = build_bundle(
        bundle_id=f"{amendment_id}:bundle",
        created_at=created,
        plan_ref=plan_ref,
        fixture_ref=fixture_ref,
        statistical_plan_ref=statistical_ref,
        protocol_ref=protocol_ref,
        evaluator_ref=evaluator_ref,
        consent_impact_ref=consent_ref,
        implementation=implementation,
    )
    bundle_ref = _write(
        output_root / "outcome-sensitive-amendment-bundle.review-required.json",
        bundle,
        "bundle_sha256",
    )
    preflight = build_preflight(
        bundle_ref=bundle_ref,
        promotion_gate_ref=sources["promotion_gate"]["ref"],
    )
    _write(
        output_root / "outcome-sensitive-amendment-preflight.json",
        preflight,
        "report_sha256",
    )
    return preflight


def _write(path: Path, value: dict[str, Any], hash_field: str) -> dict[str, str]:
    schema = value["schema_version"]
    if schema == BUNDLE_SCHEMA:
        failures = validate_bundle(value)
    elif schema == PREFLIGHT_SCHEMA:
        failures = validate_preflight(value)
    else:
        failures = validate_material(value, schema=schema, hash_field=hash_field)
    if failures:
        raise ValueError(f"generated amendment material invalid: {failures}")
    write_private_json(path, value)
    return {
        "path": str(path.resolve()),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "canonical_sha256": value[hash_field],
    }


def _read_artifact(path: Path, canonical_field: str) -> dict[str, Any]:
    resolved = path.resolve()
    if not resolved.is_file() or resolved.is_symlink():
        raise ValueError(f"artifact must be a regular file: {resolved}")
    if resolved.stat().st_mode & 0o777 != 0o600:
        raise ValueError(f"artifact must be mode 0600: {resolved}")
    raw = resolved.read_bytes()
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError(f"artifact must be a JSON object: {resolved}")
    canonical = value.get(canonical_field)
    if not _sha256(canonical):
        raise ValueError(f"artifact canonical SHA-256 invalid: {resolved}")
    return {
        "value": value,
        "ref": {
            "path": str(resolved),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "canonical_sha256": canonical,
        },
    }


def _implementation(repository_root: Path) -> dict[str, str]:
    revision = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repository_root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    return {
        "source_revision": revision,
        "domain_source_sha256": hashlib.sha256(DOMAIN_SOURCE.read_bytes()).hexdigest(),
        "operation_source_sha256": hashlib.sha256(
            OPERATION_SOURCE.read_bytes()
        ).hexdigest(),
    }


def _sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--amendment-id", required=True)
    parser.add_argument("--reviewed-candidate", type=Path, required=True)
    parser.add_argument("--promotion-gate", type=Path, required=True)
    parser.add_argument("--current-protocol", type=Path, required=True)
    parser.add_argument("--current-evaluator", type=Path, required=True)
    parser.add_argument("--current-consent-manifest", type=Path, required=True)
    parser.add_argument("--reviewed-assignment", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--created-at")
    parser.add_argument(
        "--repository-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
    )
    return parser


def main() -> int:
    args = _parser().parse_args()
    preflight = generate_materials(
        amendment_id=args.amendment_id,
        reviewed_candidate_path=args.reviewed_candidate,
        promotion_gate_path=args.promotion_gate,
        current_protocol_path=args.current_protocol,
        current_evaluator_path=args.current_evaluator,
        current_consent_manifest_path=args.current_consent_manifest,
        reviewed_assignment_path=args.reviewed_assignment,
        output_root=args.output_root,
        repository_root=args.repository_root,
        created_at=args.created_at,
    )
    print(json.dumps(preflight, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
