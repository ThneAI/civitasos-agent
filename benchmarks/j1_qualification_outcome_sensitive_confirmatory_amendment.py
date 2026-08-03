"""Generate review-required J1-D confirmatory-method amendment materials."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from benchmarks.j1.controlled_comparison import write_private_json
from benchmarks.j1.qualification_outcome_sensitive_confirmatory_amendment import (
    BUNDLE_SCHEMA,
    CONSENT_SCHEMA,
    EVALUATOR_SCHEMA,
    METHOD_SCHEMA,
    PLAN_SCHEMA,
    PREFLIGHT_SCHEMA,
    PROTOCOL_SCHEMA,
    VERIFICATION_SCHEMA,
    build_bundle,
    build_consent_impact,
    build_evaluator_addendum,
    build_method,
    build_plan,
    build_preflight,
    build_protocol_addendum,
    build_verification,
    validate_bundle,
    validate_material,
    validate_preflight,
)


OPERATION_SOURCE = Path(__file__)
DOMAIN_SOURCES = (
    Path(__file__).parent / "j1" / "qualification_outcome_sensitive_confirmatory.py",
    Path(__file__).parent
    / "j1"
    / "qualification_outcome_sensitive_confirmatory_amendment.py",
)
SOURCE_FIELDS = {
    "postmortem_promotion_gate": "report_sha256",
    "frozen_postmortem": "frozen_review_sha256",
    "parent_protocol": "protocol_sha256",
    "parent_evaluator": "evaluator_sha256",
    "parent_statistical_plan": "statistical_plan_sha256",
    "task_fixture": "fixture_sha256",
    "reviewed_assignment": "reviewed_rebound_assignment_sha256",
    "prior_consent_manifest": "manifest_sha256",
}
HASH_FIELDS = {
    PLAN_SCHEMA: "plan_sha256",
    METHOD_SCHEMA: "method_sha256",
    PROTOCOL_SCHEMA: "addendum_sha256",
    EVALUATOR_SCHEMA: "evaluator_sha256",
    CONSENT_SCHEMA: "assessment_sha256",
    VERIFICATION_SCHEMA: "verification_sha256",
    BUNDLE_SCHEMA: "bundle_sha256",
    PREFLIGHT_SCHEMA: "report_sha256",
}


def generate_materials(
    *,
    amendment_id: str,
    source_paths: dict[str, Path],
    output_root: Path,
    repository_root: Path,
    created_at: str | None = None,
) -> dict[str, Any]:
    if output_root.exists():
        raise FileExistsError(f"confirmatory amendment output exists: {output_root}")
    if set(source_paths) != set(SOURCE_FIELDS):
        raise ValueError("confirmatory amendment source path inventory invalid")

    created = created_at or datetime.now(UTC).isoformat()
    sources = {
        name: _read_artifact(source_paths[name], canonical_field)
        for name, canonical_field in SOURCE_FIELDS.items()
    }
    implementation = _implementation(repository_root)
    output_root.mkdir(parents=True, mode=0o700)
    output_root.chmod(0o700)

    source_refs = {name: item["ref"] for name, item in sources.items()}
    plan = build_plan(
        amendment_id=amendment_id,
        created_at=created,
        sources=source_refs,
        implementation=implementation,
    )
    plan_ref = _write(
        output_root / "confirmatory-amendment-plan.review-required.json",
        plan,
    )
    method = build_method(
        method_id=f"{amendment_id}:method",
        created_at=created,
        plan_ref=plan_ref,
        parent_statistical_ref=source_refs["parent_statistical_plan"],
    )
    method_ref = _write(
        output_root / "confirmatory-method.review-required.json",
        method,
    )
    protocol = build_protocol_addendum(
        addendum_id=f"{amendment_id}:protocol-addendum",
        created_at=created,
        plan_ref=plan_ref,
        parent_protocol_ref=source_refs["parent_protocol"],
        method_ref=method_ref,
    )
    protocol_ref = _write(
        output_root / "confirmatory-protocol-addendum.review-required.json",
        protocol,
    )
    evaluator = build_evaluator_addendum(
        evaluator_id=f"{amendment_id}:evaluator-addendum",
        created_at=created,
        plan_ref=plan_ref,
        parent_evaluator_ref=source_refs["parent_evaluator"],
        method_ref=method_ref,
        protocol_addendum_ref=protocol_ref,
        implementation=implementation,
    )
    evaluator_ref = _write(
        output_root / "confirmatory-evaluator-addendum.review-required.json",
        evaluator,
    )
    consent = build_consent_impact(
        assessment_id=f"{amendment_id}:consent-impact",
        created_at=created,
        plan_ref=plan_ref,
        prior_consent_ref=source_refs["prior_consent_manifest"],
        method_ref=method_ref,
        protocol_addendum_ref=protocol_ref,
        evaluator_ref=evaluator_ref,
    )
    consent_ref = _write(
        output_root / "confirmatory-consent-impact.review-required.json",
        consent,
    )
    verification = build_verification(
        verification_id=f"{amendment_id}:verification",
        created_at=created,
        plan_ref=plan_ref,
        method_ref=method_ref,
    )
    verification_ref = _write(
        output_root / "confirmatory-method-verification.review-required.json",
        verification,
    )
    bundle = build_bundle(
        bundle_id=f"{amendment_id}:bundle",
        created_at=created,
        plan_ref=plan_ref,
        method_ref=method_ref,
        protocol_addendum_ref=protocol_ref,
        evaluator_ref=evaluator_ref,
        consent_ref=consent_ref,
        verification_ref=verification_ref,
        implementation=implementation,
    )
    bundle_ref = _write(
        output_root / "confirmatory-amendment-bundle.review-required.json",
        bundle,
    )
    preflight = build_preflight(
        bundle_ref=bundle_ref,
        bundle=bundle,
        postmortem_gate_ref=source_refs["postmortem_promotion_gate"],
    )
    _write(output_root / "confirmatory-amendment-preflight.json", preflight)
    return preflight


def _write(path: Path, value: dict[str, Any]) -> dict[str, str]:
    schema = value["schema_version"]
    if schema == BUNDLE_SCHEMA:
        failures = validate_bundle(value)
    elif schema == PREFLIGHT_SCHEMA:
        failures = validate_preflight(value)
    else:
        failures = validate_material(
            value,
            schema=schema,
            hash_field=HASH_FIELDS[schema],
        )
    if failures:
        raise ValueError(f"generated confirmatory material invalid: {failures}")
    write_private_json(path, value)
    return {
        "path": str(path.resolve()),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "canonical_sha256": value[HASH_FIELDS[schema]],
    }


def _read_artifact(path: Path, canonical_field: str) -> dict[str, Any]:
    resolved = path.resolve()
    if not resolved.is_file() or resolved.is_symlink():
        raise ValueError(f"source must be a regular file: {resolved}")
    if resolved.stat().st_mode & 0o777 != 0o600:
        raise ValueError(f"source must be mode 0600: {resolved}")
    raw = resolved.read_bytes()
    value = json.loads(raw)
    canonical = value.get(canonical_field) if isinstance(value, dict) else None
    if not _sha256(canonical):
        raise ValueError(f"source canonical SHA-256 invalid: {resolved}")
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
        "confirmatory_source_sha256": hashlib.sha256(
            DOMAIN_SOURCES[0].read_bytes()
        ).hexdigest(),
        "amendment_source_sha256": hashlib.sha256(
            DOMAIN_SOURCES[1].read_bytes()
        ).hexdigest(),
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
    for name in SOURCE_FIELDS:
        parser.add_argument(f"--{name.replace('_', '-')}", type=Path, required=True)
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
        source_paths={name: getattr(args, name) for name in SOURCE_FIELDS},
        output_root=args.output_root,
        repository_root=args.repository_root,
        created_at=args.created_at,
    )
    print(json.dumps(preflight, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
