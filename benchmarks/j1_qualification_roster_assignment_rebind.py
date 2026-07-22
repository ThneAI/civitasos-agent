"""Prepare no-token J1-D roster/assignment rebind candidates for review."""

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
from benchmarks.j1.qualification_cohort_assignment import validate_reviewed_assignment
from benchmarks.j1.qualification_consent_extension import validate_consent_extension
from benchmarks.j1.qualification_roster_assignment_rebind import (
    approval_statement,
    build_rebind_plan,
    build_rebound_assignment,
    build_rebound_roster,
    validate_rebind_plan,
    validate_rebound_assignment,
    validate_rebound_roster,
)


REPORT_SCHEMA = "j1-qualification-roster-assignment-rebind-preflight:v1"
DOMAIN_SOURCE = (
    Path(__file__).parent / "j1" / "qualification_roster_assignment_rebind.py"
)
OPERATION_SOURCE = Path(__file__)


def prepare_rebind(
    *,
    rebind_id: str,
    created_at: str,
    amendment_bundle_path: Path,
    protocol_amendment_path: Path,
    design_amendment_path: Path,
    signed_consent_manifest_path: Path,
    consent_extension_gate_path: Path,
    reviewed_roster_path: Path,
    roster_gate_path: Path,
    reviewed_assignment_path: Path,
    assignment_gate_path: Path,
    reviewed_migration_plan_path: Path,
    migration_review_gate_path: Path,
    repository_root: Path,
    output_root: Path,
) -> dict[str, Any]:
    if output_root.exists():
        raise ValueError(f"rebind output already exists: {output_root}")
    paths = {
        "amendment_bundle": amendment_bundle_path,
        "protocol_amendment": protocol_amendment_path,
        "design_amendment": design_amendment_path,
        "signed_consent_manifest": signed_consent_manifest_path,
        "consent_extension_gate": consent_extension_gate_path,
        "reviewed_roster": reviewed_roster_path,
        "roster_gate": roster_gate_path,
        "reviewed_assignment": reviewed_assignment_path,
        "assignment_gate": assignment_gate_path,
        "reviewed_migration_plan": reviewed_migration_plan_path,
        "migration_review_gate": migration_review_gate_path,
    }
    sources = {name: _read_private(path) for name, path in paths.items()}
    values = {name: value for name, (value, _) in sources.items()}
    extensions = _load_extensions(values["signed_consent_manifest"])
    _validate_sources(paths=paths, sources=sources, extensions=extensions)
    implementation = _implementation(repository_root)
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
    roster_inputs = {
        "rebind_id": rebind_id,
        "created_at": created_at,
        "source_binding": source_binding,
        "reviewed_roster": values["reviewed_roster"],
        "reviewed_assignment": values["reviewed_assignment"],
        "amendment_bundle": values["amendment_bundle"],
        "protocol_amendment": values["protocol_amendment"],
        "design_amendment": values["design_amendment"],
        "extensions": extensions,
    }
    roster = build_rebound_roster(**roster_inputs)
    roster_failures = validate_rebound_roster(roster, **roster_inputs)
    if roster_failures:
        raise ValueError(f"rebound roster candidate invalid: {roster_failures}")
    assignment_inputs = {
        "rebind_id": rebind_id,
        "created_at": created_at,
        "source_binding": source_binding,
        "reviewed_assignment": values["reviewed_assignment"],
        "rebound_roster": roster,
        "amendment_bundle": values["amendment_bundle"],
        "protocol_amendment": values["protocol_amendment"],
        "design_amendment": values["design_amendment"],
    }
    assignment = build_rebound_assignment(**assignment_inputs)
    assignment_failures = validate_rebound_assignment(assignment, **assignment_inputs)
    if assignment_failures:
        raise ValueError(f"rebound assignment candidate invalid: {assignment_failures}")
    output_root.mkdir(parents=True, mode=0o700)
    output_root.chmod(0o700)
    try:
        roster_path = output_root / "qualification-roster.rebind-candidate.json"
        assignment_path = output_root / "cohort-assignment.rebind-candidate.json"
        write_private_json(roster_path, roster)
        write_private_json(assignment_path, assignment)
        plan_inputs = {
            "rebind_id": rebind_id,
            "created_at": created_at,
            "source_binding": source_binding,
            "rebound_roster_artifact": _artifact(roster_path),
            "rebound_roster": roster,
            "rebound_assignment_artifact": _artifact(assignment_path),
            "rebound_assignment": assignment,
            "implementation": implementation,
        }
        plan = build_rebind_plan(**plan_inputs)
        plan_failures = validate_rebind_plan(plan, **plan_inputs)
        if plan_failures:
            raise ValueError(f"rebind plan invalid: {plan_failures}")
        plan_path = output_root / "roster-assignment-rebind-plan.review-required.json"
        write_private_json(plan_path, plan)
        plan_artifact_sha256 = hashlib.sha256(plan_path.read_bytes()).hexdigest()
        statement = approval_statement(
            plan=plan, plan_artifact_sha256=plan_artifact_sha256
        )
        report = {
            "schema_version": REPORT_SCHEMA,
            "passed": True,
            "state": "roster_assignment_rebind_candidates_independent_review_required",
            "created_at": created_at,
            "plan": {
                **_artifact(plan_path),
                "canonical_sha256": plan["plan_sha256"],
            },
            "candidate_artifacts": plan["candidate_artifacts"],
            "source_artifacts": {
                name: _artifact_bytes(paths[name], raw)
                for name, (_, raw) in sources.items()
            },
            "inventory": plan["inventory"],
            "approval_request": {
                "required_exact_statement": statement,
                "statement_sha256": hashlib.sha256(statement.encode()).hexdigest(),
                "independent_human_review_required": True,
            },
            "readiness": plan["readiness"],
            "implementation": implementation,
            "execution_boundary": plan["execution_boundary"],
        }
        report["report_sha256"] = canonical_sha256(report)
        write_private_json(
            output_root / "roster-assignment-rebind-preflight.json", report
        )
        return report
    except Exception:
        shutil.rmtree(output_root, ignore_errors=True)
        raise


def _validate_sources(
    *,
    paths: dict[str, Path],
    sources: dict[str, tuple[dict[str, Any], bytes]],
    extensions: list[dict[str, Any]],
) -> None:
    values = {name: value for name, (value, _) in sources.items()}
    raws = {name: raw for name, (_, raw) in sources.items()}
    bundle = values["amendment_bundle"]
    protocol = values["protocol_amendment"]
    design = values["design_amendment"]
    manifest = values["signed_consent_manifest"]
    consent_gate = values["consent_extension_gate"]
    roster = values["reviewed_roster"]
    roster_gate = values["roster_gate"]
    assignment = values["reviewed_assignment"]
    assignment_gate = values["assignment_gate"]
    migration_plan = values["reviewed_migration_plan"]
    migration_gate = values["migration_review_gate"]
    failures = validate_reviewed_assignment(assignment)
    if not (
        bundle.get("status") == "reviewed_plan_derived_consent_extension_required"
        and _canonical_valid(bundle, "bundle_sha256")
        and _canonical_valid(protocol, "amended_protocol_sha256")
        and _canonical_valid(design, "amended_design_sha256")
        and bundle.get("protocol_amendment")
        == {
            **_artifact_bytes(paths["protocol_amendment"], raws["protocol_amendment"]),
            "canonical_sha256": protocol.get("amended_protocol_sha256"),
        }
        and bundle.get("design_amendment")
        == {
            **_artifact_bytes(paths["design_amendment"], raws["design_amendment"]),
            "canonical_sha256": design.get("amended_design_sha256"),
        }
    ):
        failures.append("rebind_amendment_source_invalid")
    if not (
        manifest.get("status") == "signed_gate_required"
        and _canonical_valid(manifest, "manifest_sha256")
        and manifest.get("inventory", {}).get("signed_extension_count") == 40
        and consent_gate.get("passed") is True
        and consent_gate.get("failure_reasons") == []
        and consent_gate.get("state")
        == "participant_consent_extensions_complete_downstream_rebind_required"
        and consent_gate.get("signed_manifest_sha256")
        == manifest.get("manifest_sha256")
        and consent_gate.get("artifacts", {}).get("signed_manifest")
        == _artifact_bytes(
            paths["signed_consent_manifest"], raws["signed_consent_manifest"]
        )
    ):
        failures.append("rebind_consent_extension_gate_invalid")
    if not (
        roster.get("status") == "operator_reviewed"
        and _canonical_valid(roster, "roster_sha256")
        and len(roster.get("participants", [])) == 40
        and roster_gate.get("passed") is True
        and roster_gate.get("artifacts", {}).get("reviewed_roster")
        == _artifact_bytes(paths["reviewed_roster"], raws["reviewed_roster"])
    ):
        failures.append("rebind_reviewed_roster_gate_invalid")
    if not (
        assignment_gate.get("passed") is True
        and assignment_gate.get("failure_reasons") == []
        and assignment_gate.get("reviewed_assignment_sha256")
        == assignment.get("reviewed_assignment_sha256")
        and assignment_gate.get("artifacts", {}).get("reviewed_assignment")
        == _artifact_bytes(paths["reviewed_assignment"], raws["reviewed_assignment"])
        and assignment.get("reviewed_roster_sha256") == roster.get("roster_sha256")
    ):
        failures.append("rebind_reviewed_assignment_gate_invalid")
    if not (
        migration_plan.get("status") == "operator_reviewed"
        and _canonical_valid(migration_plan, "reviewed_plan_sha256")
        and migration_gate.get("passed") is True
        and migration_gate.get("failure_reasons") == []
        and migration_gate.get("reviewed_plan")
        == {
            **_artifact_bytes(
                paths["reviewed_migration_plan"], raws["reviewed_migration_plan"]
            ),
            "canonical_sha256": migration_plan.get("reviewed_plan_sha256"),
        }
    ):
        failures.append("rebind_migration_review_gate_invalid")
    extension_ids = set()
    assignment_index = _assignment_index(assignment)
    roster_index = {item["participant_id"]: item for item in roster["participants"]}
    for record in extensions:
        extension = record["value"]
        failures.extend(validate_consent_extension(extension))
        participant = extension.get("participant", {})
        participant_id = participant.get("participant_id")
        extension_ids.add(participant_id)
        expected_assignment = assignment_index.get(participant_id, {})
        expected_roster = roster_index.get(participant_id, {})
        cohort = extension.get("cohort_binding", {})
        amendment = extension.get("amendment_binding", {})
        if not (
            participant.get("execution_did") == expected_roster.get("execution_did")
            and cohort.get("pair_id") == expected_assignment.get("pair_id")
            and cohort.get("cohort") == expected_assignment.get("cohort")
            and cohort.get("assignment_commitment_sha256")
            == expected_assignment.get("assignment_commitment_sha256")
            and amendment.get("amendment_bundle_sha256") == bundle.get("bundle_sha256")
            and amendment.get("protocol_amendment_sha256")
            == protocol.get("amended_protocol_sha256")
            and amendment.get("design_amendment_sha256")
            == design.get("amended_design_sha256")
        ):
            failures.append("rebind_participant_extension_binding_invalid")
    if not (
        len(extensions) == 40
        and len(extension_ids) == 40
        and extension_ids == set(roster_index) == set(assignment_index)
    ):
        failures.append("rebind_participant_inventory_invalid")
    if failures:
        raise ValueError(
            f"roster/assignment rebind source invalid: {list(dict.fromkeys(failures))}"
        )


def _load_extensions(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    records = []
    for descriptor in manifest.get("extensions", []):
        path = Path(str(descriptor.get("path", "")))
        value, raw = _read_private(path)
        artifact = {
            "path": str(path.resolve()),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "canonical_sha256": value.get("extension_sha256"),
        }
        if descriptor != {
            **artifact,
            "participant_id": value.get("participant", {}).get("participant_id"),
            "cohort": value.get("cohort_binding", {}).get("cohort"),
        }:
            raise ValueError(f"consent extension descriptor drift: {path.name}")
        records.append({"artifact": artifact, "value": value})
    return records


def _assignment_index(assignment: dict[str, Any]) -> dict[str, dict[str, Any]]:
    result = {}
    for pair in assignment.get("assignments", []):
        for cohort in ("mentor", "control"):
            member = pair[cohort]
            result[member["participant_id"]] = {
                "pair_id": pair["pair_id"],
                "cohort": cohort,
                "assignment_commitment_sha256": pair["assignment_commitment_sha256"],
            }
    return result


def _implementation(repository_root: Path) -> dict[str, str]:
    root = repository_root.resolve()
    if _git(root, "status", "--porcelain").strip():
        raise ValueError("repository must be clean before freezing rebind evidence")
    hashes = {
        str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in (DOMAIN_SOURCE, OPERATION_SOURCE)
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


def _canonical_valid(value: dict[str, Any], hash_field: str) -> bool:
    body = {key: item for key, item in value.items() if key != hash_field}
    return value.get(hash_field) == canonical_sha256(body)


def _artifact(path: Path) -> dict[str, str]:
    return {
        "path": str(path.resolve()),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }


def _artifact_bytes(path: Path, raw: bytes) -> dict[str, str]:
    return {"path": str(path.resolve()), "sha256": hashlib.sha256(raw).hexdigest()}


def _git(root: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", *arguments], cwd=root, check=True, capture_output=True, text=True
    ).stdout


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--rebind-id", default="j1d-roster-assignment-rebind-20260723-r1"
    )
    parser.add_argument("--amendment-bundle", type=Path, required=True)
    parser.add_argument("--protocol-amendment", type=Path, required=True)
    parser.add_argument("--design-amendment", type=Path, required=True)
    parser.add_argument("--signed-consent-manifest", type=Path, required=True)
    parser.add_argument("--consent-extension-gate", type=Path, required=True)
    parser.add_argument("--reviewed-roster", type=Path, required=True)
    parser.add_argument("--roster-gate", type=Path, required=True)
    parser.add_argument("--reviewed-assignment", type=Path, required=True)
    parser.add_argument("--assignment-gate", type=Path, required=True)
    parser.add_argument("--reviewed-migration-plan", type=Path, required=True)
    parser.add_argument("--migration-review-gate", type=Path, required=True)
    parser.add_argument(
        "--repository-root", type=Path, default=Path(__file__).parents[1]
    )
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    report = prepare_rebind(
        rebind_id=args.rebind_id,
        created_at=datetime.now(timezone.utc).isoformat(),
        amendment_bundle_path=args.amendment_bundle,
        protocol_amendment_path=args.protocol_amendment,
        design_amendment_path=args.design_amendment,
        signed_consent_manifest_path=args.signed_consent_manifest,
        consent_extension_gate_path=args.consent_extension_gate,
        reviewed_roster_path=args.reviewed_roster,
        roster_gate_path=args.roster_gate,
        reviewed_assignment_path=args.reviewed_assignment,
        assignment_gate_path=args.assignment_gate,
        reviewed_migration_plan_path=args.reviewed_migration_plan,
        migration_review_gate_path=args.migration_review_gate,
        repository_root=args.repository_root,
        output_root=args.output_root,
    )
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
