"""Prepare no-effect outcome-sensitive J1-D roster/assignment rebind candidates."""

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
from benchmarks.j1.qualification_outcome_sensitive_consent_extension import (
    authorization_statement,
    validate_consent_extension,
    validate_consent_extension_plan,
)
from benchmarks.j1.qualification_outcome_sensitive_roster_assignment_rebind import (
    approval_statement,
    build_rebind_plan,
    build_rebound_assignment,
    build_rebound_roster,
    validate_rebind_plan,
    validate_rebound_assignment,
    validate_rebound_roster,
)
from benchmarks.j1_qualification_outcome_sensitive_consent_extension_sign import (
    _validate_frozen_sources,
    _validate_preflight,
    validate_signed_manifest,
)


REPORT_SCHEMA = (
    "j1-qualification-outcome-sensitive-roster-assignment-rebind-preflight:v1"
)
DOMAIN_SOURCE = (
    Path(__file__).parent
    / "j1"
    / "qualification_outcome_sensitive_roster_assignment_rebind.py"
)
OPERATION_SOURCE = Path(__file__)


def prepare_rebind(
    *,
    rebind_id: str,
    created_at: str,
    consent_plan_path: Path,
    consent_preflight_path: Path,
    signed_consent_manifest_path: Path,
    consent_signing_operation_path: Path,
    consent_gate_path: Path,
    reviewed_roster_path: Path,
    reviewed_assignment_path: Path,
    assignment_gate_path: Path,
    repository_root: Path,
    output_root: Path,
) -> dict[str, Any]:
    if output_root.exists():
        raise FileExistsError(f"outcome rebind output exists: {output_root}")
    paths = {
        "outcome_consent_plan": consent_plan_path,
        "outcome_consent_preflight": consent_preflight_path,
        "signed_consent_manifest": signed_consent_manifest_path,
        "consent_signing_operation": consent_signing_operation_path,
        "consent_gate": consent_gate_path,
        "parent_reviewed_roster": reviewed_roster_path,
        "parent_reviewed_assignment": reviewed_assignment_path,
        "parent_assignment_gate": assignment_gate_path,
    }
    sources = {name: _read_private(path) for name, path in paths.items()}
    values = {name: value for name, (value, _) in sources.items()}
    extensions = _load_extensions(values["signed_consent_manifest"])
    _validate_sources(paths=paths, sources=sources, extensions=extensions)
    implementation = _implementation(repository_root)
    consent_source = values["outcome_consent_plan"]["source_binding"]
    source_binding = {
        "material_promotion_gate": _copy_ref(consent_source["promotion_gate"]),
        "frozen_review": _copy_ref(consent_source["frozen_review"]),
        "frozen_materials": {
            name: _copy_ref(descriptor)
            for name, descriptor in sorted(
                consent_source["frozen_materials"].items()
            )
        },
        "outcome_consent_plan": _ref(
            consent_plan_path,
            sources["outcome_consent_plan"][1],
            values["outcome_consent_plan"]["plan_sha256"],
        ),
        "outcome_consent_preflight": _ref(
            consent_preflight_path,
            sources["outcome_consent_preflight"][1],
            values["outcome_consent_preflight"]["report_sha256"],
        ),
        "signed_consent_manifest": _ref(
            signed_consent_manifest_path,
            sources["signed_consent_manifest"][1],
            values["signed_consent_manifest"]["manifest_sha256"],
        ),
        "consent_signing_operation": _ref(
            consent_signing_operation_path,
            sources["consent_signing_operation"][1],
            values["consent_signing_operation"]["report_sha256"],
        ),
        "consent_gate": _ref(
            consent_gate_path,
            sources["consent_gate"][1],
            values["consent_gate"]["report_sha256"],
        ),
        "parent_reviewed_roster": _ref(
            reviewed_roster_path,
            sources["parent_reviewed_roster"][1],
            values["parent_reviewed_roster"][
                "reviewed_rebound_roster_sha256"
            ],
        ),
        "parent_reviewed_assignment": _ref(
            reviewed_assignment_path,
            sources["parent_reviewed_assignment"][1],
            values["parent_reviewed_assignment"][
                "reviewed_rebound_assignment_sha256"
            ],
        ),
        "parent_assignment_gate": _ref(
            assignment_gate_path,
            sources["parent_assignment_gate"][1],
            values["parent_assignment_gate"]["report_sha256"],
        ),
    }
    protocol = _read_private(
        Path(consent_source["frozen_materials"]["protocol"]["path"])
    )[0]
    roster_inputs = {
        "rebind_id": rebind_id,
        "created_at": created_at,
        "source_binding": source_binding,
        "reviewed_roster": values["parent_reviewed_roster"],
        "reviewed_assignment": values["parent_reviewed_assignment"],
        "protocol": protocol,
        "extensions": extensions,
    }
    roster = build_rebound_roster(**roster_inputs)
    roster_failures = validate_rebound_roster(roster, **roster_inputs)
    if roster_failures:
        raise ValueError(f"outcome rebound roster invalid: {roster_failures}")
    assignment_inputs = {
        "rebind_id": rebind_id,
        "created_at": created_at,
        "source_binding": source_binding,
        "reviewed_assignment": values["parent_reviewed_assignment"],
        "rebound_roster": roster,
        "protocol": protocol,
    }
    assignment = build_rebound_assignment(**assignment_inputs)
    assignment_failures = validate_rebound_assignment(
        assignment, **assignment_inputs
    )
    if assignment_failures:
        raise ValueError(
            f"outcome rebound assignment invalid: {assignment_failures}"
        )
    parent = output_root.resolve().parent
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    parent.chmod(0o700)
    staging = Path(tempfile.mkdtemp(prefix=f".{output_root.name}.", dir=parent))
    staging.chmod(0o700)
    try:
        roster_path = staging / "qualification-roster.rebind-candidate.json"
        assignment_path = staging / "cohort-assignment.rebind-candidate.json"
        write_private_json(roster_path, roster)
        write_private_json(assignment_path, assignment)
        plan_inputs = {
            "rebind_id": rebind_id,
            "created_at": created_at,
            "source_binding": source_binding,
            "rebound_roster_artifact": _published_artifact(
                roster_path, output_root / roster_path.name
            ),
            "rebound_roster": roster,
            "rebound_assignment_artifact": _published_artifact(
                assignment_path, output_root / assignment_path.name
            ),
            "rebound_assignment": assignment,
            "implementation": implementation,
        }
        plan = build_rebind_plan(**plan_inputs)
        plan_failures = validate_rebind_plan(plan, **plan_inputs)
        if plan_failures:
            raise ValueError(f"outcome rebind plan invalid: {plan_failures}")
        plan_path = (
            staging
            / "outcome-sensitive-roster-assignment-rebind-plan.review-required.json"
        )
        write_private_json(plan_path, plan)
        plan_raw_sha = hashlib.sha256(plan_path.read_bytes()).hexdigest()
        statement = approval_statement(
            plan=plan, plan_artifact_sha256=plan_raw_sha
        )
        report = {
            "schema_version": REPORT_SCHEMA,
            "passed": True,
            "failure_reasons": [],
            "state": (
                "outcome_sensitive_roster_assignment_candidates_"
                "independent_review_required"
            ),
            "created_at": created_at,
            "plan": {
                **_published_artifact(plan_path, output_root / plan_path.name),
                "canonical_sha256": plan["plan_sha256"],
            },
            "candidate_artifacts": plan["candidate_artifacts"],
            "source_artifacts": {
                name: _raw_ref(paths[name], raw)
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
            staging
            / "outcome-sensitive-roster-assignment-rebind-preflight.json",
            report,
        )
        os.rename(staging, output_root)
        _fsync_directory(parent)
        return report
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def _validate_sources(
    *,
    paths: dict[str, Path],
    sources: dict[str, tuple[dict[str, Any], bytes]],
    extensions: list[dict[str, Any]],
) -> None:
    values = {name: value for name, (value, _) in sources.items()}
    raws = {name: raw for name, (_, raw) in sources.items()}
    plan = values["outcome_consent_plan"]
    preflight = values["outcome_consent_preflight"]
    manifest = values["signed_consent_manifest"]
    operation = values["consent_signing_operation"]
    consent_gate = values["consent_gate"]
    roster = values["parent_reviewed_roster"]
    assignment = values["parent_reviewed_assignment"]
    assignment_gate = values["parent_assignment_gate"]
    failures = validate_consent_extension_plan(plan)
    statement = authorization_statement(
        plan, hashlib.sha256(raws["outcome_consent_plan"]).hexdigest()
    )
    try:
        _validate_preflight(
            plan=plan,
            plan_path=paths["outcome_consent_plan"],
            plan_raw=raws["outcome_consent_plan"],
            preflight=preflight,
            expected_statement=statement,
            expected_statement_sha=hashlib.sha256(statement.encode()).hexdigest(),
        )
        _validate_frozen_sources(plan=plan, preflight=preflight)
    except (KeyError, OSError, TypeError, ValueError, json.JSONDecodeError) as error:
        failures.append(f"outcome_rebind_consent_source_invalid:{type(error).__name__}")
    authorization = manifest.get("authorization", {})
    try:
        failures.extend(
            validate_signed_manifest(
                manifest,
                plan=plan,
                plan_raw=raws["outcome_consent_plan"],
                preflight_raw=raws["outcome_consent_preflight"],
                authorization_id=str(authorization.get("authorization_id", "")),
                authorization_statement_sha256=str(
                    authorization.get("statement_sha256", "")
                ),
                implementation=manifest.get("implementation", {}),
            )
        )
    except (KeyError, OSError, TypeError, ValueError, json.JSONDecodeError) as error:
        failures.append(
            f"outcome_rebind_signed_consent_invalid:{type(error).__name__}"
        )
    expected_manifest = {
        **_raw_ref(
            paths["signed_consent_manifest"], raws["signed_consent_manifest"]
        ),
        "canonical_sha256": manifest.get("manifest_sha256"),
    }
    operation_body = {
        key: item for key, item in operation.items() if key != "report_sha256"
    }
    if not (
        operation.get("passed") is True
        and operation.get("failure_reasons") == []
        and operation.get("state")
        == "outcome_sensitive_participant_consents_signed_gate_required"
        and operation.get("signed_manifest") == expected_manifest
        and operation.get("inventory") == manifest.get("inventory")
        and operation.get("report_sha256") == canonical_sha256(operation_body)
    ):
        failures.append("outcome_rebind_consent_operation_invalid")
    consent_gate_body = {
        key: item for key, item in consent_gate.items() if key != "report_sha256"
    }
    expected_gate_manifest = _raw_ref(
        paths["signed_consent_manifest"], raws["signed_consent_manifest"]
    )
    if not (
        consent_gate.get("passed") is True
        and consent_gate.get("failure_reasons") == []
        and consent_gate.get("state")
        == (
            "outcome_sensitive_participant_consents_complete_"
            "downstream_rebind_required"
        )
        and consent_gate.get("signed_manifest_sha256")
        == manifest.get("manifest_sha256")
        and consent_gate.get("artifacts", {}).get("signed_manifest")
        == expected_gate_manifest
        and consent_gate.get("artifacts", {}).get("signing_operation")
        == _raw_ref(
            paths["consent_signing_operation"],
            raws["consent_signing_operation"],
        )
        and consent_gate.get("inventory") == manifest.get("inventory")
        and consent_gate.get("report_sha256") == canonical_sha256(consent_gate_body)
    ):
        failures.append("outcome_rebind_consent_gate_invalid")
    roster_body = {
        key: item
        for key, item in roster.items()
        if key != "reviewed_rebound_roster_sha256"
    }
    assignment_body = {
        key: item
        for key, item in assignment.items()
        if key != "reviewed_rebound_assignment_sha256"
    }
    gate_body = {
        key: item for key, item in assignment_gate.items() if key != "report_sha256"
    }
    expected_roster_ref = _ref(
        paths["parent_reviewed_roster"],
        raws["parent_reviewed_roster"],
        roster.get("reviewed_rebound_roster_sha256", ""),
    )
    expected_assignment_ref = _ref(
        paths["parent_reviewed_assignment"],
        raws["parent_reviewed_assignment"],
        assignment.get("reviewed_rebound_assignment_sha256", ""),
    )
    if not (
        roster.get("status") == "operator_reviewed"
        and roster.get("reviewed_rebound_roster_sha256")
        == canonical_sha256(roster_body)
        and len(roster.get("participants", [])) == 40
        and assignment.get("status") == "operator_reviewed"
        and assignment.get("reviewed_rebound_assignment_sha256")
        == canonical_sha256(assignment_body)
        and assignment.get("operator_reviewed_roster_sha256")
        == roster.get("reviewed_rebound_roster_sha256")
        and len(assignment.get("assignments", [])) == 20
        and assignment_gate.get("passed") is True
        and assignment_gate.get("failure_reasons") == []
        and assignment_gate.get("reviewed_artifacts", {}).get("rebound_roster")
        == expected_roster_ref
        and assignment_gate.get("reviewed_artifacts", {}).get(
            "rebound_assignment"
        )
        == expected_assignment_ref
        and assignment_gate.get("report_sha256") == canonical_sha256(gate_body)
    ):
        failures.append("outcome_rebind_parent_roster_assignment_invalid")
    plan_assignment = plan.get("source_binding", {}).get(
        "reviewed_assignment", {}
    )
    if plan_assignment != expected_assignment_ref:
        failures.append("outcome_rebind_consent_parent_assignment_mismatch")
    roster_index = {
        item.get("participant_id"): item for item in roster.get("participants", [])
    }
    assignment_index = _assignment_index(assignment)
    extension_ids = set()
    for record in extensions:
        extension = record["value"]
        failures.extend(validate_consent_extension(extension))
        participant = extension.get("participant", {})
        participant_id = participant.get("participant_id")
        extension_ids.add(participant_id)
        roster_entry = roster_index.get(participant_id, {})
        assignment_entry = assignment_index.get(participant_id, {})
        cohort = extension.get("cohort_binding", {})
        if not (
            participant.get("execution_did") == roster_entry.get("execution_did")
            and participant.get("credential_version")
            == roster_entry.get("credential_version")
            and cohort.get("pair_id") == assignment_entry.get("pair_id")
            and cohort.get("cohort") == assignment_entry.get("cohort")
            and cohort.get("assignment_commitment_sha256")
            == assignment_entry.get("assignment_commitment_sha256")
        ):
            failures.append(
                f"outcome_rebind_participant_binding_invalid:{participant_id}"
            )
    if not (
        len(extensions) == 40
        and len(extension_ids) == 40
        and extension_ids == set(roster_index) == set(assignment_index)
    ):
        failures.append("outcome_rebind_participant_inventory_invalid")
    if failures:
        raise ValueError(
            "outcome-sensitive roster/assignment source invalid: "
            f"{list(dict.fromkeys(failures))}"
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
            raise ValueError(f"outcome consent descriptor invalid: {path}")
        records.append({"artifact": artifact, "value": value})
    return records


def _assignment_index(
    assignment: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    result = {}
    for pair in assignment.get("assignments", []):
        for cohort in ("mentor", "control"):
            member = pair.get(cohort, {})
            participant_id = member.get("participant_id")
            if isinstance(participant_id, str):
                result[participant_id] = {
                    "pair_id": pair.get("pair_id"),
                    "cohort": cohort,
                    "assignment_commitment_sha256": pair.get(
                        "rebind_commitment_sha256"
                    ),
                }
    return result


def _implementation(repository_root: Path) -> dict[str, str]:
    root = repository_root.resolve()
    if _git(root, "status", "--porcelain"):
        raise ValueError("repository must be clean before outcome rebind preflight")
    revision = _git(root, "rev-parse", "HEAD")
    upstream = subprocess.run(
        ["git", "merge-base", "--is-ancestor", revision, "@{upstream}"],
        cwd=root,
        check=False,
    )
    if upstream.returncode != 0:
        raise ValueError("outcome rebind preflight revision is not pushed")
    hashes = {
        str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in (DOMAIN_SOURCE, OPERATION_SOURCE)
    }
    return {
        "source_revision": revision,
        "source_sha256": canonical_sha256(hashes),
    }


def _copy_ref(value: dict[str, Any]) -> dict[str, str]:
    return {
        "path": str(value["path"]),
        "sha256": str(value["sha256"]),
        "canonical_sha256": str(value["canonical_sha256"]),
    }


def _ref(path: Path, raw: bytes, canonical_sha256_value: str) -> dict[str, str]:
    return {
        **_raw_ref(path, raw),
        "canonical_sha256": canonical_sha256_value,
    }


def _raw_ref(path: Path, raw: bytes) -> dict[str, str]:
    return {
        "path": str(path.resolve()),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def _published_artifact(path: Path, published_path: Path) -> dict[str, str]:
    return {
        "path": str(published_path.resolve()),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }


def _read_private(path: Path) -> tuple[dict[str, Any], bytes]:
    resolved = path.resolve()
    if not resolved.is_file() or resolved.is_symlink():
        raise ValueError(f"private artifact is not a regular file: {resolved}")
    if resolved.stat().st_mode & 0o077:
        raise PermissionError(f"private artifact permissions too broad: {resolved}")
    raw = resolved.read_bytes()
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError(f"private artifact must contain an object: {resolved}")
    return value, raw


def _git(root: Path, *args: str) -> str:
    return subprocess.check_output(
        ["git", *args], cwd=root, text=True
    ).strip()


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rebind-id", required=True)
    parser.add_argument(
        "--created-at",
        default=datetime.now(timezone.utc).astimezone().isoformat(),
    )
    parser.add_argument("--consent-plan", type=Path, required=True)
    parser.add_argument("--consent-preflight", type=Path, required=True)
    parser.add_argument("--signed-consent-manifest", type=Path, required=True)
    parser.add_argument("--consent-signing-operation", type=Path, required=True)
    parser.add_argument("--consent-gate", type=Path, required=True)
    parser.add_argument("--reviewed-roster", type=Path, required=True)
    parser.add_argument("--reviewed-assignment", type=Path, required=True)
    parser.add_argument("--assignment-gate", type=Path, required=True)
    parser.add_argument(
        "--repository-root", type=Path, default=Path(__file__).parents[1]
    )
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    report = prepare_rebind(
        rebind_id=args.rebind_id,
        created_at=args.created_at,
        consent_plan_path=args.consent_plan,
        consent_preflight_path=args.consent_preflight,
        signed_consent_manifest_path=args.signed_consent_manifest,
        consent_signing_operation_path=args.consent_signing_operation,
        consent_gate_path=args.consent_gate,
        reviewed_roster_path=args.reviewed_roster,
        reviewed_assignment_path=args.reviewed_assignment,
        assignment_gate_path=args.assignment_gate,
        repository_root=args.repository_root,
        output_root=args.output_root,
    )
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
