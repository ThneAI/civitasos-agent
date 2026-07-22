"""Prepare the no-token J1-D participant consent-extension authorization plan."""

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
from benchmarks.j1.qualification_baseline_consent import validate_participant_consent
from benchmarks.j1.qualification_cohort_assignment import validate_reviewed_assignment
from benchmarks.j1.qualification_consent_extension import (
    authorization_statement,
    build_consent_extension_plan,
    validate_consent_extension_plan,
)
from benchmarks.j1.qualification_participant_provisioning import (
    validate_participant_profile,
)


REPORT_SCHEMA = "j1-qualification-consent-extension-preflight:v1"
DOMAIN_SOURCE = Path(__file__).parent / "j1" / "qualification_consent_extension.py"
OPERATION_SOURCE = Path(__file__)


def prepare_consent_extension_plan(
    *,
    plan_id: str,
    created_at: str,
    amendment_bundle_path: Path,
    protocol_amendment_path: Path,
    design_amendment_path: Path,
    reviewed_assignment_path: Path,
    assignment_gate_path: Path,
    participant_provisioning_report_path: Path,
    participant_profiles_root: Path,
    prior_consent_manifest_path: Path,
    repository_root: Path,
    output_root: Path,
) -> dict[str, Any]:
    if output_root.exists():
        raise ValueError(
            f"consent-extension preflight output already exists: {output_root}"
        )
    paths = {
        "amendment_bundle": amendment_bundle_path,
        "protocol_amendment": protocol_amendment_path,
        "design_amendment": design_amendment_path,
        "reviewed_assignment": reviewed_assignment_path,
        "assignment_gate": assignment_gate_path,
        "participant_provisioning_report": participant_provisioning_report_path,
        "prior_consent_manifest": prior_consent_manifest_path,
    }
    sources = {name: _read_private(path) for name, path in paths.items()}
    values = {name: value for name, (value, _) in sources.items()}
    _validate_source_chain(paths=paths, sources=sources)
    profiles = _load_profiles(participant_profiles_root)
    assignments = _assignment_index(values["reviewed_assignment"])
    prior_consents = _load_prior_consents(values["prior_consent_manifest"])
    participant_ids = set(profiles)
    if participant_ids != set(assignments) or participant_ids != set(prior_consents):
        raise ValueError("consent-extension participant source sets differ")
    identity_set = [
        _identity_record(profiles[item]) for item in sorted(participant_ids)
    ]
    targets = [
        _consent_target(
            profile=profiles[participant_id],
            assignment=assignments[participant_id],
            prior_consent=prior_consents[participant_id],
        )
        for participant_id in sorted(participant_ids)
    ]
    bundle = values["amendment_bundle"]
    protocol = values["protocol_amendment"]
    design = values["design_amendment"]
    assignment = values["reviewed_assignment"]
    manifest = values["prior_consent_manifest"]
    provisioning = values["participant_provisioning_report"]
    source_binding = {
        "amendment_bundle_artifact_sha256": _raw_sha(sources["amendment_bundle"]),
        "amendment_bundle_sha256": bundle["bundle_sha256"],
        "protocol_amendment_artifact_sha256": _raw_sha(sources["protocol_amendment"]),
        "protocol_amendment_sha256": protocol["amended_protocol_sha256"],
        "design_amendment_artifact_sha256": _raw_sha(sources["design_amendment"]),
        "design_amendment_sha256": design["amended_design_sha256"],
        "reviewed_assignment_artifact_sha256": _raw_sha(sources["reviewed_assignment"]),
        "reviewed_assignment_sha256": assignment["reviewed_assignment_sha256"],
        "assignment_gate_artifact_sha256": _raw_sha(sources["assignment_gate"]),
        "participant_provisioning_report_artifact_sha256": _raw_sha(
            sources["participant_provisioning_report"]
        ),
        "prior_consent_manifest_artifact_sha256": _raw_sha(
            sources["prior_consent_manifest"]
        ),
        "prior_consent_manifest_sha256": manifest["manifest_sha256"],
        "token_label": provisioning["pkcs11_boundary"]["token_label"],
    }
    implementation = _implementation(repository_root)
    plan = build_consent_extension_plan(
        plan_id=plan_id,
        created_at=created_at,
        source_binding=source_binding,
        participant_identity_set=identity_set,
        consent_targets=targets,
        implementation=implementation,
    )
    failures = validate_consent_extension_plan(plan)
    if failures:
        raise ValueError(f"consent-extension plan invalid: {failures}")
    output_root.mkdir(parents=True, mode=0o700)
    output_root.chmod(0o700)
    try:
        plan_path = output_root / "consent-extension-plan.review-required.json"
        write_private_json(plan_path, plan)
        plan_raw_sha = hashlib.sha256(plan_path.read_bytes()).hexdigest()
        statement = authorization_statement(plan, plan_raw_sha)
        report = {
            "schema_version": REPORT_SCHEMA,
            "passed": True,
            "state": "consent_extension_explicit_owner_signing_authorization_required",
            "plan": {
                **_artifact(plan_path),
                "canonical_sha256": plan["plan_sha256"],
            },
            "approval_request": {
                "required_exact_statement": statement,
                "statement_sha256": hashlib.sha256(statement.encode()).hexdigest(),
                "participant_consent_extension_signing_authorization_required": True,
            },
            "inventory": plan["inventory"],
            "source_artifacts": {
                name: _artifact_bytes(paths[name], raw)
                for name, (_, raw) in sources.items()
            },
            "implementation": implementation,
            "execution_boundary": plan["current_execution_boundary"],
        }
        report["report_sha256"] = canonical_sha256(report)
        write_private_json(output_root / "consent-extension-preflight.json", report)
        return report
    except Exception:
        shutil.rmtree(output_root, ignore_errors=True)
        raise


def _validate_source_chain(
    *,
    paths: dict[str, Path],
    sources: dict[str, tuple[dict[str, Any], bytes]],
) -> None:
    values = {name: value for name, (value, _) in sources.items()}
    bundle = values["amendment_bundle"]
    protocol = values["protocol_amendment"]
    design = values["design_amendment"]
    assignment = values["reviewed_assignment"]
    gate = values["assignment_gate"]
    provisioning = values["participant_provisioning_report"]
    manifest = values["prior_consent_manifest"]
    failures = validate_reviewed_assignment(assignment)
    if not (
        bundle.get("schema_version")
        == "j1-qualification-protocol-design-amendment-bundle:v1"
        and bundle.get("status") == "reviewed_plan_derived_consent_extension_required"
        and bundle.get("readiness", {}).get("participant_consent_extensions_complete")
        is False
        and _canonical_valid(bundle, "bundle_sha256")
        and _canonical_valid(protocol, "amended_protocol_sha256")
        and _canonical_valid(design, "amended_design_sha256")
        and bundle.get("protocol_amendment")
        == {
            **_artifact_bytes(
                paths["protocol_amendment"], sources["protocol_amendment"][1]
            ),
            "canonical_sha256": protocol.get("amended_protocol_sha256"),
        }
        and bundle.get("design_amendment")
        == {
            **_artifact_bytes(
                paths["design_amendment"], sources["design_amendment"][1]
            ),
            "canonical_sha256": design.get("amended_design_sha256"),
        }
    ):
        failures.append("consent_extension_amendment_source_invalid")
    if not (
        gate.get("passed") is True
        and gate.get("failure_reasons") == []
        and gate.get("reviewed_assignment_sha256")
        == assignment.get("reviewed_assignment_sha256")
        and gate.get("artifacts", {}).get("reviewed_assignment")
        == _artifact_bytes(
            paths["reviewed_assignment"], sources["reviewed_assignment"][1]
        )
    ):
        failures.append("consent_extension_assignment_gate_invalid")
    if not (
        provisioning.get("passed") is True
        and provisioning.get("pkcs11_boundary", {}).get("unique_key_count") == 40
        and provisioning.get("pkcs11_boundary", {}).get("private_keys_sensitive")
        is True
        and provisioning.get("pkcs11_boundary", {}).get("private_keys_extractable")
        is False
        and manifest.get("schema_version")
        == "j1-qualification-baseline-consent-manifest:v1"
        and manifest.get("counts", {}).get("participant_consents") == 40
        and _canonical_valid(manifest, "manifest_sha256")
    ):
        failures.append("consent_extension_participant_parent_source_invalid")
    if failures:
        raise ValueError(
            f"consent-extension source chain invalid: {list(dict.fromkeys(failures))}"
        )


def _load_profiles(root: Path) -> dict[str, dict[str, Any]]:
    profiles = {}
    for path in sorted(root.glob("*.json")):
        profile, _ = _read_private(path)
        failures = validate_participant_profile(profile)
        if failures:
            raise ValueError(f"participant profile invalid ({path.name}): {failures}")
        participant_id = profile["participant"]["participant_id"]
        profiles[participant_id] = {
            **profile,
            "_artifact_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }
    if len(profiles) != 40:
        raise ValueError("consent-extension requires exactly 40 participant profiles")
    return profiles


def _assignment_index(assignment: dict[str, Any]) -> dict[str, dict[str, Any]]:
    result = {}
    for item in assignment["assignments"]:
        for cohort in ("mentor", "control"):
            participant = item[cohort]
            result[participant["participant_id"]] = {
                "pair_id": item["pair_id"],
                "cohort": cohort,
                "assignment_commitment_sha256": item["assignment_commitment_sha256"],
                "execution_did": participant["execution_did"],
            }
    if len(result) != 40:
        raise ValueError("reviewed assignment does not contain 40 unique participants")
    return result


def _load_prior_consents(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    result = {}
    descriptors = [
        item
        for item in manifest["artifacts"]
        if Path(str(item.get("path", ""))).name.endswith(".consent.json")
    ]
    for descriptor in descriptors:
        path = Path(descriptor["path"])
        consent, raw = _read_private(path)
        if descriptor.get("sha256") != hashlib.sha256(raw).hexdigest():
            raise ValueError(f"prior consent artifact drift: {path.name}")
        failures = validate_participant_consent(consent)
        if failures:
            raise ValueError(
                f"prior participant consent invalid ({path.name}): {failures}"
            )
        result[consent["participant_id"]] = {
            "value": consent,
            "artifact_sha256": hashlib.sha256(raw).hexdigest(),
            "canonical_sha256": canonical_sha256(consent),
        }
    if len(result) != 40:
        raise ValueError("prior consent manifest does not contain 40 unique consents")
    return result


def _identity_record(profile: dict[str, Any]) -> dict[str, Any]:
    participant = profile["participant"]
    key = profile["pkcs11_key"]
    return {
        "participant_id": participant["participant_id"],
        "execution_did": participant["execution_did"],
        "public_key_sha256": participant["public_key_sha256"],
        "key_label": key["key_label"],
        "key_id_hex": key["key_id_hex"],
        "profile_sha256": profile["profile_sha256"],
    }


def _consent_target(
    *,
    profile: dict[str, Any],
    assignment: dict[str, Any],
    prior_consent: dict[str, Any],
) -> dict[str, Any]:
    participant = profile["participant"]
    if participant["execution_did"] != assignment["execution_did"]:
        raise ValueError(f"assignment DID mismatch: {participant['participant_id']}")
    prior = prior_consent["value"]
    if (
        prior["participant_profile_sha256"] != profile["profile_sha256"]
        or prior["pair_id"] != assignment["pair_id"]
    ):
        raise ValueError(
            f"prior consent binding mismatch: {participant['participant_id']}"
        )
    return {
        "participant_id": participant["participant_id"],
        "execution_did": participant["execution_did"],
        "pair_id": assignment["pair_id"],
        "cohort": assignment["cohort"],
        "assignment_commitment_sha256": assignment["assignment_commitment_sha256"],
        "participant_profile_sha256": profile["profile_sha256"],
        "prior_consent_artifact_sha256": prior_consent["artifact_sha256"],
        "prior_consent_sha256": prior_consent["canonical_sha256"],
    }


def _implementation(repository_root: Path) -> dict[str, str]:
    root = repository_root.resolve()
    if _git(root, "status", "--porcelain").strip():
        raise ValueError(
            "repository must be clean before freezing consent-extension preflight"
        )
    hashes = {
        str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in (DOMAIN_SOURCE, OPERATION_SOURCE)
    }
    return {
        "source_revision": _git(root, "rev-parse", "HEAD").strip(),
        "source_sha256": canonical_sha256(hashes),
    }


def _git(root: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", *arguments], cwd=root, check=True, capture_output=True, text=True
    ).stdout


def _canonical_valid(value: dict[str, Any], field: str) -> bool:
    body = {key: item for key, item in value.items() if key != field}
    return value.get(field) == canonical_sha256(body)


def _read_private(path: Path) -> tuple[dict[str, Any], bytes]:
    resolved = path.resolve()
    if path.is_symlink() or not resolved.is_file() or resolved.stat().st_mode & 0o077:
        raise ValueError(f"private JSON artifact invalid: {resolved}")
    raw = resolved.read_bytes()
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError(f"JSON artifact must contain an object: {resolved}")
    return value, raw


def _raw_sha(source: tuple[dict[str, Any], bytes]) -> str:
    return hashlib.sha256(source[1]).hexdigest()


def _artifact(path: Path) -> dict[str, str]:
    return _artifact_bytes(path, path.read_bytes())


def _artifact_bytes(path: Path, raw: bytes) -> dict[str, str]:
    return {"path": str(path.resolve()), "sha256": hashlib.sha256(raw).hexdigest()}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan-id", required=True)
    parser.add_argument("--amendment-bundle", type=Path, required=True)
    parser.add_argument("--protocol-amendment", type=Path, required=True)
    parser.add_argument("--design-amendment", type=Path, required=True)
    parser.add_argument("--reviewed-assignment", type=Path, required=True)
    parser.add_argument("--assignment-gate", type=Path, required=True)
    parser.add_argument("--participant-provisioning-report", type=Path, required=True)
    parser.add_argument("--participant-profiles-root", type=Path, required=True)
    parser.add_argument("--prior-consent-manifest", type=Path, required=True)
    parser.add_argument(
        "--repository-root", type=Path, default=Path(__file__).parents[1]
    )
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    report = prepare_consent_extension_plan(
        plan_id=args.plan_id,
        created_at=datetime.now(timezone.utc).isoformat(),
        amendment_bundle_path=args.amendment_bundle,
        protocol_amendment_path=args.protocol_amendment,
        design_amendment_path=args.design_amendment,
        reviewed_assignment_path=args.reviewed_assignment,
        assignment_gate_path=args.assignment_gate,
        participant_provisioning_report_path=args.participant_provisioning_report,
        participant_profiles_root=args.participant_profiles_root,
        prior_consent_manifest_path=args.prior_consent_manifest,
        repository_root=args.repository_root,
        output_root=args.output_root,
    )
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
