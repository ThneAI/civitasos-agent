"""Prepare the no-token outcome-sensitive J1-D consent authorization plan."""

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
from benchmarks.j1.qualification_consent_extension import (
    validate_consent_extension as validate_prior_consent_extension,
)
from benchmarks.j1.qualification_outcome_sensitive_amendment import (
    CONSENT_SCHEMA,
    EVALUATOR_SCHEMA,
    FIXTURE_SCHEMA,
    PLAN_SCHEMA,
    PROTOCOL_SCHEMA,
    STATISTICAL_SCHEMA,
    validate_material,
)
from benchmarks.j1.qualification_outcome_sensitive_amendment_review import (
    validate_signed_review_receipt,
)
from benchmarks.j1.qualification_outcome_sensitive_consent_extension import (
    REQUIRED_MATERIALS,
    authorization_statement,
    build_consent_extension_plan,
)
from benchmarks.j1.qualification_participant_provisioning import (
    validate_participant_profile,
)


REPORT_SCHEMA = "j1-qualification-outcome-sensitive-consent-preflight:v1"
PROMOTION_STATE = (
    "outcome_sensitive_amendment_materials_reviewed_frozen_"
    "40_of_40_consent_required_execution_blocked"
)
MATERIAL_CONTRACTS = {
    "plan": (PLAN_SCHEMA, "plan_sha256"),
    "task_fixture": (FIXTURE_SCHEMA, "fixture_sha256"),
    "statistical_plan": (STATISTICAL_SCHEMA, "statistical_plan_sha256"),
    "protocol": (PROTOCOL_SCHEMA, "protocol_sha256"),
    "evaluator": (EVALUATOR_SCHEMA, "evaluator_sha256"),
    "consent_impact": (CONSENT_SCHEMA, "assessment_sha256"),
}
DOMAIN_SOURCE = (
    Path(__file__).parent
    / "j1"
    / "qualification_outcome_sensitive_consent_extension.py"
)
OPERATION_SOURCE = Path(__file__)


def prepare_consent_extension_plan(
    *,
    plan_id: str,
    created_at: str,
    promotion_gate_path: Path,
    frozen_review_path: Path,
    review_receipt_path: Path,
    reviewed_assignment_path: Path,
    assignment_gate_path: Path,
    participant_provisioning_report_path: Path,
    participant_profiles_root: Path,
    prior_consent_manifest_path: Path,
    prior_consent_gate_path: Path,
    repository_root: Path,
    output_root: Path,
) -> dict[str, Any]:
    """Replay all immutable sources and emit an unsigned authorization plan."""
    if output_root.exists():
        raise FileExistsError(f"outcome consent preflight exists: {output_root}")
    paths = {
        "promotion_gate": promotion_gate_path,
        "frozen_review": frozen_review_path,
        "review_receipt": review_receipt_path,
        "reviewed_assignment": reviewed_assignment_path,
        "assignment_gate": assignment_gate_path,
        "participant_provisioning_report": participant_provisioning_report_path,
        "prior_consent_manifest": prior_consent_manifest_path,
        "prior_consent_gate": prior_consent_gate_path,
    }
    sources = {name: _read_private(path) for name, path in paths.items()}
    values = {name: source[0] for name, source in sources.items()}
    frozen_materials = _validate_promotion_chain(
        paths=paths,
        sources=sources,
    )
    assignments = _validate_assignment_chain(
        assignment=values["reviewed_assignment"],
        assignment_path=reviewed_assignment_path,
        assignment_raw=sources["reviewed_assignment"][1],
        gate=values["assignment_gate"],
    )
    prior_consents = _validate_prior_consent_chain(
        manifest=values["prior_consent_manifest"],
        manifest_path=prior_consent_manifest_path,
        manifest_raw=sources["prior_consent_manifest"][1],
        gate=values["prior_consent_gate"],
    )
    profiles = _load_profiles(participant_profiles_root)
    participant_ids = set(profiles)
    if participant_ids != set(assignments) or participant_ids != set(prior_consents):
        raise ValueError("outcome consent participant source sets differ")
    provisioning = values["participant_provisioning_report"]
    if not (
        provisioning.get("passed") is True
        and provisioning.get("pkcs11_boundary", {}).get("unique_key_count") == 40
        and provisioning.get("pkcs11_boundary", {}).get("private_keys_sensitive")
        is True
        and provisioning.get("pkcs11_boundary", {}).get("private_keys_extractable")
        is False
        and provisioning.get("pkcs11_boundary", {}).get("pin_recorded") is False
    ):
        raise ValueError("participant provisioning PKCS#11 boundary invalid")
    identity_set = [
        _identity_record(profiles[participant_id])
        for participant_id in sorted(participant_ids)
    ]
    targets = [
        _target_record(
            profile=profiles[participant_id],
            assignment=assignments[participant_id],
            prior_consent=prior_consents[participant_id],
        )
        for participant_id in sorted(participant_ids)
    ]
    source_binding = {
        "promotion_gate": _ref(
            promotion_gate_path,
            sources["promotion_gate"][1],
            values["promotion_gate"]["report_sha256"],
        ),
        "frozen_review": _ref(
            frozen_review_path,
            sources["frozen_review"][1],
            values["frozen_review"]["frozen_review_sha256"],
        ),
        "review_receipt": _ref(
            review_receipt_path,
            sources["review_receipt"][1],
            values["review_receipt"]["receipt_sha256"],
        ),
        "frozen_materials": {
            name: frozen_materials[name]["ref"] for name in sorted(frozen_materials)
        },
        "reviewed_assignment": _ref(
            reviewed_assignment_path,
            sources["reviewed_assignment"][1],
            values["reviewed_assignment"]["reviewed_rebound_assignment_sha256"],
        ),
        "assignment_gate": _ref(
            assignment_gate_path,
            sources["assignment_gate"][1],
            values["assignment_gate"]["report_sha256"],
        ),
        "participant_provisioning_report": _raw_ref(
            participant_provisioning_report_path,
            sources["participant_provisioning_report"][1],
        ),
        "prior_consent_manifest": _ref(
            prior_consent_manifest_path,
            sources["prior_consent_manifest"][1],
            values["prior_consent_manifest"]["manifest_sha256"],
        ),
        "prior_consent_gate": _ref(
            prior_consent_gate_path,
            sources["prior_consent_gate"][1],
            values["prior_consent_gate"]["report_sha256"],
        ),
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
    parent = output_root.resolve().parent
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    parent.chmod(0o700)
    staging = Path(tempfile.mkdtemp(prefix=f".{output_root.name}.", dir=parent))
    staging.chmod(0o700)
    try:
        plan_path = staging / "outcome-sensitive-consent-plan.review-required.json"
        write_private_json(plan_path, plan)
        plan_raw_sha = hashlib.sha256(plan_path.read_bytes()).hexdigest()
        statement = authorization_statement(plan, plan_raw_sha)
        published_plan = output_root / plan_path.name
        report = {
            "schema_version": REPORT_SCHEMA,
            "passed": True,
            "failure_reasons": [],
            "state": (
                "outcome_sensitive_consent_exact_owner_signing_"
                "authorization_required"
            ),
            "plan": {
                "path": str(published_plan.resolve()),
                "sha256": plan_raw_sha,
                "canonical_sha256": plan["plan_sha256"],
            },
            "approval_request": {
                "required_exact_statement": statement,
                "statement_sha256": hashlib.sha256(statement.encode()).hexdigest(),
                "participant_consent_extension_signing_authorization_required": True,
            },
            "inventory": copy_inventory(plan),
            "consent_scope": copy_scope(plan),
            "source_artifacts": {
                name: _raw_ref(paths[name], raw)
                for name, (_, raw) in sources.items()
            },
            "frozen_materials": {
                name: item["ref"] for name, item in sorted(frozen_materials.items())
            },
            "implementation": implementation,
            "execution_boundary": plan["current_execution_boundary"],
        }
        report["report_sha256"] = canonical_sha256(report)
        write_private_json(
            staging / "outcome-sensitive-consent-preflight.json",
            report,
        )
        os.rename(staging, output_root)
        _fsync_directory(parent)
        return report
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def copy_inventory(plan: dict[str, Any]) -> dict[str, Any]:
    return dict(plan["inventory"])


def copy_scope(plan: dict[str, Any]) -> dict[str, Any]:
    scope = plan["consent_scope"]
    return {
        **scope,
        "baseline_ordinals": list(scope["baseline_ordinals"]),
        "treatment_ordinals": list(scope["treatment_ordinals"]),
    }


def _validate_promotion_chain(
    *,
    paths: dict[str, Path],
    sources: dict[str, tuple[dict[str, Any], bytes]],
) -> dict[str, dict[str, Any]]:
    gate = sources["promotion_gate"][0]
    frozen = sources["frozen_review"][0]
    receipt = sources["review_receipt"][0]
    gate_body = {key: item for key, item in gate.items() if key != "report_sha256"}
    frozen_body = {
        key: item for key, item in frozen.items() if key != "frozen_review_sha256"
    }
    expected_receipt_ref = _ref(
        paths["review_receipt"],
        sources["review_receipt"][1],
        receipt.get("receipt_sha256", ""),
    )
    expected_frozen_ref = _ref(
        paths["frozen_review"],
        sources["frozen_review"][1],
        frozen.get("frozen_review_sha256", ""),
    )
    readiness = frozen.get("readiness", {})
    if not (
        gate.get("passed") is True
        and gate.get("failure_reasons") == []
        and gate.get("state") == PROMOTION_STATE
        and gate.get("signature_valid") is True
        and gate.get("review_receipt") == expected_receipt_ref
        and gate.get("frozen_review") == expected_frozen_ref
        and gate.get("report_sha256") == canonical_sha256(gate_body)
        and frozen.get("status") == "operator_reviewed_frozen"
        and frozen.get("frozen_review_sha256") == canonical_sha256(frozen_body)
        and frozen.get("operator_review", {}).get("review_receipt")
        == expected_receipt_ref
        and readiness.get("participant_consent_extension_count") == 0
        and readiness.get("participant_consent_extension_required_count") == 40
        and readiness.get("participant_consent_extensions_complete") is False
        and readiness.get("execution_preflight_allowed") is False
        and readiness.get("provider_or_model_execution_allowed") is False
        and readiness.get("si13_maturity_upgrade_allowed") is False
    ):
        raise ValueError("outcome-sensitive promotion chain invalid")
    reviewer = receipt.get("reviewer", {})
    receipt_failures = validate_signed_review_receipt(
        receipt,
        expected_request_ref=receipt.get("request", {}),
        expected_bundle_ref=receipt.get("reviewed_bundle", {}),
        expected_preflight_ref=receipt.get("owner_approval_preflight", {}),
        expected_materials=receipt.get("reviewed_materials", {}),
        expected_approval_statement_sha256=str(
            receipt.get("approval_statement_sha256", "")
        ),
        expected_reviewer={
            "did": reviewer.get("did"),
            "public_key_hex": reviewer.get("public_key_hex"),
            "credential_version": reviewer.get("credential_version"),
            "signer_kind": reviewer.get("signer_kind"),
        },
        expected_reviewer_profile_sha256=str(
            reviewer.get("identity_profile_sha256", "")
        ),
        expected_implementation=receipt.get("implementation", {}),
    )
    if receipt_failures:
        raise ValueError(f"outcome-sensitive review receipt invalid: {receipt_failures}")
    frozen_refs = frozen.get("frozen_source_copies", {})
    source_refs = frozen.get("source_materials", {})
    if set(frozen_refs) != REQUIRED_MATERIALS or set(source_refs) != REQUIRED_MATERIALS:
        raise ValueError("frozen material inventory invalid")
    result = {}
    for name, (schema, hash_field) in MATERIAL_CONTRACTS.items():
        frozen_ref = frozen_refs[name]
        source_ref = source_refs[name]
        material_path = Path(frozen_ref["path"])
        material, material_raw = _read_private(material_path)
        source_path = Path(source_ref["path"])
        _, source_raw = _read_private(source_path)
        failures = validate_material(material, schema=schema, hash_field=hash_field)
        expected_ref = _ref(material_path, material_raw, material[hash_field])
        if (
            failures
            or frozen_ref != expected_ref
            or source_ref["sha256"] != hashlib.sha256(source_raw).hexdigest()
            or source_ref["canonical_sha256"] != material[hash_field]
            or source_raw != material_raw
        ):
            raise ValueError(f"frozen outcome material invalid: {name}:{failures}")
        result[name] = {"value": material, "ref": expected_ref}
    protocol = result["protocol"]["value"]
    consent_impact = result["consent_impact"]["value"]
    if not (
        protocol.get("scope")
        == {
            "participant_count": 40,
            "matched_pair_count": 20,
            "tasks_per_participant": 12,
            "total_task_count": 480,
            "minimum_completed_pairs": 20,
        }
        and protocol.get("fresh_bindings_required", {}).get(
            "participant_consent_extensions"
        )
        == 40
        and consent_impact.get("decision", {}).get(
            "new_consent_extension_required"
        )
        is True
        and consent_impact.get("decision", {}).get("prior_consent_inherited")
        is False
        and consent_impact.get("decision", {}).get("decline_without_penalty_required")
        is True
    ):
        raise ValueError("outcome-sensitive consent scope invalid")
    return result


def _validate_assignment_chain(
    *,
    assignment: dict[str, Any],
    assignment_path: Path,
    assignment_raw: bytes,
    gate: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    assignment_body = {
        key: item
        for key, item in assignment.items()
        if key != "reviewed_rebound_assignment_sha256"
    }
    gate_body = {key: item for key, item in gate.items() if key != "report_sha256"}
    expected_assignment_ref = _ref(
        assignment_path,
        assignment_raw,
        assignment.get("reviewed_rebound_assignment_sha256", ""),
    )
    pairs = assignment.get("assignments")
    pair_values = pairs if isinstance(pairs, list) else []
    result = {}
    for pair in pair_values:
        for cohort in ("mentor", "control"):
            member = pair.get(cohort, {})
            participant_id = member.get("participant_id")
            if not isinstance(participant_id, str) or participant_id in result:
                raise ValueError("reviewed assignment participant inventory invalid")
            result[participant_id] = {
                "participant_id": participant_id,
                "execution_did": member.get("execution_did"),
                "pair_id": pair.get("pair_id"),
                "cohort": cohort,
                "assignment_commitment_sha256": pair.get(
                    "rebind_commitment_sha256"
                ),
                "prior_consent_sha256": member.get("consent_extension_sha256"),
            }
    if not (
        assignment.get("status") == "operator_reviewed"
        and assignment.get("reviewed_rebound_assignment_sha256")
        == canonical_sha256(assignment_body)
        and len(pair_values) == 20
        and len(result) == 40
        and gate.get("passed") is True
        and gate.get("failure_reasons") == []
        and gate.get("reviewed_artifacts", {}).get("rebound_assignment")
        == expected_assignment_ref
        and gate.get("report_sha256") == canonical_sha256(gate_body)
    ):
        raise ValueError("reviewed assignment chain invalid")
    return result


def _validate_prior_consent_chain(
    *,
    manifest: dict[str, Any],
    manifest_path: Path,
    manifest_raw: bytes,
    gate: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    body = {key: item for key, item in manifest.items() if key != "manifest_sha256"}
    gate_body = {key: item for key, item in gate.items() if key != "report_sha256"}
    descriptors = manifest.get("extensions")
    descriptor_values = descriptors if isinstance(descriptors, list) else []
    result = {}
    for descriptor in descriptor_values:
        path = Path(descriptor.get("path", ""))
        extension, raw = _read_private(path)
        failures = validate_prior_consent_extension(extension)
        participant_id = extension.get("participant", {}).get("participant_id")
        expected = {
            "path": str(path.resolve()),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "participant_id": participant_id,
            "cohort": extension.get("cohort_binding", {}).get("cohort"),
            "canonical_sha256": extension.get("extension_sha256"),
        }
        if (
            failures
            or descriptor != expected
            or not isinstance(participant_id, str)
            or participant_id in result
        ):
            raise ValueError(f"prior consent extension invalid: {participant_id}")
        result[participant_id] = {
            "artifact_sha256": expected["sha256"],
            "canonical_sha256": expected["canonical_sha256"],
        }
    manifest_ref = _raw_ref(manifest_path, manifest_raw)
    if not (
        manifest.get("status") == "signed_gate_required"
        and manifest.get("manifest_sha256") == canonical_sha256(body)
        and manifest.get("inventory", {}).get("signed_extension_count") == 40
        and manifest.get("inventory", {}).get("all_signatures_verified") is True
        and manifest.get("inventory", {}).get("prior_consent_inherited") is False
        and len(descriptor_values) == 40
        and len(result) == 40
        and gate.get("passed") is True
        and gate.get("failure_reasons") == []
        and gate.get("signed_manifest_sha256") == manifest.get("manifest_sha256")
        and gate.get("artifacts", {}).get("signed_manifest") == manifest_ref
        and gate.get("signature_verification", {}).get("verified") == 40
        and gate.get("report_sha256") == canonical_sha256(gate_body)
    ):
        raise ValueError("prior consent manifest or Gate invalid")
    return result


def _load_profiles(root: Path) -> dict[str, dict[str, Any]]:
    profiles = {}
    for path in sorted(root.glob("*.json")):
        profile, raw = _read_private(path)
        failures = validate_participant_profile(profile)
        participant_id = profile.get("participant", {}).get("participant_id")
        if failures or not isinstance(participant_id, str) or participant_id in profiles:
            raise ValueError(f"participant profile invalid: {path.name}:{failures}")
        profiles[participant_id] = {
            "value": profile,
            "artifact_sha256": hashlib.sha256(raw).hexdigest(),
        }
    if len(profiles) != 40:
        raise ValueError("outcome consent requires exactly 40 participant profiles")
    return profiles


def _identity_record(profile: dict[str, Any]) -> dict[str, Any]:
    value = profile["value"]
    participant = value["participant"]
    key = value["pkcs11_key"]
    return {
        "participant_id": participant["participant_id"],
        "execution_did": participant["execution_did"],
        "public_key_sha256": participant["public_key_sha256"],
        "key_label": key["key_label"],
        "key_id_hex": key["key_id_hex"],
        "profile_artifact_sha256": profile["artifact_sha256"],
        "profile_sha256": value["profile_sha256"],
    }


def _target_record(
    *,
    profile: dict[str, Any],
    assignment: dict[str, Any],
    prior_consent: dict[str, Any],
) -> dict[str, Any]:
    value = profile["value"]
    participant = value["participant"]
    if (
        participant["execution_did"] != assignment["execution_did"]
        or prior_consent["canonical_sha256"] != assignment["prior_consent_sha256"]
    ):
        raise ValueError(f"participant source binding mismatch: {assignment['participant_id']}")
    return {
        "participant_id": participant["participant_id"],
        "execution_did": participant["execution_did"],
        "pair_id": assignment["pair_id"],
        "cohort": assignment["cohort"],
        "assignment_commitment_sha256": assignment[
            "assignment_commitment_sha256"
        ],
        "participant_profile_artifact_sha256": profile["artifact_sha256"],
        "participant_profile_sha256": value["profile_sha256"],
        "prior_consent_artifact_sha256": prior_consent["artifact_sha256"],
        "prior_consent_sha256": prior_consent["canonical_sha256"],
    }


def _implementation(root: Path) -> dict[str, str]:
    repository_root = root.resolve()
    if _git(repository_root, "status", "--porcelain"):
        raise ValueError("repository must be clean before freezing consent preflight")
    revision = _git(repository_root, "rev-parse", "HEAD")
    if (
        subprocess.run(
            ["git", "merge-base", "--is-ancestor", revision, "@{upstream}"],
            cwd=repository_root,
            check=False,
        ).returncode
        != 0
    ):
        raise ValueError("consent preflight implementation revision is not pushed")
    hashes = {
        str(path.relative_to(repository_root)): hashlib.sha256(
            path.read_bytes()
        ).hexdigest()
        for path in (DOMAIN_SOURCE, OPERATION_SOURCE)
    }
    return {
        "source_revision": revision,
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


def _ref(path: Path, raw: bytes, canonical: str) -> dict[str, str]:
    return {
        "path": str(path.resolve()),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "canonical_sha256": canonical,
    }


def _raw_ref(path: Path, raw: bytes) -> dict[str, str]:
    return {
        "path": str(path.resolve()),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def _git(root: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", *arguments],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan-id", required=True)
    parser.add_argument("--promotion-gate", type=Path, required=True)
    parser.add_argument("--frozen-review", type=Path, required=True)
    parser.add_argument("--review-receipt", type=Path, required=True)
    parser.add_argument("--reviewed-assignment", type=Path, required=True)
    parser.add_argument("--assignment-gate", type=Path, required=True)
    parser.add_argument("--participant-provisioning-report", type=Path, required=True)
    parser.add_argument("--participant-profiles-root", type=Path, required=True)
    parser.add_argument("--prior-consent-manifest", type=Path, required=True)
    parser.add_argument("--prior-consent-gate", type=Path, required=True)
    parser.add_argument(
        "--repository-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
    )
    parser.add_argument("--output-root", type=Path, required=True)
    return parser


def main() -> int:
    args = _parser().parse_args()
    report = prepare_consent_extension_plan(
        plan_id=args.plan_id,
        created_at=datetime.now(timezone.utc).isoformat(),
        promotion_gate_path=args.promotion_gate,
        frozen_review_path=args.frozen_review,
        review_receipt_path=args.review_receipt,
        reviewed_assignment_path=args.reviewed_assignment,
        assignment_gate_path=args.assignment_gate,
        participant_provisioning_report_path=args.participant_provisioning_report,
        participant_profiles_root=args.participant_profiles_root,
        prior_consent_manifest_path=args.prior_consent_manifest,
        prior_consent_gate_path=args.prior_consent_gate,
        repository_root=args.repository_root,
        output_root=args.output_root,
    )
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
