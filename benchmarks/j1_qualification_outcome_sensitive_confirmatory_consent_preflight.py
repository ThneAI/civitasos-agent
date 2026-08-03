"""Prepare the no-token J1-D confirmatory consent authorization plan."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from benchmarks.j1.controlled_comparison import canonical_sha256, write_private_json
from benchmarks.j1.qualification_outcome_sensitive_confirmatory_amendment import (
    CONSENT_SCHEMA,
    EVALUATOR_SCHEMA,
    METHOD_SCHEMA,
    PROTOCOL_SCHEMA,
    VERIFICATION_SCHEMA,
    validate_material,
)
from benchmarks.j1.qualification_outcome_sensitive_confirmatory_consent import (
    MATERIAL_NAMES,
    authorization_statement,
    build_plan,
)
from benchmarks.j1.qualification_outcome_sensitive_confirmatory_review import (
    validate_signed_review_receipt,
)
from benchmarks.j1.qualification_outcome_sensitive_consent_extension import (
    validate_consent_extension,
)
from benchmarks.j1_qualification_outcome_sensitive_consent_extension_preflight import (
    _identity_record,
    _load_profiles,
)


REPORT_SCHEMA = "j1-outcome-sensitive-confirmatory-consent-preflight:v1"
PROMOTION_STATE = (
    "confirmatory_method_amendment_reviewed_frozen_"
    "40_of_40_consent_required_execution_blocked"
)
ASSIGNMENT_GATE_STATE = (
    "outcome_sensitive_roster_assignment_rebind_passed_"
    "mentor_advice_and_infrastructure_rebind_required"
)
PRIOR_CONSENT_GATE_STATE = (
    "outcome_sensitive_participant_consents_complete_downstream_rebind_required"
)
MATERIAL_CONTRACTS = {
    "confirmatory_method": (METHOD_SCHEMA, "method_sha256"),
    "protocol_addendum": (PROTOCOL_SCHEMA, "addendum_sha256"),
    "evaluator_addendum": (EVALUATOR_SCHEMA, "evaluator_sha256"),
    "consent_impact": (CONSENT_SCHEMA, "assessment_sha256"),
    "verification": (VERIFICATION_SCHEMA, "verification_sha256"),
}
DOMAIN_SOURCE = (
    Path(__file__).parent
    / "j1"
    / "qualification_outcome_sensitive_confirmatory_consent.py"
)
OPERATION_SOURCE = Path(__file__)


def prepare_plan(
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
    prior_outcome_consent_manifest_path: Path,
    prior_outcome_consent_gate_path: Path,
    repository_root: Path,
    output_root: Path,
) -> dict[str, Any]:
    """Replay immutable sources and emit an unsigned, no-token plan."""
    if output_root.exists():
        raise FileExistsError(f"confirmatory consent preflight exists: {output_root}")
    paths = {
        "promotion_gate": promotion_gate_path,
        "frozen_review": frozen_review_path,
        "review_receipt": review_receipt_path,
        "reviewed_assignment": reviewed_assignment_path,
        "assignment_gate": assignment_gate_path,
        "participant_provisioning_report": participant_provisioning_report_path,
        "prior_outcome_consent_manifest": prior_outcome_consent_manifest_path,
        "prior_outcome_consent_gate": prior_outcome_consent_gate_path,
    }
    sources = {name: _read_private(path) for name, path in paths.items()}
    values = {name: value for name, (value, _) in sources.items()}
    frozen_materials = _validate_confirmatory_promotion(
        paths=paths,
        sources=sources,
    )
    prior_consents = _validate_prior_consents(
        manifest=values["prior_outcome_consent_manifest"],
        manifest_raw=sources["prior_outcome_consent_manifest"][1],
        manifest_path=prior_outcome_consent_manifest_path,
        gate=values["prior_outcome_consent_gate"],
    )
    assignments = _validate_assignment(
        assignment=values["reviewed_assignment"],
        assignment_raw=sources["reviewed_assignment"][1],
        assignment_path=reviewed_assignment_path,
        gate=values["assignment_gate"],
        prior_consents=prior_consents,
    )
    profiles = _load_profiles(participant_profiles_root)
    participant_ids = set(profiles)
    if participant_ids != set(assignments) or participant_ids != set(prior_consents):
        raise ValueError("confirmatory consent participant source sets differ")
    provisioning = values["participant_provisioning_report"]
    boundary = provisioning.get("pkcs11_boundary", {})
    if not (
        provisioning.get("passed") is True
        and boundary.get("unique_key_count") == 40
        and boundary.get("private_keys_sensitive") is True
        and boundary.get("private_keys_extractable") is False
        and boundary.get("pin_recorded") is False
        and isinstance(boundary.get("token_label"), str)
    ):
        raise ValueError("confirmatory consent participant custody invalid")
    identities = [
        _identity_record(profiles[participant_id])
        for participant_id in sorted(participant_ids)
    ]
    targets = [
        _target(
            profile=profiles[participant_id],
            assignment=assignments[participant_id],
            prior=prior_consents[participant_id],
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
            name: item["ref"] for name, item in sorted(frozen_materials.items())
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
        "prior_outcome_consent_manifest": _ref(
            prior_outcome_consent_manifest_path,
            sources["prior_outcome_consent_manifest"][1],
            values["prior_outcome_consent_manifest"]["manifest_sha256"],
        ),
        "prior_outcome_consent_gate": _ref(
            prior_outcome_consent_gate_path,
            sources["prior_outcome_consent_gate"][1],
            values["prior_outcome_consent_gate"]["report_sha256"],
        ),
        "token_label": boundary["token_label"],
    }
    implementation = _implementation(repository_root)
    plan = build_plan(
        plan_id=plan_id,
        created_at=created_at,
        source_binding=source_binding,
        participant_identity_set=identities,
        consent_targets=targets,
        implementation=implementation,
    )
    parent = output_root.resolve().parent
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    parent.chmod(0o700)
    staging = Path(tempfile.mkdtemp(prefix=f".{output_root.name}.", dir=parent))
    staging.chmod(0o700)
    try:
        plan_path = staging / "confirmatory-consent-plan.review-required.json"
        write_private_json(plan_path, plan)
        plan_raw_sha = hashlib.sha256(plan_path.read_bytes()).hexdigest()
        statement = authorization_statement(plan, plan_raw_sha)
        report = {
            "schema_version": REPORT_SCHEMA,
            "passed": True,
            "failure_reasons": [],
            "state": "confirmatory_consent_exact_owner_signing_authorization_required",
            "plan": {
                "path": str(
                    (
                        output_root / "confirmatory-consent-plan.review-required.json"
                    ).resolve()
                ),
                "sha256": plan_raw_sha,
                "canonical_sha256": plan["plan_sha256"],
            },
            "approval_request": {
                "required_exact_statement": statement,
                "statement_sha256": hashlib.sha256(statement.encode()).hexdigest(),
                "participant_signature_authorization_required": True,
            },
            "inventory": plan["inventory"],
            "consent_scope": plan["consent_scope"],
            "source_artifacts": {
                name: _raw_ref(paths[name], raw) for name, (_, raw) in sources.items()
            },
            "frozen_materials": {
                name: item["ref"] for name, item in sorted(frozen_materials.items())
            },
            "implementation": implementation,
            "execution_boundary": plan["current_execution_boundary"],
        }
        report["report_sha256"] = canonical_sha256(report)
        write_private_json(
            staging / "confirmatory-consent-preflight.json",
            report,
        )
        os.rename(staging, output_root)
        _fsync_directory(parent)
        return report
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def replay_source_binding(plan: dict[str, Any]) -> None:
    """Replay every immutable source referenced by a frozen consent plan."""
    source = plan["source_binding"]
    names = (
        "promotion_gate",
        "frozen_review",
        "review_receipt",
        "reviewed_assignment",
        "assignment_gate",
        "participant_provisioning_report",
        "prior_outcome_consent_manifest",
        "prior_outcome_consent_gate",
    )
    paths = {name: Path(source[name]["path"]) for name in names}
    sources = {name: _read_private(path) for name, path in paths.items()}
    for name, (value, raw) in sources.items():
        ref = source[name]
        if hashlib.sha256(raw).hexdigest() != ref["sha256"]:
            raise ValueError(f"confirmatory consent source drift: {name}")
        canonical = ref.get("canonical_sha256")
        if canonical is not None:
            hash_field = {
                "promotion_gate": "report_sha256",
                "frozen_review": "frozen_review_sha256",
                "review_receipt": "receipt_sha256",
                "reviewed_assignment": "reviewed_rebound_assignment_sha256",
                "assignment_gate": "report_sha256",
                "prior_outcome_consent_manifest": "manifest_sha256",
                "prior_outcome_consent_gate": "report_sha256",
            }[name]
            if value.get(hash_field) != canonical:
                raise ValueError(f"confirmatory consent canonical source drift: {name}")
    materials = _validate_confirmatory_promotion(paths=paths, sources=sources)
    if {name: item["ref"] for name, item in sorted(materials.items())} != source[
        "frozen_materials"
    ]:
        raise ValueError("confirmatory consent frozen material binding drift")
    prior = _validate_prior_consents(
        manifest=sources["prior_outcome_consent_manifest"][0],
        manifest_raw=sources["prior_outcome_consent_manifest"][1],
        manifest_path=paths["prior_outcome_consent_manifest"],
        gate=sources["prior_outcome_consent_gate"][0],
    )
    assignments = _validate_assignment(
        assignment=sources["reviewed_assignment"][0],
        assignment_raw=sources["reviewed_assignment"][1],
        assignment_path=paths["reviewed_assignment"],
        gate=sources["assignment_gate"][0],
        prior_consents=prior,
    )
    plan_targets = {
        item["participant_id"]: {
            key: item[key]
            for key in (
                "participant_id",
                "execution_did",
                "pair_id",
                "cohort",
                "assignment_commitment_sha256",
            )
        }
        for item in plan["consent_targets"]
    }
    if assignments != plan_targets:
        raise ValueError("confirmatory consent assignment target drift")
    boundary = sources["participant_provisioning_report"][0].get(
        "pkcs11_boundary",
        {},
    )
    if not (
        boundary.get("unique_key_count") == 40
        and boundary.get("private_keys_sensitive") is True
        and boundary.get("private_keys_extractable") is False
        and boundary.get("pin_recorded") is False
        and boundary.get("token_label") == source["token_label"]
    ):
        raise ValueError("confirmatory consent provisioning boundary drift")


def _validate_confirmatory_promotion(
    *,
    paths: dict[str, Path],
    sources: dict[str, tuple[dict[str, Any], bytes]],
) -> dict[str, dict[str, Any]]:
    gate, gate_raw = sources["promotion_gate"]
    frozen, frozen_raw = sources["frozen_review"]
    receipt, receipt_raw = sources["review_receipt"]
    receipt_ref = _ref(
        paths["review_receipt"],
        receipt_raw,
        str(receipt.get("receipt_sha256", "")),
    )
    frozen_ref = _ref(
        paths["frozen_review"],
        frozen_raw,
        str(frozen.get("frozen_review_sha256", "")),
    )
    if not (
        gate.get("passed") is True
        and gate.get("failure_reasons") == []
        and gate.get("state") == PROMOTION_STATE
        and gate.get("signature_valid") is True
        and gate.get("review_receipt") == receipt_ref
        and gate.get("frozen_review") == frozen_ref
        and gate.get("report_sha256")
        == canonical_sha256(
            {key: item for key, item in gate.items() if key != "report_sha256"}
        )
        and frozen.get("status") == "operator_reviewed_frozen"
        and frozen.get("frozen_review_sha256")
        == canonical_sha256(
            {key: item for key, item in frozen.items() if key != "frozen_review_sha256"}
        )
        and frozen.get("operator_review", {}).get("review_receipt") == receipt_ref
        and frozen.get("readiness", {}).get("participant_consent_extension_count") == 0
        and frozen.get("readiness", {}).get(
            "participant_consent_extension_required_count"
        )
        == 40
        and frozen.get("readiness", {}).get("execution_preflight_allowed") is False
    ):
        raise ValueError("confirmatory consent promotion chain invalid")
    reviewer = receipt.get("reviewer", {})
    failures = validate_signed_review_receipt(
        receipt,
        expected_request_ref=receipt.get("request", {}),
        expected_bundle_ref=receipt.get("reviewed_bundle", {}),
        expected_preflight_ref=receipt.get("owner_approval_preflight", {}),
        expected_owner_gate_ref=receipt.get("owner_authorization_gate", {}),
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
    if failures:
        raise ValueError(f"confirmatory review receipt invalid: {failures}")
    frozen_refs = frozen.get("frozen_source_copies", {})
    source_refs = frozen.get("source_materials", {})
    if set(frozen_refs) != MATERIAL_NAMES or set(source_refs) != MATERIAL_NAMES:
        raise ValueError("confirmatory frozen material inventory invalid")
    result = {}
    for name, (schema, hash_field) in MATERIAL_CONTRACTS.items():
        path = Path(frozen_refs[name]["path"])
        material, raw = _read_private(path)
        source_path = Path(source_refs[name]["path"])
        _, source_raw = _read_private(source_path)
        expected = _ref(path, raw, str(material.get(hash_field, "")))
        failures = validate_material(material, schema=schema, hash_field=hash_field)
        if not (
            not failures
            and frozen_refs[name] == expected
            and source_refs[name]["sha256"] == hashlib.sha256(source_raw).hexdigest()
            and source_refs[name]["canonical_sha256"] == material.get(hash_field)
            and source_raw == raw
        ):
            raise ValueError(f"confirmatory frozen material invalid: {name}")
        result[name] = {"value": material, "ref": expected}
    return result


def _validate_prior_consents(
    *,
    manifest: dict[str, Any],
    manifest_raw: bytes,
    manifest_path: Path,
    gate: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    manifest_ref = _raw_ref(manifest_path, manifest_raw)
    if not (
        manifest.get("schema_version")
        == "j1-qualification-outcome-sensitive-consent-manifest:v1"
        and manifest.get("status") == "signed_gate_required"
        and manifest.get("inventory", {}).get("signed_extension_count") == 40
        and manifest.get("inventory", {}).get("all_signatures_verified") is True
        and manifest.get("manifest_sha256")
        == canonical_sha256(
            {key: item for key, item in manifest.items() if key != "manifest_sha256"}
        )
        and gate.get("passed") is True
        and gate.get("failure_reasons") == []
        and gate.get("state") == PRIOR_CONSENT_GATE_STATE
        and gate.get("signed_manifest_sha256") == manifest.get("manifest_sha256")
        and gate.get("artifacts", {}).get("signed_manifest") == manifest_ref
        and gate.get("report_sha256")
        == canonical_sha256(
            {key: item for key, item in gate.items() if key != "report_sha256"}
        )
    ):
        raise ValueError("prior outcome consent Gate invalid")
    result = {}
    for descriptor in manifest.get("extensions", []):
        path = Path(descriptor["path"])
        extension, raw = _read_private(path)
        failures = validate_consent_extension(extension)
        participant_id = descriptor.get("participant_id")
        if not (
            not failures
            and descriptor.get("sha256") == hashlib.sha256(raw).hexdigest()
            and descriptor.get("canonical_sha256") == extension.get("extension_sha256")
            and participant_id == extension.get("participant", {}).get("participant_id")
            and participant_id not in result
        ):
            raise ValueError("prior outcome consent extension invalid")
        result[str(participant_id)] = {
            "value": extension,
            "ref": _ref(path, raw, extension["extension_sha256"]),
        }
    if len(result) != 40:
        raise ValueError("prior outcome consent set incomplete")
    return result


def _validate_assignment(
    *,
    assignment: dict[str, Any],
    assignment_raw: bytes,
    assignment_path: Path,
    gate: dict[str, Any],
    prior_consents: dict[str, dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    assignment_ref = _ref(
        assignment_path,
        assignment_raw,
        str(assignment.get("reviewed_rebound_assignment_sha256", "")),
    )
    if not (
        assignment.get("status") == "operator_reviewed"
        and assignment.get("reviewed_rebound_assignment_sha256")
        == canonical_sha256(
            {
                key: item
                for key, item in assignment.items()
                if key != "reviewed_rebound_assignment_sha256"
            }
        )
        and len(assignment.get("assignments", [])) == 20
        and gate.get("passed") is True
        and gate.get("failure_reasons") == []
        and gate.get("state") == ASSIGNMENT_GATE_STATE
        and gate.get("reviewed_artifacts", {}).get("rebound_assignment")
        == assignment_ref
        and gate.get("report_sha256")
        == canonical_sha256(
            {key: item for key, item in gate.items() if key != "report_sha256"}
        )
    ):
        raise ValueError("reviewed outcome assignment invalid")
    result = {}
    for pair in assignment["assignments"]:
        for cohort in ("mentor", "control"):
            participant = pair[cohort]
            participant_id = participant["participant_id"]
            prior = prior_consents.get(participant_id, {}).get("value", {})
            if not (
                participant.get("cohort") == cohort
                and participant.get("execution_did")
                == prior.get("participant", {}).get("execution_did")
                and participant.get("outcome_sensitive_consent_sha256")
                == prior.get("extension_sha256")
                and participant_id not in result
            ):
                raise ValueError("assignment prior-consent binding invalid")
            result[participant_id] = {
                "participant_id": participant_id,
                "execution_did": participant["execution_did"],
                "pair_id": pair["pair_id"],
                "cohort": cohort,
                "assignment_commitment_sha256": pair["rebind_commitment_sha256"],
            }
    if len(result) != 40:
        raise ValueError("reviewed outcome assignment participant set invalid")
    return result


def _target(
    *,
    profile: dict[str, Any],
    assignment: dict[str, Any],
    prior: dict[str, Any],
) -> dict[str, Any]:
    value = profile["value"]
    prior_ref = prior["ref"]
    return {
        **assignment,
        "participant_profile_artifact_sha256": profile["artifact_sha256"],
        "participant_profile_sha256": value["profile_sha256"],
        "prior_outcome_consent_artifact_sha256": prior_ref["sha256"],
        "prior_outcome_consent_sha256": prior_ref["canonical_sha256"],
    }


def _implementation(root: Path) -> dict[str, str]:
    repository = root.resolve()
    if _git(repository, "status", "--porcelain"):
        raise ValueError("repository must be clean before consent preflight")
    revision = _git(repository, "rev-parse", "HEAD")
    if revision != _git(repository, "rev-parse", "@{upstream}"):
        raise ValueError("confirmatory consent preflight revision must be pushed")
    return {
        "source_revision": revision,
        "domain_source_sha256": hashlib.sha256(DOMAIN_SOURCE.read_bytes()).hexdigest(),
        "preflight_source_sha256": hashlib.sha256(
            OPERATION_SOURCE.read_bytes()
        ).hexdigest(),
    }


def _read_private(path: Path) -> tuple[dict[str, Any], bytes]:
    resolved = path.resolve()
    if path.is_symlink() or not resolved.is_file() or resolved.stat().st_mode & 0o077:
        raise ValueError(f"private artifact invalid: {resolved}")
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


def _git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args],
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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan-id", required=True)
    parser.add_argument("--created-at")
    parser.add_argument("--promotion-gate", type=Path, required=True)
    parser.add_argument("--frozen-review", type=Path, required=True)
    parser.add_argument("--review-receipt", type=Path, required=True)
    parser.add_argument("--reviewed-assignment", type=Path, required=True)
    parser.add_argument("--assignment-gate", type=Path, required=True)
    parser.add_argument("--participant-provisioning-report", type=Path, required=True)
    parser.add_argument("--participant-profiles-root", type=Path, required=True)
    parser.add_argument("--prior-outcome-consent-manifest", type=Path, required=True)
    parser.add_argument("--prior-outcome-consent-gate", type=Path, required=True)
    parser.add_argument(
        "--repository-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
    )
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    report = prepare_plan(
        plan_id=args.plan_id,
        created_at=args.created_at or datetime.now(UTC).isoformat(),
        promotion_gate_path=args.promotion_gate,
        frozen_review_path=args.frozen_review,
        review_receipt_path=args.review_receipt,
        reviewed_assignment_path=args.reviewed_assignment,
        assignment_gate_path=args.assignment_gate,
        participant_provisioning_report_path=args.participant_provisioning_report,
        participant_profiles_root=args.participant_profiles_root,
        prior_outcome_consent_manifest_path=args.prior_outcome_consent_manifest,
        prior_outcome_consent_gate_path=args.prior_outcome_consent_gate,
        repository_root=args.repository_root,
        output_root=args.output_root,
    )
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
