"""Sign exactly 180 authorized outcome-sensitive J1-D advice candidates."""

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

import pkcs11
from civitasos import CivitasError, Pkcs11Ed25519Signer

from benchmarks.j1.controlled_comparison import (
    canonical_sha256,
    write_private_json,
)
from benchmarks.j1.qualification_mentor_identity import (
    validate_mentor_identity_profile,
)
from benchmarks.j1.qualification_outcome_sensitive_treatment_advice import (
    SIGNED_MANIFEST_SCHEMA,
    TREATMENT_ORDINALS,
    authorization_statement,
    build_signed_advice,
    validate_signed_advice,
)
from benchmarks.j1_qualification_mentor_identity_preflight import (
    validate_mentor_identity_plan,
)
from benchmarks.j1_qualification_outcome_sensitive_treatment_advice import (
    _read_private,
    _validate_batch_members,
    _validate_manifest,
    _validate_sources,
)
from benchmarks.j1_qualification_reviewer_identity import (
    inspect_token_pin_state,
)
from scripts.pkcs11_identity_probe import DEFAULT_MODULE, read_pin


REPORT_SCHEMA = (
    "j1-qualification-outcome-sensitive-treatment-advice-signing-operation:v1"
)
DOMAIN_SOURCE = (
    Path(__file__).parent / "j1" / "qualification_outcome_sensitive_treatment_advice.py"
)
OPERATION_SOURCE = Path(__file__)
GATE_SOURCE = (
    Path(__file__).parent
    / "j1_qualification_outcome_sensitive_treatment_advice_gate.py"
)


def sign_treatment_advice(
    *,
    signing_id: str,
    signed_at: str,
    authorization_id: str,
    authorization_statement_sha256: str,
    candidate_manifest_path: Path,
    candidate_preflight_path: Path,
    protocol_path: Path,
    task_fixture_path: Path,
    reviewed_assignment_path: Path,
    assignment_gate_path: Path,
    mentor_plan_path: Path,
    mentor_identity_path: Path,
    mentor_identity_gate_path: Path,
    module_path: str,
    token_label: str,
    key_label: str,
    key_id_hex: str,
    repository_root: Path,
    pin: str,
    output_root: Path,
) -> dict[str, Any]:
    if not pin:
        raise ValueError("SoftHSM user PIN is empty")
    if output_root.exists():
        raise FileExistsError(f"outcome advice signing output exists: {output_root}")
    if (
        not signing_id.strip()
        or not authorization_id.strip()
        or not _rfc3339(signed_at)
    ):
        raise ValueError("outcome advice signing metadata invalid")
    context = _load_context(
        candidate_manifest_path=candidate_manifest_path,
        candidate_preflight_path=candidate_preflight_path,
        protocol_path=protocol_path,
        task_fixture_path=task_fixture_path,
        reviewed_assignment_path=reviewed_assignment_path,
        assignment_gate_path=assignment_gate_path,
        mentor_plan_path=mentor_plan_path,
        mentor_identity_path=mentor_identity_path,
        mentor_identity_gate_path=mentor_identity_gate_path,
    )
    manifest = context["manifest"]
    manifest_raw = context["manifest_raw"]
    manifest_raw_sha256 = hashlib.sha256(manifest_raw).hexdigest()
    expected_statement = authorization_statement(manifest, manifest_raw_sha256)
    expected_statement_sha256 = hashlib.sha256(expected_statement.encode()).hexdigest()
    if authorization_statement_sha256 != expected_statement_sha256:
        raise ValueError("outcome advice authorization statement mismatch")
    _validate_pkcs11_configuration(
        context["mentor"],
        module_path=module_path,
        token_label=token_label,
        key_label=key_label,
        key_id_hex=key_id_hex,
    )
    pin_state = inspect_token_pin_state(
        module_path=str(Path(module_path).resolve()),
        token_label=token_label,
    )
    if not pin_state["safe_to_attempt_user_login"]:
        raise ValueError(
            f"token user PIN retry risk: {pin_state['user_pin_risk_flags']}"
        )
    implementation = _implementation(repository_root)
    parent = output_root.resolve().parent
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    parent.chmod(0o700)
    staging = Path(tempfile.mkdtemp(prefix=f".{output_root.name}.", dir=parent))
    staging.chmod(0o700)
    signed_root = staging / "signed"
    signed_root.mkdir(mode=0o700)
    try:
        descriptors: list[dict[str, Any]] = []
        candidates = {item["advice_id"]: item for item in manifest["candidates"]}
        with Pkcs11Ed25519Signer(
            str(Path(module_path).resolve()),
            token_label,
            key_label,
            context["mentor"]["mentor"]["public_key_hex"],
            pin,
            key_id=key_id_hex,
        ) as signer:
            for advice_id in sorted(candidates):
                source = candidates[advice_id]
                candidate_path = Path(source["path"])
                candidate, candidate_raw = _read_private(candidate_path)
                signed = build_signed_advice(
                    candidate=candidate,
                    candidate_artifact_sha256=hashlib.sha256(candidate_raw).hexdigest(),
                    source_manifest_artifact_sha256=manifest_raw_sha256,
                    source_manifest_sha256=manifest["manifest_sha256"],
                    authorization_id=authorization_id,
                    authorization_statement_sha256=expected_statement_sha256,
                    signed_at=signed_at,
                    mentor_identity=context["mentor"],
                    signer=signer,
                )
                path = signed_root / f"{advice_id}.signed.json"
                write_private_json(path, signed)
                descriptors.append(
                    {
                        "path": str(
                            (
                                output_root / "signed" / f"{advice_id}.signed.json"
                            ).resolve()
                        ),
                        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                        "advice_id": advice_id,
                        "pair_id": signed["recipient"]["pair_id"],
                        "participant_id": signed["recipient"]["participant_id"],
                        "task_id": signed["task"]["task_id"],
                        "task_ordinal": signed["task"]["task_ordinal"],
                        "phase": signed["task"]["phase"],
                        "canonical_sha256": signed["signed_advice_sha256"],
                    }
                )
        signed_manifest = _build_signed_manifest(
            signing_id=signing_id,
            signed_at=signed_at,
            authorization_id=authorization_id,
            authorization_statement_sha256=expected_statement_sha256,
            source_manifest=manifest,
            source_manifest_raw=manifest_raw,
            source_preflight_raw=context["preflight_raw"],
            mentor_identity=context["mentor"],
            implementation=implementation,
            descriptors=descriptors,
        )
        failures = validate_signed_manifest(
            signed_manifest,
            source_manifest=manifest,
            source_manifest_raw=manifest_raw,
            source_preflight_raw=context["preflight_raw"],
            mentor_identity=context["mentor"],
            authorization_id=authorization_id,
            authorization_statement_sha256=expected_statement_sha256,
            implementation=implementation,
            signed_root=signed_root,
        )
        if failures:
            raise ValueError(f"outcome advice signed manifest invalid: {failures}")
        manifest_name = "outcome-sensitive-treatment-advice-manifest.signed.json"
        signed_manifest_path = staging / manifest_name
        write_private_json(signed_manifest_path, signed_manifest)
        operation = {
            "schema_version": REPORT_SCHEMA,
            "passed": True,
            "failure_reasons": [],
            "state": "outcome_sensitive_mentor_advice_signed_gate_required",
            "signed_at": signed_at,
            "source_manifest": _artifact(candidate_manifest_path),
            "signed_manifest": {
                **_published_artifact(
                    signed_manifest_path, output_root / manifest_name
                ),
                "canonical_sha256": signed_manifest["manifest_sha256"],
            },
            "authorization": signed_manifest["authorization"],
            "inventory": signed_manifest["inventory"],
            "implementation": implementation,
            "pkcs11_session_count": 1,
            "pin_recorded": False,
            "private_key_exported": False,
            "readiness": {
                "mentor_signatures_complete": True,
                "signature_verification_gate_passed": False,
                "infrastructure_rebound": False,
                "controlled_experiment_execution_ready": False,
            },
            "execution_boundary": signed_manifest["execution_boundary"],
        }
        operation["report_sha256"] = canonical_sha256(operation)
        write_private_json(
            staging / "outcome-sensitive-treatment-advice-signing-operation.json",
            operation,
        )
        os.rename(staging, output_root)
        _fsync_directory(parent)
        return operation
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def _build_signed_manifest(
    *,
    signing_id: str,
    signed_at: str,
    authorization_id: str,
    authorization_statement_sha256: str,
    source_manifest: dict[str, Any],
    source_manifest_raw: bytes,
    source_preflight_raw: bytes,
    mentor_identity: dict[str, Any],
    implementation: dict[str, str],
    descriptors: list[dict[str, Any]],
) -> dict[str, Any]:
    value = {
        "schema_version": SIGNED_MANIFEST_SCHEMA,
        "signing_id": signing_id,
        "status": "signed_non_executable_gate_required",
        "signed_at": signed_at,
        "source_binding": {
            "candidate_manifest_artifact_sha256": hashlib.sha256(
                source_manifest_raw
            ).hexdigest(),
            "candidate_manifest_sha256": source_manifest["manifest_sha256"],
            "candidate_preflight_artifact_sha256": hashlib.sha256(
                source_preflight_raw
            ).hexdigest(),
            "protocol_sha256": source_manifest["source_binding"]["protocol"][
                "canonical_sha256"
            ],
            "task_fixture_sha256": source_manifest["source_binding"]["task_fixture"][
                "canonical_sha256"
            ],
            "reviewed_assignment_sha256": source_manifest["source_binding"][
                "reviewed_assignment"
            ]["canonical_sha256"],
            "mentor_identity_sha256": mentor_identity["profile_sha256"],
        },
        "authorization": {
            "authorization_id": authorization_id,
            "statement_sha256": authorization_statement_sha256,
        },
        "mentor": source_manifest["mentor"],
        "inventory": {
            "cohort": "mentor",
            "participant_count": 20,
            "treatment_task_count": 9,
            "signed_advice_count": len(descriptors),
            "unique_signed_advice_count": len(
                {item["canonical_sha256"] for item in descriptors}
            ),
            "baseline_advice_count": 0,
            "control_advice_count": 0,
            "phase_template_count": 3,
            "prompt_copy_count": 0,
            "ground_truth_copy_count": 0,
            "action_or_pattern_identifier_copy_count": 0,
            "all_signatures_verified": True,
        },
        "implementation": implementation,
        "signed_advice": descriptors,
        "execution_boundary": _execution_boundary(),
    }
    value["manifest_sha256"] = canonical_sha256(value)
    return value


def validate_signed_manifest(
    value: Any,
    *,
    source_manifest: dict[str, Any],
    source_manifest_raw: bytes,
    source_preflight_raw: bytes,
    mentor_identity: dict[str, Any],
    authorization_id: str,
    authorization_statement_sha256: str,
    implementation: dict[str, str],
    signed_root: Path | None = None,
) -> list[str]:
    manifest = value if isinstance(value, dict) else {}
    failures: list[str] = []
    descriptors = manifest.get("signed_advice", [])
    if not isinstance(descriptors, list):
        return ["signed_outcome_advice_descriptors_invalid"]
    sources = {
        item["advice_id"]: item for item in source_manifest.get("candidates", [])
    }
    combinations: set[tuple[str, str]] = set()
    advice_ids: set[str] = set()
    canonical_hashes: set[str] = set()
    phases: set[str] = set()
    for descriptor in descriptors:
        if not isinstance(descriptor, dict) or set(descriptor) != {
            "path",
            "sha256",
            "advice_id",
            "pair_id",
            "participant_id",
            "task_id",
            "task_ordinal",
            "phase",
            "canonical_sha256",
        }:
            failures.append("signed_outcome_advice_descriptor_invalid")
            continue
        source = sources.get(descriptor["advice_id"])
        if source is None:
            failures.append("signed_outcome_advice_source_missing")
            continue
        signed_path = (
            signed_root / Path(descriptor["path"]).name
            if signed_root is not None
            else Path(descriptor["path"])
        )
        try:
            candidate, candidate_raw = _read_private(Path(source["path"]))
            signed, signed_raw = _read_private(signed_path)
        except (OSError, ValueError, KeyError, json.JSONDecodeError):
            failures.append("signed_outcome_advice_artifact_unreadable")
            continue
        failures.extend(
            validate_signed_advice(
                signed,
                candidate=candidate,
                candidate_artifact_sha256=hashlib.sha256(candidate_raw).hexdigest(),
                source_manifest_artifact_sha256=hashlib.sha256(
                    source_manifest_raw
                ).hexdigest(),
                source_manifest_sha256=source_manifest["manifest_sha256"],
                authorization_id=authorization_id,
                authorization_statement_sha256=authorization_statement_sha256,
                mentor_identity=mentor_identity,
            )
        )
        if not (
            descriptor["sha256"] == hashlib.sha256(signed_raw).hexdigest()
            and descriptor["canonical_sha256"] == signed.get("signed_advice_sha256")
            and descriptor["pair_id"] == signed.get("recipient", {}).get("pair_id")
            and descriptor["participant_id"]
            == signed.get("recipient", {}).get("participant_id")
            and descriptor["task_id"] == signed.get("task", {}).get("task_id")
            and descriptor["task_ordinal"] == signed.get("task", {}).get("task_ordinal")
            and descriptor["phase"] == signed.get("task", {}).get("phase")
            and Path(descriptor["path"]).name
            == f"{descriptor['advice_id']}.signed.json"
        ):
            failures.append("signed_outcome_advice_descriptor_binding_invalid")
        advice_ids.add(descriptor["advice_id"])
        canonical_hashes.add(descriptor["canonical_sha256"])
        combinations.add((descriptor["participant_id"], descriptor["task_id"]))
        phases.add(descriptor["phase"])
    expected_combinations = {
        (item["participant_id"], item["task_id"])
        for item in source_manifest.get("candidates", [])
    }
    expected_source = {
        "candidate_manifest_artifact_sha256": hashlib.sha256(
            source_manifest_raw
        ).hexdigest(),
        "candidate_manifest_sha256": source_manifest.get("manifest_sha256"),
        "candidate_preflight_artifact_sha256": hashlib.sha256(
            source_preflight_raw
        ).hexdigest(),
        "protocol_sha256": source_manifest["source_binding"]["protocol"][
            "canonical_sha256"
        ],
        "task_fixture_sha256": source_manifest["source_binding"]["task_fixture"][
            "canonical_sha256"
        ],
        "reviewed_assignment_sha256": source_manifest["source_binding"][
            "reviewed_assignment"
        ]["canonical_sha256"],
        "mentor_identity_sha256": mentor_identity.get("profile_sha256"),
    }
    expected_inventory = {
        "cohort": "mentor",
        "participant_count": 20,
        "treatment_task_count": 9,
        "signed_advice_count": 180,
        "unique_signed_advice_count": 180,
        "baseline_advice_count": 0,
        "control_advice_count": 0,
        "phase_template_count": 3,
        "prompt_copy_count": 0,
        "ground_truth_copy_count": 0,
        "action_or_pattern_identifier_copy_count": 0,
        "all_signatures_verified": True,
    }
    body = {key: item for key, item in manifest.items() if key != "manifest_sha256"}
    if not (
        set(manifest)
        == {
            "schema_version",
            "signing_id",
            "status",
            "signed_at",
            "source_binding",
            "authorization",
            "mentor",
            "inventory",
            "implementation",
            "signed_advice",
            "execution_boundary",
            "manifest_sha256",
        }
        and manifest.get("schema_version") == SIGNED_MANIFEST_SCHEMA
        and isinstance(manifest.get("signing_id"), str)
        and bool(manifest["signing_id"].strip())
        and manifest.get("status") == "signed_non_executable_gate_required"
        and _rfc3339(manifest.get("signed_at"))
        and manifest.get("source_binding") == expected_source
        and manifest.get("authorization")
        == {
            "authorization_id": authorization_id,
            "statement_sha256": authorization_statement_sha256,
        }
        and manifest.get("mentor") == source_manifest.get("mentor")
        and manifest.get("inventory") == expected_inventory
        and manifest.get("implementation") == implementation
        and manifest.get("execution_boundary") == _execution_boundary()
        and len(descriptors) == 180
        and len(advice_ids) == 180
        and len(canonical_hashes) == 180
        and combinations == expected_combinations
        and phases == {"near_transfer", "heldout_transfer", "false_positive_sentinels"}
        and manifest.get("manifest_sha256") == canonical_sha256(body)
    ):
        failures.append("signed_outcome_advice_manifest_invalid")
    return list(dict.fromkeys(failures))


def _load_context(**paths: Any) -> dict[str, Any]:
    manifest, manifest_raw = _read_private(Path(paths["candidate_manifest_path"]))
    preflight, preflight_raw = _read_private(Path(paths["candidate_preflight_path"]))
    source_paths = {
        "protocol": Path(paths["protocol_path"]),
        "task_fixture": Path(paths["task_fixture_path"]),
        "reviewed_assignment": Path(paths["reviewed_assignment_path"]),
        "assignment_gate": Path(paths["assignment_gate_path"]),
        "mentor_identity": Path(paths["mentor_identity_path"]),
        "mentor_identity_gate": Path(paths["mentor_identity_gate_path"]),
    }
    sources = {name: _read_private(path) for name, path in source_paths.items()}
    _validate_sources(paths=source_paths, sources=sources)
    values = {name: value for name, (value, _) in sources.items()}
    mentor_plan, _ = _read_private(Path(paths["mentor_plan_path"]))
    mentor_failures = validate_mentor_identity_plan(mentor_plan)
    mentor_failures.extend(
        validate_mentor_identity_profile(values["mentor_identity"], plan=mentor_plan)
    )
    if mentor_failures:
        raise ValueError(f"mentor identity invalid: {mentor_failures}")
    assignments = sorted(
        values["reviewed_assignment"]["assignments"],
        key=lambda item: item["pair_id"],
    )
    tasks = sorted(
        (
            task
            for task in values["task_fixture"]["fixtures"]
            if task["task_ordinal"] in TREATMENT_ORDINALS
        ),
        key=lambda item: item["task_ordinal"],
    )
    _validate_batch_members(assignments, tasks)
    _validate_manifest(
        manifest,
        batch_id=manifest["batch_id"],
        created_at=manifest["created_at"],
        source_binding=manifest["source_binding"],
        mentor=values["mentor_identity"],
        assignments=assignments,
        tasks=tasks,
        implementation=manifest["implementation"],
        candidate_root=Path(paths["candidate_manifest_path"]).parent / "candidates",
    )
    expected_statement = authorization_statement(
        manifest, hashlib.sha256(manifest_raw).hexdigest()
    )
    preflight_body = {
        key: item for key, item in preflight.items() if key != "report_sha256"
    }
    if not (
        preflight.get("passed") is True
        and preflight.get("report_sha256") == canonical_sha256(preflight_body)
        and preflight.get("manifest")
        == {
            "path": str(Path(paths["candidate_manifest_path"]).resolve()),
            "sha256": hashlib.sha256(manifest_raw).hexdigest(),
            "canonical_sha256": manifest["manifest_sha256"],
        }
        and preflight.get("inventory") == manifest["inventory"]
        and preflight.get("authorization_request", {}).get("required_exact_statement")
        == expected_statement
        and preflight.get("authorization_request", {}).get("statement_sha256")
        == hashlib.sha256(expected_statement.encode()).hexdigest()
        and preflight.get("authorization_request", {}).get("signature_count") == 180
        and preflight.get("authorization_request", {}).get(
            "single_pkcs11_session_required"
        )
        is True
    ):
        raise ValueError("outcome advice candidate preflight drift")
    return {
        "manifest": manifest,
        "manifest_raw": manifest_raw,
        "preflight": preflight,
        "preflight_raw": preflight_raw,
        "mentor": values["mentor_identity"],
    }


def _validate_pkcs11_configuration(
    mentor: dict[str, Any],
    *,
    module_path: str,
    token_label: str,
    key_label: str,
    key_id_hex: str,
) -> None:
    key = mentor["pkcs11_key"]
    module = str(Path(module_path).resolve())
    if not (
        key.get("module_path") == module
        and key.get("module_sha256")
        == hashlib.sha256(Path(module).read_bytes()).hexdigest()
        and key.get("token_label") == token_label
        and key.get("key_label") == key_label
        and key.get("key_id_hex") == key_id_hex.lower()
    ):
        raise ValueError("mentor PKCS#11 configuration mismatch")


def _implementation(repository_root: Path) -> dict[str, str]:
    root = repository_root.resolve()
    if _git(root, "status", "--porcelain"):
        raise ValueError("repository must be clean before outcome advice signing")
    revision = _git(root, "rev-parse", "HEAD")
    if subprocess.run(
        ["git", "merge-base", "--is-ancestor", revision, "@{upstream}"],
        cwd=root,
        check=False,
    ).returncode:
        raise ValueError("outcome advice signing revision is not pushed")
    hashes = {
        str(source.relative_to(root)): hashlib.sha256(source.read_bytes()).hexdigest()
        for source in (DOMAIN_SOURCE, OPERATION_SOURCE, GATE_SOURCE)
    }
    return {
        "source_revision": revision,
        "source_sha256": canonical_sha256(hashes),
    }


def _execution_boundary() -> dict[str, bool]:
    return {
        "outcome_sensitive_treatment_advice_signature_only": True,
        "token_login_performed": True,
        "pkcs11_session_count_one": True,
        "pin_recorded": False,
        "private_key_exported": False,
        "runtime_projection_performed": False,
        "provider_credential_read": False,
        "provider_api_call_performed": False,
        "model_invocation_performed": False,
        "agent_execution_performed": False,
        "backend_fact_append_performed": False,
        "ledger_append_performed": False,
        "execution_authorization_issued_or_consumed": False,
        "effectiveness_claim_authorized": False,
        "si13_maturity_upgrade_authorized": False,
    }


def _artifact(path: Path) -> dict[str, str]:
    return {
        "path": str(path.resolve()),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }


def _published_artifact(path: Path, published_path: Path) -> dict[str, str]:
    return {
        "path": str(published_path.resolve()),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }


def _git(root: Path, *arguments: str) -> str:
    return subprocess.check_output(["git", *arguments], cwd=root, text=True).strip()


def _rfc3339(value: Any) -> bool:
    if not isinstance(value, str) or not value.strip():
        return False
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).tzinfo is not None
    except ValueError:
        return False


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--signing-id", required=True)
    parser.add_argument("--authorization-id", required=True)
    parser.add_argument("--authorization-statement-sha256", required=True)
    parser.add_argument("--candidate-manifest", type=Path, required=True)
    parser.add_argument("--candidate-preflight", type=Path, required=True)
    parser.add_argument("--protocol", type=Path, required=True)
    parser.add_argument("--task-fixture", type=Path, required=True)
    parser.add_argument("--reviewed-assignment", type=Path, required=True)
    parser.add_argument("--assignment-gate", type=Path, required=True)
    parser.add_argument("--mentor-plan", type=Path, required=True)
    parser.add_argument("--mentor-identity", type=Path, required=True)
    parser.add_argument("--mentor-identity-gate", type=Path, required=True)
    parser.add_argument("--module", default=DEFAULT_MODULE)
    parser.add_argument("--token-label", required=True)
    parser.add_argument("--key-label", required=True)
    parser.add_argument("--key-id", required=True)
    parser.add_argument(
        "--repository-root", type=Path, default=Path(__file__).parents[1]
    )
    parser.add_argument("--pin-file", type=Path)
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    pin = ""
    try:
        pin = read_pin(args.pin_file)
        report = sign_treatment_advice(
            signing_id=args.signing_id,
            signed_at=datetime.now(timezone.utc).astimezone().isoformat(),
            authorization_id=args.authorization_id,
            authorization_statement_sha256=args.authorization_statement_sha256,
            candidate_manifest_path=args.candidate_manifest,
            candidate_preflight_path=args.candidate_preflight,
            protocol_path=args.protocol,
            task_fixture_path=args.task_fixture,
            reviewed_assignment_path=args.reviewed_assignment,
            assignment_gate_path=args.assignment_gate,
            mentor_plan_path=args.mentor_plan,
            mentor_identity_path=args.mentor_identity,
            mentor_identity_gate_path=args.mentor_identity_gate,
            module_path=args.module,
            token_label=args.token_label,
            key_label=args.key_label,
            key_id_hex=args.key_id,
            repository_root=args.repository_root,
            pin=pin,
            output_root=args.output_root,
        )
    except (
        OSError,
        ValueError,
        RuntimeError,
        CivitasError,
        KeyError,
        json.JSONDecodeError,
        pkcs11.PKCS11Error,
    ) as error:
        report = {
            "schema_version": REPORT_SCHEMA,
            "passed": False,
            "state": "blocked_outcome_sensitive_treatment_advice_signing",
            "error_class": type(error).__name__,
            "error": str(error),
            "pin_recorded": False,
            "private_key_exported": False,
            "provider_api_call_performed": False,
            "model_invocation_performed": False,
            "agent_execution_performed": False,
            "backend_fact_append_performed": False,
            "ledger_append_performed": False,
        }
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
        return 1
    finally:
        pin = ""
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
