"""Sign exactly 160 owner-authorized J1-D treatment advice candidates."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pkcs11
from civitasos import CivitasError, Pkcs11Ed25519Signer

from benchmarks.j1.controlled_comparison import canonical_sha256, write_private_json
from benchmarks.j1.qualification_mentor_identity import (
    validate_mentor_identity_profile,
)
from benchmarks.j1.qualification_treatment_advice import (
    SIGNED_MANIFEST_SCHEMA,
    build_signed_advice,
    validate_signed_advice,
)
from benchmarks.j1_qualification_reviewer_identity import inspect_token_pin_state
from benchmarks.j1_qualification_mentor_identity_preflight import (
    validate_mentor_identity_plan,
)
from benchmarks.j1_qualification_treatment_advice import (
    _validate_batch_members,
    _validate_manifest,
    _validate_sources,
    approval_statement,
)
from scripts.pkcs11_identity_probe import DEFAULT_MODULE, read_pin


REPORT_SCHEMA = "j1-qualification-treatment-advice-signing-operation:v1"
CONTRACT_SOURCE = Path(__file__).parent / "j1" / "qualification_treatment_advice.py"
OPERATION_SOURCE = Path(__file__)
GATE_SOURCE = Path(__file__).parent / "j1_qualification_treatment_advice_gate.py"


def sign_treatment_advice(
    *,
    signing_id: str,
    signed_at: str,
    authorization_id: str,
    authorization_statement_sha256: str,
    candidate_manifest_path: Path,
    candidate_preflight_path: Path,
    reviewed_design_path: Path,
    design_gate_path: Path,
    reviewed_assignment_path: Path,
    assignment_gate_path: Path,
    mentor_plan_path: Path,
    mentor_identity_path: Path,
    mentor_identity_gate_path: Path,
    module_path: str,
    token_label: str,
    key_label: str,
    key_id_hex: str,
    agent_revision: str,
    pin: str,
    output_root: Path,
) -> dict[str, Any]:
    if not pin:
        raise ValueError("SoftHSM user PIN is empty")
    if output_root.exists():
        raise ValueError(
            f"signed treatment advice output already exists: {output_root}"
        )
    if not _text(signing_id) or not _text(authorization_id) or not _rfc3339(signed_at):
        raise ValueError("treatment advice signing metadata invalid")
    context = _load_context(
        candidate_manifest_path=candidate_manifest_path,
        candidate_preflight_path=candidate_preflight_path,
        reviewed_design_path=reviewed_design_path,
        design_gate_path=design_gate_path,
        reviewed_assignment_path=reviewed_assignment_path,
        assignment_gate_path=assignment_gate_path,
        mentor_plan_path=mentor_plan_path,
        mentor_identity_path=mentor_identity_path,
        mentor_identity_gate_path=mentor_identity_gate_path,
    )
    manifest = context["manifest"]
    manifest_raw_sha256 = hashlib.sha256(context["manifest_raw"]).hexdigest()
    expected_statement = approval_statement(manifest, manifest_raw_sha256)
    expected_statement_sha256 = hashlib.sha256(expected_statement.encode()).hexdigest()
    preflight = context["preflight"]
    if not (
        preflight.get("approval_request", {}).get("required_exact_statement")
        == expected_statement
        and preflight.get("approval_request", {}).get("statement_sha256")
        == expected_statement_sha256
        and authorization_statement_sha256 == expected_statement_sha256
    ):
        raise ValueError("treatment advice owner authorization statement/hash mismatch")
    mentor = context["mentor"]
    _validate_pkcs11_configuration(
        mentor,
        module_path=module_path,
        token_label=token_label,
        key_label=key_label,
        key_id_hex=key_id_hex,
    )
    pin_state = inspect_token_pin_state(
        module_path=str(Path(module_path).resolve()), token_label=token_label
    )
    if not pin_state["safe_to_attempt_user_login"]:
        raise ValueError(
            f"token user PIN retry risk: {pin_state['user_pin_risk_flags']}"
        )
    implementation = _implementation(agent_revision)

    output_root.mkdir(parents=True, mode=0o700)
    output_root.chmod(0o700)
    signed_root = output_root / "signed"
    signed_root.mkdir(mode=0o700)
    try:
        descriptors: list[dict[str, str]] = []
        source_by_advice_id = {
            item["advice_id"]: item for item in manifest["candidates"]
        }
        with Pkcs11Ed25519Signer(
            str(Path(module_path).resolve()),
            token_label,
            key_label,
            mentor["mentor"]["public_key_hex"],
            pin,
            key_id=key_id_hex,
        ) as signer:
            for advice_id in sorted(source_by_advice_id):
                source = source_by_advice_id[advice_id]
                candidate, candidate_raw = _read_private(Path(source["path"]))
                signed = build_signed_advice(
                    candidate=candidate,
                    candidate_artifact_sha256=hashlib.sha256(candidate_raw).hexdigest(),
                    source_manifest_artifact_sha256=manifest_raw_sha256,
                    source_manifest_sha256=manifest["manifest_sha256"],
                    authorization_id=authorization_id,
                    authorization_statement_sha256=authorization_statement_sha256,
                    signed_at=signed_at,
                    mentor_identity=mentor,
                    signer=signer,
                )
                path = signed_root / f"{advice_id}.signed.json"
                write_private_json(path, signed)
                descriptors.append(
                    {
                        **_artifact(path),
                        "advice_id": advice_id,
                        "participant_id": signed["recipient"]["participant_id"],
                        "task_id": signed["task"]["task_id"],
                        "canonical_sha256": signed["signed_advice_sha256"],
                    }
                )
        signed_manifest = {
            "schema_version": SIGNED_MANIFEST_SCHEMA,
            "signing_id": signing_id,
            "status": "signed_non_executable_gate_required",
            "signed_at": signed_at,
            "source_binding": {
                "candidate_manifest_artifact_sha256": manifest_raw_sha256,
                "candidate_manifest_sha256": manifest["manifest_sha256"],
                "candidate_preflight_artifact_sha256": hashlib.sha256(
                    context["preflight_raw"]
                ).hexdigest(),
                "reviewed_design_sha256": manifest["source_binding"][
                    "reviewed_design_sha256"
                ],
                "reviewed_assignment_sha256": manifest["source_binding"][
                    "reviewed_assignment_sha256"
                ],
                "mentor_identity_sha256": mentor["profile_sha256"],
            },
            "authorization": {
                "authorization_id": authorization_id,
                "statement_sha256": authorization_statement_sha256,
            },
            "mentor": manifest["mentor"],
            "inventory": {
                "cohort": "mentor",
                "participant_count": 20,
                "task_count": 8,
                "signed_advice_count": len(descriptors),
                "unique_signed_advice_count": len(
                    {item["canonical_sha256"] for item in descriptors}
                ),
                "all_signatures_verified": True,
                "control_advice_count": 0,
            },
            "implementation": implementation,
            "signed_advice": descriptors,
            "execution_boundary": _execution_boundary(),
        }
        signed_manifest["manifest_sha256"] = canonical_sha256(signed_manifest)
        failures = validate_signed_manifest(
            signed_manifest,
            source_manifest=manifest,
            source_manifest_raw=context["manifest_raw"],
            source_preflight_raw=context["preflight_raw"],
            mentor_identity=mentor,
            authorization_id=authorization_id,
            authorization_statement_sha256=authorization_statement_sha256,
            implementation=implementation,
        )
        if failures:
            raise ValueError(f"signed treatment advice manifest invalid: {failures}")
        signed_manifest_path = output_root / "treatment-advice-manifest.signed.json"
        write_private_json(signed_manifest_path, signed_manifest)
        report = {
            "schema_version": REPORT_SCHEMA,
            "passed": True,
            "state": "treatment_advice_signed_gate_required",
            "signed_at": signed_at,
            "source_manifest": _artifact(candidate_manifest_path),
            "signed_manifest": {
                **_artifact(signed_manifest_path),
                "canonical_sha256": signed_manifest["manifest_sha256"],
            },
            "authorization": signed_manifest["authorization"],
            "inventory": signed_manifest["inventory"],
            "pin_recorded": False,
            "execution_boundary": signed_manifest["execution_boundary"],
        }
        write_private_json(
            output_root / "treatment-advice-signing-operation.json", report
        )
        return report
    except Exception:
        shutil.rmtree(output_root, ignore_errors=True)
        raise


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
) -> list[str]:
    manifest = value if isinstance(value, dict) else {}
    failures: list[str] = []
    expected_fields = {
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
    expected_source = {
        "candidate_manifest_artifact_sha256": hashlib.sha256(
            source_manifest_raw
        ).hexdigest(),
        "candidate_manifest_sha256": source_manifest.get("manifest_sha256"),
        "candidate_preflight_artifact_sha256": hashlib.sha256(
            source_preflight_raw
        ).hexdigest(),
        "reviewed_design_sha256": source_manifest.get("source_binding", {}).get(
            "reviewed_design_sha256"
        ),
        "reviewed_assignment_sha256": source_manifest.get("source_binding", {}).get(
            "reviewed_assignment_sha256"
        ),
        "mentor_identity_sha256": mentor_identity.get("profile_sha256"),
    }
    expected_authorization = {
        "authorization_id": authorization_id,
        "statement_sha256": authorization_statement_sha256,
    }
    expected_inventory = {
        "cohort": "mentor",
        "participant_count": 20,
        "task_count": 8,
        "signed_advice_count": 160,
        "unique_signed_advice_count": 160,
        "all_signatures_verified": True,
        "control_advice_count": 0,
    }
    descriptors = manifest.get("signed_advice")
    if not isinstance(descriptors, list):
        return ["signed_treatment_advice_manifest_artifacts_invalid"]
    sources = {
        item.get("advice_id"): item
        for item in source_manifest.get("candidates", [])
        if isinstance(item, dict)
    }
    combinations: set[tuple[str, str]] = set()
    canonical_hashes: set[str] = set()
    advice_ids: set[str] = set()
    for descriptor in descriptors:
        if not isinstance(descriptor, dict) or set(descriptor) != {
            "path",
            "sha256",
            "advice_id",
            "participant_id",
            "task_id",
            "canonical_sha256",
        }:
            failures.append("signed_treatment_advice_descriptor_invalid")
            continue
        source = sources.get(descriptor["advice_id"])
        if source is None:
            failures.append("signed_treatment_advice_source_missing")
            continue
        try:
            candidate, candidate_raw = _read_private(Path(source["path"]))
            signed, signed_raw = _read_private(Path(descriptor["path"]))
        except (OSError, ValueError, KeyError, json.JSONDecodeError):
            failures.append("signed_treatment_advice_artifact_unreadable")
            continue
        if not (
            source.get("sha256") == hashlib.sha256(candidate_raw).hexdigest()
            and source.get("canonical_sha256") == candidate.get("candidate_sha256")
            and source.get("participant_id")
            == candidate.get("recipient", {}).get("participant_id")
            and source.get("task_id") == candidate.get("task", {}).get("task_id")
        ):
            failures.append("signed_treatment_advice_source_descriptor_invalid")
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
            and descriptor["participant_id"]
            == signed.get("recipient", {}).get("participant_id")
            and descriptor["task_id"] == signed.get("task", {}).get("task_id")
            and Path(descriptor["path"]).name
            == f"{descriptor['advice_id']}.signed.json"
        ):
            failures.append("signed_treatment_advice_descriptor_binding_invalid")
        advice_ids.add(descriptor["advice_id"])
        canonical_hashes.add(descriptor["canonical_sha256"])
        combinations.add((descriptor["participant_id"], descriptor["task_id"]))
    expected_combinations = {
        (item["participant_id"], item["task_id"])
        for item in source_manifest.get("candidates", [])
    }
    body = {key: item for key, item in manifest.items() if key != "manifest_sha256"}
    if not (
        set(manifest) == expected_fields
        and manifest.get("schema_version") == SIGNED_MANIFEST_SCHEMA
        and _text(manifest.get("signing_id"))
        and manifest.get("status") == "signed_non_executable_gate_required"
        and _rfc3339(manifest.get("signed_at"))
        and manifest.get("source_binding") == expected_source
        and manifest.get("authorization") == expected_authorization
        and manifest.get("mentor") == source_manifest.get("mentor")
        and manifest.get("inventory") == expected_inventory
        and manifest.get("implementation") == implementation
        and manifest.get("execution_boundary") == _execution_boundary()
        and len(descriptors) == 160
        and len(advice_ids) == 160
        and len(canonical_hashes) == 160
        and combinations == expected_combinations
        and manifest.get("manifest_sha256") == canonical_sha256(body)
    ):
        failures.append("signed_treatment_advice_manifest_invalid")
    return list(dict.fromkeys(failures))


def _load_context(**paths: Any) -> dict[str, Any]:
    manifest, manifest_raw = _read_private(Path(paths["candidate_manifest_path"]))
    preflight, preflight_raw = _read_private(Path(paths["candidate_preflight_path"]))
    design, design_raw = _read_private(Path(paths["reviewed_design_path"]))
    design_gate, design_gate_raw = _read_private(Path(paths["design_gate_path"]))
    assignment, assignment_raw = _read_private(Path(paths["reviewed_assignment_path"]))
    assignment_gate, assignment_gate_raw = _read_private(
        Path(paths["assignment_gate_path"])
    )
    mentor_plan, _ = _read_private(Path(paths["mentor_plan_path"]))
    mentor, mentor_raw = _read_private(Path(paths["mentor_identity_path"]))
    mentor_gate, mentor_gate_raw = _read_private(
        Path(paths["mentor_identity_gate_path"])
    )
    _validate_sources(
        design=design,
        design_path=Path(paths["reviewed_design_path"]),
        design_raw=design_raw,
        design_gate=design_gate,
        assignment=assignment,
        assignment_path=Path(paths["reviewed_assignment_path"]),
        assignment_raw=assignment_raw,
        assignment_gate=assignment_gate,
        mentor=mentor,
        mentor_path=Path(paths["mentor_identity_path"]),
        mentor_raw=mentor_raw,
        mentor_gate=mentor_gate,
    )
    mentor_failures = validate_mentor_identity_plan(mentor_plan)
    mentor_failures.extend(validate_mentor_identity_profile(mentor, plan=mentor_plan))
    if mentor_failures:
        raise ValueError(f"mentor identity invalid: {mentor_failures}")
    assignments = sorted(assignment["assignments"], key=lambda item: item["pair_id"])
    tasks = sorted(design["treatment"]["tasks"], key=lambda item: item["task_id"])
    _validate_batch_members(assignments, tasks)
    _validate_manifest(
        manifest,
        batch_id=manifest["batch_id"],
        created_at=manifest["created_at"],
        design=design,
        design_raw=design_raw,
        design_gate_raw=design_gate_raw,
        assignment=assignment,
        assignment_raw=assignment_raw,
        assignment_gate_raw=assignment_gate_raw,
        mentor=mentor,
        mentor_raw=mentor_raw,
        mentor_gate_raw=mentor_gate_raw,
        implementation=manifest["implementation"],
        assignments=assignments,
        tasks=tasks,
    )
    expected_manifest = {
        "path": str(Path(paths["candidate_manifest_path"]).resolve()),
        "sha256": hashlib.sha256(manifest_raw).hexdigest(),
        "canonical_sha256": manifest["manifest_sha256"],
    }
    if not (
        preflight.get("passed") is True
        and preflight.get("state")
        == "treatment_advice_prepared_explicit_owner_signing_authorization_required"
        and preflight.get("manifest") == expected_manifest
        and preflight.get("inventory") == manifest.get("inventory")
        and preflight.get("execution_boundary") == manifest.get("execution_boundary")
    ):
        raise ValueError("treatment advice candidate preflight drift")
    return {
        "manifest": manifest,
        "manifest_raw": manifest_raw,
        "preflight": preflight,
        "preflight_raw": preflight_raw,
        "mentor": mentor,
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


def _implementation(agent_revision: str) -> dict[str, str]:
    repository = OPERATION_SOURCE.parent.parent
    revision = agent_revision.lower()
    head = subprocess.run(
        ["git", "-C", str(repository), "rev-parse", "HEAD"],
        check=False,
        capture_output=True,
        text=True,
    )
    status = subprocess.run(
        ["git", "-C", str(repository), "status", "--porcelain"],
        check=False,
        capture_output=True,
        text=True,
    )
    if head.returncode or head.stdout.strip().lower() != revision:
        raise ValueError("treatment advice signing revision is not checked out")
    if status.returncode or status.stdout.strip():
        raise ValueError("treatment advice signing worktree must be clean")
    return {
        "agent_revision": revision,
        "contract_source_sha256": hashlib.sha256(
            CONTRACT_SOURCE.read_bytes()
        ).hexdigest(),
        "operation_source_sha256": hashlib.sha256(
            OPERATION_SOURCE.read_bytes()
        ).hexdigest(),
        "gate_source_sha256": hashlib.sha256(GATE_SOURCE.read_bytes()).hexdigest(),
    }


def _execution_boundary() -> dict[str, bool]:
    return {
        "treatment_advice_signature_only": True,
        "pin_recorded": False,
        "token_login_performed": True,
        "runtime_projection_performed": False,
        "provider_api_call_performed": False,
        "model_invocation_performed": False,
        "agent_execution_performed": False,
        "backend_fact_append_performed": False,
        "ledger_append_performed": False,
    }


def _read_private(path: Path) -> tuple[dict[str, Any], bytes]:
    if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o077:
        raise ValueError(f"private JSON artifact invalid: {path}")
    raw = path.read_bytes()
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError(f"JSON artifact must be object: {path}")
    return value, raw


def _artifact(path: Path) -> dict[str, str]:
    return {
        "path": str(path.resolve()),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _rfc3339(value: Any) -> bool:
    if not _text(value):
        return False
    try:
        return (
            datetime.fromisoformat(str(value).replace("Z", "+00:00")).tzinfo is not None
        )
    except ValueError:
        return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--signing-id", required=True)
    parser.add_argument("--authorization-id", required=True)
    parser.add_argument("--authorization-statement-sha256", required=True)
    parser.add_argument("--candidate-manifest", type=Path, required=True)
    parser.add_argument("--candidate-preflight", type=Path, required=True)
    parser.add_argument("--reviewed-design", type=Path, required=True)
    parser.add_argument("--design-gate", type=Path, required=True)
    parser.add_argument("--reviewed-assignment", type=Path, required=True)
    parser.add_argument("--assignment-gate", type=Path, required=True)
    parser.add_argument("--mentor-plan", type=Path, required=True)
    parser.add_argument("--mentor-identity", type=Path, required=True)
    parser.add_argument("--mentor-identity-gate", type=Path, required=True)
    parser.add_argument("--module", default=DEFAULT_MODULE)
    parser.add_argument("--token-label", required=True)
    parser.add_argument("--key-label", required=True)
    parser.add_argument("--key-id", required=True)
    parser.add_argument("--agent-revision", required=True)
    parser.add_argument("--pin-file", type=Path)
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    pin = ""
    try:
        pin = read_pin(args.pin_file)
        report = sign_treatment_advice(
            signing_id=args.signing_id,
            signed_at=datetime.now(timezone.utc).isoformat(),
            authorization_id=args.authorization_id,
            authorization_statement_sha256=args.authorization_statement_sha256,
            candidate_manifest_path=args.candidate_manifest,
            candidate_preflight_path=args.candidate_preflight,
            reviewed_design_path=args.reviewed_design,
            design_gate_path=args.design_gate,
            reviewed_assignment_path=args.reviewed_assignment,
            assignment_gate_path=args.assignment_gate,
            mentor_plan_path=args.mentor_plan,
            mentor_identity_path=args.mentor_identity,
            mentor_identity_gate_path=args.mentor_identity_gate,
            module_path=args.module,
            token_label=args.token_label,
            key_label=args.key_label,
            key_id_hex=args.key_id,
            agent_revision=args.agent_revision,
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
            "state": "blocked_treatment_advice_signing",
            "error_class": type(error).__name__,
            "error": str(error),
            "pin_recorded": False,
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
