"""Sign exactly 40 owner-authorized confirmatory consent extensions."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import shutil
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pkcs11

from benchmarks.j1.controlled_comparison import canonical_sha256, write_private_json
from benchmarks.j1.qualification_outcome_sensitive_confirmatory_consent import (
    authorization_statement,
    build_extension,
    validate_extension,
    validate_plan,
)
from benchmarks.j1_qualification_outcome_sensitive_confirmatory_consent_preflight import (
    REPORT_SCHEMA as PREFLIGHT_SCHEMA,
    _identity_record,
    _load_profiles,
    replay_source_binding,
)
from benchmarks.j1_qualification_outcome_sensitive_consent_extension_sign import (
    _SessionSigner,
    _session_key,
    _validate_pkcs11_configuration,
)
from benchmarks.j1_qualification_reviewer_identity import inspect_token_pin_state
from scripts.pkcs11_identity_probe import DEFAULT_MODULE, read_pin


REPORT_SCHEMA = "j1-outcome-sensitive-confirmatory-consent-signing:v1"
MANIFEST_SCHEMA = "j1-outcome-sensitive-confirmatory-consent-manifest:v1"
DOMAIN_SOURCE = (
    Path(__file__).parent
    / "j1"
    / "qualification_outcome_sensitive_confirmatory_consent.py"
)
PREFLIGHT_SOURCE = (
    Path(__file__).parent
    / "j1_qualification_outcome_sensitive_confirmatory_consent_preflight.py"
)
OPERATION_SOURCE = Path(__file__)
GATE_SOURCE = (
    Path(__file__).parent
    / "j1_qualification_outcome_sensitive_confirmatory_consent_gate.py"
)
SIGNING_BOUNDARY = {
    "consent_extension_signature_only": True,
    "token_login_performed": True,
    "participant_consent_extended": True,
    "participant_signature_count": 40,
    "pin_recorded": False,
    "private_key_exported": False,
    "downstream_binding_refreshed": False,
    "provider_api_call_performed": False,
    "model_invocation_performed": False,
    "agent_or_container_execution_performed": False,
    "backend_fact_append_performed": False,
    "ledger_append_performed": False,
    "execution_authorization_issued_or_consumed": False,
    "effectiveness_or_causal_claim_authorized": False,
    "si13_maturity_upgrade_authorized": False,
}


def sign_extensions(
    *,
    signing_id: str,
    signed_at: str,
    authorization_id: str,
    authorization_statement_sha256: str,
    plan_path: Path,
    preflight_path: Path,
    participant_profiles_root: Path,
    module_path: str,
    token_label: str,
    repository_root: Path,
    pin: str,
    output_root: Path,
) -> dict[str, Any]:
    """Use one token session to publish exactly 40 participant signatures."""
    if not pin:
        raise ValueError("SoftHSM user PIN is empty")
    if output_root.exists():
        raise FileExistsError(f"confirmatory consent signing exists: {output_root}")
    plan, plan_raw = _read_private(plan_path)
    preflight, preflight_raw = _read_private(preflight_path)
    failures = validate_plan(plan)
    if failures:
        raise ValueError(f"confirmatory consent plan invalid: {failures}")
    plan_raw_sha = hashlib.sha256(plan_raw).hexdigest()
    statement = authorization_statement(plan, plan_raw_sha)
    statement_sha = hashlib.sha256(statement.encode()).hexdigest()
    _validate_preflight(
        plan=plan,
        plan_path=plan_path,
        plan_raw=plan_raw,
        preflight=preflight,
        statement=statement,
        statement_sha=statement_sha,
    )
    if authorization_statement_sha256 != statement_sha:
        raise ValueError("confirmatory consent authorization hash mismatch")
    replay_source_binding(plan)
    profiles = _load_profiles(participant_profiles_root)
    identities = [
        _identity_record(profiles[participant_id])
        for participant_id in sorted(profiles)
    ]
    if identities != plan["participant_identity_set"]:
        raise ValueError("participant profiles drift from confirmatory consent plan")
    module = Path(module_path).resolve()
    _validate_pkcs11_configuration(
        profiles=profiles,
        module=module,
        token_label=token_label,
        expected_token_label=plan["source_binding"]["token_label"],
    )
    pin_state = inspect_token_pin_state(
        module_path=str(module),
        token_label=token_label,
    )
    if not pin_state["safe_to_attempt_user_login"]:
        raise ValueError(
            f"token user PIN retry risk: {pin_state['user_pin_risk_flags']}"
        )
    implementation = _implementation(repository_root)
    targets = {item["participant_id"]: item for item in plan["consent_targets"]}
    identity_map = {
        item["participant_id"]: item for item in plan["participant_identity_set"]
    }
    preflight_raw_sha = hashlib.sha256(preflight_raw).hexdigest()
    parent = output_root.resolve().parent
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    parent.chmod(0o700)
    staging = Path(tempfile.mkdtemp(prefix=f".{output_root.name}.", dir=parent))
    staging.chmod(0o700)
    evidence_root = staging / "extensions"
    evidence_root.mkdir(mode=0o700)
    try:
        library = pkcs11.lib(str(module))
        token = library.get_token(token_label=token_label)
        descriptors = []
        with token.open(user_pin=pin) as session:
            for participant_id in sorted(profiles):
                profile = profiles[participant_id]["value"]
                participant = profile["participant"]
                private_key = _session_key(
                    session,
                    profile["pkcs11_key"],
                    participant["public_key_hex"],
                )
                extension = build_extension(
                    extension_id=f"{signing_id}:{participant_id}",
                    signed_at=signed_at,
                    target=targets[participant_id],
                    identity=identity_map[participant_id],
                    public_key_hex=participant["public_key_hex"],
                    plan=plan,
                    plan_artifact_sha256=plan_raw_sha,
                    preflight_artifact_sha256=preflight_raw_sha,
                    authorization_id=authorization_id,
                    authorization_statement_sha256=authorization_statement_sha256,
                    nonce=secrets.token_bytes(32),
                    signer=_SessionSigner(
                        private_key,
                        participant["public_key_hex"],
                    ),
                )
                filename = f"{participant_id}.confirmatory-consent-extension.json"
                path = evidence_root / filename
                write_private_json(path, extension)
                descriptors.append(
                    {
                        "path": str((output_root / "extensions" / filename).resolve()),
                        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                        "canonical_sha256": extension["extension_sha256"],
                        "participant_id": participant_id,
                        "cohort": extension["cohort_binding"]["cohort"],
                    }
                )
        manifest = _build_manifest(
            signing_id=signing_id,
            signed_at=signed_at,
            plan=plan,
            plan_raw=plan_raw,
            preflight_raw=preflight_raw,
            authorization_id=authorization_id,
            authorization_statement_sha256=authorization_statement_sha256,
            descriptors=descriptors,
            implementation=implementation,
        )
        failures = validate_manifest(
            manifest,
            plan=plan,
            plan_raw=plan_raw,
            preflight_raw=preflight_raw,
            authorization_id=authorization_id,
            authorization_statement_sha256=authorization_statement_sha256,
            implementation=implementation,
            read_root=evidence_root,
        )
        if failures:
            raise ValueError(f"confirmatory consent manifest invalid: {failures}")
        manifest_path = staging / "confirmatory-consent-manifest.signed.json"
        write_private_json(manifest_path, manifest)
        report = {
            "schema_version": REPORT_SCHEMA,
            "passed": True,
            "failure_reasons": [],
            "state": "confirmatory_consents_signed_gate_required",
            "signed_at": signed_at,
            "plan": _artifact(plan_path),
            "preflight": _artifact(preflight_path),
            "signed_manifest": {
                "path": str(
                    (
                        output_root / "confirmatory-consent-manifest.signed.json"
                    ).resolve()
                ),
                "sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
                "canonical_sha256": manifest["manifest_sha256"],
            },
            "authorization": manifest["authorization"],
            "inventory": manifest["inventory"],
            "pkcs11_boundary": {
                "module_path": str(module),
                "module_sha256": hashlib.sha256(module.read_bytes()).hexdigest(),
                "token_label": token_label,
                "single_session_login": True,
                "distinct_participant_signatures": 40,
                "pin_recorded": False,
                "private_key_exported": False,
            },
            "execution_boundary": SIGNING_BOUNDARY,
            "implementation": implementation,
        }
        report["report_sha256"] = canonical_sha256(report)
        write_private_json(
            staging / "confirmatory-consent-signing-operation.json",
            report,
        )
        os.rename(staging, output_root)
        _fsync_directory(parent)
        return report
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def validate_manifest(
    manifest: Any,
    *,
    plan: dict[str, Any],
    plan_raw: bytes,
    preflight_raw: bytes,
    authorization_id: str,
    authorization_statement_sha256: str,
    implementation: dict[str, str],
    read_root: Path | None = None,
) -> list[str]:
    """Validate all 40 extensions without token access."""
    value = manifest if isinstance(manifest, dict) else {}
    failures: list[str] = []
    descriptors = value.get("extensions", [])
    expected_authorization = {
        "authorization_id": authorization_id,
        "statement_sha256": authorization_statement_sha256,
        "plan_artifact_sha256": hashlib.sha256(plan_raw).hexdigest(),
        "plan_sha256": plan["plan_sha256"],
        "preflight_artifact_sha256": hashlib.sha256(preflight_raw).hexdigest(),
    }
    if not (
        value.get("schema_version") == MANIFEST_SCHEMA
        and value.get("status") == "signed_gate_required"
        and value.get("source_binding") == plan["source_binding"]
        and value.get("authorization") == expected_authorization
        and value.get("implementation") == implementation
        and value.get("execution_boundary") == SIGNING_BOUNDARY
        and isinstance(descriptors, list)
        and len(descriptors) == 40
    ):
        failures.append("confirmatory_consent_manifest_contract_invalid")
    targets = {item["participant_id"]: item for item in plan["consent_targets"]}
    identities = {
        item["participant_id"]: item for item in plan["participant_identity_set"]
    }
    seen_ids: set[str] = set()
    seen_nonces: set[str] = set()
    seen_hashes: set[str] = set()
    for descriptor in descriptors if isinstance(descriptors, list) else []:
        try:
            published = Path(descriptor["path"])
            path = read_root / published.name if read_root is not None else published
            extension, raw = _read_private(path)
            participant_id = str(descriptor["participant_id"])
            target = targets[participant_id]
            identity = identities[participant_id]
            extension_failures = validate_extension(extension)
            if extension_failures:
                failures.extend(extension_failures)
            if not (
                descriptor
                == {
                    "path": str(published.resolve()),
                    "sha256": hashlib.sha256(raw).hexdigest(),
                    "canonical_sha256": extension.get("extension_sha256"),
                    "participant_id": participant_id,
                    "cohort": target["cohort"],
                }
                and extension.get("participant", {}).get("participant_id")
                == participant_id
                and extension.get("participant", {}).get("execution_did")
                == target["execution_did"]
                and extension.get("participant", {}).get("public_key_sha256")
                == identity["public_key_sha256"]
                and extension.get("cohort_binding", {}).get("pair_id")
                == target["pair_id"]
                and extension.get("cohort_binding", {}).get("cohort")
                == target["cohort"]
                and extension.get("prior_outcome_consent", {}).get("canonical_sha256")
                == target["prior_outcome_consent_sha256"]
                and extension.get("authorization") == expected_authorization
            ):
                failures.append(
                    f"confirmatory_consent_extension_binding_invalid:{participant_id}"
                )
            seen_ids.add(participant_id)
            seen_nonces.add(str(extension.get("consent_nonce_hex", "")))
            seen_hashes.add(str(extension.get("extension_sha256", "")))
        except (
            KeyError,
            OSError,
            ValueError,
            TypeError,
            json.JSONDecodeError,
        ) as error:
            failures.append(
                f"confirmatory_consent_extension_unreadable:{type(error).__name__}"
            )
    if not (
        len(seen_ids) == len(seen_nonces) == len(seen_hashes) == 40
        and seen_ids == set(targets)
    ):
        failures.append("confirmatory_consent_extension_set_invalid")
    expected_inventory = {
        "participant_count": 40,
        "mentor_participant_count": 20,
        "control_participant_count": 20,
        "signed_extension_count": 40,
        "unique_extension_count": 40,
        "prior_consent_inherited": False,
        "all_signatures_verified": True,
    }
    if value.get("inventory") != expected_inventory:
        failures.append("confirmatory_consent_manifest_inventory_invalid")
    body = {key: item for key, item in value.items() if key != "manifest_sha256"}
    if value.get("manifest_sha256") != canonical_sha256(body):
        failures.append("confirmatory_consent_manifest_hash_invalid")
    return list(dict.fromkeys(failures))


def _build_manifest(
    *,
    signing_id: str,
    signed_at: str,
    plan: dict[str, Any],
    plan_raw: bytes,
    preflight_raw: bytes,
    authorization_id: str,
    authorization_statement_sha256: str,
    descriptors: list[dict[str, Any]],
    implementation: dict[str, str],
) -> dict[str, Any]:
    value = {
        "schema_version": MANIFEST_SCHEMA,
        "signing_id": signing_id,
        "status": "signed_gate_required",
        "signed_at": signed_at,
        "source_binding": plan["source_binding"],
        "authorization": {
            "authorization_id": authorization_id,
            "statement_sha256": authorization_statement_sha256,
            "plan_artifact_sha256": hashlib.sha256(plan_raw).hexdigest(),
            "plan_sha256": plan["plan_sha256"],
            "preflight_artifact_sha256": hashlib.sha256(preflight_raw).hexdigest(),
        },
        "extensions": descriptors,
        "inventory": {
            "participant_count": 40,
            "mentor_participant_count": 20,
            "control_participant_count": 20,
            "signed_extension_count": 40,
            "unique_extension_count": 40,
            "prior_consent_inherited": False,
            "all_signatures_verified": True,
        },
        "execution_boundary": SIGNING_BOUNDARY,
        "implementation": implementation,
    }
    value["manifest_sha256"] = canonical_sha256(value)
    return value


def _validate_preflight(
    *,
    plan: dict[str, Any],
    plan_path: Path,
    plan_raw: bytes,
    preflight: dict[str, Any],
    statement: str,
    statement_sha: str,
) -> None:
    body = {key: item for key, item in preflight.items() if key != "report_sha256"}
    if not (
        preflight.get("schema_version") == PREFLIGHT_SCHEMA
        and preflight.get("passed") is True
        and preflight.get("failure_reasons") == []
        and preflight.get("state")
        == "confirmatory_consent_exact_owner_signing_authorization_required"
        and preflight.get("plan")
        == {
            "path": str(plan_path.resolve()),
            "sha256": hashlib.sha256(plan_raw).hexdigest(),
            "canonical_sha256": plan["plan_sha256"],
        }
        and preflight.get("approval_request", {}).get("required_exact_statement")
        == statement
        and preflight.get("approval_request", {}).get("statement_sha256")
        == statement_sha
        and preflight.get("implementation") == plan["implementation"]
        and preflight.get("execution_boundary") == plan["current_execution_boundary"]
        and preflight.get("report_sha256") == canonical_sha256(body)
    ):
        raise ValueError("confirmatory consent preflight invalid")


def _implementation(root: Path) -> dict[str, str]:
    repository = root.resolve()
    if _git(repository, "status", "--porcelain"):
        raise ValueError("repository must be clean before consent signing")
    revision = _git(repository, "rev-parse", "HEAD")
    if revision != _git(repository, "rev-parse", "@{upstream}"):
        raise ValueError("confirmatory consent signing revision must be pushed")
    hashes = {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in (DOMAIN_SOURCE, PREFLIGHT_SOURCE, OPERATION_SOURCE, GATE_SOURCE)
    }
    return {
        "source_revision": revision,
        "source_sha256": canonical_sha256(hashes),
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


def _artifact(path: Path) -> dict[str, str]:
    return {
        "path": str(path.resolve()),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
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
    parser.add_argument("--signing-id", required=True)
    parser.add_argument("--authorization-id", required=True)
    parser.add_argument("--authorization-statement-sha256", required=True)
    parser.add_argument("--signed-at")
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--preflight", type=Path, required=True)
    parser.add_argument("--participant-profiles-root", type=Path, required=True)
    parser.add_argument("--module", default=DEFAULT_MODULE)
    parser.add_argument("--token-label", required=True)
    parser.add_argument("--pin-file", type=Path)
    parser.add_argument(
        "--repository-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
    )
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    report = sign_extensions(
        signing_id=args.signing_id,
        signed_at=args.signed_at or datetime.now(UTC).isoformat(),
        authorization_id=args.authorization_id,
        authorization_statement_sha256=args.authorization_statement_sha256,
        plan_path=args.plan,
        preflight_path=args.preflight,
        participant_profiles_root=args.participant_profiles_root,
        module_path=args.module,
        token_label=args.token_label,
        repository_root=args.repository_root,
        pin=read_pin(args.pin_file),
        output_root=args.output_root,
    )
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
