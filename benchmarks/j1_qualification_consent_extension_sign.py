"""Sign exactly 40 owner-authorized J1-D participant consent extensions."""

from __future__ import annotations

import argparse
import hashlib
import json
import secrets
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pkcs11

from benchmarks.j1.controlled_comparison import canonical_sha256, write_private_json
from benchmarks.j1.qualification_consent_extension import (
    authorization_statement,
    build_consent_extension,
    validate_consent_extension,
    validate_consent_extension_plan,
)
from benchmarks.j1_qualification_consent_extension_preflight import (
    _identity_record,
    _load_profiles,
)
from benchmarks.j1_qualification_reviewer_identity import inspect_token_pin_state
from scripts.pkcs11_identity_probe import DEFAULT_MODULE, read_pin


REPORT_SCHEMA = "j1-qualification-consent-extension-signing-operation:v1"
MANIFEST_SCHEMA = "j1-qualification-consent-extension-manifest:v1"
DOMAIN_SOURCE = Path(__file__).parent / "j1" / "qualification_consent_extension.py"
PREFLIGHT_SOURCE = (
    Path(__file__).parent / "j1_qualification_consent_extension_preflight.py"
)
OPERATION_SOURCE = Path(__file__)
GATE_SOURCE = Path(__file__).parent / "j1_qualification_consent_extension_gate.py"


class _SessionSigner:
    def __init__(self, private_key: Any, public_key_hex: str) -> None:
        self._private_key = private_key
        self._public_key_hex = public_key_hex

    @property
    def public_key_hex(self) -> str:
        return self._public_key_hex

    def sign(self, message: bytes) -> bytes:
        return bytes(self._private_key.sign(message, mechanism=pkcs11.Mechanism.EDDSA))


def sign_consent_extensions(
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
    if not pin:
        raise ValueError("SoftHSM user PIN is empty")
    if output_root.exists():
        raise ValueError(
            f"consent-extension signing output already exists: {output_root}"
        )
    if not signing_id.strip() or not authorization_id.strip():
        raise ValueError("consent-extension signing metadata invalid")
    plan, plan_raw = _read_private(plan_path)
    preflight, preflight_raw = _read_private(preflight_path)
    failures = validate_consent_extension_plan(plan)
    if failures:
        raise ValueError(f"consent-extension plan invalid: {failures}")
    plan_raw_sha = hashlib.sha256(plan_raw).hexdigest()
    expected_statement = authorization_statement(plan, plan_raw_sha)
    expected_statement_sha = hashlib.sha256(expected_statement.encode()).hexdigest()
    _validate_preflight(
        plan=plan,
        plan_path=plan_path,
        plan_raw=plan_raw,
        preflight=preflight,
        expected_statement=expected_statement,
        expected_statement_sha=expected_statement_sha,
    )
    if authorization_statement_sha256 != expected_statement_sha:
        raise ValueError(
            "consent-extension owner authorization statement/hash mismatch"
        )
    _validate_frozen_sources(preflight)
    profiles = _load_profiles(participant_profiles_root)
    identity_set = [_identity_record(profiles[item]) for item in sorted(profiles)]
    if identity_set != plan["participant_identity_set"]:
        raise ValueError("participant profiles drift from consent-extension plan")
    module = Path(module_path).resolve()
    _validate_pkcs11_configuration(
        profiles=profiles,
        module=module,
        token_label=token_label,
        expected_token_label=plan["source_binding"]["token_label"],
    )
    pin_state = inspect_token_pin_state(
        module_path=str(module), token_label=token_label
    )
    if not pin_state["safe_to_attempt_user_login"]:
        raise ValueError(
            f"token user PIN retry risk: {pin_state['user_pin_risk_flags']}"
        )
    implementation = _implementation(repository_root)
    targets = {target["participant_id"]: target for target in plan["consent_targets"]}
    identities = {
        identity["participant_id"]: identity
        for identity in plan["participant_identity_set"]
    }
    preflight_raw_sha = hashlib.sha256(preflight_raw).hexdigest()
    output_root.mkdir(parents=True, mode=0o700)
    output_root.chmod(0o700)
    evidence_root = output_root / "extensions"
    evidence_root.mkdir(mode=0o700)
    try:
        library = pkcs11.lib(str(module))
        token = library.get_token(token_label=token_label)
        descriptors = []
        with token.open(user_pin=pin) as session:
            for participant_id in sorted(profiles):
                profile = profiles[participant_id]
                participant = profile["participant"]
                private_key = _session_key(
                    session,
                    profile["pkcs11_key"],
                    participant["public_key_hex"],
                )
                extension = build_consent_extension(
                    extension_id=f"{signing_id}:{participant_id}",
                    signed_at=signed_at,
                    target=targets[participant_id],
                    identity=identities[participant_id],
                    public_key_hex=participant["public_key_hex"],
                    plan=plan,
                    plan_artifact_sha256=plan_raw_sha,
                    preflight_artifact_sha256=preflight_raw_sha,
                    authorization_id=authorization_id,
                    authorization_statement_sha256=authorization_statement_sha256,
                    nonce=secrets.token_bytes(32),
                    signer=_SessionSigner(private_key, participant["public_key_hex"]),
                )
                path = evidence_root / f"{participant_id}.consent-extension.json"
                write_private_json(path, extension)
                descriptors.append(
                    {
                        **_artifact(path),
                        "participant_id": participant_id,
                        "cohort": extension["cohort_binding"]["cohort"],
                        "canonical_sha256": extension["extension_sha256"],
                    }
                )
        manifest = {
            "schema_version": MANIFEST_SCHEMA,
            "signing_id": signing_id,
            "status": "signed_gate_required",
            "signed_at": signed_at,
            "source_binding": {
                "plan_artifact_sha256": plan_raw_sha,
                "plan_sha256": plan["plan_sha256"],
                "preflight_artifact_sha256": preflight_raw_sha,
                "participant_identity_set_sha256": plan[
                    "participant_identity_set_sha256"
                ],
                "amendment_bundle_sha256": plan["source_binding"][
                    "amendment_bundle_sha256"
                ],
                "reviewed_assignment_sha256": plan["source_binding"][
                    "reviewed_assignment_sha256"
                ],
            },
            "authorization": {
                "authorization_id": authorization_id,
                "statement_sha256": authorization_statement_sha256,
            },
            "inventory": {
                "participant_count": 40,
                "mentor_participant_count": 20,
                "control_participant_count": 20,
                "signed_extension_count": len(descriptors),
                "unique_extension_count": len(
                    {item["canonical_sha256"] for item in descriptors}
                ),
                "all_signatures_verified": True,
                "prior_consent_inherited": False,
            },
            "extensions": descriptors,
            "implementation": implementation,
            "execution_boundary": _execution_boundary(),
        }
        manifest["manifest_sha256"] = canonical_sha256(manifest)
        failures = validate_signed_manifest(
            manifest,
            plan=plan,
            plan_raw=plan_raw,
            preflight_raw=preflight_raw,
            authorization_id=authorization_id,
            authorization_statement_sha256=authorization_statement_sha256,
            implementation=implementation,
        )
        if failures:
            raise ValueError(f"signed consent-extension manifest invalid: {failures}")
        manifest_path = output_root / "consent-extension-manifest.signed.json"
        write_private_json(manifest_path, manifest)
        report = {
            "schema_version": REPORT_SCHEMA,
            "passed": True,
            "state": "participant_consent_extensions_signed_gate_required",
            "signed_at": signed_at,
            "plan": _artifact(plan_path),
            "preflight": _artifact(preflight_path),
            "signed_manifest": {
                **_artifact(manifest_path),
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
            "execution_boundary": manifest["execution_boundary"],
        }
        report["report_sha256"] = canonical_sha256(report)
        write_private_json(
            output_root / "consent-extension-signing-operation.json", report
        )
        return report
    except Exception:
        shutil.rmtree(output_root, ignore_errors=True)
        raise


def validate_signed_manifest(
    manifest: Any,
    *,
    plan: dict[str, Any],
    plan_raw: bytes,
    preflight_raw: bytes,
    authorization_id: str,
    authorization_statement_sha256: str,
    implementation: dict[str, str],
) -> list[str]:
    value = manifest if isinstance(manifest, dict) else {}
    failures: list[str] = []
    expected_source = {
        "plan_artifact_sha256": hashlib.sha256(plan_raw).hexdigest(),
        "plan_sha256": plan["plan_sha256"],
        "preflight_artifact_sha256": hashlib.sha256(preflight_raw).hexdigest(),
        "participant_identity_set_sha256": plan["participant_identity_set_sha256"],
        "amendment_bundle_sha256": plan["source_binding"]["amendment_bundle_sha256"],
        "reviewed_assignment_sha256": plan["source_binding"][
            "reviewed_assignment_sha256"
        ],
    }
    expected_authorization = {
        "authorization_id": authorization_id,
        "statement_sha256": authorization_statement_sha256,
    }
    descriptors = value.get("extensions")
    descriptor_values = descriptors if isinstance(descriptors, list) else []
    targets = {item["participant_id"]: item for item in plan["consent_targets"]}
    identities = {
        item["participant_id"]: item for item in plan["participant_identity_set"]
    }
    participant_ids = set()
    canonical_hashes = set()
    cohorts = []
    for descriptor in descriptor_values:
        try:
            path = Path(descriptor["path"])
            extension, raw = _read_private(path)
            participant_id = extension["participant"]["participant_id"]
            failures.extend(validate_consent_extension(extension))
            expected_target = targets[participant_id]
            expected_identity = identities[participant_id]
            if not (
                descriptor
                == {
                    "path": str(path.resolve()),
                    "sha256": hashlib.sha256(raw).hexdigest(),
                    "participant_id": participant_id,
                    "cohort": expected_target["cohort"],
                    "canonical_sha256": extension["extension_sha256"],
                }
                and extension["participant"]["execution_did"]
                == expected_target["execution_did"]
                and extension["participant"]["participant_profile_sha256"]
                == expected_target["participant_profile_sha256"]
                and extension["participant"]["public_key_sha256"]
                == expected_identity["public_key_sha256"]
                and extension["cohort_binding"]
                == {
                    "pair_id": expected_target["pair_id"],
                    "cohort": expected_target["cohort"],
                    "reviewed_assignment_sha256": plan["source_binding"][
                        "reviewed_assignment_sha256"
                    ],
                    "assignment_commitment_sha256": expected_target[
                        "assignment_commitment_sha256"
                    ],
                }
                and extension["prior_consent"]
                == {
                    "artifact_sha256": expected_target["prior_consent_artifact_sha256"],
                    "canonical_sha256": expected_target["prior_consent_sha256"],
                    "inherited": False,
                    "immutable_parent_evidence": True,
                }
                and extension["authorization"]
                == {
                    "authorization_id": authorization_id,
                    "statement_sha256": authorization_statement_sha256,
                    "plan_artifact_sha256": expected_source["plan_artifact_sha256"],
                    "plan_sha256": expected_source["plan_sha256"],
                    "preflight_artifact_sha256": expected_source[
                        "preflight_artifact_sha256"
                    ],
                }
            ):
                failures.append(f"consent_extension_binding_invalid:{participant_id}")
            participant_ids.add(participant_id)
            canonical_hashes.add(extension["extension_sha256"])
            cohorts.append(expected_target["cohort"])
        except (KeyError, OSError, ValueError, json.JSONDecodeError) as error:
            failures.append(
                f"consent_extension_artifact_invalid:{type(error).__name__}"
            )
    expected_inventory = {
        "participant_count": 40,
        "mentor_participant_count": 20,
        "control_participant_count": 20,
        "signed_extension_count": 40,
        "unique_extension_count": 40,
        "all_signatures_verified": True,
        "prior_consent_inherited": False,
    }
    body = {key: item for key, item in value.items() if key != "manifest_sha256"}
    if not (
        value.get("schema_version") == MANIFEST_SCHEMA
        and value.get("status") == "signed_gate_required"
        and value.get("source_binding") == expected_source
        and value.get("authorization") == expected_authorization
        and value.get("inventory") == expected_inventory
        and value.get("implementation") == implementation
        and value.get("execution_boundary") == _execution_boundary()
        and len(descriptor_values) == 40
        and participant_ids == set(targets)
        and len(canonical_hashes) == 40
        and cohorts.count("mentor") == 20
        and cohorts.count("control") == 20
        and value.get("manifest_sha256") == canonical_sha256(body)
    ):
        failures.append("signed_consent_extension_manifest_invalid")
    return list(dict.fromkeys(failures))


def _validate_preflight(
    *,
    plan: dict[str, Any],
    plan_path: Path,
    plan_raw: bytes,
    preflight: dict[str, Any],
    expected_statement: str,
    expected_statement_sha: str,
) -> None:
    if not (
        preflight.get("passed") is True
        and preflight.get("state")
        == "consent_extension_explicit_owner_signing_authorization_required"
        and preflight.get("plan")
        == {
            "path": str(plan_path.resolve()),
            "sha256": hashlib.sha256(plan_raw).hexdigest(),
            "canonical_sha256": plan["plan_sha256"],
        }
        and preflight.get("approval_request", {}).get("required_exact_statement")
        == expected_statement
        and preflight.get("approval_request", {}).get("statement_sha256")
        == expected_statement_sha
        and preflight.get("inventory") == plan["inventory"]
        and preflight.get("execution_boundary") == plan["current_execution_boundary"]
    ):
        raise ValueError("consent-extension preflight binding invalid")


def _validate_frozen_sources(preflight: dict[str, Any]) -> None:
    for name, descriptor in preflight["source_artifacts"].items():
        path = Path(descriptor["path"])
        _, raw = _read_private(path)
        if hashlib.sha256(raw).hexdigest() != descriptor["sha256"]:
            raise ValueError(f"consent-extension frozen source drift: {name}")


def _validate_pkcs11_configuration(
    *,
    profiles: dict[str, dict[str, Any]],
    module: Path,
    token_label: str,
    expected_token_label: str,
) -> None:
    module_sha = hashlib.sha256(module.read_bytes()).hexdigest()
    if token_label != expected_token_label:
        raise ValueError("consent-extension token label differs from plan")
    for profile in profiles.values():
        key = profile["pkcs11_key"]
        if not (
            Path(key["module_path"]).resolve() == module
            and key["module_sha256"] == module_sha
            and key["token_label"] == token_label
        ):
            raise ValueError("participant PKCS#11 configuration differs from profile")


def _session_key(
    session: Any, reference: dict[str, Any], expected_public_key_hex: str
) -> Any:
    selector = {
        "label": reference["key_label"],
        "id": bytes.fromhex(reference["key_id_hex"]),
    }
    private_key = session.get_key(
        object_class=pkcs11.ObjectClass.PRIVATE_KEY, **selector
    )
    public_key = session.get_key(object_class=pkcs11.ObjectClass.PUBLIC_KEY, **selector)
    point = bytes(public_key[pkcs11.Attribute.EC_POINT])
    if point != b"\x04\x20" + bytes.fromhex(expected_public_key_hex):
        raise ValueError(f"participant public key mismatch: {reference['key_label']}")
    return private_key


def _implementation(repository_root: Path) -> dict[str, str]:
    root = repository_root.resolve()
    if _git(root, "status", "--porcelain").strip():
        raise ValueError("repository must be clean before consent-extension signing")
    hashes = {
        str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in (DOMAIN_SOURCE, PREFLIGHT_SOURCE, OPERATION_SOURCE, GATE_SOURCE)
    }
    return {
        "source_revision": _git(root, "rev-parse", "HEAD").strip(),
        "source_sha256": canonical_sha256(hashes),
    }


def _git(root: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", *arguments], cwd=root, check=True, capture_output=True, text=True
    ).stdout


def _execution_boundary() -> dict[str, bool]:
    return {
        "consent_extension_signature_only": True,
        "pin_recorded": False,
        "token_login_performed": True,
        "participant_consent_extended": True,
        "roster_rebound": False,
        "assignment_rebound": False,
        "infrastructure_rebound": False,
        "provider_api_call_performed": False,
        "model_invocation_performed": False,
        "agent_execution_performed": False,
        "container_execution_performed": False,
        "backend_fact_append_performed": False,
        "ledger_append_performed": False,
        "execution_authorization_issued_or_consumed": False,
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


def _artifact(path: Path) -> dict[str, str]:
    return {
        "path": str(path.resolve()),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--signing-id", required=True)
    parser.add_argument("--authorization-id", required=True)
    parser.add_argument("--authorization-statement-sha256", required=True)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--preflight", type=Path, required=True)
    parser.add_argument("--participant-profiles-root", type=Path, required=True)
    parser.add_argument("--module", default=DEFAULT_MODULE)
    parser.add_argument("--token-label", required=True)
    parser.add_argument(
        "--repository-root", type=Path, default=Path(__file__).parents[1]
    )
    parser.add_argument("--pin-file", type=Path)
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    pin = ""
    try:
        pin = read_pin(args.pin_file)
        report = sign_consent_extensions(
            signing_id=args.signing_id,
            signed_at=datetime.now(timezone.utc).isoformat(),
            authorization_id=args.authorization_id,
            authorization_statement_sha256=args.authorization_statement_sha256,
            plan_path=args.plan,
            preflight_path=args.preflight,
            participant_profiles_root=args.participant_profiles_root,
            module_path=args.module,
            token_label=args.token_label,
            repository_root=args.repository_root,
            pin=pin,
            output_root=args.output_root,
        )
    except (OSError, ValueError, RuntimeError, KeyError, pkcs11.PKCS11Error) as error:
        report = {
            "schema_version": REPORT_SCHEMA,
            "passed": False,
            "state": "blocked_consent_extension_signing",
            "error_class": type(error).__name__,
            "error": str(error),
            "pin_recorded": False,
            "provider_api_call_performed": False,
            "model_invocation_performed": False,
            "agent_execution_performed": False,
            "backend_fact_append_performed": False,
            "ledger_append_performed": False,
        }
        print(json.dumps(report, ensure_ascii=False, sort_keys=True))
        return 1
    finally:
        pin = ""
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
