"""Provision one explicitly authorized J1-D mentor SoftHSM identity."""

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
from nacl.signing import VerifyKey

from benchmarks.j1.controlled_comparison import canonical_sha256, write_private_json
from benchmarks.j1.qualification_mentor_identity import (
    build_mentor_identity_profile,
    validate_mentor_identity_profile,
)
from benchmarks.j1_qualification_mentor_identity_preflight import (
    approval_statement,
    load_participant_profiles,
    validate_mentor_identity_plan,
    validate_mentor_identity_sources,
)
from benchmarks.j1_qualification_reviewer_identity import inspect_token_pin_state
from scripts.pkcs11_identity_probe import DEFAULT_MODULE, read_pin


REPORT_SCHEMA = "j1-qualification-mentor-identity-provisioning:v1"
CONTRACT_SOURCE = Path(__file__).parent / "j1" / "qualification_mentor_identity.py"
OPERATION_SOURCE = Path(__file__)
GATE_SOURCE = Path(__file__).parent / "j1_qualification_mentor_identity_gate.py"


def provision_mentor_identity(
    *,
    provisioning_id: str,
    created_at: str,
    owner_authorization_id: str,
    owner_statement_sha256: str,
    plan_path: Path,
    preflight_path: Path,
    reviewed_design_path: Path,
    design_gate_path: Path,
    reviewer_profile_path: Path,
    participant_provisioning_report_path: Path,
    participant_profiles_root: Path,
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
        raise ValueError(f"mentor identity output already exists: {output_root}")
    context = _load_context(
        plan_path=plan_path,
        preflight_path=preflight_path,
        reviewed_design_path=reviewed_design_path,
        design_gate_path=design_gate_path,
        reviewer_profile_path=reviewer_profile_path,
        participant_provisioning_report_path=participant_provisioning_report_path,
        participant_profiles_root=participant_profiles_root,
        module_path=module_path,
        token_label=token_label,
        key_label=key_label,
        key_id_hex=key_id_hex,
    )
    plan = context["plan"]
    expected_statement = approval_statement(
        plan, hashlib.sha256(context["plan_raw"]).hexdigest()
    )
    expected_statement_sha256 = hashlib.sha256(expected_statement.encode()).hexdigest()
    if not (
        context["preflight"].get("approval_request", {}).get("required_exact_statement")
        == expected_statement
        and context["preflight"].get("approval_request", {}).get("statement_sha256")
        == expected_statement_sha256
        and owner_statement_sha256 == expected_statement_sha256
    ):
        raise ValueError("mentor identity owner authorization statement/hash mismatch")
    if (
        not _text(provisioning_id)
        or not _text(owner_authorization_id)
        or not _rfc3339(created_at)
    ):
        raise ValueError("mentor identity provisioning metadata invalid")
    implementation = _implementation(agent_revision)
    module = Path(module_path).resolve()
    key_id = bytes.fromhex(key_id_hex)
    library = pkcs11.lib(str(module))
    token = library.get_token(token_label=token_label)
    if (
        _decode(token.serial) != plan["proposed_identity"]["token_serial"]
        or _decode(token.model) != plan["proposed_identity"]["token_model"]
    ):
        raise ValueError("mentor identity approved PKCS#11 token metadata mismatch")
    pin_state = inspect_token_pin_state(
        module_path=str(module), token_label=token_label
    )
    if not pin_state["safe_to_attempt_user_login"]:
        raise ValueError(
            f"token user PIN retry risk: {pin_state['user_pin_risk_flags']}"
        )

    output_root.mkdir(parents=True, mode=0o700)
    output_root.chmod(0o700)
    created_keys: list[Any] = []
    try:
        with token.open(user_pin=pin, rw=True) as session:
            if list(session.get_objects({pkcs11.Attribute.LABEL: key_label})):
                raise ValueError(
                    f"mentor PKCS#11 key label already exists: {key_label}"
                )
            if list(session.get_objects({pkcs11.Attribute.ID: key_id})):
                raise ValueError(f"mentor PKCS#11 key ID already exists: {key_id_hex}")
            try:
                public_key, private_key = session.generate_keypair(
                    pkcs11.KeyType.EC_EDWARDS,
                    public_template={
                        pkcs11.Attribute.EC_PARAMS: bytes.fromhex("06032b6570"),
                        pkcs11.Attribute.VERIFY: True,
                    },
                    private_template={
                        pkcs11.Attribute.SIGN: True,
                        pkcs11.Attribute.SENSITIVE: True,
                        pkcs11.Attribute.EXTRACTABLE: False,
                    },
                    label=key_label,
                    id=key_id,
                    store=True,
                )
                created_keys.extend((public_key, private_key))
                encoded_point = bytes(public_key[pkcs11.Attribute.EC_POINT])
                if encoded_point[:2] != b"\x04\x20" or len(encoded_point) != 34:
                    raise RuntimeError("SoftHSM returned unsupported Ed25519 point")
                public_key_hex = encoded_point[2:].hex()
                challenge = secrets.token_bytes(32)
                signature = bytes(
                    private_key.sign(challenge, mechanism=pkcs11.Mechanism.EDDSA)
                )
                VerifyKey(bytes.fromhex(public_key_hex)).verify(challenge, signature)
                key_reference_sha256 = canonical_sha256(
                    {
                        "provider": "pkcs11",
                        "module_path": str(module),
                        "token_label": token_label,
                        "token_serial": _decode(token.serial),
                        "key_label": key_label,
                        "key_id_hex": key_id_hex.lower(),
                    }
                )
                profile = build_mentor_identity_profile(
                    created_at=created_at,
                    plan=plan,
                    plan_artifact_sha256=hashlib.sha256(
                        context["plan_raw"]
                    ).hexdigest(),
                    owner_authorization_id=owner_authorization_id,
                    owner_statement_sha256=owner_statement_sha256,
                    public_key_hex=public_key_hex,
                    module_path=str(module),
                    module_sha256=hashlib.sha256(module.read_bytes()).hexdigest(),
                    token_label=token_label,
                    token_serial=_decode(token.serial),
                    token_model=_decode(token.model),
                    token_manufacturer=_decode(token.manufacturer_id),
                    key_label=key_label,
                    key_id_hex=key_id_hex,
                    key_reference_sha256=key_reference_sha256,
                    challenge=challenge,
                    signature=signature,
                    private_key_sensitive=bool(private_key[pkcs11.Attribute.SENSITIVE]),
                    private_key_extractable=bool(
                        private_key[pkcs11.Attribute.EXTRACTABLE]
                    ),
                    implementation=implementation,
                )
                profile_path = output_root / "mentor-identity.json"
                write_private_json(profile_path, profile)
                failures = validate_mentor_identity_profile(profile, plan=plan)
                if failures:
                    raise ValueError(f"mentor identity profile invalid: {failures}")
                report = {
                    "schema_version": REPORT_SCHEMA,
                    "passed": True,
                    "state": "mentor_identity_provisioned_advice_authorization_required",
                    "provisioning_id": provisioning_id,
                    "created_at": created_at,
                    "mentor_identity": {
                        **_artifact(profile_path),
                        "canonical_sha256": profile["profile_sha256"],
                        "mentor_id": profile["mentor"]["mentor_id"],
                        "mentor_did": profile["mentor"]["did"],
                    },
                    "source_artifacts": context["source_artifacts"],
                    "authorization": {
                        "authorization_id": owner_authorization_id,
                        "statement_sha256": owner_statement_sha256,
                    },
                    "pin_recorded": False,
                    "execution_boundary": {
                        "identity_provisioned": True,
                        "possession_proof_created": True,
                        "treatment_advice_signed": False,
                        "provider_api_call_performed": False,
                        "model_invocation_performed": False,
                        "agent_execution_performed": False,
                        "backend_fact_append_performed": False,
                        "ledger_append_performed": False,
                    },
                }
                write_private_json(
                    output_root / "mentor-identity-operation.json", report
                )
            except Exception:
                _destroy_keys(created_keys)
                created_keys.clear()
                raise
        return report
    except Exception:
        shutil.rmtree(output_root, ignore_errors=True)
        raise


def _load_context(**values: Any) -> dict[str, Any]:
    plan, plan_raw = _read_private(Path(values["plan_path"]))
    preflight, preflight_raw = _read_private(Path(values["preflight_path"]))
    reviewed_design, reviewed_design_raw = _read_private(
        Path(values["reviewed_design_path"])
    )
    design_gate, design_gate_raw = _read_private(Path(values["design_gate_path"]))
    reviewer, reviewer_raw = _read_private(Path(values["reviewer_profile_path"]))
    participant_report, participant_report_raw = _read_private(
        Path(values["participant_provisioning_report_path"])
    )
    profiles = load_participant_profiles(Path(values["participant_profiles_root"]))
    failures = validate_mentor_identity_plan(plan)
    if failures:
        raise ValueError(f"mentor identity plan invalid: {failures}")
    proposed = plan["proposed_identity"]
    expected_target = {
        "module_path": str(Path(values["module_path"]).resolve()),
        "module_sha256": hashlib.sha256(
            Path(values["module_path"]).read_bytes()
        ).hexdigest(),
        "token_label": values["token_label"],
        "key_label": values["key_label"],
        "key_id_hex": str(values["key_id_hex"]).lower(),
    }
    if any(
        proposed.get(field) != expected for field, expected in expected_target.items()
    ):
        raise ValueError("mentor identity approved PKCS#11 target mismatch")
    validate_mentor_identity_sources(
        reviewed_design=reviewed_design,
        reviewed_design_path=Path(values["reviewed_design_path"]),
        reviewed_design_raw=reviewed_design_raw,
        design_gate=design_gate,
        reviewer=reviewer,
        participant_report=participant_report,
        participant_profiles_root=Path(values["participant_profiles_root"]),
        profiles=profiles,
        module_path=str(Path(values["module_path"]).resolve()),
        module_sha256=hashlib.sha256(
            Path(values["module_path"]).read_bytes()
        ).hexdigest(),
        token_label=values["token_label"],
        key_label=values["key_label"],
        key_id_hex=str(values["key_id_hex"]).lower(),
    )
    expected_sources = {
        "reviewed_design": _artifact_bytes(
            Path(values["reviewed_design_path"]), reviewed_design_raw
        ),
        "design_gate": _artifact_bytes(
            Path(values["design_gate_path"]), design_gate_raw
        ),
        "reviewer_identity": _artifact_bytes(
            Path(values["reviewer_profile_path"]), reviewer_raw
        ),
        "participant_provisioning_report": _artifact_bytes(
            Path(values["participant_provisioning_report_path"]),
            participant_report_raw,
        ),
    }
    if not (
        preflight.get("passed") is True
        and preflight.get("state")
        == "mentor_identity_provisioning_explicit_owner_authorization_required"
        and preflight.get("plan", {}).get("path")
        == str(Path(values["plan_path"]).resolve())
        and preflight.get("plan", {}).get("sha256")
        == hashlib.sha256(plan_raw).hexdigest()
        and preflight.get("plan", {}).get("canonical_sha256") == plan.get("plan_sha256")
        and preflight.get("source_artifacts") == expected_sources
        and hashlib.sha256(preflight_raw).hexdigest()
        == hashlib.sha256(Path(values["preflight_path"]).read_bytes()).hexdigest()
    ):
        raise ValueError("mentor identity candidate preflight drift")
    return {
        "plan": plan,
        "plan_raw": plan_raw,
        "preflight": preflight,
        "source_artifacts": expected_sources,
    }


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
        raise ValueError("mentor identity revision is not checked out")
    if status.returncode or status.stdout.strip():
        raise ValueError("mentor identity worktree must be clean")
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


def _destroy_keys(keys: list[Any]) -> None:
    for key in reversed(keys):
        try:
            key.destroy()
        except pkcs11.PKCS11Error:
            pass


def _read_private(path: Path) -> tuple[dict[str, Any], bytes]:
    if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o077:
        raise ValueError(f"private JSON artifact invalid: {path}")
    raw = path.read_bytes()
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError(f"JSON artifact must be object: {path}")
    return value, raw


def _artifact(path: Path) -> dict[str, str]:
    return _artifact_bytes(path, path.read_bytes())


def _artifact_bytes(path: Path, raw: bytes) -> dict[str, str]:
    return {"path": str(path.resolve()), "sha256": hashlib.sha256(raw).hexdigest()}


def _decode(value: Any) -> str:
    return (
        value.decode("ascii").strip()
        if isinstance(value, bytes)
        else str(value).strip()
    )


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
    parser.add_argument("--provisioning-id", required=True)
    parser.add_argument("--owner-authorization-id", required=True)
    parser.add_argument("--owner-statement-sha256", required=True)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--preflight", type=Path, required=True)
    parser.add_argument("--reviewed-design", type=Path, required=True)
    parser.add_argument("--design-gate", type=Path, required=True)
    parser.add_argument("--reviewer-profile", type=Path, required=True)
    parser.add_argument("--participant-provisioning-report", type=Path, required=True)
    parser.add_argument("--participant-profiles-root", type=Path, required=True)
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
        report = provision_mentor_identity(
            provisioning_id=args.provisioning_id,
            created_at=datetime.now(timezone.utc).isoformat(),
            owner_authorization_id=args.owner_authorization_id,
            owner_statement_sha256=args.owner_statement_sha256,
            plan_path=args.plan,
            preflight_path=args.preflight,
            reviewed_design_path=args.reviewed_design,
            design_gate_path=args.design_gate,
            reviewer_profile_path=args.reviewer_profile,
            participant_provisioning_report_path=args.participant_provisioning_report,
            participant_profiles_root=args.participant_profiles_root,
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
        KeyError,
        json.JSONDecodeError,
        pkcs11.PKCS11Error,
    ) as error:
        report = {
            "schema_version": REPORT_SCHEMA,
            "passed": False,
            "state": "blocked_mentor_identity_provisioning",
            "error_class": type(error).__name__,
            "error": str(error),
            "pin_recorded": False,
            "treatment_advice_signed": False,
            "provider_api_call_performed": False,
            "model_invocation_performed": False,
        }
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
        return 1
    finally:
        pin = ""
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
