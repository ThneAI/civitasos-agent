"""Prepare a no-key-generation J1-D mentor identity provisioning proposal."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pkcs11

from benchmarks.j1.controlled_comparison import canonical_sha256, write_private_json
from benchmarks.j1.qualification_participant_provisioning import (
    validate_participant_profile,
)
from benchmarks.j1.qualification_reviewer_identity import (
    validate_reviewer_identity_profile,
)
from benchmarks.j1_qualification_reviewer_identity import inspect_token_pin_state
from scripts.pkcs11_identity_probe import DEFAULT_MODULE


PLAN_SCHEMA = "j1-qualification-mentor-identity-provisioning-plan:v1"
REPORT_SCHEMA = "j1-qualification-mentor-identity-preflight:v1"


def prepare_mentor_identity_plan(
    *,
    plan_id: str,
    created_at: str,
    reviewed_design_path: Path,
    design_gate_path: Path,
    reviewer_profile_path: Path,
    participant_provisioning_report_path: Path,
    participant_profiles_root: Path,
    module_path: str,
    token_label: str,
    key_label: str,
    key_id_hex: str,
    output_root: Path,
) -> dict[str, Any]:
    if output_root.exists():
        raise ValueError(f"mentor identity plan output already exists: {output_root}")
    reviewed_design, reviewed_design_raw = _read_private(reviewed_design_path)
    design_gate, design_gate_raw = _read_private(design_gate_path)
    reviewer, reviewer_raw = _read_private(reviewer_profile_path)
    participant_report, participant_report_raw = _read_private(
        participant_provisioning_report_path
    )
    profiles = _load_participant_profiles(participant_profiles_root)
    module = Path(module_path).resolve()
    module_sha256 = hashlib.sha256(module.read_bytes()).hexdigest()
    key_id = _key_id(key_id_hex)
    _validate_sources(
        reviewed_design=reviewed_design,
        reviewed_design_path=reviewed_design_path,
        reviewed_design_raw=reviewed_design_raw,
        design_gate=design_gate,
        reviewer=reviewer,
        participant_report=participant_report,
        participant_profiles_root=participant_profiles_root,
        profiles=profiles,
        module_path=str(module),
        module_sha256=module_sha256,
        token_label=token_label,
        key_label=key_label,
        key_id_hex=key_id.hex(),
    )
    token_state = inspect_token_pin_state(
        module_path=str(module), token_label=token_label
    )
    if not (
        token_state["token_initialized"]
        and token_state["user_pin_initialized"]
        and token_state["safe_to_attempt_user_login"]
    ):
        raise ValueError(f"mentor identity token not ready: {token_state}")
    library = pkcs11.lib(str(module))
    token = library.get_token(token_label=token_label)
    with token.open() as session:
        label_exists = bool(
            list(session.get_objects({pkcs11.Attribute.LABEL: key_label}))
        )
        id_exists = bool(list(session.get_objects({pkcs11.Attribute.ID: key_id})))
    if label_exists or id_exists:
        raise ValueError("proposed mentor PKCS#11 label or key ID already exists")

    participant_identity_set = [
        {
            "participant_id": profile["participant"]["participant_id"],
            "execution_did": profile["participant"]["execution_did"],
            "public_key_sha256": profile["participant"]["public_key_sha256"],
            "key_label": profile["pkcs11_key"]["key_label"],
            "key_id_hex": profile["pkcs11_key"]["key_id_hex"],
            "profile_sha256": profile["profile_sha256"],
        }
        for profile in profiles
    ]
    plan = {
        "schema_version": PLAN_SCHEMA,
        "plan_id": plan_id,
        "status": "explicit_owner_authorization_required",
        "created_at": created_at,
        "source_binding": {
            "reviewed_design_sha256": reviewed_design["reviewed_design_sha256"],
            "reviewed_design_artifact_sha256": hashlib.sha256(
                reviewed_design_raw
            ).hexdigest(),
            "design_gate_artifact_sha256": hashlib.sha256(design_gate_raw).hexdigest(),
            "reviewer_identity_artifact_sha256": hashlib.sha256(
                reviewer_raw
            ).hexdigest(),
            "participant_provisioning_report_sha256": hashlib.sha256(
                participant_report_raw
            ).hexdigest(),
            "participant_identity_set_sha256": canonical_sha256(
                participant_identity_set
            ),
            "participant_count": 40,
        },
        "mentor_role": {
            "role": "qualification_treatment_advice_signer",
            "must_not_be_participant": True,
            "must_not_be_reviewer_key": True,
            "participant_identity_set": participant_identity_set,
        },
        "proposed_identity": {
            "credential_version": 1,
            "signer_kind": "pkcs11_ed25519",
            "module_path": str(module),
            "module_sha256": module_sha256,
            "token_label": token_label,
            "token_serial": str(token.serial).strip(),
            "token_model": str(token.model).strip(),
            "key_label": key_label,
            "key_id_hex": key_id.hex(),
            "private_key_sensitive": True,
            "private_key_extractable": False,
            "physical_hsm_claimed": False,
            "production_custody_claimed": False,
            "soft_token_limitations_acknowledgement_required": True,
        },
        "authorized_operation_if_approved": {
            "generate_exactly_one_keypair": True,
            "create_possession_proof": True,
            "write_private_identity_profile": True,
            "rollback_new_key_on_failure": True,
            "sign_treatment_advice": False,
            "provider_api_call": False,
            "model_invocation": False,
            "agent_execution": False,
            "backend_fact_append": False,
            "ledger_append": False,
        },
        "current_execution_boundary": {
            "pin_read": False,
            "token_login_attempted": False,
            "key_generation_performed": False,
            "possession_signature_performed": False,
            "treatment_advice_signed": False,
            "provider_api_call_performed": False,
            "model_invocation_performed": False,
            "agent_execution_performed": False,
            "backend_fact_append_performed": False,
            "ledger_append_performed": False,
        },
    }
    plan["plan_sha256"] = canonical_sha256(plan)
    failures = validate_mentor_identity_plan(plan)
    if failures:
        raise ValueError(f"mentor identity plan invalid: {failures}")

    output_root.mkdir(parents=True, mode=0o700)
    output_root.chmod(0o700)
    try:
        plan_path = output_root / "mentor-identity-provisioning.review-required.json"
        write_private_json(plan_path, plan)
        raw_sha256 = hashlib.sha256(plan_path.read_bytes()).hexdigest()
        statement = approval_statement(plan, raw_sha256)
        report = {
            "schema_version": REPORT_SCHEMA,
            "passed": True,
            "state": "mentor_identity_provisioning_explicit_owner_authorization_required",
            "plan": {
                **_artifact(plan_path),
                "canonical_sha256": plan["plan_sha256"],
            },
            "source_artifacts": {
                "reviewed_design": _artifact_bytes(
                    reviewed_design_path, reviewed_design_raw
                ),
                "design_gate": _artifact_bytes(design_gate_path, design_gate_raw),
                "reviewer_identity": _artifact_bytes(
                    reviewer_profile_path, reviewer_raw
                ),
                "participant_provisioning_report": _artifact_bytes(
                    participant_provisioning_report_path, participant_report_raw
                ),
            },
            "token_pin_state": token_state,
            "public_inventory": {
                "proposed_label_exists": label_exists,
                "proposed_key_id_exists": id_exists,
            },
            "approval_request": {
                "required_exact_statement": statement,
                "statement_sha256": hashlib.sha256(statement.encode()).hexdigest(),
                "mentor_identity_provisioning_authorization_required": True,
            },
            "execution_boundary": plan["current_execution_boundary"],
        }
        write_private_json(output_root / "mentor-identity-preflight.json", report)
        return report
    except Exception:
        shutil.rmtree(output_root, ignore_errors=True)
        raise


def validate_mentor_identity_plan(value: Any) -> list[str]:
    plan = value if isinstance(value, dict) else {}
    failures: list[str] = []
    expected_fields = {
        "schema_version",
        "plan_id",
        "status",
        "created_at",
        "source_binding",
        "mentor_role",
        "proposed_identity",
        "authorized_operation_if_approved",
        "current_execution_boundary",
        "plan_sha256",
    }
    _require(
        set(plan) == expected_fields, "mentor_identity_plan_fields_invalid", failures
    )
    _require(
        plan.get("schema_version") == PLAN_SCHEMA,
        "mentor_identity_plan_schema_invalid",
        failures,
    )
    _require(_text(plan.get("plan_id")), "mentor_identity_plan_id_invalid", failures)
    _require(
        plan.get("status") == "explicit_owner_authorization_required",
        "mentor_identity_plan_status_invalid",
        failures,
    )
    _require(
        _rfc3339(plan.get("created_at")), "mentor_identity_plan_time_invalid", failures
    )
    source = _object(plan.get("source_binding"))
    _require(
        source.get("participant_count") == 40
        and all(
            _sha256(source.get(field))
            for field in (
                "reviewed_design_sha256",
                "reviewed_design_artifact_sha256",
                "design_gate_artifact_sha256",
                "reviewer_identity_artifact_sha256",
                "participant_provisioning_report_sha256",
                "participant_identity_set_sha256",
            )
        ),
        "mentor_identity_plan_source_invalid",
        failures,
    )
    role = _object(plan.get("mentor_role"))
    identities = (
        role.get("participant_identity_set")
        if isinstance(role.get("participant_identity_set"), list)
        else []
    )
    _require(
        role.get("role") == "qualification_treatment_advice_signer"
        and role.get("must_not_be_participant") is True
        and role.get("must_not_be_reviewer_key") is True
        and len(identities) == 40
        and canonical_sha256(identities)
        == source.get("participant_identity_set_sha256"),
        "mentor_identity_plan_role_invalid",
        failures,
    )
    proposed = _object(plan.get("proposed_identity"))
    _require(
        proposed.get("credential_version") == 1
        and proposed.get("signer_kind") == "pkcs11_ed25519"
        and proposed.get("private_key_sensitive") is True
        and proposed.get("private_key_extractable") is False
        and proposed.get("physical_hsm_claimed") is False
        and proposed.get("production_custody_claimed") is False
        and proposed.get("soft_token_limitations_acknowledgement_required") is True
        and _sha256(proposed.get("module_sha256"))
        and _text(proposed.get("key_label"))
        and _variable_hex(proposed.get("key_id_hex")),
        "mentor_identity_plan_proposed_identity_invalid",
        failures,
    )
    operation = _object(plan.get("authorized_operation_if_approved"))
    allowed_true = {
        "generate_exactly_one_keypair",
        "create_possession_proof",
        "write_private_identity_profile",
        "rollback_new_key_on_failure",
    }
    _require(
        len(operation) == 10
        and all(operation.get(field) is True for field in allowed_true)
        and all(
            item is False for key, item in operation.items() if key not in allowed_true
        ),
        "mentor_identity_plan_authorized_operation_invalid",
        failures,
    )
    boundary = _object(plan.get("current_execution_boundary"))
    _require(
        len(boundary) == 10 and all(item is False for item in boundary.values()),
        "mentor_identity_plan_execution_boundary_invalid",
        failures,
    )
    body = {key: item for key, item in plan.items() if key != "plan_sha256"}
    _require(
        plan.get("plan_sha256") == canonical_sha256(body),
        "mentor_identity_plan_hash_mismatch",
        failures,
    )
    return list(dict.fromkeys(failures))


def approval_statement(plan: dict[str, Any], raw_sha256: str) -> str:
    proposed = plan["proposed_identity"]
    source = plan["source_binding"]
    return (
        "I authorize provisioning exactly one controlled-beta J1-D mentor signing identity "
        f"from plan artifact {raw_sha256}, canonical plan {plan['plan_sha256']}, on SoftHSM "
        f"token {proposed['token_label']} using key label {proposed['key_label']} and key ID "
        f"{proposed['key_id_hex']}, bound to reviewed execution design "
        f"{source['reviewed_design_sha256']} and participant identity set "
        f"{source['participant_identity_set_sha256']}. I acknowledge SoftHSM is not a physical "
        "HSM or production custody. This authorization permits only one sensitive, "
        "non-extractable Ed25519 keypair, possession proof, and private identity profile; it "
        "does not authorize treatment-advice signing, provider or model calls, Agent execution, "
        "Backend Fact append, or Ledger append."
    )


def _validate_sources(**values: Any) -> None:
    design = values["reviewed_design"]
    gate = values["design_gate"]
    reviewer = values["reviewer"]
    report = values["participant_report"]
    profiles = values["profiles"]
    failures = validate_reviewer_identity_profile(reviewer)
    for profile in profiles:
        failures.extend(validate_participant_profile(profile))
    profile_hashes = sorted(profile.get("profile_sha256") for profile in profiles)
    participant_dids = {profile["participant"]["execution_did"] for profile in profiles}
    public_keys = {profile["participant"]["public_key_hex"] for profile in profiles}
    key_labels = {profile["pkcs11_key"]["key_label"] for profile in profiles}
    key_ids = {profile["pkcs11_key"]["key_id_hex"] for profile in profiles}
    if not (
        gate.get("passed") is True
        and gate.get("failure_reasons") == []
        and gate.get("reviewed_design_sha256") == design.get("reviewed_design_sha256")
        and gate.get("readiness", {}).get("execution_design_bound") is True
        and gate.get("artifacts", {}).get("reviewed_design")
        == _artifact_bytes(
            values["reviewed_design_path"], values["reviewed_design_raw"]
        )
        and report.get("passed") is True
        and report.get("participant_count") == 40
        and sorted(report.get("participant_profile_sha256", [])) == profile_hashes
        and Path(str(report.get("profiles_root"))).resolve()
        == values["participant_profiles_root"].resolve()
        and len(profiles)
        == len(participant_dids)
        == len(public_keys)
        == len(key_labels)
        == len(key_ids)
        == 40
        and values["key_label"] not in key_labels
        and values["key_id_hex"] not in key_ids
        and reviewer["reviewer"]["did"] not in participant_dids
        and reviewer["reviewer"]["public_key_hex"] not in public_keys
        and values["key_label"] != reviewer["pkcs11_key"]["key_label"]
        and values["key_id_hex"] != reviewer["pkcs11_key"]["key_id_hex"]
        and report.get("pkcs11_boundary", {}).get("module_path")
        == values["module_path"]
        and report.get("pkcs11_boundary", {}).get("module_sha256")
        == values["module_sha256"]
        and report.get("pkcs11_boundary", {}).get("token_label")
        == values["token_label"]
    ):
        failures.append("mentor_identity_source_chain_invalid")
    if failures:
        raise ValueError(
            f"mentor identity source invalid: {list(dict.fromkeys(failures))}"
        )


def _load_participant_profiles(root: Path) -> list[dict[str, Any]]:
    if root.is_symlink() or not root.is_dir() or root.stat().st_mode & 0o077:
        raise ValueError(f"participant profiles root invalid: {root}")
    paths = sorted(root.glob("*.json"))
    if len(paths) != 40:
        raise ValueError(f"expected 40 participant profiles, found {len(paths)}")
    return [_read_private(path)[0] for path in paths]


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


def _key_id(value: str) -> bytes:
    if not _variable_hex(value):
        raise ValueError("key ID must be even-length hexadecimal")
    return bytes.fromhex(value)


def _variable_hex(value: Any) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and len(value) % 2 == 0
        and all(char in "0123456789abcdef" for char in value.lower())
    )


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(char in "0123456789abcdef" for char in value.lower())
    )


def _object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _rfc3339(value: Any) -> bool:
    if not _text(value):
        return False
    try:
        return (
            datetime.fromisoformat(str(value).replace("Z", "+00:00")).tzinfo is not None
        )
    except ValueError:
        return False


def _require(condition: bool, failure: str, failures: list[str]) -> None:
    if not condition and failure not in failures:
        failures.append(failure)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan-id", required=True)
    parser.add_argument("--reviewed-design", type=Path, required=True)
    parser.add_argument("--design-gate", type=Path, required=True)
    parser.add_argument("--reviewer-profile", type=Path, required=True)
    parser.add_argument("--participant-provisioning-report", type=Path, required=True)
    parser.add_argument("--participant-profiles-root", type=Path, required=True)
    parser.add_argument("--module", default=DEFAULT_MODULE)
    parser.add_argument("--token-label", required=True)
    parser.add_argument("--key-label", required=True)
    parser.add_argument("--key-id", required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = prepare_mentor_identity_plan(
            plan_id=args.plan_id,
            created_at=datetime.now(timezone.utc).isoformat(),
            reviewed_design_path=args.reviewed_design,
            design_gate_path=args.design_gate,
            reviewer_profile_path=args.reviewer_profile,
            participant_provisioning_report_path=args.participant_provisioning_report,
            participant_profiles_root=args.participant_profiles_root,
            module_path=args.module,
            token_label=args.token_label,
            key_label=args.key_label,
            key_id_hex=args.key_id,
            output_root=args.output_root,
        )
    except (
        OSError,
        ValueError,
        KeyError,
        json.JSONDecodeError,
        pkcs11.PKCS11Error,
    ) as error:
        report = {
            "schema_version": REPORT_SCHEMA,
            "passed": False,
            "state": "blocked_mentor_identity_preflight",
            "error_class": type(error).__name__,
            "error": str(error),
            "pin_read": False,
            "token_login_attempted": False,
            "key_generation_performed": False,
            "provider_api_call_performed": False,
            "model_invocation_performed": False,
        }
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
        return 1
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
