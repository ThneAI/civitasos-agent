#!/usr/bin/env python3
"""Record Beta-6 external Agent invitation and registration evidence.

This gate introduces an external Agent as an explicit L1 participant. It records
operator invitation and observed registration artifacts, but it does not assign
tasks, start runtime, grant merge/deploy authority, execute production actions,
or write production receipts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


INVITATION_SCHEMA = "beta6-external-agent-invitation:v1"
INVITATION_VALIDATION_SCHEMA = "beta6-external-agent-invitation-validation:v1"
INVITATION_WRITE_SCHEMA = "beta6-external-agent-invitation-write-report:v1"
AGENT_CARD_SCHEMA = "beta6-external-agent-card:v1"
REGISTRATION_SCHEMA = "beta6-external-agent-registration:v1"
REGISTRATION_VALIDATION_SCHEMA = "beta6-external-agent-registration-validation:v1"
REGISTRATION_WRITE_SCHEMA = "beta6-external-agent-registration-write-report:v1"
AGENT_KINDS = ("ai_agent", "human_operator", "service_agent")
ALLOWED_SCOPES = ("proposal_only", "review_only", "audit_observation", "l1_controlled_message")
FORBIDDEN_TOKENS = ("TODO", "REPLACE", "PLACEHOLDER", "TEMPLATE_ONLY")
NON_CLAIMS = (
    "beta6_external_agent_onboarding_is_l1_controlled_pilot_only",
    "beta6_external_agent_onboarding_does_not_assign_tasks",
    "beta6_external_agent_onboarding_does_not_grant_merge_or_deploy_authority",
    "beta6_external_agent_onboarding_does_not_start_runtime_or_llm",
    "beta6_external_agent_onboarding_does_not_claim_h3_production_readiness",
    "beta6_external_agent_onboarding_does_not_write_production_receipts",
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    invite = subparsers.add_parser("record-invitation", help="record external Agent invitation")
    invite.add_argument("--external-agent-id", required=True)
    invite.add_argument("--display-name", required=True)
    invite.add_argument("--agent-kind", choices=AGENT_KINDS, required=True)
    invite.add_argument("--capability", action="append", required=True)
    invite.add_argument("--allowed-scope", action="append", choices=ALLOWED_SCOPES, required=True)
    invite.add_argument("--contact-ref", required=True)
    invite.add_argument("--reason", required=True)
    invite.add_argument("--output", required=True)
    invite.add_argument("--operator-id", default="external-agent-registrar-001")
    invite.add_argument("--expires-at")

    validate_invitation_cmd = subparsers.add_parser("validate-invitation", help="validate invitation")
    validate_invitation_cmd.add_argument("--invitation", required=True)
    validate_invitation_cmd.add_argument("--output")

    register = subparsers.add_parser("record-registration", help="record observed external Agent registration")
    register.add_argument("--invitation", required=True)
    register.add_argument("--agent-card", required=True)
    register.add_argument("--attestation-ref", required=True)
    register.add_argument("--output", required=True)
    register.add_argument("--observer-actor-id", default="external-agent-observer-001")

    validate_registration_cmd = subparsers.add_parser("validate-registration", help="validate registration")
    validate_registration_cmd.add_argument("--registration", required=True)
    validate_registration_cmd.add_argument("--output")

    args = parser.parse_args(argv)
    if args.command == "record-invitation":
        report = record_invitation(
            external_agent_id=args.external_agent_id,
            display_name=args.display_name,
            agent_kind=args.agent_kind,
            capabilities=args.capability,
            allowed_scopes=args.allowed_scope,
            contact_ref=args.contact_ref,
            reason=args.reason,
            output_path=Path(args.output),
            operator_id=args.operator_id,
            expires_at=args.expires_at,
        )
    elif args.command == "validate-invitation":
        report = validate_invitation(Path(args.invitation))
        if args.output:
            _write_json(Path(args.output), report)
    elif args.command == "record-registration":
        report = record_registration(
            invitation_path=Path(args.invitation),
            agent_card_path=Path(args.agent_card),
            attestation_ref=args.attestation_ref,
            observer_actor_id=args.observer_actor_id,
            output_path=Path(args.output),
        )
    elif args.command == "validate-registration":
        report = validate_registration(Path(args.registration))
        if args.output:
            _write_json(Path(args.output), report)
    else:
        raise AssertionError(f"unknown command: {args.command}")
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report.get("validation", report).get("passed") else 1


def record_invitation(
    *,
    external_agent_id: str,
    display_name: str,
    agent_kind: str,
    capabilities: list[str],
    allowed_scopes: list[str],
    contact_ref: str,
    reason: str,
    output_path: Path,
    operator_id: str,
    expires_at: str | None,
) -> dict[str, Any]:
    failures: list[str] = []
    external_agent_id = _required_text(external_agent_id, "external_agent_id")
    display_name = _required_text(display_name, "display_name")
    contact_ref = _required_text(contact_ref, "contact_ref")
    reason = _required_text(reason, "reason")
    operator_id = _required_text(operator_id, "operator_id")
    if agent_kind not in AGENT_KINDS:
        failures.append(f"agent_kind must be one of {list(AGENT_KINDS)}")
    normalized_capabilities = _normalized_text_list(capabilities, "capability", failures)
    normalized_scopes = _normalized_scopes(allowed_scopes, failures)
    expiry = expires_at.strip() if isinstance(expires_at, str) and expires_at.strip() else (
        datetime.now(timezone.utc) + timedelta(days=7)
    ).isoformat()
    _parse_future_time(expiry, "expires_at", failures)
    _reject_forbidden_text(
        [external_agent_id, display_name, contact_ref, reason, operator_id, *normalized_capabilities],
        failures,
    )
    if failures:
        raise ValueError(f"external Agent invitation blocked: {failures}")

    invitation = {
        "schema_version": INVITATION_SCHEMA,
        "recorded_at": _now(),
        "authorization_scope": "external_agent_invitation_only",
        "operator_id": operator_id,
        "reason": reason,
        "external_agent_id": external_agent_id,
        "display_name": display_name,
        "agent_kind": agent_kind,
        "capabilities": normalized_capabilities,
        "allowed_scopes": normalized_scopes,
        "contact_ref": contact_ref,
        "expires_at": expiry,
        "registration_observed": False,
        "controlled_task_invitation_allowed": False,
        "direct_task_execution_allowed": False,
        "merge_allowed": False,
        "deploy_allowed": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
        "h3_boundary": _h3_boundary(),
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(output_path, invitation)
    validation = validate_invitation(output_path)
    if validation["passed"] is not True:
        raise ValueError(f"written external Agent invitation failed validation: {validation['failure_reasons']}")
    return {
        "schema_version": INVITATION_WRITE_SCHEMA,
        "invitation_written": True,
        "invitation_path": str(output_path.resolve()),
        "invitation_sha256": _sha256(output_path),
        "external_agent_id": external_agent_id,
        "validation": validation,
        "non_claims": list(NON_CLAIMS),
    }


def validate_invitation(path: Path) -> dict[str, Any]:
    failures: list[str] = []
    invitation = _safe_read_json(path, failures, "external Agent invitation")
    if not isinstance(invitation, dict):
        return _invitation_validation_report(path, failures or ["external Agent invitation must be an object"])
    _validate_invitation_shape(invitation, failures)
    return _invitation_validation_report(path, failures)


def record_registration(
    *,
    invitation_path: Path,
    agent_card_path: Path,
    attestation_ref: str,
    observer_actor_id: str,
    output_path: Path,
) -> dict[str, Any]:
    failures: list[str] = []
    invitation = _load_valid_invitation(invitation_path, failures)
    agent_card = _load_agent_card(agent_card_path, failures)
    attestation_ref = _required_text(attestation_ref, "attestation_ref")
    observer_actor_id = _required_text(observer_actor_id, "observer_actor_id")
    _validate_agent_card_matches_invitation(agent_card, invitation, failures)
    _reject_forbidden_text([attestation_ref, observer_actor_id], failures)
    if failures:
        raise ValueError(f"external Agent registration blocked: {failures}")

    registration = {
        "schema_version": REGISTRATION_SCHEMA,
        "recorded_at": _now(),
        "registration_scope": "external_agent_l1_controlled_pilot_registration_only",
        "observer_actor_id": observer_actor_id,
        "attestation_ref": attestation_ref,
        "source_invitation": _artifact_ref(invitation_path),
        "source_agent_card": _artifact_ref(agent_card_path),
        "external_agent_id": invitation["external_agent_id"],
        "display_name": invitation["display_name"],
        "agent_kind": invitation["agent_kind"],
        "capabilities": invitation["capabilities"],
        "allowed_scopes": invitation["allowed_scopes"],
        "contact_ref": invitation["contact_ref"],
        "registration_observed": True,
        "controlled_task_invitation_allowed": True,
        "direct_task_execution_allowed": False,
        "merge_allowed": False,
        "deploy_allowed": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
        "h3_boundary": _h3_boundary(),
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(output_path, registration)
    validation = validate_registration(output_path)
    if validation["passed"] is not True:
        raise ValueError(f"written external Agent registration failed validation: {validation['failure_reasons']}")
    return {
        "schema_version": REGISTRATION_WRITE_SCHEMA,
        "registration_written": True,
        "registration_path": str(output_path.resolve()),
        "registration_sha256": _sha256(output_path),
        "external_agent_id": invitation["external_agent_id"],
        "validation": validation,
        "non_claims": list(NON_CLAIMS),
    }


def validate_registration(path: Path) -> dict[str, Any]:
    failures: list[str] = []
    registration = _safe_read_json(path, failures, "external Agent registration")
    if not isinstance(registration, dict):
        return _registration_validation_report(path, failures or ["external Agent registration must be an object"])
    if registration.get("schema_version") != REGISTRATION_SCHEMA:
        failures.append(f"schema_version must be {REGISTRATION_SCHEMA}")
    if registration.get("registration_scope") != "external_agent_l1_controlled_pilot_registration_only":
        failures.append("registration_scope must be external_agent_l1_controlled_pilot_registration_only")
    for field in ("observer_actor_id", "attestation_ref", "external_agent_id", "display_name", "contact_ref"):
        if not _text(registration.get(field)):
            failures.append(f"{field} must be a non-empty string")
    invitation_ref = _as_ref(registration.get("source_invitation"), failures, "source_invitation")
    invitation_path = _validate_ref_bytes(invitation_ref, failures, "source_invitation")
    invitation = _load_valid_invitation(invitation_path, failures)
    card_ref = _as_ref(registration.get("source_agent_card"), failures, "source_agent_card")
    card_path = _validate_ref_bytes(card_ref, failures, "source_agent_card")
    agent_card = _load_agent_card(card_path, failures)
    _validate_agent_card_matches_invitation(agent_card, invitation, failures)
    for field in ("external_agent_id", "display_name", "agent_kind", "capabilities", "allowed_scopes", "contact_ref"):
        if registration.get(field) != invitation.get(field):
            failures.append(f"{field} must match source invitation")
    if registration.get("registration_observed") is not True:
        failures.append("registration_observed must be true")
    if registration.get("controlled_task_invitation_allowed") is not True:
        failures.append("controlled_task_invitation_allowed must be true")
    if registration.get("direct_task_execution_allowed") is not False:
        failures.append("direct_task_execution_allowed must be false")
    _validate_no_merge_deploy_production(registration, failures)
    _validate_h3_boundary(registration, failures)
    return _registration_validation_report(path, failures)


def _validate_invitation_shape(invitation: dict[str, Any], failures: list[str]) -> None:
    if invitation.get("schema_version") != INVITATION_SCHEMA:
        failures.append(f"schema_version must be {INVITATION_SCHEMA}")
    if invitation.get("authorization_scope") != "external_agent_invitation_only":
        failures.append("authorization_scope must be external_agent_invitation_only")
    for field in ("operator_id", "reason", "external_agent_id", "display_name", "contact_ref", "expires_at"):
        if not _text(invitation.get(field)):
            failures.append(f"{field} must be a non-empty string")
    if invitation.get("agent_kind") not in AGENT_KINDS:
        failures.append(f"agent_kind must be one of {list(AGENT_KINDS)}")
    capabilities = _normalized_text_list(_string_list(invitation.get("capabilities")), "capability", failures)
    scopes = _normalized_scopes(_string_list(invitation.get("allowed_scopes")), failures)
    if invitation.get("capabilities") != capabilities:
        failures.append("capabilities must be sorted unique non-empty strings")
    if invitation.get("allowed_scopes") != scopes:
        failures.append("allowed_scopes must be sorted unique supported scopes")
    _parse_future_time(_text(invitation.get("expires_at")), "expires_at", failures)
    if invitation.get("registration_observed") is not False:
        failures.append("registration_observed must be false in invitation")
    if invitation.get("controlled_task_invitation_allowed") is not False:
        failures.append("controlled_task_invitation_allowed must be false in invitation")
    if invitation.get("direct_task_execution_allowed") is not False:
        failures.append("direct_task_execution_allowed must be false")
    _reject_forbidden_text(
        [
            _text(invitation.get("operator_id")),
            _text(invitation.get("reason")),
            _text(invitation.get("external_agent_id")),
            _text(invitation.get("display_name")),
            _text(invitation.get("contact_ref")),
            *capabilities,
        ],
        failures,
    )
    _validate_no_merge_deploy_production(invitation, failures)
    _validate_h3_boundary(invitation, failures)


def _load_valid_invitation(path: Path | None, failures: list[str]) -> dict[str, Any]:
    if path is None:
        return {}
    validation = validate_invitation(path)
    if validation.get("passed") is not True:
        failures.extend(f"external Agent invitation invalid: {reason}" for reason in validation.get("failure_reasons", []))
    invitation = _safe_read_json(path, failures, "external Agent invitation")
    return invitation if isinstance(invitation, dict) else {}


def _load_agent_card(path: Path | None, failures: list[str]) -> dict[str, Any]:
    card = _safe_read_json(path, failures, "external Agent card")
    if not isinstance(card, dict):
        return {}
    if card.get("schema_version") != AGENT_CARD_SCHEMA:
        failures.append(f"external Agent card schema_version must be {AGENT_CARD_SCHEMA}")
    for field in ("agent_id", "display_name", "agent_kind", "contact_ref"):
        if not _text(card.get(field)):
            failures.append(f"external Agent card {field} must be a non-empty string")
    if card.get("agent_kind") not in AGENT_KINDS:
        failures.append(f"external Agent card agent_kind must be one of {list(AGENT_KINDS)}")
    capabilities = _normalized_text_list(_string_list(card.get("capabilities")), "agent_card.capability", failures)
    if card.get("capabilities") != capabilities:
        failures.append("external Agent card capabilities must be sorted unique non-empty strings")
    _reject_forbidden_text(
        [
            _text(card.get("agent_id")),
            _text(card.get("display_name")),
            _text(card.get("contact_ref")),
            *capabilities,
        ],
        failures,
    )
    return card


def _validate_agent_card_matches_invitation(
    agent_card: dict[str, Any],
    invitation: dict[str, Any],
    failures: list[str],
) -> None:
    for card_field, invite_field in (
        ("agent_id", "external_agent_id"),
        ("display_name", "display_name"),
        ("agent_kind", "agent_kind"),
        ("capabilities", "capabilities"),
        ("contact_ref", "contact_ref"),
    ):
        if agent_card.get(card_field) != invitation.get(invite_field):
            failures.append(f"external Agent card {card_field} must match invitation {invite_field}")


def _normalized_scopes(scopes: list[str], failures: list[str]) -> list[str]:
    normalized = _normalized_text_list(scopes, "allowed_scope", failures)
    for scope in normalized:
        if scope not in ALLOWED_SCOPES:
            failures.append(f"allowed_scope must be one of {list(ALLOWED_SCOPES)}")
    return sorted(normalized)


def _normalized_text_list(values: list[str], label: str, failures: list[str]) -> list[str]:
    normalized: list[str] = []
    for raw in values:
        value = _text(raw)
        if not value:
            failures.append(f"{label} must contain non-empty strings")
            continue
        if value not in normalized:
            normalized.append(value)
    if not normalized:
        failures.append(f"{label} must not be empty")
    return sorted(normalized)


def _string_list(value: Any) -> list[str]:
    return [item for item in value if isinstance(item, str)] if isinstance(value, list) else []


def _parse_future_time(value: str, field: str, failures: list[str]) -> None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        failures.append(f"{field} must be an ISO-8601 timestamp")
        return
    if parsed.tzinfo is None:
        failures.append(f"{field} must include timezone")
        return
    if parsed <= datetime.now(timezone.utc):
        failures.append(f"{field} must be in the future")


def _reject_forbidden_text(values: list[str], failures: list[str]) -> None:
    upper_values = [value.upper() for value in values if value]
    for token in FORBIDDEN_TOKENS:
        if any(token in value for value in upper_values):
            failures.append(f"forbidden placeholder token found: {token}")
            return


def _validate_no_merge_deploy_production(payload: dict[str, Any], failures: list[str]) -> None:
    for field in (
        "merge_allowed",
        "deploy_allowed",
        "production_runtime_execution_allowed",
        "production_receipt_write_allowed",
    ):
        if payload.get(field) is not False:
            failures.append(f"{field} must be false")


def _h3_boundary() -> dict[str, bool]:
    return {
        "h3_remains_blocked": True,
        "h3_production_readiness_claimed": False,
    }


def _validate_h3_boundary(payload: dict[str, Any], failures: list[str]) -> None:
    if payload.get("h3_boundary") != _h3_boundary():
        failures.append("h3_boundary must keep production readiness blocked")


def _invitation_validation_report(path: Path, failures: list[str]) -> dict[str, Any]:
    return {
        "schema_version": INVITATION_VALIDATION_SCHEMA,
        "passed": not failures,
        "failure_reasons": failures,
        "checked_at": _now(),
        "invitation_path": str(path.resolve()),
        "invitation_sha256": _sha256(path) if path.is_file() else None,
        "non_claims": list(NON_CLAIMS),
    }


def _registration_validation_report(path: Path, failures: list[str]) -> dict[str, Any]:
    return {
        "schema_version": REGISTRATION_VALIDATION_SCHEMA,
        "passed": not failures,
        "failure_reasons": failures,
        "checked_at": _now(),
        "registration_path": str(path.resolve()),
        "registration_sha256": _sha256(path) if path.is_file() else None,
        "non_claims": list(NON_CLAIMS),
    }


def _artifact_ref(path: Path) -> dict[str, str]:
    if not path.is_file():
        raise FileNotFoundError(f"artifact path is not a file: {path}")
    return {"path": str(path.resolve()), "sha256": _sha256(path)}


def _validate_ref_bytes(ref: dict[str, Any], failures: list[str], label: str) -> Path | None:
    path_text = _text(ref.get("path"))
    if not path_text:
        failures.append(f"{label}.path must be a non-empty string")
        return None
    path = Path(path_text)
    if not path.is_file():
        failures.append(f"{label}.path is not a file: {path}")
        return None
    if ref.get("sha256") != _sha256(path):
        failures.append(f"{label}.sha256 does not match file bytes")
    return path


def _as_ref(value: Any, failures: list[str], label: str) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    failures.append(f"{label} must be an object")
    return {}


def _safe_read_json(path: Path | None, failures: list[str], label: str) -> Any:
    if path is None:
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 - validators preserve artifact detail.
        failures.append(f"{label} could not be read: {exc}")
        return None
    if not isinstance(payload, dict):
        failures.append(f"{label} must be a JSON object")
        return None
    return payload


def _required_text(value: Any, field: str) -> str:
    text = _text(value)
    if not text:
        raise ValueError(f"{field} must be a non-empty string")
    return text


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


if __name__ == "__main__":
    sys.exit(main())
