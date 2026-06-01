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
import ipaddress
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


INVITATION_SCHEMA = "beta6-external-agent-invitation:v1"
INVITATION_VALIDATION_SCHEMA = "beta6-external-agent-invitation-validation:v1"
INVITATION_WRITE_SCHEMA = "beta6-external-agent-invitation-write-report:v1"
AGENT_CARD_SCHEMA = "beta6-external-agent-card:v1"
AGENT_CARD_INTAKE_REPORT_SCHEMA = "beta6-external-agent-card-intake-report:v1"
API_PROBE_REPORT_SCHEMA = "beta6-external-agent-api-probe-report:v1"
REGISTRATION_REQUEST_SCHEMA = "beta6-external-agent-registration-request:v1"
REGISTRATION_REQUEST_VALIDATION_SCHEMA = "beta6-external-agent-registration-request-validation:v1"
REGISTRATION_REQUEST_WRITE_SCHEMA = "beta6-external-agent-registration-request-write-report:v1"
REGISTRATION_SCHEMA = "beta6-external-agent-registration:v1"
REGISTRATION_VALIDATION_SCHEMA = "beta6-external-agent-registration-validation:v1"
REGISTRATION_WRITE_SCHEMA = "beta6-external-agent-registration-write-report:v1"
READINESS_SCHEMA = "beta6-external-agent-onboarding-readiness:v1"
BETA5_FEEDBACK_INDEX_SCHEMA = "beta5-owner-feedback-evidence-index:v1"
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
    invite.add_argument(
        "--readiness",
        help="optional Beta-6 readiness artifact to hash-bind invitation to Beta-5 feedback evidence",
    )

    validate_invitation_cmd = subparsers.add_parser("validate-invitation", help="validate invitation")
    validate_invitation_cmd.add_argument("--invitation", required=True)
    validate_invitation_cmd.add_argument("--output")

    registration_request = subparsers.add_parser(
        "record-registration-request",
        help="write a hash-bound request for external Agent card and attestation",
    )
    registration_request.add_argument("--invitation", required=True)
    registration_request.add_argument("--output", required=True)
    registration_request.add_argument("--requester-id", default="external-agent-registrar-001")

    validate_registration_request_cmd = subparsers.add_parser(
        "validate-registration-request",
        help="validate registration request",
    )
    validate_registration_request_cmd.add_argument("--registration-request", required=True)
    validate_registration_request_cmd.add_argument("--output")

    agent_card = subparsers.add_parser(
        "write-agent-card-from-env",
        help="write a sanitized external Agent card from a local-only API credential env file",
    )
    agent_card.add_argument("--registration-request", required=True)
    agent_card.add_argument("--env-file", required=True)
    agent_card.add_argument("--output", required=True)
    agent_card.add_argument("--report-output")

    api_probe = subparsers.add_parser(
        "probe-external-api-from-env",
        help="probe a sanitized external Agent API card using local-only credentials",
    )
    api_probe.add_argument("--agent-card", required=True)
    api_probe.add_argument("--env-file", required=True)
    api_probe.add_argument("--output", required=True)

    register = subparsers.add_parser("record-registration", help="record observed external Agent registration")
    register.add_argument("--invitation", required=True)
    register.add_argument("--agent-card", required=True)
    register.add_argument("--attestation-ref", required=True)
    register.add_argument("--output", required=True)
    register.add_argument("--observer-actor-id", default="external-agent-observer-001")

    validate_registration_cmd = subparsers.add_parser("validate-registration", help="validate registration")
    validate_registration_cmd.add_argument("--registration", required=True)
    validate_registration_cmd.add_argument("--output")

    readiness_cmd = subparsers.add_parser("validate-readiness", help="validate Beta-6 onboarding readiness from Beta-5 owner feedback index")
    readiness_cmd.add_argument("--feedback-index", required=True)
    readiness_cmd.add_argument("--output")
    readiness_cmd.add_argument("--min-packets", type=int, default=2)
    readiness_cmd.add_argument("--min-accepted-ratio", type=float, default=0.5)

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
            readiness_path=Path(args.readiness) if args.readiness else None,
        )
    elif args.command == "validate-invitation":
        report = validate_invitation(Path(args.invitation))
        if args.output:
            _write_json(Path(args.output), report)
    elif args.command == "record-registration-request":
        report = record_registration_request(
            invitation_path=Path(args.invitation),
            output_path=Path(args.output),
            requester_id=args.requester_id,
        )
    elif args.command == "validate-registration-request":
        report = validate_registration_request(Path(args.registration_request))
        if args.output:
            _write_json(Path(args.output), report)
    elif args.command == "write-agent-card-from-env":
        report = write_agent_card_from_env(
            registration_request_path=Path(args.registration_request),
            env_file_path=Path(args.env_file),
            output_path=Path(args.output),
        )
        if args.report_output:
            _write_json(Path(args.report_output), report)
    elif args.command == "probe-external-api-from-env":
        report = probe_external_api_from_env(
            agent_card_path=Path(args.agent_card),
            env_file_path=Path(args.env_file),
            output_path=Path(args.output),
        )
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
    elif args.command == "validate-readiness":
        report = validate_onboarding_readiness(
            feedback_index_path=Path(args.feedback_index),
            min_packets=args.min_packets,
            min_accepted_ratio=args.min_accepted_ratio,
        )
        if args.output:
            _write_json(Path(args.output), report)
    else:
        raise AssertionError(f"unknown command: {args.command}")
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report.get("validation", report).get("passed") else 1


def validate_onboarding_readiness(
    *,
    feedback_index_path: Path,
    min_packets: int = 2,
    min_accepted_ratio: float = 0.5,
) -> dict[str, Any]:
    failures: list[str] = []
    index = _safe_read_json(feedback_index_path, failures, "Beta-5 owner feedback index")
    if min_packets < 1:
        failures.append("min_packets must be >= 1")
    if not 0 <= min_accepted_ratio <= 1:
        failures.append("min_accepted_ratio must be between 0 and 1")
    if not isinstance(index, dict):
        index = {}
    _validate_feedback_index_shape(index, min_packets, min_accepted_ratio, failures)
    verdict_counts = index.get("verdict_counts") if isinstance(index.get("verdict_counts"), dict) else {}
    followup_count = int(verdict_counts.get("needs_followup", 0) or 0)
    readiness_state = "blocked"
    if not failures:
        readiness_state = "ready_with_owner_followup" if followup_count else "ready"
    return {
        "schema_version": READINESS_SCHEMA,
        "checked_at": _now(),
        "passed": not failures,
        "failure_reasons": failures,
        "readiness_state": readiness_state,
        "controlled_external_agent_invitation_allowed": not failures,
        "owner_followup_required": not failures and followup_count > 0,
        "source_beta5_owner_feedback_index": _artifact_ref(feedback_index_path) if feedback_index_path.is_file() else None,
        "required_min_packets": min_packets,
        "required_min_accepted_ratio": min_accepted_ratio,
        "observed_packet_count": index.get("packet_count"),
        "observed_accepted_ratio": index.get("accepted_ratio"),
        "observed_verdict_counts": verdict_counts,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
        "h3_boundary": _h3_boundary(),
        "non_claims": list(NON_CLAIMS),
    }


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
    readiness_path: Path | None = None,
) -> dict[str, Any]:
    failures: list[str] = []
    readiness = _load_valid_readiness(readiness_path, failures) if readiness_path else {}
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
        "source_onboarding_readiness": _artifact_ref(readiness_path) if readiness_path else None,
        "readiness_state": readiness.get("readiness_state") if readiness else None,
        "owner_followup_required": readiness.get("owner_followup_required") if readiness else None,
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
        "readiness_state": readiness.get("readiness_state") if readiness else None,
        "owner_followup_required": readiness.get("owner_followup_required") if readiness else None,
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


def record_registration_request(
    *,
    invitation_path: Path,
    output_path: Path,
    requester_id: str,
) -> dict[str, Any]:
    failures: list[str] = []
    invitation = _load_valid_invitation(invitation_path, failures)
    requester_id = _required_text(requester_id, "requester_id")
    _reject_forbidden_text([requester_id], failures)
    if failures:
        raise ValueError(f"external Agent registration request blocked: {failures}")

    request = {
        "schema_version": REGISTRATION_REQUEST_SCHEMA,
        "recorded_at": _now(),
        "request_scope": "external_agent_registration_intake_only",
        "requester_id": requester_id,
        "source_invitation": _artifact_ref(invitation_path),
        "expected_agent_card": _expected_agent_card(invitation),
        "required_attestation": {
            "attestation_ref_required": True,
            "observer_actor_id_required": True,
        },
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
    _write_json(output_path, request)
    validation = validate_registration_request(output_path)
    if validation["passed"] is not True:
        raise ValueError(f"written external Agent registration request failed validation: {validation['failure_reasons']}")
    return {
        "schema_version": REGISTRATION_REQUEST_WRITE_SCHEMA,
        "registration_request_written": True,
        "registration_request_path": str(output_path.resolve()),
        "registration_request_sha256": _sha256(output_path),
        "external_agent_id": invitation["external_agent_id"],
        "validation": validation,
        "non_claims": list(NON_CLAIMS),
    }


def validate_registration_request(path: Path) -> dict[str, Any]:
    failures: list[str] = []
    request = _safe_read_json(path, failures, "external Agent registration request")
    if not isinstance(request, dict):
        return _registration_request_validation_report(
            path,
            failures or ["external Agent registration request must be an object"],
        )
    if request.get("schema_version") != REGISTRATION_REQUEST_SCHEMA:
        failures.append(f"schema_version must be {REGISTRATION_REQUEST_SCHEMA}")
    if request.get("request_scope") != "external_agent_registration_intake_only":
        failures.append("request_scope must be external_agent_registration_intake_only")
    if not _text(request.get("requester_id")):
        failures.append("requester_id must be a non-empty string")
    invitation_ref = _as_ref(request.get("source_invitation"), failures, "source_invitation")
    invitation_path = _validate_ref_bytes(invitation_ref, failures, "source_invitation")
    invitation = _load_valid_invitation(invitation_path, failures)
    expected_card = request.get("expected_agent_card")
    if not isinstance(expected_card, dict):
        failures.append("expected_agent_card must be an object")
        expected_card = {}
    if expected_card.get("schema_version") != AGENT_CARD_SCHEMA:
        failures.append(f"expected_agent_card.schema_version must be {AGENT_CARD_SCHEMA}")
    _validate_agent_card_matches_invitation(expected_card, invitation, failures)
    required_attestation = request.get("required_attestation")
    if not isinstance(required_attestation, dict):
        failures.append("required_attestation must be an object")
        required_attestation = {}
    if required_attestation.get("attestation_ref_required") is not True:
        failures.append("required_attestation.attestation_ref_required must be true")
    if required_attestation.get("observer_actor_id_required") is not True:
        failures.append("required_attestation.observer_actor_id_required must be true")
    if request.get("registration_observed") is not False:
        failures.append("registration_observed must be false in registration request")
    if request.get("controlled_task_invitation_allowed") is not False:
        failures.append("controlled_task_invitation_allowed must be false in registration request")
    if request.get("direct_task_execution_allowed") is not False:
        failures.append("direct_task_execution_allowed must be false")
    _reject_forbidden_text(
        [
            _text(request.get("requester_id")),
            _text(expected_card.get("agent_id")),
            _text(expected_card.get("display_name")),
            _text(expected_card.get("contact_ref")),
            *_string_list(expected_card.get("capabilities")),
        ],
        failures,
    )
    _validate_no_merge_deploy_production(request, failures)
    _validate_h3_boundary(request, failures)
    return _registration_request_validation_report(path, failures)


def write_agent_card_from_env(
    *,
    registration_request_path: Path,
    env_file_path: Path,
    output_path: Path,
) -> dict[str, Any]:
    failures: list[str] = []
    request = _load_valid_registration_request(registration_request_path, failures)
    env = _read_env_file(env_file_path, failures)
    base_url = _required_env(env, "BETA6_EXTERNAL_AGENT_API_BASE_URL", failures)
    model = _required_env(env, "BETA6_EXTERNAL_AGENT_MODEL", failures)
    api_key = _required_env(env, "BETA6_EXTERNAL_AGENT_API_KEY", failures)
    provider = _text(env.get("BETA6_EXTERNAL_AGENT_PROVIDER")) or "openai_compatible"
    _reject_forbidden_text([base_url, model, api_key, provider], failures)
    _validate_api_base_url(base_url, env, failures)
    if failures:
        raise ValueError(f"external Agent card intake blocked: {failures}")

    local_http_allowed = _env_flag(env, "BETA6_EXTERNAL_AGENT_ALLOW_LOCAL_HTTP")
    expected_card = request["expected_agent_card"]
    card = dict(expected_card)
    card["external_api"] = {
        "provider": provider,
        "base_url": base_url.rstrip("/"),
        "model": model,
        "credential_source": str(env_file_path.resolve()),
        "api_key_present": True,
        "api_key_redacted": True,
        "local_http_allowed": local_http_allowed,
        "transport_security": "https" if base_url.startswith("https://") else "local_http_opt_in",
    }
    card["non_claims"] = sorted(set(_string_list(card.get("non_claims")) + [
        "external_agent_api_key_is_local_only_and_not_recorded",
        "external_agent_card_does_not_prove_provider_runtime_success",
        "external_agent_card_does_not_authorize_controlled_task_invitation",
    ]))
    _write_json(output_path, card)
    validation_failures: list[str] = []
    _load_agent_card(output_path, validation_failures)
    if _file_contains_secret(output_path, api_key):
        validation_failures.append("agent card must not contain API key bytes")
    if validation_failures:
        raise ValueError(f"written external Agent card failed validation: {validation_failures}")
    return {
        "schema_version": AGENT_CARD_INTAKE_REPORT_SCHEMA,
        "agent_card_written": True,
        "agent_card_path": str(output_path.resolve()),
        "agent_card_sha256": _sha256(output_path),
        "source_registration_request": _artifact_ref(registration_request_path),
        "credential_env_file": str(env_file_path.resolve()),
        "api_key_present": True,
        "api_key_recorded": False,
        "external_api": card["external_api"],
        "non_claims": list(NON_CLAIMS) + [
            "agent_card_intake_does_not_store_api_key",
            "agent_card_intake_does_not_call_external_provider",
        ],
    }


def probe_external_api_from_env(
    *,
    agent_card_path: Path,
    env_file_path: Path,
    output_path: Path,
) -> dict[str, Any]:
    failures: list[str] = []
    card = _load_agent_card(agent_card_path, failures)
    env = _read_env_file(env_file_path, failures)
    base_url = _required_env(env, "BETA6_EXTERNAL_AGENT_API_BASE_URL", failures).rstrip("/")
    model = _required_env(env, "BETA6_EXTERNAL_AGENT_MODEL", failures)
    api_key = _required_env(env, "BETA6_EXTERNAL_AGENT_API_KEY", failures)
    provider = _text(env.get("BETA6_EXTERNAL_AGENT_PROVIDER")) or "openai_compatible"
    _reject_forbidden_text([base_url, model, api_key, provider], failures)
    _validate_api_base_url(base_url, env, failures)
    external_api = card.get("external_api") if isinstance(card.get("external_api"), dict) else {}
    if external_api.get("base_url") != base_url:
        failures.append("agent card external_api.base_url must match env file")
    if external_api.get("model") != model:
        failures.append("agent card external_api.model must match env file")
    if external_api.get("provider") != provider:
        failures.append("agent card external_api.provider must match env file")
    if _file_contains_secret(agent_card_path, api_key):
        failures.append("agent card must not contain API key bytes")

    probe = _probe_models_endpoint(base_url=base_url, api_key=api_key, model=model) if not failures else {
        "provider_probe_attempted": False,
        "reachable": False,
        "http_status": None,
        "models_endpoint": None,
        "requested_model_visible": None,
        "model_count": None,
        "error_class": None,
    }
    if probe.get("reachable") is not True:
        failures.append("external Agent API models endpoint must be reachable")
    if probe.get("http_status") != 200:
        failures.append("external Agent API models endpoint must return HTTP 200")
    if probe.get("requested_model_visible") is not True:
        failures.append("external Agent model must be visible in provider models response")

    report = {
        "schema_version": API_PROBE_REPORT_SCHEMA,
        "checked_at": _now(),
        "passed": not failures,
        "failure_reasons": failures,
        "source_agent_card": _artifact_ref(agent_card_path) if agent_card_path.is_file() else None,
        "credential_env_file": str(env_file_path.resolve()),
        "api_key_present": bool(api_key),
        "api_key_recorded": False,
        "provider": provider,
        "base_url": base_url,
        "model": model,
        "probe": probe,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
        "h3_boundary": _h3_boundary(),
        "non_claims": list(NON_CLAIMS) + [
            "external_agent_api_probe_does_not_store_api_key",
            "external_agent_api_probe_does_not_assign_or_execute_tasks",
            "external_agent_api_probe_does_not_authorize_production_runtime",
        ],
    }
    _write_json(output_path, report)
    if _file_contains_secret(output_path, api_key):
        output = _safe_read_json(output_path, [], "external Agent API probe report")
        failures.append("external Agent API probe report must not contain API key bytes")
        if isinstance(output, dict):
            output["passed"] = False
            output["failure_reasons"] = failures
            _write_json(output_path, output)
            report = output
    return report


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
    readiness_ref = invitation.get("source_onboarding_readiness")
    if readiness_ref is not None:
        readiness_path = _validate_ref_bytes(
            _as_ref(readiness_ref, failures, "source_onboarding_readiness"),
            failures,
            "source_onboarding_readiness",
        )
        readiness = _load_valid_readiness(readiness_path, failures)
        if readiness:
            if invitation.get("readiness_state") != readiness.get("readiness_state"):
                failures.append("readiness_state must match source onboarding readiness")
            if invitation.get("owner_followup_required") != readiness.get("owner_followup_required"):
                failures.append("owner_followup_required must match source onboarding readiness")
    else:
        if invitation.get("readiness_state") is not None:
            failures.append("readiness_state must be null when source_onboarding_readiness is absent")
        if invitation.get("owner_followup_required") is not None:
            failures.append("owner_followup_required must be null when source_onboarding_readiness is absent")
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


def _load_valid_readiness(path: Path | None, failures: list[str]) -> dict[str, Any]:
    if path is None:
        return {}
    readiness = _safe_read_json(path, failures, "Beta-6 onboarding readiness")
    if not isinstance(readiness, dict):
        return {}
    _validate_readiness_artifact_shape(readiness, failures)
    return readiness


def _validate_readiness_artifact_shape(readiness: dict[str, Any], failures: list[str]) -> None:
    if readiness.get("schema_version") != READINESS_SCHEMA:
        failures.append(f"readiness schema_version must be {READINESS_SCHEMA}")
    if readiness.get("passed") is not True:
        failures.append("readiness must have passed=true")
    if readiness.get("controlled_external_agent_invitation_allowed") is not True:
        failures.append("readiness must allow controlled external Agent invitation")
    if readiness.get("readiness_state") not in ("ready", "ready_with_owner_followup"):
        failures.append("readiness_state must be ready or ready_with_owner_followup")
    if not isinstance(readiness.get("owner_followup_required"), bool):
        failures.append("owner_followup_required must be boolean")
    if readiness.get("production_runtime_execution_allowed") is not False:
        failures.append("readiness production_runtime_execution_allowed must be false")
    if readiness.get("production_receipt_write_allowed") is not False:
        failures.append("readiness production_receipt_write_allowed must be false")
    if readiness.get("h3_boundary") != _h3_boundary():
        failures.append("readiness h3_boundary must keep production readiness blocked")
    index_ref = readiness.get("source_beta5_owner_feedback_index")
    if index_ref is None:
        failures.append("readiness source_beta5_owner_feedback_index must be present")
    else:
        _validate_ref_bytes(
            _as_ref(index_ref, failures, "source_beta5_owner_feedback_index"),
            failures,
            "source_beta5_owner_feedback_index",
        )


def _expected_agent_card(invitation: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": AGENT_CARD_SCHEMA,
        "agent_id": invitation["external_agent_id"],
        "display_name": invitation["display_name"],
        "agent_kind": invitation["agent_kind"],
        "capabilities": invitation["capabilities"],
        "contact_ref": invitation["contact_ref"],
        "non_claims": [
            "external_agent_card_does_not_authorize_task_execution",
            "external_agent_card_does_not_authorize_merge_or_deploy",
            "external_agent_card_does_not_authorize_production_runtime",
        ],
    }


def _validate_feedback_index_shape(
    index: dict[str, Any],
    min_packets: int,
    min_accepted_ratio: float,
    failures: list[str],
) -> None:
    if index.get("schema_version") != BETA5_FEEDBACK_INDEX_SCHEMA:
        failures.append(f"feedback index schema_version must be {BETA5_FEEDBACK_INDEX_SCHEMA}")
    if index.get("passed") is not True:
        failures.append("feedback index must have passed=true")
    packet_count = index.get("packet_count")
    if not isinstance(packet_count, int):
        failures.append("feedback index packet_count must be an integer")
    elif packet_count < min_packets:
        failures.append(f"feedback index packet_count {packet_count} below required {min_packets}")
    accepted_ratio = index.get("accepted_ratio")
    if not isinstance(accepted_ratio, int | float):
        failures.append("feedback index accepted_ratio must be numeric")
    elif accepted_ratio < min_accepted_ratio:
        failures.append(f"feedback index accepted_ratio {accepted_ratio} below required {min_accepted_ratio}")
    verdict_counts = index.get("verdict_counts")
    if not isinstance(verdict_counts, dict):
        failures.append("feedback index verdict_counts must be an object")
    else:
        if int(verdict_counts.get("rejected", 0) or 0) > 0:
            failures.append("feedback index must not contain rejected owner feedback")
    if index.get("production_deploy_allowed") is not False:
        failures.append("feedback index production_deploy_allowed must be false")
    for field in ("production_runtime_execution_allowed", "production_receipt_write_allowed", "h3_production_readiness_claimed"):
        if index.get(field) is not False:
            failures.append(f"feedback index {field} must be false")
    if index.get("h3_boundary") != _h3_boundary():
        failures.append("feedback index h3_boundary must keep production readiness blocked")


def _load_valid_invitation(path: Path | None, failures: list[str]) -> dict[str, Any]:
    if path is None:
        return {}
    validation = validate_invitation(path)
    if validation.get("passed") is not True:
        failures.extend(f"external Agent invitation invalid: {reason}" for reason in validation.get("failure_reasons", []))
    invitation = _safe_read_json(path, failures, "external Agent invitation")
    return invitation if isinstance(invitation, dict) else {}


def _load_valid_registration_request(path: Path | None, failures: list[str]) -> dict[str, Any]:
    if path is None:
        return {}
    validation = validate_registration_request(path)
    if validation.get("passed") is not True:
        failures.extend(
            f"external Agent registration request invalid: {reason}"
            for reason in validation.get("failure_reasons", [])
        )
    request = _safe_read_json(path, failures, "external Agent registration request")
    return request if isinstance(request, dict) else {}


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


def _env_flag(env: dict[str, str], key: str) -> bool:
    return _text(env.get(key)).lower() in {"1", "true", "yes", "on"}


def _validate_api_base_url(base_url: str, env: dict[str, str], failures: list[str]) -> None:
    parsed = urllib.parse.urlparse(base_url)
    if parsed.scheme == "https":
        return
    if parsed.scheme == "http" and _env_flag(env, "BETA6_EXTERNAL_AGENT_ALLOW_LOCAL_HTTP"):
        if _is_loopback_or_private_host(parsed.hostname):
            return
        failures.append("BETA6_EXTERNAL_AGENT_API_BASE_URL local HTTP opt-in only allows loopback/private hosts")
        return
    failures.append(
        "BETA6_EXTERNAL_AGENT_API_BASE_URL must use https:// unless "
        "BETA6_EXTERNAL_AGENT_ALLOW_LOCAL_HTTP=true and host is loopback/private"
    )


def _is_loopback_or_private_host(host: str | None) -> bool:
    if not host:
        return False
    if host.lower() == "localhost":
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_loopback or ip.is_private


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


def _registration_request_validation_report(path: Path, failures: list[str]) -> dict[str, Any]:
    return {
        "schema_version": REGISTRATION_REQUEST_VALIDATION_SCHEMA,
        "passed": not failures,
        "failure_reasons": failures,
        "checked_at": _now(),
        "registration_request_path": str(path.resolve()),
        "registration_request_sha256": _sha256(path) if path.is_file() else None,
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


def _read_env_file(path: Path, failures: list[str]) -> dict[str, str]:
    if not path.is_file():
        failures.append(f"env file is not a file: {path}")
        return {}
    env: dict[str, str] = {}
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            failures.append(f"env file line {line_number} must be KEY=VALUE")
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip("'\"")
        if not key:
            failures.append(f"env file line {line_number} has empty key")
            continue
        env[key] = value
    return env


def _required_env(env: dict[str, str], key: str, failures: list[str]) -> str:
    value = _text(env.get(key))
    if not value:
        failures.append(f"{key} must be set in env file")
    return value


def _file_contains_secret(path: Path, secret: str) -> bool:
    if not secret:
        return False
    return secret.encode("utf-8") in path.read_bytes()


def _probe_models_endpoint(*, base_url: str, api_key: str, model: str) -> dict[str, Any]:
    urls = [base_url.rstrip("/") + "/models"]
    if not base_url.rstrip("/").endswith("/v1"):
        urls.append(base_url.rstrip("/") + "/v1/models")
    result: dict[str, Any] = {
        "provider_probe_attempted": True,
        "reachable": False,
        "http_status": None,
        "models_endpoint": None,
        "requested_model_visible": None,
        "model_count": None,
        "error_class": None,
    }
    for url in urls:
        request = urllib.request.Request(url, headers={"Authorization": f"Bearer {api_key}"})
        try:
            with urllib.request.urlopen(request, timeout=12) as response:
                body = response.read(512 * 1024)
                model_ids = _extract_model_ids(body)
                result.update(
                    {
                        "reachable": True,
                        "http_status": response.status,
                        "models_endpoint": url,
                        "requested_model_visible": model in model_ids,
                        "model_count": len(model_ids),
                        "error_class": None,
                    }
                )
                return result
        except urllib.error.HTTPError as exc:
            result.update({"http_status": exc.code, "models_endpoint": url, "error_class": "HTTPError"})
            if exc.code not in (404, 405):
                return result
        except Exception as exc:  # noqa: BLE001 - operator-facing probe preserves failure class only.
            result.update({"models_endpoint": url, "error_class": exc.__class__.__name__})
            return result
    return result


def _extract_model_ids(body: bytes) -> list[str]:
    try:
        payload = json.loads(body.decode("utf-8"))
    except Exception:  # noqa: BLE001 - malformed provider body means no visible models.
        return []
    data = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(data, list):
        return []
    return [item["id"] for item in data if isinstance(item, dict) and isinstance(item.get("id"), str)]


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
