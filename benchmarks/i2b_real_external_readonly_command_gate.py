"""Run I.2-B real external Agent read-only command gate.

This gate is the first real external Agent command after I.2-A. It is still
bounded to a read-only review command: the external provider may be called, but
source writes, Git operations, runtime mutation, external system writes,
deployment, and production transition remain forbidden.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

CHAIN_SCHEMA = "i2b-real-external-readonly-command-chain:v1"
OPERATOR_REVIEW_SCHEMA = "i2b-operator-review:v1"
REGISTRATION_SCHEMA = "i2b-real-external-agent-registration-receipt:v1"
AUTHORIZATION_SCHEMA = "i2b-scoped-command-authorization:v1"
PREFLIGHT_SCHEMA = "i2b-isolation-preflight:v1"
API_CALL_SCHEMA = "i2b-real-external-agent-api-call-report:v1"
ACCEPTANCE_SCHEMA = "i2b-real-external-agent-acceptance-receipt:v1"
EXECUTION_SCHEMA = "i2b-command-execution-receipt:v1"
ROLLBACK_SCHEMA = "i2b-rollback-or-abort-receipt:v1"
RECONCILIATION_SCHEMA = "i2b-operator-reconciliation:v1"
RESPONSE_SCHEMA = "i2b-external-agent-command-response:v1"

DEFAULT_ENV_FILE = ".env.beta6.external.local"
DEFAULT_OBJECTIVE = (
    "Review the I.2-A controlled command protocol smoke artifact and decide "
    "whether it is safe to proceed beyond protocol smoke. Return only a bounded "
    "read-only JSON receipt."
)
ALLOWED_ACTIONS = [
    "read_hash_bound_i2a_summary",
    "call_configured_provider_chat_completion_api",
    "write_receipts_under_run_root",
]
FORBIDDEN_ACTIONS = [
    "source_tree_write",
    "git_write",
    "git_push",
    "external_system_write",
    "runtime_state_mutation",
    "credential_exfiltration",
    "deploy",
    "production_transition",
]


def run_gate(
    *,
    i2a_summary_path: Path,
    env_file: Path,
    output_root: Path,
    operator_id: str = "operator-cc",
    executor_alias: str = "deepseek-api-agent",
    objective: str = DEFAULT_OBJECTIVE,
    expiry_minutes: int = 30,
    max_tokens: int = 2000,
    temperature: float = 0.0,
    api_response_override: str | None = None,
) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "operator_review": output_root / "i2b_operator_review.json",
        "registration": output_root / "i2b_real_external_agent_registration_receipt.json",
        "authorization": output_root / "i2b_scoped_command_authorization.json",
        "preflight": output_root / "i2b_isolation_preflight.json",
        "api_call": output_root / "i2b_real_external_agent_api_call_report.json",
        "acceptance": output_root / "i2b_real_external_agent_acceptance_receipt.json",
        "execution": output_root / "i2b_command_execution_receipt.json",
        "rollback_or_abort": output_root / "i2b_rollback_or_abort_receipt.json",
        "reconciliation": output_root / "i2b_operator_reconciliation.json",
        "summary": output_root / "i2b_chain_summary.json",
    }

    review = write_operator_review(
        i2a_summary_path=i2a_summary_path,
        output=artifacts["operator_review"],
        operator_id=operator_id,
    )
    registration = write_registration(
        operator_review_path=artifacts["operator_review"],
        env_file=env_file,
        output=artifacts["registration"],
        executor_alias=executor_alias,
    )
    authorization = write_authorization(
        operator_review_path=artifacts["operator_review"],
        registration_path=artifacts["registration"],
        output=artifacts["authorization"],
        objective=objective,
        expiry_minutes=expiry_minutes,
        i2a_summary_path=i2a_summary_path,
    )
    preflight = write_preflight(
        authorization_path=artifacts["authorization"],
        registration_path=artifacts["registration"],
        env_file=env_file,
        output=artifacts["preflight"],
    )
    api_call = write_api_call_report(
        authorization_path=artifacts["authorization"],
        registration_path=artifacts["registration"],
        preflight_path=artifacts["preflight"],
        env_file=env_file,
        output=artifacts["api_call"],
        response_output=output_root / "i2b_external_agent_response.json",
        max_tokens=max_tokens,
        temperature=temperature,
        api_response_override=api_response_override,
    )
    acceptance = write_acceptance(
        api_call_path=artifacts["api_call"],
        authorization_path=artifacts["authorization"],
        output=artifacts["acceptance"],
    )
    execution = write_execution(
        api_call_path=artifacts["api_call"],
        acceptance_path=artifacts["acceptance"],
        authorization_path=artifacts["authorization"],
        output=artifacts["execution"],
    )
    rollback = write_rollback_or_abort(
        execution_path=artifacts["execution"],
        output=artifacts["rollback_or_abort"],
    )
    reconciliation = write_reconciliation(
        operator_review_path=artifacts["operator_review"],
        registration_path=artifacts["registration"],
        authorization_path=artifacts["authorization"],
        preflight_path=artifacts["preflight"],
        api_call_path=artifacts["api_call"],
        acceptance_path=artifacts["acceptance"],
        execution_path=artifacts["execution"],
        rollback_or_abort_path=artifacts["rollback_or_abort"],
        output=artifacts["reconciliation"],
    )

    reports = [review, registration, authorization, preflight, api_call, acceptance, execution, rollback, reconciliation]
    summary = {
        "schema_version": CHAIN_SCHEMA,
        "passed": all(report.get("passed") is True for report in reports),
        "failure_reasons": _collect_failures(*reports),
        "source_i2a_summary": _artifact_ref(i2a_summary_path),
        "command_id": _object(authorization.get("command")).get("command_id"),
        "executor_alias": executor_alias,
        "artifacts": {name: _artifact_ref(path) for name, path in artifacts.items() if name != "summary"},
        "readiness": {
            "state": "i2b_read_only_external_command_passed" if reconciliation.get("passed") is True else "blocked_i2b_read_only_external_command",
            "i2b_read_only_external_command_complete": reconciliation.get("passed") is True,
            "i2c_bounded_apply_discussion_ready": reconciliation.get("passed") is True,
            "real_task_command_allowed": False,
            "source_or_git_write_allowed": False,
            "production_transition_allowed": False,
        },
        "boundary": _boundary(scoped_external_agent_command_allowed=True, provider_api_network_allowed=True),
        "non_claims": [
            "i2b_allows_only_one_read_only_external_model_command",
            "i2b_does_not_authorize_source_writes_git_or_deploy",
            "i2b_does_not_authorize_i2c_or_production",
        ],
    }
    _write_json(artifacts["summary"], summary)
    return summary


def write_operator_review(*, i2a_summary_path: Path, output: Path, operator_id: str) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    summary = _read_json(i2a_summary_path)
    readiness = _object(summary.get("readiness"))
    boundary = _object(summary.get("boundary"))
    _check(checks, failures, "i2a_summary_passed", summary.get("schema_version") == "i2a-controlled-command-chain:v1" and summary.get("passed") is True)
    _check(checks, failures, "i2a_discussion_ready", readiness.get("operator_discussion_required_for_i2b") is True)
    _check(checks, failures, "i2a_kept_real_task_blocked", readiness.get("real_task_command_allowed") is False and boundary.get("real_task_command_allowed") is False)
    passed = _passed(checks, failures)
    report = {
        "schema_version": OPERATOR_REVIEW_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "source_artifacts": {"i2a_summary": _artifact_ref(i2a_summary_path)},
        "operator_review": {
            "operator_id": operator_id,
            "decision": "approve_i2b_real_external_read_only_command" if passed else "blocked_i2b_operator_review",
            "approved_scope": "one_time_external_model_read_only_artifact_review" if passed else None,
            "reason": "Approve one real external provider call for read-only artifact review; no source, Git, runtime, deploy, or production side effects." if passed else "I.2-A did not satisfy I.2-B prerequisites.",
        },
        "readiness": {"state": "i2b_registration_authorization_ready" if passed else "blocked_i2b_operator_review", "i2b_operator_review_complete": passed},
        "boundary": _boundary(operator_review_recording_allowed=True),
    }
    _write_json(output, report)
    return report


def write_registration(*, operator_review_path: Path, env_file: Path, output: Path, executor_alias: str) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    review = _read_json(operator_review_path)
    env = _load_env(env_file, failures)
    provider = _required_env(env, "BETA6_EXTERNAL_AGENT_PROVIDER", failures)
    base_url = _required_env(env, "BETA6_EXTERNAL_AGENT_API_BASE_URL", failures).rstrip("/")
    model = _required_env(env, "BETA6_EXTERNAL_AGENT_MODEL", failures)
    api_key = _required_env(env, "BETA6_EXTERNAL_AGENT_API_KEY", failures)
    host = urllib.parse.urlparse(base_url).hostname or ""
    _check(checks, failures, "operator_review_passed", review.get("schema_version") == OPERATOR_REVIEW_SCHEMA and review.get("passed") is True)
    _check(checks, failures, "env_file_mode_private", env_file.is_file() and stat.S_IMODE(env_file.stat().st_mode) & 0o077 == 0)
    _check(checks, failures, "provider_is_openai_compatible", provider == "openai_compatible")
    _check(checks, failures, "base_url_is_https", base_url.startswith("https://"))
    _check(checks, failures, "api_key_present_not_recorded", bool(api_key))
    _check(checks, failures, "model_present", bool(model))
    passed = _passed(checks, failures)
    report = {
        "schema_version": REGISTRATION_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "source_artifacts": {"operator_review": _artifact_ref(operator_review_path)},
        "external_agent": {
            "agent_alias": executor_alias,
            "agent_did": "did:civ:i2b:" + _sha256_text(f"{executor_alias}:{base_url}:{model}")[:32],
            "agent_kind": "real_external_model_agent",
            "provider": provider,
            "provider_host": host,
            "model": model,
            "capabilities": ["read_only_artifact_review", "structured_receipt_generation", "boundary_attestation"],
            "registration_scope": "i2b_one_time_read_only_external_model_command",
            "api_key_present": bool(api_key),
            "api_key_recorded": False,
        },
        "readiness": {"state": "i2b_real_external_agent_registered" if passed else "blocked_i2b_registration", "registration_receipt_present": passed},
        "boundary": _boundary(registration_recording_allowed=True),
    }
    _write_json(output, report)
    _reject_secret_written(output, api_key, failures)
    return report


def write_authorization(
    *,
    operator_review_path: Path,
    registration_path: Path,
    output: Path,
    objective: str,
    expiry_minutes: int,
    i2a_summary_path: Path,
) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    review = _read_json(operator_review_path)
    registration = _read_json(registration_path)
    agent = _object(registration.get("external_agent"))
    _check(checks, failures, "operator_review_passed", review.get("passed") is True)
    _check(checks, failures, "registration_passed", registration.get("schema_version") == REGISTRATION_SCHEMA and registration.get("passed") is True)
    _check(checks, failures, "expiry_within_limit", 1 <= expiry_minutes <= 60)
    _check(checks, failures, "objective_nonempty", bool(objective.strip()))
    now = datetime.now(timezone.utc)
    seed = _sha256_json({"source": _artifact_ref(i2a_summary_path), "agent": agent, "objective": objective})
    command_id = "i2b-command:" + seed[:20]
    passed = _passed(checks, failures)
    report = {
        "schema_version": AUTHORIZATION_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "source_artifacts": {
            "operator_review": _artifact_ref(operator_review_path),
            "registration": _artifact_ref(registration_path),
            "i2a_summary": _artifact_ref(i2a_summary_path),
        },
        "command": {
            "command_id": command_id,
            "command_class": "real_external_read_only_artifact_review",
            "objective": objective,
            "executor_alias": agent.get("agent_alias"),
            "executor_did": agent.get("agent_did"),
            "provider_host_allowlist": [agent.get("provider_host")],
            "input_artifacts": [_artifact_ref(i2a_summary_path)],
            "allowed_actions": ALLOWED_ACTIONS,
            "forbidden_actions": FORBIDDEN_ACTIONS,
            "single_use": True,
            "single_use_nonce": seed[:24],
            "created_at": _iso(now),
            "expires_at": _iso(now + timedelta(minutes=expiry_minutes)),
            "max_duration_seconds": 180,
            "max_output_bytes": 65536,
            "receipt_sink": "run_root_only",
            "rollback_plan": "read_only_external_model_call_no_state_change_revoke_no_tokens_required",
        },
        "readiness": {"state": "i2b_scoped_command_authorized_for_preflight" if passed else "blocked_i2b_authorization", "single_use_command_ready_for_preflight": passed},
        "boundary": _boundary(scoped_command_authorization_recording_allowed=True, provider_api_network_allowed=True),
    }
    _write_json(output, report)
    return report


def write_preflight(*, authorization_path: Path, registration_path: Path, env_file: Path, output: Path) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    authorization = _read_json(authorization_path)
    registration = _read_json(registration_path)
    env = _load_env(env_file, failures)
    api_key = env.get("BETA6_EXTERNAL_AGENT_API_KEY", "")
    command = _object(authorization.get("command"))
    agent = _object(registration.get("external_agent"))
    _check(checks, failures, "authorization_passed", authorization.get("schema_version") == AUTHORIZATION_SCHEMA and authorization.get("passed") is True)
    _check(checks, failures, "registration_passed", registration.get("passed") is True)
    _check(checks, failures, "env_file_private", env_file.is_file() and stat.S_IMODE(env_file.stat().st_mode) & 0o077 == 0)
    _check(checks, failures, "api_key_present", bool(api_key))
    _check(checks, failures, "provider_host_allowlisted", agent.get("provider_host") in command.get("provider_host_allowlist", []))
    _check(checks, failures, "source_git_runtime_deploy_forbidden", set(FORBIDDEN_ACTIONS).issubset(set(command.get("forbidden_actions", []))))
    passed = _passed(checks, failures)
    report = {
        "schema_version": PREFLIGHT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "source_artifacts": {"authorization": _artifact_ref(authorization_path), "registration": _artifact_ref(registration_path)},
        "isolation": {
            "profile": "i2b_real_external_provider_read_only",
            "provider_api_network_allowed": True,
            "allowed_provider_hosts": command.get("provider_host_allowlist", []),
            "general_network_allowed": False,
            "source_tree_write_allowed": False,
            "git_allowed": False,
            "runtime_state_mutation_allowed": False,
            "production_credential_allowed": False,
            "api_key_local_only": True,
            "api_key_recorded": False,
        },
        "readiness": {"state": "i2b_isolation_preflight_passed" if passed else "blocked_i2b_preflight", "external_provider_call_allowed_once": passed},
        "boundary": _boundary(isolation_preflight_recording_allowed=True, provider_api_network_allowed=passed),
    }
    _write_json(output, report)
    _reject_secret_written(output, api_key, failures)
    return report


def write_api_call_report(
    *,
    authorization_path: Path,
    registration_path: Path,
    preflight_path: Path,
    env_file: Path,
    output: Path,
    response_output: Path,
    max_tokens: int,
    temperature: float,
    api_response_override: str | None = None,
) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    authorization = _read_json(authorization_path)
    registration = _read_json(registration_path)
    preflight = _read_json(preflight_path)
    env = _load_env(env_file, failures)
    api_key = _required_env(env, "BETA6_EXTERNAL_AGENT_API_KEY", failures)
    base_url = _required_env(env, "BETA6_EXTERNAL_AGENT_API_BASE_URL", failures).rstrip("/")
    model = _required_env(env, "BETA6_EXTERNAL_AGENT_MODEL", failures)
    command = _object(authorization.get("command"))
    i2a_summary_path = Path(str(_objects(command.get("input_artifacts"))[0].get("path"))) if _objects(command.get("input_artifacts")) else Path()
    i2a_excerpt = _safe_excerpt(i2a_summary_path, 8000)
    _check(checks, failures, "authorization_passed", authorization.get("passed") is True)
    _check(checks, failures, "registration_passed", registration.get("passed") is True)
    _check(checks, failures, "preflight_passed", preflight.get("schema_version") == PREFLIGHT_SCHEMA and preflight.get("passed") is True)
    _check(checks, failures, "max_tokens_bounded", 1 <= max_tokens <= 2000)
    _check(checks, failures, "temperature_bounded", 0 <= temperature <= 0.3)

    content = ""
    http_status: int | None = None
    if _passed(checks, failures):
        if api_response_override is not None:
            content = api_response_override.replace("__COMMAND_ID__", str(command.get("command_id") or ""))
            http_status = 200
        else:
            content, http_status = _call_openai_compatible(
                base_url=base_url,
                api_key=api_key,
                model=model,
                prompt=_prompt(command=command, i2a_excerpt=i2a_excerpt),
                max_tokens=max_tokens,
                temperature=temperature,
            )
    parsed = _parse_response(content, failures) if content else {}
    _check(checks, failures, "provider_returned_http_200", http_status == 200)
    _check(checks, failures, "response_schema_valid", parsed.get("schema_version") == RESPONSE_SCHEMA)
    _check(checks, failures, "response_accepts_scope", parsed.get("accepted") is True)
    attestation = _object(parsed.get("boundary_attestation"))
    _check(checks, failures, "response_attests_no_forbidden_side_effects", attestation.get("source_tree_modified") is False and attestation.get("git_used") is False and attestation.get("runtime_state_mutated") is False and attestation.get("production_touched") is False)
    _check(checks, failures, "response_keeps_next_step_blocked", parsed.get("recommendation") in {"remain_blocked_for_real_task_commanding", "operator_review_before_next_gate"})

    if parsed:
        _write_json(response_output, parsed)
    passed = _passed(checks, failures)
    report = {
        "schema_version": API_CALL_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "source_artifacts": {"authorization": _artifact_ref(authorization_path), "registration": _artifact_ref(registration_path), "preflight": _artifact_ref(preflight_path)},
        "api_call": {
            "provider": _object(registration.get("external_agent")).get("provider"),
            "provider_host": urllib.parse.urlparse(base_url).hostname,
            "model": model,
            "http_status": http_status,
            "api_key_present": bool(api_key),
            "api_key_recorded": False,
            "request_prompt_sha256": _sha256_text(_prompt(command=command, i2a_excerpt=i2a_excerpt)) if command else None,
            "response_content_sha256": _sha256_text(content) if content else None,
            "response_artifact": _artifact_ref(response_output) if response_output.is_file() else None,
        },
        "readiness": {"state": "i2b_external_agent_response_ready" if passed else "blocked_i2b_api_call", "external_agent_api_call_receipt_present": passed},
        "boundary": _boundary(api_call_report_recording_allowed=True, provider_api_network_allowed=True),
    }
    _write_json(output, report)
    for path in (output, response_output):
        if path.is_file():
            _reject_secret_written(path, api_key, failures)
    return report


def write_acceptance(*, api_call_path: Path, authorization_path: Path, output: Path) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    api_call = _read_json(api_call_path)
    authorization = _read_json(authorization_path)
    response_ref = _object(_object(api_call.get("api_call")).get("response_artifact"))
    response = _read_json(Path(str(response_ref.get("path")))) if response_ref.get("path") else {}
    command = _object(authorization.get("command"))
    _check(checks, failures, "api_call_passed", api_call.get("schema_version") == API_CALL_SCHEMA and api_call.get("passed") is True)
    _check(checks, failures, "authorization_passed", authorization.get("passed") is True)
    _check(checks, failures, "response_accepted", response.get("accepted") is True)
    _check(checks, failures, "command_id_matches", response.get("command_id") == command.get("command_id"))
    passed = _passed(checks, failures)
    report = {
        "schema_version": ACCEPTANCE_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "source_artifacts": {"api_call": _artifact_ref(api_call_path), "authorization": _artifact_ref(authorization_path)},
        "acceptance": {
            "accepted": passed,
            "accepted_command_id": command.get("command_id"),
            "external_agent_verdict": response.get("verdict"),
            "scope_hash": _sha256_json(command),
        },
        "readiness": {"state": "i2b_external_agent_accepted_scope" if passed else "blocked_i2b_acceptance", "acceptance_receipt_present": passed},
        "boundary": _boundary(acceptance_recording_allowed=True, provider_api_network_allowed=True),
    }
    _write_json(output, report)
    return report


def write_execution(*, api_call_path: Path, acceptance_path: Path, authorization_path: Path, output: Path) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    api_call = _read_json(api_call_path)
    acceptance = _read_json(acceptance_path)
    authorization = _read_json(authorization_path)
    response_ref = _object(_object(api_call.get("api_call")).get("response_artifact"))
    response = _read_json(Path(str(response_ref.get("path")))) if response_ref.get("path") else {}
    command = _object(authorization.get("command"))
    attestation = _object(response.get("boundary_attestation"))
    _check(checks, failures, "api_call_passed", api_call.get("passed") is True)
    _check(checks, failures, "acceptance_passed", acceptance.get("schema_version") == ACCEPTANCE_SCHEMA and acceptance.get("passed") is True)
    _check(checks, failures, "command_consumed_once", response.get("command_id") == command.get("command_id"))
    _check(checks, failures, "no_source_git_runtime_production_side_effects", attestation.get("source_tree_modified") is False and attestation.get("git_used") is False and attestation.get("runtime_state_mutated") is False and attestation.get("production_touched") is False)
    passed = _passed(checks, failures)
    report = {
        "schema_version": EXECUTION_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "source_artifacts": {"api_call": _artifact_ref(api_call_path), "acceptance": _artifact_ref(acceptance_path), "authorization": _artifact_ref(authorization_path)},
        "execution": {
            "execution_kind": "real_external_model_read_only_artifact_review",
            "command_id": command.get("command_id"),
            "single_use_nonce": command.get("single_use_nonce"),
            "command_consumed": passed,
            "provider_api_network_used": True,
            "external_side_effect_observed": False,
            "output_artifact": response_ref or None,
            "summary": response.get("summary"),
            "observations": response.get("observations", []),
            "recommendation": response.get("recommendation"),
        },
        "readiness": {"state": "i2b_command_execution_receipt_present" if passed else "blocked_i2b_execution", "execution_receipt_present": passed},
        "boundary": _boundary(execution_receipt_recording_allowed=True, provider_api_network_allowed=True),
    }
    _write_json(output, report)
    return report


def write_rollback_or_abort(*, execution_path: Path, output: Path) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    execution = _read_json(execution_path)
    _check(checks, failures, "execution_passed", execution.get("schema_version") == EXECUTION_SCHEMA and execution.get("passed") is True)
    _check(checks, failures, "no_external_side_effects", _object(execution.get("execution")).get("external_side_effect_observed") is False)
    passed = _passed(checks, failures)
    report = {
        "schema_version": ROLLBACK_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "source_artifacts": {"execution": _artifact_ref(execution_path)},
        "rollback_or_abort": {
            "rollback_required": False,
            "abort_required": False,
            "reason": "read_only_external_model_call_with_no_source_git_runtime_or_production_side_effects",
            "recovery_action": "discard_run_root_artifacts_if_operator_rejects_reconciliation",
        },
        "readiness": {"state": "i2b_rollback_or_abort_receipt_present" if passed else "blocked_i2b_rollback_or_abort", "rollback_or_abort_receipt_present": passed},
        "boundary": _boundary(rollback_or_abort_recording_allowed=True),
    }
    _write_json(output, report)
    return report


def write_reconciliation(
    *,
    operator_review_path: Path,
    registration_path: Path,
    authorization_path: Path,
    preflight_path: Path,
    api_call_path: Path,
    acceptance_path: Path,
    execution_path: Path,
    rollback_or_abort_path: Path,
    output: Path,
) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    pairs = [
        ("operator_review", operator_review_path, OPERATOR_REVIEW_SCHEMA),
        ("registration", registration_path, REGISTRATION_SCHEMA),
        ("authorization", authorization_path, AUTHORIZATION_SCHEMA),
        ("preflight", preflight_path, PREFLIGHT_SCHEMA),
        ("api_call", api_call_path, API_CALL_SCHEMA),
        ("acceptance", acceptance_path, ACCEPTANCE_SCHEMA),
        ("execution", execution_path, EXECUTION_SCHEMA),
        ("rollback_or_abort", rollback_or_abort_path, ROLLBACK_SCHEMA),
    ]
    reports = {name: _read_json(path) for name, path, _ in pairs}
    for name, _path, schema in pairs:
        _check(checks, failures, f"{name}_passed", reports[name].get("schema_version") == schema and reports[name].get("passed") is True)
    execution = _object(reports["execution"].get("execution"))
    rollback = _object(reports["rollback_or_abort"].get("rollback_or_abort"))
    _check(checks, failures, "command_consumed_once", execution.get("command_consumed") is True)
    _check(checks, failures, "provider_call_only_side_effect", execution.get("provider_api_network_used") is True and execution.get("external_side_effect_observed") is False)
    _check(checks, failures, "rollback_closed", rollback.get("rollback_required") is False and rollback.get("abort_required") is False)
    passed = _passed(checks, failures)
    report = {
        "schema_version": RECONCILIATION_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "source_artifacts": {name: _artifact_ref(path) for name, path, _ in pairs},
        "operator_reconciliation": {
            "decision": "i2b_read_only_external_command_passed" if passed else "blocked_i2b_reconciliation",
            "reason": "A real external model Agent accepted and executed one scoped read-only artifact review command; no source, Git, runtime, deploy, or production side effects were authorized or observed." if passed else "I.2-B evidence chain failed hard controls.",
            "command_id": execution.get("command_id"),
        },
        "readiness": {
            "state": "i2b_read_only_external_command_passed" if passed else "blocked_i2b_reconciliation",
            "i2b_complete": passed,
            "i2c_bounded_apply_discussion_ready": passed,
            "real_task_command_allowed": False,
            "source_or_git_write_allowed": False,
            "production_transition_allowed": False,
        },
        "boundary": _boundary(operator_reconciliation_recording_allowed=True, provider_api_network_allowed=True),
        "non_claims": [
            "i2b_reconciliation_does_not_authorize_i2c",
            "i2b_reconciliation_does_not_authorize_source_git_deploy_or_production",
        ],
    }
    _write_json(output, report)
    return report


def _call_openai_compatible(*, base_url: str, api_key: str, model: str, prompt: str, max_tokens: int, temperature: float) -> tuple[str, int]:
    endpoint = base_url if base_url.endswith("/chat/completions") else f"{base_url}/chat/completions"
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": "You are an external CivitasOS Agent. Return strict JSON only."},
            {"role": "user", "content": prompt},
        ],
        "temperature": temperature,
        "max_tokens": max_tokens,
    }
    request = urllib.request.Request(
        endpoint,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            raw = response.read().decode("utf-8", errors="replace")
            data = json.loads(raw)
            choices = data.get("choices") if isinstance(data, dict) else []
            if not choices:
                raise RuntimeError("provider returned no choices")
            content = choices[0].get("message", {}).get("content", "")
            return str(content), int(response.status)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:800]
        raise RuntimeError(f"external provider HTTP {exc.code}: {detail}") from exc


def _prompt(*, command: dict[str, Any], i2a_excerpt: str) -> str:
    return f"""
You are executing a single I.2-B read-only external Agent command.

Return strict JSON matching this schema:
{{
  "schema_version": "{RESPONSE_SCHEMA}",
  "command_id": "{command.get('command_id')}",
  "accepted": true,
  "verdict": "accepted_scope_executed_read_only",
  "summary": "one concise sentence",
  "observations": ["2-4 concrete observations"],
  "recommendation": "remain_blocked_for_real_task_commanding",
  "boundary_attestation": {{
    "network_used_only_for_provider_api": true,
    "source_tree_modified": false,
    "git_used": false,
    "runtime_state_mutated": false,
    "production_touched": false
  }}
}}

Hard rules:
- Do not ask for more context.
- Do not claim source, Git, runtime, deploy, or production authority.
- Do not recommend real task commanding without a separate operator gate.
- Keep recommendation exactly one of: remain_blocked_for_real_task_commanding, operator_review_before_next_gate.

Command envelope:
{json.dumps(command, ensure_ascii=False, indent=2, sort_keys=True)}

I.2-A summary excerpt:
{i2a_excerpt}
""".strip()


def _parse_response(content: str, failures: list[str]) -> dict[str, Any]:
    text = content.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text).strip()
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if not match:
            failures.append("external response was not JSON")
            return {}
        try:
            value = json.loads(match.group(0))
        except json.JSONDecodeError:
            failures.append("external response JSON parse failed")
            return {}
    if not isinstance(value, dict):
        failures.append("external response JSON must be object")
        return {}
    return value


def _safe_excerpt(path: Path, max_chars: int) -> str:
    if not path.is_file():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")[:max_chars]


def _load_env(path: Path, failures: list[str]) -> dict[str, str]:
    if not path.is_file():
        failures.append(f"env file missing: {path}")
        return {}
    env: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        env[key.strip()] = value.strip().strip('"').strip("'")
    return env


def _required_env(env: dict[str, str], key: str, failures: list[str]) -> str:
    value = env.get(key, "").strip()
    if not value:
        failures.append(f"missing env {key}")
    return value


def _boundary(**overrides: bool) -> dict[str, bool]:
    base = {
        "scoped_external_agent_command_allowed": False,
        "general_external_agent_command_allowed": False,
        "provider_api_network_allowed": False,
        "general_network_allowed": False,
        "real_task_command_allowed": False,
        "source_tree_write_allowed": False,
        "git_write_allowed": False,
        "runtime_state_mutation_allowed": False,
        "external_system_write_allowed": False,
        "deploy_allowed": False,
        "production_transition_allowed": False,
    }
    base.update(overrides)
    return base


def _collect_failures(*reports: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    for report in reports:
        failures.extend(str(item) for item in report.get("failure_reasons", []))
    return failures


def _passed(checks: dict[str, bool], failures: list[str]) -> bool:
    return bool(checks) and all(checks.values()) and not failures


def _check(checks: dict[str, bool], failures: list[str], name: str, passed: bool) -> None:
    checks[name] = bool(passed)
    if not passed:
        failures.append(name)


def _objects(value: Any) -> list[dict[str, Any]]:
    return [item for item in value] if isinstance(value, list) and all(isinstance(item, dict) for item in value) else []


def _object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def _write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _artifact_ref(path: Path) -> dict[str, str]:
    return {"path": str(path.resolve()), "sha256": _sha256(path)}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _sha256_json(value: Any) -> str:
    return _sha256_text(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")))


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _reject_secret_written(path: Path, secret: str, failures: list[str]) -> None:
    if secret and path.is_file() and secret in path.read_text(encoding="utf-8", errors="ignore"):
        failures.append(f"secret leaked into {path}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--i2a-summary", required=True)
    parser.add_argument("--output-root", required=True)
    parser.add_argument("--env-file", default=DEFAULT_ENV_FILE)
    parser.add_argument("--operator-id", default="operator-cc")
    parser.add_argument("--executor-alias", default="deepseek-api-agent")
    parser.add_argument("--objective", default=DEFAULT_OBJECTIVE)
    parser.add_argument("--expiry-minutes", type=int, default=30)
    parser.add_argument("--max-tokens", type=int, default=2000)
    parser.add_argument("--temperature", type=float, default=0.0)
    args = parser.parse_args()
    report = run_gate(
        i2a_summary_path=Path(args.i2a_summary).resolve(),
        env_file=Path(args.env_file).resolve(),
        output_root=Path(args.output_root).resolve(),
        operator_id=args.operator_id,
        executor_alias=args.executor_alias,
        objective=args.objective,
        expiry_minutes=args.expiry_minutes,
        max_tokens=args.max_tokens,
        temperature=args.temperature,
    )
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    raise SystemExit(0 if report["passed"] else 2)


if __name__ == "__main__":
    main()
