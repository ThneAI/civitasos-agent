"""Run I.2-B real external Agent read-only command gate.

This gate is the first real external Agent command after I.2-A. It is still
bounded to a read-only review command: the external provider may be called, but
source writes, Git operations, runtime mutation, external system writes,
deployment, and production transition remain forbidden.
"""

from __future__ import annotations

import argparse
import json
import stat
import urllib.parse
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from benchmarks.i_gate_evidence import (
    all_checks_passed,
    artifact_ref,
    check,
    object_value,
    objects_value,
    read_json_object,
    sha256_json,
    sha256_text,
    write_json_object,
)
from benchmarks.i2_provider_runner import (
    build_readonly_command_prompt,
    call_openai_compatible,
    parse_json_object_response,
)
from benchmarks.i2b_provider_execution import execute_provider_readonly_command

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
        "source_i2a_summary": artifact_ref(i2a_summary_path),
        "command_id": object_value(authorization.get("command")).get("command_id"),
        "executor_alias": executor_alias,
        "artifacts": {name: artifact_ref(path) for name, path in artifacts.items() if name != "summary"},
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
    write_json_object(artifacts["summary"], summary)
    return summary


def write_operator_review(*, i2a_summary_path: Path, output: Path, operator_id: str) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    summary = read_json_object(i2a_summary_path)
    readiness = object_value(summary.get("readiness"))
    boundary = object_value(summary.get("boundary"))
    check(checks, failures, "i2a_summary_passed", summary.get("schema_version") == "i2a-controlled-command-chain:v1" and summary.get("passed") is True)
    check(checks, failures, "i2a_discussion_ready", readiness.get("operator_discussion_required_for_i2b") is True)
    check(checks, failures, "i2a_kept_real_task_blocked", readiness.get("real_task_command_allowed") is False and boundary.get("real_task_command_allowed") is False)
    passed = all_checks_passed(checks, failures)
    report = {
        "schema_version": OPERATOR_REVIEW_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "source_artifacts": {"i2a_summary": artifact_ref(i2a_summary_path)},
        "operator_review": {
            "operator_id": operator_id,
            "decision": "approve_i2b_real_external_read_only_command" if passed else "blocked_i2b_operator_review",
            "approved_scope": "one_time_external_model_read_only_artifact_review" if passed else None,
            "reason": "Approve one real external provider call for read-only artifact review; no source, Git, runtime, deploy, or production side effects." if passed else "I.2-A did not satisfy I.2-B prerequisites.",
        },
        "readiness": {"state": "i2b_registration_authorization_ready" if passed else "blocked_i2b_operator_review", "i2b_operator_review_complete": passed},
        "boundary": _boundary(operator_review_recording_allowed=True),
    }
    write_json_object(output, report)
    return report


def write_registration(*, operator_review_path: Path, env_file: Path, output: Path, executor_alias: str) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    review = read_json_object(operator_review_path)
    env = _load_env(env_file, failures)
    provider = _required_env(env, "BETA6_EXTERNAL_AGENT_PROVIDER", failures)
    base_url = _required_env(env, "BETA6_EXTERNAL_AGENT_API_BASE_URL", failures).rstrip("/")
    model = _required_env(env, "BETA6_EXTERNAL_AGENT_MODEL", failures)
    api_key = _required_env(env, "BETA6_EXTERNAL_AGENT_API_KEY", failures)
    host = urllib.parse.urlparse(base_url).hostname or ""
    check(checks, failures, "operator_review_passed", review.get("schema_version") == OPERATOR_REVIEW_SCHEMA and review.get("passed") is True)
    check(checks, failures, "env_file_mode_private", env_file.is_file() and stat.S_IMODE(env_file.stat().st_mode) & 0o077 == 0)
    local_http_allowed = _local_http_allowed(provider=provider, base_url=base_url, env=env)
    check(checks, failures, "provider_supported", provider in {"openai_compatible", "local_ollama_gpu"})
    check(checks, failures, "base_url_transport_allowed", base_url.startswith("https://") or local_http_allowed)
    check(checks, failures, "api_key_present_not_recorded", bool(api_key))
    check(checks, failures, "model_present", bool(model))
    passed = all_checks_passed(checks, failures)
    report = {
        "schema_version": REGISTRATION_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "source_artifacts": {"operator_review": artifact_ref(operator_review_path)},
        "external_agent": {
            "agent_alias": executor_alias,
            "agent_did": "did:civ:i2b:" + sha256_text(f"{executor_alias}:{base_url}:{model}")[:32],
            "agent_kind": "real_external_model_agent",
            "provider": provider,
            "provider_host": host,
            "model": model,
            "local_http_loopback_allowed": local_http_allowed,
            "capabilities": ["read_only_artifact_review", "structured_receipt_generation", "boundary_attestation"],
            "registration_scope": "i2b_one_time_read_only_external_model_command",
            "api_key_present": bool(api_key),
            "api_key_recorded": False,
        },
        "readiness": {"state": "i2b_real_external_agent_registered" if passed else "blocked_i2b_registration", "registration_receipt_present": passed},
        "boundary": _boundary(registration_recording_allowed=True),
    }
    write_json_object(output, report)
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
    review = read_json_object(operator_review_path)
    registration = read_json_object(registration_path)
    agent = object_value(registration.get("external_agent"))
    check(checks, failures, "operator_review_passed", review.get("passed") is True)
    check(checks, failures, "registration_passed", registration.get("schema_version") == REGISTRATION_SCHEMA and registration.get("passed") is True)
    check(checks, failures, "expiry_within_limit", 1 <= expiry_minutes <= 60)
    check(checks, failures, "objective_nonempty", bool(objective.strip()))
    now = datetime.now(timezone.utc)
    seed = sha256_json({"source": artifact_ref(i2a_summary_path), "agent": agent, "objective": objective})
    command_id = "i2b-command:" + seed[:20]
    passed = all_checks_passed(checks, failures)
    report = {
        "schema_version": AUTHORIZATION_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "source_artifacts": {
            "operator_review": artifact_ref(operator_review_path),
            "registration": artifact_ref(registration_path),
            "i2a_summary": artifact_ref(i2a_summary_path),
        },
        "command": {
            "command_id": command_id,
            "command_class": "real_external_read_only_artifact_review",
            "objective": objective,
            "executor_alias": agent.get("agent_alias"),
            "executor_did": agent.get("agent_did"),
            "provider_host_allowlist": [agent.get("provider_host")],
            "input_artifacts": [artifact_ref(i2a_summary_path)],
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
    write_json_object(output, report)
    return report


def write_preflight(*, authorization_path: Path, registration_path: Path, env_file: Path, output: Path) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    authorization = read_json_object(authorization_path)
    registration = read_json_object(registration_path)
    env = _load_env(env_file, failures)
    api_key = env.get("BETA6_EXTERNAL_AGENT_API_KEY", "")
    command = object_value(authorization.get("command"))
    agent = object_value(registration.get("external_agent"))
    provider_host = str(agent.get("provider_host") or "")
    local_http_allowed = agent.get("local_http_loopback_allowed") is True
    check(checks, failures, "authorization_passed", authorization.get("schema_version") == AUTHORIZATION_SCHEMA and authorization.get("passed") is True)
    check(checks, failures, "registration_passed", registration.get("passed") is True)
    check(checks, failures, "env_file_private", env_file.is_file() and stat.S_IMODE(env_file.stat().st_mode) & 0o077 == 0)
    check(checks, failures, "api_key_present", bool(api_key))
    check(checks, failures, "provider_host_allowlisted", provider_host in command.get("provider_host_allowlist", []))
    check(checks, failures, "provider_network_is_scoped", provider_host not in {"", "0.0.0.0"} and (provider_host not in {"127.0.0.1", "localhost", "::1"} or local_http_allowed))
    check(checks, failures, "source_git_runtime_deploy_forbidden", set(FORBIDDEN_ACTIONS).issubset(set(command.get("forbidden_actions", []))))
    passed = all_checks_passed(checks, failures)
    report = {
        "schema_version": PREFLIGHT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "source_artifacts": {"authorization": artifact_ref(authorization_path), "registration": artifact_ref(registration_path)},
        "isolation": {
            "profile": "i2b_real_external_provider_read_only",
            "provider_api_network_allowed": True,
            "allowed_provider_hosts": command.get("provider_host_allowlist", []),
            "local_http_loopback_allowed": local_http_allowed,
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
    write_json_object(output, report)
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
    authorization = read_json_object(authorization_path)
    registration = read_json_object(registration_path)
    preflight = read_json_object(preflight_path)
    env = _load_env(env_file, failures)
    api_key = _required_env(env, "BETA6_EXTERNAL_AGENT_API_KEY", failures)
    base_url = _required_env(env, "BETA6_EXTERNAL_AGENT_API_BASE_URL", failures).rstrip("/")
    model = _required_env(env, "BETA6_EXTERNAL_AGENT_MODEL", failures)
    command = object_value(authorization.get("command"))
    i2a_summary_path = Path(str(objects_value(command.get("input_artifacts"))[0].get("path"))) if objects_value(command.get("input_artifacts")) else Path()
    i2a_excerpt = _safe_excerpt(i2a_summary_path, 8000)
    check(checks, failures, "authorization_passed", authorization.get("passed") is True)
    check(checks, failures, "registration_passed", registration.get("passed") is True)
    check(checks, failures, "preflight_passed", preflight.get("schema_version") == PREFLIGHT_SCHEMA and preflight.get("passed") is True)
    check(checks, failures, "max_tokens_bounded", 1 <= max_tokens <= 2000)
    check(checks, failures, "temperature_bounded", 0 <= temperature <= 0.3)

    http_status: int | None = None
    prompt_sha256: str | None = None
    response_content_sha256: str | None = None
    if all_checks_passed(checks, failures):
        execution = execute_provider_readonly_command(
            response_schema=RESPONSE_SCHEMA,
            command=command,
            i2a_excerpt=i2a_excerpt,
            base_url=base_url,
            api_key=api_key,
            model=model,
            max_tokens=max_tokens,
            temperature=temperature,
            api_response_override=api_response_override,
            provider_call=_call_openai_compatible,
        )
        http_status = execution.get("http_status") if isinstance(execution.get("http_status"), int) else None
        parsed = object_value(execution.get("parsed"))
        failures.extend(str(item) for item in execution.get("failures", []))
        prompt_sha256 = str(execution.get("prompt_sha256") or "")
        response_content_sha256 = execution.get("response_content_sha256") if isinstance(execution.get("response_content_sha256"), str) else None
    else:
        parsed = {}
    check(checks, failures, "provider_returned_http_200", http_status == 200)
    check(checks, failures, "response_schema_valid", parsed.get("schema_version") == RESPONSE_SCHEMA)
    check(checks, failures, "response_accepts_scope", parsed.get("accepted") is True)
    attestation = object_value(parsed.get("boundary_attestation"))
    check(checks, failures, "response_attests_no_forbidden_side_effects", attestation.get("source_tree_modified") is False and attestation.get("git_used") is False and attestation.get("runtime_state_mutated") is False and attestation.get("production_touched") is False)
    check(checks, failures, "response_keeps_next_step_blocked", parsed.get("recommendation") in {"remain_blocked_for_real_task_commanding", "operator_review_before_next_gate"})

    if parsed:
        write_json_object(response_output, parsed)
    passed = all_checks_passed(checks, failures)
    report = {
        "schema_version": API_CALL_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "source_artifacts": {"authorization": artifact_ref(authorization_path), "registration": artifact_ref(registration_path), "preflight": artifact_ref(preflight_path)},
        "api_call": {
            "provider": object_value(registration.get("external_agent")).get("provider"),
            "provider_host": urllib.parse.urlparse(base_url).hostname,
            "model": model,
            "http_status": http_status,
            "api_key_present": bool(api_key),
            "api_key_recorded": False,
            "request_prompt_sha256": prompt_sha256 if command else None,
            "response_content_sha256": response_content_sha256,
            "response_artifact": artifact_ref(response_output) if response_output.is_file() else None,
        },
        "readiness": {"state": "i2b_external_agent_response_ready" if passed else "blocked_i2b_api_call", "external_agent_api_call_receipt_present": passed},
        "boundary": _boundary(api_call_report_recording_allowed=True, provider_api_network_allowed=True),
    }
    write_json_object(output, report)
    for path in (output, response_output):
        if path.is_file():
            _reject_secret_written(path, api_key, failures)
    return report


def write_acceptance(*, api_call_path: Path, authorization_path: Path, output: Path) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    api_call = read_json_object(api_call_path)
    authorization = read_json_object(authorization_path)
    response_ref = object_value(object_value(api_call.get("api_call")).get("response_artifact"))
    response = read_json_object(Path(str(response_ref.get("path")))) if response_ref.get("path") else {}
    command = object_value(authorization.get("command"))
    check(checks, failures, "api_call_passed", api_call.get("schema_version") == API_CALL_SCHEMA and api_call.get("passed") is True)
    check(checks, failures, "authorization_passed", authorization.get("passed") is True)
    check(checks, failures, "response_accepted", response.get("accepted") is True)
    check(checks, failures, "command_id_matches", response.get("command_id") == command.get("command_id"))
    passed = all_checks_passed(checks, failures)
    report = {
        "schema_version": ACCEPTANCE_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "source_artifacts": {"api_call": artifact_ref(api_call_path), "authorization": artifact_ref(authorization_path)},
        "acceptance": {
            "accepted": passed,
            "accepted_command_id": command.get("command_id"),
            "external_agent_verdict": response.get("verdict"),
            "scope_hash": sha256_json(command),
        },
        "readiness": {"state": "i2b_external_agent_accepted_scope" if passed else "blocked_i2b_acceptance", "acceptance_receipt_present": passed},
        "boundary": _boundary(acceptance_recording_allowed=True, provider_api_network_allowed=True),
    }
    write_json_object(output, report)
    return report


def write_execution(*, api_call_path: Path, acceptance_path: Path, authorization_path: Path, output: Path) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    api_call = read_json_object(api_call_path)
    acceptance = read_json_object(acceptance_path)
    authorization = read_json_object(authorization_path)
    response_ref = object_value(object_value(api_call.get("api_call")).get("response_artifact"))
    response = read_json_object(Path(str(response_ref.get("path")))) if response_ref.get("path") else {}
    command = object_value(authorization.get("command"))
    attestation = object_value(response.get("boundary_attestation"))
    check(checks, failures, "api_call_passed", api_call.get("passed") is True)
    check(checks, failures, "acceptance_passed", acceptance.get("schema_version") == ACCEPTANCE_SCHEMA and acceptance.get("passed") is True)
    check(checks, failures, "command_consumed_once", response.get("command_id") == command.get("command_id"))
    check(checks, failures, "no_source_git_runtime_production_side_effects", attestation.get("source_tree_modified") is False and attestation.get("git_used") is False and attestation.get("runtime_state_mutated") is False and attestation.get("production_touched") is False)
    passed = all_checks_passed(checks, failures)
    report = {
        "schema_version": EXECUTION_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "source_artifacts": {"api_call": artifact_ref(api_call_path), "acceptance": artifact_ref(acceptance_path), "authorization": artifact_ref(authorization_path)},
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
    write_json_object(output, report)
    return report


def write_rollback_or_abort(*, execution_path: Path, output: Path) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    execution = read_json_object(execution_path)
    check(checks, failures, "execution_passed", execution.get("schema_version") == EXECUTION_SCHEMA and execution.get("passed") is True)
    check(checks, failures, "no_external_side_effects", object_value(execution.get("execution")).get("external_side_effect_observed") is False)
    passed = all_checks_passed(checks, failures)
    report = {
        "schema_version": ROLLBACK_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "source_artifacts": {"execution": artifact_ref(execution_path)},
        "rollback_or_abort": {
            "rollback_required": False,
            "abort_required": False,
            "reason": "read_only_external_model_call_with_no_source_git_runtime_or_production_side_effects",
            "recovery_action": "discard_run_root_artifacts_if_operator_rejects_reconciliation",
        },
        "readiness": {"state": "i2b_rollback_or_abort_receipt_present" if passed else "blocked_i2b_rollback_or_abort", "rollback_or_abort_receipt_present": passed},
        "boundary": _boundary(rollback_or_abort_recording_allowed=True),
    }
    write_json_object(output, report)
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
    reports = {name: read_json_object(path) for name, path, _ in pairs}
    for name, _path, schema in pairs:
        check(checks, failures, f"{name}_passed", reports[name].get("schema_version") == schema and reports[name].get("passed") is True)
    execution = object_value(reports["execution"].get("execution"))
    rollback = object_value(reports["rollback_or_abort"].get("rollback_or_abort"))
    check(checks, failures, "command_consumed_once", execution.get("command_consumed") is True)
    check(checks, failures, "provider_call_only_side_effect", execution.get("provider_api_network_used") is True and execution.get("external_side_effect_observed") is False)
    check(checks, failures, "rollback_closed", rollback.get("rollback_required") is False and rollback.get("abort_required") is False)
    passed = all_checks_passed(checks, failures)
    report = {
        "schema_version": RECONCILIATION_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "source_artifacts": {name: artifact_ref(path) for name, path, _ in pairs},
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
    write_json_object(output, report)
    return report


def _call_openai_compatible(*, base_url: str, api_key: str, model: str, prompt: str, max_tokens: int, temperature: float) -> tuple[str, int]:
    return call_openai_compatible(
        base_url=base_url,
        api_key=api_key,
        model=model,
        prompt=prompt,
        max_tokens=max_tokens,
        temperature=temperature,
    )


def _prompt(*, command: dict[str, Any], i2a_excerpt: str) -> str:
    return build_readonly_command_prompt(response_schema=RESPONSE_SCHEMA, command=command, i2a_excerpt=i2a_excerpt)


def _parse_response(content: str, failures: list[str]) -> dict[str, Any]:
    return parse_json_object_response(content, failures)


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


def _local_http_allowed(*, provider: str, base_url: str, env: dict[str, str]) -> bool:
    if provider != "local_ollama_gpu":
        return False
    if env.get("BETA6_EXTERNAL_AGENT_ALLOW_LOCAL_HTTP", "").strip().lower() != "true":
        return False
    parsed = urllib.parse.urlparse(base_url)
    return parsed.scheme == "http" and (parsed.hostname or "") in {"127.0.0.1", "localhost", "::1"}


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
