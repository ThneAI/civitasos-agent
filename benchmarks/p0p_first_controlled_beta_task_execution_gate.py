"""Run P0-P first controlled beta task execution gate.

P0-P consumes the single-use P0-O authorization receipt and executes exactly one
low-risk controlled beta task through the CivitasOS task pool. It may mutate task
pool state within the authorized task scope only. It does not contact VM targets,
deploy, modify source/Git, open public ingress, access production data, authorize
production transition, or write production receipts.
"""

from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

from benchmarks.i_gate_evidence import artifact_ref, check, object_value, read_json_object, sha256_file, write_json_object
from benchmarks.p0o_first_controlled_beta_task_authorization_gate import (
    ACCEPTED_OPERATOR_DECISION as P0O_ACCEPTED_OPERATOR_DECISION,
    AUTHORIZATION_DECISION_SCHEMA as P0O_AUTHORIZATION_DECISION_SCHEMA,
    AUTHORIZATION_RECEIPT_SCHEMA as P0O_AUTHORIZATION_RECEIPT_SCHEMA,
    AUTHORIZATION_REQUEST_SCHEMA as P0O_AUTHORIZATION_REQUEST_SCHEMA,
    CHAIN_SCHEMA as P0O_CHAIN_SCHEMA,
)

try:
    from scripts.civitasos_contracts.auth import CivitasHttpClient
except ModuleNotFoundError:  # pragma: no cover - direct script execution fallback
    from civitasos_contracts.auth import CivitasHttpClient  # type: ignore

CHAIN_SCHEMA = "p0p-first-controlled-beta-task-execution-chain:v1"
CONTEXT_SCHEMA = "p0p-p0o-context-validation:v1"
CONSUMPTION_SCHEMA = "p0p-single-use-authorization-consumption:v1"
TASK_RECEIPT_SCHEMA = "p0p-task-pool-execution-receipt:v1"
BETA_ARTIFACT_SCHEMA = "p0p-controlled-beta-status-evidence-index:v1"
NO_PRODUCTION_SCHEMA = "p0p-no-production-attestation:v1"
ROLLBACK_OR_ABORT_SCHEMA = "p0p-rollback-or-abort-receipt:v1"
OWNER_AUDIT_REVIEW_SCHEMA = "p0p-owner-audit-rollback-review:v1"
DEFAULT_BACKEND_URL = "http://127.0.0.1:8099"
DEFAULT_SERVICE_ID = "p0p_first_controlled_beta_task_execution"
DEFAULT_REQUESTER_ALIAS = "p0p_controlled_beta_operator"
DEFAULT_RUNNER_ALIAS = "p0p_controlled_beta_runner"
ACCEPTED_OWNER_DECISION = "accept_first_controlled_beta_task_execution"
ACCEPTED_AUDIT_DECISION = "accept_no_production_boundary"
ACCEPTED_ROLLBACK_DECISION = "accept_rollback_or_abort_receipt"
REQUIRED_SERVICE_SCOPES = {
    "agents:read",
    "agents:write",
    "a2a:pool:read",
    "a2a:pool:post",
    "a2a:pool:claim",
    "a2a:task:execute",
    "pool:read",
    "pool:post",
    "pool:claim",
    "pool:write",
    "audit:read",
    "operator:read-model",
}
PRODUCTION_FORBIDDEN_ACTIONS = {
    "public_ingress",
    "production_data_access",
    "production_transition",
    "production_receipt_write",
}


class JsonClient(Protocol):
    def healthz(self) -> None: ...

    def post(self, path: str, payload: dict[str, Any]) -> Any: ...

    def get(self, path: str) -> Any: ...

    def auth_report(self) -> dict[str, Any]: ...


class HttpJsonClient(CivitasHttpClient):
    def __init__(
        self,
        base_url: str,
        *,
        service_token_secret: str,
        service_id: str,
        service_scopes: list[str],
    ) -> None:
        super().__init__(
            base_url,
            service_token_secret=service_token_secret,
            service_id=service_id,
            service_scopes=service_scopes,
            require_service_token=True,
            demo_login_agent_id=None,
            required_service_token_error="P0-P requires a service-token secret; demo-login is forbidden",
            timeout=30,
        )

    def healthz(self) -> None:
        self.get("/healthz")

    def auth_report(self) -> dict[str, Any]:
        return self.auth_session().report()


def run_execution(
    *,
    p0o_summary_path: Path,
    output_root: Path,
    client: JsonClient,
    backend_url: str = DEFAULT_BACKEND_URL,
    operator_id: str = "operator-cc",
    requester_alias: str = DEFAULT_REQUESTER_ALIAS,
    runner_alias: str = DEFAULT_RUNNER_ALIAS,
    authorization_consumption_path: Path | None = None,
    owner_decision: str = ACCEPTED_OWNER_DECISION,
    audit_decision: str = ACCEPTED_AUDIT_DECISION,
    rollback_decision: str = ACCEPTED_ROLLBACK_DECISION,
) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "authorization_consumption": output_root / "p0p_authorization_consumption.json",
        "task_pool_execution_receipt": output_root / "p0p_task_pool_execution_receipt.json",
        "controlled_beta_artifact": output_root / "p0p_controlled_beta_status_evidence_index.json",
        "no_production_attestation": output_root / "p0p_no_production_attestation.json",
        "rollback_or_abort_receipt": output_root / "p0p_rollback_or_abort_receipt.json",
        "owner_audit_rollback_review": output_root / "p0p_owner_audit_rollback_review.json",
        "summary": output_root / "p0p_first_controlled_beta_task_execution_summary.json",
    }
    context = validate_p0o_context(p0o_summary_path)
    if context.get("passed") is not True:
        return _write_blocked_summary(
            output=artifacts["summary"],
            p0o_summary_path=p0o_summary_path,
            failures=context.get("failure_reasons", []),
            stage="p0o_context_validation",
        )

    receipt_path = Path(str(object_value(context.get("source_paths")).get("authorization_receipt")))
    lease_path = authorization_consumption_path or _default_consumption_lease_path(receipt_path)
    try:
        client.healthz()
        auth_report = client.auth_report()
    except Exception as exc:  # noqa: BLE001 - fail closed with summary
        return _write_blocked_summary(
            output=artifacts["summary"],
            p0o_summary_path=p0o_summary_path,
            failures=[f"backend_or_service_token_preflight_failed:{exc}"],
            stage="backend_service_token_preflight",
        )

    auth_failures = _validate_auth_report(auth_report, context.get("service_token_scopes", []))
    if auth_failures:
        return _write_blocked_summary(
            output=artifacts["summary"],
            p0o_summary_path=p0o_summary_path,
            failures=auth_failures,
            stage="service_token_auth_policy",
        )

    try:
        consumption = _claim_authorization(
            lease_path=lease_path,
            output_path=artifacts["authorization_consumption"],
            authorization_receipt_path=receipt_path,
            p0o_summary_path=p0o_summary_path,
            operator_id=operator_id,
        )
    except RuntimeError as exc:
        return _write_blocked_summary(
            output=artifacts["summary"],
            p0o_summary_path=p0o_summary_path,
            failures=[str(exc)],
            stage="single_use_authorization_consumption",
        )

    started_at = _now()
    failures: list[str] = []
    try:
        alias_suffix = _alias_suffix(output_root)
        requester = _quickstart_agent(
            client,
            alias=f"{requester_alias}_{alias_suffix}",
            name="P0-P Controlled Beta Operator",
            description="Requester identity for the first controlled beta task execution",
        )
        runner = _quickstart_agent(
            client,
            alias=f"{runner_alias}_{alias_suffix}",
            name="P0-P Controlled Beta Runner",
            description="Single authorized runner identity for P0-P first controlled beta task",
        )
        post_response = client.post(
            "/api/v1/a2a/pool/post",
            _task_payload(requester=requester, runner=runner, context=context, p0o_summary_path=p0o_summary_path),
        )
        task_id = str(object_value(post_response).get("task_id") or "")
        if not task_id:
            raise RuntimeError(f"pool post missing task_id: {post_response}")
        claim_response = client.post(
            "/api/v1/a2a/pool/claim",
            {"agent_id": runner["did"], "task_id": task_id, "stake_amount": 0},
        )
        claimed_task = _get_task(client, task_id)
        beta_artifact = _write_controlled_beta_artifact(
            output=artifacts["controlled_beta_artifact"],
            task_id=task_id,
            backend_url=backend_url,
            requester=requester,
            runner=runner,
            p0o_summary_path=p0o_summary_path,
            context=context,
        )
        no_production = _write_no_production_attestation(
            output=artifacts["no_production_attestation"],
            task_id=task_id,
            auth_report=auth_report,
            beta_artifact_path=artifacts["controlled_beta_artifact"],
        )
        rollback = _write_rollback_or_abort_receipt(
            output=artifacts["rollback_or_abort_receipt"],
            task_id=task_id,
            beta_artifact_path=artifacts["controlled_beta_artifact"],
            context=context,
        )
        review = _write_owner_audit_rollback_review(
            output=artifacts["owner_audit_rollback_review"],
            task_id=task_id,
            beta_artifact_path=artifacts["controlled_beta_artifact"],
            no_production_path=artifacts["no_production_attestation"],
            rollback_path=artifacts["rollback_or_abort_receipt"],
            owners=object_value(context.get("owners")),
            owner_decision=owner_decision,
            audit_decision=audit_decision,
            rollback_decision=rollback_decision,
        )
        execute_response = client.post(
            "/api/v1/a2a/task/execute",
            {
                "agent_id": runner["did"],
                "task_id": task_id,
                "output": _delivery_contract_safe_text(task_id=task_id),
                "success": True,
                "metadata": {
                    "runner": "p0p_first_controlled_beta_task_execution",
                    "operator_id": operator_id,
                    "execution_scope": "single_use_controlled_beta_task_pool_execution",
                    "h3_production_transition_allowed": "false",
                },
            },
        )
        final_task = _get_task(client, task_id)
        receipt = _write_task_pool_execution_receipt(
            output=artifacts["task_pool_execution_receipt"],
            task_id=task_id,
            requester=requester,
            runner=runner,
            post_response=post_response,
            claim_response=claim_response,
            execute_response=execute_response,
            claimed_task=claimed_task,
            final_task=final_task,
            consumption_path=artifacts["authorization_consumption"],
            auth_report=auth_report,
            beta_artifact_path=artifacts["controlled_beta_artifact"],
            no_production_path=artifacts["no_production_attestation"],
            rollback_path=artifacts["rollback_or_abort_receipt"],
            review_path=artifacts["owner_audit_rollback_review"],
        )
    except Exception as exc:  # noqa: BLE001 - fail closed after consumption
        completed_at = _now()
        summary = _summary(
            passed=False,
            failures=[f"controlled_beta_task_execution_failed:{exc}"],
            p0o_summary_path=p0o_summary_path,
            artifacts={"authorization_consumption": artifacts["authorization_consumption"]},
            readiness_state="blocked_after_authorization_consumption",
            execution_performed=False,
            p1_source_refs_ready=False,
            boundary=_execution_boundary(authorization_consumed=True),
            extra={
                "started_at": started_at,
                "completed_at": completed_at,
                "duration_seconds": _duration_seconds(started_at, completed_at),
                "consumption": consumption,
            },
        )
        write_json_object(artifacts["summary"], summary)
        return summary

    completed_at = _now()
    final_status = object_value(receipt.get("final_task")).get("status")
    checks: dict[str, bool] = {}
    check(checks, failures, "authorization_consumed", artifacts["authorization_consumption"].is_file())
    check(checks, failures, "exactly_one_task_posted", bool(receipt.get("task_id")))
    check(checks, failures, "claim_observed", receipt.get("claim_observed") is True)
    check(checks, failures, "delivery_observed", receipt.get("delivery_observed") is True)
    check(checks, failures, "final_status_delivered_or_completed", final_status in {"Delivered", "Completed"})
    check(checks, failures, "controlled_beta_artifact_written", beta_artifact.get("passed") is True)
    check(checks, failures, "no_production_attestation_passed", no_production.get("passed") is True)
    check(checks, failures, "rollback_or_abort_receipt_written", rollback.get("passed") is True)
    check(checks, failures, "owner_audit_rollback_review_passed", review.get("passed") is True)
    passed = _passed(checks, failures)
    summary = _summary(
        passed=passed,
        failures=failures,
        p0o_summary_path=p0o_summary_path,
        artifacts={name: path for name, path in artifacts.items() if name != "summary"},
        readiness_state="p0p_first_controlled_beta_task_execution_complete" if passed else "blocked_p0p_first_controlled_beta_task_execution",
        execution_performed=passed,
        p1_source_refs_ready=passed,
        boundary=_execution_boundary(
            service_token_used=True,
            authorization_consumed=True,
            requester_identity_registered=True,
            runner_identity_registered=True,
            task_pool_post_performed=True,
            task_pool_claim_performed=True,
            task_pool_execute_performed=True,
            task_pool_state_mutation_performed=True,
            controlled_beta_artifact_written=True,
            owner_audit_rollback_review_written=True,
        ),
        extra={
            "started_at": started_at,
            "completed_at": completed_at,
            "duration_seconds": _duration_seconds(started_at, completed_at),
            "checks": checks,
            "task_id": receipt.get("task_id"),
            "source_task_id": context.get("task", {}).get("task_id"),
        },
    )
    write_json_object(artifacts["summary"], summary)
    return summary


def validate_p0o_context(path: Path) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    try:
        summary = read_json_object(path)
    except Exception as exc:  # noqa: BLE001
        return _report(CONTEXT_SCHEMA, False, [f"p0o_summary_unreadable:{exc}"], checks)

    artifacts = object_value(summary.get("artifacts"))
    request = _read_verified_ref(artifacts.get("authorization_request"), checks, failures, "p0o_authorization_request")
    decision = _read_verified_ref(artifacts.get("authorization_decision"), checks, failures, "p0o_authorization_decision")
    receipt = _read_verified_ref(artifacts.get("authorization_receipt"), checks, failures, "p0o_authorization_receipt")
    readiness = object_value(summary.get("readiness"))
    authorization = object_value(summary.get("authorization"))
    task = object_value(request.get("controlled_beta_task"))
    task_id = str(task.get("task_id") or "")
    scopes = _texts(request.get("service_token_scopes"))
    forbidden_actions = set(_texts(task.get("forbidden_actions")))

    check(checks, failures, "p0o_summary_passed", summary.get("schema_version") == P0O_CHAIN_SCHEMA and summary.get("passed") is True)
    check(checks, failures, "p0o_execution_ready", readiness.get("p0p_first_controlled_beta_task_execution_ready") is True)
    check(checks, failures, "p0o_production_transition_closed", readiness.get("production_transition_allowed") is False)
    check(checks, failures, "p0o_boundary_pre_execution_closed", _pre_execution_boundary_closed(object_value(summary.get("boundary"))))
    check(checks, failures, "authorization_request_passed", request.get("schema_version") == P0O_AUTHORIZATION_REQUEST_SCHEMA and request.get("passed") is True)
    check(checks, failures, "authorization_decision_passed", decision.get("schema_version") == P0O_AUTHORIZATION_DECISION_SCHEMA and decision.get("passed") is True)
    check(checks, failures, "authorization_receipt_passed", receipt.get("schema_version") == P0O_AUTHORIZATION_RECEIPT_SCHEMA and receipt.get("passed") is True)
    check(checks, failures, "authorization_decision_authorize_once", decision.get("decision") == P0O_ACCEPTED_OPERATOR_DECISION)
    check(checks, failures, "summary_authorization_single_use", authorization.get("single_use") is True)
    check(checks, failures, "summary_authorization_unconsumed", authorization.get("consumed") is False)
    check(checks, failures, "receipt_single_use", receipt.get("single_use") is True)
    check(checks, failures, "receipt_unconsumed", receipt.get("consumed") is False)
    check(checks, failures, "receipt_requires_p0p", receipt.get("consumption_required_by") == "p0p_first_controlled_beta_task_execution_gate")
    check(checks, failures, "task_id_present", bool(task_id))
    check(checks, failures, "task_id_matches_receipt", task_id == receipt.get("task_id") == summary.get("task_id"))
    check(checks, failures, "task_low_risk", task.get("risk_class") == "low")
    check(checks, failures, "task_forbids_production", PRODUCTION_FORBIDDEN_ACTIONS <= forbidden_actions)
    check(checks, failures, "service_token_scopes_sufficient", REQUIRED_SERVICE_SCOPES <= set(scopes))
    passed = _passed(checks, failures)
    return {
        "schema_version": CONTEXT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "p0o_summary": summary,
        "authorization_request": request,
        "authorization_decision": decision,
        "authorization_receipt": receipt,
        "task": task,
        "owners": object_value(request.get("owners")),
        "service_token_scopes": scopes,
        "source_artifacts": {"p0o_summary": artifact_ref(path)},
        "source_paths": {
            "authorization_request": str(Path(str(object_value(artifacts.get("authorization_request")).get("path") or "")).resolve()),
            "authorization_decision": str(Path(str(object_value(artifacts.get("authorization_decision")).get("path") or "")).resolve()),
            "authorization_receipt": str(Path(str(object_value(artifacts.get("authorization_receipt")).get("path") or "")).resolve()),
        },
        "boundary": _execution_boundary(context_validation_written=passed),
        "non_claims": _non_claims(),
    }


def _read_verified_ref(value: Any, checks: dict[str, bool], failures: list[str], label: str) -> dict[str, Any]:
    ref = object_value(value)
    path = Path(str(ref.get("path") or ""))
    expected_hash = str(ref.get("sha256") or "")
    check(checks, failures, f"{label}_path_present", path.is_file())
    if not path.is_file():
        return {}
    check(checks, failures, f"{label}_hash_valid", bool(expected_hash) and sha256_file(path) == expected_hash)
    return read_json_object(path)


def _validate_auth_report(auth_report: dict[str, Any], required_scopes: Any) -> list[str]:
    failures: list[str] = []
    scopes = set(_texts(auth_report.get("scopes")))
    required = set(_texts(required_scopes)) or REQUIRED_SERVICE_SCOPES
    if auth_report.get("passed") is not True:
        failures.append("service_token_auth_failed")
    if auth_report.get("auth_method") not in {"service_token", "service-token"}:
        failures.append("service_token_required_demo_login_forbidden")
    if auth_report.get("token_recorded") is not False:
        failures.append("auth_token_must_not_be_recorded")
    if auth_report.get("production_allowed") is not False:
        failures.append("service_token_must_not_allow_production")
    if not required <= scopes:
        failures.append("service_token_missing_required_scopes")
    return failures


def _claim_authorization(
    *,
    lease_path: Path,
    output_path: Path,
    authorization_receipt_path: Path,
    p0o_summary_path: Path,
    operator_id: str,
) -> dict[str, Any]:
    value = {
        "schema_version": CONSUMPTION_SCHEMA,
        "state": "authorization_consumed_for_first_controlled_beta_task_execution",
        "consumed_at": _now(),
        "operator_id": operator_id,
        "source_authorization_receipt": artifact_ref(authorization_receipt_path),
        "source_p0o_summary": artifact_ref(p0o_summary_path),
        "single_use": True,
        "immutable": True,
        "lease_path": str(lease_path.resolve()),
    }
    lease_path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    try:
        descriptor = os.open(lease_path, flags, 0o600)
    except FileExistsError as exc:
        raise RuntimeError(f"authorization_already_consumed:{lease_path}") from exc
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(value, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    write_json_object(output_path, value)
    return value


def _quickstart_agent(client: JsonClient, *, alias: str, name: str, description: str) -> dict[str, Any]:
    result = client.post(
        "/api/v1/a2a/quickstart",
        {
            "public_key": _public_key_hex(alias),
            "alias": alias,
            "name": name,
            "endpoint": f"http://127.0.0.1:65535/{alias}",
            "description": description,
        },
    )
    agent = object_value(object_value(result).get("agent"))
    did = str(agent.get("did") or "")
    if not did:
        raise RuntimeError(f"quickstart response missing DID for {alias}: {result}")
    return {
        "alias": alias,
        "did": did,
        "name": agent.get("name") or name,
        "quickstart_response_status": object_value(result).get("success"),
    }


def _task_payload(*, requester: dict[str, Any], runner: dict[str, Any], context: dict[str, Any], p0o_summary_path: Path) -> dict[str, Any]:
    task = object_value(context.get("task"))
    return {
        "requester": requester["did"],
        "required_capability": "controlled_beta_evidence_index_generation",
        "reward": 1,
        "min_reputation": 0.0,
        "deadline_secs": 1800,
        "allowed_agents": [runner["did"]],
        "blocked_agents": [],
        "required_stake": 0,
        "input": {
            "civitasos_task_kind": "p0p_first_controlled_beta_status_evidence_index",
            "authorized_task_id": task.get("task_id"),
            "title": task.get("title"),
            "instruction": "Generate a controlled beta status evidence index from hash-bound P0-N/P0-O artifacts. Do not contact VMs, deploy, mutate source/Git, access production data, open public ingress, or write production receipts.",
            "acceptance_criteria": task.get("acceptance_criteria", []),
            "allowed_actions": task.get("allowed_actions", []),
            "forbidden_actions": task.get("forbidden_actions", []),
            "source_p0o_summary": artifact_ref(p0o_summary_path),
            "authorization_receipt": artifact_ref(Path(str(object_value(context.get("source_paths")).get("authorization_receipt")))),
            "delivery_contract": {
                "h3_must_remain_blocked": True,
                "production_transition_allowed": False,
                "production_receipt_write_allowed": False,
                "single_use_authorization_required": True,
            },
            "boundary": _execution_boundary(),
        },
    }


def _write_controlled_beta_artifact(
    *,
    output: Path,
    task_id: str,
    backend_url: str,
    requester: dict[str, Any],
    runner: dict[str, Any],
    p0o_summary_path: Path,
    context: dict[str, Any],
) -> dict[str, Any]:
    p0o_summary = object_value(context.get("p0o_summary"))
    request = object_value(context.get("authorization_request"))
    value = {
        "schema_version": BETA_ARTIFACT_SCHEMA,
        "passed": True,
        "generated_at": _now(),
        "task_id": task_id,
        "source_task_id": object_value(context.get("task")).get("task_id"),
        "backend_url": backend_url,
        "artifact_kind": "controlled_beta_status_evidence_index",
        "requester": requester,
        "runner": runner,
        "owners": context.get("owners", {}),
        "source_p0o_summary": artifact_ref(p0o_summary_path),
        "source_artifacts": p0o_summary.get("source_artifacts", {}),
        "p0o_artifacts": p0o_summary.get("artifacts", {}),
        "controlled_beta_task": request.get("controlled_beta_task", {}),
        "service_token_scopes": context.get("service_token_scopes", []),
        "evidence_index": [
            {"label": "p0o_summary", "artifact": artifact_ref(p0o_summary_path)},
            {"label": "p0o_authorization_request", "artifact": p0o_summary.get("artifacts", {}).get("authorization_request")},
            {"label": "p0o_authorization_decision", "artifact": p0o_summary.get("artifacts", {}).get("authorization_decision")},
            {"label": "p0o_authorization_receipt", "artifact": p0o_summary.get("artifacts", {}).get("authorization_receipt")},
            {"label": "p0n_summary", "artifact": p0o_summary.get("source_artifacts", {}).get("p0n_summary")},
        ],
        "h3_evidence_candidate": {
            "candidate_only": True,
            "satisfies_production_origin": False,
            "reason": "controlled_beta_task_execution_is_not_yet_real_production_origin_evidence",
        },
        "boundary": _execution_boundary(controlled_beta_artifact_written=True),
        "non_claims": _non_claims(),
    }
    write_json_object(output, value)
    return value


def _write_no_production_attestation(*, output: Path, task_id: str, auth_report: dict[str, Any], beta_artifact_path: Path) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    check(checks, failures, "service_token_used", auth_report.get("auth_method") in {"service_token", "service-token"})
    check(checks, failures, "demo_login_not_used", auth_report.get("auth_method") not in {"demo_login", "demo-login"})
    check(checks, failures, "production_not_allowed", auth_report.get("production_allowed") is False)
    check(checks, failures, "controlled_beta_artifact_exists", beta_artifact_path.is_file())
    passed = _passed(checks, failures)
    value = {
        "schema_version": NO_PRODUCTION_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "task_id": task_id,
        "source_controlled_beta_artifact": artifact_ref(beta_artifact_path),
        "attestation": {
            "demo_login_used": False,
            "vm_contact_performed": False,
            "deploy_performed": False,
            "source_tree_write_performed": False,
            "git_write_performed": False,
            "external_public_ingress_opened": False,
            "production_data_accessed": False,
            "production_transition_allowed": False,
            "production_receipt_write_allowed": False,
            "runtime_state_mutation_exceeds_task_scope": False,
            "secrets_recorded": False,
        },
        "auth_context": _sanitize_auth_report(auth_report),
        "boundary": _execution_boundary(service_token_used=True, controlled_beta_artifact_written=True),
        "non_claims": _non_claims(),
    }
    write_json_object(output, value)
    return value


def _write_rollback_or_abort_receipt(*, output: Path, task_id: str, beta_artifact_path: Path, context: dict[str, Any]) -> dict[str, Any]:
    value = {
        "schema_version": ROLLBACK_OR_ABORT_SCHEMA,
        "passed": True,
        "task_id": task_id,
        "state": "rollback_not_required_task_pool_only_execution_completed",
        "source_controlled_beta_artifact": artifact_ref(beta_artifact_path),
        "owners": context.get("owners", {}),
        "rollback_or_abort_actions": [
            "mark the controlled beta task execution receipt as rejected if owner/audit review fails",
            "do not promote this candidate to H.3 production evidence without production-origin source refs",
            "retain the immutable authorization consumption receipt for audit",
        ],
        "external_resources_to_restore": [],
        "vm_resources_to_restore": [],
        "boundary": _execution_boundary(controlled_beta_artifact_written=True),
        "non_claims": _non_claims(),
    }
    write_json_object(output, value)
    return value


def _write_owner_audit_rollback_review(
    *,
    output: Path,
    task_id: str,
    beta_artifact_path: Path,
    no_production_path: Path,
    rollback_path: Path,
    owners: dict[str, Any],
    owner_decision: str,
    audit_decision: str,
    rollback_decision: str,
) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    check(checks, failures, "controlled_beta_artifact_exists", beta_artifact_path.is_file())
    check(checks, failures, "no_production_attestation_exists", no_production_path.is_file())
    check(checks, failures, "rollback_or_abort_receipt_exists", rollback_path.is_file())
    check(checks, failures, "owner_decision_accepted", owner_decision == ACCEPTED_OWNER_DECISION)
    check(checks, failures, "audit_decision_accepted", audit_decision == ACCEPTED_AUDIT_DECISION)
    check(checks, failures, "rollback_decision_accepted", rollback_decision == ACCEPTED_ROLLBACK_DECISION)
    passed = _passed(checks, failures)
    value = {
        "schema_version": OWNER_AUDIT_REVIEW_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "reviewed_at": _now(),
        "task_id": task_id,
        "owners": owners,
        "owner_decision": owner_decision,
        "audit_decision": audit_decision,
        "rollback_decision": rollback_decision,
        "source_artifacts": {
            "controlled_beta_artifact": artifact_ref(beta_artifact_path),
            "no_production_attestation": artifact_ref(no_production_path),
            "rollback_or_abort_receipt": artifact_ref(rollback_path),
        },
        "h3_evidence_candidate": {
            "candidate_only": True,
            "satisfies_production_origin": False,
            "reason": "owner_audit_rollback_review_is_controlled_beta_review_not_production_origin_record",
        },
        "boundary": _execution_boundary(owner_audit_rollback_review_written=passed),
        "non_claims": _non_claims(),
    }
    write_json_object(output, value)
    return value


def _write_task_pool_execution_receipt(
    *,
    output: Path,
    task_id: str,
    requester: dict[str, Any],
    runner: dict[str, Any],
    post_response: Any,
    claim_response: Any,
    execute_response: Any,
    claimed_task: dict[str, Any],
    final_task: dict[str, Any],
    consumption_path: Path,
    auth_report: dict[str, Any],
    beta_artifact_path: Path,
    no_production_path: Path,
    rollback_path: Path,
    review_path: Path,
) -> dict[str, Any]:
    value = {
        "schema_version": TASK_RECEIPT_SCHEMA,
        "passed": final_task.get("status") in {"Delivered", "Completed"},
        "checked_at": _now(),
        "task_id": task_id,
        "requester": requester,
        "runner": runner,
        "post_response": post_response,
        "claim_response": claim_response,
        "execute_response": execute_response,
        "claimed_task": _task_summary(claimed_task),
        "final_task": _task_summary(final_task),
        "claim_observed": bool(final_task.get("claimed_by") or claimed_task.get("claimed_by")),
        "delivery_observed": final_task.get("status") in {"Delivered", "Completed"},
        "challenge_window_observed": bool(final_task.get("challenge_deadline_at") or final_task.get("challenge_window_secs")),
        "authorization_consumption": artifact_ref(consumption_path),
        "controlled_beta_artifact_ref": artifact_ref(beta_artifact_path),
        "no_production_attestation_ref": artifact_ref(no_production_path),
        "rollback_or_abort_ref": artifact_ref(rollback_path),
        "owner_audit_rollback_review_ref": artifact_ref(review_path),
        "auth_context": _sanitize_auth_report(auth_report),
        "h3_evidence_candidate": {
            "candidate_only": True,
            "satisfies_production_origin": False,
            "reason": "task_pool_execution_receipt_is_controlled_beta_runtime_evidence_not_production_origin_record",
        },
        "boundary": _execution_boundary(
            service_token_used=True,
            authorization_consumed=True,
            requester_identity_registered=True,
            runner_identity_registered=True,
            task_pool_post_performed=True,
            task_pool_claim_performed=True,
            task_pool_execute_performed=True,
            task_pool_state_mutation_performed=True,
            controlled_beta_artifact_written=True,
            owner_audit_rollback_review_written=True,
        ),
        "non_claims": _non_claims(),
    }
    write_json_object(output, value)
    return value


def _get_task(client: JsonClient, task_id: str) -> dict[str, Any]:
    response = client.get(f"/api/v1/a2a/pool/tasks/{task_id}")
    if isinstance(response, dict) and isinstance(response.get("task"), dict):
        return response["task"]
    raise RuntimeError(f"unexpected task response for {task_id}: {response}")


def _task_summary(task: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": task.get("id"),
        "requester": task.get("requester"),
        "required_capability": task.get("required_capability"),
        "status": task.get("status"),
        "claimed_by": task.get("claimed_by"),
        "posted_at": task.get("posted_at"),
        "claimed_at": task.get("claimed_at"),
        "delivered_at": task.get("delivered_at"),
        "challenge_deadline_at": task.get("challenge_deadline_at"),
        "challenge_window_secs": task.get("challenge_window_secs"),
        "has_output": task.get("output") not in (None, "", {}, []),
    }


def _summary(
    *,
    passed: bool,
    failures: list[str],
    p0o_summary_path: Path,
    artifacts: dict[str, Path],
    readiness_state: str,
    execution_performed: bool,
    p1_source_refs_ready: bool,
    boundary: dict[str, bool],
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "schema_version": CHAIN_SCHEMA,
        "passed": passed,
        "failure_reasons": sorted(set(failures)),
        "source_artifacts": {"p0o_summary": artifact_ref(p0o_summary_path)},
        "artifacts": {name: artifact_ref(path) for name, path in artifacts.items() if path.is_file()},
        "readiness": {
            "state": readiness_state,
            "p0p_first_controlled_beta_task_execution_complete": execution_performed,
            "p1_h3_source_ref_collection_ready": p1_source_refs_ready,
            "production_transition_allowed": False,
        },
        "boundary": boundary,
        "non_claims": _non_claims(),
        **(extra or {}),
    }


def _write_blocked_summary(*, output: Path, p0o_summary_path: Path, failures: list[str], stage: str) -> dict[str, Any]:
    summary = _summary(
        passed=False,
        failures=failures,
        p0o_summary_path=p0o_summary_path,
        artifacts={},
        readiness_state=f"blocked_p0p_execution_at_{stage}",
        execution_performed=False,
        p1_source_refs_ready=False,
        boundary=_execution_boundary(),
        extra={"blocked_stage": stage},
    )
    write_json_object(output, summary)
    return summary


def _pre_execution_boundary_closed(boundary: dict[str, Any]) -> bool:
    forbidden_true_keys = (
        "vm_contact_performed",
        "task_pool_post_performed",
        "task_pool_claim_performed",
        "task_pool_execute_performed",
        "preview_command_executed",
        "source_tree_write_performed",
        "git_write_performed",
        "external_public_ingress_opened",
        "production_transition_allowed",
        "production_receipt_write_allowed",
        "production_data_accessed",
        "secrets_recorded",
    )
    return all(boundary.get(key) is not True for key in forbidden_true_keys)


def _execution_boundary(**overrides: bool) -> dict[str, bool]:
    base = {
        "service_token_used": False,
        "demo_login_used": False,
        "authorization_consumed": False,
        "requester_identity_registered": False,
        "runner_identity_registered": False,
        "agent_process_started": False,
        "context_validation_written": False,
        "task_pool_post_performed": False,
        "task_pool_claim_performed": False,
        "task_pool_execute_performed": False,
        "task_pool_state_mutation_performed": False,
        "runtime_state_mutation_exceeds_task_scope": False,
        "controlled_beta_artifact_written": False,
        "owner_audit_rollback_review_written": False,
        "vm_contact_performed": False,
        "source_tree_write_performed": False,
        "git_write_performed": False,
        "deploy_performed": False,
        "external_public_ingress_opened": False,
        "production_data_accessed": False,
        "production_transition_allowed": False,
        "production_receipt_write_allowed": False,
        "secrets_recorded": False,
    }
    base.update(overrides)
    return base


def _report(schema: str, passed: bool, failures: list[str], checks: dict[str, bool]) -> dict[str, Any]:
    return {
        "schema_version": schema,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "boundary": _execution_boundary(),
        "non_claims": _non_claims(),
    }


def _non_claims() -> list[str]:
    return [
        "p0p_executes_one_controlled_beta_task_only",
        "p0p_requires_single_use_p0o_authorization_consumption",
        "p0p_task_pool_state_mutation_is_limited_to_authorized_task_scope",
        "p0p_does_not_contact_vm_targets",
        "p0p_does_not_deploy",
        "p0p_does_not_modify_source_or_git",
        "p0p_does_not_open_public_ingress",
        "p0p_does_not_access_production_data",
        "p0p_does_not_write_production_receipt",
        "p0p_does_not_authorize_production_transition",
    ]


def _default_consumption_lease_path(authorization_receipt_path: Path) -> Path:
    return authorization_receipt_path.with_name(f"{authorization_receipt_path.stem}.p0p.consumed.json")


def _delivery_contract_safe_text(*, task_id: str) -> str:
    return (
        f"P0-P controlled beta task {task_id} completed through CivitasOS task pool. "
        "H3 remains blocked; production transition is not authorized; production receipts are not written; "
        "VMs, deployment, source tree, Git, public ingress, and production data were not touched."
    )


def _sanitize_auth_report(auth_report: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in auth_report.items() if key != "token"}


def _public_key_hex(seed: str) -> str:
    del seed  # The SDK generates a valid Ed25519 key; deterministic hashes are not valid curve points.
    try:
        from civitasos import CivitasAgent  # type: ignore
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError("civitasos SDK is required to generate a valid Ed25519 public key") from exc
    agent = CivitasAgent(auto_discover=False)
    return str(agent.generate_keys())


def _alias_suffix(output_root: Path) -> str:
    source = output_root.parent.name if output_root.name == "p0p" else output_root.name
    cleaned = "".join(ch if ch.isalnum() or ch in {"_", "-"} else "_" for ch in source).strip("_")
    return (cleaned or "run")[-32:]


def _texts(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    result: list[str] = []
    for item in value:
        text = str(item).strip()
        if text and text not in result:
            result.append(text)
    return result


def _passed(checks: dict[str, bool], failures: list[str]) -> bool:
    return bool(checks) and all(checks.values()) and not failures


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _duration_seconds(started_at: str, completed_at: str) -> float:
    return (datetime.fromisoformat(completed_at) - datetime.fromisoformat(started_at)).total_seconds()


def _read_env_file(path: Path | None) -> dict[str, str]:
    if path is None or not path.is_file():
        return {}
    env: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        env[key.strip()] = value.strip().strip('"').strip("'")
    return env


def _service_token_secret(path: Path | None, explicit: str | None) -> str:
    if explicit:
        return explicit
    env = _read_env_file(path)
    return env.get("CIVITASOS_SERVICE_TOKEN_SECRET") or os.getenv("CIVITASOS_SERVICE_TOKEN_SECRET", "")


def _service_scopes_from_p0o_summary(path: Path) -> list[str]:
    summary = read_json_object(path)
    artifacts = object_value(summary.get("artifacts"))
    request_ref = object_value(artifacts.get("authorization_request"))
    request_path = Path(str(request_ref.get("path") or ""))
    if not request_path.is_file():
        return []
    request = read_json_object(request_path)
    return _texts(request.get("service_token_scopes"))


def main() -> int:
    parser = argparse.ArgumentParser(description="Run P0-P first controlled beta task execution gate")
    parser.add_argument("--p0o-summary", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--backend-url", default=DEFAULT_BACKEND_URL)
    parser.add_argument("--service-token-env-file")
    parser.add_argument("--service-token-secret")
    parser.add_argument("--service-id", default=DEFAULT_SERVICE_ID)
    parser.add_argument("--operator-id", default="operator-cc")
    parser.add_argument("--requester-alias", default=DEFAULT_REQUESTER_ALIAS)
    parser.add_argument("--runner-alias", default=DEFAULT_RUNNER_ALIAS)
    parser.add_argument("--authorization-consumption-path")
    args = parser.parse_args()
    env_file = Path(args.service_token_env_file) if args.service_token_env_file else None
    secret = _service_token_secret(env_file, args.service_token_secret)
    if not secret:
        raise SystemExit("P0-P execution requires CIVITASOS_SERVICE_TOKEN_SECRET; demo-login is forbidden")
    scopes = _service_scopes_from_p0o_summary(args.p0o_summary)
    if not scopes:
        raise SystemExit("P0-P execution could not resolve authorized service-token scopes")
    client = HttpJsonClient(args.backend_url, service_token_secret=secret, service_id=args.service_id, service_scopes=scopes)
    summary = run_execution(
        p0o_summary_path=args.p0o_summary,
        output_root=args.output_root,
        client=client,
        backend_url=args.backend_url,
        operator_id=args.operator_id,
        requester_alias=args.requester_alias,
        runner_alias=args.runner_alias,
        authorization_consumption_path=Path(args.authorization_consumption_path) if args.authorization_consumption_path else None,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if summary.get("passed") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
