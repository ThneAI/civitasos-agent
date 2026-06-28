"""Execute the first Post-H3 internal controlled runtime task.

PostH3-D consumes PostH3-A/B/C artifacts and executes exactly one low-risk
internal task through the CivitasOS task pool. The only allowed runtime mutation
is task-pool state for the authorized task. It does not contact VMs, deploy,
modify source/Git, open public ingress, access production data, or write
production runtime receipts.
"""

from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

from benchmarks.i_gate_evidence import artifact_ref, check, object_value, read_json_object, sha256_file, write_json_object
from benchmarks.post_h3_deployment_boundary_gate import CHAIN_SCHEMA as POST_H3B_SCHEMA
from benchmarks.post_h3_internal_runtime_authorization_gate import CHAIN_SCHEMA as POST_H3A_SCHEMA
from benchmarks.post_h3_internal_runtime_authorization_gate import RECEIPT_SCHEMA as POST_H3A_RECEIPT_SCHEMA
from benchmarks.post_h3_internal_runtime_authorization_gate import REQUEST_SCHEMA as POST_H3A_REQUEST_SCHEMA
from benchmarks.post_h3_rollback_abort_drill_gate import CHAIN_SCHEMA as POST_H3C_SCHEMA

try:
    from scripts.civitasos_contracts.auth import CivitasHttpClient
except ModuleNotFoundError:  # pragma: no cover - direct script execution fallback
    from civitasos_contracts.auth import CivitasHttpClient  # type: ignore


CHAIN_SCHEMA = "post-h3-first-internal-runtime-execution-chain:v1"
CONTEXT_SCHEMA = "post-h3d-runtime-context-validation:v1"
CONSUMPTION_SCHEMA = "post-h3d-internal-runtime-authorization-consumption:v1"
TASK_RECEIPT_SCHEMA = "post-h3d-task-pool-execution-receipt:v1"
STATUS_INDEX_SCHEMA = "post-h3d-internal-runtime-status-evidence-index:v1"
NO_PRODUCTION_SCHEMA = "post-h3d-no-production-attestation:v1"
ROLLBACK_DECISION_SCHEMA = "post-h3d-rollback-or-continue-decision:v1"
OWNER_AUDIT_REVIEW_SCHEMA = "post-h3d-owner-audit-review:v1"

DEFAULT_BACKEND_URL = "http://127.0.0.1:8099"
DEFAULT_SERVICE_ID = "post_h3d_first_internal_runtime_execution"
DEFAULT_REQUESTER_ALIAS = "post_h3d_internal_runtime_operator"
DEFAULT_RUNNER_ALIAS = "post_h3d_internal_runtime_runner"
POST_H3D_TASK_ID = "post-h3d-task:first-internal-runtime-status-evidence-index"
ACCEPTED_OWNER_DECISION = "accept_post_h3d_first_internal_runtime_execution"
ACCEPTED_AUDIT_DECISION = "accept_post_h3d_no_production_boundary"
ACCEPTED_ROLLBACK_DECISION = "continue_after_post_h3d_no_rollback_required"

REQUIRED_SERVICE_SCOPES = {
    "agents:read",
    "agents:write",
    "audit:read",
    "audit:write",
    "pool:claim",
    "pool:post",
    "pool:read",
    "pool:write",
}
PRODUCTION_FORBIDDEN_ACTIONS = {
    "public_ingress",
    "production_data_access",
    "production_transition",
    "production_runtime_receipt_write",
}
NON_CLAIMS = (
    "post_h3d_executes_one_internal_task_only",
    "post_h3d_task_pool_state_mutation_is_limited_to_authorized_task_scope",
    "post_h3d_does_not_contact_vm_targets",
    "post_h3d_does_not_deploy",
    "post_h3d_does_not_modify_source_or_git",
    "post_h3d_does_not_open_public_ingress",
    "post_h3d_does_not_access_production_data",
    "post_h3d_does_not_write_production_runtime_receipts",
)


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
            required_service_token_error="PostH3-D requires a service-token secret; demo-login is forbidden",
            timeout=30,
        )

    def healthz(self) -> None:
        self.get("/healthz")

    def auth_report(self) -> dict[str, Any]:
        return self.auth_session().report()


def run_execution(
    *,
    post_h3a_summary_path: Path,
    post_h3b_summary_path: Path,
    post_h3c_summary_path: Path,
    output_root: Path,
    client: JsonClient,
    backend_url: str = DEFAULT_BACKEND_URL,
    operator_id: str = "operator-primary",
    requester_alias: str = DEFAULT_REQUESTER_ALIAS,
    runner_alias: str = DEFAULT_RUNNER_ALIAS,
    authorization_consumption_path: Path | None = None,
    owner_decision: str = ACCEPTED_OWNER_DECISION,
    audit_decision: str = ACCEPTED_AUDIT_DECISION,
    rollback_decision: str = ACCEPTED_ROLLBACK_DECISION,
) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "context_validation": output_root / "post_h3d_runtime_context_validation.json",
        "authorization_consumption": output_root / "post_h3d_authorization_consumption.json",
        "task_pool_execution_receipt": output_root / "post_h3d_task_pool_execution_receipt.json",
        "status_evidence_index": output_root / "post_h3d_internal_runtime_status_evidence_index.json",
        "no_production_attestation": output_root / "post_h3d_no_production_attestation.json",
        "rollback_or_continue_decision": output_root / "post_h3d_rollback_or_continue_decision.json",
        "owner_audit_review": output_root / "post_h3d_owner_audit_review.json",
        "summary": output_root / "post_h3d_first_internal_runtime_execution_summary.json",
    }
    context = validate_post_h3_runtime_context(
        post_h3a_summary_path=post_h3a_summary_path,
        post_h3b_summary_path=post_h3b_summary_path,
        post_h3c_summary_path=post_h3c_summary_path,
        output=artifacts["context_validation"],
    )
    if context.get("passed") is not True:
        return _write_blocked_summary(
            output=artifacts["summary"],
            context_paths=_context_paths(post_h3a_summary_path, post_h3b_summary_path, post_h3c_summary_path),
            failures=context.get("failure_reasons", []),
            stage="post_h3_context_validation",
        )

    try:
        client.healthz()
        auth_report = client.auth_report()
    except Exception as exc:  # noqa: BLE001
        return _write_blocked_summary(
            output=artifacts["summary"],
            context_paths=_context_paths(post_h3a_summary_path, post_h3b_summary_path, post_h3c_summary_path),
            failures=[f"backend_or_service_token_preflight_failed:{exc}"],
            stage="backend_service_token_preflight",
        )
    auth_failures = _validate_auth_report(auth_report, context.get("service_token_scopes", []))
    if auth_failures:
        return _write_blocked_summary(
            output=artifacts["summary"],
            context_paths=_context_paths(post_h3a_summary_path, post_h3b_summary_path, post_h3c_summary_path),
            failures=auth_failures,
            stage="service_token_auth_policy",
        )

    receipt_path = Path(str(object_value(context.get("source_paths")).get("post_h3a_authorization_receipt")))
    lease_path = authorization_consumption_path or _default_consumption_lease_path(receipt_path)
    try:
        consumption = _claim_authorization(
            lease_path=lease_path,
            output_path=artifacts["authorization_consumption"],
            authorization_receipt_path=receipt_path,
            post_h3c_summary_path=post_h3c_summary_path,
            operator_id=operator_id,
        )
    except RuntimeError as exc:
        return _write_blocked_summary(
            output=artifacts["summary"],
            context_paths=_context_paths(post_h3a_summary_path, post_h3b_summary_path, post_h3c_summary_path),
            failures=[str(exc)],
            stage="internal_runtime_authorization_consumption",
        )

    started_at = _now()
    try:
        requester, runner, task_id, receipt, status_index, no_production, rollback, review = _execute_task_pool_path(
            client=client,
            output_root=output_root,
            artifacts=artifacts,
            context=context,
            post_h3a_summary_path=post_h3a_summary_path,
            post_h3b_summary_path=post_h3b_summary_path,
            post_h3c_summary_path=post_h3c_summary_path,
            backend_url=backend_url,
            operator_id=operator_id,
            requester_alias=requester_alias,
            runner_alias=runner_alias,
            auth_report=auth_report,
            owner_decision=owner_decision,
            audit_decision=audit_decision,
            rollback_decision=rollback_decision,
        )
    except Exception as exc:  # noqa: BLE001
        completed_at = _now()
        summary = _summary(
            passed=False,
            failures=[f"post_h3d_task_pool_execution_failed:{exc}"],
            context_paths=_context_paths(post_h3a_summary_path, post_h3b_summary_path, post_h3c_summary_path),
            artifacts={"authorization_consumption": artifacts["authorization_consumption"]},
            readiness_state="blocked_after_internal_runtime_authorization_consumption",
            execution_performed=False,
            post_h3e_ready=False,
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
    failures: list[str] = []
    checks: dict[str, bool] = {}
    final_task = object_value(receipt.get("final_task"))
    check(checks, failures, "authorization_consumed", artifacts["authorization_consumption"].is_file())
    check(checks, failures, "exactly_one_task_posted", bool(task_id))
    check(checks, failures, "claim_observed", receipt.get("claim_observed") is True)
    check(checks, failures, "delivery_observed", receipt.get("delivery_observed") is True)
    check(checks, failures, "final_status_delivered_or_completed", final_task.get("status") in {"Delivered", "Completed"})
    check(checks, failures, "status_evidence_index_written", status_index.get("passed") is True)
    check(checks, failures, "no_production_attestation_passed", no_production.get("passed") is True)
    check(checks, failures, "rollback_or_continue_decision_passed", rollback.get("passed") is True)
    check(checks, failures, "owner_audit_review_passed", review.get("passed") is True)
    passed = _passed(checks, failures)
    summary = _summary(
        passed=passed,
        failures=failures,
        context_paths=_context_paths(post_h3a_summary_path, post_h3b_summary_path, post_h3c_summary_path),
        artifacts={name: path for name, path in artifacts.items() if name != "summary"},
        readiness_state="post_h3d_first_internal_runtime_execution_complete" if passed else "blocked_post_h3d_first_internal_runtime_execution",
        execution_performed=passed,
        post_h3e_ready=passed,
        boundary=_execution_boundary(
            service_token_used=True,
            authorization_consumed=True,
            requester_identity_registered=True,
            runner_identity_registered=True,
            context_validation_written=True,
            task_pool_post_performed=True,
            task_pool_claim_performed=True,
            task_pool_execute_performed=True,
            task_pool_state_mutation_performed=True,
            internal_runtime_status_evidence_index_written=True,
            owner_audit_review_written=True,
        ),
        extra={
            "started_at": started_at,
            "completed_at": completed_at,
            "duration_seconds": _duration_seconds(started_at, completed_at),
            "checks": checks,
            "task_id": task_id,
            "source_task_id": POST_H3D_TASK_ID,
            "requester": requester,
            "runner": runner,
        },
    )
    write_json_object(artifacts["summary"], summary)
    return summary


def validate_post_h3_runtime_context(
    *,
    post_h3a_summary_path: Path,
    post_h3b_summary_path: Path,
    post_h3c_summary_path: Path,
    output: Path | None = None,
) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    post_h3a = _read_json_checked(post_h3a_summary_path, checks, failures, "post_h3a_summary")
    post_h3b = _read_json_checked(post_h3b_summary_path, checks, failures, "post_h3b_summary")
    post_h3c = _read_json_checked(post_h3c_summary_path, checks, failures, "post_h3c_summary")
    a_artifacts = object_value(post_h3a.get("artifacts"))
    request = _read_verified_ref(a_artifacts.get("authorization_request"), checks, failures, "post_h3a_authorization_request")
    receipt = _read_verified_ref(a_artifacts.get("authorization_receipt"), checks, failures, "post_h3a_authorization_receipt")

    _check_post_h3a(post_h3a, request, receipt, checks, failures)
    _check_post_h3b(post_h3b, post_h3a_summary_path, checks, failures)
    _check_post_h3c(post_h3c, post_h3b_summary_path, checks, failures)

    task = _post_h3d_task()
    scopes = _request_service_scopes(request)
    passed = _passed(checks, failures)
    report = {
        "schema_version": CONTEXT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "task": task,
        "service_token_scopes": scopes,
        "owners": _owners_from_post_h3b(post_h3b),
        "post_h3a_summary": post_h3a,
        "post_h3b_summary": post_h3b,
        "post_h3c_summary": post_h3c,
        "source_artifacts": _context_refs(post_h3a_summary_path, post_h3b_summary_path, post_h3c_summary_path),
        "source_paths": {
            "post_h3a_authorization_request": str(_ref_path(a_artifacts.get("authorization_request")).resolve()),
            "post_h3a_authorization_receipt": str(_ref_path(a_artifacts.get("authorization_receipt")).resolve()),
        },
        "boundary": _execution_boundary(context_validation_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    if output is not None:
        write_json_object(output, report)
    return report


def _execute_task_pool_path(
    *,
    client: JsonClient,
    output_root: Path,
    artifacts: dict[str, Path],
    context: dict[str, Any],
    post_h3a_summary_path: Path,
    post_h3b_summary_path: Path,
    post_h3c_summary_path: Path,
    backend_url: str,
    operator_id: str,
    requester_alias: str,
    runner_alias: str,
    auth_report: dict[str, Any],
    owner_decision: str,
    audit_decision: str,
    rollback_decision: str,
) -> tuple[dict[str, Any], dict[str, Any], str, dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    alias_suffix = _alias_suffix(output_root)
    requester = _quickstart_agent(
        client,
        alias=f"{requester_alias}_{alias_suffix}",
        name="PostH3-D Internal Runtime Operator",
        description="Requester identity for first Post-H3 internal controlled runtime task",
    )
    runner = _quickstart_agent(
        client,
        alias=f"{runner_alias}_{alias_suffix}",
        name="PostH3-D Internal Runtime Runner",
        description="Single authorized runner identity for first Post-H3 internal controlled runtime task",
    )
    post_response = client.post(
        "/api/v1/a2a/pool/post",
        _task_payload(
            requester=requester,
            runner=runner,
            context=context,
            post_h3a_summary_path=post_h3a_summary_path,
            post_h3b_summary_path=post_h3b_summary_path,
            post_h3c_summary_path=post_h3c_summary_path,
        ),
    )
    task_id = str(object_value(post_response).get("task_id") or "")
    if not task_id:
        raise RuntimeError(f"pool post missing task_id: {post_response}")
    claim_response = client.post("/api/v1/a2a/pool/claim", {"agent_id": runner["did"], "task_id": task_id, "stake_amount": 0})
    claimed_task = _get_task(client, task_id)
    status_index = _write_status_evidence_index(
        output=artifacts["status_evidence_index"],
        task_id=task_id,
        backend_url=backend_url,
        requester=requester,
        runner=runner,
        context=context,
        paths=_context_paths(post_h3a_summary_path, post_h3b_summary_path, post_h3c_summary_path),
    )
    no_production = _write_no_production_attestation(
        output=artifacts["no_production_attestation"],
        task_id=task_id,
        auth_report=auth_report,
        status_index_path=artifacts["status_evidence_index"],
    )
    rollback = _write_rollback_or_continue_decision(
        output=artifacts["rollback_or_continue_decision"],
        task_id=task_id,
        status_index_path=artifacts["status_evidence_index"],
        context=context,
        rollback_decision=rollback_decision,
    )
    review = _write_owner_audit_review(
        output=artifacts["owner_audit_review"],
        task_id=task_id,
        status_index_path=artifacts["status_evidence_index"],
        no_production_path=artifacts["no_production_attestation"],
        rollback_path=artifacts["rollback_or_continue_decision"],
        owners=object_value(context.get("owners")),
        owner_decision=owner_decision,
        audit_decision=audit_decision,
    )
    execute_response = client.post(
        "/api/v1/a2a/task/execute",
        {
            "agent_id": runner["did"],
            "task_id": task_id,
            "output": _delivery_contract_safe_text(task_id=task_id),
            "success": True,
            "metadata": {
                "runner": "post_h3_first_internal_runtime_execution",
                "operator_id": operator_id,
                "execution_scope": "single_post_h3_internal_runtime_task_pool_execution",
                "production_runtime_receipt_write_allowed": "false",
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
        status_index_path=artifacts["status_evidence_index"],
        no_production_path=artifacts["no_production_attestation"],
        rollback_path=artifacts["rollback_or_continue_decision"],
        review_path=artifacts["owner_audit_review"],
        auth_report=auth_report,
    )
    return requester, runner, task_id, receipt, status_index, no_production, rollback, review


def _check_post_h3a(summary: dict[str, Any], request: dict[str, Any], receipt: dict[str, Any], checks: dict[str, bool], failures: list[str]) -> None:
    readiness = object_value(summary.get("readiness"))
    boundary = object_value(summary.get("boundary"))
    scopes = set(_request_service_scopes(request))
    check(checks, failures, "post_h3a_schema_valid", summary.get("schema_version") == POST_H3A_SCHEMA)
    check(checks, failures, "post_h3a_passed", summary.get("passed") is True)
    check(checks, failures, "post_h3a_runtime_allowed", readiness.get("runtime_execution_allowed") is True)
    check(checks, failures, "post_h3a_runtime_not_performed", readiness.get("runtime_execution_performed") is False)
    check(checks, failures, "post_h3a_receipt_write_not_allowed", readiness.get("production_runtime_receipt_write_allowed") is False)
    check(checks, failures, "post_h3a_no_deploy", boundary.get("deploy_performed") is False)
    check(checks, failures, "post_h3a_no_public_ingress", boundary.get("external_public_ingress_opened") is False)
    check(checks, failures, "post_h3a_request_passed", request.get("schema_version") == POST_H3A_REQUEST_SCHEMA and request.get("passed") is True)
    check(checks, failures, "post_h3a_receipt_passed", receipt.get("schema_version") == POST_H3A_RECEIPT_SCHEMA and receipt.get("passed") is True)
    check(checks, failures, "post_h3a_receipt_single_use", receipt.get("single_use") is True)
    check(checks, failures, "post_h3a_receipt_unconsumed", receipt.get("consumed") is False)
    check(checks, failures, "post_h3a_service_scopes_sufficient", REQUIRED_SERVICE_SCOPES <= scopes)


def _check_post_h3b(summary: dict[str, Any], post_h3a_summary_path: Path, checks: dict[str, bool], failures: list[str]) -> None:
    readiness = object_value(summary.get("readiness"))
    boundary = object_value(summary.get("boundary"))
    source = object_value(summary.get("source_artifacts")).get("post_h3a_summary")
    check(checks, failures, "post_h3b_schema_valid", summary.get("schema_version") == POST_H3B_SCHEMA)
    check(checks, failures, "post_h3b_passed", summary.get("passed") is True)
    check(checks, failures, "post_h3b_boundary_ready", readiness.get("post_h3_deployment_boundary_ready") is True)
    check(checks, failures, "post_h3b_runtime_allowed", readiness.get("runtime_execution_allowed") is True)
    check(checks, failures, "post_h3b_runtime_not_performed", readiness.get("runtime_execution_performed") is False)
    check(checks, failures, "post_h3b_no_deploy", boundary.get("deploy_performed") is False)
    check(checks, failures, "post_h3b_no_public_ingress", boundary.get("external_public_ingress_opened") is False)
    check(checks, failures, "post_h3b_source_matches_post_h3a", _artifact_matches(source, post_h3a_summary_path))


def _check_post_h3c(summary: dict[str, Any], post_h3b_summary_path: Path, checks: dict[str, bool], failures: list[str]) -> None:
    readiness = object_value(summary.get("readiness"))
    boundary = object_value(summary.get("boundary"))
    source = object_value(summary.get("source_artifacts")).get("post_h3b_summary")
    check(checks, failures, "post_h3c_schema_valid", summary.get("schema_version") == POST_H3C_SCHEMA)
    check(checks, failures, "post_h3c_passed", summary.get("passed") is True)
    check(checks, failures, "post_h3c_first_execution_ready", readiness.get("first_internal_runtime_execution_ready") is True)
    check(checks, failures, "post_h3c_runtime_allowed", readiness.get("runtime_execution_allowed") is True)
    check(checks, failures, "post_h3c_runtime_not_performed", readiness.get("runtime_execution_performed") is False)
    check(checks, failures, "post_h3c_abort_path_verified", boundary.get("abort_path_verified") is True)
    check(checks, failures, "post_h3c_rollback_path_verified", boundary.get("rollback_path_verified") is True)
    check(checks, failures, "post_h3c_no_deploy", boundary.get("deploy_performed") is False)
    check(checks, failures, "post_h3c_no_public_ingress", boundary.get("external_public_ingress_opened") is False)
    check(checks, failures, "post_h3c_receipt_write_not_allowed", boundary.get("production_runtime_receipt_write_allowed") is False)
    check(checks, failures, "post_h3c_source_matches_post_h3b", _artifact_matches(source, post_h3b_summary_path))


def _post_h3d_task() -> dict[str, Any]:
    return {
        "task_id": POST_H3D_TASK_ID,
        "title": "Generate first internal runtime status and evidence index",
        "risk_class": "low",
        "environment": "internal_controlled_runtime_task_pool_only",
        "allowed_actions": [
            "service_token_task_pool_post_claim_execute",
            "internal_runtime_status_evidence_index_generation",
            "owner_audit_rollback_review_packaging",
        ],
        "forbidden_actions": sorted(PRODUCTION_FORBIDDEN_ACTIONS),
        "acceptance_criteria": [
            "task is posted, claimed, executed, and delivered through CivitasOS task pool",
            "result artifact summarizes PostH3-A/B/C and H.3 transition refs without secrets",
            "owner, audit, rollback-or-continue receipts are written",
            "production receipt write remains unauthorized",
        ],
    }


def _task_payload(
    *,
    requester: dict[str, Any],
    runner: dict[str, Any],
    context: dict[str, Any],
    post_h3a_summary_path: Path,
    post_h3b_summary_path: Path,
    post_h3c_summary_path: Path,
) -> dict[str, Any]:
    task = object_value(context.get("task"))
    return {
        "requester": requester["did"],
        "required_capability": "post_h3_internal_runtime_evidence_index_generation",
        "reward": 1,
        "min_reputation": 0.0,
        "deadline_secs": 1800,
        "allowed_agents": [runner["did"]],
        "blocked_agents": [],
        "required_stake": 0,
        "input": {
            "civitasos_task_kind": "post_h3d_first_internal_runtime_status_evidence_index",
            "authorized_task_id": task.get("task_id"),
            "title": task.get("title"),
            "instruction": "Generate a PostH3-D internal runtime status and evidence index from hash-bound PostH3-A/B/C artifacts. Do not contact VMs, deploy, mutate source/Git, access production data, open public ingress, or write production runtime receipts.",
            "acceptance_criteria": task.get("acceptance_criteria", []),
            "allowed_actions": task.get("allowed_actions", []),
            "forbidden_actions": task.get("forbidden_actions", []),
            "source_post_h3a_summary": artifact_ref(post_h3a_summary_path),
            "source_post_h3b_summary": artifact_ref(post_h3b_summary_path),
            "source_post_h3c_summary": artifact_ref(post_h3c_summary_path),
            "delivery_contract": {
                "runtime_execution_allowed": True,
                "production_runtime_receipt_write_allowed": False,
                "single_internal_task_only": True,
            },
            "boundary": _execution_boundary(),
        },
    }


def _write_status_evidence_index(
    *,
    output: Path,
    task_id: str,
    backend_url: str,
    requester: dict[str, Any],
    runner: dict[str, Any],
    context: dict[str, Any],
    paths: dict[str, Path],
) -> dict[str, Any]:
    value = {
        "schema_version": STATUS_INDEX_SCHEMA,
        "passed": True,
        "generated_at": _now(),
        "task_id": task_id,
        "source_task_id": POST_H3D_TASK_ID,
        "backend_url": backend_url,
        "artifact_kind": "post_h3_internal_runtime_status_evidence_index",
        "requester": requester,
        "runner": runner,
        "owners": context.get("owners", {}),
        "service_token_scopes": context.get("service_token_scopes", []),
        "evidence_index": [
            {"label": "post_h3a_summary", "artifact": artifact_ref(paths["post_h3a_summary"])},
            {"label": "post_h3b_summary", "artifact": artifact_ref(paths["post_h3b_summary"])},
            {"label": "post_h3c_summary", "artifact": artifact_ref(paths["post_h3c_summary"])},
        ],
        "post_h3e_candidate": {
            "production_runtime_receipt_write_authorization_ready": False,
            "reason": "PostH3-D execution must be reviewed before PostH3-E receipt-write authorization.",
        },
        "boundary": _execution_boundary(internal_runtime_status_evidence_index_written=True),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, value)
    return value


def _write_no_production_attestation(*, output: Path, task_id: str, auth_report: dict[str, Any], status_index_path: Path) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    check(checks, failures, "service_token_used", auth_report.get("auth_method") in {"service_token", "service-token"})
    check(checks, failures, "demo_login_not_used", auth_report.get("auth_method") not in {"demo_login", "demo-login"})
    check(checks, failures, "production_not_allowed", auth_report.get("production_allowed") is False)
    check(checks, failures, "status_index_exists", status_index_path.is_file())
    passed = _passed(checks, failures)
    value = {
        "schema_version": NO_PRODUCTION_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "task_id": task_id,
        "source_status_evidence_index": artifact_ref(status_index_path),
        "attestation": {
            "demo_login_used": False,
            "vm_contact_performed": False,
            "deploy_performed": False,
            "source_tree_write_performed": False,
            "git_write_performed": False,
            "external_public_ingress_opened": False,
            "production_data_accessed": False,
            "production_runtime_receipt_write_allowed": False,
            "runtime_state_mutation_exceeds_task_scope": False,
            "secrets_recorded": False,
        },
        "auth_context": _sanitize_auth_report(auth_report),
        "boundary": _execution_boundary(service_token_used=True, internal_runtime_status_evidence_index_written=True),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, value)
    return value


def _write_rollback_or_continue_decision(
    *,
    output: Path,
    task_id: str,
    status_index_path: Path,
    context: dict[str, Any],
    rollback_decision: str,
) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    check(checks, failures, "status_index_exists", status_index_path.is_file())
    check(checks, failures, "rollback_decision_accepted", rollback_decision == ACCEPTED_ROLLBACK_DECISION)
    passed = _passed(checks, failures)
    value = {
        "schema_version": ROLLBACK_DECISION_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "task_id": task_id,
        "decision": rollback_decision,
        "state": "continue_no_rollback_required" if passed else "blocked_post_h3d_rollback_decision",
        "source_status_evidence_index": artifact_ref(status_index_path),
        "owners": context.get("owners", {}),
        "rollback_or_abort_actions": [
            "mark PostH3-D execution rejected if owner/audit review fails",
            "do not write production runtime receipt until PostH3-E authorization passes",
            "retain authorization consumption and task-pool receipt for audit",
        ],
        "external_resources_to_restore": [],
        "vm_resources_to_restore": [],
        "boundary": _execution_boundary(internal_runtime_status_evidence_index_written=True),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, value)
    return value


def _write_owner_audit_review(
    *,
    output: Path,
    task_id: str,
    status_index_path: Path,
    no_production_path: Path,
    rollback_path: Path,
    owners: dict[str, Any],
    owner_decision: str,
    audit_decision: str,
) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    check(checks, failures, "status_index_exists", status_index_path.is_file())
    check(checks, failures, "no_production_attestation_exists", no_production_path.is_file())
    check(checks, failures, "rollback_or_continue_decision_exists", rollback_path.is_file())
    check(checks, failures, "owner_decision_accepted", owner_decision == ACCEPTED_OWNER_DECISION)
    check(checks, failures, "audit_decision_accepted", audit_decision == ACCEPTED_AUDIT_DECISION)
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
        "source_artifacts": {
            "status_evidence_index": artifact_ref(status_index_path),
            "no_production_attestation": artifact_ref(no_production_path),
            "rollback_or_continue_decision": artifact_ref(rollback_path),
        },
        "post_h3e_candidate": {
            "production_runtime_receipt_write_authorization_ready": passed,
            "reason": "Owner and audit review accepted PostH3-D internal runtime execution; PostH3-E must still authorize receipt writing separately.",
        },
        "boundary": _execution_boundary(owner_audit_review_written=passed),
        "non_claims": list(NON_CLAIMS),
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
    status_index_path: Path,
    no_production_path: Path,
    rollback_path: Path,
    review_path: Path,
    auth_report: dict[str, Any],
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
        "status_evidence_index_ref": artifact_ref(status_index_path),
        "no_production_attestation_ref": artifact_ref(no_production_path),
        "rollback_or_continue_ref": artifact_ref(rollback_path),
        "owner_audit_review_ref": artifact_ref(review_path),
        "auth_context": _sanitize_auth_report(auth_report),
        "boundary": _execution_boundary(
            service_token_used=True,
            requester_identity_registered=True,
            runner_identity_registered=True,
            task_pool_post_performed=True,
            task_pool_claim_performed=True,
            task_pool_execute_performed=True,
            task_pool_state_mutation_performed=True,
            internal_runtime_status_evidence_index_written=True,
            owner_audit_review_written=True,
        ),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, value)
    return value


def _claim_authorization(
    *,
    lease_path: Path,
    output_path: Path,
    authorization_receipt_path: Path,
    post_h3c_summary_path: Path,
    operator_id: str,
) -> dict[str, Any]:
    value = {
        "schema_version": CONSUMPTION_SCHEMA,
        "state": "authorization_consumed_for_post_h3d_first_internal_runtime_execution",
        "consumed_at": _now(),
        "operator_id": operator_id,
        "source_authorization_receipt": artifact_ref(authorization_receipt_path),
        "source_post_h3c_summary": artifact_ref(post_h3c_summary_path),
        "single_use": True,
        "immutable": True,
        "lease_path": str(lease_path.resolve()),
    }
    lease_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(lease_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
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
    return {"alias": alias, "did": did, "name": agent.get("name") or name, "quickstart_response_status": object_value(result).get("success")}


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
    context_paths: dict[str, Path],
    artifacts: dict[str, Path],
    readiness_state: str,
    execution_performed: bool,
    post_h3e_ready: bool,
    boundary: dict[str, bool],
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "schema_version": CHAIN_SCHEMA,
        "passed": passed,
        "failure_reasons": sorted(set(failures)),
        "source_artifacts": {name: artifact_ref(path) for name, path in context_paths.items()},
        "artifacts": {name: artifact_ref(path) for name, path in artifacts.items() if path.is_file()},
        "readiness": {
            "state": readiness_state,
            "post_h3d_first_internal_runtime_execution_complete": execution_performed,
            "post_h3e_production_receipt_write_authorization_ready": post_h3e_ready,
            "runtime_execution_performed": execution_performed,
            "production_runtime_receipt_write_allowed": False,
        },
        "boundary": boundary,
        "non_claims": list(NON_CLAIMS),
        **(extra or {}),
    }


def _write_blocked_summary(*, output: Path, context_paths: dict[str, Path], failures: list[str], stage: str) -> dict[str, Any]:
    summary = _summary(
        passed=False,
        failures=failures,
        context_paths=context_paths,
        artifacts={},
        readiness_state=f"blocked_post_h3d_execution_at_{stage}",
        execution_performed=False,
        post_h3e_ready=False,
        boundary=_execution_boundary(),
        extra={"blocked_stage": stage},
    )
    write_json_object(output, summary)
    return summary


def _execution_boundary(**overrides: bool) -> dict[str, bool]:
    base = {
        "service_token_used": False,
        "demo_login_used": False,
        "authorization_consumed": False,
        "requester_identity_registered": False,
        "runner_identity_registered": False,
        "context_validation_written": False,
        "task_pool_post_performed": False,
        "task_pool_claim_performed": False,
        "task_pool_execute_performed": False,
        "task_pool_state_mutation_performed": False,
        "runtime_state_mutation_exceeds_task_scope": False,
        "internal_runtime_status_evidence_index_written": False,
        "owner_audit_review_written": False,
        "vm_contact_performed": False,
        "source_tree_write_performed": False,
        "git_write_performed": False,
        "deploy_performed": False,
        "external_public_ingress_opened": False,
        "production_data_accessed": False,
        "production_transition_allowed": False,
        "production_runtime_receipt_write_allowed": False,
        "production_runtime_receipt_written": False,
        "secrets_recorded": False,
    }
    base.update(overrides)
    return base


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


def _read_json_checked(path: Path, checks: dict[str, bool], failures: list[str], label: str) -> dict[str, Any]:
    check(checks, failures, f"{label}_exists", path.is_file())
    if not path.is_file():
        return {}
    try:
        return read_json_object(path)
    except Exception as exc:  # noqa: BLE001
        failures.append(f"{label}_unreadable:{exc}")
        return {}


def _read_verified_ref(value: Any, checks: dict[str, bool], failures: list[str], label: str) -> dict[str, Any]:
    path = _ref_path(value)
    expected_hash = str(object_value(value).get("sha256") or "")
    check(checks, failures, f"{label}_path_present", path.is_file())
    if not path.is_file():
        return {}
    check(checks, failures, f"{label}_hash_valid", bool(expected_hash) and sha256_file(path) == expected_hash)
    return read_json_object(path)


def _ref_path(value: Any) -> Path:
    return Path(str(object_value(value).get("path") or ""))


def _artifact_matches(value: Any, path: Path) -> bool:
    ref = object_value(value)
    return Path(str(ref.get("path") or "")).resolve() == path.resolve() and ref.get("sha256") == artifact_ref(path).get("sha256")


def _owners_from_post_h3b(post_h3b: dict[str, Any]) -> dict[str, Any]:
    artifacts = object_value(post_h3b.get("artifacts"))
    environment_path = _ref_path(artifacts.get("environment_proof"))
    if not environment_path.is_file():
        return {}
    environment = read_json_object(environment_path)
    return object_value(object_value(environment.get("environment")).get("roles"))


def _context_paths(post_h3a_summary_path: Path, post_h3b_summary_path: Path, post_h3c_summary_path: Path) -> dict[str, Path]:
    return {
        "post_h3a_summary": post_h3a_summary_path,
        "post_h3b_summary": post_h3b_summary_path,
        "post_h3c_summary": post_h3c_summary_path,
    }


def _context_refs(post_h3a_summary_path: Path, post_h3b_summary_path: Path, post_h3c_summary_path: Path) -> dict[str, Any]:
    return {name: artifact_ref(path) for name, path in _context_paths(post_h3a_summary_path, post_h3b_summary_path, post_h3c_summary_path).items()}


def _default_consumption_lease_path(authorization_receipt_path: Path) -> Path:
    return authorization_receipt_path.with_name(f"{authorization_receipt_path.stem}.post_h3d.consumed.json")


def _delivery_contract_safe_text(*, task_id: str) -> str:
    return (
        f"## H3\nH.3 保持阻断状态；无生产就绪性；无生产运行时执行权限；无生产接收写入能力。\n"
        f"## 执行边界\n内部任务 {task_id} 仅完成 task-pool 交付；未接触 VM；未部署；"
        "未写源码或 Git；未开放 public ingress；未访问生产数据。"
    )


def _public_key_hex(seed: str) -> str:
    del seed
    try:
        from civitasos import CivitasAgent  # type: ignore
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError("civitasos SDK is required to generate a valid Ed25519 public key") from exc
    return str(CivitasAgent(auto_discover=False).generate_keys())


def _alias_suffix(output_root: Path) -> str:
    source = output_root.parent.name if output_root.name == "post_h3d" else output_root.name
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


def _sanitize_auth_report(auth_report: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in auth_report.items() if key != "token"}


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


def _service_scopes_from_post_h3a(path: Path) -> list[str]:
    summary = read_json_object(path)
    request_path = _ref_path(object_value(summary.get("artifacts")).get("authorization_request"))
    if not request_path.is_file():
        return []
    request = read_json_object(request_path)
    return _request_service_scopes(request)


def _request_service_scopes(request: dict[str, Any]) -> list[str]:
    runtime_request = object_value(request.get("runtime_request"))
    return _texts(runtime_request.get("required_service_token_scopes")) or _texts(request.get("required_service_token_scopes"))


def main() -> int:
    parser = argparse.ArgumentParser(description="Run PostH3-D first internal runtime execution gate")
    parser.add_argument("--post-h3a-summary", required=True, type=Path)
    parser.add_argument("--post-h3b-summary", required=True, type=Path)
    parser.add_argument("--post-h3c-summary", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--backend-url", default=DEFAULT_BACKEND_URL)
    parser.add_argument("--service-token-env-file")
    parser.add_argument("--service-token-secret")
    parser.add_argument("--service-id", default=DEFAULT_SERVICE_ID)
    parser.add_argument("--operator-id", default="operator-primary")
    parser.add_argument("--requester-alias", default=DEFAULT_REQUESTER_ALIAS)
    parser.add_argument("--runner-alias", default=DEFAULT_RUNNER_ALIAS)
    parser.add_argument("--authorization-consumption-path")
    args = parser.parse_args()
    env_file = Path(args.service_token_env_file) if args.service_token_env_file else None
    secret = _service_token_secret(env_file, args.service_token_secret)
    if not secret:
        raise SystemExit("PostH3-D execution requires CIVITASOS_SERVICE_TOKEN_SECRET; demo-login is forbidden")
    scopes = _service_scopes_from_post_h3a(args.post_h3a_summary)
    if not scopes:
        raise SystemExit("PostH3-D execution could not resolve authorized service-token scopes")
    client = HttpJsonClient(args.backend_url, service_token_secret=secret, service_id=args.service_id, service_scopes=scopes)
    summary = run_execution(
        post_h3a_summary_path=args.post_h3a_summary,
        post_h3b_summary_path=args.post_h3b_summary,
        post_h3c_summary_path=args.post_h3c_summary,
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
