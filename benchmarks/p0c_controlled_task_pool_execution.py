"""Run P0-C one-time controlled task-pool execution.

This runner consumes a passed P0-C authorization and performs exactly one
controlled task-pool preview execution. It posts one task, registers one
transient runner identity, claims the task, writes a local preview artifact,
delivers the artifact through CivitasOS task state, and records receipts.

It does not contact VM targets, deploy, write source/Git state, transition to
production, or write production receipts.
"""

from __future__ import annotations

import argparse
import json
import os
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Protocol
from urllib import request as urllib_request

from benchmarks.i_gate_evidence import artifact_ref, check, object_value, read_json_object, sha256_file, write_json_object
from benchmarks.p0c_controlled_execution_authorization_gate import (
    AUTHORIZATION_SCHEMA,
    BOUNDED_SPEC_SCHEMA,
    CHAIN_SCHEMA as P0C_AUTH_CHAIN_SCHEMA,
    ROLLBACK_DRY_RUN_SCHEMA,
    SERVICE_PREFLIGHT_SCHEMA,
)

try:
    from scripts.civitasos_contracts.auth import CivitasHttpClient
except ModuleNotFoundError:  # pragma: no cover - direct script execution fallback
    from civitasos_contracts.auth import CivitasHttpClient  # type: ignore

CHAIN_SCHEMA = "p0c-controlled-task-pool-execution-chain:v1"
CONSUMPTION_SCHEMA = "p0c-one-time-authorization-consumption:v1"
TASK_RECEIPT_SCHEMA = "p0c-task-pool-execution-receipt:v1"
PREVIEW_SCHEMA = "p0c-pilot-status-evidence-index-preview:v1"
NO_PRODUCTION_SCHEMA = "p0c-no-production-attestation:v1"
ROLLBACK_OR_ABORT_SCHEMA = "p0c-rollback-or-abort-ref:v1"
DELIVERY_OUTPUT_SCHEMA = "p0c-preview-delivery-output:v1"
CALLBACK_SINK_SCHEMA = "p0c-callback-sink-receipt:v1"
DEFAULT_BACKEND_URL = "http://127.0.0.1:8099"
DEFAULT_SERVICE_ID = "p0c_controlled_task_pool_execution"
DEFAULT_RUNNER_ALIAS = "p0c_controlled_preview_runner"
DEFAULT_REQUESTER_ALIAS = "p0c_controlled_preview_operator"

REQUIRED_OUTPUT_FILES = (
    "p0c_authorization_consumption.json",
    "p0c_task_pool_execution_receipt.json",
    "p0c_preview_artifact.json",
    "p0c_no_production_attestation.json",
    "p0c_rollback_or_abort_ref.json",
    "p0c_controlled_task_pool_execution_chain_summary.json",
)
OPTIONAL_OUTPUT_FILES = ("p0c_callback_sink_receipt.json",)


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
            required_service_token_error="P0-C execution requires a service-token secret; demo-login is forbidden",
            timeout=30,
        )

    def healthz(self) -> None:
        self.get("/healthz")

    def auth_report(self) -> dict[str, Any]:
        return self.auth_session().report()


def run_execution(
    *,
    p0c_summary_path: Path,
    output_root: Path,
    client: JsonClient,
    backend_url: str = DEFAULT_BACKEND_URL,
    operator_id: str = "operator-cc",
    runner_alias: str = DEFAULT_RUNNER_ALIAS,
    requester_alias: str = DEFAULT_REQUESTER_ALIAS,
    authorization_consumption_path: Path | None = None,
    enable_callback_sink: bool = False,
    callback_wait_seconds: float = 5.0,
) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "authorization_consumption": output_root / "p0c_authorization_consumption.json",
        "task_pool_execution_receipt": output_root / "p0c_task_pool_execution_receipt.json",
        "preview_artifact": output_root / "p0c_preview_artifact.json",
        "no_production_attestation": output_root / "p0c_no_production_attestation.json",
        "rollback_or_abort_ref": output_root / "p0c_rollback_or_abort_ref.json",
        "callback_sink_receipt": output_root / "p0c_callback_sink_receipt.json",
        "summary": output_root / "p0c_controlled_task_pool_execution_chain_summary.json",
    }
    context = _validate_authorization_chain(p0c_summary_path)
    if not context["passed"]:
        return _write_blocked_summary(
            output=artifacts["summary"],
            p0c_summary_path=p0c_summary_path,
            failures=context["failure_reasons"],
            stage="authorization_chain_validation",
        )

    auth = context["authorization"]
    spec = context["bounded_execution_spec"]
    execution_spec = object_value(spec.get("execution_spec"))
    global_consumption_path = authorization_consumption_path or _default_consumption_lease_path(context["authorization_path"])

    try:
        client.healthz()
        auth_report = client.auth_report()
    except Exception as exc:  # noqa: BLE001 - fail closed with receipt
        return _write_blocked_summary(
            output=artifacts["summary"],
            p0c_summary_path=p0c_summary_path,
            failures=[f"backend_or_service_token_preflight_failed:{exc}"],
            stage="backend_service_token_preflight",
        )

    auth_failures = _validate_auth_report(auth_report)
    if auth_failures:
        return _write_blocked_summary(
            output=artifacts["summary"],
            p0c_summary_path=p0c_summary_path,
            failures=auth_failures,
            stage="service_token_auth_policy",
        )

    try:
        consumption = _claim_authorization(
            lease_path=global_consumption_path,
            output_path=artifacts["authorization_consumption"],
            authorization_path=context["authorization_path"],
            p0c_summary_path=p0c_summary_path,
            operator_id=operator_id,
        )
    except RuntimeError as exc:
        return _write_blocked_summary(
            output=artifacts["summary"],
            p0c_summary_path=p0c_summary_path,
            failures=[str(exc)],
            stage="single_use_authorization_consumption",
        )

    started_at = _now()
    failures: list[str] = []
    try:
        with CallbackAuditSink(enabled=enable_callback_sink) as callback_sink:
            alias_suffix = _alias_suffix(output_root)
            endpoint = callback_sink.endpoint if callback_sink.enabled else None
            requester = _quickstart_agent(
                client,
                alias=f"{requester_alias}_{alias_suffix}",
                name="P0-C Controlled Preview Operator",
                description="Requester identity for one-time P0-C controlled task-pool preview execution",
                endpoint=endpoint,
            )
            runner = _quickstart_agent(
                client,
                alias=f"{runner_alias}_{alias_suffix}",
                name="P0-C Controlled Preview Runner",
                description="Single authorized runner identity for P0-C pilot status evidence index preview",
                endpoint=endpoint,
            )
            post = client.post("/api/v1/a2a/pool/post", _task_payload(requester=requester, runner=runner, p0c_summary_path=p0c_summary_path, context=context))
            task_id = str(object_value(post).get("task_id") or "")
            if not task_id:
                raise RuntimeError(f"pool post missing task_id: {post}")
            claim_response = client.post("/api/v1/a2a/pool/claim", {"agent_id": runner["did"], "task_id": task_id, "stake_amount": 0})
            claimed_task = _get_task(client, task_id)
            preview = _write_preview_artifact(
                output=artifacts["preview_artifact"],
                task_id=task_id,
                backend_url=backend_url,
                requester=requester,
                runner=runner,
                p0c_summary_path=p0c_summary_path,
                context=context,
            )
            no_production = _write_no_production_attestation(
                output=artifacts["no_production_attestation"],
                task_id=task_id,
                auth_report=auth_report,
                preview_path=artifacts["preview_artifact"],
            )
            rollback = _write_rollback_or_abort_ref(
                output=artifacts["rollback_or_abort_ref"],
                task_id=task_id,
                preview_path=artifacts["preview_artifact"],
                execution_spec=execution_spec,
            )
            delivery_output = _delivery_contract_safe_text(task_id=task_id)
            execute_response = client.post(
                "/api/v1/a2a/task/execute",
                {
                    "agent_id": runner["did"],
                    "task_id": task_id,
                    "output": delivery_output,
                    "success": True,
                    "metadata": {
                        "runner": "p0c_controlled_task_pool_execution",
                        "operator_id": operator_id,
                        "execution_scope": "one_time_controlled_preview",
                    },
                },
            )
            callback_sink.wait_for(task_id=task_id, event="task_completed", timeout_seconds=callback_wait_seconds)
            final_task = _get_task(client, task_id)
            callback_receipt = (
                _write_callback_sink_receipt(
                    output=artifacts["callback_sink_receipt"],
                    task_id=task_id,
                    callback_sink=callback_sink,
                    requester=requester,
                    runner=runner,
                )
                if enable_callback_sink
                else {"enabled": False, "passed": False}
            )
            receipt = _write_task_pool_execution_receipt(
                output=artifacts["task_pool_execution_receipt"],
                task_id=task_id,
                requester=requester,
                runner=runner,
                post_response=post,
                claim_response=claim_response,
                execute_response=execute_response,
                claimed_task=claimed_task,
                final_task=final_task,
                consumption_path=artifacts["authorization_consumption"],
                auth_report=auth_report,
                preview_path=artifacts["preview_artifact"],
                no_production_path=artifacts["no_production_attestation"],
                rollback_path=artifacts["rollback_or_abort_ref"],
                callback_sink_path=artifacts["callback_sink_receipt"] if callback_receipt.get("passed") is True else None,
            )
    except Exception as exc:  # noqa: BLE001 - fail closed after consumption
        failures.append(f"controlled_task_pool_execution_failed:{exc}")
        completed_at = _now()
        summary = _summary(
            passed=False,
            failures=failures,
            p0c_summary_path=p0c_summary_path,
            artifacts={"authorization_consumption": artifacts["authorization_consumption"]},
            readiness_state="blocked_after_authorization_consumption",
            execution_performed=False,
            p0d_ready=False,
            boundary=_execution_boundary(authorization_consumed=True),
            extra={
                "started_at": started_at,
                "completed_at": completed_at,
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
    check(checks, failures, "preview_artifact_written", artifacts["preview_artifact"].is_file() and preview.get("passed") is True)
    check(checks, failures, "no_production_attestation_passed", no_production.get("passed") is True)
    check(checks, failures, "rollback_or_abort_ref_written", rollback.get("passed") is True)
    if enable_callback_sink:
        check(checks, failures, "callback_sink_receipt_passed", callback_receipt.get("passed") is True)
    passed = bool(checks) and all(checks.values()) and not failures
    summary = _summary(
        passed=passed,
        failures=failures,
        p0c_summary_path=p0c_summary_path,
        artifacts={name: path for name, path in artifacts.items() if name != "summary"},
        readiness_state="p0c_controlled_task_pool_execution_complete" if passed else "blocked_p0c_controlled_task_pool_execution",
        execution_performed=passed,
        p0d_ready=passed,
        boundary=_execution_boundary(
            authorization_consumed=True,
            service_token_used=True,
            callback_sink_started=enable_callback_sink,
            callback_delivery_observed=callback_receipt.get("passed") is True if enable_callback_sink else False,
            runner_identity_registered=True,
            requester_identity_registered=True,
            task_pool_post_performed=True,
            task_pool_claim_performed=True,
            task_pool_execute_performed=True,
            task_pool_state_mutation_performed=True,
            preview_artifact_written=True,
        ),
        extra={
            "started_at": started_at,
            "completed_at": completed_at,
            "duration_seconds": _duration_seconds(started_at, completed_at),
            "checks": checks,
            "selected_task": object_value(context["p0c_summary"].get("selected_task")),
            "task_id": receipt.get("task_id"),
        },
    )
    write_json_object(artifacts["summary"], summary)
    return summary


def _validate_authorization_chain(path: Path) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    try:
        summary = read_json_object(path)
    except Exception as exc:  # noqa: BLE001
        return {"passed": False, "failure_reasons": [f"p0c_summary_unreadable:{exc}"]}
    artifacts = object_value(summary.get("artifacts"))
    auth = _read_verified_ref(artifacts.get("authorization"), checks, failures, "authorization")
    spec = _read_verified_ref(artifacts.get("bounded_execution_spec"), checks, failures, "bounded_execution_spec")
    preflight = _read_verified_ref(artifacts.get("service_token_preflight"), checks, failures, "service_token_preflight")
    rollback = _read_verified_ref(artifacts.get("rollback_dry_run"), checks, failures, "rollback_dry_run")
    readiness = object_value(summary.get("readiness"))
    boundary = object_value(summary.get("boundary"))
    authorization = object_value(auth.get("authorization"))
    service = object_value(preflight.get("service_token_preflight"))
    execution_spec = object_value(spec.get("execution_spec"))
    check(checks, failures, "p0c_summary_passed", summary.get("schema_version") == P0C_AUTH_CHAIN_SCHEMA and summary.get("passed") is True)
    check(checks, failures, "p0c_authorized", readiness.get("p0c_one_time_controlled_execution_authorized") is True)
    check(checks, failures, "p0c_not_yet_executed", readiness.get("p0c_execution_performed") is False)
    check(checks, failures, "authorization_schema_passed", auth.get("schema_version") == AUTHORIZATION_SCHEMA and auth.get("passed") is True)
    check(checks, failures, "authorization_decision", authorization.get("decision") == "authorize_one_time_p0c_controlled_execution")
    check(checks, failures, "authorization_not_executed", authorization.get("execution_performed") is False)
    check(checks, failures, "authorization_expires_after_use", authorization.get("expires_after_use") is True)
    check(checks, failures, "bounded_spec_passed", spec.get("schema_version") == BOUNDED_SPEC_SCHEMA and spec.get("passed") is True)
    check(checks, failures, "max_tasks_one", execution_spec.get("max_tasks") == 1 and authorization.get("max_tasks") == 1)
    check(checks, failures, "max_agents_one", execution_spec.get("max_agents") == 1 and authorization.get("max_agents") == 1)
    check(checks, failures, "service_preflight_passed", preflight.get("schema_version") == SERVICE_PREFLIGHT_SCHEMA and preflight.get("passed") is True)
    check(checks, failures, "service_secret_not_recorded", service.get("secret_recorded") is False and service.get("secret_sha256_recorded") is False)
    check(checks, failures, "service_token_not_issued_by_preflight", service.get("token_issued") is False)
    check(checks, failures, "demo_login_forbidden", service.get("demo_login_allowed") is False)
    check(checks, failures, "rollback_dry_run_passed", rollback.get("schema_version") == ROLLBACK_DRY_RUN_SCHEMA and rollback.get("passed") is True)
    check(checks, failures, "pre_execution_boundary_closed", boundary.get("task_pool_post_performed") is False and boundary.get("deploy_performed") is False)
    return {
        "passed": bool(checks) and all(checks.values()) and not failures,
        "failure_reasons": failures,
        "checks": checks,
        "p0c_summary": summary,
        "authorization": auth,
        "authorization_path": Path(str(object_value(artifacts.get("authorization")).get("path"))),
        "bounded_execution_spec": spec,
        "service_token_preflight": preflight,
        "rollback_dry_run": rollback,
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


def _validate_auth_report(auth_report: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    if auth_report.get("passed") is not True:
        failures.append("service_token_auth_failed")
    if auth_report.get("auth_method") not in {"service_token", "service-token"}:
        failures.append("service_token_required_demo_login_forbidden")
    if auth_report.get("token_recorded") is not False:
        failures.append("auth_token_must_not_be_recorded")
    if auth_report.get("production_allowed") is not False:
        failures.append("service_token_must_not_allow_production")
    return failures


def _claim_authorization(*, lease_path: Path, output_path: Path, authorization_path: Path, p0c_summary_path: Path, operator_id: str) -> dict[str, Any]:
    value = {
        "schema_version": CONSUMPTION_SCHEMA,
        "state": "authorization_consumed_for_one_time_p0c_task_pool_execution",
        "consumed_at": _now(),
        "operator_id": operator_id,
        "source_authorization": artifact_ref(authorization_path),
        "source_p0c_summary": artifact_ref(p0c_summary_path),
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


def _default_consumption_lease_path(authorization_path: Path) -> Path:
    return authorization_path.with_name(f"{authorization_path.stem}.consumed.json")


def _quickstart_agent(client: JsonClient, *, alias: str, name: str, description: str, endpoint: str | None = None) -> dict[str, Any]:
    result = client.post(
        "/api/v1/a2a/quickstart",
        {
            "public_key": _public_key_hex(alias),
            "alias": alias,
            "name": name,
            "endpoint": endpoint or f"http://127.0.0.1:65535/{alias}",
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


def _task_payload(*, requester: dict[str, Any], runner: dict[str, Any], p0c_summary_path: Path, context: dict[str, Any]) -> dict[str, Any]:
    execution_spec = object_value(context["bounded_execution_spec"].get("execution_spec"))
    return {
        "requester": requester["did"],
        "required_capability": "evidence_index_generation",
        "reward": 1,
        "min_reputation": 0.0,
        "deadline_secs": min(int(execution_spec.get("max_duration_seconds") or 900), 1800),
        "allowed_agents": [runner["did"]],
        "blocked_agents": [],
        "required_stake": 0,
        "input": {
            "civitasos_task_kind": "p0_controlled_pilot_status_evidence_index_preview",
            "instruction": "Generate a preview-only P0 pilot status and evidence index artifact from hash-bound P0-A/P0-B/P0-C evidence. Do not contact VMs, deploy, mutate source/Git, or write production receipts.",
            "source_p0c_summary": artifact_ref(p0c_summary_path),
            "execution_spec": execution_spec,
            "expected_outputs": list(execution_spec.get("execution_output_required") or []),
            "delivery_contract": {
                "h3_must_remain_blocked": True,
                "canonical_h3_boundary": True,
                "forbid_upstream_replay": True,
                "required_sections": [],
                "review_must_have_issue_list": False,
            },
            "boundary": _execution_boundary(),
        },
    }


def _delivery_contract_safe_text(*, task_id: str) -> str:
    return (
        f"执行摘要：P0-C 预览任务 {task_id} 已生成本地预览证据索引。"
        "H3 保持阻断；生产执行不授权；生产回执不产生；"
        "VM、部署、Git、源码均未触达。"
    )


def _write_preview_artifact(*, output: Path, task_id: str, backend_url: str, requester: dict[str, Any], runner: dict[str, Any], p0c_summary_path: Path, context: dict[str, Any]) -> dict[str, Any]:
    p0c_summary = context["p0c_summary"]
    execution_spec = object_value(context["bounded_execution_spec"].get("execution_spec"))
    preview = {
        "schema_version": PREVIEW_SCHEMA,
        "passed": True,
        "generated_at": _now(),
        "task_id": task_id,
        "backend_url": backend_url,
        "preview_kind": "p0_pilot_status_and_evidence_index_preview",
        "source_p0c_summary": artifact_ref(p0c_summary_path),
        "source_artifacts": p0c_summary.get("source_artifacts", {}),
        "p0c_authorization_artifacts": p0c_summary.get("artifacts", {}),
        "selected_task": p0c_summary.get("selected_task", {}),
        "requester": requester,
        "runner": runner,
        "execution_scope": {
            "max_tasks": execution_spec.get("max_tasks"),
            "max_agents": execution_spec.get("max_agents"),
            "allowed_actions_after_authorization": execution_spec.get("allowed_actions_after_authorization", []),
            "allowed_vm_targets": execution_spec.get("allowed_vm_targets", []),
            "allowed_service_token_scopes": execution_spec.get("allowed_service_token_scopes", []),
            "forbidden_operations": execution_spec.get("forbidden_operations", []),
        },
        "evidence_index": [
            {"label": "p0c_summary", "artifact": artifact_ref(p0c_summary_path)},
            {"label": "p0c_authorization", "artifact": p0c_summary.get("artifacts", {}).get("authorization")},
            {"label": "p0c_bounded_execution_spec", "artifact": p0c_summary.get("artifacts", {}).get("bounded_execution_spec")},
            {"label": "p0c_service_token_preflight", "artifact": p0c_summary.get("artifacts", {}).get("service_token_preflight")},
            {"label": "p0c_rollback_dry_run", "artifact": p0c_summary.get("artifacts", {}).get("rollback_dry_run")},
        ],
        "boundary": _execution_boundary(preview_artifact_written=True),
        "non_claims": _non_claims(),
    }
    write_json_object(output, preview)
    return preview


def _write_no_production_attestation(*, output: Path, task_id: str, auth_report: dict[str, Any], preview_path: Path) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    check(checks, failures, "service_token_used", auth_report.get("auth_method") in {"service_token", "service-token"})
    check(checks, failures, "demo_login_not_used", auth_report.get("auth_method") not in {"demo_login", "demo-login"})
    check(checks, failures, "production_not_allowed", auth_report.get("production_allowed") is False)
    check(checks, failures, "preview_artifact_exists", preview_path.is_file())
    passed = bool(checks) and all(checks.values()) and not failures
    value = {
        "schema_version": NO_PRODUCTION_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "task_id": task_id,
        "source_preview_artifact": artifact_ref(preview_path),
        "attestation": {
            "demo_login_used": False,
            "vm_contact_performed": False,
            "deploy_performed": False,
            "source_tree_write_performed": False,
            "git_write_performed": False,
            "production_transition_allowed": False,
            "production_receipt_write_allowed": False,
            "runtime_state_mutation_exceeds_task_scope": False,
            "production_data_accessed": False,
            "secrets_recorded": False,
        },
        "auth_context": {key: value for key, value in auth_report.items() if key != "token"},
        "boundary": _execution_boundary(service_token_used=True, preview_artifact_written=True),
    }
    write_json_object(output, value)
    return value


def _write_rollback_or_abort_ref(*, output: Path, task_id: str, preview_path: Path, execution_spec: dict[str, Any]) -> dict[str, Any]:
    value = {
        "schema_version": ROLLBACK_OR_ABORT_SCHEMA,
        "passed": True,
        "task_id": task_id,
        "state": "rollback_not_required_preview_only_execution_completed",
        "source_preview_artifact": artifact_ref(preview_path),
        "rollback_command": execution_spec.get("rollback_command"),
        "abort_or_rollback_actions": [
            "do not promote preview artifact to production evidence",
            "discard preview artifact if owner/audit review rejects it",
            "retain this receipt chain for audit",
        ],
        "external_resources_to_restore": [],
        "vm_resources_to_restore": [],
        "boundary": _execution_boundary(preview_artifact_written=True),
    }
    write_json_object(output, value)
    return value


def _write_callback_sink_receipt(*, output: Path, task_id: str, callback_sink: "CallbackAuditSink", requester: dict[str, Any], runner: dict[str, Any]) -> dict[str, Any]:
    events = callback_sink.records()
    task_events = [event for event in events if _callback_task_id(event) == task_id]
    completed_events = [event for event in task_events if _callback_event(event) == "task_completed"]
    checks: dict[str, bool] = {}
    failures: list[str] = []
    check(checks, failures, "callback_sink_enabled", callback_sink.enabled)
    check(checks, failures, "callback_sink_endpoint_private", callback_sink.endpoint.startswith("http://127.0.0.1:"))
    check(checks, failures, "callback_event_for_task_observed", bool(task_events))
    check(checks, failures, "task_completed_callback_observed", bool(completed_events))
    passed = bool(checks) and all(checks.values()) and not failures
    value = {
        "schema_version": CALLBACK_SINK_SCHEMA,
        "enabled": callback_sink.enabled,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "task_id": task_id,
        "endpoint": callback_sink.endpoint,
        "requester": requester,
        "runner": runner,
        "received_event_count": len(events),
        "task_event_count": len(task_events),
        "task_completed_event_count": len(completed_events),
        "events": task_events,
        "boundary": _execution_boundary(callback_sink_started=callback_sink.enabled, callback_delivery_observed=passed),
        "non_claims": [
            "callback_sink_receipt_proves_local_private_callback_delivery_only",
            "callback_sink_receipt_does_not_authorize_vm_preview",
            "callback_sink_receipt_does_not_authorize_production_transition",
        ],
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
    preview_path: Path,
    no_production_path: Path,
    rollback_path: Path,
    callback_sink_path: Path | None = None,
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
        "preview_artifact_ref": artifact_ref(preview_path),
        "no_production_attestation_ref": artifact_ref(no_production_path),
        "rollback_or_abort_ref": artifact_ref(rollback_path),
        "callback_sink_receipt_ref": artifact_ref(callback_sink_path) if callback_sink_path and callback_sink_path.is_file() else None,
        "auth_context": {key: value for key, value in auth_report.items() if key != "token"},
        "boundary": _execution_boundary(
            service_token_used=True,
            runner_identity_registered=True,
            requester_identity_registered=True,
            task_pool_post_performed=True,
            task_pool_claim_performed=True,
            task_pool_execute_performed=True,
            task_pool_state_mutation_performed=True,
            preview_artifact_written=True,
            callback_sink_started=callback_sink_path is not None,
            callback_delivery_observed=callback_sink_path is not None,
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


def _summary(*, passed: bool, failures: list[str], p0c_summary_path: Path, artifacts: dict[str, Path], readiness_state: str, execution_performed: bool, p0d_ready: bool, boundary: dict[str, bool], extra: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "schema_version": CHAIN_SCHEMA,
        "passed": passed,
        "failure_reasons": sorted(set(failures)),
        "source_artifacts": {"p0c_summary": artifact_ref(p0c_summary_path)},
        "artifacts": {name: artifact_ref(path) for name, path in artifacts.items() if path.is_file()},
        "readiness": {
            "state": readiness_state,
            "p0c_execution_performed": execution_performed,
            "p0d_preview_smoke_ready": p0d_ready,
            "production_transition_allowed": False,
        },
        "boundary": boundary,
        "required_output_files": list(REQUIRED_OUTPUT_FILES),
        "non_claims": _non_claims(),
        **(extra or {}),
    }


def _write_blocked_summary(*, output: Path, p0c_summary_path: Path, failures: list[str], stage: str) -> dict[str, Any]:
    summary = _summary(
        passed=False,
        failures=failures,
        p0c_summary_path=p0c_summary_path,
        artifacts={},
        readiness_state=f"blocked_p0c_execution_at_{stage}",
        execution_performed=False,
        p0d_ready=False,
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
        "agent_process_started": False,
        "callback_sink_started": False,
        "callback_delivery_observed": False,
        "task_pool_post_performed": False,
        "task_pool_claim_performed": False,
        "task_pool_execute_performed": False,
        "task_pool_state_mutation_performed": False,
        "runtime_state_mutation_exceeds_task_scope": False,
        "preview_artifact_written": False,
        "vm_contact_performed": False,
        "source_tree_write_performed": False,
        "git_write_performed": False,
        "deploy_performed": False,
        "external_public_ingress_opened": False,
        "production_transition_allowed": False,
        "production_receipt_write_allowed": False,
    }
    base.update(overrides)
    return base


def _non_claims() -> list[str]:
    return [
        "p0c_execution_is_one_time_controlled_task_pool_preview_only",
        "p0c_execution_does_not_contact_vm_targets",
        "p0c_execution_does_not_deploy",
        "p0c_execution_does_not_modify_source_or_git",
        "p0c_execution_does_not_write_production_receipt",
        "p0c_execution_does_not_authorize_production_transition",
    ]


class CallbackAuditSink:
    def __init__(self, *, enabled: bool) -> None:
        self.enabled = enabled
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._records: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        self.endpoint = ""

    def __enter__(self) -> "CallbackAuditSink":
        if not self.enabled:
            return self
        sink = self

        class Handler(BaseHTTPRequestHandler):
            def do_HEAD(self) -> None:  # noqa: N802
                self.send_response(200)
                self.end_headers()

            def do_GET(self) -> None:  # noqa: N802
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"ok":true}')

            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers.get("Content-Length", "0") or "0")
                body = self.rfile.read(length)
                record = _callback_record(path=self.path, headers=dict(self.headers), body=body)
                with sink._lock:
                    sink._records.append(record)
                self.send_response(204)
                self.end_headers()

            def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
                return

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        host, port = self._server.server_address
        self.endpoint = f"http://{host}:{port}/p0c-callback-sink"
        self._thread = threading.Thread(target=self._server.serve_forever, name="p0c-callback-sink", daemon=True)
        self._thread.start()
        _wait_for_local_http(self.endpoint)
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=2)

    def records(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._records)

    def wait_for(self, *, task_id: str, event: str, timeout_seconds: float) -> bool:
        if not self.enabled:
            return False
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            if any(_callback_task_id(record) == task_id and _callback_event(record) == event for record in self.records()):
                return True
            time.sleep(0.05)
        return False


def _callback_record(*, path: str, headers: dict[str, str], body: bytes) -> dict[str, Any]:
    raw_body = body.decode("utf-8", errors="replace")
    try:
        json_body: Any = json.loads(raw_body) if raw_body else None
    except json.JSONDecodeError:
        json_body = None
    signature = _header_value(headers, "X-Civitas-Webhook-Signature")
    return {
        "received_at": _now(),
        "method": "POST",
        "path": path,
        "headers": {
            "content_type": _header_value(headers, "Content-Type") or None,
            "issuer": _header_value(headers, "X-Civitas-Webhook-Issuer") or None,
            "timestamp": _header_value(headers, "X-Civitas-Webhook-Timestamp") or None,
            "signature_present": bool(signature),
            "signature_sha256": _sha256_text(signature) if signature else None,
        },
        "body_sha256": _sha256_text(raw_body),
        "body": json_body if isinstance(json_body, dict) else {"raw": raw_body},
    }


def _header_value(headers: dict[str, str], name: str) -> str:
    lowered = name.lower()
    for key, value in headers.items():
        if key.lower() == lowered:
            return value
    return ""


def _callback_event(record: dict[str, Any]) -> str:
    body = object_value(record.get("body"))
    return str(body.get("event") or "")


def _callback_task_id(record: dict[str, Any]) -> str:
    body = object_value(record.get("body"))
    if body.get("task_id"):
        return str(body.get("task_id"))
    data = object_value(body.get("data"))
    return str(data.get("task_id") or "")


def _wait_for_local_http(endpoint: str) -> None:
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        try:
            with urllib_request.urlopen(endpoint, timeout=0.2) as response:
                if response.status < 500:
                    return
        except Exception:
            time.sleep(0.02)
    raise RuntimeError(f"callback sink failed to start: {endpoint}")


def _sha256_text(value: str) -> str:
    import hashlib

    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _public_key_hex(seed: str) -> str:
    del seed  # The SDK generates a valid Ed25519 key; deterministic hashes are not valid curve points.
    try:
        from civitasos import CivitasAgent  # type: ignore
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError("civitasos SDK is required to generate a valid Ed25519 public key") from exc
    agent = CivitasAgent(auto_discover=False)
    return str(agent.generate_keys())


def _alias_suffix(output_root: Path) -> str:
    source = output_root.parent.name if output_root.name == "p0c_execution" else output_root.name
    cleaned = "".join(ch if ch.isalnum() or ch in {"_", "-"} else "_" for ch in source).strip("_")
    return (cleaned or "run")[-32:]


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


def _service_scopes_from_p0c_summary(path: Path) -> list[str]:
    summary = read_json_object(path)
    artifacts = object_value(summary.get("artifacts"))
    auth_ref = object_value(artifacts.get("authorization"))
    auth_path = Path(str(auth_ref.get("path") or ""))
    if not auth_path.is_file():
        return []
    auth = read_json_object(auth_path)
    scopes = object_value(auth.get("authorization")).get("authorized_service_token_scopes")
    return [str(item).strip() for item in scopes] if isinstance(scopes, list) else []


def main() -> int:
    parser = argparse.ArgumentParser(description="Run P0-C one-time controlled task-pool execution")
    parser.add_argument("--p0c-summary", required=True)
    parser.add_argument("--output-root", required=True)
    parser.add_argument("--backend-url", default=DEFAULT_BACKEND_URL)
    parser.add_argument("--service-token-env-file")
    parser.add_argument("--service-token-secret")
    parser.add_argument("--service-id", default=DEFAULT_SERVICE_ID)
    parser.add_argument("--operator-id", default="operator-cc")
    parser.add_argument("--runner-alias", default=DEFAULT_RUNNER_ALIAS)
    parser.add_argument("--requester-alias", default=DEFAULT_REQUESTER_ALIAS)
    parser.add_argument("--authorization-consumption-path")
    parser.add_argument("--enable-callback-sink", action="store_true")
    parser.add_argument("--callback-wait-seconds", type=float, default=5.0)
    args = parser.parse_args()
    p0c_summary = Path(args.p0c_summary)
    env_file = Path(args.service_token_env_file) if args.service_token_env_file else None
    secret = _service_token_secret(env_file, args.service_token_secret)
    if not secret:
        raise SystemExit("P0-C execution requires CIVITASOS_SERVICE_TOKEN_SECRET; demo-login is forbidden")
    scopes = _service_scopes_from_p0c_summary(p0c_summary)
    if not scopes:
        raise SystemExit("P0-C execution could not resolve authorized service-token scopes")
    client = HttpJsonClient(args.backend_url, service_token_secret=secret, service_id=args.service_id, service_scopes=scopes)
    summary = run_execution(
        p0c_summary_path=p0c_summary,
        output_root=Path(args.output_root),
        client=client,
        backend_url=args.backend_url,
        operator_id=args.operator_id,
        runner_alias=args.runner_alias,
        requester_alias=args.requester_alias,
        authorization_consumption_path=Path(args.authorization_consumption_path) if args.authorization_consumption_path else None,
        enable_callback_sink=args.enable_callback_sink,
        callback_wait_seconds=args.callback_wait_seconds,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if summary.get("passed") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
