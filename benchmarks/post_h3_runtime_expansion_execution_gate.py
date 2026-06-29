"""Execute a bounded PostH3 runtime expansion and close it.

PostH3-R consumes PostH3-P's one-time runtime expansion authorization receipt.
The execution action starts bounded local worker heartbeats, verifies they ran,
stops them, and writes an execution receipt. It does not execute user tasks, open
public ingress, deploy, contact VMs, access production data, or write source/Git.
"""

from __future__ import annotations

import argparse
import json
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from benchmarks.i_gate_evidence import artifact_ref, check, object_value, read_json_object, sha256_file, sha256_json, write_json_object
from benchmarks.post_h3_runtime_expansion_authorization_gate import (
    AUTHORIZATION_RECEIPT_SCHEMA as POST_H3P_AUTHORIZATION_RECEIPT_SCHEMA,
    BOUNDARY_REPORT_SCHEMA as POST_H3P_BOUNDARY_REPORT_SCHEMA,
    CHAIN_SCHEMA as POST_H3P_SCHEMA,
)

CHAIN_SCHEMA = "post-h3-runtime-expansion-execution-chain:v1"
CONTEXT_SCHEMA = "post-h3r-post-h3p-context-validation:v1"
AUTHORIZATION_CONSUMPTION_SCHEMA = "post-h3r-runtime-expansion-authorization-consumption:v1"
RUNTIME_EXPANSION_EXECUTION_SCHEMA = "post-h3r-runtime-expansion-execution:v1"
EXECUTION_RECEIPT_SCHEMA = "post-h3r-runtime-expansion-execution-receipt:v1"
BOUNDARY_REPORT_SCHEMA = "post-h3r-runtime-expansion-execution-boundary-report:v1"

ACCEPTED_OPERATOR_DECISION = "execute_post_h3_runtime_expansion_once"
ACCEPTED_AUDIT_DECISION = "accept_post_h3p_authorization_for_runtime_expansion_execution"
NON_CLAIMS = (
    "post_h3r_starts_bounded_local_runtime_workers_only",
    "post_h3r_stops_workers_after_probe",
    "post_h3r_does_not_execute_user_tasks",
    "post_h3r_does_not_open_public_ingress",
    "post_h3r_does_not_contact_vm_targets",
    "post_h3r_does_not_deploy",
    "post_h3r_does_not_access_production_data",
    "post_h3r_does_not_write_source_or_git",
)


def run_gate(
    *,
    post_h3p_summary_path: Path,
    output_root: Path,
    operator_id: str = "operator-primary",
    operator_decision: str = ACCEPTED_OPERATOR_DECISION,
    audit_decision: str = ACCEPTED_AUDIT_DECISION,
    operator_statement: str = "Execute one bounded runtime expansion by starting local worker heartbeats and stopping them after probe.",
    worker_count: int = 2,
    expansion_seconds: float = 1.0,
    parallel_task_count: int = 0,
    ack_runtime_expansion_execution: bool = False,
) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "context_validation": output_root / "post_h3r_post_h3p_context_validation.json",
        "authorization_consumption": output_root / "post_h3r_runtime_expansion_authorization_consumption.json",
        "runtime_expansion_execution": output_root / "post_h3r_runtime_expansion_execution.json",
        "execution_receipt": output_root / "post_h3r_runtime_expansion_execution_receipt.json",
        "boundary_report": output_root / "post_h3r_runtime_expansion_execution_boundary_report.json",
        "summary": output_root / "post_h3r_runtime_expansion_execution_summary.json",
    }
    context = validate_post_h3p_context(post_h3p_summary_path, output=artifacts["context_validation"])
    consumption = _write_authorization_consumption(
        context=context,
        post_h3p_summary_path=post_h3p_summary_path,
        output=artifacts["authorization_consumption"],
        operator_id=operator_id,
        operator_decision=operator_decision,
        audit_decision=audit_decision,
        operator_statement=operator_statement,
        ack_runtime_expansion_execution=ack_runtime_expansion_execution,
    )
    execution = _write_runtime_expansion_execution(
        context=context,
        consumption_path=artifacts["authorization_consumption"],
        output=artifacts["runtime_expansion_execution"],
        worker_count=worker_count,
        expansion_seconds=expansion_seconds,
        parallel_task_count=parallel_task_count,
    )
    receipt = _write_execution_receipt(context=context, runtime_expansion_execution_path=artifacts["runtime_expansion_execution"], output=artifacts["execution_receipt"])
    boundary = _write_boundary_report(context=context, execution_receipt_path=artifacts["execution_receipt"], output=artifacts["boundary_report"])
    reports = [context, consumption, execution, receipt, boundary]
    passed = all(report.get("passed") is True for report in reports)
    summary = {
        "schema_version": CHAIN_SCHEMA,
        "passed": passed,
        "failure_reasons": _failures(reports),
        "checked_at": _now(),
        "source_artifacts": {"post_h3p_summary": artifact_ref(post_h3p_summary_path)},
        "artifacts": {name: artifact_ref(path) for name, path in artifacts.items() if name != "summary"},
        "runtime_expansion_authorization_id": object_value(context.get("authorization_receipt")).get("authorization_id"),
        "runtime_expansion_execution_id": execution.get("runtime_expansion_execution_id"),
        "execution_receipt_id": receipt.get("execution_receipt_id"),
        "readiness": {
            "state": "post_h3_runtime_expansion_execution_complete" if passed else "blocked_post_h3_runtime_expansion_execution",
            "runtime_expansion_execution_complete": passed,
            "runtime_expansion_authorization_consumed": consumption.get("passed") is True,
            "runtime_expansion_performed": passed,
            "runtime_workers_started": passed,
            "runtime_workers_stopped": passed,
            "runtime_execution_performed": False,
            "public_ingress_authorized": False,
            "external_public_ingress_opened": False,
            "production_runtime_receipt_write_allowed": False,
        },
        "boundary": _boundary(
            context_validation_written=context.get("passed") is True,
            authorization_consumed=consumption.get("passed") is True,
            runtime_expansion_execution_written=execution.get("passed") is True,
            execution_receipt_written=receipt.get("passed") is True,
            boundary_report_written=boundary.get("passed") is True,
            runtime_expansion_authorized=consumption.get("passed") is True,
            runtime_expansion_performed=passed,
            runtime_workers_started=passed,
            runtime_workers_stopped=passed,
        ),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(artifacts["summary"], summary)
    return summary


def validate_post_h3p_context(post_h3p_summary_path: Path, *, output: Path | None = None) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    try:
        summary = read_json_object(post_h3p_summary_path)
    except Exception as exc:  # noqa: BLE001
        return _write_optional(_report(CONTEXT_SCHEMA, False, [f"post_h3p_summary_unreadable:{exc}"], checks), output)
    artifacts = object_value(summary.get("artifacts"))
    receipt = _read_verified_ref(artifacts.get("authorization_receipt"), checks, failures, "post_h3p_authorization_receipt")
    boundary_report = _read_verified_ref(artifacts.get("boundary_report"), checks, failures, "post_h3p_boundary_report")
    _check_summary(summary, checks, failures)
    _check_authorization_receipt(summary, receipt, checks, failures)
    _check_boundary_report(boundary_report, checks, failures)
    passed = _passed(checks, failures)
    report = {
        "schema_version": CONTEXT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "post_h3p_summary": summary,
        "authorization_receipt": receipt,
        "boundary_report": boundary_report,
        "source_artifacts": {"post_h3p_summary": artifact_ref(post_h3p_summary_path)},
        "boundary": _boundary(context_validation_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    return _write_optional(report, output)


def _write_authorization_consumption(
    *,
    context: dict[str, Any],
    post_h3p_summary_path: Path,
    output: Path,
    operator_id: str,
    operator_decision: str,
    audit_decision: str,
    operator_statement: str,
    ack_runtime_expansion_execution: bool,
) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    receipt = object_value(context.get("authorization_receipt"))
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "authorization_receipt_passed", receipt.get("passed") is True)
    check(checks, failures, "authorization_granted", receipt.get("authorization_granted") is True)
    check(checks, failures, "authorization_single_use", receipt.get("single_use") is True)
    check(checks, failures, "authorization_unconsumed", receipt.get("consumed") is False)
    check(checks, failures, "operator_id_present", bool(operator_id.strip()))
    check(checks, failures, "operator_decision_accepted", operator_decision == ACCEPTED_OPERATOR_DECISION)
    check(checks, failures, "audit_decision_accepted", audit_decision == ACCEPTED_AUDIT_DECISION)
    check(checks, failures, "operator_statement_present", bool(operator_statement.strip()))
    check(checks, failures, "explicit_operator_ack", ack_runtime_expansion_execution is True)
    passed = _passed(checks, failures)
    report = {
        "schema_version": AUTHORIZATION_CONSUMPTION_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "consumed_at": _now(),
        "authorization_id": receipt.get("authorization_id"),
        "single_use_consumption": passed,
        "operator_id": operator_id,
        "operator_decision": operator_decision,
        "audit_decision": audit_decision,
        "operator_statement": operator_statement,
        "operator_statement_sha256": sha256_json(operator_statement),
        "ack_runtime_expansion_execution": ack_runtime_expansion_execution,
        "source_artifacts": {"post_h3p_summary": artifact_ref(post_h3p_summary_path)},
        "boundary": _boundary(authorization_consumed=passed, runtime_expansion_authorized=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def _write_runtime_expansion_execution(
    *,
    context: dict[str, Any],
    consumption_path: Path,
    output: Path,
    worker_count: int,
    expansion_seconds: float,
    parallel_task_count: int,
) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    receipt = object_value(context.get("authorization_receipt"))
    scope = object_value(receipt.get("authorization_scope"))
    consumption = read_json_object(consumption_path)
    max_agents = int(scope.get("max_runtime_agents") or 0)
    max_parallel_tasks = int(scope.get("max_parallel_tasks") or 0)
    max_seconds = float(scope.get("max_expansion_seconds") or 0)
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "authorization_consumed", consumption.get("passed") is True)
    check(checks, failures, "authorization_id_bound", consumption.get("authorization_id") == receipt.get("authorization_id"))
    check(checks, failures, "scope_authorizes_runtime_expansion_once", scope.get("authorize_runtime_expansion_execution_once") is True)
    check(checks, failures, "worker_count_within_scope", 1 <= worker_count <= max_agents)
    check(checks, failures, "parallel_task_count_within_scope", 0 <= parallel_task_count <= max_parallel_tasks)
    check(checks, failures, "parallel_task_count_zero_for_probe", parallel_task_count == 0)
    check(checks, failures, "expansion_seconds_positive", expansion_seconds > 0)
    check(checks, failures, "expansion_seconds_within_scope", expansion_seconds <= max_seconds)
    action_result: dict[str, Any] = {"attempted": False}
    if _passed(checks, failures):
        action_result = _run_worker_heartbeat_probe(worker_count=worker_count, expansion_seconds=expansion_seconds)
        check(checks, failures, "workers_started", action_result.get("workers_started") == worker_count)
        check(checks, failures, "workers_stopped", action_result.get("workers_stopped") == worker_count)
        check(checks, failures, "heartbeats_observed", action_result.get("heartbeat_count", 0) >= worker_count)
    passed = _passed(checks, failures)
    report = {
        "schema_version": RUNTIME_EXPANSION_EXECUTION_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "executed_at": _now(),
        "runtime_expansion_execution_id": f"post-h3r-runtime-expansion-exec:{sha256_json([artifact_ref(consumption_path), worker_count, expansion_seconds, parallel_task_count])[:24]}",
        "execution_scope": {
            "worker_count": worker_count,
            "expansion_seconds": expansion_seconds,
            "parallel_task_count": parallel_task_count,
            "allowed_runtime_scope": scope.get("allowed_runtime_scope"),
        },
        "action_result": action_result,
        "source_artifacts": {"authorization_consumption": artifact_ref(consumption_path)},
        "readiness": {
            "runtime_expansion_execution_complete": passed,
            "runtime_expansion_performed": passed,
            "runtime_workers_started": passed,
            "runtime_workers_stopped": passed,
            "runtime_execution_performed": False,
            "public_ingress_authorized": False,
        },
        "boundary": _boundary(runtime_expansion_execution_written=passed, runtime_expansion_authorized=passed, runtime_expansion_performed=passed, runtime_workers_started=passed, runtime_workers_stopped=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def _write_execution_receipt(*, context: dict[str, Any], runtime_expansion_execution_path: Path, output: Path) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    execution = read_json_object(runtime_expansion_execution_path)
    receipt = object_value(context.get("authorization_receipt"))
    readiness = object_value(execution.get("readiness"))
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "runtime_expansion_execution_passed", execution.get("passed") is True)
    check(checks, failures, "runtime_expansion_performed", readiness.get("runtime_expansion_performed") is True)
    check(checks, failures, "workers_stopped", readiness.get("runtime_workers_stopped") is True)
    check(checks, failures, "no_user_task_execution", readiness.get("runtime_execution_performed") is False)
    passed = _passed(checks, failures)
    execution_receipt = {
        "schema_version": EXECUTION_RECEIPT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "written_at": _now(),
        "execution_receipt_id": f"post-h3r-runtime-expansion-receipt:{sha256_json([artifact_ref(runtime_expansion_execution_path), receipt.get('authorization_id')])[:24]}",
        "authorization_id": receipt.get("authorization_id"),
        "runtime_expansion_execution_id": execution.get("runtime_expansion_execution_id"),
        "source_artifacts": {"runtime_expansion_execution": artifact_ref(runtime_expansion_execution_path)},
        "readiness": {
            "runtime_expansion_execution_complete": passed,
            "runtime_expansion_performed": passed,
            "runtime_workers_stopped": passed,
            "runtime_execution_performed": False,
            "public_ingress_authorized": False,
        },
        "boundary": _boundary(execution_receipt_written=passed, runtime_expansion_authorized=passed, runtime_expansion_performed=passed, runtime_workers_started=passed, runtime_workers_stopped=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, execution_receipt)
    return execution_receipt


def _write_boundary_report(*, context: dict[str, Any], execution_receipt_path: Path, output: Path) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    receipt = read_json_object(execution_receipt_path)
    readiness = object_value(receipt.get("readiness"))
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "execution_receipt_passed", receipt.get("passed") is True)
    check(checks, failures, "runtime_expansion_performed", readiness.get("runtime_expansion_performed") is True)
    check(checks, failures, "runtime_workers_stopped", readiness.get("runtime_workers_stopped") is True)
    check(checks, failures, "runtime_execution_not_performed", readiness.get("runtime_execution_performed") is False)
    check(checks, failures, "public_ingress_not_authorized", readiness.get("public_ingress_authorized") is False)
    passed = _passed(checks, failures)
    report = {
        "schema_version": BOUNDARY_REPORT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "source_artifacts": {"execution_receipt": artifact_ref(execution_receipt_path)},
        "boundary": _boundary(boundary_report_written=passed, runtime_expansion_authorized=passed, runtime_expansion_performed=passed, runtime_workers_started=passed, runtime_workers_stopped=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def _run_worker_heartbeat_probe(*, worker_count: int, expansion_seconds: float) -> dict[str, Any]:
    stop_event = threading.Event()
    heartbeats: list[dict[str, Any]] = []
    lock = threading.Lock()

    def worker(worker_id: int) -> None:
        started_at = _now()
        with lock:
            heartbeats.append({"worker_id": worker_id, "event": "started", "at": started_at})
        while not stop_event.is_set():
            with lock:
                heartbeats.append({"worker_id": worker_id, "event": "heartbeat", "at": _now()})
            time.sleep(0.05)
        with lock:
            heartbeats.append({"worker_id": worker_id, "event": "stopped", "at": _now()})

    threads = [threading.Thread(target=worker, args=(idx,), name=f"post-h3r-runtime-worker-{idx}", daemon=True) for idx in range(worker_count)]
    started_at = _now()
    for thread in threads:
        thread.start()
    time.sleep(expansion_seconds)
    stop_event.set()
    for thread in threads:
        thread.join(timeout=2)
    closed_at = _now()
    with lock:
        snapshot = list(heartbeats)
    return {
        "attempted": True,
        "workers_started": len({item["worker_id"] for item in snapshot if item.get("event") == "started"}),
        "workers_stopped": len({item["worker_id"] for item in snapshot if item.get("event") == "stopped"}),
        "heartbeat_count": sum(1 for item in snapshot if item.get("event") == "heartbeat"),
        "started_at": started_at,
        "closed_at": closed_at,
        "heartbeats_sha256": sha256_json(snapshot),
    }


def _check_summary(summary: dict[str, Any], checks: dict[str, bool], failures: list[str]) -> None:
    readiness = object_value(summary.get("readiness"))
    boundary = object_value(summary.get("boundary"))
    check(checks, failures, "post_h3p_schema_valid", summary.get("schema_version") == POST_H3P_SCHEMA)
    check(checks, failures, "post_h3p_passed", summary.get("passed") is True)
    check(checks, failures, "runtime_expansion_authorized", readiness.get("runtime_expansion_authorized") is True)
    check(checks, failures, "runtime_expansion_execution_ready", readiness.get("runtime_expansion_execution_ready") is True)
    check(checks, failures, "runtime_not_previously_executed", readiness.get("runtime_execution_performed") is False)
    check(checks, failures, "public_ingress_not_authorized", readiness.get("public_ingress_authorized") is False)
    check(checks, failures, "boundary_no_runtime_execution", boundary.get("runtime_execution_performed") is False)
    check(checks, failures, "boundary_no_public_ingress", boundary.get("external_public_ingress_opened") is False)


def _check_authorization_receipt(summary: dict[str, Any], receipt: dict[str, Any], checks: dict[str, bool], failures: list[str]) -> None:
    check(checks, failures, "receipt_schema_valid", receipt.get("schema_version") == POST_H3P_AUTHORIZATION_RECEIPT_SCHEMA)
    check(checks, failures, "receipt_passed", receipt.get("passed") is True)
    check(checks, failures, "receipt_authorization_granted", receipt.get("authorization_granted") is True)
    check(checks, failures, "receipt_id_matches", receipt.get("authorization_id") == summary.get("runtime_expansion_authorization_id"))
    check(checks, failures, "receipt_single_use", receipt.get("single_use") is True)
    check(checks, failures, "receipt_unconsumed", receipt.get("consumed") is False)
    scope = object_value(receipt.get("authorization_scope"))
    check(checks, failures, "scope_runtime_expansion_once", scope.get("authorize_runtime_expansion_execution_once") is True)
    check(checks, failures, "scope_no_public_ingress", scope.get("authorize_public_ingress") is False)


def _check_boundary_report(report: dict[str, Any], checks: dict[str, bool], failures: list[str]) -> None:
    check(checks, failures, "boundary_report_schema_valid", report.get("schema_version") == POST_H3P_BOUNDARY_REPORT_SCHEMA and report.get("passed") is True)
    boundary = object_value(report.get("boundary"))
    check(checks, failures, "boundary_runtime_authorized", boundary.get("runtime_expansion_authorized") is True)
    check(checks, failures, "boundary_no_runtime_execution", boundary.get("runtime_execution_performed") is False)
    check(checks, failures, "boundary_no_public_ingress", boundary.get("external_public_ingress_opened") is False)


def _read_verified_ref(value: Any, checks: dict[str, bool], failures: list[str], label: str) -> dict[str, Any]:
    ref = object_value(value)
    path = Path(str(ref.get("path") or ""))
    expected_hash = str(ref.get("sha256") or "")
    check(checks, failures, f"{label}_path_present", path.is_file())
    if not path.is_file():
        return {}
    check(checks, failures, f"{label}_hash_valid", bool(expected_hash) and sha256_file(path) == expected_hash)
    return read_json_object(path)


def _boundary(**overrides: bool) -> dict[str, bool]:
    boundary = {
        "context_validation_written": False,
        "authorization_consumed": False,
        "runtime_expansion_execution_written": False,
        "execution_receipt_written": False,
        "boundary_report_written": False,
        "runtime_expansion_authorized": False,
        "runtime_expansion_performed": False,
        "runtime_workers_started": False,
        "runtime_workers_stopped": False,
        "runtime_execution_performed": False,
        "public_ingress_authorized": False,
        "external_public_ingress_opened": False,
        "vm_contact_performed": False,
        "deploy_performed": False,
        "production_data_accessed": False,
        "production_runtime_receipt_write_allowed": False,
        "source_tree_write_performed": False,
        "git_write_performed": False,
        "secrets_recorded": False,
    }
    boundary.update(overrides)
    return boundary


def _report(schema: str, passed: bool, failures: list[str], checks: dict[str, bool]) -> dict[str, Any]:
    return {"schema_version": schema, "passed": passed, "failure_reasons": failures, "checks": checks, "checked_at": _now(), "boundary": _boundary(), "non_claims": list(NON_CLAIMS)}


def _write_optional(report: dict[str, Any], output: Path | None) -> dict[str, Any]:
    if output is not None:
        write_json_object(output, report)
    return report


def _failures(reports: list[dict[str, Any]]) -> list[str]:
    failures: list[str] = []
    for report in reports:
        failures.extend(str(item) for item in report.get("failure_reasons", []))
    return sorted(set(failures))


def _passed(checks: dict[str, bool], failures: list[str]) -> bool:
    return bool(checks) and all(checks.values()) and not failures


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def main() -> int:
    parser = argparse.ArgumentParser(description="Run PostH3-R runtime expansion execution gate")
    parser.add_argument("--post-h3p-summary", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--operator-id", default="operator-primary")
    parser.add_argument("--operator-decision", default=ACCEPTED_OPERATOR_DECISION)
    parser.add_argument("--audit-decision", default=ACCEPTED_AUDIT_DECISION)
    parser.add_argument("--operator-statement", default="Execute one bounded runtime expansion by starting local worker heartbeats and stopping them after probe.")
    parser.add_argument("--worker-count", type=int, default=2)
    parser.add_argument("--expansion-seconds", type=float, default=1.0)
    parser.add_argument("--parallel-task-count", type=int, default=0)
    parser.add_argument("--ack-runtime-expansion-execution", action="store_true")
    args = parser.parse_args()
    summary = run_gate(
        post_h3p_summary_path=args.post_h3p_summary,
        output_root=args.output_root,
        operator_id=args.operator_id,
        operator_decision=args.operator_decision,
        audit_decision=args.audit_decision,
        operator_statement=args.operator_statement,
        worker_count=args.worker_count,
        expansion_seconds=args.expansion_seconds,
        parallel_task_count=args.parallel_task_count,
        ack_runtime_expansion_execution=args.ack_runtime_expansion_execution,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if summary.get("passed") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
