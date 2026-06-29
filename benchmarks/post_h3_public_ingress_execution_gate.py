"""Execute a bounded PostH3 public ingress opening and close it.

PostH3-Q consumes PostH3-O's one-time public ingress authorization receipt. The
execution action opens a temporary status-only HTTP ingress on a bounded port,
probes it locally, closes it, and writes an execution receipt. It does not expand
runtime execution, deploy, contact VMs, access production data, or write source/Git.
"""

from __future__ import annotations

import argparse
import json
import threading
import time
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from benchmarks.i_gate_evidence import artifact_ref, check, object_value, read_json_object, sha256_file, sha256_json, write_json_object
from benchmarks.post_h3_public_ingress_authorization_gate import (
    AUTHORIZATION_RECEIPT_SCHEMA as POST_H3O_AUTHORIZATION_RECEIPT_SCHEMA,
    BOUNDARY_REPORT_SCHEMA as POST_H3O_BOUNDARY_REPORT_SCHEMA,
    CHAIN_SCHEMA as POST_H3O_SCHEMA,
)

CHAIN_SCHEMA = "post-h3-public-ingress-execution-chain:v1"
CONTEXT_SCHEMA = "post-h3q-post-h3o-context-validation:v1"
AUTHORIZATION_CONSUMPTION_SCHEMA = "post-h3q-public-ingress-authorization-consumption:v1"
INGRESS_EXECUTION_SCHEMA = "post-h3q-public-ingress-execution:v1"
EXECUTION_RECEIPT_SCHEMA = "post-h3q-public-ingress-execution-receipt:v1"
BOUNDARY_REPORT_SCHEMA = "post-h3q-public-ingress-execution-boundary-report:v1"

ACCEPTED_OPERATOR_DECISION = "execute_post_h3_public_ingress_once"
ACCEPTED_AUDIT_DECISION = "accept_post_h3o_authorization_for_public_ingress_execution"
NON_CLAIMS = (
    "post_h3q_opens_bounded_status_only_ingress",
    "post_h3q_closes_ingress_after_probe",
    "post_h3q_does_not_expand_runtime_execution",
    "post_h3q_does_not_execute_runtime_task",
    "post_h3q_does_not_contact_vm_targets",
    "post_h3q_does_not_deploy",
    "post_h3q_does_not_access_production_data",
    "post_h3q_does_not_write_source_or_git",
)


def run_gate(
    *,
    post_h3o_summary_path: Path,
    output_root: Path,
    operator_id: str = "operator-primary",
    operator_decision: str = ACCEPTED_OPERATOR_DECISION,
    audit_decision: str = ACCEPTED_AUDIT_DECISION,
    operator_statement: str = "Execute one bounded status-only public ingress opening and close it after probe.",
    bind_host: str = "0.0.0.0",
    probe_host: str = "127.0.0.1",
    open_seconds: float = 1.0,
    expected_external_participants: int = 0,
    ack_public_ingress_execution: bool = False,
) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "context_validation": output_root / "post_h3q_post_h3o_context_validation.json",
        "authorization_consumption": output_root / "post_h3q_public_ingress_authorization_consumption.json",
        "ingress_execution": output_root / "post_h3q_public_ingress_execution.json",
        "execution_receipt": output_root / "post_h3q_public_ingress_execution_receipt.json",
        "boundary_report": output_root / "post_h3q_public_ingress_execution_boundary_report.json",
        "summary": output_root / "post_h3q_public_ingress_execution_summary.json",
    }
    context = validate_post_h3o_context(post_h3o_summary_path, output=artifacts["context_validation"])
    consumption = _write_authorization_consumption(
        context=context,
        post_h3o_summary_path=post_h3o_summary_path,
        output=artifacts["authorization_consumption"],
        operator_id=operator_id,
        operator_decision=operator_decision,
        audit_decision=audit_decision,
        operator_statement=operator_statement,
        ack_public_ingress_execution=ack_public_ingress_execution,
    )
    execution = _write_ingress_execution(
        context=context,
        consumption_path=artifacts["authorization_consumption"],
        output=artifacts["ingress_execution"],
        bind_host=bind_host,
        probe_host=probe_host,
        open_seconds=open_seconds,
        expected_external_participants=expected_external_participants,
    )
    receipt = _write_execution_receipt(context=context, ingress_execution_path=artifacts["ingress_execution"], output=artifacts["execution_receipt"])
    boundary = _write_boundary_report(context=context, execution_receipt_path=artifacts["execution_receipt"], output=artifacts["boundary_report"])
    reports = [context, consumption, execution, receipt, boundary]
    passed = all(report.get("passed") is True for report in reports)
    summary = {
        "schema_version": CHAIN_SCHEMA,
        "passed": passed,
        "failure_reasons": _failures(reports),
        "checked_at": _now(),
        "source_artifacts": {"post_h3o_summary": artifact_ref(post_h3o_summary_path)},
        "artifacts": {name: artifact_ref(path) for name, path in artifacts.items() if name != "summary"},
        "public_ingress_authorization_id": object_value(context.get("authorization_receipt")).get("authorization_id"),
        "public_ingress_execution_id": execution.get("public_ingress_execution_id"),
        "execution_receipt_id": receipt.get("execution_receipt_id"),
        "readiness": {
            "state": "post_h3_public_ingress_execution_complete" if passed else "blocked_post_h3_public_ingress_execution",
            "public_ingress_execution_complete": passed,
            "public_ingress_authorization_consumed": consumption.get("passed") is True,
            "external_public_ingress_opened": passed,
            "external_public_ingress_closed": passed,
            "runtime_expansion_authorized": False,
            "runtime_execution_performed": False,
            "production_runtime_receipt_write_allowed": False,
        },
        "boundary": _boundary(
            context_validation_written=context.get("passed") is True,
            authorization_consumed=consumption.get("passed") is True,
            ingress_execution_written=execution.get("passed") is True,
            execution_receipt_written=receipt.get("passed") is True,
            boundary_report_written=boundary.get("passed") is True,
            public_ingress_authorized=consumption.get("passed") is True,
            external_public_ingress_opened=passed,
            external_public_ingress_closed=passed,
        ),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(artifacts["summary"], summary)
    return summary


def validate_post_h3o_context(post_h3o_summary_path: Path, *, output: Path | None = None) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    try:
        summary = read_json_object(post_h3o_summary_path)
    except Exception as exc:  # noqa: BLE001
        return _write_optional(_report(CONTEXT_SCHEMA, False, [f"post_h3o_summary_unreadable:{exc}"], checks), output)
    artifacts = object_value(summary.get("artifacts"))
    receipt = _read_verified_ref(artifacts.get("authorization_receipt"), checks, failures, "post_h3o_authorization_receipt")
    boundary_report = _read_verified_ref(artifacts.get("boundary_report"), checks, failures, "post_h3o_boundary_report")
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
        "post_h3o_summary": summary,
        "authorization_receipt": receipt,
        "boundary_report": boundary_report,
        "source_artifacts": {"post_h3o_summary": artifact_ref(post_h3o_summary_path)},
        "boundary": _boundary(context_validation_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    return _write_optional(report, output)


def _write_authorization_consumption(
    *,
    context: dict[str, Any],
    post_h3o_summary_path: Path,
    output: Path,
    operator_id: str,
    operator_decision: str,
    audit_decision: str,
    operator_statement: str,
    ack_public_ingress_execution: bool,
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
    check(checks, failures, "explicit_operator_ack", ack_public_ingress_execution is True)
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
        "ack_public_ingress_execution": ack_public_ingress_execution,
        "source_artifacts": {"post_h3o_summary": artifact_ref(post_h3o_summary_path)},
        "boundary": _boundary(authorization_consumed=passed, public_ingress_authorized=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def _write_ingress_execution(
    *,
    context: dict[str, Any],
    consumption_path: Path,
    output: Path,
    bind_host: str,
    probe_host: str,
    open_seconds: float,
    expected_external_participants: int,
) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    receipt = object_value(context.get("authorization_receipt"))
    scope = object_value(receipt.get("authorization_scope"))
    consumption = read_json_object(consumption_path)
    max_seconds = float(scope.get("max_public_ingress_seconds") or 0)
    max_participants = int(scope.get("max_external_participants") or 0)
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "authorization_consumed", consumption.get("passed") is True)
    check(checks, failures, "authorization_id_bound", consumption.get("authorization_id") == receipt.get("authorization_id"))
    check(checks, failures, "scope_authorizes_public_ingress_once", scope.get("authorize_public_ingress_execution_once") is True)
    check(checks, failures, "open_seconds_positive", open_seconds > 0)
    check(checks, failures, "open_seconds_within_scope", open_seconds <= max_seconds)
    check(checks, failures, "external_participants_within_scope", 0 <= expected_external_participants <= max_participants)
    check(checks, failures, "bind_host_present", bool(bind_host.strip()))
    action_result: dict[str, Any] = {"attempted": False}
    if _passed(checks, failures):
        action_result = _open_probe_close_status_ingress(bind_host=bind_host, probe_host=probe_host, open_seconds=open_seconds)
        check(checks, failures, "ingress_opened", action_result.get("opened") is True)
        check(checks, failures, "ingress_probe_passed", action_result.get("probe_passed") is True)
        check(checks, failures, "ingress_closed", action_result.get("closed") is True)
    passed = _passed(checks, failures)
    report = {
        "schema_version": INGRESS_EXECUTION_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "executed_at": _now(),
        "public_ingress_execution_id": f"post-h3q-public-ingress-exec:{sha256_json([artifact_ref(consumption_path), bind_host, probe_host, open_seconds, expected_external_participants])[:24]}",
        "execution_scope": {
            "bind_host": bind_host,
            "probe_host": probe_host,
            "open_seconds": open_seconds,
            "expected_external_participants": expected_external_participants,
            "allowed_ingress_scope": scope.get("allowed_ingress_scope"),
        },
        "action_result": action_result,
        "source_artifacts": {"authorization_consumption": artifact_ref(consumption_path)},
        "readiness": {
            "public_ingress_execution_complete": passed,
            "external_public_ingress_opened": passed,
            "external_public_ingress_closed": passed,
            "runtime_expansion_authorized": False,
            "runtime_execution_performed": False,
        },
        "boundary": _boundary(ingress_execution_written=passed, public_ingress_authorized=passed, external_public_ingress_opened=passed, external_public_ingress_closed=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def _write_execution_receipt(*, context: dict[str, Any], ingress_execution_path: Path, output: Path) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    execution = read_json_object(ingress_execution_path)
    receipt = object_value(context.get("authorization_receipt"))
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "ingress_execution_passed", execution.get("passed") is True)
    readiness = object_value(execution.get("readiness"))
    check(checks, failures, "ingress_opened", readiness.get("external_public_ingress_opened") is True)
    check(checks, failures, "ingress_closed", readiness.get("external_public_ingress_closed") is True)
    check(checks, failures, "no_runtime_expansion", readiness.get("runtime_expansion_authorized") is False)
    passed = _passed(checks, failures)
    execution_receipt = {
        "schema_version": EXECUTION_RECEIPT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "written_at": _now(),
        "execution_receipt_id": f"post-h3q-public-ingress-receipt:{sha256_json([artifact_ref(ingress_execution_path), receipt.get('authorization_id')])[:24]}",
        "authorization_id": receipt.get("authorization_id"),
        "public_ingress_execution_id": execution.get("public_ingress_execution_id"),
        "source_artifacts": {"public_ingress_execution": artifact_ref(ingress_execution_path)},
        "readiness": {
            "public_ingress_execution_complete": passed,
            "external_public_ingress_opened": passed,
            "external_public_ingress_closed": passed,
            "runtime_expansion_authorized": False,
            "runtime_execution_performed": False,
        },
        "boundary": _boundary(execution_receipt_written=passed, public_ingress_authorized=passed, external_public_ingress_opened=passed, external_public_ingress_closed=passed),
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
    check(checks, failures, "ingress_opened", readiness.get("external_public_ingress_opened") is True)
    check(checks, failures, "ingress_closed", readiness.get("external_public_ingress_closed") is True)
    check(checks, failures, "runtime_expansion_not_authorized", readiness.get("runtime_expansion_authorized") is False)
    check(checks, failures, "runtime_execution_not_performed", readiness.get("runtime_execution_performed") is False)
    passed = _passed(checks, failures)
    report = {
        "schema_version": BOUNDARY_REPORT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "source_artifacts": {"execution_receipt": artifact_ref(execution_receipt_path)},
        "boundary": _boundary(boundary_report_written=passed, public_ingress_authorized=passed, external_public_ingress_opened=passed, external_public_ingress_closed=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def _open_probe_close_status_ingress(*, bind_host: str, probe_host: str, open_seconds: float) -> dict[str, Any]:
    status_payload = {
        "schema_version": "post-h3q-status-only-ingress:v1",
        "status": "ok",
        "production_data": False,
        "scope": "invite_only_status_endpoint_preview",
    }

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            if self.path != "/status":
                self.send_response(404)
                self.end_headers()
                return
            body = json.dumps(status_payload, sort_keys=True).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            return

    server: ThreadingHTTPServer | None = None
    started_at = _now()
    try:
        server = ThreadingHTTPServer((bind_host, 0), Handler)
        server.daemon_threads = True
        port = int(server.server_address[1])
        thread = threading.Thread(target=server.serve_forever, name="post-h3q-public-ingress", daemon=True)
        thread.start()
        probe_url = f"http://{probe_host}:{port}/status"
        with urllib.request.urlopen(probe_url, timeout=2) as response:  # noqa: S310 - local bounded probe
            body = response.read().decode("utf-8")
            probe_status = response.status
        time.sleep(open_seconds)
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()
        return {
            "attempted": True,
            "opened": True,
            "closed": True,
            "bind_host": bind_host,
            "probe_host": probe_host,
            "port": port,
            "probe_url": probe_url,
            "probe_status": probe_status,
            "probe_body_sha256": sha256_json(body),
            "started_at": started_at,
            "closed_at": _now(),
            "probe_passed": probe_status == 200 and json.loads(body).get("status") == "ok",
        }
    except Exception as exc:  # noqa: BLE001
        if server is not None:
            try:
                server.shutdown()
                server.server_close()
            except Exception:  # noqa: BLE001
                pass
        return {"attempted": True, "opened": False, "closed": server is not None, "started_at": started_at, "error": str(exc), "probe_passed": False}


def _check_summary(summary: dict[str, Any], checks: dict[str, bool], failures: list[str]) -> None:
    readiness = object_value(summary.get("readiness"))
    boundary = object_value(summary.get("boundary"))
    check(checks, failures, "post_h3o_schema_valid", summary.get("schema_version") == POST_H3O_SCHEMA)
    check(checks, failures, "post_h3o_passed", summary.get("passed") is True)
    check(checks, failures, "public_ingress_authorized", readiness.get("public_ingress_authorized") is True)
    check(checks, failures, "public_ingress_execution_ready", readiness.get("public_ingress_execution_ready") is True)
    check(checks, failures, "ingress_not_previously_opened", readiness.get("external_public_ingress_opened") is False)
    check(checks, failures, "runtime_expansion_not_authorized", readiness.get("runtime_expansion_authorized") is False)
    check(checks, failures, "boundary_no_ingress_opened", boundary.get("external_public_ingress_opened") is False)
    check(checks, failures, "boundary_no_runtime_execution", boundary.get("runtime_execution_performed") is False)


def _check_authorization_receipt(summary: dict[str, Any], receipt: dict[str, Any], checks: dict[str, bool], failures: list[str]) -> None:
    check(checks, failures, "receipt_schema_valid", receipt.get("schema_version") == POST_H3O_AUTHORIZATION_RECEIPT_SCHEMA)
    check(checks, failures, "receipt_passed", receipt.get("passed") is True)
    check(checks, failures, "receipt_authorization_granted", receipt.get("authorization_granted") is True)
    check(checks, failures, "receipt_id_matches", receipt.get("authorization_id") == summary.get("public_ingress_authorization_id"))
    check(checks, failures, "receipt_single_use", receipt.get("single_use") is True)
    check(checks, failures, "receipt_unconsumed", receipt.get("consumed") is False)
    scope = object_value(receipt.get("authorization_scope"))
    check(checks, failures, "scope_public_ingress_once", scope.get("authorize_public_ingress_execution_once") is True)
    check(checks, failures, "scope_no_runtime_expansion", scope.get("authorize_runtime_expansion") is False)


def _check_boundary_report(report: dict[str, Any], checks: dict[str, bool], failures: list[str]) -> None:
    check(checks, failures, "boundary_report_schema_valid", report.get("schema_version") == POST_H3O_BOUNDARY_REPORT_SCHEMA and report.get("passed") is True)
    boundary = object_value(report.get("boundary"))
    check(checks, failures, "boundary_public_authorized", boundary.get("public_ingress_authorized") is True)
    check(checks, failures, "boundary_no_ingress_opened", boundary.get("external_public_ingress_opened") is False)
    check(checks, failures, "boundary_no_runtime_execution", boundary.get("runtime_execution_performed") is False)


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
        "ingress_execution_written": False,
        "execution_receipt_written": False,
        "boundary_report_written": False,
        "public_ingress_authorized": False,
        "external_public_ingress_opened": False,
        "external_public_ingress_closed": False,
        "runtime_expansion_authorized": False,
        "runtime_execution_performed": False,
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
    parser = argparse.ArgumentParser(description="Run PostH3-Q public ingress execution gate")
    parser.add_argument("--post-h3o-summary", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--operator-id", default="operator-primary")
    parser.add_argument("--operator-decision", default=ACCEPTED_OPERATOR_DECISION)
    parser.add_argument("--audit-decision", default=ACCEPTED_AUDIT_DECISION)
    parser.add_argument("--operator-statement", default="Execute one bounded status-only public ingress opening and close it after probe.")
    parser.add_argument("--bind-host", default="0.0.0.0")
    parser.add_argument("--probe-host", default="127.0.0.1")
    parser.add_argument("--open-seconds", type=float, default=1.0)
    parser.add_argument("--expected-external-participants", type=int, default=0)
    parser.add_argument("--ack-public-ingress-execution", action="store_true")
    args = parser.parse_args()
    summary = run_gate(
        post_h3o_summary_path=args.post_h3o_summary,
        output_root=args.output_root,
        operator_id=args.operator_id,
        operator_decision=args.operator_decision,
        audit_decision=args.audit_decision,
        operator_statement=args.operator_statement,
        bind_host=args.bind_host,
        probe_host=args.probe_host,
        open_seconds=args.open_seconds,
        expected_external_participants=args.expected_external_participants,
        ack_public_ingress_execution=args.ack_public_ingress_execution,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if summary.get("passed") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
