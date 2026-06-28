"""Authorize the first internal controlled runtime after H.3 transition.

PostH3-A consumes a passed H.3 production transition authorization artifact and
writes a one-time internal runtime authorization package. It authorizes the
next stage to start an internal controlled runtime path, but it does not run the
runtime, deploy, open public ingress, access production data, or write
production runtime receipts.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from benchmarks.h3_production_transition_authorization_gate import SCHEMA_VERSION as H3_TRANSITION_SCHEMA
from benchmarks.i_gate_evidence import artifact_ref, check, object_value, read_json_object, sha256_json, write_json_object

CHAIN_SCHEMA = "post-h3-internal-runtime-authorization-chain:v1"
REQUEST_SCHEMA = "post-h3-internal-runtime-authorization-request:v1"
DECISION_SCHEMA = "post-h3-internal-runtime-authorization-decision:v1"
RECEIPT_SCHEMA = "post-h3-internal-runtime-authorization-receipt:v1"

REQUIRED_OPERATOR_DECISION = "authorize_internal_controlled_runtime"
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
FORBIDDEN_SCOPE_TOKENS = ("*", "admin", "root", "secret", "wallet", "payment", "public_ingress")
NON_CLAIMS = (
    "post_h3a_authorizes_internal_runtime_only",
    "post_h3a_does_not_execute_runtime",
    "post_h3a_does_not_deploy",
    "post_h3a_does_not_open_public_ingress",
    "post_h3a_does_not_access_production_data",
    "post_h3a_does_not_write_production_runtime_receipts",
)


def run_gate(
    *,
    h3_transition_path: Path,
    output_root: Path,
    operator_id: str = "operator-primary",
    operator_decision: str = REQUIRED_OPERATOR_DECISION,
    operator_statement: str = "Authorize first internal controlled runtime after H.3 transition.",
    ack_internal_runtime: bool = False,
    service_token_scopes: list[str] | None = None,
    max_runtime_seconds: int = 1800,
    max_agent_count: int = 5,
    runtime_id: str | None = None,
) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "authorization_request": output_root / "post_h3a_internal_runtime_authorization_request.json",
        "authorization_decision": output_root / "post_h3a_internal_runtime_authorization_decision.json",
        "authorization_receipt": output_root / "post_h3a_internal_runtime_authorization_receipt.json",
        "summary": output_root / "post_h3a_internal_runtime_authorization_summary.json",
    }
    context = _validate_h3_transition(h3_transition_path)
    request = _write_request(
        context=context,
        h3_transition_path=h3_transition_path,
        output=artifacts["authorization_request"],
        service_token_scopes=service_token_scopes,
        max_runtime_seconds=max_runtime_seconds,
        max_agent_count=max_agent_count,
        runtime_id=runtime_id,
    )
    decision = _write_decision(
        request_path=artifacts["authorization_request"],
        output=artifacts["authorization_decision"],
        operator_id=operator_id,
        operator_decision=operator_decision,
        operator_statement=operator_statement,
        ack_internal_runtime=ack_internal_runtime,
    )
    receipt = _write_receipt(
        request_path=artifacts["authorization_request"],
        decision_path=artifacts["authorization_decision"],
        output=artifacts["authorization_receipt"],
    )
    reports = [context, request, decision, receipt]
    passed = all(report.get("passed") is True for report in reports)
    summary = {
        "schema_version": CHAIN_SCHEMA,
        "passed": passed,
        "failure_reasons": _failures(reports),
        "checked_at": _now(),
        "runtime_id": request.get("runtime_request", {}).get("runtime_id"),
        "source_artifacts": {"h3_transition_authorization": artifact_ref(h3_transition_path)},
        "artifacts": {name: artifact_ref(path) for name, path in artifacts.items() if name != "summary"},
        "authorization": {
            "decision": decision.get("operator_decision"),
            "authorization_id": receipt.get("authorization_id"),
            "single_use": receipt.get("single_use") is True,
            "consumed": receipt.get("consumed") is True,
        },
        "readiness": {
            "state": "post_h3_internal_runtime_authorized" if passed else "blocked_post_h3_internal_runtime_authorization",
            "post_h3_internal_runtime_authorized": passed,
            "runtime_execution_allowed": passed,
            "runtime_execution_performed": False,
            "deployment_boundary_ready": passed,
            "production_transition_allowed": True,
            "production_runtime_receipt_write_allowed": False,
        },
        "boundary": _boundary(
            authorization_request_written=request.get("passed") is True,
            authorization_decision_written=decision.get("passed") is True,
            authorization_receipt_written=receipt.get("passed") is True,
            internal_runtime_execution_authorized=passed,
        ),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(artifacts["summary"], summary)
    return summary


def _validate_h3_transition(path: Path) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    try:
        report = read_json_object(path)
    except Exception as exc:  # noqa: BLE001
        return _report("post-h3a-h3-transition-context:v1", False, [f"h3_transition_unreadable:{exc}"], checks)
    readiness = object_value(report.get("readiness"))
    boundary = object_value(report.get("boundary"))
    check(checks, failures, "h3_transition_schema_valid", report.get("schema_version") == H3_TRANSITION_SCHEMA)
    check(checks, failures, "h3_transition_passed", report.get("passed") is True)
    check(checks, failures, "h3_transition_authorized", readiness.get("h3_production_transition_authorized") is True)
    check(checks, failures, "production_transition_allowed", readiness.get("production_transition_allowed") is True)
    check(checks, failures, "runtime_not_previously_allowed", readiness.get("runtime_execution_allowed") is False)
    check(checks, failures, "receipt_write_not_previously_allowed", readiness.get("production_runtime_receipt_write_allowed") is False)
    check(checks, failures, "boundary_transition_allowed", boundary.get("production_transition_allowed") is True)
    check(checks, failures, "boundary_runtime_not_performed", boundary.get("runtime_execution_allowed") is False)
    check(checks, failures, "boundary_no_deploy", boundary.get("deploy_performed") is False)
    check(checks, failures, "boundary_no_public_ingress", boundary.get("external_public_ingress_opened") is False)
    passed = _passed(checks, failures)
    return {
        "schema_version": "post-h3a-h3-transition-context:v1",
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "transition": report,
        "source_artifacts": {"h3_transition_authorization": artifact_ref(path)},
        "boundary": _boundary(),
        "non_claims": list(NON_CLAIMS),
    }


def _write_request(
    *,
    context: dict[str, Any],
    h3_transition_path: Path,
    output: Path,
    service_token_scopes: list[str] | None,
    max_runtime_seconds: int,
    max_agent_count: int,
    runtime_id: str | None,
) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    scopes = sorted(set(service_token_scopes or REQUIRED_SERVICE_SCOPES))
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "required_service_scopes_present", REQUIRED_SERVICE_SCOPES <= set(scopes))
    check(checks, failures, "no_forbidden_service_scope", _scopes_safe(scopes))
    check(checks, failures, "max_runtime_seconds_within_limit", 60 <= max_runtime_seconds <= 7200)
    check(checks, failures, "max_agent_count_within_limit", 1 <= max_agent_count <= 5)
    passed = _passed(checks, failures)
    request = {
        "schema_version": REQUEST_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "source_artifacts": {"h3_transition_authorization": artifact_ref(h3_transition_path)},
        "runtime_request": {
            "runtime_id": runtime_id or "post-h3-runtime:civitasos-internal-controlled-pilot:001",
            "mode": "internal_controlled_production_pilot_runtime",
            "max_runtime_seconds": max_runtime_seconds,
            "max_agent_count": max_agent_count,
            "allowed_agent_roles": [
                "operator_agent",
                "audit_agent",
                "rollback_agent",
                "monitoring_agent",
                "external_review_agent",
            ],
            "allowed_actions": [
                "task_pool_post_low_risk_internal_task",
                "task_pool_claim_by_authorized_agent",
                "llm_generation_with_budgeted_provider",
                "operator_review_reconciliation",
                "write_internal_runtime_receipt_candidate",
            ],
            "required_service_token_scopes": scopes,
            "required_next_gates": [
                "post_h3b_deployment_boundary",
                "post_h3c_rollback_abort_drill",
                "post_h3d_production_receipt_write_authorization",
            ],
            "forbidden_actions": [
                "public_ingress",
                "production_data_access",
                "unscoped_external_mutation",
                "deploy_without_boundary_gate",
                "production_runtime_receipt_write_without_receipt_gate",
            ],
        },
        "readiness": {
            "state": "post_h3a_runtime_request_ready" if passed else "blocked_post_h3a_runtime_request",
            "decision_ready": passed,
            "runtime_execution_performed": False,
        },
        "boundary": _boundary(authorization_request_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, request)
    return request


def _write_decision(
    *,
    request_path: Path,
    output: Path,
    operator_id: str,
    operator_decision: str,
    operator_statement: str,
    ack_internal_runtime: bool,
) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    request = read_json_object(request_path)
    check(checks, failures, "request_passed", request.get("schema_version") == REQUEST_SCHEMA and request.get("passed") is True)
    check(checks, failures, "operator_id_present", bool(operator_id.strip()))
    check(checks, failures, "operator_decision_authorizes_internal_runtime", operator_decision == REQUIRED_OPERATOR_DECISION)
    check(checks, failures, "operator_statement_present", bool(operator_statement.strip()))
    check(checks, failures, "explicit_operator_ack", ack_internal_runtime is True)
    passed = _passed(checks, failures)
    decision = {
        "schema_version": DECISION_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "source_artifacts": {"authorization_request": artifact_ref(request_path)},
        "operator_id": operator_id,
        "operator_decision": operator_decision,
        "required_operator_decision": REQUIRED_OPERATOR_DECISION,
        "operator_statement": operator_statement,
        "operator_statement_sha256": sha256_json(operator_statement),
        "ack_internal_runtime": ack_internal_runtime,
        "readiness": {
            "state": "post_h3a_runtime_decision_authorized" if passed else "blocked_post_h3a_runtime_decision",
            "receipt_ready": passed,
        },
        "boundary": _boundary(authorization_decision_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, decision)
    return decision


def _write_receipt(*, request_path: Path, decision_path: Path, output: Path) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    request = read_json_object(request_path)
    decision = read_json_object(decision_path)
    check(checks, failures, "request_passed", request.get("schema_version") == REQUEST_SCHEMA and request.get("passed") is True)
    check(checks, failures, "decision_passed", decision.get("schema_version") == DECISION_SCHEMA and decision.get("passed") is True)
    passed = _passed(checks, failures)
    auth_id = f"post-h3a-auth:{sha256_json([artifact_ref(request_path), artifact_ref(decision_path)])[:24]}"
    receipt = {
        "schema_version": RECEIPT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "authorization_id": auth_id,
        "single_use": True,
        "consumed": False,
        "source_artifacts": {
            "authorization_request": artifact_ref(request_path),
            "authorization_decision": artifact_ref(decision_path),
        },
        "readiness": {
            "state": "post_h3a_internal_runtime_authorization_receipt_ready" if passed else "blocked_post_h3a_authorization_receipt",
            "internal_runtime_execution_ready": passed,
            "runtime_execution_performed": False,
        },
        "boundary": _boundary(authorization_receipt_written=passed, internal_runtime_execution_authorized=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, receipt)
    return receipt


def _scopes_safe(scopes: list[str]) -> bool:
    scope_text = " ".join(scope.lower() for scope in scopes)
    return not any(token in scope_text for token in FORBIDDEN_SCOPE_TOKENS)


def _failures(reports: list[dict[str, Any]]) -> list[str]:
    failures: list[str] = []
    for report in reports:
        failures.extend(str(item) for item in report.get("failure_reasons", []))
    return sorted(set(failures))


def _passed(checks: dict[str, bool], failures: list[str]) -> bool:
    return bool(checks) and all(checks.values()) and not failures


def _report(schema: str, passed: bool, failures: list[str], checks: dict[str, bool]) -> dict[str, Any]:
    return {
        "schema_version": schema,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "boundary": _boundary(),
        "non_claims": list(NON_CLAIMS),
    }


def _boundary(**overrides: bool) -> dict[str, bool]:
    boundary = {
        "production_transition_allowed": True,
        "authorization_request_written": False,
        "authorization_decision_written": False,
        "authorization_receipt_written": False,
        "internal_runtime_execution_authorized": False,
        "runtime_execution_performed": False,
        "deploy_performed": False,
        "external_public_ingress_opened": False,
        "production_data_accessed": False,
        "production_runtime_receipt_write_allowed": False,
        "production_runtime_receipt_written": False,
        "source_tree_write_performed": False,
        "git_write_performed": False,
        "secrets_recorded": False,
    }
    boundary.update(overrides)
    return boundary


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def main() -> int:
    parser = argparse.ArgumentParser(description="Authorize Post-H3 internal controlled runtime")
    parser.add_argument("--h3-transition", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--operator-id", default="operator-primary")
    parser.add_argument("--operator-decision", default=REQUIRED_OPERATOR_DECISION)
    parser.add_argument("--operator-statement", default="Authorize first internal controlled runtime after H.3 transition.")
    parser.add_argument("--ack-internal-runtime", action="store_true")
    parser.add_argument("--service-token-scope", action="append", dest="service_token_scopes")
    parser.add_argument("--max-runtime-seconds", type=int, default=1800)
    parser.add_argument("--max-agent-count", type=int, default=5)
    parser.add_argument("--runtime-id")
    args = parser.parse_args()
    summary = run_gate(
        h3_transition_path=args.h3_transition,
        output_root=args.output_root,
        operator_id=args.operator_id,
        operator_decision=args.operator_decision,
        operator_statement=args.operator_statement,
        ack_internal_runtime=args.ack_internal_runtime,
        service_token_scopes=args.service_token_scopes,
        max_runtime_seconds=args.max_runtime_seconds,
        max_agent_count=args.max_agent_count,
        runtime_id=args.runtime_id,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if summary.get("passed") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
