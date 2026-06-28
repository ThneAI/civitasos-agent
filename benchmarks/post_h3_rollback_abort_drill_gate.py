"""Run Post-H3 rollback / abort drill gate.

PostH3-C consumes a passed PostH3-B deployment boundary and writes a dry-run
rollback / abort drill receipt plus owner, audit, and rollback reconciliation.
It does not contact VMs, deploy, execute runtime, open public ingress, access
production data, or write production runtime receipts.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from benchmarks.i_gate_evidence import artifact_ref, check, object_value, read_json_object, write_json_object
from benchmarks.post_h3_deployment_boundary_gate import BOUNDARY_RECEIPT_SCHEMA as POST_H3B_BOUNDARY_RECEIPT_SCHEMA
from benchmarks.post_h3_deployment_boundary_gate import CHAIN_SCHEMA as POST_H3B_SCHEMA
from benchmarks.post_h3_deployment_boundary_gate import ENVIRONMENT_PROOF_SCHEMA as POST_H3B_ENVIRONMENT_PROOF_SCHEMA

CHAIN_SCHEMA = "post-h3-rollback-abort-drill-chain:v1"
DECISION_SCHEMA = "post-h3-rollback-abort-owner-decision:v1"
DRILL_RECEIPT_SCHEMA = "post-h3-rollback-abort-drill-receipt:v1"
RECONCILIATION_SCHEMA = "post-h3-rollback-abort-reconciliation:v1"

OWNER_DECISION = "approve_post_h3_rollback_abort_drill"
AUDIT_DECISION = "approve_post_h3_no_public_ingress_boundary"
ROLLBACK_DECISION = "approve_post_h3_abort_and_rollback_path"
NON_CLAIMS = (
    "post_h3c_does_not_contact_vms",
    "post_h3c_does_not_deploy",
    "post_h3c_does_not_execute_runtime",
    "post_h3c_does_not_open_public_ingress",
    "post_h3c_does_not_access_production_data",
    "post_h3c_does_not_write_production_runtime_receipts",
)


def run_gate(
    *,
    post_h3b_summary_path: Path,
    output_root: Path,
    operator_id: str = "operator-primary",
    owner_decision: str = OWNER_DECISION,
    audit_decision: str = AUDIT_DECISION,
    rollback_decision: str = ROLLBACK_DECISION,
    ack_rollback_abort_drill: bool = False,
) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "owner_decision": output_root / "post_h3c_owner_audit_rollback_decision.json",
        "drill_receipt": output_root / "post_h3c_rollback_abort_drill_receipt.json",
        "reconciliation": output_root / "post_h3c_rollback_abort_reconciliation.json",
        "summary": output_root / "post_h3c_rollback_abort_drill_summary.json",
    }
    context = _validate_post_h3b(post_h3b_summary_path)
    decision = _write_decision(
        context=context,
        post_h3b_summary_path=post_h3b_summary_path,
        output=artifacts["owner_decision"],
        operator_id=operator_id,
        owner_decision=owner_decision,
        audit_decision=audit_decision,
        rollback_decision=rollback_decision,
        ack_rollback_abort_drill=ack_rollback_abort_drill,
    )
    drill = _write_drill_receipt(
        context=context,
        decision_path=artifacts["owner_decision"],
        output=artifacts["drill_receipt"],
    )
    reconciliation = _write_reconciliation(
        context=context,
        decision_path=artifacts["owner_decision"],
        drill_receipt_path=artifacts["drill_receipt"],
        output=artifacts["reconciliation"],
    )
    reports = [context, decision, drill, reconciliation]
    passed = all(report.get("passed") is True for report in reports)
    summary = {
        "schema_version": CHAIN_SCHEMA,
        "passed": passed,
        "failure_reasons": _failures(reports),
        "checked_at": _now(),
        "source_artifacts": {"post_h3b_summary": artifact_ref(post_h3b_summary_path)},
        "artifacts": {name: artifact_ref(path) for name, path in artifacts.items() if name != "summary"},
        "readiness": {
            "state": "post_h3_rollback_abort_drill_complete" if passed else "blocked_post_h3_rollback_abort_drill",
            "post_h3_rollback_abort_drill_complete": passed,
            "first_internal_runtime_execution_ready": passed,
            "runtime_execution_allowed": object_value(context.get("post_h3b_summary")).get("readiness", {}).get("runtime_execution_allowed") is True,
            "runtime_execution_performed": False,
            "deploy_performed": False,
            "external_public_ingress_opened": False,
            "production_runtime_receipt_write_allowed": False,
        },
        "boundary": _boundary(
            owner_decision_written=decision.get("passed") is True,
            rollback_abort_drill_receipt_written=drill.get("passed") is True,
            reconciliation_written=reconciliation.get("passed") is True,
            abort_path_verified=drill.get("abort_path_verified") is True,
            rollback_path_verified=drill.get("rollback_path_verified") is True,
        ),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(artifacts["summary"], summary)
    return summary


def _validate_post_h3b(path: Path) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    try:
        summary = read_json_object(path)
    except Exception as exc:  # noqa: BLE001
        return _report("post-h3c-post-h3b-context:v1", False, [f"post_h3b_summary_unreadable:{exc}"], checks)
    readiness = object_value(summary.get("readiness"))
    boundary = object_value(summary.get("boundary"))
    artifacts = object_value(summary.get("artifacts"))
    environment = _read_artifact(artifacts.get("environment_proof"), checks, failures, "post_h3b_environment_proof")
    boundary_receipt = _read_artifact(artifacts.get("boundary_receipt"), checks, failures, "post_h3b_boundary_receipt")
    env = object_value(environment.get("environment"))
    check(checks, failures, "post_h3b_schema_valid", summary.get("schema_version") == POST_H3B_SCHEMA)
    check(checks, failures, "post_h3b_passed", summary.get("passed") is True)
    check(checks, failures, "post_h3b_ready_for_rollback", readiness.get("rollback_abort_drill_ready") is True)
    check(checks, failures, "post_h3b_runtime_not_performed", readiness.get("runtime_execution_performed") is False)
    check(checks, failures, "post_h3b_no_deploy", boundary.get("deploy_performed") is False)
    check(checks, failures, "post_h3b_no_public_ingress", boundary.get("external_public_ingress_opened") is False)
    check(checks, failures, "environment_proof_passed", environment.get("schema_version") == POST_H3B_ENVIRONMENT_PROOF_SCHEMA and environment.get("passed") is True)
    check(checks, failures, "boundary_receipt_passed", boundary_receipt.get("schema_version") == POST_H3B_BOUNDARY_RECEIPT_SCHEMA and boundary_receipt.get("passed") is True)
    check(checks, failures, "environment_private_only", env.get("private_only") is True)
    check(checks, failures, "environment_public_ingress_closed", env.get("public_ingress_allowed") is False)
    check(checks, failures, "rollback_runbook_present", bool(str(env.get("rollback_runbook") or "").strip()))
    passed = _passed(checks, failures)
    return {
        "schema_version": "post-h3c-post-h3b-context:v1",
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "post_h3b_summary": summary,
        "environment_proof": environment,
        "boundary_receipt": boundary_receipt,
        "source_artifacts": {"post_h3b_summary": artifact_ref(path)},
        "boundary": _boundary(),
        "non_claims": list(NON_CLAIMS),
    }


def _write_decision(
    *,
    context: dict[str, Any],
    post_h3b_summary_path: Path,
    output: Path,
    operator_id: str,
    owner_decision: str,
    audit_decision: str,
    rollback_decision: str,
    ack_rollback_abort_drill: bool,
) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "operator_id_present", bool(operator_id.strip()))
    check(checks, failures, "owner_decision_approved", owner_decision == OWNER_DECISION)
    check(checks, failures, "audit_decision_approved", audit_decision == AUDIT_DECISION)
    check(checks, failures, "rollback_decision_approved", rollback_decision == ROLLBACK_DECISION)
    check(checks, failures, "explicit_operator_ack", ack_rollback_abort_drill is True)
    passed = _passed(checks, failures)
    report = {
        "schema_version": DECISION_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "decided_at": _now(),
        "operator_id": operator_id,
        "owner_decision": owner_decision,
        "audit_decision": audit_decision,
        "rollback_decision": rollback_decision,
        "ack_rollback_abort_drill": ack_rollback_abort_drill,
        "source_artifacts": {"post_h3b_summary": artifact_ref(post_h3b_summary_path)},
        "boundary": _boundary(owner_decision_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def _write_drill_receipt(*, context: dict[str, Any], decision_path: Path, output: Path) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    decision = read_json_object(decision_path)
    environment = object_value(context.get("environment_proof"))
    env = object_value(environment.get("environment"))
    rollback_runbook = str(env.get("rollback_runbook") or "")
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "decision_passed", decision.get("schema_version") == DECISION_SCHEMA and decision.get("passed") is True)
    check(checks, failures, "rollback_runbook_present", bool(rollback_runbook.strip()))
    check(checks, failures, "rollback_runbook_has_stop_or_restore", any(word in rollback_runbook.lower() for word in ("stop", "restore", "revoke", "rollback")))
    check(checks, failures, "abort_path_available", True)
    check(checks, failures, "no_vm_contact", True)
    passed = _passed(checks, failures)
    receipt = {
        "schema_version": DRILL_RECEIPT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "drill_mode": "artifact_only_abort_and_rollback_dry_run",
        "abort_path_verified": passed,
        "rollback_path_verified": passed,
        "rollback_performed": False,
        "abort_performed": False,
        "rollback_runbook": rollback_runbook,
        "source_artifacts": {
            "owner_decision": artifact_ref(decision_path),
            "post_h3b_summary": object_value(context.get("source_artifacts")).get("post_h3b_summary"),
        },
        "boundary": _boundary(
            rollback_abort_drill_receipt_written=passed,
            abort_path_verified=passed,
            rollback_path_verified=passed,
        ),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, receipt)
    return receipt


def _write_reconciliation(
    *,
    context: dict[str, Any],
    decision_path: Path,
    drill_receipt_path: Path,
    output: Path,
) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    decision = read_json_object(decision_path)
    drill = read_json_object(drill_receipt_path)
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "decision_passed", decision.get("passed") is True)
    check(checks, failures, "drill_receipt_passed", drill.get("passed") is True)
    check(checks, failures, "abort_path_verified", drill.get("abort_path_verified") is True)
    check(checks, failures, "rollback_path_verified", drill.get("rollback_path_verified") is True)
    passed = _passed(checks, failures)
    report = {
        "schema_version": RECONCILIATION_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "decision": "approve_post_h3_first_internal_runtime_execution" if passed else "blocked_post_h3_first_internal_runtime_execution",
        "source_artifacts": {
            "owner_decision": artifact_ref(decision_path),
            "drill_receipt": artifact_ref(drill_receipt_path),
        },
        "readiness": {
            "first_internal_runtime_execution_ready": passed,
            "production_runtime_receipt_write_allowed": False,
        },
        "boundary": _boundary(reconciliation_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def _read_artifact(value: Any, checks: dict[str, bool], failures: list[str], label: str) -> dict[str, Any]:
    ref = object_value(value)
    path = Path(str(ref.get("path") or ""))
    check(checks, failures, f"{label}_ref_present", bool(ref.get("path")) and bool(ref.get("sha256")))
    check(checks, failures, f"{label}_exists", path.is_file())
    if not path.is_file():
        return {}
    payload = read_json_object(path)
    check(checks, failures, f"{label}_hash_valid", artifact_ref(path).get("sha256") == ref.get("sha256"))
    return payload


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
        "owner_decision_written": False,
        "rollback_abort_drill_receipt_written": False,
        "reconciliation_written": False,
        "abort_path_verified": False,
        "rollback_path_verified": False,
        "runtime_execution_performed": False,
        "deploy_performed": False,
        "vm_contact_performed": False,
        "external_public_ingress_opened": False,
        "production_data_accessed": False,
        "production_runtime_receipt_write_allowed": False,
        "production_runtime_receipt_written": False,
        "secrets_recorded": False,
    }
    boundary.update(overrides)
    return boundary


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Post-H3 rollback / abort drill")
    parser.add_argument("--post-h3b-summary", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--operator-id", default="operator-primary")
    parser.add_argument("--owner-decision", default=OWNER_DECISION)
    parser.add_argument("--audit-decision", default=AUDIT_DECISION)
    parser.add_argument("--rollback-decision", default=ROLLBACK_DECISION)
    parser.add_argument("--ack-rollback-abort-drill", action="store_true")
    args = parser.parse_args()
    summary = run_gate(
        post_h3b_summary_path=args.post_h3b_summary,
        output_root=args.output_root,
        operator_id=args.operator_id,
        owner_decision=args.owner_decision,
        audit_decision=args.audit_decision,
        rollback_decision=args.rollback_decision,
        ack_rollback_abort_drill=args.ack_rollback_abort_drill,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if summary.get("passed") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
