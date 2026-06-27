"""Run P0-L external preview evidence gate.

P0-L consumes a passed P0-K private preview soak summary and packages the soak
result into reviewable external-preview evidence byproducts. It does not contact
VMs, deploy services, mutate source/Git, open public ingress, authorize
production transition, or write production receipts.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from benchmarks.i_gate_evidence import artifact_ref, check, object_value, read_json_object, write_json_object
from benchmarks.p0j_multi_vm_private_preview_gate import _closed_no_production_boundary, _read_verified_ref, _unique_texts
from benchmarks.p0k_private_preview_soak_gate import (
    AUTHORIZATION_SCHEMA as P0K_AUTHORIZATION_SCHEMA,
    CHAIN_SCHEMA as P0K_CHAIN_SCHEMA,
    MONITORING_AUDIT_SCHEMA as P0K_MONITORING_AUDIT_SCHEMA,
    RECONCILIATION_SCHEMA as P0K_RECONCILIATION_SCHEMA,
    ROLLBACK_SCHEMA as P0K_ROLLBACK_SCHEMA,
    SOAK_RECEIPT_SCHEMA as P0K_SOAK_RECEIPT_SCHEMA,
)

CHAIN_SCHEMA = "p0l-external-preview-evidence-chain:v1"
CONTEXT_SCHEMA = "p0l-p0k-context-validation:v1"
OWNER_FEEDBACK_SCHEMA = "p0l-owner-feedback-evidence:v1"
AUDIT_REVIEW_SCHEMA = "p0l-audit-review-evidence:v1"
ENVIRONMENT_PROOF_SCHEMA = "p0l-environment-proof-evidence:v1"
ROLLBACK_PROOF_SCHEMA = "p0l-rollback-proof-evidence:v1"
NO_PRODUCTION_BOUNDARY_SCHEMA = "p0l-no-production-boundary-evidence:v1"

ACCEPTED_OWNER_DECISION = "accepted_for_external_preview_evidence"
ACCEPTED_AUDIT_DECISION = "accepted_no_production_boundary"
ACCEPTED_ROLLBACK_DECISION = "accepted_rollback_verified"

NON_CLAIMS = (
    "p0l_is_external_preview_evidence_packaging_only",
    "p0l_requires_passed_p0k_private_preview_soak",
    "p0l_does_not_contact_vms_or_run_preview_commands",
    "p0l_does_not_open_public_ingress",
    "p0l_does_not_touch_production_data",
    "p0l_does_not_modify_source_or_git",
    "p0l_does_not_write_production_receipts",
    "p0l_does_not_authorize_production_transition",
)


def run_gate(
    *,
    p0k_summary_path: Path,
    output_root: Path,
    operator_id: str = "operator-cc",
    owner_feedback_decision: str = ACCEPTED_OWNER_DECISION,
    audit_review_decision: str = ACCEPTED_AUDIT_DECISION,
    rollback_owner_decision: str = ACCEPTED_ROLLBACK_DECISION,
    ack_external_preview_evidence: bool = False,
) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    context = validate_p0k_context(p0k_summary_path)
    artifacts = {
        "owner_feedback": output_root / "p0l_owner_feedback_evidence.json",
        "audit_review": output_root / "p0l_audit_review_evidence.json",
        "environment_proof": output_root / "p0l_environment_proof_evidence.json",
        "rollback_proof": output_root / "p0l_rollback_proof_evidence.json",
        "no_production_boundary": output_root / "p0l_no_production_boundary_evidence.json",
        "summary": output_root / "p0l_external_preview_evidence_chain_summary.json",
    }
    owner_feedback = write_owner_feedback_evidence(
        context=context,
        output=artifacts["owner_feedback"],
        operator_id=operator_id,
        decision=owner_feedback_decision,
        ack_external_preview_evidence=ack_external_preview_evidence,
        p0k_summary_path=p0k_summary_path,
    )
    audit_review = write_audit_review_evidence(
        context=context,
        output=artifacts["audit_review"],
        operator_id=operator_id,
        decision=audit_review_decision,
        ack_external_preview_evidence=ack_external_preview_evidence,
        p0k_summary_path=p0k_summary_path,
    )
    environment_proof = write_environment_proof_evidence(
        context=context,
        output=artifacts["environment_proof"],
        p0k_summary_path=p0k_summary_path,
    )
    rollback_proof = write_rollback_proof_evidence(
        context=context,
        output=artifacts["rollback_proof"],
        operator_id=operator_id,
        decision=rollback_owner_decision,
        ack_external_preview_evidence=ack_external_preview_evidence,
        p0k_summary_path=p0k_summary_path,
    )
    no_production = write_no_production_boundary_evidence(
        context=context,
        output=artifacts["no_production_boundary"],
        p0k_summary_path=p0k_summary_path,
    )
    reports = [owner_feedback, audit_review, environment_proof, rollback_proof, no_production]
    passed = context.get("passed") is True and all(report.get("passed") is True for report in reports)
    summary = {
        "schema_version": CHAIN_SCHEMA,
        "passed": passed,
        "failure_reasons": _failures([context, *reports]),
        "checked_at": _now(),
        "task_id": context.get("task_id"),
        "vm_target_ids": context.get("vm_target_ids", []),
        "operator_id": operator_id,
        "owners": context.get("owners", {}),
        "source_artifacts": {"p0k_summary": artifact_ref(p0k_summary_path)},
        "artifacts": {name: artifact_ref(path) for name, path in artifacts.items() if name != "summary"},
        "evidence": {
            "owner_feedback_decision": owner_feedback.get("decision"),
            "audit_review_decision": audit_review.get("decision"),
            "rollback_owner_decision": rollback_proof.get("decision"),
            "environment_scope": environment_proof.get("environment_scope"),
            "latency_summary": environment_proof.get("latency_summary", {}),
        },
        "readiness": {
            "state": "p0l_external_preview_evidence_passed" if passed else "blocked_p0l_external_preview_evidence",
            "p0l_external_preview_evidence_complete": passed,
            "p0m_controlled_beta_readiness_review_ready": passed,
            "production_transition_allowed": False,
        },
        "boundary": _boundary(
            owner_feedback_written=owner_feedback.get("passed") is True,
            audit_review_written=audit_review.get("passed") is True,
            environment_proof_written=environment_proof.get("passed") is True,
            rollback_proof_written=rollback_proof.get("passed") is True,
            no_production_boundary_evidence_written=no_production.get("passed") is True,
        ),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(artifacts["summary"], summary)
    return summary


def validate_p0k_context(p0k_summary_path: Path) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    try:
        p0k = read_json_object(p0k_summary_path)
    except Exception as exc:  # noqa: BLE001
        return _report(CONTEXT_SCHEMA, False, [f"p0k_summary_unreadable:{exc}"], checks)
    refs = object_value(p0k.get("artifacts"))
    authorization = _read_verified_ref(refs.get("authorization"), checks, failures, "p0k_authorization")
    soak = _read_verified_ref(refs.get("soak_receipt"), checks, failures, "p0k_soak_receipt")
    rollback = _read_verified_ref(refs.get("rollback_receipt"), checks, failures, "p0k_rollback_receipt")
    audit = _read_verified_ref(refs.get("monitoring_audit_receipt"), checks, failures, "p0k_monitoring_audit_receipt")
    reconciliation = _read_verified_ref(refs.get("reconciliation"), checks, failures, "p0k_reconciliation")
    readiness = object_value(p0k.get("readiness"))
    boundary = object_value(p0k.get("boundary"))
    task_id = str(p0k.get("task_id") or authorization.get("task_id") or "")

    check(checks, failures, "p0k_summary_passed", p0k.get("schema_version") == P0K_CHAIN_SCHEMA and p0k.get("passed") is True)
    check(checks, failures, "p0k_ready_for_p0l", readiness.get("p0l_external_preview_evidence_ready") is True)
    check(checks, failures, "p0k_production_transition_closed", readiness.get("production_transition_allowed") is False)
    check(checks, failures, "p0k_authorization_passed", authorization.get("schema_version") == P0K_AUTHORIZATION_SCHEMA and authorization.get("passed") is True)
    check(checks, failures, "p0k_soak_passed", soak.get("schema_version") == P0K_SOAK_RECEIPT_SCHEMA and soak.get("passed") is True)
    check(checks, failures, "p0k_rollback_passed", rollback.get("schema_version") == P0K_ROLLBACK_SCHEMA and rollback.get("passed") is True)
    check(checks, failures, "p0k_audit_passed", audit.get("schema_version") == P0K_MONITORING_AUDIT_SCHEMA and audit.get("passed") is True)
    check(checks, failures, "p0k_reconciliation_passed", reconciliation.get("schema_version") == P0K_RECONCILIATION_SCHEMA and reconciliation.get("passed") is True)
    check(checks, failures, "task_id_consistent", all(item.get("task_id") == task_id for item in (authorization, soak, rollback, audit, reconciliation)))
    check(checks, failures, "p0k_boundary_soak_observed", _p0k_soak_observed(boundary))
    check(checks, failures, "p0k_boundary_closed", _closed_no_production_boundary(boundary))
    check(checks, failures, "p0k_latency_summary_present", int(object_value(p0k.get("soak")).get("completed_cycles") or 0) >= 2)
    return {
        "schema_version": CONTEXT_SCHEMA,
        "passed": _passed(checks, failures),
        "failure_reasons": failures,
        "checks": checks,
        "task_id": task_id,
        "vm_target_ids": _unique_texts(p0k.get("vm_target_ids")),
        "owners": object_value(p0k.get("owners")),
        "p0k_artifacts": refs,
        "p0k_summary": p0k,
        "authorization": authorization,
        "soak": soak,
        "rollback": rollback,
        "audit": audit,
        "reconciliation": reconciliation,
    }


def write_owner_feedback_evidence(
    *,
    context: dict[str, Any],
    output: Path,
    operator_id: str,
    decision: str,
    ack_external_preview_evidence: bool,
    p0k_summary_path: Path,
) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    owners = object_value(context.get("owners"))
    check(checks, failures, "p0k_context_passed", context.get("passed") is True)
    check(checks, failures, "operator_id_present", bool(str(operator_id).strip()))
    check(checks, failures, "owner_present", bool(str(owners.get("owner_id") or "").strip()))
    check(checks, failures, "explicit_operator_ack", ack_external_preview_evidence is True)
    check(checks, failures, "owner_decision_accepted", decision == ACCEPTED_OWNER_DECISION)
    passed = _passed(checks, failures)
    report = {
        "schema_version": OWNER_FEEDBACK_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "recorded_at": _now(),
        "task_id": context.get("task_id"),
        "operator_id": operator_id,
        "owner_id": owners.get("owner_id"),
        "decision": decision,
        "feedback_summary": "P0-K private preview soak evidence accepted as external-preview byproduct only.",
        "source_artifacts": {"p0k_summary": artifact_ref(p0k_summary_path)},
        "boundary": _boundary(owner_feedback_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def write_audit_review_evidence(
    *,
    context: dict[str, Any],
    output: Path,
    operator_id: str,
    decision: str,
    ack_external_preview_evidence: bool,
    p0k_summary_path: Path,
) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    owners = object_value(context.get("owners"))
    boundary = object_value(context.get("p0k_summary")).get("boundary")
    check(checks, failures, "p0k_context_passed", context.get("passed") is True)
    check(checks, failures, "operator_id_present", bool(str(operator_id).strip()))
    check(checks, failures, "audit_owner_present", bool(str(owners.get("audit_owner_id") or "").strip()))
    check(checks, failures, "explicit_operator_ack", ack_external_preview_evidence is True)
    check(checks, failures, "audit_decision_accepted", decision == ACCEPTED_AUDIT_DECISION)
    check(checks, failures, "p0k_boundary_closed", _closed_no_production_boundary(object_value(boundary)))
    passed = _passed(checks, failures)
    report = {
        "schema_version": AUDIT_REVIEW_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "recorded_at": _now(),
        "task_id": context.get("task_id"),
        "operator_id": operator_id,
        "audit_owner_id": owners.get("audit_owner_id"),
        "decision": decision,
        "review_summary": "Audit boundary confirms P0-K is private-preview evidence only and does not authorize production transition.",
        "source_artifacts": {"p0k_summary": artifact_ref(p0k_summary_path)},
        "boundary": _boundary(audit_review_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def write_environment_proof_evidence(*, context: dict[str, Any], output: Path, p0k_summary_path: Path) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    soak = object_value(context.get("soak"))
    p0k = object_value(context.get("p0k_summary"))
    vm_targets = _unique_texts(context.get("vm_target_ids"))
    ports = _extract_ports(soak)
    latency = object_value(object_value(p0k.get("soak")).get("latency_summary"))
    completed_cycles = int(object_value(p0k.get("soak")).get("completed_cycles") or 0)
    check(checks, failures, "p0k_context_passed", context.get("passed") is True)
    check(checks, failures, "vm_targets_present", len(vm_targets) >= 2)
    check(checks, failures, "completed_cycles_present", completed_cycles >= 2)
    check(checks, failures, "latency_summary_present", int(latency.get("sample_count") or 0) > 0)
    check(checks, failures, "ports_observed", bool(ports.get("backend_ports")) and bool(ports.get("frontend_ports")))
    passed = _passed(checks, failures)
    report = {
        "schema_version": ENVIRONMENT_PROOF_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "recorded_at": _now(),
        "task_id": context.get("task_id"),
        "environment_scope": "virtualbox_private_network_preview",
        "vm_target_ids": vm_targets,
        "completed_cycles": completed_cycles,
        "latency_summary": latency,
        "backend_ports": ports.get("backend_ports", []),
        "frontend_ports": ports.get("frontend_ports", []),
        "source_artifacts": {"p0k_summary": artifact_ref(p0k_summary_path)},
        "boundary": _boundary(environment_proof_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def write_rollback_proof_evidence(
    *,
    context: dict[str, Any],
    output: Path,
    operator_id: str,
    decision: str,
    ack_external_preview_evidence: bool,
    p0k_summary_path: Path,
) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    rollback = object_value(context.get("rollback"))
    owners = object_value(context.get("owners"))
    check(checks, failures, "p0k_context_passed", context.get("passed") is True)
    check(checks, failures, "operator_id_present", bool(str(operator_id).strip()))
    check(checks, failures, "rollback_owner_present", bool(str(owners.get("rollback_owner_id") or "").strip()))
    check(checks, failures, "explicit_operator_ack", ack_external_preview_evidence is True)
    check(checks, failures, "rollback_decision_accepted", decision == ACCEPTED_ROLLBACK_DECISION)
    check(checks, failures, "rollback_performed", rollback.get("rollback_performed") is True)
    check(checks, failures, "rollback_health_check_performed", rollback.get("rollback_health_check_performed") is True)
    check(checks, failures, "rollback_boundary_closed", _closed_no_production_boundary(object_value(rollback.get("boundary"))))
    passed = _passed(checks, failures)
    report = {
        "schema_version": ROLLBACK_PROOF_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "recorded_at": _now(),
        "task_id": context.get("task_id"),
        "operator_id": operator_id,
        "rollback_owner_id": owners.get("rollback_owner_id"),
        "decision": decision,
        "rollback_performed": rollback.get("rollback_performed") is True,
        "rollback_health_check_performed": rollback.get("rollback_health_check_performed") is True,
        "source_artifacts": {"p0k_summary": artifact_ref(p0k_summary_path)},
        "boundary": _boundary(rollback_proof_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def write_no_production_boundary_evidence(*, context: dict[str, Any], output: Path, p0k_summary_path: Path) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    boundaries = {
        "p0k_summary": object_value(object_value(context.get("p0k_summary")).get("boundary")),
        "soak": object_value(object_value(context.get("soak")).get("boundary")),
        "rollback": object_value(object_value(context.get("rollback")).get("boundary")),
        "audit": object_value(object_value(context.get("audit")).get("boundary")),
        "reconciliation": object_value(object_value(context.get("reconciliation")).get("boundary")),
    }
    check(checks, failures, "p0k_context_passed", context.get("passed") is True)
    for name, boundary in boundaries.items():
        check(checks, failures, f"{name}_boundary_closed", _closed_no_production_boundary(boundary))
    passed = _passed(checks, failures)
    report = {
        "schema_version": NO_PRODUCTION_BOUNDARY_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "recorded_at": _now(),
        "task_id": context.get("task_id"),
        "boundaries": boundaries,
        "source_artifacts": {"p0k_summary": artifact_ref(p0k_summary_path)},
        "boundary": _boundary(no_production_boundary_evidence_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def _extract_ports(soak: dict[str, Any]) -> dict[str, list[int]]:
    backend_ports: list[int] = []
    frontend_ports: list[int] = []
    for cycle in soak.get("cycle_reports", []):
        summary = object_value(object_value(cycle).get("smoke_summary"))
        backend = _int_or_none(summary.get("backend_port"))
        frontend = _int_or_none(summary.get("frontend_port"))
        if backend is not None and backend not in backend_ports:
            backend_ports.append(backend)
        if frontend is not None and frontend not in frontend_ports:
            frontend_ports.append(frontend)
    return {"backend_ports": backend_ports, "frontend_ports": frontend_ports}


def _int_or_none(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _p0k_soak_observed(boundary: dict[str, Any]) -> bool:
    return (
        boundary.get("vm_contact_performed") is True
        and boundary.get("private_preview_soak_deploy_performed") is True
        and boundary.get("multi_cycle_smoke_performed") is True
        and boundary.get("rollback_performed") is True
        and boundary.get("rollback_health_check_performed") is True
    )


def _boundary(**overrides: bool) -> dict[str, bool]:
    base = {
        "owner_feedback_written": False,
        "audit_review_written": False,
        "environment_proof_written": False,
        "rollback_proof_written": False,
        "no_production_boundary_evidence_written": False,
        "vm_contact_performed": False,
        "preview_command_executed": False,
        "source_tree_write_performed": False,
        "git_write_performed": False,
        "external_public_ingress_opened": False,
        "production_transition_allowed": False,
        "production_receipt_write_allowed": False,
        "production_data_accessed": False,
        "secrets_recorded": False,
    }
    base.update(overrides)
    return base


def _failures(reports: list[dict[str, Any]]) -> list[str]:
    values: list[str] = []
    for report in reports:
        values.extend(str(item) for item in report.get("failure_reasons", []))
    return sorted(set(values))


def _passed(checks: dict[str, bool], failures: list[str]) -> bool:
    return bool(checks) and all(checks.values()) and not failures


def _report(schema: str, passed: bool, failures: list[str], checks: dict[str, bool]) -> dict[str, Any]:
    return {"schema_version": schema, "passed": passed, "failure_reasons": failures, "checks": checks}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def main() -> int:
    parser = argparse.ArgumentParser(description="Run P0-L external preview evidence gate")
    parser.add_argument("--p0k-summary", required=True)
    parser.add_argument("--output-root", required=True)
    parser.add_argument("--operator-id", default="operator-cc")
    parser.add_argument("--owner-feedback-decision", default=ACCEPTED_OWNER_DECISION)
    parser.add_argument("--audit-review-decision", default=ACCEPTED_AUDIT_DECISION)
    parser.add_argument("--rollback-owner-decision", default=ACCEPTED_ROLLBACK_DECISION)
    parser.add_argument("--ack-external-preview-evidence", action="store_true")
    args = parser.parse_args()
    summary = run_gate(
        p0k_summary_path=Path(args.p0k_summary),
        output_root=Path(args.output_root),
        operator_id=args.operator_id,
        owner_feedback_decision=args.owner_feedback_decision,
        audit_review_decision=args.audit_review_decision,
        rollback_owner_decision=args.rollback_owner_decision,
        ack_external_preview_evidence=bool(args.ack_external_preview_evidence),
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if summary.get("passed") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
