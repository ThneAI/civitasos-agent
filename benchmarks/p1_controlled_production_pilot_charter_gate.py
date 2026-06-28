"""Run P1 controlled production pilot charter gate.

P1 charter consumes a passed P0-O authorization summary and writes a production
pilot charter plus evidence collection plan. It prepares a real production-origin
evidence path, but does not start runtime, contact VMs, open public ingress, or
write production receipts.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from benchmarks.i_gate_evidence import (
    artifact_ref,
    check,
    object_value,
    read_json_object,
    write_json_object,
)
from benchmarks.p0o_first_controlled_beta_task_authorization_gate import CHAIN_SCHEMA as P0O_CHAIN_SCHEMA

CHAIN_SCHEMA = "p1-controlled-production-pilot-charter-chain:v1"
CONTEXT_SCHEMA = "p1-p0o-context-validation:v1"
CHARTER_SCHEMA = "p1-controlled-production-pilot-charter:v1"
EVIDENCE_PLAN_SCHEMA = "p1-h3-production-evidence-collection-plan:v1"
OPERATOR_ACCEPTANCE_SCHEMA = "p1-controlled-production-pilot-operator-acceptance:v1"
ACCEPTED_OPERATOR_DECISION = "approve_p1_charter_for_evidence_collection"

PILOT_ID = "p1-production-pilot:civitasos-status-evidence-index"
NON_CLAIMS = (
    "p1_charter_prepares_production_origin_evidence_collection_only",
    "p1_charter_requires_passed_p0o_authorization",
    "p1_charter_does_not_start_runtime_or_contact_vms",
    "p1_charter_does_not_open_public_ingress",
    "p1_charter_does_not_touch_production_data",
    "p1_charter_does_not_write_production_receipts",
    "p1_charter_does_not_authorize_h3_production_transition",
)


def run_gate(
    *,
    p0o_summary_path: Path,
    output_root: Path,
    operator_id: str = "operator-cc",
    operator_decision: str = ACCEPTED_OPERATOR_DECISION,
    owner_id: str = "product_owner",
    audit_owner_id: str = "audit_owner",
    monitoring_owner_id: str = "observability_owner",
    rollback_owner_id: str = "rollback_owner",
    primary_vm_target: str = "vm1",
    standby_vm_targets: list[str] | None = None,
    ack_p1_charter: bool = False,
) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "charter": output_root / "p1_controlled_production_pilot_charter.json",
        "evidence_collection_plan": output_root / "p1_h3_production_evidence_collection_plan.json",
        "operator_acceptance": output_root / "p1_operator_acceptance.json",
        "summary": output_root / "p1_controlled_production_pilot_charter_summary.json",
    }
    context = validate_p0o_context(p0o_summary_path)
    owners = {
        "owner_id": owner_id,
        "audit_owner_id": audit_owner_id,
        "monitoring_owner_id": monitoring_owner_id,
        "rollback_owner_id": rollback_owner_id,
    }
    standby_targets = standby_vm_targets or ["vm2", "vm3"]
    charter = write_charter(
        context=context,
        output=artifacts["charter"],
        p0o_summary_path=p0o_summary_path,
        owners=owners,
        primary_vm_target=primary_vm_target,
        standby_vm_targets=standby_targets,
    )
    evidence_plan = write_evidence_collection_plan(
        charter_path=artifacts["charter"],
        output=artifacts["evidence_collection_plan"],
    )
    acceptance = write_operator_acceptance(
        charter_path=artifacts["charter"],
        evidence_plan_path=artifacts["evidence_collection_plan"],
        output=artifacts["operator_acceptance"],
        operator_id=operator_id,
        operator_decision=operator_decision,
        ack_p1_charter=ack_p1_charter,
    )
    reports = [context, charter, evidence_plan, acceptance]
    passed = all(report.get("passed") is True for report in reports)
    summary = {
        "schema_version": CHAIN_SCHEMA,
        "passed": passed,
        "failure_reasons": _failures(reports),
        "checked_at": _now(),
        "pilot_id": PILOT_ID,
        "operator_id": operator_id,
        "owners": owners,
        "vm_targets": {"primary": primary_vm_target, "standby": standby_targets},
        "source_artifacts": {"p0o_summary": artifact_ref(p0o_summary_path)},
        "artifacts": {name: artifact_ref(path) for name, path in artifacts.items() if name != "summary"},
        "readiness": {
            "state": "p1_controlled_production_pilot_charter_ready" if passed else "blocked_p1_charter",
            "p1_charter_ready": passed,
            "h3_production_evidence_collection_ready": passed,
            "runtime_execution_allowed": False,
            "production_transition_allowed": False,
        },
        "boundary": _boundary(
            charter_written=charter.get("passed") is True,
            evidence_collection_plan_written=evidence_plan.get("passed") is True,
            operator_acceptance_written=acceptance.get("passed") is True,
        ),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(artifacts["summary"], summary)
    return summary


def validate_p0o_context(path: Path) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    try:
        summary = read_json_object(path)
    except Exception as exc:  # noqa: BLE001
        return _report(CONTEXT_SCHEMA, False, [f"p0o_summary_unreadable:{exc}"], checks)
    readiness = object_value(summary.get("readiness"))
    authorization = object_value(summary.get("authorization"))
    check(
        checks,
        failures,
        "p0o_summary_passed",
        summary.get("schema_version") == P0O_CHAIN_SCHEMA and summary.get("passed") is True,
    )
    check(checks, failures, "p0o_authorized", readiness.get("p0o_first_controlled_beta_task_authorized") is True)
    check(checks, failures, "p0p_ready", readiness.get("p0p_first_controlled_beta_task_execution_ready") is True)
    check(checks, failures, "p0o_production_transition_closed", readiness.get("production_transition_allowed") is False)
    check(checks, failures, "p0o_boundary_closed", _no_production_violation(object_value(summary.get("boundary"))))
    check(checks, failures, "authorization_single_use", authorization.get("single_use") is True)
    check(checks, failures, "authorization_not_consumed", authorization.get("consumed") is False)
    passed = _passed(checks, failures)
    return {
        "schema_version": CONTEXT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "p0o_summary": summary,
        "source_artifacts": {"p0o_summary": artifact_ref(path)},
        "boundary": _boundary(context_validation_written=passed),
        "non_claims": list(NON_CLAIMS),
    }


def write_charter(
    *,
    context: dict[str, Any],
    output: Path,
    p0o_summary_path: Path,
    owners: dict[str, str],
    primary_vm_target: str,
    standby_vm_targets: list[str],
) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "owner_roles_present", all(bool(value) for value in owners.values()))
    check(checks, failures, "primary_vm_target_present", bool(primary_vm_target))
    check(checks, failures, "standby_vm_targets_present", bool(standby_vm_targets))
    passed = _passed(checks, failures)
    charter = {
        "pilot_id": PILOT_ID,
        "title": "CivitasOS controlled production pilot status/evidence index service",
        "risk_class": "low",
        "production_pilot_kind": "internal_controlled_production_pilot_candidate",
        "purpose": "Provide owner/audit operators a real status and evidence index entrypoint.",
        "non_objectives": [
            "no public ingress",
            "no production user data",
            "no financial or chain mutation",
            "no unscoped external deploy",
            "no H.3 production transition without A/B/C evidence bundle",
        ],
        "owners": owners,
        "vm_targets": {"primary": primary_vm_target, "standby": standby_vm_targets},
        "required_before_execution": [
            "Round 2 production-origin evidence collection starts from this charter",
            "explicit runtime start authorization gate",
            "monitoring green and audit sink ready",
            "rollback checkpoint and kill switch armed",
            "dual operator acknowledgement",
        ],
        "allowed_scope": [
            "private/internal read-only status evidence index",
            "service-token scoped task-pool interaction",
            "owner/audit/rollback evidence collection",
        ],
        "forbidden_scope": [
            "public_ingress",
            "production_data_access",
            "production_transition",
            "production_receipt_write_without_h3_bundle",
        ],
    }
    report = {
        "schema_version": CHARTER_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "recorded_at": _now(),
        "controlled_production_pilot_charter": charter,
        "source_artifacts": {"p0o_summary": artifact_ref(p0o_summary_path)},
        "boundary": _boundary(charter_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def write_evidence_collection_plan(*, charter_path: Path, output: Path) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    charter = read_json_object(charter_path)
    check(
        checks,
        failures,
        "charter_passed",
        charter.get("schema_version") == CHARTER_SCHEMA and charter.get("passed") is True,
    )
    steps = [
        "collect 16 Round 2 production-origin records from real owner/operator/audit systems",
        "assemble production_evidence_submission.json only after all source refs are real",
        "write L2 external anchor for the exact Round 2 submission",
        "obtain independent anchor verification with provider inclusion refs",
        "run bundle validation and H.3 stage preflight before any runtime start",
    ]
    check(checks, failures, "collection_steps_present", len(steps) == 5)
    passed = _passed(checks, failures)
    report = {
        "schema_version": EVIDENCE_PLAN_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "recorded_at": _now(),
        "production_evidence_collection_steps": steps,
        "round2_required_evidence_count": 16,
        "source_artifacts": {"charter": artifact_ref(charter_path)},
        "boundary": _boundary(evidence_collection_plan_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def write_operator_acceptance(
    *,
    charter_path: Path,
    evidence_plan_path: Path,
    output: Path,
    operator_id: str,
    operator_decision: str,
    ack_p1_charter: bool,
) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    charter = read_json_object(charter_path)
    plan = read_json_object(evidence_plan_path)
    check(checks, failures, "charter_passed", charter.get("passed") is True)
    check(checks, failures, "evidence_plan_passed", plan.get("passed") is True)
    check(checks, failures, "operator_id_present", bool(str(operator_id).strip()))
    check(checks, failures, "explicit_operator_ack", ack_p1_charter is True)
    check(checks, failures, "operator_decision_accepted", operator_decision == ACCEPTED_OPERATOR_DECISION)
    passed = _passed(checks, failures)
    report = {
        "schema_version": OPERATOR_ACCEPTANCE_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "decided_at": _now(),
        "operator_id": operator_id,
        "decision": operator_decision if passed else "blocked_p1_charter",
        "source_artifacts": {
            "charter": artifact_ref(charter_path),
            "evidence_collection_plan": artifact_ref(evidence_plan_path),
        },
        "boundary": _boundary(operator_acceptance_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def _no_production_violation(boundary: dict[str, Any]) -> bool:
    forbidden_true_keys = (
        "vm_contact_performed",
        "task_pool_post_performed",
        "task_pool_execute_performed",
        "preview_command_executed",
        "external_public_ingress_opened",
        "production_transition_allowed",
        "production_receipt_write_allowed",
        "production_data_accessed",
        "secrets_recorded",
        "source_tree_write_performed",
        "git_write_performed",
    )
    return all(boundary.get(key) is not True for key in forbidden_true_keys)


def _boundary(**overrides: bool) -> dict[str, bool]:
    base = {
        "context_validation_written": False,
        "charter_written": False,
        "evidence_collection_plan_written": False,
        "operator_acceptance_written": False,
        "runtime_execution_allowed": False,
        "vm_contact_performed": False,
        "preview_command_executed": False,
        "external_public_ingress_opened": False,
        "production_data_accessed": False,
        "production_transition_allowed": False,
        "production_receipt_write_allowed": False,
        "secrets_recorded": False,
        "source_tree_write_performed": False,
        "git_write_performed": False,
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
        "boundary": _boundary(),
        "non_claims": list(NON_CLAIMS),
    }


def _failures(reports: list[dict[str, Any]]) -> list[str]:
    values: list[str] = []
    for report in reports:
        values.extend(str(item) for item in report.get("failure_reasons", []))
    return values


def _passed(checks: dict[str, bool], failures: list[str]) -> bool:
    return bool(checks) and all(checks.values()) and not failures


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def main() -> int:
    parser = argparse.ArgumentParser(description="Run P1 controlled production pilot charter gate")
    parser.add_argument("--p0o-summary", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--operator-id", default="operator-cc")
    parser.add_argument("--operator-decision", default=ACCEPTED_OPERATOR_DECISION)
    parser.add_argument("--owner-id", default="product_owner")
    parser.add_argument("--audit-owner-id", default="audit_owner")
    parser.add_argument("--monitoring-owner-id", default="observability_owner")
    parser.add_argument("--rollback-owner-id", default="rollback_owner")
    parser.add_argument("--primary-vm-target", default="vm1")
    parser.add_argument("--standby-vm-target", action="append", dest="standby_vm_targets")
    parser.add_argument("--ack-p1-charter", action="store_true")
    args = parser.parse_args()
    summary = run_gate(
        p0o_summary_path=args.p0o_summary,
        output_root=args.output_root,
        operator_id=args.operator_id,
        operator_decision=args.operator_decision,
        owner_id=args.owner_id,
        audit_owner_id=args.audit_owner_id,
        monitoring_owner_id=args.monitoring_owner_id,
        rollback_owner_id=args.rollback_owner_id,
        primary_vm_target=args.primary_vm_target,
        standby_vm_targets=args.standby_vm_targets,
        ack_p1_charter=args.ack_p1_charter,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if summary.get("passed") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
