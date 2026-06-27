"""Run P0-H private preview owner review gate.

P0-H consumes a passed P0-G single-VM private preview summary and performs a
read-only owner/audit/rollback review. It does not contact VMs, deploy, mutate
source/Git, open public ingress, transition to production, or write production
receipts.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from benchmarks.i_gate_evidence import artifact_ref, check, object_value, read_json_object, sha256_file, write_json_object
from benchmarks.p0g_single_vm_private_preview_gate import (
    AUTHORIZATION_SCHEMA as P0G_AUTHORIZATION_SCHEMA,
    CHAIN_SCHEMA as P0G_CHAIN_SCHEMA,
    MONITORING_AUDIT_SCHEMA as P0G_MONITORING_AUDIT_SCHEMA,
    PREVIEW_RECEIPT_SCHEMA as P0G_PREVIEW_RECEIPT_SCHEMA,
    RECONCILIATION_SCHEMA as P0G_RECONCILIATION_SCHEMA,
    ROLLBACK_RECEIPT_SCHEMA as P0G_ROLLBACK_RECEIPT_SCHEMA,
)

CHAIN_SCHEMA = "p0h-private-preview-owner-review-chain:v1"
CONTEXT_SCHEMA = "p0h-p0g-context-validation:v1"
OWNER_ACCEPTANCE_SCHEMA = "p0h-private-preview-owner-acceptance:v1"
AUDIT_BOUNDARY_SCHEMA = "p0h-private-preview-audit-boundary-review:v1"
ROLLBACK_OWNER_SCHEMA = "p0h-private-preview-rollback-owner-review:v1"
RECONCILIATION_SCHEMA = "p0h-private-preview-owner-reconciliation:v1"

APPROVE_PRIVATE_PREVIEW = "approve_private_preview_evidence"
APPROVE_NO_PRODUCTION = "approve_no_production_boundary"
APPROVE_ROLLBACK = "approve_rollback_receipt"


def run_gate(
    *,
    p0g_summary_path: Path,
    output_root: Path,
    operator_id: str = "operator-cc",
    owner_decision: str = APPROVE_PRIVATE_PREVIEW,
    audit_decision: str = APPROVE_NO_PRODUCTION,
    rollback_owner_decision: str = APPROVE_ROLLBACK,
) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "owner_acceptance": output_root / "p0h_private_preview_owner_acceptance.json",
        "audit_boundary_review": output_root / "p0h_private_preview_audit_boundary_review.json",
        "rollback_owner_review": output_root / "p0h_private_preview_rollback_owner_review.json",
        "reconciliation": output_root / "p0h_private_preview_owner_reconciliation.json",
        "summary": output_root / "p0h_private_preview_owner_review_chain_summary.json",
    }
    context = validate_p0g_context(p0g_summary_path)
    owner = write_owner_acceptance(
        context=context,
        p0g_summary_path=p0g_summary_path,
        output=artifacts["owner_acceptance"],
        operator_id=operator_id,
        owner_decision=owner_decision,
    )
    audit = write_audit_boundary_review(
        context=context,
        owner_acceptance_path=artifacts["owner_acceptance"],
        output=artifacts["audit_boundary_review"],
        audit_decision=audit_decision,
    )
    rollback = write_rollback_owner_review(
        context=context,
        audit_boundary_review_path=artifacts["audit_boundary_review"],
        output=artifacts["rollback_owner_review"],
        rollback_owner_decision=rollback_owner_decision,
    )
    reconciliation = write_reconciliation(
        context=context,
        owner_acceptance_path=artifacts["owner_acceptance"],
        audit_boundary_review_path=artifacts["audit_boundary_review"],
        rollback_owner_review_path=artifacts["rollback_owner_review"],
        output=artifacts["reconciliation"],
    )
    reports = [context, owner, audit, rollback, reconciliation]
    passed = all(report.get("passed") is True for report in reports)
    summary = {
        "schema_version": CHAIN_SCHEMA,
        "passed": passed,
        "failure_reasons": _failures(reports),
        "checked_at": _now(),
        "task_id": context.get("task_id"),
        "vm_target_id": context.get("vm_target_id"),
        "operator_id": operator_id,
        "owners": context.get("owners", {}),
        "source_artifacts": {"p0g_summary": artifact_ref(p0g_summary_path)},
        "artifacts": {name: artifact_ref(path) for name, path in artifacts.items() if name != "summary"},
        "readiness": {
            "state": "p0h_private_preview_owner_review_passed" if passed else "blocked_p0h_private_preview_owner_review",
            "p0h_private_preview_owner_review_complete": passed,
            "p0i_vm_service_private_preview_ready": passed,
            "production_transition_allowed": False,
        },
        "boundary": _boundary(
            owner_acceptance_written=owner.get("passed") is True,
            audit_boundary_review_written=audit.get("passed") is True,
            rollback_owner_review_written=rollback.get("passed") is True,
            owner_reconciliation_written=reconciliation.get("passed") is True,
        ),
        "non_claims": _non_claims(),
    }
    write_json_object(artifacts["summary"], summary)
    return summary


def validate_p0g_context(p0g_summary_path: Path) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    try:
        p0g = read_json_object(p0g_summary_path)
    except Exception as exc:  # noqa: BLE001
        return _report(CONTEXT_SCHEMA, False, [f"p0g_summary_unreadable:{exc}"], checks)

    refs = object_value(p0g.get("artifacts"))
    authorization = _read_verified_ref(refs.get("authorization"), checks, failures, "p0g_authorization")
    preview = _read_verified_ref(refs.get("preview_receipt"), checks, failures, "p0g_preview_receipt")
    rollback = _read_verified_ref(refs.get("rollback_receipt"), checks, failures, "p0g_rollback_receipt")
    audit = _read_verified_ref(refs.get("monitoring_audit_receipt"), checks, failures, "p0g_monitoring_audit_receipt")
    reconciliation = _read_verified_ref(refs.get("reconciliation"), checks, failures, "p0g_reconciliation")

    readiness = object_value(p0g.get("readiness"))
    summary_boundary = object_value(p0g.get("boundary"))
    owners = object_value(authorization.get("owners"))
    task_id = str(p0g.get("task_id") or authorization.get("task_id") or "")
    vm_target_id = str(p0g.get("vm_target_id") or authorization.get("vm_target_id") or "")

    check(checks, failures, "p0g_summary_passed", p0g.get("schema_version") == P0G_CHAIN_SCHEMA and p0g.get("passed") is True)
    check(checks, failures, "p0g_ready_for_p0h", readiness.get("p0h_private_preview_owner_review_ready") is True)
    check(checks, failures, "p0g_production_transition_closed", readiness.get("production_transition_allowed") is False)
    check(checks, failures, "p0g_authorization_passed", authorization.get("schema_version") == P0G_AUTHORIZATION_SCHEMA and authorization.get("passed") is True)
    check(checks, failures, "p0g_preview_passed", preview.get("schema_version") == P0G_PREVIEW_RECEIPT_SCHEMA and preview.get("passed") is True)
    check(checks, failures, "p0g_rollback_passed", rollback.get("schema_version") == P0G_ROLLBACK_RECEIPT_SCHEMA and rollback.get("passed") is True)
    check(checks, failures, "p0g_audit_passed", audit.get("schema_version") == P0G_MONITORING_AUDIT_SCHEMA and audit.get("passed") is True)
    check(checks, failures, "p0g_reconciliation_passed", reconciliation.get("schema_version") == P0G_RECONCILIATION_SCHEMA and reconciliation.get("passed") is True)
    check(checks, failures, "task_id_consistent", all(item.get("task_id") == task_id for item in (authorization, preview, rollback, audit, reconciliation)))
    check(checks, failures, "vm_target_consistent", all(item.get("vm_target_id") == vm_target_id for item in (authorization, preview, rollback, audit, reconciliation)))
    check(checks, failures, "owners_present", all(bool(owners.get(key)) for key in ("owner_id", "audit_owner_id", "rollback_owner_id", "monitoring_owner_id")))
    check(checks, failures, "summary_boundary_private_preview_observed", _private_preview_observed(summary_boundary))
    check(checks, failures, "summary_boundary_closed", _closed_no_production_boundary(summary_boundary))
    check(checks, failures, "preview_boundary_closed", _closed_no_production_boundary(object_value(preview.get("boundary"))))
    check(checks, failures, "rollback_boundary_closed", _closed_no_production_boundary(object_value(rollback.get("boundary"))))
    check(checks, failures, "audit_boundary_closed", _closed_no_production_boundary(object_value(audit.get("boundary"))))
    check(checks, failures, "reconciliation_boundary_closed", _closed_no_production_boundary(object_value(reconciliation.get("boundary"))))

    return {
        "schema_version": CONTEXT_SCHEMA,
        "passed": _passed(checks, failures),
        "failure_reasons": failures,
        "checks": checks,
        "task_id": task_id,
        "vm_target_id": vm_target_id,
        "owners": owners,
        "p0g_summary": p0g,
        "authorization": authorization,
        "preview_receipt": preview,
        "rollback_receipt": rollback,
        "monitoring_audit_receipt": audit,
        "reconciliation": reconciliation,
        "source_artifacts": {"p0g_summary": artifact_ref(p0g_summary_path)},
    }


def write_owner_acceptance(
    *,
    context: dict[str, Any],
    p0g_summary_path: Path,
    output: Path,
    operator_id: str,
    owner_decision: str,
) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    owners = object_value(context.get("owners"))
    check(checks, failures, "p0g_context_passed", context.get("passed") is True)
    check(checks, failures, "operator_id_present", bool(str(operator_id).strip()))
    check(checks, failures, "owner_id_present", bool(owners.get("owner_id")))
    check(checks, failures, "owner_decision_approves_private_preview", owner_decision == APPROVE_PRIVATE_PREVIEW)
    check(checks, failures, "private_preview_observed", _private_preview_observed(object_value(object_value(context.get("p0g_summary")).get("boundary"))))
    passed = _passed(checks, failures)
    report = {
        "schema_version": OWNER_ACCEPTANCE_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "decided_at": _now(),
        "task_id": context.get("task_id"),
        "vm_target_id": context.get("vm_target_id"),
        "operator_id": operator_id,
        "owner_id": owners.get("owner_id"),
        "owner_decision": owner_decision,
        "decision": "owner_accepts_p0g_private_preview" if passed else "blocked_owner_acceptance",
        "source_artifacts": {"p0g_summary": artifact_ref(p0g_summary_path)},
        "boundary": _boundary(owner_acceptance_written=passed),
        "non_claims": _non_claims(),
    }
    write_json_object(output, report)
    return report


def write_audit_boundary_review(
    *,
    context: dict[str, Any],
    owner_acceptance_path: Path,
    output: Path,
    audit_decision: str,
) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    owner_acceptance = read_json_object(owner_acceptance_path)
    owners = object_value(context.get("owners"))
    p0g_boundary = object_value(object_value(context.get("p0g_summary")).get("boundary"))
    check(checks, failures, "owner_acceptance_passed", owner_acceptance.get("passed") is True)
    check(checks, failures, "audit_owner_id_present", bool(owners.get("audit_owner_id")))
    check(checks, failures, "audit_decision_approves_no_production", audit_decision == APPROVE_NO_PRODUCTION)
    check(checks, failures, "p0g_boundary_closed", _closed_no_production_boundary(p0g_boundary))
    check(checks, failures, "public_ingress_closed", p0g_boundary.get("external_public_ingress_opened") is False)
    check(checks, failures, "production_receipt_closed", p0g_boundary.get("production_receipt_write_allowed") is False)
    passed = _passed(checks, failures)
    report = {
        "schema_version": AUDIT_BOUNDARY_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "task_id": context.get("task_id"),
        "vm_target_id": context.get("vm_target_id"),
        "audit_owner_id": owners.get("audit_owner_id"),
        "audit_decision": audit_decision,
        "source_artifacts": {
            "owner_acceptance": artifact_ref(owner_acceptance_path),
            "p0g_summary": object_value(context.get("source_artifacts")).get("p0g_summary"),
        },
        "boundary": _boundary(audit_boundary_review_written=passed),
        "non_claims": _non_claims(),
    }
    write_json_object(output, report)
    return report


def write_rollback_owner_review(
    *,
    context: dict[str, Any],
    audit_boundary_review_path: Path,
    output: Path,
    rollback_owner_decision: str,
) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    audit_review = read_json_object(audit_boundary_review_path)
    owners = object_value(context.get("owners"))
    rollback = object_value(context.get("rollback_receipt"))
    rollback_boundary = object_value(rollback.get("boundary"))
    check(checks, failures, "audit_boundary_review_passed", audit_review.get("passed") is True)
    check(checks, failures, "rollback_owner_id_present", bool(owners.get("rollback_owner_id")))
    check(checks, failures, "rollback_owner_decision_approves_receipt", rollback_owner_decision == APPROVE_ROLLBACK)
    check(checks, failures, "rollback_receipt_passed", rollback.get("passed") is True)
    check(checks, failures, "rollback_performed", rollback.get("rollback_performed") is True)
    check(checks, failures, "rollback_health_check_performed", rollback.get("rollback_health_check_performed") is True)
    check(checks, failures, "rollback_boundary_closed", _closed_no_production_boundary(rollback_boundary))
    passed = _passed(checks, failures)
    report = {
        "schema_version": ROLLBACK_OWNER_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "task_id": context.get("task_id"),
        "vm_target_id": context.get("vm_target_id"),
        "rollback_owner_id": owners.get("rollback_owner_id"),
        "rollback_owner_decision": rollback_owner_decision,
        "source_artifacts": {
            "audit_boundary_review": artifact_ref(audit_boundary_review_path),
            "p0g_rollback_receipt": object_value(object_value(context.get("p0g_summary")).get("artifacts")).get("rollback_receipt"),
        },
        "boundary": _boundary(rollback_owner_review_written=passed),
        "non_claims": _non_claims(),
    }
    write_json_object(output, report)
    return report


def write_reconciliation(
    *,
    context: dict[str, Any],
    owner_acceptance_path: Path,
    audit_boundary_review_path: Path,
    rollback_owner_review_path: Path,
    output: Path,
) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    owner = read_json_object(owner_acceptance_path)
    audit = read_json_object(audit_boundary_review_path)
    rollback = read_json_object(rollback_owner_review_path)
    check(checks, failures, "p0g_context_passed", context.get("passed") is True)
    check(checks, failures, "owner_acceptance_passed", owner.get("passed") is True)
    check(checks, failures, "audit_boundary_review_passed", audit.get("passed") is True)
    check(checks, failures, "rollback_owner_review_passed", rollback.get("passed") is True)
    check(checks, failures, "task_id_consistent", owner.get("task_id") == audit.get("task_id") == rollback.get("task_id") == context.get("task_id"))
    check(checks, failures, "vm_target_consistent", owner.get("vm_target_id") == audit.get("vm_target_id") == rollback.get("vm_target_id") == context.get("vm_target_id"))
    passed = _passed(checks, failures)
    report = {
        "schema_version": RECONCILIATION_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "decided_at": _now(),
        "task_id": context.get("task_id"),
        "vm_target_id": context.get("vm_target_id"),
        "decision": "p0h_private_preview_owner_review_passed" if passed else "blocked_p0h_private_preview_owner_review",
        "source_artifacts": {
            "owner_acceptance": artifact_ref(owner_acceptance_path),
            "audit_boundary_review": artifact_ref(audit_boundary_review_path),
            "rollback_owner_review": artifact_ref(rollback_owner_review_path),
        },
        "boundary": _boundary(owner_reconciliation_written=passed),
        "non_claims": _non_claims(),
    }
    write_json_object(output, report)
    return report


def _read_verified_ref(value: Any, checks: dict[str, bool], failures: list[str], label: str) -> dict[str, Any]:
    ref = object_value(value)
    path = Path(str(ref.get("path") or ""))
    expected_hash = str(ref.get("sha256") or "")
    check(checks, failures, f"{label}_path_present", path.is_file())
    if not path.is_file():
        return {}
    check(checks, failures, f"{label}_hash_valid", bool(expected_hash) and sha256_file(path) == expected_hash)
    return read_json_object(path)


def _private_preview_observed(boundary: dict[str, Any]) -> bool:
    return (
        boundary.get("vm_contact_performed") is True
        and boundary.get("private_preview_deploy_performed") is True
        and boundary.get("private_preview_health_check_performed") is True
        and boundary.get("rollback_performed") is True
        and boundary.get("rollback_health_check_performed") is True
    )


def _closed_no_production_boundary(boundary: dict[str, Any]) -> bool:
    return (
        boundary.get("external_public_ingress_opened") is False
        and boundary.get("production_transition_allowed") is False
        and boundary.get("production_receipt_write_allowed") is False
        and boundary.get("source_tree_write_performed") is False
        and boundary.get("git_write_performed") is False
        and boundary.get("production_data_accessed") is False
        and boundary.get("secrets_recorded") is False
    )


def _boundary(**overrides: bool) -> dict[str, bool]:
    base = {
        "owner_acceptance_written": False,
        "audit_boundary_review_written": False,
        "rollback_owner_review_written": False,
        "owner_reconciliation_written": False,
        "vm_contact_performed": False,
        "private_preview_deploy_performed": False,
        "external_public_ingress_opened": False,
        "source_tree_write_performed": False,
        "git_write_performed": False,
        "production_data_accessed": False,
        "production_transition_allowed": False,
        "production_receipt_write_allowed": False,
        "secrets_recorded": False,
    }
    base.update(overrides)
    return base


def _non_claims() -> list[str]:
    return [
        "p0h_is_private_preview_owner_review_only",
        "p0h_requires_passed_p0g_private_preview",
        "p0h_does_not_contact_vms",
        "p0h_does_not_deploy",
        "p0h_does_not_open_public_ingress",
        "p0h_does_not_touch_production_data",
        "p0h_does_not_modify_source_or_git",
        "p0h_does_not_write_production_receipts",
        "p0h_does_not_authorize_production_transition",
    ]


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
    parser = argparse.ArgumentParser(description="Run P0-H private preview owner review gate")
    parser.add_argument("--p0g-summary", required=True)
    parser.add_argument("--output-root", required=True)
    parser.add_argument("--operator-id", default="operator-cc")
    parser.add_argument("--owner-decision", default=APPROVE_PRIVATE_PREVIEW)
    parser.add_argument("--audit-decision", default=APPROVE_NO_PRODUCTION)
    parser.add_argument("--rollback-owner-decision", default=APPROVE_ROLLBACK)
    args = parser.parse_args()
    summary = run_gate(
        p0g_summary_path=Path(args.p0g_summary),
        output_root=Path(args.output_root),
        operator_id=args.operator_id,
        owner_decision=args.owner_decision,
        audit_decision=args.audit_decision,
        rollback_owner_decision=args.rollback_owner_decision,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if summary.get("passed") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
