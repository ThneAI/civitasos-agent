"""Run P0-E rollback / abort drill gate.

P0-E consumes a passed P0-D callback-backed preview smoke summary. It verifies
rollback/abort references, owner/audit decisions, callback evidence, and the
no-production boundary. It does not contact VM targets, deploy, mutate source or
Git, transition to production, or write production receipts.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from benchmarks.i_gate_evidence import artifact_ref, check, object_value, read_json_object, sha256_file, write_json_object
from benchmarks.p0c_controlled_task_pool_execution import CALLBACK_SINK_SCHEMA, NO_PRODUCTION_SCHEMA, PREVIEW_SCHEMA, ROLLBACK_OR_ABORT_SCHEMA
from benchmarks.p0d_preview_smoke_gate import BACKEND_SMOKE_SCHEMA, CHAIN_SCHEMA as P0D_CHAIN_SCHEMA, INTEGRITY_SCHEMA as P0D_INTEGRITY_SCHEMA, OWNER_AUDIT_PACKET_SCHEMA as P0D_OWNER_AUDIT_PACKET_SCHEMA

CHAIN_SCHEMA = "p0e-rollback-abort-drill-chain:v1"
OWNER_AUDIT_DECISION_SCHEMA = "p0e-owner-audit-decision:v1"
ROLLBACK_ABORT_DRILL_SCHEMA = "p0e-rollback-abort-drill-receipt:v1"
NO_PRODUCTION_BOUNDARY_SCHEMA = "p0e-no-production-boundary-review:v1"

APPROVE_ROLLBACK_DRILL = "approve_rollback_abort_drill"
APPROVE_NO_PRODUCTION = "approve_no_production_boundary"
APPROVE_ABORT_ONLY = "approve_abort_only_receipt"


def run_gate(
    *,
    p0d_summary_path: Path,
    output_root: Path,
    operator_id: str = "operator-cc",
    owner_decision: str = APPROVE_ROLLBACK_DRILL,
    audit_decision: str = APPROVE_NO_PRODUCTION,
    rollback_owner_decision: str = APPROVE_ABORT_ONLY,
) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "owner_audit_decision": output_root / "p0e_owner_audit_decision.json",
        "no_production_boundary_review": output_root / "p0e_no_production_boundary_review.json",
        "rollback_abort_drill_receipt": output_root / "p0e_rollback_abort_drill_receipt.json",
        "summary": output_root / "p0e_rollback_abort_drill_chain_summary.json",
    }
    context = validate_p0d_context(p0d_summary_path)
    decision = write_owner_audit_decision(
        context=context,
        p0d_summary_path=p0d_summary_path,
        output=artifacts["owner_audit_decision"],
        operator_id=operator_id,
        owner_decision=owner_decision,
        audit_decision=audit_decision,
        rollback_owner_decision=rollback_owner_decision,
    )
    boundary = write_no_production_boundary_review(
        context=context,
        decision_path=artifacts["owner_audit_decision"],
        output=artifacts["no_production_boundary_review"],
    )
    drill = write_rollback_abort_drill_receipt(
        context=context,
        decision_path=artifacts["owner_audit_decision"],
        boundary_review_path=artifacts["no_production_boundary_review"],
        output=artifacts["rollback_abort_drill_receipt"],
    )
    reports = [context, decision, boundary, drill]
    passed = all(report.get("passed") is True for report in reports)
    summary = {
        "schema_version": CHAIN_SCHEMA,
        "passed": passed,
        "failure_reasons": _failures(reports),
        "checked_at": _now(),
        "task_id": context.get("task_id"),
        "source_artifacts": {"p0d_summary": artifact_ref(p0d_summary_path)},
        "artifacts": {name: artifact_ref(path) for name, path in artifacts.items() if name != "summary"},
        "readiness": {
            "state": "p0e_rollback_abort_drill_passed" if passed else "blocked_p0e_rollback_abort_drill",
            "p0e_rollback_abort_drill_complete": passed,
            "p0f_vm_preview_preflight_ready": passed,
            "production_transition_allowed": False,
        },
        "boundary": _boundary(
            owner_audit_decision_written=decision.get("passed") is True,
            rollback_abort_receipt_written=drill.get("passed") is True,
            no_production_boundary_review_written=boundary.get("passed") is True,
            callback_delivery_observed=context.get("callback_sink_evidence_present") is True,
        ),
        "non_claims": _non_claims(),
    }
    write_json_object(artifacts["summary"], summary)
    return summary


def validate_p0d_context(p0d_summary_path: Path) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    try:
        p0d = read_json_object(p0d_summary_path)
    except Exception as exc:  # noqa: BLE001
        return _report("p0e-p0d-context-validation:v1", False, [f"p0d_summary_unreadable:{exc}"], checks)
    refs = object_value(p0d.get("artifacts"))
    integrity = _read_verified_ref(refs.get("artifact_integrity"), checks, failures, "p0d_artifact_integrity")
    backend = _read_verified_ref(refs.get("backend_smoke"), checks, failures, "p0d_backend_smoke")
    owner_packet = _read_verified_ref(refs.get("owner_audit_review_packet"), checks, failures, "p0d_owner_audit_review_packet")
    verified = object_value(integrity.get("verified_artifacts"))
    rollback = _read_verified_ref(verified.get("rollback_or_abort_ref"), checks, failures, "rollback_or_abort_ref")
    no_prod = _read_verified_ref(verified.get("no_production_attestation"), checks, failures, "no_production_attestation")
    preview = _read_verified_ref(verified.get("preview_artifact"), checks, failures, "preview_artifact")
    callback = _read_verified_ref(verified.get("callback_sink_receipt"), checks, failures, "callback_sink_receipt")
    readiness = object_value(p0d.get("readiness"))
    p0d_boundary = object_value(p0d.get("boundary"))
    owner_review = object_value(owner_packet.get("review_packet"))
    task_id = str(p0d.get("task_id") or integrity.get("task_id") or rollback.get("task_id") or "")

    check(checks, failures, "p0d_summary_passed", p0d.get("schema_version") == P0D_CHAIN_SCHEMA and p0d.get("passed") is True)
    check(checks, failures, "p0d_ready_for_p0e", readiness.get("p0e_rollback_drill_ready") is True)
    check(checks, failures, "p0d_production_transition_closed", readiness.get("production_transition_allowed") is False)
    check(checks, failures, "p0d_boundary_closed", _closed_no_production_boundary(p0d_boundary))
    check(checks, failures, "p0d_integrity_passed", integrity.get("schema_version") == P0D_INTEGRITY_SCHEMA and integrity.get("passed") is True)
    check(checks, failures, "p0d_backend_smoke_passed", backend.get("schema_version") == BACKEND_SMOKE_SCHEMA and backend.get("passed") is True)
    check(checks, failures, "p0d_owner_packet_passed", owner_packet.get("schema_version") == P0D_OWNER_AUDIT_PACKET_SCHEMA and owner_packet.get("passed") is True)
    check(checks, failures, "callback_review_cleared", owner_review.get("callback_sink_review_required") is False)
    check(checks, failures, "callback_sink_evidence_present", integrity.get("callback_sink_evidence_present") is True and backend.get("callback_sink_evidence_present") is True)
    check(checks, failures, "callback_sink_receipt_passed", callback.get("schema_version") == CALLBACK_SINK_SCHEMA and callback.get("passed") is True)
    check(checks, failures, "callback_task_matches", callback.get("task_id") == task_id)
    check(checks, failures, "rollback_ref_passed", rollback.get("schema_version") == ROLLBACK_OR_ABORT_SCHEMA and rollback.get("passed") is True)
    check(checks, failures, "rollback_task_matches", rollback.get("task_id") == task_id)
    check(checks, failures, "no_production_attestation_passed", no_prod.get("schema_version") == NO_PRODUCTION_SCHEMA and no_prod.get("passed") is True)
    check(checks, failures, "preview_artifact_passed", preview.get("schema_version") == PREVIEW_SCHEMA and preview.get("passed") is True)

    report = {
        "schema_version": "p0e-p0d-context-validation:v1",
        "passed": bool(checks) and all(checks.values()) and not failures,
        "failure_reasons": failures,
        "checks": checks,
        "task_id": task_id,
        "source_artifacts": {"p0d_summary": artifact_ref(p0d_summary_path)},
        "p0d_summary": p0d,
        "integrity": integrity,
        "backend_smoke": backend,
        "owner_packet": owner_packet,
        "rollback_or_abort_ref": rollback,
        "no_production_attestation": no_prod,
        "preview_artifact": preview,
        "callback_sink_receipt": callback,
        "callback_sink_evidence_present": integrity.get("callback_sink_evidence_present") is True and backend.get("callback_sink_evidence_present") is True,
    }
    return report


def write_owner_audit_decision(
    *,
    context: dict[str, Any],
    p0d_summary_path: Path,
    output: Path,
    operator_id: str,
    owner_decision: str,
    audit_decision: str,
    rollback_owner_decision: str,
) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    owner_packet = object_value(context.get("owner_packet"))
    review = object_value(owner_packet.get("review_packet"))
    check(checks, failures, "p0d_context_passed", context.get("passed") is True)
    check(checks, failures, "operator_id_present", bool(str(operator_id).strip()))
    check(checks, failures, "owner_decision_approves_drill", owner_decision == APPROVE_ROLLBACK_DRILL)
    check(checks, failures, "audit_decision_approves_no_production", audit_decision == APPROVE_NO_PRODUCTION)
    check(checks, failures, "rollback_owner_decision_approves_abort_only", rollback_owner_decision == APPROVE_ABORT_ONLY)
    check(checks, failures, "callback_review_not_required", review.get("callback_sink_review_required") is False)
    check(checks, failures, "production_boundary_review_item_present", any(item.get("item") == "production_boundary" for item in _list_of_dicts(review.get("review_items"))))
    passed = bool(checks) and all(checks.values()) and not failures
    p0d_artifacts = object_value(object_value(context.get("p0d_summary")).get("artifacts"))
    owner_packet_ref = object_value(p0d_artifacts.get("owner_audit_review_packet"))
    owner_packet_path = Path(str(owner_packet_ref.get("path") or ""))
    decision = {
        "schema_version": OWNER_AUDIT_DECISION_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "decided_at": _now(),
        "task_id": context.get("task_id"),
        "operator_id": operator_id,
        "owner_id": review.get("owner_id"),
        "audit_owner_id": review.get("audit_owner_id"),
        "rollback_owner_id": review.get("rollback_owner_id"),
        "owner_decision": owner_decision,
        "audit_decision": audit_decision,
        "rollback_owner_decision": rollback_owner_decision,
        "decision": "approve_p0e_abort_only_drill" if passed else "blocked_p0e_abort_only_drill",
        "source_artifacts": {
            "p0d_summary": artifact_ref(p0d_summary_path),
            "p0d_owner_audit_review_packet": artifact_ref(owner_packet_path) if owner_packet_path.is_file() else owner_packet_ref,
        },
        "boundary": _boundary(owner_audit_decision_written=passed, callback_delivery_observed=context.get("callback_sink_evidence_present") is True),
    }
    write_json_object(output, decision)
    return decision


def write_no_production_boundary_review(*, context: dict[str, Any], decision_path: Path, output: Path) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    decision = read_json_object(decision_path)
    p0d_boundary = object_value(object_value(context.get("p0d_summary")).get("boundary"))
    rollback_boundary = object_value(object_value(context.get("rollback_or_abort_ref")).get("boundary"))
    no_prod_attestation = object_value(object_value(context.get("no_production_attestation")).get("attestation"))
    check(checks, failures, "owner_audit_decision_passed", decision.get("passed") is True)
    check(checks, failures, "p0d_boundary_closed", _closed_no_production_boundary(p0d_boundary))
    check(checks, failures, "rollback_ref_boundary_closed", _closed_no_production_boundary(rollback_boundary))
    check(checks, failures, "no_production_attestation_closed", _attestation_no_production(no_prod_attestation))
    check(checks, failures, "callback_delivery_observed", context.get("callback_sink_evidence_present") is True)
    passed = bool(checks) and all(checks.values()) and not failures
    review = {
        "schema_version": NO_PRODUCTION_BOUNDARY_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "task_id": context.get("task_id"),
        "source_artifacts": {
            "owner_audit_decision": artifact_ref(decision_path),
            "p0d_summary": object_value(context.get("source_artifacts")).get("p0d_summary"),
        },
        "boundary_review": {
            "vm_contact_performed": False,
            "deploy_performed": False,
            "source_tree_write_performed": False,
            "git_write_performed": False,
            "external_public_ingress_opened": False,
            "production_transition_allowed": False,
            "production_receipt_write_allowed": False,
            "production_data_accessed": False,
            "secrets_recorded": False,
        },
        "boundary": _boundary(no_production_boundary_review_written=passed, callback_delivery_observed=context.get("callback_sink_evidence_present") is True),
    }
    write_json_object(output, review)
    return review


def write_rollback_abort_drill_receipt(*, context: dict[str, Any], decision_path: Path, boundary_review_path: Path, output: Path) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    decision = read_json_object(decision_path)
    boundary_review = read_json_object(boundary_review_path)
    rollback = object_value(context.get("rollback_or_abort_ref"))
    task_id = str(context.get("task_id") or "")
    check(checks, failures, "p0d_context_passed", context.get("passed") is True)
    check(checks, failures, "owner_audit_decision_passed", decision.get("passed") is True)
    check(checks, failures, "no_production_boundary_review_passed", boundary_review.get("passed") is True)
    check(checks, failures, "rollback_ref_passed", rollback.get("passed") is True)
    check(checks, failures, "rollback_ref_task_matches", rollback.get("task_id") == task_id)
    check(checks, failures, "callback_delivery_observed", context.get("callback_sink_evidence_present") is True)
    passed = bool(checks) and all(checks.values()) and not failures
    receipt = {
        "schema_version": ROLLBACK_ABORT_DRILL_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "completed_at": _now(),
        "task_id": task_id,
        "drill_mode": "abort_only_no_deploy_rollback_not_required",
        "rollback_command_from_p0c": rollback.get("rollback_command"),
        "actions_performed": [
            "verified_p0d_callback_backed_preview_smoke_passed",
            "verified_preview_artifact_not_promoted_to_production_evidence",
            "verified_no_vm_contact_no_deploy_no_source_or_git_write",
            "verified_no_production_transition_and_no_production_receipt",
            "retained_hash_bound_p0_chain_for_audit",
        ],
        "rollback_performed": False,
        "abort_receipt_written": passed,
        "source_artifacts": {
            "owner_audit_decision": artifact_ref(decision_path),
            "no_production_boundary_review": artifact_ref(boundary_review_path),
            "rollback_or_abort_ref": object_value(object_value(context.get("integrity")).get("verified_artifacts")).get("rollback_or_abort_ref"),
            "callback_sink_receipt": object_value(object_value(context.get("integrity")).get("verified_artifacts")).get("callback_sink_receipt"),
        },
        "boundary": _boundary(
            rollback_abort_receipt_written=passed,
            no_production_boundary_review_written=boundary_review.get("passed") is True,
            owner_audit_decision_written=decision.get("passed") is True,
            callback_delivery_observed=context.get("callback_sink_evidence_present") is True,
        ),
        "non_claims": _non_claims(),
    }
    write_json_object(output, receipt)
    return receipt


def _read_verified_ref(value: Any, checks: dict[str, bool], failures: list[str], label: str) -> dict[str, Any]:
    ref = object_value(value)
    path = Path(str(ref.get("path") or ""))
    expected_hash = str(ref.get("sha256") or "")
    check(checks, failures, f"{label}_path_present", path.is_file())
    if not path.is_file():
        return {}
    check(checks, failures, f"{label}_hash_valid", bool(expected_hash) and sha256_file(path) == expected_hash)
    return read_json_object(path)


def _closed_no_production_boundary(boundary: dict[str, Any]) -> bool:
    required_false = (
        "vm_contact_performed",
        "deploy_performed",
        "source_tree_write_performed",
        "git_write_performed",
        "external_public_ingress_opened",
        "production_transition_allowed",
        "production_receipt_write_allowed",
    )
    return all(boundary.get(key) is False for key in required_false)


def _attestation_no_production(attestation: dict[str, Any]) -> bool:
    keys = (
        "vm_contact_performed",
        "deploy_performed",
        "source_tree_write_performed",
        "git_write_performed",
        "production_transition_allowed",
        "production_receipt_write_allowed",
        "production_data_accessed",
        "secrets_recorded",
    )
    return all(attestation.get(key) is False for key in keys)


def _list_of_dicts(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _boundary(**overrides: bool) -> dict[str, bool]:
    base = {
        "owner_audit_decision_written": False,
        "no_production_boundary_review_written": False,
        "rollback_abort_receipt_written": False,
        "callback_delivery_observed": False,
        "vm_contact_performed": False,
        "deploy_performed": False,
        "source_tree_write_performed": False,
        "git_write_performed": False,
        "external_public_ingress_opened": False,
        "production_transition_allowed": False,
        "production_receipt_write_allowed": False,
    }
    base.update(overrides)
    return base


def _non_claims() -> list[str]:
    return [
        "p0e_is_abort_only_rollback_drill_for_preview_evidence",
        "p0e_does_not_contact_vm_targets",
        "p0e_does_not_deploy",
        "p0e_does_not_modify_source_or_git",
        "p0e_does_not_write_production_receipt",
        "p0e_does_not_authorize_production_transition",
    ]


def _failures(reports: list[dict[str, Any]]) -> list[str]:
    values: list[str] = []
    for report in reports:
        values.extend(str(item) for item in report.get("failure_reasons", []))
    return sorted(set(values))


def _report(schema: str, passed: bool, failures: list[str], checks: dict[str, bool]) -> dict[str, Any]:
    return {"schema_version": schema, "passed": passed, "failure_reasons": failures, "checks": checks}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def main() -> int:
    parser = argparse.ArgumentParser(description="Run P0-E rollback / abort drill gate")
    parser.add_argument("--p0d-summary", required=True)
    parser.add_argument("--output-root", required=True)
    parser.add_argument("--operator-id", default="operator-cc")
    parser.add_argument("--owner-decision", default=APPROVE_ROLLBACK_DRILL)
    parser.add_argument("--audit-decision", default=APPROVE_NO_PRODUCTION)
    parser.add_argument("--rollback-owner-decision", default=APPROVE_ABORT_ONLY)
    args = parser.parse_args()
    summary = run_gate(
        p0d_summary_path=Path(args.p0d_summary),
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
