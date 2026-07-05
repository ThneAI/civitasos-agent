"""PostH3 minimal production task chain blueprint.

This artifact-only gate consumes PostH3-AC observer-mode readiness and writes a
stable production task chain shape:

intake -> authorization -> execute -> monitor -> rollback/abort -> closeout -> strategy review

It does not authorize or execute any production task. The output is a blueprint
for the next bounded gate implementation and a readiness index input.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from benchmarks.i_gate_evidence import artifact_ref, check, object_value, read_json_object, sha256_file, sha256_json, write_json_object
from benchmarks.post_h3_observer_mode_readiness_gate import (
    BOUNDARY_REPORT_SCHEMA as POST_H3AC_BOUNDARY_REPORT_SCHEMA,
    CHAIN_SCHEMA as POST_H3AC_SCHEMA,
    CONTEXT_SCHEMA as POST_H3AC_CONTEXT_SCHEMA,
    OBSERVER_EVIDENCE_SCHEMA as POST_H3AC_OBSERVER_EVIDENCE_SCHEMA,
    READINESS_REVIEW_SCHEMA as POST_H3AC_READINESS_REVIEW_SCHEMA,
)

CHAIN_SCHEMA = "post-h3-minimal-production-task-chain-summary:v1"
CONTEXT_SCHEMA = "post-h3-minimal-production-task-chain-context-validation:v1"
BLUEPRINT_SCHEMA = "post-h3-minimal-production-task-chain-blueprint:v1"
BOUNDARY_SCHEMA = "post-h3-minimal-production-task-chain-boundary-report:v1"

ORDERED_STAGES = (
    "intake",
    "authorization",
    "execute",
    "monitor",
    "rollback_abort",
    "closeout",
    "strategy_review",
)

NON_CLAIMS = (
    "minimal_production_task_chain_is_blueprint_only",
    "minimal_production_task_chain_does_not_authorize_execution",
    "minimal_production_task_chain_does_not_execute_runtime_task",
    "minimal_production_task_chain_does_not_open_public_ingress",
    "minimal_production_task_chain_does_not_deploy",
    "minimal_production_task_chain_does_not_access_production_data",
    "minimal_production_task_chain_does_not_write_production_runtime_receipts",
    "minimal_production_task_chain_does_not_write_source_or_git",
)


def run_gate(*, post_h3ac_summary_path: Path, output_root: Path) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "context_validation": output_root / "post_h3_minimal_production_task_chain_context_validation.json",
        "blueprint": output_root / "post_h3_minimal_production_task_chain_blueprint.json",
        "boundary_report": output_root / "post_h3_minimal_production_task_chain_boundary_report.json",
        "summary": output_root / "post_h3_minimal_production_task_chain_summary.json",
    }
    context = validate_post_h3ac_context(post_h3ac_summary_path, output=artifacts["context_validation"])
    blueprint = _write_blueprint(context=context, output=artifacts["blueprint"])
    boundary = _write_boundary_report(context=context, blueprint_path=artifacts["blueprint"], output=artifacts["boundary_report"])
    reports = [context, blueprint, boundary]
    passed = all(report.get("passed") is True for report in reports)
    summary = {
        "schema_version": CHAIN_SCHEMA,
        "passed": passed,
        "failure_reasons": _failures(reports),
        "checked_at": _now(),
        "chain_id": blueprint.get("chain_id"),
        "source_artifacts": {"post_h3ac_summary": artifact_ref(post_h3ac_summary_path)},
        "artifacts": {name: artifact_ref(path) for name, path in artifacts.items() if name != "summary"},
        "ordered_stages": list(ORDERED_STAGES),
        "readiness": {
            "minimal_production_task_chain_blueprint_ready": passed,
            "intake_gate_design_ready": passed,
            "authorization_gate_design_ready": passed,
            "execution_gate_design_ready": passed,
            "monitoring_gate_design_ready": passed,
            "rollback_abort_gate_design_ready": passed,
            "closeout_gate_design_ready": passed,
            "strategy_review_gate_design_ready": passed,
            "production_task_execution_allowed": False,
            "next_single_use_gate_input_ready": False,
            "artifact_only": True,
        },
        "boundary": _closed_boundary(
            context_validation_written=context.get("passed") is True,
            blueprint_written=blueprint.get("passed") is True,
            boundary_report_written=boundary.get("passed") is True,
        ),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(artifacts["summary"], summary)
    return summary


def validate_post_h3ac_context(post_h3ac_summary_path: Path, *, output: Path | None = None) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    try:
        summary = read_json_object(post_h3ac_summary_path)
    except Exception as exc:  # noqa: BLE001
        report = _report(CONTEXT_SCHEMA, False, [f"post_h3ac_summary_unreadable:{exc}"], checks)
        return _write_optional(report, output)

    artifacts = object_value(summary.get("artifacts"))
    context = _read_verified_ref(artifacts.get("context_validation"), checks, failures, "post_h3ac_context_validation")
    snapshot = _read_verified_ref(artifacts.get("observer_evidence_snapshot"), checks, failures, "post_h3ac_observer_evidence_snapshot")
    review = _read_verified_ref(artifacts.get("readiness_review"), checks, failures, "post_h3ac_readiness_review")
    boundary_report = _read_verified_ref(artifacts.get("boundary_report"), checks, failures, "post_h3ac_boundary_report")

    readiness = object_value(summary.get("readiness"))
    boundary = object_value(summary.get("boundary"))
    check(checks, failures, "post_h3ac_schema", summary.get("schema_version") == POST_H3AC_SCHEMA)
    check(checks, failures, "post_h3ac_passed", summary.get("passed") is True)
    check(checks, failures, "post_h3ac_observer_mode_continues", readiness.get("observer_mode_continues") is True)
    check(checks, failures, "post_h3ac_readiness_review_complete", readiness.get("observer_mode_readiness_review_complete") is True)
    check(checks, failures, "post_h3ac_no_next_single_use_input", readiness.get("next_single_use_gate_input_ready") is False)
    check(checks, failures, "post_h3ac_no_external_usage_allowed", readiness.get("external_user_usage_allowed") is False)
    check(checks, failures, "post_h3ac_no_runtime_execution", readiness.get("runtime_execution_performed") is False)
    check(checks, failures, "post_h3ac_no_production_runtime_receipts", readiness.get("production_runtime_receipt_write_allowed") is False)
    _check_closed_side_effect_boundary("post_h3ac_summary", boundary, checks, failures)
    check(checks, failures, "post_h3ac_context_schema", context.get("schema_version") == POST_H3AC_CONTEXT_SCHEMA)
    check(checks, failures, "post_h3ac_snapshot_schema", snapshot.get("schema_version") == POST_H3AC_OBSERVER_EVIDENCE_SCHEMA)
    check(checks, failures, "post_h3ac_review_schema", review.get("schema_version") == POST_H3AC_READINESS_REVIEW_SCHEMA)
    check(checks, failures, "post_h3ac_boundary_schema", boundary_report.get("schema_version") == POST_H3AC_BOUNDARY_REPORT_SCHEMA)
    check(checks, failures, "post_h3ac_context_passed", context.get("passed") is True)
    check(checks, failures, "post_h3ac_snapshot_passed", snapshot.get("passed") is True)
    check(checks, failures, "post_h3ac_review_passed", review.get("passed") is True)
    check(checks, failures, "post_h3ac_boundary_passed", boundary_report.get("passed") is True)
    _check_closed_side_effect_boundary("post_h3ac_boundary_report", object_value(boundary_report.get("boundary")), checks, failures)

    passed = _passed(checks, failures)
    report = {
        "schema_version": CONTEXT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "post_h3ac_summary": summary,
        "post_h3ac_context_validation": context,
        "post_h3ac_observer_evidence_snapshot": snapshot,
        "post_h3ac_readiness_review": review,
        "post_h3ac_boundary_report": boundary_report,
        "source_artifacts": {"post_h3ac_summary": artifact_ref(post_h3ac_summary_path)},
        "boundary": _closed_boundary(context_validation_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    return _write_optional(report, output)


def _write_blueprint(*, context: dict[str, Any], output: Path) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    check(checks, failures, "context_passed", context.get("passed") is True)
    stages = _stages()
    check(checks, failures, "stage_order_complete", tuple(stage["stage"] for stage in stages) == ORDERED_STAGES)
    check(checks, failures, "all_stages_artifact_only", all(stage["boundary"]["artifact_only_design"] is True for stage in stages))
    check(checks, failures, "all_stages_require_explicit_authorization", all(stage["boundary"]["automatic_transition_allowed"] is False for stage in stages))
    passed = _passed(checks, failures)
    source_summary = object_value(context.get("post_h3ac_summary"))
    chain_id = f"post-h3-minimal-production-task-chain:{sha256_json([source_summary.get('observer_mode_readiness_review_id'), ORDERED_STAGES])[:24]}"
    blueprint = {
        "schema_version": BLUEPRINT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "written_at": _now(),
        "chain_id": chain_id,
        "source_observer_readiness_review_id": source_summary.get("observer_mode_readiness_review_id"),
        "ordered_stages": stages,
        "stage_order": list(ORDERED_STAGES),
        "transition_rules": {
            "each_stage_consumes_previous_stage_receipt": True,
            "each_stage_has_single_owner_decision": True,
            "audit_owner_required_at_authorization_closeout_and_strategy_review": True,
            "rollback_or_abort_receipt_required_before_closeout": True,
            "strategy_review_cannot_authorize_runtime_action_directly": True,
            "no_stage_auto_expands_public_ingress_or_runtime_scope": True,
        },
        "readiness": {
            "minimal_production_task_chain_blueprint_ready": passed,
            "next_gate": "post_h3_controlled_production_task_intake_gate",
            "next_single_use_gate_input_ready": False,
            "production_task_execution_allowed": False,
            "artifact_only": True,
        },
        "boundary": _closed_boundary(blueprint_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, blueprint)
    return blueprint


def _write_boundary_report(*, context: dict[str, Any], blueprint_path: Path, output: Path) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    try:
        blueprint = read_json_object(blueprint_path)
    except Exception as exc:  # noqa: BLE001
        blueprint = {}
        failures.append(f"blueprint_unreadable:{exc}")
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "blueprint_passed", blueprint.get("schema_version") == BLUEPRINT_SCHEMA and blueprint.get("passed") is True)
    _check_closed_side_effect_boundary("blueprint", object_value(blueprint.get("boundary")), checks, failures)
    passed = _passed(checks, failures)
    report = {
        "schema_version": BOUNDARY_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "chain_id": blueprint.get("chain_id"),
        "boundary": _closed_boundary(boundary_report_written=passed),
        "readiness": {
            "minimal_production_task_chain_blueprint_ready": passed,
            "production_task_execution_allowed": False,
            "next_single_use_gate_input_ready": False,
            "artifact_only": True,
        },
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def _stages() -> list[dict[str, Any]]:
    return [
        _stage(
            "intake",
            requires=[],
            inputs=["task_request", "owner_binding", "audit_owner", "rollback_owner", "monitoring_owner", "risk_scope"],
            outputs=["intake_packet", "risk_boundary", "candidate_rollback_runbook"],
            purpose="Convert a real low-risk request into a bounded task packet without execution rights.",
        ),
        _stage(
            "authorization",
            requires=["intake_packet"],
            inputs=["intake_packet", "risk_boundary", "service_token_scope", "rollback_runbook", "owner_decision", "audit_decision"],
            outputs=["single_use_authorization_request", "single_use_authorization_decision"],
            purpose="Make an explicit one-time decision for a bounded execution attempt.",
        ),
        _stage(
            "execute",
            requires=["single_use_authorization_decision"],
            inputs=["single_use_authorization_decision", "selected_runner", "execution_plan", "rollback_runbook"],
            outputs=["execution_receipt", "command_stdout_ref", "command_stderr_ref"],
            purpose="Run only the authorized action and write a hash-bound execution receipt.",
        ),
        _stage(
            "monitor",
            requires=["execution_receipt"],
            inputs=["execution_receipt", "health_probe", "telemetry_snapshot", "owner_observation", "audit_observation"],
            outputs=["monitoring_receipt", "anomaly_report"],
            purpose="Record observed effects and detect whether rollback/abort review is needed.",
        ),
        _stage(
            "rollback_abort",
            requires=["execution_receipt", "monitoring_receipt"],
            inputs=["execution_receipt", "monitoring_receipt", "rollback_runbook", "rollback_owner_decision"],
            outputs=["rollback_or_abort_receipt", "post_action_health_probe"],
            purpose="Prove either rollback execution, abort decision, or no-op rollback justification.",
        ),
        _stage(
            "closeout",
            requires=["execution_receipt", "monitoring_receipt", "rollback_or_abort_receipt"],
            inputs=["execution_receipt", "monitoring_receipt", "rollback_or_abort_receipt", "owner_reconciliation", "audit_reconciliation"],
            outputs=["task_closeout_summary", "task_evidence_index"],
            purpose="Freeze the bounded task result into a reviewable evidence packet.",
        ),
        _stage(
            "strategy_review",
            requires=["task_closeout_summary", "task_evidence_index"],
            inputs=["task_closeout_summary", "task_evidence_index", "delayed_consequence_report", "owner_feedback"],
            outputs=["strategy_review_packet", "continue_expand_or_revise_decision"],
            purpose="Decide whether the system should continue, revise, or request a new bounded authorization.",
        ),
    ]


def _stage(stage: str, *, requires: list[str], inputs: list[str], outputs: list[str], purpose: str) -> dict[str, Any]:
    return {
        "stage": stage,
        "purpose": purpose,
        "requires": requires,
        "inputs": inputs,
        "outputs": outputs,
        "boundary": {
            "artifact_only_design": True,
            "automatic_transition_allowed": False,
            "runtime_execution_allowed_by_blueprint": False,
            "public_ingress_expansion_allowed_by_blueprint": False,
            "production_receipt_write_allowed_by_blueprint": False,
        },
    }


def _read_verified_ref(ref: Any, checks: dict[str, bool], failures: list[str], label: str) -> dict[str, Any]:
    ref_obj = object_value(ref)
    path_text = ref_obj.get("path")
    expected_hash = ref_obj.get("sha256")
    check(checks, failures, f"{label}_ref_present", bool(path_text and expected_hash))
    if not path_text or not expected_hash:
        return {}
    path = Path(path_text)
    check(checks, failures, f"{label}_exists", path.is_file())
    if not path.is_file():
        return {}
    actual_hash = sha256_file(path)
    check(checks, failures, f"{label}_hash_valid", actual_hash == expected_hash)
    try:
        value = read_json_object(path)
    except Exception as exc:  # noqa: BLE001
        failures.append(f"{label}_unreadable:{exc}")
        return {}
    return value


def _check_closed_side_effect_boundary(label: str, boundary: dict[str, Any], checks: dict[str, bool], failures: list[str]) -> None:
    expected_false = (
        "deploy_performed",
        "external_public_ingress_opened",
        "external_user_feedback_collection_ready",
        "external_user_usage_allowed",
        "git_write_performed",
        "next_single_use_gate_input_ready",
        "production_data_accessed",
        "production_runtime_receipt_write_allowed",
        "runtime_execution_performed",
        "runtime_workers_currently_running",
        "second_external_user_usage_execution_ready",
        "secrets_recorded",
        "source_tree_write_performed",
        "vm_contact_performed",
        "production_task_execution_allowed",
    )
    for key in expected_false:
        if key in boundary:
            check(checks, failures, f"{label}_{key}_false", boundary.get(key) is False)


def _closed_boundary(**overrides: Any) -> dict[str, Any]:
    boundary = {
        "artifact_only": True,
        "context_validation_written": False,
        "blueprint_written": False,
        "boundary_report_written": False,
        "production_task_execution_allowed": False,
        "next_single_use_gate_input_ready": False,
        "runtime_execution_performed": False,
        "runtime_workers_currently_running": False,
        "external_user_usage_allowed": False,
        "external_public_ingress_opened": False,
        "deploy_performed": False,
        "vm_contact_performed": False,
        "production_data_accessed": False,
        "production_runtime_receipt_write_allowed": False,
        "source_tree_write_performed": False,
        "git_write_performed": False,
        "secrets_recorded": False,
    }
    boundary.update(overrides)
    return boundary


def _report(schema: str, passed: bool, failures: list[str], checks: dict[str, bool]) -> dict[str, Any]:
    return {
        "schema_version": schema,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "boundary": _closed_boundary(),
        "non_claims": list(NON_CLAIMS),
    }


def _write_optional(report: dict[str, Any], output: Path | None) -> dict[str, Any]:
    if output is not None:
        write_json_object(output, report)
    return report


def _passed(checks: dict[str, bool], failures: list[str]) -> bool:
    return bool(checks) and all(checks.values()) and not failures


def _failures(reports: list[dict[str, Any]]) -> list[str]:
    failures: list[str] = []
    for report in reports:
        for failure in report.get("failure_reasons", []):
            if isinstance(failure, str) and failure not in failures:
                failures.append(failure)
    return failures


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--post-h3ac-summary", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args(argv)
    summary = run_gate(post_h3ac_summary_path=args.post_h3ac_summary, output_root=args.output_root)
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if summary.get("passed") is True else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
