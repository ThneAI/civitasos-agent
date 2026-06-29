"""Bind limited external usage scope, monitoring SLO, and rollback ownership.

PostH3-V consumes PostH3-U identity/consent evidence and records a bounded
external usage scope. It converts the previous open requirements into a limited,
invite-only, status/read-only usage profile with explicit monitoring and
rollback/abort ownership. It does not authorize or execute usage, open ingress,
start runtime workers, contact VMs, deploy, access production data, or write
source/Git state.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from benchmarks.i_gate_evidence import artifact_ref, check, object_value, read_json_object, sha256_file, sha256_json, write_json_object

CHAIN_SCHEMA = "post-h3-limited-external-usage-scope-binding-chain:v1"
CONTEXT_SCHEMA = "post-h3v-post-h3u-context-validation:v1"
USAGE_SCOPE_SCHEMA = "post-h3v-limited-external-usage-scope:v1"
MONITORING_ROLLBACK_SCHEMA = "post-h3v-monitoring-rollback-binding:v1"
BOUNDARY_REPORT_SCHEMA = "post-h3v-limited-external-usage-scope-boundary-report:v1"

POST_H3U_SCHEMA = "post-h3-external-user-identity-consent-chain:v1"
POST_H3U_CONSENT_RECEIPT_SCHEMA = "post-h3u-external-user-consent-receipt:v1"

ALLOWED_USAGE_SCOPE = "invite-only-status-read-only-task"
ALLOWED_PUBLIC_INGRESS_MODE = "status_only_bounded_ingress"
ALLOWED_RUNTIME_EXPANSION_MODE = "bounded_worker_heartbeat_only"
NON_CLAIMS = (
    "post_h3v_binds_limited_usage_scope_only",
    "post_h3v_does_not_authorize_external_user_usage",
    "post_h3v_does_not_execute_external_user_usage",
    "post_h3v_does_not_open_public_ingress",
    "post_h3v_does_not_start_runtime_workers",
    "post_h3v_does_not_execute_runtime_task",
    "post_h3v_does_not_contact_vm_targets",
    "post_h3v_does_not_deploy",
    "post_h3v_does_not_access_production_data",
    "post_h3v_does_not_write_source_or_git",
)


def run_gate(
    *,
    post_h3u_summary_path: Path,
    output_root: Path,
    operator_id: str = "operator-primary",
    external_user_handle: str = "Thneoly",
    allowed_usage_scope: str = ALLOWED_USAGE_SCOPE,
    max_external_users: int = 1,
    max_runtime_tasks: int = 1,
    max_usage_seconds: int = 600,
    public_ingress_mode: str = ALLOWED_PUBLIC_INGRESS_MODE,
    runtime_expansion_mode: str = ALLOWED_RUNTIME_EXPANSION_MODE,
    monitoring_owner: str = "monitoring_owner",
    audit_owner: str = "audit_owner",
    rollback_owner: str = "rollback_owner",
    monitoring_slo_id: str = "post-h3-limited-external-usage-slo:v1",
    max_probe_latency_ms: int = 2000,
    heartbeat_interval_seconds: int = 30,
    abort_path: str = "operator abort command writes abort receipt and closes ingress/workers",
    rollback_runbook_id: str = "post-h3-limited-external-usage-rollback:v1",
    ack_limited_usage_scope_binding: bool = False,
) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "context_validation": output_root / "post_h3v_post_h3u_context_validation.json",
        "usage_scope": output_root / "post_h3v_limited_external_usage_scope.json",
        "monitoring_rollback_binding": output_root / "post_h3v_monitoring_rollback_binding.json",
        "boundary_report": output_root / "post_h3v_limited_external_usage_scope_boundary_report.json",
        "summary": output_root / "post_h3v_limited_external_usage_scope_binding_summary.json",
    }
    context = validate_post_h3u_context(post_h3u_summary_path, output=artifacts["context_validation"])
    usage_scope = _write_usage_scope(
        context=context,
        post_h3u_summary_path=post_h3u_summary_path,
        output=artifacts["usage_scope"],
        operator_id=operator_id,
        external_user_handle=external_user_handle,
        allowed_usage_scope=allowed_usage_scope,
        max_external_users=max_external_users,
        max_runtime_tasks=max_runtime_tasks,
        max_usage_seconds=max_usage_seconds,
        public_ingress_mode=public_ingress_mode,
        runtime_expansion_mode=runtime_expansion_mode,
        ack_limited_usage_scope_binding=ack_limited_usage_scope_binding,
    )
    monitoring = _write_monitoring_rollback_binding(
        usage_scope_path=artifacts["usage_scope"],
        output=artifacts["monitoring_rollback_binding"],
        monitoring_owner=monitoring_owner,
        audit_owner=audit_owner,
        rollback_owner=rollback_owner,
        monitoring_slo_id=monitoring_slo_id,
        max_probe_latency_ms=max_probe_latency_ms,
        heartbeat_interval_seconds=heartbeat_interval_seconds,
        abort_path=abort_path,
        rollback_runbook_id=rollback_runbook_id,
    )
    boundary = _write_boundary_report(context=context, usage_scope_path=artifacts["usage_scope"], monitoring_path=artifacts["monitoring_rollback_binding"], output=artifacts["boundary_report"])
    reports = [context, usage_scope, monitoring, boundary]
    passed = all(report.get("passed") is True for report in reports)
    summary = {
        "schema_version": CHAIN_SCHEMA,
        "passed": passed,
        "failure_reasons": _failures(reports),
        "checked_at": _now(),
        "source_artifacts": {"post_h3u_summary": artifact_ref(post_h3u_summary_path)},
        "artifacts": {name: artifact_ref(path) for name, path in artifacts.items() if name != "summary"},
        "limited_external_usage_scope_binding_id": monitoring.get("limited_external_usage_scope_binding_id"),
        "external_user_handle": external_user_handle,
        "allowed_usage_scope": allowed_usage_scope,
        "max_external_users": max_external_users,
        "max_runtime_tasks": max_runtime_tasks,
        "readiness": {
            "state": "post_h3_limited_external_usage_scope_bound" if passed else "blocked_post_h3_limited_external_usage_scope_binding",
            "limited_external_usage_scope_bound": passed,
            "external_user_task_scope_bound": passed,
            "external_user_monitoring_slo_bound": passed,
            "external_user_rollback_abort_owner_bound": passed,
            "limited_usage_public_ingress_boundary_bound": passed,
            "limited_usage_runtime_expansion_boundary_bound": passed,
            "external_user_usage_authorization_review_ready": passed,
            "external_user_usage_allowed": False,
            "external_user_usage_execution_ready": False,
            "external_public_ingress_opened": False,
            "runtime_workers_currently_running": False,
            "runtime_execution_performed": False,
            "production_runtime_receipt_write_allowed": False,
        },
        "bounded_requirement_resolution": {
            "production_grade_public_ingress_required": False,
            "sustained_runtime_expansion_required": False,
            "external_user_task_scope_bound": passed,
            "external_user_monitoring_slo_bound": passed,
            "external_user_rollback_abort_owner_bound": passed,
        },
        "remaining_requirements": [] if passed else [
            "external_user_task_scope_not_bound",
            "external_user_monitoring_slo_not_bound",
            "external_user_rollback_abort_owner_not_bound",
        ],
        "boundary": _boundary(
            context_validation_written=context.get("passed") is True,
            usage_scope_written=usage_scope.get("passed") is True,
            monitoring_rollback_binding_written=monitoring.get("passed") is True,
            boundary_report_written=boundary.get("passed") is True,
            limited_external_usage_scope_bound=passed,
            external_user_usage_authorization_review_ready=passed,
        ),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(artifacts["summary"], summary)
    return summary


def validate_post_h3u_context(post_h3u_summary_path: Path, *, output: Path | None = None) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    try:
        summary = read_json_object(post_h3u_summary_path)
    except Exception as exc:  # noqa: BLE001
        return _write_optional(_report(CONTEXT_SCHEMA, False, [f"post_h3u_summary_unreadable:{exc}"], checks), output)
    artifacts = object_value(summary.get("artifacts"))
    consent_receipt = _read_verified_ref(artifacts.get("consent_receipt"), checks, failures, "post_h3u_consent_receipt")
    boundary_report = _read_verified_ref(artifacts.get("boundary_report"), checks, failures, "post_h3u_boundary_report")
    _check_u_summary(summary, checks, failures)
    _check_u_consent_receipt(consent_receipt, checks, failures)
    _check_u_boundary(boundary_report, checks, failures)
    passed = _passed(checks, failures)
    report = {
        "schema_version": CONTEXT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "post_h3u_summary": summary,
        "consent_receipt": consent_receipt,
        "boundary_report": boundary_report,
        "source_artifacts": {"post_h3u_summary": artifact_ref(post_h3u_summary_path)},
        "boundary": _boundary(context_validation_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    return _write_optional(report, output)


def _write_usage_scope(
    *,
    context: dict[str, Any],
    post_h3u_summary_path: Path,
    output: Path,
    operator_id: str,
    external_user_handle: str,
    allowed_usage_scope: str,
    max_external_users: int,
    max_runtime_tasks: int,
    max_usage_seconds: int,
    public_ingress_mode: str,
    runtime_expansion_mode: str,
    ack_limited_usage_scope_binding: bool,
) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    u_summary = object_value(context.get("post_h3u_summary"))
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "operator_id_present", bool(operator_id.strip()))
    check(checks, failures, "external_user_handle_matches_u", external_user_handle == u_summary.get("external_user_handle"))
    check(checks, failures, "allowed_usage_scope_bounded", allowed_usage_scope == ALLOWED_USAGE_SCOPE)
    check(checks, failures, "max_external_users_one", max_external_users == 1)
    check(checks, failures, "max_runtime_tasks_one", max_runtime_tasks == 1)
    check(checks, failures, "max_usage_seconds_bounded", 1 <= max_usage_seconds <= 1800)
    check(checks, failures, "public_ingress_mode_limited", public_ingress_mode == ALLOWED_PUBLIC_INGRESS_MODE)
    check(checks, failures, "runtime_expansion_mode_limited", runtime_expansion_mode == ALLOWED_RUNTIME_EXPANSION_MODE)
    check(checks, failures, "explicit_operator_ack", ack_limited_usage_scope_binding is True)
    passed = _passed(checks, failures)
    report = {
        "schema_version": USAGE_SCOPE_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "written_at": _now(),
        "usage_scope_id": f"post-h3v-usage-scope:{sha256_json([artifact_ref(post_h3u_summary_path), operator_id, external_user_handle, allowed_usage_scope, max_external_users, max_runtime_tasks, max_usage_seconds])[:24]}",
        "operator_id": operator_id,
        "external_user_handle": external_user_handle,
        "allowed_usage_scope": allowed_usage_scope,
        "max_external_users": max_external_users,
        "max_runtime_tasks": max_runtime_tasks,
        "max_usage_seconds": max_usage_seconds,
        "public_ingress_mode": public_ingress_mode,
        "runtime_expansion_mode": runtime_expansion_mode,
        "production_grade_public_ingress_required": False,
        "sustained_runtime_expansion_required": False,
        "forbidden_actions": [
            "production_data_access",
            "source_tree_write",
            "git_write",
            "deploy",
            "unbounded_public_ingress",
            "sustained_runtime_expansion",
            "multiple_external_users",
            "multiple_runtime_tasks",
        ],
        "ack_limited_usage_scope_binding": ack_limited_usage_scope_binding,
        "source_artifacts": {"post_h3u_summary": artifact_ref(post_h3u_summary_path)},
        "readiness": {
            "external_user_task_scope_bound": passed,
            "limited_usage_public_ingress_boundary_bound": passed,
            "limited_usage_runtime_expansion_boundary_bound": passed,
            "external_user_usage_allowed": False,
        },
        "boundary": _boundary(usage_scope_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def _write_monitoring_rollback_binding(
    *,
    usage_scope_path: Path,
    output: Path,
    monitoring_owner: str,
    audit_owner: str,
    rollback_owner: str,
    monitoring_slo_id: str,
    max_probe_latency_ms: int,
    heartbeat_interval_seconds: int,
    abort_path: str,
    rollback_runbook_id: str,
) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    usage_scope = read_json_object(usage_scope_path)
    check(checks, failures, "usage_scope_passed", usage_scope.get("schema_version") == USAGE_SCOPE_SCHEMA and usage_scope.get("passed") is True)
    check(checks, failures, "monitoring_owner_present", bool(monitoring_owner.strip()))
    check(checks, failures, "audit_owner_present", bool(audit_owner.strip()))
    check(checks, failures, "rollback_owner_present", bool(rollback_owner.strip()))
    check(checks, failures, "distinct_monitoring_and_audit", monitoring_owner != audit_owner)
    check(checks, failures, "monitoring_slo_id_present", bool(monitoring_slo_id.strip()))
    check(checks, failures, "max_probe_latency_ms_bounded", 1 <= max_probe_latency_ms <= 5000)
    check(checks, failures, "heartbeat_interval_seconds_bounded", 5 <= heartbeat_interval_seconds <= 60)
    check(checks, failures, "abort_path_present", bool(abort_path.strip()))
    check(checks, failures, "rollback_runbook_id_present", bool(rollback_runbook_id.strip()))
    passed = _passed(checks, failures)
    report = {
        "schema_version": MONITORING_ROLLBACK_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "written_at": _now(),
        "limited_external_usage_scope_binding_id": f"post-h3v-binding:{sha256_json([artifact_ref(usage_scope_path), monitoring_owner, audit_owner, rollback_owner, monitoring_slo_id, rollback_runbook_id])[:24]}",
        "monitoring_owner": monitoring_owner,
        "audit_owner": audit_owner,
        "rollback_owner": rollback_owner,
        "monitoring_slo": {
            "monitoring_slo_id": monitoring_slo_id,
            "max_probe_latency_ms": max_probe_latency_ms,
            "heartbeat_interval_seconds": heartbeat_interval_seconds,
            "required_events": ["usage_start", "probe_result", "usage_stop_or_abort", "operator_closeout"],
        },
        "abort_path": abort_path,
        "rollback_runbook_id": rollback_runbook_id,
        "source_artifacts": {"usage_scope": artifact_ref(usage_scope_path)},
        "readiness": {
            "external_user_monitoring_slo_bound": passed,
            "external_user_rollback_abort_owner_bound": passed,
            "external_user_usage_authorization_review_ready": passed,
            "external_user_usage_allowed": False,
        },
        "boundary": _boundary(monitoring_rollback_binding_written=passed, external_user_usage_authorization_review_ready=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def _write_boundary_report(*, context: dict[str, Any], usage_scope_path: Path, monitoring_path: Path, output: Path) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    usage_scope = read_json_object(usage_scope_path)
    monitoring = read_json_object(monitoring_path)
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "usage_scope_passed", usage_scope.get("passed") is True)
    check(checks, failures, "monitoring_binding_passed", monitoring.get("passed") is True)
    check(checks, failures, "production_ingress_not_required", usage_scope.get("production_grade_public_ingress_required") is False)
    check(checks, failures, "sustained_runtime_not_required", usage_scope.get("sustained_runtime_expansion_required") is False)
    passed = _passed(checks, failures)
    report = {
        "schema_version": BOUNDARY_REPORT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "source_artifacts": {"usage_scope": artifact_ref(usage_scope_path), "monitoring_rollback_binding": artifact_ref(monitoring_path)},
        "boundary": _boundary(
            boundary_report_written=passed,
            limited_external_usage_scope_bound=passed,
            external_user_usage_authorization_review_ready=passed,
        ),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def _check_u_summary(summary: dict[str, Any], checks: dict[str, bool], failures: list[str]) -> None:
    readiness = object_value(summary.get("readiness"))
    check(checks, failures, "post_h3u_schema_valid", summary.get("schema_version") == POST_H3U_SCHEMA)
    check(checks, failures, "post_h3u_passed", summary.get("passed") is True)
    check(checks, failures, "u_identity_consent_bound", readiness.get("external_user_identity_and_consent_bound") is True)
    check(checks, failures, "u_review_rerun_ready", readiness.get("external_user_usage_review_rerun_ready") is True)
    check(checks, failures, "u_usage_not_allowed", readiness.get("external_user_usage_allowed") is False)


def _check_u_consent_receipt(receipt: dict[str, Any], checks: dict[str, bool], failures: list[str]) -> None:
    readiness = object_value(receipt.get("readiness"))
    check(checks, failures, "u_consent_receipt_schema_valid", receipt.get("schema_version") == POST_H3U_CONSENT_RECEIPT_SCHEMA)
    check(checks, failures, "u_consent_receipt_passed", receipt.get("passed") is True)
    check(checks, failures, "u_consent_bound", readiness.get("external_user_identity_and_consent_bound") is True)


def _check_u_boundary(report: dict[str, Any], checks: dict[str, bool], failures: list[str]) -> None:
    boundary = object_value(report.get("boundary"))
    check(checks, failures, "u_boundary_passed", report.get("passed") is True)
    for key in ("external_user_usage_allowed", "external_public_ingress_opened", "runtime_workers_currently_running", "runtime_execution_performed", "vm_contact_performed", "deploy_performed", "production_data_accessed", "source_tree_write_performed", "git_write_performed"):
        check(checks, failures, f"u_boundary_no_{key}", boundary.get(key) is False)


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
        "usage_scope_written": False,
        "monitoring_rollback_binding_written": False,
        "boundary_report_written": False,
        "limited_external_usage_scope_bound": False,
        "external_user_usage_authorization_review_ready": False,
        "external_user_usage_allowed": False,
        "external_public_ingress_opened": False,
        "runtime_workers_currently_running": False,
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
    parser = argparse.ArgumentParser(description="Run PostH3-V limited external usage scope binding gate")
    parser.add_argument("--post-h3u-summary", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--operator-id", default="operator-primary")
    parser.add_argument("--external-user-handle", default="Thneoly")
    parser.add_argument("--allowed-usage-scope", default=ALLOWED_USAGE_SCOPE)
    parser.add_argument("--max-external-users", default=1, type=int)
    parser.add_argument("--max-runtime-tasks", default=1, type=int)
    parser.add_argument("--max-usage-seconds", default=600, type=int)
    parser.add_argument("--public-ingress-mode", default=ALLOWED_PUBLIC_INGRESS_MODE)
    parser.add_argument("--runtime-expansion-mode", default=ALLOWED_RUNTIME_EXPANSION_MODE)
    parser.add_argument("--monitoring-owner", default="monitoring_owner")
    parser.add_argument("--audit-owner", default="audit_owner")
    parser.add_argument("--rollback-owner", default="rollback_owner")
    parser.add_argument("--monitoring-slo-id", default="post-h3-limited-external-usage-slo:v1")
    parser.add_argument("--max-probe-latency-ms", default=2000, type=int)
    parser.add_argument("--heartbeat-interval-seconds", default=30, type=int)
    parser.add_argument("--abort-path", default="operator abort command writes abort receipt and closes ingress/workers")
    parser.add_argument("--rollback-runbook-id", default="post-h3-limited-external-usage-rollback:v1")
    parser.add_argument("--ack-limited-usage-scope-binding", action="store_true")
    args = parser.parse_args()
    summary = run_gate(
        post_h3u_summary_path=args.post_h3u_summary,
        output_root=args.output_root,
        operator_id=args.operator_id,
        external_user_handle=args.external_user_handle,
        allowed_usage_scope=args.allowed_usage_scope,
        max_external_users=args.max_external_users,
        max_runtime_tasks=args.max_runtime_tasks,
        max_usage_seconds=args.max_usage_seconds,
        public_ingress_mode=args.public_ingress_mode,
        runtime_expansion_mode=args.runtime_expansion_mode,
        monitoring_owner=args.monitoring_owner,
        audit_owner=args.audit_owner,
        rollback_owner=args.rollback_owner,
        monitoring_slo_id=args.monitoring_slo_id,
        max_probe_latency_ms=args.max_probe_latency_ms,
        heartbeat_interval_seconds=args.heartbeat_interval_seconds,
        abort_path=args.abort_path,
        rollback_runbook_id=args.rollback_runbook_id,
        ack_limited_usage_scope_binding=args.ack_limited_usage_scope_binding,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if summary.get("passed") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
