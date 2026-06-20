"""Run P0-C controlled execution authorization gate.

P0-C consumes a passed P0-B Agent proposal summary and records the evidence
needed to authorize one future controlled task-pool execution. It generates a
bounded execution spec, validates the scoped service-token surface, performs a
local rollback dry-run marker probe, and writes a one-time authorization
receipt. It does not post tasks, start agents, contact VMs, deploy, mutate
runtime state, or write production receipts.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
from pathlib import Path
from typing import Any

from benchmarks.i_gate_evidence import artifact_ref, check, object_value, read_json_object, sha256_file, write_json_object

CHAIN_SCHEMA = "p0c-controlled-execution-authorization-chain:v1"
BOUNDED_SPEC_SCHEMA = "p0c-bounded-execution-spec:v1"
SERVICE_PREFLIGHT_SCHEMA = "p0c-service-token-preflight:v1"
ROLLBACK_DRY_RUN_SCHEMA = "p0c-rollback-dry-run-receipt:v1"
AUTHORIZATION_SCHEMA = "p0c-one-time-controlled-execution-authorization:v1"
P0B_SCHEMA = "p0b-agent-proposal-chain:v1"
P0B_RECONCILIATION_SCHEMA = "p0b-operator-reconciliation:v1"
P0A_SCHEMA = "p0a-task-intake-chain:v1"
P0A_INTAKE_RECEIPT_SCHEMA = "p0a-task-intake-receipt:v1"

REQUIRED_EXECUTION_SCOPES = {
    "agents:read",
    "agents:write",
    "audit:read",
    "pool:claim",
    "pool:post",
    "pool:read",
    "pool:write",
    "webhooks:write",
}

FORBIDDEN_SCOPE_FRAGMENTS = (
    "*",
    "admin",
    "root",
    "production",
    "prod",
    "deploy",
    "secret",
    "secrets",
    "wallet",
    "payment",
    "git",
    "merge",
)


def run_gate(
    *,
    p0b_summary_path: Path,
    output_root: Path,
    service_token_env_file: Path | None = None,
    service_token_scopes: list[str] | None = None,
    operator_id: str = "operator-cc",
    max_duration_seconds: int = 900,
) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "bounded_execution_spec": output_root / "p0c_bounded_execution_spec.json",
        "service_token_preflight": output_root / "p0c_service_token_preflight.json",
        "rollback_dry_run": output_root / "p0c_rollback_dry_run_receipt.json",
        "authorization": output_root / "p0c_one_time_controlled_execution_authorization.json",
        "summary": output_root / "p0c_controlled_execution_authorization_chain_summary.json",
    }
    context = _validate_p0b_summary(p0b_summary_path)
    spec = write_bounded_execution_spec(
        p0b_summary_path=p0b_summary_path,
        context=context,
        output=artifacts["bounded_execution_spec"],
        max_duration_seconds=max_duration_seconds,
    )
    preflight = write_service_token_preflight(
        bounded_spec_path=artifacts["bounded_execution_spec"],
        service_token_env_file=service_token_env_file,
        requested_scopes=service_token_scopes,
        output=artifacts["service_token_preflight"],
    )
    rollback = write_rollback_dry_run(
        bounded_spec_path=artifacts["bounded_execution_spec"],
        output=artifacts["rollback_dry_run"],
        workspace=output_root / "rollback_dry_run_workspace",
    )
    authorization = write_authorization(
        bounded_spec_path=artifacts["bounded_execution_spec"],
        service_token_preflight_path=artifacts["service_token_preflight"],
        rollback_dry_run_path=artifacts["rollback_dry_run"],
        output=artifacts["authorization"],
        operator_id=operator_id,
    )
    reports = [spec, preflight, rollback, authorization]
    passed = all(report.get("passed") is True for report in reports)
    summary = {
        "schema_version": CHAIN_SCHEMA,
        "passed": passed,
        "failure_reasons": _collect_failures(*reports),
        "source_artifacts": {"p0b_summary": artifact_ref(p0b_summary_path)},
        "artifacts": {name: artifact_ref(path) for name, path in artifacts.items() if name != "summary"},
        "selected_task": object_value(context.get("p0a_summary")).get("selected_task", {}),
        "readiness": {
            "state": "p0c_controlled_execution_authorized" if passed else "blocked_p0c_controlled_execution_authorization",
            "p0c_one_time_controlled_execution_authorized": passed,
            "p0c_execution_performed": False,
            "p0d_preview_smoke_ready": False,
            "production_transition_allowed": False,
        },
        "boundary": _boundary(
            bounded_execution_spec_recording_allowed=True,
            service_token_preflight_recording_allowed=True,
            rollback_dry_run_recording_allowed=True,
            authorization_recording_allowed=True,
            one_time_controlled_task_pool_execution_authorized=passed,
        ),
        "non_claims": [
            "p0c_authorization_does_not_post_task",
            "p0c_authorization_does_not_start_agent",
            "p0c_authorization_does_not_contact_vms",
            "p0c_authorization_does_not_deploy",
            "p0c_authorization_does_not_mutate_runtime_state",
            "p0c_authorization_does_not_write_production_receipt",
        ],
    }
    write_json_object(artifacts["summary"], summary)
    return summary


def write_bounded_execution_spec(*, p0b_summary_path: Path, context: dict[str, Any], output: Path, max_duration_seconds: int) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    p0b = object_value(context.get("p0b_summary"))
    p0a = object_value(context.get("p0a_summary"))
    task_intake = object_value(context.get("task_intake_receipt")).get("task_intake", {})
    selected_task = object_value(p0a.get("selected_task"))
    p0b_ready = object_value(p0b.get("readiness"))
    check(checks, failures, "p0b_context_valid", context.get("passed") is True)
    check(checks, failures, "p0b_authorization_request_ready", p0b_ready.get("p0c_authorization_request_ready") is True)
    check(checks, failures, "max_duration_within_limit", 60 <= max_duration_seconds <= 1800)
    check(checks, failures, "selected_task_present", bool(selected_task.get("task_id")))
    allowed_scopes = selected_task.get("service_token_scopes") if isinstance(selected_task.get("service_token_scopes"), list) else []
    check(checks, failures, "service_scopes_present", REQUIRED_EXECUTION_SCOPES.issubset(set(str(item) for item in allowed_scopes)))
    passed = _all_checks(checks, failures)
    spec = {
        "schema_version": BOUNDED_SPEC_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "source_artifacts": {"p0b_summary": artifact_ref(p0b_summary_path)},
        "execution_spec": {
            "spec_id": "p0c-spec:pilot-status-evidence-index-preview:v1",
            "task_id": selected_task.get("task_id"),
            "title": selected_task.get("title"),
            "mode": "one_time_controlled_task_pool_execution_authorization_only",
            "max_tasks": 1,
            "max_agents": 1,
            "max_duration_seconds": max_duration_seconds,
            "allowed_next_action": "single_task_pool_execution_after_operator_ack",
            "allowed_actions_after_authorization": [
                "pool:post_one_task",
                "pool:claim_by_authorized_runner",
                "generate_preview_under_pilot_run_root",
                "pool:complete_or_fail_once",
                "write_execution_receipt_under_pilot_run_root",
            ],
            "allowed_systems": task_intake.get("allowed_systems", []),
            "allowed_files": task_intake.get("allowed_files", []),
            "allowed_vm_targets": task_intake.get("vm_targets", []),
            "allowed_service_token_scopes": allowed_scopes,
            "forbidden_operations": task_intake.get("forbidden_operations", []),
            "rollback_command": object_value(task_intake.get("rollback")).get("command"),
            "execution_output_required": [
                "task_pool_execution_receipt",
                "preview_artifact_ref",
                "no_production_attestation",
                "rollback_or_abort_ref",
            ],
        },
        "readiness": {
            "state": "p0c_bounded_execution_spec_ready" if passed else "blocked_p0c_bounded_execution_spec",
            "service_token_preflight_ready": passed,
            "execution_performed": False,
        },
        "boundary": _boundary(bounded_execution_spec_recording_allowed=True),
    }
    write_json_object(output, spec)
    return spec


def write_service_token_preflight(*, bounded_spec_path: Path, service_token_env_file: Path | None, requested_scopes: list[str] | None, output: Path) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    spec = read_json_object(bounded_spec_path)
    execution_spec = object_value(spec.get("execution_spec"))
    allowed_scopes = _strings(execution_spec.get("allowed_service_token_scopes"))
    scopes = requested_scopes or allowed_scopes
    env = _read_env_file(service_token_env_file) if service_token_env_file else {}
    secret_present = bool(env.get("CIVITASOS_SERVICE_TOKEN_SECRET") or os.getenv("CIVITASOS_SERVICE_TOKEN_SECRET"))
    check(checks, failures, "bounded_spec_passed", spec.get("schema_version") == BOUNDED_SPEC_SCHEMA and spec.get("passed") is True)
    check(checks, failures, "service_token_secret_present", secret_present)
    check(checks, failures, "secret_not_recorded", True)
    check(checks, failures, "scopes_present", bool(scopes))
    check(checks, failures, "scopes_match_allowed_scope", sorted(scopes) == sorted(allowed_scopes))
    check(checks, failures, "required_execution_scopes_present", REQUIRED_EXECUTION_SCOPES.issubset(set(scopes)))
    check(checks, failures, "no_forbidden_scope", _scopes_have_no_forbidden_tokens(scopes))
    passed = _all_checks(checks, failures)
    report = {
        "schema_version": SERVICE_PREFLIGHT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "source_artifacts": {"bounded_execution_spec": artifact_ref(bounded_spec_path)},
        "service_token_preflight": {
            "mode": "scope_and_secret_presence_only_no_token_issuance",
            "env_file": str(service_token_env_file.resolve()) if service_token_env_file else None,
            "secret_present": secret_present,
            "secret_recorded": False,
            "secret_sha256_recorded": False,
            "requested_scopes": scopes,
            "production_allowed": False,
            "evidence_allowed": False,
            "demo_login_allowed": False,
            "token_issued": False,
        },
        "readiness": {
            "state": "p0c_service_token_preflight_passed" if passed else "blocked_p0c_service_token_preflight",
            "rollback_dry_run_ready": passed,
            "execution_performed": False,
        },
        "boundary": _boundary(service_token_preflight_recording_allowed=True),
    }
    write_json_object(output, report)
    return report


def write_rollback_dry_run(*, bounded_spec_path: Path, output: Path, workspace: Path) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    spec = read_json_object(bounded_spec_path)
    execution_spec = object_value(spec.get("execution_spec"))
    if workspace.exists():
        shutil.rmtree(workspace)
    workspace.mkdir(parents=True, exist_ok=True)
    marker = workspace / "p0c_rollback_probe.marker"
    marker.write_text("p0c rollback dry run marker\n", encoding="utf-8")
    marker_created = marker.is_file()
    marker.unlink(missing_ok=True)
    marker_removed = not marker.exists()
    shutil.rmtree(workspace, ignore_errors=True)
    workspace_removed = not workspace.exists()
    check(checks, failures, "bounded_spec_passed", spec.get("schema_version") == BOUNDED_SPEC_SCHEMA and spec.get("passed") is True)
    check(checks, failures, "rollback_command_present", bool(_text(execution_spec.get("rollback_command"))))
    check(checks, failures, "dry_run_marker_created", marker_created)
    check(checks, failures, "dry_run_marker_removed", marker_removed)
    check(checks, failures, "dry_run_workspace_removed", workspace_removed)
    passed = _all_checks(checks, failures)
    report = {
        "schema_version": ROLLBACK_DRY_RUN_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "source_artifacts": {"bounded_execution_spec": artifact_ref(bounded_spec_path)},
        "rollback_dry_run": {
            "mode": "local_marker_probe_only_no_vm_no_runtime",
            "rollback_command": execution_spec.get("rollback_command"),
            "workspace": str(workspace.resolve()),
            "marker_created": marker_created,
            "marker_removed": marker_removed,
            "workspace_removed": workspace_removed,
            "vm_contacted": False,
            "runtime_mutated": False,
        },
        "readiness": {
            "state": "p0c_rollback_dry_run_passed" if passed else "blocked_p0c_rollback_dry_run",
            "authorization_ready": passed,
            "execution_performed": False,
        },
        "boundary": _boundary(rollback_dry_run_recording_allowed=True),
    }
    write_json_object(output, report)
    return report


def write_authorization(*, bounded_spec_path: Path, service_token_preflight_path: Path, rollback_dry_run_path: Path, output: Path, operator_id: str) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    spec = read_json_object(bounded_spec_path)
    preflight = read_json_object(service_token_preflight_path)
    rollback = read_json_object(rollback_dry_run_path)
    execution_spec = object_value(spec.get("execution_spec"))
    service = object_value(preflight.get("service_token_preflight"))
    check(checks, failures, "bounded_spec_passed", spec.get("schema_version") == BOUNDED_SPEC_SCHEMA and spec.get("passed") is True)
    check(checks, failures, "service_token_preflight_passed", preflight.get("schema_version") == SERVICE_PREFLIGHT_SCHEMA and preflight.get("passed") is True)
    check(checks, failures, "rollback_dry_run_passed", rollback.get("schema_version") == ROLLBACK_DRY_RUN_SCHEMA and rollback.get("passed") is True)
    check(checks, failures, "operator_id_present", bool(_text(operator_id)))
    check(checks, failures, "no_token_issued_by_preflight", service.get("token_issued") is False)
    check(checks, failures, "production_closed", service.get("production_allowed") is False and service.get("demo_login_allowed") is False)
    passed = _all_checks(checks, failures)
    report = {
        "schema_version": AUTHORIZATION_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "source_artifacts": {
            "bounded_execution_spec": artifact_ref(bounded_spec_path),
            "service_token_preflight": artifact_ref(service_token_preflight_path),
            "rollback_dry_run": artifact_ref(rollback_dry_run_path),
        },
        "authorization": {
            "operator_id": operator_id,
            "decision": "authorize_one_time_p0c_controlled_execution" if passed else "blocked_p0c_authorization",
            "scope": "one_time_controlled_task_pool_execution_only",
            "task_id": execution_spec.get("task_id"),
            "max_tasks": execution_spec.get("max_tasks"),
            "max_agents": execution_spec.get("max_agents"),
            "max_duration_seconds": execution_spec.get("max_duration_seconds"),
            "authorized_service_token_scopes": service.get("requested_scopes", []),
            "execution_performed": False,
            "expires_after_use": True,
        },
        "readiness": {
            "state": "p0c_one_time_execution_authorized" if passed else "blocked_p0c_authorization",
            "one_time_controlled_execution_authorized": passed,
            "execution_performed": False,
            "p0d_preview_smoke_ready": False,
            "production_transition_allowed": False,
        },
        "boundary": _boundary(
            authorization_recording_allowed=True,
            one_time_controlled_task_pool_execution_authorized=passed,
        ),
    }
    write_json_object(output, report)
    return report


def _validate_p0b_summary(path: Path) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    p0b = read_json_object(path)
    p0b_artifacts = object_value(p0b.get("artifacts"))
    reconciliation = _read_verified_ref(p0b_artifacts.get("operator_reconciliation"), checks, failures, "p0b.reconciliation")
    for index, ref in enumerate(p0b_artifacts.get("agent_responses", []) if isinstance(p0b_artifacts.get("agent_responses"), list) else []):
        _read_verified_ref(ref, checks, failures, f"p0b.agent_response_{index}")
    p0a = _read_verified_ref(object_value(p0b.get("source_artifacts")).get("p0a_summary"), checks, failures, "p0b.source_p0a")
    task_intake = _read_verified_ref(object_value(p0a.get("artifacts")).get("task_intake_receipt"), checks, failures, "p0a.task_intake") if p0a else {}
    p0b_ready = object_value(p0b.get("readiness"))
    p0b_boundary = object_value(p0b.get("boundary"))
    p0a_ready = object_value(p0a.get("readiness"))
    check(checks, failures, "p0b_summary_passed", p0b.get("schema_version") == P0B_SCHEMA and p0b.get("passed") is True)
    check(checks, failures, "p0b_reconciliation_ready", reconciliation.get("schema_version") == P0B_RECONCILIATION_SCHEMA and reconciliation.get("passed") is True)
    check(checks, failures, "p0b_ready_for_p0c", p0b_ready.get("p0c_authorization_request_ready") is True)
    check(checks, failures, "p0b_execution_closed", p0b_ready.get("p0c_execution_allowed") is False)
    check(checks, failures, "p0b_boundary_closed", p0b_boundary.get("vm_contact_allowed") is False and p0b_boundary.get("deploy_allowed") is False)
    check(checks, failures, "p0a_summary_passed", p0a.get("schema_version") == P0A_SCHEMA and p0a.get("passed") is True)
    check(checks, failures, "p0a_execution_closed", p0a_ready.get("p0c_execution_allowed") is False)
    check(checks, failures, "p0a_task_intake_passed", task_intake.get("schema_version") == P0A_INTAKE_RECEIPT_SCHEMA and task_intake.get("passed") is True)
    return {
        "passed": _all_checks(checks, failures),
        "failure_reasons": failures,
        "checks": checks,
        "p0b_summary": p0b,
        "p0b_reconciliation": reconciliation,
        "p0a_summary": p0a,
        "task_intake_receipt": task_intake,
    }


def _read_verified_ref(value: Any, checks: dict[str, bool], failures: list[str], label: str) -> dict[str, Any]:
    ref = object_value(value)
    path = Path(str(ref.get("path") or ""))
    expected_hash = str(ref.get("sha256") or "")
    check(checks, failures, f"{label}_artifact_path_present", path.is_file())
    if not path.is_file():
        return {}
    check(checks, failures, f"{label}_artifact_hash_valid", expected_hash == sha256_file(path) and bool(expected_hash))
    return read_json_object(path)


def _read_env_file(path: Path | None) -> dict[str, str]:
    if path is None or not path.is_file():
        return {}
    env: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        env[key.strip()] = value.strip().strip('"').strip("'")
    return env


def _scopes_have_no_forbidden_tokens(scopes: list[str]) -> bool:
    for scope in scopes:
        compact = scope.strip().lower()
        if compact == "*" or compact.endswith(":*"):
            return False
        if any(fragment in compact for fragment in FORBIDDEN_SCOPE_FRAGMENTS):
            return False
    return True


def _boundary(**overrides: bool) -> dict[str, bool]:
    base = {
        "bounded_execution_spec_recording_allowed": False,
        "service_token_preflight_recording_allowed": False,
        "rollback_dry_run_recording_allowed": False,
        "authorization_recording_allowed": False,
        "one_time_controlled_task_pool_execution_authorized": False,
        "task_pool_post_performed": False,
        "agent_started": False,
        "vm_contact_performed": False,
        "source_tree_write_performed": False,
        "git_write_performed": False,
        "deploy_performed": False,
        "runtime_state_mutation_performed": False,
        "production_transition_allowed": False,
        "production_receipt_write_allowed": False,
    }
    base.update(overrides)
    return base


def _collect_failures(*reports: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    for report in reports:
        failures.extend(str(item) for item in report.get("failure_reasons", []))
    return sorted(set(failures))


def _all_checks(checks: dict[str, bool], failures: list[str]) -> bool:
    return bool(checks) and all(checks.values()) and not failures


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    if not isinstance(value, list):
        return []
    return [str(item).strip() for item in value if str(item).strip()]


def _text(value: Any) -> str:
    return str(value or "").strip()


def main() -> int:
    parser = argparse.ArgumentParser(description="Run P0-C controlled execution authorization gate")
    parser.add_argument("--p0b-summary", required=True)
    parser.add_argument("--output-root", required=True)
    parser.add_argument("--service-token-env-file")
    parser.add_argument("--service-token-scope", action="append", default=[])
    parser.add_argument("--operator-id", default="operator-cc")
    parser.add_argument("--max-duration-seconds", type=int, default=900)
    args = parser.parse_args()
    summary = run_gate(
        p0b_summary_path=Path(args.p0b_summary),
        output_root=Path(args.output_root),
        service_token_env_file=Path(args.service_token_env_file) if args.service_token_env_file else None,
        service_token_scopes=args.service_token_scope or None,
        operator_id=args.operator_id,
        max_duration_seconds=args.max_duration_seconds,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if summary.get("passed") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
