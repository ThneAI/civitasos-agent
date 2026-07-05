"""PostH3 minimal production task intake gate.

This gate consumes the PostH3 readiness index and records one bounded,
low-risk production task intake packet. It does not authorize or execute the
task. The next stage must consume this summary through a separate single-use
authorization gate.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from benchmarks.i_gate_evidence import artifact_ref, check, object_value, read_json_object, sha256_file, sha256_json, write_json_object
from benchmarks.post_h3_readiness_index import SCHEMA_VERSION as POST_H3_READINESS_INDEX_SCHEMA

CHAIN_SCHEMA = "post-h3-minimal-production-task-intake-chain:v1"
CONTEXT_SCHEMA = "post-h3-minimal-production-task-intake-context-validation:v1"
INTAKE_PACKET_SCHEMA = "post-h3-minimal-production-task-intake-packet:v1"
RISK_BOUNDARY_SCHEMA = "post-h3-minimal-production-task-risk-boundary:v1"
ROLLBACK_RUNBOOK_SCHEMA = "post-h3-minimal-production-task-rollback-runbook:v1"

ALLOWED_TASK_CLASSES = {
    "read_only_status_evidence_index",
    "observer_evidence_review",
    "bounded_internal_report_generation",
    "low_risk_monitoring_snapshot",
}
ALLOWED_RISK_CLASSES = {"low"}
REQUIRED_SERVICE_TOKEN_SCOPES = {"pool:post", "pool:read", "pool:claim", "pool:write", "audit:read"}
ALLOWED_SERVICE_TOKEN_SCOPES = REQUIRED_SERVICE_TOKEN_SCOPES | {"outcomes:read", "webhooks:read"}
FORBIDDEN_SCOPE_TOKENS = ("*", "admin", "root", "secret", "secrets", "wallet", "payment", "deploy", "git", "merge", "public_ingress")
REQUIRED_FORBIDDEN_ACTIONS = {
    "public_ingress",
    "production_data_access",
    "deploy",
    "source_tree_write",
    "git_write",
    "production_runtime_receipt_write",
    "unscoped_external_mutation",
}
NON_CLAIMS = (
    "minimal_production_task_intake_does_not_authorize_execution",
    "minimal_production_task_intake_does_not_execute_runtime_task",
    "minimal_production_task_intake_does_not_open_public_ingress",
    "minimal_production_task_intake_does_not_deploy",
    "minimal_production_task_intake_does_not_access_production_data",
    "minimal_production_task_intake_does_not_write_production_runtime_receipts",
    "minimal_production_task_intake_does_not_write_source_or_git",
)

DEFAULT_TASK_REQUEST: dict[str, Any] = {
    "task_id": "post-h3-task:minimal-production-status-evidence-index-001",
    "title": "Generate minimal production status/evidence index packet",
    "task_class": "read_only_status_evidence_index",
    "risk_class": "low",
    "owner_id": "product_owner",
    "operator_id": "operator-primary",
    "audit_owner_id": "audit_owner",
    "rollback_owner_id": "rollback_owner",
    "monitoring_owner_id": "observability_owner",
    "scope": {
        "max_runtime_tasks": 1,
        "max_external_users": 0,
        "allowed_systems": ["civitasos task pool", "posth3 evidence run-root"],
        "allowed_outputs": ["owner-readable status/evidence index", "monitoring snapshot"],
        "service_token_scopes": sorted(REQUIRED_SERVICE_TOKEN_SCOPES | {"outcomes:read"}),
        "forbidden_actions": sorted(REQUIRED_FORBIDDEN_ACTIONS),
    },
    "rollback": {
        "owner_id": "rollback_owner",
        "strategy": "abort_or_noop_before_any_external_side_effect",
        "runbook": "If execution output violates scope, mark authorization consumed, abort delivery, retain receipts, and keep public ingress/runtime expansion closed.",
    },
    "success_criteria": [
        "one bounded status/evidence index packet is generated",
        "all output is hash-bound to intake and authorization artifacts",
        "no production data, public ingress, deploy, Git, source write, or production runtime receipt write occurs",
    ],
}


def run_gate(*, readiness_index_path: Path, output_root: Path, task_request_path: Path | None = None) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "context_validation": output_root / "post_h3_minimal_task_intake_context_validation.json",
        "intake_packet": output_root / "post_h3_minimal_task_intake_packet.json",
        "risk_boundary": output_root / "post_h3_minimal_task_risk_boundary.json",
        "rollback_runbook": output_root / "post_h3_minimal_task_rollback_runbook.json",
        "summary": output_root / "post_h3_minimal_task_intake_summary.json",
    }
    task_request = _load_task_request(task_request_path)
    context = validate_readiness_index(readiness_index_path, output=artifacts["context_validation"])
    intake = _write_intake_packet(context=context, task_request=task_request, readiness_index_path=readiness_index_path, output=artifacts["intake_packet"])
    risk = _write_risk_boundary(intake_packet_path=artifacts["intake_packet"], output=artifacts["risk_boundary"])
    rollback = _write_rollback_runbook(intake_packet_path=artifacts["intake_packet"], risk_boundary_path=artifacts["risk_boundary"], output=artifacts["rollback_runbook"])
    reports = [context, intake, risk, rollback]
    passed = all(report.get("passed") is True for report in reports)
    summary = {
        "schema_version": CHAIN_SCHEMA,
        "passed": passed,
        "failure_reasons": _failures(reports),
        "checked_at": _now(),
        "task_id": task_request.get("task_id"),
        "task_class": task_request.get("task_class"),
        "risk_class": task_request.get("risk_class"),
        "owners": {
            "owner_id": task_request.get("owner_id"),
            "operator_id": task_request.get("operator_id"),
            "audit_owner_id": task_request.get("audit_owner_id"),
            "rollback_owner_id": task_request.get("rollback_owner_id"),
            "monitoring_owner_id": task_request.get("monitoring_owner_id"),
        },
        "source_artifacts": {"post_h3_readiness_index": artifact_ref(readiness_index_path)},
        "artifacts": {name: artifact_ref(path) for name, path in artifacts.items() if name != "summary"},
        "readiness": {
            "state": "post_h3_minimal_production_task_intake_ready" if passed else "blocked_post_h3_minimal_production_task_intake",
            "minimal_production_task_intake_ready": passed,
            "authorization_gate_input_ready": passed,
            "production_task_execution_allowed": False,
            "next_single_use_gate_input_ready": passed,
            "artifact_only": True,
        },
        "boundary": _closed_boundary(
            context_validation_written=context.get("passed") is True,
            intake_packet_written=intake.get("passed") is True,
            risk_boundary_written=risk.get("passed") is True,
            rollback_runbook_written=rollback.get("passed") is True,
        ),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(artifacts["summary"], summary)
    return summary


def validate_readiness_index(readiness_index_path: Path, *, output: Path | None = None) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    try:
        index = read_json_object(readiness_index_path)
    except Exception as exc:  # noqa: BLE001
        return _write_optional(_report(CONTEXT_SCHEMA, False, [f"readiness_index_unreadable:{exc}"], checks), output)
    readiness = object_value(index.get("readiness"))
    boundary = object_value(index.get("boundary"))
    check(checks, failures, "readiness_index_schema", index.get("schema_version") == POST_H3_READINESS_INDEX_SCHEMA)
    check(checks, failures, "readiness_index_passed", index.get("passed") is True)
    check(checks, failures, "observer_mode_ready", readiness.get("post_h3_observer_mode_ready") is True)
    check(checks, failures, "minimal_chain_blueprint_ready", readiness.get("minimal_production_task_chain_blueprint_ready") is True)
    check(checks, failures, "readiness_no_execution_allowed", readiness.get("production_task_execution_allowed") is False)
    check(checks, failures, "readiness_no_next_single_use_input", readiness.get("next_single_use_gate_input_ready") is False)
    check(checks, failures, "boundary_runtime_closed", boundary.get("runtime_execution_allowed") is False)
    check(checks, failures, "boundary_ingress_closed", boundary.get("external_public_ingress_allowed") is False)
    check(checks, failures, "boundary_deploy_closed", boundary.get("deploy_allowed") is False)
    check(checks, failures, "boundary_production_receipt_closed", boundary.get("production_runtime_receipt_write_allowed") is False)
    passed = _passed(checks, failures)
    report = {
        "schema_version": CONTEXT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "post_h3_readiness_index": index,
        "source_artifacts": {"post_h3_readiness_index": artifact_ref(readiness_index_path)},
        "boundary": _closed_boundary(context_validation_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    return _write_optional(report, output)


def _write_intake_packet(*, context: dict[str, Any], task_request: dict[str, Any], readiness_index_path: Path, output: Path) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    scope = object_value(task_request.get("scope"))
    rollback = object_value(task_request.get("rollback"))
    scopes = _texts(scope.get("service_token_scopes"))
    forbidden_actions = set(_texts(scope.get("forbidden_actions")))
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "task_id_present", bool(str(task_request.get("task_id") or "").strip()))
    check(checks, failures, "task_class_allowed", task_request.get("task_class") in ALLOWED_TASK_CLASSES)
    check(checks, failures, "risk_class_low", task_request.get("risk_class") in ALLOWED_RISK_CLASSES)
    for field in ("owner_id", "operator_id", "audit_owner_id", "rollback_owner_id", "monitoring_owner_id"):
        check(checks, failures, f"{field}_present", bool(str(task_request.get(field) or "").strip()))
    check(checks, failures, "required_service_scopes_present", REQUIRED_SERVICE_TOKEN_SCOPES <= set(scopes))
    check(checks, failures, "service_scopes_allowlisted", set(scopes) <= ALLOWED_SERVICE_TOKEN_SCOPES)
    check(checks, failures, "service_scopes_safe", _scopes_safe(scopes))
    check(checks, failures, "forbidden_actions_complete", REQUIRED_FORBIDDEN_ACTIONS <= forbidden_actions)
    check(checks, failures, "max_runtime_tasks_one", scope.get("max_runtime_tasks") == 1)
    check(checks, failures, "max_external_users_zero", scope.get("max_external_users") == 0)
    check(checks, failures, "rollback_owner_matches", rollback.get("owner_id") == task_request.get("rollback_owner_id"))
    check(checks, failures, "rollback_runbook_present", bool(str(rollback.get("runbook") or "").strip()))
    passed = _passed(checks, failures)
    packet = {
        "schema_version": INTAKE_PACKET_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "written_at": _now(),
        "intake_id": f"post-h3-minimal-task-intake:{sha256_json([task_request.get('task_id'), artifact_ref(readiness_index_path)])[:24]}",
        "task_request": task_request,
        "source_artifacts": {"post_h3_readiness_index": artifact_ref(readiness_index_path)},
        "readiness": {
            "authorization_gate_input_ready": passed,
            "production_task_execution_allowed": False,
            "artifact_only": True,
        },
        "boundary": _closed_boundary(intake_packet_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, packet)
    return packet


def _write_risk_boundary(*, intake_packet_path: Path, output: Path) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    packet = read_json_object(intake_packet_path)
    task = object_value(packet.get("task_request"))
    scope = object_value(task.get("scope"))
    check(checks, failures, "intake_packet_passed", packet.get("schema_version") == INTAKE_PACKET_SCHEMA and packet.get("passed") is True)
    check(checks, failures, "risk_class_low", task.get("risk_class") == "low")
    check(checks, failures, "no_external_users", scope.get("max_external_users") == 0)
    check(checks, failures, "single_runtime_task", scope.get("max_runtime_tasks") == 1)
    check(checks, failures, "forbidden_actions_complete", REQUIRED_FORBIDDEN_ACTIONS <= set(_texts(scope.get("forbidden_actions"))))
    passed = _passed(checks, failures)
    report = {
        "schema_version": RISK_BOUNDARY_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "written_at": _now(),
        "risk_class": task.get("risk_class"),
        "forbidden_actions": sorted(REQUIRED_FORBIDDEN_ACTIONS),
        "source_artifacts": {"intake_packet": artifact_ref(intake_packet_path)},
        "boundary": _closed_boundary(risk_boundary_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def _write_rollback_runbook(*, intake_packet_path: Path, risk_boundary_path: Path, output: Path) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    packet = read_json_object(intake_packet_path)
    risk = read_json_object(risk_boundary_path)
    task = object_value(packet.get("task_request"))
    rollback = object_value(task.get("rollback"))
    check(checks, failures, "intake_packet_passed", packet.get("passed") is True)
    check(checks, failures, "risk_boundary_passed", risk.get("schema_version") == RISK_BOUNDARY_SCHEMA and risk.get("passed") is True)
    check(checks, failures, "rollback_owner_present", bool(str(rollback.get("owner_id") or "").strip()))
    check(checks, failures, "rollback_runbook_present", bool(str(rollback.get("runbook") or "").strip()))
    check(checks, failures, "rollback_strategy_safe", rollback.get("strategy") == "abort_or_noop_before_any_external_side_effect")
    passed = _passed(checks, failures)
    report = {
        "schema_version": ROLLBACK_RUNBOOK_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "written_at": _now(),
        "rollback_owner_id": rollback.get("owner_id"),
        "rollback_strategy": rollback.get("strategy"),
        "rollback_runbook": rollback.get("runbook"),
        "source_artifacts": {
            "intake_packet": artifact_ref(intake_packet_path),
            "risk_boundary": artifact_ref(risk_boundary_path),
        },
        "boundary": _closed_boundary(rollback_runbook_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def _load_task_request(path: Path | None) -> dict[str, Any]:
    if path is None:
        return json.loads(json.dumps(DEFAULT_TASK_REQUEST))
    value = read_json_object(path)
    return value


def _scopes_safe(scopes: list[str]) -> bool:
    lowered = [scope.lower() for scope in scopes]
    return all(not any(token in scope for token in FORBIDDEN_SCOPE_TOKENS) for scope in lowered)


def _texts(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    result: list[str] = []
    for item in value:
        text = str(item).strip()
        if text and text not in result:
            result.append(text)
    return result


def _closed_boundary(**overrides: Any) -> dict[str, Any]:
    boundary = {
        "artifact_only": True,
        "context_validation_written": False,
        "intake_packet_written": False,
        "risk_boundary_written": False,
        "rollback_runbook_written": False,
        "production_task_execution_allowed": False,
        "runtime_execution_performed": False,
        "runtime_workers_currently_running": False,
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
    parser.add_argument("--readiness-index", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--task-request", type=Path)
    args = parser.parse_args(argv)
    summary = run_gate(readiness_index_path=args.readiness_index, output_root=args.output_root, task_request_path=args.task_request)
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if summary.get("passed") is True else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
