"""Validate deployment boundary for the internal Post-H3 pilot.

PostH3-B consumes the PostH3-A runtime authorization summary and records the
deployment boundary needed before any internal runtime execution can happen. It
does not deploy, contact VMs, open public ingress, execute runtime, or write
production runtime receipts.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from benchmarks.i_gate_evidence import artifact_ref, check, object_value, read_json_object, write_json_object
from benchmarks.post_h3_internal_runtime_authorization_gate import CHAIN_SCHEMA as POST_H3A_SCHEMA
from benchmarks.post_h3_internal_runtime_authorization_gate import REQUIRED_SERVICE_SCOPES

CHAIN_SCHEMA = "post-h3-deployment-boundary-chain:v1"
ENVIRONMENT_PROOF_SCHEMA = "post-h3-deployment-boundary-environment-proof:v1"
BOUNDARY_RECEIPT_SCHEMA = "post-h3-deployment-boundary-receipt:v1"

REQUIRED_ROLES = ("owner", "audit_owner", "monitoring_owner", "rollback_owner")
NON_CLAIMS = (
    "post_h3b_does_not_deploy",
    "post_h3b_does_not_contact_vms",
    "post_h3b_does_not_open_public_ingress",
    "post_h3b_does_not_execute_runtime",
    "post_h3b_does_not_write_production_runtime_receipts",
)


def run_gate(
    *,
    post_h3a_summary_path: Path,
    output_root: Path,
    vm_targets: list[str] | None = None,
    private_ips: list[str] | None = None,
    service_token_scopes: list[str] | None = None,
    owner: str = "product_owner",
    audit_owner: str = "audit_owner",
    monitoring_owner: str = "observability_owner",
    rollback_owner: str = "rollback_owner",
    rollback_runbook: str = "stop internal runtime, revoke token, restore previous VM snapshot/checkpoint",
) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "environment_proof": output_root / "post_h3b_deployment_environment_proof.json",
        "boundary_receipt": output_root / "post_h3b_deployment_boundary_receipt.json",
        "summary": output_root / "post_h3b_deployment_boundary_summary.json",
    }
    context = _validate_post_h3a(post_h3a_summary_path)
    environment = _write_environment_proof(
        context=context,
        post_h3a_summary_path=post_h3a_summary_path,
        output=artifacts["environment_proof"],
        vm_targets=vm_targets or ["vm1", "vm2", "vm3"],
        private_ips=private_ips or ["192.168.56.4", "192.168.56.5", "192.168.56.6"],
        service_token_scopes=service_token_scopes,
        owner=owner,
        audit_owner=audit_owner,
        monitoring_owner=monitoring_owner,
        rollback_owner=rollback_owner,
        rollback_runbook=rollback_runbook,
    )
    receipt = _write_boundary_receipt(
        environment_proof_path=artifacts["environment_proof"],
        output=artifacts["boundary_receipt"],
    )
    reports = [context, environment, receipt]
    passed = all(report.get("passed") is True for report in reports)
    summary = {
        "schema_version": CHAIN_SCHEMA,
        "passed": passed,
        "failure_reasons": _failures(reports),
        "checked_at": _now(),
        "source_artifacts": {"post_h3a_summary": artifact_ref(post_h3a_summary_path)},
        "artifacts": {name: artifact_ref(path) for name, path in artifacts.items() if name != "summary"},
        "readiness": {
            "state": "post_h3_deployment_boundary_ready" if passed else "blocked_post_h3_deployment_boundary",
            "post_h3_deployment_boundary_ready": passed,
            "rollback_abort_drill_ready": passed,
            "runtime_execution_allowed": object_value(context.get("post_h3a_summary")).get("readiness", {}).get("runtime_execution_allowed") is True,
            "runtime_execution_performed": False,
            "deploy_performed": False,
            "external_public_ingress_opened": False,
            "production_runtime_receipt_write_allowed": False,
        },
        "boundary": _boundary(
            deployment_boundary_written=passed,
            private_vm_targets_verified=passed,
            service_token_scope_verified=passed,
            owner_roles_verified=passed,
            rollback_runbook_verified=passed,
        ),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(artifacts["summary"], summary)
    return summary


def _validate_post_h3a(path: Path) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    try:
        summary = read_json_object(path)
    except Exception as exc:  # noqa: BLE001
        return _report("post-h3b-post-h3a-context:v1", False, [f"post_h3a_summary_unreadable:{exc}"], checks)
    readiness = object_value(summary.get("readiness"))
    boundary = object_value(summary.get("boundary"))
    check(checks, failures, "post_h3a_schema_valid", summary.get("schema_version") == POST_H3A_SCHEMA)
    check(checks, failures, "post_h3a_passed", summary.get("passed") is True)
    check(checks, failures, "post_h3a_runtime_authorized", readiness.get("post_h3_internal_runtime_authorized") is True)
    check(checks, failures, "post_h3a_deployment_boundary_ready", readiness.get("deployment_boundary_ready") is True)
    check(checks, failures, "post_h3a_runtime_not_performed", readiness.get("runtime_execution_performed") is False)
    check(checks, failures, "post_h3a_receipt_write_not_allowed", readiness.get("production_runtime_receipt_write_allowed") is False)
    check(checks, failures, "post_h3a_no_deploy", boundary.get("deploy_performed") is False)
    check(checks, failures, "post_h3a_no_public_ingress", boundary.get("external_public_ingress_opened") is False)
    passed = _passed(checks, failures)
    return {
        "schema_version": "post-h3b-post-h3a-context:v1",
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "post_h3a_summary": summary,
        "source_artifacts": {"post_h3a_summary": artifact_ref(path)},
        "boundary": _boundary(),
        "non_claims": list(NON_CLAIMS),
    }


def _write_environment_proof(
    *,
    context: dict[str, Any],
    post_h3a_summary_path: Path,
    output: Path,
    vm_targets: list[str],
    private_ips: list[str],
    service_token_scopes: list[str] | None,
    owner: str,
    audit_owner: str,
    monitoring_owner: str,
    rollback_owner: str,
    rollback_runbook: str,
) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    scopes = sorted(set(service_token_scopes or REQUIRED_SERVICE_SCOPES))
    roles = {
        "owner": owner,
        "audit_owner": audit_owner,
        "monitoring_owner": monitoring_owner,
        "rollback_owner": rollback_owner,
    }
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "vm_targets_present", bool(vm_targets))
    check(checks, failures, "private_ips_match_targets", len(private_ips) == len(vm_targets))
    check(checks, failures, "private_ips_are_private", all(_private_ip(ip) for ip in private_ips))
    check(checks, failures, "service_token_scopes_match_post_h3a", REQUIRED_SERVICE_SCOPES <= set(scopes))
    check(checks, failures, "required_roles_present", all(bool(roles[role]) for role in REQUIRED_ROLES))
    check(checks, failures, "rollback_runbook_present", bool(rollback_runbook.strip()))
    passed = _passed(checks, failures)
    report = {
        "schema_version": ENVIRONMENT_PROOF_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "source_artifacts": {"post_h3a_summary": artifact_ref(post_h3a_summary_path)},
        "environment": {
            "target_kind": "internal_private_vm_cluster",
            "vm_targets": vm_targets,
            "private_ips": private_ips,
            "private_only": True,
            "public_ingress_allowed": False,
            "production_data_access_allowed": False,
            "service_token_scopes": scopes,
            "roles": roles,
            "rollback_runbook": rollback_runbook,
        },
        "readiness": {
            "state": "post_h3b_environment_proof_ready" if passed else "blocked_post_h3b_environment_proof",
            "boundary_receipt_ready": passed,
        },
        "boundary": _boundary(
            private_vm_targets_verified=passed,
            service_token_scope_verified=passed,
            owner_roles_verified=passed,
            rollback_runbook_verified=passed,
        ),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def _write_boundary_receipt(*, environment_proof_path: Path, output: Path) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    environment = read_json_object(environment_proof_path)
    env = object_value(environment.get("environment"))
    check(checks, failures, "environment_proof_passed", environment.get("schema_version") == ENVIRONMENT_PROOF_SCHEMA and environment.get("passed") is True)
    check(checks, failures, "private_only", env.get("private_only") is True)
    check(checks, failures, "public_ingress_closed", env.get("public_ingress_allowed") is False)
    check(checks, failures, "production_data_access_closed", env.get("production_data_access_allowed") is False)
    passed = _passed(checks, failures)
    receipt = {
        "schema_version": BOUNDARY_RECEIPT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "source_artifacts": {"environment_proof": artifact_ref(environment_proof_path)},
        "readiness": {
            "state": "post_h3b_deployment_boundary_receipt_ready" if passed else "blocked_post_h3b_deployment_boundary_receipt",
            "rollback_abort_drill_ready": passed,
        },
        "boundary": _boundary(deployment_boundary_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, receipt)
    return receipt


def _private_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback


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
        "deployment_boundary_written": False,
        "private_vm_targets_verified": False,
        "service_token_scope_verified": False,
        "owner_roles_verified": False,
        "rollback_runbook_verified": False,
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
    parser = argparse.ArgumentParser(description="Validate Post-H3 internal deployment boundary")
    parser.add_argument("--post-h3a-summary", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--vm-target", action="append", dest="vm_targets")
    parser.add_argument("--private-ip", action="append", dest="private_ips")
    parser.add_argument("--service-token-scope", action="append", dest="service_token_scopes")
    parser.add_argument("--owner", default="product_owner")
    parser.add_argument("--audit-owner", default="audit_owner")
    parser.add_argument("--monitoring-owner", default="observability_owner")
    parser.add_argument("--rollback-owner", default="rollback_owner")
    parser.add_argument("--rollback-runbook", default="stop internal runtime, revoke token, restore previous VM snapshot/checkpoint")
    args = parser.parse_args()
    summary = run_gate(
        post_h3a_summary_path=args.post_h3a_summary,
        output_root=args.output_root,
        vm_targets=args.vm_targets,
        private_ips=args.private_ips,
        service_token_scopes=args.service_token_scopes,
        owner=args.owner,
        audit_owner=args.audit_owner,
        monitoring_owner=args.monitoring_owner,
        rollback_owner=args.rollback_owner,
        rollback_runbook=args.rollback_runbook,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if summary.get("passed") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
