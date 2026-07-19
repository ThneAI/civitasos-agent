#!/usr/bin/env python3
"""Execute one private Beta VM preview from a deploy-ops authorization.

This execution gate consumes a passed private Beta deploy/rollback/monitoring
single-use authorization and performs a bounded vm1/vm2/vm3 private preview.
It may contact the configured VMs, run non-production preview services, run
smoke checks, and then run rollback/rollback-health checks.

It never opens public ingress, expands production runtime, writes production
receipts, mutates source/Git, or claims H.3 production readiness.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from beta5_real_multivm_preview_prepare import DEFAULT_BACKEND_PORT
from beta5_real_multivm_preview_prepare import DEFAULT_FRONTEND_PORT
from beta5_real_multivm_preview_prepare import DEFAULT_REMOTE_ROOT
from beta5_real_multivm_preview_prepare import PreviewNode
from beta5_real_multivm_preview_prepare import parse_node
from beta5_real_multivm_preview_prepare import write_real_multivm_preview_run

try:
    from civitasos_contracts.artifacts import artifact_ref, build_artifact_envelope
except ModuleNotFoundError:
    from scripts.civitasos_contracts.artifacts import artifact_ref, build_artifact_envelope


AUTHORIZATION_SCHEMA = "private-beta-deploy-ops-single-use-authorization:v1"
EXECUTION_SCHEMA = "private-beta-vm-preview-execution-receipt:v1"
MONITORING_SCHEMA = "private-beta-vm-preview-monitoring-receipt:v1"
ROLLBACK_SCHEMA = "private-beta-vm-preview-rollback-receipt:v1"
SUMMARY_SCHEMA = "private-beta-vm-preview-chain-summary:v1"
SMOKE_SCHEMA = "beta5-real-backend-frontend-multivm-smoke:v1"
DEFAULT_NODES = (
    "vm1,vm1,192.168.56.4",
    "vm2,vm2,192.168.56.5",
    "vm3,vm3,192.168.56.6",
)
NON_CLAIMS = (
    "private_beta_vm_preview_is_private_controlled_preview_only",
    "private_beta_vm_preview_requires_single_use_deploy_ops_authorization",
    "private_beta_vm_preview_runs_rollback_before_success",
    "private_beta_vm_preview_does_not_open_public_ingress",
    "private_beta_vm_preview_does_not_mutate_source_or_git",
    "private_beta_vm_preview_does_not_execute_production_runtime",
    "private_beta_vm_preview_does_not_write_production_receipts",
    "private_beta_vm_preview_does_not_claim_h3_production_readiness",
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--single-use-authorization", required=True)
    parser.add_argument("--output-root", required=True)
    parser.add_argument("--backend-bin", default="../civitasos-backend/target/debug/api_only")
    parser.add_argument("--frontend-build-dir", default="../civitasos-frontend/build")
    parser.add_argument("--node", action="append", default=[])
    parser.add_argument("--remote-root", default=DEFAULT_REMOTE_ROOT)
    parser.add_argument("--backend-port", type=int, default=DEFAULT_BACKEND_PORT)
    parser.add_argument("--frontend-port", type=int, default=DEFAULT_FRONTEND_PORT)
    parser.add_argument("--prepared-run-root")
    parser.add_argument("--operator-id", default="local-operator-cc")
    parser.add_argument("--ack-private-beta-vm-preview-execution", action="store_true")
    args = parser.parse_args(argv)

    summary = run_gate(
        authorization_path=Path(args.single_use_authorization),
        output_root=Path(args.output_root),
        backend_bin=Path(args.backend_bin),
        frontend_build_dir=Path(args.frontend_build_dir),
        nodes=[parse_node(raw) for raw in (args.node or list(DEFAULT_NODES))],
        remote_root=args.remote_root,
        backend_port=args.backend_port,
        frontend_port=args.frontend_port,
        prepared_run_root=Path(args.prepared_run_root) if args.prepared_run_root else None,
        operator_id=args.operator_id,
        ack_private_beta_vm_preview_execution=bool(args.ack_private_beta_vm_preview_execution),
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if summary.get("passed") is True else 1


def run_gate(
    *,
    authorization_path: Path,
    output_root: Path,
    backend_bin: Path,
    frontend_build_dir: Path,
    nodes: list[PreviewNode],
    remote_root: str,
    backend_port: int,
    frontend_port: int,
    prepared_run_root: Path | None,
    operator_id: str,
    ack_private_beta_vm_preview_execution: bool,
) -> dict[str, Any]:
    output_root = output_root.resolve()
    output_root.mkdir(parents=True, exist_ok=True)
    failures: list[str] = []
    authorization = _read_json(authorization_path, failures, "single-use authorization")
    _validate_authorization(authorization, failures)
    if not ack_private_beta_vm_preview_execution:
        failures.append("explicit private Beta VM preview execution acknowledgement is required")
    if not operator_id.strip():
        failures.append("operator_id is required")
    if not nodes:
        failures.append("at least one preview node is required")
    if _node_ids(nodes) != ["vm1", "vm2", "vm3"]:
        failures.append("private Beta VM preview must target exactly vm1/vm2/vm3")

    preview_root = (prepared_run_root or (output_root / "preview_run")).resolve()
    prepare_report: dict[str, Any] = {}
    if not failures:
        prepare_report = _prepare_or_load_preview_root(
            preview_root=preview_root,
            backend_bin=backend_bin,
            frontend_build_dir=frontend_build_dir,
            nodes=nodes,
            remote_root=remote_root,
            backend_port=backend_port,
            frontend_port=frontend_port,
            operator_id=operator_id,
            failures=failures,
        )

    deploy = smoke = rollback = rollback_health = None
    smoke_summary: dict[str, Any] = {}
    if not failures:
        deploy = _run_script(preview_root / "deploy_multivm_real_service.sh", output_root / "deploy_command", timeout_seconds=900)
        if deploy["returncode"] != 0:
            failures.append("deploy_command_failed")
        if deploy["returncode"] == 0:
            smoke = _run_script(preview_root / "smoke_multivm_real_service.py", output_root / "smoke_command", timeout_seconds=180)
            if smoke["returncode"] != 0:
                failures.append("smoke_command_failed")
            smoke_summary = _read_json(preview_root / "multivm_real_service_smoke_summary.json", failures, "multi-VM smoke summary") if smoke["returncode"] == 0 else {}
            _validate_smoke_summary(smoke_summary, _node_ids(nodes), failures)
        rollback = _run_script(preview_root / "rollback_multivm_real_service.sh", output_root / "rollback_command", timeout_seconds=300)
        if rollback["returncode"] != 0:
            failures.append("rollback_command_failed")
        if rollback["returncode"] == 0:
            rollback_health = _run_script(preview_root / "smoke_rollback_multivm_real_service.sh", output_root / "rollback_health_command", timeout_seconds=180)
            if rollback_health["returncode"] != 0:
                failures.append("rollback_health_command_failed")

    execution_passed = (
        not failures
        and _returncode(deploy) == 0
        and _returncode(smoke) == 0
        and _returncode(rollback) == 0
        and _returncode(rollback_health) == 0
    )
    _write_execution_receipt(
        output_root=output_root,
        authorization_path=authorization_path,
        authorization=authorization,
        prepare_report=prepare_report,
        deploy=deploy,
        smoke=smoke,
        smoke_summary=smoke_summary,
        passed=execution_passed,
        failures=failures,
    )
    _write_rollback_receipt(
        output_root=output_root,
        authorization_path=authorization_path,
        rollback=rollback,
        rollback_health=rollback_health,
        passed=execution_passed and _returncode(rollback) == 0 and _returncode(rollback_health) == 0,
        failures=failures,
    )
    monitoring_receipt = _write_monitoring_receipt(
        output_root=output_root,
        authorization_path=authorization_path,
        execution_receipt_path=output_root / "private_beta_vm_preview_execution_receipt.json",
        rollback_receipt_path=output_root / "private_beta_vm_preview_rollback_receipt.json",
        authorization=authorization,
        smoke_summary=smoke_summary,
        passed=execution_passed,
        failures=failures,
    )
    summary = {
        "schema_version": SUMMARY_SCHEMA,
        "artifact_envelope": build_artifact_envelope(
            artifact_kind="receipt",
            plane="runtime",
            schema_version=SUMMARY_SCHEMA,
            artifact_id=f"private-beta-vm-preview:{_digest([authorization_path.resolve(), operator_id, _now_day()])[:24]}",
            subject_id="private-beta-vm-preview",
            producer="private_beta_vm_preview_execution",
            source_refs=[artifact_ref(authorization_path)],
            scope="private_beta_vm_preview_chain",
        ),
        "checked_at": _now(),
        "passed": execution_passed,
        "decision": "private_beta_vm_preview_passed" if execution_passed else "blocked_or_failed_private_beta_vm_preview",
        "failure_reasons": failures,
        "operator_id": operator_id,
        "authorization_id": authorization.get("authorization_id"),
        "vm_target_ids": _node_ids(nodes),
        "artifacts": {
            "execution_receipt": artifact_ref(output_root / "private_beta_vm_preview_execution_receipt.json"),
            "rollback_receipt": artifact_ref(output_root / "private_beta_vm_preview_rollback_receipt.json"),
            "monitoring_receipt": artifact_ref(output_root / "private_beta_vm_preview_monitoring_receipt.json"),
        },
        "readiness": {
            "authorization_consumed": execution_passed,
            "deploy_executed": _returncode(deploy) == 0,
            "smoke_passed": _returncode(smoke) == 0 and smoke_summary.get("passed") is True,
            "rollback_executed": _returncode(rollback) == 0,
            "rollback_health_passed": _returncode(rollback_health) == 0,
            "monitoring_receipt_written": monitoring_receipt.get("passed") is True,
            "private_beta_vm_preview_complete": execution_passed,
            "production_transition_allowed": False,
        },
        "boundary": _boundary(
            authorization_consumed=execution_passed,
            vm_contact_performed=deploy is not None,
            deploy_executed=_returncode(deploy) == 0,
            rollback_executed=_returncode(rollback) == 0,
        ),
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(output_root / "private_beta_vm_preview_chain_summary.json", summary)
    return summary


def _prepare_or_load_preview_root(
    *,
    preview_root: Path,
    backend_bin: Path,
    frontend_build_dir: Path,
    nodes: list[PreviewNode],
    remote_root: str,
    backend_port: int,
    frontend_port: int,
    operator_id: str,
    failures: list[str],
) -> dict[str, Any]:
    if (preview_root / "prepare_report.json").is_file():
        report = _read_json(preview_root / "prepare_report.json", failures, "prepared run report")
    else:
        try:
            report = write_real_multivm_preview_run(
                run_root=preview_root,
                backend_bin=backend_bin,
                frontend_build_dir=frontend_build_dir,
                nodes=nodes,
                remote_root=remote_root,
                backend_port=backend_port,
                frontend_port=frontend_port,
                owner=operator_id,
                overwrite=False,
            )
        except Exception as exc:  # noqa: BLE001
            failures.append(f"preview_run_prepare_failed:{exc}")
            return {}
    if report.get("prepared") is not True:
        failures.append("prepared run report must be prepared=true")
    if report.get("production_deploy_allowed") is not False:
        failures.append("prepared run must keep production_deploy_allowed=false")
    return report


def _validate_authorization(authorization: Any, failures: list[str]) -> None:
    if not isinstance(authorization, dict):
        failures.append("single-use authorization must be a JSON object")
        return
    if authorization.get("schema_version") != AUTHORIZATION_SCHEMA:
        failures.append(f"single-use authorization schema_version must be {AUTHORIZATION_SCHEMA}")
    if authorization.get("passed") is not True:
        failures.append("single-use authorization must be passed")
    if authorization.get("decision") != "private_beta_deploy_ops_authorized_once":
        failures.append("single-use authorization decision must authorize once")
    if authorization.get("single_use") is not True or authorization.get("consumed") is not False:
        failures.append("single-use authorization must be unconsumed")
    scope = authorization.get("authorized_scope") if isinstance(authorization.get("authorized_scope"), dict) else {}
    if scope.get("target_scope") != "private_vm_preview":
        failures.append("authorized target_scope must be private_vm_preview")
    if scope.get("deploy_target") != "vm1-vm2-vm3-private-preview":
        failures.append("authorized deploy_target must be vm1-vm2-vm3-private-preview")
    for key in ("public_ingress_allowed", "production_runtime_execution_allowed", "production_receipt_write_allowed"):
        if scope.get(key) is not False:
            failures.append(f"authorized scope must keep {key}=false")
    scopes = set(scope.get("service_token_scopes") or [])
    if not {"pool:read", "audit:read"}.issubset(scopes):
        failures.append("authorized service_token_scopes must include pool:read and audit:read")
    boundary = authorization.get("boundary") if isinstance(authorization.get("boundary"), dict) else {}
    if boundary.get("deploy_execution_authorized_once") is not True:
        failures.append("authorization boundary must authorize deploy once")
    if boundary.get("rollback_or_abort_authorized_once") is not True:
        failures.append("authorization boundary must authorize rollback/abort once")
    for key in ("deploy_executed", "rollback_executed", "public_ingress_allowed", "production_runtime_execution_allowed", "production_receipt_write_allowed"):
        if boundary.get(key) is not False:
            failures.append(f"authorization boundary must keep {key}=false")


def _validate_smoke_summary(summary: dict[str, Any], expected_nodes: list[str], failures: list[str]) -> None:
    if not summary:
        return
    if summary.get("schema_version") != SMOKE_SCHEMA:
        failures.append(f"smoke summary schema_version must be {SMOKE_SCHEMA}")
    if summary.get("passed") is not True:
        failures.append("smoke summary must pass")
    if sorted(str(item) for item in summary.get("nodes") or []) != expected_nodes:
        failures.append("smoke summary nodes must match vm1/vm2/vm3")
    if int(summary.get("total_checks") or 0) < len(expected_nodes):
        failures.append("smoke summary must include checks for every VM")
    for key in ("production_deploy_allowed", "production_runtime_execution_allowed", "production_receipt_write_allowed", "h3_production_readiness_claimed"):
        if summary.get(key) is not False:
            failures.append(f"smoke summary must keep {key}=false")


def _write_execution_receipt(
    *,
    output_root: Path,
    authorization_path: Path,
    authorization: dict[str, Any],
    prepare_report: dict[str, Any],
    deploy: dict[str, Any] | None,
    smoke: dict[str, Any] | None,
    smoke_summary: dict[str, Any],
    passed: bool,
    failures: list[str],
) -> dict[str, Any]:
    receipt = {
        "schema_version": EXECUTION_SCHEMA,
        "artifact_envelope": _receipt_envelope("private-beta-vm-preview-execution", authorization_path),
        "checked_at": _now(),
        "passed": passed,
        "failure_reasons": failures,
        "authorization_id": authorization.get("authorization_id"),
        "source_authorization": artifact_ref(authorization_path),
        "prepare_report": prepare_report,
        "deploy": deploy,
        "smoke": smoke,
        "smoke_summary": smoke_summary,
        "deploy_executed": _returncode(deploy) == 0,
        "smoke_passed": _returncode(smoke) == 0 and smoke_summary.get("passed") is True,
        "boundary": _boundary(
            authorization_consumed=passed,
            vm_contact_performed=deploy is not None,
            deploy_executed=_returncode(deploy) == 0,
            rollback_executed=False,
        ),
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(output_root / "private_beta_vm_preview_execution_receipt.json", receipt)
    return receipt


def _write_rollback_receipt(
    *,
    output_root: Path,
    authorization_path: Path,
    rollback: dict[str, Any] | None,
    rollback_health: dict[str, Any] | None,
    passed: bool,
    failures: list[str],
) -> dict[str, Any]:
    receipt = {
        "schema_version": ROLLBACK_SCHEMA,
        "artifact_envelope": _receipt_envelope("private-beta-vm-preview-rollback", authorization_path),
        "checked_at": _now(),
        "passed": passed,
        "failure_reasons": failures,
        "source_authorization": artifact_ref(authorization_path),
        "rollback": rollback,
        "rollback_health": rollback_health,
        "rollback_executed": _returncode(rollback) == 0,
        "rollback_health_passed": _returncode(rollback_health) == 0,
        "boundary": _boundary(
            authorization_consumed=passed,
            vm_contact_performed=rollback is not None,
            deploy_executed=False,
            rollback_executed=_returncode(rollback) == 0,
        ),
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(output_root / "private_beta_vm_preview_rollback_receipt.json", receipt)
    return receipt


def _write_monitoring_receipt(
    *,
    output_root: Path,
    authorization_path: Path,
    execution_receipt_path: Path,
    rollback_receipt_path: Path,
    authorization: dict[str, Any],
    smoke_summary: dict[str, Any],
    passed: bool,
    failures: list[str],
) -> dict[str, Any]:
    roles = authorization.get("roles") if isinstance(authorization.get("roles"), dict) else {}
    receipt = {
        "schema_version": MONITORING_SCHEMA,
        "artifact_envelope": _receipt_envelope("private-beta-vm-preview-monitoring", authorization_path),
        "checked_at": _now(),
        "passed": passed,
        "failure_reasons": failures,
        "source_authorization": artifact_ref(authorization_path),
        "source_execution_receipt": artifact_ref(execution_receipt_path) if execution_receipt_path.is_file() else None,
        "source_rollback_receipt": artifact_ref(rollback_receipt_path) if rollback_receipt_path.is_file() else None,
        "roles": roles,
        "monitoring_owner": roles.get("monitoring_owner"),
        "audit_owner": roles.get("audit_owner"),
        "rollback_owner": roles.get("rollback_owner"),
        "latency_summary": {
            "latency_ms_min": smoke_summary.get("latency_ms_min"),
            "latency_ms_median": smoke_summary.get("latency_ms_median"),
            "latency_ms_max": smoke_summary.get("latency_ms_max"),
            "total_checks": smoke_summary.get("total_checks", 0),
        },
        "owner_audit_reconciliation": {
            "operator_decision": "accept_private_beta_vm_preview" if passed else "blocked_or_failed_private_beta_vm_preview",
            "audit_decision": "accept_private_beta_no_public_or_production_boundary" if passed else "review_required",
            "rollback_decision": "accept_rollback_completed" if passed else "review_required",
            "monitoring_decision": "accept_smoke_monitoring_receipt" if passed else "review_required",
        },
        "boundary": _boundary(
            authorization_consumed=passed,
            vm_contact_performed=passed,
            deploy_executed=passed,
            rollback_executed=passed,
        ),
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(output_root / "private_beta_vm_preview_monitoring_receipt.json", receipt)
    return receipt


def _receipt_envelope(subject_id: str, authorization_path: Path) -> dict[str, Any]:
    return build_artifact_envelope(
        artifact_kind="receipt",
        plane="runtime",
        schema_version=EXECUTION_SCHEMA,
        artifact_id=f"{subject_id}:{_digest([authorization_path.resolve(), _now_day()])[:24]}",
        subject_id=subject_id,
        producer="private_beta_vm_preview_execution",
        source_refs=[artifact_ref(authorization_path)],
        scope=subject_id,
    )


def _run_script(path: Path, output_prefix: Path, *, timeout_seconds: int) -> dict[str, Any]:
    started = _now()
    output_prefix.parent.mkdir(parents=True, exist_ok=True)
    try:
        completed = subprocess.run(
            [str(path.resolve())],
            cwd=str(path.parent.resolve()),
            text=True,
            capture_output=True,
            timeout=timeout_seconds,
            check=False,
        )
        returncode = completed.returncode
        stdout = completed.stdout
        stderr = completed.stderr
        timed_out = False
    except subprocess.TimeoutExpired as exc:
        returncode = 124
        stdout = exc.stdout if isinstance(exc.stdout, str) else (exc.stdout or b"").decode("utf-8", errors="replace")
        stderr = exc.stderr if isinstance(exc.stderr, str) else (exc.stderr or b"").decode("utf-8", errors="replace")
        timed_out = True
    output_prefix.with_suffix(".stdout").write_text(stdout, encoding="utf-8")
    output_prefix.with_suffix(".stderr").write_text(stderr, encoding="utf-8")
    return {
        "command": [str(path.resolve())],
        "started_at": started,
        "completed_at": _now(),
        "returncode": returncode,
        "timed_out": timed_out,
        "stdout_path": str(output_prefix.with_suffix(".stdout").resolve()),
        "stderr_path": str(output_prefix.with_suffix(".stderr").resolve()),
        "stdout_tail": stdout[-4000:],
        "stderr_tail": stderr[-4000:],
    }


def _read_json(path: Path, failures: list[str], label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        failures.append(f"{label} not found: {path}")
    except json.JSONDecodeError as exc:
        failures.append(f"{label} invalid JSON: {exc}")
    return {}


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _node_ids(nodes: list[PreviewNode]) -> list[str]:
    return sorted(node.node_id for node in nodes)


def _returncode(report: dict[str, Any] | None) -> int | None:
    if not report:
        return None
    value = report.get("returncode")
    return int(value) if isinstance(value, int) else None


def _boundary(
    *,
    authorization_consumed: bool,
    vm_contact_performed: bool,
    deploy_executed: bool,
    rollback_executed: bool,
) -> dict[str, bool]:
    return {
        "authorization_consumed": authorization_consumed,
        "vm_contact_performed": vm_contact_performed,
        "private_preview_deploy_executed": deploy_executed,
        "rollback_executed": rollback_executed,
        "monitoring_receipt_written": authorization_consumed,
        "public_ingress_allowed": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
        "source_or_git_mutation_allowed": False,
        "h3_production_readiness_claimed": False,
    }


def _digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True, default=str).encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _now_day() -> str:
    return datetime.now(timezone.utc).date().isoformat()


if __name__ == "__main__":
    raise SystemExit(main())
