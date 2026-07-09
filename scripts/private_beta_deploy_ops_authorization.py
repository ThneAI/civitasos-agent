#!/usr/bin/env python3
"""Authorization gate for private Beta deploy/rollback/monitoring operations.

This gate consumes a passed frontend release-chain closeout, cumulative index,
and FE-10 private preview receipt. It can write an authorization request and a
single-use authorization receipt, but it never executes deploy, rollback,
monitoring, public ingress, production runtime actions, or production receipts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from civitasos_contracts.artifacts import artifact_ref, build_artifact_envelope
except ModuleNotFoundError:
    from scripts.civitasos_contracts.artifacts import artifact_ref, build_artifact_envelope

HANDOFF_SCHEMA = "beta-fe-frontend-chain-operator-handoff:v1"
INDEX_SCHEMA = "beta-fe-frontend-cumulative-evidence-index:v1"
FE10_SCHEMA = "beta-fe10-frontend-preview-receipt:v1"
REQUEST_SCHEMA = "private-beta-deploy-ops-authorization-request:v1"
AUTHORIZATION_SCHEMA = "private-beta-deploy-ops-single-use-authorization:v1"
VALIDATION_SCHEMA = "private-beta-deploy-ops-authorization-validation:v1"
ALLOWED_TARGET_SCOPES = {"local_staging_preview", "private_vm_preview"}
DEFAULT_SERVICE_SCOPES = ("pool:read", "audit:read")
NON_CLAIMS = (
    "private_beta_deploy_ops_authorization_does_not_execute_deploy",
    "private_beta_deploy_ops_authorization_does_not_execute_rollback",
    "private_beta_deploy_ops_authorization_does_not_open_public_ingress",
    "private_beta_deploy_ops_authorization_does_not_execute_production_runtime",
    "private_beta_deploy_ops_authorization_does_not_write_production_receipts",
    "single_use_authorization_must_be_consumed_by_a_separate_execution_gate",
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    request = sub.add_parser("request", help="write a deploy/rollback/monitoring authorization request")
    request.add_argument("--frontend-chain-handoff", required=True)
    request.add_argument("--frontend-chain-index", required=True)
    request.add_argument("--preview-receipt", required=True)
    request.add_argument("--output-root", required=True)
    request.add_argument("--operator-id", default="local-operator-cc")
    request.add_argument("--operator-statement", required=True)
    request.add_argument("--deploy-owner", required=True)
    request.add_argument("--rollback-owner", required=True)
    request.add_argument("--monitoring-owner", required=True)
    request.add_argument("--audit-owner", required=True)
    request.add_argument("--deploy-target", required=True)
    request.add_argument("--target-scope", choices=sorted(ALLOWED_TARGET_SCOPES), default="private_vm_preview")
    request.add_argument("--service-token-scope", action="append", default=[])
    request.add_argument("--rollback-runbook-ref", required=True)
    request.add_argument("--monitoring-plan-ref", required=True)
    request.add_argument("--ack-deploy-boundary", action="store_true")
    request.add_argument("--ack-rollback-runbook", action="store_true")
    request.add_argument("--ack-monitoring-owner", action="store_true")

    decide = sub.add_parser("decide", help="write a single-use deploy/rollback/monitoring authorization")
    decide.add_argument("--authorization-request", required=True)
    decide.add_argument("--output-root", required=True)
    decide.add_argument("--operator-id", default="local-operator-cc")
    decide.add_argument("--operator-decision", choices=("authorize_once", "request_revision", "reject"), default="authorize_once")
    decide.add_argument("--operator-statement", required=True)
    decide.add_argument("--ack-authorization-decision", action="store_true")

    validate = sub.add_parser("validate-authorization", help="validate a single-use authorization")
    validate.add_argument("--authorization", required=True)
    validate.add_argument("--output")

    args = parser.parse_args(argv)
    if args.command == "request":
        report = write_authorization_request(
            frontend_chain_handoff=Path(args.frontend_chain_handoff),
            frontend_chain_index=Path(args.frontend_chain_index),
            preview_receipt=Path(args.preview_receipt),
            output_root=Path(args.output_root),
            operator_id=args.operator_id,
            operator_statement=args.operator_statement,
            deploy_owner=args.deploy_owner,
            rollback_owner=args.rollback_owner,
            monitoring_owner=args.monitoring_owner,
            audit_owner=args.audit_owner,
            deploy_target=args.deploy_target,
            target_scope=args.target_scope,
            service_token_scopes=args.service_token_scope or list(DEFAULT_SERVICE_SCOPES),
            rollback_runbook_ref=args.rollback_runbook_ref,
            monitoring_plan_ref=args.monitoring_plan_ref,
            ack_deploy_boundary=bool(args.ack_deploy_boundary),
            ack_rollback_runbook=bool(args.ack_rollback_runbook),
            ack_monitoring_owner=bool(args.ack_monitoring_owner),
        )
    elif args.command == "decide":
        report = write_authorization_decision(
            authorization_request=Path(args.authorization_request),
            output_root=Path(args.output_root),
            operator_id=args.operator_id,
            operator_decision=args.operator_decision,
            operator_statement=args.operator_statement,
            ack_authorization_decision=bool(args.ack_authorization_decision),
        )
    else:
        report = validate_authorization(Path(args.authorization), output=Path(args.output) if args.output else None)
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report.get("passed") is True else 1


def write_authorization_request(
    *,
    frontend_chain_handoff: Path,
    frontend_chain_index: Path,
    preview_receipt: Path,
    output_root: Path,
    operator_id: str,
    operator_statement: str,
    deploy_owner: str,
    rollback_owner: str,
    monitoring_owner: str,
    audit_owner: str,
    deploy_target: str,
    target_scope: str,
    service_token_scopes: list[str],
    rollback_runbook_ref: str,
    monitoring_plan_ref: str,
    ack_deploy_boundary: bool,
    ack_rollback_runbook: bool,
    ack_monitoring_owner: bool,
) -> dict[str, Any]:
    output_root = output_root.resolve()
    output_root.mkdir(parents=True, exist_ok=True)
    failures: list[str] = []
    handoff = _read_json(frontend_chain_handoff, failures, "frontend chain handoff")
    index = _read_json(frontend_chain_index, failures, "frontend chain index")
    preview = _read_json(preview_receipt, failures, "FE-10 preview receipt")
    _validate_handoff(handoff, failures)
    _validate_index(index, handoff, failures)
    _validate_preview(preview, failures)
    _validate_roles(
        {
            "operator_id": operator_id,
            "deploy_owner": deploy_owner,
            "rollback_owner": rollback_owner,
            "monitoring_owner": monitoring_owner,
            "audit_owner": audit_owner,
        },
        failures,
    )
    if not operator_statement.strip():
        failures.append("operator_statement is required")
    if target_scope not in ALLOWED_TARGET_SCOPES:
        failures.append(f"target_scope must be one of {sorted(ALLOWED_TARGET_SCOPES)}")
    if not deploy_target.strip():
        failures.append("deploy_target is required")
    if _unsafe_text(deploy_target):
        failures.append("deploy_target must not name public or production environments")
    if _unsafe_text(rollback_runbook_ref):
        failures.append("rollback_runbook_ref must not be placeholder/public/production")
    if _unsafe_text(monitoring_plan_ref):
        failures.append("monitoring_plan_ref must not be placeholder/public/production")
    if not ack_deploy_boundary:
        failures.append("explicit deploy boundary acknowledgement is required")
    if not ack_rollback_runbook:
        failures.append("explicit rollback runbook acknowledgement is required")
    if not ack_monitoring_owner:
        failures.append("explicit monitoring owner acknowledgement is required")
    _validate_service_scopes(service_token_scopes, failures)

    passed = not failures
    refs = _source_refs(frontend_chain_handoff, frontend_chain_index, preview_receipt)
    request_id = f"private-beta-deploy-ops-request:{_digest([refs, operator_id, deploy_target, target_scope])[:24]}"
    report = {
        "schema_version": REQUEST_SCHEMA,
        "artifact_envelope": build_artifact_envelope(
            artifact_kind="approval",
            plane="governance",
            schema_version=REQUEST_SCHEMA,
            artifact_id=request_id,
            subject_id="private-beta-deploy-rollback-monitoring",
            producer="private_beta_deploy_ops_authorization",
            source_refs=list(refs.values()),
            scope="deploy_rollback_monitoring_authorization_request",
        ),
        "checked_at": _now(),
        "passed": passed,
        "decision": "private_beta_deploy_ops_authorization_request_ready" if passed else "blocked",
        "failure_reasons": failures,
        "authorization_request_id": request_id,
        "source_artifacts": refs,
        "operator_id": operator_id,
        "operator_statement": operator_statement,
        "requested_scope": {
            "target_scope": target_scope,
            "deploy_target": deploy_target,
            "rollback_runbook_ref": rollback_runbook_ref,
            "monitoring_plan_ref": monitoring_plan_ref,
            "service_token_scopes": sorted(service_token_scopes),
            "public_ingress_allowed": False,
            "production_runtime_execution_allowed": False,
            "production_receipt_write_allowed": False,
        },
        "roles": {
            "deploy_owner": deploy_owner,
            "rollback_owner": rollback_owner,
            "monitoring_owner": monitoring_owner,
            "audit_owner": audit_owner,
        },
        "readiness": {
            "authorization_request_ready": passed,
            "authorization_granted": False,
            "deploy_execution_ready": False,
            "rollback_or_abort_ready": passed,
            "monitoring_required": passed,
        },
        "boundary": _boundary(request_written=passed, authorization_granted=False),
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(output_root / "private_beta_deploy_ops_authorization_request.json", report)
    return report


def write_authorization_decision(
    *,
    authorization_request: Path,
    output_root: Path,
    operator_id: str,
    operator_decision: str,
    operator_statement: str,
    ack_authorization_decision: bool,
) -> dict[str, Any]:
    output_root = output_root.resolve()
    output_root.mkdir(parents=True, exist_ok=True)
    failures: list[str] = []
    request = _read_json(authorization_request, failures, "deploy ops authorization request")
    if request.get("schema_version") != REQUEST_SCHEMA:
        failures.append(f"authorization request schema_version must be {REQUEST_SCHEMA}")
    if request.get("passed") is not True:
        failures.append("authorization request must be passed")
    if request.get("decision") != "private_beta_deploy_ops_authorization_request_ready":
        failures.append("authorization request decision must be ready")
    if operator_decision != "authorize_once":
        failures.append("operator_decision must be authorize_once to write a single-use authorization")
    if not operator_id.strip():
        failures.append("operator_id is required")
    if not operator_statement.strip():
        failures.append("operator_statement is required")
    if not ack_authorization_decision:
        failures.append("explicit deploy ops authorization decision acknowledgement is required")

    passed = not failures
    request_ref = artifact_ref(authorization_request) if authorization_request.is_file() else None
    authorization_id = f"private-beta-deploy-ops-auth:{_digest([request_ref, operator_id, operator_statement])[:24]}"
    report = {
        "schema_version": AUTHORIZATION_SCHEMA,
        "artifact_envelope": build_artifact_envelope(
            artifact_kind="approval",
            plane="governance",
            schema_version=AUTHORIZATION_SCHEMA,
            artifact_id=authorization_id,
            subject_id="private-beta-deploy-rollback-monitoring",
            producer="private_beta_deploy_ops_authorization",
            source_refs=[request_ref] if request_ref else [],
            scope="single_use_deploy_rollback_monitoring_authorization",
        ),
        "checked_at": _now(),
        "passed": passed,
        "decision": "private_beta_deploy_ops_authorized_once" if passed else "blocked",
        "failure_reasons": failures,
        "authorization_id": authorization_id,
        "source_authorization_request": request_ref,
        "operator_id": operator_id,
        "operator_decision": operator_decision,
        "operator_statement": operator_statement,
        "single_use": passed,
        "consumed": False,
        "authorized_scope": request.get("requested_scope") if isinstance(request.get("requested_scope"), dict) else {},
        "roles": request.get("roles") if isinstance(request.get("roles"), dict) else {},
        "readiness": {
            "authorization_granted": passed,
            "deploy_execution_ready": passed,
            "rollback_or_abort_ready": passed,
            "monitoring_required": passed,
        },
        "boundary": _boundary(request_written=True, authorization_granted=passed),
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(output_root / "private_beta_deploy_ops_authorization.json", report)
    return report


def validate_authorization(path: Path, *, output: Path | None = None) -> dict[str, Any]:
    failures: list[str] = []
    authorization = _read_json(path, failures, "deploy ops authorization")
    if authorization.get("schema_version") != AUTHORIZATION_SCHEMA:
        failures.append(f"authorization schema_version must be {AUTHORIZATION_SCHEMA}")
    if authorization.get("passed") is not True:
        failures.append("authorization must be passed")
    if authorization.get("decision") != "private_beta_deploy_ops_authorized_once":
        failures.append("authorization decision must authorize once")
    if authorization.get("single_use") is not True or authorization.get("consumed") is not False:
        failures.append("authorization must be single_use and unconsumed")
    scope = authorization.get("authorized_scope") if isinstance(authorization.get("authorized_scope"), dict) else {}
    if scope.get("public_ingress_allowed") is not False:
        failures.append("authorization must keep public_ingress_allowed=false")
    for key in ("production_runtime_execution_allowed", "production_receipt_write_allowed"):
        if scope.get(key) is not False:
            failures.append(f"authorization must keep {key}=false")
    _validate_boundary(authorization.get("boundary"), failures)
    report = {
        "schema_version": VALIDATION_SCHEMA,
        "checked_at": _now(),
        "passed": not failures,
        "failure_reasons": failures,
        "authorization": artifact_ref(path) if path.is_file() else {"path": str(path.resolve()), "sha256": None},
        "authorization_id": authorization.get("authorization_id"),
        "readiness": {
            "deploy_ops_authorization_valid": not failures,
            "deploy_execution_ready": not failures,
            "rollback_or_abort_ready": not failures,
            "monitoring_required": not failures,
        },
    }
    if output:
        _write_json(output, report)
    return report


def _validate_handoff(handoff: Any, failures: list[str]) -> None:
    if not isinstance(handoff, dict):
        failures.append("frontend chain handoff must be an object")
        return
    if handoff.get("schema_version") != HANDOFF_SCHEMA:
        failures.append(f"frontend chain handoff schema_version must be {HANDOFF_SCHEMA}")
    if handoff.get("passed") is not True:
        failures.append("frontend chain handoff must be passed")
    if handoff.get("decision") != "beta_fe_frontend_operator_handoff_ready":
        failures.append("frontend chain handoff decision must be ready")
    boundary = handoff.get("handoff_boundary") if isinstance(handoff.get("handoff_boundary"), dict) else {}
    for key in ("deploy_allowed", "production_runtime_execution_allowed", "production_receipt_write_allowed"):
        if boundary.get(key) is not False:
            failures.append(f"frontend chain handoff boundary must keep {key}=false")


def _validate_index(index: Any, handoff: Any, failures: list[str]) -> None:
    if not isinstance(index, dict):
        failures.append("frontend chain index must be an object")
        return
    if index.get("schema_version") != INDEX_SCHEMA:
        failures.append(f"frontend chain index schema_version must be {INDEX_SCHEMA}")
    if index.get("passed") is not True:
        failures.append("frontend chain index must be passed")
    chain_id = str(handoff.get("chain_id") or "") if isinstance(handoff, dict) else ""
    chains = index.get("chains") if isinstance(index.get("chains"), list) else []
    if chain_id and chain_id not in {str(item.get("chain_id") or "") for item in chains if isinstance(item, dict)}:
        failures.append("frontend chain index must include source handoff chain_id")


def _validate_preview(preview: Any, failures: list[str]) -> None:
    if not isinstance(preview, dict):
        failures.append("FE-10 preview receipt must be an object")
        return
    if preview.get("schema_version") != FE10_SCHEMA:
        failures.append(f"FE-10 preview receipt schema_version must be {FE10_SCHEMA}")
    if preview.get("passed") is not True:
        failures.append("FE-10 preview receipt must be passed")
    auth = preview.get("backend_auth") if isinstance(preview.get("backend_auth"), dict) else {}
    if auth.get("auth_method") != "service_token":
        failures.append("FE-10 preview must use service_token auth")
    if auth.get("token_recorded") is not False:
        failures.append("FE-10 preview must not record service token")
    boundary = preview.get("boundary") if isinstance(preview.get("boundary"), dict) else {}
    for key in ("deploy_allowed", "production_runtime_execution_allowed", "production_receipt_write_allowed"):
        if boundary.get(key) is not False:
            failures.append(f"FE-10 preview boundary must keep {key}=false")


def _validate_roles(roles: dict[str, str], failures: list[str]) -> None:
    seen: set[str] = set()
    for key, value in roles.items():
        text = str(value or "").strip()
        if not text:
            failures.append(f"{key} is required")
        if _unsafe_text(text):
            failures.append(f"{key} must not be placeholder/public/production")
        if text in seen:
            failures.append(f"{key} must be distinct")
        seen.add(text)


def _validate_service_scopes(scopes: list[str], failures: list[str]) -> None:
    normalized = {str(item).strip() for item in scopes if str(item).strip()}
    if not set(DEFAULT_SERVICE_SCOPES).issubset(normalized):
        failures.append(f"service_token_scopes missing required scopes: {sorted(set(DEFAULT_SERVICE_SCOPES) - normalized)}")
    forbidden = normalized & {"deploy:write", "production:write", "evidence:write", "admin", "root"}
    if forbidden:
        failures.append(f"service_token_scopes include forbidden scopes: {sorted(forbidden)}")


def _validate_boundary(boundary: Any, failures: list[str]) -> None:
    if not isinstance(boundary, dict):
        failures.append("authorization boundary must be an object")
        return
    if boundary.get("deploy_execution_authorized_once") is not True:
        failures.append("authorization boundary must set deploy_execution_authorized_once=true")
    if boundary.get("rollback_or_abort_authorized_once") is not True:
        failures.append("authorization boundary must set rollback_or_abort_authorized_once=true")
    for key in ("deploy_executed", "rollback_executed", "public_ingress_allowed", "production_runtime_execution_allowed", "production_receipt_write_allowed"):
        if boundary.get(key) is not False:
            failures.append(f"authorization boundary must keep {key}=false")


def _boundary(*, request_written: bool, authorization_granted: bool) -> dict[str, bool]:
    return {
        "authorization_request_written": request_written,
        "single_use_authorization_written": authorization_granted,
        "deploy_execution_authorized_once": authorization_granted,
        "rollback_or_abort_authorized_once": authorization_granted,
        "monitoring_required": request_written or authorization_granted,
        "deploy_executed": False,
        "rollback_executed": False,
        "public_ingress_allowed": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
    }


def _unsafe_text(value: str) -> bool:
    text = str(value or "").strip().lower()
    return not text or any(token in text for token in ("todo", "replace_me", "placeholder", "public", "production"))


def _source_refs(handoff: Path, index: Path, preview: Path) -> dict[str, dict[str, str | None]]:
    return {
        "frontend_chain_handoff": artifact_ref(handoff),
        "frontend_chain_index": artifact_ref(index),
        "preview_receipt": artifact_ref(preview),
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


def _digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True, default=str).encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


if __name__ == "__main__":
    raise SystemExit(main())
