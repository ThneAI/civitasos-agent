#!/usr/bin/env python3
"""Authorize and execute one Beta-5 controlled external deploy evidence gate.

This gate starts only after a valid Beta-5 local-controlled deploy receipt. It
requires an external non-production environment proof, explicit operator
authorization, rollback evidence, and an external smoke command. It writes a
receipt only when the deploy command and external smoke both pass. It never
authorizes production deploy, production runtime execution, or production
receipt writes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shlex
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from beta5_local_controlled_deploy_executor import RECEIPT_SCHEMA as LOCAL_DEPLOY_RECEIPT_SCHEMA
from beta5_local_controlled_deploy_executor import validate_deploy_receipt as validate_local_deploy_receipt


ENVIRONMENT_PROOF_SCHEMA = "beta5-external-deploy-environment-proof:v1"
ENVIRONMENT_PROOF_VALIDATION_SCHEMA = "beta5-external-deploy-environment-proof-validation:v1"
AUTHORIZATION_SCHEMA = "beta5-external-deploy-authorization:v1"
AUTHORIZATION_VALIDATION_SCHEMA = "beta5-external-deploy-authorization-validation:v1"
AUTHORIZATION_WRITE_SCHEMA = "beta5-external-deploy-authorization-write-report:v1"
EXECUTION_SCHEMA = "beta5-external-deploy-execution-report:v1"
RECEIPT_SCHEMA = "beta5-external-deploy-receipt:v1"
RECEIPT_VALIDATION_SCHEMA = "beta5-external-deploy-receipt-validation:v1"
DEPLOYMENT_MODE = "controlled_external_non_production"
ALLOWED_ENVIRONMENT_CLASSIFICATIONS = (
    "external_staging",
    "external_preview",
    "external_sandbox",
    "controlled_external",
)
NON_CLAIMS = (
    "beta5_external_deploy_is_l1_controlled_pilot_only",
    "beta5_external_deploy_requires_valid_local_controlled_deploy_receipt",
    "beta5_external_deploy_requires_external_non_production_environment_proof",
    "beta5_external_deploy_requires_explicit_operator_authorization",
    "beta5_external_deploy_requires_rollback_evidence_ref",
    "beta5_external_deploy_requires_external_smoke_success",
    "beta5_external_deploy_does_not_authorize_production_deploy",
    "beta5_external_deploy_does_not_authorize_production_runtime_execution",
    "beta5_external_deploy_does_not_claim_h3_production_readiness",
    "beta5_external_deploy_does_not_write_production_receipts",
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    template = subparsers.add_parser("write-environment-proof-template", help="write an external environment proof template")
    template.add_argument("--output", required=True)
    template.add_argument("--overwrite", action="store_true")

    validate_environment = subparsers.add_parser("validate-environment-proof", help="validate external environment proof")
    validate_environment.add_argument("--environment-proof", required=True)
    validate_environment.add_argument("--output")

    record = subparsers.add_parser("record-authorization", help="record external deploy authorization")
    record.add_argument("--local-deploy-receipt", required=True)
    record.add_argument("--environment-proof", required=True)
    record.add_argument("--deploy-target", required=True)
    record.add_argument("--deploy-command", required=True)
    record.add_argument("--external-smoke-command", required=True)
    record.add_argument("--working-directory", default=".")
    record.add_argument("--output", required=True)
    record.add_argument("--operator-id", default="l1-controlled-pilot-operator")
    record.add_argument("--reason", required=True)
    record.add_argument("--rollback-evidence-ref", required=True)
    record.add_argument("--ack-external-controlled-deploy", action="store_true")

    validate_authorization = subparsers.add_parser("validate-authorization", help="validate authorization")
    validate_authorization.add_argument("--authorization", required=True)
    validate_authorization.add_argument("--output")

    deploy = subparsers.add_parser("deploy", help="run authorized external deploy and smoke")
    deploy.add_argument("--authorization", required=True)
    deploy.add_argument("--output-root", required=True)

    validate_receipt = subparsers.add_parser("validate-receipt", help="validate external deploy receipt")
    validate_receipt.add_argument("--receipt", required=True)
    validate_receipt.add_argument("--output")

    args = parser.parse_args(argv)
    if args.command == "write-environment-proof-template":
        report = write_environment_proof_template(Path(args.output), overwrite=bool(args.overwrite))
    elif args.command == "validate-environment-proof":
        report = validate_environment_proof(Path(args.environment_proof))
        if args.output:
            _write_json(Path(args.output), report)
    elif args.command == "record-authorization":
        report = record_external_deploy_authorization(
            local_deploy_receipt_path=Path(args.local_deploy_receipt),
            environment_proof_path=Path(args.environment_proof),
            deploy_target=args.deploy_target,
            deploy_command=args.deploy_command,
            external_smoke_command=args.external_smoke_command,
            working_directory=Path(args.working_directory),
            output_path=Path(args.output),
            operator_id=args.operator_id,
            reason=args.reason,
            rollback_evidence_ref=args.rollback_evidence_ref,
            ack_external_controlled_deploy=bool(args.ack_external_controlled_deploy),
        )
    elif args.command == "validate-authorization":
        report = validate_external_deploy_authorization(Path(args.authorization))
        if args.output:
            _write_json(Path(args.output), report)
    elif args.command == "deploy":
        report = run_external_deploy(authorization_path=Path(args.authorization), output_root=Path(args.output_root))
    elif args.command == "validate-receipt":
        report = validate_external_deploy_receipt(Path(args.receipt))
        if args.output:
            _write_json(Path(args.output), report)
    else:
        raise AssertionError(f"unknown command: {args.command}")
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    validation = report.get("receipt_validation") or report.get("validation") or report
    passed = validation.get("passed") and report.get("passed", True)
    return 0 if passed else 1


def write_environment_proof_template(output_path: Path, *, overwrite: bool = False) -> dict[str, Any]:
    if output_path.exists() and not overwrite:
        raise FileExistsError(f"refusing to overwrite existing environment proof template: {output_path}")
    proof = {
        "schema_version": ENVIRONMENT_PROOF_SCHEMA,
        "recorded_at": _now(),
        "environment_id": "TODO_REPLACE_EXTERNAL_ENVIRONMENT_ID",
        "environment_kind": "preview",
        "environment_classification": "external_preview",
        "environment_url": "TODO_REPLACE_EXTERNAL_PREVIEW_URL",
        "owner": "TODO_REPLACE_ENVIRONMENT_OWNER",
        "proof_ref": "TODO_REPLACE_ENVIRONMENT_PROOF_REF",
        "production_environment": False,
        "customer_traffic_allowed": False,
        "production_data_allowed": False,
        "destructive_action_allowed": False,
        "secret_material_included": False,
        "no_production_flags": _no_production_flags(),
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(output_path, proof)
    return {
        "schema_version": "beta5-external-deploy-environment-proof-template-write-report:v1",
        "template_written": True,
        "environment_proof_path": str(output_path.resolve()),
        "environment_proof_sha256": _sha256(output_path),
        "validation_expected_to_fail": True,
        "non_claims": list(NON_CLAIMS),
    }


def validate_environment_proof(path: Path) -> dict[str, Any]:
    failures: list[str] = []
    proof = _safe_read_json(path, failures, "external environment proof")
    if not isinstance(proof, dict):
        return _environment_validation_report(path, failures or ["environment proof must be a JSON object"])
    if proof.get("schema_version") != ENVIRONMENT_PROOF_SCHEMA:
        failures.append(f"schema_version must be {ENVIRONMENT_PROOF_SCHEMA}")
    for field in ("environment_id", "environment_kind", "environment_classification", "environment_url", "owner", "proof_ref"):
        if not _text(proof.get(field)):
            failures.append(f"{field} must be a non-empty string")
    classification = proof.get("environment_classification")
    if classification not in ALLOWED_ENVIRONMENT_CLASSIFICATIONS:
        failures.append(f"environment_classification must be one of {list(ALLOWED_ENVIRONMENT_CLASSIFICATIONS)}")
    for flag in (
        "production_environment",
        "customer_traffic_allowed",
        "production_data_allowed",
        "destructive_action_allowed",
        "secret_material_included",
    ):
        if proof.get(flag) is not False:
            failures.append(f"{flag} must be false")
    if proof.get("no_production_flags") != _no_production_flags():
        failures.append("no_production_flags must preserve all false production boundary flags")
    if _contains_placeholder(proof):
        failures.append("environment proof must not contain TODO/placeholder tokens")
    return _environment_validation_report(path, failures)


def record_external_deploy_authorization(
    *,
    local_deploy_receipt_path: Path,
    environment_proof_path: Path,
    deploy_target: str,
    deploy_command: str,
    external_smoke_command: str,
    working_directory: Path,
    output_path: Path,
    operator_id: str,
    reason: str,
    rollback_evidence_ref: str,
    ack_external_controlled_deploy: bool,
) -> dict[str, Any]:
    failures: list[str] = []
    local_receipt = _load_local_deploy_receipt(local_deploy_receipt_path, failures)
    environment_proof = _load_environment_proof(environment_proof_path, failures)
    workdir = _working_directory(working_directory, failures)
    deploy_target = _required_text(deploy_target, failures, "deploy_target")
    operator_id = _required_text(operator_id, failures, "operator_id")
    reason = _required_text(reason, failures, "reason")
    rollback_evidence_ref = _required_text(rollback_evidence_ref, failures, "rollback_evidence_ref")
    deploy_argv = _command_argv_from_raw(deploy_command, failures, "deploy_command")
    smoke_argv = _command_argv_from_raw(external_smoke_command, failures, "external_smoke_command")
    if ack_external_controlled_deploy is not True:
        failures.append("external deploy authorization requires explicit acknowledgement")
    if failures:
        raise ValueError(f"external deploy authorization blocked: {failures}")

    authorization = {
        "schema_version": AUTHORIZATION_SCHEMA,
        "recorded_at": _now(),
        "request_id": local_receipt["request_id"],
        "authorization_scope": "post_local_deploy_controlled_external_evidence_only",
        "deployment_mode": DEPLOYMENT_MODE,
        "operator_id": operator_id,
        "reason": reason,
        "rollback_evidence_ref": rollback_evidence_ref,
        "ack_external_controlled_deploy": True,
        "source_beta5_local_deploy_receipt": _artifact_ref(local_deploy_receipt_path),
        "source_beta5_github_merge_receipt": local_receipt["source_beta5_github_merge_receipt"],
        "source_beta5_merge_authorization": local_receipt["source_beta5_merge_authorization"],
        "source_merge_commit_id": local_receipt["source_merge_commit_id"],
        "github_repo": local_receipt["github_repo"],
        "pr_number": local_receipt["pr_number"],
        "source_branch": local_receipt["source_branch"],
        "base_branch": local_receipt["base_branch"],
        "source_local_deploy_target": local_receipt["deploy_target"],
        "external_environment_proof": _artifact_ref(environment_proof_path),
        "external_environment": _environment_summary(environment_proof),
        "working_directory": str(workdir),
        "deploy_target": deploy_target,
        "deploy_command": {"raw": deploy_command, "argv": deploy_argv, "shell": False},
        "external_smoke_command": {"raw": external_smoke_command, "argv": smoke_argv, "shell": False},
        "external_deploy_authorized": True,
        "external_deploy_performed": False,
        "external_smoke_performed": False,
        "production_deploy_allowed": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
        "no_production_flags": _no_production_flags(),
        "h3_boundary": _h3_boundary(),
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(output_path, authorization)
    validation = validate_external_deploy_authorization(output_path)
    if validation["passed"] is not True:
        raise ValueError(f"written external deploy authorization failed validation: {validation['failure_reasons']}")
    return {
        "schema_version": AUTHORIZATION_WRITE_SCHEMA,
        "authorization_written": True,
        "authorization_path": str(output_path.resolve()),
        "authorization_sha256": _sha256(output_path),
        "request_id": local_receipt["request_id"],
        "validation": validation,
        "non_claims": list(NON_CLAIMS),
    }


def validate_external_deploy_authorization(path: Path) -> dict[str, Any]:
    failures: list[str] = []
    authorization = _safe_read_json(path, failures, "external deploy authorization")
    if not isinstance(authorization, dict):
        return _authorization_validation_report(path, failures or ["authorization must be a JSON object"])
    _validate_authorization_static(authorization, failures)
    return _authorization_validation_report(path, failures)


def run_external_deploy(*, authorization_path: Path, output_root: Path) -> dict[str, Any]:
    output_root = output_root.resolve()
    output_root.mkdir(parents=True, exist_ok=True)
    validation = validate_external_deploy_authorization(authorization_path)
    if validation.get("passed") is not True:
        report = _authorization_refusal_report(authorization_path, validation)
        _write_json(output_root / "beta5_external_deploy_execution_report.json", report)
        return report

    failures: list[str] = []
    failure_codes: list[str] = []
    authorization = _read_json_object(authorization_path)
    workdir = _working_directory(Path(authorization.get("working_directory", "")), failures)
    deploy = _run_command(workdir, _command_argv(authorization, "deploy_command", failures), failures) if workdir else None
    if deploy and deploy["returncode"] != 0:
        _append_code(failure_codes, "external_deploy_command_failed")
    smoke = None
    if deploy and deploy["returncode"] == 0 and workdir:
        smoke = _run_command(workdir, _command_argv(authorization, "external_smoke_command", failures), failures)
        if smoke["returncode"] != 0:
            _append_code(failure_codes, "external_deploy_smoke_failed")
    deploy_performed = bool(deploy and deploy["returncode"] == 0)
    smoke_performed = bool(smoke and smoke["returncode"] == 0)
    if not deploy_performed:
        failures.append("external deploy command was not performed successfully")
        _append_code(failure_codes, "external_deploy_not_successful")
    if not smoke_performed:
        failures.append("external smoke command was not performed successfully")
        _append_code(failure_codes, "external_smoke_not_successful")

    receipt_path = output_root / "beta5_external_deploy_receipt.json"
    receipt_validation = None
    if not failures:
        _write_external_deploy_receipt(
            receipt_path=receipt_path,
            authorization_path=authorization_path,
            authorization=authorization,
            deploy=deploy,
            smoke=smoke,
        )
        receipt_validation = validate_external_deploy_receipt(receipt_path)
        if receipt_validation["passed"] is not True:
            failures.extend(f"receipt invalid: {reason}" for reason in receipt_validation["failure_reasons"])
            _append_code(failure_codes, "external_deploy_receipt_invalid")

    report = {
        "schema_version": EXECUTION_SCHEMA,
        "passed": not failures,
        "deploy_status": "controlled_external_deployed_with_receipt" if not failures else "blocked_or_failed",
        "failure_reasons": failures,
        "failure_codes": failure_codes,
        "checked_at": _now(),
        "source_external_deploy_authorization": _artifact_ref(authorization_path),
        "source_external_deploy_authorization_validation": validation,
        "source_beta5_local_deploy_receipt": authorization.get("source_beta5_local_deploy_receipt"),
        "external_environment": authorization.get("external_environment"),
        "working_directory": authorization.get("working_directory"),
        "deploy_target": authorization.get("deploy_target"),
        "deploy": deploy,
        "external_smoke": smoke,
        "deploy_receipt_path": str(receipt_path.resolve()) if receipt_path.is_file() else None,
        "receipt_validation": receipt_validation,
        "external_deploy_performed": deploy_performed,
        "external_smoke_performed": smoke_performed,
        "production_deploy_allowed": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
        "no_production_flags": _no_production_flags(),
        "h3_boundary": _h3_boundary(),
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(output_root / "beta5_external_deploy_execution_report.json", report)
    return report


def validate_external_deploy_receipt(path: Path) -> dict[str, Any]:
    failures: list[str] = []
    receipt = _safe_read_json(path, failures, "external deploy receipt")
    if not isinstance(receipt, dict):
        return _receipt_validation_report(path, failures or ["receipt must be a JSON object"])
    if receipt.get("schema_version") != RECEIPT_SCHEMA:
        failures.append(f"schema_version must be {RECEIPT_SCHEMA}")
    if receipt.get("receipt_scope") != "post_local_deploy_controlled_external_evidence_only":
        failures.append("receipt_scope must be post_local_deploy_controlled_external_evidence_only")
    if receipt.get("deployment_mode") != DEPLOYMENT_MODE:
        failures.append(f"deployment_mode must be {DEPLOYMENT_MODE}")
    authorization_ref = _as_ref(receipt.get("source_external_deploy_authorization"), failures, "source_external_deploy_authorization")
    authorization_path = _validate_ref_bytes(authorization_ref, failures, "source_external_deploy_authorization")
    authorization = _safe_read_json(authorization_path, failures, "external deploy authorization")
    if not isinstance(authorization, dict):
        authorization = {}
    _validate_authorization_static(authorization, failures)
    for field in (
        "request_id",
        "source_beta5_local_deploy_receipt",
        "source_beta5_github_merge_receipt",
        "source_beta5_merge_authorization",
        "source_merge_commit_id",
        "github_repo",
        "pr_number",
        "source_branch",
        "base_branch",
        "source_local_deploy_target",
        "external_environment_proof",
        "external_environment",
        "working_directory",
        "deploy_target",
        "deploy_command",
        "external_smoke_command",
        "rollback_evidence_ref",
    ):
        if receipt.get(field) != authorization.get(field):
            failures.append(f"{field} must match external deploy authorization")
    if receipt.get("external_deploy_performed") is not True:
        failures.append("external_deploy_performed must be true")
    if receipt.get("external_smoke_performed") is not True:
        failures.append("external_smoke_performed must be true")
    _validate_no_production_boundary(receipt, failures)
    _validate_h3_boundary(receipt, failures)
    for command_field in ("deploy", "external_smoke"):
        command = _as_dict(receipt.get(command_field), failures, command_field)
        if command.get("returncode") != 0:
            failures.append(f"{command_field}.returncode must be zero")
    return _receipt_validation_report(path, failures)


def _validate_authorization_static(authorization: dict[str, Any], failures: list[str]) -> dict[str, Any]:
    if authorization.get("schema_version") != AUTHORIZATION_SCHEMA:
        failures.append(f"schema_version must be {AUTHORIZATION_SCHEMA}")
    if authorization.get("authorization_scope") != "post_local_deploy_controlled_external_evidence_only":
        failures.append("authorization_scope must be post_local_deploy_controlled_external_evidence_only")
    if authorization.get("deployment_mode") != DEPLOYMENT_MODE:
        failures.append(f"deployment_mode must be {DEPLOYMENT_MODE}")
    for field in ("operator_id", "reason", "rollback_evidence_ref", "source_merge_commit_id", "base_branch", "deploy_target"):
        if not _text(authorization.get(field)):
            failures.append(f"{field} must be a non-empty string")
    if authorization.get("ack_external_controlled_deploy") is not True:
        failures.append("ack_external_controlled_deploy must be true")
    for field in ("deploy_command", "external_smoke_command"):
        command = _as_dict(authorization.get(field), failures, field)
        if command.get("shell") is not False:
            failures.append(f"{field}.shell must be false")
        if not _text(command.get("raw")):
            failures.append(f"{field}.raw must be non-empty")
        if not _argv_valid(command.get("argv")):
            failures.append(f"{field}.argv must be a non-empty list of strings")
    if authorization.get("external_deploy_authorized") is not True:
        failures.append("external_deploy_authorized must be true")
    if authorization.get("external_deploy_performed") is not False:
        failures.append("external_deploy_performed must be false before execution")
    if authorization.get("external_smoke_performed") is not False:
        failures.append("external_smoke_performed must be false before execution")
    _validate_no_production_boundary(authorization, failures)
    _validate_h3_boundary(authorization, failures)
    local_ref = _as_ref(authorization.get("source_beta5_local_deploy_receipt"), failures, "source_beta5_local_deploy_receipt")
    local_path = _validate_ref_bytes(local_ref, failures, "source_beta5_local_deploy_receipt")
    local_receipt = _load_local_deploy_receipt(local_path, failures) if local_path else {}
    proof_ref = _as_ref(authorization.get("external_environment_proof"), failures, "external_environment_proof")
    proof_path = _validate_ref_bytes(proof_ref, failures, "external_environment_proof")
    environment_proof = _load_environment_proof(proof_path, failures) if proof_path else {}
    if environment_proof and authorization.get("external_environment") != _environment_summary(environment_proof):
        failures.append("external_environment must match external environment proof summary")
    if local_receipt:
        for field in ("request_id", "source_beta5_github_merge_receipt", "source_beta5_merge_authorization", "source_merge_commit_id", "github_repo", "pr_number", "source_branch", "base_branch"):
            if authorization.get(field) != local_receipt.get(field):
                failures.append(f"{field} must match Beta-5 local-controlled deploy receipt")
        if authorization.get("source_local_deploy_target") != local_receipt.get("deploy_target"):
            failures.append("source_local_deploy_target must match Beta-5 local-controlled deploy receipt")
    _working_directory(Path(_text(authorization.get("working_directory"))), failures)
    return local_receipt


def _load_local_deploy_receipt(path: Path | None, failures: list[str]) -> dict[str, Any]:
    if path is None:
        return {}
    validation = validate_local_deploy_receipt(path)
    if validation.get("passed") is not True:
        failures.extend(f"Beta-5 local deploy receipt invalid: {reason}" for reason in validation.get("failure_reasons", []))
    receipt = _safe_read_json(path, failures, "Beta-5 local deploy receipt")
    if not isinstance(receipt, dict):
        return {}
    if receipt.get("schema_version") != LOCAL_DEPLOY_RECEIPT_SCHEMA:
        failures.append(f"Beta-5 local deploy receipt schema_version must be {LOCAL_DEPLOY_RECEIPT_SCHEMA}")
    if receipt.get("local_deploy_performed") is not True:
        failures.append("Beta-5 local deploy receipt must have local_deploy_performed=true")
    if receipt.get("smoke_performed") is not True:
        failures.append("Beta-5 local deploy receipt must have smoke_performed=true")
    if receipt.get("external_deploy_allowed") is not False:
        failures.append("Beta-5 local deploy receipt must not already allow external deploy")
    return receipt


def _load_environment_proof(path: Path | None, failures: list[str]) -> dict[str, Any]:
    if path is None:
        return {}
    validation = validate_environment_proof(path)
    if validation.get("passed") is not True:
        failures.extend(f"external environment proof invalid: {reason}" for reason in validation.get("failure_reasons", []))
    proof = _safe_read_json(path, failures, "external environment proof")
    return proof if isinstance(proof, dict) else {}


def _write_external_deploy_receipt(
    *,
    receipt_path: Path,
    authorization_path: Path,
    authorization: dict[str, Any],
    deploy: dict[str, Any] | None,
    smoke: dict[str, Any] | None,
) -> None:
    receipt = {
        "schema_version": RECEIPT_SCHEMA,
        "recorded_at": _now(),
        "request_id": authorization["request_id"],
        "receipt_scope": "post_local_deploy_controlled_external_evidence_only",
        "deployment_mode": DEPLOYMENT_MODE,
        "source_external_deploy_authorization": _artifact_ref(authorization_path),
        "source_beta5_local_deploy_receipt": authorization["source_beta5_local_deploy_receipt"],
        "source_beta5_github_merge_receipt": authorization["source_beta5_github_merge_receipt"],
        "source_beta5_merge_authorization": authorization["source_beta5_merge_authorization"],
        "source_merge_commit_id": authorization["source_merge_commit_id"],
        "github_repo": authorization["github_repo"],
        "pr_number": authorization["pr_number"],
        "source_branch": authorization["source_branch"],
        "base_branch": authorization["base_branch"],
        "source_local_deploy_target": authorization["source_local_deploy_target"],
        "external_environment_proof": authorization["external_environment_proof"],
        "external_environment": authorization["external_environment"],
        "working_directory": authorization["working_directory"],
        "deploy_target": authorization["deploy_target"],
        "deploy_command": authorization["deploy_command"],
        "external_smoke_command": authorization["external_smoke_command"],
        "rollback_evidence_ref": authorization["rollback_evidence_ref"],
        "deploy": deploy,
        "external_smoke": smoke,
        "external_deploy_performed": True,
        "external_smoke_performed": True,
        "production_deploy_allowed": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
        "no_production_flags": _no_production_flags(),
        "h3_boundary": _h3_boundary(),
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(receipt_path, receipt)


def _environment_summary(proof: dict[str, Any]) -> dict[str, Any]:
    return {
        "environment_id": proof.get("environment_id"),
        "environment_kind": proof.get("environment_kind"),
        "environment_classification": proof.get("environment_classification"),
        "environment_url": proof.get("environment_url"),
        "owner": proof.get("owner"),
        "proof_ref": proof.get("proof_ref"),
        "production_environment": proof.get("production_environment"),
        "customer_traffic_allowed": proof.get("customer_traffic_allowed"),
        "production_data_allowed": proof.get("production_data_allowed"),
    }


def _authorization_refusal_report(path: Path, validation: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": EXECUTION_SCHEMA,
        "passed": False,
        "deploy_status": "authorization_refused",
        "failure_reasons": [f"authorization failed validation: {reason}" for reason in validation.get("failure_reasons", [])],
        "failure_codes": ["external_deploy_authorization_refused"],
        "checked_at": _now(),
        "source_external_deploy_authorization": _artifact_ref_or_path(path),
        "source_external_deploy_authorization_validation": validation,
        "deploy_receipt_path": None,
        "receipt_validation": None,
        "external_deploy_performed": False,
        "external_smoke_performed": False,
        "production_deploy_allowed": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
        "no_production_flags": _no_production_flags(),
        "h3_boundary": _h3_boundary(),
        "non_claims": list(NON_CLAIMS),
    }


def _working_directory(path: Path, failures: list[str]) -> Path | None:
    text = _text(str(path))
    if not text:
        failures.append("working_directory must be a non-empty path")
        return None
    resolved = Path(text).resolve()
    if not resolved.is_dir():
        failures.append(f"working_directory must exist: {resolved}")
        return None
    return resolved


def _validate_no_production_boundary(payload: dict[str, Any], failures: list[str]) -> None:
    for flag in ("production_deploy_allowed", "production_runtime_execution_allowed", "production_receipt_write_allowed"):
        if payload.get(flag) is not False:
            failures.append(f"{flag} must be false")
    if payload.get("no_production_flags") != _no_production_flags():
        failures.append("no_production_flags must preserve all false production boundary flags")


def _no_production_flags() -> dict[str, bool]:
    return {
        "production_environment": False,
        "customer_traffic_allowed": False,
        "production_data_allowed": False,
        "production_deploy_allowed": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
        "h3_production_readiness_claimed": False,
    }


def _validate_h3_boundary(payload: dict[str, Any], failures: list[str]) -> None:
    if payload.get("h3_boundary") != _h3_boundary():
        failures.append("h3_boundary must keep production readiness blocked")


def _h3_boundary() -> dict[str, bool]:
    return {"h3_remains_blocked": True, "h3_production_readiness_claimed": False}


def _environment_validation_report(path: Path, failures: list[str]) -> dict[str, Any]:
    return {
        "schema_version": ENVIRONMENT_PROOF_VALIDATION_SCHEMA,
        "passed": not failures,
        "failure_reasons": failures,
        "checked_at": _now(),
        "environment_proof_path": str(path.resolve()),
        "environment_proof_sha256": _sha256(path) if path.is_file() else None,
        "non_claims": list(NON_CLAIMS),
    }


def _authorization_validation_report(path: Path, failures: list[str]) -> dict[str, Any]:
    return {
        "schema_version": AUTHORIZATION_VALIDATION_SCHEMA,
        "passed": not failures,
        "failure_reasons": failures,
        "checked_at": _now(),
        "authorization_path": str(path.resolve()),
        "authorization_sha256": _sha256(path) if path.is_file() else None,
        "non_claims": list(NON_CLAIMS),
    }


def _receipt_validation_report(path: Path, failures: list[str]) -> dict[str, Any]:
    return {
        "schema_version": RECEIPT_VALIDATION_SCHEMA,
        "passed": not failures,
        "failure_reasons": failures,
        "checked_at": _now(),
        "receipt_path": str(path.resolve()),
        "receipt_sha256": _sha256(path) if path.is_file() else None,
        "non_claims": list(NON_CLAIMS),
    }


def _artifact_ref(path: Path) -> dict[str, str]:
    if not path.is_file():
        raise FileNotFoundError(f"artifact path is not a file: {path}")
    return {"path": str(path.resolve()), "sha256": _sha256(path)}


def _artifact_ref_or_path(path: Path) -> dict[str, str | None]:
    return {"path": str(path.resolve()), "sha256": _sha256(path) if path.is_file() else None}


def _validate_ref_bytes(ref: dict[str, Any], failures: list[str], label: str) -> Path | None:
    path_text = _text(ref.get("path"))
    if not path_text:
        failures.append(f"{label}.path must be a non-empty string")
        return None
    path = Path(path_text)
    if not path.is_file():
        failures.append(f"{label}.path is not a file: {path}")
        return None
    if ref.get("sha256") != _sha256(path):
        failures.append(f"{label}.sha256 does not match file bytes")
    return path


def _as_ref(value: Any, failures: list[str], label: str) -> dict[str, Any]:
    return _as_dict(value, failures, label)


def _as_dict(value: Any, failures: list[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        failures.append(f"{label} must be an object")
        return {}
    return value


def _command_argv(authorization: dict[str, Any], field: str, failures: list[str]) -> list[str]:
    command = _as_dict(authorization.get(field), failures, field)
    argv = command.get("argv")
    if not _argv_valid(argv):
        failures.append(f"{field}.argv must be a non-empty list of strings")
        return []
    return list(argv)


def _command_argv_from_raw(raw: str, failures: list[str], label: str) -> list[str]:
    raw = _required_text(raw, failures, label)
    try:
        argv = shlex.split(raw)
    except ValueError as exc:
        failures.append(f"{label} must parse as argv: {exc}")
        return []
    if not _argv_valid(argv):
        failures.append(f"{label} must parse to non-empty argv tokens")
    return argv


def _argv_valid(value: Any) -> bool:
    return isinstance(value, list) and bool(value) and all(isinstance(item, str) and item for item in value)


def _run_command(cwd: Path, argv: list[str], failures: list[str]) -> dict[str, Any]:
    if not argv:
        failures.append("command argv cannot be empty")
        return {"command": [], "returncode": 1, "stdout": "", "stderr": "empty command"}
    result = subprocess.run(argv, cwd=cwd, check=False, text=True, capture_output=True)
    run = {"command": argv, "returncode": result.returncode, "stdout": result.stdout, "stderr": result.stderr}
    if run["returncode"] != 0:
        failures.append(f"command failed: {' '.join(argv)}")
    return run


def _read_json_object(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"JSON payload must be an object: {path}")
    return payload


def _safe_read_json(path: Path | None, failures: list[str], label: str) -> Any:
    if path is None:
        failures.append(f"missing {label} path")
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 - validation should return reasons, not raise.
        failures.append(f"failed to read {label}: {exc}")
        return None


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _required_text(value: Any, failures: list[str], label: str) -> str:
    text = _text(value)
    if not text:
        failures.append(f"{label} must be a non-empty string")
    return text


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _contains_placeholder(value: Any) -> bool:
    if isinstance(value, str):
        upper = value.upper()
        return any(token in upper for token in ("TODO", "REPLACE_ME", "TO_BE_FILLED", "PLACEHOLDER", "TEMPLATE_ONLY"))
    if isinstance(value, dict):
        return any(_contains_placeholder(item) for item in value.values())
    if isinstance(value, list):
        return any(_contains_placeholder(item) for item in value)
    return False


def _append_code(codes: list[str], code: str) -> None:
    if code not in codes:
        codes.append(code)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


if __name__ == "__main__":
    raise SystemExit(main())
