#!/usr/bin/env python3
"""Record and execute a Beta-5 external deploy rollback drill.

The drill consumes a valid Beta-5 external deploy receipt, records explicit
operator authorization, runs a rollback command plus a rollback smoke command,
and writes a receipt only when both pass. It keeps all production flags false
and does not claim H.3 production readiness.
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

from beta5_external_deploy_evidence_executor import RECEIPT_SCHEMA as EXTERNAL_DEPLOY_RECEIPT_SCHEMA
from beta5_external_deploy_evidence_executor import validate_external_deploy_receipt


AUTHORIZATION_SCHEMA = "beta5-external-deploy-rollback-drill-authorization:v1"
AUTHORIZATION_VALIDATION_SCHEMA = "beta5-external-deploy-rollback-drill-authorization-validation:v1"
AUTHORIZATION_WRITE_SCHEMA = "beta5-external-deploy-rollback-drill-authorization-write-report:v1"
EXECUTION_SCHEMA = "beta5-external-deploy-rollback-drill-execution-report:v1"
RECEIPT_SCHEMA = "beta5-external-deploy-rollback-drill-receipt:v1"
RECEIPT_VALIDATION_SCHEMA = "beta5-external-deploy-rollback-drill-receipt-validation:v1"
DRILL_SCOPE = "post_external_deploy_rollback_drill_only"
NON_CLAIMS = (
    "beta5_external_rollback_drill_is_l1_controlled_pilot_only",
    "beta5_external_rollback_drill_requires_valid_external_deploy_receipt",
    "beta5_external_rollback_drill_requires_explicit_operator_authorization",
    "beta5_external_rollback_drill_requires_rollback_command_success",
    "beta5_external_rollback_drill_requires_rollback_smoke_success",
    "beta5_external_rollback_drill_does_not_authorize_production_deploy",
    "beta5_external_rollback_drill_does_not_authorize_production_runtime_execution",
    "beta5_external_rollback_drill_does_not_claim_h3_production_readiness",
    "beta5_external_rollback_drill_does_not_write_production_receipts",
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    record = subparsers.add_parser("record-authorization", help="record rollback drill authorization")
    record.add_argument("--external-deploy-receipt", required=True)
    record.add_argument("--rollback-command", required=True)
    record.add_argument("--rollback-smoke-command", required=True)
    record.add_argument("--working-directory", default=".")
    record.add_argument("--output", required=True)
    record.add_argument("--operator-id", default="l1-controlled-pilot-operator")
    record.add_argument("--reason", required=True)
    record.add_argument("--ack-rollback-drill", action="store_true")

    validate_authorization = subparsers.add_parser("validate-authorization", help="validate authorization")
    validate_authorization.add_argument("--authorization", required=True)
    validate_authorization.add_argument("--output")

    execute = subparsers.add_parser("execute", help="run authorized rollback drill")
    execute.add_argument("--authorization", required=True)
    execute.add_argument("--output-root", required=True)

    validate_receipt = subparsers.add_parser("validate-receipt", help="validate rollback drill receipt")
    validate_receipt.add_argument("--receipt", required=True)
    validate_receipt.add_argument("--output")

    args = parser.parse_args(argv)
    if args.command == "record-authorization":
        report = record_rollback_authorization(
            external_deploy_receipt_path=Path(args.external_deploy_receipt),
            rollback_command=args.rollback_command,
            rollback_smoke_command=args.rollback_smoke_command,
            working_directory=Path(args.working_directory),
            output_path=Path(args.output),
            operator_id=args.operator_id,
            reason=args.reason,
            ack_rollback_drill=bool(args.ack_rollback_drill),
        )
    elif args.command == "validate-authorization":
        report = validate_rollback_authorization(Path(args.authorization))
        if args.output:
            _write_json(Path(args.output), report)
    elif args.command == "execute":
        report = run_rollback_drill(authorization_path=Path(args.authorization), output_root=Path(args.output_root))
    elif args.command == "validate-receipt":
        report = validate_rollback_receipt(Path(args.receipt))
        if args.output:
            _write_json(Path(args.output), report)
    else:
        raise AssertionError(f"unknown command: {args.command}")
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    validation = report.get("receipt_validation") or report.get("validation") or report
    passed = validation.get("passed") and report.get("passed", True)
    return 0 if passed else 1


def record_rollback_authorization(
    *,
    external_deploy_receipt_path: Path,
    rollback_command: str,
    rollback_smoke_command: str,
    working_directory: Path,
    output_path: Path,
    operator_id: str,
    reason: str,
    ack_rollback_drill: bool,
) -> dict[str, Any]:
    failures: list[str] = []
    external_receipt = _load_external_deploy_receipt(external_deploy_receipt_path, failures)
    workdir = _working_directory(working_directory, failures)
    rollback_argv = _command_argv_from_raw(rollback_command, failures, "rollback_command")
    smoke_argv = _command_argv_from_raw(rollback_smoke_command, failures, "rollback_smoke_command")
    operator_id = _required_text(operator_id, failures, "operator_id")
    reason = _required_text(reason, failures, "reason")
    if ack_rollback_drill is not True:
        failures.append("rollback drill authorization requires explicit acknowledgement")
    if failures:
        raise ValueError(f"rollback drill authorization blocked: {failures}")

    authorization = {
        "schema_version": AUTHORIZATION_SCHEMA,
        "recorded_at": _now(),
        "request_id": external_receipt["request_id"],
        "authorization_scope": DRILL_SCOPE,
        "operator_id": operator_id,
        "reason": reason,
        "ack_rollback_drill": True,
        "source_beta5_external_deploy_receipt": _artifact_ref(external_deploy_receipt_path),
        "source_beta5_local_deploy_receipt": external_receipt["source_beta5_local_deploy_receipt"],
        "source_beta5_github_merge_receipt": external_receipt["source_beta5_github_merge_receipt"],
        "source_merge_commit_id": external_receipt["source_merge_commit_id"],
        "github_repo": external_receipt["github_repo"],
        "pr_number": external_receipt["pr_number"],
        "external_environment": external_receipt["external_environment"],
        "deploy_target": external_receipt["deploy_target"],
        "external_deploy_receipt_rollback_ref": external_receipt["rollback_evidence_ref"],
        "working_directory": str(workdir),
        "rollback_command": {"raw": rollback_command, "argv": rollback_argv, "shell": False},
        "rollback_smoke_command": {"raw": rollback_smoke_command, "argv": smoke_argv, "shell": False},
        "rollback_drill_authorized": True,
        "rollback_performed": False,
        "rollback_smoke_performed": False,
        "production_deploy_allowed": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
        "h3_boundary": _h3_boundary(),
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(output_path, authorization)
    validation = validate_rollback_authorization(output_path)
    if validation["passed"] is not True:
        raise ValueError(f"written rollback drill authorization failed validation: {validation['failure_reasons']}")
    return {
        "schema_version": AUTHORIZATION_WRITE_SCHEMA,
        "authorization_written": True,
        "authorization_path": str(output_path.resolve()),
        "authorization_sha256": _sha256(output_path),
        "request_id": external_receipt["request_id"],
        "validation": validation,
        "non_claims": list(NON_CLAIMS),
    }


def validate_rollback_authorization(path: Path) -> dict[str, Any]:
    failures: list[str] = []
    authorization = _safe_read_json(path, failures, "rollback drill authorization")
    if not isinstance(authorization, dict):
        return _authorization_validation_report(path, failures or ["authorization must be a JSON object"])
    _validate_authorization_static(authorization, failures)
    return _authorization_validation_report(path, failures)


def run_rollback_drill(*, authorization_path: Path, output_root: Path) -> dict[str, Any]:
    output_root = output_root.resolve()
    output_root.mkdir(parents=True, exist_ok=True)
    validation = validate_rollback_authorization(authorization_path)
    if validation.get("passed") is not True:
        report = _authorization_refusal_report(authorization_path, validation)
        _write_json(output_root / "beta5_external_deploy_rollback_drill_execution_report.json", report)
        return report

    failures: list[str] = []
    failure_codes: list[str] = []
    authorization = _read_json_object(authorization_path)
    workdir = _working_directory(Path(authorization.get("working_directory", "")), failures)
    rollback = _run_command(workdir, _command_argv(authorization, "rollback_command", failures), failures) if workdir else None
    if rollback and rollback["returncode"] != 0:
        _append_code(failure_codes, "rollback_command_failed")
    smoke = None
    if rollback and rollback["returncode"] == 0 and workdir:
        smoke = _run_command(workdir, _command_argv(authorization, "rollback_smoke_command", failures), failures)
        if smoke["returncode"] != 0:
            _append_code(failure_codes, "rollback_smoke_failed")
    rollback_performed = bool(rollback and rollback["returncode"] == 0)
    smoke_performed = bool(smoke and smoke["returncode"] == 0)
    if not rollback_performed:
        failures.append("rollback command was not performed successfully")
        _append_code(failure_codes, "rollback_not_successful")
    if not smoke_performed:
        failures.append("rollback smoke command was not performed successfully")
        _append_code(failure_codes, "rollback_smoke_not_successful")

    receipt_path = output_root / "beta5_external_deploy_rollback_drill_receipt.json"
    receipt_validation = None
    if not failures:
        _write_rollback_receipt(
            receipt_path=receipt_path,
            authorization_path=authorization_path,
            authorization=authorization,
            rollback=rollback,
            smoke=smoke,
        )
        receipt_validation = validate_rollback_receipt(receipt_path)
        if receipt_validation["passed"] is not True:
            failures.extend(f"receipt invalid: {reason}" for reason in receipt_validation["failure_reasons"])
            _append_code(failure_codes, "rollback_receipt_invalid")

    report = {
        "schema_version": EXECUTION_SCHEMA,
        "passed": not failures,
        "rollback_status": "rolled_back_with_receipt" if not failures else "blocked_or_failed",
        "failure_reasons": failures,
        "failure_codes": failure_codes,
        "checked_at": _now(),
        "source_rollback_authorization": _artifact_ref(authorization_path),
        "source_rollback_authorization_validation": validation,
        "source_beta5_external_deploy_receipt": authorization.get("source_beta5_external_deploy_receipt"),
        "external_environment": authorization.get("external_environment"),
        "deploy_target": authorization.get("deploy_target"),
        "rollback": rollback,
        "rollback_smoke": smoke,
        "rollback_receipt_path": str(receipt_path.resolve()) if receipt_path.is_file() else None,
        "receipt_validation": receipt_validation,
        "rollback_performed": rollback_performed,
        "rollback_smoke_performed": smoke_performed,
        "production_deploy_allowed": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
        "h3_boundary": _h3_boundary(),
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(output_root / "beta5_external_deploy_rollback_drill_execution_report.json", report)
    return report


def validate_rollback_receipt(path: Path) -> dict[str, Any]:
    failures: list[str] = []
    receipt = _safe_read_json(path, failures, "rollback drill receipt")
    if not isinstance(receipt, dict):
        return _receipt_validation_report(path, failures or ["receipt must be a JSON object"])
    if receipt.get("schema_version") != RECEIPT_SCHEMA:
        failures.append(f"schema_version must be {RECEIPT_SCHEMA}")
    if receipt.get("receipt_scope") != DRILL_SCOPE:
        failures.append(f"receipt_scope must be {DRILL_SCOPE}")
    authorization_ref = _as_ref(receipt.get("source_rollback_authorization"), failures, "source_rollback_authorization")
    authorization_path = _validate_ref_bytes(authorization_ref, failures, "source_rollback_authorization")
    authorization = _safe_read_json(authorization_path, failures, "rollback drill authorization")
    if not isinstance(authorization, dict):
        authorization = {}
    _validate_authorization_static(authorization, failures)
    for field in (
        "request_id",
        "source_beta5_external_deploy_receipt",
        "source_beta5_local_deploy_receipt",
        "source_beta5_github_merge_receipt",
        "source_merge_commit_id",
        "github_repo",
        "pr_number",
        "external_environment",
        "deploy_target",
        "external_deploy_receipt_rollback_ref",
        "working_directory",
        "rollback_command",
        "rollback_smoke_command",
    ):
        if receipt.get(field) != authorization.get(field):
            failures.append(f"{field} must match rollback authorization")
    if receipt.get("rollback_performed") is not True:
        failures.append("rollback_performed must be true")
    if receipt.get("rollback_smoke_performed") is not True:
        failures.append("rollback_smoke_performed must be true")
    _validate_false_boundary_flags(receipt, failures)
    _validate_h3_boundary(receipt, failures)
    for command_field in ("rollback", "rollback_smoke"):
        command = _as_dict(receipt.get(command_field), failures, command_field)
        if command.get("returncode") != 0:
            failures.append(f"{command_field}.returncode must be zero")
    return _receipt_validation_report(path, failures)


def _validate_authorization_static(authorization: dict[str, Any], failures: list[str]) -> dict[str, Any]:
    if authorization.get("schema_version") != AUTHORIZATION_SCHEMA:
        failures.append(f"schema_version must be {AUTHORIZATION_SCHEMA}")
    if authorization.get("authorization_scope") != DRILL_SCOPE:
        failures.append(f"authorization_scope must be {DRILL_SCOPE}")
    for field in ("operator_id", "reason", "source_merge_commit_id", "deploy_target", "external_deploy_receipt_rollback_ref"):
        if not _text(authorization.get(field)):
            failures.append(f"{field} must be a non-empty string")
    if authorization.get("ack_rollback_drill") is not True:
        failures.append("ack_rollback_drill must be true")
    for field in ("rollback_command", "rollback_smoke_command"):
        command = _as_dict(authorization.get(field), failures, field)
        if command.get("shell") is not False:
            failures.append(f"{field}.shell must be false")
        if not _text(command.get("raw")):
            failures.append(f"{field}.raw must be non-empty")
        if not _argv_valid(command.get("argv")):
            failures.append(f"{field}.argv must be a non-empty list of strings")
    if authorization.get("rollback_drill_authorized") is not True:
        failures.append("rollback_drill_authorized must be true")
    if authorization.get("rollback_performed") is not False:
        failures.append("rollback_performed must be false before execution")
    if authorization.get("rollback_smoke_performed") is not False:
        failures.append("rollback_smoke_performed must be false before execution")
    _validate_false_boundary_flags(authorization, failures)
    _validate_h3_boundary(authorization, failures)
    external_ref = _as_ref(authorization.get("source_beta5_external_deploy_receipt"), failures, "source_beta5_external_deploy_receipt")
    external_path = _validate_ref_bytes(external_ref, failures, "source_beta5_external_deploy_receipt")
    external_receipt = _load_external_deploy_receipt(external_path, failures) if external_path else {}
    if external_receipt:
        for field in ("request_id", "source_beta5_local_deploy_receipt", "source_beta5_github_merge_receipt", "source_merge_commit_id", "github_repo", "pr_number", "external_environment", "deploy_target"):
            if authorization.get(field) != external_receipt.get(field):
                failures.append(f"{field} must match external deploy receipt")
        if authorization.get("external_deploy_receipt_rollback_ref") != external_receipt.get("rollback_evidence_ref"):
            failures.append("external_deploy_receipt_rollback_ref must match external deploy receipt rollback_evidence_ref")
    _working_directory(Path(_text(authorization.get("working_directory"))), failures)
    return external_receipt


def _load_external_deploy_receipt(path: Path | None, failures: list[str]) -> dict[str, Any]:
    if path is None:
        return {}
    validation = validate_external_deploy_receipt(path)
    if validation.get("passed") is not True:
        failures.extend(f"Beta-5 external deploy receipt invalid: {reason}" for reason in validation.get("failure_reasons", []))
    receipt = _safe_read_json(path, failures, "Beta-5 external deploy receipt")
    if not isinstance(receipt, dict):
        return {}
    if receipt.get("schema_version") != EXTERNAL_DEPLOY_RECEIPT_SCHEMA:
        failures.append(f"Beta-5 external deploy receipt schema_version must be {EXTERNAL_DEPLOY_RECEIPT_SCHEMA}")
    if receipt.get("external_deploy_performed") is not True:
        failures.append("Beta-5 external deploy receipt must have external_deploy_performed=true")
    if receipt.get("external_smoke_performed") is not True:
        failures.append("Beta-5 external deploy receipt must have external_smoke_performed=true")
    return receipt


def _write_rollback_receipt(
    *,
    receipt_path: Path,
    authorization_path: Path,
    authorization: dict[str, Any],
    rollback: dict[str, Any] | None,
    smoke: dict[str, Any] | None,
) -> None:
    receipt = {
        "schema_version": RECEIPT_SCHEMA,
        "recorded_at": _now(),
        "request_id": authorization["request_id"],
        "receipt_scope": DRILL_SCOPE,
        "source_rollback_authorization": _artifact_ref(authorization_path),
        "source_beta5_external_deploy_receipt": authorization["source_beta5_external_deploy_receipt"],
        "source_beta5_local_deploy_receipt": authorization["source_beta5_local_deploy_receipt"],
        "source_beta5_github_merge_receipt": authorization["source_beta5_github_merge_receipt"],
        "source_merge_commit_id": authorization["source_merge_commit_id"],
        "github_repo": authorization["github_repo"],
        "pr_number": authorization["pr_number"],
        "external_environment": authorization["external_environment"],
        "deploy_target": authorization["deploy_target"],
        "external_deploy_receipt_rollback_ref": authorization["external_deploy_receipt_rollback_ref"],
        "working_directory": authorization["working_directory"],
        "rollback_command": authorization["rollback_command"],
        "rollback_smoke_command": authorization["rollback_smoke_command"],
        "rollback": rollback,
        "rollback_smoke": smoke,
        "rollback_performed": True,
        "rollback_smoke_performed": True,
        "production_deploy_allowed": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
        "h3_boundary": _h3_boundary(),
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(receipt_path, receipt)


def _authorization_refusal_report(path: Path, validation: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": EXECUTION_SCHEMA,
        "passed": False,
        "rollback_status": "authorization_refused",
        "failure_reasons": [f"authorization failed validation: {reason}" for reason in validation.get("failure_reasons", [])],
        "failure_codes": ["rollback_drill_authorization_refused"],
        "checked_at": _now(),
        "source_rollback_authorization": _artifact_ref_or_path(path),
        "source_rollback_authorization_validation": validation,
        "rollback_receipt_path": None,
        "receipt_validation": None,
        "rollback_performed": False,
        "rollback_smoke_performed": False,
        "production_deploy_allowed": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
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


def _validate_false_boundary_flags(payload: dict[str, Any], failures: list[str]) -> None:
    for flag in ("production_deploy_allowed", "production_runtime_execution_allowed", "production_receipt_write_allowed"):
        if payload.get(flag) is not False:
            failures.append(f"{flag} must be false")


def _validate_h3_boundary(payload: dict[str, Any], failures: list[str]) -> None:
    if payload.get("h3_boundary") != _h3_boundary():
        failures.append("h3_boundary must keep production readiness blocked")


def _h3_boundary() -> dict[str, bool]:
    return {"h3_remains_blocked": True, "h3_production_readiness_claimed": False}


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


def _append_code(codes: list[str], code: str) -> None:
    if code not in codes:
        codes.append(code)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


if __name__ == "__main__":
    raise SystemExit(main())
