#!/usr/bin/env python3
"""Authorize and execute one Beta-5 post-merge local-controlled deploy probe.

A GitHub merge receipt is not deployment approval. This gate consumes one valid
Beta-5 GitHub merge receipt, records explicit operator authorization for a
local/staging-only deploy command plus a smoke command, requires rollback
evidence, verifies the local main worktree is still at the merge commit, and
writes a receipt only when both commands pass without mutating the Git snapshot.
It never authorizes external deploy, production runtime actions, or production
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

from beta5_github_merge_executor import RECEIPT_SCHEMA as BETA5_MERGE_RECEIPT_SCHEMA
from beta5_github_merge_executor import validate_github_merge_receipt


AUTHORIZATION_SCHEMA = "beta5-local-controlled-deploy-authorization:v1"
AUTHORIZATION_VALIDATION_SCHEMA = "beta5-local-controlled-deploy-authorization-validation:v1"
AUTHORIZATION_WRITE_SCHEMA = "beta5-local-controlled-deploy-authorization-write-report:v1"
EXECUTION_SCHEMA = "beta5-local-controlled-deploy-execution-report:v1"
RECEIPT_SCHEMA = "beta5-local-controlled-deploy-receipt:v1"
RECEIPT_VALIDATION_SCHEMA = "beta5-local-controlled-deploy-receipt-validation:v1"
DEPLOYMENT_MODE = "local_controlled_staging"
NON_CLAIMS = (
    "beta5_local_deploy_is_l1_controlled_pilot_only",
    "beta5_local_deploy_requires_valid_beta5_github_merge_receipt",
    "beta5_local_deploy_requires_explicit_operator_authorization",
    "beta5_local_deploy_requires_rollback_evidence_ref",
    "beta5_local_deploy_requires_smoke_command_success",
    "beta5_local_deploy_must_not_mutate_git_snapshot",
    "beta5_local_deploy_does_not_authorize_external_deploy",
    "beta5_local_deploy_does_not_authorize_production_deploy",
    "beta5_local_deploy_does_not_claim_h3_production_readiness",
    "beta5_local_deploy_does_not_write_production_receipts",
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    record = subparsers.add_parser("record-authorization", help="record local-controlled deploy authorization")
    record.add_argument("--github-merge-receipt", required=True)
    record.add_argument("--target-repo", required=True)
    record.add_argument("--deploy-target", required=True)
    record.add_argument("--deploy-command", required=True)
    record.add_argument("--smoke-command", required=True)
    record.add_argument("--output", required=True)
    record.add_argument("--operator-id", default="l1-controlled-pilot-operator")
    record.add_argument("--reason", required=True)
    record.add_argument("--rollback-evidence-ref", required=True)
    record.add_argument("--ack-local-controlled-deploy", action="store_true")

    validate_authorization = subparsers.add_parser("validate-authorization", help="validate authorization")
    validate_authorization.add_argument("--authorization", required=True)
    validate_authorization.add_argument("--output")

    deploy = subparsers.add_parser("deploy", help="run authorized local-controlled deploy and smoke")
    deploy.add_argument("--authorization", required=True)
    deploy.add_argument("--output-root", required=True)

    validate_receipt = subparsers.add_parser("validate-receipt", help="validate deploy receipt")
    validate_receipt.add_argument("--receipt", required=True)
    validate_receipt.add_argument("--output")

    args = parser.parse_args(argv)
    if args.command == "record-authorization":
        report = record_deploy_authorization(
            github_merge_receipt_path=Path(args.github_merge_receipt),
            target_repo=Path(args.target_repo),
            deploy_target=args.deploy_target,
            deploy_command=args.deploy_command,
            smoke_command=args.smoke_command,
            output_path=Path(args.output),
            operator_id=args.operator_id,
            reason=args.reason,
            rollback_evidence_ref=args.rollback_evidence_ref,
            ack_local_controlled_deploy=bool(args.ack_local_controlled_deploy),
        )
    elif args.command == "validate-authorization":
        report = validate_deploy_authorization(Path(args.authorization))
        if args.output:
            _write_json(Path(args.output), report)
    elif args.command == "deploy":
        report = run_local_controlled_deploy(
            authorization_path=Path(args.authorization),
            output_root=Path(args.output_root),
        )
    elif args.command == "validate-receipt":
        report = validate_deploy_receipt(Path(args.receipt))
        if args.output:
            _write_json(Path(args.output), report)
    else:
        raise AssertionError(f"unknown command: {args.command}")
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    passed = report.get("receipt_validation", report.get("validation", report)).get("passed") and report.get(
        "passed",
        True,
    )
    return 0 if passed else 1


def record_deploy_authorization(
    *,
    github_merge_receipt_path: Path,
    target_repo: Path,
    deploy_target: str,
    deploy_command: str,
    smoke_command: str,
    output_path: Path,
    operator_id: str,
    reason: str,
    rollback_evidence_ref: str,
    ack_local_controlled_deploy: bool,
) -> dict[str, Any]:
    failures: list[str] = []
    merge_receipt = _load_merge_receipt(github_merge_receipt_path, failures)
    repo = _repo_path(target_repo, failures)
    snapshot = _repo_snapshot(repo, failures) if repo else {}
    merge_commit = _merge_commit_id(merge_receipt, failures)
    base_branch = _required_text(merge_receipt.get("base_branch"), failures, "base_branch")
    if snapshot.get("head_commit") != merge_commit:
        failures.append("target repo HEAD must equal Beta-5 merge receipt merge commit")
    if snapshot.get("current_branch") != base_branch:
        failures.append("target repo branch must equal Beta-5 merge receipt base_branch")
    if snapshot.get("status_short"):
        failures.append("target repo must be clean before local-controlled deploy authorization")
    deploy_target = _required_text(deploy_target, failures, "deploy_target")
    operator_id = _required_text(operator_id, failures, "operator_id")
    reason = _required_text(reason, failures, "reason")
    rollback_evidence_ref = _required_text(rollback_evidence_ref, failures, "rollback_evidence_ref")
    deploy_argv = _command_argv_from_raw(deploy_command, failures, "deploy_command")
    smoke_argv = _command_argv_from_raw(smoke_command, failures, "smoke_command")
    if ack_local_controlled_deploy is not True:
        failures.append("local-controlled deploy authorization requires explicit acknowledgement")
    if failures:
        raise ValueError(f"local-controlled deploy authorization blocked: {failures}")

    authorization = {
        "schema_version": AUTHORIZATION_SCHEMA,
        "recorded_at": _now(),
        "request_id": merge_receipt["request_id"],
        "authorization_scope": "post_merge_local_controlled_deploy_only",
        "deployment_mode": DEPLOYMENT_MODE,
        "operator_id": operator_id,
        "reason": reason,
        "rollback_evidence_ref": rollback_evidence_ref,
        "ack_local_controlled_deploy": True,
        "source_beta5_github_merge_receipt": _artifact_ref(github_merge_receipt_path),
        "source_beta5_merge_authorization": merge_receipt["source_beta5_merge_authorization"],
        "source_merge_commit_id": merge_commit,
        "github_repo": merge_receipt["github_repo"],
        "pr_number": merge_receipt["pr_number"],
        "source_branch": merge_receipt["source_branch"],
        "base_branch": base_branch,
        "target_repo": {"repo_root": str(repo), "authorization_snapshot": snapshot},
        "deploy_target": deploy_target,
        "deploy_command": {"raw": deploy_command, "argv": deploy_argv, "shell": False},
        "smoke_command": {"raw": smoke_command, "argv": smoke_argv, "shell": False},
        "deploy_authorized": True,
        "local_deploy_performed": False,
        "smoke_performed": False,
        "git_actions_performed": {"commit": True, "push": True, "merge": True},
        "external_deploy_allowed": False,
        "production_deploy_allowed": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
        "h3_boundary": _h3_boundary(),
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(output_path, authorization)
    validation = validate_deploy_authorization(output_path)
    if validation["passed"] is not True:
        raise ValueError(f"written local deploy authorization failed validation: {validation['failure_reasons']}")
    return {
        "schema_version": AUTHORIZATION_WRITE_SCHEMA,
        "authorization_written": True,
        "authorization_path": str(output_path.resolve()),
        "authorization_sha256": _sha256(output_path),
        "request_id": merge_receipt["request_id"],
        "validation": validation,
        "non_claims": list(NON_CLAIMS),
    }


def validate_deploy_authorization(path: Path) -> dict[str, Any]:
    failures: list[str] = []
    authorization = _safe_read_json(path, failures, "local-controlled deploy authorization")
    if not isinstance(authorization, dict):
        return _authorization_validation_report(path, failures or ["authorization must be a JSON object"])
    merge_receipt = _validate_authorization_static(authorization, failures)
    repo = _repo_from_authorization(authorization, failures)
    snapshot = _repo_snapshot(repo, failures) if repo else {}
    if snapshot != authorization.get("target_repo", {}).get("authorization_snapshot"):
        failures.append("target repo snapshot drifted after deploy authorization")
    if merge_receipt and snapshot.get("head_commit") != _merge_commit_id(merge_receipt, failures):
        failures.append("target repo HEAD must still equal Beta-5 merge receipt merge commit")
    if snapshot.get("current_branch") != authorization.get("base_branch"):
        failures.append("target repo branch must still equal authorization base_branch")
    return _authorization_validation_report(path, failures)


def run_local_controlled_deploy(*, authorization_path: Path, output_root: Path) -> dict[str, Any]:
    output_root = output_root.resolve()
    output_root.mkdir(parents=True, exist_ok=True)
    validation = validate_deploy_authorization(authorization_path)
    if validation.get("passed") is not True:
        report = _authorization_refusal_report(authorization_path, validation)
        _write_json(output_root / "beta5_local_controlled_deploy_execution_report.json", report)
        return report

    failures: list[str] = []
    failure_codes: list[str] = []
    authorization = _read_json_object(authorization_path)
    repo = _repo_from_authorization(authorization, failures)
    before = _repo_snapshot(repo, failures) if repo else {}
    deploy = _run_command(repo, _command_argv(authorization, "deploy_command", failures), failures) if repo else None
    if deploy and deploy["returncode"] != 0:
        _append_code(failure_codes, "local_deploy_command_failed")
    smoke = None
    if deploy and deploy["returncode"] == 0 and repo:
        smoke = _run_command(repo, _command_argv(authorization, "smoke_command", failures), failures)
        if smoke["returncode"] != 0:
            _append_code(failure_codes, "local_deploy_smoke_failed")
    after = _repo_snapshot(repo, failures) if repo else {}
    if before != after:
        failures.append("local-controlled deploy and smoke must not mutate Git snapshot")
        _append_code(failure_codes, "local_deploy_git_snapshot_changed")
    deploy_performed = bool(deploy and deploy["returncode"] == 0)
    smoke_performed = bool(smoke and smoke["returncode"] == 0)
    if not deploy_performed:
        failures.append("local-controlled deploy command was not performed successfully")
        _append_code(failure_codes, "local_deploy_not_successful")
    if not smoke_performed:
        failures.append("local-controlled deploy smoke command was not performed successfully")
        _append_code(failure_codes, "local_deploy_smoke_not_successful")

    receipt_path = output_root / "beta5_local_controlled_deploy_receipt.json"
    receipt_validation = None
    if not failures:
        _write_deploy_receipt(
            receipt_path=receipt_path,
            authorization_path=authorization_path,
            authorization=authorization,
            before=before,
            after=after,
            deploy=deploy,
            smoke=smoke,
        )
        receipt_validation = validate_deploy_receipt(receipt_path)
        if receipt_validation["passed"] is not True:
            failures.extend(f"receipt invalid: {reason}" for reason in receipt_validation["failure_reasons"])
            _append_code(failure_codes, "local_deploy_receipt_invalid")

    report = {
        "schema_version": EXECUTION_SCHEMA,
        "passed": not failures,
        "deploy_status": "local_controlled_deployed_with_receipt" if not failures else "blocked_or_failed",
        "failure_reasons": failures,
        "failure_codes": failure_codes,
        "checked_at": _now(),
        "source_local_deploy_authorization": _artifact_ref(authorization_path),
        "source_local_deploy_authorization_validation": validation,
        "source_beta5_github_merge_receipt": authorization.get("source_beta5_github_merge_receipt"),
        "source_merge_commit_id": authorization.get("source_merge_commit_id"),
        "target_repo": {"repo_root": str(repo) if repo else None, "before": before, "after": after},
        "base_branch": authorization.get("base_branch"),
        "deploy_target": authorization.get("deploy_target"),
        "deploy": deploy,
        "smoke": smoke,
        "deploy_receipt_path": str(receipt_path.resolve()) if receipt_path.is_file() else None,
        "receipt_validation": receipt_validation,
        "local_deploy_performed": deploy_performed,
        "smoke_performed": smoke_performed,
        "external_deploy_allowed": False,
        "production_deploy_allowed": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
        "h3_boundary": _h3_boundary(),
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(output_root / "beta5_local_controlled_deploy_execution_report.json", report)
    return report


def validate_deploy_receipt(path: Path) -> dict[str, Any]:
    failures: list[str] = []
    receipt = _safe_read_json(path, failures, "local-controlled deploy receipt")
    if not isinstance(receipt, dict):
        return _receipt_validation_report(path, failures or ["receipt must be a JSON object"])
    if receipt.get("schema_version") != RECEIPT_SCHEMA:
        failures.append(f"schema_version must be {RECEIPT_SCHEMA}")
    if receipt.get("receipt_scope") != "post_merge_local_controlled_deploy_only":
        failures.append("receipt_scope must be post_merge_local_controlled_deploy_only")
    if receipt.get("deployment_mode") != DEPLOYMENT_MODE:
        failures.append(f"deployment_mode must be {DEPLOYMENT_MODE}")
    authorization_ref = _as_ref(receipt.get("source_local_deploy_authorization"), failures, "source_local_deploy_authorization")
    authorization_path = _validate_ref_bytes(authorization_ref, failures, "source_local_deploy_authorization")
    authorization = _safe_read_json(authorization_path, failures, "local-controlled deploy authorization")
    if not isinstance(authorization, dict):
        authorization = {}
    _validate_authorization_static(authorization, failures)
    for field in (
        "request_id",
        "source_beta5_github_merge_receipt",
        "source_beta5_merge_authorization",
        "source_merge_commit_id",
        "github_repo",
        "pr_number",
        "source_branch",
        "base_branch",
        "deploy_target",
        "deploy_command",
        "smoke_command",
        "rollback_evidence_ref",
    ):
        if receipt.get(field) != authorization.get(field):
            failures.append(f"{field} must match local-controlled deploy authorization")
    if receipt.get("local_deploy_performed") is not True:
        failures.append("local_deploy_performed must be true")
    if receipt.get("smoke_performed") is not True:
        failures.append("smoke_performed must be true")
    _validate_false_boundary_flags(receipt, failures)
    _validate_h3_boundary(receipt, failures)
    target_repo = _as_dict(receipt.get("target_repo"), failures, "target_repo")
    if target_repo.get("before") != authorization.get("target_repo", {}).get("authorization_snapshot"):
        failures.append("target_repo.before must match authorization snapshot")
    if target_repo.get("after") != target_repo.get("before"):
        failures.append("target_repo snapshots must be unchanged")
    repo = _repo_path(target_repo.get("repo_root"), failures)
    if repo:
        snapshot = _repo_snapshot(repo, failures)
        if snapshot != target_repo.get("after"):
            failures.append("target repo snapshot drifted after deploy receipt")
    for command_field in ("deploy", "smoke"):
        command = _as_dict(receipt.get(command_field), failures, command_field)
        if command.get("returncode") != 0:
            failures.append(f"{command_field}.returncode must be zero")
    return _receipt_validation_report(path, failures)


def _validate_authorization_static(authorization: dict[str, Any], failures: list[str]) -> dict[str, Any]:
    if authorization.get("schema_version") != AUTHORIZATION_SCHEMA:
        failures.append(f"schema_version must be {AUTHORIZATION_SCHEMA}")
    if authorization.get("authorization_scope") != "post_merge_local_controlled_deploy_only":
        failures.append("authorization_scope must be post_merge_local_controlled_deploy_only")
    if authorization.get("deployment_mode") != DEPLOYMENT_MODE:
        failures.append(f"deployment_mode must be {DEPLOYMENT_MODE}")
    for field in ("operator_id", "reason", "rollback_evidence_ref", "source_merge_commit_id", "base_branch", "deploy_target"):
        if not _text(authorization.get(field)):
            failures.append(f"{field} must be a non-empty string")
    if authorization.get("ack_local_controlled_deploy") is not True:
        failures.append("ack_local_controlled_deploy must be true")
    for field in ("deploy_command", "smoke_command"):
        command = _as_dict(authorization.get(field), failures, field)
        if command.get("shell") is not False:
            failures.append(f"{field}.shell must be false")
        if not _text(command.get("raw")):
            failures.append(f"{field}.raw must be non-empty")
        if not _argv_valid(command.get("argv")):
            failures.append(f"{field}.argv must be a non-empty list of strings")
    if authorization.get("deploy_authorized") is not True:
        failures.append("deploy_authorized must be true")
    if authorization.get("local_deploy_performed") is not False:
        failures.append("local_deploy_performed must be false before execution")
    if authorization.get("smoke_performed") is not False:
        failures.append("smoke_performed must be false before execution")
    if authorization.get("git_actions_performed") != {"commit": True, "push": True, "merge": True}:
        failures.append("git_actions_performed must preserve completed merge evidence")
    _validate_false_boundary_flags(authorization, failures)
    _validate_h3_boundary(authorization, failures)
    merge_ref = _as_ref(authorization.get("source_beta5_github_merge_receipt"), failures, "source_beta5_github_merge_receipt")
    merge_path = _validate_ref_bytes(merge_ref, failures, "source_beta5_github_merge_receipt")
    merge_receipt = _load_merge_receipt(merge_path, failures) if merge_path else {}
    if merge_receipt:
        if authorization.get("request_id") != merge_receipt.get("request_id"):
            failures.append("request_id must match Beta-5 merge receipt")
        if authorization.get("source_merge_commit_id") != _merge_commit_id(merge_receipt, failures):
            failures.append("source_merge_commit_id must match Beta-5 merge receipt")
        for field in ("github_repo", "pr_number", "source_branch", "base_branch"):
            if authorization.get(field) != merge_receipt.get(field):
                failures.append(f"{field} must match Beta-5 merge receipt")
    return merge_receipt


def _load_merge_receipt(path: Path | None, failures: list[str]) -> dict[str, Any]:
    if path is None:
        return {}
    validation = validate_github_merge_receipt(path)
    if validation.get("passed") is not True:
        failures.extend(f"Beta-5 merge receipt invalid: {reason}" for reason in validation.get("failure_reasons", []))
    receipt = _safe_read_json(path, failures, "Beta-5 merge receipt")
    if not isinstance(receipt, dict):
        return {}
    if receipt.get("schema_version") != BETA5_MERGE_RECEIPT_SCHEMA:
        failures.append(f"Beta-5 merge receipt schema_version must be {BETA5_MERGE_RECEIPT_SCHEMA}")
    if receipt.get("merge_performed") is not True:
        failures.append("Beta-5 merge receipt must have merge_performed=true")
    if receipt.get("git_actions_performed") != {"commit": True, "push": True, "merge": True}:
        failures.append("Beta-5 merge receipt must preserve completed merge evidence")
    return receipt


def _write_deploy_receipt(
    *,
    receipt_path: Path,
    authorization_path: Path,
    authorization: dict[str, Any],
    before: dict[str, str],
    after: dict[str, str],
    deploy: dict[str, Any] | None,
    smoke: dict[str, Any] | None,
) -> None:
    receipt = {
        "schema_version": RECEIPT_SCHEMA,
        "recorded_at": _now(),
        "request_id": authorization["request_id"],
        "receipt_scope": "post_merge_local_controlled_deploy_only",
        "deployment_mode": DEPLOYMENT_MODE,
        "source_local_deploy_authorization": _artifact_ref(authorization_path),
        "source_beta5_github_merge_receipt": authorization["source_beta5_github_merge_receipt"],
        "source_beta5_merge_authorization": authorization["source_beta5_merge_authorization"],
        "source_merge_commit_id": authorization["source_merge_commit_id"],
        "github_repo": authorization["github_repo"],
        "pr_number": authorization["pr_number"],
        "source_branch": authorization["source_branch"],
        "base_branch": authorization["base_branch"],
        "target_repo": {"repo_root": authorization["target_repo"]["repo_root"], "before": before, "after": after},
        "deploy_target": authorization["deploy_target"],
        "deploy_command": authorization["deploy_command"],
        "smoke_command": authorization["smoke_command"],
        "rollback_evidence_ref": authorization["rollback_evidence_ref"],
        "deploy": deploy,
        "smoke": smoke,
        "local_deploy_performed": True,
        "smoke_performed": True,
        "git_actions_performed": {"commit": True, "push": True, "merge": True},
        "external_deploy_allowed": False,
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
        "deploy_status": "authorization_refused",
        "failure_reasons": [f"authorization failed validation: {reason}" for reason in validation.get("failure_reasons", [])],
        "failure_codes": ["local_controlled_deploy_authorization_refused"],
        "checked_at": _now(),
        "source_local_deploy_authorization": _artifact_ref_or_path(path),
        "source_local_deploy_authorization_validation": validation,
        "deploy_receipt_path": None,
        "receipt_validation": None,
        "local_deploy_performed": False,
        "smoke_performed": False,
        "external_deploy_allowed": False,
        "production_deploy_allowed": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
        "h3_boundary": _h3_boundary(),
        "non_claims": list(NON_CLAIMS),
    }


def _repo_from_authorization(authorization: dict[str, Any], failures: list[str]) -> Path | None:
    return _repo_path(authorization.get("target_repo", {}).get("repo_root"), failures)


def _repo_path(value: Any, failures: list[str]) -> Path | None:
    text = _text(str(value)) if isinstance(value, Path) else _text(value)
    if not text:
        failures.append("target_repo.repo_root must be a non-empty Git worktree path")
        return None
    result = subprocess.run(["git", "rev-parse", "--show-toplevel"], cwd=Path(text), check=False, text=True, capture_output=True)
    if result.returncode != 0:
        failures.append(f"target_repo.repo_root must be a Git worktree: {text}")
        return None
    return Path(result.stdout.strip()).resolve()


def _repo_snapshot(repo: Path, failures: list[str]) -> dict[str, str]:
    return {
        "head_commit": _git_text(repo, failures, "rev-parse", "HEAD").strip(),
        "current_branch": _git_text(repo, failures, "branch", "--show-current").strip(),
        "status_short": _git_text(repo, failures, "status", "--short"),
    }


def _git_text(repo: Path, failures: list[str], *args: str) -> str:
    return str(_run_command(repo, ["git", *args], failures)["stdout"])


def _run_command(repo: Path, argv: list[str], failures: list[str]) -> dict[str, Any]:
    if not argv:
        failures.append("command argv cannot be empty")
        return {"command": [], "returncode": 1, "stdout": "", "stderr": "empty command"}
    result = subprocess.run(argv, cwd=repo, check=False, text=True, capture_output=True)
    run = {"command": argv, "returncode": result.returncode, "stdout": result.stdout, "stderr": result.stderr}
    if run["returncode"] != 0:
        failures.append(f"command failed: {' '.join(argv)}")
    return run


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


def _merge_commit_id(receipt: dict[str, Any], failures: list[str]) -> str:
    commit = _as_dict(receipt.get("post_merge_pr"), failures, "post_merge_pr").get("mergeCommit")
    oid = _text(_as_dict(commit, failures, "post_merge_pr.mergeCommit").get("oid")) if commit is not None else ""
    if not oid:
        failures.append("Beta-5 merge receipt must include post_merge_pr.mergeCommit.oid")
    return oid


def _validate_false_boundary_flags(payload: dict[str, Any], failures: list[str]) -> None:
    for flag in (
        "external_deploy_allowed",
        "production_deploy_allowed",
        "production_runtime_execution_allowed",
        "production_receipt_write_allowed",
    ):
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
    if isinstance(value, dict):
        return value
    failures.append(f"{label} must be an object")
    return {}


def _safe_read_json(path: Path | None, failures: list[str], label: str) -> Any:
    if path is None:
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 - validators preserve artifact detail.
        failures.append(f"{label} could not be read: {exc}")
        return None
    if not isinstance(payload, dict):
        failures.append(f"{label} must be a JSON object")
        return None
    return payload


def _read_json_object(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"expected JSON object: {path}")
    return payload


def _required_text(value: Any, failures: list[str], label: str) -> str:
    text = _text(value)
    if not text:
        failures.append(f"{label} must be a non-empty string")
    return text


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _argv_valid(value: Any) -> bool:
    return isinstance(value, list) and bool(value) and all(isinstance(item, str) and item.strip() for item in value)


def _append_code(codes: list[str], code: str) -> None:
    if code not in codes:
        codes.append(code)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


if __name__ == "__main__":
    sys.exit(main())
