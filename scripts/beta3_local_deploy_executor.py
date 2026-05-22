#!/usr/bin/env python3
"""Authorize and execute one Beta-3 local-controlled deploy command.

Merge evidence is not deployment approval. This gate starts from a valid Git
merge receipt, records explicit operator authorization for one local-controlled
command, rechecks the merged target repo snapshot before execution, and writes a
deploy receipt only when the command succeeds without mutating the Git worktree.
It never authorizes production runtime execution or production receipt writes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shlex
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from beta3_git_merge_executor import RECEIPT_SCHEMA as MERGE_RECEIPT_SCHEMA
from beta3_git_merge_executor import validate_git_merge_receipt


AUTHORIZATION_SCHEMA = "beta3-local-deploy-authorization:v1"
AUTHORIZATION_VALIDATION_SCHEMA = "beta3-local-deploy-authorization-validation:v1"
AUTHORIZATION_WRITE_SCHEMA = "beta3-local-deploy-authorization-write-report:v1"
EXECUTION_SCHEMA = "beta3-local-deploy-execution-report:v1"
RECEIPT_SCHEMA = "beta3-local-deploy-receipt:v1"
RECEIPT_VALIDATION_SCHEMA = "beta3-local-deploy-receipt-validation:v1"
DEPLOYMENT_MODE = "local_controlled"
NON_CLAIMS = (
    "beta3_local_deploy_executor_is_l1_controlled_pilot_only",
    "beta3_local_deploy_executor_requires_fresh_deploy_authorization_after_merge",
    "beta3_local_deploy_executor_runs_one_explicit_non_shell_command",
    "beta3_local_deploy_executor_requires_merged_target_snapshot_to_remain_clean",
    "beta3_local_deploy_executor_does_not_authorize_production_deploy",
    "beta3_local_deploy_executor_does_not_claim_h3_production_readiness",
    "beta3_local_deploy_executor_does_not_write_production_receipts",
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    record = subparsers.add_parser("record-authorization", help="record local deploy authorization")
    record.add_argument("--git-merge-receipt", required=True)
    record.add_argument("--deploy-target", required=True)
    record.add_argument("--deploy-command", required=True)
    record.add_argument("--output", required=True)
    record.add_argument("--operator-id", default="l1-controlled-pilot-operator")
    record.add_argument("--reason", required=True)
    record.add_argument("--rollback-evidence-ref", required=True)
    record.add_argument("--ack-local-controlled-deploy", action="store_true")

    validate_authorization = subparsers.add_parser(
        "validate-authorization",
        help="validate local deploy authorization and merged target snapshot",
    )
    validate_authorization.add_argument("--authorization", required=True)
    validate_authorization.add_argument("--output")

    deploy = subparsers.add_parser("deploy", help="execute one authorized local-controlled deploy command")
    deploy.add_argument("--authorization", required=True)
    deploy.add_argument("--output-root", required=True)

    validate_receipt = subparsers.add_parser("validate-receipt", help="validate local deploy receipt")
    validate_receipt.add_argument("--receipt", required=True)
    validate_receipt.add_argument("--output")

    args = parser.parse_args(argv)
    if args.command == "record-authorization":
        report = record_deploy_authorization(
            merge_receipt_path=Path(args.git_merge_receipt),
            deploy_target=args.deploy_target,
            deploy_command=args.deploy_command,
            output_path=Path(args.output),
            operator_id=args.operator_id,
            reason=args.reason,
            rollback_evidence_ref=args.rollback_evidence_ref,
            ack_local_controlled_deploy=args.ack_local_controlled_deploy,
        )
    elif args.command == "validate-authorization":
        report = validate_deploy_authorization(Path(args.authorization))
        if args.output:
            _write_json(Path(args.output), report)
    elif args.command == "deploy":
        report = run_local_deploy(
            authorization_path=Path(args.authorization),
            output_root=Path(args.output_root),
        )
    elif args.command == "validate-receipt":
        report = validate_local_deploy_receipt(Path(args.receipt))
        if args.output:
            _write_json(Path(args.output), report)
    else:
        raise AssertionError(f"unknown command: {args.command}")
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report.get("receipt_validation", report.get("validation", report)).get("passed") and report.get(
        "passed",
        True,
    ) else 1


def record_deploy_authorization(
    *,
    merge_receipt_path: Path,
    deploy_target: str,
    deploy_command: str,
    output_path: Path,
    operator_id: str,
    reason: str,
    rollback_evidence_ref: str,
    ack_local_controlled_deploy: bool,
) -> dict[str, Any]:
    failures: list[str] = []
    merge_receipt = _load_merge_receipt(merge_receipt_path, failures)
    repo = _repo_from_merge_receipt(merge_receipt, failures)
    snapshot = _repo_snapshot(repo, failures) if repo is not None else {}
    if snapshot != merge_receipt.get("target_repo", {}).get("after"):
        failures.append("merged target repo snapshot must match Git merge receipt after snapshot")
    deploy_target = _required_text(deploy_target, "deploy_target")
    operator_id = _required_text(operator_id, "operator_id")
    reason = _required_text(reason, "reason")
    rollback_evidence_ref = _required_text(rollback_evidence_ref, "rollback_evidence_ref")
    command_argv = _deploy_command_argv(deploy_command, failures)
    if ack_local_controlled_deploy is not True:
        failures.append("local controlled deploy authorization requires explicit acknowledgement")
    if failures:
        raise ValueError(f"local deploy authorization blocked: {failures}")

    authorization = {
        "schema_version": AUTHORIZATION_SCHEMA,
        "recorded_at": _now(),
        "request_id": merge_receipt["request_id"],
        "authorization_scope": "local_controlled_deploy_only",
        "deployment_mode": DEPLOYMENT_MODE,
        "operator_id": operator_id,
        "reason": reason,
        "rollback_evidence_ref": rollback_evidence_ref,
        "ack_local_controlled_deploy": True,
        "source_git_merge_receipt": _artifact_ref(merge_receipt_path),
        "source_git_push_receipt": merge_receipt["source_git_push_receipt"],
        "source_git_commit_receipt": merge_receipt["source_git_commit_receipt"],
        "source_patch_proposal": merge_receipt["source_patch_proposal"],
        "source_merge_commit_id": merge_receipt["merge_commit_id"],
        "target_repo": {
            "repo_root": str(repo),
            "authorization_snapshot": snapshot,
        },
        "target_branch": merge_receipt["target_branch"],
        "deploy_target": deploy_target,
        "deploy_command": {
            "raw": deploy_command,
            "argv": command_argv,
            "shell": False,
        },
        "deploy_authorized": True,
        "git_actions_performed": {"commit": True, "push": True, "merge": True},
        "local_deploy_performed": False,
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
    authorization = _safe_read_json(path, failures, "local deploy authorization")
    if not isinstance(authorization, dict):
        return _authorization_validation_report(path, failures or ["local deploy authorization must be an object"])
    merge_receipt = _validate_authorization_static(authorization, failures)
    repo = _repo_from_authorization(authorization, failures)
    snapshot = _repo_snapshot(repo, failures) if repo is not None else {}
    if snapshot != authorization.get("target_repo", {}).get("authorization_snapshot"):
        failures.append("merged target repo snapshot drifted after local deploy authorization")
    if snapshot.get("current_branch") != authorization.get("target_branch"):
        failures.append("merged target repo branch must match local deploy authorization target_branch")
    if merge_receipt and snapshot.get("head_commit") != merge_receipt.get("merge_commit_id"):
        failures.append("merged target repo HEAD must still equal Git merge receipt merge_commit_id")
    return _authorization_validation_report(path, failures)


def run_local_deploy(*, authorization_path: Path, output_root: Path) -> dict[str, Any]:
    output_root = output_root.resolve()
    output_root.mkdir(parents=True, exist_ok=True)
    validation = validate_deploy_authorization(authorization_path)
    if validation.get("passed") is not True:
        report = _authorization_refusal_report(authorization_path, validation)
        _write_json(output_root / "beta3_local_deploy_execution_report.json", report)
        return report

    failures: list[str] = []
    failure_codes: list[str] = []
    authorization = _read_json_object(authorization_path)
    repo = _repo_from_authorization(authorization, failures)
    before = _repo_snapshot(repo, failures) if repo is not None else {}
    deploy: dict[str, Any] | None = None
    if not failures and repo is not None:
        deploy = _command(repo, failures, _command_argv(authorization, failures))
        if deploy["returncode"] != 0:
            _append_code(failure_codes, "local_deploy_command_failed")
    after = _repo_snapshot(repo, failures) if repo is not None else {}
    deploy_performed = deploy is not None and deploy["returncode"] == 0
    if deploy_performed:
        if after != before:
            failures.append("local deploy command must not mutate merged target Git snapshot")
            _append_code(failure_codes, "local_deploy_repo_snapshot_changed")
    elif not failures:
        failures.append("local deploy command was not performed")
        _append_code(failure_codes, "local_deploy_not_performed")
    if failures and not failure_codes:
        _append_code(failure_codes, "local_deploy_internal_failure")

    receipt_path = output_root / "beta3_local_deploy_receipt.json"
    receipt_validation = None
    if deploy_performed and not failures:
        _write_deploy_receipt(
            receipt_path=receipt_path,
            authorization_path=authorization_path,
            authorization=authorization,
            before=before,
            after=after,
            deploy=deploy,
        )
        receipt_validation = validate_local_deploy_receipt(receipt_path)
        if receipt_validation["passed"] is not True:
            failures.extend(f"local deploy receipt invalid: {reason}" for reason in receipt_validation["failure_reasons"])
            _append_code(failure_codes, "local_deploy_receipt_invalid")

    report = {
        "schema_version": EXECUTION_SCHEMA,
        "passed": not failures,
        "deploy_status": "local_deployed_with_receipt" if not failures else "blocked_or_failed",
        "failure_reasons": failures,
        "failure_codes": failure_codes,
        "checked_at": _now(),
        "source_local_deploy_authorization": _artifact_ref(authorization_path),
        "source_local_deploy_authorization_validation": validation,
        "source_git_merge_receipt": authorization.get("source_git_merge_receipt"),
        "source_merge_commit_id": authorization.get("source_merge_commit_id"),
        "target_repo": {
            "repo_root": str(repo) if repo is not None else None,
            "before": before,
            "after": after,
        },
        "target_branch": authorization.get("target_branch"),
        "deploy_target": authorization.get("deploy_target"),
        "deploy": deploy,
        "deploy_receipt_path": str(receipt_path.resolve()) if receipt_path.is_file() else None,
        "receipt_validation": receipt_validation,
        "git_actions_performed": {"commit": True, "push": True, "merge": True},
        "local_deploy_performed": deploy_performed,
        "production_deploy_allowed": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
        "h3_boundary": _h3_boundary(),
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(output_root / "beta3_local_deploy_execution_report.json", report)
    return report


def validate_local_deploy_receipt(receipt_path: Path) -> dict[str, Any]:
    failures: list[str] = []
    receipt = _safe_read_json(receipt_path, failures, "local deploy receipt")
    if not isinstance(receipt, dict):
        return _receipt_validation_report(receipt_path, failures or ["local deploy receipt must be an object"])
    if receipt.get("schema_version") != RECEIPT_SCHEMA:
        failures.append(f"schema_version must be {RECEIPT_SCHEMA}")
    if receipt.get("receipt_scope") != "local_controlled_deploy_only":
        failures.append("receipt_scope must be local_controlled_deploy_only")
    if receipt.get("deployment_mode") != DEPLOYMENT_MODE:
        failures.append(f"deployment_mode must be {DEPLOYMENT_MODE}")
    _validate_deploy_action_boundary(receipt, failures)
    _validate_h3_boundary(receipt, failures)

    authorization_ref = _as_ref(
        receipt.get("source_local_deploy_authorization"),
        failures,
        "source_local_deploy_authorization",
    )
    authorization_path = _validate_ref_bytes(authorization_ref, failures, "source_local_deploy_authorization")
    authorization = _safe_read_json(authorization_path, failures, "local deploy authorization")
    if not isinstance(authorization, dict):
        authorization = {}
    _validate_authorization_static(authorization, failures)
    for field in (
        "request_id",
        "source_git_merge_receipt",
        "source_git_push_receipt",
        "source_git_commit_receipt",
        "source_patch_proposal",
        "source_merge_commit_id",
        "target_branch",
        "deploy_target",
        "deploy_command",
    ):
        if receipt.get(field) != authorization.get(field):
            failures.append(f"{field} must match local deploy authorization")
    deploy = _as_dict(receipt.get("deploy"), failures, "deploy")
    if deploy.get("returncode") != 0:
        failures.append("deploy command returncode must be zero")

    target_repo = _as_dict(receipt.get("target_repo"), failures, "target_repo")
    if target_repo.get("before") != authorization.get("target_repo", {}).get("authorization_snapshot"):
        failures.append("target_repo.before must match local deploy authorization snapshot")
    if target_repo.get("after") != target_repo.get("before"):
        failures.append("local deploy receipt target repo snapshots must be unchanged")
    repo = _repo_path(target_repo.get("repo_root"), failures)
    if repo is not None:
        snapshot = _repo_snapshot(repo, failures)
        if snapshot != target_repo.get("after"):
            failures.append("merged target repo snapshot drifted after local deploy receipt")
        if snapshot.get("current_branch") != receipt.get("target_branch"):
            failures.append("merged target repo branch must match local deploy receipt target_branch")
        if snapshot.get("head_commit") != receipt.get("source_merge_commit_id"):
            failures.append("merged target repo HEAD must equal source_merge_commit_id")
    return _receipt_validation_report(receipt_path, failures)


def _validate_authorization_static(authorization: dict[str, Any], failures: list[str]) -> dict[str, Any]:
    _validate_authorization_shape(authorization, failures)
    merge_ref = _as_ref(authorization.get("source_git_merge_receipt"), failures, "source_git_merge_receipt")
    merge_path = _validate_ref_bytes(merge_ref, failures, "source_git_merge_receipt")
    merge_receipt = _load_merge_receipt(merge_path, failures) if merge_path else {}
    if authorization.get("request_id") != merge_receipt.get("request_id"):
        failures.append("request_id must match Git merge receipt")
    for field, merge_field in (
        ("source_git_push_receipt", "source_git_push_receipt"),
        ("source_git_commit_receipt", "source_git_commit_receipt"),
        ("source_patch_proposal", "source_patch_proposal"),
        ("source_merge_commit_id", "merge_commit_id"),
        ("target_branch", "target_branch"),
    ):
        if authorization.get(field) != merge_receipt.get(merge_field):
            failures.append(f"{field} must match Git merge receipt {merge_field}")
    if authorization.get("target_repo", {}).get("authorization_snapshot") != merge_receipt.get("target_repo", {}).get(
        "after"
    ):
        failures.append("target repo authorization snapshot must match Git merge receipt after snapshot")
    return merge_receipt


def _validate_authorization_shape(authorization: dict[str, Any], failures: list[str]) -> None:
    if authorization.get("schema_version") != AUTHORIZATION_SCHEMA:
        failures.append(f"schema_version must be {AUTHORIZATION_SCHEMA}")
    if authorization.get("authorization_scope") != "local_controlled_deploy_only":
        failures.append("authorization_scope must be local_controlled_deploy_only")
    if authorization.get("deployment_mode") != DEPLOYMENT_MODE:
        failures.append(f"deployment_mode must be {DEPLOYMENT_MODE}")
    for field in (
        "operator_id",
        "reason",
        "rollback_evidence_ref",
        "source_merge_commit_id",
        "target_branch",
        "deploy_target",
    ):
        if not _target_text(authorization.get(field)):
            failures.append(f"{field} must be a non-empty string")
    if authorization.get("ack_local_controlled_deploy") is not True:
        failures.append("ack_local_controlled_deploy must be true")
    command = _as_dict(authorization.get("deploy_command"), failures, "deploy_command")
    argv = command.get("argv")
    if not _command_tokens_valid(argv):
        failures.append("deploy_command.argv must be a non-empty argv string list")
    if not _target_text(command.get("raw")):
        failures.append("deploy_command.raw must be a non-empty string")
    if command.get("shell") is not False:
        failures.append("deploy_command.shell must be false")
    if authorization.get("deploy_authorized") is not True:
        failures.append("deploy_authorized must be true")
    if authorization.get("local_deploy_performed") is not False:
        failures.append("local_deploy_performed must be false before execution")
    if authorization.get("git_actions_performed") != {"commit": True, "push": True, "merge": True}:
        failures.append("authorization git_actions_performed must preserve merge receipt evidence")
    _validate_false_boundary_flags(authorization, failures)
    _validate_h3_boundary(authorization, failures)


def _load_merge_receipt(path: Path | None, failures: list[str]) -> dict[str, Any]:
    if path is None:
        return {}
    validation = validate_git_merge_receipt(path)
    if validation.get("passed") is not True:
        failures.extend(f"Git merge receipt invalid: {reason}" for reason in validation["failure_reasons"])
    receipt = _safe_read_json(path, failures, "Git merge receipt")
    if not isinstance(receipt, dict):
        return {}
    if receipt.get("schema_version") != MERGE_RECEIPT_SCHEMA:
        failures.append(f"Git merge receipt schema_version must be {MERGE_RECEIPT_SCHEMA}")
    if receipt.get("receipt_scope") != "git_merge_only":
        failures.append("local deploy requires git_merge_only receipt")
    if receipt.get("git_actions_performed") != {"commit": True, "push": True, "merge": True}:
        failures.append("local deploy requires completed Git merge receipt")
    return receipt


def _write_deploy_receipt(
    *,
    receipt_path: Path,
    authorization_path: Path,
    authorization: dict[str, Any],
    before: dict[str, str],
    after: dict[str, str],
    deploy: dict[str, Any] | None,
) -> None:
    receipt = {
        "schema_version": RECEIPT_SCHEMA,
        "recorded_at": _now(),
        "request_id": authorization["request_id"],
        "receipt_scope": "local_controlled_deploy_only",
        "deployment_mode": DEPLOYMENT_MODE,
        "source_local_deploy_authorization": _artifact_ref(authorization_path),
        "source_git_merge_receipt": authorization["source_git_merge_receipt"],
        "source_git_push_receipt": authorization["source_git_push_receipt"],
        "source_git_commit_receipt": authorization["source_git_commit_receipt"],
        "source_patch_proposal": authorization["source_patch_proposal"],
        "source_merge_commit_id": authorization["source_merge_commit_id"],
        "target_repo": {
            "repo_root": authorization["target_repo"]["repo_root"],
            "before": before,
            "after": after,
        },
        "target_branch": authorization["target_branch"],
        "deploy_target": authorization["deploy_target"],
        "deploy_command": authorization["deploy_command"],
        "deploy": deploy,
        "git_actions_performed": {"commit": True, "push": True, "merge": True},
        "local_deploy_performed": True,
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
        "failure_reasons": [
            f"local deploy authorization failed validation: {reason}"
            for reason in validation.get("failure_reasons", [])
        ],
        "failure_codes": ["local_deploy_authorization_refused"],
        "checked_at": _now(),
        "source_local_deploy_authorization": _artifact_ref_or_path(path),
        "source_local_deploy_authorization_validation": validation,
        "source_git_merge_receipt": None,
        "source_merge_commit_id": None,
        "target_repo": None,
        "target_branch": None,
        "deploy_target": None,
        "deploy": None,
        "deploy_receipt_path": None,
        "receipt_validation": None,
        "git_actions_performed": {"commit": True, "push": True, "merge": True},
        "local_deploy_performed": False,
        "production_deploy_allowed": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
        "h3_boundary": _h3_boundary(),
        "non_claims": list(NON_CLAIMS),
    }


def _validate_deploy_action_boundary(payload: dict[str, Any], failures: list[str]) -> None:
    if payload.get("git_actions_performed") != {"commit": True, "push": True, "merge": True}:
        failures.append("git_actions_performed must preserve completed Git merge evidence")
    if payload.get("local_deploy_performed") is not True:
        failures.append("local_deploy_performed must be true")
    _validate_false_boundary_flags(payload, failures)


def _validate_false_boundary_flags(payload: dict[str, Any], failures: list[str]) -> None:
    for flag in (
        "production_deploy_allowed",
        "production_runtime_execution_allowed",
        "production_receipt_write_allowed",
    ):
        if payload.get(flag) is not False:
            failures.append(f"{flag} must be false")


def _validate_h3_boundary(payload: dict[str, Any], failures: list[str]) -> None:
    boundary = _as_dict(payload.get("h3_boundary"), failures, "h3_boundary")
    if boundary.get("h3_remains_blocked") is not True:
        failures.append("h3_boundary.h3_remains_blocked must be true")
    if boundary.get("h3_production_readiness_claimed") is not False:
        failures.append("h3_boundary.h3_production_readiness_claimed must be false")


def _h3_boundary() -> dict[str, bool]:
    return {"h3_remains_blocked": True, "h3_production_readiness_claimed": False}


def _repo_from_merge_receipt(receipt: dict[str, Any], failures: list[str]) -> Path | None:
    return _repo_path(receipt.get("target_repo", {}).get("repo_root"), failures)


def _repo_from_authorization(authorization: dict[str, Any], failures: list[str]) -> Path | None:
    return _repo_path(authorization.get("target_repo", {}).get("repo_root"), failures)


def _repo_path(value: Any, failures: list[str]) -> Path | None:
    text = _target_text(value)
    if not text:
        failures.append("target_repo.repo_root must be a non-empty Git worktree path")
        return None
    result = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        cwd=Path(text),
        check=False,
        text=True,
        capture_output=True,
    )
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
    return str(_command(repo, failures, ["git", *args])["stdout"])


def _command_argv(authorization: dict[str, Any], failures: list[str]) -> list[str]:
    command = _as_dict(authorization.get("deploy_command"), failures, "deploy_command")
    argv = command.get("argv")
    if not _command_tokens_valid(argv):
        failures.append("deploy command argv must be a non-empty string list")
        return []
    return list(argv)


def _deploy_command_argv(raw: str, failures: list[str]) -> list[str]:
    raw = _required_text(raw, "deploy_command")
    try:
        argv = shlex.split(raw)
    except ValueError as exc:
        failures.append(f"deploy_command must parse as argv: {exc}")
        return []
    if not _command_tokens_valid(argv):
        failures.append("deploy_command must parse to non-empty argv tokens with an executable first token")
    return argv


def _command(repo: Path, failures: list[str], argv: list[str]) -> dict[str, Any]:
    if not argv:
        return {"command": [], "returncode": 1, "stdout": "", "stderr": "missing argv"}
    result = subprocess.run(argv, cwd=repo, check=False, text=True, capture_output=True)
    run = {
        "command": argv,
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }
    if run["returncode"] != 0:
        failures.append(f"command failed: {' '.join(argv)}")
    return run


def _artifact_ref(path: Path) -> dict[str, str]:
    if not path.is_file():
        raise FileNotFoundError(f"artifact path is not a file: {path}")
    return {"path": str(path.resolve()), "sha256": _sha256(path)}


def _artifact_ref_or_path(path: Path) -> dict[str, str | None]:
    return {"path": str(path.resolve()), "sha256": _sha256(path) if path.is_file() else None}


def _validate_ref_bytes(ref: dict[str, Any], failures: list[str], field: str) -> Path | None:
    path_text = _target_text(ref.get("path"))
    sha = _target_text(ref.get("sha256"))
    if not path_text or not sha:
        failures.append(f"{field} must include artifact path and sha256")
        return None
    path = Path(path_text)
    if not path.is_file():
        failures.append(f"{field} artifact path must be a file")
        return None
    if _sha256(path) != sha:
        failures.append(f"{field} sha256 must match artifact bytes")
        return None
    return path


def _as_ref(value: Any, failures: list[str], field: str) -> dict[str, Any]:
    return _as_dict(value, failures, field)


def _as_dict(value: Any, failures: list[str], field: str) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    failures.append(f"{field} must be an object")
    return {}


def _safe_read_json(path: Path | None, failures: list[str], label: str) -> Any:
    if path is None or not path.is_file():
        failures.append(f"{label} path must be a file")
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        failures.append(f"{label} must be readable JSON: {exc}")
        return None


def _read_json_object(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"JSON object required: {path}")
    return data


def _target_text(value: Any) -> str:
    text = value.strip() if isinstance(value, str) else ""
    return text if text and not text.startswith("-") else ""


def _command_tokens_valid(value: Any) -> bool:
    if not isinstance(value, list) or not value:
        return False
    if not all(isinstance(item, str) and item.strip() for item in value):
        return False
    return not value[0].strip().startswith("-")


def _required_text(value: Any, field: str) -> str:
    text = value.strip() if isinstance(value, str) else ""
    if not text:
        raise ValueError(f"{field} must be a non-empty string")
    return text


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _append_code(codes: list[str], code: str) -> None:
    if code not in codes:
        codes.append(code)


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _authorization_validation_report(path: Path, failures: list[str]) -> dict[str, Any]:
    return {
        "schema_version": AUTHORIZATION_VALIDATION_SCHEMA,
        "authorization_path": str(path.resolve()),
        "checked_at": _now(),
        "passed": not failures,
        "failure_reasons": failures,
        "non_claims": list(NON_CLAIMS),
    }


def _receipt_validation_report(path: Path, failures: list[str]) -> dict[str, Any]:
    return {
        "schema_version": RECEIPT_VALIDATION_SCHEMA,
        "receipt_path": str(path.resolve()),
        "checked_at": _now(),
        "passed": not failures,
        "failure_reasons": failures,
        "non_claims": list(NON_CLAIMS),
    }


if __name__ == "__main__":
    raise SystemExit(main())
