#!/usr/bin/env python3
"""Authorize and execute one bounded Beta-3 Git push from a commit receipt.

Push authorization starts after a commit-only receipt exists. It binds an
explicit remote URL, target branch, and observed remote branch head lease. The
executor rechecks that lease before a plain Git push, writes a push receipt,
and never merges, deploys, executes production runtime actions, or writes
production receipts.
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

from beta3_git_commit_executor import RECEIPT_SCHEMA as COMMIT_RECEIPT_SCHEMA
from beta3_git_commit_executor import validate_git_commit_receipt


AUTHORIZATION_SCHEMA = "beta3-git-push-authorization:v1"
AUTHORIZATION_VALIDATION_SCHEMA = "beta3-git-push-authorization-validation:v1"
AUTHORIZATION_WRITE_SCHEMA = "beta3-git-push-authorization-write-report:v1"
EXECUTION_SCHEMA = "beta3-git-push-execution-report:v1"
RECEIPT_SCHEMA = "beta3-git-push-receipt:v1"
RECEIPT_VALIDATION_SCHEMA = "beta3-git-push-receipt-validation:v1"
NON_CLAIMS = (
    "beta3_git_push_executor_is_l1_controlled_pilot_only",
    "beta3_git_push_executor_requires_explicit_remote_url_and_branch",
    "beta3_git_push_executor_uses_remote_branch_head_lease_before_push",
    "beta3_git_push_executor_does_not_merge_or_deploy",
    "beta3_git_push_executor_does_not_claim_h3_production_readiness",
    "beta3_git_push_executor_does_not_write_production_receipts",
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    record = subparsers.add_parser("record-authorization", help="record push authorization")
    record.add_argument("--git-commit-receipt", required=True)
    record.add_argument("--remote-url", required=True)
    record.add_argument("--target-branch", required=True)
    record.add_argument("--output", required=True)
    record.add_argument("--operator-id", default="l1-controlled-pilot-operator")
    record.add_argument("--reason", required=True)
    record.add_argument("--rollback-evidence-ref", required=True)

    validate_authorization = subparsers.add_parser(
        "validate-authorization",
        help="validate push authorization and current remote lease",
    )
    validate_authorization.add_argument("--authorization", required=True)
    validate_authorization.add_argument("--output")

    push = subparsers.add_parser("push", help="execute one authorized bounded Git push")
    push.add_argument("--authorization", required=True)
    push.add_argument("--output-root", required=True)

    validate_receipt = subparsers.add_parser("validate-receipt", help="validate Git push receipt")
    validate_receipt.add_argument("--receipt", required=True)
    validate_receipt.add_argument("--output")

    args = parser.parse_args(argv)
    if args.command == "record-authorization":
        report = record_push_authorization(
            commit_receipt_path=Path(args.git_commit_receipt),
            remote_url=args.remote_url,
            target_branch=args.target_branch,
            output_path=Path(args.output),
            operator_id=args.operator_id,
            reason=args.reason,
            rollback_evidence_ref=args.rollback_evidence_ref,
        )
    elif args.command == "validate-authorization":
        report = validate_push_authorization(Path(args.authorization))
        if args.output:
            _write_json(Path(args.output), report)
    elif args.command == "push":
        report = run_git_push(
            authorization_path=Path(args.authorization),
            output_root=Path(args.output_root),
        )
    elif args.command == "validate-receipt":
        report = validate_git_push_receipt(Path(args.receipt))
        if args.output:
            _write_json(Path(args.output), report)
    else:
        raise AssertionError(f"unknown command: {args.command}")
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report.get("receipt_validation", report.get("validation", report)).get("passed") and report.get(
        "passed",
        True,
    ) else 1


def record_push_authorization(
    *,
    commit_receipt_path: Path,
    remote_url: str,
    target_branch: str,
    output_path: Path,
    operator_id: str,
    reason: str,
    rollback_evidence_ref: str,
) -> dict[str, Any]:
    failures: list[str] = []
    commit_receipt = _load_commit_receipt(commit_receipt_path, failures)
    repo = _repo_from_commit_receipt(commit_receipt, failures)
    remote_url = _required_target_text(remote_url, "remote_url", failures)
    target_branch = _valid_branch(repo, target_branch, failures)
    operator_id = _required_text(operator_id, "operator_id")
    reason = _required_text(reason, "reason")
    rollback_evidence_ref = _required_text(rollback_evidence_ref, "rollback_evidence_ref")
    repo_snapshot = _repo_snapshot(repo, failures) if repo is not None else {}
    if repo_snapshot != commit_receipt.get("target_repo", {}).get("after"):
        failures.append("target repo snapshot must match Git commit receipt after snapshot")
    remote_before = _remote_branch_head(repo, remote_url, target_branch, failures) if repo and target_branch else None
    if failures:
        raise ValueError(f"Git push authorization blocked: {failures}")

    authorization = {
        "schema_version": AUTHORIZATION_SCHEMA,
        "recorded_at": _now(),
        "request_id": commit_receipt["request_id"],
        "authorization_scope": "git_push_only",
        "operator_id": operator_id,
        "reason": reason,
        "rollback_evidence_ref": rollback_evidence_ref,
        "source_git_commit_receipt": _artifact_ref(commit_receipt_path),
        "source_patch_proposal": commit_receipt["source_patch_proposal"],
        "commit_id": commit_receipt["commit_id"],
        "target_repo": {
            "repo_root": str(repo),
            "authorization_snapshot": repo_snapshot,
        },
        "remote_url": remote_url,
        "target_branch": target_branch,
        "remote_branch_before_head": remote_before,
        "lease_strategy": "observed_remote_branch_head_and_plain_fast_forward_push",
        "push_authorized": True,
        "git_actions_performed": {"commit": True, "push": False, "merge": False},
        "merge_allowed": False,
        "deploy_allowed": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
        "h3_boundary": _h3_boundary(),
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(output_path, authorization)
    validation = validate_push_authorization(output_path)
    if validation["passed"] is not True:
        raise ValueError(f"written Git push authorization failed validation: {validation['failure_reasons']}")
    return {
        "schema_version": AUTHORIZATION_WRITE_SCHEMA,
        "authorization_written": True,
        "authorization_path": str(output_path.resolve()),
        "authorization_sha256": _sha256(output_path),
        "request_id": commit_receipt["request_id"],
        "validation": validation,
        "non_claims": list(NON_CLAIMS),
    }


def validate_push_authorization(path: Path) -> dict[str, Any]:
    failures: list[str] = []
    authorization = _safe_read_json(path, failures, "Git push authorization")
    if not isinstance(authorization, dict):
        return _authorization_validation_report(path, failures or ["Git push authorization must be a JSON object"])
    _validate_authorization_shape(authorization, failures)
    commit_ref = _as_ref(authorization.get("source_git_commit_receipt"), failures, "source_git_commit_receipt")
    commit_path = _validate_ref_bytes(commit_ref, failures, "source_git_commit_receipt")
    commit_receipt = _load_commit_receipt(commit_path, failures) if commit_path else {}
    _validate_authorization_commit_binding(authorization, commit_receipt, failures)
    repo = _repo_from_authorization(authorization, failures)
    snapshot = _repo_snapshot(repo, failures) if repo is not None else {}
    if snapshot != authorization.get("target_repo", {}).get("authorization_snapshot"):
        failures.append("target repo snapshot drifted after Git push authorization")
    remote_url = _target_text(authorization.get("remote_url"))
    target_branch = _valid_branch(repo, authorization.get("target_branch"), failures)
    if repo is not None and remote_url and target_branch:
        remote_head = _remote_branch_head(repo, remote_url, target_branch, failures)
        if remote_head != authorization.get("remote_branch_before_head"):
            failures.append("remote branch lease drifted after Git push authorization")
    return _authorization_validation_report(path, failures)


def run_git_push(*, authorization_path: Path, output_root: Path) -> dict[str, Any]:
    output_root = output_root.resolve()
    output_root.mkdir(parents=True, exist_ok=True)
    validation = validate_push_authorization(authorization_path)
    if validation.get("passed") is not True:
        report = _authorization_refusal_report(authorization_path, validation)
        _write_json(output_root / "beta3_git_push_execution_report.json", report)
        return report

    failures: list[str] = []
    failure_codes: list[str] = []
    authorization = _read_json_object(authorization_path)
    repo = _repo_from_authorization(authorization, failures)
    remote_url = str(authorization["remote_url"])
    target_branch = str(authorization["target_branch"])
    before_snapshot = _repo_snapshot(repo, failures) if repo is not None else {}
    before_remote = _remote_branch_head(repo, remote_url, target_branch, failures) if repo is not None else None
    if before_remote != authorization.get("remote_branch_before_head"):
        failures.append("remote branch lease drifted before Git push")
        _append_code(failure_codes, "git_push_remote_lease_drift")

    push_run: dict[str, Any] | None = None
    after_snapshot: dict[str, str] = before_snapshot
    after_remote: str | None = before_remote
    if not failures and repo is not None:
        push_run = _git(
            repo,
            failures,
            "push",
            "--porcelain",
            remote_url,
            f"HEAD:refs/heads/{target_branch}",
        )
        if push_run["returncode"] != 0:
            _append_code(failure_codes, "git_push_failed")
        after_snapshot = _repo_snapshot(repo, failures)
        after_remote = _remote_branch_head(repo, remote_url, target_branch, failures)
    push_performed = push_run is not None and push_run["returncode"] == 0
    if push_performed:
        if after_remote != authorization.get("commit_id"):
            failures.append("remote branch head must equal authorized commit after Git push")
            _append_code(failure_codes, "git_push_remote_head_mismatch")
        if after_snapshot != before_snapshot:
            failures.append("Git push must not change target repo worktree snapshot")
            _append_code(failure_codes, "git_push_repo_snapshot_changed")
    elif not failures:
        failures.append("Git push was not performed")
        _append_code(failure_codes, "git_push_not_performed")

    receipt_path = output_root / "beta3_git_push_receipt.json"
    receipt_validation = None
    if push_performed and not failures:
        _write_push_receipt(
            receipt_path=receipt_path,
            authorization_path=authorization_path,
            authorization=authorization,
            before_snapshot=before_snapshot,
            after_snapshot=after_snapshot,
            before_remote=before_remote,
            after_remote=after_remote,
            push_run=push_run,
        )
        receipt_validation = validate_git_push_receipt(receipt_path)
        if receipt_validation["passed"] is not True:
            failures.extend(f"Git push receipt invalid: {reason}" for reason in receipt_validation["failure_reasons"])
            _append_code(failure_codes, "git_push_receipt_invalid")
    if failures and not failure_codes:
        _append_code(failure_codes, "git_push_internal_failure")

    report = {
        "schema_version": EXECUTION_SCHEMA,
        "passed": not failures,
        "push_status": "pushed_with_receipt" if not failures else "blocked_or_failed",
        "failure_reasons": failures,
        "failure_codes": failure_codes,
        "checked_at": _now(),
        "source_git_push_authorization": _artifact_ref(authorization_path),
        "source_git_push_authorization_validation": validation,
        "source_git_commit_receipt": authorization.get("source_git_commit_receipt"),
        "target_repo": {
            "repo_root": str(repo) if repo is not None else None,
            "before": before_snapshot,
            "after": after_snapshot,
        },
        "remote_url": remote_url,
        "target_branch": target_branch,
        "remote_branch_before_head": before_remote,
        "remote_branch_after_head": after_remote,
        "push": push_run,
        "push_receipt_path": str(receipt_path.resolve()) if receipt_path.is_file() else None,
        "receipt_validation": receipt_validation,
        "git_actions_performed": {"commit": True, "push": push_performed, "merge": False},
        "merge_allowed": False,
        "deploy_allowed": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
        "h3_boundary": _h3_boundary(),
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(output_root / "beta3_git_push_execution_report.json", report)
    return report


def validate_git_push_receipt(receipt_path: Path) -> dict[str, Any]:
    failures: list[str] = []
    receipt = _safe_read_json(receipt_path, failures, "Git push receipt")
    if not isinstance(receipt, dict):
        return _receipt_validation_report(receipt_path, failures or ["Git push receipt must be a JSON object"])
    if receipt.get("schema_version") != RECEIPT_SCHEMA:
        failures.append(f"schema_version must be {RECEIPT_SCHEMA}")
    if receipt.get("receipt_scope") != "git_push_only":
        failures.append("receipt_scope must be git_push_only")
    _validate_push_action_boundary(receipt, failures)
    _validate_h3_boundary(receipt, failures)

    authorization_ref = _as_ref(receipt.get("source_git_push_authorization"), failures, "source_git_push_authorization")
    authorization_path = _validate_ref_bytes(authorization_ref, failures, "source_git_push_authorization")
    authorization = _safe_read_json(authorization_path, failures, "Git push authorization")
    if not isinstance(authorization, dict):
        authorization = {}
    _validate_authorization_shape(authorization, failures)
    commit_ref = _as_ref(authorization.get("source_git_commit_receipt"), failures, "source_git_commit_receipt")
    commit_path = _validate_ref_bytes(commit_ref, failures, "source_git_commit_receipt")
    commit_receipt = _load_commit_receipt_static(commit_path, failures) if commit_path else {}
    _validate_authorization_commit_binding(authorization, commit_receipt, failures)
    for field in (
        "request_id",
        "source_git_commit_receipt",
        "source_patch_proposal",
        "commit_id",
        "remote_url",
        "target_branch",
        "remote_branch_before_head",
    ):
        if receipt.get(field) != authorization.get(field):
            failures.append(f"{field} must match Git push authorization")
    if receipt.get("remote_branch_after_head") != receipt.get("commit_id"):
        failures.append("remote_branch_after_head must equal commit_id")
    push_run = _as_dict(receipt.get("push"), failures, "push")
    if push_run.get("returncode") != 0:
        failures.append("push command returncode must be zero")

    target_repo = _as_dict(receipt.get("target_repo"), failures, "target_repo")
    repo = _repo_path(target_repo.get("repo_root"), failures)
    if target_repo.get("before") != authorization.get("target_repo", {}).get("authorization_snapshot"):
        failures.append("target_repo.before must match Git push authorization snapshot")
    if target_repo.get("after") != target_repo.get("before"):
        failures.append("Git push receipt target repo snapshots must be unchanged")
    if repo is not None:
        snapshot = _repo_snapshot(repo, failures)
        if target_repo.get("after") != snapshot:
            failures.append("target repo snapshot drifted after Git push receipt")
        if not _commit_exists(repo, receipt.get("commit_id"), failures):
            failures.append("authorized commit must exist in target repo")
    return _receipt_validation_report(receipt_path, failures)


def _load_commit_receipt(path: Path | None, failures: list[str]) -> dict[str, Any]:
    if path is None:
        return {}
    validation = validate_git_commit_receipt(path)
    if validation.get("passed") is not True:
        failures.extend(f"Git commit receipt invalid: {reason}" for reason in validation["failure_reasons"])
    return _load_commit_receipt_static(path, failures)


def _load_commit_receipt_static(path: Path | None, failures: list[str]) -> dict[str, Any]:
    receipt = _safe_read_json(path, failures, "Git commit receipt")
    if not isinstance(receipt, dict):
        return {}
    if receipt.get("schema_version") != COMMIT_RECEIPT_SCHEMA:
        failures.append(f"Git commit receipt schema_version must be {COMMIT_RECEIPT_SCHEMA}")
    if receipt.get("receipt_scope") != "git_commit_only":
        failures.append("Git push requires git_commit_only receipt")
    if receipt.get("git_actions_performed") != {"commit": True, "merge": False, "push": False}:
        failures.append("Git push requires commit-only Git action receipt")
    if not _target_text(receipt.get("commit_id")):
        failures.append("Git commit receipt commit_id must be non-empty")
    return receipt


def _validate_authorization_shape(authorization: dict[str, Any], failures: list[str]) -> None:
    if authorization.get("schema_version") != AUTHORIZATION_SCHEMA:
        failures.append(f"schema_version must be {AUTHORIZATION_SCHEMA}")
    if authorization.get("authorization_scope") != "git_push_only":
        failures.append("authorization_scope must be git_push_only")
    for field in ("operator_id", "reason", "rollback_evidence_ref", "remote_url", "commit_id"):
        if not _target_text(authorization.get(field)):
            failures.append(f"{field} must be a non-empty string")
    if authorization.get("lease_strategy") != "observed_remote_branch_head_and_plain_fast_forward_push":
        failures.append("lease_strategy must use observed remote branch head and plain fast-forward push")
    if authorization.get("push_authorized") is not True:
        failures.append("push_authorized must be true")
    if authorization.get("git_actions_performed") != {"commit": True, "merge": False, "push": False}:
        failures.append("authorization git_actions_performed must preserve commit-only evidence")
    _validate_false_boundary_flags(authorization, failures)
    _validate_h3_boundary(authorization, failures)


def _validate_authorization_commit_binding(
    authorization: dict[str, Any],
    commit_receipt: dict[str, Any],
    failures: list[str],
) -> None:
    if authorization.get("request_id") != commit_receipt.get("request_id"):
        failures.append("request_id must match Git commit receipt")
    if authorization.get("source_patch_proposal") != commit_receipt.get("source_patch_proposal"):
        failures.append("source_patch_proposal must match Git commit receipt")
    if authorization.get("commit_id") != commit_receipt.get("commit_id"):
        failures.append("commit_id must match Git commit receipt")
    repo_snapshot = authorization.get("target_repo", {}).get("authorization_snapshot")
    if repo_snapshot != commit_receipt.get("target_repo", {}).get("after"):
        failures.append("target repo authorization snapshot must match Git commit receipt after snapshot")


def _write_push_receipt(
    *,
    receipt_path: Path,
    authorization_path: Path,
    authorization: dict[str, Any],
    before_snapshot: dict[str, str],
    after_snapshot: dict[str, str],
    before_remote: str | None,
    after_remote: str | None,
    push_run: dict[str, Any],
) -> None:
    receipt = {
        "schema_version": RECEIPT_SCHEMA,
        "recorded_at": _now(),
        "request_id": authorization["request_id"],
        "receipt_scope": "git_push_only",
        "source_git_push_authorization": _artifact_ref(authorization_path),
        "source_git_commit_receipt": authorization["source_git_commit_receipt"],
        "source_patch_proposal": authorization["source_patch_proposal"],
        "commit_id": authorization["commit_id"],
        "target_repo": {
            "repo_root": authorization["target_repo"]["repo_root"],
            "before": before_snapshot,
            "after": after_snapshot,
        },
        "remote_url": authorization["remote_url"],
        "target_branch": authorization["target_branch"],
        "remote_branch_before_head": before_remote,
        "remote_branch_after_head": after_remote,
        "push": push_run,
        "git_actions_performed": {"commit": True, "push": True, "merge": False},
        "merge_allowed": False,
        "deploy_allowed": False,
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
        "push_status": "authorization_refused",
        "failure_reasons": [
            f"Git push authorization failed validation: {reason}"
            for reason in validation.get("failure_reasons", [])
        ],
        "failure_codes": ["git_push_authorization_refused"],
        "checked_at": _now(),
        "source_git_push_authorization": _artifact_ref_or_path(path),
        "source_git_push_authorization_validation": validation,
        "source_git_commit_receipt": None,
        "target_repo": None,
        "remote_url": None,
        "target_branch": None,
        "remote_branch_before_head": None,
        "remote_branch_after_head": None,
        "push": None,
        "push_receipt_path": None,
        "receipt_validation": None,
        "git_actions_performed": {"commit": True, "push": False, "merge": False},
        "merge_allowed": False,
        "deploy_allowed": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
        "h3_boundary": _h3_boundary(),
        "non_claims": list(NON_CLAIMS),
    }


def _validate_push_action_boundary(payload: dict[str, Any], failures: list[str]) -> None:
    if payload.get("git_actions_performed") != {"commit": True, "merge": False, "push": True}:
        failures.append("git_actions_performed must prove push without merge")
    _validate_false_boundary_flags(payload, failures)


def _validate_false_boundary_flags(payload: dict[str, Any], failures: list[str]) -> None:
    for flag in (
        "merge_allowed",
        "deploy_allowed",
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


def _repo_from_commit_receipt(receipt: dict[str, Any], failures: list[str]) -> Path | None:
    return _repo_path(receipt.get("target_repo", {}).get("repo_root"), failures)


def _repo_from_authorization(authorization: dict[str, Any], failures: list[str]) -> Path | None:
    return _repo_path(authorization.get("target_repo", {}).get("repo_root"), failures)


def _repo_path(value: Any, failures: list[str]) -> Path | None:
    text = _target_text(value)
    if not text:
        failures.append("target_repo.repo_root must be a non-empty string")
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
        "status_short": _git_text(repo, failures, "status", "--short"),
    }


def _remote_branch_head(repo: Path, remote_url: str, branch: str, failures: list[str]) -> str | None:
    run = _git(repo, failures, "ls-remote", "--heads", remote_url, f"refs/heads/{branch}")
    if run["returncode"] != 0:
        return None
    lines = [line.split() for line in str(run["stdout"]).splitlines() if line.strip()]
    if not lines:
        return None
    if len(lines) != 1 or len(lines[0]) < 2:
        failures.append("git ls-remote returned ambiguous branch head")
        return None
    return lines[0][0]


def _valid_branch(repo: Path | None, value: Any, failures: list[str]) -> str:
    branch = _required_target_text(value, "target_branch", failures)
    if repo is None or not branch:
        return branch
    run = _git(repo, failures, "check-ref-format", "--branch", branch)
    if run["returncode"] != 0:
        failures.append("target_branch must pass git check-ref-format --branch")
    return branch


def _required_target_text(value: Any, field: str, failures: list[str]) -> str:
    text = _target_text(value)
    if not text:
        failures.append(f"{field} must be a non-empty string that does not start with '-'")
    return text


def _target_text(value: Any) -> str:
    text = value.strip() if isinstance(value, str) else ""
    return text if text and not text.startswith("-") else ""


def _required_text(value: Any, field: str) -> str:
    text = value.strip() if isinstance(value, str) else ""
    if not text:
        raise ValueError(f"{field} must be a non-empty string")
    return text


def _commit_exists(repo: Path, commit_id: Any, failures: list[str]) -> bool:
    commit = _target_text(commit_id)
    if not commit:
        return False
    run = _git(repo, failures, "cat-file", "-e", f"{commit}^{{commit}}")
    return run["returncode"] == 0


def _git_text(repo: Path, failures: list[str], *args: str) -> str:
    return str(_git(repo, failures, *args)["stdout"])


def _git(repo: Path, failures: list[str], *args: str) -> dict[str, Any]:
    result = subprocess.run(["git", *args], cwd=repo, check=False, text=True, capture_output=True)
    run = _command_report(" ".join(["git", *args]), result)
    if run["returncode"] != 0:
        failures.append(f"{run['command']} failed")
    return run


def _command_report(command: str, result: subprocess.CompletedProcess[str]) -> dict[str, Any]:
    return {
        "command": command,
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


def _artifact_ref(path: Path) -> dict[str, str]:
    if not path.is_file():
        raise FileNotFoundError(f"artifact path is not a file: {path}")
    return {"path": str(path.resolve()), "sha256": _sha256(path)}


def _artifact_ref_or_path(path: Path) -> dict[str, str | None]:
    return {"path": str(path.resolve()), "sha256": _sha256(path) if path.is_file() else None}


def _validate_ref_bytes(ref: dict[str, Any], failures: list[str], label: str) -> Path | None:
    path_text = _target_text(ref.get("path"))
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
    if isinstance(value, dict):
        return value
    failures.append(f"{label} must be an object")
    return {}


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
    except Exception as exc:  # noqa: BLE001 - validation needs artifact detail.
        failures.append(f"{label} could not be read: {exc}")
        return None
    if not isinstance(payload, dict):
        failures.append(f"{label} must be a JSON object")
        return None
    return payload


def _read_json_object(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"JSON object required: {path}")
    return payload


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


def _append_code(codes: list[str], code: str) -> None:
    if code not in codes:
        codes.append(code)


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


if __name__ == "__main__":
    sys.exit(main())
