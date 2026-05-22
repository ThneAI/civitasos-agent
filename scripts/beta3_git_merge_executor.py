#!/usr/bin/env python3
"""Authorize and execute one controlled Beta-3 Git merge from a push receipt.

Push evidence is not merge approval. This executor requires a fresh operator
authorization bound to a pushed source branch, a clean target worktree, and an
explicit controlled target branch. It fetches only the pushed branch, performs
one no-fast-forward merge into the controlled branch, writes a merge receipt,
and never deploys or writes production receipts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from beta3_git_push_executor import RECEIPT_SCHEMA as PUSH_RECEIPT_SCHEMA
from beta3_git_push_executor import validate_git_push_receipt


AUTHORIZATION_SCHEMA = "beta3-git-merge-authorization:v1"
AUTHORIZATION_VALIDATION_SCHEMA = "beta3-git-merge-authorization-validation:v1"
AUTHORIZATION_WRITE_SCHEMA = "beta3-git-merge-authorization-write-report:v1"
EXECUTION_SCHEMA = "beta3-git-merge-execution-report:v1"
RECEIPT_SCHEMA = "beta3-git-merge-receipt:v1"
RECEIPT_VALIDATION_SCHEMA = "beta3-git-merge-receipt-validation:v1"
NON_CLAIMS = (
    "beta3_git_merge_executor_is_l1_controlled_pilot_only",
    "beta3_git_merge_executor_requires_fresh_merge_authorization_after_push",
    "beta3_git_merge_executor_requires_clean_controlled_target_branch",
    "beta3_git_merge_executor_fetches_only_the_pushed_source_branch",
    "beta3_git_merge_executor_does_not_deploy",
    "beta3_git_merge_executor_does_not_claim_h3_production_readiness",
    "beta3_git_merge_executor_does_not_write_production_receipts",
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    record = subparsers.add_parser("record-authorization", help="record merge authorization")
    record.add_argument("--git-push-receipt", required=True)
    record.add_argument("--target-repo", required=True)
    record.add_argument("--target-branch", required=True)
    record.add_argument("--merge-message", required=True)
    record.add_argument("--output", required=True)
    record.add_argument("--operator-id", default="l1-controlled-pilot-operator")
    record.add_argument("--reason", required=True)
    record.add_argument("--rollback-evidence-ref", required=True)

    validate_authorization = subparsers.add_parser(
        "validate-authorization",
        help="validate merge authorization and current branch leases",
    )
    validate_authorization.add_argument("--authorization", required=True)
    validate_authorization.add_argument("--output")

    merge = subparsers.add_parser("merge", help="execute one authorized controlled Git merge")
    merge.add_argument("--authorization", required=True)
    merge.add_argument("--output-root", required=True)

    validate_receipt = subparsers.add_parser("validate-receipt", help="validate Git merge receipt")
    validate_receipt.add_argument("--receipt", required=True)
    validate_receipt.add_argument("--output")

    args = parser.parse_args(argv)
    if args.command == "record-authorization":
        report = record_merge_authorization(
            push_receipt_path=Path(args.git_push_receipt),
            target_repo=Path(args.target_repo),
            target_branch=args.target_branch,
            merge_message=args.merge_message,
            output_path=Path(args.output),
            operator_id=args.operator_id,
            reason=args.reason,
            rollback_evidence_ref=args.rollback_evidence_ref,
        )
    elif args.command == "validate-authorization":
        report = validate_merge_authorization(Path(args.authorization))
        if args.output:
            _write_json(Path(args.output), report)
    elif args.command == "merge":
        report = run_git_merge(
            authorization_path=Path(args.authorization),
            output_root=Path(args.output_root),
        )
    elif args.command == "validate-receipt":
        report = validate_git_merge_receipt(Path(args.receipt))
        if args.output:
            _write_json(Path(args.output), report)
    else:
        raise AssertionError(f"unknown command: {args.command}")
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report.get("receipt_validation", report.get("validation", report)).get("passed") and report.get(
        "passed",
        True,
    ) else 1


def record_merge_authorization(
    *,
    push_receipt_path: Path,
    target_repo: Path,
    target_branch: str,
    merge_message: str,
    output_path: Path,
    operator_id: str,
    reason: str,
    rollback_evidence_ref: str,
) -> dict[str, Any]:
    failures: list[str] = []
    push_receipt = _load_push_receipt(push_receipt_path, failures)
    repo = _repo_path(target_repo, failures)
    target_branch = _valid_branch(repo, target_branch, failures)
    operator_id = _required_text(operator_id, "operator_id")
    reason = _required_text(reason, "reason")
    rollback_evidence_ref = _required_text(rollback_evidence_ref, "rollback_evidence_ref")
    merge_message = _required_text(merge_message, "merge_message")
    snapshot = _controlled_target_snapshot(repo, target_branch, failures)
    source_remote_url = _target_text(push_receipt.get("remote_url"))
    source_branch = _target_text(push_receipt.get("target_branch"))
    source_commit_id = _target_text(push_receipt.get("commit_id"))
    source_remote_head = (
        _remote_branch_head(repo, source_remote_url, source_branch, failures)
        if repo is not None and source_remote_url and source_branch
        else None
    )
    if source_remote_head != source_commit_id:
        failures.append("pushed source branch head must still equal Git push receipt commit_id")
    if failures:
        raise ValueError(f"Git merge authorization blocked: {failures}")

    authorization = {
        "schema_version": AUTHORIZATION_SCHEMA,
        "recorded_at": _now(),
        "request_id": push_receipt["request_id"],
        "authorization_scope": "git_merge_only",
        "operator_id": operator_id,
        "reason": reason,
        "rollback_evidence_ref": rollback_evidence_ref,
        "merge_message": merge_message,
        "source_git_push_receipt": _artifact_ref(push_receipt_path),
        "source_git_commit_receipt": push_receipt["source_git_commit_receipt"],
        "source_patch_proposal": push_receipt["source_patch_proposal"],
        "source_commit_id": source_commit_id,
        "source_remote_url": source_remote_url,
        "source_branch": source_branch,
        "source_remote_head": source_remote_head,
        "target_repo": {
            "repo_root": str(repo),
            "authorization_snapshot": snapshot,
        },
        "target_branch": target_branch,
        "lease_strategy": "pushed_source_remote_head_and_controlled_target_branch_snapshot_before_no_ff_merge",
        "merge_authorized": True,
        "git_actions_performed": {"commit": True, "push": True, "merge": False},
        "deploy_allowed": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
        "h3_boundary": _h3_boundary(),
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(output_path, authorization)
    validation = validate_merge_authorization(output_path)
    if validation["passed"] is not True:
        raise ValueError(f"written Git merge authorization failed validation: {validation['failure_reasons']}")
    return {
        "schema_version": AUTHORIZATION_WRITE_SCHEMA,
        "authorization_written": True,
        "authorization_path": str(output_path.resolve()),
        "authorization_sha256": _sha256(output_path),
        "request_id": push_receipt["request_id"],
        "validation": validation,
        "non_claims": list(NON_CLAIMS),
    }


def validate_merge_authorization(path: Path) -> dict[str, Any]:
    failures: list[str] = []
    authorization = _safe_read_json(path, failures, "Git merge authorization")
    if not isinstance(authorization, dict):
        return _authorization_validation_report(path, failures or ["Git merge authorization must be a JSON object"])
    push_receipt = _validate_authorization_static(authorization, failures)
    repo = _repo_from_authorization(authorization, failures)
    branch = _valid_branch(repo, authorization.get("target_branch"), failures)
    snapshot = _controlled_target_snapshot(repo, branch, failures)
    if snapshot != authorization.get("target_repo", {}).get("authorization_snapshot"):
        failures.append("controlled target branch snapshot drifted after Git merge authorization")
    source_head = _remote_branch_head(
        repo,
        _target_text(authorization.get("source_remote_url")),
        _target_text(authorization.get("source_branch")),
        failures,
    ) if repo is not None else None
    if source_head != authorization.get("source_remote_head"):
        failures.append("pushed source branch head drifted after Git merge authorization")
    if push_receipt and source_head != push_receipt.get("commit_id"):
        failures.append("pushed source branch no longer points at Git push receipt commit_id")
    return _authorization_validation_report(path, failures)


def run_git_merge(*, authorization_path: Path, output_root: Path) -> dict[str, Any]:
    output_root = output_root.resolve()
    output_root.mkdir(parents=True, exist_ok=True)
    validation = validate_merge_authorization(authorization_path)
    if validation.get("passed") is not True:
        report = _authorization_refusal_report(authorization_path, validation)
        _write_json(output_root / "beta3_git_merge_execution_report.json", report)
        return report

    failures: list[str] = []
    failure_codes: list[str] = []
    authorization = _read_json_object(authorization_path)
    repo = _repo_from_authorization(authorization, failures)
    target_branch = str(authorization["target_branch"])
    before = _controlled_target_snapshot(repo, target_branch, failures)
    fetch: dict[str, Any] | None = None
    merge: dict[str, Any] | None = None
    fetched_source_commit: str | None = None
    merge_commit_id: str | None = None
    merge_parents: list[str] = []

    if not failures and repo is not None:
        fetch = _git(
            repo,
            failures,
            "fetch",
            "--no-tags",
            str(authorization["source_remote_url"]),
            f"refs/heads/{authorization['source_branch']}",
        )
        if fetch["returncode"] != 0:
            _append_code(failure_codes, "git_merge_fetch_failed")
        fetched_source_commit = _git_text(repo, failures, "rev-parse", "FETCH_HEAD").strip()
        if fetched_source_commit != authorization["source_commit_id"]:
            failures.append("fetched source commit must equal authorized pushed commit")
            _append_code(failure_codes, "git_merge_fetched_source_mismatch")
    if not failures and repo is not None:
        merge = _git(
            repo,
            failures,
            "merge",
            "--no-ff",
            "-m",
            str(authorization["merge_message"]),
            "FETCH_HEAD",
        )
        if merge["returncode"] != 0:
            _append_code(failure_codes, "git_merge_failed")

    after = _repo_snapshot(repo, failures) if repo is not None else {}
    merge_performed = merge is not None and merge["returncode"] == 0
    if merge_performed and repo is not None:
        merge_commit_id = after.get("head_commit")
        merge_parents = _commit_parents(repo, merge_commit_id, failures)
        if merge_commit_id == before.get("head_commit"):
            failures.append("Git merge did not advance controlled target branch HEAD")
            _append_code(failure_codes, "git_merge_head_not_advanced")
        if after.get("current_branch") != target_branch:
            failures.append("Git merge must stay on the controlled target branch")
            _append_code(failure_codes, "git_merge_target_branch_changed")
        if after.get("status_short"):
            failures.append("controlled target repo must be clean after Git merge")
            _append_code(failure_codes, "git_merge_after_snapshot_dirty")
        expected_parents = [before.get("head_commit"), authorization["source_commit_id"]]
        if merge_parents != expected_parents:
            failures.append("Git merge commit parents must bind target before HEAD and pushed source commit")
            _append_code(failure_codes, "git_merge_parent_binding_mismatch")
    elif not failures:
        failures.append("Git merge was not performed")
        _append_code(failure_codes, "git_merge_not_performed")
    if failures and not failure_codes:
        _append_code(failure_codes, "git_merge_internal_failure")

    receipt_path = output_root / "beta3_git_merge_receipt.json"
    receipt_validation = None
    if merge_performed and not failures:
        _write_merge_receipt(
            receipt_path=receipt_path,
            authorization_path=authorization_path,
            authorization=authorization,
            before=before,
            after=after,
            fetch=fetch,
            fetched_source_commit=fetched_source_commit,
            merge=merge,
            merge_commit_id=merge_commit_id,
            merge_parents=merge_parents,
        )
        receipt_validation = validate_git_merge_receipt(receipt_path)
        if receipt_validation["passed"] is not True:
            failures.extend(f"Git merge receipt invalid: {reason}" for reason in receipt_validation["failure_reasons"])
            _append_code(failure_codes, "git_merge_receipt_invalid")

    report = {
        "schema_version": EXECUTION_SCHEMA,
        "passed": not failures,
        "merge_status": "merged_with_receipt" if not failures else "blocked_or_failed",
        "failure_reasons": failures,
        "failure_codes": failure_codes,
        "checked_at": _now(),
        "source_git_merge_authorization": _artifact_ref(authorization_path),
        "source_git_merge_authorization_validation": validation,
        "source_git_push_receipt": authorization.get("source_git_push_receipt"),
        "source_remote_url": authorization.get("source_remote_url"),
        "source_branch": authorization.get("source_branch"),
        "source_commit_id": authorization.get("source_commit_id"),
        "target_repo": {
            "repo_root": str(repo) if repo is not None else None,
            "before": before,
            "after": after,
        },
        "target_branch": target_branch,
        "fetch": fetch,
        "fetched_source_commit": fetched_source_commit,
        "merge": merge,
        "merge_commit_id": merge_commit_id,
        "merge_parents": merge_parents,
        "merge_receipt_path": str(receipt_path.resolve()) if receipt_path.is_file() else None,
        "receipt_validation": receipt_validation,
        "git_actions_performed": {"commit": True, "push": True, "merge": merge_performed},
        "deploy_allowed": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
        "h3_boundary": _h3_boundary(),
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(output_root / "beta3_git_merge_execution_report.json", report)
    return report


def validate_git_merge_receipt(receipt_path: Path) -> dict[str, Any]:
    failures: list[str] = []
    receipt = _safe_read_json(receipt_path, failures, "Git merge receipt")
    if not isinstance(receipt, dict):
        return _receipt_validation_report(receipt_path, failures or ["Git merge receipt must be a JSON object"])
    if receipt.get("schema_version") != RECEIPT_SCHEMA:
        failures.append(f"schema_version must be {RECEIPT_SCHEMA}")
    if receipt.get("receipt_scope") != "git_merge_only":
        failures.append("receipt_scope must be git_merge_only")
    _validate_merge_action_boundary(receipt, failures)
    _validate_h3_boundary(receipt, failures)

    authorization_ref = _as_ref(
        receipt.get("source_git_merge_authorization"),
        failures,
        "source_git_merge_authorization",
    )
    authorization_path = _validate_ref_bytes(authorization_ref, failures, "source_git_merge_authorization")
    authorization = _safe_read_json(authorization_path, failures, "Git merge authorization")
    if not isinstance(authorization, dict):
        authorization = {}
    _validate_authorization_static(authorization, failures)
    for field in (
        "request_id",
        "source_git_push_receipt",
        "source_git_commit_receipt",
        "source_patch_proposal",
        "source_commit_id",
        "source_remote_url",
        "source_branch",
        "target_branch",
    ):
        if receipt.get(field) != authorization.get(field):
            failures.append(f"{field} must match Git merge authorization")
    if receipt.get("fetched_source_commit") != receipt.get("source_commit_id"):
        failures.append("fetched_source_commit must equal source_commit_id")

    fetch = _as_dict(receipt.get("fetch"), failures, "fetch")
    merge = _as_dict(receipt.get("merge"), failures, "merge")
    if fetch.get("returncode") != 0:
        failures.append("fetch command returncode must be zero")
    if merge.get("returncode") != 0:
        failures.append("merge command returncode must be zero")
    target_repo = _as_dict(receipt.get("target_repo"), failures, "target_repo")
    if target_repo.get("before") != authorization.get("target_repo", {}).get("authorization_snapshot"):
        failures.append("target_repo.before must match Git merge authorization snapshot")
    repo = _repo_path(target_repo.get("repo_root"), failures)
    if repo is not None:
        snapshot = _repo_snapshot(repo, failures)
        if snapshot != target_repo.get("after"):
            failures.append("controlled target repo snapshot drifted after Git merge receipt")
        if snapshot.get("current_branch") != receipt.get("target_branch"):
            failures.append("controlled target repo branch must match Git merge receipt target_branch")
        if snapshot.get("head_commit") != receipt.get("merge_commit_id"):
            failures.append("controlled target repo HEAD must equal merge_commit_id")
        parents = _commit_parents(repo, receipt.get("merge_commit_id"), failures)
        if parents != receipt.get("merge_parents"):
            failures.append("merge_parents must match target repo merge commit")
        if not _commit_exists(repo, receipt.get("source_commit_id"), failures):
            failures.append("source_commit_id must exist in controlled target repo")
    expected_parents = [
        target_repo.get("before", {}).get("head_commit"),
        receipt.get("source_commit_id"),
    ]
    if receipt.get("merge_parents") != expected_parents:
        failures.append("merge_parents must bind target before HEAD and pushed source commit")
    return _receipt_validation_report(receipt_path, failures)


def _validate_authorization_static(authorization: dict[str, Any], failures: list[str]) -> dict[str, Any]:
    _validate_authorization_shape(authorization, failures)
    push_ref = _as_ref(authorization.get("source_git_push_receipt"), failures, "source_git_push_receipt")
    push_path = _validate_ref_bytes(push_ref, failures, "source_git_push_receipt")
    push_receipt = _load_push_receipt(push_path, failures) if push_path else {}
    if authorization.get("request_id") != push_receipt.get("request_id"):
        failures.append("request_id must match Git push receipt")
    for field, push_field in (
        ("source_git_commit_receipt", "source_git_commit_receipt"),
        ("source_patch_proposal", "source_patch_proposal"),
        ("source_commit_id", "commit_id"),
        ("source_remote_url", "remote_url"),
        ("source_branch", "target_branch"),
        ("source_remote_head", "remote_branch_after_head"),
    ):
        if authorization.get(field) != push_receipt.get(push_field):
            failures.append(f"{field} must match Git push receipt {push_field}")
    return push_receipt


def _validate_authorization_shape(authorization: dict[str, Any], failures: list[str]) -> None:
    if authorization.get("schema_version") != AUTHORIZATION_SCHEMA:
        failures.append(f"schema_version must be {AUTHORIZATION_SCHEMA}")
    if authorization.get("authorization_scope") != "git_merge_only":
        failures.append("authorization_scope must be git_merge_only")
    for field in (
        "operator_id",
        "reason",
        "rollback_evidence_ref",
        "merge_message",
        "source_commit_id",
        "source_remote_url",
        "source_branch",
        "source_remote_head",
    ):
        if not _target_text(authorization.get(field)):
            failures.append(f"{field} must be a non-empty string")
    if (
        authorization.get("lease_strategy")
        != "pushed_source_remote_head_and_controlled_target_branch_snapshot_before_no_ff_merge"
    ):
        failures.append("lease_strategy must bind source remote head and controlled target branch snapshot")
    if authorization.get("merge_authorized") is not True:
        failures.append("merge_authorized must be true")
    if authorization.get("git_actions_performed") != {"commit": True, "push": True, "merge": False}:
        failures.append("authorization git_actions_performed must preserve push-only evidence before merge")
    _validate_false_boundary_flags(authorization, failures)
    _validate_h3_boundary(authorization, failures)


def _load_push_receipt(path: Path | None, failures: list[str]) -> dict[str, Any]:
    if path is None:
        return {}
    validation = validate_git_push_receipt(path)
    if validation.get("passed") is not True:
        failures.extend(f"Git push receipt invalid: {reason}" for reason in validation["failure_reasons"])
    receipt = _safe_read_json(path, failures, "Git push receipt")
    if not isinstance(receipt, dict):
        return {}
    if receipt.get("schema_version") != PUSH_RECEIPT_SCHEMA:
        failures.append(f"Git push receipt schema_version must be {PUSH_RECEIPT_SCHEMA}")
    if receipt.get("receipt_scope") != "git_push_only":
        failures.append("Git merge requires git_push_only receipt")
    if receipt.get("git_actions_performed") != {"commit": True, "push": True, "merge": False}:
        failures.append("Git merge requires pushed source without prior merge")
    if receipt.get("remote_branch_after_head") != receipt.get("commit_id"):
        failures.append("Git push receipt must bind remote branch head to commit_id")
    return receipt


def _write_merge_receipt(
    *,
    receipt_path: Path,
    authorization_path: Path,
    authorization: dict[str, Any],
    before: dict[str, str],
    after: dict[str, str],
    fetch: dict[str, Any] | None,
    fetched_source_commit: str | None,
    merge: dict[str, Any] | None,
    merge_commit_id: str | None,
    merge_parents: list[str],
) -> None:
    receipt = {
        "schema_version": RECEIPT_SCHEMA,
        "recorded_at": _now(),
        "request_id": authorization["request_id"],
        "receipt_scope": "git_merge_only",
        "source_git_merge_authorization": _artifact_ref(authorization_path),
        "source_git_push_receipt": authorization["source_git_push_receipt"],
        "source_git_commit_receipt": authorization["source_git_commit_receipt"],
        "source_patch_proposal": authorization["source_patch_proposal"],
        "source_commit_id": authorization["source_commit_id"],
        "source_remote_url": authorization["source_remote_url"],
        "source_branch": authorization["source_branch"],
        "target_repo": {
            "repo_root": authorization["target_repo"]["repo_root"],
            "before": before,
            "after": after,
        },
        "target_branch": authorization["target_branch"],
        "fetch": fetch,
        "fetched_source_commit": fetched_source_commit,
        "merge": merge,
        "merge_commit_id": merge_commit_id,
        "merge_parents": merge_parents,
        "git_actions_performed": {"commit": True, "push": True, "merge": True},
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
        "merge_status": "authorization_refused",
        "failure_reasons": [
            f"Git merge authorization failed validation: {reason}"
            for reason in validation.get("failure_reasons", [])
        ],
        "failure_codes": ["git_merge_authorization_refused"],
        "checked_at": _now(),
        "source_git_merge_authorization": _artifact_ref_or_path(path),
        "source_git_merge_authorization_validation": validation,
        "source_git_push_receipt": None,
        "source_remote_url": None,
        "source_branch": None,
        "source_commit_id": None,
        "target_repo": None,
        "target_branch": None,
        "fetch": None,
        "fetched_source_commit": None,
        "merge": None,
        "merge_commit_id": None,
        "merge_parents": [],
        "merge_receipt_path": None,
        "receipt_validation": None,
        "git_actions_performed": {"commit": True, "push": True, "merge": False},
        "deploy_allowed": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
        "h3_boundary": _h3_boundary(),
        "non_claims": list(NON_CLAIMS),
    }


def _validate_merge_action_boundary(payload: dict[str, Any], failures: list[str]) -> None:
    if payload.get("git_actions_performed") != {"commit": True, "push": True, "merge": True}:
        failures.append("git_actions_performed must prove controlled merge after push")
    _validate_false_boundary_flags(payload, failures)


def _validate_false_boundary_flags(payload: dict[str, Any], failures: list[str]) -> None:
    for flag in (
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


def _controlled_target_snapshot(repo: Path | None, branch: str, failures: list[str]) -> dict[str, str]:
    if repo is None:
        return {}
    snapshot = _repo_snapshot(repo, failures)
    if snapshot.get("current_branch") != branch:
        failures.append("target repo must be checked out on explicit controlled target_branch")
    if snapshot.get("status_short"):
        failures.append("controlled target repo worktree must be clean")
    return snapshot


def _repo_from_authorization(authorization: dict[str, Any], failures: list[str]) -> Path | None:
    return _repo_path(authorization.get("target_repo", {}).get("repo_root"), failures)


def _repo_path(value: Any, failures: list[str]) -> Path | None:
    text = str(value).strip() if isinstance(value, (str, Path)) else ""
    if not text or text.startswith("-"):
        failures.append("target_repo must be a non-empty Git worktree path")
        return None
    result = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        cwd=Path(text),
        check=False,
        text=True,
        capture_output=True,
    )
    if result.returncode != 0:
        failures.append(f"target_repo must be a Git worktree: {text}")
        return None
    return Path(result.stdout.strip()).resolve()


def _repo_snapshot(repo: Path, failures: list[str]) -> dict[str, str]:
    return {
        "head_commit": _git_text(repo, failures, "rev-parse", "HEAD").strip(),
        "current_branch": _git_text(repo, failures, "branch", "--show-current").strip(),
        "status_short": _git_text(repo, failures, "status", "--short"),
    }


def _valid_branch(repo: Path | None, value: Any, failures: list[str]) -> str:
    branch = _required_target_text(value, "target_branch", failures)
    if repo is None or not branch:
        return branch
    run = _git(repo, failures, "check-ref-format", "--branch", branch)
    if run["returncode"] != 0:
        failures.append("target_branch must pass git check-ref-format --branch")
    return branch


def _remote_branch_head(repo: Path | None, remote_url: str, branch: str, failures: list[str]) -> str | None:
    if repo is None or not remote_url or not branch:
        return None
    run = _git(repo, failures, "ls-remote", "--heads", remote_url, f"refs/heads/{branch}")
    if run["returncode"] != 0:
        return None
    lines = [line.split() for line in str(run["stdout"]).splitlines() if line.strip()]
    if not lines:
        return None
    if len(lines) != 1 or len(lines[0]) < 2:
        failures.append("git ls-remote returned ambiguous source branch head")
        return None
    return lines[0][0]


def _commit_parents(repo: Path, commit_id: Any, failures: list[str]) -> list[str]:
    commit = _target_text(commit_id)
    if not commit:
        return []
    line = _git_text(repo, failures, "rev-list", "--parents", "-n", "1", commit).split()
    return line[1:] if line else []


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
    run = {
        "command": " ".join(["git", *args]),
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }
    if run["returncode"] != 0:
        failures.append(f"{run['command']} failed")
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
