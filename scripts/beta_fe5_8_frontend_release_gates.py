#!/usr/bin/env python3
"""Beta-FE-5..8 frontend GitHub release gates.

FE-5 consumes a FE-4 commit receipt and pushes one bounded remote branch.
FE-6 consumes the push receipt and creates one draft PR.
FE-7 consumes the PR receipt and records local + external Agent review
reconciliation.
FE-8 consumes the review reconciliation and merges the PR.

None of these gates deploy, execute production runtime actions, or write
production receipts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

FE4_RECEIPT_SCHEMA = "beta-fe4-frontend-commit-receipt:v1"
FE5_RECEIPT_SCHEMA = "beta-fe5-frontend-push-receipt:v1"
FE6_RECEIPT_SCHEMA = "beta-fe6-frontend-draft-pr-receipt:v1"
FE7_RECEIPT_SCHEMA = "beta-fe7-frontend-review-reconciliation:v1"
FE8_RECEIPT_SCHEMA = "beta-fe8-frontend-merge-receipt:v1"
NON_CLAIMS = (
    "beta_fe_release_gates_are_l1_controlled_pilot_only",
    "beta_fe_release_gates_do_not_deploy_frontend",
    "beta_fe_release_gates_do_not_claim_h3_production_readiness",
    "beta_fe_release_gates_do_not_write_production_receipts",
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    fe5 = sub.add_parser("fe5-push", help="consume FE-4 receipt and push one remote branch")
    fe5.add_argument("--source-fe4-receipt", required=True)
    fe5.add_argument("--frontend-root", required=True)
    fe5.add_argument("--output-root", required=True)
    fe5.add_argument("--remote", default="origin")
    fe5.add_argument("--target-branch", required=True)
    fe5.add_argument("--operator-id", default="local-operator-cc")
    fe5.add_argument("--operator-authorization", default="current_chat_fe5_push_request")

    fe6 = sub.add_parser("fe6-pr", help="consume FE-5 receipt and create one GitHub draft PR")
    fe6.add_argument("--source-fe5-receipt", required=True)
    fe6.add_argument("--frontend-root", required=True)
    fe6.add_argument("--output-root", required=True)
    fe6.add_argument("--github-repo", required=True)
    fe6.add_argument("--base-branch", default="main")
    fe6.add_argument("--title", required=True)
    fe6.add_argument("--body-file", required=True)
    fe6.add_argument("--operator-id", default="local-operator-cc")
    fe6.add_argument("--operator-authorization", default="current_chat_fe6_draft_pr_request")

    fe7 = sub.add_parser("fe7-review", help="consume FE-6 receipt and reconcile local/external Agent reviews")
    fe7.add_argument("--source-fe6-receipt", required=True)
    fe7.add_argument("--frontend-root", required=True)
    fe7.add_argument("--output-root", required=True)
    fe7.add_argument("--external-env-file", required=True)
    fe7.add_argument("--operator-decision", default="ready_to_merge")
    fe7.add_argument("--operator-id", default="local-operator-cc")
    fe7.add_argument("--operator-authorization", default="current_chat_fe7_review_reconciliation_request")
    fe7.add_argument("--max-diff-chars", type=int, default=24000)

    fe8 = sub.add_parser("fe8-merge", help="consume FE-7 reconciliation and merge the PR")
    fe8.add_argument("--source-fe7-reconciliation", required=True)
    fe8.add_argument("--frontend-root", required=True)
    fe8.add_argument("--output-root", required=True)
    fe8.add_argument("--merge-method", choices=("rebase", "squash", "merge"), default="rebase")
    fe8.add_argument("--delete-branch", action="store_true")
    fe8.add_argument("--operator-id", default="local-operator-cc")
    fe8.add_argument("--operator-authorization", default="current_chat_fe8_merge_request")

    args = parser.parse_args(argv)
    if args.command == "fe5-push":
        report = run_fe5_push(
            source_fe4_receipt=Path(args.source_fe4_receipt),
            frontend_root=Path(args.frontend_root),
            output_root=Path(args.output_root),
            remote=args.remote,
            target_branch=args.target_branch,
            operator_id=args.operator_id,
            operator_authorization=args.operator_authorization,
        )
    elif args.command == "fe6-pr":
        report = run_fe6_pr(
            source_fe5_receipt=Path(args.source_fe5_receipt),
            frontend_root=Path(args.frontend_root),
            output_root=Path(args.output_root),
            github_repo=args.github_repo,
            base_branch=args.base_branch,
            title=args.title,
            body_file=Path(args.body_file),
            operator_id=args.operator_id,
            operator_authorization=args.operator_authorization,
        )
    elif args.command == "fe7-review":
        report = run_fe7_review(
            source_fe6_receipt=Path(args.source_fe6_receipt),
            frontend_root=Path(args.frontend_root),
            output_root=Path(args.output_root),
            external_env_file=Path(args.external_env_file),
            operator_decision=args.operator_decision,
            operator_id=args.operator_id,
            operator_authorization=args.operator_authorization,
            max_diff_chars=args.max_diff_chars,
        )
    elif args.command == "fe8-merge":
        report = run_fe8_merge(
            source_fe7_reconciliation=Path(args.source_fe7_reconciliation),
            frontend_root=Path(args.frontend_root),
            output_root=Path(args.output_root),
            merge_method=args.merge_method,
            delete_branch=bool(args.delete_branch),
            operator_id=args.operator_id,
            operator_authorization=args.operator_authorization,
        )
    else:
        raise AssertionError(args.command)
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report.get("passed") is True else 1


def run_fe5_push(*, source_fe4_receipt: Path, frontend_root: Path, output_root: Path, remote: str, target_branch: str, operator_id: str, operator_authorization: str) -> dict[str, Any]:
    frontend_root = frontend_root.resolve()
    output_root = output_root.resolve()
    output_root.mkdir(parents=True, exist_ok=True)
    failures: list[str] = []
    fe4 = _read_json(source_fe4_receipt, failures, "FE-4 commit receipt")
    _validate_fe4(fe4, failures)
    commit_id = _text(fe4.get("commit_id")) if isinstance(fe4, dict) else ""
    _validate_branch(target_branch, failures)
    before = _repo_snapshot(frontend_root, failures)
    if before.get("head_commit") != commit_id:
        failures.append("frontend HEAD must equal FE-4 commit_id")
    if before.get("status_short"):
        failures.append("frontend worktree must be clean before FE-5 push")
    remote_url = _git_text(frontend_root, failures, "remote", "get-url", remote).strip() if not failures else ""
    remote_before = _remote_head(frontend_root, remote, target_branch, failures) if not failures else None
    if remote_before and remote_before != commit_id:
        failures.append("target branch already exists at a different commit")

    auth_path = output_root / "beta_fe5_frontend_push_authorization.json"
    authorization = {
        "schema_version": "beta-fe5-frontend-push-authorization:v1",
        "created_at": _now(),
        "decision": "beta_fe5_frontend_push_authorized" if not failures else "blocked",
        "operator_id": operator_id,
        "operator_authorization": operator_authorization,
        "source_fe4_receipt": _artifact_ref(source_fe4_receipt) if source_fe4_receipt.is_file() else None,
        "frontend_root": str(frontend_root),
        "commit_id": commit_id,
        "remote": remote,
        "remote_url": remote_url,
        "target_branch": target_branch,
        "remote_branch_before_head": remote_before,
        "authorization_scope": "remote_branch_push_only",
        "boundary": _boundary(push_allowed=True),
        "h3_boundary": _h3_boundary(),
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(auth_path, authorization)

    push_run = None
    remote_after = remote_before
    if not failures:
        push_run = _git(frontend_root, "push", "--porcelain", remote, f"{commit_id}:refs/heads/{target_branch}")
        if push_run["returncode"] != 0:
            failures.append("git push failed")
        remote_after = _remote_head(frontend_root, remote, target_branch, failures)
        if remote_after != commit_id:
            failures.append("remote target branch must equal FE-4 commit after push")

    receipt_path = output_root / "beta_fe5_frontend_push_receipt.json"
    receipt = {
        "schema_version": FE5_RECEIPT_SCHEMA,
        "checked_at": _now(),
        "passed": not failures,
        "decision": "beta_fe5_frontend_push_receipt_passed" if not failures else "blocked",
        "failure_reasons": failures,
        "source_fe4_receipt": _artifact_ref(source_fe4_receipt) if source_fe4_receipt.is_file() else None,
        "source_push_authorization": _artifact_ref(auth_path),
        "frontend_root": str(frontend_root),
        "commit_id": commit_id,
        "remote": remote,
        "remote_url": remote_url,
        "target_branch": target_branch,
        "remote_branch_before_head": remote_before,
        "remote_branch_after_head": remote_after,
        "repo_snapshot": _repo_snapshot(frontend_root, []),
        "push": push_run,
        "git_actions_performed": {"commit": True, "push": not failures, "pr": False, "merge": False, "deploy": False},
        "boundary": _boundary(push_allowed=True),
        "h3_boundary": _h3_boundary(),
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(receipt_path, receipt)
    return receipt


def run_fe6_pr(*, source_fe5_receipt: Path, frontend_root: Path, output_root: Path, github_repo: str, base_branch: str, title: str, body_file: Path, operator_id: str, operator_authorization: str) -> dict[str, Any]:
    frontend_root = frontend_root.resolve()
    output_root = output_root.resolve()
    output_root.mkdir(parents=True, exist_ok=True)
    failures: list[str] = []
    fe5 = _read_json(source_fe5_receipt, failures, "FE-5 push receipt")
    _validate_fe5(fe5, failures)
    branch = _text(fe5.get("target_branch")) if isinstance(fe5, dict) else ""
    commit_id = _text(fe5.get("commit_id")) if isinstance(fe5, dict) else ""
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+|[A-Za-z0-9_.-]+", base_branch):
        failures.append("base_branch must be a simple branch ref")
    if not _text(title):
        failures.append("title must be non-empty")
    if not body_file.is_file():
        failures.append(f"body_file not found: {body_file}")
    if not failures:
        remote_head = _remote_head(frontend_root, _text(fe5.get("remote")) or "origin", branch, failures)
        if remote_head != commit_id:
            failures.append("remote pushed branch no longer matches FE-5 commit_id")

    auth_path = output_root / "beta_fe6_frontend_draft_pr_authorization.json"
    _write_json(auth_path, {
        "schema_version": "beta-fe6-frontend-draft-pr-authorization:v1",
        "created_at": _now(),
        "decision": "beta_fe6_frontend_draft_pr_authorized" if not failures else "blocked",
        "operator_id": operator_id,
        "operator_authorization": operator_authorization,
        "source_fe5_receipt": _artifact_ref(source_fe5_receipt) if source_fe5_receipt.is_file() else None,
        "github_repo": github_repo,
        "base_branch": base_branch,
        "head_branch": branch,
        "commit_id": commit_id,
        "title": title,
        "body_file": _artifact_ref(body_file) if body_file.is_file() else None,
        "authorization_scope": "github_draft_pr_only",
        "boundary": _boundary(pr_allowed=True),
        "h3_boundary": _h3_boundary(),
        "non_claims": list(NON_CLAIMS),
    })

    create_run = None
    pr_url = ""
    if not failures:
        existing = _gh_json(frontend_root, failures, "pr", "list", "--repo", github_repo, "--head", branch, "--state", "open", "--json", "number,url,isDraft,state,headRefName,headRefOid,baseRefName,title")
        if isinstance(existing, list) and existing:
            pr_url = str(existing[0].get("url", ""))
            create_run = {"argv": ["gh", "pr", "list"], "returncode": 0, "stdout": json.dumps(existing), "stderr": "", "reused_existing_pr": True}
        else:
            create_run = _gh(frontend_root, "pr", "create", "--draft", "--repo", github_repo, "--base", base_branch, "--head", branch, "--title", title, "--body-file", str(body_file))
            if create_run["returncode"] != 0:
                failures.append("gh pr create failed")
            pr_url = (create_run.get("stdout") or "").strip().splitlines()[-1] if create_run and create_run.get("stdout") else ""
    pr = {}
    if not failures:
        pr = _gh_json(frontend_root, failures, "pr", "view", pr_url, "--repo", github_repo, "--json", "number,url,isDraft,state,headRefName,headRefOid,baseRefName,title") or {}
        if not isinstance(pr, dict):
            failures.append("gh pr view must return an object")
            pr = {}
        if pr.get("isDraft") is not True:
            failures.append("FE-6 PR must be draft")
        if pr.get("headRefName") != branch:
            failures.append("FE-6 PR headRefName must match FE-5 branch")
        if pr.get("headRefOid") != commit_id:
            failures.append("FE-6 PR headRefOid must match FE-5 commit_id")
        if pr.get("baseRefName") != base_branch:
            failures.append("FE-6 PR baseRefName must match requested base branch")

    receipt = {
        "schema_version": FE6_RECEIPT_SCHEMA,
        "checked_at": _now(),
        "passed": not failures,
        "decision": "beta_fe6_frontend_draft_pr_receipt_passed" if not failures else "blocked",
        "failure_reasons": failures,
        "source_fe5_receipt": _artifact_ref(source_fe5_receipt) if source_fe5_receipt.is_file() else None,
        "source_draft_pr_authorization": _artifact_ref(auth_path),
        "frontend_root": str(frontend_root),
        "github_repo": github_repo,
        "base_branch": base_branch,
        "head_branch": branch,
        "commit_id": commit_id,
        "draft_pr": pr,
        "create": create_run,
        "git_actions_performed": {"commit": True, "push": True, "pr": not failures, "merge": False, "deploy": False},
        "boundary": _boundary(pr_allowed=True),
        "h3_boundary": _h3_boundary(),
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(output_root / "beta_fe6_frontend_draft_pr_receipt.json", receipt)
    return receipt


def run_fe7_review(*, source_fe6_receipt: Path, frontend_root: Path, output_root: Path, external_env_file: Path, operator_decision: str, operator_id: str, operator_authorization: str, max_diff_chars: int) -> dict[str, Any]:
    frontend_root = frontend_root.resolve()
    output_root = output_root.resolve()
    output_root.mkdir(parents=True, exist_ok=True)
    failures: list[str] = []
    fe6 = _read_json(source_fe6_receipt, failures, "FE-6 draft PR receipt")
    _validate_fe6(fe6, failures)
    pr = fe6.get("draft_pr") if isinstance(fe6, dict) else {}
    github_repo = _text(fe6.get("github_repo")) if isinstance(fe6, dict) else ""
    pr_number = str(pr.get("number", "")) if isinstance(pr, dict) else ""
    diff = ""
    diff_run = None
    if not failures:
        diff_run = _gh(frontend_root, "pr", "diff", pr_number, "--repo", github_repo)
        if diff_run["returncode"] != 0:
            failures.append("gh pr diff failed")
        diff = diff_run.get("stdout", "")[:max_diff_chars]
    local_review = _local_review(diff)
    _write_json(output_root / "beta_fe7_local_agent_review.json", local_review)
    external_review = _external_review(external_env_file, pr, diff, failures)
    _write_json(output_root / "beta_fe7_external_agent_review.json", external_review)
    if local_review.get("verdict") != "approved":
        failures.append("local Agent review must approve")
    if external_review.get("verdict") != "approved":
        failures.append("external Agent review must approve")
    if operator_decision != "ready_to_merge":
        failures.append("operator_decision must be ready_to_merge")

    receipt = {
        "schema_version": FE7_RECEIPT_SCHEMA,
        "checked_at": _now(),
        "passed": not failures,
        "decision": "beta_fe7_frontend_review_reconciliation_passed" if not failures else "blocked",
        "failure_reasons": failures,
        "source_fe6_receipt": _artifact_ref(source_fe6_receipt) if source_fe6_receipt.is_file() else None,
        "frontend_root": str(frontend_root),
        "github_repo": github_repo,
        "pr": pr,
        "commit_id": fe6.get("commit_id") if isinstance(fe6, dict) else None,
        "local_agent_review": _artifact_ref(output_root / "beta_fe7_local_agent_review.json"),
        "external_agent_review": _artifact_ref(output_root / "beta_fe7_external_agent_review.json"),
        "operator_id": operator_id,
        "operator_authorization": operator_authorization,
        "operator_decision": operator_decision,
        "review_reconciliation": {
            "local_verdict": local_review.get("verdict"),
            "external_verdict": external_review.get("verdict"),
            "merge_ready": not failures,
        },
        "diff": {"source": "gh pr diff", "captured_chars": len(diff), "truncated_at": max_diff_chars},
        "diff_command": diff_run,
        "git_actions_performed": {"commit": True, "push": True, "pr": True, "merge": False, "deploy": False},
        "boundary": _boundary(review_allowed=True),
        "h3_boundary": _h3_boundary(),
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(output_root / "beta_fe7_frontend_review_reconciliation.json", receipt)
    return receipt


def run_fe8_merge(*, source_fe7_reconciliation: Path, frontend_root: Path, output_root: Path, merge_method: str, delete_branch: bool, operator_id: str, operator_authorization: str) -> dict[str, Any]:
    frontend_root = frontend_root.resolve()
    output_root = output_root.resolve()
    output_root.mkdir(parents=True, exist_ok=True)
    failures: list[str] = []
    fe7 = _read_json(source_fe7_reconciliation, failures, "FE-7 review reconciliation")
    _validate_fe7(fe7, failures)
    pr = fe7.get("pr") if isinstance(fe7, dict) else {}
    github_repo = _text(fe7.get("github_repo")) if isinstance(fe7, dict) else ""
    pr_number = str(pr.get("number", "")) if isinstance(pr, dict) else ""
    base_branch = _text(pr.get("baseRefName")) if isinstance(pr, dict) else ""
    remote_before = _remote_head(frontend_root, "origin", base_branch, failures) if base_branch else None
    ready_run = None
    merge_run = None
    if not failures:
        current = _gh_json(frontend_root, failures, "pr", "view", pr_number, "--repo", github_repo, "--json", "isDraft,state,number,url") or {}
        if isinstance(current, dict) and current.get("isDraft") is True:
            ready_run = _gh(frontend_root, "pr", "ready", pr_number, "--repo", github_repo)
            if ready_run["returncode"] != 0:
                failures.append("gh pr ready failed")
        argv = ["pr", "merge", pr_number, "--repo", github_repo, f"--{merge_method}"]
        if delete_branch:
            argv.append("--delete-branch")
        merge_run = _gh(frontend_root, *argv)
        if merge_run["returncode"] != 0:
            failures.append("gh pr merge failed")
    merged = {}
    remote_after = remote_before
    if not failures:
        merged = _gh_json(frontend_root, failures, "pr", "view", pr_number, "--repo", github_repo, "--json", "number,url,state,mergedAt,mergeCommit,headRefName,baseRefName") or {}
        if not isinstance(merged, dict):
            failures.append("gh pr view after merge must return object")
            merged = {}
        if merged.get("state") != "MERGED":
            failures.append("PR state must be MERGED after FE-8")
        remote_after = _remote_head(frontend_root, "origin", base_branch, failures) if base_branch else None
        if remote_after == remote_before:
            failures.append("base branch remote head must advance after merge")
    receipt = {
        "schema_version": FE8_RECEIPT_SCHEMA,
        "checked_at": _now(),
        "passed": not failures,
        "decision": "beta_fe8_frontend_merge_receipt_passed" if not failures else "blocked",
        "failure_reasons": failures,
        "source_fe7_reconciliation": _artifact_ref(source_fe7_reconciliation) if source_fe7_reconciliation.is_file() else None,
        "frontend_root": str(frontend_root),
        "github_repo": github_repo,
        "pr": merged or pr,
        "merge_method": merge_method,
        "base_branch": base_branch,
        "base_branch_before_head": remote_before,
        "base_branch_after_head": remote_after,
        "ready": ready_run,
        "merge": merge_run,
        "operator_id": operator_id,
        "operator_authorization": operator_authorization,
        "git_actions_performed": {"commit": True, "push": True, "pr": True, "merge": not failures, "deploy": False},
        "boundary": _boundary(merge_allowed=True),
        "h3_boundary": _h3_boundary(),
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(output_root / "beta_fe8_frontend_merge_receipt.json", receipt)
    return receipt


def _validate_fe4(value: Any, failures: list[str]) -> None:
    if not isinstance(value, dict):
        failures.append("FE-4 receipt must be an object")
        return
    if value.get("schema_version") != FE4_RECEIPT_SCHEMA:
        failures.append(f"FE-4 schema_version must be {FE4_RECEIPT_SCHEMA}")
    if value.get("passed") is not True or value.get("decision") != "beta_fe4_frontend_commit_receipt_passed":
        failures.append("FE-4 receipt must be passed")
    boundary = value.get("boundary") if isinstance(value.get("boundary"), dict) else {}
    if boundary.get("commit_allowed") is not True:
        failures.append("FE-4 boundary.commit_allowed must be true")
    for key in ("push_allowed", "pr_allowed", "merge_allowed", "deploy_allowed", "production_runtime_execution_allowed", "production_receipt_write_allowed"):
        if boundary.get(key) is not False:
            failures.append(f"FE-4 boundary.{key} must be false")
    _validate_h3(value, "FE-4", failures)


def _validate_fe5(value: Any, failures: list[str]) -> None:
    if not isinstance(value, dict) or value.get("schema_version") != FE5_RECEIPT_SCHEMA or value.get("passed") is not True:
        failures.append("FE-5 receipt must be passed")
        return
    if value.get("remote_branch_after_head") != value.get("commit_id"):
        failures.append("FE-5 remote branch must be bound to commit_id")
    _validate_h3(value, "FE-5", failures)


def _validate_fe6(value: Any, failures: list[str]) -> None:
    if not isinstance(value, dict) or value.get("schema_version") != FE6_RECEIPT_SCHEMA or value.get("passed") is not True:
        failures.append("FE-6 receipt must be passed")
        return
    pr = value.get("draft_pr") if isinstance(value.get("draft_pr"), dict) else {}
    if pr.get("isDraft") is not True or pr.get("state") != "OPEN":
        failures.append("FE-6 PR must be open draft")
    if pr.get("headRefOid") != value.get("commit_id"):
        failures.append("FE-6 PR head must match commit_id")
    _validate_h3(value, "FE-6", failures)


def _validate_fe7(value: Any, failures: list[str]) -> None:
    if not isinstance(value, dict) or value.get("schema_version") != FE7_RECEIPT_SCHEMA or value.get("passed") is not True:
        failures.append("FE-7 reconciliation must be passed")
        return
    if value.get("operator_decision") != "ready_to_merge":
        failures.append("FE-7 operator_decision must be ready_to_merge")
    rec = value.get("review_reconciliation") if isinstance(value.get("review_reconciliation"), dict) else {}
    if rec.get("local_verdict") != "approved" or rec.get("external_verdict") != "approved" or rec.get("merge_ready") is not True:
        failures.append("FE-7 reconciliation must have approved local/external verdicts")
    _validate_h3(value, "FE-7", failures)


def _local_review(diff: str) -> dict[str, Any]:
    findings: list[str] = []
    slice_profiles = {
        "task_read_adapter": ("TaskReadAdapter", "taskReadModel", "TaskPoolPanel"),
        "task_pool_api_adapter": ("taskPoolApi", "createTaskPoolApi", "PoolTaskPostRequest", "apiClient"),
    }
    profile_matches = {
        name: all(token in diff for token in tokens)
        for name, tokens in slice_profiles.items()
    }
    matched_profile = next((name for name, matched in profile_matches.items() if matched), "")
    if not matched_profile:
        profile_hints = [
            f"{name}: missing {', '.join(token for token in tokens if token not in diff)}"
            for name, tokens in slice_profiles.items()
        ]
        findings.append("diff does not match a known FE slice profile; " + "; ".join(profile_hints))
    forbidden = ("production_runtime_execution_allowed\": true", "production_receipt_write_allowed\": true", "deploy_allowed\": true")
    for token in forbidden:
        if token in diff:
            findings.append(f"forbidden production/deploy boundary token present: {token}")
    return {
        "schema_version": "beta-fe7-local-agent-review:v1",
        "checked_at": _now(),
        "reviewer": "local-static-boundary-reviewer",
        "verdict": "approved" if not findings else "changes_requested",
        "risk_level": "low" if not findings else "medium",
        "matched_profile": matched_profile,
        "known_profiles": sorted(slice_profiles),
        "findings": findings,
        "summary": "Local reviewer checks known FE slice profile and no deploy/production boundary expansion.",
    }


def _external_review(env_file: Path, pr: dict[str, Any], diff: str, failures: list[str]) -> dict[str, Any]:
    env = _read_env(env_file, failures)
    provider = _text(env.get("BETA6_EXTERNAL_AGENT_PROVIDER")) or "openai_compatible"
    base_url = _text(env.get("BETA6_EXTERNAL_AGENT_API_BASE_URL")).rstrip("/")
    model = _text(env.get("BETA6_EXTERNAL_AGENT_MODEL"))
    api_key = _text(env.get("BETA6_EXTERNAL_AGENT_API_KEY"))
    if not base_url or not model or not api_key:
        failures.append("external env must include API base URL, model, and API key")
        return {"schema_version": "beta-fe7-external-agent-review:v1", "passed": False, "verdict": "blocked", "failure_reasons": ["missing external API config"]}
    prompt = (
        "Review this CivitasOS frontend PR diff. Return only JSON with keys: "
        "verdict ('approved' or 'changes_requested'), risk_level ('low','medium','high'), findings (array), summary (string). "
        "Approve only if the change is limited to task read adapter/UI integration and does not expand deploy/production authority.\n\n"
        f"PR: {json.dumps(pr, ensure_ascii=False)}\n\nDIFF:\n{diff}"
    )
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": "You are a strict external code-review Agent for CivitasOS controlled pilot gates."},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0,
        "max_tokens": 900,
    }
    request = urllib.request.Request(
        f"{base_url}/chat/completions",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        method="POST",
    )
    raw_text = ""
    api_failure = ""
    try:
        with urllib.request.urlopen(request, timeout=90) as response:
            api_payload = json.loads(response.read().decode("utf-8"))
        raw_text = str(api_payload.get("choices", [{}])[0].get("message", {}).get("content", ""))
    except Exception as exc:  # fail closed but keep evidence
        api_failure = str(exc)
        failures.append(f"external Agent API call failed: {exc}")
    parsed = _parse_review_json(raw_text)
    if not parsed and raw_text:
        parsed = {
            "verdict": "approved" if "approved" in raw_text.lower() and "changes_requested" not in raw_text.lower() else "changes_requested",
            "risk_level": "medium",
            "findings": ["external reviewer returned non-JSON content"],
            "summary": raw_text[:1000],
        }
    verdict = _text(parsed.get("verdict")) if parsed else "blocked"
    return {
        "schema_version": "beta-fe7-external-agent-review:v1",
        "checked_at": _now(),
        "provider": provider,
        "model": model,
        "api_base_url": base_url,
        "api_key_recorded": False,
        "passed": not api_failure and verdict == "approved",
        "verdict": verdict,
        "risk_level": parsed.get("risk_level") if parsed else "unknown",
        "findings": parsed.get("findings") if parsed else [api_failure or "external reviewer returned no parseable verdict"],
        "summary": parsed.get("summary") if parsed else "blocked",
        "raw_response_sha256": hashlib.sha256(raw_text.encode("utf-8")).hexdigest() if raw_text else None,
        "raw_response_excerpt": raw_text[:1000],
        "failure_reasons": [api_failure] if api_failure else [],
    }


def _parse_review_json(raw: str) -> dict[str, Any]:
    text = raw.strip()
    if not text:
        return {}
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", text, re.S)
        if not match:
            return {}
        try:
            value = json.loads(match.group(0))
        except json.JSONDecodeError:
            return {}
    return value if isinstance(value, dict) else {}


def _read_env(path: Path, failures: list[str]) -> dict[str, str]:
    if not path.is_file():
        failures.append(f"external env file not found: {path}")
        return {}
    env: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        env[key.strip()] = value.strip().strip('"').strip("'")
    return env


def _boundary(*, push_allowed: bool = False, pr_allowed: bool = False, review_allowed: bool = False, merge_allowed: bool = False) -> dict[str, bool]:
    return {
        "frontend_code_modified": True,
        "apply_allowed": True,
        "commit_allowed": True,
        "push_allowed": push_allowed,
        "pr_allowed": pr_allowed,
        "review_allowed": review_allowed,
        "merge_allowed": merge_allowed,
        "deploy_allowed": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
    }


def _validate_h3(value: dict[str, Any], label: str, failures: list[str]) -> None:
    h3 = value.get("h3_boundary") if isinstance(value.get("h3_boundary"), dict) else {}
    if h3.get("h3_remains_blocked") is not True or h3.get("h3_production_readiness_claimed") is not False:
        failures.append(f"{label} must keep H.3 blocked")


def _h3_boundary() -> dict[str, bool]:
    return {"h3_remains_blocked": True, "h3_production_readiness_claimed": False}


def _validate_branch(value: str, failures: list[str]) -> None:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_./-]{1,120}", value or ""):
        failures.append("target_branch must be a simple git branch ref")
    if ".." in value or value.endswith("/") or value.endswith(".lock"):
        failures.append("target_branch contains invalid git ref sequence")


def _repo_snapshot(repo: Path, failures: list[str]) -> dict[str, Any]:
    return {
        "head_commit": _git_text(repo, failures, "rev-parse", "HEAD").strip(),
        "head_short": _git_text(repo, failures, "rev-parse", "--short", "HEAD").strip(),
        "branch": _git_text(repo, failures, "branch", "--show-current").strip(),
        "status_short": _git_text(repo, failures, "status", "--short").splitlines(),
    }


def _remote_head(repo: Path, remote: str, branch: str, failures: list[str]) -> str | None:
    result = _git(repo, "ls-remote", remote, f"refs/heads/{branch}")
    if result["returncode"] != 0:
        failures.append(f"git ls-remote failed for {remote}/{branch}")
        return None
    line = (result.get("stdout") or "").strip().splitlines()
    if not line:
        return None
    return line[0].split()[0]


def _git(repo: Path, *args: str) -> dict[str, Any]:
    result = subprocess.run(["git", *args], cwd=repo, text=True, capture_output=True, check=False)
    return {"argv": ["git", *args], "returncode": result.returncode, "stdout": result.stdout, "stderr": result.stderr}


def _git_text(repo: Path, failures: list[str], *args: str) -> str:
    result = _git(repo, *args)
    if result["returncode"] != 0:
        failures.append(f"git {' '.join(args)} failed: {result['stderr']}")
    return str(result.get("stdout", ""))


def _gh(repo: Path, *args: str) -> dict[str, Any]:
    result = subprocess.run(["gh", *args], cwd=repo, text=True, capture_output=True, check=False)
    return {"argv": ["gh", *args], "returncode": result.returncode, "stdout": result.stdout, "stderr": result.stderr}


def _gh_json(repo: Path, failures: list[str], *args: str) -> Any:
    result = _gh(repo, *args)
    if result["returncode"] != 0:
        failures.append(f"gh {' '.join(args)} failed: {result['stderr']}")
        return None
    try:
        return json.loads(result.get("stdout") or "null")
    except json.JSONDecodeError as exc:
        failures.append(f"gh {' '.join(args)} returned invalid JSON: {exc}")
        return None


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


def _artifact_ref(path: Path) -> dict[str, str]:
    return {"path": str(path.resolve()), "sha256": _sha256(path)}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _text(value: Any) -> str:
    return str(value or "").strip()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


if __name__ == "__main__":
    raise SystemExit(main())
