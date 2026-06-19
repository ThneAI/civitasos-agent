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
import shlex
import subprocess
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from civitasos_contracts.artifacts import build_artifact_envelope
    from civitasos_contracts.provenance import (
        build_git_release_provenance,
        build_governance_evidence,
    )
except ModuleNotFoundError:
    from scripts.civitasos_contracts.artifacts import build_artifact_envelope
    from scripts.civitasos_contracts.provenance import (
        build_git_release_provenance,
        build_governance_evidence,
    )

try:
    from beta_fe_ollama_native_reviewer import OllamaNativeReviewer
except ModuleNotFoundError:
    from scripts.beta_fe_ollama_native_reviewer import OllamaNativeReviewer

try:
    from beta_evidence import (
        artifact_ref as _evidence_artifact_ref,
        read_json_any_or_empty,
        require_schema,
        sha256_file,
        write_json,
    )
except ModuleNotFoundError:
    from scripts.beta_evidence import (
        artifact_ref as _evidence_artifact_ref,
        read_json_any_or_empty,
        require_schema,
        sha256_file,
        write_json,
    )

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
    fe7.add_argument(
        "--additional-reviewer-spec",
        action="append",
        default=[],
        help="reviewer_id=openai-env:/path, reviewer_id=ollama-native:model, or reviewer_id=command:argv",
    )

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
            additional_reviewer_specs=args.additional_reviewer_spec,
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
    source_fe4_ref = _artifact_ref(source_fe4_receipt) if source_fe4_receipt.is_file() else None
    authorization = {
        "schema_version": "beta-fe5-frontend-push-authorization:v1",
        "artifact_envelope": build_artifact_envelope(
            artifact_kind="approval",
            plane="governance",
            schema_version="beta-fe5-frontend-push-authorization:v1",
            artifact_id=f"fe5-push-approval:{commit_id or 'unknown'}",
            subject_id=f"git-branch:{target_branch}",
            producer="beta_fe5_8_frontend_release_gates",
            source_refs=[source_fe4_ref] if source_fe4_ref else [],
            scope="remote_branch_push_only",
        ),
        "created_at": _now(),
        "decision": "beta_fe5_frontend_push_authorized" if not failures else "blocked",
        "operator_id": operator_id,
        "operator_authorization": operator_authorization,
        "source_fe4_receipt": source_fe4_ref,
        "frontend_root": str(frontend_root),
        "commit_id": commit_id,
        "remote": remote,
        "remote_url": remote_url,
        "target_branch": target_branch,
        "remote_branch_before_head": remote_before,
        "authorization_scope": "remote_branch_push_only",
        "governance_evidence": build_governance_evidence(
            {"source_commit_receipt": source_fe4_ref},
            assertions={
                "operator_id": operator_id,
                "target_branch": target_branch,
                "authorization_scope": "remote_branch_push_only",
            },
        ),
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
    authorization_ref = _artifact_ref(auth_path)
    receipt = {
        "schema_version": FE5_RECEIPT_SCHEMA,
        "artifact_envelope": build_artifact_envelope(
            artifact_kind="receipt",
            plane="release",
            schema_version=FE5_RECEIPT_SCHEMA,
            artifact_id=f"fe5-push:{commit_id or 'unknown'}",
            subject_id=f"git-branch:{target_branch}",
            producer="beta_fe5_8_frontend_release_gates",
            source_refs=[
                ref for ref in (source_fe4_ref, authorization_ref) if ref
            ],
            scope="remote_branch_push",
        ),
        "checked_at": _now(),
        "passed": not failures,
        "decision": "beta_fe5_frontend_push_receipt_passed" if not failures else "blocked",
        "failure_reasons": failures,
        "source_fe4_receipt": source_fe4_ref,
        "source_push_authorization": authorization_ref,
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
        "release_provenance": build_git_release_provenance(
            {
                "source_commit_receipt": source_fe4_ref,
                "push_authorization": authorization_ref,
            },
            actions_observed={"commit": True, "push": not failures},
            actions_performed_by_current_step={"push": not failures},
        ),
        "boundary": _boundary(push_allowed=True),
        "h3_boundary": _h3_boundary(),
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(receipt_path, receipt)
    return receipt


def run_fe6_pr(*, source_fe5_receipt: Path, frontend_root: Path, output_root: Path, github_repo: str, base_branch: str, title: str, body_file: Path, operator_id: str, operator_authorization: str) -> dict[str, Any]:
    frontend_root = frontend_root.resolve()
    output_root = output_root.resolve()
    body_file = body_file.resolve()
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
    source_fe5_ref = _artifact_ref(source_fe5_receipt) if source_fe5_receipt.is_file() else None
    _write_json(auth_path, {
        "schema_version": "beta-fe6-frontend-draft-pr-authorization:v1",
        "artifact_envelope": build_artifact_envelope(
            artifact_kind="approval",
            plane="governance",
            schema_version="beta-fe6-frontend-draft-pr-authorization:v1",
            artifact_id=f"fe6-pr-approval:{commit_id or 'unknown'}",
            subject_id=f"github-pr:{github_repo}:{branch or 'unknown'}",
            producer="beta_fe5_8_frontend_release_gates",
            source_refs=[source_fe5_ref] if source_fe5_ref else [],
            scope="github_draft_pr_only",
        ),
        "created_at": _now(),
        "decision": "beta_fe6_frontend_draft_pr_authorized" if not failures else "blocked",
        "operator_id": operator_id,
        "operator_authorization": operator_authorization,
        "source_fe5_receipt": source_fe5_ref,
        "github_repo": github_repo,
        "base_branch": base_branch,
        "head_branch": branch,
        "commit_id": commit_id,
        "title": title,
        "body_file": _artifact_ref(body_file) if body_file.is_file() else None,
        "authorization_scope": "github_draft_pr_only",
        "governance_evidence": build_governance_evidence(
            {"source_push_receipt": source_fe5_ref},
            assertions={
                "operator_id": operator_id,
                "github_repo": github_repo,
                "base_branch": base_branch,
                "authorization_scope": "github_draft_pr_only",
            },
        ),
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

    authorization_ref = _artifact_ref(auth_path)
    receipt = {
        "schema_version": FE6_RECEIPT_SCHEMA,
        "artifact_envelope": build_artifact_envelope(
            artifact_kind="receipt",
            plane="release",
            schema_version=FE6_RECEIPT_SCHEMA,
            artifact_id=f"fe6-pr:{github_repo}:{pr.get('number') or branch or 'unknown'}",
            subject_id=f"github-pr:{github_repo}:{pr.get('number') or branch or 'unknown'}",
            producer="beta_fe5_8_frontend_release_gates",
            source_refs=[
                ref for ref in (source_fe5_ref, authorization_ref) if ref
            ],
            scope="github_draft_pr",
        ),
        "checked_at": _now(),
        "passed": not failures,
        "decision": "beta_fe6_frontend_draft_pr_receipt_passed" if not failures else "blocked",
        "failure_reasons": failures,
        "source_fe5_receipt": source_fe5_ref,
        "source_draft_pr_authorization": authorization_ref,
        "frontend_root": str(frontend_root),
        "github_repo": github_repo,
        "base_branch": base_branch,
        "head_branch": branch,
        "commit_id": commit_id,
        "draft_pr": pr,
        "create": create_run,
        "git_actions_performed": {"commit": True, "push": True, "pr": not failures, "merge": False, "deploy": False},
        "release_provenance": build_git_release_provenance(
            {
                "source_push_receipt": source_fe5_ref,
                "draft_pr_authorization": authorization_ref,
            },
            actions_observed={"commit": True, "push": True, "pr": not failures},
            actions_performed_by_current_step={"pr": not failures},
        ),
        "boundary": _boundary(pr_allowed=True),
        "h3_boundary": _h3_boundary(),
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(output_root / "beta_fe6_frontend_draft_pr_receipt.json", receipt)
    return receipt


def run_fe7_review(*, source_fe6_receipt: Path, frontend_root: Path, output_root: Path, external_env_file: Path, operator_decision: str, operator_id: str, operator_authorization: str, max_diff_chars: int, additional_reviewer_specs: list[str] | None = None) -> dict[str, Any]:
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
    additional_reviews = _additional_agent_reviews(
        specs=additional_reviewer_specs or [],
        pr=pr,
        diff=diff,
        output_root=output_root,
        failures=failures,
    )
    if local_review.get("verdict") != "approved":
        failures.append("local Agent review must approve")
    if external_review.get("verdict") != "approved":
        failures.append("external Agent review must approve")
    for review in additional_reviews:
        if review.get("verdict") != "approved":
            failures.append(f"additional Agent review must approve: {review.get('reviewer_id')}")
    if operator_decision != "ready_to_merge":
        failures.append("operator_decision must be ready_to_merge")
    additional_verdicts = {
        str(review.get("reviewer_id")): review.get("verdict")
        for review in additional_reviews
    }

    source_fe6_ref = _artifact_ref(source_fe6_receipt) if source_fe6_receipt.is_file() else None
    local_review_ref = _artifact_ref(output_root / "beta_fe7_local_agent_review.json")
    external_review_ref = _artifact_ref(output_root / "beta_fe7_external_agent_review.json")
    additional_review_refs = [
        _artifact_ref(output_root / f"beta_fe7_{_safe_file_token(str(review.get('reviewer_id')))}_agent_review.json")
        for review in additional_reviews
    ]
    receipt = {
        "schema_version": FE7_RECEIPT_SCHEMA,
        "artifact_envelope": build_artifact_envelope(
            artifact_kind="review",
            plane="governance",
            schema_version=FE7_RECEIPT_SCHEMA,
            artifact_id=f"fe7-review:{github_repo}:{pr_number or 'unknown'}",
            subject_id=f"github-pr:{github_repo}:{pr_number or 'unknown'}",
            producer="beta_fe5_8_frontend_release_gates",
            source_refs=[
                ref
                for ref in (
                    source_fe6_ref,
                    local_review_ref,
                    external_review_ref,
                    *additional_review_refs,
                )
                if ref
            ],
            scope="multi_agent_release_review_reconciliation",
        ),
        "checked_at": _now(),
        "passed": not failures,
        "decision": "beta_fe7_frontend_review_reconciliation_passed" if not failures else "blocked",
        "failure_reasons": failures,
        "source_fe6_receipt": source_fe6_ref,
        "frontend_root": str(frontend_root),
        "github_repo": github_repo,
        "pr": pr,
        "commit_id": fe6.get("commit_id") if isinstance(fe6, dict) else None,
        "local_agent_review": local_review_ref,
        "external_agent_review": external_review_ref,
        "additional_agent_reviews": additional_review_refs,
        "operator_id": operator_id,
        "operator_authorization": operator_authorization,
        "operator_decision": operator_decision,
        "review_reconciliation": {
            "local_verdict": local_review.get("verdict"),
            "external_verdict": external_review.get("verdict"),
            "additional_verdicts": additional_verdicts,
            "additional_review_count": len(additional_reviews),
            "all_agent_verdicts": {
                "local-static-boundary-reviewer": local_review.get("verdict"),
                "external-api-reviewer": external_review.get("verdict"),
                **additional_verdicts,
            },
            "merge_ready": not failures,
        },
        "governance_evidence": build_governance_evidence(
            {
                "source_draft_pr_receipt": source_fe6_ref,
                "local_agent_review": local_review_ref,
                "external_agent_review": external_review_ref,
                **{
                    f"additional_agent_review_{index}": ref
                    for index, ref in enumerate(additional_review_refs, start=1)
                },
            },
            assertions={
                "operator_id": operator_id,
                "operator_decision": operator_decision,
                "merge_ready": not failures,
            },
        ),
        "diff": {"source": "gh pr diff", "captured_chars": len(diff), "truncated_at": max_diff_chars},
        "diff_command": diff_run,
        "git_actions_performed": {"commit": True, "push": True, "pr": True, "merge": False, "deploy": False},
        "boundary": _boundary(review_allowed=True),
        "h3_boundary": _h3_boundary(),
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(output_root / "beta_fe7_frontend_review_reconciliation.json", receipt)
    return receipt


def _additional_agent_reviews(*, specs: list[str], pr: dict[str, Any], diff: str, output_root: Path, failures: list[str]) -> list[dict[str, Any]]:
    reviews: list[dict[str, Any]] = []
    for spec in specs:
        try:
            reviewer_id, mode, arg = _parse_reviewer_spec(spec)
            review = _run_direct_reviewer(reviewer_id=reviewer_id, mode=mode, arg=arg, pr=pr, diff=diff)
        except Exception as exc:
            reviewer_id = spec.partition("=")[0] or "unknown-reviewer"
            failures.append(f"additional Agent review failed: {reviewer_id}: {exc}")
            review = {
                "schema_version": "beta-fe7-direct-agent-review:v1",
                "checked_at": _now(),
                "reviewer_id": reviewer_id,
                "runner_kind": "unknown",
                "passed": False,
                "verdict": "blocked",
                "risk_level": "unknown",
                "findings": [str(exc)],
                "summary": "additional reviewer failed",
                "api_key_recorded": False,
                "raw_response_sha256": None,
                "raw_response_excerpt": "",
            }
        path = output_root / f"beta_fe7_{_safe_file_token(str(review.get('reviewer_id')))}_agent_review.json"
        _write_json(path, review)
        reviews.append(review)
    return reviews


def _parse_reviewer_spec(value: str) -> tuple[str, str, str]:
    reviewer_id, sep, spec = value.partition("=")
    if not sep or not reviewer_id.strip() or not spec.strip():
        raise ValueError(
            "reviewer spec must be reviewer_id=openai-env:/path, "
            "reviewer_id=ollama-native:model, or reviewer_id=command:argv"
        )
    mode, mode_sep, arg = spec.partition(":")
    if not mode_sep or not arg.strip():
        raise ValueError(f"reviewer spec missing mode argument: {value}")
    if mode not in {"openai-env", "ollama-native", "command"}:
        raise ValueError(f"unsupported reviewer spec mode {mode!r}")
    return reviewer_id.strip(), mode, arg.strip()


def _run_direct_reviewer(*, reviewer_id: str, mode: str, arg: str, pr: dict[str, Any], diff: str) -> dict[str, Any]:
    prompt = (
        "Review this CivitasOS frontend PR diff. Return only JSON with keys: "
        "verdict ('approved' or 'changes_requested'), risk_level ('low','medium','high'), findings (array), summary (string). "
        "Approve only if the change is limited to a bounded frontend adapter/presentation/app-shell helper slice and does not expand deploy/production authority.\n\n"
        f"Reviewer: {reviewer_id}\nPR: {json.dumps(pr, ensure_ascii=False)}\n\nDIFF:\n{diff}"
    )
    if mode == "openai-env":
        raw_text, raw_report = _run_openai_reviewer(reviewer_id, Path(arg), prompt)
        runner_kind = "openai_compatible"
    elif mode == "ollama-native":
        result = OllamaNativeReviewer(model=arg).review_release(prompt)
        raw_text = json.dumps(result.payload, ensure_ascii=False, sort_keys=True)
        raw_report = result.report
        runner_kind = "ollama_native_reviewer"
    else:
        raw_text, raw_report = _run_command_reviewer(reviewer_id, arg, prompt)
        runner_kind = "command"
    parsed = _parse_review_json(raw_text)
    if not parsed and raw_text:
        parsed = {
            "verdict": "approved" if "approved" in raw_text.lower() and "changes_requested" not in raw_text.lower() else "changes_requested",
            "risk_level": "medium",
            "findings": ["direct reviewer returned non-JSON content"],
            "summary": raw_text[:1000],
        }
    verdict = _text(parsed.get("verdict")) if parsed else "blocked"
    return {
        "schema_version": "beta-fe7-direct-agent-review:v1",
        "checked_at": _now(),
        "reviewer_id": reviewer_id,
        "runner_kind": runner_kind,
        "passed": verdict == "approved",
        "verdict": verdict,
        "risk_level": parsed.get("risk_level") if parsed else "unknown",
        "findings": parsed.get("findings") if parsed else ["direct reviewer returned no parseable verdict"],
        "summary": parsed.get("summary") if parsed else "blocked",
        "raw_report": raw_report,
        "api_key_recorded": False,
        "raw_response_sha256": hashlib.sha256(raw_text.encode("utf-8")).hexdigest() if raw_text else None,
        "raw_response_excerpt": raw_text[:1000],
    }


def _run_openai_reviewer(reviewer_id: str, env_file: Path, prompt: str) -> tuple[str, dict[str, Any]]:
    env = _read_env(env_file, [])
    base_url = (_text(env.get("BETA6_EXTERNAL_AGENT_API_BASE_URL")) or _text(env.get("LLM_BASE_URL"))).rstrip("/")
    model = _normalize_model(_text(env.get("BETA6_EXTERNAL_AGENT_MODEL")) or _text(env.get("AGENT_LLM")))
    api_key = _text(env.get("BETA6_EXTERNAL_AGENT_API_KEY")) or _text(env.get("LLM_API_KEY"))
    if not base_url or not model:
        raise ValueError(f"reviewer env missing base URL or model: {env_file}")
    endpoint = base_url.rstrip("/")
    if not endpoint.endswith("/chat/completions"):
        endpoint = f"{endpoint}/chat/completions"
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": "You are a strict CivitasOS release review Agent."},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0,
        "max_tokens": 900,
    }
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    request = urllib.request.Request(endpoint, data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            status = response.status
            body = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"{reviewer_id} HTTP {exc.code}: {detail}") from exc
    raw_text = str(body.get("choices", [{}])[0].get("message", {}).get("content", ""))
    return raw_text, {
        "status": status,
        "model": model,
        "env_file": str(env_file.resolve()),
        "api_key_recorded": False,
        "content_chars": len(raw_text),
    }


def _run_command_reviewer(reviewer_id: str, command: str, prompt: str) -> tuple[str, dict[str, Any]]:
    env = os.environ.copy()
    env.setdefault("CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS", "0")
    argv = [prompt if part == "{prompt}" else part for part in shlex.split(command)]
    stdin = None if "{prompt}" in command else prompt
    result = subprocess.run(argv, input=stdin, text=True, capture_output=True, check=False, timeout=180, env=env)
    if result.returncode != 0:
        raise RuntimeError(f"{reviewer_id} command exited {result.returncode}; stderr={result.stderr[:500]}")
    raw_text = result.stdout.strip()
    if not raw_text:
        raise RuntimeError(f"{reviewer_id} command returned empty stdout; stderr={result.stderr[:500]}")
    return raw_text, {
        "command": argv,
        "returncode": result.returncode,
        "stderr_excerpt": result.stderr[:1000],
        "content_chars": len(raw_text),
    }


def run_fe8_merge(*, source_fe7_reconciliation: Path, frontend_root: Path, output_root: Path, merge_method: str, delete_branch: bool, operator_id: str, operator_authorization: str) -> dict[str, Any]:
    frontend_root = frontend_root.resolve()
    output_root = output_root.resolve()
    output_root.mkdir(parents=True, exist_ok=True)
    failures: list[str] = []
    fe7 = _read_json(source_fe7_reconciliation, failures, "FE-7 review reconciliation")
    _validate_fe7(fe7, failures)
    _validate_operator_authorization(operator_id, operator_authorization, failures)
    pr = fe7.get("pr") if isinstance(fe7, dict) else {}
    github_repo = _text(fe7.get("github_repo")) if isinstance(fe7, dict) else ""
    pr_number = str(pr.get("number", "")) if isinstance(pr, dict) else ""
    base_branch = _text(pr.get("baseRefName")) if isinstance(pr, dict) else ""
    if not github_repo:
        failures.append("FE-7 github_repo is required")
    if not pr_number or not base_branch:
        failures.append("FE-7 PR number and base branch are required")
    remote_before = _remote_head(frontend_root, "origin", base_branch, failures) if base_branch else None
    ready_run = None
    merge_run = None
    live_before: dict[str, Any] = {}
    live_ready: dict[str, Any] = {}
    merge_authorized = False
    if not failures:
        live_before = _gh_json(
            frontend_root,
            failures,
            "pr",
            "view",
            pr_number,
            "--repo",
            github_repo,
            "--json",
            "isDraft,state,number,url,headRefName,headRefOid,baseRefName,mergeable,statusCheckRollup",
        ) or {}
        _validate_fe8_live_pr(live_before, pr, failures, expect_draft=True)
    if not failures:
        if live_before.get("isDraft") is True:
            ready_run = _gh(frontend_root, "pr", "ready", pr_number, "--repo", github_repo)
            if ready_run["returncode"] != 0:
                failures.append(f"gh pr ready failed: {ready_run.get('stderr', '')}")
    if not failures:
        live_ready = _gh_json(
            frontend_root,
            failures,
            "pr",
            "view",
            pr_number,
            "--repo",
            github_repo,
            "--json",
            "isDraft,state,number,url,headRefName,headRefOid,baseRefName,mergeable,statusCheckRollup",
        ) or {}
        _validate_fe8_live_pr(live_ready, pr, failures, expect_draft=False)
    if not failures:
        merge_authorized = True
        argv = ["pr", "merge", pr_number, "--repo", github_repo, f"--{merge_method}"]
        if delete_branch:
            argv.append("--delete-branch")
        merge_run = _gh(frontend_root, *argv)
        if merge_run["returncode"] != 0:
            failures.append(f"gh pr merge failed: {merge_run.get('stderr', '')}")
    merged = {}
    remote_after = remote_before
    merge_performed = bool(merge_run and merge_run.get("returncode") == 0)
    if merge_performed:
        merged = _gh_json(frontend_root, failures, "pr", "view", pr_number, "--repo", github_repo, "--json", "number,url,state,mergedAt,mergeCommit,headRefName,baseRefName") or {}
        if not isinstance(merged, dict):
            failures.append("gh pr view after merge must return object")
            merged = {}
        if merged.get("state") != "MERGED":
            failures.append("PR state must be MERGED after FE-8")
        if merged.get("headRefName") != pr.get("headRefName") or merged.get("baseRefName") != base_branch:
            failures.append("merged PR refs must remain bound to FE-7")
        merge_commit = merged.get("mergeCommit") if isinstance(merged.get("mergeCommit"), dict) else {}
        merge_commit_oid = _text(merge_commit.get("oid"))
        if not merge_commit_oid:
            failures.append("merged PR must expose mergeCommit.oid")
        remote_after = _remote_head(frontend_root, "origin", base_branch, failures) if base_branch else None
        if remote_after == remote_before:
            failures.append("base branch remote head must advance after merge")
        if merge_commit_oid and remote_after != merge_commit_oid:
            failures.append("base branch remote head must equal GitHub mergeCommit.oid")
    source_fe7_ref = _artifact_ref(source_fe7_reconciliation) if source_fe7_reconciliation.is_file() else None
    receipt = {
        "schema_version": FE8_RECEIPT_SCHEMA,
        "artifact_envelope": build_artifact_envelope(
            artifact_kind="receipt",
            plane="release",
            schema_version=FE8_RECEIPT_SCHEMA,
            artifact_id=f"fe8-merge:{github_repo}:{pr_number or 'unknown'}",
            subject_id=f"github-pr:{github_repo}:{pr_number or 'unknown'}",
            producer="beta_fe5_8_frontend_release_gates",
            source_refs=[source_fe7_ref] if source_fe7_ref else [],
            scope="github_pr_merge",
        ),
        "checked_at": _now(),
        "passed": not failures,
        "decision": "beta_fe8_frontend_merge_receipt_passed" if not failures else "blocked",
        "failure_reasons": failures,
        "source_fe7_reconciliation": source_fe7_ref,
        "frontend_root": str(frontend_root),
        "github_repo": github_repo,
        "pr": merged or pr,
        "merge_method": merge_method,
        "base_branch": base_branch,
        "base_branch_before_head": remote_before,
        "base_branch_after_head": remote_after,
        "pr_before": live_before,
        "pr_ready": live_ready,
        "ready": ready_run,
        "merge": merge_run,
        "operator_id": operator_id,
        "operator_authorization": operator_authorization,
        "git_actions_performed": {"commit": True, "push": True, "pr": True, "merge": merge_performed, "deploy": False},
        "release_provenance": build_git_release_provenance(
            {"source_review_reconciliation": source_fe7_ref},
            actions_observed={
                "commit": True,
                "push": True,
                "pr": True,
                "merge": merge_performed,
            },
            actions_performed_by_current_step={"merge": merge_performed},
        ),
        "boundary": _boundary(merge_allowed=merge_authorized),
        "h3_boundary": _h3_boundary(),
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(output_root / "beta_fe8_frontend_merge_receipt.json", receipt)
    return receipt


def _validate_fe4(value: Any, failures: list[str]) -> None:
    if not require_schema(value, FE4_RECEIPT_SCHEMA, failures, "FE-4 receipt"):
        return
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
    if not require_schema(value, FE5_RECEIPT_SCHEMA, failures, "FE-5 receipt"):
        return
    if value.get("passed") is not True:
        failures.append("FE-5 receipt must be passed")
        return
    if value.get("remote_branch_after_head") != value.get("commit_id"):
        failures.append("FE-5 remote branch must be bound to commit_id")
    _validate_h3(value, "FE-5", failures)


def _validate_fe6(value: Any, failures: list[str]) -> None:
    if not require_schema(value, FE6_RECEIPT_SCHEMA, failures, "FE-6 receipt"):
        return
    if value.get("passed") is not True:
        failures.append("FE-6 receipt must be passed")
        return
    pr = value.get("draft_pr") if isinstance(value.get("draft_pr"), dict) else {}
    if pr.get("isDraft") is not True or pr.get("state") != "OPEN":
        failures.append("FE-6 PR must be open draft")
    if pr.get("headRefOid") != value.get("commit_id"):
        failures.append("FE-6 PR head must match commit_id")
    _validate_h3(value, "FE-6", failures)


def _validate_fe7(value: Any, failures: list[str]) -> None:
    if not require_schema(value, FE7_RECEIPT_SCHEMA, failures, "FE-7 reconciliation"):
        return
    if value.get("passed") is not True:
        failures.append("FE-7 reconciliation must be passed")
        return
    if value.get("operator_decision") != "ready_to_merge":
        failures.append("FE-7 operator_decision must be ready_to_merge")
    rec = value.get("review_reconciliation") if isinstance(value.get("review_reconciliation"), dict) else {}
    if rec.get("local_verdict") != "approved" or rec.get("external_verdict") != "approved" or rec.get("merge_ready") is not True:
        failures.append("FE-7 reconciliation must have approved local/external verdicts")
    _validate_h3(value, "FE-7", failures)


def _validate_operator_authorization(operator_id: str, operator_authorization: str, failures: list[str]) -> None:
    if not _text(operator_id):
        failures.append("operator_id is required")
    authorization = _text(operator_authorization)
    if not authorization:
        failures.append("operator_authorization is required")
    if any(token in authorization.upper() for token in ("TODO", "REPLACE_ME", "PLACEHOLDER")):
        failures.append("operator_authorization must not be a placeholder")


def _validate_fe8_live_pr(
    current: Any,
    expected: Any,
    failures: list[str],
    *,
    expect_draft: bool,
) -> None:
    if not isinstance(current, dict) or not isinstance(expected, dict):
        failures.append("live and FE-7 PR records must be objects")
        return
    expected_number = expected.get("number")
    expected_refs = {
        "headRefName": _text(expected.get("headRefName")),
        "headRefOid": _text(expected.get("headRefOid")),
        "baseRefName": _text(expected.get("baseRefName")),
    }
    if not expected_number or not all(expected_refs.values()):
        failures.append("FE-7 PR record must bind number, headRefName, headRefOid, and baseRefName")
        return
    if current.get("number") != expected_number:
        failures.append("live PR number must match FE-7")
    if current.get("state") != "OPEN":
        failures.append("live PR state must be OPEN before merge")
    if current.get("isDraft") is not expect_draft:
        failures.append(f"live PR isDraft must be {str(expect_draft).lower()}")
    for field, expected_value in expected_refs.items():
        if _text(current.get(field)) != expected_value:
            failures.append(f"live PR {field} must match FE-7")
    mergeable = _text(current.get("mergeable"))
    if mergeable and mergeable != "MERGEABLE":
        failures.append(f"live PR mergeable must be MERGEABLE, got {mergeable}")
    checks = current.get("statusCheckRollup")
    if checks is None:
        return
    if not isinstance(checks, list):
        failures.append("live PR statusCheckRollup must be a list")
        return
    for check in checks:
        if not isinstance(check, dict):
            failures.append("live PR status check must be an object")
            continue
        status = _text(check.get("status")).upper()
        conclusion = _text(check.get("conclusion")).upper()
        state = _text(check.get("state")).upper()
        if status and status != "COMPLETED":
            failures.append(f"live PR status check is not completed: {status}")
        if conclusion and conclusion not in {"SUCCESS", "NEUTRAL", "SKIPPED"}:
            failures.append(f"live PR status check conclusion blocks merge: {conclusion}")
        if state and state not in {"SUCCESS", "NEUTRAL", "SKIPPED"}:
            failures.append(f"live PR status context blocks merge: {state}")


def _local_review(diff: str) -> dict[str, Any]:
    findings: list[str] = []
    slice_profiles = {
        "task_read_adapter": ("TaskReadAdapter", "taskReadModel", "TaskPoolPanel"),
        "task_pool_api_adapter": ("taskPoolApi", "createTaskPoolApi", "PoolTaskPostRequest", "apiClient"),
        "task_pool_presentation": ("taskPoolPresentation", "operatorFollowUp", "wakeTraceDetail", "TaskPoolPanel"),
        "app_shell_panel_registry": ("AppShell", "PANEL_REGISTRY", "PanelRenderContext", "panelRegistry"),
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
    base_url = (_text(env.get("BETA6_EXTERNAL_AGENT_API_BASE_URL")) or _text(env.get("LLM_BASE_URL"))).rstrip("/")
    model = _normalize_model(_text(env.get("BETA6_EXTERNAL_AGENT_MODEL")) or _text(env.get("AGENT_LLM")))
    api_key = _text(env.get("BETA6_EXTERNAL_AGENT_API_KEY")) or _text(env.get("LLM_API_KEY"))
    if not base_url or not model or not api_key:
        failures.append("external env must include API base URL, model, and API key")
        return {"schema_version": "beta-fe7-external-agent-review:v1", "passed": False, "verdict": "blocked", "failure_reasons": ["missing external API config"]}
    prompt = (
        "Review this CivitasOS frontend PR diff. Return only JSON with keys: "
        "verdict ('approved' or 'changes_requested'), risk_level ('low','medium','high'), findings (array), summary (string). "
        "Approve only if the change is limited to a bounded frontend adapter, presentation, or app-shell helper slice "
        "and does not expand deploy/production authority.\n\n"
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
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        api_failure = f"HTTP {exc.code}: {detail[:1000]}"
        failures.append(f"external Agent API call failed: {api_failure}")
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
    return read_json_any_or_empty(path, failures, label)


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    write_json(path, payload)


def _artifact_ref(path: Path) -> dict[str, str]:
    return _evidence_artifact_ref(path)


def _sha256(path: Path) -> str:
    return sha256_file(path)


def _text(value: Any) -> str:
    return str(value or "").strip()


def _normalize_model(model: str) -> str:
    normalized = _text(model)
    for prefix in ("openai:", "anthropic:", "litellm:"):
        if normalized.startswith(prefix):
            return normalized[len(prefix):]
    return normalized


def _safe_file_token(value: str) -> str:
    token = re.sub(r"[^A-Za-z0-9_.-]+", "_", value.strip())
    return token.strip("._") or "reviewer"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


if __name__ == "__main__":
    raise SystemExit(main())
