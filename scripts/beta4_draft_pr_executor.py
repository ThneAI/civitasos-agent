#!/usr/bin/env python3
"""Authorize and create one Beta-4 GitHub draft PR from a Git push receipt.

Branch push evidence is not review approval. This gate requires a fresh operator
authorization bound to one valid Beta-3 Git push receipt, creates only a draft
PR through `gh`, records the returned GitHub metadata, and never merges,
deploys, executes production runtime actions, or writes production receipts.
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

from beta3_git_push_executor import RECEIPT_SCHEMA as PUSH_RECEIPT_SCHEMA
from beta3_git_push_executor import validate_git_push_receipt


AUTHORIZATION_SCHEMA = "beta4-draft-pr-authorization:v1"
AUTHORIZATION_VALIDATION_SCHEMA = "beta4-draft-pr-authorization-validation:v1"
AUTHORIZATION_WRITE_SCHEMA = "beta4-draft-pr-authorization-write-report:v1"
EXECUTION_SCHEMA = "beta4-draft-pr-execution-report:v1"
RECEIPT_SCHEMA = "beta4-draft-pr-receipt:v1"
RECEIPT_VALIDATION_SCHEMA = "beta4-draft-pr-receipt-validation:v1"
PR_VIEW_FIELDS = "number,url,isDraft,state,headRefName,headRefOid,baseRefName,title"
NON_CLAIMS = (
    "beta4_draft_pr_executor_is_l1_controlled_pilot_only",
    "beta4_draft_pr_executor_requires_fresh_authorization_after_git_push",
    "beta4_draft_pr_executor_creates_draft_pr_only",
    "beta4_draft_pr_executor_does_not_claim_pr_review_approval",
    "beta4_draft_pr_executor_does_not_merge_or_deploy",
    "beta4_draft_pr_executor_does_not_claim_h3_production_readiness",
    "beta4_draft_pr_executor_does_not_write_production_receipts",
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    record = subparsers.add_parser("record-authorization", help="record draft PR authorization")
    record.add_argument("--git-push-receipt", required=True)
    record.add_argument("--github-repo", required=True)
    record.add_argument("--base-branch", required=True)
    record.add_argument("--title", required=True)
    record.add_argument("--body-file", required=True)
    record.add_argument("--output", required=True)
    record.add_argument("--operator-id", default="l1-controlled-pilot-operator")
    record.add_argument("--reason", required=True)
    record.add_argument("--rollback-evidence-ref", required=True)

    validate_authorization = subparsers.add_parser(
        "validate-authorization",
        help="validate draft PR authorization and pushed branch lease",
    )
    validate_authorization.add_argument("--authorization", required=True)
    validate_authorization.add_argument("--output")

    create = subparsers.add_parser("create", help="create one authorized GitHub draft PR")
    create.add_argument("--authorization", required=True)
    create.add_argument("--output-root", required=True)

    validate_receipt = subparsers.add_parser("validate-receipt", help="validate draft PR receipt")
    validate_receipt.add_argument("--receipt", required=True)
    validate_receipt.add_argument("--output")

    args = parser.parse_args(argv)
    if args.command == "record-authorization":
        report = record_draft_pr_authorization(
            push_receipt_path=Path(args.git_push_receipt),
            github_repo=args.github_repo,
            base_branch=args.base_branch,
            title=args.title,
            body_file=Path(args.body_file),
            output_path=Path(args.output),
            operator_id=args.operator_id,
            reason=args.reason,
            rollback_evidence_ref=args.rollback_evidence_ref,
        )
    elif args.command == "validate-authorization":
        report = validate_draft_pr_authorization(Path(args.authorization))
        if args.output:
            _write_json(Path(args.output), report)
    elif args.command == "create":
        report = run_draft_pr_create(
            authorization_path=Path(args.authorization),
            output_root=Path(args.output_root),
        )
    elif args.command == "validate-receipt":
        report = validate_draft_pr_receipt(Path(args.receipt))
        if args.output:
            _write_json(Path(args.output), report)
    else:
        raise AssertionError(f"unknown command: {args.command}")
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report.get("receipt_validation", report.get("validation", report)).get("passed") and report.get(
        "passed",
        True,
    ) else 1


def record_draft_pr_authorization(
    *,
    push_receipt_path: Path,
    github_repo: str,
    base_branch: str,
    title: str,
    body_file: Path,
    output_path: Path,
    operator_id: str,
    reason: str,
    rollback_evidence_ref: str,
) -> dict[str, Any]:
    failures: list[str] = []
    push_receipt = _load_push_receipt(push_receipt_path, failures)
    repo = _repo_from_push_receipt(push_receipt, failures)
    source_branch = _required_target_text(push_receipt.get("target_branch"), "source_branch", failures)
    base_branch = _valid_branch(repo, base_branch, "base_branch", failures)
    _require_distinct_branches(source_branch, base_branch, failures)
    github_repo = _valid_github_repo(github_repo, failures)
    title = _required_text(title, "title")
    operator_id = _required_text(operator_id, "operator_id")
    reason = _required_text(reason, "reason")
    rollback_evidence_ref = _required_text(rollback_evidence_ref, "rollback_evidence_ref")
    body = _read_body(body_file, failures)
    remote_head = _remote_branch_head(
        repo,
        _target_text(push_receipt.get("remote_url")),
        source_branch,
        failures,
    ) if repo is not None and source_branch else None
    if remote_head != push_receipt.get("commit_id"):
        failures.append("pushed source branch head must still equal Git push receipt commit_id")
    if failures:
        raise ValueError(f"draft PR authorization blocked: {failures}")

    authorization = {
        "schema_version": AUTHORIZATION_SCHEMA,
        "recorded_at": _now(),
        "request_id": push_receipt["request_id"],
        "authorization_scope": "github_draft_pr_only",
        "operator_id": operator_id,
        "reason": reason,
        "rollback_evidence_ref": rollback_evidence_ref,
        "source_git_push_receipt": _artifact_ref(push_receipt_path),
        "source_git_commit_receipt": push_receipt["source_git_commit_receipt"],
        "source_patch_proposal": push_receipt["source_patch_proposal"],
        "source_commit_id": push_receipt["commit_id"],
        "source_remote_url": push_receipt["remote_url"],
        "source_branch": source_branch,
        "source_remote_head": remote_head,
        "github_repo": github_repo,
        "base_branch": base_branch,
        "title": title,
        "body": {
            "text": body,
            "source": _artifact_ref(body_file),
        },
        "lease_strategy": "pushed_source_remote_head_before_github_draft_pr_create",
        "draft_pr_authorized": True,
        "draft_required": True,
        "draft_pr_created": False,
        "pr_review_approved": False,
        "git_actions_performed": {"commit": True, "push": True, "merge": False},
        "merge_allowed": False,
        "deploy_allowed": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
        "h3_boundary": _h3_boundary(),
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(output_path, authorization)
    validation = validate_draft_pr_authorization(output_path)
    if validation["passed"] is not True:
        raise ValueError(f"written draft PR authorization failed validation: {validation['failure_reasons']}")
    return {
        "schema_version": AUTHORIZATION_WRITE_SCHEMA,
        "authorization_written": True,
        "authorization_path": str(output_path.resolve()),
        "authorization_sha256": _sha256(output_path),
        "request_id": push_receipt["request_id"],
        "validation": validation,
        "non_claims": list(NON_CLAIMS),
    }


def validate_draft_pr_authorization(path: Path) -> dict[str, Any]:
    failures: list[str] = []
    authorization = _safe_read_json(path, failures, "draft PR authorization")
    if not isinstance(authorization, dict):
        return _authorization_validation_report(path, failures or ["draft PR authorization must be an object"])
    push_receipt = _validate_authorization_static(authorization, failures)
    repo = _repo_from_push_receipt(push_receipt, failures)
    source_branch = _valid_branch(repo, authorization.get("source_branch"), "source_branch", failures)
    base_branch = _valid_branch(repo, authorization.get("base_branch"), "base_branch", failures)
    _require_distinct_branches(source_branch, base_branch, failures)
    source_head = _remote_branch_head(
        repo,
        _target_text(authorization.get("source_remote_url")),
        source_branch,
        failures,
    ) if repo is not None and source_branch else None
    if source_head != authorization.get("source_remote_head"):
        failures.append("pushed source branch head drifted after draft PR authorization")
    if push_receipt and source_head != push_receipt.get("commit_id"):
        failures.append("pushed source branch no longer points at Git push receipt commit_id")
    return _authorization_validation_report(path, failures)


def run_draft_pr_create(*, authorization_path: Path, output_root: Path) -> dict[str, Any]:
    output_root = output_root.resolve()
    output_root.mkdir(parents=True, exist_ok=True)
    validation = validate_draft_pr_authorization(authorization_path)
    if validation.get("passed") is not True:
        report = _authorization_refusal_report(authorization_path, validation)
        _write_json(output_root / "beta4_draft_pr_execution_report.json", report)
        return report

    failures: list[str] = []
    failure_codes: list[str] = []
    authorization = _read_json_object(authorization_path)
    repo = _repo_from_authorization(authorization, failures)
    create_run: dict[str, Any] | None = None
    view_run: dict[str, Any] | None = None
    pr_metadata: dict[str, Any] = {}
    if not failures and repo is not None:
        create_run = _gh(
            repo,
            failures,
            "pr",
            "create",
            "--draft",
            "--repo",
            str(authorization["github_repo"]),
            "--head",
            str(authorization["source_branch"]),
            "--base",
            str(authorization["base_branch"]),
            "--title",
            str(authorization["title"]),
            "--body-file",
            "-",
            input_text=str(authorization["body"]["text"]),
        )
        if create_run["returncode"] != 0:
            _append_code(failure_codes, "draft_pr_create_failed")
    pr_url = _first_line(create_run.get("stdout")) if create_run else ""
    if create_run is not None and create_run["returncode"] == 0 and not pr_url:
        failures.append("gh pr create must return a PR URL")
        _append_code(failure_codes, "draft_pr_create_missing_url")
    if not failures and repo is not None:
        view_run = _gh(
            repo,
            failures,
            "pr",
            "view",
            pr_url,
            "--repo",
            str(authorization["github_repo"]),
            "--json",
            PR_VIEW_FIELDS,
        )
        if view_run["returncode"] != 0:
            _append_code(failure_codes, "draft_pr_view_failed")
        else:
            pr_metadata = _parse_pr_metadata(view_run.get("stdout"), failures)
            _validate_pr_metadata(pr_metadata, authorization, failures)
    pr_created = create_run is not None and create_run["returncode"] == 0 and bool(pr_metadata) and not failures
    if not pr_created and not failures:
        failures.append("draft PR was not created with verified metadata")
        _append_code(failure_codes, "draft_pr_not_verified")
    if failures and not failure_codes:
        _append_code(failure_codes, "draft_pr_internal_failure")

    receipt_path = output_root / "beta4_draft_pr_receipt.json"
    receipt_validation = None
    if pr_created:
        _write_draft_pr_receipt(
            receipt_path=receipt_path,
            authorization_path=authorization_path,
            authorization=authorization,
            create_run=create_run,
            view_run=view_run,
            pr_metadata=pr_metadata,
        )
        receipt_validation = validate_draft_pr_receipt(receipt_path)
        if receipt_validation["passed"] is not True:
            failures.extend(f"draft PR receipt invalid: {reason}" for reason in receipt_validation["failure_reasons"])
            _append_code(failure_codes, "draft_pr_receipt_invalid")
    report = {
        "schema_version": EXECUTION_SCHEMA,
        "passed": not failures,
        "draft_pr_status": "draft_pr_created_with_receipt" if not failures else "blocked_or_failed",
        "failure_reasons": failures,
        "failure_codes": failure_codes,
        "checked_at": _now(),
        "source_draft_pr_authorization": _artifact_ref(authorization_path),
        "source_draft_pr_authorization_validation": validation,
        "source_git_push_receipt": authorization.get("source_git_push_receipt"),
        "github_repo": authorization.get("github_repo"),
        "source_branch": authorization.get("source_branch"),
        "base_branch": authorization.get("base_branch"),
        "source_commit_id": authorization.get("source_commit_id"),
        "draft_pr": pr_metadata,
        "gh_create": create_run,
        "gh_view": view_run,
        "draft_pr_receipt_path": str(receipt_path.resolve()) if receipt_path.is_file() else None,
        "receipt_validation": receipt_validation,
        "draft_pr_created": pr_created,
        "pr_review_approved": False,
        "git_actions_performed": {"commit": True, "push": True, "merge": False},
        "merge_allowed": False,
        "deploy_allowed": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
        "h3_boundary": _h3_boundary(),
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(output_root / "beta4_draft_pr_execution_report.json", report)
    return report


def validate_draft_pr_receipt(receipt_path: Path) -> dict[str, Any]:
    failures: list[str] = []
    receipt = _safe_read_json(receipt_path, failures, "draft PR receipt")
    if not isinstance(receipt, dict):
        return _receipt_validation_report(receipt_path, failures or ["draft PR receipt must be an object"])
    if receipt.get("schema_version") != RECEIPT_SCHEMA:
        failures.append(f"schema_version must be {RECEIPT_SCHEMA}")
    if receipt.get("receipt_scope") != "github_draft_pr_only":
        failures.append("receipt_scope must be github_draft_pr_only")
    _validate_pr_boundary(receipt, failures)
    _validate_h3_boundary(receipt, failures)
    authorization_ref = _as_ref(receipt.get("source_draft_pr_authorization"), failures, "source_draft_pr_authorization")
    authorization_path = _validate_ref_bytes(authorization_ref, failures, "source_draft_pr_authorization")
    authorization = _safe_read_json(authorization_path, failures, "draft PR authorization")
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
        "github_repo",
        "base_branch",
        "title",
    ):
        if receipt.get(field) != authorization.get(field):
            failures.append(f"{field} must match draft PR authorization")
    pr_metadata = _as_dict(receipt.get("draft_pr"), failures, "draft_pr")
    _validate_pr_metadata(pr_metadata, authorization, failures)
    create_run = _as_dict(receipt.get("gh_create"), failures, "gh_create")
    view_run = _as_dict(receipt.get("gh_view"), failures, "gh_view")
    if create_run.get("returncode") != 0:
        failures.append("gh_create returncode must be zero")
    if view_run.get("returncode") != 0:
        failures.append("gh_view returncode must be zero")
    return _receipt_validation_report(receipt_path, failures)


def _validate_authorization_static(authorization: dict[str, Any], failures: list[str]) -> dict[str, Any]:
    if authorization.get("schema_version") != AUTHORIZATION_SCHEMA:
        failures.append(f"schema_version must be {AUTHORIZATION_SCHEMA}")
    if authorization.get("authorization_scope") != "github_draft_pr_only":
        failures.append("authorization_scope must be github_draft_pr_only")
    for field in ("operator_id", "reason", "rollback_evidence_ref", "source_commit_id", "title"):
        if not _target_text(authorization.get(field)):
            failures.append(f"{field} must be a non-empty string")
    _valid_github_repo(authorization.get("github_repo"), failures)
    body = _as_dict(authorization.get("body"), failures, "body")
    if not _text(body.get("text")):
        failures.append("body.text must be a non-empty string")
    body_ref = _as_ref(body.get("source"), failures, "body.source")
    _validate_ref_bytes(body_ref, failures, "body.source")
    if authorization.get("lease_strategy") != "pushed_source_remote_head_before_github_draft_pr_create":
        failures.append("lease_strategy must bind pushed source head before draft PR create")
    if authorization.get("draft_pr_authorized") is not True:
        failures.append("draft_pr_authorized must be true")
    if authorization.get("draft_required") is not True:
        failures.append("draft_required must be true")
    if authorization.get("draft_pr_created") is not False:
        failures.append("draft_pr_created must be false in authorization")
    _validate_pr_boundary(authorization, failures)
    _validate_h3_boundary(authorization, failures)
    push_ref = _as_ref(authorization.get("source_git_push_receipt"), failures, "source_git_push_receipt")
    push_path = _validate_ref_bytes(push_ref, failures, "source_git_push_receipt")
    push_receipt = _load_push_receipt(push_path, failures) if push_path else {}
    _validate_authorization_push_binding(authorization, push_receipt, failures)
    return push_receipt


def _validate_authorization_push_binding(
    authorization: dict[str, Any],
    push_receipt: dict[str, Any],
    failures: list[str],
) -> None:
    bindings = {
        "request_id": "request_id",
        "source_git_commit_receipt": "source_git_commit_receipt",
        "source_patch_proposal": "source_patch_proposal",
        "source_commit_id": "commit_id",
        "source_remote_url": "remote_url",
        "source_branch": "target_branch",
        "source_remote_head": "remote_branch_after_head",
    }
    for auth_field, receipt_field in bindings.items():
        if authorization.get(auth_field) != push_receipt.get(receipt_field):
            failures.append(f"{auth_field} must match Git push receipt {receipt_field}")


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
        failures.append("draft PR requires git_push_only receipt")
    if receipt.get("git_actions_performed") != {"commit": True, "merge": False, "push": True}:
        failures.append("draft PR requires push receipt without merge")
    if receipt.get("remote_branch_after_head") != receipt.get("commit_id"):
        failures.append("Git push receipt must bind remote branch head to commit_id")
    return receipt


def _write_draft_pr_receipt(
    *,
    receipt_path: Path,
    authorization_path: Path,
    authorization: dict[str, Any],
    create_run: dict[str, Any],
    view_run: dict[str, Any] | None,
    pr_metadata: dict[str, Any],
) -> None:
    receipt = {
        "schema_version": RECEIPT_SCHEMA,
        "recorded_at": _now(),
        "request_id": authorization["request_id"],
        "receipt_scope": "github_draft_pr_only",
        "source_draft_pr_authorization": _artifact_ref(authorization_path),
        "source_git_push_receipt": authorization["source_git_push_receipt"],
        "source_git_commit_receipt": authorization["source_git_commit_receipt"],
        "source_patch_proposal": authorization["source_patch_proposal"],
        "source_commit_id": authorization["source_commit_id"],
        "source_remote_url": authorization["source_remote_url"],
        "source_branch": authorization["source_branch"],
        "github_repo": authorization["github_repo"],
        "base_branch": authorization["base_branch"],
        "title": authorization["title"],
        "draft_pr": pr_metadata,
        "gh_create": create_run,
        "gh_view": view_run,
        "draft_pr_created": True,
        "pr_review_approved": False,
        "git_actions_performed": {"commit": True, "push": True, "merge": False},
        "merge_allowed": False,
        "deploy_allowed": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
        "h3_boundary": _h3_boundary(),
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(receipt_path, receipt)


def _validate_pr_metadata(pr: dict[str, Any], authorization: dict[str, Any], failures: list[str]) -> None:
    if not isinstance(pr.get("number"), int) or pr.get("number", 0) <= 0:
        failures.append("draft_pr.number must be a positive integer")
    if not _text(pr.get("url")):
        failures.append("draft_pr.url must be a non-empty string")
    if pr.get("isDraft") is not True:
        failures.append("draft_pr.isDraft must be true")
    if pr.get("state") != "OPEN":
        failures.append("draft_pr.state must be OPEN")
    expected = {
        "headRefName": authorization.get("source_branch"),
        "headRefOid": authorization.get("source_commit_id"),
        "baseRefName": authorization.get("base_branch"),
        "title": authorization.get("title"),
    }
    for field, value in expected.items():
        if pr.get(field) != value:
            failures.append(f"draft_pr.{field} must match authorization")


def _validate_pr_boundary(payload: dict[str, Any], failures: list[str]) -> None:
    if payload.get("pr_review_approved") is not False:
        failures.append("pr_review_approved must be false")
    if payload.get("git_actions_performed") != {"commit": True, "merge": False, "push": True}:
        failures.append("git_actions_performed must prove pushed branch without merge")
    for flag in (
        "merge_allowed",
        "deploy_allowed",
        "production_runtime_execution_allowed",
        "production_receipt_write_allowed",
    ):
        if payload.get(flag) is not False:
            failures.append(f"{flag} must be false")


def _parse_pr_metadata(stdout: Any, failures: list[str]) -> dict[str, Any]:
    try:
        payload = json.loads(stdout if isinstance(stdout, str) else "")
    except Exception as exc:  # noqa: BLE001 - gh output is an evidence input.
        failures.append(f"gh pr view JSON could not be parsed: {exc}")
        return {}
    if not isinstance(payload, dict):
        failures.append("gh pr view JSON must be an object")
        return {}
    return payload


def _authorization_refusal_report(path: Path, validation: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": EXECUTION_SCHEMA,
        "passed": False,
        "draft_pr_status": "authorization_refused",
        "failure_reasons": [
            f"draft PR authorization failed validation: {reason}"
            for reason in validation.get("failure_reasons", [])
        ],
        "failure_codes": ["draft_pr_authorization_refused"],
        "checked_at": _now(),
        "source_draft_pr_authorization": _artifact_ref_or_path(path),
        "source_draft_pr_authorization_validation": validation,
        "source_git_push_receipt": None,
        "github_repo": None,
        "source_branch": None,
        "base_branch": None,
        "source_commit_id": None,
        "draft_pr": {},
        "gh_create": None,
        "gh_view": None,
        "draft_pr_receipt_path": None,
        "receipt_validation": None,
        "draft_pr_created": False,
        "pr_review_approved": False,
        "git_actions_performed": {"commit": True, "push": True, "merge": False},
        "merge_allowed": False,
        "deploy_allowed": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
        "h3_boundary": _h3_boundary(),
        "non_claims": list(NON_CLAIMS),
    }


def _read_body(path: Path, failures: list[str]) -> str:
    if not path.is_file():
        failures.append(f"body_file must be a file: {path}")
        return ""
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        failures.append("body_file must contain non-empty PR body text")
    return text


def _valid_github_repo(value: Any, failures: list[str]) -> str:
    text = _required_target_text(value, "github_repo", failures)
    if not text:
        return text
    parts = text.split("/")
    if len(parts) not in (2, 3) or any(not part or any(char.isspace() for char in part) for part in parts):
        failures.append("github_repo must use OWNER/REPO or HOST/OWNER/REPO format")
    return text


def _require_distinct_branches(source_branch: str, base_branch: str, failures: list[str]) -> None:
    if source_branch and base_branch and source_branch == base_branch:
        failures.append("base_branch must differ from pushed source branch")


def _repo_from_push_receipt(receipt: dict[str, Any], failures: list[str]) -> Path | None:
    return _repo_path(receipt.get("target_repo", {}).get("repo_root"), failures)


def _repo_from_authorization(authorization: dict[str, Any], failures: list[str]) -> Path | None:
    push_ref = authorization.get("source_git_push_receipt")
    path = Path(push_ref["path"]) if isinstance(push_ref, dict) and _target_text(push_ref.get("path")) else None
    push_receipt = _safe_read_json(path, failures, "Git push receipt")
    return _repo_from_push_receipt(push_receipt if isinstance(push_receipt, dict) else {}, failures)


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


def _valid_branch(repo: Path | None, value: Any, field: str, failures: list[str]) -> str:
    branch = _required_target_text(value, field, failures)
    if repo is None or not branch:
        return branch
    run = _git(repo, failures, "check-ref-format", "--branch", branch)
    if run["returncode"] != 0:
        failures.append(f"{field} must pass git check-ref-format --branch")
    return branch


def _gh(repo: Path, failures: list[str], *args: str, input_text: str | None = None) -> dict[str, Any]:
    result = subprocess.run(
        ["gh", *args],
        cwd=repo,
        check=False,
        text=True,
        input=input_text,
        capture_output=True,
    )
    run = _command_report(" ".join(["gh", *args]), result)
    if run["returncode"] != 0:
        failures.append(f"{run['command']} failed")
    return run


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


def _first_line(value: Any) -> str:
    lines = [line.strip() for line in str(value or "").splitlines() if line.strip()]
    return lines[0] if lines else ""


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


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


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


def _validate_h3_boundary(payload: dict[str, Any], failures: list[str]) -> None:
    boundary = _as_dict(payload.get("h3_boundary"), failures, "h3_boundary")
    if boundary.get("h3_remains_blocked") is not True:
        failures.append("h3_boundary.h3_remains_blocked must be true")
    if boundary.get("h3_production_readiness_claimed") is not False:
        failures.append("h3_boundary.h3_production_readiness_claimed must be false")


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
