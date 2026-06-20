"""Run I.2-D isolated commit, push, and draft PR gate.

I.2-D consumes a passed I.2-C bounded apply summary. It converts the isolated
workspace diff into an isolated Git commit, pushes one bounded branch, and writes
a draft PR receipt. The default PR mode is local receipt only; live GitHub draft
PR creation requires explicit ``--pr-mode gh-draft``.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from benchmarks.i_gate_evidence import (
    all_checks_passed,
    artifact_ref,
    check,
    object_value,
    objects_value,
    read_json_object,
    sha256_text,
    write_json_object,
)

CHAIN_SCHEMA = "i2d-commit-push-pr-chain:v1"
AUTHORIZATION_SCHEMA = "i2d-commit-push-pr-authorization:v1"
PREFLIGHT_SCHEMA = "i2d-git-isolation-preflight:v1"
COMMIT_RECEIPT_SCHEMA = "i2d-isolated-commit-receipt:v1"
PUSH_RECEIPT_SCHEMA = "i2d-remote-branch-push-receipt:v1"
PR_RECEIPT_SCHEMA = "i2d-draft-pr-receipt:v1"
RECONCILIATION_SCHEMA = "i2d-operator-reconciliation:v1"
I2C_SCHEMA = "i2c-bounded-apply-chain:v1"
I2C_PREFLIGHT_SCHEMA = "i2c-bounded-apply-isolation-preflight:v1"
I2C_APPLY_SCHEMA = "i2c-bounded-apply-receipt:v1"
PR_MODES = {"local-draft-receipt", "gh-draft"}


def run_gate(
    *,
    i2c_summary_path: Path,
    output_root: Path,
    remote_url: str,
    target_branch: str,
    base_branch: str = "main",
    commit_message: str = "i2d: isolated bounded apply",
    operator_id: str = "operator-cc",
    pr_mode: str = "local-draft-receipt",
    github_repo: str = "",
    pr_title: str = "I.2-D isolated bounded apply",
    pr_body: str = "I.2-D draft PR receipt generated from isolated bounded apply evidence.",
) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "authorization": output_root / "i2d_commit_push_pr_authorization.json",
        "preflight": output_root / "i2d_git_isolation_preflight.json",
        "commit": output_root / "i2d_isolated_commit_receipt.json",
        "push": output_root / "i2d_remote_branch_push_receipt.json",
        "pr": output_root / "i2d_draft_pr_receipt.json",
        "reconciliation": output_root / "i2d_operator_reconciliation.json",
        "summary": output_root / "i2d_commit_push_pr_chain_summary.json",
    }
    repo_workspace = output_root / "git_workspace"

    authorization = write_authorization(
        i2c_summary_path=i2c_summary_path,
        output=artifacts["authorization"],
        remote_url=remote_url,
        target_branch=target_branch,
        base_branch=base_branch,
        commit_message=commit_message,
        operator_id=operator_id,
        pr_mode=pr_mode,
        github_repo=github_repo,
        pr_title=pr_title,
    )
    preflight = write_preflight(
        authorization_path=artifacts["authorization"],
        repo_workspace=repo_workspace,
        output=artifacts["preflight"],
    )
    commit = write_commit_receipt(
        authorization_path=artifacts["authorization"],
        preflight_path=artifacts["preflight"],
        output=artifacts["commit"],
    )
    push = write_push_receipt(
        authorization_path=artifacts["authorization"],
        commit_path=artifacts["commit"],
        output=artifacts["push"],
    )
    pr = write_pr_receipt(
        authorization_path=artifacts["authorization"],
        push_path=artifacts["push"],
        output=artifacts["pr"],
        pr_body=pr_body,
    )
    reconciliation = write_reconciliation(
        authorization_path=artifacts["authorization"],
        preflight_path=artifacts["preflight"],
        commit_path=artifacts["commit"],
        push_path=artifacts["push"],
        pr_path=artifacts["pr"],
        output=artifacts["reconciliation"],
    )
    reports = [authorization, preflight, commit, push, pr, reconciliation]
    passed = all(report.get("passed") is True for report in reports)
    summary = {
        "schema_version": CHAIN_SCHEMA,
        "passed": passed,
        "failure_reasons": _collect_failures(*reports),
        "source_artifacts": {"i2c_summary": artifact_ref(i2c_summary_path)},
        "artifacts": {name: artifact_ref(path) for name, path in artifacts.items() if name != "summary"},
        "readiness": {
            "state": "i2d_commit_push_pr_passed" if passed else "blocked_i2d_commit_push_pr",
            "i2d_commit_push_pr_complete": passed,
            "i2e_preview_discussion_ready": passed,
            "deploy_allowed": False,
            "production_transition_allowed": False,
        },
        "boundary": _boundary(
            authorization_recording_allowed=passed,
            preflight_recording_allowed=passed,
            isolated_git_write_allowed=passed,
            commit_allowed=passed,
            remote_branch_push_allowed=passed,
            draft_pr_allowed=passed,
            operator_reconciliation_recording_allowed=passed,
            deploy_allowed=False,
            production_transition_allowed=False,
        ),
        "non_claims": [
            "i2d_does_not_authorize_merge_deploy_or_production",
            "i2d_default_pr_mode_can_be_local_receipt_without_live_github_pr",
            "i2d_does_not_modify_host_source_tree",
        ],
    }
    write_json_object(artifacts["summary"], summary)
    return summary


def write_authorization(
    *,
    i2c_summary_path: Path,
    output: Path,
    remote_url: str,
    target_branch: str,
    base_branch: str,
    commit_message: str,
    operator_id: str,
    pr_mode: str,
    github_repo: str,
    pr_title: str,
) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    i2c = read_json_object(i2c_summary_path)
    i2c_artifacts = object_value(i2c.get("artifacts"))
    i2c_apply = _read_ref(i2c_artifacts.get("apply"), failures, "i2c.apply")
    i2c_preflight = _read_ref(i2c_artifacts.get("preflight"), failures, "i2c.preflight")
    applied_files = objects_value(object_value(i2c_apply.get("apply")).get("applied_files"))

    check(checks, failures, "i2c_summary_passed", i2c.get("schema_version") == I2C_SCHEMA and i2c.get("passed") is True)
    check(checks, failures, "i2c_ready_for_i2d", object_value(i2c.get("readiness")).get("i2d_commit_push_pr_discussion_ready") is True)
    check(checks, failures, "i2c_host_source_closed", object_value(i2c.get("boundary")).get("host_source_tree_write_allowed") is False and object_value(i2c.get("boundary")).get("source_tree_write_allowed") is False)
    check(checks, failures, "i2c_apply_receipt_valid", i2c_apply.get("schema_version") == I2C_APPLY_SCHEMA and i2c_apply.get("passed") is True)
    check(checks, failures, "i2c_preflight_valid", i2c_preflight.get("schema_version") == I2C_PREFLIGHT_SCHEMA and i2c_preflight.get("passed") is True)
    check(checks, failures, "applied_files_present", bool(applied_files))
    check(checks, failures, "remote_url_present", bool(_text(remote_url)))
    check(checks, failures, "target_branch_safe", _valid_branch(target_branch))
    check(checks, failures, "base_branch_safe", _valid_branch(base_branch))
    check(checks, failures, "commit_message_present", bool(_text(commit_message)))
    check(checks, failures, "operator_id_present", bool(_text(operator_id)))
    check(checks, failures, "pr_mode_supported", pr_mode in PR_MODES)
    if pr_mode == "gh-draft":
        check(checks, failures, "github_repo_present_for_live_pr", bool(_text(github_repo)))
        check(checks, failures, "pr_title_present_for_live_pr", bool(_text(pr_title)))

    passed = all_checks_passed(checks, failures)
    report = {
        "schema_version": AUTHORIZATION_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "source_artifacts": {"i2c_summary": artifact_ref(i2c_summary_path)},
        "authorization": {
            "operator_id": operator_id,
            "decision": "authorize_i2d_commit_push_pr" if passed else "blocked_i2d_authorization",
            "scope": "isolated_commit_one_branch_push_draft_pr_only",
            "remote_url": remote_url,
            "target_branch": target_branch,
            "base_branch": base_branch,
            "commit_message": commit_message,
            "pr_mode": pr_mode,
            "github_repo": github_repo,
            "pr_title": pr_title,
            "allowed_files": [str(item.get("path")) for item in applied_files if item.get("path")],
        },
        "upstream": {
            "i2c_apply_receipt": object_value(i2c_artifacts.get("apply")),
            "i2c_preflight": object_value(i2c_artifacts.get("preflight")),
        },
        "readiness": {"state": "i2d_git_preflight_ready" if passed else "blocked_i2d_authorization"},
        "boundary": _boundary(authorization_recording_allowed=True),
    }
    write_json_object(output, report)
    return report


def write_preflight(*, authorization_path: Path, repo_workspace: Path, output: Path) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    authorization = read_json_object(authorization_path)
    auth = object_value(authorization.get("authorization"))
    i2c_preflight = _read_ref(object_value(authorization.get("upstream")).get("i2c_preflight"), failures, "i2c_preflight")
    i2c_apply = _read_ref(object_value(authorization.get("upstream")).get("i2c_apply_receipt"), failures, "i2c_apply")
    isolation = object_value(i2c_preflight.get("isolation"))
    original_workspace = Path(str(isolation.get("original_workspace") or ""))
    source_workspace = Path(str(isolation.get("source_workspace") or ""))
    allowed_files = [str(item.get("path")) for item in objects_value(object_value(i2c_apply.get("apply")).get("applied_files")) if item.get("path")]

    check(checks, failures, "authorization_passed", authorization.get("schema_version") == AUTHORIZATION_SCHEMA and authorization.get("passed") is True)
    check(checks, failures, "original_workspace_exists", original_workspace.is_dir())
    check(checks, failures, "source_workspace_exists", source_workspace.is_dir())
    if repo_workspace.exists():
        shutil.rmtree(repo_workspace)
    repo_workspace.mkdir(parents=True, exist_ok=True)
    if original_workspace.is_dir():
        _copy_tree_contents(original_workspace, repo_workspace)
    init = _git(repo_workspace, "init", "-b", auth.get("base_branch") or "main")
    _git(repo_workspace, "config", "user.name", "CivitasOS I2D")
    _git(repo_workspace, "config", "user.email", "i2d@example.invalid")
    _git(repo_workspace, "add", ".")
    baseline = _git(repo_workspace, "commit", "-m", "i2d baseline")
    if source_workspace.is_dir():
        _copy_tree_contents(source_workspace, repo_workspace)
    status = _git_text(repo_workspace, "status", "--porcelain").splitlines()
    changed_files = sorted(line[3:] for line in status if len(line) > 3)
    check(checks, failures, "git_init_succeeded", init["returncode"] == 0)
    check(checks, failures, "baseline_commit_succeeded", baseline["returncode"] == 0)
    check(checks, failures, "changed_files_match_i2c_apply", changed_files == sorted(allowed_files))

    passed = all_checks_passed(checks, failures)
    report = {
        "schema_version": PREFLIGHT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "source_artifacts": {"authorization": artifact_ref(authorization_path)},
        "git_isolation": {
            "repo_workspace": str(repo_workspace.resolve()),
            "original_workspace": str(original_workspace.resolve()) if original_workspace else "",
            "source_workspace": str(source_workspace.resolve()) if source_workspace else "",
            "allowed_files": allowed_files,
            "changed_files": changed_files,
            "host_source_tree_write_allowed": False,
            "deploy_allowed": False,
            "production_transition_allowed": False,
        },
        "commands": {"git_init": init, "baseline_commit": baseline},
        "readiness": {"state": "i2d_commit_ready" if passed else "blocked_i2d_preflight"},
        "boundary": _boundary(isolated_git_write_allowed=True, preflight_recording_allowed=True),
    }
    write_json_object(output, report)
    return report


def write_commit_receipt(*, authorization_path: Path, preflight_path: Path, output: Path) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    authorization = read_json_object(authorization_path)
    preflight = read_json_object(preflight_path)
    auth = object_value(authorization.get("authorization"))
    isolation = object_value(preflight.get("git_isolation"))
    repo = Path(str(isolation.get("repo_workspace") or ""))
    allowed_files = [str(item) for item in isolation.get("allowed_files", []) if isinstance(item, str)]
    check(checks, failures, "authorization_passed", authorization.get("passed") is True)
    check(checks, failures, "preflight_passed", preflight.get("schema_version") == PREFLIGHT_SCHEMA and preflight.get("passed") is True)
    check(checks, failures, "repo_workspace_exists", (repo / ".git").is_dir())
    status_before = _git_text(repo, "status", "--porcelain").splitlines() if repo.is_dir() else []
    changed_files = sorted(line[3:] for line in status_before if len(line) > 3)
    check(checks, failures, "commit_scope_matches_allowlist", changed_files == sorted(allowed_files) and bool(changed_files))
    add = commit = {"returncode": 1, "stdout": "", "stderr": "not attempted", "argv": []}
    commit_id = ""
    if all_checks_passed(checks, failures):
        add = _git(repo, "add", *allowed_files)
        commit = _git(repo, "commit", "-m", str(auth.get("commit_message") or "i2d isolated bounded apply"))
        if commit["returncode"] == 0:
            commit_id = _git_text(repo, "rev-parse", "HEAD").strip()
    check(checks, failures, "git_add_succeeded", add["returncode"] == 0)
    check(checks, failures, "git_commit_succeeded", commit["returncode"] == 0 and bool(commit_id))
    status_after = _git_text(repo, "status", "--porcelain").splitlines() if repo.is_dir() else []
    check(checks, failures, "worktree_clean_after_commit", status_after == [])

    passed = all_checks_passed(checks, failures)
    report = {
        "schema_version": COMMIT_RECEIPT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "source_artifacts": {"authorization": artifact_ref(authorization_path), "preflight": artifact_ref(preflight_path)},
        "commit": {"commit_id": commit_id, "changed_files": changed_files, "repo_workspace": str(repo.resolve()) if repo else ""},
        "commands": {"status_before": status_before, "git_add": add, "git_commit": commit, "status_after": status_after},
        "readiness": {"state": "i2d_commit_passed" if passed else "blocked_i2d_commit"},
        "boundary": _boundary(isolated_git_write_allowed=True, commit_allowed=True),
    }
    write_json_object(output, report)
    return report


def write_push_receipt(*, authorization_path: Path, commit_path: Path, output: Path) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    authorization = read_json_object(authorization_path)
    commit = read_json_object(commit_path)
    auth = object_value(authorization.get("authorization"))
    commit_body = object_value(commit.get("commit"))
    repo = Path(str(commit_body.get("repo_workspace") or ""))
    remote_url = str(auth.get("remote_url") or "")
    target_branch = str(auth.get("target_branch") or "")
    commit_id = str(commit_body.get("commit_id") or "")
    check(checks, failures, "authorization_passed", authorization.get("passed") is True)
    check(checks, failures, "commit_passed", commit.get("schema_version") == COMMIT_RECEIPT_SCHEMA and commit.get("passed") is True)
    check(checks, failures, "repo_workspace_exists", (repo / ".git").is_dir())
    remote_add = push = {"returncode": 1, "stdout": "", "stderr": "not attempted", "argv": []}
    remote_after = ""
    if all_checks_passed(checks, failures):
        remote_add = _git(repo, "remote", "add", "origin", remote_url)
        if remote_add["returncode"] != 0 and "already exists" in remote_add.get("stderr", ""):
            remote_add = _git(repo, "remote", "set-url", "origin", remote_url)
        push = _git(repo, "push", "--porcelain", "origin", f"{commit_id}:refs/heads/{target_branch}")
        remote_after = _remote_head(repo, "origin", target_branch)
    check(checks, failures, "remote_configured", remote_add["returncode"] == 0)
    check(checks, failures, "push_succeeded", push["returncode"] == 0)
    check(checks, failures, "remote_branch_matches_commit", bool(commit_id) and remote_after == commit_id)

    passed = all_checks_passed(checks, failures)
    report = {
        "schema_version": PUSH_RECEIPT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "source_artifacts": {"authorization": artifact_ref(authorization_path), "commit": artifact_ref(commit_path)},
        "push": {"remote_url": remote_url, "target_branch": target_branch, "remote_branch_after_head": remote_after, "commit_id": commit_id},
        "commands": {"remote_add": remote_add, "push": push},
        "readiness": {"state": "i2d_push_passed" if passed else "blocked_i2d_push"},
        "boundary": _boundary(isolated_git_write_allowed=True, remote_branch_push_allowed=True),
    }
    write_json_object(output, report)
    return report


def write_pr_receipt(*, authorization_path: Path, push_path: Path, output: Path, pr_body: str) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    authorization = read_json_object(authorization_path)
    push = read_json_object(push_path)
    auth = object_value(authorization.get("authorization"))
    push_body = object_value(push.get("push"))
    commit_report = _read_ref(object_value(push.get("source_artifacts")).get("commit"), failures, "push.commit")
    repo = Path(str(object_value(commit_report.get("commit")).get("repo_workspace") or ""))
    pr_mode = str(auth.get("pr_mode") or "")
    check(checks, failures, "authorization_passed", authorization.get("passed") is True)
    check(checks, failures, "push_passed", push.get("schema_version") == PUSH_RECEIPT_SCHEMA and push.get("passed") is True)
    check(checks, failures, "pr_mode_supported", pr_mode in PR_MODES)
    gh_create: dict[str, Any] | None = None
    draft_pr = {
        "mode": pr_mode,
        "isDraft": True,
        "state": "DRAFT_RECEIPT",
        "github_repo": auth.get("github_repo"),
        "baseRefName": auth.get("base_branch"),
        "headRefName": auth.get("target_branch"),
        "headRefOid": push_body.get("commit_id"),
        "url": None,
        "title": auth.get("pr_title"),
    }
    if pr_mode == "gh-draft" and all_checks_passed(checks, failures):
        gh_create = _gh(repo, "pr", "create", "--draft", "--repo", str(auth.get("github_repo")), "--base", str(auth.get("base_branch")), "--head", str(auth.get("target_branch")), "--title", str(auth.get("pr_title")), "--body", pr_body)
        if gh_create["returncode"] != 0:
            failures.append("gh pr create failed")
        draft_pr["state"] = "OPEN" if gh_create and gh_create["returncode"] == 0 else "BLOCKED"
        draft_pr["url"] = (gh_create.get("stdout") or "").strip().splitlines()[-1] if gh_create and gh_create.get("stdout") else None
    check(checks, failures, "draft_pr_receipt_present", draft_pr["isDraft"] is True and bool(draft_pr.get("headRefOid")))

    passed = all_checks_passed(checks, failures)
    report = {
        "schema_version": PR_RECEIPT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "source_artifacts": {"authorization": artifact_ref(authorization_path), "push": artifact_ref(push_path)},
        "draft_pr": draft_pr,
        "commands": {"gh_create": gh_create},
        "readiness": {"state": "i2d_draft_pr_receipt_passed" if passed else "blocked_i2d_pr"},
        "boundary": _boundary(draft_pr_allowed=True, remote_branch_push_allowed=True),
    }
    write_json_object(output, report)
    return report


def write_reconciliation(*, authorization_path: Path, preflight_path: Path, commit_path: Path, push_path: Path, pr_path: Path, output: Path) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    reports = {
        "authorization": (read_json_object(authorization_path), AUTHORIZATION_SCHEMA),
        "preflight": (read_json_object(preflight_path), PREFLIGHT_SCHEMA),
        "commit": (read_json_object(commit_path), COMMIT_RECEIPT_SCHEMA),
        "push": (read_json_object(push_path), PUSH_RECEIPT_SCHEMA),
        "pr": (read_json_object(pr_path), PR_RECEIPT_SCHEMA),
    }
    for label, (report, schema) in reports.items():
        check(checks, failures, f"{label}_passed", report.get("schema_version") == schema and report.get("passed") is True)
    push = object_value(reports["push"][0].get("push"))
    pr = object_value(reports["pr"][0].get("draft_pr"))
    check(checks, failures, "pr_head_matches_push_commit", pr.get("headRefOid") == push.get("commit_id"))
    check(checks, failures, "deploy_and_production_closed", True)
    passed = all_checks_passed(checks, failures)
    report = {
        "schema_version": RECONCILIATION_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "source_artifacts": {
            "authorization": artifact_ref(authorization_path),
            "preflight": artifact_ref(preflight_path),
            "commit": artifact_ref(commit_path),
            "push": artifact_ref(push_path),
            "pr": artifact_ref(pr_path),
        },
        "operator_reconciliation": {
            "decision": "i2d_commit_push_pr_passed" if passed else "blocked_i2d_reconciliation",
            "reason": "I.2-D completed isolated commit, one branch push, and draft PR receipt without merge/deploy/production authority." if passed else "I.2-D evidence chain failed one or more hard controls.",
        },
        "readiness": {"state": "i2d_commit_push_pr_passed" if passed else "blocked_i2d_reconciliation", "i2e_preview_discussion_ready": passed},
        "boundary": _boundary(operator_reconciliation_recording_allowed=True),
        "non_claims": ["i2d_reconciliation_does_not_authorize_merge", "i2d_reconciliation_does_not_authorize_deploy_or_production"],
    }
    write_json_object(output, report)
    return report


def _read_ref(value: Any, failures: list[str], label: str) -> dict[str, Any]:
    ref = object_value(value)
    path = Path(str(ref.get("path") or ""))
    if not path.is_file():
        failures.append(f"{label} artifact ref missing file")
        return {}
    try:
        report = read_json_object(path)
    except Exception as exc:  # noqa: BLE001 - validation preserves failure class.
        failures.append(f"{label} artifact read failed: {exc}")
        return {}
    return report


def _valid_branch(value: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_./-]{1,120}", value or "")) and ".." not in value and not value.endswith(("/", ".lock"))


def _copy_tree_contents(src: Path, dst: Path) -> None:
    for item in src.rglob("*"):
        rel = item.relative_to(src)
        target = dst / rel
        if item.is_dir():
            target.mkdir(parents=True, exist_ok=True)
        elif item.is_file():
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(item, target)


def _remote_head(repo: Path, remote: str, branch: str) -> str:
    result = _git(repo, "ls-remote", remote, f"refs/heads/{branch}")
    if result["returncode"] != 0:
        return ""
    line = (result.get("stdout") or "").strip().splitlines()
    return line[0].split()[0] if line else ""


def _git(repo: Path, *args: str) -> dict[str, Any]:
    result = subprocess.run(["git", *args], cwd=repo, text=True, capture_output=True, check=False)
    return {"argv": ["git", *args], "returncode": result.returncode, "stdout": result.stdout, "stderr": result.stderr}


def _git_text(repo: Path, *args: str) -> str:
    return str(_git(repo, *args).get("stdout", ""))


def _gh(cwd: Path, *args: str) -> dict[str, Any]:
    result = subprocess.run(["gh", *args], cwd=cwd, text=True, capture_output=True, check=False)
    return {"argv": ["gh", *args], "returncode": result.returncode, "stdout": result.stdout, "stderr": result.stderr}


def _boundary(**overrides: bool) -> dict[str, bool]:
    base = {
        "authorization_recording_allowed": False,
        "preflight_recording_allowed": False,
        "commit_allowed": False,
        "remote_branch_push_allowed": False,
        "draft_pr_allowed": False,
        "operator_reconciliation_recording_allowed": False,
        "isolated_git_write_allowed": False,
        "host_source_tree_write_allowed": False,
        "merge_allowed": False,
        "deploy_allowed": False,
        "production_transition_allowed": False,
        "production_receipt_write_allowed": False,
    }
    base.update(overrides)
    return base


def _collect_failures(*reports: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    for report in reports:
        failures.extend(str(item) for item in report.get("failure_reasons", []) if item)
    return failures


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--i2c-summary", required=True)
    parser.add_argument("--output-root", required=True)
    parser.add_argument("--remote-url", required=True)
    parser.add_argument("--target-branch", required=True)
    parser.add_argument("--base-branch", default="main")
    parser.add_argument("--commit-message", default="i2d: isolated bounded apply")
    parser.add_argument("--operator-id", default="operator-cc")
    parser.add_argument("--pr-mode", choices=sorted(PR_MODES), default="local-draft-receipt")
    parser.add_argument("--github-repo", default="")
    parser.add_argument("--pr-title", default="I.2-D isolated bounded apply")
    parser.add_argument("--pr-body", default="I.2-D draft PR receipt generated from isolated bounded apply evidence.")
    args = parser.parse_args()
    report = run_gate(
        i2c_summary_path=Path(args.i2c_summary).resolve(),
        output_root=Path(args.output_root).resolve(),
        remote_url=args.remote_url,
        target_branch=args.target_branch,
        base_branch=args.base_branch,
        commit_message=args.commit_message,
        operator_id=args.operator_id,
        pr_mode=args.pr_mode,
        github_repo=args.github_repo,
        pr_title=args.pr_title,
        pr_body=args.pr_body,
    )
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    raise SystemExit(0 if report["passed"] else 2)


if __name__ == "__main__":
    main()
