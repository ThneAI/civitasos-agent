"""Run I.2-G isolated merge authorization gate.

I.2-G consumes a passed I.2-F review/reconciliation summary. It traces the
I.2-F -> I.2-E -> I.2-D provenance chain, performs an isolated merge into a
controlled remote base branch, and records a merge receipt. It never deploys,
mutates runtime state, or writes production receipts.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from benchmarks.i_gate_evidence import (
    all_checks_passed,
    artifact_ref,
    check,
    object_value,
    read_json_object,
    sha256_file,
    write_json_object,
)

CHAIN_SCHEMA = "i2g-merge-authorization-chain:v1"
AUTHORIZATION_SCHEMA = "i2g-merge-authorization:v1"
PREFLIGHT_SCHEMA = "i2g-merge-preflight:v1"
MERGE_RECEIPT_SCHEMA = "i2g-isolated-merge-receipt:v1"
RECONCILIATION_SCHEMA = "i2g-operator-reconciliation:v1"

I2F_SCHEMA = "i2f-review-reconciliation-chain:v1"
I2F_RECONCILIATION_SCHEMA = "i2f-operator-reconciliation:v1"
I2E_SCHEMA = "i2e-preview-rollback-audit-chain:v1"
I2D_SCHEMA = "i2d-commit-push-pr-chain:v1"
I2D_AUTHORIZATION_SCHEMA = "i2d-commit-push-pr-authorization:v1"
I2D_PUSH_SCHEMA = "i2d-remote-branch-push-receipt:v1"


def run_gate(
    *,
    i2f_summary_path: Path,
    output_root: Path,
    operator_id: str = "operator-cc",
    merge_strategy: str = "ff-only",
) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "authorization": output_root / "i2g_merge_authorization.json",
        "preflight": output_root / "i2g_merge_preflight.json",
        "merge": output_root / "i2g_isolated_merge_receipt.json",
        "reconciliation": output_root / "i2g_operator_reconciliation.json",
        "summary": output_root / "i2g_merge_authorization_chain_summary.json",
    }
    merge_workspace = output_root / "merge_workspace"
    authorization = write_authorization(
        i2f_summary_path=i2f_summary_path,
        output=artifacts["authorization"],
        operator_id=operator_id,
        merge_strategy=merge_strategy,
    )
    preflight = write_preflight(
        authorization_path=artifacts["authorization"],
        merge_workspace=merge_workspace,
        output=artifacts["preflight"],
    )
    merge = write_merge_receipt(
        authorization_path=artifacts["authorization"],
        preflight_path=artifacts["preflight"],
        output=artifacts["merge"],
    )
    reconciliation = write_reconciliation(
        authorization_path=artifacts["authorization"],
        preflight_path=artifacts["preflight"],
        merge_path=artifacts["merge"],
        output=artifacts["reconciliation"],
    )
    reports = [authorization, preflight, merge, reconciliation]
    passed = all(report.get("passed") is True for report in reports)
    summary = {
        "schema_version": CHAIN_SCHEMA,
        "passed": passed,
        "failure_reasons": _collect_failures(*reports),
        "source_artifacts": {"i2f_summary": artifact_ref(i2f_summary_path)},
        "artifacts": {name: artifact_ref(path) for name, path in artifacts.items() if name != "summary"},
        "readiness": {
            "state": "i2g_merge_authorization_passed" if passed else "blocked_i2g_merge_authorization",
            "i2g_merge_authorization_complete": passed,
            "i2h_post_merge_smoke_discussion_ready": passed,
            "deploy_allowed": False,
            "production_transition_allowed": False,
        },
        "boundary": _boundary(
            authorization_recording_allowed=passed,
            merge_preflight_recording_allowed=passed,
            isolated_merge_allowed=passed,
            remote_base_branch_update_allowed=passed,
            operator_reconciliation_recording_allowed=passed,
        ),
        "non_claims": [
            "i2g_merge_does_not_deploy",
            "i2g_merge_does_not_mutate_runtime_state",
            "i2g_merge_does_not_authorize_production_transition",
            "i2g_merge_does_not_write_production_receipt",
        ],
    }
    write_json_object(artifacts["summary"], summary)
    return summary


def write_authorization(*, i2f_summary_path: Path, output: Path, operator_id: str, merge_strategy: str) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    i2f = read_json_object(i2f_summary_path)
    i2f_artifacts = object_value(i2f.get("artifacts"))
    i2f_reconciliation = _read_verified_ref(i2f_artifacts.get("reconciliation"), checks, failures, "i2f.reconciliation")
    i2e_summary = _read_verified_ref(object_value(i2f.get("source_artifacts")).get("i2e_summary"), checks, failures, "i2f.source_i2e_summary")
    i2d_summary = _read_verified_ref(object_value(i2e_summary.get("source_artifacts")).get("i2d_summary"), checks, failures, "i2e.source_i2d_summary")
    i2d_artifacts = object_value(i2d_summary.get("artifacts"))
    i2d_authorization = _read_verified_ref(i2d_artifacts.get("authorization"), checks, failures, "i2d.authorization")
    i2d_push = _read_verified_ref(i2d_artifacts.get("push"), checks, failures, "i2d.push")

    i2f_boundary = object_value(i2f.get("boundary"))
    i2f_readiness = object_value(i2f.get("readiness"))
    i2f_recon = object_value(i2f_reconciliation.get("operator_reconciliation"))
    i2d_auth = object_value(i2d_authorization.get("authorization"))
    push = object_value(i2d_push.get("push"))
    base_branch = str(i2d_auth.get("base_branch") or "main")
    target_branch = str(push.get("target_branch") or "")
    remote_url = str(push.get("remote_url") or "")
    target_commit = str(push.get("commit_id") or "")

    check(checks, failures, "i2f_summary_passed", i2f.get("schema_version") == I2F_SCHEMA and i2f.get("passed") is True)
    check(checks, failures, "i2f_ready_for_i2g", i2f_readiness.get("i2g_merge_discussion_ready") is True)
    check(checks, failures, "i2f_kept_deploy_closed", i2f_boundary.get("deploy_allowed") is False)
    check(checks, failures, "i2f_kept_runtime_closed", i2f_boundary.get("runtime_state_mutation_allowed") is False)
    check(checks, failures, "i2f_kept_production_closed", i2f_boundary.get("production_transition_allowed") is False and i2f_boundary.get("production_receipt_write_allowed") is False)
    check(checks, failures, "i2f_reconciliation_passed", i2f_reconciliation.get("schema_version") == I2F_RECONCILIATION_SCHEMA and i2f_reconciliation.get("passed") is True)
    check(checks, failures, "i2f_operator_decision_passed", i2f_recon.get("decision") == "i2f_review_reconciliation_passed")
    check(checks, failures, "i2e_summary_passed", i2e_summary.get("schema_version") == I2E_SCHEMA and i2e_summary.get("passed") is True)
    check(checks, failures, "i2d_summary_passed", i2d_summary.get("schema_version") == I2D_SCHEMA and i2d_summary.get("passed") is True)
    check(checks, failures, "i2d_authorization_passed", i2d_authorization.get("schema_version") == I2D_AUTHORIZATION_SCHEMA and i2d_authorization.get("passed") is True)
    check(checks, failures, "i2d_push_passed", i2d_push.get("schema_version") == I2D_PUSH_SCHEMA and i2d_push.get("passed") is True)
    check(checks, failures, "operator_id_present", bool(_text(operator_id)))
    check(checks, failures, "merge_strategy_supported", merge_strategy == "ff-only")
    check(checks, failures, "remote_url_present", bool(remote_url))
    check(checks, failures, "base_branch_present", bool(base_branch))
    check(checks, failures, "target_branch_present", bool(target_branch))
    check(checks, failures, "target_commit_present", bool(target_commit))
    check(checks, failures, "pushed_branch_matches_target_commit", push.get("remote_branch_after_head") == target_commit)

    passed = all_checks_passed(checks, failures)
    report = {
        "schema_version": AUTHORIZATION_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "source_artifacts": {"i2f_summary": artifact_ref(i2f_summary_path)},
        "authorization": {
            "operator_id": operator_id,
            "decision": "authorize_i2g_isolated_merge" if passed else "blocked_i2g_authorization",
            "scope": "isolated_merge_to_controlled_remote_base_only",
            "remote_url": remote_url,
            "base_branch": base_branch,
            "target_branch": target_branch,
            "target_commit": target_commit,
            "merge_strategy": merge_strategy,
        },
        "readiness": {
            "state": "i2g_merge_preflight_ready" if passed else "blocked_i2g_authorization",
            "merge_preflight_allowed": passed,
            "deploy_allowed": False,
            "production_transition_allowed": False,
        },
        "boundary": _boundary(authorization_recording_allowed=True),
    }
    write_json_object(output, report)
    return report


def write_preflight(*, authorization_path: Path, merge_workspace: Path, output: Path) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    authorization = read_json_object(authorization_path)
    auth = object_value(authorization.get("authorization"))
    remote_url = str(auth.get("remote_url") or "")
    base_branch = str(auth.get("base_branch") or "")
    target_branch = str(auth.get("target_branch") or "")
    target_commit = str(auth.get("target_commit") or "")
    if merge_workspace.exists():
        shutil.rmtree(merge_workspace)
    merge_workspace.parent.mkdir(parents=True, exist_ok=True)

    base_remote = _git(merge_workspace.parent, "ls-remote", remote_url, f"refs/heads/{base_branch}")
    target_remote = _git(merge_workspace.parent, "ls-remote", remote_url, f"refs/heads/{target_branch}")
    base_head = _remote_head_from_ls_remote(base_remote)
    target_head = _remote_head_from_ls_remote(target_remote)
    clone = {"argv": [], "returncode": 1, "stdout": "", "stderr": "not attempted"}
    base_init_parent = ""
    if target_head == target_commit and bool(remote_url):
        if base_head:
            clone = _git(merge_workspace.parent, "clone", "--branch", base_branch, "--single-branch", remote_url, str(merge_workspace))
        else:
            clone = _git(merge_workspace.parent, "clone", "--branch", target_branch, "--single-branch", remote_url, str(merge_workspace))
            if clone["returncode"] == 0:
                _git(merge_workspace, "config", "user.name", "CivitasOS I2G")
                _git(merge_workspace, "config", "user.email", "i2g@example.invalid")
                base_init_parent = _git_text(merge_workspace, "rev-parse", f"{target_commit}^").strip()
                if base_init_parent:
                    _git(merge_workspace, "checkout", "-B", base_branch, base_init_parent)
                    _git(merge_workspace, "push", "origin", f"HEAD:refs/heads/{base_branch}")
                    base_remote = _git(merge_workspace.parent, "ls-remote", remote_url, f"refs/heads/{base_branch}")
                    base_head = _remote_head_from_ls_remote(base_remote)
    check(checks, failures, "authorization_passed", authorization.get("schema_version") == AUTHORIZATION_SCHEMA and authorization.get("passed") is True)
    check(checks, failures, "merge_workspace_absent_before_clone", merge_workspace.is_dir())
    check(checks, failures, "target_branch_reachable", bool(target_head))
    check(checks, failures, "target_branch_matches_authorized_commit", target_head == target_commit)
    check(checks, failures, "base_branch_ready", bool(base_head))
    check(checks, failures, "clone_succeeded", clone["returncode"] == 0 and (merge_workspace / ".git").is_dir())

    passed = all_checks_passed(checks, failures)
    report = {
        "schema_version": PREFLIGHT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "source_artifacts": {"authorization": artifact_ref(authorization_path)},
        "preflight": {
            "merge_workspace": str(merge_workspace.resolve()),
            "remote_url": remote_url,
            "base_branch": base_branch,
            "target_branch": target_branch,
            "target_commit": target_commit,
            "base_head_before": base_head,
            "base_initialized_from_target_parent": base_init_parent,
            "target_head": target_head,
            "deploy_allowed": False,
            "runtime_state_mutation_allowed": False,
            "production_transition_allowed": False,
        },
        "commands": {"base_ls_remote": base_remote, "target_ls_remote": target_remote, "git_clone": clone},
        "readiness": {"state": "i2g_merge_ready" if passed else "blocked_i2g_preflight"},
        "boundary": _boundary(merge_preflight_recording_allowed=True),
    }
    write_json_object(output, report)
    return report


def write_merge_receipt(*, authorization_path: Path, preflight_path: Path, output: Path) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    authorization = read_json_object(authorization_path)
    preflight = read_json_object(preflight_path)
    auth = object_value(authorization.get("authorization"))
    preflight_body = object_value(preflight.get("preflight"))
    repo = Path(str(preflight_body.get("merge_workspace") or ""))
    remote_url = str(auth.get("remote_url") or "")
    base_branch = str(auth.get("base_branch") or "")
    target_branch = str(auth.get("target_branch") or "")
    target_commit = str(auth.get("target_commit") or "")
    base_before = str(preflight_body.get("base_head_before") or "")
    fetch_target = merge = push = {"argv": [], "returncode": 1, "stdout": "", "stderr": "not attempted"}
    merged_head = ""
    remote_base_after = ""
    status_after: list[str] = []
    if preflight.get("passed") is True:
        _git(repo, "config", "user.name", "CivitasOS I2G")
        _git(repo, "config", "user.email", "i2g@example.invalid")
        fetch_target = _git(repo, "fetch", "origin", f"{target_branch}:refs/remotes/origin/{target_branch}")
        merge = _git(repo, "merge", "--ff-only", target_commit)
        if merge["returncode"] == 0:
            merged_head = _git_text(repo, "rev-parse", "HEAD").strip()
            status_after = _git_text(repo, "status", "--porcelain").splitlines()
            push = _git(repo, "push", "--porcelain", "origin", f"HEAD:refs/heads/{base_branch}")
            remote_base_after = _remote_head(repo, "origin", base_branch)
    check(checks, failures, "authorization_passed", authorization.get("schema_version") == AUTHORIZATION_SCHEMA and authorization.get("passed") is True)
    check(checks, failures, "preflight_passed", preflight.get("schema_version") == PREFLIGHT_SCHEMA and preflight.get("passed") is True)
    check(checks, failures, "fetch_target_succeeded", fetch_target["returncode"] == 0)
    check(checks, failures, "ff_merge_succeeded", merge["returncode"] == 0)
    check(checks, failures, "merged_head_matches_target_commit", merged_head == target_commit)
    check(checks, failures, "worktree_clean_after_merge", status_after == [])
    check(checks, failures, "push_base_succeeded", push["returncode"] == 0)
    check(checks, failures, "remote_base_matches_merged_head", remote_base_after == merged_head and bool(remote_base_after))

    passed = all_checks_passed(checks, failures)
    report = {
        "schema_version": MERGE_RECEIPT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "source_artifacts": {"authorization": artifact_ref(authorization_path), "preflight": artifact_ref(preflight_path)},
        "merge": {
            "mode": "isolated_ff_only_merge_to_controlled_remote_base",
            "remote_url": remote_url,
            "base_branch": base_branch,
            "target_branch": target_branch,
            "base_head_before": base_before,
            "target_commit": target_commit,
            "merged_head": merged_head,
            "remote_base_after": remote_base_after,
            "deploy_allowed": False,
            "runtime_state_mutation_allowed": False,
            "production_transition_allowed": False,
        },
        "commands": {"fetch_target": fetch_target, "merge": merge, "push_base": push, "status_after": status_after},
        "readiness": {"state": "i2g_merge_passed" if passed else "blocked_i2g_merge"},
        "boundary": _boundary(isolated_merge_allowed=True, remote_base_branch_update_allowed=True),
    }
    write_json_object(output, report)
    return report


def write_reconciliation(*, authorization_path: Path, preflight_path: Path, merge_path: Path, output: Path) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    authorization = read_json_object(authorization_path)
    preflight = read_json_object(preflight_path)
    merge = read_json_object(merge_path)
    merge_body = object_value(merge.get("merge"))
    auth = object_value(authorization.get("authorization"))
    check(checks, failures, "authorization_passed", authorization.get("schema_version") == AUTHORIZATION_SCHEMA and authorization.get("passed") is True)
    check(checks, failures, "preflight_passed", preflight.get("schema_version") == PREFLIGHT_SCHEMA and preflight.get("passed") is True)
    check(checks, failures, "merge_passed", merge.get("schema_version") == MERGE_RECEIPT_SCHEMA and merge.get("passed") is True)
    check(checks, failures, "merged_commit_matches_authorized_target", merge_body.get("merged_head") == auth.get("target_commit"))
    check(checks, failures, "deploy_runtime_production_closed", True)
    passed = all_checks_passed(checks, failures)
    report = {
        "schema_version": RECONCILIATION_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "source_artifacts": {
            "authorization": artifact_ref(authorization_path),
            "preflight": artifact_ref(preflight_path),
            "merge": artifact_ref(merge_path),
        },
        "operator_reconciliation": {
            "decision": "i2g_merge_authorization_passed" if passed else "blocked_i2g_reconciliation",
            "reason": "I.2-G completed isolated ff-only merge to controlled remote base while deploy/runtime/production boundaries stayed closed." if passed else "I.2-G merge evidence failed hard controls.",
        },
        "readiness": {
            "state": "i2g_merge_authorization_passed" if passed else "blocked_i2g_reconciliation",
            "i2h_post_merge_smoke_discussion_ready": passed,
            "deploy_allowed": False,
            "production_transition_allowed": False,
        },
        "boundary": _boundary(operator_reconciliation_recording_allowed=True),
        "non_claims": [
            "i2g_reconciliation_does_not_authorize_deploy",
            "i2g_reconciliation_does_not_authorize_runtime_or_production",
        ],
    }
    write_json_object(output, report)
    return report


def _read_verified_ref(value: Any, checks: dict[str, bool], failures: list[str], label: str) -> dict[str, Any]:
    ref = object_value(value)
    path = Path(str(ref.get("path") or ""))
    expected_hash = str(ref.get("sha256") or "")
    path_exists = path.is_file()
    check(checks, failures, f"{label}_artifact_path_present", path_exists)
    if not path_exists:
        return {}
    actual_hash = sha256_file(path)
    check(checks, failures, f"{label}_artifact_hash_valid", bool(expected_hash) and actual_hash == expected_hash)
    try:
        return read_json_object(path)
    except Exception as exc:  # noqa: BLE001 - gate records validation failures.
        failures.append(f"{label}_artifact_read_failed:{exc}")
        return {}


def _remote_head_from_ls_remote(result: dict[str, Any]) -> str:
    if result.get("returncode") != 0:
        return ""
    lines = str(result.get("stdout") or "").strip().splitlines()
    return lines[0].split()[0] if lines else ""


def _remote_head(repo: Path, remote: str, branch: str) -> str:
    return _remote_head_from_ls_remote(_git(repo, "ls-remote", remote, f"refs/heads/{branch}"))


def _git(cwd: Path, *args: str) -> dict[str, Any]:
    cwd.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(["git", *args], cwd=cwd, text=True, capture_output=True, check=False)
    return {"argv": ["git", *args], "returncode": result.returncode, "stdout": result.stdout, "stderr": result.stderr}


def _git_text(cwd: Path, *args: str) -> str:
    return str(_git(cwd, *args).get("stdout", ""))


def _boundary(**overrides: bool) -> dict[str, bool]:
    base = {
        "authorization_recording_allowed": False,
        "merge_preflight_recording_allowed": False,
        "isolated_merge_allowed": False,
        "remote_base_branch_update_allowed": False,
        "operator_reconciliation_recording_allowed": False,
        "host_source_tree_write_allowed": False,
        "deploy_allowed": False,
        "runtime_state_mutation_allowed": False,
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
    parser.add_argument("--i2f-summary", required=True)
    parser.add_argument("--output-root", required=True)
    parser.add_argument("--operator-id", default="operator-cc")
    parser.add_argument("--merge-strategy", default="ff-only")
    args = parser.parse_args()
    report = run_gate(
        i2f_summary_path=Path(args.i2f_summary).resolve(),
        output_root=Path(args.output_root).resolve(),
        operator_id=args.operator_id,
        merge_strategy=args.merge_strategy,
    )
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    raise SystemExit(0 if report["passed"] else 2)


if __name__ == "__main__":
    main()
