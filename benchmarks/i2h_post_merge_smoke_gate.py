"""Run I.2-H post-merge smoke gate.

I.2-H consumes a passed I.2-G merge authorization summary. It checks out the
merged controlled remote base branch into an isolated smoke workspace, verifies
HEAD and changed-file visibility, and writes post-merge smoke receipts. It does
not deploy, mutate runtime state, or write production receipts.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from benchmarks.i_gate_evidence import all_checks_passed, artifact_ref, check, object_value, read_json_object, sha256_file, write_json_object

CHAIN_SCHEMA = "i2h-post-merge-smoke-chain:v1"
AUTHORIZATION_SCHEMA = "i2h-post-merge-smoke-authorization:v1"
SMOKE_RECEIPT_SCHEMA = "i2h-post-merge-smoke-receipt:v1"
RECONCILIATION_SCHEMA = "i2h-operator-reconciliation:v1"
I2G_SCHEMA = "i2g-merge-authorization-chain:v1"
I2G_MERGE_SCHEMA = "i2g-isolated-merge-receipt:v1"
I2G_RECONCILIATION_SCHEMA = "i2g-operator-reconciliation:v1"


def run_gate(*, i2g_summary_path: Path, output_root: Path, operator_id: str = "operator-cc") -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "authorization": output_root / "i2h_post_merge_smoke_authorization.json",
        "smoke": output_root / "i2h_post_merge_smoke_receipt.json",
        "reconciliation": output_root / "i2h_operator_reconciliation.json",
        "summary": output_root / "i2h_post_merge_smoke_chain_summary.json",
    }
    smoke_workspace = output_root / "post_merge_smoke_workspace"
    authorization = write_authorization(i2g_summary_path=i2g_summary_path, output=artifacts["authorization"], operator_id=operator_id)
    smoke = write_smoke_receipt(authorization_path=artifacts["authorization"], smoke_workspace=smoke_workspace, output=artifacts["smoke"])
    reconciliation = write_reconciliation(authorization_path=artifacts["authorization"], smoke_path=artifacts["smoke"], output=artifacts["reconciliation"])
    reports = [authorization, smoke, reconciliation]
    passed = all(report.get("passed") is True for report in reports)
    summary = {
        "schema_version": CHAIN_SCHEMA,
        "passed": passed,
        "failure_reasons": _collect_failures(*reports),
        "source_artifacts": {"i2g_summary": artifact_ref(i2g_summary_path)},
        "artifacts": {name: artifact_ref(path) for name, path in artifacts.items() if name != "summary"},
        "readiness": {
            "state": "i2h_post_merge_smoke_passed" if passed else "blocked_i2h_post_merge_smoke",
            "i2h_post_merge_smoke_complete": passed,
            "p0_controlled_pilot_discussion_ready": passed,
            "deploy_allowed": False,
            "production_transition_allowed": False,
        },
        "boundary": _boundary(
            authorization_recording_allowed=passed,
            post_merge_smoke_allowed=passed,
            operator_reconciliation_recording_allowed=passed,
        ),
        "non_claims": [
            "i2h_does_not_deploy",
            "i2h_does_not_mutate_runtime_state",
            "i2h_does_not_authorize_production_transition",
            "i2h_does_not_write_production_receipt",
        ],
    }
    write_json_object(artifacts["summary"], summary)
    return summary


def write_authorization(*, i2g_summary_path: Path, output: Path, operator_id: str) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    i2g = read_json_object(i2g_summary_path)
    i2g_artifacts = object_value(i2g.get("artifacts"))
    merge_report = _read_verified_ref(i2g_artifacts.get("merge"), checks, failures, "i2g.merge")
    reconciliation = _read_verified_ref(i2g_artifacts.get("reconciliation"), checks, failures, "i2g.reconciliation")
    boundary = object_value(i2g.get("boundary"))
    readiness = object_value(i2g.get("readiness"))
    merge = object_value(merge_report.get("merge"))
    check(checks, failures, "i2g_summary_passed", i2g.get("schema_version") == I2G_SCHEMA and i2g.get("passed") is True)
    check(checks, failures, "i2g_ready_for_i2h", readiness.get("i2h_post_merge_smoke_discussion_ready") is True)
    check(checks, failures, "i2g_deploy_closed", boundary.get("deploy_allowed") is False)
    check(checks, failures, "i2g_runtime_closed", boundary.get("runtime_state_mutation_allowed") is False)
    check(checks, failures, "i2g_production_closed", boundary.get("production_transition_allowed") is False and boundary.get("production_receipt_write_allowed") is False)
    check(checks, failures, "i2g_merge_passed", merge_report.get("schema_version") == I2G_MERGE_SCHEMA and merge_report.get("passed") is True)
    check(checks, failures, "i2g_reconciliation_passed", reconciliation.get("schema_version") == I2G_RECONCILIATION_SCHEMA and reconciliation.get("passed") is True)
    check(checks, failures, "operator_id_present", bool(_text(operator_id)))
    check(checks, failures, "remote_url_present", bool(_text(merge.get("remote_url"))))
    check(checks, failures, "base_branch_present", bool(_text(merge.get("base_branch"))))
    check(checks, failures, "merged_head_present", bool(_text(merge.get("merged_head"))))
    check(checks, failures, "remote_base_matches_merged_head", merge.get("remote_base_after") == merge.get("merged_head"))
    passed = all_checks_passed(checks, failures)
    report = {
        "schema_version": AUTHORIZATION_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "source_artifacts": {"i2g_summary": artifact_ref(i2g_summary_path)},
        "authorization": {
            "operator_id": operator_id,
            "decision": "authorize_i2h_post_merge_smoke" if passed else "blocked_i2h_authorization",
            "scope": "post_merge_smoke_only",
            "remote_url": merge.get("remote_url"),
            "base_branch": merge.get("base_branch"),
            "merged_head": merge.get("merged_head"),
            "target_commit": merge.get("target_commit"),
            "target_branch": merge.get("target_branch"),
        },
        "readiness": {"state": "i2h_smoke_ready" if passed else "blocked_i2h_authorization", "deploy_allowed": False, "production_transition_allowed": False},
        "boundary": _boundary(authorization_recording_allowed=True),
    }
    write_json_object(output, report)
    return report


def write_smoke_receipt(*, authorization_path: Path, smoke_workspace: Path, output: Path) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    authorization = read_json_object(authorization_path)
    auth = object_value(authorization.get("authorization"))
    remote_url = str(auth.get("remote_url") or "")
    base_branch = str(auth.get("base_branch") or "")
    expected_head = str(auth.get("merged_head") or "")
    if smoke_workspace.exists():
        shutil.rmtree(smoke_workspace)
    smoke_workspace.parent.mkdir(parents=True, exist_ok=True)
    remote = _git(smoke_workspace.parent, "ls-remote", remote_url, f"refs/heads/{base_branch}")
    remote_head = _remote_head_from_ls_remote(remote)
    clone = {"argv": [], "returncode": 1, "stdout": "", "stderr": "not attempted"}
    observed_head = ""
    status: list[str] = []
    file_count = 0
    if remote_head == expected_head:
        clone = _git(smoke_workspace.parent, "clone", "--branch", base_branch, "--single-branch", remote_url, str(smoke_workspace))
        if clone["returncode"] == 0:
            observed_head = _git_text(smoke_workspace, "rev-parse", "HEAD").strip()
            status = _git_text(smoke_workspace, "status", "--porcelain").splitlines()
            file_count = sum(1 for item in smoke_workspace.rglob("*") if item.is_file() and ".git" not in item.parts)
    check(checks, failures, "authorization_passed", authorization.get("schema_version") == AUTHORIZATION_SCHEMA and authorization.get("passed") is True)
    check(checks, failures, "remote_base_reachable", bool(remote_head))
    check(checks, failures, "remote_base_matches_expected_head", remote_head == expected_head and bool(expected_head))
    check(checks, failures, "clone_succeeded", clone["returncode"] == 0)
    check(checks, failures, "observed_head_matches_expected_head", observed_head == expected_head)
    check(checks, failures, "smoke_worktree_clean", status == [])
    check(checks, failures, "smoke_workspace_has_files", file_count > 0)
    passed = all_checks_passed(checks, failures)
    report = {
        "schema_version": SMOKE_RECEIPT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "source_artifacts": {"authorization": artifact_ref(authorization_path)},
        "smoke": {
            "mode": "isolated_post_merge_checkout_smoke",
            "remote_url": remote_url,
            "base_branch": base_branch,
            "expected_head": expected_head,
            "remote_head": remote_head,
            "observed_head": observed_head,
            "file_count": file_count,
            "smoke_workspace": str(smoke_workspace.resolve()),
            "deploy_allowed": False,
            "runtime_state_mutation_allowed": False,
            "production_transition_allowed": False,
        },
        "commands": {"ls_remote": remote, "git_clone": clone, "status": status},
        "readiness": {"state": "i2h_post_merge_smoke_passed" if passed else "blocked_i2h_smoke"},
        "boundary": _boundary(post_merge_smoke_allowed=True),
    }
    write_json_object(output, report)
    return report


def write_reconciliation(*, authorization_path: Path, smoke_path: Path, output: Path) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    authorization = read_json_object(authorization_path)
    smoke = read_json_object(smoke_path)
    auth = object_value(authorization.get("authorization"))
    smoke_body = object_value(smoke.get("smoke"))
    check(checks, failures, "authorization_passed", authorization.get("schema_version") == AUTHORIZATION_SCHEMA and authorization.get("passed") is True)
    check(checks, failures, "smoke_passed", smoke.get("schema_version") == SMOKE_RECEIPT_SCHEMA and smoke.get("passed") is True)
    check(checks, failures, "smoke_head_matches_authorized_merge", smoke_body.get("observed_head") == auth.get("merged_head"))
    check(checks, failures, "deploy_runtime_production_closed", True)
    passed = all_checks_passed(checks, failures)
    report = {
        "schema_version": RECONCILIATION_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "source_artifacts": {"authorization": artifact_ref(authorization_path), "smoke": artifact_ref(smoke_path)},
        "operator_reconciliation": {
            "decision": "i2h_post_merge_smoke_passed" if passed else "blocked_i2h_reconciliation",
            "reason": "I.2-H checked the merged controlled base branch without deploy/runtime/production authority." if passed else "I.2-H smoke evidence failed hard controls.",
        },
        "readiness": {
            "state": "i2h_post_merge_smoke_passed" if passed else "blocked_i2h_reconciliation",
            "p0_controlled_pilot_discussion_ready": passed,
            "deploy_allowed": False,
            "production_transition_allowed": False,
        },
        "boundary": _boundary(operator_reconciliation_recording_allowed=True),
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
    except Exception as exc:  # noqa: BLE001
        failures.append(f"{label}_artifact_read_failed:{exc}")
        return {}


def _remote_head_from_ls_remote(result: dict[str, Any]) -> str:
    if result.get("returncode") != 0:
        return ""
    lines = str(result.get("stdout") or "").strip().splitlines()
    return lines[0].split()[0] if lines else ""


def _git(cwd: Path, *args: str) -> dict[str, Any]:
    cwd.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(["git", *args], cwd=cwd, text=True, capture_output=True, check=False)
    return {"argv": ["git", *args], "returncode": result.returncode, "stdout": result.stdout, "stderr": result.stderr}


def _git_text(cwd: Path, *args: str) -> str:
    return str(_git(cwd, *args).get("stdout", ""))


def _boundary(**overrides: bool) -> dict[str, bool]:
    base = {
        "authorization_recording_allowed": False,
        "post_merge_smoke_allowed": False,
        "operator_reconciliation_recording_allowed": False,
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
    parser.add_argument("--i2g-summary", required=True)
    parser.add_argument("--output-root", required=True)
    parser.add_argument("--operator-id", default="operator-cc")
    args = parser.parse_args()
    report = run_gate(i2g_summary_path=Path(args.i2g_summary).resolve(), output_root=Path(args.output_root).resolve(), operator_id=args.operator_id)
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    raise SystemExit(0 if report["passed"] else 2)


if __name__ == "__main__":
    main()
