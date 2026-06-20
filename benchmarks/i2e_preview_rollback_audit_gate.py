"""Run I.2-E local/private preview, rollback drill, and audit gate.

I.2-E consumes a passed I.2-D commit/push/PR summary. It clones the pushed
branch into an isolated preview workspace, verifies provenance and changed-file
visibility, performs a rollback cleanup drill, and writes an audit receipt. It
never merges, deploys, mutates runtime state, or writes production receipts.
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

CHAIN_SCHEMA = "i2e-preview-rollback-audit-chain:v1"
AUTHORIZATION_SCHEMA = "i2e-preview-rollback-audit-authorization:v1"
PREFLIGHT_SCHEMA = "i2e-preview-preflight:v1"
PREVIEW_RECEIPT_SCHEMA = "i2e-local-private-preview-receipt:v1"
ROLLBACK_RECEIPT_SCHEMA = "i2e-rollback-drill-receipt:v1"
AUDIT_RECEIPT_SCHEMA = "i2e-audit-receipt:v1"
RECONCILIATION_SCHEMA = "i2e-operator-reconciliation:v1"

I2D_SCHEMA = "i2d-commit-push-pr-chain:v1"
I2D_AUTHORIZATION_SCHEMA = "i2d-commit-push-pr-authorization:v1"
I2D_COMMIT_RECEIPT_SCHEMA = "i2d-isolated-commit-receipt:v1"
I2D_PUSH_RECEIPT_SCHEMA = "i2d-remote-branch-push-receipt:v1"
I2D_PR_RECEIPT_SCHEMA = "i2d-draft-pr-receipt:v1"


def run_gate(
    *,
    i2d_summary_path: Path,
    output_root: Path,
    operator_id: str = "operator-cc",
    audit_owner: str = "audit_owner",
) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "authorization": output_root / "i2e_preview_rollback_audit_authorization.json",
        "preflight": output_root / "i2e_preview_preflight.json",
        "preview": output_root / "i2e_local_private_preview_receipt.json",
        "rollback": output_root / "i2e_rollback_drill_receipt.json",
        "audit": output_root / "i2e_audit_receipt.json",
        "reconciliation": output_root / "i2e_operator_reconciliation.json",
        "summary": output_root / "i2e_preview_rollback_audit_chain_summary.json",
    }
    preview_workspace = output_root / "preview_workspace"

    authorization = write_authorization(
        i2d_summary_path=i2d_summary_path,
        output=artifacts["authorization"],
        operator_id=operator_id,
        audit_owner=audit_owner,
    )
    preflight = write_preflight(
        authorization_path=artifacts["authorization"],
        preview_workspace=preview_workspace,
        output=artifacts["preflight"],
    )
    preview = write_preview_receipt(
        authorization_path=artifacts["authorization"],
        preflight_path=artifacts["preflight"],
        output=artifacts["preview"],
    )
    rollback = write_rollback_receipt(
        preview_path=artifacts["preview"],
        output=artifacts["rollback"],
    )
    audit = write_audit_receipt(
        authorization_path=artifacts["authorization"],
        preflight_path=artifacts["preflight"],
        preview_path=artifacts["preview"],
        rollback_path=artifacts["rollback"],
        output=artifacts["audit"],
    )
    reconciliation = write_reconciliation(
        authorization_path=artifacts["authorization"],
        preflight_path=artifacts["preflight"],
        preview_path=artifacts["preview"],
        rollback_path=artifacts["rollback"],
        audit_path=artifacts["audit"],
        output=artifacts["reconciliation"],
    )
    reports = [authorization, preflight, preview, rollback, audit, reconciliation]
    passed = all(report.get("passed") is True for report in reports)
    summary = {
        "schema_version": CHAIN_SCHEMA,
        "passed": passed,
        "failure_reasons": _collect_failures(*reports),
        "source_artifacts": {"i2d_summary": artifact_ref(i2d_summary_path)},
        "artifacts": {name: artifact_ref(path) for name, path in artifacts.items() if name != "summary"},
        "readiness": {
            "state": "i2e_preview_rollback_audit_passed" if passed else "blocked_i2e_preview_rollback_audit",
            "i2e_preview_rollback_audit_complete": passed,
            "i2f_review_reconciliation_discussion_ready": passed,
            "merge_allowed": False,
            "deploy_allowed": False,
            "production_transition_allowed": False,
        },
        "boundary": _boundary(
            authorization_recording_allowed=passed,
            preview_preflight_recording_allowed=passed,
            local_private_preview_allowed=passed,
            rollback_drill_allowed=passed,
            audit_recording_allowed=passed,
            operator_reconciliation_recording_allowed=passed,
        ),
        "non_claims": [
            "i2e_does_not_create_or_update_live_github_pr",
            "i2e_does_not_merge",
            "i2e_does_not_deploy",
            "i2e_does_not_mutate_runtime_state",
            "i2e_does_not_authorize_production_transition",
            "i2e_does_not_write_production_receipt",
        ],
    }
    write_json_object(artifacts["summary"], summary)
    return summary


def write_authorization(
    *,
    i2d_summary_path: Path,
    output: Path,
    operator_id: str,
    audit_owner: str,
) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    i2d = read_json_object(i2d_summary_path)
    i2d_artifacts = object_value(i2d.get("artifacts"))
    i2d_authorization = _read_verified_ref(i2d_artifacts.get("authorization"), checks, failures, "i2d.authorization")
    i2d_commit = _read_verified_ref(i2d_artifacts.get("commit"), checks, failures, "i2d.commit")
    i2d_push = _read_verified_ref(i2d_artifacts.get("push"), checks, failures, "i2d.push")
    i2d_pr = _read_verified_ref(i2d_artifacts.get("pr"), checks, failures, "i2d.pr")

    auth = object_value(i2d_authorization.get("authorization"))
    commit = object_value(i2d_commit.get("commit"))
    push = object_value(i2d_push.get("push"))
    draft_pr = object_value(i2d_pr.get("draft_pr"))
    boundary = object_value(i2d.get("boundary"))
    readiness = object_value(i2d.get("readiness"))
    commit_id = str(push.get("commit_id") or "")
    changed_files = [str(item) for item in commit.get("changed_files", []) if isinstance(item, str)]

    check(checks, failures, "i2d_summary_passed", i2d.get("schema_version") == I2D_SCHEMA and i2d.get("passed") is True)
    check(checks, failures, "i2d_ready_for_i2e", readiness.get("i2e_preview_discussion_ready") is True)
    check(checks, failures, "i2d_kept_host_source_closed", boundary.get("host_source_tree_write_allowed") is False)
    check(checks, failures, "i2d_kept_merge_closed", boundary.get("merge_allowed") is False)
    check(checks, failures, "i2d_kept_deploy_closed", boundary.get("deploy_allowed") is False)
    check(checks, failures, "i2d_kept_production_closed", boundary.get("production_transition_allowed") is False and boundary.get("production_receipt_write_allowed") is False)
    check(checks, failures, "i2d_authorization_passed", i2d_authorization.get("schema_version") == I2D_AUTHORIZATION_SCHEMA and i2d_authorization.get("passed") is True)
    check(checks, failures, "i2d_commit_passed", i2d_commit.get("schema_version") == I2D_COMMIT_RECEIPT_SCHEMA and i2d_commit.get("passed") is True)
    check(checks, failures, "i2d_push_passed", i2d_push.get("schema_version") == I2D_PUSH_RECEIPT_SCHEMA and i2d_push.get("passed") is True)
    check(checks, failures, "i2d_pr_passed", i2d_pr.get("schema_version") == I2D_PR_RECEIPT_SCHEMA and i2d_pr.get("passed") is True)
    check(checks, failures, "operator_id_present", bool(_text(operator_id)))
    check(checks, failures, "audit_owner_present", bool(_text(audit_owner)))
    check(checks, failures, "remote_url_present", bool(_text(push.get("remote_url"))))
    check(checks, failures, "target_branch_present", bool(_text(push.get("target_branch"))))
    check(checks, failures, "commit_id_present", bool(commit_id))
    check(checks, failures, "changed_files_present", bool(changed_files))
    check(checks, failures, "push_commit_matches_commit_receipt", commit_id == commit.get("commit_id"))
    check(checks, failures, "push_target_matches_authorization", push.get("target_branch") == auth.get("target_branch"))
    check(checks, failures, "pr_head_matches_push_commit", draft_pr.get("headRefOid") == commit_id)
    check(checks, failures, "pr_is_draft_or_receipt", draft_pr.get("isDraft") is True and draft_pr.get("state") in {"DRAFT_RECEIPT", "OPEN"})

    passed = all_checks_passed(checks, failures)
    report = {
        "schema_version": AUTHORIZATION_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "source_artifacts": {"i2d_summary": artifact_ref(i2d_summary_path)},
        "authorization": {
            "operator_id": operator_id,
            "audit_owner": audit_owner,
            "decision": "authorize_i2e_local_private_preview_rollback_audit" if passed else "blocked_i2e_authorization",
            "scope": "local_private_preview_rollback_audit_only",
            "remote_url": push.get("remote_url"),
            "target_branch": push.get("target_branch"),
            "commit_id": commit_id,
            "changed_files": changed_files,
            "draft_pr_mode": draft_pr.get("mode"),
            "draft_pr_state": draft_pr.get("state"),
            "draft_pr_url": draft_pr.get("url"),
        },
        "readiness": {
            "state": "i2e_preview_preflight_ready" if passed else "blocked_i2e_authorization",
            "local_private_preview_preflight_allowed": passed,
            "merge_allowed": False,
            "deploy_allowed": False,
            "production_transition_allowed": False,
        },
        "boundary": _boundary(authorization_recording_allowed=True),
    }
    write_json_object(output, report)
    return report


def write_preflight(*, authorization_path: Path, preview_workspace: Path, output: Path) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    authorization = read_json_object(authorization_path)
    auth = object_value(authorization.get("authorization"))
    remote_url = str(auth.get("remote_url") or "")
    target_branch = str(auth.get("target_branch") or "")
    expected_commit = str(auth.get("commit_id") or "")

    if preview_workspace.exists():
        shutil.rmtree(preview_workspace)
    preview_workspace.parent.mkdir(parents=True, exist_ok=True)
    remote = _git(preview_workspace.parent, "ls-remote", remote_url, f"refs/heads/{target_branch}")
    remote_head = _remote_head_from_ls_remote(remote)

    check(checks, failures, "authorization_passed", authorization.get("schema_version") == AUTHORIZATION_SCHEMA and authorization.get("passed") is True)
    check(checks, failures, "preview_workspace_absent_before_clone", not preview_workspace.exists())
    check(checks, failures, "remote_branch_reachable", remote["returncode"] == 0 and bool(remote_head))
    check(checks, failures, "remote_branch_matches_authorized_commit", bool(expected_commit) and remote_head == expected_commit)

    passed = all_checks_passed(checks, failures)
    report = {
        "schema_version": PREFLIGHT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "source_artifacts": {"authorization": artifact_ref(authorization_path)},
        "preflight": {
            "preview_workspace": str(preview_workspace.resolve()),
            "remote_url": remote_url,
            "target_branch": target_branch,
            "expected_commit": expected_commit,
            "remote_branch_head": remote_head,
            "host_source_tree_write_allowed": False,
            "merge_allowed": False,
            "deploy_allowed": False,
            "runtime_state_mutation_allowed": False,
            "production_transition_allowed": False,
        },
        "commands": {"git_ls_remote": remote},
        "readiness": {"state": "i2e_preview_ready" if passed else "blocked_i2e_preflight"},
        "boundary": _boundary(preview_preflight_recording_allowed=True),
    }
    write_json_object(output, report)
    return report


def write_preview_receipt(*, authorization_path: Path, preflight_path: Path, output: Path) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    authorization = read_json_object(authorization_path)
    preflight = read_json_object(preflight_path)
    auth = object_value(authorization.get("authorization"))
    preflight_body = object_value(preflight.get("preflight"))
    preview_workspace = Path(str(preflight_body.get("preview_workspace") or ""))
    remote_url = str(auth.get("remote_url") or "")
    target_branch = str(auth.get("target_branch") or "")
    expected_commit = str(auth.get("commit_id") or "")
    changed_files = [str(item) for item in auth.get("changed_files", []) if isinstance(item, str)]

    clone = {"argv": [], "returncode": 1, "stdout": "", "stderr": "not attempted"}
    head = ""
    status_after_clone: list[str] = []
    changed_file_hashes: dict[str, str] = {}
    if preflight.get("passed") is True:
        clone = _git(preview_workspace.parent, "clone", "--branch", target_branch, "--single-branch", remote_url, str(preview_workspace))
        if clone["returncode"] == 0:
            head = _git_text(preview_workspace, "rev-parse", "HEAD").strip()
            status_after_clone = _git_text(preview_workspace, "status", "--porcelain").splitlines()
            for rel in changed_files:
                path = preview_workspace / rel
                if path.is_file():
                    changed_file_hashes[rel] = sha256_file(path)

    check(checks, failures, "authorization_passed", authorization.get("schema_version") == AUTHORIZATION_SCHEMA and authorization.get("passed") is True)
    check(checks, failures, "preflight_passed", preflight.get("schema_version") == PREFLIGHT_SCHEMA and preflight.get("passed") is True)
    check(checks, failures, "clone_succeeded", clone["returncode"] == 0)
    check(checks, failures, "preview_head_matches_authorized_commit", bool(expected_commit) and head == expected_commit)
    check(checks, failures, "preview_worktree_clean", status_after_clone == [])
    check(checks, failures, "changed_files_visible_in_preview", bool(changed_files) and sorted(changed_file_hashes) == sorted(changed_files))

    passed = all_checks_passed(checks, failures)
    report = {
        "schema_version": PREVIEW_RECEIPT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "source_artifacts": {"authorization": artifact_ref(authorization_path), "preflight": artifact_ref(preflight_path)},
        "preview": {
            "mode": "local_private_preview_clone",
            "preview_workspace": str(preview_workspace.resolve()),
            "remote_url": remote_url,
            "target_branch": target_branch,
            "expected_commit": expected_commit,
            "observed_head": head,
            "changed_files": changed_files,
            "changed_file_hashes": changed_file_hashes,
            "host_source_tree_write_allowed": False,
            "merge_allowed": False,
            "deploy_allowed": False,
            "runtime_state_mutation_allowed": False,
            "production_transition_allowed": False,
        },
        "commands": {"git_clone": clone, "status_after_clone": status_after_clone},
        "readiness": {"state": "i2e_local_private_preview_passed" if passed else "blocked_i2e_preview"},
        "boundary": _boundary(local_private_preview_allowed=True),
    }
    write_json_object(output, report)
    return report


def write_rollback_receipt(*, preview_path: Path, output: Path) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    preview = read_json_object(preview_path)
    preview_body = object_value(preview.get("preview"))
    preview_workspace = Path(str(preview_body.get("preview_workspace") or ""))
    existed_before_cleanup = preview_workspace.exists()
    if existed_before_cleanup:
        shutil.rmtree(preview_workspace)
    exists_after_cleanup = preview_workspace.exists()

    check(checks, failures, "preview_passed", preview.get("schema_version") == PREVIEW_RECEIPT_SCHEMA and preview.get("passed") is True)
    check(checks, failures, "preview_workspace_existed_before_cleanup", existed_before_cleanup)
    check(checks, failures, "preview_workspace_removed", not exists_after_cleanup)

    passed = all_checks_passed(checks, failures)
    report = {
        "schema_version": ROLLBACK_RECEIPT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "source_artifacts": {"preview": artifact_ref(preview_path)},
        "rollback": {
            "mode": "local_private_preview_cleanup",
            "preview_workspace": str(preview_workspace.resolve()),
            "existed_before_cleanup": existed_before_cleanup,
            "exists_after_cleanup": exists_after_cleanup,
            "remote_branch_delete_allowed": False,
            "merge_revert_allowed": False,
            "deploy_rollback_allowed": False,
            "production_rollback_allowed": False,
        },
        "readiness": {"state": "i2e_rollback_drill_passed" if passed else "blocked_i2e_rollback"},
        "boundary": _boundary(rollback_drill_allowed=True),
    }
    write_json_object(output, report)
    return report


def write_audit_receipt(
    *,
    authorization_path: Path,
    preflight_path: Path,
    preview_path: Path,
    rollback_path: Path,
    output: Path,
) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    reports = {
        "authorization": (read_json_object(authorization_path), AUTHORIZATION_SCHEMA),
        "preflight": (read_json_object(preflight_path), PREFLIGHT_SCHEMA),
        "preview": (read_json_object(preview_path), PREVIEW_RECEIPT_SCHEMA),
        "rollback": (read_json_object(rollback_path), ROLLBACK_RECEIPT_SCHEMA),
    }
    for label, (report, schema) in reports.items():
        check(checks, failures, f"{label}_passed", report.get("schema_version") == schema and report.get("passed") is True)
    preview_body = object_value(reports["preview"][0].get("preview"))
    rollback_body = object_value(reports["rollback"][0].get("rollback"))
    check(checks, failures, "preview_commit_observed", bool(preview_body.get("observed_head")))
    check(checks, failures, "rollback_cleanup_observed", rollback_body.get("exists_after_cleanup") is False)
    check(checks, failures, "production_receipt_not_written", True)

    passed = all_checks_passed(checks, failures)
    report = {
        "schema_version": AUDIT_RECEIPT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "source_artifacts": {
            "authorization": artifact_ref(authorization_path),
            "preflight": artifact_ref(preflight_path),
            "preview": artifact_ref(preview_path),
            "rollback": artifact_ref(rollback_path),
        },
        "audit": {
            "events": [
                {"event": "i2e_authorization_recorded", "artifact": artifact_ref(authorization_path)},
                {"event": "i2e_preview_preflight_recorded", "artifact": artifact_ref(preflight_path)},
                {"event": "i2e_local_private_preview_recorded", "artifact": artifact_ref(preview_path)},
                {"event": "i2e_rollback_drill_recorded", "artifact": artifact_ref(rollback_path)},
            ],
            "production_receipt_written": False,
            "deploy_observed": False,
            "merge_observed": False,
        },
        "readiness": {"state": "i2e_audit_passed" if passed else "blocked_i2e_audit"},
        "boundary": _boundary(audit_recording_allowed=True),
    }
    write_json_object(output, report)
    return report


def write_reconciliation(
    *,
    authorization_path: Path,
    preflight_path: Path,
    preview_path: Path,
    rollback_path: Path,
    audit_path: Path,
    output: Path,
) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    reports = {
        "authorization": (read_json_object(authorization_path), AUTHORIZATION_SCHEMA),
        "preflight": (read_json_object(preflight_path), PREFLIGHT_SCHEMA),
        "preview": (read_json_object(preview_path), PREVIEW_RECEIPT_SCHEMA),
        "rollback": (read_json_object(rollback_path), ROLLBACK_RECEIPT_SCHEMA),
        "audit": (read_json_object(audit_path), AUDIT_RECEIPT_SCHEMA),
    }
    for label, (report, schema) in reports.items():
        check(checks, failures, f"{label}_passed", report.get("schema_version") == schema and report.get("passed") is True)
    preview_body = object_value(reports["preview"][0].get("preview"))
    authorization_body = object_value(reports["authorization"][0].get("authorization"))
    check(checks, failures, "preview_head_matches_authorized_commit", preview_body.get("observed_head") == authorization_body.get("commit_id"))
    check(checks, failures, "merge_deploy_production_closed", True)

    passed = all_checks_passed(checks, failures)
    report = {
        "schema_version": RECONCILIATION_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "source_artifacts": {
            "authorization": artifact_ref(authorization_path),
            "preflight": artifact_ref(preflight_path),
            "preview": artifact_ref(preview_path),
            "rollback": artifact_ref(rollback_path),
            "audit": artifact_ref(audit_path),
        },
        "operator_reconciliation": {
            "decision": "i2e_preview_rollback_audit_passed" if passed else "blocked_i2e_reconciliation",
            "reason": "I.2-E completed local/private preview, rollback cleanup, and audit without merge/deploy/production authority." if passed else "I.2-E evidence chain failed one or more hard controls.",
        },
        "readiness": {
            "state": "i2e_preview_rollback_audit_passed" if passed else "blocked_i2e_reconciliation",
            "i2f_review_reconciliation_discussion_ready": passed,
        },
        "boundary": _boundary(operator_reconciliation_recording_allowed=True),
        "non_claims": [
            "i2e_reconciliation_does_not_authorize_merge",
            "i2e_reconciliation_does_not_authorize_deploy_or_production",
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


def _git(cwd: Path, *args: str) -> dict[str, Any]:
    cwd.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(["git", *args], cwd=cwd, text=True, capture_output=True, check=False)
    return {"argv": ["git", *args], "returncode": result.returncode, "stdout": result.stdout, "stderr": result.stderr}


def _git_text(cwd: Path, *args: str) -> str:
    return str(_git(cwd, *args).get("stdout", ""))


def _boundary(**overrides: bool) -> dict[str, bool]:
    base = {
        "authorization_recording_allowed": False,
        "preview_preflight_recording_allowed": False,
        "local_private_preview_allowed": False,
        "rollback_drill_allowed": False,
        "audit_recording_allowed": False,
        "operator_reconciliation_recording_allowed": False,
        "host_source_tree_write_allowed": False,
        "merge_allowed": False,
        "deploy_allowed": False,
        "runtime_state_mutation_allowed": False,
        "production_transition_allowed": False,
        "production_receipt_write_allowed": False,
        "remote_branch_delete_allowed": False,
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
    parser.add_argument("--i2d-summary", required=True)
    parser.add_argument("--output-root", required=True)
    parser.add_argument("--operator-id", default="operator-cc")
    parser.add_argument("--audit-owner", default="audit_owner")
    args = parser.parse_args()
    report = run_gate(
        i2d_summary_path=Path(args.i2d_summary).resolve(),
        output_root=Path(args.output_root).resolve(),
        operator_id=args.operator_id,
        audit_owner=args.audit_owner,
    )
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    raise SystemExit(0 if report["passed"] else 2)


if __name__ == "__main__":
    main()
