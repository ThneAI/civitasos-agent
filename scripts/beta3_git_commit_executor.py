#!/usr/bin/env python3
"""Create a bounded Beta-3 Git commit and write a commit receipt.

The executor consumes a still-valid commit-only Git publication authorization,
stages only post-source-apply receipt target paths, creates one commit, and
records the Git evidence needed to inspect that action later. It never pushes,
merges, deploys, executes production runtime actions, or writes production
receipts.
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

from beta3_git_publication_authorization import AUTHORIZATION_SCHEMA
from beta3_git_publication_authorization import validate_git_publication_authorization
from beta3_source_apply_executor import RECEIPT_SCHEMA as SOURCE_APPLY_RECEIPT_SCHEMA


EXECUTION_SCHEMA = "beta3-git-commit-execution-report:v1"
RECEIPT_SCHEMA = "beta3-git-commit-receipt:v1"
RECEIPT_VALIDATION_SCHEMA = "beta3-git-commit-receipt-validation:v1"
NON_CLAIMS = (
    "beta3_git_commit_executor_is_l1_controlled_pilot_only",
    "beta3_git_commit_executor_commits_only_authorized_post_apply_target_paths",
    "beta3_git_commit_executor_does_not_push_merge_or_deploy",
    "beta3_git_commit_executor_does_not_claim_h3_production_readiness",
    "beta3_git_commit_executor_does_not_write_production_receipts",
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    commit = subparsers.add_parser("commit", help="create one authorized bounded Git commit")
    commit.add_argument("--authorization", required=True)
    commit.add_argument("--output-root", required=True)

    validate = subparsers.add_parser("validate-receipt", help="validate an existing Git commit receipt")
    validate.add_argument("--receipt", required=True)
    validate.add_argument("--output")

    args = parser.parse_args(argv)
    if args.command == "commit":
        report = run_git_commit(
            authorization_path=Path(args.authorization),
            output_root=Path(args.output_root),
        )
    elif args.command == "validate-receipt":
        report = validate_git_commit_receipt(Path(args.receipt))
        if args.output:
            _write_json(Path(args.output), report)
    else:
        raise AssertionError(f"unknown command: {args.command}")
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report.get("receipt_validation", report).get("passed") and report.get("passed", True) else 1


def run_git_commit(*, authorization_path: Path, output_root: Path) -> dict[str, Any]:
    output_root = output_root.resolve()
    output_root.mkdir(parents=True, exist_ok=True)
    authorization_validation = validate_git_publication_authorization(authorization_path)
    if authorization_validation.get("passed") is not True:
        report = _authorization_refusal_report(authorization_path, authorization_validation)
        _write_json(output_root / "beta3_git_commit_execution_report.json", report)
        return report

    failures: list[str] = []
    failure_codes: list[str] = []
    authorization = _read_json_object(authorization_path)
    source_receipt = _load_commit_only_context(authorization, failures, failure_codes)
    repo = _repo_from_authorization(authorization, failures)
    before = _repo_snapshot(repo, failures) if repo is not None else {}
    expected_before = authorization.get("target_repo", {}).get("after")
    if before != expected_before:
        failures.append("target repo snapshot drifted before Git commit")
        _append_code(failure_codes, "git_commit_snapshot_drift")

    target_paths = _string_list(source_receipt.get("applied_target_paths"))
    if not target_paths:
        failures.append("post-source-apply receipt applied_target_paths must not be empty")
        _append_code(failure_codes, "git_commit_missing_target_paths")

    stage: dict[str, Any] | None = None
    staged_paths: list[str] = []
    commit_run: dict[str, Any] | None = None
    commit_id: str | None = None
    committed_paths: list[str] = []
    if not failures and repo is not None:
        stage = _git(repo, failures, "add", "--", *target_paths)
        staged_paths = _git_lines(repo, failures, "diff", "--cached", "--name-only")
        if stage["returncode"] != 0:
            _append_code(failure_codes, "git_stage_failed")
        if sorted(staged_paths) != sorted(target_paths):
            failures.append("staged target paths must match post-source-apply receipt paths")
            _append_code(failure_codes, "git_stage_target_paths_mismatch")
        if not staged_paths:
            failures.append("Git commit requires at least one staged target path")
            _append_code(failure_codes, "git_commit_nothing_staged")
    if not failures and repo is not None:
        commit_run = _git(repo, failures, "commit", "-m", str(authorization["commit_message"]))
        if commit_run["returncode"] != 0:
            _append_code(failure_codes, "git_commit_failed")

    after = _repo_snapshot(repo, failures) if repo is not None else {}
    commit_performed = commit_run is not None and commit_run["returncode"] == 0
    if commit_performed and repo is not None:
        commit_id = after.get("head_commit")
        if commit_id == before.get("head_commit"):
            failures.append("Git commit did not advance HEAD")
            _append_code(failure_codes, "git_commit_head_not_advanced")
        committed_paths = _commit_paths(repo, commit_id, failures)
        if sorted(committed_paths) != sorted(target_paths):
            failures.append("committed target paths must match post-source-apply receipt paths")
            _append_code(failure_codes, "git_commit_target_paths_mismatch")
        if after.get("status_short"):
            failures.append("target repo worktree must be clean after bounded Git commit")
            _append_code(failure_codes, "git_commit_after_snapshot_dirty")
    elif not failures:
        failures.append("Git commit was not performed")
        _append_code(failure_codes, "git_commit_not_performed")

    receipt_path = output_root / "beta3_git_commit_receipt.json"
    receipt_validation = None
    if commit_performed and not failures and repo is not None and commit_id is not None:
        _write_commit_receipt(
            receipt_path=receipt_path,
            authorization_path=authorization_path,
            authorization=authorization,
            source_receipt=source_receipt,
            before=before,
            after=after,
            staged_paths=staged_paths,
            committed_paths=committed_paths,
            commit_id=commit_id,
        )
        receipt_validation = validate_git_commit_receipt(receipt_path)
        if receipt_validation["passed"] is not True:
            failures.extend(f"Git commit receipt invalid: {reason}" for reason in receipt_validation["failure_reasons"])
            _append_code(failure_codes, "git_commit_receipt_invalid")
    if failures and not failure_codes:
        _append_code(failure_codes, "git_commit_internal_failure")

    report = {
        "schema_version": EXECUTION_SCHEMA,
        "passed": not failures,
        "commit_status": "committed_with_receipt" if not failures else "blocked_or_failed",
        "failure_reasons": failures,
        "failure_codes": failure_codes,
        "checked_at": _now(),
        "source_git_publication_authorization": _artifact_ref(authorization_path),
        "source_git_publication_authorization_validation": authorization_validation,
        "source_post_apply_receipt": authorization.get("source_post_apply_receipt"),
        "target_repo": {
            "repo_root": str(repo) if repo is not None else None,
            "before": before,
            "after": after,
        },
        "staged_target_paths": staged_paths,
        "committed_target_paths": committed_paths,
        "stage": stage,
        "commit": commit_run,
        "commit_id": commit_id,
        "commit_receipt_path": str(receipt_path.resolve()) if receipt_path.is_file() else None,
        "receipt_validation": receipt_validation,
        "git_actions_performed": {
            "commit": commit_performed,
            "push": False,
            "merge": False,
        },
        "push_allowed": False,
        "merge_allowed": False,
        "deploy_allowed": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
        "h3_boundary": _h3_boundary(),
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(output_root / "beta3_git_commit_execution_report.json", report)
    return report


def validate_git_commit_receipt(receipt_path: Path) -> dict[str, Any]:
    failures: list[str] = []
    receipt = _safe_read_json(receipt_path, failures, "Git commit receipt")
    if not isinstance(receipt, dict):
        return _receipt_validation_report(receipt_path, failures or ["Git commit receipt must be a JSON object"])
    if receipt.get("schema_version") != RECEIPT_SCHEMA:
        failures.append(f"schema_version must be {RECEIPT_SCHEMA}")
    if receipt.get("receipt_scope") != "git_commit_only":
        failures.append("receipt_scope must be git_commit_only")
    if not _text(receipt.get("commit_id")):
        failures.append("commit_id must be a non-empty string")
    if not _text(receipt.get("commit_message")):
        failures.append("commit_message must be a non-empty string")
    _validate_commit_receipt_action_boundary(receipt, failures)
    _validate_h3_boundary(receipt, failures)

    authorization_ref = _as_ref(
        receipt.get("source_git_publication_authorization"),
        failures,
        "source_git_publication_authorization",
    )
    authorization_path = _validate_ref_bytes(authorization_ref, failures, "source_git_publication_authorization")
    authorization = _safe_read_json(authorization_path, failures, "Git publication authorization")
    if not isinstance(authorization, dict):
        authorization = {}
    source_receipt = _load_static_authorization_context(authorization, failures)
    if receipt.get("request_id") != authorization.get("request_id"):
        failures.append("request_id must match Git publication authorization")
    if receipt.get("source_post_apply_receipt") != authorization.get("source_post_apply_receipt"):
        failures.append("source_post_apply_receipt must match Git publication authorization")
    if receipt.get("source_patch_proposal") != authorization.get("source_patch_proposal"):
        failures.append("source_patch_proposal must match Git publication authorization")
    if receipt.get("commit_message") != authorization.get("commit_message"):
        failures.append("commit_message must match Git publication authorization")

    target_paths = _string_list(source_receipt.get("applied_target_paths"))
    if receipt.get("staged_target_paths") != target_paths:
        failures.append("staged_target_paths must match post-source-apply applied_target_paths")
    if receipt.get("committed_target_paths") != target_paths:
        failures.append("committed_target_paths must match post-source-apply applied_target_paths")

    target_repo = _as_dict(receipt.get("target_repo"), failures, "target_repo")
    repo = _repo_path(target_repo.get("repo_root"), failures)
    before = target_repo.get("before")
    if before != authorization.get("target_repo", {}).get("after"):
        failures.append("target_repo.before must match Git publication authorization target_repo.after")
    if before != source_receipt.get("target_repo", {}).get("after"):
        failures.append("target_repo.before must match post-source-apply target_repo.after")
    after = target_repo.get("after")
    snapshot = _repo_snapshot(repo, failures) if repo is not None else {}
    if after != snapshot:
        failures.append("target repo snapshot drifted after Git commit receipt")
    if after.get("head_commit") != receipt.get("commit_id"):
        failures.append("target_repo.after.head_commit must match commit_id")
    if after.get("status_short"):
        failures.append("target repo worktree must be clean after Git commit receipt")
    if repo is not None and _text(receipt.get("commit_id")):
        committed_paths = _commit_paths(repo, receipt["commit_id"], failures)
        if receipt.get("committed_target_paths") != committed_paths:
            failures.append("committed_target_paths must match commit tree")
        if _commit_parent(repo, receipt["commit_id"], failures) != _as_dict(before, failures, "target_repo.before").get(
            "head_commit"
        ):
            failures.append("Git commit parent must match target_repo.before.head_commit")
        if _commit_message(repo, receipt["commit_id"], failures) != receipt.get("commit_message"):
            failures.append("Git commit message must match receipt")
    return _receipt_validation_report(receipt_path, failures)


def _load_commit_only_context(
    authorization: dict[str, Any],
    failures: list[str],
    failure_codes: list[str],
) -> dict[str, Any]:
    if authorization.get("allowed_git_actions") != ["commit"]:
        failures.append("Git commit executor requires commit-only publication authorization")
        _append_code(failure_codes, "git_commit_authorization_not_commit_only")
    if authorization.get("commit_allowed") is not True:
        failures.append("Git commit executor requires commit_allowed=true")
        _append_code(failure_codes, "git_commit_not_authorized")
    return _load_static_authorization_context(authorization, failures)


def _load_static_authorization_context(authorization: dict[str, Any], failures: list[str]) -> dict[str, Any]:
    if authorization.get("schema_version") != AUTHORIZATION_SCHEMA:
        failures.append(f"Git publication authorization schema_version must be {AUTHORIZATION_SCHEMA}")
    if authorization.get("authorization_scope") != "git_publication_actions_only":
        failures.append("Git publication authorization scope must be git_publication_actions_only")
    if authorization.get("allowed_git_actions") != ["commit"]:
        failures.append("Git commit receipt requires commit-only publication authorization")
    if authorization.get("git_actions_performed") != {"commit": False, "merge": False, "push": False}:
        failures.append("Git publication authorization must not claim Git actions performed")
    if authorization.get("commit_allowed") is not True:
        failures.append("Git publication authorization commit_allowed must be true")
    if authorization.get("push_allowed") is not False or authorization.get("merge_allowed") is not False:
        failures.append("Git publication authorization push_allowed and merge_allowed must be false")
    source_ref = _as_ref(authorization.get("source_post_apply_receipt"), failures, "source_post_apply_receipt")
    source_path = _validate_ref_bytes(source_ref, failures, "source_post_apply_receipt")
    source_receipt = _safe_read_json(source_path, failures, "post-source-apply receipt")
    if not isinstance(source_receipt, dict):
        return {}
    if source_receipt.get("schema_version") != SOURCE_APPLY_RECEIPT_SCHEMA:
        failures.append(f"post-source-apply receipt schema_version must be {SOURCE_APPLY_RECEIPT_SCHEMA}")
    if source_receipt.get("source_repo_apply_performed") is not True:
        failures.append("post-source-apply receipt must prove source repo apply performed")
    if source_receipt.get("tests_passed") is not True or source_receipt.get("test_evidence_status") != "passed":
        failures.append("post-source-apply receipt must prove passed tests")
    if not isinstance(source_receipt.get("applied_target_paths"), list) or not source_receipt["applied_target_paths"]:
        failures.append("post-source-apply receipt applied_target_paths must be a non-empty list")
    return source_receipt


def _write_commit_receipt(
    *,
    receipt_path: Path,
    authorization_path: Path,
    authorization: dict[str, Any],
    source_receipt: dict[str, Any],
    before: dict[str, str],
    after: dict[str, str],
    staged_paths: list[str],
    committed_paths: list[str],
    commit_id: str,
) -> None:
    receipt = {
        "schema_version": RECEIPT_SCHEMA,
        "recorded_at": _now(),
        "request_id": authorization.get("request_id"),
        "receipt_scope": "git_commit_only",
        "source_git_publication_authorization": _artifact_ref(authorization_path),
        "source_post_apply_receipt": authorization["source_post_apply_receipt"],
        "source_patch_proposal": authorization["source_patch_proposal"],
        "target_repo": {
            "repo_root": authorization["target_repo"]["repo_root"],
            "before": before,
            "after": after,
        },
        "staged_target_paths": staged_paths,
        "committed_target_paths": committed_paths,
        "commit_id": commit_id,
        "commit_message": authorization["commit_message"],
        "source_apply_target_paths": source_receipt["applied_target_paths"],
        "git_actions_performed": {"commit": True, "push": False, "merge": False},
        "push_allowed": False,
        "merge_allowed": False,
        "deploy_allowed": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
        "h3_boundary": _h3_boundary(),
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(receipt_path, receipt)


def _authorization_refusal_report(authorization_path: Path, validation: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": EXECUTION_SCHEMA,
        "passed": False,
        "commit_status": "authorization_refused",
        "failure_reasons": [
            f"Git publication authorization failed validation: {reason}"
            for reason in validation.get("failure_reasons", [])
        ],
        "failure_codes": ["git_publication_authorization_refused"],
        "checked_at": _now(),
        "source_git_publication_authorization": _artifact_ref_or_path(authorization_path),
        "source_git_publication_authorization_validation": validation,
        "source_post_apply_receipt": None,
        "target_repo": None,
        "staged_target_paths": [],
        "committed_target_paths": [],
        "stage": None,
        "commit": None,
        "commit_id": None,
        "commit_receipt_path": None,
        "receipt_validation": None,
        "git_actions_performed": {"commit": False, "push": False, "merge": False},
        "push_allowed": False,
        "merge_allowed": False,
        "deploy_allowed": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
        "h3_boundary": _h3_boundary(),
        "non_claims": list(NON_CLAIMS),
    }


def _validate_commit_receipt_action_boundary(payload: dict[str, Any], failures: list[str]) -> None:
    if payload.get("git_actions_performed") != {"commit": True, "merge": False, "push": False}:
        failures.append("git_actions_performed must prove commit only")
    for flag in (
        "push_allowed",
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


def _repo_from_authorization(authorization: dict[str, Any], failures: list[str]) -> Path | None:
    target_repo = _as_dict(authorization.get("target_repo"), failures, "target_repo")
    return _repo_path(target_repo.get("repo_root"), failures)


def _repo_path(value: Any, failures: list[str]) -> Path | None:
    text = _text(value)
    if not text:
        failures.append("target_repo.repo_root must be a non-empty string")
        return None
    repo = Path(text)
    result = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        cwd=repo,
        check=False,
        text=True,
        capture_output=True,
    )
    if result.returncode != 0:
        failures.append(f"target_repo.repo_root must be a Git worktree: {repo}")
        return None
    return Path(result.stdout.strip()).resolve()


def _repo_snapshot(repo: Path, failures: list[str]) -> dict[str, str]:
    return {
        "head_commit": _git_text(repo, failures, "rev-parse", "HEAD").strip(),
        "status_short": _git_text(repo, failures, "status", "--short"),
    }


def _commit_paths(repo: Path, commit_id: str | None, failures: list[str]) -> list[str]:
    if not commit_id:
        return []
    return _git_lines(repo, failures, "diff-tree", "--root", "--no-commit-id", "--name-only", "-r", commit_id)


def _commit_parent(repo: Path, commit_id: str, failures: list[str]) -> str:
    parts = _git_text(repo, failures, "rev-list", "--parents", "-n", "1", commit_id).split()
    return parts[1] if len(parts) > 1 else ""


def _commit_message(repo: Path, commit_id: str, failures: list[str]) -> str:
    return _git_text(repo, failures, "log", "-1", "--format=%B", commit_id).strip()


def _git_lines(repo: Path, failures: list[str], *args: str) -> list[str]:
    return [line for line in _git_text(repo, failures, *args).splitlines() if line]


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
    path_text = _text(ref.get("path"))
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
    except Exception as exc:  # noqa: BLE001 - validation needs the artifact error.
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


def _string_list(value: Any) -> list[str]:
    return [item for item in value if isinstance(item, str)] if isinstance(value, list) else []


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _append_code(codes: list[str], code: str) -> None:
    if code not in codes:
        codes.append(code)


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


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


if __name__ == "__main__":
    sys.exit(main())
