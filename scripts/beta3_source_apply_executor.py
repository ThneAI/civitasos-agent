#!/usr/bin/env python3
"""Apply an authorized Beta-3 patch to the source worktree and write receipt.

The executor only runs after a still-valid Beta-3 source apply authorization. It
rechecks the authorization, performs git apply on the authorized source
worktree, records applied diff and optional test evidence, and writes a
post-apply receipt. It never commits, pushes, merges, deploys, executes
production runtime actions, or writes production receipts.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from beta_evidence import (
        artifact_ref as _evidence_artifact_ref,
        artifact_ref_or_path as _evidence_artifact_ref_or_path,
        read_json_object,
        safe_read_json_object,
        sha256_file,
        validate_ref_bytes,
        write_json,
    )
except ModuleNotFoundError:
    from scripts.beta_evidence import (
        artifact_ref as _evidence_artifact_ref,
        artifact_ref_or_path as _evidence_artifact_ref_or_path,
        read_json_object,
        safe_read_json_object,
        sha256_file,
        validate_ref_bytes,
        write_json,
    )

try:
    from beta3_source_apply_boundaries import (
        NON_CLAIMS,
        h3_boundary as _h3_boundary,
        source_apply_operator_followup as _source_apply_operator_followup,
        source_apply_outcome as _source_apply_outcome,
        test_evidence_status as _test_evidence_status,
        validate_false_boundary_flags as _validate_false_boundary_flags,
        validate_h3_boundary as _validate_h3_boundary,
    )
except ModuleNotFoundError:
    from scripts.beta3_source_apply_boundaries import (
        NON_CLAIMS,
        h3_boundary as _h3_boundary,
        source_apply_operator_followup as _source_apply_operator_followup,
        source_apply_outcome as _source_apply_outcome,
        test_evidence_status as _test_evidence_status,
        validate_false_boundary_flags as _validate_false_boundary_flags,
        validate_h3_boundary as _validate_h3_boundary,
    )

from beta2_patch_proposal import parse_patch_target_paths
from beta3_source_apply_authorization import AUTHORIZATION_SCHEMA
from beta3_source_apply_authorization import validate_source_apply_authorization


EXECUTION_SCHEMA = "beta3-source-apply-execution-report:v1"
RECEIPT_SCHEMA = "beta3-post-source-apply-receipt:v1"
RECEIPT_VALIDATION_SCHEMA = "beta3-post-source-apply-receipt-validation:v1"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    apply = subparsers.add_parser("apply", help="apply an authorized patch to the source worktree")
    apply.add_argument("--authorization", required=True)
    apply.add_argument("--output-root", required=True)
    apply.add_argument("--test-command", action="append", default=[])

    validate = subparsers.add_parser("validate-receipt", help="validate an existing post-apply receipt")
    validate.add_argument("--receipt", required=True)
    validate.add_argument("--output")

    args = parser.parse_args(argv)
    if args.command == "apply":
        report = run_source_apply(
            authorization_path=Path(args.authorization),
            output_root=Path(args.output_root),
            test_commands=args.test_command,
        )
    elif args.command == "validate-receipt":
        report = validate_post_source_apply_receipt(Path(args.receipt))
        if args.output:
            _write_json(Path(args.output), report)
    else:
        raise AssertionError(f"unknown command: {args.command}")
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report.get("receipt_validation", report).get("passed") and report.get("passed", True) else 1


def run_source_apply(
    *,
    authorization_path: Path,
    output_root: Path,
    test_commands: list[str] | None,
) -> dict[str, Any]:
    output_root = output_root.resolve()
    output_root.mkdir(parents=True, exist_ok=True)
    validation = validate_source_apply_authorization(authorization_path)
    if validation.get("passed") is not True:
        report = _authorization_refusal_report(authorization_path, validation)
        _write_json(output_root / "beta3_source_apply_execution_report.json", report)
        return report
    authorization = _read_json_object(authorization_path)
    repo = Path(authorization["target_repo"]["repo_root"])
    patch_ref = authorization["source_patch_proposal"]
    patch_path = _validate_ref_path(patch_ref, "source_patch_proposal")

    failures: list[str] = []
    failure_codes: list[str] = []
    before = _repo_snapshot(repo, failures)
    apply_check = _git(repo, failures, "apply", "--check", str(patch_path))
    apply_run: dict[str, Any] | None = None
    diff_ref: dict[str, Any] | None = None
    test_runs: list[dict[str, Any]] = []
    if apply_check["returncode"] == 0:
        apply_run = _git(repo, failures, "apply", str(patch_path))
        if apply_run["returncode"] == 0:
            diff_path = output_root / "source_applied_diff.patch"
            diff_path.write_text(_git_text(repo, failures, "diff", "--binary"), encoding="utf-8")
            diff_ref = _artifact_ref(diff_path)
            test_runs = _run_test_commands(repo, test_commands or [], failures, failure_codes)
    after = _repo_snapshot(repo, failures)
    source_apply_performed = apply_run is not None and apply_run["returncode"] == 0
    if apply_check["returncode"] != 0:
        failures.append("source git apply --check failed")
        _append_code(failure_codes, "source_apply_check_refused")
    if apply_run is not None and apply_run["returncode"] != 0:
        failures.append("source git apply failed")
        _append_code(failure_codes, "source_apply_failed")
    if not source_apply_performed:
        failures.append("source worktree apply was not performed")
        _append_code(failure_codes, "source_apply_not_performed")

    receipt_path = output_root / "beta3_post_source_apply_receipt.json"
    receipt_validation = None
    if source_apply_performed and diff_ref is not None:
        _write_post_apply_receipt(
            receipt_path=receipt_path,
            authorization_path=authorization_path,
            authorization=authorization,
            before=before,
            after=after,
            applied_diff=diff_ref,
            test_runs=test_runs,
            tests_passed=not any(run["returncode"] != 0 for run in test_runs),
        )
        receipt_validation = validate_post_source_apply_receipt(receipt_path)
        if receipt_validation["passed"] is not True:
            failures.extend(f"post-apply receipt invalid: {reason}" for reason in receipt_validation["failure_reasons"])
            _append_code(failure_codes, "post_apply_receipt_invalid")
    if failures and not failure_codes:
        _append_code(failure_codes, "source_apply_internal_failure")

    report = {
        "schema_version": EXECUTION_SCHEMA,
        "passed": not failures,
        "apply_status": "applied_with_receipt" if not failures else "blocked_or_failed",
        "source_apply_outcome": _source_apply_outcome(
            source_apply_performed=source_apply_performed,
            failure_codes=failure_codes,
            test_runs=test_runs,
        ),
        "failure_reasons": failures,
        "failure_codes": failure_codes,
        "checked_at": _now(),
        "source_authorization": _artifact_ref(authorization_path),
        "source_authorization_validation": validation,
        "source_patch_proposal": patch_ref,
        "target_repo": {
            "repo_root": str(repo),
            "before": before,
            "after": after,
        },
        "apply_check": apply_check,
        "apply": apply_run,
        "applied_diff": diff_ref,
        "tests": test_runs,
        "test_evidence_status": _test_evidence_status(test_runs),
        "post_apply_receipt_path": str(receipt_path.resolve()) if receipt_path.is_file() else None,
        "receipt_validation": receipt_validation,
        "source_repo_apply_performed": source_apply_performed,
        "operator_followup": _source_apply_operator_followup(failure_codes),
        "commit_allowed": False,
        "push_allowed": False,
        "merge_allowed": False,
        "deploy_allowed": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
        "h3_boundary": _h3_boundary(),
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(output_root / "beta3_source_apply_execution_report.json", report)
    return report


def validate_post_source_apply_receipt(receipt_path: Path) -> dict[str, Any]:
    failures: list[str] = []
    receipt = _safe_read_json(receipt_path, failures, "receipt")
    if not isinstance(receipt, dict):
        return _receipt_validation_report(receipt_path, failures or ["receipt must be a JSON object"])
    if receipt.get("schema_version") != RECEIPT_SCHEMA:
        failures.append(f"schema_version must be {RECEIPT_SCHEMA}")
    if receipt.get("receipt_scope") != "source_worktree_apply_only":
        failures.append("receipt_scope must be source_worktree_apply_only")
    if receipt.get("source_repo_apply_performed") is not True:
        failures.append("source_repo_apply_performed must be true")
    if receipt.get("test_evidence_status") not in {"not_run", "passed", "failed"}:
        failures.append("test_evidence_status must be not_run, passed, or failed")
    _validate_false_boundary_flags(receipt, failures)
    _validate_h3_boundary(receipt, failures)

    authorization_ref = _as_ref(receipt.get("source_authorization"), failures, "source_authorization")
    authorization_path = _validate_ref_bytes(authorization_ref, failures, "source_authorization")
    authorization = _safe_read_json(authorization_path, failures, "source authorization")
    if not isinstance(authorization, dict):
        authorization = {}
    if authorization.get("schema_version") != AUTHORIZATION_SCHEMA:
        failures.append(f"source authorization schema_version must be {AUTHORIZATION_SCHEMA}")
    if authorization.get("source_repo_apply_authorized") is not True:
        failures.append("source authorization must authorize source repo apply")
    if authorization.get("source_repo_apply_performed") is not False:
        failures.append("source authorization must not claim source repo apply performed")
    if receipt.get("request_id") != authorization.get("request_id"):
        failures.append("request_id must match source authorization")
    if receipt.get("source_patch_proposal") != authorization.get("source_patch_proposal"):
        failures.append("source_patch_proposal must match source authorization")

    patch_path = _validate_ref_bytes(
        _as_ref(receipt.get("source_patch_proposal"), failures, "source_patch_proposal"),
        failures,
        "source_patch_proposal",
    )
    if patch_path is not None:
        target_paths = parse_patch_target_paths(patch_path.read_text(encoding="utf-8"))
        if receipt.get("applied_target_paths") != target_paths:
            failures.append("applied_target_paths must match source patch proposal")
        _validate_allowlist(target_paths, authorization.get("allowed_path_prefixes"), failures)
    _validate_ref_bytes(_as_ref(receipt.get("applied_diff"), failures, "applied_diff"), failures, "applied_diff")

    target_repo = _as_dict(receipt.get("target_repo"), failures, "target_repo")
    repo = Path(str(target_repo.get("repo_root") or ""))
    snapshot = _repo_snapshot(repo, failures)
    if target_repo.get("before") != authorization.get("target_repo", {}).get("authorization_snapshot"):
        failures.append("target_repo.before must match authorization snapshot")
    if target_repo.get("after") != snapshot:
        failures.append("target repo snapshot drifted after post-apply receipt")
    if target_repo.get("after", {}).get("head_commit") != authorization.get("target_repo", {}).get(
        "expected_head_commit"
    ):
        failures.append("post-apply HEAD must remain at authorized expected_head_commit")
    tests = receipt.get("tests")
    if not isinstance(tests, list):
        failures.append("tests must be a list")
    elif receipt.get("tests_passed") is True and any(
        not isinstance(run, dict) or run.get("returncode") != 0 for run in tests
    ):
        failures.append("tests_passed receipt requires all test returncodes to be zero")
    elif receipt.get("test_evidence_status") != _test_evidence_status([run for run in tests if isinstance(run, dict)]):
        failures.append("test_evidence_status must match tests")
    return _receipt_validation_report(receipt_path, failures)


def _write_post_apply_receipt(
    *,
    receipt_path: Path,
    authorization_path: Path,
    authorization: dict[str, Any],
    before: dict[str, str],
    after: dict[str, str],
    applied_diff: dict[str, str],
    test_runs: list[dict[str, Any]],
    tests_passed: bool,
) -> None:
    patch_path = _validate_ref_path(authorization["source_patch_proposal"], "source_patch_proposal")
    receipt = {
        "schema_version": RECEIPT_SCHEMA,
        "recorded_at": _now(),
        "request_id": authorization.get("request_id"),
        "receipt_scope": "source_worktree_apply_only",
        "source_authorization": _artifact_ref(authorization_path),
        "source_patch_proposal": authorization["source_patch_proposal"],
        "applied_target_paths": parse_patch_target_paths(patch_path.read_text(encoding="utf-8")),
        "target_repo": {
            "repo_root": authorization["target_repo"]["repo_root"],
            "before": before,
            "after": after,
        },
        "applied_diff": applied_diff,
        "tests": test_runs,
        "tests_passed": tests_passed,
        "test_evidence_status": _test_evidence_status(test_runs),
        "source_repo_apply_performed": True,
        "commit_allowed": False,
        "push_allowed": False,
        "merge_allowed": False,
        "deploy_allowed": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
        "h3_boundary": _h3_boundary(),
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(receipt_path, receipt)


def _run_test_commands(
    repo: Path,
    commands: list[str],
    failures: list[str],
    failure_codes: list[str],
) -> list[dict[str, Any]]:
    runs: list[dict[str, Any]] = []
    for command in commands:
        result = subprocess.run(command, cwd=repo, shell=True, check=False, text=True, capture_output=True)
        run = _command_report(command, result)
        runs.append(run)
        if run["returncode"] != 0:
            failures.append(f"source apply test command failed: {command}")
            _append_code(failure_codes, "post_apply_test_failed")
    return runs


def _authorization_refusal_report(authorization_path: Path, validation: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": EXECUTION_SCHEMA,
        "passed": False,
        "apply_status": "authorization_refused",
        "source_apply_outcome": "authorization_refused",
        "failure_reasons": [
            f"source apply authorization failed validation: {reason}"
            for reason in validation.get("failure_reasons", [])
        ],
        "failure_codes": ["source_apply_authorization_refused"],
        "checked_at": _now(),
        "source_authorization": _artifact_ref_or_path(authorization_path),
        "source_authorization_validation": validation,
        "source_patch_proposal": None,
        "target_repo": None,
        "apply_check": None,
        "apply": None,
        "applied_diff": None,
        "tests": [],
        "test_evidence_status": "not_run",
        "post_apply_receipt_path": None,
        "receipt_validation": None,
        "source_repo_apply_performed": False,
        "operator_followup": _source_apply_operator_followup(["source_apply_authorization_refused"]),
        "commit_allowed": False,
        "push_allowed": False,
        "merge_allowed": False,
        "deploy_allowed": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
        "h3_boundary": _h3_boundary(),
        "non_claims": list(NON_CLAIMS),
    }


def _validate_allowlist(target_paths: list[str], prefixes: Any, failures: list[str]) -> None:
    allowed = [item for item in prefixes if isinstance(item, str)] if isinstance(prefixes, list) else []
    if not allowed:
        failures.append("source authorization allowed_path_prefixes must not be empty")
    for target in target_paths:
        if not any(target.startswith(prefix) if prefix.endswith("/") else target == prefix for prefix in allowed):
            failures.append(f"applied target path is outside authorization allowlist: {target}")


def _repo_snapshot(repo: Path, failures: list[str]) -> dict[str, str]:
    return {
        "head_commit": _git_text(repo, failures, "rev-parse", "HEAD").strip(),
        "status_short": _git_text(repo, failures, "status", "--short"),
    }


def _git(repo: Path, failures: list[str], *args: str) -> dict[str, Any]:
    result = subprocess.run(["git", *args], cwd=repo, check=False, text=True, capture_output=True)
    run = _command_report(" ".join(["git", *args]), result)
    if run["returncode"] != 0:
        failures.append(f"{run['command']} failed")
    return run


def _git_text(repo: Path, failures: list[str], *args: str) -> str:
    run = _git(repo, failures, *args)
    return str(run["stdout"])


def _command_report(command: str, result: subprocess.CompletedProcess[str]) -> dict[str, Any]:
    return {
        "command": command,
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


def _validate_ref_path(ref: dict[str, Any], label: str) -> Path:
    path = Path(str(ref.get("path") or ""))
    if not path.is_file():
        raise FileNotFoundError(f"{label}.path is not a file: {path}")
    return path


def _artifact_ref(path: Path) -> dict[str, str]:
    return _evidence_artifact_ref(path)


def _artifact_ref_or_path(path: Path) -> dict[str, str | None]:
    return _evidence_artifact_ref_or_path(path)


def _append_code(codes: list[str], code: str) -> None:
    if code not in codes:
        codes.append(code)


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


def _validate_ref_bytes(ref: dict[str, Any], failures: list[str], label: str) -> Path | None:
    return validate_ref_bytes(ref, failures, label)


def _safe_read_json(path: Path | None, failures: list[str], label: str) -> Any:
    return safe_read_json_object(path, failures, label)


def _read_json_object(path: Path) -> dict[str, Any]:
    return read_json_object(path)


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
    write_json(path, payload)


def _sha256(path: Path) -> str:
    return sha256_file(path)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


if __name__ == "__main__":
    sys.exit(main())
