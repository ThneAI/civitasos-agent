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
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from beta_evidence import (
        artifact_ref as _evidence_artifact_ref,
        artifact_ref_or_path as _evidence_artifact_ref_or_path,
        read_json_object,
        write_json,
    )
except ModuleNotFoundError:
    from scripts.beta_evidence import (
        artifact_ref as _evidence_artifact_ref,
        artifact_ref_or_path as _evidence_artifact_ref_or_path,
        read_json_object,
        write_json,
    )

try:
    from beta3_source_apply_boundaries import (
        NON_CLAIMS,
        h3_boundary as _h3_boundary,
        source_apply_operator_followup as _source_apply_operator_followup,
        source_apply_outcome as _source_apply_outcome,
        test_evidence_status as _test_evidence_status,
    )
except ModuleNotFoundError:
    from scripts.beta3_source_apply_boundaries import (
        NON_CLAIMS,
        h3_boundary as _h3_boundary,
        source_apply_operator_followup as _source_apply_operator_followup,
        source_apply_outcome as _source_apply_outcome,
        test_evidence_status as _test_evidence_status,
    )

try:
    from beta3_source_apply_authorization import validate_source_apply_authorization
    from beta3_source_apply_receipts import (
        RECEIPT_SCHEMA,
        validate_post_source_apply_receipt,
        write_post_apply_receipt,
    )
    from beta3_source_apply_worktree import (
        append_code as _append_code,
        git as _git,
        git_text as _git_text,
        repo_snapshot as _repo_snapshot,
        run_test_commands as _run_test_commands,
    )
except ModuleNotFoundError:
    from scripts.beta3_source_apply_authorization import (
        validate_source_apply_authorization,
    )
    from scripts.beta3_source_apply_receipts import (
        RECEIPT_SCHEMA,
        validate_post_source_apply_receipt,
        write_post_apply_receipt,
    )
    from scripts.beta3_source_apply_worktree import (
        append_code as _append_code,
        git as _git,
        git_text as _git_text,
        repo_snapshot as _repo_snapshot,
        run_test_commands as _run_test_commands,
    )


EXECUTION_SCHEMA = "beta3-source-apply-execution-report:v1"


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
        write_post_apply_receipt(
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


def _validate_ref_path(ref: dict[str, Any], label: str) -> Path:
    path = Path(str(ref.get("path") or ""))
    if not path.is_file():
        raise FileNotFoundError(f"{label}.path is not a file: {path}")
    return path


def _artifact_ref(path: Path) -> dict[str, str]:
    return _evidence_artifact_ref(path)


def _artifact_ref_or_path(path: Path) -> dict[str, str | None]:
    return _evidence_artifact_ref_or_path(path)


def _read_json_object(path: Path) -> dict[str, Any]:
    return read_json_object(path)


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    write_json(path, payload)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


if __name__ == "__main__":
    sys.exit(main())
