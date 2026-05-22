#!/usr/bin/env python3
"""Apply a Beta-3 candidate patch only inside an isolated Git worktree.

This gate consumes an already-validated Beta-3 candidate report, reconstructs
the proposal commit in a detached worktree, records sandbox apply/test evidence,
and removes the worktree again. It never applies the patch to the source repo
worktree, commits, pushes, merges, deploys, or writes production receipts.
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

from beta3_controlled_apply_candidate import SCHEMA_VERSION as CANDIDATE_SCHEMA
from beta3_controlled_apply_candidate import evaluate_candidate


SCHEMA_VERSION = "beta3-controlled-apply-sandbox:v1"
NON_CLAIMS = (
    "beta3_sandbox_apply_is_l1_controlled_pilot_only",
    "beta3_sandbox_apply_does_not_apply_patch_to_source_repo_worktree",
    "beta3_sandbox_apply_does_not_authorize_commit_push_merge_or_deploy",
    "beta3_sandbox_apply_does_not_claim_h3_production_readiness",
    "beta3_sandbox_apply_does_not_write_production_receipts",
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-report", required=True)
    parser.add_argument("--output-root", required=True)
    parser.add_argument(
        "--test-command",
        action="append",
        default=[],
        help="Optional shell command run only inside the applied sandbox. Repeatable.",
    )
    args = parser.parse_args(argv)

    report = run_sandbox_apply(
        candidate_report_path=Path(args.candidate_report),
        output_root=Path(args.output_root),
        test_commands=args.test_command,
    )
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report["passed"] else 1


def run_sandbox_apply(
    *,
    candidate_report_path: Path,
    output_root: Path,
    test_commands: list[str] | None = None,
) -> dict[str, Any]:
    output_root = output_root.resolve()
    output_root.mkdir(parents=True, exist_ok=True)
    failures: list[str] = []
    failure_codes: list[str] = []
    candidate = _read_json_object(candidate_report_path, failures, "candidate report")
    candidate_recheck = _recheck_candidate(candidate, failures)
    run_root = Path(candidate.get("run_root", "")) if isinstance(candidate, dict) else Path()
    patch_validation = _read_json_object(
        run_root / "beta2_patch_proposal_validation.json",
        failures,
        "Beta-2 patch validation",
    )
    request = _read_json_object(Path(patch_validation.get("request_path", "")), failures, "proposal request")
    repo_root, patch_path, source_commit = _load_source_inputs(patch_validation, request, failures)

    applied_diff_path = output_root / "sandbox_applied_diff.patch"
    source_before = _repo_snapshot(repo_root) if repo_root else None
    apply_check: dict[str, Any] | None = None
    apply_run: dict[str, Any] | None = None
    test_runs: list[dict[str, Any]] = []
    cleanup: dict[str, Any] | None = None
    worktree_add: dict[str, Any] | None = None
    worktree_added = False
    worktree_path = output_root / "sandbox_worktree"

    if not failures and worktree_path.exists():
        failures.append(f"sandbox worktree path must not already exist: {worktree_path}")
        _append_code(failure_codes, "sandbox_worktree_path_conflict")
    if not failures and repo_root and source_commit and patch_path:
        worktree_add = _git(repo_root, "worktree", "add", "--detach", str(worktree_path), source_commit)
        if worktree_add["returncode"] != 0:
            failures.append("sandbox worktree creation failed")
            _append_code(failure_codes, "sandbox_worktree_create_failed")
        else:
            worktree_added = True
            apply_check = _git(worktree_path, "apply", "--check", str(patch_path))
            if apply_check["returncode"] != 0:
                failures.append("sandbox git apply --check failed")
                _append_code(failure_codes, "sandbox_apply_check_refused")
            else:
                apply_run = _git(worktree_path, "apply", str(patch_path))
                if apply_run["returncode"] != 0:
                    failures.append("sandbox git apply failed")
                    _append_code(failure_codes, "sandbox_apply_failed")
                else:
                    applied_diff_path.write_text(_git_text(worktree_path, "diff", "--binary"), encoding="utf-8")
                    test_runs = _run_test_commands(worktree_path, test_commands or [], failures, failure_codes)
    if worktree_added and repo_root:
        cleanup = _git(repo_root, "worktree", "remove", "--force", str(worktree_path))
        if cleanup["returncode"] != 0:
            failures.append("sandbox worktree cleanup failed")
            _append_code(failure_codes, "sandbox_cleanup_failed")

    source_after = _repo_snapshot(repo_root) if repo_root else None
    source_unchanged = source_before == source_after if source_before and source_after else False
    if source_before and source_after and not source_unchanged:
        failures.append("source repo snapshot changed during sandbox gate")
        _append_code(failure_codes, "source_repo_snapshot_changed")
    if failures and not failure_codes:
        _append_code(failure_codes, "sandbox_input_refused")

    report = {
        "schema_version": SCHEMA_VERSION,
        "passed": not failures,
        "sandbox_status": "applied_and_cleaned" if not failures else "blocked",
        "sandbox_outcome": _sandbox_outcome(
            failures=failures,
            failure_codes=failure_codes,
            apply_run=apply_run,
            test_runs=test_runs,
        ),
        "failure_reasons": failures,
        "failure_codes": failure_codes,
        "checked_at": _now(),
        "candidate_report": _artifact_ref(candidate_report_path),
        "candidate_recheck": candidate_recheck,
        "source_patch_validation": _artifact_ref(run_root / "beta2_patch_proposal_validation.json"),
        "source_patch": _artifact_ref(patch_path) if patch_path else None,
        "source_repo": {
            "repo_root": str(repo_root) if repo_root else None,
            "proposal_head_commit": source_commit,
            "before": source_before,
            "after": source_after,
            "worktree_snapshot_unchanged": source_unchanged,
        },
        "sandbox": {
            "output_root": str(output_root),
            "worktree_path": str(worktree_path),
            "worktree_add": worktree_add,
            "worktree_cleaned": worktree_added and cleanup is not None and cleanup["returncode"] == 0,
            "apply_check": apply_check,
            "apply": apply_run,
            "applied_diff": _artifact_ref(applied_diff_path) if applied_diff_path.is_file() else None,
            "tests": test_runs,
            "test_evidence_status": _test_evidence_status(test_runs),
        },
        "operator_followup": _operator_followup(failure_codes),
        "execution_boundary": {
            "sandbox_patch_apply_performed": apply_run is not None and apply_run["returncode"] == 0,
            "source_repo_patch_apply_performed": False,
            "commit_allowed_by_this_gate": False,
            "push_allowed_by_this_gate": False,
            "merge_allowed_by_this_gate": False,
            "deploy_allowed_by_this_gate": False,
            "production_runtime_execution_allowed": False,
            "production_receipt_write_allowed": False,
        },
        "h3_boundary": {
            "h3_remains_blocked": True,
            "h3_production_readiness_claimed": False,
        },
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(output_root / "beta3_controlled_apply_sandbox_report.json", report)
    return report


def _recheck_candidate(candidate: dict[str, Any], failures: list[str]) -> dict[str, Any] | None:
    if candidate.get("schema_version") != CANDIDATE_SCHEMA:
        failures.append(f"candidate report schema_version must be {CANDIDATE_SCHEMA}")
        return None
    if candidate.get("passed") is not True:
        failures.append("candidate report must be passed")
        return None
    selection = candidate.get("operator_selection")
    if not isinstance(selection, dict):
        failures.append("candidate operator_selection must be an object")
        return None
    report = evaluate_candidate(
        run_root=Path(candidate.get("run_root", "")),
        operator_selection_reason=str(selection.get("reason", "")),
        operator_id=str(selection.get("operator_id", "")),
        allow_path_prefixes=_string_list(candidate.get("low_risk_allow_path_prefixes")),
    )
    if report["passed"] is not True:
        failures.extend(f"candidate recheck failed: {reason}" for reason in report["failure_reasons"])
    return report


def _load_source_inputs(
    patch_validation: dict[str, Any],
    request: dict[str, Any],
    failures: list[str],
) -> tuple[Path | None, Path | None, str | None]:
    repo_root = Path(patch_validation.get("repo_root", "")) if patch_validation.get("repo_root") else None
    patch_path = Path(patch_validation.get("patch_path", "")) if patch_validation.get("patch_path") else None
    snapshot = request.get("repo_snapshot")
    if not repo_root or not (repo_root / ".git").exists():
        failures.append("patch validation repo_root must be a Git repository")
        repo_root = None
    if not patch_path or not patch_path.is_file():
        failures.append("patch validation patch_path must exist")
    if not isinstance(snapshot, dict):
        failures.append("proposal request repo_snapshot must be an object")
        return repo_root, patch_path, None
    if str(snapshot.get("status_short", "")).strip():
        failures.append("proposal request repo_snapshot.status_short must be clean for sandbox replay")
    source_commit = snapshot.get("head_commit")
    if not isinstance(source_commit, str) or not source_commit.strip():
        failures.append("proposal request repo_snapshot.head_commit must be present")
        return repo_root, patch_path, None
    return repo_root, patch_path, source_commit


def _run_test_commands(
    worktree: Path,
    commands: list[str],
    failures: list[str],
    failure_codes: list[str],
) -> list[dict[str, Any]]:
    runs: list[dict[str, Any]] = []
    for command in commands:
        run = _command(command, worktree)
        runs.append(run)
        if run["returncode"] != 0:
            failures.append(f"sandbox test command failed: {command}")
            _append_code(failure_codes, "sandbox_test_failed")
    return runs


def _sandbox_outcome(
    *,
    failures: list[str],
    failure_codes: list[str],
    apply_run: dict[str, Any] | None,
    test_runs: list[dict[str, Any]],
) -> str:
    if not failures:
        return "applied_tests_passed" if test_runs else "applied_without_tests"
    if apply_run is not None and apply_run["returncode"] == 0 and "sandbox_test_failed" in failure_codes:
        return "applied_tests_failed"
    if "sandbox_apply_check_refused" in failure_codes:
        return "apply_check_refused"
    if "sandbox_apply_failed" in failure_codes:
        return "apply_failed"
    if "sandbox_worktree_create_failed" in failure_codes:
        return "worktree_create_failed"
    return "blocked_before_verified_apply"


def _test_evidence_status(test_runs: list[dict[str, Any]]) -> str:
    if not test_runs:
        return "not_run"
    if any(run["returncode"] != 0 for run in test_runs):
        return "failed"
    return "passed"


def _operator_followup(failure_codes: list[str]) -> dict[str, Any]:
    test_failure = "sandbox_test_failed" in failure_codes
    return {
        "required": bool(failure_codes),
        "reason_codes": failure_codes,
        "source_apply_must_remain_blocked": bool(failure_codes),
        "sandbox_test_failure_requires_operator_review": test_failure,
    }


def _append_code(codes: list[str], code: str) -> None:
    if code not in codes:
        codes.append(code)


def _read_json_object(path: Path, failures: list[str], label: str) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 - gate report needs readable failure reason.
        failures.append(f"{label} could not be read: {exc}")
        return {}
    if not isinstance(data, dict):
        failures.append(f"{label} must be a JSON object")
        return {}
    return data


def _repo_snapshot(repo: Path) -> dict[str, str]:
    return {
        "head_commit": _git_text(repo, "rev-parse", "HEAD").strip(),
        "status_short": _git_text(repo, "status", "--short"),
    }


def _git(cwd: Path, *args: str) -> dict[str, Any]:
    return _run(["git", *args], cwd)


def _git_text(cwd: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=cwd, check=True, text=True, capture_output=True).stdout


def _command(command: str, cwd: Path) -> dict[str, Any]:
    result = subprocess.run(command, cwd=cwd, shell=True, text=True, capture_output=True, check=False)
    return _run_report(command, result)


def _run(argv: list[str], cwd: Path) -> dict[str, Any]:
    result = subprocess.run(argv, cwd=cwd, text=True, capture_output=True, check=False)
    return _run_report(" ".join(argv), result)


def _run_report(command: str, result: subprocess.CompletedProcess[str]) -> dict[str, Any]:
    return {
        "command": command,
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


def _artifact_ref(path: Path) -> dict[str, Any]:
    return {
        "path": str(path.resolve()),
        "sha256": _sha256(path) if path.is_file() else None,
    }


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    digest.update(path.read_bytes())
    return digest.hexdigest()


def _string_list(value: Any) -> list[str]:
    return [item for item in value if isinstance(item, str) and item] if isinstance(value, list) else []


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


if __name__ == "__main__":
    sys.exit(main())
