#!/usr/bin/env python3
"""Preflight and execute one Beta-5 GitHub PR merge from post-review authorization.

Beta-5 authorization is not a merge receipt. This gate consumes one valid
post-review authorization, re-reads the live GitHub PR state, checks the PR is
still open, ready, approved, head/base-bound, and mergeable, then writes either
a refusal/preflight report or an explicit merge receipt. It never deploys,
executes production runtime actions, or writes production receipts.
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

from beta5_post_review_merge_authorization import AUTHORIZATION_SCHEMA as BETA5_AUTHORIZATION_SCHEMA
from beta5_post_review_merge_authorization import validate_post_review_merge_authorization


PREFLIGHT_SCHEMA = "beta5-github-merge-preflight-report:v1"
EXECUTION_SCHEMA = "beta5-github-merge-execution-report:v1"
RECEIPT_SCHEMA = "beta5-github-merge-receipt:v1"
RECEIPT_VALIDATION_SCHEMA = "beta5-github-merge-receipt-validation:v1"
PR_VIEW_FIELDS = (
    "number,url,isDraft,state,headRefName,headRefOid,baseRefName,title,author,"
    "reviewDecision,reviews,latestReviews,statusCheckRollup,mergeStateStatus,mergedAt,mergedBy,mergeCommit"
)
ALLOWED_PREFLIGHT_MERGE_STATES = {"CLEAN"}
NON_CLAIMS = (
    "beta5_github_merge_executor_is_l1_controlled_pilot_only",
    "beta5_github_merge_executor_requires_valid_beta5_authorization",
    "beta5_github_merge_executor_rechecks_live_github_pr_state_before_merge",
    "beta5_github_merge_executor_requires_explicit_operator_confirmation",
    "beta5_github_merge_executor_does_not_deploy",
    "beta5_github_merge_executor_does_not_claim_h3_production_readiness",
    "beta5_github_merge_executor_does_not_write_production_receipts",
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    preflight = subparsers.add_parser("preflight", help="re-check current GitHub PR merge readiness")
    preflight.add_argument("--authorization", required=True)
    preflight.add_argument("--output", required=True)

    merge = subparsers.add_parser("merge", help="execute one explicitly confirmed GitHub PR merge")
    merge.add_argument("--authorization", required=True)
    merge.add_argument("--output-root", required=True)
    merge.add_argument("--merge-method", choices=("merge", "squash", "rebase"), default="merge")
    merge.add_argument("--operator-merge-confirmed", action="store_true")

    validate_receipt = subparsers.add_parser("validate-receipt", help="validate a Beta-5 GitHub merge receipt")
    validate_receipt.add_argument("--receipt", required=True)
    validate_receipt.add_argument("--output")

    args = parser.parse_args(argv)
    if args.command == "preflight":
        report = run_merge_preflight(authorization_path=Path(args.authorization))
        _write_json(Path(args.output), report)
    elif args.command == "merge":
        report = run_github_merge(
            authorization_path=Path(args.authorization),
            output_root=Path(args.output_root),
            merge_method=args.merge_method,
            operator_merge_confirmed=bool(args.operator_merge_confirmed),
        )
    elif args.command == "validate-receipt":
        report = validate_github_merge_receipt(Path(args.receipt))
        if args.output:
            _write_json(Path(args.output), report)
    else:
        raise AssertionError(f"unknown command: {args.command}")
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    passed = report.get("passed", report.get("receipt_validation", report).get("passed", False))
    return 0 if passed else 1


def run_merge_preflight(*, authorization_path: Path) -> dict[str, Any]:
    failures: list[str] = []
    authorization = _load_authorization(authorization_path, failures)
    current_view: dict[str, Any] = {}
    gh_view: dict[str, Any] | None = None
    if not failures:
        gh_view = _gh(
            failures,
            "pr",
            "view",
            str(_pr_number(authorization)),
            "--repo",
            _required_text(authorization.get("github_repo"), failures, "github_repo"),
            "--json",
            PR_VIEW_FIELDS,
        )
        if gh_view["returncode"] == 0:
            current_view = _parse_object(gh_view.get("stdout"), failures, "gh pr view JSON")
            _validate_live_pr_state(authorization, current_view, failures)
    return _preflight_report(
        authorization_path=authorization_path,
        authorization=authorization,
        current_view=current_view,
        gh_view=gh_view,
        failures=failures,
    )


def run_github_merge(
    *,
    authorization_path: Path,
    output_root: Path,
    merge_method: str,
    operator_merge_confirmed: bool,
) -> dict[str, Any]:
    output_root = output_root.resolve()
    output_root.mkdir(parents=True, exist_ok=True)
    preflight = run_merge_preflight(authorization_path=authorization_path)
    if preflight["passed"] is not True:
        report = _execution_refusal_report(preflight, ["github_merge_preflight_failed"])
        _write_json(output_root / "beta5_github_merge_execution_report.json", report)
        return report
    if operator_merge_confirmed is not True:
        report = _execution_refusal_report(preflight, ["operator_merge_confirmation_missing"])
        _write_json(output_root / "beta5_github_merge_execution_report.json", report)
        return report

    authorization = _read_json_object(authorization_path)
    pr_number = str(_pr_number(authorization))
    repo = _required_text(authorization.get("github_repo"), [], "github_repo")
    method_flag = f"--{merge_method}"
    gh_merge = _gh(
        [],
        "pr",
        "merge",
        pr_number,
        "--repo",
        repo,
        method_flag,
        "--match-head-commit",
        str(authorization["source_commit_id"]),
    )
    post_view_run = _gh(
        [],
        "pr",
        "view",
        pr_number,
        "--repo",
        repo,
        "--json",
        PR_VIEW_FIELDS,
    )
    post_view = _parse_object(post_view_run.get("stdout"), [], "post-merge gh pr view JSON") if post_view_run["returncode"] == 0 else {}
    failures: list[str] = []
    if gh_merge["returncode"] != 0:
        failures.append("gh pr merge failed")
    if post_view_run["returncode"] != 0:
        failures.append("post-merge gh pr view failed")
    if post_view and post_view.get("state") != "MERGED":
        failures.append("post-merge PR state must be MERGED")
    if post_view and not _text(post_view.get("mergedAt")):
        failures.append("post-merge PR mergedAt must be present")
    receipt_path = output_root / "beta5_github_merge_receipt.json"
    receipt_written = False
    receipt_validation: dict[str, Any] | None = None
    if not failures:
        _write_github_merge_receipt(
            path=receipt_path,
            authorization_path=authorization_path,
            preflight=preflight,
            gh_merge=gh_merge,
            post_view_run=post_view_run,
            post_view=post_view,
            merge_method=merge_method,
        )
        receipt_written = True
        receipt_validation = validate_github_merge_receipt(receipt_path)
        if receipt_validation["passed"] is not True:
            failures.extend(f"receipt invalid: {reason}" for reason in receipt_validation["failure_reasons"])

    report = {
        "schema_version": EXECUTION_SCHEMA,
        "passed": not failures,
        "failure_reasons": failures,
        "failure_codes": [] if not failures else ["github_merge_execution_failed"],
        "checked_at": _now(),
        "merge_method": merge_method,
        "source_merge_preflight": preflight,
        "gh_merge": gh_merge,
        "post_merge_gh_view": post_view_run,
        "post_merge_pr": post_view,
        "receipt_written": receipt_written,
        "receipt_path": str(receipt_path) if receipt_written else None,
        "receipt_sha256": _sha256(receipt_path) if receipt_written else None,
        "receipt_validation": receipt_validation,
        "deploy_allowed": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
        "h3_boundary": _h3_boundary(),
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(output_root / "beta5_github_merge_execution_report.json", report)
    return report


def validate_github_merge_receipt(path: Path) -> dict[str, Any]:
    failures: list[str] = []
    receipt = _safe_read_json(path, failures, "GitHub merge receipt")
    if not isinstance(receipt, dict):
        return _receipt_validation_report(path, failures or ["GitHub merge receipt must be an object"])
    if receipt.get("schema_version") != RECEIPT_SCHEMA:
        failures.append(f"schema_version must be {RECEIPT_SCHEMA}")
    if receipt.get("receipt_scope") != "github_post_review_merge_receipt_only":
        failures.append("receipt_scope must be github_post_review_merge_receipt_only")
    auth_ref = _as_ref(receipt.get("source_beta5_merge_authorization"), failures, "source_beta5_merge_authorization")
    auth_path = _validate_ref_bytes(auth_ref, failures, "source_beta5_merge_authorization")
    preflight = _as_dict(receipt.get("source_merge_preflight"), failures, "source_merge_preflight")
    authorization = _load_authorization(auth_path, failures)
    if preflight.get("passed") is not True:
        failures.append("source_merge_preflight.passed must be true")
    if authorization and preflight.get("authorization_sha256") != _sha256(auth_path):
        failures.append("source_merge_preflight must bind the same Beta-5 authorization")
    for field in ("request_id", "github_repo", "source_commit_id", "source_branch", "base_branch"):
        if receipt.get(field) != authorization.get(field):
            failures.append(f"{field} must match Beta-5 authorization")
    if receipt.get("merge_performed") is not True:
        failures.append("merge_performed must be true")
    if receipt.get("deploy_allowed") is not False:
        failures.append("deploy_allowed must be false")
    if receipt.get("production_runtime_execution_allowed") is not False:
        failures.append("production_runtime_execution_allowed must be false")
    if receipt.get("production_receipt_write_allowed") is not False:
        failures.append("production_receipt_write_allowed must be false")
    if receipt.get("git_actions_performed") != {"commit": True, "push": True, "merge": True}:
        failures.append("git_actions_performed must prove commit, push, and merge")
    if receipt.get("h3_boundary") != _h3_boundary():
        failures.append("h3_boundary must keep production readiness blocked")
    post_view = _as_dict(receipt.get("post_merge_pr"), failures, "post_merge_pr")
    if post_view.get("state") != "MERGED":
        failures.append("post_merge_pr.state must be MERGED")
    if not _text(post_view.get("mergedAt")):
        failures.append("post_merge_pr.mergedAt must be present")
    return _receipt_validation_report(path, failures)


def _load_authorization(path: Path | None, failures: list[str]) -> dict[str, Any]:
    if path is None:
        return {}
    validation = validate_post_review_merge_authorization(path)
    if validation.get("passed") is not True:
        failures.extend(f"Beta-5 authorization invalid: {reason}" for reason in validation.get("failure_reasons", []))
    authorization = _safe_read_json(path, failures, "Beta-5 authorization")
    if not isinstance(authorization, dict):
        return {}
    if authorization.get("schema_version") != BETA5_AUTHORIZATION_SCHEMA:
        failures.append(f"Beta-5 authorization schema_version must be {BETA5_AUTHORIZATION_SCHEMA}")
    return authorization


def _validate_live_pr_state(authorization: dict[str, Any], view: dict[str, Any], failures: list[str]) -> None:
    expected = {
        "number": _pr_number(authorization),
        "url": _as_dict(authorization.get("pr"), failures, "authorization.pr").get("url"),
        "isDraft": False,
        "state": "OPEN",
        "headRefName": authorization.get("source_branch"),
        "headRefOid": authorization.get("source_commit_id"),
        "baseRefName": authorization.get("base_branch"),
        "title": _as_dict(authorization.get("pr"), failures, "authorization.pr").get("title"),
    }
    for field, value in expected.items():
        if view.get(field) != value:
            failures.append(f"github_pr.{field} must match Beta-5 authorization")
    if _text(view.get("reviewDecision")).upper() != "APPROVED":
        failures.append("github_pr.reviewDecision must still be APPROVED")
    if _text(view.get("mergeStateStatus")).upper() not in ALLOWED_PREFLIGHT_MERGE_STATES:
        failures.append("github_pr.mergeStateStatus must be CLEAN before merge")
    expected_approvers = set(_as_list(_as_dict(authorization.get("review_observation"), failures, "review_observation").get("approvers"), failures, "review_observation.approvers"))
    current_approvers = set(_approved_reviewers(view, failures))
    if not expected_approvers:
        failures.append("Beta-5 authorization must include approver evidence")
    elif not expected_approvers.intersection(current_approvers):
        failures.append("at least one authorized approver must still appear in current GitHub approval reviews")


def _preflight_report(
    *,
    authorization_path: Path,
    authorization: dict[str, Any],
    current_view: dict[str, Any],
    gh_view: dict[str, Any] | None,
    failures: list[str],
) -> dict[str, Any]:
    return {
        "schema_version": PREFLIGHT_SCHEMA,
        "passed": not failures,
        "failure_reasons": failures,
        "checked_at": _now(),
        "authorization_path": str(authorization_path.resolve()),
        "authorization_sha256": _sha256(authorization_path) if authorization_path.is_file() else None,
        "request_id": authorization.get("request_id"),
        "github_repo": authorization.get("github_repo"),
        "pr_number": _pr_number_or_none(authorization),
        "current_pr": current_view,
        "gh_view": gh_view,
        "merge_allowed_by_preflight": not failures,
        "deploy_allowed": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
        "h3_boundary": _h3_boundary(),
        "non_claims": list(NON_CLAIMS),
    }


def _write_github_merge_receipt(
    *,
    path: Path,
    authorization_path: Path,
    preflight: dict[str, Any],
    gh_merge: dict[str, Any],
    post_view_run: dict[str, Any],
    post_view: dict[str, Any],
    merge_method: str,
) -> None:
    authorization = _read_json_object(authorization_path)
    receipt = {
        "schema_version": RECEIPT_SCHEMA,
        "recorded_at": _now(),
        "receipt_scope": "github_post_review_merge_receipt_only",
        "request_id": authorization.get("request_id"),
        "source_beta5_merge_authorization": _artifact_ref(authorization_path),
        "source_merge_preflight": preflight,
        "github_repo": authorization.get("github_repo"),
        "pr_number": _pr_number(authorization),
        "source_commit_id": authorization.get("source_commit_id"),
        "source_branch": authorization.get("source_branch"),
        "base_branch": authorization.get("base_branch"),
        "merge_method": merge_method,
        "gh_merge": gh_merge,
        "post_merge_gh_view": post_view_run,
        "post_merge_pr": post_view,
        "merge_performed": True,
        "git_actions_performed": {"commit": True, "push": True, "merge": True},
        "deploy_allowed": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
        "h3_boundary": _h3_boundary(),
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(path, receipt)


def _execution_refusal_report(preflight: dict[str, Any], failure_codes: list[str]) -> dict[str, Any]:
    return {
        "schema_version": EXECUTION_SCHEMA,
        "passed": False,
        "failure_reasons": preflight.get("failure_reasons", []) if failure_codes == ["github_merge_preflight_failed"] else ["operator merge confirmation missing"],
        "failure_codes": failure_codes,
        "checked_at": _now(),
        "source_merge_preflight": preflight,
        "receipt_written": False,
        "receipt_path": None,
        "deploy_allowed": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
        "h3_boundary": _h3_boundary(),
        "non_claims": list(NON_CLAIMS),
    }


def _approved_reviewers(view: dict[str, Any], failures: list[str]) -> list[str]:
    reviewers = set()
    for collection_name in ("reviews", "latestReviews"):
        for review in _as_list(view.get(collection_name), failures, f"github_pr.{collection_name}"):
            if isinstance(review, dict) and _text(review.get("state")).upper() == "APPROVED":
                login = _text(_as_plain_dict(review.get("author")).get("login"))
                if login:
                    reviewers.add(login)
    return sorted(reviewers)


def _pr_number(authorization: dict[str, Any]) -> int:
    number = _pr_number_or_none(authorization)
    if number is None:
        raise ValueError("Beta-5 authorization PR number missing")
    return number


def _pr_number_or_none(authorization: dict[str, Any]) -> int | None:
    pr = authorization.get("pr")
    if isinstance(pr, dict) and isinstance(pr.get("number"), int) and pr["number"] > 0:
        return pr["number"]
    return None


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
    return _as_dict(value, failures, label)


def _as_dict(value: Any, failures: list[str], label: str) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    failures.append(f"{label} must be an object")
    return {}


def _as_plain_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any, failures: list[str], label: str) -> list[Any]:
    if isinstance(value, list):
        return value
    failures.append(f"{label} must be a list")
    return []


def _safe_read_json(path: Path | None, failures: list[str], label: str) -> Any:
    if path is None:
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 - validators preserve artifact detail.
        failures.append(f"{label} could not be read: {exc}")
        return None
    if not isinstance(payload, dict):
        failures.append(f"{label} must be a JSON object")
        return None
    return payload


def _read_json_object(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"expected JSON object: {path}")
    return payload


def _parse_object(text: Any, failures: list[str], label: str) -> dict[str, Any]:
    try:
        payload = json.loads(text if isinstance(text, str) else "")
    except json.JSONDecodeError as exc:
        failures.append(f"{label} could not be parsed: {exc}")
        return {}
    if not isinstance(payload, dict):
        failures.append(f"{label} must be an object")
        return {}
    return payload


def _required_text(value: Any, failures: list[str], label: str) -> str:
    text = _text(value)
    if not text:
        failures.append(f"{label} must be a non-empty string")
    return text


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _gh(failures: list[str], *args: str) -> dict[str, Any]:
    command = ["gh", *args]
    try:
        completed = subprocess.run(command, check=False, capture_output=True, text=True)
    except FileNotFoundError:
        failures.append("gh command not found")
        return {"command": " ".join(command), "returncode": 127, "stdout": "", "stderr": "gh command not found"}
    result = {
        "command": " ".join(command),
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }
    if completed.returncode != 0:
        failures.append(f"gh command failed: {result['command']}")
    return result


def _h3_boundary() -> dict[str, bool]:
    return {
        "h3_remains_blocked": True,
        "h3_production_readiness_claimed": False,
    }


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


if __name__ == "__main__":
    sys.exit(main())
