#!/usr/bin/env python3
"""Authorize and execute one Beta-4 draft PR -> ready-for-review transition.

GitHub approval can only exist after a PR is ready for review. This gate bridges
the draft-only Beta-4 PR receipt to a ready-for-review PR state with an explicit
operator authorization and a hash-bound receipt. It does not create reviews,
observe approval, merge, deploy, execute production runtime actions, or write
production receipts.
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

from beta4_draft_pr_executor import RECEIPT_SCHEMA as DRAFT_PR_RECEIPT_SCHEMA
from beta4_draft_pr_executor import validate_draft_pr_receipt


AUTHORIZATION_SCHEMA = "beta4-ready-pr-transition-authorization:v1"
AUTHORIZATION_VALIDATION_SCHEMA = "beta4-ready-pr-transition-authorization-validation:v1"
AUTHORIZATION_WRITE_SCHEMA = "beta4-ready-pr-transition-authorization-write-report:v1"
EXECUTION_SCHEMA = "beta4-ready-pr-transition-execution-report:v1"
RECEIPT_SCHEMA = "beta4-ready-pr-transition-receipt:v1"
RECEIPT_VALIDATION_SCHEMA = "beta4-ready-pr-transition-receipt-validation:v1"
PR_VIEW_FIELDS = "number,url,isDraft,state,headRefName,headRefOid,baseRefName,title"
NON_CLAIMS = (
    "beta4_ready_pr_transition_is_l1_controlled_pilot_only",
    "beta4_ready_pr_transition_requires_fresh_operator_authorization",
    "beta4_ready_pr_transition_marks_pr_ready_for_review_only",
    "beta4_ready_pr_transition_does_not_create_or_observe_review_approval",
    "beta4_ready_pr_transition_does_not_merge_or_deploy",
    "beta4_ready_pr_transition_does_not_claim_h3_production_readiness",
    "beta4_ready_pr_transition_does_not_write_production_receipts",
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    record = subparsers.add_parser("record-authorization", help="record ready PR transition authorization")
    record.add_argument("--draft-pr-receipt", required=True)
    record.add_argument("--output", required=True)
    record.add_argument("--operator-id", default="l1-controlled-pilot-operator")
    record.add_argument("--reason", required=True)
    record.add_argument("--rollback-evidence-ref", required=True)

    validate_authorization = subparsers.add_parser("validate-authorization", help="validate transition authorization")
    validate_authorization.add_argument("--authorization", required=True)
    validate_authorization.add_argument("--output")

    execute = subparsers.add_parser("execute", help="mark one authorized draft PR ready for review")
    execute.add_argument("--authorization", required=True)
    execute.add_argument("--output-root", required=True)

    validate_receipt = subparsers.add_parser("validate-receipt", help="validate ready PR transition receipt")
    validate_receipt.add_argument("--receipt", required=True)
    validate_receipt.add_argument("--output")

    args = parser.parse_args(argv)
    if args.command == "record-authorization":
        report = record_ready_pr_transition_authorization(
            draft_pr_receipt_path=Path(args.draft_pr_receipt),
            output_path=Path(args.output),
            operator_id=args.operator_id,
            reason=args.reason,
            rollback_evidence_ref=args.rollback_evidence_ref,
        )
    elif args.command == "validate-authorization":
        report = validate_ready_pr_transition_authorization(Path(args.authorization))
        if args.output:
            _write_json(Path(args.output), report)
    elif args.command == "execute":
        report = run_ready_pr_transition(
            authorization_path=Path(args.authorization),
            output_root=Path(args.output_root),
        )
    elif args.command == "validate-receipt":
        report = validate_ready_pr_transition_receipt(Path(args.receipt))
        if args.output:
            _write_json(Path(args.output), report)
    else:
        raise AssertionError(f"unknown command: {args.command}")
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report.get("receipt_validation", report.get("validation", report)).get("passed") and report.get(
        "passed",
        True,
    ) else 1


def record_ready_pr_transition_authorization(
    *,
    draft_pr_receipt_path: Path,
    output_path: Path,
    operator_id: str,
    reason: str,
    rollback_evidence_ref: str,
) -> dict[str, Any]:
    failures: list[str] = []
    receipt = _load_draft_pr_receipt(draft_pr_receipt_path, failures)
    pr = _as_dict(receipt.get("draft_pr"), failures, "draft_pr")
    github_repo = _required_text(receipt.get("github_repo"), failures, "github_repo")
    number = _required_positive_int(pr.get("number"), failures, "draft_pr.number")
    operator_id = _required_text(operator_id, failures, "operator_id")
    reason = _required_text(reason, failures, "reason")
    rollback_evidence_ref = _required_text(rollback_evidence_ref, failures, "rollback_evidence_ref")
    view_run: dict[str, Any] | None = None
    view = {}
    if not failures:
        view_run = _gh(failures, "pr", "view", str(number), "--repo", github_repo, "--json", PR_VIEW_FIELDS)
        if view_run["returncode"] == 0:
            view = _parse_object(view_run.get("stdout"), failures, "gh pr view JSON")
            _validate_pr_binding(view, receipt, failures, expect_draft=True)
    if failures:
        raise ValueError(f"ready PR transition authorization blocked: {failures}")

    authorization = {
        "schema_version": AUTHORIZATION_SCHEMA,
        "recorded_at": _now(),
        "request_id": receipt["request_id"],
        "authorization_scope": "github_ready_pr_transition_only",
        "operator_id": operator_id,
        "reason": reason,
        "rollback_evidence_ref": rollback_evidence_ref,
        "source_draft_pr_receipt": _artifact_ref(draft_pr_receipt_path),
        "source_git_push_receipt": receipt["source_git_push_receipt"],
        "source_git_commit_receipt": receipt["source_git_commit_receipt"],
        "source_commit_id": receipt["source_commit_id"],
        "source_branch": receipt["source_branch"],
        "github_repo": receipt["github_repo"],
        "base_branch": receipt["base_branch"],
        "draft_pr": receipt["draft_pr"],
        "github_pr_pre_transition_state": view,
        "gh_pre_transition_view": view_run,
        "ready_transition_authorized": True,
        "ready_transition_performed": False,
        "github_review_approval_observed": False,
        "merge_authorized": False,
        "merge_performed": False,
        "git_actions_performed": {"commit": True, "push": True, "merge": False},
        "deploy_allowed": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
        "h3_boundary": _h3_boundary(),
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(output_path, authorization)
    validation = validate_ready_pr_transition_authorization(output_path)
    if validation["passed"] is not True:
        raise ValueError(f"written ready PR transition authorization failed validation: {validation['failure_reasons']}")
    return {
        "schema_version": AUTHORIZATION_WRITE_SCHEMA,
        "authorization_written": True,
        "authorization_path": str(output_path.resolve()),
        "authorization_sha256": _sha256(output_path),
        "request_id": receipt["request_id"],
        "validation": validation,
        "non_claims": list(NON_CLAIMS),
    }


def validate_ready_pr_transition_authorization(path: Path) -> dict[str, Any]:
    failures: list[str] = []
    authorization = _safe_read_json(path, failures, "ready PR transition authorization")
    if not isinstance(authorization, dict):
        return _authorization_validation_report(path, failures or ["ready PR transition authorization must be an object"])
    _validate_authorization_static(authorization, failures)
    return _authorization_validation_report(path, failures)


def run_ready_pr_transition(*, authorization_path: Path, output_root: Path) -> dict[str, Any]:
    output_root = output_root.resolve()
    output_root.mkdir(parents=True, exist_ok=True)
    validation = validate_ready_pr_transition_authorization(authorization_path)
    if validation.get("passed") is not True:
        report = _authorization_refusal_report(authorization_path, validation)
        _write_json(output_root / "beta4_ready_pr_transition_execution_report.json", report)
        return report

    failures: list[str] = []
    failure_codes: list[str] = []
    authorization = _read_json_object(authorization_path)
    number = _required_positive_int(_as_dict(authorization.get("draft_pr"), failures, "draft_pr").get("number"), failures, "draft_pr.number")
    repo = _required_text(authorization.get("github_repo"), failures, "github_repo")
    pre_view_run: dict[str, Any] | None = None
    ready_run: dict[str, Any] | None = None
    post_view_run: dict[str, Any] | None = None
    pre_view: dict[str, Any] = {}
    post_view: dict[str, Any] = {}
    if not failures:
        pre_view_run = _gh(failures, "pr", "view", str(number), "--repo", repo, "--json", PR_VIEW_FIELDS)
        if pre_view_run["returncode"] == 0:
            pre_view = _parse_object(pre_view_run.get("stdout"), failures, "pre-transition gh pr view JSON")
            _validate_pr_binding(pre_view, authorization, failures, expect_draft=True)
    if not failures:
        ready_run = _gh(failures, "pr", "ready", str(number), "--repo", repo)
        if ready_run["returncode"] != 0:
            _append_code(failure_codes, "ready_pr_transition_failed")
    if not failures:
        post_view_run = _gh(failures, "pr", "view", str(number), "--repo", repo, "--json", PR_VIEW_FIELDS)
        if post_view_run["returncode"] == 0:
            post_view = _parse_object(post_view_run.get("stdout"), failures, "post-transition gh pr view JSON")
            _validate_pr_binding(post_view, authorization, failures, expect_draft=False)
    transition_performed = ready_run is not None and ready_run["returncode"] == 0 and bool(post_view) and not failures
    if not transition_performed and not failure_codes:
        _append_code(failure_codes, "ready_pr_transition_not_verified")

    receipt_path = output_root / "beta4_ready_pr_transition_receipt.json"
    receipt_validation = None
    if transition_performed:
        _write_ready_pr_transition_receipt(
            receipt_path=receipt_path,
            authorization_path=authorization_path,
            authorization=authorization,
            pre_view_run=pre_view_run,
            ready_run=ready_run,
            post_view_run=post_view_run,
            pre_view=pre_view,
            post_view=post_view,
        )
        receipt_validation = validate_ready_pr_transition_receipt(receipt_path)
        if receipt_validation["passed"] is not True:
            failures.extend(f"ready PR transition receipt invalid: {reason}" for reason in receipt_validation["failure_reasons"])
            _append_code(failure_codes, "ready_pr_transition_receipt_invalid")
    report = {
        "schema_version": EXECUTION_SCHEMA,
        "passed": not failures,
        "ready_pr_transition_status": "pr_marked_ready_with_receipt" if not failures else "blocked_or_failed",
        "failure_reasons": failures,
        "failure_codes": failure_codes,
        "checked_at": _now(),
        "source_ready_pr_transition_authorization": _artifact_ref(authorization_path),
        "source_ready_pr_transition_authorization_validation": validation,
        "source_draft_pr_receipt": authorization.get("source_draft_pr_receipt"),
        "github_repo": authorization.get("github_repo"),
        "source_branch": authorization.get("source_branch"),
        "base_branch": authorization.get("base_branch"),
        "source_commit_id": authorization.get("source_commit_id"),
        "draft_pr": authorization.get("draft_pr"),
        "ready_pr": post_view,
        "gh_pre_transition_view": pre_view_run,
        "gh_ready": ready_run,
        "gh_post_transition_view": post_view_run,
        "ready_pr_transition_receipt_path": str(receipt_path.resolve()) if receipt_path.is_file() else None,
        "receipt_validation": receipt_validation,
        "ready_transition_performed": transition_performed,
        "github_review_approval_observed": False,
        "merge_authorized": False,
        "merge_performed": False,
        "deploy_allowed": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
        "h3_boundary": _h3_boundary(),
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(output_root / "beta4_ready_pr_transition_execution_report.json", report)
    return report


def validate_ready_pr_transition_receipt(path: Path) -> dict[str, Any]:
    failures: list[str] = []
    receipt = _safe_read_json(path, failures, "ready PR transition receipt")
    if not isinstance(receipt, dict):
        return _receipt_validation_report(path, failures or ["ready PR transition receipt must be an object"])
    if receipt.get("schema_version") != RECEIPT_SCHEMA:
        failures.append(f"schema_version must be {RECEIPT_SCHEMA}")
    if receipt.get("receipt_scope") != "github_ready_pr_transition_only":
        failures.append("receipt_scope must be github_ready_pr_transition_only")
    auth_ref = _as_ref(receipt.get("source_ready_pr_transition_authorization"), failures, "source_ready_pr_transition_authorization")
    auth_path = _validate_ref_bytes(auth_ref, failures, "source_ready_pr_transition_authorization")
    authorization = _load_valid_authorization(auth_path, failures)
    for field in (
        "request_id",
        "source_draft_pr_receipt",
        "source_git_push_receipt",
        "source_git_commit_receipt",
        "source_commit_id",
        "source_branch",
        "github_repo",
        "base_branch",
        "draft_pr",
    ):
        if receipt.get(field) != authorization.get(field):
            failures.append(f"{field} must match ready PR transition authorization")
    _validate_pr_binding(_as_dict(receipt.get("draft_pr"), failures, "draft_pr"), authorization, failures, expect_draft=True)
    _validate_pr_binding(_as_dict(receipt.get("ready_pr"), failures, "ready_pr"), authorization, failures, expect_draft=False)
    if receipt.get("ready_transition_performed") is not True:
        failures.append("ready_transition_performed must be true")
    if receipt.get("github_review_approval_observed") is not False:
        failures.append("github_review_approval_observed must be false")
    _validate_non_authority_boundary(receipt, failures)
    _validate_h3_boundary(receipt, failures)
    return _receipt_validation_report(path, failures)


def _write_ready_pr_transition_receipt(
    *,
    receipt_path: Path,
    authorization_path: Path,
    authorization: dict[str, Any],
    pre_view_run: dict[str, Any] | None,
    ready_run: dict[str, Any] | None,
    post_view_run: dict[str, Any] | None,
    pre_view: dict[str, Any],
    post_view: dict[str, Any],
) -> None:
    receipt = {
        "schema_version": RECEIPT_SCHEMA,
        "recorded_at": _now(),
        "request_id": authorization["request_id"],
        "receipt_scope": "github_ready_pr_transition_only",
        "source_ready_pr_transition_authorization": _artifact_ref(authorization_path),
        "source_draft_pr_receipt": authorization["source_draft_pr_receipt"],
        "source_git_push_receipt": authorization["source_git_push_receipt"],
        "source_git_commit_receipt": authorization["source_git_commit_receipt"],
        "source_commit_id": authorization["source_commit_id"],
        "source_branch": authorization["source_branch"],
        "github_repo": authorization["github_repo"],
        "base_branch": authorization["base_branch"],
        "draft_pr": pre_view,
        "ready_pr": post_view,
        "gh_pre_transition_view": pre_view_run,
        "gh_ready": ready_run,
        "gh_post_transition_view": post_view_run,
        "ready_transition_performed": True,
        "github_review_approval_observed": False,
        "merge_authorized": False,
        "merge_performed": False,
        "git_actions_performed": {"commit": True, "push": True, "merge": False},
        "deploy_allowed": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
        "h3_boundary": _h3_boundary(),
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(receipt_path, receipt)


def _validate_authorization_static(authorization: dict[str, Any], failures: list[str]) -> dict[str, Any]:
    if authorization.get("schema_version") != AUTHORIZATION_SCHEMA:
        failures.append(f"schema_version must be {AUTHORIZATION_SCHEMA}")
    if authorization.get("authorization_scope") != "github_ready_pr_transition_only":
        failures.append("authorization_scope must be github_ready_pr_transition_only")
    for field in ("operator_id", "reason", "rollback_evidence_ref"):
        if not _text(authorization.get(field)):
            failures.append(f"{field} must be a non-empty string")
    receipt_ref = _as_ref(authorization.get("source_draft_pr_receipt"), failures, "source_draft_pr_receipt")
    receipt_path = _validate_ref_bytes(receipt_ref, failures, "source_draft_pr_receipt")
    draft_receipt = _load_draft_pr_receipt(receipt_path, failures)
    for field in (
        "request_id",
        "source_git_push_receipt",
        "source_git_commit_receipt",
        "source_commit_id",
        "source_branch",
        "github_repo",
        "base_branch",
        "draft_pr",
    ):
        if authorization.get(field) != draft_receipt.get(field):
            failures.append(f"{field} must match draft PR receipt")
    _validate_pr_binding(
        _as_dict(authorization.get("github_pr_pre_transition_state"), failures, "github_pr_pre_transition_state"),
        authorization,
        failures,
        expect_draft=True,
    )
    gh_view = _as_dict(authorization.get("gh_pre_transition_view"), failures, "gh_pre_transition_view")
    if gh_view.get("returncode") != 0:
        failures.append("gh_pre_transition_view returncode must be zero")
    if authorization.get("ready_transition_authorized") is not True:
        failures.append("ready_transition_authorized must be true")
    if authorization.get("ready_transition_performed") is not False:
        failures.append("ready_transition_performed must be false")
    if authorization.get("github_review_approval_observed") is not False:
        failures.append("github_review_approval_observed must be false")
    _validate_non_authority_boundary(authorization, failures)
    _validate_h3_boundary(authorization, failures)
    return draft_receipt


def _load_valid_authorization(path: Path | None, failures: list[str]) -> dict[str, Any]:
    if path is None:
        return {}
    validation = validate_ready_pr_transition_authorization(path)
    if validation.get("passed") is not True:
        failures.extend(f"ready PR transition authorization invalid: {reason}" for reason in validation.get("failure_reasons", []))
    authorization = _safe_read_json(path, failures, "ready PR transition authorization")
    return authorization if isinstance(authorization, dict) else {}


def _load_draft_pr_receipt(path: Path | None, failures: list[str]) -> dict[str, Any]:
    if path is None:
        return {}
    validation = validate_draft_pr_receipt(path)
    if validation.get("passed") is not True:
        failures.extend(f"draft PR receipt invalid: {reason}" for reason in validation.get("failure_reasons", []))
    receipt = _safe_read_json(path, failures, "draft PR receipt")
    if not isinstance(receipt, dict):
        return {}
    if receipt.get("schema_version") != DRAFT_PR_RECEIPT_SCHEMA:
        failures.append(f"draft PR receipt schema_version must be {DRAFT_PR_RECEIPT_SCHEMA}")
    return receipt


def _validate_pr_binding(view: dict[str, Any], source: dict[str, Any], failures: list[str], *, expect_draft: bool) -> None:
    draft_pr = _as_dict(source.get("draft_pr"), failures, "source draft_pr")
    expected = {
        "number": draft_pr.get("number"),
        "url": draft_pr.get("url"),
        "isDraft": expect_draft,
        "state": "OPEN",
        "headRefName": source.get("source_branch"),
        "headRefOid": source.get("source_commit_id"),
        "baseRefName": source.get("base_branch"),
        "title": draft_pr.get("title"),
    }
    for field, value in expected.items():
        if view.get(field) != value:
            state = "draft" if expect_draft else "ready"
            failures.append(f"{state} PR {field} must match draft PR receipt")


def _authorization_refusal_report(authorization_path: Path, validation: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": EXECUTION_SCHEMA,
        "passed": False,
        "ready_pr_transition_status": "authorization_refused",
        "failure_reasons": validation.get("failure_reasons", []),
        "failure_codes": ["ready_pr_transition_authorization_refused"],
        "checked_at": _now(),
        "source_ready_pr_transition_authorization": _artifact_ref_or_path(authorization_path),
        "source_ready_pr_transition_authorization_validation": validation,
        "ready_transition_performed": False,
        "github_review_approval_observed": False,
        "merge_authorized": False,
        "merge_performed": False,
        "deploy_allowed": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
        "h3_boundary": _h3_boundary(),
        "non_claims": list(NON_CLAIMS),
    }


def _validate_non_authority_boundary(payload: dict[str, Any], failures: list[str]) -> None:
    if payload.get("git_actions_performed") != {"commit": True, "push": True, "merge": False}:
        failures.append("git_actions_performed must prove pushed branch without merge")
    for field in (
        "merge_authorized",
        "merge_performed",
        "deploy_allowed",
        "production_runtime_execution_allowed",
        "production_receipt_write_allowed",
    ):
        if payload.get(field) is not False:
            failures.append(f"{field} must be false")


def _h3_boundary() -> dict[str, bool]:
    return {
        "h3_remains_blocked": True,
        "h3_production_readiness_claimed": False,
    }


def _validate_h3_boundary(payload: dict[str, Any], failures: list[str]) -> None:
    if payload.get("h3_boundary") != _h3_boundary():
        failures.append("h3_boundary must keep production readiness blocked")


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


def _gh(failures: list[str], *args: str, input_text: str | None = None) -> dict[str, Any]:
    result = subprocess.run(["gh", *args], input=input_text, check=False, text=True, capture_output=True)
    run = {
        "command": " ".join(["gh", *args]),
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }
    if result.returncode != 0:
        failures.append(f"{run['command']} failed")
    return run


def _parse_object(value: Any, failures: list[str], label: str) -> dict[str, Any]:
    try:
        payload = json.loads(value if isinstance(value, str) else "")
    except Exception as exc:  # noqa: BLE001 - GitHub output is evidence input.
        failures.append(f"{label} could not be parsed: {exc}")
        return {}
    if not isinstance(payload, dict):
        failures.append(f"{label} must be an object")
        return {}
    return payload


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
        raise ValueError(f"expected object JSON: {path}")
    return payload


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


def _required_positive_int(value: Any, failures: list[str], label: str) -> int:
    if isinstance(value, int) and value > 0:
        return value
    failures.append(f"{label} must be a positive integer")
    return 0


def _required_text(value: Any, failures: list[str], label: str) -> str:
    text = _text(value)
    if not text:
        failures.append(f"{label} must be a non-empty string")
    return text


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _append_code(codes: list[str], code: str) -> None:
    if code not in codes:
        codes.append(code)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


if __name__ == "__main__":
    sys.exit(main())
