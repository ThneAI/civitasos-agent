#!/usr/bin/env python3
"""Record Beta-3 operator authorization for explicit Git publication actions.

This gate consumes a passed post-source-apply receipt after source worktree
mutation has already been recorded. It records which Git actions an operator
authorizes next. It does not commit, push, merge, deploy, execute production
runtime actions, or write production receipts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from beta3_source_apply_executor import RECEIPT_SCHEMA
from beta3_source_apply_executor import validate_post_source_apply_receipt


AUTHORIZATION_SCHEMA = "beta3-git-publication-authorization:v1"
VALIDATION_SCHEMA = "beta3-git-publication-authorization-validation:v1"
WRITE_REPORT_SCHEMA = "beta3-git-publication-authorization-write-report:v1"
GIT_ACTIONS = ("commit", "push", "merge")
NON_CLAIMS = (
    "beta3_git_publication_authorization_is_l1_controlled_pilot_only",
    "beta3_git_publication_authorization_does_not_perform_commit_push_merge_or_deploy",
    "beta3_git_publication_authorization_does_not_claim_git_actions_performed",
    "beta3_git_publication_authorization_does_not_claim_h3_production_readiness",
    "beta3_git_publication_authorization_does_not_write_production_receipts",
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    record = subparsers.add_parser("record", help="record explicit Git publication authorization")
    record.add_argument("--post-source-apply-receipt", required=True)
    record.add_argument("--output", required=True)
    record.add_argument("--operator-id", default="l1-controlled-pilot-operator")
    record.add_argument("--reason", required=True)
    record.add_argument("--rollback-evidence-ref", required=True)
    record.add_argument("--allow-git-action", action="append", choices=GIT_ACTIONS, default=[])
    record.add_argument("--commit-message")
    record.add_argument("--target-branch")

    validate = subparsers.add_parser("validate", help="validate Git publication authorization")
    validate.add_argument("--authorization", required=True)
    validate.add_argument("--output")

    args = parser.parse_args(argv)
    if args.command == "record":
        report = record_git_publication_authorization(
            receipt_path=Path(args.post_source_apply_receipt),
            output_path=Path(args.output),
            operator_id=args.operator_id,
            reason=args.reason,
            rollback_evidence_ref=args.rollback_evidence_ref,
            allowed_git_actions=args.allow_git_action,
            commit_message=args.commit_message,
            target_branch=args.target_branch,
        )
    elif args.command == "validate":
        report = validate_git_publication_authorization(Path(args.authorization))
        if args.output:
            _write_json(Path(args.output), report)
    else:
        raise AssertionError(f"unknown command: {args.command}")
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report.get("validation", report).get("passed") else 1


def record_git_publication_authorization(
    *,
    receipt_path: Path,
    output_path: Path,
    operator_id: str,
    reason: str,
    rollback_evidence_ref: str,
    allowed_git_actions: list[str] | None,
    commit_message: str | None,
    target_branch: str | None,
) -> dict[str, Any]:
    failures: list[str] = []
    receipt = _load_usable_receipt(receipt_path, failures)
    actions = _normalize_actions(allowed_git_actions or [], failures)
    _validate_action_dependencies(actions, failures)
    operator_id = _required_text(operator_id, "operator_id")
    reason = _required_text(reason, "reason")
    rollback_evidence_ref = _required_text(rollback_evidence_ref, "rollback_evidence_ref")
    commit_message = _optional_text(commit_message)
    target_branch = _optional_text(target_branch)
    _validate_action_metadata(actions, commit_message, target_branch, failures)
    if failures:
        raise ValueError(f"Git publication authorization blocked: {failures}")

    authorization = {
        "schema_version": AUTHORIZATION_SCHEMA,
        "recorded_at": _now(),
        "request_id": receipt["request_id"],
        "authorization_scope": "git_publication_actions_only",
        "operator_id": operator_id,
        "reason": reason,
        "rollback_evidence_ref": rollback_evidence_ref,
        "source_post_apply_receipt": _artifact_ref(receipt_path),
        "source_patch_proposal": receipt["source_patch_proposal"],
        "target_repo": receipt["target_repo"],
        "allowed_git_actions": actions,
        "action_authorizations": _action_flags(actions),
        "git_actions_performed": {action: False for action in GIT_ACTIONS},
        "commit_message": commit_message,
        "target_branch": target_branch,
        "source_repo_apply_performed_observed": True,
        "commit_allowed": "commit" in actions,
        "push_allowed": "push" in actions,
        "merge_allowed": "merge" in actions,
        "deploy_allowed": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
        "h3_boundary": _h3_boundary(),
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(output_path, authorization)
    validation = validate_git_publication_authorization(output_path)
    if validation["passed"] is not True:
        raise ValueError(f"written Git publication authorization failed validation: {validation['failure_reasons']}")
    return {
        "schema_version": WRITE_REPORT_SCHEMA,
        "authorization_written": True,
        "authorization_path": str(output_path.resolve()),
        "authorization_sha256": _sha256(output_path),
        "request_id": receipt["request_id"],
        "allowed_git_actions": actions,
        "validation": validation,
        "non_claims": list(NON_CLAIMS),
    }


def validate_git_publication_authorization(path: Path) -> dict[str, Any]:
    failures: list[str] = []
    authorization = _safe_read_json(path, failures, "authorization")
    if not isinstance(authorization, dict):
        return _validation_report(path, failures or ["authorization must be a JSON object"])
    if authorization.get("schema_version") != AUTHORIZATION_SCHEMA:
        failures.append(f"schema_version must be {AUTHORIZATION_SCHEMA}")
    if authorization.get("authorization_scope") != "git_publication_actions_only":
        failures.append("authorization_scope must be git_publication_actions_only")
    for field in ("operator_id", "reason", "rollback_evidence_ref"):
        if not _text(authorization.get(field)):
            failures.append(f"{field} must be a non-empty string")
    actions = _normalize_actions(_string_list(authorization.get("allowed_git_actions")), failures)
    _validate_action_dependencies(actions, failures)
    _validate_action_metadata(
        actions,
        _optional_text(authorization.get("commit_message")),
        _optional_text(authorization.get("target_branch")),
        failures,
    )
    if authorization.get("action_authorizations") != _action_flags(actions):
        failures.append("action_authorizations must match allowed_git_actions")
    performed = _as_dict(authorization.get("git_actions_performed"), failures, "git_actions_performed")
    for action in GIT_ACTIONS:
        if performed.get(action) is not False:
            failures.append(f"git_actions_performed.{action} must be false")
        if authorization.get(f"{action}_allowed") is not (action in actions):
            failures.append(f"{action}_allowed must match allowed_git_actions")
    _validate_false_boundary_flags(authorization, failures)
    _validate_h3_boundary(authorization, failures)
    if authorization.get("source_repo_apply_performed_observed") is not True:
        failures.append("source_repo_apply_performed_observed must be true")

    receipt_ref = _as_ref(authorization.get("source_post_apply_receipt"), failures, "source_post_apply_receipt")
    receipt_path = _validate_ref_bytes(receipt_ref, failures, "source_post_apply_receipt")
    receipt = _load_usable_receipt(receipt_path, failures) if receipt_path else {}
    if authorization.get("request_id") != receipt.get("request_id"):
        failures.append("request_id must match source post-apply receipt")
    for field in ("source_patch_proposal", "target_repo"):
        if authorization.get(field) != receipt.get(field):
            failures.append(f"{field} must match source post-apply receipt")
    return _validation_report(path, failures)


def _load_usable_receipt(receipt_path: Path | None, failures: list[str]) -> dict[str, Any]:
    if receipt_path is None:
        return {}
    validation = validate_post_source_apply_receipt(receipt_path)
    if validation.get("passed") is not True:
        failures.extend(f"post-source-apply receipt invalid: {reason}" for reason in validation["failure_reasons"])
    receipt = _safe_read_json(receipt_path, failures, "post-source-apply receipt")
    if not isinstance(receipt, dict):
        return {}
    if receipt.get("schema_version") != RECEIPT_SCHEMA:
        failures.append(f"post-source-apply receipt schema_version must be {RECEIPT_SCHEMA}")
    if receipt.get("source_repo_apply_performed") is not True:
        failures.append("post-source-apply receipt must prove source repo apply performed")
    if receipt.get("tests_passed") is not True or receipt.get("test_evidence_status") != "passed":
        failures.append("Git publication authorization requires passed post-source-apply test evidence")
    if not isinstance(receipt.get("tests"), list) or not receipt.get("tests"):
        failures.append("Git publication authorization requires at least one post-source-apply test")
    return receipt


def _normalize_actions(actions: list[str], failures: list[str]) -> list[str]:
    normalized: list[str] = []
    for raw in actions:
        action = raw.strip() if isinstance(raw, str) else ""
        if action not in GIT_ACTIONS:
            failures.append(f"allowed git action must be one of {list(GIT_ACTIONS)}")
            continue
        if action not in normalized:
            normalized.append(action)
    if not normalized:
        failures.append("allowed_git_actions must not be empty")
    return [action for action in GIT_ACTIONS if action in normalized]


def _validate_action_dependencies(actions: list[str], failures: list[str]) -> None:
    if "push" in actions and "commit" not in actions:
        failures.append("push authorization requires commit authorization")
    if "merge" in actions and "push" not in actions:
        failures.append("merge authorization requires push authorization")


def _validate_action_metadata(
    actions: list[str],
    commit_message: str | None,
    target_branch: str | None,
    failures: list[str],
) -> None:
    if "commit" in actions and not commit_message:
        failures.append("commit authorization requires commit_message")
    if any(action in actions for action in ("push", "merge")) and not target_branch:
        failures.append("push or merge authorization requires target_branch")


def _action_flags(actions: list[str]) -> dict[str, bool]:
    return {action: action in actions for action in GIT_ACTIONS}


def _validate_false_boundary_flags(payload: dict[str, Any], failures: list[str]) -> None:
    for flag in (
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


def _required_text(value: Any, field: str) -> str:
    text = _text(value)
    if not text:
        raise ValueError(f"{field} must be a non-empty string")
    return text


def _optional_text(value: Any) -> str | None:
    return _text(value) or None


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _string_list(value: Any) -> list[str]:
    return [item for item in value if isinstance(item, str)] if isinstance(value, list) else []


def _artifact_ref(path: Path) -> dict[str, str]:
    if not path.is_file():
        raise FileNotFoundError(f"artifact path is not a file: {path}")
    return {"path": str(path.resolve()), "sha256": _sha256(path)}


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
    except Exception as exc:  # noqa: BLE001 - validation requires artifact detail.
        failures.append(f"{label} could not be read: {exc}")
        return None
    if not isinstance(payload, dict):
        failures.append(f"{label} must be a JSON object")
        return None
    return payload


def _validation_report(path: Path, failures: list[str]) -> dict[str, Any]:
    return {
        "schema_version": VALIDATION_SCHEMA,
        "passed": not failures,
        "failure_reasons": failures,
        "checked_at": _now(),
        "authorization_path": str(path.resolve()),
        "authorization_sha256": _sha256(path) if path.is_file() else None,
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
