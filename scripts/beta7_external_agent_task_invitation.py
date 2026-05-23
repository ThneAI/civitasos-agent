#!/usr/bin/env python3
"""Record Beta-7 controlled task invitation for a registered external Agent.

This gate consumes a valid Beta-6 external Agent registration and records one
bounded task invitation. It does not deliver the message, execute the task,
accept a response, merge, deploy, start runtime, or write production receipts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from beta6_external_agent_onboarding import REGISTRATION_SCHEMA
from beta6_external_agent_onboarding import validate_registration


TASK_INVITATION_SCHEMA = "beta7-external-agent-task-invitation:v1"
TASK_INVITATION_VALIDATION_SCHEMA = "beta7-external-agent-task-invitation-validation:v1"
TASK_INVITATION_WRITE_SCHEMA = "beta7-external-agent-task-invitation-write-report:v1"
TASK_KINDS = ("github_pr_review", "repo_review", "boundary_review", "l1_message_review")
EXPECTED_OUTPUTS = ("review_verdict", "boundary_observation", "proposal_comment", "audit_observation")
REQUIRED_SCOPE_BY_TASK_KIND = {
    "github_pr_review": "review_only",
    "repo_review": "review_only",
    "boundary_review": "review_only",
    "l1_message_review": "l1_controlled_message",
}
FORBIDDEN_TOKENS = ("TODO", "REPLACE", "PLACEHOLDER", "TEMPLATE_ONLY")
NON_CLAIMS = (
    "beta7_external_agent_task_invitation_is_l1_controlled_pilot_only",
    "beta7_external_agent_task_invitation_requires_beta6_registration",
    "beta7_external_agent_task_invitation_does_not_deliver_or_execute_task",
    "beta7_external_agent_task_invitation_does_not_accept_external_agent_response",
    "beta7_external_agent_task_invitation_does_not_grant_merge_or_deploy_authority",
    "beta7_external_agent_task_invitation_does_not_claim_h3_production_readiness",
    "beta7_external_agent_task_invitation_does_not_write_production_receipts",
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    record = subparsers.add_parser("record", help="record controlled external Agent task invitation")
    record.add_argument("--registration", required=True)
    record.add_argument("--task-kind", choices=TASK_KINDS, required=True)
    record.add_argument("--task-title", required=True)
    record.add_argument("--task-brief-file", required=True)
    record.add_argument("--expected-output", choices=EXPECTED_OUTPUTS, required=True)
    record.add_argument("--source-artifact", action="append", default=[])
    record.add_argument("--reason", required=True)
    record.add_argument("--output", required=True)
    record.add_argument("--operator-id", default="external-agent-task-coordinator-001")
    record.add_argument("--due-at")

    validate = subparsers.add_parser("validate", help="validate controlled task invitation")
    validate.add_argument("--invitation", required=True)
    validate.add_argument("--output")

    args = parser.parse_args(argv)
    if args.command == "record":
        report = record_task_invitation(
            registration_path=Path(args.registration),
            task_kind=args.task_kind,
            task_title=args.task_title,
            task_brief_file=Path(args.task_brief_file),
            expected_output=args.expected_output,
            source_artifacts=[Path(path) for path in args.source_artifact],
            reason=args.reason,
            output_path=Path(args.output),
            operator_id=args.operator_id,
            due_at=args.due_at,
        )
    elif args.command == "validate":
        report = validate_task_invitation(Path(args.invitation))
        if args.output:
            _write_json(Path(args.output), report)
    else:
        raise AssertionError(f"unknown command: {args.command}")
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report.get("validation", report).get("passed") else 1


def record_task_invitation(
    *,
    registration_path: Path,
    task_kind: str,
    task_title: str,
    task_brief_file: Path,
    expected_output: str,
    source_artifacts: list[Path],
    reason: str,
    output_path: Path,
    operator_id: str,
    due_at: str | None,
) -> dict[str, Any]:
    failures: list[str] = []
    registration = _load_valid_registration(registration_path, failures)
    operator_id = _required_text(operator_id, "operator_id")
    reason = _required_text(reason, "reason")
    task_title = _required_text(task_title, "task_title")
    if task_kind not in TASK_KINDS:
        failures.append(f"task_kind must be one of {list(TASK_KINDS)}")
    if expected_output not in EXPECTED_OUTPUTS:
        failures.append(f"expected_output must be one of {list(EXPECTED_OUTPUTS)}")
    due = due_at.strip() if isinstance(due_at, str) and due_at.strip() else (
        datetime.now(timezone.utc) + timedelta(days=3)
    ).isoformat()
    _parse_future_time(due, "due_at", failures)
    _require_task_scope(registration, task_kind, failures)
    task_brief_ref = _artifact_ref_if_file(task_brief_file, failures, "task_brief_file")
    source_refs = [_artifact_ref_if_file(path, failures, "source_artifact") for path in source_artifacts]
    _reject_forbidden_text([operator_id, reason, task_title], failures)
    if failures:
        raise ValueError(f"external Agent task invitation blocked: {failures}")

    invitation = {
        "schema_version": TASK_INVITATION_SCHEMA,
        "recorded_at": _now(),
        "task_invitation_scope": "external_agent_controlled_task_invitation_only",
        "operator_id": operator_id,
        "reason": reason,
        "source_external_agent_registration": _artifact_ref(registration_path),
        "external_agent_id": registration["external_agent_id"],
        "display_name": registration["display_name"],
        "agent_kind": registration["agent_kind"],
        "capabilities": registration["capabilities"],
        "allowed_scopes": registration["allowed_scopes"],
        "task_kind": task_kind,
        "task_title": task_title,
        "task_brief": task_brief_ref,
        "source_artifacts": source_refs,
        "expected_output": expected_output,
        "due_at": due,
        "task_invitation_recorded": True,
        "message_delivered": False,
        "response_observed": False,
        "direct_task_execution_allowed": False,
        "merge_allowed": False,
        "deploy_allowed": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
        "h3_boundary": _h3_boundary(),
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(output_path, invitation)
    validation = validate_task_invitation(output_path)
    if validation["passed"] is not True:
        raise ValueError(f"written external Agent task invitation failed validation: {validation['failure_reasons']}")
    return {
        "schema_version": TASK_INVITATION_WRITE_SCHEMA,
        "task_invitation_written": True,
        "task_invitation_path": str(output_path.resolve()),
        "task_invitation_sha256": _sha256(output_path),
        "external_agent_id": registration["external_agent_id"],
        "validation": validation,
        "non_claims": list(NON_CLAIMS),
    }


def validate_task_invitation(path: Path) -> dict[str, Any]:
    failures: list[str] = []
    invitation = _safe_read_json(path, failures, "external Agent task invitation")
    if not isinstance(invitation, dict):
        return _validation_report(path, failures or ["external Agent task invitation must be an object"])
    if invitation.get("schema_version") != TASK_INVITATION_SCHEMA:
        failures.append(f"schema_version must be {TASK_INVITATION_SCHEMA}")
    if invitation.get("task_invitation_scope") != "external_agent_controlled_task_invitation_only":
        failures.append("task_invitation_scope must be external_agent_controlled_task_invitation_only")
    for field in ("operator_id", "reason", "external_agent_id", "display_name", "task_title", "due_at"):
        if not _text(invitation.get(field)):
            failures.append(f"{field} must be a non-empty string")
    task_kind = _text(invitation.get("task_kind"))
    expected_output = _text(invitation.get("expected_output"))
    if task_kind not in TASK_KINDS:
        failures.append(f"task_kind must be one of {list(TASK_KINDS)}")
    if expected_output not in EXPECTED_OUTPUTS:
        failures.append(f"expected_output must be one of {list(EXPECTED_OUTPUTS)}")
    _parse_future_time(_text(invitation.get("due_at")), "due_at", failures)
    registration_ref = _as_ref(
        invitation.get("source_external_agent_registration"),
        failures,
        "source_external_agent_registration",
    )
    registration_path = _validate_ref_bytes(registration_ref, failures, "source_external_agent_registration")
    registration = _load_valid_registration(registration_path, failures)
    _validate_registration_binding(invitation, registration, failures)
    _require_task_scope(registration, task_kind, failures)
    _validate_ref_bytes(_as_ref(invitation.get("task_brief"), failures, "task_brief"), failures, "task_brief")
    source_artifacts = invitation.get("source_artifacts")
    if not isinstance(source_artifacts, list):
        failures.append("source_artifacts must be an array")
    else:
        for index, ref in enumerate(source_artifacts):
            _validate_ref_bytes(_as_ref(ref, failures, f"source_artifacts[{index}]"), failures, f"source_artifacts[{index}]")
    if invitation.get("task_invitation_recorded") is not True:
        failures.append("task_invitation_recorded must be true")
    for field in ("message_delivered", "response_observed", "direct_task_execution_allowed"):
        if invitation.get(field) is not False:
            failures.append(f"{field} must be false")
    _validate_no_merge_deploy_production(invitation, failures)
    _validate_h3_boundary(invitation, failures)
    return _validation_report(path, failures)


def _load_valid_registration(path: Path | None, failures: list[str]) -> dict[str, Any]:
    if path is None:
        return {}
    validation = validate_registration(path)
    if validation.get("passed") is not True:
        failures.extend(f"external Agent registration invalid: {reason}" for reason in validation.get("failure_reasons", []))
    registration = _safe_read_json(path, failures, "external Agent registration")
    if not isinstance(registration, dict):
        return {}
    if registration.get("schema_version") != REGISTRATION_SCHEMA:
        failures.append(f"external Agent registration schema_version must be {REGISTRATION_SCHEMA}")
    if registration.get("registration_observed") is not True:
        failures.append("external Agent registration must be observed")
    if registration.get("controlled_task_invitation_allowed") is not True:
        failures.append("external Agent registration must allow controlled task invitation")
    if registration.get("direct_task_execution_allowed") is not False:
        failures.append("external Agent registration must not allow direct task execution")
    return registration


def _validate_registration_binding(
    invitation: dict[str, Any],
    registration: dict[str, Any],
    failures: list[str],
) -> None:
    for field in ("external_agent_id", "display_name", "agent_kind", "capabilities", "allowed_scopes"):
        if invitation.get(field) != registration.get(field):
            failures.append(f"{field} must match external Agent registration")


def _require_task_scope(registration: dict[str, Any], task_kind: str, failures: list[str]) -> None:
    required = REQUIRED_SCOPE_BY_TASK_KIND.get(task_kind)
    scopes = registration.get("allowed_scopes") if isinstance(registration, dict) else None
    if required and (not isinstance(scopes, list) or required not in scopes):
        failures.append(f"task_kind {task_kind} requires external Agent scope {required}")


def _artifact_ref_if_file(path: Path, failures: list[str], label: str) -> dict[str, str]:
    if not path.is_file():
        failures.append(f"{label} must be a file: {path}")
        return {"path": str(path.resolve()), "sha256": ""}
    return _artifact_ref(path)


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


def _parse_future_time(value: str, field: str, failures: list[str]) -> None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        failures.append(f"{field} must be an ISO-8601 timestamp")
        return
    if parsed.tzinfo is None:
        failures.append(f"{field} must include timezone")
        return
    if parsed <= datetime.now(timezone.utc):
        failures.append(f"{field} must be in the future")


def _reject_forbidden_text(values: list[str], failures: list[str]) -> None:
    upper_values = [value.upper() for value in values if value]
    for token in FORBIDDEN_TOKENS:
        if any(token in value for value in upper_values):
            failures.append(f"forbidden placeholder token found: {token}")
            return


def _validate_no_merge_deploy_production(payload: dict[str, Any], failures: list[str]) -> None:
    for field in (
        "merge_allowed",
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


def _validation_report(path: Path, failures: list[str]) -> dict[str, Any]:
    return {
        "schema_version": TASK_INVITATION_VALIDATION_SCHEMA,
        "passed": not failures,
        "failure_reasons": failures,
        "checked_at": _now(),
        "task_invitation_path": str(path.resolve()),
        "task_invitation_sha256": _sha256(path) if path.is_file() else None,
        "non_claims": list(NON_CLAIMS),
    }


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


def _required_text(value: Any, field: str) -> str:
    text = _text(value)
    if not text:
        raise ValueError(f"{field} must be a non-empty string")
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


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


if __name__ == "__main__":
    sys.exit(main())
