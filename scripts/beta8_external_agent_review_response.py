#!/usr/bin/env python3
"""Record Beta-8 external Agent review response evidence.

This gate consumes a valid Beta-7 controlled task invitation and records an
observed external Agent response/verdict. It does not turn that verdict into a
GitHub approval, merge authorization, deploy permission, runtime execution, or
production receipt.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from beta7_external_agent_task_invitation import TASK_INVITATION_SCHEMA
from beta7_external_agent_task_invitation import validate_task_invitation


REVIEW_RESPONSE_SCHEMA = "beta8-external-agent-review-response:v1"
REVIEW_RESPONSE_VALIDATION_SCHEMA = "beta8-external-agent-review-response-validation:v1"
REVIEW_RESPONSE_WRITE_SCHEMA = "beta8-external-agent-review-response-write-report:v1"
REVIEW_VERDICTS = ("approved", "changes_requested", "commented", "rejected", "inconclusive")
RESPONSE_CHANNELS = ("github_comment", "github_review", "api_callback", "email_ref", "manual_operator_observed")
FORBIDDEN_TOKENS = ("TODO", "REPLACE", "PLACEHOLDER", "TEMPLATE_ONLY")
NON_CLAIMS = (
    "beta8_external_agent_response_is_l1_controlled_pilot_evidence_only",
    "beta8_external_agent_response_requires_beta7_task_invitation",
    "beta8_external_agent_response_does_not_replace_github_review_state_packet",
    "beta8_external_agent_response_does_not_create_github_review_approval",
    "beta8_external_agent_response_does_not_authorize_merge_or_deploy",
    "beta8_external_agent_response_does_not_claim_h3_production_readiness",
    "beta8_external_agent_response_does_not_write_production_receipts",
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    record = subparsers.add_parser("record", help="record external Agent review response evidence")
    record.add_argument("--task-invitation", required=True)
    record.add_argument("--external-agent-id", required=True)
    record.add_argument("--response-channel", choices=RESPONSE_CHANNELS, required=True)
    record.add_argument("--review-verdict", choices=REVIEW_VERDICTS, required=True)
    record.add_argument("--response-file", required=True)
    record.add_argument("--attestation-ref", required=True)
    record.add_argument("--observer-actor-id", default="external-agent-observer-001")
    record.add_argument("--reason", required=True)
    record.add_argument("--output", required=True)

    validate = subparsers.add_parser("validate", help="validate external Agent review response evidence")
    validate.add_argument("--response", required=True)
    validate.add_argument("--output")

    args = parser.parse_args(argv)
    if args.command == "record":
        report = record_review_response(
            task_invitation_path=Path(args.task_invitation),
            external_agent_id=args.external_agent_id,
            response_channel=args.response_channel,
            review_verdict=args.review_verdict,
            response_file=Path(args.response_file),
            attestation_ref=args.attestation_ref,
            observer_actor_id=args.observer_actor_id,
            reason=args.reason,
            output_path=Path(args.output),
        )
    elif args.command == "validate":
        report = validate_review_response(Path(args.response))
        if args.output:
            _write_json(Path(args.output), report)
    else:
        raise AssertionError(f"unknown command: {args.command}")
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report.get("validation", report).get("passed") else 1


def record_review_response(
    *,
    task_invitation_path: Path,
    external_agent_id: str,
    response_channel: str,
    review_verdict: str,
    response_file: Path,
    attestation_ref: str,
    observer_actor_id: str,
    reason: str,
    output_path: Path,
) -> dict[str, Any]:
    failures: list[str] = []
    task_invitation = _load_valid_task_invitation(task_invitation_path, failures)
    external_agent_id = _required_text(external_agent_id, "external_agent_id")
    attestation_ref = _required_text(attestation_ref, "attestation_ref")
    observer_actor_id = _required_text(observer_actor_id, "observer_actor_id")
    reason = _required_text(reason, "reason")
    if response_channel not in RESPONSE_CHANNELS:
        failures.append(f"response_channel must be one of {list(RESPONSE_CHANNELS)}")
    if review_verdict not in REVIEW_VERDICTS:
        failures.append(f"review_verdict must be one of {list(REVIEW_VERDICTS)}")
    if task_invitation.get("external_agent_id") != external_agent_id:
        failures.append("external_agent_id must match task invitation")
    response_ref = _artifact_ref_if_file(response_file, failures, "response_file")
    if response_file.is_file() and response_file.stat().st_size == 0:
        failures.append("response_file must be non-empty")
    _reject_forbidden_text([external_agent_id, attestation_ref, observer_actor_id, reason], failures)
    if failures:
        raise ValueError(f"external Agent review response blocked: {failures}")

    response = {
        "schema_version": REVIEW_RESPONSE_SCHEMA,
        "recorded_at": _now(),
        "response_scope": "external_agent_controlled_review_response_only",
        "source_task_invitation": _artifact_ref(task_invitation_path),
        "external_agent_id": external_agent_id,
        "display_name": task_invitation["display_name"],
        "agent_kind": task_invitation["agent_kind"],
        "task_kind": task_invitation["task_kind"],
        "task_title": task_invitation["task_title"],
        "expected_output": task_invitation["expected_output"],
        "response_channel": response_channel,
        "review_verdict": review_verdict,
        "response_file": response_ref,
        "attestation_ref": attestation_ref,
        "observer_actor_id": observer_actor_id,
        "reason": reason,
        "external_agent_response_observed": True,
        "upstream_evidence_only": True,
        "github_review_approval_observed": False,
        "beta4_review_state_packet_replaced": False,
        "beta5_merge_authorization_allowed": False,
        "merge_allowed": False,
        "deploy_allowed": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
        "h3_boundary": _h3_boundary(),
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(output_path, response)
    validation = validate_review_response(output_path)
    if validation["passed"] is not True:
        raise ValueError(f"written external Agent review response failed validation: {validation['failure_reasons']}")
    return {
        "schema_version": REVIEW_RESPONSE_WRITE_SCHEMA,
        "review_response_written": True,
        "review_response_path": str(output_path.resolve()),
        "review_response_sha256": _sha256(output_path),
        "external_agent_id": external_agent_id,
        "review_verdict": review_verdict,
        "validation": validation,
        "non_claims": list(NON_CLAIMS),
    }


def validate_review_response(path: Path) -> dict[str, Any]:
    failures: list[str] = []
    response = _safe_read_json(path, failures, "external Agent review response")
    if not isinstance(response, dict):
        return _validation_report(path, failures or ["external Agent review response must be an object"])
    if response.get("schema_version") != REVIEW_RESPONSE_SCHEMA:
        failures.append(f"schema_version must be {REVIEW_RESPONSE_SCHEMA}")
    if response.get("response_scope") != "external_agent_controlled_review_response_only":
        failures.append("response_scope must be external_agent_controlled_review_response_only")
    for field in ("external_agent_id", "display_name", "task_title", "attestation_ref", "observer_actor_id", "reason"):
        if not _text(response.get(field)):
            failures.append(f"{field} must be a non-empty string")
    if _text(response.get("response_channel")) not in RESPONSE_CHANNELS:
        failures.append(f"response_channel must be one of {list(RESPONSE_CHANNELS)}")
    if _text(response.get("review_verdict")) not in REVIEW_VERDICTS:
        failures.append(f"review_verdict must be one of {list(REVIEW_VERDICTS)}")
    task_ref = _as_ref(response.get("source_task_invitation"), failures, "source_task_invitation")
    task_path = _validate_ref_bytes(task_ref, failures, "source_task_invitation")
    task_invitation = _load_valid_task_invitation(task_path, failures)
    _validate_task_binding(response, task_invitation, failures)
    response_file = _validate_ref_bytes(_as_ref(response.get("response_file"), failures, "response_file"), failures, "response_file")
    if response_file is not None and response_file.stat().st_size == 0:
        failures.append("response_file must be non-empty")
    if response.get("external_agent_response_observed") is not True:
        failures.append("external_agent_response_observed must be true")
    if response.get("upstream_evidence_only") is not True:
        failures.append("upstream_evidence_only must be true")
    for field in (
        "github_review_approval_observed",
        "beta4_review_state_packet_replaced",
        "beta5_merge_authorization_allowed",
        "merge_allowed",
        "deploy_allowed",
        "production_runtime_execution_allowed",
        "production_receipt_write_allowed",
    ):
        if response.get(field) is not False:
            failures.append(f"{field} must be false")
    _validate_h3_boundary(response, failures)
    return _validation_report(path, failures)


def _load_valid_task_invitation(path: Path | None, failures: list[str]) -> dict[str, Any]:
    if path is None:
        return {}
    validation = validate_task_invitation(path)
    if validation.get("passed") is not True:
        failures.extend(f"external Agent task invitation invalid: {reason}" for reason in validation.get("failure_reasons", []))
    invitation = _safe_read_json(path, failures, "external Agent task invitation")
    if not isinstance(invitation, dict):
        return {}
    if invitation.get("schema_version") != TASK_INVITATION_SCHEMA:
        failures.append(f"external Agent task invitation schema_version must be {TASK_INVITATION_SCHEMA}")
    if invitation.get("task_invitation_recorded") is not True:
        failures.append("external Agent task invitation must be recorded")
    if invitation.get("direct_task_execution_allowed") is not False:
        failures.append("external Agent task invitation must not allow direct task execution")
    return invitation


def _validate_task_binding(response: dict[str, Any], task_invitation: dict[str, Any], failures: list[str]) -> None:
    for field in ("external_agent_id", "display_name", "agent_kind", "task_kind", "task_title", "expected_output"):
        if response.get(field) != task_invitation.get(field):
            failures.append(f"{field} must match source task invitation")


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


def _reject_forbidden_text(values: list[str], failures: list[str]) -> None:
    upper_values = [value.upper() for value in values if value]
    for token in FORBIDDEN_TOKENS:
        if any(token in value for value in upper_values):
            failures.append(f"forbidden placeholder token found: {token}")
            return


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
        "schema_version": REVIEW_RESPONSE_VALIDATION_SCHEMA,
        "passed": not failures,
        "failure_reasons": failures,
        "checked_at": _now(),
        "review_response_path": str(path.resolve()),
        "review_response_sha256": _sha256(path) if path.is_file() else None,
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
