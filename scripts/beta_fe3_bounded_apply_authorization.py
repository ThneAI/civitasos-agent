#!/usr/bin/env python3
"""Single-use authorization gate for Beta-FE-3 bounded frontend apply.

This gate separates authorization from apply receipt writing. It consumes a
passed CivitasOS-mediated Agent runner summary and produces either a request or
single-use authorization receipt. It never modifies source, commits, pushes,
merges, deploys, runs production, or writes production receipts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from civitasos_contracts.artifacts import artifact_ref, build_artifact_envelope
except ModuleNotFoundError:
    from scripts.civitasos_contracts.artifacts import artifact_ref, build_artifact_envelope

try:
    import beta_fe3_frontend_apply_receipt as fe3
except ModuleNotFoundError:
    from scripts import beta_fe3_frontend_apply_receipt as fe3

REQUEST_SCHEMA = "beta-fe3-bounded-apply-authorization-request:v1"
AUTHORIZATION_SCHEMA = "beta-fe3-bounded-apply-single-use-authorization:v1"
VALIDATION_SCHEMA = "beta-fe3-bounded-apply-single-use-authorization-validation:v1"
NON_CLAIMS = (
    "beta_fe3_bounded_apply_authorization_does_not_modify_source",
    "beta_fe3_bounded_apply_authorization_does_not_commit_push_merge_or_deploy",
    "beta_fe3_bounded_apply_authorization_does_not_write_production_receipts",
    "beta_fe3_bounded_apply_requires_a_separate_apply_receipt_to_consume_this_authorization",
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    request = subparsers.add_parser("request", help="write a bounded apply authorization request")
    request.add_argument("--source-mediation-summary", required=True)
    request.add_argument("--output-root", required=True)
    request.add_argument("--operator-id", default="local-operator-cc")
    request.add_argument("--operator-statement", default="Request one bounded FE-3 frontend apply authorization.")
    request.add_argument("--allowed-changed-file", action="append", required=True)
    request.add_argument("--ack-authorization-request", action="store_true")

    decide = subparsers.add_parser("decide", help="write a single-use bounded apply authorization")
    decide.add_argument("--authorization-request", required=True)
    decide.add_argument("--output-root", required=True)
    decide.add_argument("--operator-id", default="local-operator-cc")
    decide.add_argument("--operator-decision", choices=("authorize_once", "request_revision", "reject"), default="authorize_once")
    decide.add_argument("--operator-statement", default="Authorize one bounded FE-3 frontend apply attempt.")
    decide.add_argument("--ack-authorization-decision", action="store_true")

    validate = subparsers.add_parser("validate-authorization", help="validate a single-use bounded apply authorization")
    validate.add_argument("--authorization", required=True)
    validate.add_argument("--output")

    args = parser.parse_args(argv)
    if args.command == "request":
        report = write_authorization_request(
            source_mediation_summary=Path(args.source_mediation_summary),
            output_root=Path(args.output_root),
            operator_id=args.operator_id,
            operator_statement=args.operator_statement,
            allowed_changed_files=args.allowed_changed_file,
            ack_authorization_request=bool(args.ack_authorization_request),
        )
    elif args.command == "decide":
        report = write_authorization_decision(
            authorization_request=Path(args.authorization_request),
            output_root=Path(args.output_root),
            operator_id=args.operator_id,
            operator_decision=args.operator_decision,
            operator_statement=args.operator_statement,
            ack_authorization_decision=bool(args.ack_authorization_decision),
        )
    else:
        report = validate_authorization(Path(args.authorization), output=Path(args.output) if args.output else None)
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report.get("passed") is True else 1


def write_authorization_request(
    *,
    source_mediation_summary: Path,
    output_root: Path,
    operator_id: str,
    operator_statement: str,
    allowed_changed_files: list[str],
    ack_authorization_request: bool = False,
) -> dict[str, Any]:
    output_root = output_root.resolve()
    output_root.mkdir(parents=True, exist_ok=True)
    failures: list[str] = []
    source = _read_json(source_mediation_summary, failures, "source mediation summary")
    fe3.validate_source_mediation_summary(source, failures)
    allowed = sorted(fe3.validate_allowed_changed_files(allowed_changed_files, failures))
    if not operator_id.strip():
        failures.append("operator_id is required")
    if not operator_statement.strip():
        failures.append("operator_statement is required")
    if ack_authorization_request is not True:
        failures.append("explicit bounded apply authorization request acknowledgement is required")

    passed = not failures
    source_ref = artifact_ref(source_mediation_summary) if source_mediation_summary.is_file() else None
    request_id = f"beta-fe3-apply-auth-request:{_digest([source_ref, allowed, operator_id])[:24]}" if source_ref else ""
    report = {
        "schema_version": REQUEST_SCHEMA,
        "artifact_envelope": build_artifact_envelope(
            artifact_kind="approval",
            plane="governance",
            schema_version=REQUEST_SCHEMA,
            artifact_id=request_id or "beta-fe3-apply-auth-request:blocked",
            subject_id="frontend-bounded-apply",
            producer="beta_fe3_bounded_apply_authorization",
            source_refs=[source_ref] if source_ref else [],
            scope="bounded_frontend_apply_authorization_request",
        ),
        "checked_at": _now(),
        "passed": passed,
        "decision": "beta_fe3_bounded_apply_authorization_request_ready" if passed else "blocked",
        "failure_reasons": failures,
        "authorization_request_id": request_id,
        "operator_id": operator_id,
        "operator_statement": operator_statement,
        "source_mediation_summary": source_ref,
        "allowed_changed_files": allowed,
        "readiness": {
            "single_use_authorization_request_ready": passed,
            "authorization_granted": False,
            "bounded_apply_ready": False,
        },
        "boundary": _boundary(request_written=passed, authorization_written=False, authorization_granted=False),
        "h3_boundary": {"h3_remains_blocked": True, "h3_production_readiness_claimed": False},
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(output_root / "beta_fe3_bounded_apply_authorization_request.json", report)
    return report


def write_authorization_decision(
    *,
    authorization_request: Path,
    output_root: Path,
    operator_id: str,
    operator_decision: str,
    operator_statement: str,
    ack_authorization_decision: bool = False,
) -> dict[str, Any]:
    output_root = output_root.resolve()
    output_root.mkdir(parents=True, exist_ok=True)
    failures: list[str] = []
    request = _read_json(authorization_request, failures, "bounded apply authorization request")
    if request.get("schema_version") != REQUEST_SCHEMA:
        failures.append(f"authorization request schema_version must be {REQUEST_SCHEMA}")
    if request.get("passed") is not True:
        failures.append("authorization request must be passed")
    if request.get("decision") != "beta_fe3_bounded_apply_authorization_request_ready":
        failures.append("authorization request decision must be ready")
    if operator_decision != "authorize_once":
        failures.append("operator_decision must be authorize_once for bounded apply authorization")
    if ack_authorization_decision is not True:
        failures.append("explicit bounded apply authorization decision acknowledgement is required")
    if not operator_id.strip():
        failures.append("operator_id is required")
    if not operator_statement.strip():
        failures.append("operator_statement is required")

    passed = not failures
    request_ref = artifact_ref(authorization_request) if authorization_request.is_file() else None
    source_ref = request.get("source_mediation_summary") if isinstance(request.get("source_mediation_summary"), dict) else None
    authorization_id = f"beta-fe3-apply-auth:{_digest([request_ref, operator_id, operator_statement])[:24]}" if request_ref else ""
    report = {
        "schema_version": AUTHORIZATION_SCHEMA,
        "artifact_envelope": build_artifact_envelope(
            artifact_kind="approval",
            plane="governance",
            schema_version=AUTHORIZATION_SCHEMA,
            artifact_id=authorization_id or "beta-fe3-apply-auth:blocked",
            subject_id="frontend-bounded-apply",
            producer="beta_fe3_bounded_apply_authorization",
            source_refs=[request_ref] if request_ref else [],
            scope="single_use_bounded_frontend_apply",
        ),
        "checked_at": _now(),
        "passed": passed,
        "decision": "beta_fe3_bounded_apply_authorized_once" if passed else "blocked",
        "failure_reasons": failures,
        "authorization_id": authorization_id,
        "source_authorization_request": request_ref,
        "source_mediation_summary": source_ref,
        "allowed_changed_files": sorted(str(item) for item in request.get("allowed_changed_files", []) if str(item).strip()),
        "operator_id": operator_id,
        "operator_decision": operator_decision,
        "operator_statement": operator_statement,
        "single_use": True,
        "consumed": False,
        "readiness": {
            "bounded_apply_authorized": passed,
            "bounded_apply_ready": passed,
            "future_apply_requires_fresh_authorization": True,
        },
        "boundary": _boundary(request_written=True, authorization_written=passed, authorization_granted=passed),
        "h3_boundary": {"h3_remains_blocked": True, "h3_production_readiness_claimed": False},
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(output_root / "beta_fe3_bounded_apply_authorization.json", report)
    return report


def validate_authorization(path: Path, *, output: Path | None = None) -> dict[str, Any]:
    failures: list[str] = []
    authorization = _read_json(path, failures, "bounded apply authorization")
    allowed = authorization.get("allowed_changed_files") if isinstance(authorization.get("allowed_changed_files"), list) else []
    source_ref = authorization.get("source_mediation_summary") if isinstance(authorization.get("source_mediation_summary"), dict) else None
    if authorization.get("schema_version") != AUTHORIZATION_SCHEMA:
        failures.append(f"authorization schema_version must be {AUTHORIZATION_SCHEMA}")
    if authorization.get("passed") is not True:
        failures.append("authorization must be passed")
    if authorization.get("decision") != "beta_fe3_bounded_apply_authorized_once":
        failures.append("authorization decision must be beta_fe3_bounded_apply_authorized_once")
    if authorization.get("single_use") is not True:
        failures.append("authorization must be single_use")
    if authorization.get("consumed") is not False:
        failures.append("authorization must be unconsumed before FE-3 apply")
    if not source_ref:
        failures.append("authorization must include source_mediation_summary artifact ref")
    if not allowed:
        failures.append("authorization must include allowed_changed_files")
    boundary = authorization.get("boundary") if isinstance(authorization.get("boundary"), dict) else {}
    if boundary.get("apply_allowed") is not True:
        failures.append("authorization boundary must allow only bounded apply")
    for key in ("commit_allowed", "push_allowed", "merge_allowed", "deploy_allowed", "production_runtime_execution_allowed", "production_receipt_write_allowed"):
        if boundary.get(key) is not False:
            failures.append(f"authorization boundary must keep {key}=false")
    report = {
        "schema_version": VALIDATION_SCHEMA,
        "checked_at": _now(),
        "passed": not failures,
        "failure_reasons": failures,
        "authorization": artifact_ref(path) if path.is_file() else {"path": str(path.resolve()), "sha256": ""},
        "authorization_id": authorization.get("authorization_id"),
        "source_mediation_summary": source_ref,
        "allowed_changed_files": sorted(str(item) for item in allowed),
        "readiness": {"bounded_apply_ready": not failures, "authorization_consumable_once": not failures},
    }
    if output:
        _write_json(output, report)
    return report


def _boundary(*, request_written: bool, authorization_written: bool, authorization_granted: bool) -> dict[str, Any]:
    return {
        "authorization_request_written": request_written,
        "authorization_written": authorization_written,
        "authorization_granted": authorization_granted,
        "single_use_authorization": authorization_granted,
        "frontend_code_modified": False,
        "apply_allowed": authorization_granted,
        "commit_allowed": False,
        "push_allowed": False,
        "merge_allowed": False,
        "deploy_allowed": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
        "secrets_recorded": False,
    }


def _read_json(path: Path, failures: list[str], label: str) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        failures.append(f"{label} not found: {path}")
        return {}
    except json.JSONDecodeError as exc:
        failures.append(f"{label} is not valid JSON: {exc}")
        return {}
    return payload if isinstance(payload, dict) else {}


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _digest(payload: Any) -> str:
    return hashlib.sha256(json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


if __name__ == "__main__":
    raise SystemExit(main())
