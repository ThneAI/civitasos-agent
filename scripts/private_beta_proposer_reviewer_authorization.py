#!/usr/bin/env python3
"""Authorization gate for private Beta controlled proposer/reviewer work.

This gate consumes a passed private Beta deployment package and writes either a
controlled proposer/reviewer authorization request or a single-use authorization
receipt. It does not execute Agent work, apply patches, commit, push, merge,
deploy, open public ingress, run production runtime actions, or write production
receipts.
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

PACKAGE_SCHEMA = "private-beta-deployment-package:v1"
REQUEST_SCHEMA = "private-beta-controlled-proposer-reviewer-authorization-request:v1"
AUTHORIZATION_SCHEMA = "private-beta-controlled-proposer-reviewer-single-use-authorization:v1"
VALIDATION_SCHEMA = "private-beta-controlled-proposer-reviewer-authorization-validation:v1"
ALLOWED_MODES = {"patch_proposal", "release_review"}
DEFAULT_SERVICE_SCOPES = ["agents:read", "pool:post", "pool:read", "pool:claim", "pool:write"]
FORBIDDEN_SERVICE_SCOPES = {"agents:write", "evidence:write", "production:write", "deploy:write", "git:write"}
FORBIDDEN_ACTIONS = [
    "apply",
    "commit",
    "push",
    "merge",
    "deploy",
    "public_ingress",
    "production_runtime_execution",
    "production_receipt_write",
]
NON_CLAIMS = (
    "controlled_proposer_reviewer_authorization_does_not_execute_agents",
    "controlled_proposer_reviewer_authorization_does_not_apply_commit_push_merge_or_deploy",
    "controlled_proposer_reviewer_authorization_does_not_open_public_ingress",
    "controlled_proposer_reviewer_authorization_does_not_write_production_receipts",
    "controlled_proposer_reviewer_output_requires_followup_closeout_before_any_bounded_apply",
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    request = subparsers.add_parser("request", help="write a controlled proposer/reviewer authorization request")
    request.add_argument("--private-beta-package", required=True)
    request.add_argument("--output-root", required=True)
    request.add_argument("--operator-id", default="local-operator-cc")
    request.add_argument("--operator-statement", default="Request one private Beta proposer/reviewer authorization.")
    request.add_argument("--proposer-agent", action="append", required=True)
    request.add_argument("--reviewer-agent", action="append", required=True)
    request.add_argument("--allowed-mode", action="append", default=[])
    request.add_argument("--max-proposals", type=int, default=1)
    request.add_argument("--max-reviews", type=int, default=3)
    request.add_argument("--service-token-scope", action="append", default=[])
    request.add_argument("--scenario-id")
    request.add_argument("--patch-slice-id")
    request.add_argument("--ack-authorization-request", action="store_true")

    decide = subparsers.add_parser("decide", help="write a single-use proposer/reviewer authorization")
    decide.add_argument("--authorization-request", required=True)
    decide.add_argument("--output-root", required=True)
    decide.add_argument("--operator-id", default="local-operator-cc")
    decide.add_argument("--operator-decision", choices=("authorize_once", "request_revision", "reject"), default="authorize_once")
    decide.add_argument("--operator-statement", default="Authorize one private Beta proposer/reviewer run.")
    decide.add_argument("--ack-authorization-decision", action="store_true")

    validate = subparsers.add_parser("validate-authorization", help="validate a single-use proposer/reviewer authorization")
    validate.add_argument("--authorization", required=True)
    validate.add_argument("--output")

    args = parser.parse_args(argv)
    if args.command == "request":
        report = write_authorization_request(
            private_beta_package=Path(args.private_beta_package),
            output_root=Path(args.output_root),
            operator_id=args.operator_id,
            operator_statement=args.operator_statement,
            proposer_agents=args.proposer_agent,
            reviewer_agents=args.reviewer_agent,
            allowed_modes=args.allowed_mode or sorted(ALLOWED_MODES),
            max_proposals=args.max_proposals,
            max_reviews=args.max_reviews,
            service_token_scopes=args.service_token_scope or list(DEFAULT_SERVICE_SCOPES),
            scenario_id=args.scenario_id,
            patch_slice_id=args.patch_slice_id,
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
    private_beta_package: Path,
    output_root: Path,
    operator_id: str,
    operator_statement: str,
    proposer_agents: list[str],
    reviewer_agents: list[str],
    allowed_modes: list[str],
    max_proposals: int,
    max_reviews: int,
    service_token_scopes: list[str],
    scenario_id: str | None = None,
    patch_slice_id: str | None = None,
    ack_authorization_request: bool = False,
) -> dict[str, Any]:
    output_root = output_root.resolve()
    output_root.mkdir(parents=True, exist_ok=True)
    failures: list[str] = []
    package = _read_json(private_beta_package, failures, "private Beta deployment package")
    _validate_package(package, failures)
    participants = _participants(package)
    proposers = _validate_agents(proposer_agents, participants, "proposer_agents", failures)
    reviewers = _validate_agents(reviewer_agents, participants, "reviewer_agents", failures)
    modes = _validate_modes(allowed_modes, package, failures)
    scopes = _validate_service_scopes(service_token_scopes, failures)
    scenario = _scenario_scope(scenario_id, patch_slice_id, failures)
    if set(proposers) & set(reviewers):
        failures.append("proposer and reviewer sets must be disjoint")
    if max_proposals < 1 or max_proposals > 3:
        failures.append("max_proposals must be between 1 and 3")
    if max_reviews < 1 or max_reviews > len(reviewers or [None]):
        failures.append("max_reviews must be between 1 and reviewer count")
    if not operator_id.strip():
        failures.append("operator_id is required")
    if not operator_statement.strip():
        failures.append("operator_statement is required")
    if ack_authorization_request is not True:
        failures.append("explicit controlled proposer/reviewer authorization request acknowledgement is required")

    passed = not failures
    package_ref = artifact_ref(private_beta_package) if private_beta_package.is_file() else None
    request_id = f"private-beta-proposer-reviewer-request:{_digest([package_ref, proposers, reviewers, modes, scopes, scenario])[:24]}" if package_ref else ""
    report = {
        "schema_version": REQUEST_SCHEMA,
        "artifact_envelope": build_artifact_envelope(
            artifact_kind="approval",
            plane="governance",
            schema_version=REQUEST_SCHEMA,
            artifact_id=request_id or "private-beta-proposer-reviewer-request:blocked",
            subject_id="private-beta-controlled-proposer-reviewer",
            producer="private_beta_proposer_reviewer_authorization",
            source_refs=[package_ref] if package_ref else [],
            scope="controlled_proposer_reviewer_authorization_request",
        ),
        "checked_at": _now(),
        "passed": passed,
        "decision": "controlled_proposer_reviewer_authorization_request_ready" if passed else "blocked",
        "failure_reasons": failures,
        "authorization_request_id": request_id,
        "operator_id": operator_id,
        "operator_statement": operator_statement,
        "source_private_beta_package": package_ref,
        "requested_scope": _scope(proposers, reviewers, modes, max_proposals, max_reviews, scopes, scenario),
        "readiness": {
            "authorization_request_ready": passed,
            "authorization_granted": False,
            "controlled_proposer_reviewer_execution_ready": False,
        },
        "boundary": _boundary(request_written=passed, authorization_written=False, authorization_granted=False),
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(output_root / "private_beta_proposer_reviewer_authorization_request.json", report)
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
    request = _read_json(authorization_request, failures, "controlled proposer/reviewer authorization request")
    if request.get("schema_version") != REQUEST_SCHEMA:
        failures.append(f"authorization request schema_version must be {REQUEST_SCHEMA}")
    if request.get("passed") is not True:
        failures.append("authorization request must be passed")
    if request.get("decision") != "controlled_proposer_reviewer_authorization_request_ready":
        failures.append("authorization request decision must be ready")
    if operator_decision != "authorize_once":
        failures.append("operator_decision must be authorize_once for controlled proposer/reviewer authorization")
    if ack_authorization_decision is not True:
        failures.append("explicit controlled proposer/reviewer authorization decision acknowledgement is required")
    if not operator_id.strip():
        failures.append("operator_id is required")
    if not operator_statement.strip():
        failures.append("operator_statement is required")

    passed = not failures
    request_ref = artifact_ref(authorization_request) if authorization_request.is_file() else None
    authorization_id = f"private-beta-proposer-reviewer-auth:{_digest([request_ref, operator_id, operator_statement])[:24]}" if request_ref else ""
    report = {
        "schema_version": AUTHORIZATION_SCHEMA,
        "artifact_envelope": build_artifact_envelope(
            artifact_kind="approval",
            plane="governance",
            schema_version=AUTHORIZATION_SCHEMA,
            artifact_id=authorization_id or "private-beta-proposer-reviewer-auth:blocked",
            subject_id="private-beta-controlled-proposer-reviewer",
            producer="private_beta_proposer_reviewer_authorization",
            source_refs=[request_ref] if request_ref else [],
            scope="single_use_controlled_proposer_reviewer",
        ),
        "checked_at": _now(),
        "passed": passed,
        "decision": "controlled_proposer_reviewer_authorized_once" if passed else "blocked",
        "failure_reasons": failures,
        "authorization_id": authorization_id,
        "source_authorization_request": request_ref,
        "source_private_beta_package": request.get("source_private_beta_package") if isinstance(request.get("source_private_beta_package"), dict) else None,
        "authorized_scope": request.get("requested_scope") if isinstance(request.get("requested_scope"), dict) else {},
        "operator_id": operator_id,
        "operator_decision": operator_decision,
        "operator_statement": operator_statement,
        "single_use": True,
        "consumed": False,
        "readiness": {
            "controlled_proposer_reviewer_authorized": passed,
            "controlled_proposer_reviewer_execution_ready": passed,
            "future_execution_requires_fresh_authorization": True,
        },
        "boundary": _boundary(request_written=True, authorization_written=passed, authorization_granted=passed),
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(output_root / "private_beta_proposer_reviewer_authorization.json", report)
    return report


def validate_authorization(path: Path, *, output: Path | None = None) -> dict[str, Any]:
    failures: list[str] = []
    authorization = _read_json(path, failures, "controlled proposer/reviewer authorization")
    if authorization.get("schema_version") != AUTHORIZATION_SCHEMA:
        failures.append(f"authorization schema_version must be {AUTHORIZATION_SCHEMA}")
    if authorization.get("passed") is not True:
        failures.append("authorization must be passed")
    if authorization.get("decision") != "controlled_proposer_reviewer_authorized_once":
        failures.append("authorization decision must be controlled_proposer_reviewer_authorized_once")
    if authorization.get("single_use") is not True or authorization.get("consumed") is not False:
        failures.append("authorization must be single_use and unconsumed")
    _validate_authorization_boundary(authorization, failures)
    report = {
        "schema_version": VALIDATION_SCHEMA,
        "checked_at": _now(),
        "passed": not failures,
        "failure_reasons": failures,
        "authorization": artifact_ref(path) if path.is_file() else {"path": str(path.resolve()), "sha256": ""},
        "authorization_id": authorization.get("authorization_id"),
        "readiness": {"controlled_proposer_reviewer_execution_ready": not failures},
    }
    if output:
        _write_json(output, report)
    return report


def _validate_package(package: Any, failures: list[str]) -> None:
    if not isinstance(package, dict):
        failures.append("private Beta deployment package must be an object")
        return
    if package.get("schema_version") != PACKAGE_SCHEMA:
        failures.append(f"private Beta deployment package schema_version must be {PACKAGE_SCHEMA}")
    if package.get("passed") is not True:
        failures.append("private Beta deployment package must be passed")
    if package.get("decision") != "private_beta_deployment_package_ready":
        failures.append("private Beta deployment package decision must be ready")
    readiness = package.get("readiness") if isinstance(package.get("readiness"), dict) else {}
    if readiness.get("controlled_proposer_reviewer_extension_ready") is not True:
        failures.append("controlled proposer/reviewer extension must be ready")
    boundary = package.get("boundary") if isinstance(package.get("boundary"), dict) else {}
    for key in ("apply_allowed", "commit_allowed", "push_allowed", "merge_allowed", "deploy_allowed", "external_public_ingress_opened", "production_runtime_execution_allowed", "production_receipt_write_allowed"):
        if boundary.get(key) is not False:
            failures.append(f"private Beta package boundary must keep {key}=false")


def _validate_agents(values: list[str], participants: set[str], label: str, failures: list[str]) -> list[str]:
    normalized = sorted({str(item).strip() for item in values if str(item).strip()})
    if not normalized:
        failures.append(f"{label} must be non-empty")
        return []
    unknown = sorted(set(normalized) - participants)
    if unknown:
        failures.append(f"{label} contains agents outside private Beta package participants: {unknown}")
    return normalized


def _validate_modes(values: list[str], package: dict[str, Any], failures: list[str]) -> list[str]:
    requested = sorted({str(item).strip() for item in values if str(item).strip()})
    if not requested:
        failures.append("allowed_modes must be non-empty")
        return []
    unknown = sorted(set(requested) - ALLOWED_MODES)
    if unknown:
        failures.append(f"allowed_modes contains unsupported modes: {unknown}")
    package_modes = set(_agent_model(package).get("allowed_modes") or [])
    missing = sorted(set(requested) - package_modes)
    if missing:
        failures.append(f"allowed_modes not allowed by private Beta package: {missing}")
    return requested


def _validate_service_scopes(values: list[str], failures: list[str]) -> list[str]:
    scopes = sorted({str(item).strip() for item in values if str(item).strip()})
    if not set(DEFAULT_SERVICE_SCOPES).issubset(scopes):
        failures.append(f"service token scopes missing required scopes: {sorted(set(DEFAULT_SERVICE_SCOPES) - set(scopes))}")
    forbidden = sorted(set(scopes) & FORBIDDEN_SERVICE_SCOPES)
    if forbidden:
        failures.append(f"service token scopes include forbidden scopes: {forbidden}")
    return scopes


def _scenario_scope(scenario_id: str | None, patch_slice_id: str | None, failures: list[str]) -> dict[str, str] | None:
    scenario = str(scenario_id or "").strip()
    patch_slice = str(patch_slice_id or "").strip()
    if not scenario and not patch_slice:
        return None
    if not scenario or not patch_slice:
        failures.append("scenario_id and patch_slice_id must be supplied together")
        return None
    return {"scenario_id": scenario, "patch_slice_id": patch_slice}



def _validate_authorization_boundary(authorization: dict[str, Any], failures: list[str]) -> None:
    boundary = authorization.get("boundary") if isinstance(authorization.get("boundary"), dict) else {}
    if boundary.get("patch_proposal_allowed") is not True:
        failures.append("authorization boundary must allow patch proposal")
    if boundary.get("release_review_allowed") is not True:
        failures.append("authorization boundary must allow release review")
    for key in ("apply_allowed", "commit_allowed", "push_allowed", "merge_allowed", "deploy_allowed", "external_public_ingress_opened", "production_runtime_execution_allowed", "production_receipt_write_allowed"):
        if boundary.get(key) is not False:
            failures.append(f"authorization boundary must keep {key}=false")


def _participants(package: dict[str, Any]) -> set[str]:
    return set(str(item) for item in _agent_model(package).get("participants") or [])


def _agent_model(package: dict[str, Any]) -> dict[str, Any]:
    value = package.get("agent_operating_model")
    return value if isinstance(value, dict) else {}


def _scope(
    proposers: list[str],
    reviewers: list[str],
    modes: list[str],
    max_proposals: int,
    max_reviews: int,
    scopes: list[str],
    scenario: dict[str, str] | None,
) -> dict[str, Any]:
    result = {
        "proposer_agents": proposers,
        "reviewer_agents": reviewers,
        "allowed_modes": modes,
        "max_proposals": max_proposals,
        "max_reviews": max_reviews,
        "service_token_scopes": scopes,
        "forbidden_actions": list(FORBIDDEN_ACTIONS),
    }
    if scenario:
        result.update(scenario)
    return result


def _boundary(*, request_written: bool, authorization_written: bool, authorization_granted: bool) -> dict[str, Any]:
    return {
        "authorization_request_written": request_written,
        "authorization_written": authorization_written,
        "authorization_granted": authorization_granted,
        "patch_proposal_allowed": authorization_granted,
        "release_review_allowed": authorization_granted,
        "agent_execution_performed": False,
        "frontend_code_modified": False,
        "apply_allowed": False,
        "commit_allowed": False,
        "push_allowed": False,
        "merge_allowed": False,
        "deploy_allowed": False,
        "external_public_ingress_opened": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
        "service_token_secret_recorded": False,
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
    if isinstance(payload, dict):
        return payload
    failures.append(f"{label} must be a JSON object")
    return {}


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


if __name__ == "__main__":
    raise SystemExit(main())
