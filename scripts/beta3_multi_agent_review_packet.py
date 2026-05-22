#!/usr/bin/env python3
"""Write Beta-3 role-separated review verdicts and evidence packets.

This gate keeps Beta-3 multi-Agent work on the evidence path. Review and risk
agents can record structured verdicts over the same post-sandbox receipt, then
the packet gate hash-binds those verdicts with the proposal, sandbox report, and
operator receipt. It never applies a patch to the source repo, commits, pushes,
merges, deploys, executes production runtime actions, or writes production
receipts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from beta3_post_sandbox_operator_receipt import RECEIPT_SCHEMA
from beta3_post_sandbox_operator_receipt import validate_post_sandbox_receipt


VERDICT_SCHEMA = "beta3-multi-agent-review-verdict:v1"
PACKET_SCHEMA = "beta3-multi-agent-review-packet:v1"
PACKET_VALIDATION_SCHEMA = "beta3-multi-agent-review-packet-validation:v1"
ROLES = {"review_agent", "risk_agent"}
DECISIONS = {"approved", "rejected", "deferred"}
REVIEW_SCOPES = {
    "review_agent": "proposal_sandbox_review_only",
    "risk_agent": "boundary_risk_review_only",
}
NON_CLAIMS = (
    "beta3_multi_agent_packet_is_l1_controlled_pilot_only",
    "beta3_multi_agent_packet_does_not_apply_patch_to_source_repo_worktree",
    "beta3_multi_agent_packet_does_not_authorize_commit_push_merge_or_deploy",
    "beta3_multi_agent_packet_does_not_claim_h3_production_readiness",
    "beta3_multi_agent_packet_does_not_write_production_receipts",
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    verdict = subparsers.add_parser("record-verdict", help="record one structured Agent verdict")
    verdict.add_argument("--operator-receipt", required=True)
    verdict.add_argument("--role", required=True, choices=sorted(ROLES))
    verdict.add_argument("--agent-id", required=True)
    verdict.add_argument("--decision", required=True, choices=sorted(DECISIONS))
    verdict.add_argument("--reason", required=True)
    verdict.add_argument("--blocking-finding", action="append", default=[])
    verdict.add_argument("--observation", action="append", default=[])
    verdict.add_argument("--output", required=True)

    packet = subparsers.add_parser("build-packet", help="build the role-separated evidence packet")
    packet.add_argument("--operator-receipt", required=True)
    packet.add_argument("--review-verdict", required=True)
    packet.add_argument("--risk-verdict", required=True)
    packet.add_argument("--output", required=True)

    validate = subparsers.add_parser("validate", help="validate an existing review packet")
    validate.add_argument("--packet", required=True)
    validate.add_argument("--output")

    args = parser.parse_args(argv)
    if args.command == "record-verdict":
        report = record_verdict(
            operator_receipt_path=Path(args.operator_receipt),
            role=args.role,
            agent_id=args.agent_id,
            decision=args.decision,
            reason=args.reason,
            blocking_findings=args.blocking_finding,
            observations=args.observation,
            output_path=Path(args.output),
        )
    elif args.command == "build-packet":
        report = build_review_packet(
            operator_receipt_path=Path(args.operator_receipt),
            review_verdict_path=Path(args.review_verdict),
            risk_verdict_path=Path(args.risk_verdict),
            output_path=Path(args.output),
        )
    elif args.command == "validate":
        report = validate_review_packet(Path(args.packet))
        if args.output:
            _write_json(Path(args.output), report)
    else:
        raise AssertionError(f"unknown command: {args.command}")
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report.get("validation", report).get("passed") else 1


def record_verdict(
    *,
    operator_receipt_path: Path,
    role: str,
    agent_id: str,
    decision: str,
    reason: str,
    blocking_findings: list[str] | None,
    observations: list[str] | None,
    output_path: Path,
) -> dict[str, Any]:
    failures: list[str] = []
    context = _load_operator_context(operator_receipt_path, failures, require_approved=True)
    agent_id = _required_text(agent_id, "agent_id")
    reason = _required_text(reason, "reason")
    if role not in ROLES:
        raise ValueError(f"role must be one of {sorted(ROLES)}")
    if decision not in DECISIONS:
        raise ValueError(f"decision must be one of {sorted(DECISIONS)}")
    blocking = _clean_text_list(blocking_findings or [])
    if decision == "approved" and blocking:
        failures.append("approved verdict must not contain blocking_findings")
    if failures:
        raise ValueError(f"operator receipt is not usable for {role} verdict: {failures}")

    verdict = {
        "schema_version": VERDICT_SCHEMA,
        "recorded_at": _now(),
        "request_id": context["request_id"],
        "role": role,
        "agent_id": agent_id,
        "decision": decision,
        "review_scope": REVIEW_SCOPES[role],
        "reason": reason,
        "blocking_findings": blocking,
        "observations": _clean_text_list(observations or []),
        "source_patch_proposal": context["source_patch_proposal"],
        "source_candidate_report": context["source_candidate_report"],
        "source_sandbox_report": context["source_sandbox_report"],
        "source_operator_receipt": context["source_operator_receipt"],
        "source_repo_apply_allowed": False,
        "commit_allowed": False,
        "push_allowed": False,
        "merge_allowed": False,
        "deploy_allowed": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
        "h3_boundary": {
            "h3_remains_blocked": True,
            "h3_production_readiness_claimed": False,
        },
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(output_path, verdict)
    validation_failures: list[str] = []
    _validate_verdict(
        _artifact_ref(output_path),
        expected_role=role,
        expected_context=context,
        failures=validation_failures,
    )
    if validation_failures:
        raise ValueError(f"written {role} verdict failed validation: {validation_failures}")
    return {
        "schema_version": "beta3-multi-agent-review-verdict-write-report:v1",
        "verdict_written": True,
        "verdict_path": str(output_path.resolve()),
        "verdict_sha256": _sha256(output_path),
        "request_id": context["request_id"],
        "role": role,
        "decision": decision,
        "passed": True,
        "non_claims": list(NON_CLAIMS),
    }


def build_review_packet(
    *,
    operator_receipt_path: Path,
    review_verdict_path: Path,
    risk_verdict_path: Path,
    output_path: Path,
) -> dict[str, Any]:
    failures: list[str] = []
    context = _load_operator_context(operator_receipt_path, failures, require_approved=True)
    review_ref = _artifact_ref_if_file(review_verdict_path, failures, "review verdict")
    risk_ref = _artifact_ref_if_file(risk_verdict_path, failures, "risk verdict")
    review_verdict = _validate_verdict(
        review_ref,
        expected_role="review_agent",
        expected_context=context,
        failures=failures,
    )
    risk_verdict = _validate_verdict(
        risk_ref,
        expected_role="risk_agent",
        expected_context=context,
        failures=failures,
    )
    _require_approved_verdict(review_verdict, "review_agent", failures)
    _require_approved_verdict(risk_verdict, "risk_agent", failures)

    packet = {
        "schema_version": PACKET_SCHEMA,
        "passed": not failures,
        "packet_status": "ready_for_source_apply_authorization_review" if not failures else "blocked",
        "failure_reasons": failures,
        "checked_at": _now(),
        "request_id": context.get("request_id"),
        "source_patch_proposal": context.get("source_patch_proposal"),
        "source_candidate_report": context.get("source_candidate_report"),
        "source_sandbox_report": context.get("source_sandbox_report"),
        "source_operator_receipt": _artifact_ref_if_file(operator_receipt_path, [], "operator receipt"),
        "review_verdict": review_ref,
        "risk_verdict": risk_ref,
        "role_decisions": {
            "review_agent": review_verdict.get("decision") if isinstance(review_verdict, dict) else None,
            "risk_agent": risk_verdict.get("decision") if isinstance(risk_verdict, dict) else None,
            "operator": context.get("operator_decision"),
        },
        "next_gate_source_apply_authorization_review_allowed": not failures,
        "source_repo_apply_allowed": False,
        "commit_allowed": False,
        "push_allowed": False,
        "merge_allowed": False,
        "deploy_allowed": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
        "h3_boundary": {
            "h3_remains_blocked": True,
            "h3_production_readiness_claimed": False,
        },
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(output_path, packet)
    validation = validate_review_packet(output_path)
    return {
        "schema_version": "beta3-multi-agent-review-packet-write-report:v1",
        "packet_written": True,
        "packet_path": str(output_path.resolve()),
        "packet_sha256": _sha256(output_path),
        "request_id": packet.get("request_id"),
        "packet_status": packet["packet_status"],
        "validation": validation,
        "non_claims": list(NON_CLAIMS),
    }


def validate_review_packet(packet_path: Path) -> dict[str, Any]:
    failures: list[str] = []
    packet = _safe_read_json(packet_path, failures, "packet")
    if not isinstance(packet, dict):
        return _validation_report(packet_path, failures or ["packet must be a JSON object"])
    if packet.get("schema_version") != PACKET_SCHEMA:
        failures.append(f"schema_version must be {PACKET_SCHEMA}")

    operator_ref = _as_ref(packet.get("source_operator_receipt"), failures, "source_operator_receipt")
    operator_path = _validate_ref_bytes(operator_ref, failures, "source_operator_receipt")
    context = _load_operator_context(operator_path, failures, require_approved=True) if operator_path else {}
    for field in ("source_patch_proposal", "source_candidate_report", "source_sandbox_report"):
        if packet.get(field) != context.get(field):
            failures.append(f"{field} must match operator receipt evidence chain")
    if packet.get("request_id") != context.get("request_id"):
        failures.append("request_id must match operator receipt evidence chain")

    review = _validate_verdict(
        _as_ref(packet.get("review_verdict"), failures, "review_verdict"),
        expected_role="review_agent",
        expected_context=context,
        failures=failures,
    )
    risk = _validate_verdict(
        _as_ref(packet.get("risk_verdict"), failures, "risk_verdict"),
        expected_role="risk_agent",
        expected_context=context,
        failures=failures,
    )
    _require_approved_verdict(review, "review_agent", failures)
    _require_approved_verdict(risk, "risk_agent", failures)
    if packet.get("passed") is not (not failures):
        failures.append("passed must match packet evidence checks")
    if packet.get("packet_status") != (
        "ready_for_source_apply_authorization_review" if not failures else "blocked"
    ):
        failures.append("packet_status must match packet evidence checks")
    if packet.get("next_gate_source_apply_authorization_review_allowed") is not (not failures):
        failures.append("next_gate_source_apply_authorization_review_allowed must match packet checks")
    _validate_false_authority_flags(packet, failures)
    _validate_h3_boundary(packet, failures)
    return _validation_report(packet_path, failures)


def _load_operator_context(
    operator_receipt_path: Path | None,
    failures: list[str],
    *,
    require_approved: bool,
) -> dict[str, Any]:
    if operator_receipt_path is None:
        return {}
    validation = validate_post_sandbox_receipt(operator_receipt_path)
    if validation.get("passed") is not True:
        failures.extend(f"operator receipt invalid: {reason}" for reason in validation.get("failure_reasons", []))
    receipt = _safe_read_json(operator_receipt_path, failures, "operator receipt")
    if not isinstance(receipt, dict):
        return {}
    if receipt.get("schema_version") != RECEIPT_SCHEMA:
        failures.append(f"operator receipt schema_version must be {RECEIPT_SCHEMA}")
    if require_approved and receipt.get("decision") != "approved":
        failures.append("multi-Agent packet requires approved post-sandbox operator receipt")
    sandbox_ref = _as_ref(receipt.get("source_sandbox_report"), failures, "operator source_sandbox_report")
    sandbox = _validate_ref_json(sandbox_ref, failures, "operator source_sandbox_report")
    patch_ref = _as_ref(sandbox.get("source_patch") if isinstance(sandbox, dict) else None, failures, "source_patch")
    _validate_ref_bytes(patch_ref, failures, "source_patch")
    candidate_ref = _as_ref(receipt.get("source_candidate_report"), failures, "operator source_candidate_report")
    _validate_ref_bytes(candidate_ref, failures, "operator source_candidate_report")
    return {
        "request_id": receipt.get("request_id"),
        "operator_decision": receipt.get("decision"),
        "source_patch_proposal": patch_ref,
        "source_candidate_report": candidate_ref,
        "source_sandbox_report": sandbox_ref,
        "source_operator_receipt": _artifact_ref(operator_receipt_path),
    }


def _validate_verdict(
    ref: dict[str, Any],
    *,
    expected_role: str,
    expected_context: dict[str, Any],
    failures: list[str],
) -> dict[str, Any]:
    verdict = _validate_ref_json(ref, failures, expected_role)
    if not isinstance(verdict, dict):
        return {}
    if verdict.get("schema_version") != VERDICT_SCHEMA:
        failures.append(f"{expected_role} schema_version must be {VERDICT_SCHEMA}")
    if verdict.get("role") != expected_role:
        failures.append(f"{expected_role} role must be {expected_role}")
    if verdict.get("review_scope") != REVIEW_SCOPES[expected_role]:
        failures.append(f"{expected_role} review_scope must be {REVIEW_SCOPES[expected_role]}")
    if verdict.get("decision") not in DECISIONS:
        failures.append(f"{expected_role} decision must be approved, rejected, or deferred")
    if not _text(verdict.get("agent_id")):
        failures.append(f"{expected_role} agent_id must be a non-empty string")
    if not _text(verdict.get("reason")):
        failures.append(f"{expected_role} reason must be a non-empty string")
    if verdict.get("decision") == "approved" and _list(verdict.get("blocking_findings")):
        failures.append(f"{expected_role} approved verdict must not contain blocking_findings")
    for field in ("source_patch_proposal", "source_candidate_report", "source_sandbox_report"):
        if verdict.get(field) != expected_context.get(field):
            failures.append(f"{expected_role} {field} must match operator receipt evidence chain")
    operator_ref = _as_ref(verdict.get("source_operator_receipt"), failures, f"{expected_role} source_operator_receipt")
    operator_path = _validate_ref_bytes(operator_ref, failures, f"{expected_role} source_operator_receipt")
    if operator_ref != expected_context.get("source_operator_receipt"):
        failures.append(f"{expected_role} source_operator_receipt must match packet operator receipt")
    if operator_path and verdict.get("request_id") != expected_context.get("request_id"):
        failures.append(f"{expected_role} request_id must match operator receipt evidence chain")
    _validate_false_authority_flags(verdict, failures, prefix=f"{expected_role} ")
    _validate_h3_boundary(verdict, failures, prefix=f"{expected_role} ")
    return verdict


def _require_approved_verdict(verdict: dict[str, Any], role: str, failures: list[str]) -> None:
    if verdict.get("decision") != "approved":
        failures.append(f"{role} verdict must be approved")


def _validate_false_authority_flags(payload: dict[str, Any], failures: list[str], prefix: str = "") -> None:
    for flag in (
        "source_repo_apply_allowed",
        "commit_allowed",
        "push_allowed",
        "merge_allowed",
        "deploy_allowed",
        "production_runtime_execution_allowed",
        "production_receipt_write_allowed",
    ):
        if payload.get(flag) is not False:
            failures.append(f"{prefix}{flag} must be false")


def _validate_h3_boundary(payload: dict[str, Any], failures: list[str], prefix: str = "") -> None:
    boundary = payload.get("h3_boundary")
    if not isinstance(boundary, dict):
        failures.append(f"{prefix}h3_boundary must be an object")
        return
    if boundary.get("h3_remains_blocked") is not True:
        failures.append(f"{prefix}h3_boundary.h3_remains_blocked must be true")
    if boundary.get("h3_production_readiness_claimed") is not False:
        failures.append(f"{prefix}h3_boundary.h3_production_readiness_claimed must be false")


def _artifact_ref(path: Path) -> dict[str, str]:
    if not path.is_file():
        raise FileNotFoundError(f"artifact path is not a file: {path}")
    return {"path": str(path.resolve()), "sha256": _sha256(path)}


def _artifact_ref_if_file(path: Path, failures: list[str], label: str) -> dict[str, Any]:
    if not path.is_file():
        failures.append(f"{label} path is not a file: {path}")
        return {"path": str(path.resolve()), "sha256": None}
    return _artifact_ref(path)


def _as_ref(value: Any, failures: list[str], label: str) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    failures.append(f"{label} must be an object")
    return {}


def _validate_ref_json(ref: dict[str, Any], failures: list[str], label: str) -> Any:
    path = _validate_ref_bytes(ref, failures, label)
    return _safe_read_json(path, failures, label) if path else None


def _validate_ref_bytes(ref: dict[str, Any], failures: list[str], label: str) -> Path | None:
    path_text = ref.get("path")
    if not _text(path_text):
        failures.append(f"{label}.path must be a non-empty string")
        return None
    path = Path(path_text)
    if not path.is_file():
        failures.append(f"{label}.path is not a file: {path}")
        return None
    if ref.get("sha256") != _sha256(path):
        failures.append(f"{label}.sha256 does not match file bytes")
    return path


def _safe_read_json(path: Path | None, failures: list[str], label: str) -> Any:
    if path is None:
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 - gate reports need artifact reasons.
        failures.append(f"{label} could not be read: {exc}")
        return None
    if not isinstance(data, dict):
        failures.append(f"{label} must be a JSON object")
        return None
    return data


def _required_text(value: Any, label: str) -> str:
    cleaned = _text(value)
    if not cleaned:
        raise ValueError(f"{label} must be a non-empty string")
    return cleaned


def _clean_text_list(values: list[str]) -> list[str]:
    return [cleaned for value in values if (cleaned := _text(value))]


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _validation_report(packet_path: Path, failures: list[str]) -> dict[str, Any]:
    return {
        "schema_version": PACKET_VALIDATION_SCHEMA,
        "passed": not failures,
        "failure_reasons": failures,
        "checked_at": _now(),
        "packet_path": str(packet_path.resolve()),
        "packet_sha256": _sha256(packet_path) if packet_path.is_file() else None,
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
