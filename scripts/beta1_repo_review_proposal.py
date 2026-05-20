#!/usr/bin/env python3
"""Prepare and verify Beta-1 repo review proposal-only packets.

Beta-1 allows a real external model to review a real repository, but the model
is only allowed to produce a proposal. Merge, push, deploy, production runtime
execution, and production receipt writes remain explicitly forbidden.
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


REQUEST_SCHEMA = "beta1-repo-review-proposal-request:v1"
TASK_SCHEMA = "beta1-repo-review-task-payload:v1"
RECEIPT_SCHEMA = "beta1-operator-decision-receipt:v1"
VALIDATION_SCHEMA = "beta1-operator-decision-receipt-validation:v1"
DEFAULT_OPERATOR_ID = "l1-controlled-pilot-operator"
DEFAULT_AUDIT_ACTOR_ID = "audit-owner-001"
ALLOWED_DECISIONS = {"approved", "rejected", "deferred"}
DANGEROUS_FLAGS = (
    "merge_allowed",
    "push_allowed",
    "deploy_allowed",
    "production_runtime_execution_allowed",
    "production_receipt_write_allowed",
)
NON_CLAIMS = (
    "beta1_repo_review_is_l1_controlled_pilot_only",
    "beta1_repo_review_does_not_authorize_merge_push_or_deploy",
    "beta1_repo_review_does_not_claim_h3_production_readiness",
    "beta1_operator_receipt_does_not_authorize_production_runtime_execution",
    "beta1_operator_receipt_does_not_write_production_receipts",
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    prepare = subparsers.add_parser("prepare", help="write a repo review proposal request packet")
    prepare.add_argument("--repo", required=True, help="Path to the repository to review.")
    prepare.add_argument("--output-root", required=True, help="Directory for generated Beta-1 packet files.")
    prepare.add_argument("--request-id", help="Stable request id. Defaults to beta1-repo-review-<utc>.")
    prepare.add_argument("--request-text", default="Review this repository state and produce a proposal only.")
    prepare.add_argument("--base-ref", help="Optional base ref for review context.")
    prepare.add_argument("--operator-id", default=DEFAULT_OPERATOR_ID)
    prepare.add_argument("--target-agent", default="external-model-reviewer")

    receipt = subparsers.add_parser("receipt", help="write an operator decision receipt")
    receipt.add_argument("--request", required=True, help="Path to beta1_repo_review_proposal_request.json.")
    receipt.add_argument("--proposal", required=True, help="Path to the model proposal artifact.")
    receipt.add_argument("--output", required=True, help="Receipt JSON output path.")
    receipt.add_argument("--decision", required=True, choices=sorted(ALLOWED_DECISIONS))
    receipt.add_argument("--operator-id", default=DEFAULT_OPERATOR_ID)
    receipt.add_argument("--reason", default="operator_decision_recorded")
    receipt.add_argument("--audit-output", help="Optional packet-compatible audit-events.jsonl output.")
    receipt.add_argument("--audit-actor-id", default=DEFAULT_AUDIT_ACTOR_ID)
    receipt.add_argument("--append", action="store_true")

    validate = subparsers.add_parser("validate", help="validate an operator decision receipt")
    validate.add_argument("--receipt", required=True, help="Receipt JSON path.")
    validate.add_argument("--request", help="Optional request path override.")
    validate.add_argument("--proposal", help="Optional proposal path override.")
    validate.add_argument("--output", help="Optional validation report JSON path.")

    args = parser.parse_args(argv)
    if args.command == "prepare":
        report = prepare_request(
            repo=Path(args.repo),
            output_root=Path(args.output_root),
            request_id=args.request_id,
            request_text=args.request_text,
            base_ref=args.base_ref,
            operator_id=args.operator_id,
            target_agent=args.target_agent,
        )
        print(_json(report))
        return 0
    if args.command == "receipt":
        report = write_operator_receipt(
            request_path=Path(args.request),
            proposal_path=Path(args.proposal),
            output_path=Path(args.output),
            decision=args.decision,
            operator_id=args.operator_id,
            reason=args.reason,
            audit_output_path=Path(args.audit_output) if args.audit_output else None,
            audit_actor_id=args.audit_actor_id,
            append=args.append,
        )
        print(_json(report))
        return 0
    if args.command == "validate":
        report = validate_receipt(
            receipt_path=Path(args.receipt),
            request_path=Path(args.request) if args.request else None,
            proposal_path=Path(args.proposal) if args.proposal else None,
        )
        if args.output:
            _write_json(Path(args.output), report)
        print(_json(report))
        return 0 if report["passed"] else 1
    raise AssertionError(f"unknown command: {args.command}")


def prepare_request(
    *,
    repo: Path,
    output_root: Path,
    request_id: str | None = None,
    request_text: str,
    base_ref: str | None,
    operator_id: str,
    target_agent: str,
) -> dict[str, Any]:
    repo_root = _repo_root(repo)
    output_root.mkdir(parents=True, exist_ok=True)
    request_id = request_id or f"beta1-repo-review-{_timestamp_id()}"
    created_at = _now()
    repo_snapshot = _repo_snapshot(repo_root, base_ref=base_ref)

    request_path = output_root / "beta1_repo_review_proposal_request.json"
    task_path = output_root / "beta1_repo_review_task_payload.json"
    prepare_report_path = output_root / "beta1_repo_review_prepare_report.json"

    request_packet = {
        "schema_version": REQUEST_SCHEMA,
        "request_id": request_id,
        "created_at": created_at,
        "phase": "Beta-1",
        "mode": "proposal_only",
        "operator_id": operator_id,
        "target_agent": target_agent,
        "request_text": request_text,
        "repo_snapshot": repo_snapshot,
        "allowed_actions": [
            "read_repository_snapshot",
            "write_proposal_artifact",
            "write_operator_decision_receipt",
        ],
        "forbidden_actions": [
            "merge",
            "push",
            "deploy",
            "write_to_external_system",
            "execute_production_runtime",
            "write_production_receipt",
        ],
        "operator_decision_required": True,
        "h3_boundary": _h3_boundary(),
        "delivery_contract": _delivery_contract(),
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(request_path, request_packet)
    request_hash = _sha256(request_path)

    task_payload = {
        "schema_version": TASK_SCHEMA,
        "request_id": request_id,
        "created_at": created_at,
        "task_kind": "repo_review_proposal_only",
        "required_capability": "review",
        "target_agent": target_agent,
        "proposal_request_path": str(request_path.resolve()),
        "proposal_request_sha256": request_hash,
        "instructions": [
            "Review the supplied repository snapshot.",
            "Produce a proposal artifact only.",
            "Do not merge, push, deploy, or mutate external systems.",
            "Do not claim H.3 production readiness.",
            "Leave the final decision to an explicit operator receipt.",
        ],
        "required_sections": _delivery_contract()["required_sections"],
        "h3_boundary": _h3_boundary(),
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(task_path, task_payload)

    report = {
        "schema_version": "beta1-repo-review-prepare-report:v1",
        "prepared": True,
        "request_id": request_id,
        "request_path": str(request_path.resolve()),
        "request_sha256": request_hash,
        "task_payload_path": str(task_path.resolve()),
        "task_payload_sha256": _sha256(task_path),
        "repo_root": str(repo_root),
        "mode": "proposal_only",
        "operator_decision_required": True,
        "forbidden_actions": request_packet["forbidden_actions"],
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(prepare_report_path, report)
    return report


def write_operator_receipt(
    *,
    request_path: Path,
    proposal_path: Path,
    output_path: Path,
    decision: str,
    operator_id: str,
    reason: str,
    audit_output_path: Path | None,
    audit_actor_id: str,
    append: bool,
) -> dict[str, Any]:
    request = _read_json(request_path)
    if request.get("schema_version") != REQUEST_SCHEMA:
        raise ValueError(f"request schema must be {REQUEST_SCHEMA}")
    if request.get("mode") != "proposal_only":
        raise ValueError("Beta-1 request mode must be proposal_only")
    if decision not in ALLOWED_DECISIONS:
        raise ValueError(f"decision must be one of {sorted(ALLOWED_DECISIONS)}")
    if not proposal_path.is_file():
        raise FileNotFoundError(f"missing proposal artifact: {proposal_path}")

    now = _now()
    receipt = {
        "schema_version": RECEIPT_SCHEMA,
        "request_id": _required_str(request.get("request_id"), "request_id"),
        "decided_at": now,
        "operator_id": operator_id,
        "decision": decision,
        "decision_scope": "proposal_review_only",
        "reason": reason,
        "proposal_request": {
            "path": str(request_path.resolve()),
            "sha256": _sha256(request_path),
        },
        "proposal_artifact": {
            "path": str(proposal_path.resolve()),
            "sha256": _sha256(proposal_path),
        },
        "mode": "proposal_only",
        "merge_allowed": False,
        "push_allowed": False,
        "deploy_allowed": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
        "h3_boundary": _h3_boundary(),
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(output_path, receipt)
    validation = validate_receipt(receipt_path=output_path)
    if not validation["passed"]:
        raise ValueError(f"operator receipt failed validation: {validation['failure_reasons']}")

    audit_written = False
    if audit_output_path is not None:
        _write_jsonl(
            audit_output_path,
            [_audit_record(receipt, output_path=output_path, actor_id=audit_actor_id, recorded_at=now)],
            append=append,
        )
        audit_written = True

    return {
        "schema_version": "beta1-operator-decision-receipt-write-report:v1",
        "receipt_written": True,
        "receipt_path": str(output_path.resolve()),
        "receipt_sha256": _sha256(output_path),
        "request_id": receipt["request_id"],
        "decision": decision,
        "audit_output_path": str(audit_output_path.resolve()) if audit_output_path else None,
        "audit_written": audit_written,
        "validation": validation,
        "non_claims": list(NON_CLAIMS),
    }


def validate_receipt(
    *,
    receipt_path: Path,
    request_path: Path | None = None,
    proposal_path: Path | None = None,
) -> dict[str, Any]:
    failures: list[str] = []
    receipt = _safe_read_json(receipt_path, failures, "receipt")
    if not isinstance(receipt, dict):
        return _validation_report(receipt_path, failures or ["receipt must be a JSON object"])

    if receipt.get("schema_version") != RECEIPT_SCHEMA:
        failures.append(f"schema_version must be {RECEIPT_SCHEMA}")
    if receipt.get("decision") not in ALLOWED_DECISIONS:
        failures.append("decision must be approved, rejected, or deferred")
    if receipt.get("decision_scope") != "proposal_review_only":
        failures.append("decision_scope must be proposal_review_only")
    if receipt.get("mode") != "proposal_only":
        failures.append("mode must be proposal_only")
    for flag in DANGEROUS_FLAGS:
        if receipt.get(flag) is not False:
            failures.append(f"{flag} must be false")

    request_ref = _as_dict(receipt.get("proposal_request"), "proposal_request", failures)
    proposal_ref = _as_dict(receipt.get("proposal_artifact"), "proposal_artifact", failures)
    expected_request = request_path or _path_from_ref(request_ref)
    expected_proposal = proposal_path or _path_from_ref(proposal_ref)
    request = _validate_file_hash(expected_request, request_ref, failures, "proposal_request")
    _validate_file_hash(expected_proposal, proposal_ref, failures, "proposal_artifact")

    if isinstance(request, dict):
        if request.get("schema_version") != REQUEST_SCHEMA:
            failures.append(f"proposal_request schema_version must be {REQUEST_SCHEMA}")
        if request.get("mode") != "proposal_only":
            failures.append("proposal_request.mode must be proposal_only")
        if request.get("request_id") != receipt.get("request_id"):
            failures.append("receipt request_id must match proposal_request request_id")
        if request.get("h3_boundary", {}).get("h3_production_readiness_claimed") is not False:
            failures.append("proposal_request must not claim H.3 production readiness")

    return _validation_report(receipt_path, failures)


def _repo_snapshot(repo_root: Path, *, base_ref: str | None) -> dict[str, Any]:
    snapshot = {
        "repo_root": str(repo_root),
        "branch": _git(repo_root, "rev-parse", "--abbrev-ref", "HEAD").strip(),
        "head_commit": _git(repo_root, "rev-parse", "HEAD").strip(),
        "remote_origin_url": _git_optional(repo_root, "config", "--get", "remote.origin.url"),
        "status_short": _git(repo_root, "status", "--short"),
        "diff_stat": _git_optional(repo_root, "diff", "--stat"),
        "diff_name_status": _git_optional(repo_root, "diff", "--name-status"),
        "tracked_file_count": _count_lines(_git_optional(repo_root, "ls-files")),
    }
    if base_ref:
        snapshot["base_ref"] = base_ref
        snapshot["base_commit"] = _git(repo_root, "rev-parse", base_ref).strip()
        snapshot["base_diff_stat"] = _git_optional(repo_root, "diff", "--stat", base_ref, "HEAD")
        snapshot["base_diff_name_status"] = _git_optional(repo_root, "diff", "--name-status", base_ref, "HEAD")
    return snapshot


def _delivery_contract() -> dict[str, Any]:
    return {
        "required_sections": [
            "Scope",
            "Repository Evidence",
            "Findings",
            "Proposal",
            "Risks",
            "Operator Decision Required",
            "H3 Boundary",
        ],
        "proposal_only": True,
        "operator_decision_required": True,
        "forbidden_output_claims": [
            "merged",
            "pushed",
            "deployed",
            "production ready",
            "H.3 ready",
        ],
    }


def _h3_boundary() -> dict[str, Any]:
    return {
        "h3_remains_blocked": True,
        "h3_production_readiness_claimed": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
    }


def _audit_record(receipt: dict[str, Any], *, output_path: Path, actor_id: str, recorded_at: str) -> dict[str, Any]:
    return {
        "type": "audit_event_recorded",
        "actor_id": actor_id,
        "status": "recorded",
        "audit_event_ref": f"beta1-operator-decision:{receipt['request_id']}",
        "audit_ref_kind": "beta1_repo_review_operator_decision_receipt",
        "recorded_at": recorded_at,
        "source_evidence_ref": str(output_path.resolve()),
        "request_id": receipt["request_id"],
        "decision": receipt["decision"],
        "decision_scope": receipt["decision_scope"],
        "merge_allowed": receipt["merge_allowed"],
        "push_allowed": receipt["push_allowed"],
        "deploy_allowed": receipt["deploy_allowed"],
        "production_runtime_execution_allowed": receipt["production_runtime_execution_allowed"],
        "production_receipt_write_allowed": receipt["production_receipt_write_allowed"],
        "non_claims": list(NON_CLAIMS),
    }


def _repo_root(repo: Path) -> Path:
    root = _git(repo, "rev-parse", "--show-toplevel").strip()
    if not root:
        raise RuntimeError(f"not a git repository: {repo}")
    return Path(root).resolve()


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=repo,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout


def _git_optional(repo: Path, *args: str) -> str | None:
    result = subprocess.run(
        ["git", *args],
        cwd=repo,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return result.stdout if result.returncode == 0 else None


def _validate_file_hash(
    path: Path | None,
    ref: dict[str, Any],
    failures: list[str],
    label: str,
) -> dict[str, Any] | None:
    if path is None:
        failures.append(f"{label}.path is missing")
        return None
    if not path.is_file():
        failures.append(f"{label}.path is not a file: {path}")
        return None
    actual_hash = _sha256(path)
    if str(ref.get("sha256") or "") != actual_hash:
        failures.append(f"{label}.sha256 does not match file bytes")
    if label == "proposal_request":
        data = _safe_read_json(path, failures, label)
        return data if isinstance(data, dict) else None
    return None


def _path_from_ref(ref: dict[str, Any]) -> Path | None:
    raw = ref.get("path")
    return Path(str(raw)) if raw else None


def _as_dict(value: Any, label: str, failures: list[str]) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    failures.append(f"{label} must be an object")
    return {}


def _safe_read_json(path: Path, failures: list[str], label: str) -> Any:
    try:
        return _read_json(path)
    except Exception as exc:  # noqa: BLE001 - validation report needs the reason.
        failures.append(f"{label} could not be read: {exc}")
        return None


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_json(payload) + "\n", encoding="utf-8")


def _write_jsonl(path: Path, rows: list[dict[str, Any]], *, append: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    mode = "a" if append else "w"
    with path.open(mode, encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def _json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _required_str(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a non-empty string")
    return value


def _validation_report(receipt_path: Path, failures: list[str]) -> dict[str, Any]:
    return {
        "schema_version": VALIDATION_SCHEMA,
        "receipt_path": str(receipt_path.resolve()),
        "passed": not failures,
        "failure_reasons": failures,
        "checked_at": _now(),
        "non_claims": list(NON_CLAIMS),
    }


def _count_lines(value: str | None) -> int:
    if not value:
        return 0
    return len([line for line in value.splitlines() if line.strip()])


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _timestamp_id() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


if __name__ == "__main__":
    sys.exit(main())
