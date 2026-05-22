#!/usr/bin/env python3
"""Record operator decisions on Beta-3 sandbox apply evidence.

This receipt closes the sandbox-review step. Even an approved receipt only
allows the next source-apply gate to be designed or reviewed. It never applies
patches to the source repo, commits, pushes, merges, deploys, executes
production runtime actions, or writes production receipts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from beta3_controlled_apply_sandbox import SCHEMA_VERSION as SANDBOX_SCHEMA


RECEIPT_SCHEMA = "beta3-post-sandbox-operator-receipt:v1"
VALIDATION_SCHEMA = "beta3-post-sandbox-operator-receipt-validation:v1"
DECISIONS = {"approved", "rejected", "deferred"}
NON_CLAIMS = (
    "beta3_post_sandbox_receipt_is_l1_controlled_pilot_only",
    "beta3_post_sandbox_receipt_does_not_apply_patch_to_source_repo_worktree",
    "beta3_post_sandbox_receipt_does_not_authorize_commit_push_merge_or_deploy",
    "beta3_post_sandbox_receipt_does_not_claim_h3_production_readiness",
    "beta3_post_sandbox_receipt_does_not_write_production_receipts",
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    record = subparsers.add_parser("record", help="record post-sandbox operator decision")
    record.add_argument("--sandbox-report", required=True)
    record.add_argument("--output", required=True)
    record.add_argument("--decision", required=True, choices=sorted(DECISIONS))
    record.add_argument("--operator-id", default="l1-controlled-pilot-operator")
    record.add_argument("--reason", required=True)
    record.add_argument("--audit-output")
    record.add_argument("--audit-actor-id", default="audit-owner-001")
    record.add_argument("--append", action="store_true")

    validate = subparsers.add_parser("validate", help="validate a post-sandbox operator receipt")
    validate.add_argument("--receipt", required=True)
    validate.add_argument("--output")

    args = parser.parse_args(argv)
    if args.command == "record":
        report = record_post_sandbox_receipt(
            sandbox_report_path=Path(args.sandbox_report),
            output_path=Path(args.output),
            decision=args.decision,
            operator_id=args.operator_id,
            reason=args.reason,
            audit_output_path=Path(args.audit_output) if args.audit_output else None,
            audit_actor_id=args.audit_actor_id,
            append=args.append,
        )
    elif args.command == "validate":
        report = validate_post_sandbox_receipt(Path(args.receipt))
        if args.output:
            _write_json(Path(args.output), report)
    else:
        raise AssertionError(f"unknown command: {args.command}")
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report.get("validation", report).get("passed") else 1


def record_post_sandbox_receipt(
    *,
    sandbox_report_path: Path,
    output_path: Path,
    decision: str,
    operator_id: str,
    reason: str,
    audit_output_path: Path | None,
    audit_actor_id: str,
    append: bool,
) -> dict[str, Any]:
    if decision not in DECISIONS:
        raise ValueError(f"decision must be one of {sorted(DECISIONS)}")
    operator_id = _required_str(operator_id, "operator_id")
    reason = _required_str(reason, "reason")
    sandbox_report = _read_json_object(sandbox_report_path)
    sandbox_failures: list[str] = []
    _validate_sandbox_report(sandbox_report, sandbox_failures, approval_required=decision == "approved")
    if sandbox_failures:
        raise ValueError(f"sandbox report is not usable for {decision} receipt: {sandbox_failures}")

    now = _now()
    request_id = _sandbox_request_id(sandbox_report)
    receipt = {
        "schema_version": RECEIPT_SCHEMA,
        "request_id": request_id,
        "recorded_at": now,
        "operator_id": operator_id,
        "decision": decision,
        "decision_scope": "sandbox_replay_review_only",
        "reason": reason,
        "source_sandbox_report": _artifact_ref(sandbox_report_path),
        "source_candidate_report": _sandbox_candidate_ref(sandbox_report),
        "sandbox_summary": {
            "passed": sandbox_report.get("passed"),
            "sandbox_status": sandbox_report.get("sandbox_status"),
            "sandbox_patch_apply_performed": sandbox_report.get("execution_boundary", {}).get(
                "sandbox_patch_apply_performed"
            ),
            "source_repo_patch_apply_performed": sandbox_report.get("execution_boundary", {}).get(
                "source_repo_patch_apply_performed"
            ),
            "worktree_cleaned": sandbox_report.get("sandbox", {}).get("worktree_cleaned"),
            "worktree_snapshot_unchanged": sandbox_report.get("source_repo", {}).get(
                "worktree_snapshot_unchanged"
            ),
            "test_command_count": len(_as_list(sandbox_report.get("sandbox", {}).get("tests"))),
        },
        "next_gate_review_allowed": decision == "approved",
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
    _write_json(output_path, receipt)
    validation = validate_post_sandbox_receipt(output_path)
    if validation["passed"] is not True:
        raise ValueError(f"post-sandbox receipt failed validation: {validation['failure_reasons']}")

    audit_written = False
    if audit_output_path is not None:
        _write_jsonl(
            audit_output_path,
            [_audit_record(receipt, output_path=output_path, actor_id=audit_actor_id, recorded_at=now)],
            append=append,
        )
        audit_written = True
    return {
        "schema_version": "beta3-post-sandbox-operator-receipt-write-report:v1",
        "receipt_written": True,
        "receipt_path": str(output_path.resolve()),
        "receipt_sha256": _sha256(output_path),
        "request_id": request_id,
        "decision": decision,
        "audit_written": audit_written,
        "audit_output_path": str(audit_output_path.resolve()) if audit_output_path else None,
        "validation": validation,
        "non_claims": list(NON_CLAIMS),
    }


def validate_post_sandbox_receipt(receipt_path: Path) -> dict[str, Any]:
    failures: list[str] = []
    receipt = _safe_read_json(receipt_path, failures, "receipt")
    if not isinstance(receipt, dict):
        return _validation_report(receipt_path, failures or ["receipt must be a JSON object"])
    if receipt.get("schema_version") != RECEIPT_SCHEMA:
        failures.append(f"schema_version must be {RECEIPT_SCHEMA}")
    if receipt.get("decision") not in DECISIONS:
        failures.append("decision must be approved, rejected, or deferred")
    if receipt.get("decision_scope") != "sandbox_replay_review_only":
        failures.append("decision_scope must be sandbox_replay_review_only")
    if not isinstance(receipt.get("reason"), str) or not receipt.get("reason", "").strip():
        failures.append("reason must be a non-empty string")
    for flag in (
        "source_repo_apply_allowed",
        "commit_allowed",
        "push_allowed",
        "merge_allowed",
        "deploy_allowed",
        "production_runtime_execution_allowed",
        "production_receipt_write_allowed",
    ):
        if receipt.get(flag) is not False:
            failures.append(f"{flag} must be false")
    if receipt.get("next_gate_review_allowed") is not (receipt.get("decision") == "approved"):
        failures.append("next_gate_review_allowed must match approved decision only")

    sandbox_ref = _as_dict(receipt.get("source_sandbox_report"), "source_sandbox_report", failures)
    sandbox_report = _validate_ref_json(sandbox_ref, failures, "source_sandbox_report")
    if isinstance(sandbox_report, dict):
        _validate_sandbox_report(
            sandbox_report,
            failures,
            approval_required=receipt.get("decision") == "approved",
        )
        if _sandbox_request_id(sandbox_report) != receipt.get("request_id"):
            failures.append("request_id must match source sandbox candidate")
        candidate_ref = _as_dict(receipt.get("source_candidate_report"), "source_candidate_report", failures)
        expected_candidate = _sandbox_candidate_ref(sandbox_report)
        if candidate_ref != expected_candidate:
            failures.append("source_candidate_report must match sandbox candidate report reference")
    h3_boundary = _as_dict(receipt.get("h3_boundary"), "h3_boundary", failures)
    if h3_boundary.get("h3_remains_blocked") is not True:
        failures.append("h3_boundary.h3_remains_blocked must be true")
    if h3_boundary.get("h3_production_readiness_claimed") is not False:
        failures.append("h3_boundary.h3_production_readiness_claimed must be false")
    return _validation_report(receipt_path, failures)


def _validate_sandbox_report(
    report: dict[str, Any],
    failures: list[str],
    *,
    approval_required: bool,
) -> None:
    if report.get("schema_version") != SANDBOX_SCHEMA:
        failures.append(f"sandbox report schema_version must be {SANDBOX_SCHEMA}")
        return
    boundary = _as_dict(report.get("execution_boundary"), "sandbox.execution_boundary", failures)
    if boundary.get("source_repo_patch_apply_performed") is not False:
        failures.append("sandbox source_repo_patch_apply_performed must be false")
    for flag in (
        "commit_allowed_by_this_gate",
        "push_allowed_by_this_gate",
        "merge_allowed_by_this_gate",
        "deploy_allowed_by_this_gate",
        "production_runtime_execution_allowed",
        "production_receipt_write_allowed",
    ):
        if boundary.get(flag) is not False:
            failures.append(f"sandbox execution_boundary.{flag} must be false")
    if not approval_required:
        return
    if report.get("passed") is not True:
        failures.append("approved receipt requires passed sandbox report")
    if report.get("sandbox_status") != "applied_and_cleaned":
        failures.append("approved receipt requires sandbox_status applied_and_cleaned")
    if boundary.get("sandbox_patch_apply_performed") is not True:
        failures.append("approved receipt requires sandbox patch apply performed")
    if report.get("source_repo", {}).get("worktree_snapshot_unchanged") is not True:
        failures.append("approved receipt requires unchanged source repo Git snapshot")
    sandbox = _as_dict(report.get("sandbox"), "sandbox", failures)
    if sandbox.get("worktree_cleaned") is not True:
        failures.append("approved receipt requires cleaned sandbox worktree")
    applied_diff = _as_dict(sandbox.get("applied_diff"), "sandbox.applied_diff", failures)
    _validate_ref_bytes(applied_diff, failures, "sandbox.applied_diff")
    for index, test in enumerate(_as_list(sandbox.get("tests"))):
        if not isinstance(test, dict) or test.get("returncode") != 0:
            failures.append(f"approved receipt requires sandbox test #{index + 1} success")


def _sandbox_candidate_ref(sandbox_report: dict[str, Any]) -> dict[str, Any]:
    value = sandbox_report.get("candidate_report")
    return dict(value) if isinstance(value, dict) else {}


def _sandbox_request_id(sandbox_report: dict[str, Any]) -> str | None:
    recheck = sandbox_report.get("candidate_recheck")
    source = recheck.get("source_beta2_outcome") if isinstance(recheck, dict) else None
    value = source.get("request_id") if isinstance(source, dict) else None
    return value if isinstance(value, str) and value else None


def _audit_record(receipt: dict[str, Any], *, output_path: Path, actor_id: str, recorded_at: str) -> dict[str, Any]:
    return {
        "type": "audit_event_recorded",
        "actor_id": actor_id,
        "status": "recorded",
        "audit_event_ref": f"beta3-post-sandbox-operator-decision:{receipt['request_id']}",
        "audit_ref_kind": "beta3_post_sandbox_operator_receipt",
        "recorded_at": recorded_at,
        "source_evidence_ref": str(output_path.resolve()),
        "request_id": receipt["request_id"],
        "decision": receipt["decision"],
        "decision_scope": receipt["decision_scope"],
        "next_gate_review_allowed": receipt["next_gate_review_allowed"],
        "source_repo_apply_allowed": False,
        "commit_allowed": False,
        "push_allowed": False,
        "merge_allowed": False,
        "deploy_allowed": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
        "non_claims": list(NON_CLAIMS),
    }


def _artifact_ref(path: Path) -> dict[str, str]:
    if not path.is_file():
        raise FileNotFoundError(f"artifact path is not a file: {path}")
    return {"path": str(path.resolve()), "sha256": _sha256(path)}


def _validate_ref_json(ref: dict[str, Any], failures: list[str], label: str) -> Any:
    path = _validate_ref_bytes(ref, failures, label)
    return _safe_read_json(path, failures, label) if path else None


def _validate_ref_bytes(ref: dict[str, Any], failures: list[str], label: str) -> Path | None:
    raw_path = ref.get("path")
    if not isinstance(raw_path, str) or not raw_path.strip():
        failures.append(f"{label}.path must be a non-empty string")
        return None
    path = Path(raw_path)
    if not path.is_file():
        failures.append(f"{label}.path is not a file: {path}")
        return None
    if ref.get("sha256") != _sha256(path):
        failures.append(f"{label}.sha256 does not match file bytes")
    return path


def _as_dict(value: Any, label: str, failures: list[str]) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    failures.append(f"{label} must be an object")
    return {}


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _read_json_object(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"JSON object required: {path}")
    return data


def _safe_read_json(path: Path | None, failures: list[str], label: str) -> Any:
    if path is None:
        return None
    try:
        return _read_json_object(path)
    except Exception as exc:  # noqa: BLE001 - validation report needs artifact reason.
        failures.append(f"{label} could not be read: {exc}")
        return None


def _required_str(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a non-empty string")
    return value


def _validation_report(path: Path, failures: list[str]) -> dict[str, Any]:
    return {
        "schema_version": VALIDATION_SCHEMA,
        "passed": not failures,
        "failure_reasons": failures,
        "checked_at": _now(),
        "receipt_path": str(path.resolve()),
        "receipt_sha256": _sha256(path) if path.is_file() else None,
        "non_claims": list(NON_CLAIMS),
    }


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_jsonl(path: Path, rows: list[dict[str, Any]], *, append: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a" if append else "w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


if __name__ == "__main__":
    sys.exit(main())
