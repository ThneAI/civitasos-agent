#!/usr/bin/env python3
"""Record and validate manual Beta-2 patch application evidence.

This script runs after an operator has manually applied a Beta-2 patch proposal.
It records the applied diff and test reference. It does not apply patches,
commit, push, merge, deploy, execute production runtime actions, or write
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

from beta1_repo_review_proposal import DANGEROUS_FLAGS
from beta2_patch_proposal import VALIDATION_SCHEMA as PATCH_VALIDATION_SCHEMA
from beta2_patch_proposal import validate_patch_proposal


RECEIPT_SCHEMA = "beta2-operator-applied-patch-receipt:v1"
VALIDATION_SCHEMA = "beta2-operator-applied-patch-receipt-validation:v1"
TEST_STATUSES = {"passed", "failed", "not-run"}
NON_CLAIMS = (
    "beta2_operator_apply_receipt_records_manual_l1_action_only",
    "beta2_operator_apply_receipt_does_not_apply_patch",
    "beta2_operator_apply_receipt_does_not_commit_push_merge_or_deploy",
    "beta2_operator_apply_receipt_does_not_authorize_production_runtime_execution",
    "beta2_operator_apply_receipt_does_not_write_production_receipts",
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    record = subparsers.add_parser("record", help="record operator manual patch application")
    record.add_argument("--repo", required=True)
    record.add_argument("--patch-validation", required=True)
    record.add_argument("--proposal-receipt", required=True)
    record.add_argument("--applied-diff", required=True)
    record.add_argument("--output", required=True)
    record.add_argument("--operator-id", default="l1-controlled-pilot-operator")
    record.add_argument("--reason", default="operator manually applied approved Beta-2 patch proposal")
    record.add_argument("--tests-status", required=True, choices=sorted(TEST_STATUSES))
    record.add_argument("--tests-ref", required=True)
    record.add_argument("--manual-apply-confirmed", action="store_true")
    record.add_argument("--audit-output")
    record.add_argument("--audit-actor-id", default="audit-owner-001")
    record.add_argument("--append", action="store_true")

    validate = subparsers.add_parser("validate", help="validate an operator applied-patch receipt")
    validate.add_argument("--receipt", required=True)
    validate.add_argument("--output")

    args = parser.parse_args(argv)
    if args.command == "record":
        report = record_operator_apply_receipt(
            repo=Path(args.repo),
            patch_validation_path=Path(args.patch_validation),
            proposal_receipt_path=Path(args.proposal_receipt),
            applied_diff_path=Path(args.applied_diff),
            output_path=Path(args.output),
            operator_id=args.operator_id,
            reason=args.reason,
            tests_status=args.tests_status,
            tests_ref=args.tests_ref,
            manual_apply_confirmed=args.manual_apply_confirmed,
            audit_output_path=Path(args.audit_output) if args.audit_output else None,
            audit_actor_id=args.audit_actor_id,
            append=args.append,
        )
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    if args.command == "validate":
        report = validate_operator_apply_receipt(Path(args.receipt))
        if args.output:
            _write_json(Path(args.output), report)
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
        return 0 if report["passed"] else 1
    raise AssertionError(f"unknown command: {args.command}")


def record_operator_apply_receipt(
    *,
    repo: Path,
    patch_validation_path: Path,
    proposal_receipt_path: Path,
    applied_diff_path: Path,
    output_path: Path,
    operator_id: str,
    reason: str,
    tests_status: str,
    tests_ref: str,
    manual_apply_confirmed: bool,
    audit_output_path: Path | None,
    audit_actor_id: str,
    append: bool,
) -> dict[str, Any]:
    if manual_apply_confirmed is not True:
        raise ValueError("record requires --manual-apply-confirmed")
    reason = _required_str(reason, "reason")
    if tests_status not in TEST_STATUSES:
        raise ValueError(f"tests_status must be one of {sorted(TEST_STATUSES)}")
    patch_validation = _load_passed_patch_validation(patch_validation_path)
    proposal_receipt = _load_approved_proposal_receipt(proposal_receipt_path)
    repo_root = _repo_root(repo)
    applied_validation = _validate_applied_diff(
        repo_root=repo_root,
        applied_diff_path=applied_diff_path,
        patch_validation=patch_validation,
    )

    now = _now()
    receipt = {
        "schema_version": RECEIPT_SCHEMA,
        "request_id": proposal_receipt["request_id"],
        "recorded_at": now,
        "operator_id": operator_id,
        "reason": reason,
        "manual_apply_confirmed": True,
        "source_patch_proposal": {
            "path": patch_validation["patch_path"],
            "sha256": patch_validation["patch_sha256"],
            "target_paths": patch_validation.get("target_paths", []),
        },
        "source_patch_validation": _artifact_ref(patch_validation_path),
        "source_proposal_receipt": _artifact_ref(proposal_receipt_path),
        "applied_diff": {
            **_artifact_ref(applied_diff_path),
            "target_paths": applied_validation.get("target_paths", []),
        },
        "applied_diff_validation": applied_validation,
        "repo_snapshot": _repo_snapshot(repo_root),
        "tests": {
            "status": tests_status,
            "ref": _required_str(tests_ref, "tests_ref"),
        },
        "auto_apply_performed": False,
        "commit_created_by_tool": False,
        "push_performed_by_tool": False,
        "merge_performed_by_tool": False,
        "deploy_performed_by_tool": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
        "h3_boundary": {
            "h3_remains_blocked": True,
            "h3_production_readiness_claimed": False,
        },
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(output_path, receipt)
    validation = validate_operator_apply_receipt(output_path)
    if validation["passed"] is not True:
        raise ValueError(f"operator apply receipt failed validation: {validation['failure_reasons']}")

    audit_written = False
    if audit_output_path is not None:
        _write_jsonl(
            audit_output_path,
            [_audit_record(receipt, output_path=output_path, actor_id=audit_actor_id, recorded_at=now)],
            append=append,
        )
        audit_written = True
    return {
        "schema_version": "beta2-operator-applied-patch-receipt-write-report:v1",
        "receipt_written": True,
        "receipt_path": str(output_path.resolve()),
        "receipt_sha256": _sha256(output_path),
        "request_id": receipt["request_id"],
        "manual_apply_confirmed": True,
        "tests_status": tests_status,
        "audit_written": audit_written,
        "audit_output_path": str(audit_output_path.resolve()) if audit_output_path else None,
        "validation": validation,
        "non_claims": list(NON_CLAIMS),
    }


def validate_operator_apply_receipt(receipt_path: Path) -> dict[str, Any]:
    failures: list[str] = []
    receipt = _safe_read_json(receipt_path, failures, "receipt")
    if not isinstance(receipt, dict):
        return _validation_report(receipt_path, failures or ["receipt must be a JSON object"])
    if receipt.get("schema_version") != RECEIPT_SCHEMA:
        failures.append(f"schema_version must be {RECEIPT_SCHEMA}")
    if receipt.get("manual_apply_confirmed") is not True:
        failures.append("manual_apply_confirmed must be true")
    if not isinstance(receipt.get("reason"), str) or not receipt.get("reason", "").strip():
        failures.append("reason must be a non-empty string")
    for flag in (
        "auto_apply_performed",
        "commit_created_by_tool",
        "push_performed_by_tool",
        "merge_performed_by_tool",
        "deploy_performed_by_tool",
        "production_runtime_execution_allowed",
        "production_receipt_write_allowed",
    ):
        if receipt.get(flag) is not False:
            failures.append(f"{flag} must be false")
    tests = _as_dict(receipt.get("tests"), "tests", failures)
    if tests.get("status") not in TEST_STATUSES:
        failures.append("tests.status must be passed, failed, or not-run")
    if not isinstance(tests.get("ref"), str) or not tests.get("ref", "").strip():
        failures.append("tests.ref must be a non-empty string")

    patch_validation_ref = _as_dict(receipt.get("source_patch_validation"), "source_patch_validation", failures)
    proposal_receipt_ref = _as_dict(receipt.get("source_proposal_receipt"), "source_proposal_receipt", failures)
    applied_diff_ref = _as_dict(receipt.get("applied_diff"), "applied_diff", failures)
    patch_validation = _validate_ref_json(patch_validation_ref, failures, "source_patch_validation")
    proposal_receipt = _validate_ref_json(proposal_receipt_ref, failures, "source_proposal_receipt")
    _validate_ref_bytes(applied_diff_ref, failures, "applied_diff")
    if isinstance(patch_validation, dict):
        _validate_patch_validation(patch_validation, failures)
        source_patch = _as_dict(receipt.get("source_patch_proposal"), "source_patch_proposal", failures)
        if source_patch.get("sha256") != patch_validation.get("patch_sha256"):
            failures.append("source_patch_proposal.sha256 must match source patch validation")
        if source_patch.get("path") != patch_validation.get("patch_path"):
            failures.append("source_patch_proposal.path must match source patch validation")
        _validate_target_subset(
            applied_diff_ref.get("target_paths"),
            patch_validation.get("target_paths"),
            failures,
        )
    if isinstance(proposal_receipt, dict):
        _validate_proposal_receipt(proposal_receipt, failures)
        if proposal_receipt.get("request_id") != receipt.get("request_id"):
            failures.append("request_id must match source proposal receipt")
    h3_boundary = _as_dict(receipt.get("h3_boundary"), "h3_boundary", failures)
    if h3_boundary.get("h3_remains_blocked") is not True:
        failures.append("h3_boundary.h3_remains_blocked must be true")
    if h3_boundary.get("h3_production_readiness_claimed") is not False:
        failures.append("h3_boundary.h3_production_readiness_claimed must be false")
    return _validation_report(receipt_path, failures)


def _load_passed_patch_validation(path: Path) -> dict[str, Any]:
    data = _read_json(path)
    failures: list[str] = []
    _validate_patch_validation(data, failures)
    if failures:
        raise ValueError(f"patch validation is not usable: {failures}")
    return data


def _load_approved_proposal_receipt(path: Path) -> dict[str, Any]:
    data = _read_json(path)
    failures: list[str] = []
    _validate_proposal_receipt(data, failures)
    if failures:
        raise ValueError(f"proposal receipt is not approved for manual apply: {failures}")
    return data


def _validate_patch_validation(data: dict[str, Any], failures: list[str]) -> None:
    if data.get("schema_version") != PATCH_VALIDATION_SCHEMA:
        failures.append(f"patch validation schema_version must be {PATCH_VALIDATION_SCHEMA}")
    if data.get("passed") is not True:
        failures.append("patch validation must be passed")
    patch_path = data.get("patch_path")
    patch_sha = data.get("patch_sha256")
    if not isinstance(patch_path, str) or not Path(patch_path).is_file():
        failures.append("patch validation patch_path must exist")
    elif _sha256(Path(patch_path)) != patch_sha:
        failures.append("patch validation patch_sha256 must match patch bytes")
    if not isinstance(data.get("target_paths"), list) or not data.get("target_paths"):
        failures.append("patch validation target_paths must be non-empty")


def _validate_proposal_receipt(data: dict[str, Any], failures: list[str]) -> None:
    if data.get("decision") != "approved":
        failures.append("source proposal receipt decision must be approved")
    for flag in DANGEROUS_FLAGS:
        if data.get(flag) is not False:
            failures.append(f"source proposal receipt {flag} must be false")


def _validate_applied_diff(*, repo_root: Path, applied_diff_path: Path, patch_validation: dict[str, Any]) -> dict[str, Any]:
    report = validate_patch_proposal(
        repo=repo_root,
        patch_path=applied_diff_path,
        allow_path_prefixes=patch_validation.get("allow_path_prefixes", []),
        deny_path_fragments=[],
    )
    if report["passed"] is not True:
        raise ValueError(f"applied diff validation failed: {report['failure_reasons']}")
    failures: list[str] = []
    _validate_target_subset(report.get("target_paths"), patch_validation.get("target_paths"), failures)
    if failures:
        raise ValueError(f"applied diff target paths do not match proposal: {failures}")
    return report


def _validate_target_subset(applied: Any, proposed: Any, failures: list[str]) -> None:
    if not isinstance(applied, list) or not applied:
        failures.append("applied diff target_paths must be non-empty")
        return
    if not isinstance(proposed, list) or not proposed:
        failures.append("source patch target_paths must be non-empty")
        return
    unexpected = sorted(set(str(path) for path in applied) - set(str(path) for path in proposed))
    if unexpected:
        failures.append(f"applied diff target_paths are outside proposal: {unexpected}")


def _audit_record(receipt: dict[str, Any], *, output_path: Path, actor_id: str, recorded_at: str) -> dict[str, Any]:
    return {
        "type": "audit_event_recorded",
        "actor_id": actor_id,
        "status": "recorded",
        "audit_event_ref": f"beta2-operator-applied-patch:{receipt['request_id']}",
        "audit_ref_kind": "beta2_operator_applied_patch_receipt",
        "recorded_at": recorded_at,
        "source_evidence_ref": str(output_path.resolve()),
        "request_id": receipt["request_id"],
        "manual_apply_confirmed": True,
        "applied_diff_sha256": receipt["applied_diff"]["sha256"],
        "applied_target_paths": receipt["applied_diff"].get("target_paths", []),
        "tests": receipt["tests"],
        "auto_apply_performed": False,
        "commit_created_by_tool": False,
        "push_performed_by_tool": False,
        "merge_performed_by_tool": False,
        "deploy_performed_by_tool": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
        "non_claims": list(NON_CLAIMS),
    }


def _repo_snapshot(repo_root: Path) -> dict[str, Any]:
    return {
        "repo_root": str(repo_root),
        "branch": _git(repo_root, "rev-parse", "--abbrev-ref", "HEAD").strip(),
        "head_commit": _git(repo_root, "rev-parse", "HEAD").strip(),
        "status_short": _git(repo_root, "status", "--short"),
    }


def _repo_root(repo: Path) -> Path:
    return Path(_git(repo, "rev-parse", "--show-toplevel").strip()).resolve()


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


def _artifact_ref(path: Path) -> dict[str, str]:
    if not path.is_file():
        raise FileNotFoundError(f"artifact path is not a file: {path}")
    return {"path": str(path.resolve()), "sha256": _sha256(path)}


def _validate_ref_json(ref: dict[str, Any], failures: list[str], label: str) -> Any:
    path = _validate_ref_bytes(ref, failures, label)
    if path is None:
        return None
    return _safe_read_json(path, failures, label)


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


def _safe_read_json(path: Path, failures: list[str], label: str) -> Any:
    try:
        return _read_json(path)
    except Exception as exc:  # noqa: BLE001
        failures.append(f"{label} could not be read: {exc}")
        return None


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _required_str(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a non-empty string")
    return value


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_jsonl(path: Path, rows: list[dict[str, Any]], *, append: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    mode = "a" if append else "w"
    with path.open(mode, encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _validation_report(path: Path, failures: list[str]) -> dict[str, Any]:
    return {
        "schema_version": VALIDATION_SCHEMA,
        "receipt_path": str(path.resolve()),
        "passed": not failures,
        "failure_reasons": failures,
        "checked_at": _now(),
        "non_claims": list(NON_CLAIMS),
    }


if __name__ == "__main__":
    sys.exit(main())
