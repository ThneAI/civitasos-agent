#!/usr/bin/env python3
"""Record explicit Beta-3 operator authorization for source worktree apply.

This gate consumes a passed Beta-3 multi-Agent review packet and records the
operator intent required before a later source-worktree apply tool may run. It
requires a clean source Git snapshot, explicit allowed paths, and a rollback
evidence reference. It never applies patches, commits, pushes, merges, deploys,
executes production runtime actions, or writes production receipts.
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

from beta2_patch_proposal import parse_patch_target_paths
from beta3_multi_agent_review_packet import NON_CLAIMS as PACKET_NON_CLAIMS
from beta3_multi_agent_review_packet import validate_review_packet


AUTHORIZATION_SCHEMA = "beta3-source-apply-authorization:v1"
VALIDATION_SCHEMA = "beta3-source-apply-authorization-validation:v1"
NON_CLAIMS = (
    "beta3_source_apply_authorization_is_l1_controlled_pilot_only",
    "beta3_source_apply_authorization_does_not_apply_patch",
    "beta3_source_apply_authorization_does_not_authorize_commit_push_merge_or_deploy",
    "beta3_source_apply_authorization_does_not_claim_h3_production_readiness",
    "beta3_source_apply_authorization_does_not_write_production_receipts",
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    record = subparsers.add_parser("record", help="record source apply authorization")
    record.add_argument("--review-packet", required=True)
    record.add_argument("--repo", required=True)
    record.add_argument("--output", required=True)
    record.add_argument("--operator-id", default="l1-controlled-pilot-operator")
    record.add_argument("--reason", required=True)
    record.add_argument("--rollback-evidence-ref", required=True)
    record.add_argument("--allow-path-prefix", action="append", default=[])

    validate = subparsers.add_parser("validate", help="validate source apply authorization")
    validate.add_argument("--authorization", required=True)
    validate.add_argument("--output")

    args = parser.parse_args(argv)
    if args.command == "record":
        report = record_source_apply_authorization(
            review_packet_path=Path(args.review_packet),
            repo=Path(args.repo),
            output_path=Path(args.output),
            operator_id=args.operator_id,
            reason=args.reason,
            rollback_evidence_ref=args.rollback_evidence_ref,
            allow_path_prefixes=args.allow_path_prefix,
        )
    elif args.command == "validate":
        report = validate_source_apply_authorization(Path(args.authorization))
        if args.output:
            _write_json(Path(args.output), report)
    else:
        raise AssertionError(f"unknown command: {args.command}")
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report.get("validation", report).get("passed") else 1


def record_source_apply_authorization(
    *,
    review_packet_path: Path,
    repo: Path,
    output_path: Path,
    operator_id: str,
    reason: str,
    rollback_evidence_ref: str,
    allow_path_prefixes: list[str] | None,
) -> dict[str, Any]:
    failures: list[str] = []
    context = _load_packet_context(review_packet_path, failures)
    repo_root = _repo_root(repo, failures)
    operator_id = _required_text(operator_id, "operator_id")
    reason = _required_text(reason, "reason")
    rollback_evidence_ref = _required_text(rollback_evidence_ref, "rollback_evidence_ref")
    allowed_prefixes = _normalize_prefixes(allow_path_prefixes or [])
    if not allowed_prefixes:
        failures.append("allow_path_prefixes must not be empty")
    target_paths = _patch_target_paths(context.get("source_patch_proposal"), failures)
    for target in target_paths:
        if not _is_allowed_path(target, allowed_prefixes):
            failures.append(f"authorized target path is outside explicit allowlist: {target}")
    sandbox_repo = context.get("sandbox_source_repo", {})
    if repo_root is not None and sandbox_repo.get("repo_root") != str(repo_root):
        failures.append("authorization repo must match sandbox source repo")
    snapshot = _repo_snapshot(repo_root, failures) if repo_root is not None else {}
    if snapshot.get("head_commit") != sandbox_repo.get("proposal_head_commit"):
        failures.append("authorization repo HEAD must match sandbox proposal_head_commit")
    if snapshot.get("status_short"):
        failures.append("authorization repo worktree must be clean")
    if failures:
        raise ValueError(f"source apply authorization blocked: {failures}")

    authorization = {
        "schema_version": AUTHORIZATION_SCHEMA,
        "recorded_at": _now(),
        "request_id": context["request_id"],
        "operator_id": operator_id,
        "reason": reason,
        "rollback_evidence_ref": rollback_evidence_ref,
        "authorization_scope": "source_worktree_apply_only",
        "source_review_packet": _artifact_ref(review_packet_path),
        "source_patch_proposal": context["source_patch_proposal"],
        "source_sandbox_report": context["source_sandbox_report"],
        "target_repo": {
            "repo_root": str(repo_root),
            "expected_head_commit": sandbox_repo.get("proposal_head_commit"),
            "authorization_snapshot": snapshot,
        },
        "allowed_path_prefixes": allowed_prefixes,
        "authorized_target_paths": target_paths,
        "source_repo_apply_authorized": True,
        "source_repo_apply_performed": False,
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
    _write_json(output_path, authorization)
    validation = validate_source_apply_authorization(output_path)
    if validation["passed"] is not True:
        raise ValueError(f"written source apply authorization failed validation: {validation['failure_reasons']}")
    return {
        "schema_version": "beta3-source-apply-authorization-write-report:v1",
        "authorization_written": True,
        "authorization_path": str(output_path.resolve()),
        "authorization_sha256": _sha256(output_path),
        "request_id": context["request_id"],
        "validation": validation,
        "non_claims": list(NON_CLAIMS),
    }


def validate_source_apply_authorization(authorization_path: Path) -> dict[str, Any]:
    failures: list[str] = []
    authorization = _safe_read_json(authorization_path, failures, "authorization")
    if not isinstance(authorization, dict):
        return _validation_report(authorization_path, failures or ["authorization must be a JSON object"])
    if authorization.get("schema_version") != AUTHORIZATION_SCHEMA:
        failures.append(f"schema_version must be {AUTHORIZATION_SCHEMA}")
    if authorization.get("authorization_scope") != "source_worktree_apply_only":
        failures.append("authorization_scope must be source_worktree_apply_only")
    if not _text(authorization.get("operator_id")):
        failures.append("operator_id must be a non-empty string")
    if not _text(authorization.get("reason")):
        failures.append("reason must be a non-empty string")
    if not _text(authorization.get("rollback_evidence_ref")):
        failures.append("rollback_evidence_ref must be a non-empty string")
    if authorization.get("source_repo_apply_authorized") is not True:
        failures.append("source_repo_apply_authorized must be true")
    if authorization.get("source_repo_apply_performed") is not False:
        failures.append("source_repo_apply_performed must be false")
    _validate_false_boundary_flags(authorization, failures)
    _validate_h3_boundary(authorization, failures)

    packet_ref = _as_ref(authorization.get("source_review_packet"), failures, "source_review_packet")
    packet_path = _validate_ref_bytes(packet_ref, failures, "source_review_packet")
    context = _load_packet_context(packet_path, failures) if packet_path else {}
    if authorization.get("request_id") != context.get("request_id"):
        failures.append("request_id must match source review packet")
    for field in ("source_patch_proposal", "source_sandbox_report"):
        if authorization.get(field) != context.get(field):
            failures.append(f"{field} must match source review packet")

    target_paths = _patch_target_paths(context.get("source_patch_proposal"), failures)
    allowed_prefixes = _normalize_prefixes(_string_list(authorization.get("allowed_path_prefixes")))
    if not allowed_prefixes:
        failures.append("allowed_path_prefixes must not be empty")
    if authorization.get("authorized_target_paths") != target_paths:
        failures.append("authorized_target_paths must match source patch proposal")
    for target in target_paths:
        if not _is_allowed_path(target, allowed_prefixes):
            failures.append(f"authorized target path is outside explicit allowlist: {target}")

    target_repo = _as_dict(authorization.get("target_repo"), failures, "target_repo")
    repo_root = _repo_root(Path(str(target_repo.get("repo_root") or "")), failures)
    sandbox_repo = context.get("sandbox_source_repo", {})
    if repo_root is not None and str(repo_root) != sandbox_repo.get("repo_root"):
        failures.append("target_repo.repo_root must match sandbox source repo")
    snapshot = _repo_snapshot(repo_root, failures) if repo_root is not None else {}
    expected_snapshot = target_repo.get("authorization_snapshot")
    if snapshot != expected_snapshot:
        failures.append("target repo snapshot drifted after authorization")
    if target_repo.get("expected_head_commit") != sandbox_repo.get("proposal_head_commit"):
        failures.append("target_repo.expected_head_commit must match sandbox proposal_head_commit")
    if snapshot.get("head_commit") != target_repo.get("expected_head_commit"):
        failures.append("target repo HEAD must match expected_head_commit")
    if snapshot.get("status_short"):
        failures.append("target repo worktree must be clean")
    return _validation_report(authorization_path, failures)


def _load_packet_context(packet_path: Path | None, failures: list[str]) -> dict[str, Any]:
    if packet_path is None:
        return {}
    validation = validate_review_packet(packet_path)
    if validation.get("passed") is not True:
        failures.extend(f"review packet invalid: {reason}" for reason in validation.get("failure_reasons", []))
    packet = _safe_read_json(packet_path, failures, "review packet")
    if not isinstance(packet, dict):
        return {}
    if packet.get("passed") is not True:
        failures.append("source apply authorization requires passed multi-Agent review packet")
    sandbox_ref = _as_ref(packet.get("source_sandbox_report"), failures, "source_sandbox_report")
    sandbox = _validate_ref_json(sandbox_ref, failures, "source_sandbox_report")
    sandbox_repo = sandbox.get("source_repo") if isinstance(sandbox, dict) else None
    if not isinstance(sandbox_repo, dict):
        failures.append("source sandbox report source_repo must be an object")
        sandbox_repo = {}
    patch_ref = _as_ref(packet.get("source_patch_proposal"), failures, "source_patch_proposal")
    _validate_ref_bytes(patch_ref, failures, "source_patch_proposal")
    return {
        "request_id": packet.get("request_id"),
        "source_patch_proposal": patch_ref,
        "source_sandbox_report": sandbox_ref,
        "sandbox_source_repo": {
            "repo_root": sandbox_repo.get("repo_root"),
            "proposal_head_commit": sandbox_repo.get("proposal_head_commit"),
        },
    }


def _patch_target_paths(ref: Any, failures: list[str]) -> list[str]:
    patch_path = _validate_ref_bytes(_as_ref(ref, failures, "source_patch_proposal"), failures, "source_patch_proposal")
    if patch_path is None:
        return []
    targets = parse_patch_target_paths(patch_path.read_text(encoding="utf-8"))
    if not targets:
        failures.append("source patch proposal must contain target paths")
    return targets


def _repo_root(repo: Path, failures: list[str]) -> Path | None:
    result = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        cwd=repo,
        check=False,
        text=True,
        capture_output=True,
    )
    if result.returncode != 0:
        failures.append(f"repo must be a Git worktree: {repo}")
        return None
    return Path(result.stdout.strip()).resolve()


def _repo_snapshot(repo: Path | None, failures: list[str]) -> dict[str, str]:
    if repo is None:
        return {}
    head = _git(repo, failures, "rev-parse", "HEAD")
    status = _git(repo, failures, "status", "--short")
    return {"head_commit": head.strip(), "status_short": status}


def _git(repo: Path, failures: list[str], *args: str) -> str:
    result = subprocess.run(["git", *args], cwd=repo, check=False, text=True, capture_output=True)
    if result.returncode != 0:
        failures.append(f"git {' '.join(args)} failed for {repo}: {result.stderr.strip()}")
        return ""
    return result.stdout


def _normalize_prefixes(prefixes: list[str]) -> list[str]:
    normalized: list[str] = []
    for raw in prefixes:
        prefix = raw.strip().replace("\\", "/")
        if not prefix or prefix.startswith("/") or prefix.startswith("../") or "/../" in prefix:
            continue
        if prefix not in normalized:
            normalized.append(prefix)
    return normalized


def _is_allowed_path(target: str, prefixes: list[str]) -> bool:
    normalized = target.replace("\\", "/")
    return any(normalized.startswith(prefix) if prefix.endswith("/") else normalized == prefix for prefix in prefixes)


def _validate_false_boundary_flags(payload: dict[str, Any], failures: list[str]) -> None:
    for flag in (
        "commit_allowed",
        "push_allowed",
        "merge_allowed",
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


def _artifact_ref(path: Path) -> dict[str, str]:
    if not path.is_file():
        raise FileNotFoundError(f"artifact path is not a file: {path}")
    return {"path": str(path.resolve()), "sha256": _sha256(path)}


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


def _validate_ref_json(ref: dict[str, Any], failures: list[str], label: str) -> Any:
    path = _validate_ref_bytes(ref, failures, label)
    return _safe_read_json(path, failures, label) if path else None


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


def _safe_read_json(path: Path | None, failures: list[str], label: str) -> Any:
    if path is None:
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 - validation needs artifact reason.
        failures.append(f"{label} could not be read: {exc}")
        return None
    if not isinstance(payload, dict):
        failures.append(f"{label} must be a JSON object")
        return None
    return payload


def _required_text(value: Any, label: str) -> str:
    cleaned = _text(value)
    if not cleaned:
        raise ValueError(f"{label} must be a non-empty string")
    return cleaned


def _string_list(value: Any) -> list[str]:
    return [item for item in value if isinstance(item, str)] if isinstance(value, list) else []


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _validation_report(path: Path, failures: list[str]) -> dict[str, Any]:
    return {
        "schema_version": VALIDATION_SCHEMA,
        "passed": not failures,
        "failure_reasons": failures,
        "checked_at": _now(),
        "authorization_path": str(path.resolve()),
        "authorization_sha256": _sha256(path) if path.is_file() else None,
        "packet_non_claims": list(PACKET_NON_CLAIMS),
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
