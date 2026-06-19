"""Receipt writing and validation for Beta-3 source apply."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from beta_evidence import (
        artifact_ref as _evidence_artifact_ref,
        safe_read_json_object,
        sha256_file,
        validate_ref_bytes,
        write_json,
    )
except ModuleNotFoundError:
    from scripts.beta_evidence import (
        artifact_ref as _evidence_artifact_ref,
        safe_read_json_object,
        sha256_file,
        validate_ref_bytes,
        write_json,
    )

try:
    from beta3_source_apply_boundaries import (
        NON_CLAIMS,
        h3_boundary,
        test_evidence_status,
        validate_false_boundary_flags,
        validate_h3_boundary,
    )
except ModuleNotFoundError:
    from scripts.beta3_source_apply_boundaries import (
        NON_CLAIMS,
        h3_boundary,
        test_evidence_status,
        validate_false_boundary_flags,
        validate_h3_boundary,
    )

try:
    from beta2_patch_proposal import parse_patch_target_paths
    from beta3_source_apply_authorization import AUTHORIZATION_SCHEMA
    from beta3_source_apply_worktree import repo_snapshot
except ModuleNotFoundError:
    from scripts.beta2_patch_proposal import parse_patch_target_paths
    from scripts.beta3_source_apply_authorization import AUTHORIZATION_SCHEMA
    from scripts.beta3_source_apply_worktree import repo_snapshot


RECEIPT_SCHEMA = "beta3-post-source-apply-receipt:v1"
RECEIPT_VALIDATION_SCHEMA = "beta3-post-source-apply-receipt-validation:v1"


def write_post_apply_receipt(
    *,
    receipt_path: Path,
    authorization_path: Path,
    authorization: dict[str, Any],
    before: dict[str, str],
    after: dict[str, str],
    applied_diff: dict[str, str],
    test_runs: list[dict[str, Any]],
    tests_passed: bool,
) -> None:
    patch_path = _validate_ref_path(
        authorization["source_patch_proposal"],
        "source_patch_proposal",
    )
    receipt = {
        "schema_version": RECEIPT_SCHEMA,
        "recorded_at": _now(),
        "request_id": authorization.get("request_id"),
        "receipt_scope": "source_worktree_apply_only",
        "source_authorization": _artifact_ref(authorization_path),
        "source_patch_proposal": authorization["source_patch_proposal"],
        "applied_target_paths": parse_patch_target_paths(
            patch_path.read_text(encoding="utf-8")
        ),
        "target_repo": {
            "repo_root": authorization["target_repo"]["repo_root"],
            "before": before,
            "after": after,
        },
        "applied_diff": applied_diff,
        "tests": test_runs,
        "tests_passed": tests_passed,
        "test_evidence_status": test_evidence_status(test_runs),
        "source_repo_apply_performed": True,
        "commit_allowed": False,
        "push_allowed": False,
        "merge_allowed": False,
        "deploy_allowed": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
        "h3_boundary": h3_boundary(),
        "non_claims": list(NON_CLAIMS),
    }
    write_json(receipt_path, receipt)


def validate_post_source_apply_receipt(receipt_path: Path) -> dict[str, Any]:
    failures: list[str] = []
    receipt = _safe_read_json(receipt_path, failures, "receipt")
    if not isinstance(receipt, dict):
        return _receipt_validation_report(
            receipt_path,
            failures or ["receipt must be a JSON object"],
        )
    if receipt.get("schema_version") != RECEIPT_SCHEMA:
        failures.append(f"schema_version must be {RECEIPT_SCHEMA}")
    if receipt.get("receipt_scope") != "source_worktree_apply_only":
        failures.append("receipt_scope must be source_worktree_apply_only")
    if receipt.get("source_repo_apply_performed") is not True:
        failures.append("source_repo_apply_performed must be true")
    if receipt.get("test_evidence_status") not in {"not_run", "passed", "failed"}:
        failures.append("test_evidence_status must be not_run, passed, or failed")
    validate_false_boundary_flags(receipt, failures)
    validate_h3_boundary(receipt, failures)

    authorization_ref = _as_ref(
        receipt.get("source_authorization"),
        failures,
        "source_authorization",
    )
    authorization_path = _validate_ref_bytes(
        authorization_ref,
        failures,
        "source_authorization",
    )
    authorization = _safe_read_json(authorization_path, failures, "source authorization")
    if not isinstance(authorization, dict):
        authorization = {}
    if authorization.get("schema_version") != AUTHORIZATION_SCHEMA:
        failures.append(f"source authorization schema_version must be {AUTHORIZATION_SCHEMA}")
    if authorization.get("source_repo_apply_authorized") is not True:
        failures.append("source authorization must authorize source repo apply")
    if authorization.get("source_repo_apply_performed") is not False:
        failures.append("source authorization must not claim source repo apply performed")
    if receipt.get("request_id") != authorization.get("request_id"):
        failures.append("request_id must match source authorization")
    if receipt.get("source_patch_proposal") != authorization.get("source_patch_proposal"):
        failures.append("source_patch_proposal must match source authorization")

    patch_path = _validate_ref_bytes(
        _as_ref(receipt.get("source_patch_proposal"), failures, "source_patch_proposal"),
        failures,
        "source_patch_proposal",
    )
    if patch_path is not None:
        target_paths = parse_patch_target_paths(patch_path.read_text(encoding="utf-8"))
        if receipt.get("applied_target_paths") != target_paths:
            failures.append("applied_target_paths must match source patch proposal")
        _validate_allowlist(
            target_paths,
            authorization.get("allowed_path_prefixes"),
            failures,
        )
    _validate_ref_bytes(
        _as_ref(receipt.get("applied_diff"), failures, "applied_diff"),
        failures,
        "applied_diff",
    )

    target_repo = _as_dict(receipt.get("target_repo"), failures, "target_repo")
    repo = Path(str(target_repo.get("repo_root") or ""))
    snapshot = repo_snapshot(repo, failures)
    if target_repo.get("before") != authorization.get("target_repo", {}).get(
        "authorization_snapshot"
    ):
        failures.append("target_repo.before must match authorization snapshot")
    if target_repo.get("after") != snapshot:
        failures.append("target repo snapshot drifted after post-apply receipt")
    if target_repo.get("after", {}).get("head_commit") != authorization.get(
        "target_repo", {}
    ).get("expected_head_commit"):
        failures.append("post-apply HEAD must remain at authorized expected_head_commit")
    tests = receipt.get("tests")
    if not isinstance(tests, list):
        failures.append("tests must be a list")
    elif receipt.get("tests_passed") is True and any(
        not isinstance(run, dict) or run.get("returncode") != 0 for run in tests
    ):
        failures.append("tests_passed receipt requires all test returncodes to be zero")
    elif receipt.get("test_evidence_status") != test_evidence_status(
        [run for run in tests if isinstance(run, dict)]
    ):
        failures.append("test_evidence_status must match tests")
    return _receipt_validation_report(receipt_path, failures)


def _validate_allowlist(target_paths: list[str], prefixes: Any, failures: list[str]) -> None:
    allowed = [item for item in prefixes if isinstance(item, str)] if isinstance(prefixes, list) else []
    if not allowed:
        failures.append("source authorization allowed_path_prefixes must not be empty")
    for target in target_paths:
        if not any(
            target.startswith(prefix) if prefix.endswith("/") else target == prefix
            for prefix in allowed
        ):
            failures.append(f"applied target path is outside authorization allowlist: {target}")


def _validate_ref_path(ref: dict[str, Any], label: str) -> Path:
    path = Path(str(ref.get("path") or ""))
    if not path.is_file():
        raise FileNotFoundError(f"{label}.path is not a file: {path}")
    return path


def _artifact_ref(path: Path) -> dict[str, str]:
    return _evidence_artifact_ref(path)


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


def _validate_ref_bytes(
    ref: dict[str, Any],
    failures: list[str],
    label: str,
) -> Path | None:
    return validate_ref_bytes(ref, failures, label)


def _safe_read_json(path: Path | None, failures: list[str], label: str) -> Any:
    return safe_read_json_object(path, failures, label)


def _receipt_validation_report(path: Path, failures: list[str]) -> dict[str, Any]:
    return {
        "schema_version": RECEIPT_VALIDATION_SCHEMA,
        "passed": not failures,
        "failure_reasons": failures,
        "checked_at": _now(),
        "receipt_path": str(path.resolve()),
        "receipt_sha256": sha256_file(path) if path.is_file() else None,
        "non_claims": list(NON_CLAIMS),
    }


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
