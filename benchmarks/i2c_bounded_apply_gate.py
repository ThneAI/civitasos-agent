"""Run I.2-C bounded apply in an isolated workspace.

I.2-C consumes a passed I.2-B provider contrast report and a human/operator
bounded apply spec. It may write only under the run-root isolation workspace. It
must not modify the source tree, Git, runtime state, deploy targets, or
production systems.
"""

from __future__ import annotations

import argparse
import difflib
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from benchmarks.i_gate_evidence import (
    all_checks_passed,
    artifact_ref,
    check,
    object_value,
    objects_value,
    read_json_object,
    sha256_file,
    sha256_text,
    write_json_object,
)

CHAIN_SCHEMA = "i2c-bounded-apply-chain:v1"
APPLY_SPEC_SCHEMA = "i2c-bounded-apply-spec:v1"
AUTHORIZATION_SCHEMA = "i2c-bounded-apply-authorization:v1"
PREFLIGHT_SCHEMA = "i2c-bounded-apply-isolation-preflight:v1"
APPLY_RECEIPT_SCHEMA = "i2c-bounded-apply-receipt:v1"
ROLLBACK_SCHEMA = "i2c-bounded-apply-rollback-or-abort-receipt:v1"
RECONCILIATION_SCHEMA = "i2c-bounded-apply-operator-reconciliation:v1"
I2B_PROVIDER_CONTRAST_SCHEMA = "i2b-provider-contrast-gate:v1"

MAX_ALLOWED_FILES = 5
MAX_PATCH_BYTES = 64 * 1024


def run_gate(
    *,
    i2b_contrast_path: Path,
    apply_spec_path: Path,
    source_root: Path,
    output_root: Path,
    operator_id: str = "operator-cc",
) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "authorization": output_root / "i2c_bounded_apply_authorization.json",
        "preflight": output_root / "i2c_bounded_apply_isolation_preflight.json",
        "apply": output_root / "i2c_bounded_apply_receipt.json",
        "rollback_or_abort": output_root / "i2c_bounded_apply_rollback_or_abort_receipt.json",
        "reconciliation": output_root / "i2c_bounded_apply_operator_reconciliation.json",
        "summary": output_root / "i2c_bounded_apply_chain_summary.json",
    }
    workspace = output_root / "isolation_workspace"

    authorization = write_authorization(
        i2b_contrast_path=i2b_contrast_path,
        apply_spec_path=apply_spec_path,
        source_root=source_root,
        output=artifacts["authorization"],
        operator_id=operator_id,
    )
    preflight = write_isolation_preflight(
        authorization_path=artifacts["authorization"],
        source_root=source_root,
        workspace=workspace,
        output=artifacts["preflight"],
    )
    apply = write_apply_receipt(
        authorization_path=artifacts["authorization"],
        preflight_path=artifacts["preflight"],
        source_root=source_root,
        output=artifacts["apply"],
    )
    rollback = write_rollback_or_abort_receipt(
        apply_path=artifacts["apply"],
        preflight_path=artifacts["preflight"],
        output=artifacts["rollback_or_abort"],
    )
    reconciliation = write_reconciliation(
        authorization_path=artifacts["authorization"],
        preflight_path=artifacts["preflight"],
        apply_path=artifacts["apply"],
        rollback_or_abort_path=artifacts["rollback_or_abort"],
        output=artifacts["reconciliation"],
    )

    reports = [authorization, preflight, apply, rollback, reconciliation]
    passed = all(report.get("passed") is True for report in reports)
    summary = {
        "schema_version": CHAIN_SCHEMA,
        "passed": passed,
        "failure_reasons": _collect_failures(*reports),
        "source_artifacts": {
            "i2b_provider_contrast": artifact_ref(i2b_contrast_path),
            "apply_spec": artifact_ref(apply_spec_path),
        },
        "artifacts": {name: artifact_ref(path) for name, path in artifacts.items() if name != "summary"},
        "readiness": {
            "state": "i2c_bounded_apply_passed" if passed else "blocked_i2c_bounded_apply",
            "i2c_bounded_apply_complete": passed,
            "i2d_commit_push_pr_discussion_ready": passed,
            "real_task_command_allowed": False,
            "source_or_git_write_allowed": False,
            "production_transition_allowed": False,
        },
        "boundary": _boundary(
            authorization_recording_allowed=passed,
            isolation_preflight_recording_allowed=passed,
            apply_receipt_recording_allowed=passed,
            rollback_or_abort_recording_allowed=passed,
            operator_reconciliation_recording_allowed=passed,
            isolated_workspace_write_allowed=passed,
        ),
        "non_claims": [
            "i2c_bounded_apply_does_not_modify_host_source_tree",
            "i2c_bounded_apply_does_not_authorize_git_push_pr_merge_or_deploy",
            "i2c_bounded_apply_does_not_authorize_production_transition",
        ],
    }
    write_json_object(artifacts["summary"], summary)
    return summary


def write_authorization(
    *,
    i2b_contrast_path: Path,
    apply_spec_path: Path,
    source_root: Path,
    output: Path,
    operator_id: str,
) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    i2b = read_json_object(i2b_contrast_path)
    spec = read_json_object(apply_spec_path)
    allowed_files = _safe_relative_files(spec.get("allowed_files"), failures, "allowed_files")
    patches = objects_value(spec.get("patches"))

    check(checks, failures, "i2b_provider_contrast_passed", i2b.get("schema_version") == I2B_PROVIDER_CONTRAST_SCHEMA and i2b.get("passed") is True)
    check(checks, failures, "i2b_discussion_ready", object_value(i2b.get("readiness")).get("i2c_bounded_apply_discussion_ready") is True)
    check(checks, failures, "i2b_kept_write_boundaries_closed", _write_boundaries_closed(object_value(i2b.get("boundary"))))
    check(checks, failures, "apply_spec_schema_valid", spec.get("schema_version") == APPLY_SPEC_SCHEMA)
    check(checks, failures, "operator_id_present", bool(_text(operator_id)))
    check(checks, failures, "objective_present", bool(_text(spec.get("objective"))))
    check(checks, failures, "allowed_files_within_limit", 0 < len(allowed_files) <= MAX_ALLOWED_FILES)
    check(checks, failures, "patches_present", bool(patches))
    _validate_spec_constraints(spec, checks, failures)
    _validate_patches(
        patches=patches,
        allowed_files=allowed_files,
        source_root=source_root,
        checks=checks,
        failures=failures,
    )

    passed = all_checks_passed(checks, failures)
    report = {
        "schema_version": AUTHORIZATION_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "source_artifacts": {
            "i2b_provider_contrast": artifact_ref(i2b_contrast_path),
            "apply_spec": artifact_ref(apply_spec_path),
        },
        "authorization": {
            "operator_id": operator_id,
            "decision": "authorize_i2c_bounded_apply_in_isolation" if passed else "blocked_i2c_authorization",
            "task_id": spec.get("task_id"),
            "objective": spec.get("objective"),
            "executor_alias": spec.get("executor_alias"),
            "allowed_files": allowed_files,
            "max_allowed_files": MAX_ALLOWED_FILES,
            "max_patch_bytes": MAX_PATCH_BYTES,
            "scope": "isolated_workspace_bounded_apply_only",
        },
        "readiness": {
            "state": "i2c_bounded_apply_ready_for_preflight" if passed else "blocked_i2c_authorization",
            "bounded_apply_authorized_for_isolation_preflight": passed,
            "apply_allowed_before_preflight": False,
        },
        "boundary": _boundary(authorization_recording_allowed=True),
    }
    write_json_object(output, report)
    return report


def write_isolation_preflight(*, authorization_path: Path, source_root: Path, workspace: Path, output: Path) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    authorization = read_json_object(authorization_path)
    auth = object_value(authorization.get("authorization"))
    allowed_files = _safe_relative_files(auth.get("allowed_files"), failures, "authorization.allowed_files")

    check(checks, failures, "authorization_passed", authorization.get("schema_version") == AUTHORIZATION_SCHEMA and authorization.get("passed") is True)
    check(checks, failures, "source_root_exists", source_root.is_dir())
    if workspace.exists():
        shutil.rmtree(workspace)
    source_workspace = workspace / "source"
    original_workspace = workspace / "original"
    for rel in allowed_files:
        src = source_root / rel
        dst = source_workspace / rel
        original = original_workspace / rel
        if src.is_file():
            dst.parent.mkdir(parents=True, exist_ok=True)
            original.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
            shutil.copy2(src, original)
    check(checks, failures, "workspace_created", source_workspace.is_dir() and original_workspace.is_dir())
    check(checks, failures, "allowlisted_files_copied", all((source_workspace / rel).is_file() and (original_workspace / rel).is_file() for rel in allowed_files))

    passed = all_checks_passed(checks, failures)
    report = {
        "schema_version": PREFLIGHT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "source_artifacts": {"authorization": artifact_ref(authorization_path)},
        "isolation": {
            "workspace": str(workspace.resolve()),
            "source_workspace": str(source_workspace.resolve()),
            "original_workspace": str(original_workspace.resolve()),
            "allowed_write_roots": [str(source_workspace.resolve())],
            "source_root": str(source_root.resolve()),
            "host_source_tree_write_allowed": False,
            "git_allowed": False,
            "network_allowed": False,
            "runtime_state_mutation_allowed": False,
            "deploy_allowed": False,
            "production_transition_allowed": False,
        },
        "readiness": {
            "state": "i2c_isolation_preflight_passed" if passed else "blocked_i2c_isolation_preflight",
            "bounded_apply_allowed_in_isolation": passed,
        },
        "boundary": _boundary(isolation_preflight_recording_allowed=True, isolated_workspace_write_allowed=passed),
    }
    write_json_object(output, report)
    return report


def write_apply_receipt(*, authorization_path: Path, preflight_path: Path, source_root: Path, output: Path) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    authorization = read_json_object(authorization_path)
    preflight = read_json_object(preflight_path)
    spec_ref = object_value(authorization.get("source_artifacts")).get("apply_spec")
    spec_path = Path(str(object_value(spec_ref).get("path") or ""))
    spec = read_json_object(spec_path) if spec_path.is_file() else {}
    patches = objects_value(spec.get("patches"))
    isolation = object_value(preflight.get("isolation"))
    source_workspace = Path(str(isolation.get("source_workspace") or ""))

    check(checks, failures, "authorization_passed", authorization.get("passed") is True)
    check(checks, failures, "preflight_passed", preflight.get("schema_version") == PREFLIGHT_SCHEMA and preflight.get("passed") is True)
    check(checks, failures, "source_workspace_exists", source_workspace.is_dir())
    applied_files: list[dict[str, Any]] = []
    if all_checks_passed(checks, failures):
        for patch in patches:
            rel = _safe_relative_path(patch.get("path"), failures, "patch.path")
            if not rel:
                continue
            source_file = source_root / rel
            workspace_file = source_workspace / rel
            before_text = workspace_file.read_text(encoding="utf-8") if workspace_file.is_file() else ""
            host_before_sha = sha256_file(source_file) if source_file.is_file() else ""
            new_content = str(patch.get("new_content") or "")
            workspace_file.write_text(new_content, encoding="utf-8")
            after_text = workspace_file.read_text(encoding="utf-8")
            host_after_sha = sha256_file(source_file) if source_file.is_file() else ""
            if host_before_sha != host_after_sha:
                failures.append(f"host source file changed during isolated apply: {rel}")
            applied_files.append({
                "path": rel,
                "host_before_sha256": host_before_sha,
                "host_after_sha256": host_after_sha,
                "workspace_after_sha256": sha256_file(workspace_file),
                "diff_sha256": sha256_text(_unified_diff(rel, before_text, after_text)),
                "host_source_unchanged": host_before_sha == host_after_sha,
            })
    check(checks, failures, "patches_applied", len(applied_files) == len(patches) and bool(applied_files))
    check(checks, failures, "host_source_tree_unchanged", all(item.get("host_source_unchanged") is True for item in applied_files))

    passed = all_checks_passed(checks, failures)
    report = {
        "schema_version": APPLY_RECEIPT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "source_artifacts": {
            "authorization": artifact_ref(authorization_path),
            "preflight": artifact_ref(preflight_path),
            "apply_spec": artifact_ref(spec_path) if spec_path.is_file() else None,
        },
        "apply": {
            "execution_kind": "isolated_workspace_bounded_apply",
            "task_id": spec.get("task_id"),
            "applied_files": applied_files,
            "workspace": str(source_workspace.resolve()) if source_workspace else "",
            "host_source_tree_modified": False if applied_files else None,
            "git_used": False,
            "network_used": False,
            "runtime_state_mutated": False,
            "production_touched": False,
        },
        "readiness": {
            "state": "i2c_bounded_apply_receipt_present" if passed else "blocked_i2c_apply",
            "bounded_apply_receipt_present": passed,
        },
        "boundary": _boundary(apply_receipt_recording_allowed=True, isolated_workspace_write_allowed=passed),
    }
    write_json_object(output, report)
    return report


def write_rollback_or_abort_receipt(*, apply_path: Path, preflight_path: Path, output: Path) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    apply = read_json_object(apply_path)
    preflight = read_json_object(preflight_path)
    isolation = object_value(preflight.get("isolation"))
    original_workspace = Path(str(isolation.get("original_workspace") or ""))
    rollback_workspace = Path(str(isolation.get("workspace") or "")) / "rollback_verification"
    applied_files = objects_value(object_value(apply.get("apply")).get("applied_files"))

    check(checks, failures, "apply_passed", apply.get("schema_version") == APPLY_RECEIPT_SCHEMA and apply.get("passed") is True)
    check(checks, failures, "original_workspace_exists", original_workspace.is_dir())
    rollback_refs: list[dict[str, Any]] = []
    if all_checks_passed(checks, failures):
        for item in applied_files:
            rel = str(item.get("path") or "")
            original_file = original_workspace / rel
            rollback_file = rollback_workspace / rel
            if original_file.is_file():
                rollback_file.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(original_file, rollback_file)
                rollback_refs.append({"path": rel, "rollback_copy": artifact_ref(rollback_file)})
    check(checks, failures, "rollback_verification_written", len(rollback_refs) == len(applied_files) and bool(rollback_refs))

    passed = all_checks_passed(checks, failures)
    report = {
        "schema_version": ROLLBACK_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "source_artifacts": {"apply": artifact_ref(apply_path), "preflight": artifact_ref(preflight_path)},
        "rollback_or_abort": {
            "rollback_required_for_host": False,
            "abort_required": False,
            "reason": "bounded apply occurred only in isolated workspace",
            "rollback_verification_refs": rollback_refs,
            "workspace_cleanup_allowed": True,
        },
        "readiness": {
            "state": "i2c_rollback_or_abort_receipt_present" if passed else "blocked_i2c_rollback_or_abort",
            "rollback_or_abort_receipt_present": passed,
        },
        "boundary": _boundary(rollback_or_abort_recording_allowed=True),
    }
    write_json_object(output, report)
    return report


def write_reconciliation(
    *,
    authorization_path: Path,
    preflight_path: Path,
    apply_path: Path,
    rollback_or_abort_path: Path,
    output: Path,
) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    authorization = read_json_object(authorization_path)
    preflight = read_json_object(preflight_path)
    apply = read_json_object(apply_path)
    rollback = read_json_object(rollback_or_abort_path)
    for label, report, schema in (
        ("authorization", authorization, AUTHORIZATION_SCHEMA),
        ("preflight", preflight, PREFLIGHT_SCHEMA),
        ("apply", apply, APPLY_RECEIPT_SCHEMA),
        ("rollback_or_abort", rollback, ROLLBACK_SCHEMA),
    ):
        check(checks, failures, f"{label}_passed", report.get("schema_version") == schema and report.get("passed") is True)
    apply_body = object_value(apply.get("apply"))
    check(checks, failures, "host_source_tree_not_modified", apply_body.get("host_source_tree_modified") is False)
    check(checks, failures, "no_git_network_runtime_or_production", apply_body.get("git_used") is False and apply_body.get("network_used") is False and apply_body.get("runtime_state_mutated") is False and apply_body.get("production_touched") is False)

    passed = all_checks_passed(checks, failures)
    report = {
        "schema_version": RECONCILIATION_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "source_artifacts": {
            "authorization": artifact_ref(authorization_path),
            "preflight": artifact_ref(preflight_path),
            "apply": artifact_ref(apply_path),
            "rollback_or_abort": artifact_ref(rollback_or_abort_path),
        },
        "operator_reconciliation": {
            "decision": "i2c_bounded_apply_passed" if passed else "blocked_i2c_reconciliation",
            "reason": "Bounded apply was confined to isolated workspace; host source, Git, runtime, deploy, and production stayed closed." if passed else "I.2-C evidence chain failed one or more hard controls.",
        },
        "readiness": {
            "state": "i2c_bounded_apply_passed" if passed else "blocked_i2c_reconciliation",
            "i2c_bounded_apply_complete": passed,
            "i2d_commit_push_pr_discussion_ready": passed,
            "real_task_command_allowed": False,
            "source_or_git_write_allowed": False,
            "production_transition_allowed": False,
        },
        "boundary": _boundary(operator_reconciliation_recording_allowed=True),
        "non_claims": [
            "i2c_reconciliation_does_not_authorize_host_source_write",
            "i2c_reconciliation_does_not_authorize_git_or_deploy",
            "i2c_reconciliation_does_not_unlock_production",
        ],
    }
    write_json_object(output, report)
    return report


def _validate_spec_constraints(spec: dict[str, Any], checks: dict[str, bool], failures: list[str]) -> None:
    constraints = object_value(spec.get("constraints"))
    check(checks, failures, "constraints_present", bool(constraints))
    check(checks, failures, "git_not_allowed", constraints.get("git_allowed") is False)
    check(checks, failures, "deploy_not_allowed", constraints.get("deploy_allowed") is False)
    check(checks, failures, "production_not_allowed", constraints.get("production_transition_allowed") is False)
    check(checks, failures, "host_source_write_not_allowed", constraints.get("host_source_tree_write_allowed") is False)


def _validate_patches(
    *,
    patches: list[dict[str, Any]],
    allowed_files: list[str],
    source_root: Path,
    checks: dict[str, bool],
    failures: list[str],
) -> None:
    total_bytes = 0
    valid_paths = True
    expected_hashes = True
    for patch in patches:
        rel = _safe_relative_path(patch.get("path"), failures, "patch.path")
        if not rel or rel not in allowed_files:
            valid_paths = False
            continue
        source_file = source_root / rel
        if not source_file.is_file():
            failures.append(f"patch source file missing: {rel}")
            expected_hashes = False
            continue
        expected_sha = _text(patch.get("expected_sha256"))
        if expected_sha != sha256_file(source_file):
            expected_hashes = False
        total_bytes += len(str(patch.get("new_content") or "").encode("utf-8"))
    check(checks, failures, "patch_paths_are_allowlisted", valid_paths)
    check(checks, failures, "patch_expected_hashes_match", expected_hashes)
    check(checks, failures, "patch_bytes_within_limit", total_bytes <= MAX_PATCH_BYTES)


def _safe_relative_files(value: Any, failures: list[str], label: str) -> list[str]:
    if not isinstance(value, list):
        failures.append(f"{label} must be a list")
        return []
    result: list[str] = []
    for item in value:
        rel = _safe_relative_path(item, failures, label)
        if rel and rel not in result:
            result.append(rel)
    return result


def _safe_relative_path(value: Any, failures: list[str], label: str) -> str:
    text = _text(value)
    path = Path(text)
    if not text or path.is_absolute() or ".." in path.parts or ".git" in path.parts:
        failures.append(f"{label} must be a safe relative path")
        return ""
    return text


def _write_boundaries_closed(boundary: dict[str, Any]) -> bool:
    return (
        boundary.get("real_task_command_allowed") is False
        and boundary.get("source_tree_write_allowed") is False
        and boundary.get("git_write_allowed") is False
        and boundary.get("runtime_state_mutation_allowed") is False
        and boundary.get("deploy_allowed") is False
        and boundary.get("production_transition_allowed") is False
    )


def _boundary(**overrides: bool) -> dict[str, bool]:
    base = {
        "real_task_command_allowed": False,
        "host_source_tree_write_allowed": False,
        "source_tree_write_allowed": False,
        "isolated_workspace_write_allowed": False,
        "git_write_allowed": False,
        "runtime_state_mutation_allowed": False,
        "deploy_allowed": False,
        "production_transition_allowed": False,
        "authorization_recording_allowed": False,
        "isolation_preflight_recording_allowed": False,
        "apply_receipt_recording_allowed": False,
        "rollback_or_abort_recording_allowed": False,
        "operator_reconciliation_recording_allowed": False,
    }
    base.update(overrides)
    return base


def _unified_diff(path: str, before: str, after: str) -> str:
    return "".join(difflib.unified_diff(
        before.splitlines(keepends=True),
        after.splitlines(keepends=True),
        fromfile=f"a/{path}",
        tofile=f"b/{path}",
    ))


def _collect_failures(*reports: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    for report in reports:
        failures.extend(str(item) for item in report.get("failure_reasons", []) if item)
    return failures


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--i2b-contrast", required=True)
    parser.add_argument("--apply-spec", required=True)
    parser.add_argument("--source-root", required=True)
    parser.add_argument("--output-root", required=True)
    parser.add_argument("--operator-id", default="operator-cc")
    args = parser.parse_args()
    report = run_gate(
        i2b_contrast_path=Path(args.i2b_contrast).resolve(),
        apply_spec_path=Path(args.apply_spec).resolve(),
        source_root=Path(args.source_root).resolve(),
        output_root=Path(args.output_root).resolve(),
        operator_id=args.operator_id,
    )
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    raise SystemExit(0 if report["passed"] else 2)


if __name__ == "__main__":
    main()
