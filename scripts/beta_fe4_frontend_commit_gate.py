#!/usr/bin/env python3
"""Create a Beta-FE-4 frontend commit authorization and commit receipt.

This gate consumes a passed Beta-FE-3 frontend apply receipt, stages only the
FE-3 allowed frontend slice, creates one local Git commit, and writes a receipt.
It never pushes, opens a PR, merges, deploys, runs production, or writes
production receipts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from civitasos_contracts.artifacts import build_artifact_envelope
    from civitasos_contracts.provenance import (
        build_git_release_provenance,
        build_governance_evidence,
    )
except ModuleNotFoundError:
    from scripts.civitasos_contracts.artifacts import build_artifact_envelope
    from scripts.civitasos_contracts.provenance import (
        build_git_release_provenance,
        build_governance_evidence,
    )

AUTHORIZATION_SCHEMA = "beta-fe4-frontend-commit-authorization:v1"
EXECUTION_SCHEMA = "beta-fe4-frontend-commit-execution-report:v1"
RECEIPT_SCHEMA = "beta-fe4-frontend-commit-receipt:v1"
FE3_SCHEMA = "beta-fe3-frontend-apply-receipt:v1"
NON_CLAIMS = (
    "beta_fe4_commit_gate_is_local_git_commit_only",
    "beta_fe4_commit_gate_does_not_push_open_pr_merge_or_deploy",
    "beta_fe4_commit_gate_does_not_claim_h3_production_readiness",
    "beta_fe4_commit_gate_does_not_write_production_receipts",
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--frontend-root", required=True)
    parser.add_argument("--source-fe3-receipt", required=True)
    parser.add_argument("--output-root", required=True)
    parser.add_argument("--commit-message", required=True)
    parser.add_argument("--operator-id", default="local-operator-cc")
    parser.add_argument("--operator-authorization", default="current_chat_fe4_commit_request")
    args = parser.parse_args(argv)

    report = run_commit_gate(
        frontend_root=Path(args.frontend_root),
        source_fe3_receipt=Path(args.source_fe3_receipt),
        output_root=Path(args.output_root),
        commit_message=args.commit_message,
        operator_id=args.operator_id,
        operator_authorization=args.operator_authorization,
    )
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report.get("passed") is True else 1


def run_commit_gate(
    *,
    frontend_root: Path,
    source_fe3_receipt: Path,
    output_root: Path,
    commit_message: str,
    operator_id: str,
    operator_authorization: str,
) -> dict[str, Any]:
    frontend_root = frontend_root.resolve()
    output_root = output_root.resolve()
    output_root.mkdir(parents=True, exist_ok=True)
    failures: list[str] = []
    fe3 = _read_json(source_fe3_receipt, failures, "FE-3 apply receipt")
    _validate_fe3(fe3, failures)
    changed_files = _string_list(fe3.get("changed_files")) if isinstance(fe3, dict) else []
    if not _text(commit_message):
        failures.append("commit_message must be non-empty")

    before = _repo_snapshot(frontend_root)
    current_changes = _changed_files(frontend_root)
    if sorted(current_changes) != sorted(changed_files):
        failures.append("current frontend worktree changed files must match FE-3 receipt changed_files")

    authorization_path = output_root / "beta_fe4_frontend_commit_authorization.json"
    authorization = _authorization_payload(
        source_fe3_receipt=source_fe3_receipt,
        frontend_root=frontend_root,
        before=before,
        changed_files=changed_files,
        commit_message=commit_message,
        operator_id=operator_id,
        operator_authorization=operator_authorization,
    )
    _write_json(authorization_path, authorization)

    stage = None
    staged_files: list[str] = []
    commit_run = None
    commit_id = None
    committed_files: list[str] = []
    if not failures:
        stage = _git(frontend_root, "add", "--", *changed_files)
        if stage["returncode"] != 0:
            failures.append("git add failed")
        staged_files = _git_lines(frontend_root, "diff", "--cached", "--name-only")
        if sorted(staged_files) != sorted(changed_files):
            failures.append("staged files must match FE-3 changed_files")
    if not failures:
        commit_run = _git(frontend_root, "commit", "-m", commit_message)
        if commit_run["returncode"] != 0:
            failures.append("git commit failed")
    after = _repo_snapshot(frontend_root)
    if commit_run and commit_run["returncode"] == 0:
        commit_id = after.get("head_commit")
        committed_files = _git_lines(frontend_root, "show", "--pretty=format:", "--name-only", commit_id)
        if sorted(committed_files) != sorted(changed_files):
            failures.append("committed files must match FE-3 changed_files")
        if after.get("head_commit") == before.get("head_commit"):
            failures.append("commit must advance HEAD")
        if after.get("status_short"):
            failures.append("frontend worktree must be clean after commit")
    elif not failures:
        failures.append("git commit was not performed")

    receipt_path = output_root / "beta_fe4_frontend_commit_receipt.json"
    receipt = None
    if not failures and commit_id:
        source_fe3_ref = _artifact_ref(source_fe3_receipt)
        authorization_ref = _artifact_ref(authorization_path)
        receipt = {
            "schema_version": RECEIPT_SCHEMA,
            "artifact_envelope": build_artifact_envelope(
                artifact_kind="receipt",
                plane="release",
                schema_version=RECEIPT_SCHEMA,
                artifact_id=f"fe4-commit:{commit_id}",
                subject_id=f"git-commit:{commit_id}",
                producer="beta_fe4_frontend_commit_gate",
                source_refs=[source_fe3_ref, authorization_ref],
                scope="local_git_commit",
            ),
            "checked_at": _now(),
            "passed": True,
            "decision": "beta_fe4_frontend_commit_receipt_passed",
            "source_fe3_receipt": source_fe3_ref,
            "source_commit_authorization": authorization_ref,
            "frontend_root": str(frontend_root),
            "target_repo": {"before": before, "after": after},
            "commit_id": commit_id,
            "commit_message": commit_message,
            "staged_files": staged_files,
            "committed_files": committed_files,
            "git_actions_performed": {"commit": True, "push": False, "pr": False, "merge": False, "deploy": False},
            "release_provenance": build_git_release_provenance(
                {
                    "source_apply_receipt": source_fe3_ref,
                    "commit_authorization": authorization_ref,
                },
                actions_observed={"commit": True},
                actions_performed_by_current_step={"commit": True},
            ),
            "boundary": _boundary(commit_allowed=True),
            "h3_boundary": _h3_boundary(),
            "non_claims": list(NON_CLAIMS),
        }
        _write_json(receipt_path, receipt)

    report = {
        "schema_version": EXECUTION_SCHEMA,
        "checked_at": _now(),
        "passed": not failures,
        "decision": "beta_fe4_frontend_commit_gate_passed" if not failures else "blocked",
        "failure_reasons": failures,
        "source_fe3_receipt": _artifact_ref(source_fe3_receipt),
        "commit_authorization": _artifact_ref(authorization_path),
        "commit_receipt": _artifact_ref(receipt_path) if receipt_path.is_file() else None,
        "frontend_root": str(frontend_root),
        "target_repo": {"before": before, "after": after},
        "changed_files": changed_files,
        "staged_files": staged_files,
        "committed_files": committed_files,
        "commit_id": commit_id,
        "commit_message": commit_message,
        "stage": stage,
        "commit": commit_run,
        "git_actions_performed": {"commit": bool(commit_id), "push": False, "pr": False, "merge": False, "deploy": False},
        "boundary": _boundary(commit_allowed=True),
        "h3_boundary": _h3_boundary(),
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(output_root / "beta_fe4_frontend_commit_execution_report.json", report)
    return report


def _validate_fe3(fe3: Any, failures: list[str]) -> None:
    if not isinstance(fe3, dict):
        failures.append("FE-3 receipt must be an object")
        return
    if fe3.get("schema_version") != FE3_SCHEMA:
        failures.append(f"FE-3 schema_version must be {FE3_SCHEMA}")
    if fe3.get("passed") is not True:
        failures.append("FE-3 receipt must be passed")
    if fe3.get("decision") != "beta_fe3_frontend_apply_receipt_passed":
        failures.append("FE-3 decision must be beta_fe3_frontend_apply_receipt_passed")
    if _exit_code(fe3.get("rollback_check")) != 0:
        failures.append("FE-3 rollback_check must pass")
    if not all(_exit_code(report) == 0 for report in fe3.get("verification_commands", [])):
        failures.append("FE-3 verification_commands must all pass")
    boundary = fe3.get("boundary")
    if not isinstance(boundary, dict):
        failures.append("FE-3 boundary must be an object")
    else:
        if boundary.get("frontend_code_modified") is not True or boundary.get("apply_allowed") is not True:
            failures.append("FE-3 must be a local frontend apply receipt")
        for field in ("commit_allowed", "push_allowed", "merge_allowed", "deploy_allowed", "production_runtime_execution_allowed", "production_receipt_write_allowed"):
            if boundary.get(field) is not False:
                failures.append(f"FE-3 boundary.{field} must be false")
    h3 = fe3.get("h3_boundary")
    if not isinstance(h3, dict) or h3.get("h3_remains_blocked") is not True or h3.get("h3_production_readiness_claimed") is not False:
        failures.append("FE-3 h3_boundary must keep H.3 blocked")
    changed_files = _string_list(fe3.get("changed_files"))
    allowed_files = _string_list(fe3.get("allowed_changed_files"))
    if not changed_files:
        failures.append("FE-3 changed_files must not be empty")
    if sorted(changed_files) != sorted(allowed_files):
        failures.append("FE-3 changed_files must match allowed_changed_files")


def _authorization_payload(
    *,
    source_fe3_receipt: Path,
    frontend_root: Path,
    before: dict[str, Any],
    changed_files: list[str],
    commit_message: str,
    operator_id: str,
    operator_authorization: str,
) -> dict[str, Any]:
    source_ref = _artifact_ref(source_fe3_receipt)
    return {
        "schema_version": AUTHORIZATION_SCHEMA,
        "artifact_envelope": build_artifact_envelope(
            artifact_kind="approval",
            plane="governance",
            schema_version=AUTHORIZATION_SCHEMA,
            artifact_id=f"fe4-commit-approval:{_sha256(source_fe3_receipt)[:16]}",
            subject_id=f"frontend-slice:{frontend_root.name}",
            producer="beta_fe4_frontend_commit_gate",
            source_refs=[source_ref],
            scope="local_git_commit_only",
        ),
        "created_at": _now(),
        "decision": "beta_fe4_frontend_commit_authorized",
        "operator_id": operator_id,
        "operator_authorization": operator_authorization,
        "source_fe3_receipt": source_ref,
        "frontend_root": str(frontend_root),
        "target_repo_before": before,
        "authorized_files": changed_files,
        "commit_message": commit_message,
        "authorization_scope": "local_git_commit_only",
        "governance_evidence": build_governance_evidence(
            {"source_apply_receipt": source_ref},
            assertions={
                "operator_id": operator_id,
                "authorized_file_count": len(changed_files),
                "authorization_scope": "local_git_commit_only",
            },
        ),
        "boundary": _boundary(commit_allowed=True),
        "h3_boundary": _h3_boundary(),
        "non_claims": list(NON_CLAIMS),
    }


def _repo_snapshot(repo: Path) -> dict[str, Any]:
    return {
        "head_commit": _git_text(repo, "rev-parse", "HEAD").strip(),
        "head_short": _git_text(repo, "rev-parse", "--short", "HEAD").strip(),
        "branch": _git_text(repo, "branch", "--show-current").strip(),
        "status_short": _git_text(repo, "status", "--short").splitlines(),
    }


def _changed_files(repo: Path) -> list[str]:
    tracked = set(_git_lines(repo, "diff", "--name-only"))
    untracked = set(_git_lines(repo, "ls-files", "--others", "--exclude-standard"))
    return sorted(tracked | untracked)


def _git(repo: Path, *args: str) -> dict[str, Any]:
    result = subprocess.run(["git", *args], cwd=repo, text=True, capture_output=True, check=False)
    return {"argv": ["git", *args], "returncode": result.returncode, "stdout": result.stdout, "stderr": result.stderr}


def _git_lines(repo: Path, *args: str) -> list[str]:
    return [line.strip() for line in _git_text(repo, *args).splitlines() if line.strip()]


def _git_text(repo: Path, *args: str) -> str:
    result = subprocess.run(["git", *args], cwd=repo, text=True, capture_output=True, check=False)
    if result.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {result.stderr}")
    return result.stdout


def _read_json(path: Path, failures: list[str], label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        failures.append(f"{label} not found: {path}")
    except json.JSONDecodeError as exc:
        failures.append(f"{label} is not valid JSON: {exc}")
    return {}


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _artifact_ref(path: Path) -> dict[str, str]:
    if not path.is_file():
        raise FileNotFoundError(f"artifact path is not a file: {path}")
    return {"path": str(path.resolve()), "sha256": _sha256(path)}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if str(item)]


def _exit_code(value: Any) -> int:
    if not isinstance(value, dict):
        return -1
    raw = value.get("exit_code")
    if raw is None:
        return -1
    return int(raw)


def _text(value: Any) -> str:
    return str(value or "").strip()


def _boundary(*, commit_allowed: bool) -> dict[str, bool]:
    return {
        "frontend_code_modified": True,
        "apply_allowed": True,
        "commit_allowed": commit_allowed,
        "push_allowed": False,
        "pr_allowed": False,
        "merge_allowed": False,
        "deploy_allowed": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
    }


def _h3_boundary() -> dict[str, bool]:
    return {"h3_remains_blocked": True, "h3_production_readiness_claimed": False}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


if __name__ == "__main__":
    raise SystemExit(main())
