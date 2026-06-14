#!/usr/bin/env python3
"""Beta-FE-9 post-merge frontend smoke gate.

This gate consumes a passed FE-8 merge receipt, verifies that the frontend
checkout is aligned with the merged remote base branch, runs explicit smoke
commands, and writes a post-merge smoke receipt. It does not push, open PRs,
merge, deploy, execute production runtime actions, or write production receipts.
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
    from civitasos_contracts.artifacts import artifact_ref, build_artifact_envelope
    from civitasos_contracts.provenance import (
        build_git_release_provenance,
        build_runtime_evidence,
    )
except ModuleNotFoundError:
    from scripts.civitasos_contracts.artifacts import artifact_ref, build_artifact_envelope
    from scripts.civitasos_contracts.provenance import (
        build_git_release_provenance,
        build_runtime_evidence,
    )

FE8_SCHEMA = "beta-fe8-frontend-merge-receipt:v1"
RECEIPT_SCHEMA = "beta-fe9-frontend-post-merge-smoke-receipt:v1"
EXECUTION_SCHEMA = "beta-fe9-frontend-post-merge-smoke-execution:v1"
NON_CLAIMS = (
    "beta_fe9_post_merge_smoke_is_l1_controlled_pilot_only",
    "beta_fe9_post_merge_smoke_consumes_fe8_merge_receipt",
    "beta_fe9_post_merge_smoke_does_not_push_open_pr_merge_or_deploy",
    "beta_fe9_post_merge_smoke_does_not_claim_h3_production_readiness",
    "beta_fe9_post_merge_smoke_does_not_write_production_receipts",
)

DEFAULT_COMMANDS = (
    "CI=true npm test -- --runInBand --watchAll=false TaskReadAdapter.test.ts",
    "npm run build",
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-fe8-receipt", required=True)
    parser.add_argument("--frontend-root", required=True)
    parser.add_argument("--output-root", required=True)
    parser.add_argument("--remote", default="origin")
    parser.add_argument("--base-branch")
    parser.add_argument("--verification-command", action="append", default=[])
    parser.add_argument("--operator-id", default="local-operator-cc")
    parser.add_argument("--operator-authorization", default="current_chat_fe9_post_merge_smoke_request")
    args = parser.parse_args(argv)

    report = run_post_merge_smoke(
        source_fe8_receipt=Path(args.source_fe8_receipt),
        frontend_root=Path(args.frontend_root),
        output_root=Path(args.output_root),
        remote=args.remote,
        base_branch=args.base_branch,
        verification_commands=args.verification_command or list(DEFAULT_COMMANDS),
        operator_id=args.operator_id,
        operator_authorization=args.operator_authorization,
    )
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report.get("passed") is True else 1


def run_post_merge_smoke(
    *,
    source_fe8_receipt: Path,
    frontend_root: Path,
    output_root: Path,
    remote: str,
    base_branch: str | None,
    verification_commands: list[str],
    operator_id: str,
    operator_authorization: str,
) -> dict[str, Any]:
    frontend_root = frontend_root.resolve()
    output_root = output_root.resolve()
    output_root.mkdir(parents=True, exist_ok=True)
    failures: list[str] = []
    fe8 = _read_json(source_fe8_receipt, failures, "FE-8 merge receipt")
    _validate_fe8(fe8, failures)
    branch = base_branch or _text(fe8.get("base_branch"))
    merge_commit = _text(fe8.get("base_branch_after_head"))
    if not branch:
        failures.append("base branch must be supplied or present in FE-8 receipt")
    if not verification_commands:
        failures.append("at least one verification command is required")

    before = _repo_snapshot(frontend_root, failures)
    fetch = _git(frontend_root, "fetch", remote, branch, "--prune") if not failures else None
    if fetch and fetch["returncode"] != 0:
        failures.append("git fetch failed")
    remote_head = _remote_head(frontend_root, remote, branch, failures) if branch and not failures else None
    local_head = _git_text(frontend_root, failures, "rev-parse", "HEAD").strip() if not failures else ""
    if remote_head != merge_commit:
        failures.append("remote base branch head must equal FE-8 merge commit")
    if local_head != remote_head:
        failures.append("local frontend HEAD must equal merged remote base branch head")
    if before.get("status_short"):
        failures.append("frontend worktree must be clean before post-merge smoke")

    command_reports: list[dict[str, Any]] = []
    if not failures:
        for command in verification_commands:
            result = _run_shell(frontend_root, command)
            command_reports.append(result)
            if result["returncode"] != 0:
                failures.append(f"verification command failed: {command}")

    after = _repo_snapshot(frontend_root, [])
    if after.get("status_short"):
        failures.append("frontend worktree must remain clean after post-merge smoke")
    if after.get("head_commit") != local_head and local_head:
        failures.append("post-merge smoke must not change frontend HEAD")

    source_ref = artifact_ref(source_fe8_receipt) if source_fe8_receipt.is_file() else None
    receipt = {
        "schema_version": RECEIPT_SCHEMA,
        "artifact_envelope": build_artifact_envelope(
            artifact_kind="receipt",
            plane="runtime",
            schema_version=RECEIPT_SCHEMA,
            artifact_id=f"fe9-smoke:{merge_commit or 'unknown'}",
            subject_id=f"frontend-release:{merge_commit or frontend_root.name}",
            producer="beta_fe9_frontend_post_merge_smoke",
            source_refs=[source_ref] if source_ref else [],
            scope="post_merge_runtime_smoke",
        ),
        "checked_at": _now(),
        "passed": not failures,
        "decision": "beta_fe9_frontend_post_merge_smoke_passed" if not failures else "blocked",
        "failure_reasons": failures,
        "source_fe8_receipt": source_ref,
        "frontend_root": str(frontend_root),
        "remote": remote,
        "base_branch": branch,
        "merge_commit": merge_commit,
        "remote_head": remote_head,
        "local_head": local_head,
        "repo_before": before,
        "repo_after": after,
        "fetch": fetch,
        "verification_commands": command_reports,
        "operator_id": operator_id,
        "operator_authorization": operator_authorization,
        "runtime_evidence": build_runtime_evidence(
            {},
            assertions={
                "verification_command_count": len(command_reports),
                "all_verification_commands_passed": all(
                    report.get("returncode") == 0 for report in command_reports
                ),
                "local_head_matches_remote_head": bool(local_head and local_head == remote_head),
            },
        ),
        "release_provenance": build_git_release_provenance(
            {"source_merge_receipt": source_ref},
            actions_observed={"commit": True, "push": True, "pr": True, "merge": True},
            actions_performed_by_current_step={},
        ),
        "git_actions_performed": {"commit": False, "push": False, "pr": False, "merge": False, "deploy": False},
        "boundary": _boundary(),
        "h3_boundary": _h3_boundary(),
        "non_claims": list(NON_CLAIMS),
    }
    receipt_path = output_root / "beta_fe9_frontend_post_merge_smoke_receipt.json"
    _write_json(receipt_path, receipt)
    execution = {
        "schema_version": EXECUTION_SCHEMA,
        "checked_at": _now(),
        "passed": receipt["passed"],
        "decision": "beta_fe9_frontend_post_merge_smoke_execution_passed" if receipt["passed"] else "blocked",
        "post_merge_smoke_receipt": _artifact_ref(receipt_path),
        "failure_reasons": failures,
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(output_root / "beta_fe9_frontend_post_merge_smoke_execution.json", execution)
    return receipt


def _validate_fe8(value: Any, failures: list[str]) -> None:
    if not isinstance(value, dict):
        failures.append("FE-8 receipt must be an object")
        return
    if value.get("schema_version") != FE8_SCHEMA:
        failures.append(f"FE-8 schema_version must be {FE8_SCHEMA}")
    if value.get("passed") is not True or value.get("decision") != "beta_fe8_frontend_merge_receipt_passed":
        failures.append("FE-8 receipt must be passed")
    pr = value.get("pr") if isinstance(value.get("pr"), dict) else {}
    if pr.get("state") != "MERGED":
        failures.append("FE-8 PR state must be MERGED")
    if _text(value.get("base_branch_after_head")) != _text(pr.get("mergeCommit", {}).get("oid")):
        failures.append("FE-8 base_branch_after_head must match PR mergeCommit oid")
    boundary = value.get("boundary") if isinstance(value.get("boundary"), dict) else {}
    if boundary.get("merge_allowed") is not True:
        failures.append("FE-8 boundary.merge_allowed must be true")
    for field in ("deploy_allowed", "production_runtime_execution_allowed", "production_receipt_write_allowed"):
        if boundary.get(field) is not False:
            failures.append(f"FE-8 boundary.{field} must be false")
    h3 = value.get("h3_boundary") if isinstance(value.get("h3_boundary"), dict) else {}
    if h3.get("h3_remains_blocked") is not True or h3.get("h3_production_readiness_claimed") is not False:
        failures.append("FE-8 must keep H.3 blocked")


def _boundary() -> dict[str, bool]:
    return {
        "frontend_code_modified": True,
        "apply_allowed": True,
        "commit_allowed": True,
        "push_allowed": True,
        "pr_allowed": True,
        "review_allowed": True,
        "merge_allowed": True,
        "post_merge_smoke_allowed": True,
        "deploy_allowed": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
    }


def _h3_boundary() -> dict[str, bool]:
    return {"h3_remains_blocked": True, "h3_production_readiness_claimed": False}


def _repo_snapshot(repo: Path, failures: list[str]) -> dict[str, Any]:
    return {
        "head_commit": _git_text(repo, failures, "rev-parse", "HEAD").strip(),
        "head_short": _git_text(repo, failures, "rev-parse", "--short", "HEAD").strip(),
        "branch": _git_text(repo, failures, "branch", "--show-current").strip(),
        "status_short": _git_text(repo, failures, "status", "--short").splitlines(),
    }


def _remote_head(repo: Path, remote: str, branch: str, failures: list[str]) -> str | None:
    result = _git(repo, "ls-remote", remote, f"refs/heads/{branch}")
    if result["returncode"] != 0:
        failures.append(f"git ls-remote failed for {remote}/{branch}")
        return None
    rows = (result.get("stdout") or "").strip().splitlines()
    if not rows:
        failures.append(f"remote branch not found: {remote}/{branch}")
        return None
    return rows[0].split()[0]


def _run_shell(cwd: Path, command: str) -> dict[str, Any]:
    result = subprocess.run(command, cwd=cwd, shell=True, text=True, capture_output=True, check=False)
    return {"command": command, "returncode": result.returncode, "stdout": result.stdout, "stderr": result.stderr}


def _git(repo: Path, *args: str) -> dict[str, Any]:
    result = subprocess.run(["git", *args], cwd=repo, text=True, capture_output=True, check=False)
    return {"argv": ["git", *args], "returncode": result.returncode, "stdout": result.stdout, "stderr": result.stderr}


def _git_text(repo: Path, failures: list[str], *args: str) -> str:
    result = _git(repo, *args)
    if result["returncode"] != 0:
        failures.append(f"git {' '.join(args)} failed: {result['stderr']}")
    return str(result.get("stdout", ""))


def _read_json(path: Path, failures: list[str], label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        failures.append(f"{label} not found: {path}")
    except json.JSONDecodeError as exc:
        failures.append(f"{label} invalid JSON: {exc}")
    return {}


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _artifact_ref(path: Path) -> dict[str, str | None]:
    return artifact_ref(path)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _text(value: Any) -> str:
    return str(value or "").strip()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


if __name__ == "__main__":
    raise SystemExit(main())
