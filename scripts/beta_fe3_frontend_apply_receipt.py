#!/usr/bin/env python3
"""Write a Beta-FE-3 frontend apply receipt.

This gate consumes a passed Agent-runner mediation summary, inspects the
frontend worktree diff, runs supplied verification commands, and writes a
fail-closed receipt. It does not commit, push, merge, deploy, run production, or
write production receipts.
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
    from civitasos_contracts.provenance import build_runtime_evidence
except ModuleNotFoundError:
    from scripts.civitasos_contracts.artifacts import artifact_ref, build_artifact_envelope
    from scripts.civitasos_contracts.provenance import build_runtime_evidence

RECEIPT_SCHEMA = "beta-fe3-frontend-apply-receipt:v1"
FE26_SCHEMA = "beta-fe26-agent-runner-mediation-summary:v1"
FE12_SCHEMA = "beta-fe12-four-agent-frontend-mediation-summary:v1"
FE_ORCHESTRATION_SCHEMA = "beta-fe-four-agent-frontend-orchestration-summary:v1"
ALLOWED_CHANGED_FILES = {
    "src/adapters/taskReadModel.ts",
    "src/adapters/TaskReadAdapter.ts",
    "src/adapters/TaskReadAdapter.test.ts",
    "src/components/TaskPoolPanel.tsx",
}
NON_CLAIMS = (
    "beta_fe3_apply_receipt_is_local_controlled_frontend_apply_only",
    "beta_fe3_apply_receipt_does_not_commit_push_merge_or_deploy",
    "beta_fe3_apply_receipt_does_not_claim_h3_production_readiness",
    "beta_fe3_apply_receipt_does_not_write_production_receipts",
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--frontend-root", required=True)
    parser.add_argument("--source-fe26-summary", required=True)
    parser.add_argument("--output-root", required=True)
    parser.add_argument("--operator-id", default="local-operator-cc")
    parser.add_argument("--operator-authorization", default="current_chat_continue_request")
    parser.add_argument("--test-command", action="append", default=[])
    parser.add_argument(
        "--allowed-changed-file",
        action="append",
        default=[],
        help="repo-relative frontend path allowed for this apply slice; defaults to the original FE-3 slice",
    )
    args = parser.parse_args(argv)

    receipt = write_receipt(
        frontend_root=Path(args.frontend_root),
        source_fe26_summary=Path(args.source_fe26_summary),
        output_root=Path(args.output_root),
        operator_id=args.operator_id,
        operator_authorization=args.operator_authorization,
        test_commands=args.test_command,
        allowed_changed_files=args.allowed_changed_file or None,
    )
    print(json.dumps(receipt, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if receipt.get("passed") is True else 1


def write_receipt(
    *,
    frontend_root: Path,
    source_fe26_summary: Path,
    output_root: Path,
    operator_id: str,
    operator_authorization: str,
    test_commands: list[str],
    allowed_changed_files: list[str] | None = None,
) -> dict[str, Any]:
    frontend_root = frontend_root.resolve()
    output_root = output_root.resolve()
    output_root.mkdir(parents=True, exist_ok=True)
    failures: list[str] = []
    source_summary = _read_json(source_fe26_summary, failures, "Agent-runner mediation summary")
    _validate_source_mediation(source_summary, failures)

    allowed_set = _allowed_files(allowed_changed_files, failures)
    changed_files = _changed_files(frontend_root)
    allowed = sorted(allowed_set)
    unexpected = sorted(set(changed_files) - allowed_set)
    missing_expected = sorted(allowed_set - set(changed_files))
    if unexpected:
        failures.append(f"unexpected changed frontend files: {unexpected}")
    if missing_expected:
        failures.append(f"expected FE-3 slice files are not changed: {missing_expected}")
    if not changed_files:
        failures.append("frontend worktree must contain FE-3 apply diff")

    diff_path = output_root / "frontend_apply.diff"
    diff_path.write_text(_worktree_diff(frontend_root), encoding="utf-8")
    stat_path = output_root / "frontend_apply_stat.txt"
    stat_path.write_text(_git_text(frontend_root, ["diff", "--stat"]), encoding="utf-8")

    rollback_check = _run_argv(frontend_root, ["git", "apply", "--reverse", "--check", str(diff_path)])
    if rollback_check["exit_code"] != 0:
        failures.append("rollback reverse-apply check failed")

    command_reports = [_run_command(frontend_root, command) for command in test_commands]
    if not command_reports:
        failures.append("at least one FE-3 verification command is required")
    for report in command_reports:
        if report["exit_code"] != 0:
            failures.append(f"verification command failed: {report['command']}")

    passed = not failures
    source_ref = artifact_ref(source_fe26_summary)
    receipt = {
        "schema_version": RECEIPT_SCHEMA,
        "artifact_envelope": build_artifact_envelope(
            artifact_kind="receipt",
            plane="runtime",
            schema_version=RECEIPT_SCHEMA,
            artifact_id=f"fe3-apply:{_ref_digest(source_ref)[:16]}",
            subject_id=f"frontend-slice:{frontend_root.name}",
            producer="beta_fe3_frontend_apply_receipt",
            source_refs=[source_ref],
            scope="bounded_frontend_apply",
        ),
        "checked_at": _now(),
        "passed": passed,
        "decision": "beta_fe3_frontend_apply_receipt_passed" if passed else "blocked",
        "failure_reasons": failures,
        "operator_id": operator_id,
        "operator_authorization": operator_authorization,
        "source_mediation_schema": source_summary.get("schema_version") if isinstance(source_summary, dict) else None,
        "source_mediation_summary": source_ref,
        "source_fe26_summary": source_ref,
        "frontend_root": str(frontend_root),
        "frontend_head": _git_text(frontend_root, ["rev-parse", "--short", "HEAD"]).strip(),
        "changed_files": changed_files,
        "allowed_changed_files": allowed,
        "diff_ref": _artifact_ref(diff_path),
        "diff_stat_ref": _artifact_ref(stat_path),
        "rollback_check": rollback_check,
        "verification_commands": command_reports,
        "runtime_evidence": build_runtime_evidence(
            {
                "mediation_summary": source_ref,
                "diff": artifact_ref(diff_path),
                "diff_stat": artifact_ref(stat_path),
            },
            assertions={
                "changed_file_count": len(changed_files),
                "rollback_check_passed": rollback_check.get("exit_code") == 0,
                "verification_command_count": len(command_reports),
            },
        ),
        "boundary": {
            "frontend_code_modified": True,
            "apply_allowed": True,
            "commit_allowed": False,
            "push_allowed": False,
            "merge_allowed": False,
            "deploy_allowed": False,
            "production_runtime_execution_allowed": False,
            "production_receipt_write_allowed": False,
        },
        "h3_boundary": {"h3_remains_blocked": True, "h3_production_readiness_claimed": False},
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(output_root / "beta_fe3_frontend_apply_receipt.json", receipt)
    return receipt


def _validate_source_mediation(summary: Any, failures: list[str]) -> None:
    if not isinstance(summary, dict):
        failures.append("Agent-runner mediation summary must be an object")
        return
    schema = summary.get("schema_version")
    if schema == FE26_SCHEMA:
        _validate_fe26(summary, failures)
    elif schema == FE12_SCHEMA:
        _validate_fe12(summary, failures)
    elif schema == FE_ORCHESTRATION_SCHEMA:
        _validate_four_agent_orchestration(summary, failures)
    else:
        failures.append(f"source mediation schema_version must be {FE26_SCHEMA}, {FE12_SCHEMA}, or {FE_ORCHESTRATION_SCHEMA}")


def _validate_fe26(summary: dict[str, Any], failures: list[str]) -> None:
    if summary.get("passed") is not True:
        failures.append("FE-2.6 summary must be passed")
    if summary.get("decision") != "beta_fe26_agent_runner_mediation_passed":
        failures.append("FE-2.6 decision must be beta_fe26_agent_runner_mediation_passed")
    if summary.get("mediation_level") != "civitasos_agent_runner_claim_generate_deliver":
        failures.append("FE-2.6 mediation_level must prove claim-generate-deliver")
    if int(summary.get("generation_after_claim_observed_count") or 0) < 3:
        failures.append("FE-2.6 must observe at least 3 generation-after-claim receipts")
    _validate_common_boundaries(summary, failures, "FE-2.6")


def _validate_fe12(summary: dict[str, Any], failures: list[str]) -> None:
    if summary.get("passed") is not True:
        failures.append("FE-12 summary must be passed")
    if summary.get("decision") != "beta_fe12_four_agent_frontend_mediation_passed":
        failures.append("FE-12 decision must be beta_fe12_four_agent_frontend_mediation_passed")
    if summary.get("patch_slice_id") != "task_pool_presentation_extraction":
        failures.append("FE-12 patch_slice_id must be task_pool_presentation_extraction")
    selected = summary.get("selected_plan") if isinstance(summary.get("selected_plan"), dict) else {}
    if selected.get("slice_id") != "task_pool_presentation_extraction":
        failures.append("FE-12 selected_plan.slice_id must be task_pool_presentation_extraction")
    if int(summary.get("task_receipt_count") or 0) < 4:
        failures.append("FE-12 must include 4 task receipts")
    if int(summary.get("claim_observed_count") or 0) < 4:
        failures.append("FE-12 must observe 4 claims")
    if int(summary.get("generation_after_claim_observed_count") or 0) < 4:
        failures.append("FE-12 must observe 4 generation-after-claim receipts")
    if int(summary.get("delivery_observed_count") or 0) < 4:
        failures.append("FE-12 must observe 4 deliveries")
    if summary.get("safe_next_step") != "prepare_bounded_fe3_apply_for_task_pool_presentation_extraction":
        failures.append("FE-12 safe_next_step must authorize bounded FE-3 preparation for this slice")
    _validate_common_boundaries(summary, failures, "FE-12")


def _validate_four_agent_orchestration(summary: dict[str, Any], failures: list[str]) -> None:
    if summary.get("passed") is not True:
        failures.append("four-Agent orchestration summary must be passed")
    if summary.get("decision") != "beta_fe_four_agent_orchestration_passed":
        failures.append("four-Agent orchestration decision must be beta_fe_four_agent_orchestration_passed")
    patch_slice_id = _text(summary.get("patch_slice_id"))
    if not patch_slice_id:
        failures.append("four-Agent orchestration patch_slice_id must be non-empty")
    selected = summary.get("selected_plan") if isinstance(summary.get("selected_plan"), dict) else {}
    if _text(selected.get("slice_id")) != patch_slice_id:
        failures.append("four-Agent orchestration selected_plan.slice_id must match patch_slice_id")
    if int(summary.get("task_receipt_count") or 0) < 4:
        failures.append("four-Agent orchestration must include 4 task receipts")
    if int(summary.get("claim_observed_count") or 0) < 4:
        failures.append("four-Agent orchestration must observe 4 claims")
    if int(summary.get("generation_after_claim_observed_count") or 0) < 4:
        failures.append("four-Agent orchestration must observe 4 generation-after-claim receipts")
    if int(summary.get("delivery_observed_count") or 0) < 4:
        failures.append("four-Agent orchestration must observe 4 deliveries")
    if _text(summary.get("safe_next_step")) == "operator_review_required_before_any_apply":
        failures.append("four-Agent orchestration safe_next_step must authorize bounded FE-3 preparation")
    _validate_common_boundaries(summary, failures, "four-Agent orchestration")


def _validate_common_boundaries(summary: dict[str, Any], failures: list[str], label: str) -> None:
    boundary = summary.get("boundary")
    if not isinstance(boundary, dict) or boundary.get("frontend_code_modified") is not False:
        failures.append(f"{label} boundary must not have modified frontend code")
    h3 = summary.get("h3_boundary")
    if not isinstance(h3, dict) or h3.get("h3_remains_blocked") is not True:
        failures.append(f"{label} h3_boundary must keep H.3 blocked")


def _text(value: Any) -> str:
    return str(value).strip() if value is not None else ""


def _allowed_files(paths: list[str] | None, failures: list[str]) -> set[str]:
    if not paths:
        return set(ALLOWED_CHANGED_FILES)
    allowed: set[str] = set()
    for raw in paths:
        rel = str(raw or "").strip()
        if not rel:
            failures.append("allowed changed file must be non-empty")
            continue
        if rel.startswith("/") or ".." in Path(rel).parts:
            failures.append(f"allowed changed file must be repo-relative and safe: {rel}")
            continue
        if not rel.startswith("src/"):
            failures.append(f"allowed changed file must stay under src/: {rel}")
            continue
        allowed.add(rel)
    if not allowed:
        failures.append("allowed changed files must not be empty")
    return allowed


def _run_command(cwd: Path, command: str) -> dict[str, Any]:
    result = subprocess.run(command, cwd=cwd, shell=True, text=True, capture_output=True, check=False)
    return {
        "command": command,
        "exit_code": result.returncode,
        "stdout_excerpt": result.stdout[-4000:],
        "stderr_excerpt": result.stderr[-4000:],
    }


def _run_argv(cwd: Path, argv: list[str]) -> dict[str, Any]:
    result = subprocess.run(argv, cwd=cwd, text=True, capture_output=True, check=False)
    return {
        "command": " ".join(argv),
        "exit_code": result.returncode,
        "stdout_excerpt": result.stdout[-4000:],
        "stderr_excerpt": result.stderr[-4000:],
    }


def _worktree_diff(cwd: Path) -> str:
    tracked = _git_text(cwd, ["diff", "--binary"])
    untracked_parts = []
    for rel in _git_lines(cwd, ["ls-files", "--others", "--exclude-standard"]):
        result = subprocess.run(
            ["git", "diff", "--binary", "--no-index", "--", "/dev/null", rel],
            cwd=cwd,
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode not in {0, 1}:
            raise RuntimeError(f"git diff --no-index failed for {rel}: {result.stderr}")
        untracked_parts.append(result.stdout)
    return tracked + "".join(untracked_parts)


def _changed_files(cwd: Path) -> list[str]:
    tracked = set(_git_lines(cwd, ["diff", "--name-only"]))
    untracked = set(_git_lines(cwd, ["ls-files", "--others", "--exclude-standard"]))
    return sorted(tracked | untracked)


def _git_lines(cwd: Path, args: list[str]) -> list[str]:
    text = _git_text(cwd, args)
    return [line.strip() for line in text.splitlines() if line.strip()]


def _git_text(cwd: Path, args: list[str]) -> str:
    result = subprocess.run(["git", *args], cwd=cwd, text=True, capture_output=True, check=False)
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


def _ref_digest(ref: Any) -> str:
    return str(ref.get("sha256") or "missing") if isinstance(ref, dict) else "missing"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


if __name__ == "__main__":
    raise SystemExit(main())
