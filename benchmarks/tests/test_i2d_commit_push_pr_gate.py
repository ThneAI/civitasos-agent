from __future__ import annotations

import json
import subprocess
from pathlib import Path

from benchmarks.i_gate_evidence import sha256_file
from benchmarks.i2c_bounded_apply_gate import APPLY_SPEC_SCHEMA, run_gate as run_i2c
from benchmarks.i2d_commit_push_pr_gate import run_gate as run_i2d


def test_i2d_commits_pushes_and_writes_local_draft_pr_receipt(tmp_path: Path) -> None:
    i2c_summary = _run_i2c(tmp_path)
    remote = tmp_path / "remote.git"
    _run(["git", "init", "--bare", str(remote)], tmp_path)

    summary = run_i2d(
        i2c_summary_path=i2c_summary,
        output_root=tmp_path / "i2d",
        remote_url=str(remote),
        target_branch="i2d/test-branch",
        base_branch="main",
        commit_message="i2d: test isolated commit",
    )

    assert summary["passed"] is True
    assert summary["readiness"]["i2d_commit_push_pr_complete"] is True
    assert summary["readiness"]["i2e_preview_discussion_ready"] is True
    assert summary["boundary"]["commit_allowed"] is True
    assert summary["boundary"]["remote_branch_push_allowed"] is True
    assert summary["boundary"]["draft_pr_allowed"] is True
    assert summary["boundary"]["authorization_recording_allowed"] is True
    assert summary["boundary"]["operator_reconciliation_recording_allowed"] is True
    assert summary["boundary"]["merge_allowed"] is False
    assert summary["boundary"]["deploy_allowed"] is False
    assert summary["boundary"]["production_transition_allowed"] is False

    push = json.loads((tmp_path / "i2d" / "i2d_remote_branch_push_receipt.json").read_text(encoding="utf-8"))
    pr = json.loads((tmp_path / "i2d" / "i2d_draft_pr_receipt.json").read_text(encoding="utf-8"))
    assert push["push"]["remote_branch_after_head"] == push["push"]["commit_id"]
    assert pr["draft_pr"]["mode"] == "local-draft-receipt"
    assert pr["draft_pr"]["headRefOid"] == push["push"]["commit_id"]


def test_i2d_blocks_failed_i2c_summary(tmp_path: Path) -> None:
    i2c_summary = _run_i2c(tmp_path)
    payload = json.loads(i2c_summary.read_text(encoding="utf-8"))
    payload["passed"] = False
    payload["readiness"]["i2d_commit_push_pr_discussion_ready"] = False
    i2c_summary.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    remote = tmp_path / "remote.git"
    _run(["git", "init", "--bare", str(remote)], tmp_path)

    summary = run_i2d(
        i2c_summary_path=i2c_summary,
        output_root=tmp_path / "i2d",
        remote_url=str(remote),
        target_branch="i2d/test-branch",
    )

    assert summary["passed"] is False
    assert "i2c_summary_passed" in summary["failure_reasons"]
    assert summary["boundary"]["remote_branch_push_allowed"] is False
    assert summary["boundary"]["draft_pr_allowed"] is False


def test_i2d_blocks_invalid_target_branch(tmp_path: Path) -> None:
    i2c_summary = _run_i2c(tmp_path)
    remote = tmp_path / "remote.git"
    _run(["git", "init", "--bare", str(remote)], tmp_path)

    summary = run_i2d(
        i2c_summary_path=i2c_summary,
        output_root=tmp_path / "i2d",
        remote_url=str(remote),
        target_branch="../bad",
    )

    assert summary["passed"] is False
    assert "target_branch_safe" in summary["failure_reasons"]
    assert summary["readiness"]["i2e_preview_discussion_ready"] is False


def test_i2d_blocks_i2c_workspace_drift_outside_applied_files(tmp_path: Path) -> None:
    i2c_summary = _run_i2c(tmp_path)
    i2c = json.loads(i2c_summary.read_text(encoding="utf-8"))
    preflight_path = Path(i2c["artifacts"]["preflight"]["path"])
    preflight = json.loads(preflight_path.read_text(encoding="utf-8"))
    source_workspace = Path(preflight["isolation"]["source_workspace"])
    (source_workspace / "docs" / "extra.txt").write_text("unexpected\n", encoding="utf-8")
    remote = tmp_path / "remote.git"
    _run(["git", "init", "--bare", str(remote)], tmp_path)

    summary = run_i2d(
        i2c_summary_path=i2c_summary,
        output_root=tmp_path / "i2d",
        remote_url=str(remote),
        target_branch="i2d/test-branch",
    )

    assert summary["passed"] is False
    assert "changed_files_match_i2c_apply" in summary["failure_reasons"]
    assert summary["boundary"]["remote_branch_push_allowed"] is False


def _run_i2c(tmp_path: Path) -> Path:
    source_root = tmp_path / "source"
    (source_root / "docs").mkdir(parents=True)
    source_file = source_root / "docs" / "note.txt"
    source_file.write_text("hello\n", encoding="utf-8")
    i2b = tmp_path / "i2b.json"
    i2b.write_text(json.dumps({
        "schema_version": "i2b-provider-contrast-gate:v1",
        "passed": True,
        "readiness": {
            "i2c_bounded_apply_discussion_ready": True,
            "real_task_command_allowed": False,
            "source_or_git_write_allowed": False,
            "production_transition_allowed": False,
        },
        "boundary": {
            "real_task_command_allowed": False,
            "source_tree_write_allowed": False,
            "git_write_allowed": False,
            "runtime_state_mutation_allowed": False,
            "deploy_allowed": False,
            "production_transition_allowed": False,
        },
    }, indent=2, sort_keys=True), encoding="utf-8")
    spec = tmp_path / "apply_spec.json"
    spec.write_text(json.dumps({
        "schema_version": APPLY_SPEC_SCHEMA,
        "task_id": "i2c-task:test",
        "objective": "isolation fixture",
        "executor_alias": "i2c-controlled-apply-runner",
        "allowed_files": ["docs/note.txt"],
        "patches": [{
            "path": "docs/note.txt",
            "expected_sha256": sha256_file(source_file),
            "new_content": "hello isolated\n",
        }],
        "constraints": {
            "host_source_tree_write_allowed": False,
            "git_allowed": False,
            "deploy_allowed": False,
            "production_transition_allowed": False,
        },
    }, indent=2, sort_keys=True), encoding="utf-8")
    run_i2c(
        i2b_contrast_path=i2b,
        apply_spec_path=spec,
        source_root=source_root,
        output_root=tmp_path / "i2c",
    )
    return tmp_path / "i2c" / "i2c_bounded_apply_chain_summary.json"


def _run(argv: list[str], cwd: Path) -> None:
    result = subprocess.run(argv, cwd=cwd, text=True, capture_output=True, check=False)
    assert result.returncode == 0, result.stderr
