from __future__ import annotations

import json
import subprocess
from pathlib import Path

from benchmarks.i_gate_evidence import sha256_file
from benchmarks.i2c_bounded_apply_gate import APPLY_SPEC_SCHEMA, run_gate as run_i2c
from benchmarks.i2d_commit_push_pr_gate import run_gate as run_i2d
from benchmarks.i2e_preview_rollback_audit_gate import run_gate as run_i2e


def test_i2e_preview_rollback_audit_passes(tmp_path: Path) -> None:
    i2d_summary = _run_i2d(tmp_path)

    summary = run_i2e(
        i2d_summary_path=i2d_summary,
        output_root=tmp_path / "i2e",
        operator_id="operator-test",
        audit_owner="audit-test",
    )

    assert summary["passed"] is True
    assert summary["readiness"]["i2e_preview_rollback_audit_complete"] is True
    assert summary["readiness"]["i2f_review_reconciliation_discussion_ready"] is True
    assert summary["boundary"]["local_private_preview_allowed"] is True
    assert summary["boundary"]["rollback_drill_allowed"] is True
    assert summary["boundary"]["audit_recording_allowed"] is True
    assert summary["boundary"]["merge_allowed"] is False
    assert summary["boundary"]["deploy_allowed"] is False
    assert summary["boundary"]["production_transition_allowed"] is False
    assert not (tmp_path / "i2e" / "preview_workspace").exists()

    preview = json.loads((tmp_path / "i2e" / "i2e_local_private_preview_receipt.json").read_text(encoding="utf-8"))
    rollback = json.loads((tmp_path / "i2e" / "i2e_rollback_drill_receipt.json").read_text(encoding="utf-8"))
    audit = json.loads((tmp_path / "i2e" / "i2e_audit_receipt.json").read_text(encoding="utf-8"))
    assert preview["preview"]["observed_head"] == preview["preview"]["expected_commit"]
    assert rollback["rollback"]["exists_after_cleanup"] is False
    assert audit["audit"]["production_receipt_written"] is False


def test_i2e_blocks_failed_i2d_summary(tmp_path: Path) -> None:
    i2d_summary = _run_i2d(tmp_path)
    payload = json.loads(i2d_summary.read_text(encoding="utf-8"))
    payload["passed"] = False
    payload["readiness"]["i2e_preview_discussion_ready"] = False
    i2d_summary.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

    summary = run_i2e(i2d_summary_path=i2d_summary, output_root=tmp_path / "i2e")

    assert summary["passed"] is False
    assert "i2d_summary_passed" in summary["failure_reasons"]
    assert summary["boundary"]["local_private_preview_allowed"] is False
    assert summary["readiness"]["i2f_review_reconciliation_discussion_ready"] is False


def test_i2e_blocks_i2d_artifact_hash_drift(tmp_path: Path) -> None:
    i2d_summary = _run_i2d(tmp_path)
    i2d = json.loads(i2d_summary.read_text(encoding="utf-8"))
    push_path = Path(i2d["artifacts"]["push"]["path"])
    push = json.loads(push_path.read_text(encoding="utf-8"))
    push["push"]["target_branch"] = "i2d/drifted-artifact"
    push_path.write_text(json.dumps(push, indent=2, sort_keys=True), encoding="utf-8")

    summary = run_i2e(i2d_summary_path=i2d_summary, output_root=tmp_path / "i2e")

    assert summary["passed"] is False
    assert "i2d.push_artifact_hash_valid" in summary["failure_reasons"]
    assert summary["boundary"]["audit_recording_allowed"] is False


def test_i2e_blocks_remote_branch_head_drift(tmp_path: Path) -> None:
    i2d_summary = _run_i2d(tmp_path)
    i2d = json.loads(i2d_summary.read_text(encoding="utf-8"))
    push = json.loads(Path(i2d["artifacts"]["push"]["path"]).read_text(encoding="utf-8"))
    remote = Path(push["push"]["remote_url"])
    branch = push["push"]["target_branch"]
    _drift_remote_branch(tmp_path, remote, branch)

    summary = run_i2e(i2d_summary_path=i2d_summary, output_root=tmp_path / "i2e")

    assert summary["passed"] is False
    assert "remote_branch_matches_authorized_commit" in summary["failure_reasons"]
    assert summary["boundary"]["local_private_preview_allowed"] is False


def _run_i2d(tmp_path: Path) -> Path:
    i2c_summary = _run_i2c(tmp_path)
    remote = tmp_path / "remote.git"
    _run(["git", "init", "--bare", str(remote)], tmp_path)
    run_i2d(
        i2c_summary_path=i2c_summary,
        output_root=tmp_path / "i2d",
        remote_url=str(remote),
        target_branch="i2d/test-branch",
        base_branch="main",
        commit_message="i2d: test isolated commit",
    )
    return tmp_path / "i2d" / "i2d_commit_push_pr_chain_summary.json"


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


def _drift_remote_branch(tmp_path: Path, remote: Path, branch: str) -> None:
    drift = tmp_path / "drift"
    _run(["git", "clone", "--branch", branch, "--single-branch", str(remote), str(drift)], tmp_path)
    _run(["git", "config", "user.name", "I2E Drift"], drift)
    _run(["git", "config", "user.email", "i2e-drift@example.invalid"], drift)
    (drift / "docs" / "note.txt").write_text("remote drift\n", encoding="utf-8")
    _run(["git", "add", "docs/note.txt"], drift)
    _run(["git", "commit", "-m", "i2e remote drift"], drift)
    _run(["git", "push", "origin", f"HEAD:refs/heads/{branch}"], drift)


def _run(argv: list[str], cwd: Path) -> None:
    result = subprocess.run(argv, cwd=cwd, text=True, capture_output=True, check=False)
    assert result.returncode == 0, result.stderr
