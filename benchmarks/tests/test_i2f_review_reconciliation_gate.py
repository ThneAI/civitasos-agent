from __future__ import annotations

import json
import subprocess
from pathlib import Path

from benchmarks.i_gate_evidence import sha256_file
from benchmarks.i2c_bounded_apply_gate import APPLY_SPEC_SCHEMA, run_gate as run_i2c
from benchmarks.i2d_commit_push_pr_gate import run_gate as run_i2d
from benchmarks.i2e_preview_rollback_audit_gate import run_gate as run_i2e
from benchmarks.i2f_review_reconciliation_gate import run_gate as run_i2f


def test_i2f_review_reconciliation_passes(tmp_path: Path) -> None:
    i2e_summary = _run_i2e(tmp_path)

    summary = run_i2f(i2e_summary_path=i2e_summary, output_root=tmp_path / "i2f")

    assert summary["passed"] is True
    assert summary["readiness"]["i2f_review_reconciliation_complete"] is True
    assert summary["readiness"]["i2g_merge_discussion_ready"] is True
    assert summary["boundary"]["reviewer_verdict_recording_allowed"] is True
    assert summary["boundary"]["operator_reconciliation_recording_allowed"] is True
    assert summary["boundary"]["merge_allowed"] is False
    assert summary["boundary"]["deploy_allowed"] is False
    assert summary["boundary"]["production_transition_allowed"] is False

    reviews = json.loads((tmp_path / "i2f" / "i2f_reviewer_verdict_receipts.json").read_text(encoding="utf-8"))
    reconciliation = json.loads((tmp_path / "i2f" / "i2f_operator_reconciliation.json").read_text(encoding="utf-8"))
    assert reviews["review_summary"]["reviewer_count"] == 3
    assert reviews["review_summary"]["verdict_counts"] == {"approved": 3}
    assert reconciliation["operator_reconciliation"]["decision"] == "i2f_review_reconciliation_passed"


def test_i2f_blocks_failed_i2e_summary(tmp_path: Path) -> None:
    i2e_summary = _run_i2e(tmp_path)
    payload = json.loads(i2e_summary.read_text(encoding="utf-8"))
    payload["passed"] = False
    payload["readiness"]["i2f_review_reconciliation_discussion_ready"] = False
    i2e_summary.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

    summary = run_i2f(i2e_summary_path=i2e_summary, output_root=tmp_path / "i2f")

    assert summary["passed"] is False
    assert "i2e_summary_passed" in summary["failure_reasons"]
    assert summary["boundary"]["reviewer_verdict_recording_allowed"] is False


def test_i2f_blocks_reviewer_rejection(tmp_path: Path) -> None:
    i2e_summary = _run_i2e(tmp_path)
    reviewers = tmp_path / "reviewers.json"
    reviewers.write_text(json.dumps({
        "reviewers": [
            {"reviewer_id": "provenance-reviewer", "role": "provenance", "verdict": "approved"},
            {"reviewer_id": "rollback-reviewer", "role": "rollback", "verdict": "changes_requested"},
            {"reviewer_id": "boundary-reviewer", "role": "boundary", "verdict": "approved"},
        ]
    }, indent=2, sort_keys=True), encoding="utf-8")

    summary = run_i2f(i2e_summary_path=i2e_summary, output_root=tmp_path / "i2f", reviewers_path=reviewers)

    assert summary["passed"] is False
    assert "all_reviewers_approved" in summary["failure_reasons"]
    assert "no_blocking_verdicts" in summary["failure_reasons"]
    assert summary["readiness"]["i2g_merge_discussion_ready"] is False


def test_i2f_blocks_i2e_artifact_hash_drift(tmp_path: Path) -> None:
    i2e_summary = _run_i2e(tmp_path)
    i2e = json.loads(i2e_summary.read_text(encoding="utf-8"))
    preview_path = Path(i2e["artifacts"]["preview"]["path"])
    preview = json.loads(preview_path.read_text(encoding="utf-8"))
    preview["preview"]["observed_head"] = "0" * 40
    preview_path.write_text(json.dumps(preview, indent=2, sort_keys=True), encoding="utf-8")

    summary = run_i2f(i2e_summary_path=i2e_summary, output_root=tmp_path / "i2f")

    assert summary["passed"] is False
    assert "i2e.preview_artifact_hash_valid" in summary["failure_reasons"]
    assert summary["boundary"]["operator_reconciliation_recording_allowed"] is False


def _run_i2e(tmp_path: Path) -> Path:
    i2d_summary = _run_i2d(tmp_path)
    run_i2e(i2d_summary_path=i2d_summary, output_root=tmp_path / "i2e")
    return tmp_path / "i2e" / "i2e_preview_rollback_audit_chain_summary.json"


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


def _run(argv: list[str], cwd: Path) -> None:
    result = subprocess.run(argv, cwd=cwd, text=True, capture_output=True, check=False)
    assert result.returncode == 0, result.stderr
