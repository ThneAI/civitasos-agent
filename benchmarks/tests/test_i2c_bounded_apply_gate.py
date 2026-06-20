from __future__ import annotations

import json
from pathlib import Path

from benchmarks.i_gate_evidence import sha256_file
from benchmarks.i2c_bounded_apply_gate import APPLY_SPEC_SCHEMA, run_gate


def test_i2c_bounded_apply_writes_only_isolated_workspace(tmp_path: Path) -> None:
    source_root = _source_root(tmp_path)
    source_file = source_root / "docs" / "note.txt"
    before = source_file.read_text(encoding="utf-8")
    i2b = _write_i2b_contrast(tmp_path / "i2b.json", passed=True)
    spec = _write_apply_spec(
        tmp_path / "apply_spec.json",
        target_path="docs/note.txt",
        expected_sha256=sha256_file(source_file),
        new_content="hello from isolated I2C\n",
    )

    summary = run_gate(
        i2b_contrast_path=i2b,
        apply_spec_path=spec,
        source_root=source_root,
        output_root=tmp_path / "i2c",
    )

    assert summary["passed"] is True
    assert summary["readiness"]["i2c_bounded_apply_complete"] is True
    assert summary["readiness"]["i2d_commit_push_pr_discussion_ready"] is True
    assert summary["boundary"]["isolated_workspace_write_allowed"] is True
    assert summary["boundary"]["apply_receipt_recording_allowed"] is True
    assert summary["boundary"]["operator_reconciliation_recording_allowed"] is True
    assert summary["boundary"]["source_tree_write_allowed"] is False
    assert summary["boundary"]["git_write_allowed"] is False
    assert source_file.read_text(encoding="utf-8") == before
    workspace_file = tmp_path / "i2c" / "isolation_workspace" / "source" / "docs" / "note.txt"
    assert workspace_file.read_text(encoding="utf-8") == "hello from isolated I2C\n"

    apply = json.loads((tmp_path / "i2c" / "i2c_bounded_apply_receipt.json").read_text(encoding="utf-8"))
    assert apply["apply"]["host_source_tree_modified"] is False
    assert apply["apply"]["git_used"] is False
    assert apply["apply"]["production_touched"] is False


def test_i2c_blocks_failed_i2b_contrast(tmp_path: Path) -> None:
    source_root = _source_root(tmp_path)
    source_file = source_root / "docs" / "note.txt"
    i2b = _write_i2b_contrast(tmp_path / "i2b.json", passed=False)
    spec = _write_apply_spec(
        tmp_path / "apply_spec.json",
        target_path="docs/note.txt",
        expected_sha256=sha256_file(source_file),
        new_content="blocked\n",
    )

    summary = run_gate(
        i2b_contrast_path=i2b,
        apply_spec_path=spec,
        source_root=source_root,
        output_root=tmp_path / "i2c",
    )

    assert summary["passed"] is False
    assert "i2b_provider_contrast_passed" in summary["failure_reasons"]
    assert summary["boundary"]["isolated_workspace_write_allowed"] is False
    assert summary["readiness"]["source_or_git_write_allowed"] is False


def test_i2c_blocks_patch_outside_allowlist(tmp_path: Path) -> None:
    source_root = _source_root(tmp_path)
    source_file = source_root / "docs" / "note.txt"
    i2b = _write_i2b_contrast(tmp_path / "i2b.json", passed=True)
    spec = _write_apply_spec(
        tmp_path / "apply_spec.json",
        target_path="docs/other.txt",
        expected_sha256=sha256_file(source_file),
        new_content="blocked\n",
        allowed_files=["docs/note.txt"],
    )

    summary = run_gate(
        i2b_contrast_path=i2b,
        apply_spec_path=spec,
        source_root=source_root,
        output_root=tmp_path / "i2c",
    )

    assert summary["passed"] is False
    assert "patch_paths_are_allowlisted" in summary["failure_reasons"]
    assert summary["readiness"]["i2c_bounded_apply_complete"] is False


def test_i2c_blocks_source_hash_drift(tmp_path: Path) -> None:
    source_root = _source_root(tmp_path)
    source_file = source_root / "docs" / "note.txt"
    i2b = _write_i2b_contrast(tmp_path / "i2b.json", passed=True)
    spec = _write_apply_spec(
        tmp_path / "apply_spec.json",
        target_path="docs/note.txt",
        expected_sha256=sha256_file(source_file),
        new_content="blocked\n",
    )
    source_file.write_text("drifted\n", encoding="utf-8")

    summary = run_gate(
        i2b_contrast_path=i2b,
        apply_spec_path=spec,
        source_root=source_root,
        output_root=tmp_path / "i2c",
    )

    assert summary["passed"] is False
    assert "patch_expected_hashes_match" in summary["failure_reasons"]
    assert summary["boundary"]["source_tree_write_allowed"] is False


def _source_root(tmp_path: Path) -> Path:
    root = tmp_path / "source"
    (root / "docs").mkdir(parents=True)
    (root / "docs" / "note.txt").write_text("hello\n", encoding="utf-8")
    return root


def _write_i2b_contrast(path: Path, *, passed: bool) -> Path:
    payload = {
        "schema_version": "i2b-provider-contrast-gate:v1",
        "passed": passed,
        "failure_reasons": [] if passed else ["provider_diversity_observed"],
        "readiness": {
            "i2b_provider_contrast_complete": passed,
            "i2c_bounded_apply_discussion_ready": passed,
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
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return path


def _write_apply_spec(
    output_path: Path,
    *,
    allowlist_path: str | None = None,
    target_path: str,
    expected_sha256: str,
    new_content: str,
    allowed_files: list[str] | None = None,
) -> Path:
    file_path = allowlist_path or target_path
    payload = {
        "schema_version": APPLY_SPEC_SCHEMA,
        "task_id": "i2c-task:test-bounded-apply",
        "objective": "Change one allowlisted fixture file inside isolation only.",
        "executor_alias": "i2c-controlled-apply-runner",
        "allowed_files": allowed_files or [file_path],
        "patches": [
            {
                "path": target_path,
                "expected_sha256": expected_sha256,
                "new_content": new_content,
            }
        ],
        "constraints": {
            "host_source_tree_write_allowed": False,
            "git_allowed": False,
            "deploy_allowed": False,
            "production_transition_allowed": False,
        },
    }
    output_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return output_path
