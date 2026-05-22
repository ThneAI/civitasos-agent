from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


ROOT = Path(__file__).resolve().parents[2]
_load("beta1_repo_review_proposal", ROOT / "scripts" / "beta1_repo_review_proposal.py")
_load("beta2_patch_proposal", ROOT / "scripts" / "beta2_patch_proposal.py")
_load("beta2_operator_apply_receipt", ROOT / "scripts" / "beta2_operator_apply_receipt.py")
_load("beta2_patch_review_outcome", ROOT / "scripts" / "beta2_patch_review_outcome.py")
_load("beta3_controlled_apply_candidate", ROOT / "scripts" / "beta3_controlled_apply_candidate.py")
_load("beta3_controlled_apply_sandbox", ROOT / "scripts" / "beta3_controlled_apply_sandbox.py")
_load("beta3_post_sandbox_operator_receipt", ROOT / "scripts" / "beta3_post_sandbox_operator_receipt.py")
_load("beta3_multi_agent_review_packet", ROOT / "scripts" / "beta3_multi_agent_review_packet.py")
_load("beta3_source_apply_authorization", ROOT / "scripts" / "beta3_source_apply_authorization.py")
_load("beta3_source_apply_executor", ROOT / "scripts" / "beta3_source_apply_executor.py")
_load("beta3_git_publication_authorization", ROOT / "scripts" / "beta3_git_publication_authorization.py")
_load("beta3_git_commit_executor", ROOT / "scripts" / "beta3_git_commit_executor.py")
push = _load("beta3_git_push_executor", ROOT / "scripts" / "beta3_git_push_executor.py")
push_tests = _load(
    "beta3_git_push_executor_fixture_for_merge",
    ROOT / "benchmarks" / "tests" / "test_beta3_git_push_executor.py",
)
module = _load("beta3_git_merge_executor", ROOT / "scripts" / "beta3_git_merge_executor.py")


def test_git_merge_executor_merges_pushed_branch_into_controlled_target(tmp_path: Path) -> None:
    _, push_receipt, remote = _write_push_receipt(tmp_path)
    target_repo = _write_controlled_target_repo(tmp_path, remote, "beta3-source-fixture")
    authorization_path = tmp_path / "git_merge_authorization.json"
    module.record_merge_authorization(
        push_receipt_path=push_receipt,
        target_repo=target_repo,
        target_branch="beta3-integration-fixture",
        merge_message="merge: controlled beta3 fixture",
        output_path=authorization_path,
        operator_id="operator-001",
        reason="merge reviewed fixture branch into controlled target",
        rollback_evidence_ref="rollback:revert-fixture-merge",
    )

    report = module.run_git_merge(
        authorization_path=authorization_path,
        output_root=tmp_path / "git-merge",
    )
    receipt = json.loads(Path(report["merge_receipt_path"]).read_text(encoding="utf-8"))

    assert report["passed"] is True
    assert report["merge_status"] == "merged_with_receipt"
    assert report["receipt_validation"]["passed"] is True
    assert report["git_actions_performed"] == {"commit": True, "merge": True, "push": True}
    assert receipt["receipt_scope"] == "git_merge_only"
    assert receipt["merge_parents"] == [
        receipt["target_repo"]["before"]["head_commit"],
        receipt["source_commit_id"],
    ]
    assert receipt["deploy_allowed"] is False
    assert _git(target_repo, "branch", "--show-current").strip() == "beta3-integration-fixture"
    assert _git(target_repo, "status", "--short") == ""


def test_git_merge_authorization_requires_checked_out_controlled_target_branch(tmp_path: Path) -> None:
    _, push_receipt, remote = _write_push_receipt(tmp_path)
    target_repo = _write_controlled_target_repo(tmp_path, remote, "beta3-source-fixture")

    with pytest.raises(ValueError, match="checked out on explicit controlled target_branch"):
        module.record_merge_authorization(
            push_receipt_path=push_receipt,
            target_repo=target_repo,
            target_branch="beta3-other-target",
            merge_message="merge: wrong target fixture",
            output_path=tmp_path / "wrong_target_authorization.json",
            operator_id="operator-001",
            reason="prove target branch cannot be inferred",
            rollback_evidence_ref="rollback:wrong-target",
        )


def test_git_merge_executor_refuses_push_receipt_as_merge_authorization(tmp_path: Path) -> None:
    _, push_receipt, _ = _write_push_receipt(tmp_path)

    report = module.run_git_merge(
        authorization_path=push_receipt,
        output_root=tmp_path / "push-receipt-is-not-authorization",
    )

    assert report["passed"] is False
    assert report["failure_codes"] == ["git_merge_authorization_refused"]
    assert report["git_actions_performed"]["merge"] is False
    assert any("schema_version must be beta3-git-merge-authorization:v1" in reason for reason in report["failure_reasons"])


def test_git_merge_receipt_validation_rejects_deploy_claim(tmp_path: Path) -> None:
    _, push_receipt, remote = _write_push_receipt(tmp_path)
    target_repo = _write_controlled_target_repo(tmp_path, remote, "beta3-source-fixture")
    authorization_path = tmp_path / "git_merge_authorization.json"
    module.record_merge_authorization(
        push_receipt_path=push_receipt,
        target_repo=target_repo,
        target_branch="beta3-integration-fixture",
        merge_message="merge: receipt boundary fixture",
        output_path=authorization_path,
        operator_id="operator-001",
        reason="authorize receipt boundary fixture",
        rollback_evidence_ref="rollback:receipt-boundary",
    )
    report = module.run_git_merge(authorization_path=authorization_path, output_root=tmp_path / "merge-receipt")
    receipt_path = Path(report["merge_receipt_path"])
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["deploy_allowed"] = True
    receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    validation = module.validate_git_merge_receipt(receipt_path)

    assert validation["passed"] is False
    assert "deploy_allowed must be false" in validation["failure_reasons"]


def _write_push_receipt(tmp_path: Path) -> tuple[Path, Path, Path]:
    repo, commit_receipt, remote = push_tests._write_commit_receipt_and_bare_remote(tmp_path)
    authorization_path = tmp_path / "git_push_authorization.json"
    push.record_push_authorization(
        commit_receipt_path=commit_receipt,
        remote_url=str(remote),
        target_branch="beta3-source-fixture",
        output_path=authorization_path,
        operator_id="operator-001",
        reason="push source fixture before merge",
        rollback_evidence_ref="rollback:delete-source-fixture",
    )
    report = push.run_git_push(authorization_path=authorization_path, output_root=tmp_path / "git-push")
    return repo, Path(report["push_receipt_path"]), remote


def _write_controlled_target_repo(tmp_path: Path, remote: Path, source_branch: str) -> Path:
    target_repo = tmp_path / "controlled-target"
    target_repo.mkdir()
    _run(target_repo, "git", "init")
    _run(target_repo, "git", "config", "user.email", "beta3-merge-fixture@example.invalid")
    _run(target_repo, "git", "config", "user.name", "Beta3 Merge Fixture")
    _run(target_repo, "git", "fetch", "--no-tags", str(remote), f"refs/heads/{source_branch}")
    _run(target_repo, "git", "checkout", "-b", "beta3-integration-fixture", "FETCH_HEAD^")
    return target_repo


def _git(repo: Path, *args: str) -> str:
    return _run(repo, "git", *args).stdout


def _run(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(list(args), cwd=repo, check=True, text=True, capture_output=True)
