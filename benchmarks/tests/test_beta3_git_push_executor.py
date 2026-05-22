from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path


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
commit = _load("beta3_git_commit_executor", ROOT / "scripts" / "beta3_git_commit_executor.py")
commit_tests = _load(
    "beta3_git_commit_executor_fixture_for_push",
    ROOT / "benchmarks" / "tests" / "test_beta3_git_commit_executor.py",
)
module = _load("beta3_git_push_executor", ROOT / "scripts" / "beta3_git_push_executor.py")


def test_git_push_executor_pushes_authorized_commit_to_explicit_remote(tmp_path: Path) -> None:
    repo, commit_receipt, remote = _write_commit_receipt_and_bare_remote(tmp_path)
    authorization_path = tmp_path / "git_push_authorization.json"
    module.record_push_authorization(
        commit_receipt_path=commit_receipt,
        remote_url=str(remote),
        target_branch="beta3-push-fixture",
        output_path=authorization_path,
        operator_id="operator-001",
        reason="publish bounded fixture commit to local remote",
        rollback_evidence_ref="rollback:delete-local-fixture-branch",
    )

    report = module.run_git_push(
        authorization_path=authorization_path,
        output_root=tmp_path / "git-push",
    )
    receipt = json.loads(Path(report["push_receipt_path"]).read_text(encoding="utf-8"))

    assert report["passed"] is True
    assert report["push_status"] == "pushed_with_receipt"
    assert report["receipt_validation"]["passed"] is True
    assert report["git_actions_performed"] == {"commit": True, "merge": False, "push": True}
    assert report["remote_branch_before_head"] is None
    assert report["remote_branch_after_head"] == _git(repo, "rev-parse", "HEAD").strip()
    assert receipt["receipt_scope"] == "git_push_only"
    assert receipt["merge_allowed"] is False
    assert _remote_head(repo, remote, "beta3-push-fixture") == receipt["commit_id"]


def test_git_push_authorization_expires_when_remote_branch_lease_drifts(tmp_path: Path) -> None:
    repo, commit_receipt, remote = _write_commit_receipt_and_bare_remote(tmp_path)
    authorization_path = tmp_path / "git_push_authorization.json"
    module.record_push_authorization(
        commit_receipt_path=commit_receipt,
        remote_url=str(remote),
        target_branch="beta3-lease-fixture",
        output_path=authorization_path,
        operator_id="operator-001",
        reason="authorize before external branch drift",
        rollback_evidence_ref="rollback:lease-fixture",
    )
    _git(repo, "push", str(remote), "HEAD^:refs/heads/beta3-lease-fixture")

    validation = module.validate_push_authorization(authorization_path)

    assert validation["passed"] is False
    assert "remote branch lease drifted after Git push authorization" in validation["failure_reasons"]


def test_git_push_receipt_validation_rejects_merge_claim(tmp_path: Path) -> None:
    _, commit_receipt, remote = _write_commit_receipt_and_bare_remote(tmp_path)
    authorization_path = tmp_path / "git_push_authorization.json"
    module.record_push_authorization(
        commit_receipt_path=commit_receipt,
        remote_url=str(remote),
        target_branch="beta3-receipt-boundary",
        output_path=authorization_path,
        operator_id="operator-001",
        reason="authorize receipt boundary fixture",
        rollback_evidence_ref="rollback:receipt-boundary",
    )
    report = module.run_git_push(authorization_path=authorization_path, output_root=tmp_path / "push-receipt")
    receipt_path = Path(report["push_receipt_path"])
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["git_actions_performed"]["merge"] = True
    receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    validation = module.validate_git_push_receipt(receipt_path)

    assert validation["passed"] is False
    assert "git_actions_performed must prove push without merge" in validation["failure_reasons"]


def _write_commit_receipt_and_bare_remote(tmp_path: Path) -> tuple[Path, Path, Path]:
    repo, publication_authorization = commit_tests._write_publication_authorization(tmp_path)
    commit_report = commit.run_git_commit(
        authorization_path=publication_authorization,
        output_root=tmp_path / "git-commit",
    )
    remote = tmp_path / "remote.git"
    subprocess.run(["git", "init", "--bare", str(remote)], check=True, text=True, capture_output=True)
    return repo, Path(commit_report["commit_receipt_path"]), remote


def _remote_head(repo: Path, remote: Path, branch: str) -> str:
    output = _git(repo, "ls-remote", "--heads", str(remote), f"refs/heads/{branch}")
    return output.split()[0]


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=repo, check=True, text=True, capture_output=True).stdout
