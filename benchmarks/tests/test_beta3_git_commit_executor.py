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
publication = _load(
    "beta3_git_publication_authorization",
    ROOT / "scripts" / "beta3_git_publication_authorization.py",
)
publication_tests = _load(
    "beta3_git_publication_authorization_fixture_for_commit",
    ROOT / "benchmarks" / "tests" / "test_beta3_git_publication_authorization.py",
)
module = _load("beta3_git_commit_executor", ROOT / "scripts" / "beta3_git_commit_executor.py")


def test_git_commit_executor_commits_authorized_target_paths_and_writes_receipt(tmp_path: Path) -> None:
    repo, authorization_path = _write_publication_authorization(tmp_path)

    report = module.run_git_commit(
        authorization_path=authorization_path,
        output_root=tmp_path / "git-commit",
    )
    receipt_path = Path(report["commit_receipt_path"])
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))

    assert report["passed"] is True
    assert report["commit_status"] == "committed_with_receipt"
    assert report["receipt_validation"]["passed"] is True
    assert report["staged_target_paths"] == ["README.md"]
    assert report["committed_target_paths"] == ["README.md"]
    assert report["git_actions_performed"] == {"commit": True, "merge": False, "push": False}
    assert receipt["receipt_scope"] == "git_commit_only"
    assert receipt["git_actions_performed"] == {"commit": True, "merge": False, "push": False}
    assert receipt["push_allowed"] is False
    assert _git(repo, "status", "--short") == ""
    assert _git(repo, "log", "-1", "--format=%s").strip() == "docs: fixture bounded commit"


def test_git_commit_executor_blocks_authorization_that_also_allows_push(tmp_path: Path) -> None:
    repo, authorization_path = _write_publication_authorization(
        tmp_path,
        allowed_actions=["commit", "push"],
        target_branch="beta3-fixture",
    )

    report = module.run_git_commit(
        authorization_path=authorization_path,
        output_root=tmp_path / "blocked-push-capable-authorization",
    )

    assert report["passed"] is False
    assert report["failure_codes"] == ["git_commit_authorization_not_commit_only"]
    assert report["git_actions_performed"]["commit"] is False
    assert _git(repo, "rev-list", "--count", "HEAD").strip() == "1"


def test_git_commit_receipt_validation_rejects_push_performed_claim(tmp_path: Path) -> None:
    _, authorization_path = _write_publication_authorization(tmp_path)
    report = module.run_git_commit(
        authorization_path=authorization_path,
        output_root=tmp_path / "receipt-boundary",
    )
    receipt_path = Path(report["commit_receipt_path"])
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["git_actions_performed"]["push"] = True
    receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    validation = module.validate_git_commit_receipt(receipt_path)

    assert validation["passed"] is False
    assert "git_actions_performed must prove commit only" in validation["failure_reasons"]


def _write_publication_authorization(
    tmp_path: Path,
    *,
    allowed_actions: list[str] | None = None,
    target_branch: str | None = None,
) -> tuple[Path, Path]:
    receipt_path = publication_tests._write_passed_post_apply_receipt(tmp_path)
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    repo = Path(receipt["target_repo"]["repo_root"])
    path = tmp_path / "beta3_git_publication_authorization.json"
    publication.record_git_publication_authorization(
        receipt_path=receipt_path,
        output_path=path,
        operator_id="operator-001",
        reason="authorize bounded commit fixture",
        rollback_evidence_ref="rollback:bounded-commit-fixture",
        allowed_git_actions=allowed_actions or ["commit"],
        commit_message="docs: fixture bounded commit",
        target_branch=target_branch,
    )
    return repo, path


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=repo, check=True, text=True, capture_output=True).stdout
