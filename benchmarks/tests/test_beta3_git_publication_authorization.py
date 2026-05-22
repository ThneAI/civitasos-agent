from __future__ import annotations

import importlib.util
import json
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
executor = _load("beta3_source_apply_executor", ROOT / "scripts" / "beta3_source_apply_executor.py")
executor_tests = _load(
    "beta3_source_apply_executor_fixture_for_publication",
    ROOT / "benchmarks" / "tests" / "test_beta3_source_apply_executor.py",
)
module = _load(
    "beta3_git_publication_authorization",
    ROOT / "scripts" / "beta3_git_publication_authorization.py",
)


def test_commit_publication_authorization_records_explicit_git_boundary(tmp_path: Path) -> None:
    receipt_path = _write_passed_post_apply_receipt(tmp_path)
    authorization_path = tmp_path / "git_publication_authorization.json"

    report = module.record_git_publication_authorization(
        receipt_path=receipt_path,
        output_path=authorization_path,
        operator_id="operator-001",
        reason="authorize fixture commit review boundary",
        rollback_evidence_ref="rollback:git-publication-fixture",
        allowed_git_actions=["commit"],
        commit_message="docs: record Beta-3 source apply sample",
        target_branch=None,
    )
    authorization = json.loads(authorization_path.read_text(encoding="utf-8"))

    assert report["validation"]["passed"] is True
    assert authorization["allowed_git_actions"] == ["commit"]
    assert authorization["commit_allowed"] is True
    assert authorization["push_allowed"] is False
    assert authorization["merge_allowed"] is False
    assert authorization["git_actions_performed"] == {"commit": False, "merge": False, "push": False}
    assert authorization["deploy_allowed"] is False


def test_git_publication_authorization_requires_passed_post_apply_tests(tmp_path: Path) -> None:
    _, source_authorization = executor_tests._write_authorization(tmp_path)
    source_apply = executor.run_source_apply(
        authorization_path=source_authorization,
        output_root=tmp_path / "source-apply-no-tests",
        test_commands=[],
    )

    with pytest.raises(ValueError, match="requires passed post-source-apply test evidence"):
        module.record_git_publication_authorization(
            receipt_path=Path(source_apply["post_apply_receipt_path"]),
            output_path=tmp_path / "blocked_publication.json",
            operator_id="operator-001",
            reason="attempt fixture publication without tests",
            rollback_evidence_ref="rollback:missing-test",
            allowed_git_actions=["commit"],
            commit_message="docs: should be blocked",
            target_branch=None,
        )


def test_git_publication_authorization_keeps_push_dependent_on_commit(tmp_path: Path) -> None:
    receipt_path = _write_passed_post_apply_receipt(tmp_path)

    with pytest.raises(ValueError, match="push authorization requires commit authorization"):
        module.record_git_publication_authorization(
            receipt_path=receipt_path,
            output_path=tmp_path / "push_only.json",
            operator_id="operator-001",
            reason="attempt push-only publication",
            rollback_evidence_ref="rollback:push-only",
            allowed_git_actions=["push"],
            commit_message=None,
            target_branch="beta3-fixture",
        )


def _write_passed_post_apply_receipt(tmp_path: Path) -> Path:
    _, source_authorization = executor_tests._write_authorization(tmp_path)
    report = executor.run_source_apply(
        authorization_path=source_authorization,
        output_root=tmp_path / "source-apply-tested",
        test_commands=["grep -q 'beta3 sandbox change' README.md"],
    )
    return Path(report["post_apply_receipt_path"])
