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
_load("beta3_source_apply_executor", ROOT / "scripts" / "beta3_source_apply_executor.py")
_load("beta3_git_publication_authorization", ROOT / "scripts" / "beta3_git_publication_authorization.py")
_load("beta3_git_commit_executor", ROOT / "scripts" / "beta3_git_commit_executor.py")
_load("beta3_git_push_executor", ROOT / "scripts" / "beta3_git_push_executor.py")
push_tests = _load(
    "beta3_git_merge_executor_fixture_for_draft_pr",
    ROOT / "benchmarks" / "tests" / "test_beta3_git_merge_executor.py",
)
module = _load("beta4_draft_pr_executor", ROOT / "scripts" / "beta4_draft_pr_executor.py")


def test_draft_pr_executor_creates_draft_pr_from_push_receipt(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _, push_receipt, _ = push_tests._write_push_receipt(tmp_path)
    authorization_path = _write_authorization(tmp_path, push_receipt)
    authorization = json.loads(authorization_path.read_text(encoding="utf-8"))
    monkeypatch.setattr(module, "_gh", _fake_gh(authorization))

    report = module.run_draft_pr_create(
        authorization_path=authorization_path,
        output_root=tmp_path / "draft-pr",
    )
    receipt = json.loads(Path(report["draft_pr_receipt_path"]).read_text(encoding="utf-8"))

    assert report["passed"] is True
    assert report["draft_pr_status"] == "draft_pr_created_with_receipt"
    assert report["receipt_validation"]["passed"] is True
    assert report["draft_pr"]["isDraft"] is True
    assert report["draft_pr"]["headRefOid"] == authorization["source_commit_id"]
    assert receipt["receipt_scope"] == "github_draft_pr_only"
    assert receipt["pr_review_approved"] is False
    assert receipt["merge_allowed"] is False
    assert receipt["deploy_allowed"] is False


def test_draft_pr_authorization_requires_distinct_base_branch(tmp_path: Path) -> None:
    _, push_receipt, _ = push_tests._write_push_receipt(tmp_path)
    body = _write_body(tmp_path)

    with pytest.raises(ValueError, match="base_branch must differ from pushed source branch"):
        module.record_draft_pr_authorization(
            push_receipt_path=push_receipt,
            github_repo="fixture/repo",
            base_branch="beta3-source-fixture",
            title="Beta-4 fixture draft PR",
            body_file=body,
            output_path=tmp_path / "same-branch-authorization.json",
            operator_id="operator-001",
            reason="prove base and source branch stay distinct",
            rollback_evidence_ref="rollback:close-fixture-pr",
        )


def test_draft_pr_executor_refuses_push_receipt_as_authorization(tmp_path: Path) -> None:
    _, push_receipt, _ = push_tests._write_push_receipt(tmp_path)

    report = module.run_draft_pr_create(
        authorization_path=push_receipt,
        output_root=tmp_path / "push-receipt-is-not-pr-authorization",
    )

    assert report["passed"] is False
    assert report["failure_codes"] == ["draft_pr_authorization_refused"]
    assert report["draft_pr_created"] is False
    assert any("schema_version must be beta4-draft-pr-authorization:v1" in reason for reason in report["failure_reasons"])


def test_draft_pr_receipt_validation_rejects_review_approval_claim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, push_receipt, _ = push_tests._write_push_receipt(tmp_path)
    authorization_path = _write_authorization(tmp_path, push_receipt)
    authorization = json.loads(authorization_path.read_text(encoding="utf-8"))
    monkeypatch.setattr(module, "_gh", _fake_gh(authorization))
    report = module.run_draft_pr_create(authorization_path=authorization_path, output_root=tmp_path / "draft-pr")
    receipt_path = Path(report["draft_pr_receipt_path"])
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["pr_review_approved"] = True
    receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    validation = module.validate_draft_pr_receipt(receipt_path)

    assert validation["passed"] is False
    assert "pr_review_approved must be false" in validation["failure_reasons"]


def _write_authorization(tmp_path: Path, push_receipt: Path) -> Path:
    authorization_path = tmp_path / "draft_pr_authorization.json"
    module.record_draft_pr_authorization(
        push_receipt_path=push_receipt,
        github_repo="fixture/repo",
        base_branch="main",
        title="Beta-4 fixture draft PR",
        body_file=_write_body(tmp_path),
        output_path=authorization_path,
        operator_id="operator-001",
        reason="open a bounded draft PR for external review evidence",
        rollback_evidence_ref="rollback:close-fixture-pr",
    )
    return authorization_path


def _write_body(tmp_path: Path) -> Path:
    body = tmp_path / "draft_pr_body.md"
    body.write_text("Draft review only. Merge and deploy remain separately authorized.\n", encoding="utf-8")
    return body


def _fake_gh(authorization: dict[str, object]):
    def run(_repo: Path, _failures: list[str], *args: str, input_text: str | None = None) -> dict[str, object]:
        command = " ".join(["gh", *args])
        if args[:2] == ("pr", "create"):
            assert "--draft" in args
            assert input_text == authorization["body"]["text"]
            return {
                "command": command,
                "returncode": 0,
                "stdout": "https://example.invalid/fixture/repo/pull/17\n",
                "stderr": "",
            }
        assert args[:2] == ("pr", "view")
        metadata = {
            "number": 17,
            "url": "https://example.invalid/fixture/repo/pull/17",
            "isDraft": True,
            "state": "OPEN",
            "headRefName": authorization["source_branch"],
            "headRefOid": authorization["source_commit_id"],
            "baseRefName": authorization["base_branch"],
            "title": authorization["title"],
        }
        return {
            "command": command,
            "returncode": 0,
            "stdout": json.dumps(metadata),
            "stderr": "",
        }

    return run
