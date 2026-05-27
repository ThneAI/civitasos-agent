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
_load("beta4_draft_pr_executor", ROOT / "scripts" / "beta4_draft_pr_executor.py")
_load("beta4_ready_pr_transition_executor", ROOT / "scripts" / "beta4_ready_pr_transition_executor.py")
beta5_fixture = _load(
    "beta5_post_review_merge_authorization_fixture_for_github_merge",
    ROOT / "benchmarks" / "tests" / "test_beta5_post_review_merge_authorization.py",
)
module = _load("beta5_github_merge_executor", ROOT / "scripts" / "beta5_github_merge_executor.py")


def test_github_merge_preflight_passes_for_clean_approved_ready_pr(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authorization_path = _write_authorization(tmp_path)
    authorization = json.loads(authorization_path.read_text(encoding="utf-8"))
    monkeypatch.setattr(module, "_gh", _fake_gh(authorization))

    report = module.run_merge_preflight(authorization_path=authorization_path)

    assert report["passed"] is True
    assert report["merge_allowed_by_preflight"] is True
    assert report["current_pr"]["mergeStateStatus"] == "CLEAN"
    assert report["deploy_allowed"] is False


def test_github_merge_preflight_rejects_unknown_merge_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authorization_path = _write_authorization(tmp_path)
    authorization = json.loads(authorization_path.read_text(encoding="utf-8"))
    monkeypatch.setattr(module, "_gh", _fake_gh(authorization, merge_state="UNKNOWN"))

    report = module.run_merge_preflight(authorization_path=authorization_path)

    assert report["passed"] is False
    assert "github_pr.mergeStateStatus must be CLEAN before merge" in report["failure_reasons"]


def test_github_merge_requires_explicit_operator_confirmation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authorization_path = _write_authorization(tmp_path)
    authorization = json.loads(authorization_path.read_text(encoding="utf-8"))
    monkeypatch.setattr(module, "_gh", _fake_gh(authorization))

    report = module.run_github_merge(
        authorization_path=authorization_path,
        output_root=tmp_path / "merge-run",
        merge_method="merge",
        operator_merge_confirmed=False,
    )

    assert report["passed"] is False
    assert report["failure_codes"] == ["operator_merge_confirmation_missing"]
    assert report["receipt_written"] is False


def test_github_merge_writes_receipt_after_confirmed_clean_merge(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authorization_path = _write_authorization(tmp_path)
    authorization = json.loads(authorization_path.read_text(encoding="utf-8"))
    monkeypatch.setattr(module, "_gh", _fake_gh(authorization))

    report = module.run_github_merge(
        authorization_path=authorization_path,
        output_root=tmp_path / "merge-run",
        merge_method="merge",
        operator_merge_confirmed=True,
    )
    receipt = json.loads(Path(report["receipt_path"]).read_text(encoding="utf-8"))

    assert report["passed"] is True
    assert report["receipt_validation"]["passed"] is True
    assert receipt["merge_performed"] is True
    assert receipt["git_actions_performed"] == {"commit": True, "push": True, "merge": True}
    assert receipt["deploy_allowed"] is False
    assert receipt["production_runtime_execution_allowed"] is False


def test_github_merge_receipt_validation_rejects_deploy_claim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authorization_path = _write_authorization(tmp_path)
    authorization = json.loads(authorization_path.read_text(encoding="utf-8"))
    monkeypatch.setattr(module, "_gh", _fake_gh(authorization))
    report = module.run_github_merge(
        authorization_path=authorization_path,
        output_root=tmp_path / "merge-run",
        merge_method="merge",
        operator_merge_confirmed=True,
    )
    receipt_path = Path(report["receipt_path"])
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["deploy_allowed"] = True
    receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    validation = module.validate_github_merge_receipt(receipt_path)

    assert validation["passed"] is False
    assert "deploy_allowed must be false" in validation["failure_reasons"]


def _write_authorization(tmp_path: Path) -> Path:
    packet = beta5_fixture._write_ready_review_packet(tmp_path)
    authorization_path = tmp_path / "beta5_post_review_merge_authorization.json"
    report = beta5_fixture.module.record_post_review_merge_authorization(
        review_evidence_packet_path=packet,
        output_path=authorization_path,
        operator_id="operator-001",
        reason="approve ready PR merge executor test after GitHub approval evidence",
        rollback_evidence_ref="rollback:close-pr-or-revert-merge-commit",
    )
    assert report["validation"]["passed"] is True
    return authorization_path


def _fake_gh(authorization: dict[str, object], *, merge_state: str = "CLEAN"):
    merged = {"value": False}

    def run(_failures: list[str], *args: str) -> dict[str, object]:
        if args[:2] == ("pr", "view"):
            pr = authorization["pr"]
            assert isinstance(pr, dict)
            state = "MERGED" if merged["value"] else "OPEN"
            payload = {
                **pr,
                "isDraft": False,
                "state": state,
                "headRefName": authorization["source_branch"],
                "headRefOid": authorization["source_commit_id"],
                "baseRefName": authorization["base_branch"],
                "author": {"login": "ThneAI"},
                "reviewDecision": "APPROVED",
                "reviews": [{"state": "APPROVED", "author": {"login": "Thneoly"}}],
                "latestReviews": [{"state": "APPROVED", "author": {"login": "Thneoly"}}],
                "statusCheckRollup": [],
                "mergeStateStatus": merge_state,
                "mergedAt": "2099-01-01T00:00:00Z" if merged["value"] else None,
                "mergedBy": {"login": "operator-001"} if merged["value"] else None,
                "mergeCommit": {"oid": "merge-commit-fixture"} if merged["value"] else None,
            }
            return {
                "command": " ".join(["gh", *args]),
                "returncode": 0,
                "stdout": json.dumps(payload),
                "stderr": "",
            }
        if args[:2] == ("pr", "merge"):
            assert "--match-head-commit" in args
            assert str(authorization["source_commit_id"]) in args
            merged["value"] = True
            return {
                "command": " ".join(["gh", *args]),
                "returncode": 0,
                "stdout": "Merged pull request",
                "stderr": "",
            }
        raise AssertionError(f"unexpected gh args: {args}")

    return run
