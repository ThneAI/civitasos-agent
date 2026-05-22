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
draft = _load("beta4_draft_pr_executor", ROOT / "scripts" / "beta4_draft_pr_executor.py")
review = _load("beta4_pr_review_evidence", ROOT / "scripts" / "beta4_pr_review_evidence.py")
review_tests = _load(
    "beta4_pr_review_evidence_fixture_for_beta5",
    ROOT / "benchmarks" / "tests" / "test_beta4_pr_review_evidence.py",
)
module = _load(
    "beta5_post_review_merge_authorization",
    ROOT / "scripts" / "beta5_post_review_merge_authorization.py",
)


def test_post_review_merge_authorization_records_observed_approval(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    packet = _write_review_packet(tmp_path, monkeypatch, approved=True)
    authorization_path = tmp_path / "beta5_post_review_merge_authorization.json"

    report = module.record_post_review_merge_authorization(
        review_evidence_packet_path=packet,
        output_path=authorization_path,
        operator_id="operator-001",
        reason="approve merge execution review after GitHub approval evidence",
        rollback_evidence_ref="rollback:revert-reviewed-pr-merge",
    )
    authorization = json.loads(authorization_path.read_text(encoding="utf-8"))

    assert report["validation"]["passed"] is True
    assert authorization["merge_authorized"] is True
    assert authorization["merge_performed"] is False
    assert authorization["github_review_approval_observed"] is True
    assert authorization["deploy_allowed"] is False
    assert authorization["review_observation"]["review_state"] == "approved_review_observed"


def test_post_review_merge_authorization_blocks_pending_review(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    packet = _write_review_packet(tmp_path, monkeypatch, approved=False)

    with pytest.raises(ValueError, match="approved_review_observed"):
        module.record_post_review_merge_authorization(
            review_evidence_packet_path=packet,
            output_path=tmp_path / "must-not-write.json",
            operator_id="operator-001",
            reason="pending review cannot authorize merge",
            rollback_evidence_ref="rollback:not-authorized",
        )


def test_post_review_merge_authorization_validation_rejects_packet_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    packet = _write_review_packet(tmp_path, monkeypatch, approved=True)
    authorization_path = tmp_path / "authorization.json"
    module.record_post_review_merge_authorization(
        review_evidence_packet_path=packet,
        output_path=authorization_path,
        operator_id="operator-001",
        reason="record drift fixture",
        rollback_evidence_ref="rollback:drift-fixture",
    )
    payload = json.loads(packet.read_text(encoding="utf-8"))
    payload["review_observation"]["comment_count"] = 99
    packet.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    validation = module.validate_post_review_merge_authorization(authorization_path)

    assert validation["passed"] is False
    assert "source_review_evidence_packet.sha256 does not match file bytes" in validation["failure_reasons"]


def test_post_review_merge_authorization_validation_rejects_deploy_claim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    packet = _write_review_packet(tmp_path, monkeypatch, approved=True)
    authorization_path = tmp_path / "authorization.json"
    module.record_post_review_merge_authorization(
        review_evidence_packet_path=packet,
        output_path=authorization_path,
        operator_id="operator-001",
        reason="record deploy boundary fixture",
        rollback_evidence_ref="rollback:deploy-boundary",
    )
    authorization = json.loads(authorization_path.read_text(encoding="utf-8"))
    authorization["deploy_allowed"] = True
    authorization_path.write_text(json.dumps(authorization, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    validation = module.validate_post_review_merge_authorization(authorization_path)

    assert validation["passed"] is False
    assert "deploy_allowed must be false" in validation["failure_reasons"]


def _write_review_packet(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, approved: bool) -> Path:
    receipt = review_tests._write_draft_receipt(tmp_path, monkeypatch)
    receipt_payload = json.loads(receipt.read_text(encoding="utf-8"))
    monkeypatch.setattr(review, "_gh", _fake_gh(receipt_payload, approved=approved))
    packet = tmp_path / ("approved_review_packet.json" if approved else "pending_review_packet.json")
    report = review.capture_review_evidence(draft_pr_receipt_path=receipt, output_path=packet)
    assert report["passed"] is True
    return packet


def _fake_gh(receipt: dict[str, object], *, approved: bool):
    def run(_failures: list[str], *args: str) -> dict[str, object]:
        assert args[:2] == ("pr", "view")
        draft_pr = receipt["draft_pr"]
        assert isinstance(draft_pr, dict)
        review_state = "APPROVED" if approved else ""
        review_rows = [{"state": "APPROVED", "author": {"login": "reviewer-fixture"}}] if approved else []
        metadata = {
            **draft_pr,
            "reviewDecision": review_state,
            "reviews": review_rows,
            "latestReviews": review_rows,
            "comments": [],
            "statusCheckRollup": [],
            "mergeStateStatus": "CLEAN",
        }
        return {
            "command": " ".join(["gh", *args]),
            "returncode": 0,
            "stdout": json.dumps(metadata),
            "stderr": "",
        }

    return run
